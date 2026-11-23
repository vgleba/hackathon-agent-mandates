"""Gateway verification pipeline.

    receive (request, mandate)
      -> verify mandate: issuer accredited / signature / time / revocation
      -> verify proof of possession (request signed by cnf key, fresh nonce and ts)
      -> check request against deny, then scope: any one entry must accept the
         whole call (constraints, then how many rows it may return)
      -> decision record {ALLOW | DENY | STEP_UP, reason_code, ...}

Reason codes are stable strings so the audit log and Day 2 scorecard can
count them. Order of checks is deliberate: cheapest and most definitive first.
"""
from __future__ import annotations

import fnmatch
import posixpath
import time
from dataclasses import asdict, dataclass

import jwt

from .common import canonical, jwk_thumbprint, jwk_to_pub, pub_to_pem, sha256_hex, verify_bytes
from .status_list import is_revoked

POLICY_VERSION = "2026-11-23.1"
CLOCK_SKEW = 30

# Question 3: how much one call may return. Tools that take a `limit`, with the default the server applies when the
# request leaves it out. A scope entry may set its own `max_rows`; without one, DEFAULT_MAX_ROWS applies.
ROW_LIMITED_TOOLS = {"pupil-data.search": 100, "pupil-data.get": 100}
DEFAULT_MAX_ROWS = 100
# Question 3: arguments that pick rows by substring. A blank one matches every row.
SELECTOR_ARGS = {"pupil-data.search": "query"}
# Question 4: arguments that name a file, compared by the file they name rather than by spelling.
PATH_ARGS = {"path"}
# When no entry accepts a call, report the entry that came closest: one that failed only on volume beats one that
# failed on a value, which beats one that was missing an argument.
_MISS_RANK = {"QUERY_TOO_BROAD": 0, "LIMIT_EXCEEDED": 0, "LIMIT_INVALID": 0, "CONSTRAINT_VIOLATED": 1,
              "CONSTRAINT_MISSING": 2}


class Reject(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass
class Decision:
    decision: str            # ALLOW | DENY | STEP_UP
    reason_code: str
    policy_version: str
    mandate_hash: str
    request_hash: str
    agent_id: str | None
    ts: float
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Request:
    """What the agent sends to the gateway for a tools/call."""
    server: str
    tool: str
    arguments: dict
    mandate: str             # compact JWT
    nonce: str
    ts: int
    sig: str                 # Ed25519 over canonical(signing_input()) by cnf key

    def signing_input(self) -> bytes:
        return canonical({
            "server": self.server, "tool": self.tool, "arguments": self.arguments,
            "mandate_hash": sha256_hex(self.mandate.encode()), "nonce": self.nonce, "ts": self.ts,
        })


# ---------------------------------------------------------------- mandate

def verify_mandate(token: str, registry, status_lists: dict[str, str]) -> dict:
    """Returns the verified claims. Raises Reject."""
    hdr = jwt.get_unverified_header(token)
    if hdr.get("typ") != "mandate+jwt":
        raise Reject("WRONG_TOKEN_TYPE", hdr.get("typ"))
    unverified = jwt.decode(token, options={"verify_signature": False})

    pub = registry.issuer_key(unverified["iss"], hdr.get("kid", ""))
    if pub is None:
        raise Reject("ISSUER_NOT_ACCREDITED", unverified["iss"])
    try:
        claims = jwt.decode(token, pub_to_pem(pub), algorithms=["EdDSA"],
                            options={"verify_exp": False, "verify_nbf": False, "require": ["exp", "iss", "jti"]})
    except jwt.PyJWTError as e:
        raise Reject("SIG_INVALID", str(e))

    now = time.time()
    if claims.get("nbf", 0) > now + CLOCK_SKEW:
        raise Reject("NOT_YET_VALID", claims["jti"])
    if claims["exp"] < now - CLOCK_SKEW:
        raise Reject("EXPIRED", claims["jti"])

    sl = claims["status"]["status_list"]
    sl_jwt = status_lists.get(sl["uri"])
    if sl_jwt is None:
        raise Reject("STATUS_UNAVAILABLE", sl["uri"])     # fail closed
    try:
        if is_revoked(sl_jwt, sl["idx"], pub, sl["uri"]):
            raise Reject("REVOKED", claims["jti"])
    except ValueError as e:
        raise Reject("STATUS_UNAVAILABLE", str(e))
    return claims


# ---------------------------------------------------------------- scope

def normalise_path(value: object) -> str | None:
    """Question 4: one spelling per file. `./a/b`, `a//b` and `a/x/../b` all become `a/b`.

    Returns None for anything that is not a plain relative path inside the data directory: not a string, empty,
    absolute, or still climbing out with `..` after normalising. The MCP server opens `(DATA_ROOT / path).resolve()`,
    which names the same file as `DATA_ROOT / normalise_path(path)` as long as the data directory holds no symlinks.
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    path = posixpath.normpath(value)
    if path.startswith("/") or path == ".." or path.startswith("../"):
        return None
    return path


def _value_allowed(key: str, value: object, allowed: list) -> bool:
    if key in PATH_ARGS:
        path = normalise_path(value)
        return path is not None and path in {normalise_path(a) for a in allowed}
    return str(value) in set(map(str, allowed))


def _volume_refusal(name: str, arguments: dict, entry: dict) -> tuple[str, str] | None:
    """Question 3: the right school is not enough. Refuse a call that selects every row, or asks for more rows than
    the entry allows. Returns (reason_code, detail), or None if the call is within bounds."""
    selector = SELECTOR_ARGS.get(name)
    if selector is not None:
        query = arguments.get(selector)
        if not isinstance(query, str) or not query.strip():
            return "QUERY_TOO_BROAD", f"{selector}={query!r} matches every row"
    server_default = ROW_LIMITED_TOOLS.get(name)
    if server_default is not None:
        cap = entry.get("max_rows", DEFAULT_MAX_ROWS)
        if type(cap) is not int:
            return "LIMIT_INVALID", f"mandate max_rows={cap!r}"
        limit = arguments.get("limit", server_default)
        # Only a real int: the server coerces "1000" and 1000.0 to 1000 and True to 1, so comparing anything else
        # would mean comparing a different number from the one the server uses.
        if type(limit) is not int or limit < 1:
            return "LIMIT_INVALID", f"limit={limit!r}"
        if limit > cap:
            shown = "limit" if "limit" in arguments else f"default limit {server_default}"
            return "LIMIT_EXCEEDED", f"{shown}={limit} > max_rows {cap}"
    return None


def _entry_refusal(req: Request, name: str, entry: dict) -> tuple[str, str] | None:
    """Why this one scope entry does not cover the call, or None if it does. Every check is against this entry alone,
    so a call cannot take `urn` from one entry and `path` from another."""
    for k, allowed in entry.get("constraints", {}).items():
        if k not in req.arguments:
            return "CONSTRAINT_MISSING", k
        if not _value_allowed(k, req.arguments[k], allowed):
            return "CONSTRAINT_VIOLATED", f"{k}={req.arguments[k]!r}"
    return _volume_refusal(name, req.arguments, entry)


def check_request(req: Request, scope: list[dict], deny: list[str], step_up_patterns: list[str]) -> tuple[str, str, str]:
    name = f"{req.server}.{req.tool}"
    for pat in deny:
        if fnmatch.fnmatch(name, pat):
            return "DENY", "DENIED_BY_RULE", pat
    # Question 5: an issuer may grant the same tool in several entries (one per school). The call is allowed if any
    # one entry accepts it, not just the first entry that lists the tool.
    refusals = []
    for entry in scope:
        if entry["server"] != req.server or req.tool not in entry["tools"]:
            continue
        refusal = _entry_refusal(req, name, entry)
        if refusal is None:
            for pat in step_up_patterns:
                if fnmatch.fnmatch(name, pat):
                    return "STEP_UP", "SENSITIVE_TOOL", pat
            return "ALLOW", "IN_SCOPE", ""
        refusals.append(refusal)
    if not refusals:
        return "DENY", "OUT_OF_SCOPE", name
    code, detail = min(refusals, key=lambda r: _MISS_RANK.get(r[0], len(_MISS_RANK)))
    return "DENY", code, detail


# ---------------------------------------------------------------- the pipeline

class Gateway:
    def __init__(self, registry, status_lists: dict[str, str], step_up_patterns: list[str] | None = None):
        self.registry = registry
        self.status_lists = status_lists
        self.step_up = step_up_patterns or ["*.write", "*.draft"]
        self._seen_nonces: set[str] = set()

    def decide(self, req: Request) -> Decision:
        base = dict(policy_version=POLICY_VERSION, mandate_hash=sha256_hex(req.mandate.encode()),
                    request_hash=sha256_hex(req.signing_input()), ts=time.time())
        try:
            claims = verify_mandate(req.mandate, self.registry, self.status_lists)
            jwk = claims["cnf"]["jwk"]
            if abs(req.ts - time.time()) > 300:
                raise Reject("POP_FAILED", "request timestamp outside window")
            if req.nonce in self._seen_nonces:
                raise Reject("POP_FAILED", "replayed nonce")
            if not verify_bytes(jwk_to_pub(jwk), req.signing_input(), req.sig):
                raise Reject("POP_FAILED", f"bad signature for jkt {jwk_thumbprint(jwk)}")
            self._seen_nonces.add(req.nonce)

            decision, code, detail = check_request(req, claims["scope"], claims["deny"], self.step_up)
            return Decision(decision, code, agent_id=claims["agent_id"], detail=detail, **base)
        except Reject as r:
            return Decision("DENY", r.code, agent_id=None, detail=r.detail, **base)
