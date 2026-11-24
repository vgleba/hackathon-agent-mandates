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
import logging
import time
from dataclasses import dataclass, field, fields

import jwt

from . import delegation, paths, volume
from .common import MAX_MANDATE, canonical, jwk_thumbprint, jwk_to_pub, pub_to_pem, sha256_hex, verify_bytes
from .errors import Reject
from .record import safe_text
from .status_list import is_revoked
from .store import Store

POLICY_VERSION = "2026-11-24.2"
CLOCK_SKEW = 30          # seconds an issuer's clock may run ahead: for the start of validity (nbf) only, never exp
REQUEST_MAX_AGE = 300    # requests may be this old, but only CLOCK_SKEW seconds ahead
MAX_DETAIL = 200         # characters of `detail` sent back with a decision
OWN_SERVER = "gateway"   # where an agent asks after a call that is waiting for a person
log = logging.getLogger(__name__)


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
    # for the gateway only, never sent to the agent
    claims: dict | None = field(default=None, repr=False)      # genuine: the issuer signed them
    arguments: dict | None = field(default=None, repr=False)   # as checked, which is what gets forwarded

    def to_dict(self) -> dict:
        """What the agent is sent. `detail` can repeat text the caller chose, such as the `typ` or `iss` of a token
        nobody signed, so it is made safe to encode and kept short: otherwise a refusal becomes a 500."""
        out = {f.name: getattr(self, f.name) for f in fields(self) if f.name not in ("claims", "arguments")}
        out["detail"] = safe_text(str(out["detail"] or ""), MAX_DETAIL)
        return out


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

def verify_mandate(token: str, registry, status_lists: dict[str, str], now: float | None = None) -> dict:
    """Returns the verified claims. Raises Reject. `now` is the decision's one reading of the clock."""
    now = time.time() if now is None else now
    try:
        hdr = jwt.get_unverified_header(token)
        if hdr.get("typ") != "mandate+jwt":
            raise Reject("WRONG_TOKEN_TYPE", hdr.get("typ"))
        unverified = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise Reject("WRONG_TOKEN_TYPE", "not a readable mandate") from e

    pub = registry.issuer_key(unverified["iss"], hdr.get("kid", ""))
    if pub is None:
        raise Reject("ISSUER_NOT_ACCREDITED", unverified["iss"])
    try:
        # time is judged below, against `now`: PyJWT would read its own clock, and allow no skew on `iat`
        claims = jwt.decode(token, pub_to_pem(pub), algorithms=["EdDSA"],
                            options={"verify_exp": False, "verify_nbf": False, "verify_iat": False,
                                     "require": ["exp", "iss", "jti"]})
    except jwt.PyJWTError as e:
        raise Reject("SIG_INVALID", str(e))

    if claims.get("nbf", 0) > now + CLOCK_SKEW:
        raise Reject("NOT_YET_VALID", claims["jti"], claims)
    if now >= claims["exp"]:  # dead from its expiry second: no grace (red-team RT-02)
        raise Reject("EXPIRED", claims["jti"], claims)

    sl = claims["status"]["status_list"]
    sl_jwt = status_lists.get(sl["uri"])
    if sl_jwt is None:
        raise Reject("STATUS_UNAVAILABLE", sl["uri"], claims)     # fail closed
    try:
        if is_revoked(sl_jwt, sl["idx"], pub, sl["uri"]):
            raise Reject("REVOKED", claims["jti"], claims)
    except ValueError as e:
        raise Reject("STATUS_UNAVAILABLE", str(e), claims) from e
    return claims


# ---------------------------------------------------------------- scope

def _permits(value, allowed: list) -> bool:
    """One value, or a list in which every item is allowed. A list or object may also be allowed as a whole."""
    plain = {str(a) for a in allowed if not isinstance(a, (list, dict))}
    if isinstance(value, (list, dict)):
        if any(type(a) is type(value) and canonical(a) == canonical(value) for a in allowed):
            return True
        return isinstance(value, list) and bool(value) and all(
            isinstance(v, (str, int)) and not isinstance(v, bool) and str(v) in plain for v in value
        )
    return str(value) in plain


def _failures(arguments: dict, constraints: dict) -> list[tuple[str, str]]:
    found = []
    for k, allowed in constraints.items():
        if k not in arguments:
            found.append(("CONSTRAINT_MISSING", k))
        elif not _permits(arguments[k], allowed):
            found.append(("CONSTRAINT_VIOLATED", f"{k}={arguments[k]!r}"))
    return found


def _over_max_rows(tool: str, arguments: dict, entry: dict) -> tuple[str, str] | None:
    """Question 3: a scope entry may set `max_rows`, the most rows one call under it may ask for. It can only lower
    the gateway's own limit (volume.MAX_LIMIT), which a call that leaves `limit` out gets. A `limit` that is not a
    whole number in range is refused by volume.check_arguments, after scope."""
    if tool not in volume.GOVERNED_TOOLS or "max_rows" not in entry:
        return None
    cap = entry["max_rows"]
    if type(cap) is not int or cap < 1:
        return "CLAIM_NOT_UNDERSTOOD", f"max_rows must be a whole number of at least 1, not {cap!r}"
    limit = arguments.get("limit", volume.MAX_LIMIT)
    if type(limit) is int and limit > cap:
        shown = "limit" if "limit" in arguments else f"default limit {volume.MAX_LIMIT}"
        return "LIMIT_EXCEEDED", f"{shown}={limit} > max_rows {cap}"
    return None


def match_scope(server: str, tool: str, arguments: dict, scope: list[dict]) -> tuple[str, str] | None:
    """None if any one entry accepts the whole call, else the reason from the entry that came closest.

    Each entry is judged alone: a call can never take its school from one entry and its file from another, nor its
    school from one entry and its row cap from another.
    """
    closest = None
    for entry in scope:
        if entry["server"] != server or tool not in entry["tools"]:
            continue
        found = _failures(arguments, entry.get("constraints", {}))
        if not found and (over := _over_max_rows(tool, arguments, entry)):
            found = [over]
        if not found:
            return None
        if closest is None or len(found) < len(closest):
            closest = found
    return closest[0] if closest else ("OUT_OF_SCOPE", f"{server}.{tool}")


def check_request(req: Request, arguments: dict, scopes: list[list[dict]], deny: list[str],
                  step_up_patterns: list[str]) -> tuple[str, str, str]:
    """Every scope in `scopes` must allow the call: a mandate has one, a helper's also has its parent's."""
    name = f"{req.server}.{req.tool}"
    for pat in deny:
        if fnmatch.fnmatch(name, pat):
            return "DENY", "DENIED_BY_RULE", pat
    for scope in scopes:
        if refused := match_scope(req.server, req.tool, arguments, scope):
            return "DENY", *refused
    # only once scope has passed, so a volume refusal says nothing about data outside the mandate
    if refused := volume.check_arguments(req.tool, arguments):
        return "DENY", *refused
    for pat in step_up_patterns:
        if fnmatch.fnmatch(name, pat):
            return "STEP_UP", "SENSITIVE_TOOL", pat
    return "ALLOW", "IN_SCOPE", ""


def clean_arguments(req: Request) -> dict:
    """The arguments as they will be checked and forwarded."""
    if req.tool != "get" or "path" not in req.arguments:
        return req.arguments
    path = paths.clean(req.arguments["path"])
    if path is None:
        raise Reject("PATH_NOT_ALLOWED", "write the file's path plainly, such as folder/file.csv")
    return {**req.arguments, "path": path}


# ---------------------------------------------------------------- the pipeline

class Gateway:
    def __init__(self, registry, status_lists: dict[str, str], step_up_patterns: list[str] | None = None,
                 store: Store | None = None, started: float | None = None):
        self.registry = registry
        self.status_lists = status_lists
        self.step_up = step_up_patterns or ["*.write", "*.draft"]
        self.store = store or Store()
        self.started = time.time() if started is None else started

    def verify(self, token: str, now: float | None = None) -> dict:
        """Is this mandate good at `now` (by default, right now)? Returns its claims, or raises Reject."""
        now = time.time() if now is None else now
        if not isinstance(token, str) or len(token) > MAX_MANDATE:
            raise Reject("WRONG_TOKEN_TYPE", "too long to be a mandate")
        try:
            child = delegation.is_child(token)
        except jwt.PyJWTError as e:
            raise Reject("WRONG_TOKEN_TYPE", "not a readable mandate") from e
        if child:
            return delegation.verify_child(token, self._verify_root, self._helper_revoked, now)
        claims = self._verify_root(token, now)
        # last, so that a claim of the same name cannot stand in for these
        return {**claims, "root": claims["jti"], "scopes": [claims["scope"]]}

    def _verify_root(self, token: str, now: float) -> dict:
        claims = verify_mandate(token, self.registry, self.status_lists, now)
        return {**claims, "_kid": jwt.get_unverified_header(token).get("kid", "")}

    def _helper_revoked(self, parent: dict, number: int) -> bool:
        sl = parent["status"]["status_list"]
        try:
            return is_revoked(self.status_lists[sl["uri"]], number, self.registry.issuer_key(parent["iss"], parent["_kid"]),
                              sl["uri"])
        except (KeyError, ValueError) as e:
            raise Reject("STATUS_UNAVAILABLE", "cannot tell if this helper was stopped", parent) from e

    def check_scope(self, req: Request, claims: dict) -> tuple[str, str, str, dict]:
        arguments = clean_arguments(req)
        return *check_request(req, arguments, claims["scopes"], claims["deny"], self.step_up), arguments

    def decide(self, req: Request) -> Decision:
        now = time.time()  # the one reading: every time check in this decision is made against it
        base = dict(policy_version=POLICY_VERSION, mandate_hash="", request_hash="", ts=now)
        claims = None
        try:
            # inside the try: text that is not valid Unicode cannot be hashed
            base.update(mandate_hash=sha256_hex(req.mandate.encode()), request_hash=sha256_hex(req.signing_input()))
            claims = self.verify(req.mandate, now)
            jwk = claims["cnf"]["jwk"]
            who = jwk_thumbprint(jwk)
            if req.ts < int(self.started) or req.ts < now - REQUEST_MAX_AGE or req.ts > now + CLOCK_SKEW:
                raise Reject("POP_FAILED", "request timestamp outside window")
            if not verify_bytes(jwk_to_pub(jwk), req.signing_input(), req.sig):
                raise Reject("POP_FAILED", f"bad signature for jkt {who}")
            if not self.store.use_nonce(who, req.nonce):
                raise Reject("POP_FAILED", "replayed nonce")

            if req.server == OWN_SERVER:
                if req.tool != "held" or not isinstance(req.arguments.get("id"), str):
                    raise Reject("OUT_OF_SCOPE", "the gateway's own server has one tool: held(id)")
                return Decision("ALLOW", "HELD_STATUS", agent_id=claims["agent_id"], claims=claims,
                                arguments=req.arguments, **base)
            decision, code, detail, arguments = self.check_scope(req, claims)
            return Decision(decision, code, agent_id=claims["agent_id"], detail=detail, claims=claims,
                            arguments=arguments, **base)
        except Reject as r:
            return Decision("DENY", r.code, agent_id=None, detail=r.detail, claims=claims or r.claims, **base)
        except Exception:
            # fail closed: everything in a request is the caller's to choose, so what the checks cannot
            # handle is refused, never a 500. Logged, because it may also be a bug in the checks.
            log.exception("refused a request that could not be decided")
            return Decision("DENY", "MALFORMED_REQUEST", agent_id=None, claims=claims, **base)
