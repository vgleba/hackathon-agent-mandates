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
from .mandate_issuer import MAX_TTL, VCT
from .record import safe_text
from .status_list import is_revoked
from .store import Store

POLICY_VERSION = "2026-11-24.2"
CLOCK_SKEW = 30  # seconds an issuer's clock may run ahead: for the start of validity (nbf) only, never exp
REQUEST_MAX_AGE = 300  # requests may be this old, but only CLOCK_SKEW seconds ahead
MAX_DETAIL = 200  # characters of `detail` sent back with a decision
OWN_SERVER = "gateway"  # where an agent asks after a call that is waiting for a person
PROOF_METHOD = "POST"
PROOF_URI = "/tools/call"
AGENT_CALLS_PER_MINUTE = 300
MANDATE_CALLS_PER_MINUTE = 1000
PRINCIPAL_CALLS_PER_MINUTE = 2000
UNRESOLVED_AUDIENCE = "urn:hack:unresolved-audience"
log = logging.getLogger(__name__)


@dataclass
class Decision:
    decision: str  # ALLOW | DENY | STEP_UP
    reason_code: str
    policy_version: str
    mandate_hash: str
    request_hash: str
    agent_id: str | None
    ts: float
    detail: str = ""
    # for the gateway only, never sent to the agent
    claims: dict | None = field(default=None, repr=False)  # genuine: the issuer signed them
    arguments: dict | None = field(default=None, repr=False)  # as checked, which is what gets forwarded

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
    mandate: str  # compact JWT
    nonce: str
    ts: int
    sig: str  # Ed25519 over canonical(signing_input()) by cnf key

    def signing_input(self, audience: str | None = None) -> bytes:
        if audience is None:
            try:
                audience = mandate_audience(self.mandate)
            except (jwt.PyJWTError, TypeError, ValueError):
                # A malformed mandate is still useful in negative tests and probes. The gateway rejects it before it
                # reaches proof verification, so this sentinel can never authorize anything.
                audience = UNRESOLVED_AUDIENCE
        return canonical(
            {
                "aud": audience,
                "htm": PROOF_METHOD,
                "htu": PROOF_URI,
                "server": self.server,
                "tool": self.tool,
                "arguments": self.arguments,
                "mandate_hash": sha256_hex(self.mandate.encode()),
                "nonce": self.nonce,
                "ts": self.ts,
            }
        )


# ---------------------------------------------------------------- mandate


def mandate_audience(token: str) -> str:
    """Read the signed root's audience for client-side proof construction. Verification still happens at the gateway."""
    for _ in range(32):
        claims = jwt.decode(token, options={"verify_signature": False})
        audience = claims.get("aud")
        if isinstance(audience, str) and audience:
            return audience
        token = claims.get("parent")
        if not isinstance(token, str):
            break
    raise ValueError("mandate has no audience")


def _validate_profile(claims: dict, expected_audience: str) -> None:
    required = {
        "iss",
        "jti",
        "iat",
        "nbf",
        "exp",
        "vct",
        "aud",
        "delegator",
        "principal_epoch",
        "cnf",
        "agent_id",
        "purpose",
        "purpose_code",
        "clearance",
        "budget",
        "scope",
        "deny",
        "status",
    }
    if missing := sorted(required - set(claims)):
        raise Reject("CLAIM_NOT_UNDERSTOOD", f"hardened mandate is missing {missing}", claims)
    if claims["vct"] != VCT:
        raise Reject("CLAIM_NOT_UNDERSTOOD", f"unsupported mandate profile {claims['vct']!r}", claims)
    if claims["aud"] != expected_audience:
        raise Reject("WRONG_AUDIENCE", "mandate is for another gateway", claims)
    if not all(type(claims[name]) is int for name in ("iat", "nbf", "exp", "principal_epoch")):
        raise Reject("CLAIM_NOT_UNDERSTOOD", "mandate time and principal epoch must be whole numbers", claims)
    if claims["principal_epoch"] < 1:
        raise Reject("CLAIM_NOT_UNDERSTOOD", "principal epoch must be positive", claims)
    delegator = claims["delegator"]
    if not isinstance(delegator, dict) or not isinstance(delegator.get("principal"), str):
        raise Reject("CLAIM_NOT_UNDERSTOOD", "delegator principal is invalid", claims)
    try:
        jwk = claims["cnf"]["jwk"]
        expected_agent = jwk_thumbprint(jwk)
        jwk_to_pub(jwk)
    except (KeyError, TypeError, ValueError) as e:
        raise Reject("CLAIM_NOT_UNDERSTOOD", "proof-of-possession key is invalid", claims) from e
    if claims["agent_id"] != expected_agent:
        raise Reject("CLAIM_NOT_UNDERSTOOD", "agent id does not match its proof key", claims)
    if not isinstance(claims["purpose"], str) or not isinstance(claims["purpose_code"], str):
        raise Reject("CLAIM_NOT_UNDERSTOOD", "purpose claims must be text", claims)
    if type(claims["clearance"]) is not int or not 1 <= claims["clearance"] <= 4:
        raise Reject("CLAIM_NOT_UNDERSTOOD", "clearance must be a whole number from 1 to 4", claims)
    budget = claims["budget"]
    if not isinstance(budget, dict) or set(budget) != {"pupils"} or type(budget["pupils"]) is not int:
        raise Reject("CLAIM_NOT_UNDERSTOOD", "budget must contain one whole-number pupils limit", claims)
    if not 0 <= budget["pupils"] <= 1_000_000:
        raise Reject("CLAIM_NOT_UNDERSTOOD", "budget is outside the supported range", claims)
    scope = claims["scope"]
    if not isinstance(scope, list) or not scope or not all(isinstance(entry, dict) for entry in scope):
        raise Reject("CLAIM_NOT_UNDERSTOOD", "scope must be a non-empty list", claims)
    for entry in scope:
        tools, constraints = entry.get("tools"), entry.get("constraints", {})
        if (
            not isinstance(entry.get("server"), str)
            or not isinstance(tools, list)
            or not tools
            or not all(isinstance(tool, str) and tool != "*" for tool in tools)
            or not isinstance(constraints, dict)
            or not all(isinstance(values, list) and values for values in constraints.values())
        ):
            raise Reject("CLAIM_NOT_UNDERSTOOD", "scope entry is invalid", claims)
    if not isinstance(claims["deny"], list) or not all(isinstance(pattern, str) for pattern in claims["deny"]):
        raise Reject("CLAIM_NOT_UNDERSTOOD", "deny must be a list of patterns", claims)
    status = claims["status"]
    try:
        status_list = status["status_list"]
        uri, idx = status_list["uri"], status_list["idx"]
    except (KeyError, TypeError) as e:
        raise Reject("CLAIM_NOT_UNDERSTOOD", "status reference is invalid", claims) from e
    if not isinstance(uri, str) or type(idx) is not int or idx < 0:
        raise Reject("CLAIM_NOT_UNDERSTOOD", "status reference is invalid", claims)


def verify_mandate(
    token: str,
    registry,
    status_lists: dict[str, str],
    expected_audience: str,
    now: float | None = None,
) -> dict:
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
        claims = jwt.decode(
            token,
            pub_to_pem(pub),
            algorithms=["EdDSA"],
            options={
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "require": ["exp", "iss", "jti"],
            },
        )
    except jwt.PyJWTError as e:
        raise Reject("SIG_INVALID", str(e))

    _validate_profile(claims, expected_audience)
    if claims["nbf"] > now + CLOCK_SKEW:
        raise Reject("NOT_YET_VALID", claims["jti"], claims)
    if now >= claims["exp"]:  # dead from its expiry second: no grace (red-team RT-02)
        raise Reject("EXPIRED", claims["jti"], claims)
    if claims["exp"] <= claims["iat"] or claims["exp"] - claims["iat"] > MAX_TTL:
        raise Reject("CLAIM_NOT_UNDERSTOOD", f"mandate lifetime must be at most {MAX_TTL} seconds", claims)

    sl = claims["status"]["status_list"]
    sl_jwt = status_lists.get(sl["uri"])
    if sl_jwt is None:
        raise Reject("STATUS_UNAVAILABLE", sl["uri"], claims)  # fail closed
    try:
        if is_revoked(sl_jwt, sl["idx"], pub, sl["uri"], now):
            raise Reject("REVOKED", claims["jti"], claims)
    except ValueError as e:
        raise Reject("STATUS_UNAVAILABLE", str(e), claims) from e
    return claims


# ---------------------------------------------------------------- scope


def _permits(value, allowed: list) -> bool:
    """One value, or a list in which every item is allowed, with no string/number/bool coercion."""

    def same(left, right) -> bool:
        return type(left) is type(right) and canonical(left) == canonical(right)

    plain = [a for a in allowed if not isinstance(a, (list, dict))]
    if isinstance(value, (list, dict)):
        if any(same(a, value) for a in allowed):
            return True
        return isinstance(value, list) and bool(value) and all(any(same(v, a) for a in plain) for v in value)
    return any(same(value, a) for a in plain)


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


def check_request(
    req: Request, arguments: dict, scopes: list[list[dict]], deny: list[str], step_up_patterns: list[str]
) -> tuple[str, str, str]:
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
    def __init__(
        self,
        registry,
        status_lists: dict[str, str],
        step_up_patterns: list[str] | None = None,
        store: Store | None = None,
        started: float | None = None,
        audience: str | None = None,
    ):
        self.registry = registry
        self.status_lists = status_lists
        self.step_up = step_up_patterns or ["*.write", "*.draft"]
        self.store = store or Store()
        self.started = time.time() if started is None else started
        self.audience = audience or registry.audience

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
            return delegation.verify_child(token, self._verify_root, self._helper_revoked, self._bind_helper, now)
        claims = self._verify_root(token, now)
        # last, so that a claim of the same name cannot stand in for these
        return {**claims, "root": claims["jti"], "scopes": [claims["scope"]]}

    def _verify_root(self, token: str, now: float) -> dict:
        claims = verify_mandate(token, self.registry, self.status_lists, self.audience, now)
        return {**claims, "_kid": jwt.get_unverified_header(token).get("kid", "")}

    def _helper_revoked(self, parent: dict, number: int, now: float) -> bool:
        sl = parent["status"]["status_list"]
        try:
            return is_revoked(
                self.status_lists[sl["uri"]],
                number,
                self.registry.issuer_key(parent["iss"], parent["_kid"]),
                sl["uri"],
                now,
            )
        except (KeyError, ValueError) as e:
            raise Reject("STATUS_UNAVAILABLE", "cannot tell if this helper was stopped", parent) from e

    def _bind_helper(self, parent: dict, number: int, child_jkt: str, child_jti: str) -> bool:
        return self.store.bind_helper_slot(parent["jti"], number, child_jkt, child_jti)

    def check_scope(self, req: Request, claims: dict) -> tuple[str, str, str, dict]:
        arguments = clean_arguments(req)
        return *check_request(req, arguments, claims["scopes"], claims["deny"], self.step_up), arguments

    def decide(self, req: Request) -> Decision:
        now = time.time()  # the one reading: every time check in this decision is made against it
        base = dict(policy_version=POLICY_VERSION, mandate_hash="", request_hash="", ts=now)
        claims = None
        try:
            # inside the try: text that is not valid Unicode cannot be hashed
            base.update(mandate_hash=sha256_hex(req.mandate.encode()))
            claims = self.verify(req.mandate, now)
            proof = req.signing_input(claims["aud"])
            base.update(request_hash=sha256_hex(proof))
            jwk = claims["cnf"]["jwk"]
            who = jwk_thumbprint(jwk)
            if req.ts < int(self.started) or req.ts < now - REQUEST_MAX_AGE or req.ts > now + CLOCK_SKEW:
                raise Reject("POP_FAILED", "request timestamp outside window")
            if not verify_bytes(jwk_to_pub(jwk), proof, req.sig):
                raise Reject("POP_FAILED", f"bad signature for jkt {who}")
            if not self.store.use_nonce(who, req.nonce):
                raise Reject("POP_FAILED", "replayed nonce")
            principal = claims["delegator"]["principal"]
            if not self.store.allow_rate(f"agent:{who}:{req.tool}", AGENT_CALLS_PER_MINUTE, 60, now):
                raise Reject("RATE_LIMITED", "too many calls from this agent for this tool")
            if not self.store.allow_rate(f"mandate:{claims['root']}", MANDATE_CALLS_PER_MINUTE, 60, now):
                raise Reject("RATE_LIMITED", "too many calls under this mandate")
            if not self.store.allow_rate(f"principal:{principal}", PRINCIPAL_CALLS_PER_MINUTE, 60, now):
                raise Reject("RATE_LIMITED", "too many calls under this person's authority")

            if req.server == OWN_SERVER:
                if req.tool != "held" or not isinstance(req.arguments.get("id"), str):
                    raise Reject("OUT_OF_SCOPE", "the gateway's own server has one tool: held(id)")
                return Decision(
                    "ALLOW", "HELD_STATUS", agent_id=claims["agent_id"], claims=claims, arguments=req.arguments, **base
                )
            decision, code, detail, arguments = self.check_scope(req, claims)
            return Decision(
                decision, code, agent_id=claims["agent_id"], detail=detail, claims=claims, arguments=arguments, **base
            )
        except Reject as r:
            return Decision("DENY", r.code, agent_id=None, detail=r.detail, claims=claims or r.claims, **base)
        except Exception:
            # fail closed: everything in a request is the caller's to choose, so what the checks cannot
            # handle is refused, never a 500. Logged, because it may also be a bug in the checks.
            log.exception("refused a request that could not be decided")
            return Decision("DENY", "MALFORMED_REQUEST", agent_id=None, claims=claims, **base)
