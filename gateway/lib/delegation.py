"""Access handed on narrower, and never wider (question 7).

A helper's mandate is signed by its parent agent and has the parent's whole mandate inside it. The parent is checked
again on every call, so taking back the parent stops every helper. Two separate things keep a helper inside its
parent: its mandate must be narrower, and every call it makes must also pass the parent's own scope.

The person opts in when they grant the parent, by setting aside revocation numbers for helpers. A helper must use one
of those, so any helper can also be stopped alone.
"""
from __future__ import annotations

import jwt

from .common import MAX_MANDATE, canonical, jwk_thumbprint, jwk_to_pub, pub_to_pem
from .errors import Reject

CHILD_TYP = "mandate-child+jwt"
# everything else comes from the parent: person, purpose, clearance, budget
MAY_SET = {"parent", "scope", "deny", "exp", "cnf", "jti", "helper_idx"}
NEEDED = ["parent", "scope", "exp", "cnf", "jti", "helper_idx"]


def is_child(token: str) -> bool:
    return jwt.get_unverified_header(token).get("typ") == CHILD_TYP


def _same(a, b) -> bool:
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return type(a) is type(b) and canonical(a) == canonical(b)
    return str(a) == str(b)


def narrower(child: dict, parent: dict) -> bool:
    """One helper entry against one parent entry: same server, no new tool, every limit kept, no value added."""
    limits, kept = parent.get("constraints", {}), child.get("constraints", {})
    return (
        set(child) <= {"server", "tools", "constraints"}
        and child["server"] == parent["server"]
        and isinstance(child["tools"], list)
        and set(child["tools"]) <= set(parent["tools"])
        and isinstance(kept, dict)
        and all(isinstance(values, list) for values in kept.values())
        and all(k in kept and all(any(_same(v, p) for p in allowed) for v in kept[k]) for k, allowed in limits.items())
    )


def verify_child(token: str, verify_root, helper_revoked, now: float) -> dict:
    """Returns the claims the helper acts under at `now`, the decision's one reading of the clock, or raises Reject."""
    if len(token) > MAX_MANDATE:
        raise Reject("WRONG_TOKEN_TYPE", "too long to be a mandate")
    parent_token = jwt.decode(token, options={"verify_signature": False}).get("parent")
    if not isinstance(parent_token, str):
        raise Reject("WRONG_TOKEN_TYPE", "no parent mandate")
    if is_child(parent_token):
        raise Reject("DELEGATION_NOT_ALLOWED", "a helper cannot have helpers")
    parent = verify_root(parent_token, now)  # expiry and revocation again, on every call

    numbers = parent.get("helpers")
    if type(parent.get("may_delegate")) is not int or parent["may_delegate"] < 1:
        raise Reject("DELEGATION_NOT_ALLOWED", "this access may not be handed on", parent)
    if not isinstance(numbers, list) or not numbers:
        raise Reject("DELEGATION_NOT_ALLOWED", "no helpers were set aside", parent)

    try:  # only the parent agent's own key can make a helper
        child = jwt.decode(token, pub_to_pem(jwk_to_pub(parent["cnf"]["jwk"])), algorithms=["EdDSA"],
                           options={"verify_exp": False, "verify_nbf": False, "verify_iat": False,
                                    "verify_aud": False, "verify_iss": False, "require": NEEDED})
    except jwt.PyJWTError as e:
        raise Reject("CHILD_SIG_INVALID", "not made by the parent's key", parent) from e

    if extra := set(child) - MAY_SET:
        raise Reject("CHILD_WIDER", f"a helper cannot set {sorted(extra)}", parent)
    scope, deny = child["scope"], child.get("deny", [])
    if not isinstance(scope, list) or not scope or not all(isinstance(e, dict) for e in scope):
        raise Reject("CHILD_WIDER", "a helper needs a list of what it may do", parent)
    if not all(any(narrower(e, p) for p in parent["scope"]) for e in scope):
        raise Reject("CHILD_WIDER", "asks for more than its parent has", parent)
    if not isinstance(deny, list) or not all(isinstance(d, str) for d in deny):
        raise Reject("CHILD_WIDER", "deny must be a list", parent)
    if type(child["exp"]) is not int or child["exp"] > parent["exp"]:
        raise Reject("CHILD_WIDER", "a helper cannot outlive its parent", parent)
    if now >= child["exp"]:  # dead from its expiry second, as a root mandate is
        raise Reject("EXPIRED", str(child["jti"]), parent)
    number = child["helper_idx"]
    if type(number) is not int or number not in numbers:
        raise Reject("DELEGATION_NOT_ALLOWED", "not one of the helpers that were set aside", parent)
    if helper_revoked(parent, number, now):
        raise Reject("REVOKED", str(child["jti"]), parent)

    # start from the parent, so that nothing but what is named here can differ
    return {**parent, "exp": child["exp"], "cnf": child["cnf"], "jti": str(child["jti"])[:100], "scope": scope,
            "agent_id": jwk_thumbprint(child["cnf"]["jwk"]), "deny": [*parent["deny"], *deny], "may_delegate": 0,
            "root": parent["jti"], "scopes": [scope, parent["scope"]]}
