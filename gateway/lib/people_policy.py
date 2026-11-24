"""Signed, monotonic policy for the people whose authority mandates depend on."""

from __future__ import annotations

import time
from dataclasses import dataclass

import jwt

from .common import priv_to_pem, pub_to_pem, sha256_hex

PEOPLE_TYP = "people+jwt"
POLICY_CLOCK_SKEW = 30
POLICY_TTL = 7 * 86400


@dataclass(frozen=True)
class PeopleSnapshot:
    people: dict
    issuer: str
    sequence: int
    digest: str


def issue_people_policy(people: dict, *, issuer: str, kid: str, priv, sequence: int) -> str:
    if not isinstance(people, dict) or not people:
        raise ValueError("people policy must be a non-empty object")
    if type(sequence) is not int or sequence < 1:
        raise ValueError("people policy sequence must be a positive whole number")
    now = int(time.time())
    claims = {"iss": issuer, "iat": now, "exp": now + POLICY_TTL, "ttl": POLICY_TTL, "seq": sequence, "people": people}
    return jwt.encode(
        claims,
        priv_to_pem(priv),
        algorithm="EdDSA",
        headers={"typ": PEOPLE_TYP, "kid": kid},
    )


def validate_people_policy(
    token: str,
    registry,
    now: float | None = None,
    *,
    expected_issuer: str | None = None,
    expected_kid: str | None = None,
) -> PeopleSnapshot:
    """Verify a people policy and return the values needed for rollback protection."""
    now = time.time() if now is None else now
    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ") != PEOPLE_TYP:
            raise ValueError("not a people policy token")
        unverified = jwt.decode(token, options={"verify_signature": False})
        issuer, kid = unverified["iss"], header.get("kid", "")
        if not isinstance(issuer, str) or not isinstance(kid, str):
            raise ValueError("people policy issuer is invalid")
        if expected_issuer is not None and issuer != expected_issuer:
            raise ValueError("people policy is from the wrong issuer")
        if expected_kid is not None and kid != expected_kid:
            raise ValueError("people policy is from the wrong signing key")
        pub = registry.issuer_key(issuer, kid)
        if pub is None:
            raise ValueError("people policy issuer is not trusted")
        claims = jwt.decode(
            token,
            pub_to_pem(pub),
            algorithms=["EdDSA"],
            options={
                "verify_exp": False,
                "verify_iat": False,
                "require": ["iss", "iat", "exp", "ttl", "seq", "people"],
            },
        )
        iat, exp, ttl, sequence, people = (
            claims["iat"],
            claims["exp"],
            claims["ttl"],
            claims["seq"],
            claims["people"],
        )
        if (
            type(iat) is not int
            or type(exp) is not int
            or type(ttl) is not int
            or ttl <= 0
            or exp <= iat
            or iat > now + POLICY_CLOCK_SKEW
            or now >= min(exp, iat + ttl)
        ):
            raise ValueError("people policy time is invalid")
        if type(sequence) is not int or sequence < 1:
            raise ValueError("people policy sequence is invalid")
        if not isinstance(people, dict) or not people:
            raise ValueError("people policy is empty")
        if not all(isinstance(principal, str) and isinstance(person, dict) for principal, person in people.items()):
            raise ValueError("people policy entries are invalid")
        return PeopleSnapshot(people, issuer, sequence, sha256_hex(token.encode()))
    except ValueError:
        raise
    except (jwt.PyJWTError, KeyError, TypeError, AttributeError) as e:
        raise ValueError(f"unreadable people policy: {type(e).__name__}") from e
