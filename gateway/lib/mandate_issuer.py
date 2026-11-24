"""Issue signed mandates.

A mandate is an EdDSA-signed JWT, header {alg: EdDSA, typ: mandate+jwt, kid}.
Claims are documented in mandate.schema.json.
"""
from __future__ import annotations

import time
import uuid

import jwt

from .common import jwk_thumbprint, priv_to_pem, pub_to_jwk

VCT = "urn:hack:mandate:v2"
MAX_TTL = 7 * 86400


class MandateIssuer:
    def __init__(self, issuer_url: str, kid: str, priv, status_issuer):
        self.issuer_url = issuer_url
        self.kid = kid
        self.priv = priv
        self.status_issuer = status_issuer

    def issue(
        self,
        *,
        delegator: dict,
        delegate_pub,
        purpose: str,
        scope: list[dict],
        deny: list[str],
        audience: str,
        principal_epoch: int,
        ttl: int = 7200,
        extra: dict | None = None,
    ) -> str:
        """`extra` adds top-level claims of your own. The gateway ignores them until gateway_verify reads them."""
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
            raise ValueError(f"mandate ttl must be a whole number from 1 to {MAX_TTL}")
        if not isinstance(audience, str) or not audience:
            raise ValueError("mandate audience is required")
        if type(principal_epoch) is not int or principal_epoch < 1:
            raise ValueError("principal authorization epoch is required")
        now = int(time.time())
        jwk = pub_to_jwk(delegate_pub)
        idx = self.status_issuer.allocate()
        claims = {
            "iss": self.issuer_url,
            "jti": f"urn:uuid:{uuid.uuid4()}",
            "iat": now, "nbf": now, "exp": now + ttl,
            "vct": VCT,
            "aud": audience,
            "delegator": delegator,
            "principal_epoch": principal_epoch,
            "cnf": {"jwk": jwk},
            "agent_id": jwk_thumbprint(jwk),
            "purpose": purpose,
            "scope": scope,
            "deny": deny,
            "status": {"status_list": {"uri": self.status_issuer.list_uri, "idx": idx}},
        }
        extra = extra or {}
        if clash := sorted(extra.keys() & claims.keys()):
            raise ValueError(f"extra claims would replace built-in ones: {clash}")
        return jwt.encode({**claims, **extra}, priv_to_pem(self.priv), algorithm="EdDSA",
                          headers={"typ": "mandate+jwt", "kid": self.kid})
