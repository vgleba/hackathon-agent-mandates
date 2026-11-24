"""Who is accredited to issue mandates?

The gateway asks one question: registry.issuer_key(iss_url, kid) -> Ed25519PublicKey | None.
The template answers it from a plain JSON file {"issuers": {iss: {kid: jwk}}} that lives
next to the gateway. Teams can swap in a signed list, a federation chain, or an HTTP lookup.
"""
from __future__ import annotations

from dataclasses import dataclass

from .common import jwk_to_pub


@dataclass
class TrustedList:
    doc: dict

    @property
    def audience(self) -> str:
        audience = self.doc.get("gateway_audience")
        if not isinstance(audience, str) or not audience:
            raise ValueError("trusted list has no gateway audience")
        return audience

    def issuer_key(self, iss: str, kid: str):
        jwk = self.doc["issuers"].get(iss, {}).get(kid)
        return jwk_to_pub(jwk) if jwk else None
