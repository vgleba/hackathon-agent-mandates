"""Revocation via Token Status List (draft-ietf-oauth-status-list, RFC Ed queue).

A Status List is a bitstring, 1 bit per referenced token (we use bits=1:
0 = VALID, 1 = INVALID/revoked), zlib-compressed and base64url'd, published
inside a signed JWT (typ: statuslist+jwt):

    { "iss": ..., "sub": <list uri>, "iat": ..., "ttl": <seconds the list stays usable>,
      "status_list": { "bits": 1, "lst": "<b64url(zlib(bytes))>" } }

Each mandate carries status.status_list.{uri, idx}. The gateway fetches
the list for uri, verifies it against the issuer key, and reads bit idx.

In the hack, "fetch" is a dict lookup; teams can put it behind HTTP.
"""
from __future__ import annotations

import time
import zlib

import jwt

from .common import b64u, b64u_decode, priv_to_pem, pub_to_pem


class StatusListIssuer:
    def __init__(self, issuer_url: str, list_uri: str, priv, size: int = 8192):
        self.issuer_url = issuer_url
        self.list_uri = list_uri
        self.priv = priv
        self.bits = bytearray((size + 7) // 8)
        self._next = 0

    def allocate(self) -> int:
        idx, self._next = self._next, self._next + 1
        return idx

    def revoke(self, idx: int) -> None:
        self.bits[idx // 8] |= 1 << (idx % 8)

    def publish(self, ttl: int) -> str:
        claims = {
            "iss": self.issuer_url,
            "sub": self.list_uri,
            "iat": int(time.time()),
            "ttl": ttl,
            "status_list": {"bits": 1, "lst": b64u(zlib.compress(bytes(self.bits), 9))},
        }
        return jwt.encode(claims, priv_to_pem(self.priv), algorithm="EdDSA",
                          headers={"typ": "statuslist+jwt"})


def is_revoked(status_list_jwt: str, idx: int, issuer_pub, expected_uri: str) -> bool:
    """Returns True if bit idx is set. Raises ValueError on a malformed, forged or stale list (fail closed).

    Only ValueError, whatever went wrong inside: the gateway turns it into STATUS_UNAVAILABLE and keeps the mandate's
    person on the refusal, where any other exception would be an unattributed MALFORMED_REQUEST.
    """
    try:
        return _read_bit(status_list_jwt, idx, issuer_pub, expected_uri)
    except ValueError:
        raise
    except (jwt.PyJWTError, zlib.error, KeyError, TypeError, AttributeError) as e:
        raise ValueError(f"unreadable status list: {type(e).__name__}") from e


def _read_bit(status_list_jwt: str, idx: int, issuer_pub, expected_uri: str) -> bool:
    hdr = jwt.get_unverified_header(status_list_jwt)
    if hdr.get("typ") != "statuslist+jwt":
        raise ValueError("not a status list token")
    claims = jwt.decode(status_list_jwt, pub_to_pem(issuer_pub), algorithms=["EdDSA"])
    if claims["sub"] != expected_uri:
        raise ValueError("status list uri mismatch")
    if claims["iat"] + claims["ttl"] < time.time():
        raise ValueError("status list stale")
    sl = claims["status_list"]
    if sl["bits"] != 1:
        raise ValueError("only bits=1 supported in this sketch")
    raw = zlib.decompress(b64u_decode(sl["lst"]))
    if idx // 8 >= len(raw):
        raise ValueError("idx out of range")
    return bool(raw[idx // 8] >> (idx % 8) & 1)
