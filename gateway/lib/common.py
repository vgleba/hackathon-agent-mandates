"""Shared helpers: canonical JSON, hashing, Ed25519 keys, JWK thumbprints.

Everything that two teams must agree on byte-for-byte lives here.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_MANDATE = 32_000


# ---------------------------------------------------------------- encoding

def canonical(obj: Any) -> bytes:
    """Deterministic JSON. If this changes, every hash in the system changes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- keys

def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def priv_to_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def pub_to_pem(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pub_from_pem(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    assert isinstance(key, Ed25519PublicKey)
    return key


def priv_from_pem(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)
    return key


def pub_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


# ---------------------------------------------------------------- JWK

def pub_to_jwk(pub: Ed25519PublicKey) -> dict:
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(pub_raw(pub))}


def jwk_to_pub(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("only OKP/Ed25519 JWKs supported")
    return Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint: sha256 over the required members only, sorted."""
    required = {k: jwk[k] for k in ("crv", "kty", "x")}
    return b64u(hashlib.sha256(canonical(required)).digest())


# ---------------------------------------------------------------- detached signatures

def sign_bytes(priv: Ed25519PrivateKey, data: bytes) -> str:
    return b64u(priv.sign(data))


def verify_bytes(pub: Ed25519PublicKey, data: bytes, sig_b64u: str) -> bool:
    try:
        pub.verify(b64u_decode(sig_b64u), data)
        return True
    except Exception:
        return False
