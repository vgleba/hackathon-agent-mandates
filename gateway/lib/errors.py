"""The one way a check says no."""
from __future__ import annotations


class Reject(Exception):
    """`claims` is set once the issuer's signature has checked out, so that a refusal can be tied to a person."""

    def __init__(self, code: str, detail: str = "", claims: dict | None = None):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.claims = code, detail, claims
