"""Routes behind the frontend demo page, one per step.

The demo keeps the agent's private key on the gateway, so the browser needs no crypto.
shortcut: a real agent holds its own key; this is for teaching only, never deploy the demo router publicly.
"""

import json
import os

import jwt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from gateway.cli import issue_mandate, load_or_create_key, revoke_mandate, sign_request
from gateway.lib.gateway_verify import Request


def require_demo() -> None:
    """These routes sign with the issuer's and the agent's keys for whoever asks, so they are off by default."""
    if os.environ.get("GATEWAY_DEMO") != "1":
        raise HTTPException(404, "Not Found")


router = APIRouter(prefix="/demo", tags=["demo"], dependencies=[Depends(require_demo)])


def _gw():
    from gateway import main  # noqa: PLC0415  (main includes this router, so import lazily)

    return main


class MandateBody(BaseModel):
    urn: str = "SCH01"
    tools: list[str] = ["search", "get", "greet"]
    deny: list[str] = ["*.write", "pii.*"]
    ttl: int = 3600


class RevokeBody(BaseModel):
    idx: int


class CallDemoBody(BaseModel):
    tool: str
    arguments: dict = {}


def _unverified(token: str) -> dict:
    return {
        "header": jwt.get_unverified_header(token),
        "claims": jwt.decode(token, options={"verify_signature": False}),
    }


@router.get("/issuer")
def demo_issuer():
    """The issuer's key, and how it differs from a password-style token. Shows the public half only."""
    state_dir = _gw().state["dir"]
    meta = json.loads((state_dir / "status_list.json").read_text())
    trusted = json.loads((state_dir / "trusted_list.json").read_text())
    return {
        "explanation": (
            "`make hack` gave the issuer a key pair. The private half signs every mandate and never leaves the "
            "issuer. The public half sits on the gateway's Trusted List, so the gateway can tell a real mandate "
            "from a forged one. Guard the private half above all else: anyone who holds it can write a mandate "
            "for anything, and this gateway will accept it. It is never sent with a request, and the agent never "
            "sees it."
        ),
        "issuer": {
            "iss": meta["issuer"],
            "kid": meta["kid"],
            "public_jwk": trusted["issuers"][meta["issuer"]][meta["kid"]],
            "private_key": "gateway/state/issuer_key.pem (never shown, never sent)",  # pragma: allowlist secret
        },
        "compared_with_a_bearer_token": {
            "bearer token": "Sent with every call. Anyone who copies it gets all your access until it expires.",
            "issuer key": "Never sent. It signs mandates. Anyone who copies it can grant any access at all.",
            "mandate": "Sent with every call. A copy is no use without the agent's own key, and it only "
            "covers what it allows, until it expires or is cancelled.",
        },
    }


@router.post("/mandate")
def demo_mandate(body: MandateBody):
    """Write a mandate: a signed note that hands part of a person's access to one agent."""
    state_dir = _gw().state["dir"]
    agent_priv = load_or_create_key(state_dir / "demo_agent.pem")
    token, idx = issue_mandate(
        state_dir,
        agent_priv.public_key(),
        scope=[{"server": "pupil-data", "tools": body.tools, "constraints": {"urn": [body.urn]}}],
        deny=body.deny,
        ttl=body.ttl,
        purpose=f"Pupil-data lookups for school {body.urn}",
        principal="officer:jsmith",
        org=f"school:{body.urn}",
    )
    (state_dir / "demo_mandate.jwt").write_text(token)
    return {
        "explanation": (
            "The issuer signed this mandate. It names the agent's key (`cnf`), so no other agent can use it. "
            "It says what the agent may do (`scope`), what it must never do (`deny`), when it runs out (`exp`), "
            "and where to check whether it has been cancelled (`status`)."
        ),
        "mandate": token,
        "status_idx": idx,
        **_unverified(token),
    }


def _trust_view() -> dict:
    state_dir = _gw().state["dir"]
    trusted = json.loads((state_dir / "trusted_list.json").read_text())
    meta = json.loads((state_dir / "status_list.json").read_text())
    status_jwt = (state_dir / "status_list.jwt").read_text().strip()
    status_claims = jwt.decode(status_jwt, options={"verify_signature": False})
    import zlib  # noqa: PLC0415

    from gateway.lib.common import b64u_decode  # noqa: PLC0415

    bits = zlib.decompress(b64u_decode(status_claims["status_list"]["lst"]))
    revoked = [i for i in range(meta["next"]) if bits[i // 8] >> (i % 8) & 1]
    return {
        "explanation": (
            "The gateway only accepts mandates from issuers on its Trusted List. Each mandate gets one bit on a "
            "signed status list, which the gateway re-reads on every call. Flip a mandate's bit and it stops "
            "working at once, without waiting for it to expire."
        ),
        "trusted_list": trusted,
        "status_list": {"uri": meta["uri"], "issued": meta["next"], "revoked": revoked, "claims": status_claims},
    }


@router.get("/trust")
def demo_trust():
    """Who the gateway trusts, and which mandates are cancelled."""
    return _trust_view()


@router.post("/revoke")
def demo_revoke(body: RevokeBody):
    """Cancel a mandate by the number it was given when issued."""
    revoke_mandate(_gw().state["dir"], body.idx)
    return _trust_view()


@router.post("/call")
async def demo_call(body: CallDemoBody):
    """Sign a call with the agent's key and send it through the real gateway checks."""
    gw = _gw()
    state_dir = gw.state["dir"]
    if not (state_dir / "demo_mandate.jwt").exists():
        raise HTTPException(409, "issue a mandate first (step 1)")
    signed = sign_request(
        load_or_create_key(state_dir / "demo_agent.pem"),
        server="pupil-data",
        tool=body.tool,
        arguments=body.arguments,
        mandate=(state_dir / "demo_mandate.jwt").read_text().strip(),
    )
    status, payload = await gw.handle(gw.CallBody(**signed), "demo page")
    return {
        "explanation": (
            "The agent signs each call with its own key: The gateway checks: the mandate is genuine -> from a trusted "
            "issuer -> in date -> not cancelled. The call came from the agent the mandate names and is not a "
            "replay. The call avoids what the mandate forbids, fits what it allows, and is not a write or draft "
            "that needs a person to approve it first."
        ),
        "signing_input": Request(**signed).signing_input().decode(),
        "request": signed,
        "status": status,
        "response": payload,
    }
