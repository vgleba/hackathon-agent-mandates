from __future__ import annotations

import json

from attack_lab.config import decode_jwt_unverified
from attack_lab.probes import PROBES_BY_ID
from attack_lab.wire import build_request_bodies, mutate_mandate
from gateway.lib.common import b64u, generate_keypair, pub_to_jwk


def mandate(public_key) -> str:
    header = b64u(json.dumps({"typ": "mandate+jwt", "alg": "EdDSA"}).encode())
    claims = b64u(
        json.dumps(
            {
                "cnf": {"jwk": pub_to_jwk(public_key)},
                "scope": [{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}],
            }
        ).encode()
    )
    return f"{header}.{claims}.issuer-signature"


def test_tampered_mandate_broadens_payload_but_keeps_issuer_signature() -> None:
    _, public_key = generate_keypair()
    original = mandate(public_key)

    tampered = mutate_mandate(original, "tampered_mandate")

    assert tampered.rsplit(".", 1)[1] == "issuer-signature"
    assert "pupil" in decode_jwt_unverified(tampered)["scope"][0]["tools"]


def test_replay_probe_builds_two_identical_signed_bodies() -> None:
    private_key, public_key = generate_keypair()

    bodies = build_request_bodies(PROBES_BY_ID["replayed_signed_request"], mandate(public_key), private_key, now=1000)

    assert len(bodies) == 2
    assert bodies[0] == bodies[1]


def test_stale_probe_signs_the_stale_timestamp() -> None:
    private_key, public_key = generate_keypair()

    bodies = build_request_bodies(PROBES_BY_ID["stale_signed_request"], mandate(public_key), private_key, now=5000)

    assert bodies[0]["ts"] == 1400
    assert bodies[0]["sig"]
