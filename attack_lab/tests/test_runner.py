from __future__ import annotations

import time
from typing import TYPE_CHECKING
from unittest.mock import patch

from attack_lab.config import Expectations, LabConfig, MandateConfig, TargetConfig
from attack_lab.runner import run_lab
from attack_lab.wire import WireResponse
from gateway.lib.common import generate_keypair, priv_to_pem, pub_to_jwk

if TYPE_CHECKING:
    from pathlib import Path


def test_runner_records_request_response_and_score(tmp_path: Path) -> None:
    private_key, public_key = generate_keypair()
    key_path = tmp_path / "attack.pem"
    key_path.write_bytes(priv_to_pem(private_key))
    claims = {
        "exp": int(time.time()) + 3600,
        "cnf": {"jwk": pub_to_jwk(public_key)},
        "scope": [
            {
                "server": "pupil-data",
                "tools": ["pupil"],
                "constraints": {"pupil_id": ["P0011"], "urn": ["SCH04"]},
            }
        ],
        "deny": [],
    }
    mandate = MandateConfig(
        "default",
        "a.b.c",
        "inline",
        "",
        Expectations(deny=frozenset({"pupil_flag_pupil_other_school"})),
        False,
        claims,
    )
    target = TargetConfig("team-a", "Team A", "https://gateway.example", {"default": mandate})
    config = LabConfig(tmp_path / "config.json", key_path, (target,), 5, 0)
    response = WireResponse(
        200,
        {"content-type": "application/json"},
        {
            "decision": {"decision": "ALLOW", "reason_code": "IN_SCOPE"},
            "result": {"Psuedo ID": "P0011", "URN": "SCH04", "Ethnicity": "ASIA"},
        },
        "",
        4,
        False,
        None,
    )

    with patch("attack_lab.runner.post_gateway", return_value=response):
        report = run_lab(config, only_probes={"pupil_flag_pupil_other_school"})

    assert report["summary"]["potential_score"] == 40
    assert report["targets"][0]["observations"][0]["request"]["sig"]
    assert report["targets"][0]["findings"][0]["points"] == 40
