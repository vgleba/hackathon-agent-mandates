from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import pytest

from attack_lab.config import ConfigError, load_config
from gateway.lib.common import b64u, generate_keypair, priv_to_pem, pub_to_jwk

if TYPE_CHECKING:
    from pathlib import Path


def token_for(public_key) -> str:
    header = b64u(json.dumps({"alg": "EdDSA", "typ": "mandate+jwt"}).encode())
    claims = {
        "iss": "https://example.test",
        "jti": "test",
        "exp": int(time.time()) + 3600,
        "cnf": {"jwk": pub_to_jwk(public_key)},
        "scope": [{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}],
        "deny": [],
    }
    payload = b64u(json.dumps(claims).encode())
    return f"{header}.{payload}.signature"


def write_config(tmp_path: Path, *, authorized: bool = True, token_public_key=None) -> Path:
    private_key, public_key = generate_keypair()
    (tmp_path / "attack.pem").write_bytes(priv_to_pem(private_key))
    token_public_key = token_public_key or public_key
    (tmp_path / "default.jwt").write_text(token_for(token_public_key), encoding="utf-8")
    config = {
        "agent_key": "attack.pem",
        "targets": [
            {
                "id": "team-a",
                "name": "Team A",
                "gateway_url": "https://gateway.example/tools/call",
                "authorized": authorized,
                "mandates": {"default": "default.jwt"},
            }
        ],
    }
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def test_load_config_checks_authorization_and_normalizes_endpoint(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path))

    assert config.targets[0].gateway_url == "https://gateway.example"
    assert config.targets[0].mandates["default"].claims["jti"] == "test"


def test_load_config_requires_explicit_authorization(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="authorized"):
        load_config(write_config(tmp_path, authorized=False))


def test_load_config_rejects_mandate_for_another_key(tmp_path: Path) -> None:
    _, other_public_key = generate_keypair()

    with pytest.raises(ConfigError, match="was not issued to agent_key"):
        load_config(write_config(tmp_path, token_public_key=other_public_key))
