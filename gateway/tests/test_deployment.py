"""What the repo hands over for deployment: the compose file, and the gateway image that .dockerignore shapes.

The organisers deploy with settings the team cannot see, so none of this may rely on a setting being right (ADR-0001):
the image has no demo routes to switch on, no private key but the gateway's own, and the compose file a deploy reads
starts nothing that signs for whoever asks.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from gateway import cli, main
from mcp_server.api.routes_mcp import mcp

ROOT = Path(__file__).resolve().parents[2]
# what the running gateway reads from its state folder, and the placeholder that keeps the folder in the image
IMAGE_STATE = {
    "trusted_list.json",
    "status_list.json",
    "status_list.jwt",
    "people.json",
    "people.jwt",
    "gateway_key.pem",
    ".gitkeep",
}
KEPT_OUT = [
    "issuer_key.pem",
    "agent.pem",
    "demo_agent.pem",
    "demo_mandate.jwt",
    "person_officer_jsmith.pem",
    "mandate.jwt",
    "gateway.db",
    "record.jsonl",
    "gateway.pub",
    "some_new_secret.pem",
]
AUTO_LOADED = {
    "docker-compose.override.yaml",
    "docker-compose.override.yml",
    "compose.override.yaml",
    "compose.override.yml",
}


def compose(name: str) -> dict:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def dockerignore() -> list[str]:
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def _matches(path: str, pattern: str) -> bool:
    """Docker's matching: `*` and `?` stay within one folder, `**` crosses folders."""
    regex = re.escape(pattern).replace(r"\*\*", "\0").replace(r"\*", "[^/]*").replace(r"\?", "[^/]")
    regex = regex.replace("\0", ".*")
    return re.fullmatch(regex, path) is not None


def ignored(path: str, patterns: list[str]) -> bool:
    """As `docker build` decides: the last pattern that matches the path or a folder above it wins, `!` keeps it."""
    parts, result = path.split("/"), False
    for raw in patterns:
        keep = raw.startswith("!")
        pattern = raw.removeprefix("!").strip().strip("/")
        if any(_matches("/".join(parts[:i]), pattern) for i in range(1, len(parts) + 1)):
            result = not keep
    return result


def signed_search(state: Path) -> dict:
    """A call the default mandate allows, issued from the full state, which holds the issuer key."""
    key = cli.load_or_create_key(state / "agent.pem")
    mandate, _ = cli.issue_mandate(
        state,
        key.public_key(),
        scope=[{"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}],
        deny=[],
        ttl=600,
        purpose="test",
        principal="officer:jsmith",
        org="test",
        extra=None,
        helpers=0,
    )
    arguments = {"query": "P0004", "urn": "SCH01"}
    return cli.sign_request(key, server="pupil-data", tool="search", arguments=arguments, mandate=mandate)


# ------------------------------------------------------------ the compose files


def test_the_committed_compose_file_starts_only_what_is_deployed():
    assert set(compose("docker-compose.yaml")["services"]) == {"backend", "gateway"}
    assert "GATEWAY_DEMO" not in (ROOT / "docker-compose.yaml").read_text(encoding="utf-8")


def test_the_demo_overlay_switches_the_walkthrough_on():
    services = compose("docker-compose.demo.yaml")["services"]
    assert "frontend" in services
    assert "GATEWAY_DEMO=1" in services["gateway"]["environment"]
    assert any(v.startswith("./gateway/demo.py:/app/gateway/demo.py") for v in services["gateway"]["volumes"])


def test_no_compose_file_is_loaded_without_being_named():
    assert sorted(p.name for p in ROOT.iterdir() if p.name in AUTO_LOADED) == []


# ------------------------------------------------------------ what the image is built from


def test_the_image_leaves_out_the_demo_and_every_other_secret():
    patterns = dockerignore()
    assert ignored("gateway/demo.py", patterns)
    for name in KEPT_OUT:
        assert ignored(f"gateway/state/{name}", patterns), name
    for name in IMAGE_STATE:
        assert not ignored(f"gateway/state/{name}", patterns), name
    for path in ("gateway/main.py", "gateway/lib/gateway_verify.py", "gateway/cli.py", "pyproject.toml", "uv.lock"):
        assert not ignored(path, patterns), path


def test_without_the_demo_file_the_gateway_works_and_has_no_demo(state):
    """The production image: gateway/demo.py is not there, and GATEWAY_DEMO=1 changes nothing."""
    out = subprocess.run(  # noqa: S603  (this interpreter, a module of ours, a path and JSON we made)
        [
            sys.executable,
            "-m",
            "gateway.tests.image_probe",
            str(state),
            json.dumps(signed_search(state)),
            str(state / "agent.pem"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert out.returncode == 0, out.stderr[-3000:]
    seen = json.loads(out.stdout.strip().splitlines()[-1])
    assert seen["demo"] == dict.fromkeys(seen["demo"], 404)
    assert len(seen["demo"]) == 5  # issuer, trust, mandate, revoke, call
    assert seen["call"] == [200, "ALLOW"]
    assert not (state / "demo_mandate.jwt").exists()


def test_the_gateway_needs_only_the_state_the_image_carries(state, tmp_path, monkeypatch):
    call = signed_search(state)
    image_state = tmp_path / "image_state"
    image_state.mkdir()
    for name in IMAGE_STATE:
        if (state / name).exists():
            shutil.copy2(state / name, image_state / name)
    assert not (image_state / "issuer_key.pem").exists()

    monkeypatch.setattr(main, "STATE_DIR", image_state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)
    monkeypatch.delenv("GATEWAY_DEMO", raising=False)
    with TestClient(main.app, raise_server_exceptions=False) as client:
        reply = client.post("/tools/call", json=call)
    assert (reply.status_code, reply.json()["decision"]["decision"]) == (200, "ALLOW")


# ------------------------------------------------------------ private keys


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="Windows does not keep these mode bits")
def test_private_keys_are_written_for_their_owner_only(tmp_path):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    for name in ("issuer_key.pem", "gateway_key.pem", "person_officer_jsmith.pem"):
        assert mode(state / name) == 0o600, name

    cli.load_or_create_key(tmp_path / "agent.pem")
    assert mode(tmp_path / "agent.pem") == 0o600

    (state / "issuer_key.pem").chmod(0o644)  # a key from before this change, written again
    cli.main(["--state", str(state), "init", "--force"])
    assert mode(state / "issuer_key.pem") == 0o600
