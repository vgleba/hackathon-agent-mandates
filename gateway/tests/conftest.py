"""One gateway on throwaway state, with the real endpoint and the real data tools in-process."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway.lib.common import generate_keypair, priv_from_pem
from mcp_server.api.routes_mcp import mcp

JSMITH = "officer:jsmith"
CENSUS = "personal_data_school_census"
TERM = {"academic_year": ["2023/24"], "term": ["SPR"]}


def entry(*tools, **constraints):
    return {"server": "pupil-data", "tools": list(tools), "constraints": constraints}


class World:
    def __init__(self, state, client):
        self.state, self.client = state, client
        self.key = cli.load_or_create_key(state / "agent.pem")

    def issue(self, *scope, key=None, principal=JSMITH, ttl=600, deny=(), reserve=0, **claims):
        """Returns (mandate, revocation index). `reserve` sets aside helpers. Extra claims go in as they are."""
        return cli.issue_mandate(
            self.state,
            (key or self.key).public_key(),
            scope=list(scope),
            deny=list(deny),
            ttl=ttl,
            purpose="test",
            principal=principal,
            org="test",
            extra=claims or None,
            helpers=reserve,
        )

    def mandate(self, *scope, **kw):
        return self.issue(*scope, **kw)[0]

    def sign(self, tool, mandate, *, key=None, server="pupil-data", **arguments):
        return cli.sign_request(key or self.key, server=server, tool=tool, arguments=arguments, mandate=mandate)

    def post(self, body):
        r = self.client.post("/tools/call", json=body)
        return r.status_code, r.json()

    def call(self, tool, mandate, **kw):
        return self.post(self.sign(tool, mandate, **kw))

    def reason(self, tool, mandate, **kw):
        return self.call(tool, mandate, **kw)[1]["decision"]["reason_code"]

    def entries(self):
        path = self.state / "record.jsonl"
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []

    def people(self):
        return json.loads((self.state / "people.json").read_text())

    def person(self, principal, **fields):
        everyone = self.people()
        everyone[principal] = {**everyone.get(principal, {}), **fields}
        (self.state / "people.json").write_text(json.dumps(everyone))

    @staticmethod
    def new_key():
        return generate_keypair()[0]


@pytest.fixture
def state(tmp_path):
    cli.main(["--state", str(tmp_path / "state"), "init"])
    return tmp_path / "state"


@pytest.fixture
def world(state, monkeypatch):
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)
    monkeypatch.delenv("GATEWAY_DEMO", raising=False)
    with TestClient(main.app, raise_server_exceptions=False) as client:
        yield World(state, client)


@pytest.fixture
def issuer_key(state):
    return priv_from_pem((state / "issuer_key.pem").read_bytes())


@pytest.fixture
def now():
    return int(time.time())
