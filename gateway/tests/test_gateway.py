import json

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway import eval as ev
from gateway.lib.common import priv_from_pem
from gateway.lib.gateway_verify import Request, check_request, normalise_path
from mcp_server.api.routes_mcp import mcp


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    cli.main(
        ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(state / "mandate.jwt")]
    )
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)  # in-process upstream, no network
    agent_priv = priv_from_pem((state / "agent.pem").read_bytes())
    mandate = (state / "mandate.jwt").read_text()

    def call(client, tool, body=None, **arguments):
        body = body or cli.sign_request(
            agent_priv, server="pupil-data", tool=tool, arguments=arguments, mandate=mandate
        )
        return client.post("/tools/call", json=body), body

    with TestClient(main.app) as client:
        yield client, call, state


def test_allow_deny_replay_revoke(gw):
    client, call, state = gw

    r, body = call(client, "search", query=ev.PUPIL, urn="SCH01")
    assert r.status_code == 200, r.text
    assert r.json()["decision"]["decision"] == "ALLOW"
    assert {row["URN"] for row in r.json()["result"]} == {"SCH01"}

    # get is limited to the two files with no pupil data, so the names file is refused
    r, _ = call(client, "get", path="synthetic/synthetic_display_names.csv")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "CONSTRAINT_VIOLATED")

    r, _ = call(client, "search", body=body)  # replay of the first signed request
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "POP_FAILED")

    cli.main(["--state", str(state), "revoke", "--idx", "0"])
    r, _ = call(client, "search", query=ev.PUPIL, urn="SCH01")
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "REVOKED")


def test_tampered_mandate_is_denied(gw):
    client, call, state = gw
    mandate = (state / "mandate.jwt").read_text()
    header, payload, sig = mandate.split(".")
    claims = json.loads(cli.b64u_decode(payload))
    claims["scope"][0]["constraints"]["urn"] = ["SCH01", "SCH02"]
    forged = ".".join([header, cli.b64u(json.dumps(claims).encode()), sig])
    body = cli.sign_request(
        priv_from_pem((state / "agent.pem").read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH02"},
        mandate=forged,
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "SIG_INVALID")


def test_demo_walkthrough(gw):
    client, _, _ = gw
    m = client.post("/demo/mandate", json={"urn": "SCH01"}).json()
    assert m["header"]["typ"] == "mandate+jwt"
    assert m["claims"]["scope"][0]["constraints"] == {"urn": ["SCH01"]}

    issuer = client.get("/demo/issuer").json()["issuer"]
    assert (issuer["iss"], issuer["kid"]) == (m["claims"]["iss"], m["header"]["kid"])
    assert "d" not in issuer["public_jwk"]  # the private half never leaves the state dir

    r = client.post("/demo/call", json={"tool": "search", "arguments": {"query": "SPR", "urn": "SCH01"}}).json()
    assert (r["status"], r["response"]["decision"]["decision"]) == (200, "ALLOW")

    t = client.post("/demo/revoke", json={"idx": m["status_idx"]}).json()
    assert t["status_list"]["revoked"] == [m["status_idx"]]
    r = client.post("/demo/call", json={"tool": "search", "arguments": {"query": "SPR", "urn": "SCH01"}}).json()
    assert (r["status"], r["response"]["decision"]["reason_code"]) == (403, "REVOKED")


def test_describe_and_issue_to_public_jwk(gw, tmp_path, capsys):
    client, call, state = gw

    desc = client.get("/describe").json()
    assert [t["name"] for t in desc["servers"]["pupil-data"]] == [
        "search",
        "get",
        "aggregate",
        "classification",
        "roster",
        "pupil",
        "draft",
        "write",
    ]
    ex = desc["signing"]["example"]
    assert Request(**ex["request"]).signing_input().decode() == ex["signing_input"]

    # team runs keygen and sends only the public JWK; issuer never sees the private key
    team_key = tmp_path / "team.pem"
    cli.main(["keygen", "-o", str(team_key)])
    (tmp_path / "team.jwk").write_text(capsys.readouterr().out)
    cli.main(["--state", str(state), "issue", "--agent-key", str(tmp_path / "team.jwk"), "-o", str(tmp_path / "m.jwt")])
    body = cli.sign_request(
        priv_from_pem(team_key.read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH01"},
        mandate=(tmp_path / "m.jwt").read_text(),
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["decision"]) == (200, "ALLOW")


def test_issue_with_claims_of_your_own(gw, tmp_path, capsys):
    client, call, state = gw
    out = tmp_path / "m.jwt"
    issue = ["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(out)]

    cli.main([*issue, "--claims", '{"clearance": 2}'])
    capsys.readouterr()
    cli.main(["decode", str(out)])
    assert json.loads(capsys.readouterr().out)["clearance"] == 2

    # the starter gateway ignores a claim it does not read, so the mandate still works
    body = cli.sign_request(
        priv_from_pem((state / "agent.pem").read_bytes()),
        server="pupil-data",
        tool="search",
        arguments={"query": "SPR", "urn": "SCH01"},
        mandate=out.read_text(),
    )
    r, _ = call(client, "search", body=body)
    assert (r.status_code, r.json()["decision"]["decision"]) == (200, "ALLOW")

    with pytest.raises(ValueError, match="scope"):
        cli.main([*issue, "--claims", '{"scope": []}'])


def test_eval_set_passes(gw, tmp_path):
    client, _, state = gw
    ev.main(["build", "--state", str(state), "-o", str(tmp_path / "pack")])

    def post(body):
        r = client.post("/tools/call", json=body)
        return r.status_code, r.json()

    results = ev.run_cases(tmp_path / "pack", post)
    # questions 0 to 2 came working; 3 to 5 are fixed in check_request, so every case must pass
    assert [line for ok, line in results if not ok] == []
    assert len(results) == len(ev.VALID) + len(ev.INVALID) + len(ev.BUILD)


SCH01_SEARCH = {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}
FILES_GET = {"server": "pupil-data", "tools": ["get"], "constraints": {"path": [ev.SCHOOLS, ev.MANIFEST]}}


def decide(tool, scope, **arguments):
    """check_request on its own: (decision, reason_code), no keys or network."""
    req = Request(server="pupil-data", tool=tool, arguments=arguments, mandate="", nonce="", ts=0, sig="")
    decision, code, _ = check_request(req, scope, deny=["*.write"], step_up_patterns=["*.write", "*.draft"])
    return decision, code


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({"query": "P0004", "urn": "SCH01"}, ("ALLOW", "IN_SCOPE")),
        ({"query": "SPR", "urn": "SCH01", "limit": 100}, ("ALLOW", "IN_SCOPE")),
        ({"query": "", "urn": "SCH01"}, ("DENY", "QUERY_TOO_BROAD")),
        ({"query": "   ", "urn": "SCH01"}, ("DENY", "QUERY_TOO_BROAD")),
        ({"urn": "SCH01"}, ("DENY", "QUERY_TOO_BROAD")),
        ({"query": "SPR", "urn": "SCH01", "limit": 101}, ("DENY", "LIMIT_EXCEEDED")),
        # the server would read each of these as a number, so the gateway must not compare them as anything else
        ({"query": "SPR", "urn": "SCH01", "limit": "1000"}, ("DENY", "LIMIT_INVALID")),
        ({"query": "SPR", "urn": "SCH01", "limit": 1000.0}, ("DENY", "LIMIT_INVALID")),
        ({"query": "SPR", "urn": "SCH01", "limit": True}, ("DENY", "LIMIT_INVALID")),
        ({"query": "SPR", "urn": "SCH01", "limit": 0}, ("DENY", "LIMIT_INVALID")),
        ({"query": "SPR", "urn": "SCH01", "limit": -1}, ("DENY", "LIMIT_INVALID")),
        # the school is still checked before how much
        ({"query": "", "urn": "SCH02"}, ("DENY", "CONSTRAINT_VIOLATED")),
    ],
)
def test_q3_search_volume(arguments, expected):
    assert decide("search", [SCH01_SEARCH], **arguments) == expected


def test_q3_max_rows_in_the_mandate():
    tight = [{**SCH01_SEARCH, "max_rows": 10}]
    assert decide("search", tight, query="SPR", urn="SCH01", limit=10) == ("ALLOW", "IN_SCOPE")
    assert decide("search", tight, query="SPR", urn="SCH01", limit=11) == ("DENY", "LIMIT_EXCEEDED")
    # left out, the server returns up to 100, which is more than this mandate allows
    assert decide("search", tight, query="SPR", urn="SCH01") == ("DENY", "LIMIT_EXCEEDED")
    wide = [{**SCH01_SEARCH, "max_rows": 1000}]
    assert decide("search", wide, query="SPR", urn="SCH01", limit=1000) == ("ALLOW", "IN_SCOPE")
    assert decide("search", wide, query="", urn="SCH01", limit=1000) == ("DENY", "QUERY_TOO_BROAD")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (ev.SCHOOLS, ("ALLOW", "IN_SCOPE")),
        ("./synthetic/synthetic_schools.csv", ("ALLOW", "IN_SCOPE")),
        ("synthetic//synthetic_schools.csv", ("ALLOW", "IN_SCOPE")),
        ("synthetic/./synthetic_schools.csv", ("ALLOW", "IN_SCOPE")),
        ("synthetic/../synthetic/synthetic_schools.csv", ("ALLOW", "IN_SCOPE")),
        ("synthetic/../synthetic/synthetic_display_names.csv", ("DENY", "CONSTRAINT_VIOLATED")),
        ("../synthetic/synthetic_schools.csv", ("DENY", "CONSTRAINT_VIOLATED")),
        ("synthetic/../../data/synthetic/synthetic_schools.csv", ("DENY", "CONSTRAINT_VIOLATED")),
        ("/app/mcp_server/data/synthetic/synthetic_schools.csv", ("DENY", "CONSTRAINT_VIOLATED")),
        ("//synthetic/synthetic_schools.csv", ("DENY", "CONSTRAINT_VIOLATED")),
        ("", ("DENY", "CONSTRAINT_VIOLATED")),
        (["synthetic/synthetic_schools.csv"], ("DENY", "CONSTRAINT_VIOLATED")),
    ],
)
def test_q4_path_spellings(path, expected):
    assert decide("get", [FILES_GET], path=path) == expected


def test_q4_normalise_path():
    assert normalise_path("a/./b//c/../d") == "a/b/d"
    assert normalise_path("a/b/") == "a/b"
    assert normalise_path("a/../..") is None
    assert normalise_path("/a") is None
    assert normalise_path("a\x00b") is None


def test_q5_any_entry_can_allow():
    two = [SCH01_SEARCH, {**SCH01_SEARCH, "constraints": {"urn": ["SCH02"]}}]
    assert decide("search", two, query="SPR", urn="SCH01") == ("ALLOW", "IN_SCOPE")
    assert decide("search", two, query="SPR", urn="SCH02") == ("ALLOW", "IN_SCOPE")
    assert decide("search", two, query="SPR", urn="SCH03") == ("DENY", "CONSTRAINT_VIOLATED")
    assert decide("search", two, query="SPR") == ("DENY", "CONSTRAINT_MISSING")
    # the closest entry gives the reason: SCH02 matches the second entry, which then refuses on volume
    assert decide("search", two, query="", urn="SCH02") == ("DENY", "QUERY_TOO_BROAD")


def test_q5_entries_are_not_mixed():
    # one entry: SCH01, but only pupil P0004; another: any query, but only at SCH02
    scope = [
        {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"], "query": ["P0004"]}},
        {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH02"]}},
    ]
    assert decide("search", scope, query="P0004", urn="SCH01") == ("ALLOW", "IN_SCOPE")
    assert decide("search", scope, query="SPR", urn="SCH02") == ("ALLOW", "IN_SCOPE")
    # urn from the first entry, a free query from the second: neither entry allows that whole call
    assert decide("search", scope, query="SPR", urn="SCH01") == ("DENY", "CONSTRAINT_VIOLATED")


def test_step_up_still_applies_after_scope():
    scope = [{"server": "pupil-data", "tools": ["draft"], "constraints": {"urn": ["SCH04"]}}]
    assert decide("draft", scope, urn="SCH04", pupil_ids=["P0011"]) == ("STEP_UP", "SENSITIVE_TOOL")
    assert decide("draft", scope, urn="SCH01", pupil_ids=["P0011"]) == ("DENY", "CONSTRAINT_VIOLATED")
