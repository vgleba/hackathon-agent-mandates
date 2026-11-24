import json

import pytest
from fastapi.testclient import TestClient

from gateway import cli, eval_open, main
from gateway import eval as ev
from gateway.lib.common import priv_from_pem
from gateway.lib.errors import Reject
from gateway.lib.gateway_verify import Request, check_request, clean_arguments
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


def test_bulk_export_is_denied(gw):
    client, call, _ = gw
    for arguments, reason in (
        ({"query": ""}, "QUERY_TOO_BROAD"),
        ({"query": "  "}, "QUERY_TOO_BROAD"),
        ({"query": "SPR", "limit": 101}, "LIMIT_NOT_ALLOWED"),
        ({"query": "SPR", "limit": "5"}, "LIMIT_NOT_ALLOWED"),
        ({"query": "SPR", "limit": -1}, "LIMIT_NOT_ALLOWED"),
        ({"query": "SPR", "limit": True}, "LIMIT_NOT_ALLOWED"),
    ):
        r, _ = call(client, "search", urn="SCH01", **arguments)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, reason), arguments
    r, _ = call(client, "search", urn="SCH01", query="SPR", limit=100)
    assert r.status_code == 200, r.text


def test_path_spellings(gw):
    client, call, _ = gw
    for path in ("./" + ev.SCHOOLS, ev.SCHOOLS.replace("/", "//")):
        r, _ = call(client, "get", path=path)
        assert r.status_code == 200, path
        assert r.json()["result"][0]["URN"] == "SCH01"
    for path, reason in (
        ("synthetic/x/../synthetic_schools.csv/", "PATH_NOT_ALLOWED"),
        ("synthetic/../synthetic/synthetic_display_names.csv", "PATH_NOT_ALLOWED"),
        ("/" + ev.SCHOOLS, "PATH_NOT_ALLOWED"),
        ("../data/" + ev.SCHOOLS, "PATH_NOT_ALLOWED"),
        (ev.SCHOOLS + "/../synthetic_display_names.csv", "PATH_NOT_ALLOWED"),
        (ev.SCHOOLS.upper(), "CONSTRAINT_VIOLATED"),
        (ev.SCHOOLS + "\x00", "PATH_NOT_ALLOWED"),
        ("", "PATH_NOT_ALLOWED"),
        (123, "PATH_NOT_ALLOWED"),
        ([ev.SCHOOLS], "PATH_NOT_ALLOWED"),
    ):
        r, _ = call(client, "get", path=path)
        assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, reason), path


def test_any_scope_entry_may_allow_but_entries_do_not_mix():
    def check(tool="t", **arguments):
        req = Request("s", tool, arguments, mandate="", nonce="", ts=0, sig="")
        scope = [
            {"server": "s", "tools": ["t", "search"], "constraints": {"urn": ["SCH01"], "path": ["a"]}},
            {"server": "s", "tools": ["t", "search"], "constraints": {"urn": ["SCH02"], "path": ["b"]}},
        ]
        return check_request(req, arguments, [scope], deny=[], step_up_patterns=[])[:2]

    assert check(urn="SCH01", path="a") == ("ALLOW", "IN_SCOPE")
    assert check(urn="SCH02", path="b") == ("ALLOW", "IN_SCOPE")  # the second entry is tried
    assert check(urn="SCH01", path="b") == ("DENY", "CONSTRAINT_VIOLATED")  # urn from one, path from the other
    assert check(urn="SCH03", path="a") == ("DENY", "CONSTRAINT_VIOLATED")
    assert check(path="a") == ("DENY", "CONSTRAINT_MISSING")
    assert check(tool="search", query="SPR", urn="SCH02", path="b", limit=101) == (
        "DENY",
        "LIMIT_NOT_ALLOWED",
    )
    assert check(tool="other", urn="SCH01", path="a") == ("DENY", "OUT_OF_SCOPE")


def test_issue_warns_when_entries_for_one_tool_constrain_different_arguments():
    def entry(**constraints):
        return {"server": "pupil-data", "tools": ["pupil"], "constraints": constraints}

    assert cli.scope_warnings(cli.DEFAULT_SCOPE) == []
    assert cli.scope_warnings(ev.TWO_SCHOOLS_SCOPE) == []  # same argument in both entries: a plain second grant
    (warning,) = cli.scope_warnings([entry(urn=["SCH01"]), entry(pupil_id=["P0011"])])
    assert "pupil-data.pupil" in warning
    assert len(cli.scope_warnings([entry(urn=["SCH01"]), entry()])) == 1  # an unconstrained entry beside a narrow one


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


def test_demo_walkthrough(gw, monkeypatch):
    client, _, _ = gw
    monkeypatch.setenv("GATEWAY_DEMO", "1")  # off by default
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


def test_open_evals_pass(gw):
    """make eval_open, in-process: every case for questions 7, 10, 11 and 14 holds against this gateway."""
    client, _, state = gw

    def post(path, body):
        r = client.post(path, json=body)
        return r.status_code, r.json()

    results = eval_open.run_open(state, post)
    assert {line.split()[0] for _, line in results} == {f"Q{q}" for q in eval_open.OPEN_QUESTIONS}
    assert [line for ok, line in results if not ok] == []


SCH01_SEARCH = {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}}
FILES_GET = {"server": "pupil-data", "tools": ["get"], "constraints": {"path": [ev.SCHOOLS, ev.MANIFEST]}}


def decide(tool, scope, **arguments):
    """Path cleaning and check_request on their own: (decision, reason_code), no keys or network."""
    req = Request(server="pupil-data", tool=tool, arguments=arguments, mandate="", nonce="", ts=0, sig="")
    try:
        cleaned = clean_arguments(req)
    except Reject as r:
        return "DENY", r.code
    decision, code, _ = check_request(req, cleaned, [scope], deny=["*.write"], step_up_patterns=["*.write", "*.draft"])
    return decision, code


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({"query": "P0004", "urn": "SCH01"}, ("ALLOW", "IN_SCOPE")),
        ({"query": "SPR", "urn": "SCH01", "limit": 100}, ("ALLOW", "IN_SCOPE")),
        ({"query": "", "urn": "SCH01"}, ("DENY", "QUERY_TOO_BROAD")),
        ({"query": "   ", "urn": "SCH01"}, ("DENY", "QUERY_TOO_BROAD")),
        ({"urn": "SCH01"}, ("DENY", "QUERY_TOO_BROAD")),
        ({"query": "SPR", "urn": "SCH01", "limit": 101}, ("DENY", "LIMIT_NOT_ALLOWED")),
        # the server would read each of these as a number, so the gateway must not compare them as anything else
        ({"query": "SPR", "urn": "SCH01", "limit": "1000"}, ("DENY", "LIMIT_NOT_ALLOWED")),
        ({"query": "SPR", "urn": "SCH01", "limit": 1000.0}, ("DENY", "LIMIT_NOT_ALLOWED")),
        ({"query": "SPR", "urn": "SCH01", "limit": True}, ("DENY", "LIMIT_NOT_ALLOWED")),
        ({"query": "SPR", "urn": "SCH01", "limit": 0}, ("DENY", "LIMIT_NOT_ALLOWED")),
        ({"query": "SPR", "urn": "SCH01", "limit": -1}, ("DENY", "LIMIT_NOT_ALLOWED")),
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
    # a mandate can lower the gateway's own limit of 100, never lift it
    wide = [{**SCH01_SEARCH, "max_rows": 1000}]
    assert decide("search", wide, query="SPR", urn="SCH01") == ("ALLOW", "IN_SCOPE")
    assert decide("search", wide, query="SPR", urn="SCH01", limit=1000) == ("DENY", "LIMIT_NOT_ALLOWED")
    assert decide("search", wide, query="", urn="SCH01", limit=50) == ("DENY", "QUERY_TOO_BROAD")
    # one entry's cap is its own: a second entry for the same school without one still allows 100
    assert decide("search", [*tight, SCH01_SEARCH], query="SPR", urn="SCH01", limit=100) == ("ALLOW", "IN_SCOPE")
    for unreadable in ("10", 0, 2.5, None):
        bad = [{**SCH01_SEARCH, "max_rows": unreadable}]
        assert decide("search", bad, query="SPR", urn="SCH01", limit=5) == ("DENY", "CLAIM_NOT_UNDERSTOOD")


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (ev.SCHOOLS, ("ALLOW", "IN_SCOPE")),
        ("./synthetic/synthetic_schools.csv", ("ALLOW", "IN_SCOPE")),
        ("synthetic//synthetic_schools.csv", ("ALLOW", "IN_SCOPE")),
        ("synthetic/./synthetic_schools.csv", ("ALLOW", "IN_SCOPE")),
        # any `..` is refused, even one that would land back on an allowed file
        ("synthetic/../synthetic/synthetic_schools.csv", ("DENY", "PATH_NOT_ALLOWED")),
        ("synthetic/../synthetic/synthetic_display_names.csv", ("DENY", "PATH_NOT_ALLOWED")),
        ("../synthetic/synthetic_schools.csv", ("DENY", "PATH_NOT_ALLOWED")),
        ("synthetic/../../data/synthetic/synthetic_schools.csv", ("DENY", "PATH_NOT_ALLOWED")),
        ("/app/mcp_server/data/synthetic/synthetic_schools.csv", ("DENY", "PATH_NOT_ALLOWED")),
        ("//synthetic/synthetic_schools.csv", ("DENY", "PATH_NOT_ALLOWED")),
        ("a\x00b", ("DENY", "PATH_NOT_ALLOWED")),
        ("", ("DENY", "PATH_NOT_ALLOWED")),
        (["synthetic/synthetic_schools.csv"], ("DENY", "PATH_NOT_ALLOWED")),
        ("synthetic/synthetic_display_names.csv", ("DENY", "CONSTRAINT_VIOLATED")),
    ],
)
def test_q4_path_spellings(path, expected):
    assert decide("get", [FILES_GET], path=path) == expected


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
