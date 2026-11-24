"""Question 3: right school, but how much is too much? Every case goes through the real endpoint."""

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway.lib import volume
from gateway.lib.common import priv_from_pem
from mcp_server.api.routes_mcp import mcp

SCHOOLS = [f"SCH{i:02d}" for i in range(1, 13)]
SCHOOLS_FILE = "synthetic/synthetic_schools.csv"
CENSUS_FILE = "synthetic/synthetic_personal_data_school_census.csv"
# every school, and the census file too: the widest mandate a careless issuer might sign
WIDE_SCOPE = [
    {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": SCHOOLS}},
    {"server": "pupil-data", "tools": ["get"], "constraints": {"path": [SCHOOLS_FILE, CENSUS_FILE]}},
]


@pytest.fixture
def call(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    key = cli.load_or_create_key(state / "agent.pem")
    cli.set_person(state, "officer:jsmith", daily_pupils=10_000)
    mandate, _ = cli.issue_mandate(
        state,
        key.public_key(),
        scope=WIDE_SCOPE,
        deny=cli.DEFAULT_DENY,
        ttl=600,
        purpose="volume tests",
        principal="officer:jsmith",
        org="test",
        extra={"clearance": 4, "budget": {"pupils": 10_000}},
    )
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)
    agent = priv_from_pem((state / "agent.pem").read_bytes())

    with TestClient(main.app) as client:

        def _call(tool, **arguments):
            body = cli.sign_request(agent, server="pupil-data", tool=tool, arguments=arguments, mandate=mandate)
            r = client.post("/tools/call", json=body)
            return r.status_code, r.json()

        yield _call


def pupils(resp):
    return {row["Psuedo ID"] for row in resp["result"]}


# ------------------------------------------------------------ layer 1: before any data is touched


@pytest.mark.parametrize("query", ["", " ", "\t\n", chr(160)])
def test_blank_query_is_refused(call, query):
    status, resp = call("search", query=query, urn="SCH01")
    assert (status, resp["decision"]["reason_code"]) == (403, "QUERY_TOO_BROAD")
    assert "result" not in resp


@pytest.mark.parametrize("limit", [101, 1000, 10**12, 0, -1, "1000", "5", 1000.0, 5.0, True, None, [5], {"n": 5}])
@pytest.mark.parametrize("tool_args", [("search", {"query": "SPR", "urn": "SCH01"}), ("get", {"path": SCHOOLS_FILE})])
def test_limit_must_be_a_whole_number_in_range(call, tool_args, limit):
    # the MCP server coerces "1000" and 1000.0 to 1000, so the gateway has to be stricter than a size check
    tool, args = tool_args
    status, resp = call(tool, **args, limit=limit)
    assert (status, resp["decision"]["reason_code"]) == (403, "LIMIT_NOT_ALLOWED")


@pytest.mark.parametrize("limit", [1, 5, 100])
def test_limit_in_range_is_allowed(call, limit):
    assert call("search", query="SPR", urn="SCH01", limit=limit)[0] == 200


def test_scope_is_decided_before_volume(call):
    # out-of-scope stays CONSTRAINT_*: a volume reason must not mask, or tell an agent anything about, another scope
    assert call("search", query="", urn="SCH99")[1]["decision"]["reason_code"] == "CONSTRAINT_VIOLATED"
    assert call("search", query="")[1]["decision"]["reason_code"] == "CONSTRAINT_MISSING"


# ------------------------------------------------------------ layer 2: a query that narrows nothing


@pytest.mark.parametrize("query", ["P", "0", "1", "20", "202", "/2", "_", "C", "SCH", "sch"])
def test_a_query_matching_nearly_everything_is_refused(call, query):
    status, resp = call("search", query=query, urn="SCH01")
    assert (status, resp["decision"]["reason_code"]) == (403, "QUERY_TOO_BROAD")
    assert "result" not in resp


@pytest.mark.parametrize("urn", SCHOOLS)
def test_blanket_queries_are_refused_at_every_school(call, urn):
    for query in ("", "P", urn, urn.lower()):
        status, resp = call("search", query=query, urn=urn)
        assert (status, resp["decision"]["reason_code"]) == (403, "QUERY_TOO_BROAD"), (urn, query)


def test_a_refusal_does_not_reveal_how_many_records_there_are(call):
    _, resp = call("search", query="P", urn="SCH01")
    assert not any(ch.isdigit() for ch in resp["decision"]["detail"])
    assert set(resp) == {"decision"}


# ------------------------------------------------------------ layer 3: the guarantee


@pytest.mark.parametrize("urn", SCHOOLS)
def test_no_search_releases_more_than_the_pupil_limit(call, urn):
    for query in ("SPR", "AUT", "SUM", "2021/22", "2022/23", "2023/24", "1_ENG", "2_OTH", "WHIT", "0,0", "F,", "C,14"):
        status, resp = call("search", query=query, urn=urn, limit=100)
        if status == 200:
            assert len(pupils(resp)) <= volume.MAX_PUPILS, (urn, query)
            assert {r["URN"] for r in resp["result"]} <= {urn}


@pytest.mark.parametrize("query", [",", "C,1", "0,", ",1,2"])
def test_a_query_that_spans_columns_matches_nothing(call, query):
    # search is cell by cell, so the commas between columns are not there to be matched
    status, resp = call("search", query=query, urn="SCH01")
    assert (status, resp["result"]) == (200, [])


def test_get_on_a_pupil_file_is_capped_too(call):
    status, resp = call("get", path=CENSUS_FILE, limit=100)
    assert status == 200
    assert len(pupils(resp)) <= volume.MAX_PUPILS
    assert resp["volume"]["trimmed"] is True


def test_a_trimmed_answer_says_so(call):
    status, resp = call("search", query="SUM", urn="SCH01")
    assert status == 200
    assert resp["volume"] == {
        "returned_rows": len(resp["result"]),
        "returned_pupils": volume.MAX_PUPILS,
        "max_pupils": volume.MAX_PUPILS,
        "trimmed": True,
    }


def test_rows_cut_by_the_limit_also_count_as_trimmed(call):
    _, resp = call("search", query="P0004", urn="SCH01", limit=2)
    assert len(resp["result"]) == 2
    assert resp["volume"]["trimmed"] is True


# ------------------------------------------------------------ ordinary work still works


def test_looking_up_one_pupil_is_complete_and_untrimmed(call):
    status, resp = call("search", query="P0004", urn="SCH01")
    assert status == 200
    assert len(resp["result"]) == 5
    assert resp["volume"]["trimmed"] is False


def test_a_query_with_no_hits_is_allowed(call):
    status, resp = call("search", query="SCH02", urn="SCH01")
    assert (status, resp["result"], resp["volume"]["trimmed"]) == (200, [], False)


def test_files_without_pupils_are_untouched(call):
    status, resp = call("get", path=SCHOOLS_FILE)
    assert (status, len(resp["result"])) == (200, 12)
    assert "volume" not in resp
