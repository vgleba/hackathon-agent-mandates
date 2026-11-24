"""Day 2 boundaries: one request cannot exhaust the gateway or regain freshness after a restart."""

import json
import sqlite3
import time

import jwt
import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway.lib.common import MAX_MANDATE, sign_bytes
from gateway.lib.gateway_verify import CLOCK_SKEW, REQUEST_MAX_AGE, Request
from gateway.lib.store import Store
from mcp_server.api.routes_mcp import mcp

from .conftest import entry

SEARCH = entry("search", urn=["SCH01"])
LOOKUP = {"query": "P0004", "urn": "SCH01"}
PERSON_ROUTES = ["/holds", "/holds/answer", "/log", "/person/class", "/person/schools"]


def signed_at(world, mandate: str, ts: int, nonce: str) -> dict:
    req = Request(
        server="pupil-data",
        tool="search",
        arguments=LOOKUP,
        mandate=mandate,
        nonce=nonce,
        ts=ts,
        sig="",
    )
    req.sig = sign_bytes(world.key, req.signing_input())
    return req.__dict__


def test_body_below_the_cap_is_parsed_but_one_byte_over_is_413(world):
    below = b"{}" + b" " * (main.MAX_BODY - 3)
    assert len(below) == main.MAX_BODY - 1
    assert (
        world.client.post("/tools/call", content=below, headers={"content-type": "application/json"}).status_code == 422
    )

    over = below + b"  "
    assert len(over) == main.MAX_BODY + 1
    assert (
        world.client.post("/tools/call", content=over, headers={"content-type": "application/json"}).status_code == 413
    )


def test_chunked_body_is_counted_instead_of_trusting_content_length(world):
    def chunks():
        yield b"{"
        yield b" " * main.MAX_BODY

    response = world.client.post(
        "/tools/call", content=chunks(), headers={"content-type": "application/json", "transfer-encoding": "chunked"}
    )
    assert response.status_code == 413


@pytest.mark.parametrize("path", PERSON_ROUTES)
def test_person_routes_have_the_same_body_cap(world, path):
    response = world.client.post(
        path, content=b"{" + b" " * main.MAX_BODY, headers={"content-type": "application/json"}
    )
    assert response.status_code == 413


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("server", "s" * 65),
        ("tool", "t" * 65),
        ("nonce", ""),
        ("nonce", "n" * 129),
        ("sig", "s" * 129),
        ("mandate", "m" * (MAX_MANDATE + 1)),
    ],
)
def test_call_fields_are_bounded_before_verification(world, field, value):
    mandate = world.mandate(SEARCH)
    body = signed_at(world, mandate, int(time.time()), "field-boundary")
    body[field] = value
    assert world.client.post("/tools/call", json=body).status_code == 422


def test_nonce_is_stored_as_a_fixed_size_digest(world):
    mandate = world.mandate(SEARCH)
    raw = "n" * 128
    body = signed_at(world, mandate, int(time.time()), raw)
    assert world.post(body)[0] == 200
    (stored,) = main.state["store"].db.execute("SELECT nonce FROM nonces").fetchone()
    assert len(stored) == 64
    assert stored != raw
    assert world.post(body)[1]["decision"]["reason_code"] == "POP_FAILED"


def test_raw_nonce_rows_are_migrated_without_a_replay_window(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE nonces(who TEXT, nonce TEXT, ts REAL, PRIMARY KEY(who, nonce))")
    old.execute("CREATE TABLE seen(meter TEXT, pupil TEXT, PRIMARY KEY(meter, pupil))")
    old.execute(
        "CREATE TABLE holds(id TEXT PRIMARY KEY, body TEXT, principal TEXT, agent_id TEXT, root TEXT, "
        "state TEXT, created REAL, expires REAL, reason TEXT, result TEXT)"
    )
    old.execute("INSERT INTO nonces VALUES ('agent', 'captured', ?)", (time.time(),))
    old.commit()
    old.close()

    upgraded = Store(path)
    try:
        (stored,) = upgraded.db.execute("SELECT nonce FROM nonces").fetchone()
        assert len(stored) == 64
        assert not upgraded.use_nonce("agent", "captured")
    finally:
        upgraded.close()


def test_future_window_is_short_but_the_past_window_stays_usable(world, monkeypatch):
    now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: float(now))
    main.state["gateway"].started = now - REQUEST_MAX_AGE - 1
    mandate = world.mandate(SEARCH)

    assert world.post(signed_at(world, mandate, now + CLOCK_SKEW, "ahead-ok"))[0] == 200
    too_far = world.post(signed_at(world, mandate, now + CLOCK_SKEW + 1, "ahead-no"))
    assert (too_far[0], too_far[1]["decision"]["reason_code"]) == (403, "POP_FAILED")
    assert world.post(signed_at(world, mandate, now - REQUEST_MAX_AGE + 10, "old-ok"))[0] == 200


def test_request_from_before_process_start_is_refused_even_if_nonce_memory_was_lost(state, monkeypatch):
    key = cli.load_or_create_key(state / "agent.pem")
    mandate, _ = cli.issue_mandate(
        state,
        key.public_key(),
        scope=[SEARCH],
        deny=[],
        ttl=600,
        purpose="restart test",
        principal="officer:jsmith",
        org="test",
        extra=None,
        helpers=0,
    )
    issued = jwt.decode(mandate, options={"verify_signature": False})["nbf"]
    clock = {"now": float(issued + 1)}
    monkeypatch.setattr(time, "time", lambda: clock["now"])
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)
    body = cli.sign_request(key, server="pupil-data", tool="search", arguments=LOOKUP, mandate=mandate)

    with TestClient(main.app, raise_server_exceptions=False) as first:
        assert first.post("/tools/call", json=body).status_code == 200

    (state / "gateway.db").unlink()  # model an ephemeral volume losing replay state
    clock["now"] += 2
    with TestClient(main.app, raise_server_exceptions=False) as restarted:
        response = restarted.post("/tools/call", json=body)
    assert (response.status_code, response.json()["decision"]["reason_code"]) == (403, "POP_FAILED")


def test_healthcheck_identifies_a_process_and_changes_after_restart(world):
    first = world.client.get("/healthcheck").json()
    assert world.client.get("/healthcheck").json() == first
    assert set(first) == {"status", "instance", "started"}
    with TestClient(main.app, raise_server_exceptions=False) as restarted:
        second = restarted.get("/healthcheck").json()
    assert second["instance"] != first["instance"]


def test_person_approval_signed_before_process_start_is_refused(world):
    mandate = world.mandate(entry("draft", urn=["SCH04"], kind=["absence"]), clearance=2)
    status, reply = world.call("draft", mandate, urn="SCH04", pupil_ids=["P0011"], kind="absence")
    assert status == 202
    hold = reply["hold_id"]
    person_key = cli.load_or_create_key(world.state / "person_officer_jsmith.pem")
    answer = cli.sign_as_person(person_key, "officer:jsmith", "answer", hold=hold, answer="approve")

    main.state["started"] = answer["ts"] + 1
    response = world.client.post("/holds/answer", json=answer)
    assert (response.status_code, response.json()["reason_code"]) == (403, "APPROVER_NOT_VERIFIED")
    assert world.call("held", mandate, server="gateway", id=hold)[1]["held"]["state"] == "waiting"


def test_two_stores_on_one_state_refuse_each_others_nonce(tmp_path):
    path = tmp_path / "shared.db"
    first, second = Store(path), Store(path)
    try:
        assert first.use_nonce("agent", "same")
        assert not second.use_nonce("agent", "same")
    finally:
        first.close()
        second.close()


def test_deep_json_is_a_4xx_and_does_not_break_the_next_request(world):
    mandate = world.mandate(SEARCH)
    body = {
        "server": "pupil-data",
        "tool": "search",
        "arguments": "PLACEHOLDER",
        "mandate": mandate,
        "nonce": "deep",
        "ts": int(time.time()),
        "sig": "x",
    }
    text = json.dumps(body).replace('"PLACEHOLDER"', '{"x":' + "[" * 5000 + "0" + "]" * 5000 + "}")
    assert len(text.encode()) < main.MAX_BODY
    response = world.client.post("/tools/call", content=text, headers={"content-type": "application/json"})
    assert 400 <= response.status_code < 500

    good = world.sign("search", mandate, **LOOKUP)
    assert world.post(good)[0] == 200


@pytest.mark.parametrize(
    ("field", "value", "outcome"),
    [
        ("server", "s" * 64, (403, "OUT_OF_SCOPE")),
        ("tool", "t" * 64, (403, "OUT_OF_SCOPE")),
        ("nonce", "n" * 128, (200, "IN_SCOPE")),
        ("sig", "s" * 128, (403, "POP_FAILED")),
        ("mandate", "m" * MAX_MANDATE, (403, "WRONG_TOKEN_TYPE")),
    ],
)
def test_call_fields_at_their_limits_are_decided_as_usual(world, field, value, outcome):
    """A field at its limit reaches the checks; only one character more is refused before them."""
    req = Request(**signed_at(world, world.mandate(SEARCH), int(time.time()), "at-the-limit"))
    setattr(req, field, value)
    if field != "sig":
        req.sig = sign_bytes(world.key, req.signing_input())
    status, reply = world.post(req.__dict__)
    assert (status, reply["decision"]["reason_code"]) == outcome


def test_a_person_name_one_over_its_limit_is_refused_before_the_checks(world):
    signed = cli.sign_as_person(world.new_key(), "p" * 128, "holds")
    assert world.client.post("/holds", json=signed).status_code == 403
    assert world.client.post("/holds", json={**signed, "principal": "p" * 129}).status_code == 422
