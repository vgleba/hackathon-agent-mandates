"""Day 2 boundaries: one request cannot exhaust the gateway or regain freshness after a restart."""

import json
import sqlite3
import time

import pytest

from gateway import cli, main
from gateway.lib.common import MAX_MANDATE, sign_bytes
from gateway.lib.gateway_verify import Request
from gateway.lib.store import Store

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
