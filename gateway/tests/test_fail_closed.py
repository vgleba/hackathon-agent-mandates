"""Questions 1 and 2 only hold if nobody can crash the checks or have the gateway sign a mandate for them."""

import base64
import json
import threading
import time
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway.lib.common import priv_from_pem, priv_to_pem
from gateway.lib.gateway_verify import MAX_DETAIL
from mcp_server.api.routes_mcp import mcp


@pytest.fixture
def gw(tmp_path, monkeypatch):
    state = tmp_path / "state"
    cli.main(["--state", str(state), "init"])
    out = state / "mandate.jwt"
    cli.main(["--state", str(state), "issue", "--agent-key", str(state / "agent.pem"), "-o", str(out)])
    monkeypatch.setattr(main, "STATE_DIR", state)
    monkeypatch.setitem(main.MCP_SERVERS, "pupil-data", mcp)
    monkeypatch.delenv("GATEWAY_DEMO", raising=False)
    # as a real server would: an unhandled error becomes a 500 response rather than an exception in the test
    with TestClient(main.app, raise_server_exceptions=False) as client:
        yield client, priv_from_pem((state / "agent.pem").read_bytes()), out.read_text(), state


def body_for(mandate, **overrides):
    body = {"server": "pupil-data", "tool": "search", "arguments": {"query": "SPR", "urn": "SCH01"}}
    return {**body, "mandate": mandate, "nonce": "n", "ts": int(time.time()), "sig": "x", **overrides}


def hand_made(claims, key) -> str:
    """A signed token built without the JWT library's own checks on claims: an attacker would not use them."""
    return jwt.api_jws.encode(
        json.dumps(claims).encode(), priv_to_pem(key), algorithm="EdDSA", headers={"typ": "mandate+jwt", "kid": "k"}
    )


def post_raw(client, text):
    return client.post("/tools/call", content=text.encode(), headers={"content-type": "application/json"})


NONE_ALG = "eyJhbGciOiJub25lIn0.e30."  # pragma: allowlist secret  (an empty token that claims to need no signature)


@pytest.mark.parametrize("mandate", ["", "x", "not-a-jwt", "a.b.c", "....", NONE_ALG, "é.é.é"])
def test_junk_mandate_is_refused_not_a_crash(gw, mandate):
    client, *_ = gw
    r = client.post("/tools/call", json=body_for(mandate))
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "WRONG_TOKEN_TYPE")


@pytest.mark.parametrize(
    "claims",
    [{}, {"iss": None}, {"iss": ["https://issuer.hack.local"]}, {"iss": {"a": 1}}, {"iss": 5}],
)
def test_mandate_with_missing_or_wrongly_typed_claims(gw, claims):
    client, key, *_ = gw
    r = client.post("/tools/call", json=body_for(hand_made(claims, key)))
    assert r.status_code == 403
    assert r.json()["decision"]["decision"] == "DENY"


def test_genuinely_signed_mandate_missing_its_status_claim_is_refused(gw):
    client, _, _, state = gw
    issuer = priv_from_pem((state / "issuer_key.pem").read_bytes())
    claims = {"iss": "https://issuer.hack.local", "jti": "j", "exp": int(time.time()) + 60}
    token = jwt.encode(
        claims, priv_to_pem(issuer), algorithm="EdDSA", headers={"typ": "mandate+jwt", "kid": "issuer-2026-11"}
    )
    r = client.post("/tools/call", json=body_for(token))
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, "MALFORMED_REQUEST")


def unsigned(header: dict, claims: dict) -> str:
    """A token nobody signed. Its header and claims are read before any signature is checked."""

    def part(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{part(header)}.{part(claims)}.AAAA"


BROKEN = chr(0xD800)  # half of a character: valid inside JSON as an escape, impossible to send back as UTF-8
MANDATE = {"typ": "mandate+jwt", "alg": "EdDSA"}


@pytest.mark.parametrize(
    ("header", "claims", "reason"),
    [
        ({"typ": BROKEN, "alg": "EdDSA"}, {"iss": "x"}, "WRONG_TOKEN_TYPE"),
        ({"typ": {"a": [BROKEN]}, "alg": "EdDSA"}, {"iss": "x"}, "WRONG_TOKEN_TYPE"),
        (MANDATE, {"iss": BROKEN}, "ISSUER_NOT_ACCREDITED"),
        (MANDATE, {"iss": BROKEN * 5000}, "ISSUER_NOT_ACCREDITED"),
        (MANDATE, {"iss": "x" * 5000}, "ISSUER_NOT_ACCREDITED"),
    ],
)
def test_text_from_an_unsigned_token_cannot_break_the_refusal(gw, header, claims, reason):
    # the reason for a refusal repeats the token's own typ or iss: it has to be something that can be sent
    client, *_ = gw
    r = client.post("/tools/call", json=body_for(unsigned(header, claims)))
    assert (r.status_code, r.json()["decision"]["reason_code"]) == (403, reason)
    assert len(r.json()["decision"]["detail"]) <= MAX_DETAIL + len("...")


@pytest.mark.parametrize("ts", [10**400, -(10**400), 2**63])
def test_absurd_timestamp_is_refused(gw, ts):
    client, _, mandate, _ = gw
    assert client.post("/tools/call", json=body_for(mandate, ts=ts)).status_code in {403, 422}


@pytest.mark.parametrize("field", ["server", "tool", "mandate", "nonce", "sig"])
def test_invalid_unicode_in_any_field_is_refused(gw, field):
    client, _, mandate, _ = gw
    text = json.dumps({**body_for(mandate), field: "@@"}).replace("@@", "\\ud800")
    assert post_raw(client, text).status_code in {403, 422}


@pytest.mark.parametrize("path", ["/tools/call", "/holds", "/holds/answer", "/log", "/person/class", "/person/schools"])
@pytest.mark.parametrize("field", ["ts", "arguments", "names", "seq", "year", "principal", "sig", "hold"])
def test_invalid_unicode_where_a_number_or_object_belongs(gw, path, field):
    # the framework's own error page repeats what it was sent, which cannot always be encoded
    client, _, mandate, _ = gw
    person = {"principal": "officer:jsmith", "nonce": "n", "ts": 1, "sig": "s"}
    body = body_for(mandate) if path == "/tools/call" else person
    text = json.dumps({**body, field: "@@"}).replace("@@", "\\ud800")
    r = client.post(path, content=text.encode(), headers={"content-type": "application/json"})
    assert r.status_code in {403, 422}


def test_an_error_does_not_repeat_what_was_sent(gw):
    client, _, mandate, _ = gw
    r = client.post("/tools/call", json={**body_for(mandate), "ts": "REPEATED"})
    assert r.status_code == 422
    assert "REPEATED" not in r.text


def test_invalid_unicode_in_an_argument_is_refused(gw):
    client, _, mandate, _ = gw
    text = json.dumps(body_for(mandate, arguments={"query": "@@", "urn": "SCH01"})).replace("@@", "\\ud800")
    assert post_raw(client, text).status_code in {403, 422}


@pytest.mark.parametrize("text", ["", "{", "null", "[]", '"x"', "{}", "[" * 100_000])
def test_body_that_is_not_a_call_is_refused(gw, text):
    client, *_ = gw
    assert post_raw(client, text).status_code in {400, 403, 422}


def test_a_crash_attempt_leaves_the_gateway_working(gw):
    client, key, mandate, _ = gw
    client.post("/tools/call", json=body_for("not-a-jwt"))
    good = cli.sign_request(
        key, server="pupil-data", tool="search", arguments={"query": "P0004", "urn": "SCH01"}, mandate=mandate
    )
    assert client.post("/tools/call", json=good).status_code == 200


# ------------------------------------------------------------ files that change while they are being read


def good_call(client, key, mandate):
    body = cli.sign_request(
        key, server="pupil-data", tool="search", arguments={"query": "P0004", "urn": "SCH01"}, mandate=mandate
    )
    return client.post("/tools/call", json=body)


@pytest.mark.parametrize("name", ["status_list.jwt", "people.json"])
def test_a_file_that_is_busy_for_a_moment_is_read_again(gw, monkeypatch, name):
    # Windows refuses to open a file at the moment it is being replaced
    client, key, mandate, _ = gw
    real, busy = Path.read_text, iter([True] * 3)

    def read_text(self, *a, **k):
        if self.name == name and next(busy, False):
            raise PermissionError
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", read_text)
    assert good_call(client, key, mandate).status_code == 200


@pytest.mark.parametrize("name", ["status_list.jwt", "people.json"])
def test_a_file_that_cannot_be_read_means_no(gw, monkeypatch, name):
    client, key, mandate, _ = gw
    assert good_call(client, key, mandate).status_code == 200  # so that an old copy could have been kept
    real = Path.read_text

    def read_text(self, *a, **k):
        if self.name == name:
            raise PermissionError
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", read_text)
    r = good_call(client, key, mandate)
    assert (r.status_code, r.json()["decision"]["decision"]) == (403, "DENY")
    for path in ("/holds", "/holds/answer", "/log", "/person/class", "/person/schools"):
        assert client.post(path, json={"principal": "x", "nonce": "n", "ts": 1, "sig": "s"}).status_code == 403


def test_revoking_while_calls_are_being_made_never_breaks_them(gw):
    client, key, mandate, state = gw
    stop = threading.Event()

    def churn():
        while not stop.is_set():
            cli.revoke_mandate(state, 7)

    t = threading.Thread(target=churn)
    t.start()
    try:
        assert {good_call(client, key, mandate).status_code for _ in range(40)} == {200}
    finally:
        stop.set()
        t.join()


# ------------------------------------------------------------ the demo routes sign for anyone who asks

DEMO_ROUTES = [
    ("GET", "/demo/issuer", None),
    ("GET", "/demo/trust", None),
    ("POST", "/demo/mandate", {"urn": "SCH07", "tools": ["pupil"], "deny": []}),
    ("POST", "/demo/revoke", {"idx": 0}),
    ("POST", "/demo/call", {"tool": "pupil", "arguments": {"pupil_id": "P0586", "urn": "SCH07"}}),
]


@pytest.mark.parametrize("setting", [None, "", "0", "false", "no"])
@pytest.mark.parametrize("route", DEMO_ROUTES, ids=lambda r: r[1])
def test_demo_routes_are_off_unless_switched_on(gw, monkeypatch, setting, route):
    client, _, _, state = gw
    method, path, body = route
    if setting is not None:
        monkeypatch.setenv("GATEWAY_DEMO", setting)
    before = (state / "status_list.json").read_text()
    assert client.request(method, path, json=body).status_code == 404
    assert (state / "status_list.json").read_text() == before  # nothing minted, nothing revoked
    assert not (state / "demo_mandate.jwt").exists()


@pytest.mark.parametrize(
    "request_",
    [
        {"method": "POST", "url": "/demo/call", "json": {"tool": 5}},  # a body the route would not accept
        {"method": "POST", "url": "/demo/call", "content": b"{", "headers": {"content-type": "application/json"}},
        {"method": "GET", "url": "/demo/mandate"},  # a method the route does not have
        {"method": "GET", "url": "/demo"},
    ],
    ids=["wrong body", "not JSON", "wrong method", "bare prefix"],
)
def test_a_demo_route_that_is_off_looks_like_no_route_at_all(gw, request_):
    client, *_ = gw
    nothing_there = client.get("/no/such/path")
    r = client.request(**request_)
    assert (r.status_code, r.json()) == (404, nothing_there.json())


def test_demo_routes_are_not_listed(gw):
    client, *_ = gw
    assert [path for path in client.get("/openapi.json").json()["paths"] if path.startswith("/demo")] == []


def test_demo_routes_work_when_switched_on(gw, monkeypatch):
    client, *_ = gw
    monkeypatch.setenv("GATEWAY_DEMO", "1")
    assert client.get("/demo/issuer").status_code == 200
