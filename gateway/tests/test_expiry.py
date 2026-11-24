"""A mandate is dead from its `exp` second, with no grace: the Day 2 scoring counts any later acceptance as a break
(red-team RT-02). Clock tolerance covers only the start of validity, and one decision reads the clock once.

The `clock` fixture stands every time.time() in the gateway, the issuer and the signer at one chosen second. PyJWT
keeps its own clock, so the gateway must not let PyJWT judge time: these tests would not see it if it did.
"""

import time

import jwt
import pytest

from gateway import cli, main
from gateway.lib.common import priv_to_pem
from gateway.lib.gateway_verify import Request
from gateway.lib.status_list import is_revoked
from mcp_server.api import routes_mcp

from .conftest import JSMITH, entry
from .test_q07_helpers import Pair

SCH01 = entry("search", urn=["SCH01"])
LOOKUP = {"query": "P0004", "urn": "SCH01"}
WRITE = entry("write", urn=["SCH04"], column=["Language"])
ASK = {"pupil_id": "P0011", "urn": "SCH04", "column": "Language", "value": "2_OTH", "reason": "parent told us"}
TTL = 100


@pytest.fixture
def clock(monkeypatch):
    now = {"t": float(int(time.time()))}
    monkeypatch.setattr(time, "time", lambda: now["t"])
    return now


def at(world, clock, second, mandate):
    """Call with `mandate` as if it were `second` now: signed then, decided then."""
    clock["t"] = float(second)
    status, resp = world.call("search", mandate, **LOOKUP)
    return status, resp["decision"]["reason_code"], resp["decision"]["detail"]


def issued(world):
    mandate = world.mandate(SCH01, ttl=TTL)
    return mandate, jwt.decode(mandate, options={"verify_signature": False})


def resigned(token: str, issuer_key, **changes) -> str:
    """The same mandate with some claims changed, signed again by the real issuer: as a fast issuer clock makes it."""
    claims = {**jwt.decode(token, options={"verify_signature": False}), **changes}
    return jwt.encode(claims, priv_to_pem(issuer_key), algorithm="EdDSA", headers=jwt.get_unverified_header(token))


def resigned_status(token: str, issuer_key, **changes) -> str:
    claims = {**jwt.decode(token, options={"verify_signature": False}), **changes}
    return jwt.encode(claims, priv_to_pem(issuer_key), algorithm="EdDSA", headers={"typ": "statuslist+jwt"})


# ------------------------------------------------------------ root mandates


def test_a_mandate_works_in_its_last_second(world, clock):
    mandate, claims = issued(world)
    assert at(world, clock, claims["exp"] - 1, mandate)[:2] == (200, "IN_SCOPE")


def test_a_mandate_is_refused_from_its_expiry_second(world, clock):
    mandate, claims = issued(world)
    assert at(world, clock, claims["exp"], mandate)[:2] == (403, "EXPIRED")


def test_a_mandate_five_seconds_dead_is_refused(world, clock):
    """The red team's case: a correctly signed mandate, expired five seconds, got 200 and ALLOW."""
    mandate, claims = issued(world)
    assert at(world, clock, claims["exp"] + 5, mandate)[:2] == (403, "EXPIRED")


# ------------------------------------------------------------ helpers' mandates


def test_a_helper_is_refused_from_its_own_expiry_second(world, clock):
    pair = Pair(world)
    child = pair.child(exp=pair.claims["exp"] - 10)
    clock["t"] = float(pair.claims["exp"] - 10)
    status, resp = pair.call(child)
    assert (status, resp["decision"]["reason_code"], resp["decision"]["detail"]) == (403, "EXPIRED", "urn:uuid:child")


def test_a_helper_that_ends_with_its_parent_is_refused_on_the_parent(world, clock):
    """A helper can never outlive its parent, so the parent's expiry is what stops one that ends with it."""
    pair = Pair(world)
    child = pair.child(exp=pair.claims["exp"])
    clock["t"] = float(pair.claims["exp"])
    status, resp = pair.call(child)
    assert (status, resp["decision"]["reason_code"]) == (403, "EXPIRED")
    assert resp["decision"]["detail"] == pair.claims["jti"]


# ------------------------------------------------------------ the start of validity


def test_an_issuer_clock_twenty_seconds_fast_is_tolerated(world, clock, issuer_key):
    mandate, claims = issued(world)
    ahead = resigned(mandate, issuer_key, iat=claims["iat"] + 20, nbf=claims["nbf"] + 20)
    assert at(world, clock, claims["nbf"], ahead)[:2] == (200, "IN_SCOPE")


def test_a_mandate_forty_seconds_from_starting_is_not_yet_valid(world, clock, issuer_key):
    mandate, claims = issued(world)
    ahead = resigned(mandate, issuer_key, iat=claims["iat"] + 40, nbf=claims["nbf"] + 40)
    assert at(world, clock, claims["nbf"], ahead)[:2] == (403, "NOT_YET_VALID")


# ------------------------------------------------------------ status-list time


def test_a_status_publisher_clock_thirty_seconds_fast_is_tolerated(world, issuer_key):
    token = (world.state / "status_list.jwt").read_text()
    claims = jwt.decode(token, options={"verify_signature": False})
    ahead = resigned_status(token, issuer_key, iat=claims["iat"] + 30)
    assert not is_revoked(ahead, 0, issuer_key.public_key(), claims["sub"], now=claims["iat"])


def test_a_status_list_more_than_thirty_seconds_from_publication_is_refused(world, issuer_key):
    token = (world.state / "status_list.jwt").read_text()
    claims = jwt.decode(token, options={"verify_signature": False})
    ahead = resigned_status(token, issuer_key, iat=claims["iat"] + 31)
    with pytest.raises(ValueError, match="future"):
        is_revoked(ahead, 0, issuer_key.public_key(), claims["sub"], now=claims["iat"])


def test_a_status_list_is_stale_from_its_ttl_boundary(world, issuer_key):
    token = (world.state / "status_list.jwt").read_text()
    claims = jwt.decode(token, options={"verify_signature": False})
    short = resigned_status(token, issuer_key, iat=100, ttl=10)
    assert not is_revoked(short, 0, issuer_key.public_key(), claims["sub"], now=109.999)
    with pytest.raises(ValueError, match="stale"):
        is_revoked(short, 0, issuer_key.public_key(), claims["sub"], now=110)


def test_a_negative_status_index_is_refused(world, issuer_key):
    token = (world.state / "status_list.jwt").read_text()
    claims = jwt.decode(token, options={"verify_signature": False})
    with pytest.raises(ValueError, match="range"):
        is_revoked(token, -1, issuer_key.public_key(), claims["sub"], now=claims["iat"])


# ------------------------------------------------------------ one decision, one second


def test_a_decision_reads_the_clock_once(world, clock, monkeypatch):
    """Begun in the mandate's last second, a decision does not change its mind when the clock ticks past `exp`."""
    mandate, claims = issued(world)
    clock["t"] = float(claims["exp"] - 1)
    req = Request(**world.sign("search", mandate, **LOOKUP))
    main.refresh_revocations()
    reads = iter([float(claims["exp"] - 1)])
    monkeypatch.setattr(time, "time", lambda: next(reads, float(claims["exp"])))
    decision = main.state["gateway"].decide(req)
    assert (decision.decision, decision.reason_code) == ("ALLOW", "IN_SCOPE"), decision.detail


# ------------------------------------------------------------ calls waiting for a person


def test_a_call_approved_after_its_mandate_expired_is_not_run(world, clock, tmp_path, monkeypatch):
    """A held call lapses with its mandate, so the approval comes too late; release would check expiry again."""
    monkeypatch.setattr(routes_mcp, "WRITES_PATH", tmp_path / "writes" / "corrections.jsonl")
    mandate = world.mandate(WRITE, clearance=3, ttl=TTL)
    exp = jwt.decode(mandate, options={"verify_signature": False})["exp"]
    status, resp = world.call("write", mandate, **ASK)
    assert (status, resp["decision"]["reason_code"]) == (202, "SENSITIVE_TOOL"), resp
    hold = resp["hold_id"]

    clock["t"] = float(exp)
    jsmith = cli.load_or_create_key(world.state / "person_officer_jsmith.pem")
    body = cli.sign_as_person(jsmith, JSMITH, "answer", hold=hold, answer="approve")
    answered = world.client.post("/holds/answer", json=body).json()
    assert (answered["reason_code"], answered["detail"]) == ("HOLD_NOT_WAITING", "lapsed")
    assert not (tmp_path / "writes" / "corrections.jsonl").exists()

    status, resp = world.call("held", mandate, server="gateway", id=hold)
    assert (status, resp["decision"]["reason_code"]) == (403, "EXPIRED")
