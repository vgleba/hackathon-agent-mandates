"""Question 9: should a person approve this first?"""

import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from gateway import cli, main
from gateway.lib.store import Store
from mcp_server.api import routes_mcp

from .conftest import JSMITH, entry

WRITE = entry("write", urn=["SCH04"], column=["Language"])
DRAFT = entry("draft", urn=["SCH04"], kind=["absence"])
ASK = {"pupil_id": "P0011", "urn": "SCH04", "column": "Language", "value": "2_OTH", "reason": "parent told us"}


@pytest.fixture(autouse=True)
def writes(tmp_path, monkeypatch):
    path = tmp_path / "writes" / "corrections.jsonl"
    monkeypatch.setattr(routes_mcp, "WRITES_PATH", path)
    return lambda: path.read_text().splitlines() if path.exists() else []


@pytest.fixture
def jsmith(world):
    return cli.load_or_create_key(world.state / "person_officer_jsmith.pem")


def person_post(world, path, key, do, principal=JSMITH, *, over=None, **fields):
    body = {**cli.sign_as_person(key, principal, do, **fields), **(over or {})}
    r = world.client.post(path, json=body)
    return r.status_code, r.json()


def answer(world, key, hold, said="approve", principal=JSMITH, **kw):
    return person_post(world, "/holds/answer", key, "answer", principal, hold=hold, answer=said, **kw)


def waiting(world, key, principal=JSMITH):
    return person_post(world, "/holds", key, "holds", principal)


def collect(world, mandate, hold, key=None):
    return world.call("held", mandate, server="gateway", id=hold, key=key)


def held(world, mandate=None, **ask):
    mandate = mandate or world.mandate(WRITE, clearance=3)
    status, resp = world.call("write", mandate, **{**ASK, **ask})
    assert (status, resp["decision"]["reason_code"]) == (202, "SENSITIVE_TOOL"), resp
    return mandate, resp["hold_id"]


# ------------------------------------------------------------ the ordinary path


def test_a_held_correction_is_approved_once_and_the_agent_collects_the_answer(world, jsmith, writes):
    m, hold = held(world)
    assert writes() == []
    assert collect(world, m, hold)[1]["held"]["state"] == "waiting"
    assert answer(world, jsmith, hold)[0] == 200
    assert len(writes()) == 1
    status, resp = collect(world, m, hold)
    assert (status, resp["held"]["state"]) == (200, "done")
    assert resp["result"]["after"] == "2_OTH"
    assert "result" not in collect(world, m, hold)[1]  # once collected it is gone


def test_the_person_sees_exactly_what_will_happen(world, jsmith):
    _, hold = held(world)
    status, resp = waiting(world, jsmith)
    assert status == 200
    (item,) = resp["holds"]
    assert item["id"] == hold
    assert item["arguments"]["value"] == "2_OTH"
    assert item["preview"]["name"] == "Zara Okafor"
    assert item["preview"]["now"] in {"1_ENG", "2_OTH"}


def test_letters_are_shown_in_full_before_they_are_released(world, jsmith):
    roster = world.mandate(entry("roster", urn=["SCH04"]), clearance=2)
    ask = {"urn": "SCH04", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}
    two = [r["Psuedo ID"] for r in world.call("roster", roster, **ask)[1]["result"][:2]]
    m = world.mandate(DRAFT, clearance=2)
    status, resp = world.call("draft", m, urn="SCH04", pupil_ids=two, kind="absence")
    assert status == 202
    (item,) = waiting(world, jsmith)[1]["holds"]
    assert len(item["preview"]["letters"]) == 2
    assert answer(world, jsmith, resp["hold_id"])[0] == 200
    assert collect(world, m, resp["hold_id"])[1]["result"] == item["preview"]["letters"]


def test_refusing_means_no(world, jsmith, writes):
    m, hold = held(world)
    assert answer(world, jsmith, hold, "refuse")[0] == 200
    assert collect(world, m, hold)[1]["held"]["state"] == "refused"
    assert answer(world, jsmith, hold)[1]["reason_code"] == "HOLD_NOT_WAITING"
    assert writes() == []


@pytest.mark.parametrize("said", ["", "yes", "Approve", "approve ", "approved", "true"])
def test_anything_but_a_clear_answer_is_not_one(world, jsmith, writes, said):
    _, hold = held(world)
    assert answer(world, jsmith, hold, said)[0] == 403
    assert writes() == []


# ------------------------------------------------------------ once


def test_approving_twice_runs_once(world, jsmith, writes):
    _, hold = held(world)
    assert answer(world, jsmith, hold)[0] == 200
    assert answer(world, jsmith, hold)[1]["reason_code"] == "HOLD_NOT_WAITING"
    assert len(writes()) == 1


def test_fifty_approvals_at_once_run_once(world, jsmith, writes):
    _, hold = held(world)
    with ThreadPoolExecutor(25) as pool:
        codes = list(pool.map(lambda _: answer(world, jsmith, hold)[0], range(50)))
    assert codes.count(200) == 1
    assert len(writes()) == 1
    assert [e["reason"] for e in world.entries()].count("RELEASING") == 1


def test_only_one_caller_can_take_a_hold(tmp_path):
    s = Store(tmp_path / "x.db")
    hold = s.hold({}, principal="p", agent_id="a", root="r", until=time.time() + 60)
    with ThreadPoolExecutor(20) as pool:
        assert sum(pool.map(lambda _: s.leave_waiting(hold, "running"), range(50))) == 1


def test_a_crash_part_way_is_shown_as_unknown_and_never_retried(world, jsmith, writes):
    m, hold = held(world)
    assert main.state["store"].leave_waiting(hold, "running")  # approved, and then the gateway died
    with TestClient(main.app, raise_server_exceptions=False) as restarted:
        body = cli.sign_as_person(jsmith, JSMITH, "answer", hold=hold, answer="approve")
        assert restarted.post("/holds/answer", json=body).json()["reason_code"] == "HOLD_NOT_WAITING"
        poll = world.sign("held", m, server="gateway", id=hold)
        assert restarted.post("/tools/call", json=poll).json()["held"]["state"] == "unknown"
    assert writes() == []


# ------------------------------------------------------------ who may answer


def test_the_agent_cannot_approve_itself(world, writes):
    _, hold = held(world)
    status, resp = answer(world, world.key, hold)
    assert (status, resp["reason_code"]) == (403, "APPROVER_NOT_VERIFIED")
    assert writes() == []


def test_another_person_cannot_answer_or_see_it(world, writes):
    priya = world.new_key()
    world.person(
        "officer:priya",
        status="active",
        urns="*",
        clearance=4,
        daily_pupils=300,
        jwk=cli.pub_to_jwk(priya.public_key()),
    )
    _, hold = held(world)
    assert waiting(world, priya, "officer:priya")[1]["holds"] == []
    mine = answer(world, priya, hold, principal="officer:priya")
    nothing = answer(world, priya, "no-such-hold", principal="officer:priya")
    assert mine == nothing  # the same answer, so it does not say whether the hold exists
    assert mine[0] == 403
    assert answer(world, priya, hold, principal=JSMITH)[1]["reason_code"] == "APPROVER_NOT_VERIFIED"
    assert writes() == []


def test_a_signed_answer_cannot_be_replayed_or_moved(world, jsmith, writes):
    _, first = held(world)
    _, second = held(world, value="1_ENG")
    body = cli.sign_as_person(jsmith, JSMITH, "answer", hold=first, answer="refuse")
    assert world.client.post("/holds/answer", json={**body, "answer": "approve"}).status_code == 403
    assert world.client.post("/holds/answer", json={**body, "hold": second}).status_code == 403
    assert world.client.post("/holds/answer", json=body).status_code == 200
    assert world.client.post("/holds/answer", json=body).json()["reason_code"] == "APPROVER_NOT_VERIFIED"
    assert writes() == []


def test_a_signature_for_one_thing_is_not_good_for_another(world, jsmith):
    _, hold = held(world)
    listing = cli.sign_as_person(jsmith, JSMITH, "holds")
    assert world.client.post("/holds/answer", json={**listing, "hold": hold, "answer": "approve"}).status_code == 403
    assert world.client.post("/log", json=listing).status_code in {403, 404}


@pytest.mark.parametrize("ts", [0, 2**40, -1])
def test_a_stale_answer_is_refused(world, jsmith, ts):
    _, hold = held(world)
    assert answer(world, jsmith, hold, over={"ts": ts})[0] == 403


@pytest.mark.parametrize("seconds", [-400, 400])
def test_a_properly_signed_answer_goes_stale(world, jsmith, writes, seconds):
    _, hold = held(world)
    fields, nonce, ts = {"hold": hold, "answer": "approve"}, "n1", int(time.time()) + seconds
    sig = cli.sign_bytes(jsmith, cli.person_message(JSMITH, "answer", nonce, ts, fields))
    body = {"principal": JSMITH, "nonce": nonce, "ts": ts, "sig": sig, **fields}
    assert world.client.post("/holds/answer", json=body).json()["reason_code"] == "APPROVER_NOT_VERIFIED"
    assert writes() == []


def test_someone_who_has_left_cannot_answer(world, jsmith, writes):
    _, hold = held(world)
    world.person(JSMITH, status="left")
    assert answer(world, jsmith, hold)[0] == 403
    assert writes() == []


# ------------------------------------------------------------ everything is checked again at release


def test_revoked_while_waiting(world, jsmith, writes):
    m, idx = world.issue(WRITE, clearance=3)
    _, hold = held(world, m)
    cli.revoke_mandate(world.state, idx)
    assert answer(world, jsmith, hold)[1]["reason_code"] == "REVOKED"
    assert writes() == []
    assert answer(world, jsmith, hold)[1]["reason_code"] == "HOLD_NOT_WAITING"


def test_person_lost_the_school_while_it_waited(world, jsmith, writes):
    _, hold = held(world)
    world.person(JSMITH, urns=["SCH01"])
    assert answer(world, jsmith, hold)[1]["reason_code"] == "PERSON_LOST_ACCESS"
    assert writes() == []


def test_person_lost_clearance_while_it_waited(world, jsmith, writes):
    _, hold = held(world)
    world.person(JSMITH, clearance=2)
    assert answer(world, jsmith, hold)[1]["reason_code"] == "CLEARANCE_TOO_LOW"
    assert writes() == []


def test_approval_does_not_raise_the_clearance(world):
    m = world.mandate(entry("write", urn=["SCH04"]), clearance=3)
    assert world.reason("write", m, **{**ASK, "column": "Ethnicity"}) == "CLEARANCE_TOO_LOW"


def test_nobody_answered_in_time(world, jsmith, writes):
    _, hold = held(world)
    main.state["store"].db.execute("UPDATE holds SET expires = ? WHERE id = ?", (time.time() - 1, hold))
    assert answer(world, jsmith, hold)[1]["reason_code"] == "HOLD_NOT_WAITING"
    assert waiting(world, jsmith)[1]["holds"] == []
    assert writes() == []


def test_a_hold_never_outlives_its_mandate(world):
    m = world.mandate(WRITE, clearance=3, ttl=100)
    _, hold = held(world, m)
    assert main.state["store"].get_hold(hold)["expires"] <= time.time() + 101


def test_the_budget_is_spent_before_anything_is_changed(world, jsmith, writes):
    m = world.mandate(WRITE, clearance=3, budget={"pupils": 0})
    _, hold = held(world, m)
    assert answer(world, jsmith, hold)[1]["reason_code"] == "BUDGET_EXCEEDED"
    assert writes() == []


def test_if_the_record_cannot_be_written_nothing_is_changed(world, jsmith, writes, monkeypatch):
    _, hold = held(world)

    def broken(*_a, **_k):
        raise OSError

    monkeypatch.setattr(main.state["record"], "append", broken)
    assert answer(world, jsmith, hold)[0] == 403
    assert writes() == []


# ------------------------------------------------------------ limits, and who may collect


def test_nobody_is_worn_down_by_a_flood_of_requests(world):
    m = world.mandate(WRITE, clearance=3)
    for i in range(20):
        held(world, m, reason=str(i))
    assert world.reason("write", m, **ASK) == "TOO_MANY_WAITING"


@pytest.mark.parametrize("ids", [[f"P{i:04d}" for i in range(61)], ["P1017", "P1017"], [], "P1017", None])
def test_a_batch_of_letters_has_a_limit(world, ids):
    m = world.mandate(DRAFT, clearance=2)
    assert world.reason("draft", m, urn="SCH04", pupil_ids=ids, kind="absence") == "LIMIT_NOT_ALLOWED"


def test_another_agent_cannot_collect_the_result(world, jsmith):
    m, hold = held(world)
    answer(world, jsmith, hold)
    other = world.new_key()
    status, resp = collect(world, world.mandate(WRITE, key=other, clearance=3), hold, key=other)
    assert status == 403
    assert "result" not in resp
    assert collect(world, world.mandate(WRITE, clearance=3), hold)[0] == 403  # same agent, another job
    assert collect(world, m, hold)[0] == 200


def test_there_is_nothing_else_on_the_gateways_own_server(world):
    m = world.mandate(entry("anything"), clearance=4)
    assert world.reason("anything", m, server="gateway", id="x") == "OUT_OF_SCOPE"
    for bad in (None, 5, [], {}):
        assert world.call("held", m, server="gateway", id=bad)[0] == 403


def test_what_happened_is_recorded_without_the_values(world, jsmith):
    _, hold = held(world)
    answer(world, jsmith, hold)
    reasons = [(e["decision"], e["reason"]) for e in world.entries()]
    assert reasons == [("STEP_UP", "SENSITIVE_TOOL"), ("HELD", "RELEASING"), ("ALLOW", "APPROVED_BY_PERSON")]
    assert world.entries()[-1]["pupils"] == ["P0011"]
    assert world.entries()[-1]["columns"] == ["Language"]
    assert "2_OTH" not in json.dumps(world.entries())


def test_nothing_personal_is_kept_once_it_is_over(world, jsmith):
    m, hold = held(world)
    answer(world, jsmith, hold)
    collect(world, m, hold)
    _, other = held(world)
    answer(world, jsmith, other, "refuse")
    rows = main.state["store"].db.execute("SELECT body, result FROM holds").fetchall()
    assert rows == [("{}", None), ("{}", None)]
