"""Question 16: can the person see what was done in their name, and only that?"""

import pytest

from gateway import cli
from gateway.lib import record
from gateway.lib.common import priv_from_pem

from .conftest import JSMITH, entry

SEARCH = entry("search", urn=["SCH01"])
PRIYA = "officer:priya"


@pytest.fixture
def jsmith(world):
    return cli.load_or_create_key(world.state / "person_officer_jsmith.pem")


@pytest.fixture
def priya(world):
    cli.set_person(world.state, PRIYA, name="Priya", status="active", urns=["SCH05"], clearance=4, daily_pupils=300)
    return cli.person_key(world.state, PRIYA)


def ask(world, path, key, do, principal=JSMITH, *, over=None, **fields):
    r = world.client.post(path, json={**cli.sign_as_person(key, principal, do, **fields), **(over or {})})
    return r.status_code, r.json()


def log(world, key, principal=JSMITH, **kw):
    return ask(world, "/log", key, "log", principal, **kw)


def test_the_person_sees_their_own_entries_and_only_those(world, jsmith, priya):
    world.call("search", world.mandate(SEARCH), query="P0004", urn="SCH01")
    world.call("search", world.mandate(entry("search", urn=["SCH05"]), principal=PRIYA), query="2023/24", urn="SCH05")
    mine, hers = log(world, jsmith)[1]["entries"], log(world, priya, PRIYA)[1]["entries"]
    assert [e["args"]["urn"] for e in mine] == ["SCH01"]
    assert [e["args"]["urn"] for e in hers] == ["SCH05"]
    assert mine[0]["source"] == "testclient"
    assert mine[0]["agent_id"]
    assert not {"hash", "sig", "prev", "principal"} & mine[0].keys()


def test_asking_for_someone_elses_log_is_refused(world, priya):
    assert log(world, priya, JSMITH)[1]["reason_code"] == "LOG_READER_NOT_VERIFIED"
    body = cli.sign_as_person(priya, PRIYA, "log")
    r = world.client.post("/log", json={**body, "principal": JSMITH})
    assert (r.status_code, r.json()["reason_code"]) == (403, "LOG_READER_NOT_VERIFIED")


def test_a_thief_with_the_agent_key_and_mandate_gets_no_log(world):
    assert log(world, world.key)[1]["reason_code"] == "LOG_READER_NOT_VERIFIED"


def test_a_made_up_person_gets_no_log(world):
    assert log(world, world.new_key(), "officer:nobody")[0] == 403


def test_a_signed_request_for_the_log_works_once(world, jsmith):
    body = cli.sign_as_person(jsmith, JSMITH, "log")
    assert world.client.post("/log", json=body).status_code == 200
    assert world.client.post("/log", json=body).status_code == 403


@pytest.mark.parametrize("ts", [0, 10**11, -(10**400), 2**63])
def test_an_old_or_odd_request_is_refused(world, jsmith, ts):
    assert log(world, jsmith, over={"ts": ts})[0] in {403, 422}


def test_use_without_the_key_shows_up_as_an_alarm(world, jsmith):
    world.reason("search", world.mandate(SEARCH), key=world.new_key(), query="P0004", urn="SCH01")
    (e,) = log(world, jsmith)[1]["entries"]
    assert e["reason"] == "POP_FAILED"


def test_rubbish_cannot_be_put_in_someones_log(world, jsmith):
    for junk in ("x", "a.b.c", ""):
        world.call("search", junk, query="x", urn="SCH01")
    assert log(world, jsmith)[1]["entries"] == []


def test_the_summary_and_the_check_are_in_the_reply(world, jsmith):
    world.call("search", world.mandate(SEARCH), query="P0004", urn="SCH01")
    reply = log(world, jsmith)[1]
    assert reply["check"] == "ok"
    assert reply["summary"]["pupils"] == ["P0004"]
    assert reply["head"]["seq"] == 1
    assert log(world, jsmith, seq=1)[1]["hash_at"] == reply["head"]["hash"]
    assert log(world, jsmith, seq=99)[1]["hash_at"] is None


@pytest.mark.usefixtures("priya")
def test_names_are_given_only_for_pupils_in_your_own_entries(world, jsmith):
    world.call("search", world.mandate(SEARCH), query="P0004", urn="SCH01")
    world.call("search", world.mandate(entry("search", urn=["SCH05"]), principal=PRIYA), query="2023/24", urn="SCH05")
    assert set(log(world, jsmith, names=True)[1]["names"]) == {"P0004"}
    assert "names" not in log(world, jsmith)[1]


def test_one_job_at_a_time(world, jsmith):
    first, second = world.mandate(SEARCH), world.mandate(SEARCH)
    world.call("search", first, query="P0004", urn="SCH01")
    world.call("search", second, query="P0004", urn="SCH01")
    root = world.entries()[0]["root"]
    assert len(log(world, jsmith, root=root)[1]["entries"]) == 1


# ------------------------------------------------------------ the person's own lookups


def test_a_person_can_list_their_own_schools_and_classes(world, jsmith, priya):
    assert len(ask(world, "/person/schools", jsmith, "schools")[1]["schools"]) == 12
    assert list(ask(world, "/person/schools", priya, "schools", PRIYA)[1]["schools"]) == ["SCH05"]
    status, resp = ask(world, "/person/class", priya, "class", PRIYA, urn="SCH05", year=11)
    assert (status, len(resp["pupils"])) == (200, 38)


def test_a_person_cannot_list_a_class_they_do_not_cover(world, priya):
    assert (
        ask(world, "/person/class", priya, "class", PRIYA, urn="SCH04", year=11)[1]["reason_code"]
        == "PERSON_LOST_ACCESS"
    )


def test_an_agent_cannot_list_a_class(world):
    assert ask(world, "/person/class", world.key, "class", urn="SCH05", year=11)[0] == 403


def test_a_persons_own_lookup_is_recorded_too(world, jsmith):
    ask(world, "/person/class", jsmith, "class", urn="SCH05", year=11)
    e = world.entries()[-1]
    assert (e["principal"], e["reason"], len(e["pupils"])) == (JSMITH, "PERSON_LOOKUP", 38)


@pytest.mark.parametrize(
    "bad", [{"urn": "SCH05", "year": 9}, {"urn": "SCH99", "year": 11}, {"urn": "", "year": 11}, {"year": 11}]
)
def test_an_odd_lookup_is_refused(world, jsmith, bad):
    assert ask(world, "/person/class", jsmith, "class", **bad)[0] == 403


# ------------------------------------------------------------ checking the record from outside the gateway


def test_the_cli_checks_the_record_against_an_anchor(world, capsys):
    for _ in range(3):
        world.call("search", world.mandate(SEARCH), query="P0004", urn="SCH01")
    cli.main(["--state", str(world.state), "log-anchor"])
    anchor = capsys.readouterr().out.strip()
    cli.main(["--state", str(world.state), "log-check", "--anchor", anchor])
    assert capsys.readouterr().out.strip() == "ok"
    path = world.state / "record.jsonl"
    path.write_text("\n".join(path.read_text().splitlines()[:1]) + "\n")
    with pytest.raises(SystemExit):
        cli.main(["--state", str(world.state), "log-check", "--anchor", anchor])
    assert record.check(path, priv_from_pem((world.state / "gateway_key.pem").read_bytes()).public_key()) == "ok"
