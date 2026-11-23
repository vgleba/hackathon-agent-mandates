"""Question 8: is the answer itself sensitive? Question 11: every call is allowed, but is the whole run?"""

import itertools
from concurrent.futures import ThreadPoolExecutor

import pytest

from gateway.lib.store import Full, Store

from .conftest import CENSUS, JSMITH, entry

SPRING = {"AcademicYear": "2023/24", "CensusTerm": "SPR"}


@pytest.fixture
def counts(world):
    return world.mandate(entry("aggregate", table=[CENSUS]), clearance=4)


def count(world, m, group_by, measure="FSMeligible", **kw):
    status, resp = world.call("aggregate", m, table=CENSUS, group_by=group_by, measure=measure, **kw)
    assert status == 200, resp
    return resp


# ------------------------------------------------------------ question 8: what may be asked


@pytest.mark.parametrize(
    "change",
    [
        {"group_by": ["Psuedo ID"]},
        {"group_by": ["URN", "Psuedo ID"]},
        {"group_by": ["InCareAtCurrentSchool"]},
        {"group_by": ["FSMeligible"]},
        {"group_by": ["Language"]},
        {"group_by": ["URN", "Gender", "Ethnicity"]},
        {"group_by": ["URN", "URN"]},
        {"group_by": ["URN", "NotAColumn"]},
        {"group_by": "URN"},
        {"group_by": [["URN"]]},
        {"group_by": ["Gender", "Ethnicity"], "where": {"URN": "SCH07"}},  # three splits by another name
        {"where": {"Psuedo ID": "P0011"}},
        {"where": {"InCareAtCurrentSchool": "1"}},
        {"where": {"Ethnicity": "ASIA"}},
        {"where": {"URN": ["SCH01"]}},
        {"where": [["URN", "SCH01"]]},
        {"where": "URN=SCH01"},
        {"measure": "Psuedo ID"},
        {"measure": "Ethnicity"},
        {"measure": None},
        {"table": "display_names", "group_by": ["DisplayName"], "measure": "Gender"},
        {"table": "personal_data_deprivation", "group_by": ["DeprivationDecile"], "measure": "HomeArea"},
    ],
)
def test_a_question_that_could_single_someone_out_is_refused(world, change):
    m = world.mandate(entry("aggregate"), clearance=4)
    ask = {"table": CENSUS, "group_by": ["URN"], "measure": "FSMeligible", **change}
    status, resp = world.call("aggregate", m, **ask)
    assert status == 403, (change, resp)
    assert resp["decision"]["reason_code"] in {"UNSAFE_GROUPING", "CLEARANCE_TOO_LOW"}


def test_the_evals_own_counts_mandate_no_longer_leaks(world):
    # it fixes only the measure, so one pupil's ethnicity and care status could be read through group_by and where
    m = world.mandate(entry("aggregate", table=[CENSUS], measure=["FSMeligible"]))
    ask = {"table": CENSUS, "measure": "FSMeligible"}
    for leak in (
        {"group_by": ["Ethnicity", "InCareAtCurrentSchool"], "where": {"Psuedo ID": "P0011"}},
        {"group_by": ["URN"], "where": {"Psuedo ID": "P0011"}},
    ):
        assert world.call("aggregate", m, **ask, **leak)[0] == 403


# ------------------------------------------------------------ question 8: what comes back


def test_children_are_counted_not_rows(world, counts):
    ashfield = next(r for r in count(world, counts, ["URN"])["result"] if r["URN"] == "SCH01")
    assert ashfield == {"URN": "SCH01", "total": 125, "count": 25}  # 124 pupils and 27, from 617 rows and 133


def test_one_term_at_dunmore(world, counts):
    resp = count(world, counts, ["URN"], where=SPRING)
    dunmore = next(r for r in resp["result"] if r["URN"] == "SCH04")
    assert dunmore == {"URN": "SCH04", "total": 40, "count": 15}  # 14 of 41
    assert resp["disclosure"] == {"unit": "pupils", "smallest": 10, "rounded_to": 5, "hidden": True}


def test_pupils_in_care_by_school_and_ethnic_group_shows_no_numbers(world, counts):
    for where in (SPRING, None):
        resp = count(world, counts, ["URN", "Ethnicity"], "InCareAtCurrentSchool", where=where)
        assert all(r["count"] is None for r in resp["result"])
        assert resp["disclosure"]["hidden"] is True


def test_pupils_in_care_by_school_shows_no_numbers(world, counts):
    assert all(r["count"] is None for r in count(world, counts, ["URN"], "InCareAtCurrentSchool")["result"])


def test_the_total_in_care_shows_only_when_it_is_large_enough(world, counts):
    assert count(world, counts, [], "InCareAtCurrentSchool")["result"] == [{"total": 1500, "count": 15}]  # 14
    this_term = count(world, counts, [], "InCareAtCurrentSchool", where=SPRING)
    assert this_term["result"] == [{"total": 480, "count": None}]  # 7


def test_nothing_small_is_ever_shown_whatever_is_asked(world, counts):
    groups = ["URN", "Gender", "Ethnicity", "AcademicYear", "CensusTerm"]
    wheres = [None, SPRING, {"AcademicYear": "2021/22"}, {"CensusTerm": "SUM"}]
    asked = 0
    for n in (0, 1, 2):
        for group_by in itertools.combinations(groups, n):
            for where, measure in itertools.product(wheres, ("FSMeligible", "InCareAtCurrentSchool")):
                for r in count(world, counts, list(group_by), measure, where=where)["result"]:
                    assert r["total"] >= 10
                    assert r["total"] % 5 == 0
                    assert r["count"] is None or (10 <= r["count"] <= r["total"] and r["count"] % 5 == 0)
                asked += 1
    assert asked == 128


def test_a_group_too_small_to_show_is_left_out_not_listed(world, counts):
    # listing "Ashfield, CHIN: fewer than 10" would say that there is someone
    shown = {(r["URN"], r["Ethnicity"]) for r in count(world, counts, ["URN", "Ethnicity"])["result"]}
    assert ("SCH01", "WHIT") in shown
    assert not any(e == "CHIN" for _, e in shown)


def test_a_count_with_nearly_everyone_in_it_is_hidden_too():
    from gateway.lib import disclosure  # noqa: PLC0415

    rows = [{"URN": "SCH01", "Psuedo ID": f"P{i}", "total": 1, "count": int(i < 38)} for i in range(41)]
    out, _ = disclosure.suppress(rows, ["URN"])
    assert out == [{"URN": "SCH01", "total": 40, "count": None}]


def test_the_public_list_of_schools_can_be_counted_as_it_is(world):
    m = world.mandate(entry("aggregate"), clearance=1)
    resp = world.call("aggregate", m, table="schools", group_by=["SchoolLA"], measure="URN")
    assert resp[0] == 200
    assert resp[1]["result"] == [{"SchoolLA": "SYN", "total": 12, "count": 0}]


# ------------------------------------------------------------ question 11

ELMWOOD = [entry("roster", urn=["SCH05"], year_group=[11]), entry("search", urn=["SCH05"])]
YEAR_11 = {"urn": "SCH05", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}


def ids(resp):
    return [r["Psuedo ID"] for r in resp["result"]]


def test_the_whole_job_is_allowed_and_then_it_stops(world):
    m = world.mandate(*ELMWOOD, clearance=3, budget={"pupils": 45})
    _, resp = world.call("roster", m, **YEAR_11)
    year_11 = ids(resp)
    assert len(year_11) == 38
    meals = 0
    for p in year_11:
        status, resp = world.call("search", m, query=p, urn="SCH05")
        assert status == 200
        meals += resp["result"][0]["FSMeligible"] == "1"
    assert meals == 12
    more, stopped = 0, None
    for n in range(1, 1500):
        status, resp = world.call("search", m, query=f"P{n:04d}", urn="SCH05")
        if status != 200:
            stopped = resp["decision"]["reason_code"]
            break
        more += 1
    assert (more, stopped) == (7, "BUDGET_EXCEEDED")
    assert "result" not in resp
    assert world.call("search", m, query=year_11[0], urn="SCH05")[0] == 200  # pupils already seen cost nothing


def test_an_answer_that_would_pass_the_limit_releases_nothing_and_spends_nothing(world):
    m = world.mandate(*ELMWOOD, clearance=3, budget={"pupils": 20})
    assert world.reason("roster", m, **YEAR_11) == "BUDGET_EXCEEDED"
    assert world.entries()[-1]["pupils"] == []
    assert world.call("search", m, query="2023/24", urn="SCH05")[0] == 200


def test_asking_about_a_pupil_who_is_not_there_still_counts(world):
    # an empty answer says "not at Elmwood", which is something
    m = world.mandate(*ELMWOOD, budget={"pupils": 3})
    for i in range(3):
        status, resp = world.call("search", m, query=f"p000{i}", urn="SCH05")
        assert (status, resp["result"]) == (200, [])
    assert world.reason("search", m, query="P0009", urn="SCH05") == "BUDGET_EXCEEDED"


def test_asking_for_a_full_record_counts_even_when_it_is_empty(world):
    m = world.mandate(entry("pupil", urn=["SCH05"]), clearance=4, budget={"pupils": 1})
    assert world.call("pupil", m, pupil_id="P0001", urn="SCH05")[1]["result"] == {}
    assert world.reason("pupil", m, pupil_id="P0002", urn="SCH05") == "BUDGET_EXCEEDED"


def test_a_mandate_with_no_budget_gets_the_default(world):
    m = world.mandate(entry("roster", urn=["SCH11"]), clearance=2)
    ask = {"urn": "SCH11", "year_group": 11, "term": "SPR"}
    assert world.call("roster", m, **ask, academic_year="2023/24")[0] == 200
    assert world.reason("roster", m, **ask, academic_year="2022/23") == "BUDGET_EXCEEDED"


def test_a_persons_day_is_one_budget_across_all_their_mandates(world):
    world.person(JSMITH, daily_pupils=60)
    first = world.mandate(entry("roster", urn=["SCH05"]), clearance=2)
    second = world.mandate(entry("roster", urn=["SCH04"]), key=world.new_key(), clearance=2)
    assert world.call("roster", first, **YEAR_11)[0] == 200
    key = world.new_key()
    second = world.mandate(entry("roster", urn=["SCH04"]), key=key, clearance=2)
    status, resp = world.call("roster", second, key=key, **{**YEAR_11, "urn": "SCH04"})
    assert (status, resp["decision"]["reason_code"]) == (403, "BUDGET_EXCEEDED")


@pytest.mark.parametrize("budget", [{"pupils": -1}, {"pupils": "45"}, {"pupils": True}, {}, 45, None, [45]])
def test_a_budget_that_makes_no_sense_is_refused(world, budget):
    m = world.mandate(*ELMWOOD, budget=budget)
    assert world.reason("search", m, query="P1008", urn="SCH05") == "CLAIM_NOT_UNDERSTOOD"


def test_the_budget_survives_a_restart(tmp_path):
    s = Store(tmp_path / "x.db")
    s.spend([("job:a", 3)], {"P1", "P2"})
    s.close()
    s = Store(tmp_path / "x.db")
    with pytest.raises(Full):
        s.spend([("job:a", 3)], {"P3", "P4"})
    assert s.used("job:a") == 2


def test_two_calls_at_once_cannot_both_take_the_last_place(tmp_path):
    s = Store(tmp_path / "x.db")

    def go(i):
        try:
            s.spend([("job:a", 10), ("person:x", 10)], {f"P{i}"})
        except Full:
            return False
        return True

    with ThreadPoolExecutor(20) as pool:
        won = sum(pool.map(go, range(200)))
    assert (won, s.used("job:a"), s.used("person:x")) == (10, 10, 10)


def test_two_connections_cannot_both_take_the_last_place(tmp_path):
    # as two gateway processes on one file would be: only the database's own lock is left to stop them
    stores = [Store(tmp_path / "x.db") for _ in range(4)]

    def go(i):
        try:
            stores[i % 4].spend([("job:a", 10)], {f"P{i}"})
        except Full:
            return False
        return True

    with ThreadPoolExecutor(16) as pool:
        won = sum(pool.map(go, range(200)))
    assert (won, stores[0].used("job:a")) == (10, 10)


def test_all_meters_or_none(tmp_path):
    s = Store(tmp_path / "x.db")
    with pytest.raises(Full):
        s.spend([("job:a", 100), ("person:x", 1)], {"P1", "P2"})
    assert (s.used("job:a"), s.used("person:x")) == (0, 0)
