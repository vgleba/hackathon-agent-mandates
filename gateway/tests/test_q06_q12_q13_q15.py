"""Who granted it, what for, and how sensitive is it? Questions 13, 12, 6 and 15."""

import csv
import json
import random
import shutil

import pytest

from mcp_server.api import routes_mcp

from .conftest import CENSUS, JSMITH, TERM, entry

NEWSLETTER = entry("get", path=["synthetic/synthetic_schools.csv"])
CASTLETON = [
    entry("pupil", "search", urn=["SCH03"]),
    entry("roster", urn=["SCH03"], year_group=[11], **TERM),
]
COUNTS = entry("aggregate", table=[CENSUS])
ROSTER = {"urn": "SCH03", "year_group": 11, "academic_year": "2023/24", "term": "SPR"}
SCHOOLS = [f"SCH{i:02d}" for i in range(1, 13)]
HIDDEN = {"Ethnicity", "InCareAtCurrentSchool"}


# ------------------------------------------------------------ question 6


def test_the_full_record_needs_the_highest_clearance(world):
    args = {"pupil_id": "P1008", "urn": "SCH03"}
    status, resp = world.call("pupil", world.mandate(*CASTLETON, clearance=4), **args)
    assert status == 200
    assert resp["result"]["Psuedo ID"] == "P1008"
    for lower in (1, 2, 3):
        assert world.reason("pupil", world.mandate(*CASTLETON, clearance=lower), **args) == "CLEARANCE_TOO_LOW"


def test_no_clearance_never_means_special_category(world):
    m = world.mandate(*CASTLETON)
    assert world.reason("pupil", m, pupil_id="P1008", urn="SCH03") == "CLEARANCE_TOO_LOW"
    _, resp = world.call("search", m, query="P1008", urn="SCH03")
    assert resp["result"]
    assert all(not HIDDEN & row.keys() for row in resp["result"])


@pytest.mark.parametrize("clearance", [0, 5, -1, "4", 4.0, True, None, [4], {"level": 4}])
def test_a_clearance_that_is_not_1_to_4_is_refused(world, clearance):
    m = world.mandate(*CASTLETON, clearance=clearance)
    assert world.reason("search", m, query="P1008", urn="SCH03") == "CLAIM_NOT_UNDERSTOOD"


def test_a_call_that_touches_two_levels_counts_as_the_higher(world):
    m = world.mandate(COUNTS, clearance=3)
    ok = {"table": CENSUS, "group_by": ["URN"], "measure": "FSMeligible"}
    assert world.call("aggregate", m, **ok)[0] == 200
    for change in ({"measure": "InCareAtCurrentSchool"}, {"group_by": ["URN", "Ethnicity"]}):
        assert world.reason("aggregate", m, **{**ok, **change}) == "CLEARANCE_TOO_LOW", change


def test_a_correction_is_judged_by_its_column(world):
    m = world.mandate(entry("write", urn=["SCH01"]), clearance=3)
    args = {"pupil_id": "P0004", "urn": "SCH01", "value": "x", "reason": "r"}
    assert world.call("write", m, column="Language", **args)[0] == 202
    assert world.reason("write", m, column="Ethnicity", **args) == "CLEARANCE_TOO_LOW"
    assert world.reason("write", m, column="NotAColumn", **args) == "CLEARANCE_TOO_LOW"


@pytest.mark.parametrize(
    "path",
    [
        "synthetic/synthetic_personal_data_school_census.csv",
        "writes/corrections.jsonl",
        "other/synthetic_schools.csv",
        "README.md",
    ],
)
def test_a_file_nobody_has_labelled_counts_as_the_most_sensitive(world, path):
    m = world.mandate(entry("get", path=[path]), clearance=3)
    assert world.reason("get", m, path=path) == "CLEARANCE_TOO_LOW"


def test_relabelling_takes_effect_on_the_next_call(world, tmp_path, monkeypatch):
    root = tmp_path / "data"
    shutil.copytree(routes_mcp.SYNTH_ROOT, root)
    monkeypatch.setattr(routes_mcp, "SYNTH_ROOT", root)
    m = world.mandate(*CASTLETON, clearance=3)
    assert "FSMeligible" in world.call("search", m, query="P1008", urn="SCH03")[1]["result"][0]
    manifest = json.loads((root / "synthetic_manifest.json").read_text())
    manifest["classification"]["columns"][CENSUS]["FSMeligible"] = 4
    del manifest["classification"]["columns"][CENSUS]["Language"]  # a column nobody has labelled
    (root / "synthetic_manifest.json").write_text(json.dumps(manifest))
    row = world.call("search", m, query="P1008", urn="SCH03")[1]["result"][0]
    assert "FSMeligible" not in row
    assert "Language" not in row


def test_if_the_labels_cannot_be_read_nothing_is_released(world, tmp_path, monkeypatch):
    root = tmp_path / "data"
    shutil.copytree(routes_mcp.SYNTH_ROOT, root)
    monkeypatch.setattr(routes_mcp, "SYNTH_ROOT", root)
    (root / "synthetic_manifest.json").write_text("{}")
    status, resp = world.call("search", world.mandate(*CASTLETON), query="P1008", urn="SCH03")
    assert status == 403
    assert "result" not in resp


# ------------------------------------------------------------ question 15


def test_a_newsletter_agent_gets_public_information_only(world):
    m = world.mandate(NEWSLETTER, *CASTLETON, clearance=1)
    assert world.call("get", m, path="synthetic/synthetic_schools.csv")[0] == 200
    assert world.reason("roster", m, **ROSTER) == "CLEARANCE_TOO_LOW"
    _, resp = world.call("search", m, query="2023/24", urn="SCH03")
    assert all(row.keys() <= {"AcademicYear", "CensusTerm", "URN"} for row in resp["result"])


def test_counts_at_clearance_3(world):
    m = world.mandate(COUNTS, clearance=3)
    assert world.call("aggregate", m, table=CENSUS, group_by=["URN"], measure="FSMeligible")[0] == 200
    assert (
        world.reason("aggregate", m, table=CENSUS, group_by=["URN"], measure="InCareAtCurrentSchool")
        == "CLEARANCE_TOO_LOW"
    )


@pytest.mark.parametrize("urn", SCHOOLS)
def test_searching_for_a_hidden_value_finds_nothing(world, urn):
    m = world.mandate(entry("search", urn=[urn]), clearance=3)
    for value in ("ASIA", "BLAC", "MIXD", "WHIT", "CHIN", "AOEG", "UNCL", ",1,2", "0,1,20", ",1,", "0,0"):
        status, resp = world.call("search", m, query=value, urn=urn)
        assert (status, resp.get("result")) == (200, []), (urn, value)


@pytest.mark.parametrize("clearance", [1, 2, 3])
def test_hidden_columns_have_no_effect_on_any_answer(world, tmp_path, monkeypatch, clearance):
    """The strongest form: scramble every hidden value, and no reply may change in any way."""
    m = world.mandate(entry("search", urn=["SCH01"]), clearance=clearance, budget={"pupils": 10_000})
    world.person(JSMITH, daily_pupils=10_000)
    rng = random.Random(clearance)  # noqa: S311
    queries = ["P0004", "SPR", "1_ENG", "2023/24", "F", "M", "15", "ASIA", "WHIT", "0", "1", ",1,2", "C", "P00"]
    queries += ["".join(rng.choice("0123456789PFMCSWHIENGAUR_/,") for _ in range(rng.randint(1, 3))) for _ in range(40)]
    asks = [(q, limit) for q in queries for limit in (1, 100)]

    def replies():
        out = []
        for q, limit in asks:
            status, resp = world.call("search", m, query=q, urn="SCH01", limit=limit)
            out.append((status, resp.get("result"), resp.get("volume"), resp["decision"]["reason_code"]))
        return out

    real = replies()
    root = tmp_path / "data"
    shutil.copytree(routes_mcp.SYNTH_ROOT, root)
    levels = json.loads((root / "synthetic_manifest.json").read_text())["classification"]["columns"][CENSUS]
    file = root / f"synthetic_{CENSUS}.csv"
    with file.open(newline="") as f:
        rows = list(csv.DictReader(f))
    hidden = [c for c in rows[0] if levels[c] > clearance and c != "Psuedo ID"]
    assert hidden
    for row in rows:
        for c in hidden:
            row[c] = rng.choice(["0", "1", "P0004", "SPR", "zz"])
    with file.open("w", newline="") as f:
        w = csv.DictWriter(f, rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    monkeypatch.setattr(routes_mcp, "SYNTH_ROOT", root)
    assert replies() == real


# ------------------------------------------------------------ question 13


def priya(world, **fields):
    world.person(
        "officer:priya", **{"status": "active", "urns": ["SCH05"], "clearance": 4, "daily_pupils": 300, **fields}
    )


def test_an_agent_gets_the_overlap_of_its_mandate_and_its_person(world):
    priya(world)
    m = world.mandate(entry("search", urn=["SCH04", "SCH05"]), principal="officer:priya")
    assert world.call("search", m, query="2023/24", urn="SCH05")[0] == 200
    assert world.reason("search", m, query="2023/24", urn="SCH04") == "PERSON_LOST_ACCESS"
    priya(world, urns=["SCH06"])
    assert world.reason("search", m, query="2023/24", urn="SCH05") == "PERSON_LOST_ACCESS"
    priya(world, status="left")
    assert world.reason("search", m, query="2023/24", urn="SCH05") == "PERSON_PAUSED"


def test_someone_not_on_the_list_is_refused(world):
    priya(world)
    m = world.mandate(entry("search", urn=["SCH05"]), principal="officer:priya")
    everyone = world.people()
    del everyone["officer:priya"]
    (world.state / "people.json").write_text(json.dumps(everyone))
    assert world.reason("search", m, query="2023/24", urn="SCH05") == "PERSON_UNKNOWN"


def test_a_mandate_cannot_be_written_for_someone_not_on_the_list(world):
    with pytest.raises(ValueError, match="nobody:does-not-exist"):
        world.mandate(entry("search", urn=["SCH05"]), principal="nobody:does-not-exist")


@pytest.mark.parametrize("text", ["", "{", "[]", "null", '{"officer:jsmith": null}', '{"officer:jsmith": {}}'])
def test_a_broken_list_of_people_refuses_everyone(world, text):
    m = world.mandate(entry("search", urn=["SCH01"]))
    (world.state / "people.json").write_text(text)
    assert world.call("search", m, query="P0004", urn="SCH01")[0] == 403


def test_a_missing_list_of_people_refuses_everyone(world):
    m = world.mandate(entry("search", urn=["SCH01"]))
    (world.state / "people.json").unlink()
    assert world.call("search", m, query="P0004", urn="SCH01")[0] == 403


def test_a_mandate_cannot_exceed_its_persons_clearance(world):
    priya(world, urns=["SCH03"], clearance=2)
    m = world.mandate(*CASTLETON, principal="officer:priya", clearance=4)
    assert world.reason("pupil", m, pupil_id="P1008", urn="SCH03") == "CLEARANCE_TOO_LOW"
    assert "FSMeligible" not in world.call("search", m, query="P1008", urn="SCH03")[1]["result"][0]


def test_someone_with_one_school_cannot_count_across_all_of_them(world):
    priya(world)
    m = world.mandate(COUNTS, principal="officer:priya")
    ask = {"table": CENSUS, "group_by": ["Gender"], "measure": "FSMeligible"}
    assert world.reason("aggregate", m, **ask) == "PERSON_LOST_ACCESS"
    assert world.reason("aggregate", m, **ask, where={"URN": "SCH04"}) == "PERSON_LOST_ACCESS"
    assert world.call("aggregate", m, **ask, where={"URN": "SCH05"})[0] == 200
    assert (
        world.call(
            "get", world.mandate(NEWSLETTER, principal="officer:priya"), path=NEWSLETTER["constraints"]["path"][0]
        )[0]
        == 200
    )


# ------------------------------------------------------------ question 12


def test_the_same_grant_for_another_purpose_is_refused(world):
    scope = [entry("pupil", urn=["SCH04"]), entry("roster", urn=["SCH04"], year_group=[11], **TERM)]
    args = {"pupil_id": "P0011", "urn": "SCH04"}
    review = world.mandate(*scope, clearance=4, purpose_code="safeguarding_review")
    letters = world.mandate(*scope, clearance=4, purpose_code="absence_letters")
    assert world.call("pupil", review, **args)[0] == 200
    assert world.reason("pupil", letters, **args) == "PURPOSE_MISMATCH"
    assert world.call("roster", letters, **{**ROSTER, "urn": "SCH04"})[0] == 200


def test_the_purpose_caps_the_clearance_and_the_mandate_caps_the_purpose(world):
    scope = entry("pupil", urn=["SCH04"])
    args = {"pupil_id": "P0011", "urn": "SCH04"}
    low = world.mandate(scope, clearance=3, purpose_code="safeguarding_review")
    assert world.reason("pupil", low, **args) == "CLEARANCE_TOO_LOW"
    news = world.mandate(
        entry("get", path=["synthetic/synthetic_display_names.csv"]), clearance=4, purpose_code="newsletter"
    )
    assert world.reason("get", news, path="synthetic/synthetic_display_names.csv") == "CLEARANCE_TOO_LOW"


@pytest.mark.parametrize("code", ["anything", "", None, 5, ["absence_letters"], {"a": 1}])
def test_a_purpose_nobody_has_defined_allows_nothing(world, code):
    m = world.mandate(entry("search", urn=["SCH01"]), purpose_code=code)
    assert world.reason("search", m, query="P0004", urn="SCH01") in {"PURPOSE_MISMATCH", "CLAIM_NOT_UNDERSTOOD"}


def test_what_the_agent_says_about_itself_changes_nothing(world):
    m = world.mandate(entry("pupil", urn=["SCH04"]), clearance=2, purpose_code="absence_letters")
    args = {"pupil_id": "P0011", "urn": "SCH04", "purpose_code": "safeguarding_review", "clearance": 4}
    assert world.call("pupil", m, **args)[0] == 403
