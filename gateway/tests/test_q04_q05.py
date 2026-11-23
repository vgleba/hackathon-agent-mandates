"""Question 4: the same file written differently. Question 5: does any part of the mandate allow this?"""

import pytest

from gateway.lib import paths

from .conftest import entry

SCHOOLS, MANIFEST = "synthetic/synthetic_schools.csv", "synthetic/synthetic_manifest.json"
NAMES = "synthetic/synthetic_display_names.csv"


@pytest.fixture
def files(world):
    return world.mandate(entry("get", path=[SCHOOLS, MANIFEST]))


# ------------------------------------------------------------ question 4


@pytest.mark.parametrize(
    "path", [SCHOOLS, "./" + SCHOOLS, "synthetic//synthetic_schools.csv", "./synthetic/.//./synthetic_schools.csv"]
)
def test_other_spellings_of_an_allowed_file_are_allowed(world, files, path):
    status, resp = world.call("get", files, path=path)
    assert (status, len(resp["result"])) == (200, 12)


@pytest.mark.parametrize(
    "path",
    [
        "synthetic/../synthetic/synthetic_schools.csv",  # harmless here, but ".." has no honest use
        "synthetic/../" + NAMES,
        "../mcp_server/data/" + SCHOOLS,
        "/" + SCHOOLS,
        "//" + SCHOOLS,
        "synthetic\\synthetic_schools.csv",
        "C:" + SCHOOLS,
        SCHOOLS + "::$DATA",
        SCHOOLS + ".",
        SCHOOLS + " ",
        " " + SCHOOLS,
        SCHOOLS + "\x00",
        SCHOOLS + "\n",
        "synthetic/synthetic_schools.csv/",
        "synthetic./synthetic_schools.csv",
        "",
        ".",
        "./",
        SCHOOLS + chr(0x202E),  # right-to-left override
        f"synthetic/{chr(0xFF0E) * 2}/synthetic_schools.csv",  # full-width dots
    ],
)
def test_odd_spellings_are_refused(world, files, path):
    status, resp = world.call("get", files, path=path)
    assert status == 403, path
    assert resp["decision"]["reason_code"] in {"PATH_NOT_ALLOWED", "CONSTRAINT_VIOLATED"}


@pytest.mark.parametrize(
    "path",
    [
        "a\\b",
        "C:" + SCHOOLS,
        SCHOOLS + "::$DATA",
        SCHOOLS + " ",
        SCHOOLS + "\x00",
        SCHOOLS + "\n",
        "a/../b",
        "/a",
        "a.",
        "a/",
        "",
    ],
)
def test_odd_spellings_are_refused_even_when_the_mandate_allows_any_file(world, path):
    # here nothing else would catch them: there is no list of allowed files to fail to match
    m = world.mandate(entry("get"), clearance=4)
    assert world.reason("get", m, path=path) == "PATH_NOT_ALLOWED"


@pytest.mark.parametrize("path", [None, 5, True, [SCHOOLS], {"a": 1}])
def test_a_path_that_is_not_text_is_refused(world, files, path):
    assert world.call("get", files, path=path)[0] == 403


def test_the_names_file_stays_out_of_reach(world, files):
    for path in (NAMES, "./" + NAMES, "synthetic//synthetic_display_names.csv", "SYNTHETIC/synthetic_schools.csv"):
        assert world.reason("get", files, path=path) == "CONSTRAINT_VIOLATED"


def test_a_folder_or_pattern_in_a_mandate_grants_nothing(world):
    m = world.mandate(entry("get", path=["synthetic/*", "synthetic", "synthetic/*.csv"]))
    assert world.reason("get", m, path=SCHOOLS) == "CONSTRAINT_VIOLATED"


def test_what_was_checked_is_what_is_opened():
    assert paths.clean("./a//b/./c.csv") == "a/b/c.csv"
    assert paths.clean("a/../b") is None


# ------------------------------------------------------------ question 5


def test_any_entry_can_allow(world):
    m = world.mandate(entry("search", urn=["SCH01"]), entry("search", urn=["SCH02"]))
    assert world.call("search", m, query="SPR", urn="SCH01")[0] == 200
    assert world.call("search", m, query="SPR", urn="SCH02")[0] == 200
    assert world.reason("search", m, query="SPR", urn="SCH03") == "CONSTRAINT_VIOLATED"


def test_two_entries_cannot_be_mixed(world):
    # Year 11 at SCH04, or any year at SCH05. Not: any year at SCH04
    m = world.mandate(
        entry("roster", urn=["SCH04"], year_group=[11], academic_year=["2023/24"]),
        entry("roster", urn=["SCH05"], year_group=[10, 11], academic_year=["2022/23"]),
    )
    ok = {"urn": "SCH04", "year_group": 11, "academic_year": "2023/24"}
    assert world.call("roster", m, **ok)[0] == 200
    for change in ({"year_group": 10}, {"academic_year": "2022/23"}, {"urn": "SCH05"}):
        assert world.call("roster", m, **{**ok, **change})[0] == 403, change


def test_the_reason_comes_from_the_closest_entry(world):
    m = world.mandate(
        entry("roster", urn=["SCH04"], year_group=[10], academic_year=["2021/22"]),
        entry("roster", urn=["SCH05"], year_group=[11], academic_year=["2023/24"]),
    )
    _, resp = world.call("roster", m, urn="SCH05", year_group=11, academic_year="2022/23")
    assert resp["decision"]["detail"] == "academic_year='2022/23'"


def test_an_entry_for_another_tool_does_not_help(world):
    m = world.mandate(entry("search", urn=["SCH01"]), entry("get", path=[SCHOOLS]))
    assert world.reason("get", m, path=NAMES) == "CONSTRAINT_VIOLATED"
    assert world.reason("roster", m, urn="SCH01", year_group=11) == "OUT_OF_SCOPE"


# ------------------------------------------------------------ lists: limited item by item


def test_every_item_of_a_list_must_be_allowed(world):
    m = world.mandate(entry("draft", urn=["SCH04"], pupil_ids=["P1017", "P1018"]), clearance=2)
    ok = {"urn": "SCH04", "kind": "absence"}
    assert world.call("draft", m, pupil_ids=["P1017"], **ok)[0] == 202
    for ids in (["P1017", "P0011"], ["P0011"], [], "P1017P1018", [["P1017"]], [True], {"P1017": 1}):
        assert world.call("draft", m, pupil_ids=ids, **ok)[0] == 403, ids
