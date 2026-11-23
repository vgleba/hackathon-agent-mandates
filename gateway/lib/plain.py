"""A mandate in plain words, written from the mandate itself (question 10).

The person signs what they were shown, so the words must not be able to disagree with what is signed. Every part of
the mandate is taken out as it is described. If anything is left over, missing or not understood, there is no
description, and whoever is issuing it must not sign.
"""
from __future__ import annotations

import time

from .policy import PURPOSES

STANDARD = {"iss", "jti", "iat", "nbf", "exp", "vct", "delegator", "cnf", "agent_id", "purpose", "scope", "deny",
            "status", "shown"}
OURS = {"clearance", "budget", "purpose_code", "may_delegate", "helpers"}
TERMS = {"AUT": "autumn", "SPR": "spring", "SUM": "summer"}
KINDS = {"absence": "absence", "attendance_meeting": "attendance meeting"}
COLUMNS = {
    "Language": "first language", "FSMeligible": "free school meals", "Gender": "gender",
    "EnrolStatus": "enrolment", "Ethnicity": "ethnic group", "InCareAtCurrentSchool": "care status",
}
VALUES = {
    "Language": {"1_ENG": "English", "2_OTH": "another language"},
    "FSMeligible": {"0": "no", "1": "yes"},
    "Gender": {"F": "F", "M": "M"},
    "EnrolStatus": {"C": "current", "S": "subsidiary"},
    "Ethnicity": {"WHIT": "White", "ASIA": "Asian", "BLAC": "Black", "MIXD": "Mixed", "CHIN": "Chinese",
                  "AOEG": "Any other", "UNCL": "Not given"},
    "InCareAtCurrentSchool": {"0": "no", "1": "yes"},
}
MEASURES = {"FSMeligible": "pupils with free school meals", "InCareAtCurrentSchool": "pupils in care"}
SPLITS = {"URN": "school", "Gender": "gender", "Ethnicity": "ethnic group"}
FILES = {"synthetic/synthetic_schools.csv": "the list of schools"}
DETAIL = {
    1: "Year and term only.",
    2: "Gender, age and enrolment, but not language, free school meals, ethnicity or care status.",
    3: "Gender, age, enrolment, first language and free school meals, but not ethnicity or care status.",
    4: "Everything on the record, ethnicity and care status included.",
}


class CannotDescribe(Exception):
    """Part of the mandate cannot be put into words, so it must not be signed."""


def _join(items: list[str]) -> str:
    items = list(items)
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} and {items[-1]}"


class _Limits:
    """One entry's limits. Each is taken out as it is put into words; finish() checks that nothing is left."""

    def __init__(self, entry: dict):
        if not isinstance(entry, dict) or set(entry) != {"server", "tools", "constraints"}:
            raise CannotDescribe("an entry with fields that are not understood")
        limits = entry["constraints"]
        if entry["server"] != "pupil-data" or not isinstance(limits, dict):
            raise CannotDescribe("an entry that is not understood")
        if not all(isinstance(v, list) and v for v in limits.values()):
            raise CannotDescribe("a limit that is not a list of values")
        self.left = {k: list(v) for k, v in limits.items()}

    def take(self, name: str) -> list:
        if name not in self.left:
            raise CannotDescribe(f"no limit on {name}")
        return self.left.pop(name)

    def one(self, name: str):
        values = self.take(name)
        if len(values) != 1:
            raise CannotDescribe(f"more than one {name}")
        return values[0]

    def named(self, name: str, words: dict) -> str:
        values = self.take(name)
        if not all(isinstance(v, str) and v in words for v in values):
            raise CannotDescribe(f"a {name} that has no name")
        return _join([words[v] for v in values])

    def finish(self) -> None:
        if self.left:
            raise CannotDescribe(f"limits that are not understood: {sorted(self.left)}")


def _when(limits: _Limits) -> str:
    return f"{TERMS[limits.one('term')]} {limits.one('academic_year')}"


def _who(limits: _Limits, name: str, pupils: dict) -> str:
    return limits.named(name, pupils)


def _roster(c, schools, _pupils, _level):
    years = _join([f"Year {y}" for y in c.take("year_group")])
    return f"See the names of {years} pupils at {c.named('urn', schools)} ({_when(c)})"


def _draft(c, schools, pupils, _level):
    kind = KINDS[c.one("kind")]
    count = len(c.left.get("pupil_ids", []))
    who = _who(c, "pupil_ids", pupils)
    letters = "a letter" if count == 1 else f"{count} letters"
    return f"Write {letters} about {kind} at {c.named('urn', schools)}, for: {who}"


def _search(c, schools, pupils, level):
    return f"Look up {_who(c, 'query', pupils)} at {c.named('urn', schools)}. {DETAIL[level]}"


def _pupil(c, schools, pupils, level):
    return f"See the full record of {_who(c, 'pupil_id', pupils)} at {c.named('urn', schools)}. {DETAIL[level]}"


def _aggregate(c, schools, _pupils, _level):
    if c.one("table") != "personal_data_school_census":
        raise CannotDescribe("a table that has no name")
    what, groups, where = MEASURES[c.one("measure")], c.one("group_by"), c.one("where")
    by = "in total" if groups == [] else f"by {_join([SPLITS[g] for g in groups])}"
    where = dict(where)
    at = f" at {schools[where.pop('URN')]}" if "URN" in where else " across all schools"
    year, term = where.pop("AcademicYear", None), where.pop("CensusTerm", None)
    if where or (year is None) != (term is None):
        raise CannotDescribe("a filter that is not understood")
    when = f" in {TERMS[term]} {year}" if year else " over every term on record"
    return f"Count {what} {by}{at}{when}. Numbers only: no names, and small numbers hidden"


def _write(c, schools, pupils, _level):
    column = c.one("column")
    value = VALUES[column][c.one("value")]
    who, where = _who(c, "pupil_id", pupils), c.named("urn", schools)
    return f"Change one thing on {who}'s record at {where}: {COLUMNS[column]} becomes “{value}”"


def _get(c, _schools, _pupils, _level):
    return f"Read {c.named('path', FILES)}. Public information only"


SAY = {"roster": _roster, "draft": _draft, "search": _search, "pupil": _pupil, "aggregate": _aggregate,
       "write": _write, "get": _get}  # fmt: skip


def _whole(value, least: int, most: int) -> int:
    if type(value) is not int or not least <= value <= most:
        raise CannotDescribe("a number that makes no sense")
    return value


def describe(claims: dict, schools: dict[str, str], pupils: dict[str, str]) -> dict[str, list[str]]:
    """{"can", "cannot", "asks", "limits"}, or CannotDescribe. `pupils` is the names the person has chosen."""
    try:
        return _describe(claims, schools, pupils)
    except CannotDescribe:
        raise
    except Exception as e:  # anything it trips over is something it does not understand
        raise CannotDescribe(f"not understood: {type(e).__name__}") from e


def _describe(claims: dict, schools: dict, pupils: dict) -> dict[str, list[str]]:
    if unknown := set(claims) - STANDARD - OURS:
        raise CannotDescribe(f"fields that are not understood: {sorted(unknown)}")
    for needed in ("clearance", "budget", "purpose_code", "exp", "scope"):
        if needed not in claims:
            raise CannotDescribe(f"no {needed}")
    level = _whole(claims["clearance"], 1, 4)
    if set(claims["budget"]) != {"pupils"}:
        raise CannotDescribe("a budget that is not understood")
    budget = _whole(claims["budget"]["pupils"], 0, 1000)
    rule = PURPOSES[claims["purpose_code"]]
    helpers = len(claims["helpers"]) if claims.get("may_delegate") else 0

    can, tools = [], set()
    if not claims["scope"]:
        raise CannotDescribe("nothing it may do")
    for entry in claims["scope"]:
        for tool in entry["tools"]:
            limits = _Limits(entry)
            if tool not in SAY or tool not in rule["tools"]:
                raise CannotDescribe(f"a tool that is not understood: {tool}")
            can.append(SAY[tool](limits, schools, pupils, min(level, rule["max_level"])))
            limits.finish()
            tools.add(tool)

    cannot = []
    if tools <= {"get", "aggregate"}:
        cannot.append("See any pupil's name or record")
    else:
        cannot.append("See anything about any other pupil")
    if "write" not in tools:
        cannot.append("Change any record")
    if "draft" not in tools:
        cannot.append("Write any letter")
    if min(level, rule["max_level"]) < 4:
        cannot.append("See anyone's ethnicity or care status")
    cannot.append("Pass this on to a helper of its own" if not helpers else "Let a helper pass it on again")

    asks = []
    if "draft" in tools:
        asks.append("Before any letter is released. You will see every letter first")
    if "write" in tools:
        asks.append("Before anything is changed. You will see what it says now and what it would become")

    ends = time.strftime("%H:%M on %A %d %B", time.localtime(claims["exp"]))
    limits = [f"Stops when the job is done, or at {ends} at the latest"]
    if budget:
        limits.append(f"At most {budget} pupil{'s' if budget > 1 else ''}")
    if helpers:
        limits.append("May share the work with one helper, which gets only part of this and stops when this stops")
    return {"can": can, "cannot": cannot, "asks": asks, "limits": limits}
