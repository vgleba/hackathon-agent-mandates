"""Is the answer itself sensitive, even though it is only counts? (question 8)

The data's own tool counts rows, and each pupil has about five, so its numbers are too high to be right and too high
to be caught by a small-number check. The gateway privately asks again, grouped by pupil, and counts children.

The limits are the data owner's policy. No mandate can lower them.
"""
from __future__ import annotations

from collections import Counter

from .errors import Reject
from .volume import PUPIL_KEY

SMALLEST = 10   # a figure for fewer pupils than this is hidden, and so is one that leaves fewer than this out
NEAREST = 5     # everything shown is rounded, so that subtracting two answers says little

CENSUS = "personal_data_school_census"
PUBLIC_TABLES = {"schools"}
GROUPS = {"URN", "Gender", "Ethnicity", "AcademicYear", "CensusTerm"}
FILTERS = {"URN", "AcademicYear", "CensusTerm"}
MEASURES = {"FSMeligible", "InCareAtCurrentSchool"}
MOST_SPLITS = 2


def check_shape(arguments: dict) -> None:
    """Before the call: could this question single anyone out?"""
    if arguments.get("table") in PUBLIC_TABLES:
        return
    groups, where = arguments.get("group_by"), arguments.get("where")
    where = {} if where is None else where
    safe = (
        arguments.get("table") == CENSUS
        and arguments.get("measure") in MEASURES
        and isinstance(groups, list)
        and all(isinstance(g, str) for g in groups)
        and set(groups) <= GROUPS
        and isinstance(where, dict)
        and set(where) <= FILTERS
        and all(isinstance(v, str) for v in where.values())
        # one school named in `where` is a split too
        and len(groups) == len(set(groups))
        and len({*groups, *({"URN"} & set(where))}) <= MOST_SPLITS
    )
    if not safe:
        raise Reject("UNSAFE_GROUPING", "this could single someone out; ask by school, year, term, gender or ethnicity")


def counts_pupils(arguments: dict) -> bool:
    return arguments.get("table") not in PUBLIC_TABLES


def by_pupil(arguments: dict) -> dict:
    """The same question with one row per pupil. Its answer never leaves the gateway."""
    return {**arguments, "group_by": [*arguments["group_by"], PUPIL_KEY]}


def rounded(n: int) -> int:
    return NEAREST * ((2 * n + NEAREST) // (2 * NEAREST))


def suppress(rows: list[dict], group_by: list[str]) -> tuple[list[dict], dict]:
    """After the call: hide what is too small, on either side. Zero looks the same as any other small number."""
    everyone, yes = Counter(), Counter()
    for row in rows:
        key = tuple(row[c] for c in group_by)
        everyone[key] += 1
        yes[key] += row["count"] > 0
    out, hidden = [], False
    for key, total in sorted(everyone.items()):
        n = yes[key]
        if total < SMALLEST:
            hidden = True   # left out altogether: listing the group would say that there is someone in it
            continue
        safe = n >= SMALLEST and total - n >= SMALLEST
        hidden |= not safe
        # rounding up must not make part of a group look bigger than the whole
        shown = min(rounded(n), rounded(total)) if safe else None
        out.append({**dict(zip(group_by, key, strict=True)), "total": rounded(total), "count": shown})
    return out, {"unit": "pupils", "smallest": SMALLEST, "rounded_to": NEAREST, "hidden": hidden}
