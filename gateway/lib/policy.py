"""Who granted it, what for, and how sensitive is it? (questions 13, 12, 6 and 15)

Three rules run through all of it. Believe the signed mandate, never the request. Missing means least. Check again
on every call, because people leave and labels change.
"""
from __future__ import annotations

import re

from .errors import Reject

MOST_SENSITIVE = 4     # what an unlabelled column, file or tool counts as
SCHOOL_DATA_TOOLS = {"search", "roster", "pupil", "draft", "write", "aggregate"}

# Each purpose names the tools its job needs and the most sensitive data it can justify
PURPOSES = {
    # Explicit compatibility profile: the signed scope is the purpose boundary. New human-facing jobs should use a
    # narrower named purpose below, but no hardened mandate is allowed to omit the claim.
    "scope_only": {
        "tools": {"get", "search", "roster", "draft", "pupil", "aggregate", "write", "classification"},
        "max_level": 4,
    },
    "newsletter": {"tools": {"get"}, "max_level": 1},
    "absence_letters": {"tools": {"roster", "draft"}, "max_level": 2},
    "meeting_letters": {"tools": {"roster", "draft"}, "max_level": 2},
    "find_pupil": {"tools": {"roster", "search"}, "max_level": 3},
    "meals_check": {"tools": {"roster", "search"}, "max_level": 3},
    "pupil_counts": {"tools": {"aggregate"}, "max_level": 4},
    "record_correction": {"tools": {"roster", "search", "write"}, "max_level": 4},
    "safeguarding_review": {"tools": {"roster", "pupil"}, "max_level": 4},
}
TOOL_LEVELS = {"classification": 1, "search": 1, "roster": 2, "draft": 2, "pupil": 4}  # search is stripped instead
DATA_FILE = re.compile(r"synthetic/synthetic_([a-z_]+)\.csv")


class Labels:
    """The data's own sensitivity labels, as its `classification` tool gives them right now."""

    def __init__(self, classification: dict):
        self.tables = dict(classification["tables"])
        self.columns: dict[str, int] = {}
        for table in classification["columns"].values():
            for column, level in table.items():
                self.columns[column] = max(level, self.columns.get(column, 0))
        if not self.tables or not self.columns:
            raise ValueError("no labels")

    def column(self, name) -> int:
        return self.columns.get(name, MOST_SENSITIVE) if isinstance(name, str) else MOST_SENSITIVE

    def file(self, path) -> int:
        if path == "synthetic/synthetic_manifest.json":
            return 1
        named = DATA_FILE.fullmatch(path) if isinstance(path, str) else None
        return self.tables.get(named[1], MOST_SENSITIVE) if named else MOST_SENSITIVE


def whole_number(claims: dict, name: str, value, least: int, most: int) -> int:
    if type(value) is not int or not least <= value <= most:  # True is an int to isinstance()
        raise Reject("CLAIM_NOT_UNDERSTOOD", f"{name} must be a whole number from {least} to {most}", claims)
    return value


def needed_level(tool: str, arguments: dict, labels: Labels) -> int:
    """The most sensitive label this call would touch, worked out before it runs."""
    if tool == "aggregate":
        groups, where = arguments.get("group_by"), arguments.get("where") or {}
        if not isinstance(groups, list) or not isinstance(where, dict):
            return MOST_SENSITIVE
        return max(labels.column(c) for c in [*groups, arguments.get("measure"), *where])
    if tool == "get":
        return labels.file(arguments.get("path"))
    if tool == "write":
        return labels.column(arguments.get("column"))
    return TOOL_LEVELS.get(tool, MOST_SENSITIVE)


def check_person(people, claims: dict, tool: str, arguments: dict, need: int) -> dict:
    """The person who granted this, as they are now: still here, and still covering this school."""
    who = claims["delegator"]["principal"]
    person = people.get(who) if isinstance(people, dict) else None
    if not isinstance(person, dict):
        raise Reject("PERSON_UNKNOWN", who)
    if person.get("status") != "active":
        raise Reject("PERSON_PAUSED", f"{who} is {person.get('status', 'not active')}")
    urns = person.get("urns", [])
    if urns != "*":
        where = arguments.get("where")
        urn = arguments.get("urn", where.get("URN") if isinstance(where, dict) else None)
        if urn is None and (tool in SCHOOL_DATA_TOOLS or need > 1):
            raise Reject("PERSON_LOST_ACCESS", f"this covers schools {who} does not")
        if urn is not None and (not isinstance(urn, str) or urn not in urns):
            raise Reject("PERSON_LOST_ACCESS", f"{who} does not cover that school")
    return person


def clearance_for(claims: dict, person: dict, tool: str) -> int:
    """The lowest of what the mandate, its purpose and its person allow."""
    levels = [whole_number(claims, "clearance", claims.get("clearance"), 1, MOST_SENSITIVE)]
    code = claims.get("purpose_code")
    rule = PURPOSES.get(code) if isinstance(code, str) else None
    if rule is None or tool not in rule["tools"]:
        raise Reject("PURPOSE_MISMATCH", f"this access is for {code!r}, which does not need {tool}")
    levels.append(rule["max_level"])
    levels.append(whole_number(claims, "the person's clearance", person.get("clearance"), 1, MOST_SENSITIVE))
    return min(levels)


def check_clearance(clearance: int, need: int) -> None:
    if need > clearance:
        raise Reject("CLEARANCE_TOO_LOW", f"this needs level {need} and the access is level {clearance}")


def check_epoch(claims: dict, person: dict) -> None:
    """An authority change permanently invalidates grants from the previous principal epoch."""
    current, granted = person.get("authz_epoch"), claims.get("principal_epoch")
    if type(current) is not int or current < 1 or type(granted) is not int or granted != current:
        raise Reject("PERSON_AUTHORITY_CHANGED", "the person's authority changed; issue a new mandate")


def budgets(claims: dict, person: dict, day: str) -> list[tuple[str, int]]:
    """Both must have room: the job's, which helpers share, and the person's for today."""
    claim = claims.get("budget")
    if not isinstance(claim, dict):
        raise Reject("CLAIM_NOT_UNDERSTOOD", "budget must say how many pupils")
    job = whole_number(claims, "budget", claim.get("pupils"), 0, 1_000_000)
    daily = whole_number(claims, "the person's daily limit", person.get("daily_pupils"), 0, 1_000_000)
    who = claims["delegator"]["principal"]
    return [(f"job:{claims['root']}", job), (f"person:{who}:{day}", daily)]


def see_only(rows: list[dict], clearance: int, labels: Labels) -> list[dict]:
    return [{c: v for c, v in row.items() if labels.column(c) <= clearance} for row in rows]


def search_visible(rows: list[dict], query: str, clearance: int, labels: Labels) -> list[dict]:
    """The rows in which a cell the agent may see contains the query.

    Searching hidden columns would give them away: the agent would never see the value, but the pattern of which
    rows come back would say it.
    """
    wanted = query.lower()
    shown = [c for c in (rows[0] if rows else ()) if labels.column(c) <= clearance]
    return [row for row in rows if any(wanted in str(row[c]).lower() for c in shown)]
