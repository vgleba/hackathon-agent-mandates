"""How much data one call may release (question 3: right school, but how much is too much?).

A mandate says which school. These limits are gateway policy and say how much, in three layers:

    1. check_arguments  before the call: refuse a blank query or a limit that is not a whole number in range
    2. is_blanket       after the call, before release: refuse a search that narrows nothing
    3. release          on release: never more than MAX_PUPILS different pupils, and say when an answer was cut

Layer 2 catches intent: ",", "P" and the school's own URN match every row just as "" does, and no list of bad
queries would be complete. Layer 3 is the guarantee: it holds for queries nobody anticipated.

Each call is judged on its own. Many small calls can still add up to a school (question 11).
"""

from __future__ import annotations

MAX_PUPILS = 10  # different pupils in one response
MAX_LIMIT = 100  # rows an agent may ask for; also what it gets when it does not say
BLANKET_SHARE = 0.9  # a search matching this share of the records in its scope is not a search
EVERY_ROW = 10_000  # bounded full authorized scope, counted before the gateway releases any rows

MAX_LETTERS = 60  # pupils in one batch of letters: more than the largest year group, which is 54

GOVERNED_TOOLS = frozenset({"search", "get"})
PUPIL_KEY = "Psuedo ID"  # the data's own spelling


def check_arguments(tool: str, arguments: dict) -> tuple[str, str] | None:
    """Layer 1. Returns (reason_code, detail) to refuse, or None. Touches no data."""
    if tool == "draft":
        ids = arguments.get("pupil_ids")
        if (
            not isinstance(ids, list)
            or not all(isinstance(i, str) for i in ids)
            or len(set(ids)) != len(ids)
            or not 1 <= len(ids) <= MAX_LETTERS
        ):
            return "LIMIT_NOT_ALLOWED", f"a batch of letters is for 1 to {MAX_LETTERS} different pupils"
    if tool not in GOVERNED_TOOLS:
        return None
    if "limit" in arguments:
        limit = arguments["limit"]
        # type() and not isinstance(): True is an int, and the MCP server turns "1000" and 1000.0 into 1000
        if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
            return "LIMIT_NOT_ALLOWED", f"limit must be a whole number from 1 to {MAX_LIMIT}"
    if tool == "search":
        query = arguments.get("query")
        if not isinstance(query, str) or not query.strip():
            return "QUERY_TOO_BROAD", "query must say what to look for"
    return None


def is_blanket(matched: int, total: int) -> bool:
    """Layer 2. Does a search return (nearly) everything its scope holds?"""
    return total > 0 and matched >= total * BLANKET_SHARE


def release(tool: str, result, limit: int | None):
    """Layer 3. Returns (result, summary). The summary is None when there are no pupils to count."""
    if not isinstance(result, list):
        return result, None
    wanted = result[: MAX_LIMIT if limit is None else limit]
    if tool != "search" and not any(PUPIL_KEY in row for row in wanted):
        return wanted, None

    pupils: set[str] = set()
    released = []
    for row in wanted:
        if row.get(PUPIL_KEY) not in pupils and len(pupils) == MAX_PUPILS:
            continue
        pupils.add(row.get(PUPIL_KEY))
        released.append(row)
    return released, {
        "returned_rows": len(released),
        "returned_pupils": len(pupils),
        "max_pupils": MAX_PUPILS,
        "trimmed": len(released) < len(result),
    }
