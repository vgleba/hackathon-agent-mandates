"""What Desk says to people: results, refusals and activity, with no jargon."""

import time

from desk import jobs

WHY = {
    "REFUSED_BY_PERSON": "You said no, so it stopped.",
    "LAPSED": "Nobody answered in time, so nothing happened.",
    "BLOCKED": "Something changed while it waited, so nothing happened.",
    "UNKNOWN": "It was interrupted part way. Check the record before trying again.",
    "REVOKED": "The access was taken back.",
    "EXPIRED": "The access had run out.",
    "BUDGET_EXCEEDED": "It had reached the most pupils it may look at.",
    "PERSON_PAUSED": "Your own access is paused, so your assistants are too.",
    "PERSON_LOST_ACCESS": "That school is not one of yours at the moment.",
    "PERSON_UNKNOWN": "Your name is not on the list of people who can give access.",
    "CLEARANCE_TOO_LOW": "That information is too sensitive for this job.",
    "PURPOSE_MISMATCH": "That is not part of this job.",
    "OUT_OF_SCOPE": "That is not part of this job.",
    "CONSTRAINT_VIOLATED": "That pupil, school or file is not part of this job.",
    "CONSTRAINT_MISSING": "It left out something the job limits.",
    "DENIED_BY_RULE": "This job may never do that.",
    "QUERY_TOO_BROAD": "It asked for too much at once.",
    "LIMIT_NOT_ALLOWED": "It asked for too much at once.",
    "UNSAFE_GROUPING": "That count could identify a child.",
    "POP_FAILED": "Someone tried to use this access without its key. They got nothing.",
    "CHILD_WIDER": "A helper asked for more than it was given.",
    "CHILD_SIG_INVALID": "Something pretended to be a helper.",
    "DELEGATION_NOT_ALLOWED": "It tried to pass on access that it may not pass on.",
    "TOO_MANY_WAITING": "Too many things are already waiting for you.",
    "RECORD_UNAVAILABLE": "It could not be recorded, so it was not allowed.",
    "LABELS_UNAVAILABLE": "It could not be told how sensitive that is, so the answer is no.",
    "WRONG_TOKEN_TYPE": "Something arrived that was not a permission at all.",
}
ALARMS = {"POP_FAILED", "CHILD_SIG_INVALID", "CHILD_WIDER"}
DID = {
    "search": "Looked up a pupil",
    "pupil": "Opened a full record",
    "roster": "Read a class list",
    "draft": "Wrote letters",
    "write": "Corrected a record",
    "aggregate": "Counted pupils",
    "get": "Read a file",
    "held": "Collected an answer you approved",
}
COLUMNS = {
    "AcademicYear": "Year",
    "CensusTerm": "Term",
    "Gender": "Gender",
    "AgeAtStartOfAcademicYear": "Age in September",
    "EnrolStatus": "Enrolment",
    "Language": "First language",
    "FSMeligible": "Free school meals",
    "Ethnicity": "Ethnic group",
    "InCareAtCurrentSchool": "In care",
    "DeprivationDecile": "Deprivation (1 to 10)",
    "DisplayName": "Name",
}
TERMS = {"AUT": "Autumn", "SPR": "Spring", "SUM": "Summer"}
TOO_FEW = "Too few to show safely"


def why(reason: str) -> str:
    return WHY.get(reason, "It was not allowed.")


def value(column: str, v) -> str:
    if column == "CensusTerm":
        return TERMS.get(v, v)
    return jobs.FIELDS.get(column, {}).get("values", {}).get(v, str(v))


def _table(columns: list[str], rows: list[list[str]], note: str = "") -> dict:
    return {"kind": "table", "columns": columns, "rows": rows, "note": note}


def _latest(rows: list[dict]) -> dict | None:
    order = {"AUT": 0, "SPR": 1, "SUM": 2}
    return max(rows, key=lambda r: (r["AcademicYear"], order.get(r["CensusTerm"], 0)), default=None)


def result(job: str, choice: dict, found: list, schools: dict[str, str]) -> dict:  # noqa: PLR0911  (one per job)
    """An assistant's answer, as a person would want to read it."""
    names = choice.get("pupils", {})
    if job == "letters":
        letters = [{"name": names.get(x["Psuedo ID"], ""), "letter": x["letter"]} for x in found]
        missing = [n for i, n in names.items() if i not in {x["Psuedo ID"] for x in found}]
        note = f"No letter for {', '.join(missing)}." if missing else ""
        return {"kind": "letters", "letters": letters, "note": note}
    if job == "count":
        return _counts(choice, found, schools)
    if job == "meals_check":
        rows = []
        for i, name in names.items():
            last = _latest([r for r in found if r.get("Psuedo ID") == i])
            rows.append([name, value("FSMeligible", last["FSMeligible"]) if last else "No record found"])
        yes = sum(r[1] == "Yes" for r in rows)
        return _table(["Pupil", "Free school meals"], sorted(rows), f"{yes} of {len(rows)} have free school meals.")
    if job == "correct":
        e = found[0]
        what = jobs.FIELDS[e["column"]]["name"]
        row = [next(iter(names.values())), what, value(e["column"], e["before"]), value(e["column"], e["after"])]
        return _table(["Pupil", "What", "Was", "Now"], [row], "Recorded as a correction.")
    if job == "newsletter":
        return _table(["School"], [[r["SchoolName"]] for r in found])
    if job == "find_pupil":
        shown = [c for c in COLUMNS if found and c in found[0]]
        rows = [[value(c, r[c]) for c in shown] for r in found]
        note = "" if found else "No record was found for that pupil at that school."
        return _table([COLUMNS[c] for c in shown], rows, note)
    shown = [c for c in COLUMNS if any(c in r for r in found)]
    return _table([COLUMNS[c] for c in shown], [[value(c, r.get(c, "")) for c in shown] for r in found if r])


def _counts(choice: dict, found: list[dict], schools: dict[str, str]) -> dict:
    what = jobs.WHAT[choice["what"]]
    rows, hidden = [], False
    for r in found:
        key = next((k for k in r if k not in {"total", "count"}), None)
        label = "All pupils" if key is None else schools.get(r[key], value(key, r[key]))
        hidden |= r["count"] is None
        rows.append([label, TOO_FEW if r["count"] is None else f"About {r['count']}", f"About {r['total']}"])
    note = "Numbers are of pupils, rounded to the nearest 5."
    if hidden or not rows:
        note += " Groups of fewer than 10, or all but fewer than 10, are hidden because they could identify a child."
    return _table(["Group", what, "Pupils in the group"], rows, note)


def ago(ts: float) -> str:
    return time.strftime("%H:%M, %a %d %b", time.localtime(ts))


def activity(entry: dict, titles: dict[str, str]) -> dict:
    """One line of the record, as a sentence."""
    tool = (entry.get("tool") or "").split(".")[-1]
    pupils = len(entry.get("pupils") or [])
    about = f" ({pupils} pupil{'s' if pupils != 1 else ''})" if pupils else ""
    reason, decision = entry["reason"], entry["decision"]
    if reason == "PERSON_LOOKUP":
        text = f"You looked at a class list{about}"
    elif decision == "ALLOW":
        text = DID.get(tool, "Did something") + about
        if reason == "APPROVED_BY_PERSON":
            text += ", after you approved it"
    elif decision == "STEP_UP":
        text = "Asked you first: " + DID.get(tool, "something").lower()
    elif decision == "HELD":
        text = "You approved it, so it went ahead"
    else:
        text = "Refused: " + why(reason)
    return {
        "when": ago(entry["ts"]),
        "job": titles.get(
            entry.get("root") or "", "You" if reason == "PERSON_LOOKUP" else "Something not started here"
        ),
        "text": text,
        "alarm": reason in ALARMS,
        "refused": decision == "DENY",
        "from": entry.get("source"),
    }
