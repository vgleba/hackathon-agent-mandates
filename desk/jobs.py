"""The jobs a member of staff can give an assistant, and the access each one creates (question 10).

Words only ever pick a job from this list and fill in its blanks. Every blank has a fixed list of answers, so "every
school" and "whatever it needs" are not possible answers, and the same choices always make the same access.
"""
# ruff: noqa: EM101, N818, RUF001  (a refusal carries a code to match on; text shown to people has real apostrophes)

import re

CENSUS = "personal_data_school_census"
YEAR, TERM = "2023/24", "SPR"
HOUR = 3600
LONGEST_REASON = 120
SCHOOL_DAY = 8 * HOUR  # long enough for someone who is teaching to approve it

FIELDS = {
    "Language": {"name": "First language", "values": {"1_ENG": "English", "2_OTH": "Another language"}},
    "FSMeligible": {"name": "Free school meals", "values": {"1": "Yes", "0": "No"}},
    "Gender": {"name": "Gender", "values": {"F": "F", "M": "M"}},
    "EnrolStatus": {"name": "Enrolment", "values": {"C": "Current", "S": "Subsidiary"}},
    "Ethnicity": {
        "name": "Ethnic group",
        "values": {
            "ASIA": "Asian",
            "BLAC": "Black",
            "CHIN": "Chinese",
            "MIXD": "Mixed",
            "WHIT": "White",
            "AOEG": "Any other",
            "UNCL": "Not given",
        },
    },
    "InCareAtCurrentSchool": {"name": "In care", "values": {"1": "Yes", "0": "No"}},
}
SPECIAL = {"Ethnicity", "InCareAtCurrentSchool"}
KINDS = {"absence": "Absence", "attendance_meeting": "Invitation to an attendance meeting"}
DETAIL = {"basic": "Basic details", "meals": "Basic details, first language and free school meals"}
WHAT = {"meals": "Free school meals", "care": "In care"}
SPLIT = {"none": "One total", "school": "By school", "gender": "By gender", "ethnic": "By ethnic group"}
WHEN = {"term": "This term", "all": "Every term on record"}

# what each job asks for, in order
JOBS = {
    "letters": {
        "title": "Write letters home",
        "about": "You choose the pupils and check every letter before it is released.",
        "blanks": ["kind", "school", "year", "pupils", "helper"],
        "most": 60,
    },
    "find_pupil": {
        "title": "Find a pupil’s record",
        "about": "One pupil’s school census record.",
        "blanks": ["school", "year", "pupils", "detail"],
        "most": 1,
    },
    "count": {
        "title": "Count pupils",
        "about": "Numbers only, never names. Small numbers are hidden to protect children.",
        "blanks": ["what", "split", "school", "when"],
        "most": 0,
    },
    "meals_check": {
        "title": "Check who has free school meals",
        "about": "Goes through the pupils you choose, one at a time.",
        "blanks": ["school", "year", "pupils"],
        "most": 60,
    },
    "correct": {
        "title": "Correct a record",
        "about": "One thing, for one pupil. You approve it before it changes.",
        "blanks": ["school", "year", "pupils", "field", "value", "reason"],
        "most": 1,
    },
    "newsletter": {
        "title": "School details for a newsletter",
        "about": "Public information only. Nothing about any pupil.",
        "blanks": [],
        "most": 0,
    },
    "safeguarding": {
        "title": "Safeguarding review",
        "about": "Full records for up to 5 pupils you name, for one hour. Includes ethnicity and care status.",
        "blanks": ["school", "year", "pupils", "confirm"],
        "most": 5,
    },
}
QUESTIONS = {
    "kind": "What kind of letter?",
    "school": "Which school?",
    "year": "Which year group?",
    "pupils": "Which pupils?",
    "helper": "Share the work with a second helper?",
    "detail": "How much detail?",
    "what": "Count what?",
    "split": "Split how?",
    "when": "For when?",
    "field": "What needs correcting?",
    "value": "What should it say?",
    "reason": "Why is it being corrected?",
    "confirm": "Do you need to see ethnicity and care status for these pupils?",
}


class Ask(Exception):
    """Something is missing or not on the list. The person is asked; it is never guessed."""

    def __init__(self, field: str | None, question: str):
        super().__init__(question)
        self.field, self.question = field, question


def _pick(choice: dict, field: str, allowed) -> str:
    value = choice.get(field)
    if not isinstance(value, (str, int)) or isinstance(value, bool) or value not in allowed:
        raise Ask(field, QUESTIONS[field])
    return value


def _pupils(choice: dict, most: int) -> dict[str, str]:
    pupils = choice.get("pupils")
    if not isinstance(pupils, dict) or not 1 <= len(pupils) <= most:
        raise Ask("pupils", QUESTIONS["pupils"] if most > 1 else "Which pupil?")
    if not all(re.fullmatch(r"P\d{4}", str(i)) and isinstance(n, str) and n for i, n in pupils.items()):
        raise Ask("pupils", QUESTIONS["pupils"])
    return pupils


def _entry(tool: str, **constraints) -> dict:
    return {"server": "pupil-data", "tools": [tool], "constraints": constraints}


def _grant(purpose: str, clearance: int, pupils: int, ttl: int, *scope: dict, helpers: int = 0) -> dict:
    return {
        "purpose_code": purpose,
        "clearance": clearance,
        "budget": {"pupils": pupils},
        "ttl": ttl,
        "scope": list(scope),
        "helpers": helpers,
    }


def build(job: str, choice: dict, schools: dict[str, str]) -> dict:  # noqa: C901, PLR0911  (one branch per job)
    """The access one job needs, and nothing else. Raises Ask for anything missing or not on the list."""
    if job not in JOBS:
        raise Ask(None, "What do you need done?")
    blanks, most = JOBS[job]["blanks"], JOBS[job]["most"]
    if not isinstance(choice, dict) or set(choice) - set(blanks):
        raise Ask(None, "That is not one of the choices for this job.")
    if job == "newsletter":
        return _grant("newsletter", 1, 0, HOUR, _entry("get", path=["synthetic/synthetic_schools.csv"]))
    if job == "count":
        return _count(choice, schools)

    if job == "letters":
        _pick(choice, "kind", KINDS)
    urn = _pick(choice, "school", schools)
    _pick(choice, "year", {10, 11})
    pupils = _pupils(choice, most)
    ids = list(pupils)
    if job == "letters":
        helper = choice.get("helper", False)
        if not isinstance(helper, bool):
            raise Ask("helper", QUESTIONS["helper"])
        purpose = "absence_letters" if choice["kind"] == "absence" else "meeting_letters"
        scope = _entry("draft", urn=[urn], kind=[choice["kind"]], pupil_ids=ids)
        return _grant(purpose, 2, len(ids), SCHOOL_DAY, scope, helpers=int(helper and len(ids) > 1))
    if job == "find_pupil":
        level = {"basic": 2, "meals": 3}[_pick(choice, "detail", DETAIL)]
        return _grant("find_pupil", level, 1, HOUR, _entry("search", urn=[urn], query=ids))
    if job == "meals_check":
        return _grant("meals_check", 3, len(ids), HOUR, _entry("search", urn=[urn], query=ids))
    if job == "correct":
        field = _pick(choice, "field", FIELDS)
        value = _pick(choice, "value", FIELDS[field]["values"])
        reason = choice.get("reason")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= LONGEST_REASON:
            raise Ask("reason", QUESTIONS["reason"])
        scope = _entry("write", urn=[urn], pupil_id=ids, column=[field], value=[value])
        return _grant("record_correction", 4 if field in SPECIAL else 3, 1, SCHOOL_DAY, scope)
    if choice.get("confirm") is not True:
        raise Ask("confirm", QUESTIONS["confirm"])
    return _grant("safeguarding_review", 4, len(ids), HOUR, _entry("pupil", urn=[urn], pupil_id=ids))


def _count(choice: dict, schools: dict[str, str]) -> dict:
    what = _pick(choice, "what", WHAT)
    split = _pick(choice, "split", SPLIT)
    school = _pick(choice, "school", {"all", *schools})
    when = _pick(choice, "when", WHEN)
    if split == "school" and school != "all":
        raise Ask("split", "One school cannot be split by school. Split how?")
    ask = _count_arguments(what, split, school, when)
    scope = _entry("aggregate", **{k: [v] for k, v in ask.items()})
    return _grant("pupil_counts", 4 if what == "care" or split == "ethnic" else 3, 0, HOUR, scope)


def _count_arguments(what: str, split: str, school: str, when: str) -> dict:
    where = {} if school == "all" else {"URN": school}
    if when == "term":
        where |= {"AcademicYear": YEAR, "CensusTerm": TERM}
    return {
        "table": CENSUS,
        "measure": {"meals": "FSMeligible", "care": "InCareAtCurrentSchool"}[what],
        "group_by": {"none": [], "school": ["URN"], "gender": ["Gender"], "ethnic": ["Ethnicity"]}[split],
        "where": where,
    }


def calls(job: str, choice: dict) -> list[tuple[str, dict]]:
    """What the assistant will do, in order."""
    urn, ids = choice.get("school"), list(choice.get("pupils", {}))
    if job == "newsletter":
        return [("get", {"path": "synthetic/synthetic_schools.csv"})]
    if job == "count":
        return [("aggregate", _count_arguments(choice["what"], choice["split"], choice["school"], choice["when"]))]
    if job == "letters":
        return [("draft", {"urn": urn, "kind": choice["kind"], "pupil_ids": ids})]
    if job in {"find_pupil", "meals_check"}:
        return [("search", {"query": i, "urn": urn}) for i in ids]
    if job == "correct":
        fix = {"column": choice["field"], "value": choice["value"], "reason": choice["reason"].strip()}
        return [("write", {"pupil_id": ids[0], "urn": urn, **fix})]
    return [("pupil", {"pupil_id": i, "urn": urn}) for i in ids]


# ---------------------------------------------------------------- from a sentence

# phrases that ask for more access without saying what for. They add nothing, and the person is told so
TOO_WIDE = re.compile(
    r"\b(everything|anything|whatever it (?:needs|wants)|what(?:ever)? it needs|full access"
    r"|all (?:the )?(?:data|access|files|records)|every (?:school|pupil|record|file)|no limits?|no approval"
    r"|without (?:asking|approval)|ignore (?:all |any )?(?:previous |the )?(?:rules|limits))\b",
    re.IGNORECASE,
)
HINTS = [
    (
        "correct",
        r"\b(correct|fix|amend|change|update)\b.*\b(record|language|meals|gender|ethnic\w*|enrol\w*)|\bis wrong\b",
    ),
    ("count", r"\b(how many|count|number of|total)\b"),
    ("letters", r"\bletters?\b|\battendance meeting\b|\babsence\b"),
    ("safeguarding", r"\bsafeguard\w*|\bfull records?\b|\bcare status\b"),
    ("meals_check", r"\b(who|note|check|go through)\b.*\b(free school meals?|fsm)\b"),
    ("newsletter", r"\bnewsletter\b|\bschool (?:details|names|list)\b|\blist of schools\b"),
    ("find_pupil", r"\b(find|look up|look for|get)\b.*\b(pupil|student|child|record)"),
]


def understand(text: str, schools: dict[str, str]) -> dict:  # noqa: C901  (one branch per blank)
    """{"job", "choice", "ask", "ignored"}. Anything unclear is left blank, to be asked."""
    text = " ".join(str(text)[:500].split())
    ignored = sorted({m.group(0).lower() for m in TOO_WIDE.finditer(text)})
    job = next((name for name, pattern in HINTS if re.search(pattern, text, re.IGNORECASE)), None)
    if job is None:
        ask = "Which of these jobs is it for?"
        if ignored:
            ask = "I can only give access for one of these jobs. Which is it for?"
        return {"job": None, "choice": {}, "ask": ask, "ignored": ignored}

    blanks, choice = JOBS[job]["blanks"], {}
    named = {u for u, n in schools.items() if re.search(rf"\b({u}|{re.escape(n.split()[0])})\b", text, re.IGNORECASE)}
    if "school" in blanks and len(named) == 1:
        choice["school"] = named.pop()
    if (
        "year" in blanks
        and (years := set(re.findall(r"\by(?:ea)?r?\s*(10|11)(?=\D|$)", text, re.IGNORECASE)))
        and len(years) == 1
    ):
        choice["year"] = int(years.pop())
    if job == "letters" and re.search(r"\bmeeting\b", text, re.IGNORECASE):
        choice["kind"] = "attendance_meeting"
    elif job == "letters" and re.search(r"\babsen", text, re.IGNORECASE):
        choice["kind"] = "absence"
    if job == "count":
        if re.search(r"\b(free school meals?|fsm)\b", text, re.IGNORECASE):
            choice["what"] = "meals"
        elif re.search(r"\bin care\b", text, re.IGNORECASE):
            choice["what"] = "care"
        if re.search(r"\b(each|every|by|per) school", text, re.IGNORECASE):
            choice |= {"split": "school", "school": "all"}
        elif re.search(r"\bethnic", text, re.IGNORECASE):
            choice["split"] = "ethnic"
    return {"job": job, "choice": choice, "ask": None, "ignored": ignored}
