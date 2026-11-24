"""Evals for open questions 6, 8, 9, 12, 13, 15 and 16. Questions 7, 10, 11 and 14 are in gateway/eval_open.py.

    python -m gateway.eval local                                                      # or: make eval_local
    python -m gateway.eval open --state gateway/state --url http://localhost:8082     # or: make eval_open

`local` makes its own keys and starts its own gateway and data server, so it shares no keys, people or record with
anyone. `open` runs against a gateway that is already up: it writes the state directory that gateway reads, and grants
and revokes mandates there. Use `local` unless you need that, and not both at once: they share corrections.jsonl.

The cases check the design in docs/questions_4_to_16.md. What each answer should be is worked out from the data files
and from tables written out here, and requests are signed here, so that the gateway's own code is not its own judge.

Every run puts a few people in people.json, all named eval:something, and changes some of them part way. When it ends
they have left, and nothing is waiting for them. Question 9 approves three corrections, which the data server writes in
its corrections.jsonl without changing the data.

Question 6, sensitivity. The data's own labels decide, per column; the higher of two decides; a mandate, its purpose
and its person each cap it (CLEARANCE_TOO_LOW). No clearance means 3, never special category.

Question 8, counts. Children are counted, not rows. Under 10 on either side is hidden and the rest is rounded to 5. A
question that could single someone out is refused before it is asked (UNSAFE_GROUPING).

Question 9, approval. A held call is released once, by the person who granted it, with their own key. Every check runs
again first. Nobody answering means no.

Question 12, purpose. A code in the mandate names the tools and the most sensitive data a job needs (PURPOSE_MISMATCH).
Nothing the agent says about why it is asking is read.

Question 13, the person changes. Their access is looked up on every call (PERSON_PAUSED, PERSON_LOST_ACCESS,
PERSON_UNKNOWN). Mandates pause. They never pass to a successor.

Question 15, clearance. The columns an agent may not see are not released, and not searched either.

Question 16, the log. A person opens their own, with their own key, refusals included. A thief with the agent's key
opens nothing, and a made-up mandate appears in nobody's log.
"""

import base64
import contextlib
import csv
import hashlib
import io
import itertools
import json
import secrets
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from desk import words
from gateway import cli
from gateway.cli import DEFAULT_DENY, delegate_mandate, issue_mandate, person_key, revoke_mandate, set_person
from gateway.eval_open import (
    ASHFIELD,
    DATA,
    DUNMORE,
    ELMWOOD,
    MOST_PUPILS_PER_ANSWER,
    OTHER,
    PRINCIPAL,
    SERVER,
    SPRING,
    Data,
    Post,
    Run,
    child,
    claims_of,
    entry,
    reason,
)
from gateway.lib.common import generate_keypair, priv_from_pem, priv_to_pem

CASTLETON, FAIRHAVEN, GREYSTONE = "SCH03", "SCH06", "SCH07"
CENSUS = "personal_data_school_census"
SCHOOLS_FILE, MANIFEST_FILE = "synthetic/synthetic_schools.csv", "synthetic/synthetic_manifest.json"
NAMES_FILE, CENSUS_FILE = "synthetic/synthetic_display_names.csv", f"synthetic/synthetic_{CENSUS}.csv"
UNLABELLED_FILE, OTHER_FILE = "synthetic/synthetic_nobody_labelled_this.csv", "notes.csv"
SPRING_WHERE = {"AcademicYear": "2023/24", "CensusTerm": "SPR"}
SPECIAL = {"Ethnicity", "InCareAtCurrentSchool"}
PUPIL_ID = "Psuedo ID"  # the data's own spelling
APPROVER, LEAVER, PRIYA, EDITOR, OWNER = "eval:approver", "eval:leaver", "eval:priya", "eval:editor", "eval:owner"
EVERYTHING = {"status": "active", "urns": "*", "clearance": 4, "daily_pupils": 100_000}
MOST_WAITING = 20  # calls one job may have waiting for a person
SCHOOL_DAY = 8 * 3600  # the longest a call waits for one
MOST_ROWS = 100  # rows a search gives when it is not told how many
TOO_BROAD = 0.9  # a search that matches this share of a school is no search
TOO_OLD, A_BIT_FAST, TOO_NEW = -400, 20, 60  # a signature is good for 300 seconds, and may be 30 early
UNREADABLE_CLEARANCES = [0, 5, -1, "4", 4.5, True, None, [4]]

MORE_QUESTIONS = {
    6: "Send me the full records for Castleton's pupils, ethnicity and care status included.",
    8: "How many pupils in care does each school have, split by ethnic group?",
    9: "Just correct the record yourself.",
    12: "I gave it access for the letters. Why was it looking up who's in care?",
    13: "I'm leaving at Easter. Priya is taking over my agents.",
    15: "This one's only doing the newsletter. It doesn't need anything personal.",
    16: "I think someone may have taken my access. Can I see a log of the requests made with it?",
}

# Question 12: what each job may use, and nothing else. The calls tried reach the most sensitive data each can justify
PURPOSE_TOOLS = {
    "newsletter": {"get"},
    "absence_letters": {"roster", "draft"},
    "meeting_letters": {"roster", "draft"},
    "find_pupil": {"roster", "search"},
    "meals_check": {"roster", "search"},
    "pupil_counts": {"aggregate"},
    "record_correction": {"roster", "search", "write"},
    "safeguarding_review": {"roster", "pupil"},
}
NOT_A_PURPOSE = ["unknown", "", None, 3, ["safeguarding_review"], {"code": "safeguarding_review"}]
NOT_A_PURPOSE += ["Safeguarding_Review", " safeguarding_review", "safeguarding_review,absence_letters"]

# Question 8: what could single someone out. Each is put to a counts mandate with the highest clearance
UNSAFE = {
    "by pupil": {"group_by": [PUPIL_ID]},
    "by school and pupil": {"group_by": ["URN", PUPIL_ID]},
    "by care status": {"group_by": ["InCareAtCurrentSchool"]},
    "by free school meals": {"group_by": ["FSMeligible"]},
    "by first language": {"group_by": ["Language"]},
    "by age": {"group_by": ["AgeAtStartOfAcademicYear"]},
    "by three things at once": {"group_by": ["URN", "Gender", "Ethnicity"]},
    "one school, by two things": {"group_by": ["Gender", "Ethnicity"], "where": {"URN": GREYSTONE}},
    "the same thing twice": {"group_by": ["URN", "URN"]},
    "a group that is not a list": {"group_by": "URN"},
    "only one pupil": {"where": {PUPIL_ID: "P0011"}},
    "only pupils in care": {"where": {"InCareAtCurrentSchool": "1"}},
    "only pupils with free school meals": {"where": {"FSMeligible": "1"}},
    "only one ethnic group": {"where": {"Ethnicity": "ASIA"}},
    "only girls": {"where": {"Gender": "F"}},
    "only one language": {"where": {"Language": "2_OTH"}},
    "only one age": {"where": {"AgeAtStartOfAcademicYear": "15"}},
    "only some enrolments": {"where": {"EnrolStatus": "S"}},
    "a filter that is not one value": {"where": {"URN": [ASHFIELD]}},
    "counting ethnicity": {"measure": "Ethnicity"},
    "counting pupil IDs": {"measure": PUPIL_ID},
    "counting nothing": {"measure": None},
    "the names table": {"table": "display_names", "group_by": ["DisplayName"], "measure": "Gender"},
    "the deprivation table": {"table": "personal_data_deprivation", "group_by": ["DeprivationDecile"]},
    "the names table, asked as if it were the census": {"table": "display_names", "group_by": ["Gender"]},
}


# ---------------------------------------------------------------- signing, as GET /describe says to


def wire(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def signed_call(priv, mandate: str, tool: str, arguments: dict, server: str = SERVER) -> dict:
    """An agent's request."""
    body = {"server": server, "tool": tool, "arguments": arguments}
    body |= {"nonce": secrets.token_urlsafe(16), "ts": int(time.time())}
    mandate_hash = "sha256:" + hashlib.sha256(mandate.encode()).hexdigest()
    return {**body, "mandate": mandate, "sig": b64u(priv.sign(wire({**body, "mandate_hash": mandate_hash})))}


def signed_by(priv, principal: str, do: str, *, ts: int | None = None, **fields) -> dict:
    """A person's own request: `do` is the kind of thing it is good for."""
    body = {"principal": principal, "nonce": secrets.token_urlsafe(16), "ts": int(time.time()) if ts is None else ts}
    return {**body, "sig": b64u(priv.sign(wire({**body, "do": do, "fields": fields}))), **fields}


def thumbprint(priv) -> str:
    """How an agent's key is named (RFC 7638), from its public half."""
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64u(hashlib.sha256(wire({"crv": "Ed25519", "kty": "OKP", "x": b64u(raw)})).digest())


# ---------------------------------------------------------------- the data, and what it says may be seen


class Labelled(Data):
    """The data with its own sensitivity labels, read from the manifest."""

    def __init__(self):
        super().__init__()
        manifest = json.loads((DATA / "synthetic_manifest.json").read_text(encoding="utf-8"))
        self.levels: dict[str, int] = manifest["classification"]["columns"][CENSUS]
        with (DATA / "synthetic_personal_data_deprivation.csv").open(newline="") as f:
            self.deprivation = {r[PUPIL_ID]: r for r in csv.DictReader(f)}

    def visible(self, clearance: int) -> set[str]:
        return {c for c, level in self.levels.items() if level <= clearance}

    def latest(self, pupil: str) -> dict:
        order = {"AUT": 0, "SPR": 1, "SUM": 2}
        rows = [r for r in self.census if r[PUPIL_ID] == pupil]
        return max(rows, key=lambda r: (r["AcademicYear"], order[r["CensusTerm"]]))

    def full_record(self, pupil: str) -> dict:
        return {**self.latest(pupil), "DisplayName": self.names[pupil], **self.deprivation.get(pupil, {})}

    def searched(self, urn: str, query: str, clearance: int) -> tuple[list[dict], dict] | None:
        """What a search may release and say of it, or None if it matches so much of the school that it is no search.

        Only the cells that may be seen are searched, and at most ten pupils are released.
        """
        seen = self.visible(clearance)
        here = [r for r in self.census if r["URN"] == urn]
        rows = [r for r in here if any(query.lower() in r[c].lower() for c in seen)]
        if len(rows) >= len(here) * TOO_BROAD:
            return None
        released, pupils = [], set()
        for row in rows[:MOST_ROWS]:
            if row[PUPIL_ID] in pupils or len(pupils) < MOST_PUPILS_PER_ANSWER:
                pupils.add(row[PUPIL_ID])
                released.append({c: v for c, v in row.items() if c in seen})
        volume = {"returned_rows": len(released), "returned_pupils": len(pupils), "max_pupils": MOST_PUPILS_PER_ANSWER}
        return released, {**volume, "trimmed": len(released) < len(rows)}

    def found(self, urn: str, query: str, clearance: int) -> list[dict] | None:
        got = self.searched(urn, query, clearance)
        return got and got[0]

    def children(self, groups: list[str], measure: str, where: dict[str, str]) -> dict[tuple, tuple[int, int]]:
        """Group -> (how many different children, how many of them have the measure)."""
        everyone: dict[tuple, set[str]] = {}
        counted: dict[tuple, set[str]] = {}
        for row in self.census:
            if all(row[k] == v for k, v in where.items()):
                key = tuple(row[g] for g in groups)
                everyone.setdefault(key, set()).add(row[PUPIL_ID])
                if row[measure] == "1":
                    counted.setdefault(key, set()).add(row[PUPIL_ID])
        return {key: (len(pupils), len(counted.get(key, ()))) for key, pupils in everyone.items()}


def safe_figures(children: dict[tuple, tuple[int, int]]) -> dict[tuple, tuple[int, int | None]]:
    """What may be shown of them: nothing under 10 on either side, and the rest to the nearest 5."""
    shown = {}
    for key, (total, n) in children.items():
        if total >= 10:
            enough = n >= 10 and total - n >= 10
            shown[key] = (5 * round(total / 5), min(5 * round(n / 5), 5 * round(total / 5)) if enough else None)
    return shown


def rows_of(body: dict) -> list[dict]:
    found = body.get("result")
    return [r for r in found if isinstance(r, dict)] if isinstance(found, list) else []


def columns_of(body: dict) -> set[str]:
    return {c for row in rows_of(body) for c in row}


def said(response: tuple[int, dict]) -> str:
    return f"{response[0]} {reason(response[1])}"


# ---------------------------------------------------------------- a run with people in it


class Staff(Run):
    """People sign with their own keys, and can be changed part way: the gateway looks them up on every call."""

    def person(self, principal: str, **fields) -> None:
        set_person(self.state, principal, **fields)
        if principal not in self.person_keys:
            self.person_keys[principal] = person_key(self.state, principal)

    def resigned(self, mandate: str, **changes) -> str:
        """The same mandate with some claims changed, signed by the real issuer, as one that does not check would."""
        key = priv_from_pem((self.state / "issuer_key.pem").read_bytes())
        claims, header = {**claims_of(mandate), **changes}, jwt.get_unverified_header(mandate)
        return jwt.encode(claims, priv_to_pem(key), algorithm="EdDSA", headers=header)

    def leave(self) -> None:
        """Nothing is left waiting, and nobody made for a run stays able to grant anything after it."""
        for principal in self.person_keys:
            with contextlib.suppress(Exception):
                self.person(principal, **EVERYTHING)
                for hold in self.ask_as(principal, "/holds", "holds")[1].get("holds", []):
                    self.ask_as(principal, "/holds/answer", "answer", hold=hold["id"], answer="refuse")
            self.person(principal, status="left", urns=[], clearance=1, daily_pupils=0)

    def grant(
        self,
        priv,
        *scope: dict,
        principal: str = PRINCIPAL,
        deny: list[str] = DEFAULT_DENY,
        purpose: str = "open-question eval",
        ttl: int = 3600,
        helpers: int = 0,
        **claims,
    ) -> tuple[str, int]:
        """A mandate from anybody, with any deny list. Returns (mandate, revocation index)."""
        return issue_mandate(
            self.state,
            priv.public_key(),
            scope=list(scope),
            deny=list(deny),
            ttl=ttl,
            purpose=purpose,
            principal=principal,
            org="org:hackathon",
            extra=claims or None,
            helpers=helpers,
        )

    def call(self, priv, mandate: str, tool: str, **arguments) -> tuple[int, dict]:
        return self.post("/tools/call", signed_call(priv, mandate, tool, arguments))

    def collect(self, priv, mandate: str, hold: str) -> tuple[int, dict]:
        """The agent asks after its own held call."""
        return self.post("/tools/call", signed_call(priv, mandate, "held", {"id": hold}, server="gateway"))

    def ask_as(self, principal: str, path: str, do: str, *, key=None, over=None, ts=None, **fields) -> tuple[int, dict]:
        """A request signed by a person, for their approvals, their log or a class list."""
        body = signed_by(key or self.person_keys[principal], principal, do, ts=ts, **fields)
        return self.post(path, {**body, **(over or {})})

    def log(self, principal: str, **fields) -> dict:
        status, reply = self.ask_as(principal, "/log", "log", **fields)
        return reply if status == 200 else {}

    def entries(self, principal: str, **fields) -> list[dict]:
        """Their log of what was asked of the data, without whatever else is kept in it."""
        found = self.log(principal, **fields).get("entries", [])
        return [e for e in found if (e.get("tool") or "").startswith(f"{SERVER}.")]


# ---------------------------------------------------------------- question 6: how sensitive is it?


def q6_sensitivity(run: Staff, data: Labelled) -> None:
    agent = run.key()
    pupil = data.year_group(CASTLETON, 11)[0]
    scope = [
        entry("pupil", "search", "roster", urn=[CASTLETON]),
        entry("write", urn=[CASTLETON]),
        entry("aggregate", table=[CENSUS]),
        entry("get", path=[SCHOOLS_FILE, NAMES_FILE, CENSUS_FILE, UNLABELLED_FILE, OTHER_FILE]),
    ]

    def at(clearance=None, **claims) -> str:
        if clearance is not None:
            claims["clearance"] = clearance
        return run.grant(agent, *scope, deny=[], **claims)[0]

    cleared = {c: at(c) for c in (1, 2, 3, 4)}
    unsaid = at()

    def full_record(mandate: str, urn: str = CASTLETON) -> tuple[int, dict]:
        return run.call(agent, mandate, "pupil", pupil_id=pupil, urn=urn)

    status, body = full_record(cleared[4])
    ok = status == 200 and body.get("result") == data.full_record(pupil)
    run.check(6, "clearance 4: the full record as it is, ethnicity and care status included", ok, said((status, body)))
    for clearance in (3, 2, 1):
        status, body = full_record(cleared[clearance])
        ok = (status, reason(body)) == (403, "CLEARANCE_TOO_LOW") and "result" not in body
        run.check(6, f"clearance {clearance}: the same record, refused with nothing in it", ok, said((status, body)))
    run.expect(6, "no clearance: the same record", full_record(unsaid), "CLEARANCE_TOO_LOW")
    run.expect(6, "clearance 4 does not open another school", full_record(cleared[4], ASHFIELD), "CONSTRAINT_VIOLATED")
    for odd in UNREADABLE_CLEARANCES:
        mandate = run.grant(agent, *scope, deny=[], clearance=odd)[0]
        run.expect(6, f"a clearance of {odd!r}", full_record(mandate), "CLAIM_NOT_UNDERSTOOD")
    for clearance in (2, 3, 4):
        status, body = run.call(agent, cleared[clearance], "search", query=pupil, urn=CASTLETON)
        ok = status == 200 and rows_of(body) == data.found(CASTLETON, pupil, clearance) != []
        name = f"clearance {clearance}: a search gives exactly the cells up to {clearance}"
        run.check(6, name, ok, f"{said((status, body))} {sorted(columns_of(body) ^ data.visible(clearance))}")
    q6_levels(run, agent, pupil, cleared, unsaid)
    q6_files_and_people(run, data, agent, cleared, unsaid)


def q6_levels(run: Staff, agent, pupil: str, cleared: dict[int, str], unsaid: str) -> None:
    """One call can touch data at two levels, and a correction touches one column."""

    def counted(mandate: str, group: str, measure: str = "FSMeligible", **kw) -> tuple[int, dict]:
        return run.call(agent, mandate, "aggregate", table=CENSUS, group_by=[group], measure=measure, **kw)

    low = "CLEARANCE_TOO_LOW"
    run.expect(6, "no clearance is not no access: free meals by gender", counted(unsaid, "Gender"), "ALLOW")
    run.expect(6, "two levels in one count: free meals by gender at 3", counted(cleared[3], "Gender"), "ALLOW")
    run.expect(6, "two levels in one count: free meals by ethnic group at 3", counted(cleared[3], "Ethnicity"), low)
    run.expect(6, "the same count at 2", counted(cleared[2], "Gender"), low)
    of_one_school = counted(cleared[2], "Gender", where={"URN": CASTLETON})
    run.expect(6, "the same count at 2, of one school", of_one_school, low)
    run.expect(6, "counting a column nobody has labelled, at 3", counted(cleared[3], "Gender", "NoSuchColumn"), low)

    def correct(column: str, value: str) -> tuple[int, dict]:
        fix = {"pupil_id": pupil, "urn": CASTLETON, "column": column, "value": value, "reason": "eval"}
        return run.call(agent, cleared[3], "write", **fix)

    run.expect(6, "a correction is judged by its column: ethnicity at 3", correct("Ethnicity", "ASIA"), low)
    run.expect(6, "a correction is judged by its column: language at 3", correct("Language", "2_OTH"), "STEP_UP")
    run.expect(6, "a correction to a column nobody has labelled, at 3", correct("NoSuchColumn", "x"), low)


def q6_files_and_people(run: Staff, data: Labelled, agent, cleared: dict[int, str], unsaid: str) -> None:
    files = [
        (SCHOOLS_FILE, 1, "ALLOW"),
        (NAMES_FILE, 2, "ALLOW"),
        (NAMES_FILE, 1, "CLEARANCE_TOO_LOW"),
        (CENSUS_FILE, 3, "CLEARANCE_TOO_LOW"),
        (UNLABELLED_FILE, 3, "CLEARANCE_TOO_LOW"),
        (OTHER_FILE, 3, "CLEARANCE_TOO_LOW"),
    ]
    for path, clearance, expected in files:
        name = f"{path.rpartition('/')[2]} at clearance {clearance}"
        run.expect(6, name, run.call(agent, cleared[clearance], "get", path=path), expected)
    unsaid_file = run.call(agent, unsaid, "get", path=CENSUS_FILE)
    run.expect(6, "the census file with no clearance", unsaid_file, "CLEARANCE_TOO_LOW")
    # eval:other is cleared to 1, whatever a mandate in their name says
    lower = run.grant(agent, entry("pupil", "roster", urn=[ASHFIELD]), principal=OTHER, clearance=4)[0]
    record = run.call(agent, lower, "pupil", pupil_id=data.year_group(ASHFIELD, 11)[0], urn=ASHFIELD)
    run.expect(6, "a mandate at 4 from a person cleared to 1: a record", record, "CLEARANCE_TOO_LOW")
    listing = run.call(agent, lower, "roster", urn=ASHFIELD, year_group=11, **SPRING)
    run.expect(6, "a mandate at 4 from a person cleared to 1: a class list", listing, "CLEARANCE_TOO_LOW")


# ---------------------------------------------------------------- question 8: is the answer itself sensitive?


class Counts:
    """One counts mandate with the highest clearance, and what its answers ought to be."""

    def __init__(self, run: Staff, data: Labelled):
        self.run, self.data, self.agent = run, data, run.key()
        self.mandate = run.grant(self.agent, entry("aggregate"), clearance=4)[0]

    def ask(self, group_by, measure="InCareAtCurrentSchool", mandate="", table=CENSUS, **kw) -> tuple[int, dict]:
        ask = {"table": table, "group_by": group_by, "measure": measure, **kw}
        return self.run.call(self.agent, mandate or self.mandate, "aggregate", **ask)

    @staticmethod
    def figures(body: dict, groups: list[str]) -> dict[tuple, tuple]:
        return {tuple(r.get(g) for g in groups): (r.get("total"), r.get("count")) for r in rows_of(body)}

    def right(self, groups: list[str], measure: str, where: dict | None, mandate: str = "") -> tuple[bool, str]:
        """The figures, and nothing else: not in the rows, and not in what is said about them."""
        status, body = self.ask(groups, measure, mandate, **({} if where is None else {"where": where}))
        truth = self.data.children(groups, measure, where or {})
        want, got = safe_figures(truth), self.figures(body, groups)
        hidden = any(total < 10 for total, _ in truth.values()) or any(n is None for _, n in want.values())
        note = {"unit": "pupils", "smallest": 10, "rounded_to": 5, "hidden": hidden}
        only = all(set(r) == {*groups, "total", "count"} for r in rows_of(body)) and body.get("disclosure") == note
        only = only and body.keys() == {"decision", "disclosure", "result"}
        wrong = sorted(str(k) for k in want.keys() | got.keys() if want.get(k) != got.get(k))
        return status == 200 and got == want and only, f"{status} {reason(body)}, {len(got)} groups, wrong {wrong[:3]}"

    def whatever_is_asked(self) -> tuple[int, list[str]]:
        """Every grouping that may be asked, with each kind of filter. Returns (how many, those that came back wrong)"""
        groups = ["URN", "Gender", "Ethnicity", "AcademicYear", "CensusTerm"]
        wheres = [None, SPRING_WHERE, {"CensusTerm": "SUM"}, {"AcademicYear": "2023/24"}]
        wheres += [{"URN": DUNMORE}, {"URN": ASHFIELD, **SPRING_WHERE}]
        splits = [list(c) for n in (0, 1, 2) for c in itertools.combinations(groups, n)]
        asked = [
            (split, measure, where)
            for split, measure, where in itertools.product(splits, ("FSMeligible", "InCareAtCurrentSchool"), wheres)
            if len({*split, *({"URN"} & set(where or ()))}) <= 2  # naming one school is a split too
        ]
        answers = [(ask, self.right(*ask)) for ask in asked]
        return len(asked), [f"{ask}: {got}" for ask, (ok, got) in answers if not ok]


def q8_counts(run: Staff, data: Labelled) -> None:
    counts = Counts(run, data)
    by_school = data.children(["URN"], "FSMeligible", SPRING_WHERE)[(DUNMORE,)]
    name = f"free school meals by school, this term (Dunmore: {by_school[1]} of {by_school[0]})"
    run.attempt(8, name, partial(counts.right, ["URN"], "FSMeligible", SPRING_WHERE))
    total = data.children([], "InCareAtCurrentSchool", {})[()]
    name = f"pupils in care, everyone, every term ({total[1]} of {total[0]})"
    run.attempt(8, name, partial(counts.right, [], "InCareAtCurrentSchool", None))
    others = {"clearance 3": {"clearance": 3}, "no clearance": {}}
    for (who, claims), groups in itertools.product(others.items(), (["URN"], ["URN", "Gender"])):
        mandate = run.grant(counts.agent, entry("aggregate"), **claims)[0]
        name = f"{who}: free school meals by {' and '.join(groups)} are made just as safe"
        run.attempt(8, name, partial(counts.right, groups, "FSMeligible", SPRING_WHERE, mandate))

    rows = sum(r["URN"] == ASHFIELD for r in data.census)
    children = data.children(["URN"], "FSMeligible", {})[(ASHFIELD,)][0]
    shown = counts.figures(counts.ask(["URN"], "FSMeligible")[1], ["URN"]).get((ASHFIELD,), (0, 0))[0]
    name = f"Ashfield's {children} children are counted, not their {rows} rows"
    run.check(8, name, abs(shown - children) < 5 and abs(shown - rows) > 5, f"shown {shown}")

    for groups, where in itertools.product((["URN", "Ethnicity"], ["URN"]), (SPRING_WHERE, {})):
        status, body = counts.ask(groups, where=where)
        got = [r.get("count", "?") for r in rows_of(body)]
        name = f"pupils in care by {' and '.join(groups)}, {'this' if where else 'every'} term: no figures at all"
        ok = status == 200 and got and set(got) == {None} and body.get("disclosure", {}).get("hidden") is True
        run.check(8, name, ok, f"{status} {reason(body)}, {sum(g is not None for g in got)} figures")

    truth = data.children(["URN"], "InCareAtCurrentSchool", {})
    none = next((k for k, (t, n) in truth.items() if n == 0 and t >= 10), None)
    few = next((k for k, (t, n) in truth.items() if 0 < n < 10 and t >= 10), None)
    got = counts.figures(counts.ask(["URN"])[1], ["URN"])
    ok = none and few and got.get(none, (0, 0))[1] is None and got.get(few, (0, 0))[1] is None
    run.check(8, "a school with no pupils in care looks the same as one with a few", ok, f"{none} and {few}")
    groups = ["URN", "Ethnicity"]
    truth = data.children(groups, "FSMeligible", {})
    status, body = counts.ask(groups, "FSMeligible")
    ok = status == 200 and counts.figures(body, groups).keys() == {k for k, (t, _) in truth.items() if t >= 10}
    small = sum(t < 10 for t, _ in truth.values())
    run.check(8, f"the {small} groups of under 10 pupils are not even listed, and the rest are", ok and small, status)
    groups, then = ["URN", "Gender"], {"AcademicYear": "2021/22", "CensusTerm": "SUM"}
    most = {k for k, (t, n) in data.children(groups, "FSMeligible", then).items() if n >= 10 > t - n}
    got = counts.figures(counts.ask(groups, "FSMeligible", where=then)[1], groups)
    ok = most and all(k in got and got[k][1] is None for k in most)
    run.check(8, "a group where all but a few have free school meals is hidden too", ok, str(sorted(most)))
    asked, wrong = counts.whatever_is_asked()
    name = f"{asked} questions that may be asked: nothing under 10 on either side, the rest to the nearest 5"
    run.check(8, name, not wrong and asked == 168, f"{len(wrong)} wrong {wrong[:2]}")
    q8_refused(run, data, counts)


def q8_refused(run: Staff, data: Labelled, counts: Counts) -> None:
    for name, change in UNSAFE.items():
        status, body = counts.ask(**{"group_by": ["URN"], "measure": "FSMeligible", **change})
        ok = (status, reason(body)) == (403, "UNSAFE_GROUPING") and "result" not in body
        run.check(8, f"refused: {name}", ok, f"{status} {reason(body)}")
    evals_own = run.grant(counts.agent, entry("aggregate", table=[CENSUS], measure=["FSMeligible"]))[0]
    one_pupil = counts.ask(["URN"], "FSMeligible", evals_own, where={PUPIL_ID: "P0011"})
    run.expect(8, "the mandate from questions 0 to 5 cannot count one pupil", one_pupil, "UNSAFE_GROUPING")
    run.expect(8, "nor pupils in care", counts.ask(["URN"], mandate=evals_own), "CONSTRAINT_VIOLATED")
    status, body = counts.ask(["SchoolLA"], "URN", table="schools")
    ok = status == 200 and [r.get("total") for r in rows_of(body)] == [len(data.schools)]
    run.check(8, "the public list of schools is counted as it is", ok, f"{status} {rows_of(body)}")


# ---------------------------------------------------------------- question 9: should a person approve this first?


class Approvals:
    """A person, their agent, and a mandate to correct one field at Dunmore.

    No two corrections asked for are alike, so that each can be told apart.
    """

    def __init__(self, run: Staff, data: Labelled):
        run.person(APPROVER, **{**EVERYTHING, "urns": [DUNMORE]})
        self.run, self.agent = run, run.key()
        self.pupil, self.second = data.year_group(DUNMORE, 11)[:2]
        self.now = data.latest(self.pupil)["Language"]
        self.new = next(v for v in ("1_ENG", "2_OTH") if v != self.now)
        self.asked, self.approved, self.n = {}, [], 0
        self.before = len(self.corrections())
        self.mandate, _ = self.grant()

    @staticmethod
    def corrections() -> list[dict]:
        """What the data server has written down. It runs from this checkout, or shares its data folder."""
        from mcp_server.api import routes_mcp  # noqa: PLC0415

        path = routes_mcp.WRITES_PATH
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []

    def grant(self, ttl: int = 600, who=None, **over) -> tuple[str, int]:
        job = {"principal": APPROVER, "deny": [], "clearance": 3, "purpose_code": "record_correction", **over}
        return self.run.grant(who or self.agent, entry("write", urn=[DUNMORE], column=["Language"]), ttl=ttl, **job)

    def write(self, mandate: str = "", **change) -> tuple[int, dict]:
        self.n += 1
        fix = {"pupil_id": self.pupil, "urn": DUNMORE, "column": "Language", "value": self.new}
        self.asked = {**fix, "reason": f"eval {self.n}", **change}
        return self.run.call(self.agent, mandate or self.mandate, "write", **self.asked)

    def held(self, mandate: str = "") -> str:
        return self.write(mandate)[1].get("hold_id", "")

    def answer(self, hold: str, word: str = "approve", principal: str = APPROVER, **kw) -> tuple[int, dict]:
        return self.run.ask_as(principal, "/holds/answer", "answer", hold=hold, answer=word, **kw)

    def waiting(self, principal: str = APPROVER) -> dict[str, dict]:
        return {h["id"]: h for h in self.run.ask_as(principal, "/holds", "holds")[1].get("holds", [])}

    def not_listed(self, hold: str, principal: str = APPROVER) -> bool:
        """The list opens, and this is not on it."""
        status, body = self.run.ask_as(principal, "/holds", "holds")
        return bool(hold) and status == 200 and hold not in [h["id"] for h in body.get("holds", [])]

    def state(self, hold: str, mandate: str = "") -> str | None:
        return self.run.collect(self.agent, mandate or self.mandate, hold)[1].get("held", {}).get("state")

    def stays(self, name: str, hold: str, response: tuple[int, dict], expected: str) -> None:
        """Refused, and the call is still waiting for its person."""
        after = self.state(hold)
        ok = (response[0], reason(response[1]), after) == (403, expected, "waiting")
        self.run.check(9, name, ok, f"expected {expected}, got {said(response)}, then {after}")

    def stopped(self, name: str, hold: str, expected: str, then: dict, back: dict) -> None:
        """The person changes while it waits. They say yes, and it is refused for good."""
        self.run.person(APPROVER, **then)
        response = self.answer(hold)
        self.run.person(APPROVER, **back)
        after = self.state(hold)
        again = reason(self.answer(hold)[1])
        ok = (response[0], reason(response[1]), after, again) == (403, expected, "blocked", "HOLD_NOT_WAITING")
        self.run.check(9, name, ok, f"expected {expected}, got {said(response)}, then {after}, then {again}")


def q9_approval(run: Staff, data: Labelled) -> None:
    at = Approvals(run, data)
    status, body = at.write()
    hold, asked = body.get("hold_id", ""), at.asked
    run.check(9, "a correction is held, not done", status == 202 and hold and "result" not in body, reason(body))
    item = at.waiting().get(hold, {})
    seen = item.get("preview", {})
    ok = item.get("arguments") == asked and (seen.get("name"), seen.get("now")) == (data.names[at.pupil], at.now)
    run.check(9, "the person is shown whose record, what it says now and what it would say", ok, str(seen))
    run.check(9, "nobody else is shown it", at.not_listed(hold, OTHER))
    q9_not_approved(run, at, hold)
    q9_once(run, at, hold, asked)
    q9_whose_result(run, at)
    q9_while_it_waits(run, at)
    q9_how_long(run, at)
    q9_letters(run, data, at)

    denied, _ = at.grant(deny=DEFAULT_DENY)
    run.expect(9, "a mandate with the usual deny list", at.write(denied), "DENIED_BY_RULE")
    run.expect(9, "a column it was not given", at.write(column="Gender", value="F"), "CONSTRAINT_VIOLATED")
    run.expect(9, "a pupil at another school", at.write(urn=ASHFIELD), "CONSTRAINT_VIOLATED")
    kept = ("pupil_id", "urn", "column", "after", "reason")
    made = [tuple(c.get(k) for k in kept) for c in at.corrections()[at.before :]]
    wanted = [tuple({**a, "after": a["value"]}[k] for k in kept) for a in at.approved]
    name = f"the data server made the {len(wanted)} corrections that were approved, once each, and no others"
    run.check(9, name, made == wanted and len(wanted) == 3, f"{len(made)} made")
    entries = run.entries(APPROVER, root=claims_of(at.mandate)["jti"])
    reasons = [e["reason"] for e in entries]
    told = {"SENSITIVE_TOOL", "RELEASING", "REFUSED_BY_PERSON", "PERSON_LOST_ACCESS", "CLEARANCE_TOO_LOW"}
    ok = told | {"BUDGET_EXCEEDED"} <= set(reasons) and reasons.count("APPROVED_BY_PERSON") == 2
    run.check(9, "the log has it asked, approved twice, refused and blocked", ok, str(sorted(set(reasons))))
    releasing = [e["ts"] for e in entries if e["reason"] == "RELEASING"][:2]
    wrote = [c["ts"] for c in at.corrections()[at.before :]][:2]
    ok = len(releasing) == len(wrote) == 2 and all(r <= w for r, w in zip(releasing, wrote, strict=True))
    run.check(9, "each was recorded before it was made", ok)
    hidden = {(e["args"].get("value"), e["args"].get("reason")) for e in entries}
    run.check(9, "and neither the new value nor the reason given", hidden == {("(not recorded)",) * 2}, str(hidden))


def q9_not_approved(run: Staff, at: Approvals, hold: str) -> None:
    """Everything that is not this person, saying yes to this call, just now."""
    not_them = "APPROVER_NOT_VERIFIED"
    at.stays("the agent approves it with its own key", hold, at.answer(hold, key=at.agent), not_them)
    in_their_name = at.answer(hold, key=run.person_keys[OTHER])
    at.stays("another person signs in this person's name", hold, in_their_name, not_them)
    real = at.answer(hold, principal=OTHER)
    at.stays("another person approves as themselves", hold, real, "HOLD_NOT_WAITING")
    made_up = at.answer("no-such-call", principal=OTHER)
    ok = made_up == real and (made_up[0], reason(made_up[1])) == (403, "HOLD_NOT_WAITING")
    run.check(9, "they cannot tell a real call from a made-up one", ok, f"{said(real)} and {said(made_up)}")
    nobody = at.answer(hold, principal="eval:nobody", key=at.agent)
    at.stays("a person nobody has heard of approves it", hold, nobody, not_them)
    no = at.answer(hold, "refuse", principal=OTHER)
    at.stays("another person says no to it", hold, no, "HOLD_NOT_WAITING")
    for word in ("", "yes", "Approve", "approve "):
        at.stays(f"an answer of {word!r}", hold, at.answer(hold, word), "ANSWER_NOT_CLEAR")
    flipped = at.answer(hold, "refuse", over={"answer": "approve"})
    at.stays("a signed no, changed to a yes", hold, flipped, not_them)
    moved = at.answer(at.held(), over={"hold": hold})
    at.stays("an answer to one call, moved to another", hold, moved, not_them)
    mine = run.person_keys[APPROVER]
    yes = signed_by(mine, APPROVER, "answer", hold=hold, answer="approve")
    again = run.post("/holds/answer", {**yes, "nonce": secrets.token_urlsafe(16)})
    at.stays("a signed yes with another nonce put in", hold, again, not_them)
    again = run.post("/holds/answer", {**yes, "ts": yes["ts"] + 1})
    at.stays("a signed yes with another time put in", hold, again, not_them)
    for_the_log = {**signed_by(mine, APPROVER, "log"), "hold": hold, "answer": "approve"}
    at.stays("a signature for reading the log", hold, run.post("/holds/answer", for_the_log), not_them)
    as_a_log = signed_by(mine, APPROVER, "log", hold=hold, answer="approve")
    at.stays("the same words signed as a log request", hold, run.post("/holds/answer", as_a_log), not_them)
    for seconds in TOO_OLD, TOO_NEW:
        late = at.answer(hold, ts=int(time.time()) + seconds)
        at.stays(f"an answer signed {seconds} seconds from now", hold, late, not_them)
    run.person(APPROVER, status="away")
    away = at.answer(hold)
    run.person(APPROVER, status="active")
    at.stays("the person is away", hold, away, "PERSON_PAUSED")
    claimed = at.write(approved=True, approved_by=APPROVER)
    run.expect(9, "the agent says it is approved, in the request", claimed, "STEP_UP")


def q9_once(run: Staff, at: Approvals, hold: str, asked: dict) -> None:
    yes = signed_by(run.person_keys[APPROVER], APPROVER, "answer", hold=hold, answer="approve")
    status, body = run.post("/holds/answer", yes)
    at.approved.append(asked)
    done = body.get("result") or {}
    ok = status == 200 and body.get("state") == "done" and (done.get("before"), done.get("after")) == (at.now, at.new)
    run.check(9, "the person approves, and it is done", ok, f"{said((status, body))} {body.get('state')}")
    run.expect(9, "they approve it again", at.answer(hold), "HOLD_NOT_WAITING")
    run.expect(9, "the same signed answer, sent again", run.post("/holds/answer", yes), "APPROVER_NOT_VERIFIED")
    first, again = run.collect(at.agent, at.mandate, hold)[1], run.collect(at.agent, at.mandate, hold)[1]
    ok = (first.get("result") or {}).get("after") == at.new and "held" in again and "result" not in again
    run.check(9, "the agent collects the result once, and then it is gone", ok, str(again.get("held")))
    race = at.held()
    at.approved.append(at.asked)
    mine, start = run.person_keys[APPROVER], threading.Barrier(10)
    bodies = [signed_by(mine, APPROVER, "answer", hold=race, answer="approve") for _ in range(start.parties)]

    def at_once(signed: dict) -> int:
        start.wait()
        return run.post("/holds/answer", signed)[0]

    with ThreadPoolExecutor(start.parties) as pool:
        codes = sorted(pool.map(at_once, bodies))
    run.check(9, "ten approvals at the same moment: one counts", codes == [200] + [403] * 9, str(codes))
    no = at.held()
    said_no = at.answer(no, "refuse")[0]
    ok = said_no == 200 and at.state(no) == "refused" and "result" not in run.collect(at.agent, at.mandate, no)[1]
    run.check(9, "the person says no, and nothing happens", ok, f"{said_no} {at.state(no)}")
    run.expect(9, "approving it after saying no", at.answer(no), "HOLD_NOT_WAITING")


def q9_whose_result(run: Staff, at: Approvals) -> None:
    """Approved and not yet collected. Only the agent that asked, under the job it asked under, may have it."""
    family, _ = at.grant(helpers=1)
    hold = at.held(family)
    at.approved.append(at.asked)
    run.check(9, "another correction is approved", at.answer(hold)[0] == 200)
    thief, helper = run.key(), run.key()
    theirs, _ = at.grant(who=thief)
    run.expect(9, "another agent asks for the result", run.collect(thief, theirs, hold), "OUT_OF_SCOPE")
    other_job, _ = at.grant()
    run.expect(9, "the same agent, under another job", run.collect(at.agent, other_job, hold), "OUT_OF_SCOPE")
    part = entry("write", urn=[DUNMORE], column=["Language"])
    handed = delegate_mandate(family, at.agent, helper.public_key(), scope=[part], ttl=300)
    run.expect(9, "a helper of the same job", run.collect(helper, handed, hold), "OUT_OF_SCOPE")
    got = run.collect(at.agent, family, hold)[1].get("result") or {}
    run.check(9, "it is still there for the agent that asked", got.get("after") == at.new, str(sorted(got)))


def q9_while_it_waits(run: Staff, at: Approvals) -> None:
    back = {"urns": [DUNMORE], "clearance": 4, "daily_pupils": 100_000}
    lost, low, full = "PERSON_LOST_ACCESS", "CLEARANCE_TOO_LOW", "BUDGET_EXCEEDED"
    at.stopped("they lost that school while it waited", at.held(), lost, {"urns": [ELMWOOD]}, back)
    at.stopped("their clearance fell while it waited", at.held(), low, {"clearance": 2}, back)
    at.stopped("their day's limit was used up while it waited", at.held(), full, {"daily_pupils": 0}, back)
    waits = at.held()
    run.person(APPROVER, urns=[ELMWOOD])
    shown = at.waiting().get(waits, {}).get("preview", {"name": "it is not listed"})
    run.person(APPROVER, **back)
    ok = not shown.keys() & {"name", "now"}
    run.check(9, "while they do not cover that school, they are not shown the pupil", ok, str(sorted(shown)))
    dead, idx = at.grant()
    revoked = at.held(dead)
    revoke_mandate(run.state, idx)
    run.expect(9, "the mandate was taken back while it waited", at.answer(revoked), "REVOKED")
    run.expect(9, "and it can no longer be approved", at.answer(revoked), "HOLD_NOT_WAITING")

    busy, _ = at.grant()
    statuses = {at.write(busy, value=f"v{i}")[0] for i in range(MOST_WAITING)}
    status, body = at.write(busy, value="one more")
    ok = statuses == {202} and (status, reason(body)) == (403, "TOO_MANY_WAITING")
    run.check(9, f"{MOST_WAITING} may wait, and no more", ok, said((status, body)))
    run.expect(9, "another job is not blocked by that", at.write(), "STEP_UP")


def q9_how_long(run: Staff, at: Approvals) -> None:
    short, _ = at.grant(ttl=3)
    unanswered = at.held(short)
    listed = unanswered in at.waiting()
    time.sleep(max(0.0, claims_of(short)["exp"] + 0.5 - time.time()))
    run.check(9, "nobody answers: it is listed, and lapses with its mandate", listed and at.not_listed(unanswered))
    run.expect(9, "approving it after it lapsed", at.answer(unanswered), "HOLD_NOT_WAITING")
    run.expect(9, "its agent asks after it", run.collect(at.agent, short, unanswered), "EXPIRED")
    soon, _ = at.grant()
    waited = at.held(soon)
    item = at.waiting().get(waited, {})
    ok = item and abs(item["expires"] - claims_of(soon)["exp"]) < 1
    run.check(9, "a call never waits longer than its mandate lasts", ok, str(item.get("expires")))
    long, _ = at.grant(ttl=40_000)
    waited = at.held(long)
    item = at.waiting().get(waited, {})
    lives = item.get("expires", 0) - item.get("created", 0)
    run.check(9, "nor longer than a school day", abs(lives - SCHOOL_DAY) < 2, f"{lives:.0f} seconds")


def q9_letters(run: Staff, data: Labelled, at: Approvals) -> None:
    pupils = [at.pupil, at.second]
    scope = entry("draft", urn=[DUNMORE], kind=["absence"])
    job = {"principal": APPROVER, "ttl": 600, "clearance": 2, "purpose_code": "absence_letters"}
    letters, _ = run.grant(at.agent, scope, **job)
    _, body = run.call(at.agent, letters, "draft", urn=DUNMORE, kind="absence", pupil_ids=pupils)
    batch = body.get("hold_id", "")
    shown = at.waiting().get(batch, {}).get("preview", {}).get("letters", [])
    whole = [x.get(PUPIL_ID) for x in shown if data.names.get(x.get(PUPIL_ID), "?") in x.get("letter", "")]
    run.check(9, "letters are shown in full before anyone says yes", whole == pupils, f"{len(shown)} letters")
    at.answer(batch)
    got = run.collect(at.agent, letters, batch)[1].get("result")
    run.check(9, "what is released is what was shown", shown and got == shown)


# ---------------------------------------------------------------- question 12: is it the job it was given for?


class Jobs:
    """One agent, and mandates that differ only in their purpose: every tool, at Dunmore, at the highest clearance."""

    def __init__(self, run: Staff, data: Labelled):
        self.run, self.agent = run, run.key()
        pupil = data.year_group(DUNMORE, 11)[0]
        self.calls = {
            "get": {"path": SCHOOLS_FILE},
            "roster": {"urn": DUNMORE, "year_group": 11, **SPRING},
            "search": {"query": pupil, "urn": DUNMORE},
            "pupil": {"pupil_id": pupil, "urn": DUNMORE},
            "draft": {"urn": DUNMORE, "kind": "absence", "pupil_ids": [pupil]},
            "write": {"pupil_id": pupil, "urn": DUNMORE, "column": "Ethnicity", "value": "AOEG", "reason": "eval"},
            "aggregate": {"table": CENSUS, "group_by": ["URN"], "measure": "InCareAtCurrentSchool"},
        }

    def given(self, code, clearance: int = 4, **kw) -> str:
        scope = [
            entry("get", path=[SCHOOLS_FILE, NAMES_FILE]),
            entry("roster", "search", "pupil", "draft", "write", urn=[DUNMORE]),
            entry("aggregate", table=[CENSUS]),
        ]
        job = {"deny": [], "clearance": clearance, "budget": {"pupils": 60}, "purpose_code": code}
        return self.run.grant(self.agent, *scope, **{"ttl": 900, **job, **kw})[0]

    def call(self, mandate: str, tool: str, who=None, **change) -> tuple[int, dict]:
        return self.run.call(who or self.agent, mandate, tool, **{**self.calls[tool], **change})


def q12_purpose(run: Staff, data: Labelled) -> None:
    jobs = Jobs(run, data)
    call, given = jobs.call, jobs.given
    letters, safeguarding = given("absence_letters"), given("safeguarding_review")
    status, body = call(safeguarding, "pupil")
    ok = status == 200 and body.get("result") == data.full_record(jobs.calls["pupil"]["pupil_id"])
    run.check(12, "safeguarding review: the pupil's record, care status included", ok, said((status, body)))
    status, body = call(letters, "pupil")
    ok = (status, reason(body)) == (403, "PURPOSE_MISMATCH") and "result" not in body
    run.check(12, "absence letters: the same record, same school and scope", ok, said((status, body)))
    run.expect(12, "absence letters: the letter", call(letters, "draft"), "STEP_UP")
    run.expect(12, "safeguarding review: the same letter", call(safeguarding, "draft"), "PURPOSE_MISMATCH")

    for code, tools in PURPOSE_TOOLS.items():
        mandate = given(code)
        got = {tool: call(mandate, tool) for tool in jobs.calls}
        may = {tool for tool, (status, _) in got.items() if status in (200, 202)}
        refused = {reason(body) for tool, (_, body) in got.items() if tool not in may}
        ok = may == tools and refused == {"PURPOSE_MISMATCH"}
        why = f"{sorted(may)}, else {sorted(map(str, refused))}"
        run.check(12, f"{code} may use {sorted(tools)} and nothing else", ok, why)
    for code in NOT_A_PURPOSE:
        mandate = given(code)
        outcomes = {reason(call(mandate, tool)[1]) for tool in jobs.calls}
        run.check(12, f"a purpose of {code!r} allows nothing", outcomes == {"PURPOSE_MISMATCH"}, str(outcomes))

    claimed = call(letters, "pupil", purpose_code="safeguarding_review", purpose="Safeguarding review")
    run.expect(12, "the agent says in the request that it is for safeguarding", claimed, "PURPOSE_MISMATCH")
    worded = given("absence_letters", purpose="Safeguarding review: full records of pupils in care")
    run.expect(12, "the mandate's own wording says safeguarding", call(worded, "pupil"), "PURPOSE_MISMATCH")
    entries = [[e["tool"], e["reason"]] for e in run.entries(PRINCIPAL, root=claims_of(letters)["jti"])]
    ok = [f"{SERVER}.pupil", "PURPOSE_MISMATCH"] in entries
    run.check(12, "the person can see that it tried", ok, f"{len(entries)} entries")
    q12_caps(run, data, jobs, safeguarding)
    q12_helper(run, jobs)


def q12_caps(run: Staff, data: Labelled, jobs: Jobs, safeguarding: str) -> None:
    """The purpose, the clearance and the scope each cap the others."""
    call, given = jobs.call, jobs.given
    query = jobs.calls["search"]["query"]
    for code, level in (("find_pupil", 3), ("meals_check", 3)):
        status, body = call(given(code), "search")
        ok = status == 200 and rows_of(body) == data.found(DUNMORE, query, level) != []
        run.check(12, f"{code} at clearance 4 sees what {level} may", ok, str(sorted(columns_of(body) & SPECIAL)))
    status, body = call(given("meals_check"), "search", query="BLAC")
    ok = status == 200 and rows_of(body) == []
    run.check(12, "nor can it search for what it hides", ok, f"{status}, {len(rows_of(body))} rows")
    names = call(given("newsletter"), "get", path=NAMES_FILE)
    run.expect(12, "a newsletter at clearance 4 does not get the names", names, "CLEARANCE_TOO_LOW")
    for code, tool in (("safeguarding_review", "pupil"), ("record_correction", "write"), ("pupil_counts", "aggregate")):
        low = call(given(code, clearance=3), tool)
        run.expect(12, f"{code} cannot raise a clearance of 3", low, "CLEARANCE_TOO_LOW")
    unsaid = run.grant(jobs.agent, entry("pupil", urn=[DUNMORE]), purpose_code="safeguarding_review")[0]
    run.expect(12, "a purpose does not stand in for a clearance", call(unsaid, "pupil"), "CLEARANCE_TOO_LOW")
    elsewhere = call(safeguarding, "pupil", urn=ASHFIELD)
    run.expect(12, "the purpose does not open another school", elsewhere, "CONSTRAINT_VIOLATED")
    only = entry("roster", urn=[DUNMORE])
    narrow = run.grant(jobs.agent, only, clearance=4, purpose_code="safeguarding_review")[0]
    run.expect(12, "the purpose does not add a tool to the scope", call(narrow, "pupil"), "OUT_OF_SCOPE")


def q12_helper(run: Staff, jobs: Jobs) -> None:
    helper, handed = run.key(), [entry("roster", "pupil", urn=[DUNMORE])]
    parent = jobs.given("absence_letters", helpers=1)
    part = delegate_mandate(parent, jobs.agent, helper.public_key(), scope=handed, ttl=600)
    run.expect(12, "a helper of the letters agent: the class list", jobs.call(part, "roster", helper), "ALLOW")
    run.expect(12, "a helper of the letters agent: a record", jobs.call(part, "pupil", helper), "PURPOSE_MISMATCH")
    wider = child(parent, jobs.agent, helper.public_key(), handed, purpose_code="safeguarding_review")
    run.expect(12, "a helper given another purpose", jobs.call(wider, "pupil", helper), "CHILD_WIDER")


# ---------------------------------------------------------------- question 13: the person changes


class Colleagues:
    """J covers Dunmore and Elmwood, Priya covers Elmwood. Each has an agent, and the two mandates say the same."""

    def __init__(self, run: Staff, data: Labelled):
        run.person(LEAVER, **{**EVERYTHING, "urns": [DUNMORE, ELMWOOD], "successor": None})
        run.person(PRIYA, **{**EVERYTHING, "urns": [ELMWOOD], "successor": None})
        self.run, self.js, self.priyas, self.helper = run, run.key(), run.key(), run.key()
        self.pupil, self.other = data.year_group(ELMWOOD, 11)[0], data.year_group(DUNMORE, 11)[0]
        tools = entry("search", "roster", "pupil", "draft", urn=[ELMWOOD, DUNMORE])
        files = entry("get", path=[SCHOOLS_FILE, NAMES_FILE])
        self.scope = [tools, entry("aggregate", table=[CENSUS]), files]
        self.job = {"clearance": 4, "budget": {"pupils": 200}}
        self.j, _ = run.grant(self.js, *self.scope, principal=LEAVER, helpers=1, **self.job)
        self.priya, _ = run.grant(self.priyas, *self.scope, principal=PRIYA, **self.job)
        part = [entry("search", urn=[ELMWOOD])]
        self.child = delegate_mandate(self.j, self.js, self.helper.public_key(), scope=part, ttl=900)

    def search(self, mandate: str, who, urn: str = ELMWOOD) -> tuple[int, dict]:
        query = self.pupil if urn == ELMWOOD else self.other
        return self.run.call(who, mandate, "search", query=query, urn=urn)

    def j_searches(self, urn: str = ELMWOOD) -> tuple[int, dict]:
        return self.search(self.j, self.js, urn)

    def priya_searches(self, urn: str = ELMWOOD) -> tuple[int, dict]:
        return self.search(self.priya, self.priyas, urn)

    def priya_asks(self, tool: str, **ask) -> tuple[int, dict]:
        return self.run.call(self.priyas, self.priya, tool, **ask)


def q13_person(run: Staff, data: Labelled) -> None:
    two = Colleagues(run, data)
    run.expect(13, "J's agent, before", two.j_searches(), "ALLOW")
    run.expect(13, "J's agent at Dunmore, before", two.j_searches(DUNMORE), "ALLOW")
    run.expect(13, "J's agent's helper, before", two.search(two.child, two.helper), "ALLOW")
    q13_covers(run, data, two)
    q13_missing(run, data)
    q13_leaves(run, two)
    q13_changes(run, data, two)


def q13_covers(run: Staff, data: Labelled, two: Colleagues) -> None:
    """What Priya's agent may do is never more than Priya may."""
    lost = "PERSON_LOST_ACCESS"
    run.expect(13, "Priya's agent at Elmwood, which she covers", two.priya_searches(), "ALLOW")
    run.expect(13, "her mandate says Dunmore too, but she does not cover it", two.priya_searches(DUNMORE), lost)
    for tool, ask in {
        "roster": {"year_group": 11, **SPRING},
        "pupil": {"pupil_id": two.other},
        "draft": {"kind": "absence", "pupil_ids": [two.other]},
    }.items():
        run.expect(13, f"nor {tool} there", two.priya_asks(tool, urn=DUNMORE, **ask), lost)

    def count(where: dict) -> tuple[int, dict]:
        ask = {"table": CENSUS, "group_by": ["Gender"], "measure": "FSMeligible", "where": where}
        return two.priya_asks("aggregate", **ask)

    run.expect(13, "she counts pupils at Elmwood", count({"URN": ELMWOOD}), "ALLOW")
    run.expect(13, "she counts pupils at Dunmore", count({"URN": DUNMORE}), lost)
    run.expect(13, "she counts pupils across every school", count({}), lost)
    run.expect(13, "the public list of schools is nobody's school", two.priya_asks("get", path=SCHOOLS_FILE), "ALLOW")
    run.expect(13, "the file of every pupil's name", two.priya_asks("get", path=NAMES_FILE), lost)
    status, body = run.ask_as(PRIYA, "/person/class", "class", urn=ELMWOOD, year=11)
    ok = status == 200 and sorted(body.get("pupils", {})) == data.year_group(ELMWOOD, 11)
    run.check(13, "she looks at a class list at Elmwood herself", ok, said((status, body)))
    listing = run.ask_as(PRIYA, "/person/class", "class", urn=DUNMORE, year=11)
    run.expect(13, "she looks at a class list at Dunmore herself", listing, lost)
    hers = run.ask_as(PRIYA, "/person/schools", "schools")[1].get("schools")
    run.check(13, "she is offered her own schools only", hers == {ELMWOOD: data.schools[ELMWOOD]}, str(hers))


def q13_missing(run: Staff, data: Labelled) -> None:
    """Missing means least: whatever is not said about a person is not theirs. They have no key and can do nothing."""
    agent, pupil = run.key(), data.year_group(ELMWOOD, 11)[0]
    for field, expected in {
        "status": "PERSON_PAUSED",
        "urns": "PERSON_LOST_ACCESS",
        "clearance": "CLAIM_NOT_UNDERSTOOD",
        "daily_pupils": "CLAIM_NOT_UNDERSTOOD",
    }.items():
        who = f"eval:no-{field}"
        set_person(run.state, who, **{k: v for k, v in EVERYTHING.items() if k != field})
        mandate, _ = run.grant(agent, entry("search", urn=[ELMWOOD]), principal=who, clearance=3)
        got = run.call(agent, mandate, "search", query=pupil, urn=ELMWOOD)
        run.expect(13, f"a person with no {field} recorded", got, expected)
        set_person(run.state, who, status="left")
    listing = run.ask_as(OTHER, "/person/class", "class", urn=ASHFIELD, year=11)
    run.expect(13, "a person cleared to 1 looks at a class list", listing, "CLEARANCE_TOO_LOW")


def q13_leaves(run: Staff, two: Colleagues) -> None:
    paused, ask = "PERSON_PAUSED", {"urn": ELMWOOD, "kind": "absence", "pupil_ids": [two.pupil]}
    hold = run.call(two.js, two.j, "draft", **ask)[1].get("hold_id", "")

    def waits_for(principal: str) -> bool:
        return hold in [h["id"] for h in run.ask_as(principal, "/holds", "holds")[1].get("holds", [])]

    run.check(13, "a letter waits for J", bool(hold) and waits_for(LEAVER))
    for status in ("away", "left", "Active", "", None):
        run.person(LEAVER, status=status)
        run.expect(13, f"J is marked {status!r}", two.j_searches(), paused)
    run.person(LEAVER, status="left")
    run.expect(13, "J has left: the helper stops too", two.search(two.child, two.helper), paused)
    run.expect(13, "J has left: J's own log", run.ask_as(LEAVER, "/log", "log"), paused)
    listing = run.ask_as(LEAVER, "/person/class", "class", urn=ELMWOOD, year=11)
    run.expect(13, "J has left: a class list", listing, paused)
    yes = run.ask_as(LEAVER, "/holds/answer", "answer", hold=hold, answer="approve")
    run.expect(13, "J has left: J approves the letter that was waiting", yes, paused)
    for status in ("left", "active"):
        run.person(LEAVER, status=status, successor=PRIYA)
        hers = run.ask_as(PRIYA, "/holds/answer", "answer", hold=hold, answer="approve")
        run.expect(13, f"Priya, named as successor, approves J's letter (J is {status})", hers, "HOLD_NOT_WAITING")
        roots = {e["root"] for e in run.entries(PRIYA)}
        ok = bool(roots) and claims_of(two.j)["jti"] not in roots and not waits_for(PRIYA)
        run.check(13, f"nor does she see J's log or what waits for J (J is {status})", ok)
        run.expect(
            13, f"nor may her agent use J's mandate (J is {status})", two.search(two.j, two.priyas), "POP_FAILED"
        )
    run.person(LEAVER, status="left")
    run.expect(13, "with a successor named, J's agents stay paused", two.j_searches(), paused)
    run.expect(13, "Priya's own agent is not affected", two.priya_searches(), "ALLOW")
    run.person(LEAVER, status="active")
    run.expect(13, "J comes back: the same mandate works again", two.j_searches(), "ALLOW")
    run.check(13, "and the letter is still waiting", waits_for(LEAVER))
    yes = run.ask_as(LEAVER, "/holds/answer", "answer", hold=hold, answer="approve")
    run.check(13, "J approves it, and it is done", yes[0] == 200 and yes[1].get("state") == "done", said(yes))


def q13_changes(run: Staff, data: Labelled, two: Colleagues) -> None:
    lost = "PERSON_LOST_ACCESS"
    run.person(LEAVER, urns=[ELMWOOD])
    run.expect(13, "J loses Dunmore: Dunmore", two.j_searches(DUNMORE), lost)
    run.expect(13, "J loses Dunmore: Elmwood still works", two.j_searches(), "ALLOW")
    run.person(LEAVER, urns=[DUNMORE])
    run.expect(13, "J loses Elmwood: the helper loses it too", two.search(two.child, two.helper), lost)
    run.person(PRIYA, urns=[FAIRHAVEN])
    run.expect(13, "Priya moves to Fairhaven: Elmwood", two.priya_searches(), lost)
    run.person(PRIYA, urns=[])
    run.expect(13, "Priya covers no school", two.priya_searches(), lost)
    run.person(PRIYA, urns=[ELMWOOD], clearance=3)
    record = two.priya_asks("pupil", pupil_id=two.pupil, urn=ELMWOOD)
    run.expect(13, "Priya's clearance drops to 3: a record", record, "CLEARANCE_TOO_LOW")
    status, body = two.priya_searches()
    ok = status == 200 and rows_of(body) == data.found(ELMWOOD, two.pupil, 3) != []
    run.check(13, "and a search gives only what 3 may see", ok, str(sorted(columns_of(body) & SPECIAL)))
    run.person(PRIYA, clearance=4, daily_pupils=0)
    run.expect(13, "Priya's daily limit drops to 0", two.priya_searches(), "BUDGET_EXCEEDED")
    run.person(PRIYA, daily_pupils=100_000)
    run.expect(13, "and back", two.priya_searches(), "ALLOW")
    nobodys = run.resigned(two.priya, delegator={**claims_of(two.priya)["delegator"], "principal": "eval:nobody"})
    run.expect(
        13, "a mandate in the name of someone not on the list", two.search(nobodys, two.priyas), "PERSON_UNKNOWN"
    )

    def unsigned() -> tuple[bool, str]:
        try:
            run.grant(two.priyas, *two.scope, principal="eval:nobody", **two.job)
        except ValueError as e:
            return True, f"refused: {str(e)[:50]}"
        return False, "it was signed"

    run.attempt(13, "nothing is signed for someone who is not on the list", unsigned)


# ---------------------------------------------------------------- question 15: the newsletter


class Clearances:
    """One agent, and mandates for Castleton that differ only in their clearance."""

    def __init__(self, run: Staff):
        self.run, self.agent = run, run.key()
        self.scope = [
            entry("search", "roster", "pupil", "draft", "write", urn=[CASTLETON]),
            entry("get", path=[SCHOOLS_FILE, MANIFEST_FILE, NAMES_FILE]),
            entry("aggregate", table=[CENSUS]),
        ]
        room = {"pupils": 1000}  # a pupil asked about counts, even when nothing is found
        job = {"deny": [], "ttl": 900, "budget": room}
        self.cleared = {c: run.grant(self.agent, *self.scope, clearance=c, **job)[0] for c in (1, 2, 3, 4)}
        self.unsaid, _ = run.grant(self.agent, *self.scope, **job)

    def call(self, mandate: str, tool: str, **arguments) -> tuple[int, dict]:
        return self.run.call(self.agent, mandate, tool, **arguments)

    def count(self, mandate: str, measure: str) -> tuple[int, dict]:
        return self.call(mandate, "aggregate", table=CENSUS, group_by=["URN"], measure=measure)

    def search(self, mandate: str, query: str) -> tuple[int, dict]:
        return self.call(mandate, "search", query=query, urn=CASTLETON)


def q15_newsletter(run: Staff, data: Labelled) -> None:
    at = Clearances(run)
    newsletter, counts = at.cleared[1], at.cleared[3]
    pupil = data.year_group(CASTLETON, 11)[0]
    run.expect(15, "newsletter: the list of schools", at.call(newsletter, "get", path=SCHOOLS_FILE), "ALLOW")
    run.expect(15, "newsletter: the manifest", at.call(newsletter, "get", path=MANIFEST_FILE), "ALLOW")
    fix = {"pupil_id": pupil, "urn": CASTLETON, "column": "Gender", "value": "F", "reason": "eval"}
    personal = {
        "a class list": ("roster", {"urn": CASTLETON, "year_group": 11, **SPRING}),
        "a pupil's record": ("pupil", {"pupil_id": pupil, "urn": CASTLETON}),
        "every name": ("get", {"path": NAMES_FILE}),
        "a letter": ("draft", {"urn": CASTLETON, "kind": "absence", "pupil_ids": [pupil]}),
        "a correction": ("write", fix),
    }
    for name, (tool, ask) in personal.items():
        status, body = at.call(newsletter, tool, **ask)
        ok = (status, reason(body)) == (403, "CLEARANCE_TOO_LOW") and not body.keys() & {"result", "hold_id"}
        run.check(15, f"newsletter: {name}", ok, said((status, body)))
    low = "CLEARANCE_TOO_LOW"
    run.expect(15, "newsletter: count free school meals", at.count(newsletter, "FSMeligible"), low)
    status, body = at.search(newsletter, pupil)
    ok = status == 200 and rows_of(body) == []
    run.check(15, "newsletter: searching for a pupil finds nobody", ok, f"{status} {len(rows_of(body))} rows")
    run.expect(15, "counts: free school meals by school", at.count(counts, "FSMeligible"), "ALLOW")
    run.expect(15, "counts: pupils in care", at.count(counts, "InCareAtCurrentSchool"), low)
    record = at.call(counts, "pupil", pupil_id=pupil, urn=CASTLETON)
    run.expect(15, "counts: a pupil's record", record, low)
    run.expect(15, "no clearance: pupils in care", at.count(at.unsaid, "InCareAtCurrentSchool"), low)
    q15_searches(run, data, at, pupil)

    run.person(EDITOR, **{**EVERYTHING, "clearance": 1})
    theirs = run.grant(at.agent, *at.scope, principal=EDITOR, clearance=4)[0]
    run.expect(15, "a person cleared to 1 cannot hand out more", at.call(theirs, "get", path=NAMES_FILE), low)
    run.expect(15, "they can hand out the list of schools", at.call(theirs, "get", path=SCHOOLS_FILE), "ALLOW")
    job = run.grant(at.agent, *at.scope, clearance=4, purpose_code="newsletter")[0]
    run.expect(15, "a newsletter purpose at clearance 4: search", at.search(job, pupil), "PURPOSE_MISMATCH")


def q15_searches(run: Staff, data: Labelled, at: Clearances, pupil: str) -> None:
    """A hidden value must not decide which rows come back, so every answer is compared with one worked out here."""

    def answers(mandate: str, clearance: int, query: str) -> tuple[bool, str]:
        status, body = at.search(mandate, query)
        want = data.searched(CASTLETON, query, clearance)
        if want is None:
            return (status, reason(body)) == (403, "QUERY_TOO_BROAD"), f"{query!r}: {said((status, body))}"
        ok = status == 200 and (rows_of(body), body.get("volume")) == want
        return ok, f"{query!r}: {said((status, body))}, {len(rows_of(body))} rows, {body.get('volume')}"

    codes = sorted({r[c] for r in data.census for c in data.levels if c not in (PUPIL_ID, "URN")})
    nearly = [f"{pupil}9", "BLACK", "SPRING", ",1,", "zz"]  # found nowhere, though something close to each is
    queries = [*codes, pupil, *data.pupils_at(CASTLETON)[-3:], "SCH03", "P1", "/24", *nearly]
    for clearance, mandate in [*at.cleared.items(), (3, at.unsaid)]:
        tried = [answers(mandate, clearance, q) for q in queries]
        wrong = [got for ok, got in tried if not ok]
        what = f"clearance {clearance}" if mandate != at.unsaid else "no clearance, which acts as 3"
        name = f"{what}: {len(queries)} searches, each with the rows and cells that {clearance} may see and no others"
        run.check(15, name, not wrong, str(wrong[:3]))
    hidden = [q for q in codes if data.found(CASTLETON, q, 4) and not data.found(CASTLETON, q, 3)]
    run.check(15, f"of those, {len(hidden)} find something at 4 and nothing below it", len(hidden) >= 5, str(hidden))


# ---------------------------------------------------------------- question 16: was that me?


def forgeries(mandate: str, priv) -> dict[str, tuple[str, str]]:
    """Mandates nobody granted, all in the name of the same person, and why each is refused."""
    header, claims = jwt.get_unverified_header(mandate), claims_of(mandate)
    head, _, sig = mandate.split(".")
    stranger = generate_keypair()[0]

    def signed(key, **change) -> str:
        return jwt.encode({**claims, **change}, priv_to_pem(key), algorithm="EdDSA", headers=header)

    def segment(obj: dict) -> str:
        return b64u(json.dumps(obj).encode())

    widened = {**claims, "scope": [entry("search")]}
    return {
        "signed by someone else": (signed(stranger), "SIG_INVALID"),
        "signed by the agent": (signed(priv), "SIG_INVALID"),
        "from an unknown issuer": (signed(stranger, iss="https://issuer.example"), "ISSUER_NOT_ACCREDITED"),
        "that is real, but edited": (f"{head}.{segment(widened)}.{sig}", "SIG_INVALID"),
        "with no signature": (f"{segment({**header, 'alg': 'none'})}.{segment(claims)}.", "SIG_INVALID"),
    }


class Story:
    """One person's access, used by their agent and then by others. `what` is what their log ought to say."""

    def __init__(self, run: Staff, data: Labelled):
        run.person(OWNER, **EVERYTHING)
        self.run, self.agent, self.stranger = run, run.key(), run.key()
        self.scope = [entry("search", urn=[ASHFIELD]), entry("write", urn=[ASHFIELD], column=["Language"])]
        self.job = {"principal": OWNER, "deny": [], "clearance": 3}
        self.mandate, self.idx = run.grant(self.agent, *self.scope, ttl=900, **self.job)
        self.root = claims_of(self.mandate)["jti"]
        self.first, self.second = data.year_group(ASHFIELD, 11)[:2]
        self.began, self.what = time.time(), []

    def call(self, query: str, urn: str = ASHFIELD, who=None, body: dict | None = None) -> dict:
        arguments = {"query": query, "urn": urn}
        body = body or signed_call(who or self.agent, self.mandate, "search", arguments)
        _, reply = self.run.post("/tools/call", body)
        self.what.append([body["arguments"], reply.get("decision", {}).get("decision"), reason(reply)])
        return body

    def told(self) -> None:
        mine = self.call(self.first)
        self.call(self.second)  # the thief, who has the agent's key as well as the mandate
        self.call("SPR", DUNMORE)
        self.call("SPR", ELMWOOD)
        self.call(self.first, who=self.stranger)  # somebody with a copy of the mandate and no key
        self.call(self.first, body=mine)  # the first request, sent again
        self.call(self.first, body={**mine, "nonce": secrets.token_urlsafe(16)})  # and again, with its nonce changed
        self.call(self.first, body={**mine, "ts": mine["ts"] + 1})  # and its time
        revoke_mandate(self.run.state, self.idx)
        self.call(self.second)


def q16_log(run: Staff, data: Labelled) -> None:
    story = Story(run, data)
    story.told()
    entries = run.entries(OWNER, root=story.root)
    got = [[e.get("args"), e.get("decision"), e.get("reason")] for e in entries]
    many = f"{len(got)} of {len(story.what)}"
    run.check(16, "their log: every request in order, refusals included", got == story.what, many)
    reasons = [r for _, _, r in got]
    expected = ["IN_SCOPE"] * 2 + ["CONSTRAINT_VIOLATED"] * 2 + ["POP_FAILED"] * 4 + ["REVOKED"]
    run.check(16, "allowed, refused, copied, replayed and revoked can be told apart", reasons == expected, str(reasons))
    times = [e.get("ts") or 0 for e in entries]
    ok = times == sorted(times) and all(story.began - 60 <= t <= time.time() + 60 for t in times) and len(times) == 9
    run.check(16, "each has its time", ok)
    sources = {e.get("source") for e in entries}
    run.check(16, "and the address it came from", sources and not sources & {None, "", "unknown"}, str(sources))
    run.check(16, "and what was asked of which tool", {e.get("tool") for e in entries} == {f"{SERVER}.search"})
    whose = [e.get("pupils") for e in entries]
    run.check(16, "and whose data came back", whose == [[story.first], [story.second], *[[]] * 7], str(whose))
    second_agent, helper = run.key(), run.key()
    also, _ = run.grant(second_agent, *story.scope, ttl=900, helpers=1, **story.job)
    run.call(second_agent, also, "search", query=story.first, urn=ASHFIELD)
    search = [entry("search", urn=[ASHFIELD])]
    part = delegate_mandate(also, second_agent, helper.public_key(), scope=search, ttl=300)
    run.call(helper, part, "search", query=story.second, urn=ASHFIELD)
    named = [{e.get("agent_id") for e in run.entries(OWNER, root=r)} for r in (story.root, claims_of(also)["jti"])]
    ok = named == [{thumbprint(story.agent)}, {thumbprint(second_agent), thumbprint(helper)}]
    run.check(16, "and which of their agents it was, helpers included", ok, str(named))
    expired, _ = run.grant(story.agent, *story.scope, ttl=-1, **story.job)  # dead for a second
    run.call(story.agent, expired, "search", query=story.first, urn=ASHFIELD)
    dead = [e.get("reason") for e in run.entries(OWNER, root=claims_of(expired)["jti"])]
    run.check(16, "an expired mandate that was tried is in its person's log", dead == ["EXPIRED"], str(dead))
    soon, jti = int(time.time()) + 3600, f"urn:uuid:{secrets.token_hex(16)}"
    run.call(story.agent, run.resigned(expired, jti=jti, nbf=soon, exp=soon + 600), "search", query="x", urn=ASHFIELD)
    early = [e.get("reason") for e in run.entries(OWNER, root=jti)]
    run.check(16, "and so is one that was tried before it starts", early == ["NOT_YET_VALID"], str(early))
    alarms = [words.activity(e, {})["alarm"] for e in entries if e["reason"] in {"IN_SCOPE", "POP_FAILED"}][:3]
    ok = alarms == [False, False, True]
    run.check(16, "use without the key is an alarm, ordinary use is not", ok, str(alarms))
    q16_readers(run, story)
    q16_forged(run, story)
    q16_kept(run, data, story)


def q16_readers(run: Staff, story: Story) -> None:
    def refused(name: str, response: tuple[int, dict]) -> None:
        status, body = response
        ok = (status, reason(body)) == (403, "LOG_READER_NOT_VERIFIED") and "entries" not in body
        run.check(16, f"not opened by {name}", ok, said(response))

    log = partial(run.ask_as, OWNER, "/log", "log")
    signed = signed_by(run.person_keys[OWNER], OWNER, "log", root=story.root)
    status, _ = run.post("/log", signed)
    run.check(16, "opened by the person themselves", status == 200, str(status))
    refused("the same signed request, sent again", run.post("/log", signed))
    refused("it with another nonce put in", run.post("/log", {**signed, "nonce": secrets.token_urlsafe(16)}))
    refused("it with another time put in", run.post("/log", {**signed, "ts": signed["ts"] + 1}))
    refused("the thief, with the agent's key", log(key=story.agent))
    refused("another person, in this person's name", log(key=run.person_keys[OTHER]))
    renamed = run.ask_as(OTHER, "/log", "log", over={"principal": OWNER})
    refused("another person's own request, with the name changed", renamed)
    refused("a signature for approvals", run.ask_as(OWNER, "/log", "holds"))
    refused("a request with the job changed", log(root=story.root, over={"root": "urn:uuid:another"}))
    for seconds in TOO_OLD, TOO_NEW:
        refused(f"a request signed {seconds} seconds from now", log(ts=int(time.time()) + seconds))
    status, _ = log(ts=int(time.time()) + A_BIT_FAST)
    run.check(16, "opened by them when their clock is a little fast", status == 200, str(status))
    unknown = run.ask_as("eval:nobody", "/log", "log", key=story.stranger)
    refused("a person nobody has heard of", unknown)
    real = log(key=story.stranger)
    ok = unknown == real and reason(real[1]) == "LOG_READER_NOT_VERIFIED"
    run.check(16, "a made-up name gets the same answer as a real one", ok, f"{said(real)} and {said(unknown)}")

    theirs, _ = run.grant(story.stranger, entry("search", urn=[ASHFIELD]), principal=OTHER)
    run.call(story.stranger, theirs, "search", query=story.first, urn=ASHFIELD)  # refused, and in eval:other's log
    roots = {who: {e["root"] for e in run.entries(who)} for who in (OWNER, OTHER)}
    ok = story.root in roots[OWNER] and claims_of(theirs)["jti"] not in roots[OWNER]
    run.check(16, "their whole log has their own entries and not another person's", ok, f"{len(roots[OWNER])} jobs")
    ok = claims_of(theirs)["jti"] in roots[OTHER] and story.root not in roots[OTHER]
    run.check(16, "another person's whole log has none of theirs", ok, f"{len(roots[OTHER])} jobs")
    reply = run.log(OTHER, root=story.root)
    ok = reply.get("entries") == [] and reply.get("summary", {}).get("pupils") == []
    run.check(16, "nor does it when asked for theirs by name", ok, f"{len(reply.get('entries', []))} entries")


def q16_forged(run: Staff, story: Story) -> None:
    live, _ = run.grant(story.agent, *story.scope, ttl=900, **story.job)

    def total() -> list[int]:
        return [len(run.log(who).get("entries", [])) for who in (OWNER, OTHER)]

    for name, (forged, why) in forgeries(live, story.agent).items():
        before = total()
        status, body = run.call(story.agent, forged, "search", query=story.first, urn=ASHFIELD)
        ok = (status, reason(body)) == (403, why) and total() == before and before[0] > 0
        run.check(16, f"a mandate {name} is refused, and is in nobody's log", ok, said((status, body)))
    run.call(
        story.agent, live, "write", pupil_id=story.first, urn=ASHFIELD, column="Language", value="2_OTH", reason="rang"
    )
    text = json.dumps(run.entries(OWNER, root=claims_of(live)["jti"]))
    ok = "(not recorded)" in text and "2_OTH" not in text and "rang" not in text
    run.check(16, "a correction's new value and reason are not kept in it", ok)


def q16_kept(run: Staff, data: Labelled, story: Story) -> None:
    names = run.log(OWNER, root=story.root, names=True).get("names")
    ok = names == {p: data.names[p] for p in (story.first, story.second)}
    run.check(16, "names, if asked for, of the pupils in it and no others", ok, f"{names and len(names)} names")
    unasked = run.log(OWNER, root=story.root)
    run.check(16, "no names unless asked for", bool(unasked) and "names" not in unasked)
    lower = run.log(OTHER, names=True)
    run.check(16, "no names for a person not cleared for them", bool(lower) and "names" not in lower)
    head = unasked.get("head") or {}
    run.ask_as(OWNER, "/person/class", "class", urn=ASHFIELD, year=11)
    later = run.log(OWNER, seq=head.get("seq"))
    own = [e for e in later.get("entries", []) if e["reason"] == "PERSON_LOOKUP"]
    ok = own and own[-1]["pupils"] == data.year_group(ASHFIELD, 11) and own[-1]["agent_id"] is None
    run.check(16, "their own look at a class list is in it, as theirs", ok, f"{len(own)} lookups")
    ok = head.get("hash") and later.get("hash_at") == head["hash"] and later.get("check") == "ok"
    run.check(16, "what they noted down before is still there, unchanged", ok, f"check {later.get('check')!r}")

    def checked(folder: Path, anchor: str) -> str:
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                cli.main(["--state", str(folder), "log-check", "--anchor", anchor])
        except SystemExit as e:
            return str(e.code)
        return out.getvalue().strip()

    with tempfile.TemporaryDirectory() as folder:  # on a copy
        copy = Path(folder)
        for name in ("record.jsonl", "gateway.pub"):
            shutil.copyfile(run.state / name, copy / name)
        lines = (copy / "record.jsonl").read_text(encoding="utf-8").splitlines()
        last, middle = json.loads(lines[-1]), len(lines) // 2
        edited = json.dumps({**json.loads(lines[middle]), "decision": "EDITED"})
        broken = f"broken at entry {middle + 1}"
        for name, kept, found in (
            ("as it is", lines, "ok"),
            ("with an entry changed", [*lines[:middle], edited, *lines[middle + 1 :]], broken),
            ("with an entry taken out", [*lines[:middle], *lines[middle + 1 :]], broken),
            ("with its end cut off", lines[:-1], f"entry {last['seq']} is missing or was replaced"),
        ):
            (copy / "record.jsonl").write_text("\n".join(kept) + "\n", encoding="utf-8")
            got = checked(copy, f"{last['seq']}:{last['hash']}")
            run.check(16, f"the record {name}: {found}", got == found, got)


# ---------------------------------------------------------------- running it


def run_more(state: Path, post: Post) -> list[tuple[bool, str]]:
    """post(path, body) -> (status, json). Returns [(passed, line)]; each line starts with its question, "Q<n> "."""
    run, data = Staff(state, post), Labelled()
    questions = {
        6: q6_sensitivity,
        8: q8_counts,
        9: q9_approval,
        12: q12_purpose,
        13: q13_person,
        15: q15_newsletter,
        16: q16_log,
    }
    try:
        for number, question in questions.items():
            try:
                question(run, data)
            except Exception as e:  # noqa: BLE001  (one question that cannot be finished does not hide the others)
                run.check(number, "could not be finished", ok=False, got=f"{type(e).__name__}: {e}")
    finally:
        run.leave()
    return run.results
