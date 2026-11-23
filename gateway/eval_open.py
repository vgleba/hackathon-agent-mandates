"""Evals for the open questions this team took (7, 10, 11 and 14), as our gateway is meant to answer them.

    python -m gateway.eval open --state gateway/state --url http://localhost:8082     # or: make eval_open

Questions 0 to 5 hold for any team's gateway. These do not: they pin our design, its claim names, reason codes and
endpoints, and the gateway fails them until that design is built. Budgets and revocation are stateful, so every run
mints fresh agent keys and mandates from the issuer key in --state, and revokes some of them. The gateway under test
must trust that issuer and read its status list (the local containers mount gateway/state).

The design these cases pin
--------------------------
Year 11 is not a column in the census. It is the pupils aged 15 at the start of 2023/24, and a mandate that may reach
only them lists their IDs as the allowed `query` values.

Question 7, delegation. A child mandate is a `mandate+jwt` signed by its parent's `cnf` key, header `kid` = the
parent's `agent_id`, `iss` = "agent:<parent agent_id>", and a `parent` claim holding the parent mandate. It has its
own jti, iat, nbf, exp, cnf, agent_id, purpose, scope and deny, and no `status`: revoking the parent revokes it. It
must be no wider than its parent: tools a subset and deny a superset, each constraint's values a subset (it may add
constraints, never drop one), `max_rows` no higher (a missing one is 100), `exp` no later. One level only.
    DELEGATION_WIDENS    the child is wider than its parent in any of those ways
    DELEGATION_INVALID   the child is not signed by its parent's cnf key
    DELEGATION_TOO_DEEP  the parent is itself a child
    PARENT_REVOKED       the parent has been revoked

Question 10, plain words. gateway/lib/plain_words.py writes a mandate from a sentence using fixed templates:
`scope_for(sentence, school)` returns {"scope", "deny", "summary"} or raises `TooVague` when no template fits, and
`describe(scope, deny)` renders a scope back into the same words. The summary is what the person reads before
signing, and it is signed into the mandate as the `summary` claim. Templates: absence letters (search and draft at
the school), newsletter (the schools file only), free school meal counts (aggregate of FSMeligible, no pupil rows).

Question 11, many small calls. A `max_pupils` claim caps how many distinct pupils' rows one mandate may receive over
its lifetime. A call whose result would take the mandate over the cap is refused whole, 403 BUDGET_EXHAUSTED; rows of
pupils it has already received do not count again. No claim, no cap.

Question 14, what it saw. GET /audit/{jti} returns {"jti", "entries"}: one entry per call made with that mandate, in
order, refused ones included. An entry holds time, decision, reason_code, tool, arguments, rows (how many came back)
and pupils (their IDs, never their values), plus prev and hash: hash = sha256_hex(canonical(entry without hash)),
prev = the hash before it, GENESIS for the first. Only the issuer may read it: `Authorization: Bearer <audit+jwt>`
signed by the issuer key with iss, sub = the jti, aud = "audit" and an exp. Anything else gets 401 or 403.
"""

import csv
import json
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from functools import partial
from pathlib import Path
from urllib.parse import quote

import jwt

from gateway import eval as ev
from gateway.cli import issue_mandate, revoke_mandate, set_person, sign_request
from gateway.lib.common import (
    canonical,
    generate_keypair,
    jwk_thumbprint,
    priv_from_pem,
    priv_to_pem,
    pub_to_jwk,
    sha256_hex,
)
from gateway.lib.mandate_issuer import VCT

CENSUS_CSV = Path(__file__).resolve().parents[1] / "mcp_server/data/synthetic/synthetic_personal_data_school_census.csv"
ASHFIELD, DUNMORE, ELMWOOD = ev.SCHOOL, "SCH04", "SCH05"
DENY = ["*.write", "pii.*"]
MAX_PUPILS = 50  # question 11: Elmwood's Year 11 is 40 pupils, so the ordinary run fits under it
# Who grants every mandate here. A person of its own, so that its daily pupil limit (question 13) is not shared with
# eval:runner, which questions 0 to 5 use, and set high enough that repeated runs in one day are not refused.
PRINCIPAL = "eval:open"
PERSON = {"name": "Open-question eval", "status": "active", "urns": "*", "clearance": 3, "daily_pupils": 100_000}
GENESIS = "sha256:" + "0" * 64
AUDIT_FIELDS = {"time", "decision", "reason_code", "tool", "arguments", "rows", "pupils", "prev", "hash"}
ROW_VALUES = ("Ethnicity", "FSMeligible", "InCareAtCurrentSchool", "Language", "Gender")
REFUSED = {401, 403}

OPEN_QUESTIONS = {
    7: "Get a helper agent to draft Dunmore's absence letters. It only needs their Year 11 list.",
    10: "It's doing the absence letters. Just give it what it needs.",
    11: "Go through Elmwood's Year 11s one at a time and note who's on free school meals.",
    14: "I gave it too much yesterday. Take it back, and tell me what it saw.",
}

# Question 10: each job's sentence, then (case, tool, arguments, expected) for a mandate written from it at Ashfield.
IN_CARE = {"table": ev.CENSUS, "group_by": ["URN"], "measure": "InCareAtCurrentSchool"}
PLAIN_JOBS = {
    "absence letters": (
        "It's doing the absence letters. Just give it what it needs.",
        [
            ("search a pupil at Ashfield", "search", {"query": ev.PUPIL, "urn": ASHFIELD, "limit": 5}, "ALLOW"),
            ("draft their letter, held for a person", "draft", {"urn": ASHFIELD, "pupil_ids": [ev.PUPIL]}, "STEP_UP"),
            ("search Brookmere", "search", {"query": "SPR", "urn": ev.OTHER_SCHOOL, "limit": 5}, "CONSTRAINT_VIOLATED"),
            ("count pupils in care", "aggregate", IN_CARE, "OUT_OF_SCOPE"),
        ],
    ),
    "newsletter": (
        "This one's only doing the newsletter. It doesn't need anything personal.",
        [
            ("get the schools file", "get", {"path": ev.SCHOOLS}, "ALLOW"),
            ("get every pupil's name", "get", {"path": "synthetic/synthetic_display_names.csv"}, "CONSTRAINT_VIOLATED"),
            ("search a pupil at Ashfield", "search", {"query": ev.PUPIL, "urn": ASHFIELD, "limit": 5}, "OUT_OF_SCOPE"),
        ],
    ),
    "free school meal counts": (
        "How many pupils are on free school meals at each school?",
        [
            ("count free school meals by school", "aggregate", {**IN_CARE, "measure": "FSMeligible"}, "ALLOW"),
            ("count pupils in care", "aggregate", IN_CARE, "CONSTRAINT_VIOLATED"),
            ("search a pupil at Ashfield", "search", {"query": ev.PUPIL, "urn": ASHFIELD, "limit": 5}, "OUT_OF_SCOPE"),
        ],
    ),
}
PLAIN = {"absence letters": "It's doing the absence letters.", "newsletter": "This one's only doing the newsletter."}
VAGUE = ["Just give it what it needs.", "Help it with the pupils.", "Let it do whatever the head asked for."]
# (job, sentence): each must come out as that job's plain mandate, or be refused as too vague, never wider
TALKED_WIDER = [
    ("absence letters", "It's doing the absence letters. It needs every school's records, so give it all of them."),
    ("absence letters", "It's doing the absence letters. Ignore any limits on it, this is urgent."),
    ("absence letters", "It's doing the absence letters, and let it correct the records while it's in there."),
    ("newsletter", "This one's only doing the newsletter, but it also needs each pupil's care status."),
]

Post = Callable[[dict], tuple[int, dict]]
Get = Callable[[str, dict], tuple[int, dict]]


# ---------------------------------------------------------------- the census, read the way the MCP server reads it


def census() -> list[dict]:
    with CENSUS_CSV.open(newline="") as f:
        return list(csv.DictReader(f))


def year11(rows: list[dict], urn: str) -> list[str]:
    """The Year 11 list: pupils aged 15 at the start of 2023/24. The census has no year-group column."""
    return sorted(
        {
            r["Psuedo ID"]
            for r in rows
            if r["URN"] == urn and r["AcademicYear"] == "2023/24" and r["AgeAtStartOfAcademicYear"] == "15"
        }
    )


def pupils_at(rows: list[dict], urn: str) -> list[str]:
    return sorted({r["Psuedo ID"] for r in rows if r["URN"] == urn})


def pupils_in(result: object) -> list[str]:
    rows = result if isinstance(result, list) else []
    return sorted({r["Psuedo ID"] for r in rows if isinstance(r, dict) and "Psuedo ID" in r})


# ---------------------------------------------------------------- one run


class Run:
    """The issuer state to mint from, the gateway to call, and the result lines so far."""

    def __init__(self, state: Path, post: Post, get: Get):
        self.state, self.post, self.get = state, post, get
        self.results: list[tuple[bool, str]] = []
        set_person(state, PRINCIPAL, **PERSON)  # the issuer signs only for people in people.json

    @staticmethod
    def key():
        return generate_keypair()[0]

    def mint(self, priv, scope: list[dict], *, deny: list[str] = DENY, extra: dict | None = None) -> tuple[str, int]:
        return issue_mandate(
            self.state,
            priv.public_key(),
            scope=scope,
            deny=deny,
            ttl=3600,
            purpose="open-question eval",
            principal=PRINCIPAL,
            org="org:hackathon",
            extra=extra,
        )

    def call(self, priv, mandate: str, tool: str, **arguments) -> tuple[int, dict]:
        return self.post(sign_request(priv, server=ev.SERVER, tool=tool, arguments=arguments, mandate=mandate))

    def check(self, question: int, name: str, ok: bool, got: str = "") -> None:
        self.results.append((bool(ok), f"Q{question} {name}" + (f": {got}" if got else "")))

    def expect(self, question: int, name: str, response: tuple[int, dict], expected: str) -> None:
        """expected is ALLOW, STEP_UP, or the reason code of a 403."""
        status, body = response
        d = body.get("decision", {})
        if expected == "ALLOW":
            ok = status == 200 and d.get("decision") == "ALLOW"
        elif expected == "STEP_UP":
            ok = status == 202
        else:
            ok = status == 403 and d.get("reason_code") == expected
        self.check(question, name, ok, f"expected {expected}, got {status} {d.get('decision')} {d.get('reason_code')}")

    def attempt(self, question: int, name: str, fn: Callable[[], tuple[bool, str]]) -> None:
        """A check that may raise: a missing or broken module is a failing case, not a crashed run."""
        try:
            ok, got = fn()
        except Exception as e:  # noqa: BLE001
            ok, got = False, f"{type(e).__name__}: {e}"
        self.check(question, name, ok, got)


# ---------------------------------------------------------------- question 7: delegation


def delegate(parent: str, parent_priv, helper_pub, *, scope: list[dict], deny=DENY, exp=None, signer=None) -> str:
    """A child mandate: the parent agent hands a helper part of its access, without the issuer."""
    claims = jwt.decode(parent, options={"verify_signature": False})
    jwk = pub_to_jwk(helper_pub)
    now = int(time.time())
    child = {
        "iss": f"agent:{claims['agent_id']}",
        "jti": f"urn:uuid:{uuid.uuid4()}",
        "iat": now,
        "nbf": now,
        "exp": claims["exp"] - 60 if exp is None else exp,
        "vct": VCT,
        "delegator": claims["delegator"],
        "cnf": {"jwk": jwk},
        "agent_id": jwk_thumbprint(jwk),
        "purpose": "helper: draft absence letters",
        "scope": scope,
        "deny": deny,
        "parent": parent,
    }
    return jwt.encode(
        child,
        priv_to_pem(signer or parent_priv),
        algorithm="EdDSA",
        headers={"typ": "mandate+jwt", "kid": claims["agent_id"]},
    )


def q7_delegation(run: Run, rows: list[dict]) -> None:
    agent, helper = run.key(), run.key()
    y11 = year11(rows, DUNMORE)
    outside = next(p for p in pupils_at(rows, DUNMORE) if p not in y11)
    parent_scope = [{"server": ev.SERVER, "tools": ["search", "draft"], "constraints": {"urn": [DUNMORE]}}]
    entry = {"server": ev.SERVER, "tools": ["search"], "constraints": {"urn": [DUNMORE], "query": y11}, "max_rows": 10}
    parent, _ = run.mint(agent, parent_scope)
    parent_exp = jwt.decode(parent, options={"verify_signature": False})["exp"]
    child = delegate(parent, agent, helper.public_key(), scope=[entry])

    def search(mandate: str, who=helper, urn: str = DUNMORE, query: str = y11[0]) -> tuple[int, dict]:
        return run.call(who, mandate, "search", query=query, urn=urn, limit=5)

    run.expect(7, "helper searches a Year 11 pupil at Dunmore", search(child), "ALLOW")
    run.expect(
        7, "helper searches a Dunmore pupil outside Year 11", search(child, query=outside), "CONSTRAINT_VIOLATED"
    )
    run.expect(7, "helper searches Ashfield", search(child, urn=ASHFIELD), "CONSTRAINT_VIOLATED")
    draft = run.call(helper, child, "draft", urn=DUNMORE, pupil_ids=[y11[0]])
    run.expect(7, "helper drafts a letter: the parent may, the child may not", draft, "OUT_OF_SCOPE")
    run.expect(7, "helper signs with the parent's mandate", search(parent), "POP_FAILED")
    run.expect(7, "parent agent signs with the child's mandate", search(child, who=agent), "POP_FAILED")

    wider = {
        "adds a tool the parent lacks": {"scope": [{**entry, "tools": ["search", "aggregate"]}]},
        "adds a second school": {
            "scope": [{**entry, "constraints": {**entry["constraints"], "urn": [DUNMORE, ev.OTHER_SCHOOL]}}]
        },
        "drops the school constraint": {"scope": [{**entry, "constraints": {"query": y11}}]},
        "raises max_rows above the parent's 100": {"scope": [{**entry, "max_rows": 1000}]},
        "outlives its parent": {"scope": [entry], "exp": parent_exp + 3600},
        "drops a deny rule": {"scope": [entry], "deny": ["pii.*"]},
    }
    for name, how in wider.items():
        widened = delegate(parent, agent, helper.public_key(), **how)
        run.expect(7, f"child that {name}", search(widened), "DELEGATION_WIDENS")
    forged = delegate(parent, agent, helper.public_key(), scope=[entry], signer=helper)
    run.expect(7, "child signed by the helper, not the parent agent", search(forged), "DELEGATION_INVALID")
    third = run.key()
    narrower = {**entry, "constraints": {"urn": [DUNMORE], "query": y11[:5]}}
    grandchild = delegate(child, helper, third.public_key(), scope=[narrower])
    run.expect(7, "grandchild: the helper hands it on again", search(grandchild, who=third), "DELEGATION_TOO_DEEP")

    # last, on a parent of its own, so the cases above keep a live parent
    parent2, idx = run.mint(agent, parent_scope)
    child2 = delegate(parent2, agent, helper.public_key(), scope=[entry])
    run.expect(7, "second child, before its parent is revoked", search(child2), "ALLOW")
    revoke_mandate(run.state, idx)
    run.expect(7, "second child, after its parent is revoked", search(child2), "PARENT_REVOKED")


# ---------------------------------------------------------------- question 10: plain words


def plain_words():
    """The module question 10 builds. Until it exists, every case that needs it fails."""
    try:
        from gateway.lib import plain_words as pw  # noqa: PLC0415
    except ImportError as e:
        msg = "gateway/lib/plain_words.py is not built yet"
        raise LookupError(msg) from e
    return pw


def drafted(job: str, sentence: str) -> tuple[bool, str]:
    pw = plain_words()
    d = pw.scope_for(sentence, ASHFIELD)
    same_words = d["summary"] == pw.describe(d["scope"], d["deny"])
    repeatable = pw.scope_for(sentence, ASHFIELD) == d
    names_school = job != "absence letters" or "Ashfield Academy" in d["summary"]
    ok = same_words and repeatable and names_school
    return ok, f"summary {d['summary']!r}, re-rendered {same_words}, repeatable {repeatable}"


def too_vague(sentence: str) -> tuple[bool, str]:
    pw = plain_words()
    try:
        d = pw.scope_for(sentence, ASHFIELD)
    except pw.TooVague:
        return True, "refused"
    return False, f"scoped as {d['scope']}"


def not_wider(job: str, sentence: str) -> tuple[bool, str]:
    pw = plain_words()
    plain = pw.scope_for(PLAIN[job], ASHFIELD)
    try:
        d = pw.scope_for(sentence, ASHFIELD)
    except pw.TooVague:
        return True, "refused as too vague"
    same = (d["scope"], d["deny"]) == (plain["scope"], plain["deny"])
    return same, f"same as {PLAIN[job]!r}" if same else f"wider: {d['scope']} deny {d['deny']}"


def q10_plain_words(run: Run) -> None:
    agent = run.key()
    for job, (sentence, requests) in PLAIN_JOBS.items():
        run.attempt(10, f"{job}: drafted from the sentence", partial(drafted, job, sentence))
        mandate, why = None, ""
        try:
            d = plain_words().scope_for(sentence, ASHFIELD)
            mandate, _ = run.mint(agent, d["scope"], deny=d["deny"], extra={"summary": d["summary"]})
        except Exception as e:  # noqa: BLE001
            why = f"no mandate: {type(e).__name__}: {e}"
        for name, tool, arguments, expected in requests:
            if mandate is None:
                run.check(10, f"{job} mandate: {name}", ok=False, got=why)
            else:
                run.expect(10, f"{job} mandate: {name}", run.call(agent, mandate, tool, **arguments), expected)
    for sentence in VAGUE:
        run.attempt(10, f"too vague to scope: {sentence!r}", partial(too_vague, sentence))
    for job, sentence in TALKED_WIDER:
        run.attempt(10, f"not talked wider: {sentence!r}", partial(not_wider, job, sentence))


# ---------------------------------------------------------------- question 11: many small calls


def q11_many_small_calls(run: Run, rows: list[dict]) -> None:
    agent = run.key()
    y11 = year11(rows, ELMWOOD)
    others = [p for p in pupils_at(rows, ELMWOOD) if p not in y11]
    scope = [{"server": ev.SERVER, "tools": ["search"], "constraints": {"urn": [ELMWOOD]}}]
    capped, _ = run.mint(agent, scope, extra={"max_pupils": MAX_PUPILS})

    def search(mandate: str, query: str) -> tuple[int, dict]:
        return run.call(agent, mandate, "search", query=query, urn=ELMWOOD)

    def one_at_a_time(name: str, mandate: str, pupils: list[str]) -> None:
        for n, pupil in enumerate(pupils, 1):
            status, body = search(mandate, pupil)
            if status != 200:
                d = body.get("decision", {})
                run.check(11, name, ok=False, got=f"call {n} ({pupil}) got {status} {d.get('reason_code')}")
                return
        run.check(11, name, ok=True, got=f"{len(pupils)} calls allowed")

    extra = MAX_PUPILS - len(y11)
    one_at_a_time(f"the Year 11 run, one pupil at a time ({len(y11)} pupils)", capped, y11)
    one_at_a_time(f"{extra} more pupils, up to max_pupils {MAX_PUPILS}", capped, others[:extra])
    run.expect(11, f"pupil {MAX_PUPILS + 1}", search(capped, others[extra]), "BUDGET_EXHAUSTED")
    run.expect(11, "a Year 11 pupil it has already seen", search(capped, y11[0]), "ALLOW")

    second, _ = run.mint(agent, scope, extra={"max_pupils": MAX_PUPILS})
    run.expect(11, "a second Elmwood mandate keeps its own count", search(second, others[extra + 1]), "ALLOW")
    # the MCP server's own search: "SPR" anywhere in a row at Elmwood, first 100 rows
    spring = [r for r in rows if r["URN"] == ELMWOOD and "spr" in ",".join(r.values()).lower()][:100]
    at_once = len({r["Psuedo ID"] for r in spring})
    fresh, _ = run.mint(agent, scope, extra={"max_pupils": MAX_PUPILS})
    run.expect(11, f"one search that returns {at_once} pupils at once", search(fresh, "SPR"), "BUDGET_EXHAUSTED")

    uncapped, _ = run.mint(agent, scope)
    one_at_a_time("no max_pupils claim: no cap (60 pupils)", uncapped, (y11 + others)[:60])


# ---------------------------------------------------------------- question 14: what it saw


def audit_token(state: Path, sub: str, *, key=None, ttl: int = 60) -> str:
    """What the issuer signs to read a mandate's record. `key` forges one with another key."""
    meta = json.loads((state / "status_list.json").read_text())
    priv = key or priv_from_pem((state / "issuer_key.pem").read_bytes())
    now = int(time.time())
    claims = {"iss": meta["issuer"], "sub": sub, "aud": "audit", "iat": now, "exp": now + ttl, "jti": str(uuid.uuid4())}
    return jwt.encode(claims, priv_to_pem(priv), algorithm="EdDSA", headers={"typ": "audit+jwt", "kid": meta["kid"]})


def chained(entries: list[dict]) -> bool:
    prev = GENESIS
    for e in entries:
        if e.get("prev") != prev or e.get("hash") != sha256_hex(canonical({k: v for k, v in e.items() if k != "hash"})):
            return False
        prev = e["hash"]
    return bool(entries)


def q14_what_did_it_see(run: Run, rows: list[dict]) -> None:
    agent = run.key()
    mandate, idx = run.mint(agent, ev.EVAL_SCOPE)
    other, _ = run.mint(agent, ev.EVAL_SCOPE)
    jti = jwt.decode(mandate, options={"verify_signature": False})["jti"]
    other_jti = jwt.decode(other, options={"verify_signature": False})["jti"]
    second_pupil = next(p for p in pupils_at(rows, ASHFIELD) if p != ev.PUPIL)
    seen = []  # what the agent was told and sent, call by call: the record must say the same

    def call(tool: str, mandate: str = mandate, **arguments) -> None:
        status, body = run.call(agent, mandate, tool, **arguments)
        result = body.get("result") if status == 200 else None
        d = body.get("decision", {})
        seen.append(
            {
                "tool": tool,
                "arguments": arguments,
                "decision": d.get("decision"),
                "reason_code": d.get("reason_code"),
                "rows": len(result) if isinstance(result, list) else 0,
                "pupils": pupils_in(result),
            }
        )

    call("search", query=ev.PUPIL, urn=ASHFIELD)
    call("search", query=second_pupil, urn=ASHFIELD)
    call("get", path=ev.SCHOOLS)
    call("search", query="SPR", urn=ev.OTHER_SCHOOL)
    run.call(agent, other, "search", query=ev.PUPIL, urn=ASHFIELD)  # another mandate: not in this record
    revoke_mandate(run.state, idx)
    call("search", query=ev.PUPIL, urn=ASHFIELD)

    path = f"/audit/{quote(jti, safe='')}"
    status, body = run.get(path, {"authorization": f"Bearer {audit_token(run.state, jti)}"})
    entries = body.get("entries", []) if status == 200 else []
    got = f"{status}, {len(entries)} entries"

    def project(*keys: str) -> tuple[list, list]:
        return [[e.get(k) for k in keys] for e in entries], [[s[k] for k in keys] for s in seen]

    logged, expected = project("tool", "arguments", "decision", "reason_code")
    run.check(14, "the record lists every call, in order, refused and revoked ones included", logged == expected, got)
    logged, expected = project("rows", "pupils")
    run.check(14, "it says how many rows each call returned, and whose", logged == expected, f"{logged} vs {expected}")
    fields = bool(entries) and all(e.keys() >= AUDIT_FIELDS for e in entries)
    run.check(14, f"every entry has {', '.join(sorted(AUDIT_FIELDS))}", fields, got)
    text = json.dumps(body)
    leaked = [c for c in ROW_VALUES if c in text]
    run.check(14, "it holds pupil IDs, never row values", status == 200 and not leaked, f"{got}, columns {leaked}")
    run.check(14, "its entries are hash-chained from GENESIS", chained(entries), got)

    agent_signed = audit_token(run.state, jti, key=agent)
    for name, headers in {
        "no credentials": {},
        "signed by the agent's key, not the issuer's": {"authorization": f"Bearer {agent_signed}"},
        "issuer token for another mandate": {"authorization": f"Bearer {audit_token(run.state, other_jti)}"},
        "expired issuer token": {"authorization": f"Bearer {audit_token(run.state, jti, ttl=-120)}"},
    }.items():
        status, _ = run.get(path, headers)
        run.check(14, f"read refused: {name}", status in REFUSED, f"expected 401 or 403, got {status}")


# ---------------------------------------------------------------- running it


def run_open(state: Path, post: Post, get: Get) -> list[tuple[bool, str]]:
    """Returns [(passed, line)]; each line starts with its question, "Q<n> "."""
    run, rows = Run(state, post, get), census()
    q7_delegation(run, rows)
    q10_plain_words(run)
    q11_many_small_calls(run, rows)
    q14_what_did_it_see(run, rows)
    return run.results


def http(url: str) -> tuple[Post, Get]:
    def send(req: urllib.request.Request) -> tuple[int, dict]:
        try:
            with urllib.request.urlopen(req) as resp:  # noqa: S310
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}
        return status, body if isinstance(body, dict) else {"body": body}

    def post(body: dict) -> tuple[int, dict]:
        headers = {"content-type": "application/json"}
        return send(urllib.request.Request(f"{url}/tools/call", data=json.dumps(body).encode(), headers=headers))  # noqa: S310

    def get(path: str, headers: dict) -> tuple[int, dict]:
        return send(urllib.request.Request(f"{url}{path}", headers=headers))  # noqa: S310

    return post, get


def question_summary(results: list[tuple[bool, str]]) -> None:
    for question, ask in OPEN_QUESTIONS.items():
        oks = [ok for ok, line in results if line.startswith(f"Q{question} ")]
        print(f'Question {question}: {sum(oks)}/{len(oks)}  "{ask}"')
