"""What to show for questions 6 to 16: a real mandate, requests it allows and refuses, and what is unresolved.

Each demo sends the same signed requests to the gateway before and after our changes. Like the rest of the lab it
reports counts, column names and reasons, never a pupil's values.
"""

import json
import shutil
import time

from desk import jobs
from gateway import cli
from gateway.lib import plain, record
from gateway.lib.common import generate_keypair, pub_from_pem
from lab import server as lab

JSMITH, PRIYA = "officer:jsmith", "officer:priya"
CENSUS = "personal_data_school_census"
TERM = {"academic_year": ["2023/24"], "term": ["SPR"]}
YEAR_11 = {"year_group": 11, "academic_year": "2023/24", "term": "SPR"}
OK, NO = 200, 403
WANT = {"allow": (OK, "ALLOW"), "refuse": (NO, "DENY"), "hold": (202, "STEP_UP")}
NONE = ("Not possible", "The original gateway has no way to do this.", False)
BUDGET, YEAR_SIZE, EXTRA = 45, 38, 12


def entry(*tools, **constraints) -> dict:
    return {"server": "pupil-data", "tools": list(tools), "constraints": constraints}


def mandate(*scope, ttl=900, deny=(), **claims) -> tuple[str, int]:
    return lab.new_mandate(list(scope), "lab demo", ttl, deny=deny, **claims)


def claims_in(token: str) -> dict:
    return json.loads(cli.b64u_decode(token.split(".")[1]))


def shown(token: str) -> dict:
    claims = claims_in(token)
    keep = ("delegator", "purpose_code", "clearance", "budget", "may_delegate", "helpers", "scope", "parent", "exp")
    out = {k: claims[k] for k in keep if k in claims}
    return out | ({"parent": "(the parent's whole mandate)"} if "parent" in out else {})


async def step(label: str, want: str, tool: str, arguments: dict, token: str, **kw) -> dict:
    replies = await lab.call_both(tool, arguments, token, **kw)
    for r in replies.values():
        r["good"] = (r["status"], r["decision"]) == WANT[want]
    return {"label": label, **replies}


def text(label: str, before: tuple, after: tuple) -> dict:
    def side(outcome, why, good) -> dict:
        return {"outcome": outcome, "text": why, "good": good, "status": 0, "sensitive": [], "pupils": 0}

    return {"label": label, "before": side(*before), "after": side(*after)}


async def tell_after(path: str, body: dict) -> tuple[int, dict]:
    return await lab.send("after", path, body)


def person(principal: str = JSMITH):
    return cli.person_key(lab.STATE, principal)


async def q6() -> dict:
    castleton = entry("pupil", urn=["SCH03"])
    high, _ = mandate(castleton, clearance=4)
    low, _ = mandate(castleton, clearance=2)
    none, _ = mandate(castleton)
    ask = {"pupil_id": "P1008", "urn": "SCH03"}
    return {
        "mandate": shown(high),
        "steps": [
            await step("Clearance 4: one full record", "allow", "pupil", ask, high),
            await step("Clearance 2: the same request", "refuse", "pupil", ask, low),
            await step("No clearance: special category is never assumed", "refuse", "pupil", ask, none),
        ],
        "unresolved": "Labels sit on single columns, but harm often comes from combinations of columns.",
    }


async def q7() -> dict:
    both_years = entry("roster", urn=["SCH04"], year_group=[10, 11], **TERM)
    parent, idx = mandate(both_years, clearance=2, helpers=1, budget={"pupils": 60})
    helper, pub = generate_keypair()

    def child(*urns):
        scope = [entry("roster", urn=list(urns), year_group=[11], **TERM)]
        return cli.delegate_mandate(parent, lab.lab["agent"], pub, scope=scope, ttl=300)

    narrow, wide = child("SCH04"), child("SCH04", "SCH01")
    ask = {"urn": "SCH04", **YEAR_11}
    year_10 = {**ask, "year_group": 10}
    steps = [
        await step("The helper reads Dunmore's Year 11 list", "allow", "roster", ask, narrow, key=helper),
        await step("It tries Year 10, which its parent has", "refuse", "roster", year_10, narrow, key=helper),
        await step("A helper made for Ashfield too", "refuse", "roster", ask, wide, key=helper),
    ]
    cli.revoke_mandate(lab.STATE, idx)
    steps.append(await step("After the parent is taken back", "refuse", "roster", ask, narrow, key=helper))
    return {
        "mandate": shown(narrow),
        "steps": steps,
        "unresolved": "Two helpers can pool what each has seen, and nothing can make an agent forget.",
    }


async def q8() -> dict:
    token, _ = mandate(entry("aggregate"), clearance=4)
    care = {"table": CENSUS, "group_by": ["URN", "Ethnicity"], "measure": "InCareAtCurrentSchool"}
    figures = {}
    for name in lab.GATEWAYS:
        _, reply = await lab.send(name, "/tools/call", lab.sign("aggregate", care, token))
        figures[name] = sum(bool(r["count"]) for r in reply.get("result", []))
    meals = {"table": CENSUS, "group_by": ["URN"], "measure": "FSMeligible"}
    one = {**meals, "group_by": ["Ethnicity", "InCareAtCurrentSchool"], "where": {"Psuedo ID": "P0011"}}
    return {
        "mandate": shown(token),
        "steps": [
            await step("Free school meals by school", "allow", "aggregate", meals, token),
            text(
                "Pupils in care by school and ethnic group",
                (f"{figures['before']} figures shown", "They count rows, and stand for 1, 2 or 3 children.", False),
                (f"{figures['after']} figures shown", "Every group is under 10 children.", figures["after"] == 0),
            ),
            await step("Filtered to one pupil, by ethnicity and care", "refuse", "aggregate", one, token),
        ],
        "unresolved": "Asking again next term can still say something when rounding tips over a boundary.",
    }


async def q9() -> dict:
    scope = entry("write", urn=["SCH04"], column=["Language"])
    token, _ = mandate(scope, clearance=3, purpose_code="record_correction")
    ask = {"pupil_id": "P0011", "urn": "SCH04", "column": "Language", "value": "2_OTH", "reason": "lab demo"}
    steps = [await step("The agent asks to correct a record", "hold", "write", ask, token)]

    async def hold() -> str:
        return (await tell_after("/tools/call", lab.sign("write", ask, token)))[1]["hold_id"]

    async def said(key, hold_id: str, answer: str) -> tuple[int, dict]:
        signed = cli.sign_as_person(key, JSMITH, "answer", hold=hold_id, answer=answer)
        return await tell_after("/holds/answer", signed)

    first, second = await hold(), await hold()
    by_agent, agent = await said(lab.lab["agent"], first, "approve")
    yes, _ = await said(person(), first, "approve")
    twice, again = await said(person(), first, "approve")
    no, _ = await said(person(), second, "refuse")
    stuck = ("Stuck", "Held, and nothing can ever release it.", False)
    steps += [
        text("The agent approves itself", NONE, ("Refused", agent.get("reason_code", ""), by_agent == NO)),
        text("The person approves", stuck, ("Done once", "Every check ran again first.", yes == OK)),
        text("They approve again", stuck, ("Refused", again.get("reason_code", ""), twice == NO)),
        text("Another one: the person says no", stuck, ("Refused", "Nothing was changed.", no == OK)),
    ]
    return {
        "mandate": shown(token),
        "steps": steps,
        "unresolved": "People may approve without reading. After a crash part way, a call shows as unknown for ever.",
    }


async def q10() -> dict:
    schools = {u: s["name"] for u, s in lab.lab["schools"].items()}
    pupils = {"P1017": "(pupil 1)", "P1029": "(pupil 2)"}
    choice = {"school": "SCH04", "year": 11, "kind": "absence", "pupils": pupils, "helper": False}
    grant = jobs.build("letters", choice, schools)
    signed = {k: grant[k] for k in ("clearance", "budget", "purpose_code")}
    claims = {**signed, "scope": grant["scope"], "exp": int(time.time()) + 900}
    said = plain.describe(claims, schools, pupils)
    token, _ = mandate(*grant["scope"], **signed)
    odd = {**grant["scope"][0]["constraints"], "extra": ["x"]}
    try:
        plain.describe({**claims, "scope": [{**grant["scope"][0], "constraints": odd}]}, schools, pupils)
        refused = False
    except plain.CannotDescribe:
        refused = True
    vague = jobs.understand("It's doing the absence letters. Just give it what it needs.", schools)
    pull = jobs.understand("Just pull everything for Brookmere", schools)
    letter = {"urn": "SCH04", "kind": "absence", "pupil_ids": ["P1017"]}
    adds_nothing = vague["choice"] == {"kind": "absence"}
    words = " ".join([*said["can"], *said["asks"], *said["limits"]])
    return {
        "mandate": shown(token),
        "steps": [
            text(
                "“It's doing the absence letters. Just give it what it needs.”",
                NONE,
                ("Letters home", "“What it needs” added nothing. It asks which school, year and pupils.", adds_nothing),
            ),
            text("“Just pull everything for Brookmere”", NONE, ("Asks", pull["ask"], pull["job"] is None)),
            text(
                "What the person is shown",
                ("JSON", "Typed by hand on the command line.", False),
                ("Plain words", words, True),
            ),
            text(
                "A limit nobody can describe",
                ("Signed", "Nobody would notice.", False),
                ("Not signed", "It cannot be put into words.", refused),
            ),
            await step("The letters it was given for", "hold", "draft", letter, token),
            await step("A pupil who was not ticked", "refuse", "draft", {**letter, "pupil_ids": ["P0011"]}, token),
        ],
        "unresolved": "Only covers jobs somebody has written. Clear words are not always read.",
    }


async def q11() -> dict:
    elmwood = [entry("roster", urn=["SCH05"], year_group=[11], **TERM), entry("search", urn=["SCH05"])]
    token, _ = mandate(*elmwood, clearance=3, budget={"pupils": BUDGET}, purpose_code="meals_check")
    ask = {"urn": "SCH05", **YEAR_11}
    steps = [await step("Elmwood's Year 11 list: 38 pupils", "allow", "roster", ask, token)]
    allowed = dict.fromkeys(lab.GATEWAYS, 0)
    for n in range(1, EXTRA + 1):
        replies = await lab.call_both("search", {"query": f"P{n:04d}", "urn": "SCH05"}, token)
        for name, r in replies.items():
            allowed[name] += r["status"] == OK
    steps.append(
        text(
            f"Then {EXTRA} other pupils, one at a time",
            (f"{allowed['before']} of {EXTRA} allowed", "It would carry on through the whole school.", False),
            (
                f"{allowed['after']} of {EXTRA} allowed",
                "The job may see 45 different pupils, and 38 + 7 is 45.",
                allowed["after"] == BUDGET - YEAR_SIZE,
            ),
        )
    )
    return {
        "mandate": shown(token),
        "steps": steps,
        "unresolved": "A patient agent can come back tomorrow. Counts (question 8) do not spend the budget.",
    }


async def q12() -> dict:
    scope = entry("pupil", urn=["SCH04"])
    review, _ = mandate(scope, clearance=4, purpose_code="safeguarding_review")
    letters, _ = mandate(scope, clearance=4, purpose_code="absence_letters")
    ask = {"pupil_id": "P0011", "urn": "SCH04"}
    return {
        "mandate": shown(letters),
        "steps": [
            await step("For a safeguarding review", "allow", "pupil", ask, review),
            await step("The same access, for absence letters", "refuse", "pupil", ask, letters),
        ],
        "unresolved": "Misuse inside the purpose still works: letters to the wrong families use the right tool.",
    }


async def q13() -> dict:
    def priya(**fields):
        base = {"name": "Priya", "status": "active", "urns": ["SCH05"], "clearance": 4, "daily_pupils": 300}
        cli.set_person(lab.STATE, PRIYA, **{**base, **fields})

    priya()
    token, _ = mandate(entry("search", urn=["SCH04", "SCH05"]), principal=PRIYA)
    ask = {"query": "2023/24", "urn": "SCH05"}
    dunmore = {**ask, "urn": "SCH04"}
    steps = [
        await step("Priya covers Elmwood", "allow", "search", ask, token),
        await step("Her mandate says Dunmore too, which she does not cover", "refuse", "search", dunmore, token),
    ]
    priya(urns=["SCH06"])
    steps.append(await step("She moves to Fairhaven", "refuse", "search", ask, token))
    priya(status="left")
    steps.append(await step("She leaves", "refuse", "search", ask, token))
    priya()
    return {
        "mandate": shown(token),
        "steps": steps,
        "unresolved": "Only as current as the list of people. A successor signs afresh, so somebody must tell them.",
    }


async def q14() -> dict:
    token, idx = mandate(entry("pupil", urn=["SCH04"]), clearance=4)
    for pupil in ("P0011", "P1017"):
        await lab.call_both("pupil", {"pupil_id": pupil, "urn": "SCH04"}, token)
    cli.revoke_mandate(lab.STATE, idx)
    ask = {"pupil_id": "P0011", "urn": "SCH04"}
    stopped = await step("Taken back: the next call", "refuse", "pupil", ask, token)
    signed = cli.sign_as_person(person(), JSMITH, "log", root=claims_in(token)["jti"])
    s = (await tell_after("/log", signed))[1]["summary"]
    copy = lab.WORK / "tampered.jsonl"
    pub = pub_from_pem((lab.STATE / "gateway.pub").read_bytes())
    shutil.copy(lab.STATE / "record.jsonl", copy)
    lines = copy.read_text(encoding="utf-8").splitlines()
    last = json.loads(lines[-1])
    copy.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    cut = record.check(copy, pub, (last["seq"], last["hash"]))
    copy.write_text("\n".join(lines).replace('"ALLOW"', '"DENY"', 1) + "\n", encoding="utf-8")
    edited = record.check(copy, pub)
    copy.unlink()
    special = ", ".join(s["special"]) or "none"
    told = f"{s['requests']} requests, {len(s['pupils'])} pupils. Special category seen: {special}."
    return {
        "mandate": shown(token),
        "steps": [
            stopped,
            text(
                "Tell me what it saw",
                ("Nobody knows", "No record was kept.", False),
                ("It can say", told, s["pupils"] == ["P0011", "P1017"]),
            ),
            text("Somebody edits the record", NONE, ("Noticed", edited, edited != "ok")),
            text("Somebody cuts off the end", NONE, ("Noticed, by a copy kept elsewhere", cut, cut != "ok")),
        ],
        "unresolved": "Whoever runs the gateway could rewrite it all. Only a copy kept elsewhere shows it.",
    }


async def q15() -> dict:
    files = {"path": "synthetic/synthetic_schools.csv"}
    news, _ = mandate(entry("get", path=[files["path"]]), entry("roster", urn=["SCH03"]), clearance=1)
    two, _ = mandate(entry("search", urn=["SCH03"]), clearance=2)
    three, _ = mandate(entry("aggregate"), clearance=3)
    count = {"table": CENSUS, "group_by": ["URN"], "measure": "FSMeligible"}
    care = {**count, "measure": "InCareAtCurrentSchool"}
    hidden = await lab.call_both("search", {"query": "BLAC", "urn": "SCH03"}, two)
    found = {k: r["rows"] for k, r in hidden.items()}
    return {
        "mandate": shown(news),
        "steps": [
            await step("Newsletter, clearance 1: the list of schools", "allow", "get", files, news),
            await step("Newsletter: a class list", "refuse", "roster", {"urn": "SCH03", **YEAR_11}, news),
            await step("Counts, clearance 3: free school meals", "allow", "aggregate", count, three),
            await step("Counts: pupils in care", "refuse", "aggregate", care, three),
            text(
                "Clearance 2: search for a hidden ethnic group",
                (f"{found['before']} rows", "Each one coming back gives the answer away.", False),
                (f"{found['after']} rows", "Only what it may see is searched.", found["after"] == 0),
            ),
        ],
        "unresolved": "Raising a label takes effect at once, which is safe and can break a job half way through.",
    }


async def q16() -> dict:
    token, _ = mandate(entry("search", urn=["SCH01"]))
    thief, _ = generate_keypair()
    ask = {"query": "P0004", "urn": "SCH01"}
    used = await step("A thief uses the mandate without its key", "refuse", "search", ask, token, key=thief)
    mine = (await tell_after("/log", cli.sign_as_person(person(), JSMITH, "log", root=claims_in(token)["jti"])))[1]
    alarm = any(e["reason"] == "POP_FAILED" for e in mine["entries"])
    by_thief, stolen = await tell_after("/log", cli.sign_as_person(lab.lab["agent"], JSMITH, "log"))
    if PRIYA not in cli.load_people(lab.STATE):
        cli.set_person(lab.STATE, PRIYA, name="Priya", status="active", urns=["SCH05"], clearance=4, daily_pupils=300)
    by_other, other = await tell_after("/log", cli.sign_as_person(person(PRIYA), JSMITH, "log"))
    seen = "Use without the key is in their log, with when and where from."
    return {
        "mandate": shown(token),
        "steps": [
            used,
            text("The person opens their log", ("Nothing kept", "There is no log.", False), ("There", seen, alarm)),
            text("The thief asks for it", NONE, ("Refused", stolen.get("reason_code", ""), by_thief == NO)),
            text("Another person asks for it", NONE, ("Refused", other.get("reason_code", ""), by_other == NO)),
        ],
        "unresolved": "If the agent's key itself is stolen, both users sign alike. Only time and place differ.",
    }


DEMOS = {6: q6, 7: q7, 8: q8, 9: q9, 10: q10, 11: q11, 12: q12, 13: q13, 14: q14, 15: q15, 16: q16}
