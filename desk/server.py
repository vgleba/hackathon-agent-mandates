"""Desk: where a member of staff gives an assistant a job, approves what it asks, and takes access back.

Runs on the person's side. It holds the issuer's key and, in this local version, each person's own key; in real use a
person's key would stay on their own device and they would sign in with their school account. Assistants run as
separate processes and are given neither.

What is signed is the draft that was shown, kept here and used once. The browser never sends access back, only which
draft it was. No key or mandate is ever sent to the browser.
"""
# ruff: noqa: RUF001, TRY301  (a refusal carries a code to match on; text shown to people has real apostrophes)

import json
import os
import secrets
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware

from desk import jobs, words
from gateway import cli
from gateway.lib import plain
from gateway.lib.common import canonical, jwk_to_pub, sha256_hex

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".tmp" / "desk"
STATE = WORK / "state"
PORTS = {"data server": 8190, "gateway": 8192, "page": 8194}
GATEWAY = f"http://127.0.0.1:{PORTS['gateway']}"
ORIGINS = {f"http://127.0.0.1:{PORTS['page']}", f"http://localhost:{PORTS['page']}"}
COOKIE = "desk"
DRAFT_LIFE, SESSION_LIFE = 900, 8 * 3600
MOST_AT_ONCE = 10
OK = 200


@dataclass
class Job:
    """One job given to one assistant."""

    id: str
    principal: str
    job: str
    choice: dict
    said: dict
    root: str
    idx: int
    helpers: list[int]
    ends: float
    process: subprocess.Popen
    started: float = field(default_factory=time.time)
    state: str = "working"  # working, waiting, done, stopped, taken back
    note: str = ""
    result: dict | None = None
    helper_state: str | None = None
    cut_short: bool = False  # it stopped because its person's own access did


class Desk:
    def __init__(self):
        self.signin: dict[str, str] = {}
        self.sessions: dict[str, tuple[str, float]] = {}
        self.drafts: dict[str, dict] = {}
        self.jobs: dict[str, Job] = {}
        self.keys: dict[str, object] = {}
        self.anchors: dict[str, dict] = {}
        self.issuing = threading.Lock()  # issuing and revoking rewrite one list
        self.http: httpx.AsyncClient | None = None

    def add_person(self, principal: str) -> str:
        """Returns a link that signs them in once."""
        self.keys[principal] = cli.person_key(STATE, principal)
        token = secrets.token_urlsafe(24)
        self.signin[token] = principal
        return f"http://127.0.0.1:{PORTS['page']}/signin?t={token}"

    def people(self) -> dict:
        return cli.load_people(STATE)

    def revoke(self, *numbers: int) -> None:
        with self.issuing:
            for n in numbers:
                cli.revoke_mandate(STATE, n)

    async def gateway(self, principal: str, path: str, do: str, **fields) -> dict:
        """Ask the gateway something as this person, signed with their own key."""
        body = cli.sign_as_person(self.keys[principal], principal, do, **fields)
        try:
            r = await self.http.post(GATEWAY + path, json=body)
        except httpx.HTTPError as e:
            raise HTTPException(502, "Desk cannot reach the gateway just now.") from e
        if r.status_code != OK:
            refused = r.json() if r.headers.get("content-type") == "application/json" else {}
            raise HTTPException(403, words.why(refused.get("reason_code", "")))
        return r.json()


desk = Desk()


def assistant() -> subprocess.Popen:
    """A process of its own, given nothing but what Python needs to start."""
    keep = ("SYSTEMROOT", "PATH", "TEMP", "TMP", "HOME", "USERPROFILE", "LANG")
    env = {k: os.environ[k] for k in keep if k in os.environ} | {"PYTHONUTF8": "1"}
    return subprocess.Popen(
        [sys.executable, "-m", "desk.agent"],
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
    )


def listen(job: Job, schools: dict[str, str]) -> None:  # noqa: C901  (one branch per kind of event)
    """Follow one assistant until it stops, then end its access whatever happened."""
    for line in job.process.stdout:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if job.state == "taken back":
            break
        if "waiting" in event:
            job.state, job.note = "waiting", "Waiting for you"
        elif "doing" in event:
            job.state, job.note = "working", f"Working: {event['doing']}"
        elif "helper" in event:
            job.helper_state = f"A helper is writing {event['helper']} of the letters"
        elif "helper_stopped" in event:
            job.helper_state = "The helper stopped. " + words.why(event["helper_stopped"])
        elif "result" in event:
            try:
                job.result = words.result(job.job, job.choice, event["result"], schools)
                # everything else first: once it says "done", whoever is watching stops looking
                job.helper_state = job.helper_state and job.helper_state.replace("is writing", "wrote")
                job.note = "Finished"
                job.state = "done"
            except (KeyError, TypeError, ValueError, IndexError):
                job.state, job.note = "stopped", "The answer could not be shown."
        elif "stopped" in event and job.state != "done":
            job.state, job.note = "stopped", words.why(event["stopped"])
            job.cut_short = event["stopped"] in {"PERSON_PAUSED", "PERSON_LOST_ACCESS"}
    job.process.wait()
    if job.state in {"working", "waiting"}:
        job.state, job.note = "stopped", "It stopped unexpectedly."
    desk.revoke(job.idx, *job.helpers)  # the job is over, so the access is too


def begin(principal: str, draft: dict, schools: dict[str, str]) -> Job:
    """Start an assistant, sign exactly the draft that was shown for the key it made, and hand it over."""
    grant = draft["grant"]
    process = assistant()
    try:
        key = jwk_to_pub(json.loads(process.stdout.readline())["jwk"])
        shown = sha256_hex(canonical(draft["said"]))
        extra = {k: grant[k] for k in ("clearance", "budget", "purpose_code")} | {"shown": shown}
        with desk.issuing:
            token, idx = cli.issue_mandate(
                STATE,
                key,
                scope=grant["scope"],
                deny=[],
                ttl=int(draft["ends"] - time.time()),
                purpose=jobs.JOBS[draft["job"]]["title"],
                principal=principal,
                org="desk",
                extra=extra,
                helpers=grant["helpers"],
            )
        claims = jwt.decode(token, options={"verify_signature": False})
        claims["exp"] = draft["ends"]  # the whole second may round differently; never later than was shown
        if plain.describe(claims, schools, draft["choice"].get("pupils", {})) != draft["said"]:
            desk.revoke(idx)
            raise HTTPException(500, "What was signed did not match what you were shown, so it was cancelled.")
        job = Job(
            id=secrets.token_urlsafe(9),
            principal=principal,
            job=draft["job"],
            choice=draft["choice"],
            said=draft["said"],
            root=claims["jti"],
            idx=idx,
            helpers=claims.get("helpers", []),
            ends=draft["ends"],
            process=process,
        )
        message = {"mandate": token, "gateway": GATEWAY, "job": draft["job"], "choice": draft["choice"]}
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
    except BaseException:
        process.kill()
        raise
    threading.Thread(target=listen, args=(job, schools), daemon=True).start()
    return job


def stop(job: Job) -> None:
    """Take it back: the access first, then the assistant."""
    desk.revoke(job.idx, *job.helpers)
    if job.state in {"working", "waiting"}:
        job.state, job.note = "taken back", "You took the access back."
    job.process.kill()


# ---------------------------------------------------------------- the app


@asynccontextmanager
async def lifespan(_app: FastAPI):
    async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
        desk.http = client
        yield
    for job in desk.jobs.values():
        job.process.kill()


app = FastAPI(title="desk", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def same_origin_only(request: Request, call_next):
    if request.method not in {"GET", "HEAD"} and request.headers.get("origin") not in ORIGINS:
        response = JSONResponse({"detail": "This page only."}, status_code=403)
    else:
        response = await call_next(request)
    response.headers.update(HEADERS)
    return response


app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])


def me(request: Request) -> str:
    """Who is signed in, from the cookie and nothing else."""
    principal, until = desk.sessions.get(request.cookies.get(COOKIE, ""), ("", 0))
    if not principal or until < time.time():
        raise HTTPException(401, "Please sign in again.")
    return principal


Me = Depends(me)


@app.get("/signin")
def signin(t: str = ""):
    principal = desk.signin.pop(t, None)  # once
    if principal is None:
        return RedirectResponse("/#signed-out", status_code=303)
    session = secrets.token_urlsafe(32)
    desk.sessions[session] = (principal, time.time() + SESSION_LIFE)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(COOKIE, session, max_age=SESSION_LIFE, httponly=True, samesite="strict")
    return response


@app.post("/api/signout")
def signout(request: Request):
    desk.sessions.pop(request.cookies.get(COOKIE, ""), None)
    return {}


async def schools_of(principal: str) -> dict[str, str]:
    return (await desk.gateway(principal, "/person/schools", "schools"))["schools"]


@app.get("/api/me")
async def who_am_i(principal: str = Me):
    person = desk.people()[principal]
    return {
        "name": person["name"],
        "every_school": person.get("urns") == "*",
        "schools": await schools_of(principal),
        "jobs": {k: {f: v[f] for f in ("title", "about", "blanks", "most")} for k, v in jobs.JOBS.items()},
        "questions": jobs.QUESTIONS,
        "options": {
            "kind": jobs.KINDS,
            "detail": jobs.DETAIL,
            "what": jobs.WHAT,
            "split": jobs.SPLIT,
            "when": jobs.WHEN,
            "field": {k: v["name"] for k, v in jobs.FIELDS.items()},
            "value": {k: v["values"] for k, v in jobs.FIELDS.items()},
        },
    }


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Sentence(Body):
    text: str


@app.post("/api/understand")
async def understand(body: Sentence, principal: str = Me):
    return jobs.understand(body.text, await schools_of(principal))


class Class(Body):
    school: str
    year: int


@app.post("/api/class")
async def class_list(body: Class, principal: str = Me):
    return await desk.gateway(principal, "/person/class", "class", urn=body.school, year=body.year)


class Choice(Body):
    job: str
    choice: dict


@app.post("/api/check")
async def check(body: Choice, principal: str = Me):
    """Put the access into words. Nothing is signed yet."""
    schools = await schools_of(principal)
    choice = dict(body.choice)
    if "pupils" in choice:
        # the browser says which pupils by number; the names come from the gateway, never from the browser
        ticked = choice["pupils"] if isinstance(choice["pupils"], list) else []
        known = {}
        if isinstance(choice.get("school"), str) and choice.get("year") in (10, 11):
            found = await desk.gateway(principal, "/person/class", "class", urn=choice["school"], year=choice["year"])
            known = found["pupils"]
        choice["pupils"] = {i: known[i] for i in ticked if isinstance(i, str) and i in known}
    try:
        grant = jobs.build(body.job, choice, schools)
    except jobs.Ask as e:
        return {"ask": {"field": e.field, "question": e.question}}
    ends = int(time.time()) + grant["ttl"]
    fields = {k: grant[k] for k in ("clearance", "budget", "purpose_code", "scope")}
    if grant["helpers"]:
        fields |= {"may_delegate": 1, "helpers": [0] * grant["helpers"]}
    try:
        said = plain.describe({**fields, "exp": ends}, schools, choice.get("pupils", {}))
    except plain.CannotDescribe as e:
        raise HTTPException(500, "This could not be put into words, so it cannot be given.") from e
    now = time.time()
    desk.drafts = {k: d for k, d in desk.drafts.items() if d["until"] > now}
    draft_id = secrets.token_urlsafe(16)
    desk.drafts[draft_id] = {
        "principal": principal,
        "job": body.job,
        "choice": choice,
        "grant": grant,
        "said": said,
        "ends": ends,
        "until": now + DRAFT_LIFE,
    }
    return {"draft": draft_id, "title": jobs.JOBS[body.job]["title"], "said": said}


class Draft(Body):
    draft: str


@app.post("/api/start")
async def start(body: Draft, principal: str = Me):
    draft = desk.drafts.get(body.draft)
    if draft is None or draft["principal"] != principal or draft["until"] < time.time():
        raise HTTPException(404, "That has gone stale. Please check it again.")
    running = [j for j in desk.jobs.values() if j.principal == principal and j.state in {"working", "waiting"}]
    if len(running) >= MOST_AT_ONCE:
        raise HTTPException(409, "You already have a lot running. Wait for one to finish, or take one back.")
    del desk.drafts[body.draft]  # used once
    schools = await schools_of(principal)
    job = await run_in_threadpool(begin, principal, draft, schools)
    desk.jobs[job.id] = job
    return {"id": job.id}


def mine(job_id: str, principal: str) -> Job:
    job = desk.jobs.get(job_id)
    if job is None or job.principal != principal:
        raise HTTPException(404, "There is no such job of yours.")
    return job


@app.get("/api/work")
def work(principal: str = Me):
    out = []
    for job in sorted(desk.jobs.values(), key=lambda j: -j.started):
        if job.principal != principal:
            continue
        running = job.state in {"working", "waiting"}
        out.append(
            {
                "id": job.id,
                "title": jobs.JOBS[job.job]["title"],
                "state": job.state,
                "note": job.note or "Working",
                "started": words.ago(job.started),
                "ends": words.ago(job.ends) if running else None,
                "running": running,
                "helper": job.helper_state,
                "can_stop_helper": running and bool(job.helpers) and job.helper_state is not None,
                "said": job.said,
                "result": job.result,
            }
        )
    paused = desk.people()[principal].get("status") != "active"
    return {"jobs": out, "paused": paused}


@app.post("/api/work/{job_id}/take-back")
async def take_back(job_id: str, principal: str = Me):
    await run_in_threadpool(stop, mine(job_id, principal))
    return {}


@app.post("/api/work/{job_id}/stop-helper")
async def stop_helper(job_id: str, principal: str = Me):
    job = mine(job_id, principal)
    await run_in_threadpool(desk.revoke, *job.helpers)
    job.helper_state = "You stopped the helper."
    return {}


@app.post("/api/stop-everything")
async def stop_everything(principal: str = Me):
    for job in [j for j in desk.jobs.values() if j.principal == principal and j.state in {"working", "waiting"}]:
        await run_in_threadpool(stop, job)
    return {}


# ---------------------------------------------------------------- waiting for you


def describe_hold(hold: dict, schools: dict[str, str]) -> dict:
    args, preview = hold["arguments"], hold["preview"]
    job = next((j for j in desk.jobs.values() if j.root == hold["root"]), None)
    out = {
        "id": hold["id"],
        "until": words.ago(hold["expires"]),
        "job": jobs.JOBS[job.job]["title"] if job else "A job",
    }
    school = schools.get(args.get("urn"), "a school that is not yours")
    if hold["tool"] == "draft":
        letters = preview.get("letters", [])
        names = job.choice.get("pupils", {}) if job else {}
        shown = [{"name": names.get(x["Psuedo ID"], x["Psuedo ID"]), "letter": x["letter"]} for x in letters]
        count = f"{len(shown)} letter{'s' if len(shown) != 1 else ''}"
        out |= {"question": f"Release {count} for {school}?", "letters": shown, "yes": f"Yes, release {count}"}
        out["no"] = "No, do not release them"
    elif hold["tool"] == "write":
        column = args.get("column")
        out |= {
            "question": f"Change {preview.get('name') or 'this pupil'}’s record at {school}?",
            "change": {
                "what": jobs.FIELDS.get(column, {}).get("name", column),
                "now": words.value(column, preview.get("now")),
                "new": words.value(column, args.get("value")),
                "reason": args.get("reason"),
            },
            "yes": "Yes, change it",
            "no": "No, leave it as it is",
        }
    if "problem" in preview:
        out["problem"] = words.why(preview["problem"])
    return out


@app.get("/api/waiting")
async def waiting(principal: str = Me):
    schools = await schools_of(principal)
    found = await desk.gateway(principal, "/holds", "holds")
    return {"waiting": [describe_hold(h, schools) for h in found["holds"]]}


class Answer(Body):
    answer: str


@app.post("/api/waiting/{hold_id}")
async def answer(hold_id: str, body: Answer, principal: str = Me):
    done = await desk.gateway(principal, "/holds/answer", "answer", hold=hold_id, answer=body.answer)
    return {"state": done["state"]}


# ---------------------------------------------------------------- what did it see, and was this me?


async def read_log(principal: str, **fields) -> dict:
    before = desk.anchors.get(principal)
    if before:
        fields["seq"] = before["seq"]
    found = await desk.gateway(principal, "/log", "log", **fields)
    complete = found["check"] == "ok" and (not before or not before["seq"] or found.get("hash_at") == before["hash"])
    if complete:
        desk.anchors[principal] = found["head"]
    found["complete"] = complete
    return found


@app.get("/api/work/{job_id}/seen")
async def seen(job_id: str, principal: str = Me):
    job = mine(job_id, principal)
    found = await read_log(principal, names=True, root=job.root)
    s = found["summary"]
    kinds = [words.COLUMNS[c] for c in words.COLUMNS if c in s["columns"]]
    special = [words.COLUMNS.get(c, c) for c in s["special"] if c in words.COLUMNS]
    return {
        "pupils": sorted(found["names"].get(p, p) for p in s["pupils"]),
        "kinds": kinds,
        "special": special,
        "refused": sum(e["decision"] == "DENY" for e in found["entries"]),
        "complete": found["complete"],
    }


@app.get("/api/activity")
async def activity(principal: str = Me):
    found = await read_log(principal)
    titles = {j.root: jobs.JOBS[j.job]["title"] for j in desk.jobs.values() if j.principal == principal}
    lines = [words.activity(e, titles) for e in reversed(found["entries"][-200:])]
    return {"lines": lines, "complete": found["complete"], "alarms": sum(x["alarm"] for x in lines)}


# ---------------------------------------------------------------- someone left


@app.get("/api/handover")
def handover(principal: str = Me):
    """Jobs of someone who has left, for the person named to follow them. Their access is not passed on."""
    people = desk.people()
    out = []
    for job in sorted(desk.jobs.values(), key=lambda j: -j.started):
        owner = people.get(job.principal, {})
        unfinished = job.state in {"working", "waiting"} or job.cut_short
        if unfinished and owner.get("successor") == principal and owner.get("status") != "active":
            blanks = {k: v for k, v in job.choice.items() if k != "pupils"}
            out.append(
                {"from": owner.get("name"), "job": job.job, "title": jobs.JOBS[job.job]["title"], "choice": blanks}
            )
    return {"jobs": out}


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
