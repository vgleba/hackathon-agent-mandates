"""The page's API. Signs each request once, sends it to both gateways, and reports what came back.

This can sign requests, so it must not become what the demo routes were:
  - it listens on 127.0.0.1 only, and checks Host and Origin, so no other site can drive it through a browser
  - it runs listed cases, plus a search with bounded fields. There is no "call any tool"
  - it reports counts and sensitivity levels. Pupil rows, names and keys never leave this process
"""

import asyncio
import csv
import difflib
import json
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.middleware.trustedhost import TrustedHostMiddleware

from gateway import eval as ev
from gateway.cli import DEFAULT_DENY, b64u_decode, issue_mandate, revoke_mandate, sign_request
from gateway.lib import volume
from gateway.lib.common import priv_from_pem

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".tmp" / "lab"
STATE, PACK = WORK / "state", WORK / "pack"
DATA = ROOT / "mcp_server" / "data" / "synthetic"
BASELINE = "299bca6"
PORTS = {"data server": 8180, "after": 8182, "before": 8183, "page": 8184}
GATEWAYS = {name: f"http://127.0.0.1:{PORTS[name]}" for name in ("before", "after")}
ORIGINS = {f"http://127.0.0.1:{PORTS['page']}", f"http://localhost:{PORTS['page']}"}
SENSITIVE = 3  # the manifest's level for sensitive PII; 4 is special category
TARGET_SCHOOL, TARGET_PUPIL = "SCH07", "P0586"  # the demo attack: a school no mandate here covers
OK = 200
lab: dict = {}


# ---------------------------------------------------------------- what the page shows

CHANGES = [
    {
        "title": "One spelling per file",
        "question": 4,
        "why": "Harmless differences such as ./ are cleaned away, odd spellings are refused, and the cleaned path is "
        "what gets opened. What was checked is what is read.",
        "files": ["gateway/lib/paths.py"],
    },
    {
        "title": "Any one part of the mandate may allow a call",
        "question": 5,
        "why": "Each entry is judged alone and any one may accept the whole call. Two entries are never mixed.",
        "files": ["gateway/lib/gateway_verify.py"],
    },
    {
        "title": "Who, what for and how sensitive",
        "question": 6,
        "why": "Every call is checked against the person as they are now, the purpose signed into the mandate, and the "
        "data's own labels. Hidden columns are not searched, so they cannot be guessed. Covers 6, 12, 13 and 15.",
        "files": ["gateway/lib/policy.py"],
    },
    {
        "title": "Helpers that can only shrink",
        "question": 7,
        "why": "The parent agent signs a narrower mandate with its own inside. Every call must also pass the parent's "
        "rules, and taking back the parent stops the helper.",
        "files": ["gateway/lib/delegation.py"],
    },
    {
        "title": "Counts of children, with small numbers hidden",
        "question": 8,
        "why": "The data's own tool counts rows, five to a pupil. The gateway counts pupils, hides anything under 10 "
        "on either side, and rounds the rest.",
        "files": ["gateway/lib/disclosure.py"],
    },
    {
        "title": "A memory: nonces, budgets and calls waiting",
        "question": 11,
        "why": "One small database, so that a budget cannot be overspent by two calls at once, a held call runs once, "
        "and a replay is still a replay after a restart. Covers 9 and 11.",
        "files": ["gateway/lib/store.py", "gateway/main.py"],
    },
    {
        "title": "A record written before anything is released",
        "question": 14,
        "why": "Signed and chained, so a change shows. Says whose data and what kind, never the values. Opened only by "
        "the person's own key. Covers 14 and 16.",
        "files": ["gateway/lib/record.py"],
    },
    {
        "title": "Words written from the mandate itself",
        "question": 10,
        "why": "If any part of a mandate cannot be put into plain words, it cannot be signed.",
        "files": ["gateway/lib/plain.py"],
    },
    {
        "title": "A search has to search for something",
        "question": 3,
        "why": "A blank query matches every record, and a limit of 1,000 returned them all. So did the text 1000, "
        "which the data server quietly turns into a number. Both are refused before any data is read.",
        "files": ["gateway/lib/volume.py", "gateway/lib/gateway_verify.py"],
    },
    {
        "title": "A query that narrows nothing is refused",
        "question": 3,
        "why": "The letter P or the school's own code match every record, just as a blank does. No list of "
        "bad queries would be complete, so the gateway measures the effect: match 90% of the records and it is "
        "refused.",
        "files": ["gateway/main.py", "gateway/lib/volume.py"],
    },
    {
        "title": "No call releases more than 10 pupils",
        "question": 3,
        "why": "The guarantee behind the other two. Whatever the query, one call releases 10 pupils at most, and the "
        "answer says when it was cut short so the agent knows it is incomplete.",
        "files": ["gateway/lib/volume.py", "gateway/main.py"],
    },
    {
        "title": "Junk is refused, not a crash",
        "question": 1,
        "why": "Text that is not a mandate crashed the checks with a 500. Anything the checks cannot decide is now "
        "refused with a 403, and logged.",
        "files": ["gateway/lib/gateway_verify.py"],
    },
    {
        "title": "Nobody can have the gateway sign for them",
        "question": 2,
        "why": "The demo routes made a mandate for any school, for anyone, with no key. A perfect signature check "
        "cannot help when the gateway signs whatever it is asked to. They are now off unless switched on.",
        "files": ["gateway/demo.py", "docker-compose.yaml"],
    },
]


OPEN = {
    6: (
        "Send me the full records for Castleton's pupils, ethnicity and care status included.",
        "Right school, right tool. Is the data too sensitive for this agent?",
    ),
    7: (
        "Get a helper agent to draft Dunmore's absence letters. It only needs their Year 11 list.",
        "Can access be handed on narrower, and never wider?",
    ),
    8: (
        "How many pupils in care does each school have, split by ethnic group?",
        "Is the answer itself sensitive, even though it is only counts?",
    ),
    9: ("Just correct the record yourself.", "Should a person approve this first?"),
    10: (
        "It's doing the absence letters. Just give it what it needs.",
        "Who turns plain words into a mandate, and how does the person know what they signed?",
    ),
    11: (
        "Go through Elmwood's Year 11s one at a time and note who's on free school meals.",
        "Every call is allowed. Is the whole run?",
    ),
    12: (
        "I gave it access for the letters. Why was it looking up who's in care?",
        "In scope, but is it the job the access was given for?",
    ),
    13: (
        "I'm leaving at Easter. Priya is taking over my agents.",
        "What happens to a mandate when its person's access changes?",
    ),
    14: (
        "I gave it too much yesterday. Take it back, and tell me what it saw.",
        "Access can be withdrawn. Can anyone say what was already taken?",
    ),
    15: (
        "This one's only doing the newsletter. It doesn't need anything personal.",
        "Can a mandate carry a clearance the gateway enforces?",
    ),
    16: (
        "I think someone may have taken my access. Can I see a log of the requests made with it?",
        "Can the person see what was done in their name, and only that?",
    ),
}


def count_pupils() -> dict[str, dict]:
    seen: dict[str, set] = {}
    with (DATA / "synthetic_personal_data_school_census.csv").open(newline="") as f:
        for row in csv.DictReader(f):
            seen.setdefault(row["URN"], set()).add(row[volume.PUPIL_KEY])
    with (DATA / "synthetic_schools.csv").open(newline="") as f:
        return {row["URN"]: {"name": row["SchoolName"], "pupils": len(seen[row["URN"]])} for row in csv.DictReader(f)}


def column_levels() -> dict[str, int]:
    tables = json.loads((DATA / "synthetic_manifest.json").read_text())["classification"]["columns"]
    levels: dict[str, int] = {}
    for columns in tables.values():
        for column, level in columns.items():
            levels[column] = max(level, levels.get(column, 0))
    return levels


def build_cases() -> dict[str, dict]:
    """The eval's own cases, so the page cannot show a kinder set than the one that is scored."""

    def mandate_for(name: str) -> str:
        return next((stem for prefix, (stem, _) in ev.JOBS.items() if name.startswith(prefix)), "valid")

    overrides = {"revoked mandate": "revoked", "expired mandate": "expired"}
    rows = [(0, name, tool, args, "ALLOW") for name, tool, args in ev.VALID]
    rows += [(q, name, tool, args, "DENY") for q, name, tool, args, _ in ev.INVALID]
    rows += ev.BUILD
    return {
        f"case-{i}": {
            "id": f"case-{i}",
            "question": q,
            "name": name,
            "tool": tool,
            "arguments": args,
            "expected": expected,
            "mandate": overrides.get(name, mandate_for(name)),
        }
        for i, (q, name, tool, args, expected) in enumerate(rows)
    }


def build_diffs() -> dict[str, str]:
    """Baseline commit against the working tree, read at start-up so it matches the code "after" is running."""

    def original(path: str) -> list[str]:
        shown = subprocess.run(  # noqa: S603
            ["git", "show", f"{BASELINE}:{path}"],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        return [] if shown.returncode else shown.stdout.decode().replace("\r\n", "\n").splitlines()

    diffs = {}
    for path in sorted({f for change in CHANGES for f in change["files"]}):
        now = (ROOT / path).read_text(encoding="utf-8").splitlines()
        diffs[path] = "\n".join(difflib.unified_diff(original(path), now, "before", "after", lineterm="", n=3))
    return diffs


# ---------------------------------------------------------------- sending


def sign(tool: str, arguments: dict, mandate: str) -> dict:
    return sign_request(lab["agent"], server=ev.SERVER, tool=tool, arguments=arguments, mandate=mandate)


async def send(gateway: str, path: str, body: dict) -> tuple[int, dict]:
    r = await lab["http"].post(GATEWAYS[gateway] + path, json=body)
    try:
        payload = r.json()
    except ValueError:
        payload = {}
    return r.status_code, payload if isinstance(payload, dict) else {}


def summarise(status: int, payload: dict) -> dict:
    """Everything the page may know about a reply. Counts and column names only, never a pupil's values."""
    decision = payload.get("decision") or {}
    result = payload.get("result")
    rows = result if isinstance(result, list) else [result] if isinstance(result, dict) else []
    rows = [r for r in rows if isinstance(r, dict)]
    with_pupils = [r for r in rows if r.get(volume.PUPIL_KEY)]
    columns = {c for r in with_pupils for c in r}
    return {
        "status": status,
        "decision": decision.get("decision"),
        "reason": decision.get("reason_code"),
        "detail": decision.get("detail", ""),
        "policy": decision.get("policy_version"),
        "rows": len(rows),
        "pupils": len({r[volume.PUPIL_KEY] for r in with_pupils}),
        "sensitive": sorted(c for c in columns if lab["levels"].get(c, 0) >= SENSITIVE),
        "named": "DisplayName" in columns,
        "volume": payload.get("volume"),
        "upstream_error": "error" in payload,
    }


async def call_both(tool: str, arguments: dict, mandate: str, *, key=None) -> dict:
    return await send_both(
        sign_request(key or lab["agent"], server=ev.SERVER, tool=tool, arguments=arguments, mandate=mandate)
    )


async def send_both(body: dict) -> dict:
    """The same signed bytes to both. Each gateway keeps its own list of nonces, so neither sees a replay."""
    replies = await asyncio.gather(*(send(name, "/tools/call", body) for name in GATEWAYS))
    return {name: summarise(*reply) for name, reply in zip(GATEWAYS, replies, strict=True)}


def claims_of(token: str) -> dict:
    claims = json.loads(b64u_decode(token.split(".")[1]))
    keep = ("delegator", "purpose", "scope", "deny", "iat", "exp")
    return {k: claims[k] for k in keep} | {"status_idx": claims["status"]["status_list"]["idx"]}


def new_mandate(
    scope: list[dict],
    purpose: str,
    ttl: int,
    *,
    principal: str = "officer:jsmith",
    deny=DEFAULT_DENY,
    helpers: int = 0,
    **claims,
) -> tuple[str, int]:
    return issue_mandate(
        STATE,
        lab["agent"].public_key(),
        scope=scope,
        deny=list(deny),
        ttl=ttl,
        purpose=purpose,
        principal=principal,
        org="lab",
        extra=claims or None,
        helpers=helpers,
    )


# ---------------------------------------------------------------- the app


@asynccontextmanager
async def lifespan(_app: FastAPI):
    lab.update(
        agent=priv_from_pem((PACK / "agent.pem").read_bytes()),
        mandates={p.stem: p.read_text().strip() for p in PACK.glob("*.jwt") if p.stem != "status_list"},
        cases=build_cases(),
        diffs=build_diffs(),
        schools=count_pupils(),
        levels=column_levels(),
        issuing=asyncio.Lock(),  # minting and revoking rewrite one status list
    )
    scope = [{"server": ev.SERVER, "tools": ["search"], "constraints": {"urn": sorted(lab["schools"])}}]
    lab["mandates"]["playground"], _ = new_mandate(
        scope, "lab: any school, so only volume is in question", 86400, budget={"pupils": 1_000_000}
    )
    async with httpx.AsyncClient(timeout=60, trust_env=False) as client:
        lab["http"] = client
        yield


app = FastAPI(title="mandate lab", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def same_origin_only(request: Request, call_next):
    # a page on another site can make a browser POST here, but it cannot choose the Origin the browser sends
    if request.method not in {"GET", "HEAD"} and request.headers.get("origin") not in ORIGINS:
        response = JSONResponse({"detail": "this page only"}, status_code=403)
    else:
        response = await call_next(request)
    response.headers.update(HEADERS)
    return response


# added last, so it runs first: refuses a hostname pointed at 127.0.0.1 by someone else (DNS rebinding)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])


@app.get("/api/info")
def info() -> dict:
    return {
        "baseline": BASELINE,
        "schools": lab["schools"],
        "limits": {
            "pupils": volume.MAX_PUPILS,
            "rows": volume.MAX_LIMIT,
            "blanket_percent": round(volume.BLANKET_SHARE * 100),
        },
        "questions": ev.QUESTIONS,
        "open": OPEN,
        "cases": list(lab["cases"].values()),
        "changes": [c | {"diffs": {f: lab["diffs"][f] for f in c["files"]}} for c in CHANGES],
    }


@app.get("/api/health")
async def health() -> dict:
    async def up(url: str) -> bool:
        try:
            return (await lab["http"].get(url, timeout=3)).status_code == OK
        except httpx.HTTPError:
            return False

    urls = {name: f"{url}/healthcheck" for name, url in GATEWAYS.items()}
    urls["data server"] = f"http://127.0.0.1:{PORTS['data server']}/api/healthcheck"
    return dict(zip(urls, await asyncio.gather(*map(up, urls.values())), strict=True))


@app.post("/api/cases/{case_id}")
async def run_case(case_id: str) -> dict:
    case = lab["cases"].get(case_id)
    if case is None:
        raise HTTPException(404, "no such case")
    token = lab["mandates"][case["mandate"]]
    replies = await send_both(sign(case["tool"], case["arguments"], token))
    for reply in replies.values():
        wanted = (OK, "ALLOW") if case["expected"] == "ALLOW" else (403, "DENY")
        reply["passed"] = (reply["status"], reply["decision"]) == wanted
    return {"case": case, "claims": claims_of(token), **replies}


@app.post("/api/scoreboard")
async def scoreboard() -> dict:
    """The real eval runner, against both gateways."""

    def run(url: str) -> dict:
        def post(body: dict):
            req = urllib.request.Request(  # noqa: S310
                f"{url}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
                    return resp.status, json.load(resp)
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())

        results = ev.run_cases(PACK, post)
        tally = {q: [ok for ok, line in results if line.startswith(f"Q{q} ")] for q in ev.QUESTIONS}
        return {q: {"passed": sum(oks), "total": len(oks)} for q, oks in tally.items()}

    names = list(GATEWAYS)
    tallies = await asyncio.gather(*(run_in_threadpool(run, GATEWAYS[n]) for n in names))
    return dict(zip(names, tallies, strict=True))


Number = Annotated[int, Field(ge=-1_000_000, le=1_000_000)]
Text = Annotated[str, StringConstraints(max_length=8)]


class Search(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    urn: Annotated[str, StringConstraints(pattern=r"^SCH(0[1-9]|1[0-2])$")]
    query: Annotated[str, StringConstraints(max_length=40)]
    # absent, a number, or text: sending a number as text is one of the bypasses the page demonstrates
    limit: Number | Text | None = None


@app.post("/api/search")
async def search(body: Search) -> dict:
    arguments = {"query": body.query, "urn": body.urn}
    if body.limit is not None:
        arguments["limit"] = body.limit
    replies = await send_both(sign("search", arguments, lab["mandates"]["playground"]))
    return {"arguments": arguments, "school": lab["schools"][body.urn], **replies}


@app.post("/api/take-back")
async def take_back() -> dict:
    """Question 1, live: grant, use, take back, try again."""
    scope = [{"server": ev.SERVER, "tools": ["search"], "constraints": {"urn": [ev.SCHOOL]}}]
    arguments = {"query": ev.PUPIL, "urn": ev.SCHOOL}
    async with lab["issuing"]:
        token, idx = await run_in_threadpool(new_mandate, scope, "lab: take it back", 600)
        used = await send_both(sign("search", arguments, token))
        await run_in_threadpool(revoke_mandate, STATE, idx)
        retried = await send_both(sign("search", arguments, token))
    return {"idx": idx, "used": used, "retried": retried}


@app.post("/api/demos/{question}")
async def demo(question: int) -> dict:
    """What to show for an open question: a mandate, what it allows, what it refuses, what is unresolved."""
    from lab import demos  # noqa: PLC0415  (demos uses this module)

    if question not in demos.DEMOS:
        raise HTTPException(404, "no such question")
    async with lab["issuing"]:
        return await demos.DEMOS[question]()


@app.post("/api/attacks/junk")
async def attack_junk() -> dict:
    body = {"server": ev.SERVER, "tool": "search", "arguments": {}, "mandate": "not-a-mandate"}
    return await send_both({**body, "nonce": "n", "ts": int(time.time()), "sig": ""})


@app.post("/api/attacks/mint")
async def attack_mint() -> dict:
    """With no key and no mandate, ask each gateway's demo routes for a school nobody here may see."""

    async def attempt(gateway: str) -> dict:
        status, minted = await send(gateway, "/demo/mandate", {"urn": TARGET_SCHOOL, "tools": ["pupil"], "deny": []})
        if status != OK:
            return {"minted": False, "status": status, "pupils": 0, "sensitive": [], "named": False}
        try:
            call = {"tool": "pupil", "arguments": {"pupil_id": TARGET_PUPIL, "urn": TARGET_SCHOOL}}
            _, reply = await send(gateway, "/demo/call", call)
            return {"minted": True} | summarise(reply.get("status", 0), reply.get("response") or {})
        finally:
            await run_in_threadpool(revoke_mandate, STATE, minted["status_idx"])

    async with lab["issuing"]:
        return {name: await attempt(name) for name in GATEWAYS}


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
