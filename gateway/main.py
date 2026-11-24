"""HTTP wrapper around the gateway pipeline.

POST /tools/call  {server, tool, arguments, mandate, nonce, ts, sig}
  -> verify mandate + proof of possession (gateway/lib/gateway_verify.py)
  -> ALLOW: forward to the MCP server, DENY: 403, STEP_UP: 202
"""
# ruff: noqa: EM101, TRY301  (a refusal carries a code to match on; text shown to people has real apostrophes)

import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI
from fastapi import Request as HttpRequest
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastmcp import Client
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gateway.cli import person_message, sign_request
from gateway.lib import disclosure, policy, volume
from gateway.lib import record as records
from gateway.lib.common import (
    MAX_MANDATE,
    generate_keypair,
    jwk_to_pub,
    priv_from_pem,
    pub_to_jwk,
    verify_bytes,
)
from gateway.lib.errors import Reject
from gateway.lib.gateway_verify import CLOCK_SKEW, OWN_SERVER, Decision, Gateway, Request
from gateway.lib.record import NOBODY, Record, safe_arguments, safe_text
from gateway.lib.status_list import validate_status_list
from gateway.lib.store import Full, Store
from gateway.lib.trust_registry import TrustedList

STATE_DIR = Path(os.environ.get("GATEWAY_STATE_DIR", "gateway/state"))
# name -> URL (or an in-process FastMCP instance in tests); fastmcp.Client accepts both
MCP_SERVERS: dict[str, object] = dict(
    kv.split("=", 1) for kv in os.environ.get("MCP_SERVERS", "pupil-data=http://backend:8080/mcp/").split(",")
)
state: dict = {}
log = logging.getLogger(__name__)
READ_TRIES = 30
FRESH = 300  # seconds a signed request stays good
MAX_BODY = 128 * 1024
URN = re.compile(r"SCH(0[1-9]|1[0-2])")
THIS_TERM = {"academic_year": "2023/24", "term": "SPR"}  # the latest in the data
PUPIL_ID = re.compile(r"P\d{4}")


class CallBody(BaseModel):
    server: str = Field(max_length=64)
    tool: str = Field(max_length=64)
    arguments: dict
    mandate: str = Field(max_length=MAX_MANDATE)
    nonce: str = Field(min_length=1, max_length=128)
    ts: int
    sig: str = Field(max_length=128)


def load_state(state_dir: Path) -> None:
    started = time.time()
    registry = TrustedList(json.loads((state_dir / "trusted_list.json").read_text()))
    state["record"] = Record(state_dir / "record.jsonl", priv_from_pem((state_dir / "gateway_key.pem").read_bytes()))
    state["store"] = Store(state_dir / "gateway.db")
    state["gateway"] = Gateway(registry, status_lists={}, store=state["store"], started=started)
    status = json.loads((state_dir / "status_list.json").read_text())
    state["status_uri"] = status["uri"]
    state["status_pub"] = registry.issuer_key(status["issuer"], status["kid"])
    state["dir"] = state_dir
    state["started"] = started
    state["instance"] = secrets.token_hex(8)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    load_state(STATE_DIR)
    store = state["store"]
    yield
    store.close()


# Starlette's pure-ASGI limiter checks Content-Length and also counts streamed bytes,
# before FastAPI parses JSON or constructs one of the request models.
app = FastAPI(title="mandate gateway", lifespan=lifespan, max_body_size=MAX_BODY)


@app.exception_handler(RequestValidationError)
async def wrong_shape(_request: HttpRequest, exc: RequestValidationError):
    """Say which field is wrong, and nothing of what was sent: it may be personal, and it may not be valid text."""
    wrong = [
        {"loc": [str(x).encode("utf-8", "replace").decode() for x in e["loc"]], "type": e["type"]} for e in exc.errors()
    ]
    return JSONResponse({"detail": wrong}, status_code=422)


@app.get("/healthcheck")
def healthcheck() -> dict:
    return {"status": "ok", "instance": state["instance"], "started": int(state["started"])}


@app.get("/describe")
async def describe() -> dict:
    """Discovery for bring-your-own agents: what can be called and how a request must be signed."""
    servers = {}
    for name, target in MCP_SERVERS.items():
        async with Client(target) as client:
            servers[name] = [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in await client.list_tools()
            ]
    priv, pub = generate_keypair()
    example = sign_request(
        priv,
        server="pupil-data",
        tool="search",
        arguments={"query": "P0004", "urn": "SCH01"},
        mandate="<compact mandate JWT>",
    )
    return {
        "servers": servers,
        "step_up_patterns": state["gateway"].step_up,
        "signing": {
            "alg": "Ed25519 by the key in the mandate's cnf.jwk; sig is base64url without padding",
            "signing_input": "canonical JSON (sorted keys, separators ',' and ':', ensure_ascii=False) of "
            "{server, tool, arguments, mandate_hash, nonce, ts}",
            "mandate_hash": "'sha256:' + hex sha256 of the compact mandate JWT",
            "ts": "unix seconds, within 300s of gateway time; nonce must be unique per request",
            "example": {
                "agent_jwk": pub_to_jwk(pub),
                "signing_input": Request(**example).signing_input().decode(),
                "request": example,
            },
        },
    }


def read_shared(name: str) -> str:
    """A file that somebody else may be replacing at this moment, which Windows reports as permission denied."""
    for _ in range(READ_TRIES - 1):
        try:
            return (state["dir"] / name).read_text(encoding="utf-8")
        except PermissionError:
            time.sleep(0.01)
    return (state["dir"] / name).read_text(encoding="utf-8")


def whole_status_list(text: str) -> bool:
    """Is this a complete, authentic, current read of the configured status list?

    Read through a container's shared folder while `cli revoke` is replacing the file, the text can come back cut
    short or mixed for a moment, even though the replacement itself is atomic. A mixed read may still be valid JSON,
    JWT and zlib, so the signature must be checked before it replaces the current snapshot.
    """
    try:
        validate_status_list(text, state["status_pub"], state["status_uri"])
    except (KeyError, ValueError):
        return False
    return True


def refresh_revocations() -> None:
    """Re-read on every request, so `cli revoke` applies without a restart. Unreadable means unknown, so refused.

    A read that is not whole is tried again. If it never is, the last read is kept anyway: is_revoked refuses it.
    """
    lists = state["gateway"].status_lists
    try:
        for attempt in range(READ_TRIES):
            text = read_shared("status_list.jwt").strip()
            if whole_status_list(text):
                break
            if attempt < READ_TRIES - 1:
                time.sleep(0.01)
        lists[state["status_uri"]] = text
    except OSError:
        log.exception("the revocation list cannot be read")
        lists.pop(state["status_uri"], None)


def people() -> dict:
    """Re-read on every request, so that someone leaving takes effect on the next call."""
    return json.loads(read_shared("people.json"))


@dataclass
class Grant:
    """What this call may do, once every check before it has passed."""

    claims: dict
    arguments: dict
    labels: policy.Labels
    person: dict
    clearance: int


async def check_policy(client: Client, req: Request, claims: dict, arguments: dict) -> Grant:
    try:
        labels = policy.Labels((await client.call_tool("classification", {})).data)
    except (ToolError, KeyError, TypeError, ValueError, AttributeError) as e:
        raise Reject("LABELS_UNAVAILABLE", "cannot tell how sensitive this is, so the answer is no") from e
    need = policy.needed_level(req.tool, arguments, labels)
    person = policy.check_person(people(), claims, req.tool, arguments, need)
    clearance = policy.clearance_for(claims, person, req.tool)
    policy.check_clearance(clearance, need)
    if req.tool == "aggregate":
        disclosure.check_shape(arguments)
    return Grant(claims, arguments, labels, person, clearance)


async def governed_call(client: Client, tool: str, grant: Grant) -> tuple[object, dict | None]:
    """Run a search or get under the volume limits and the clearance. Pupils are counted before IDs are hidden."""
    everything = {"limit": volume.EVERY_ROW}
    if tool == "search":
        # fetch the whole scope and search it here, so that hidden columns cannot affect which rows come back
        in_scope = (await client.call_tool(tool, {**grant.arguments, "query": "", **everything})).data
        result = policy.search_visible(in_scope, grant.arguments["query"], grant.clearance, grant.labels)
        if volume.is_blanket(len(result), len(in_scope)):
            # no counts in the detail: how many records a school holds is itself an answer
            raise Reject("QUERY_TOO_BROAD", "query matches nearly every record; look for something more specific")
    else:
        result = (await client.call_tool(tool, {**grant.arguments, **everything})).data
    return volume.release(tool, result, grant.arguments.get("limit"))


def asked_about(tool: str, arguments: dict) -> set[str]:
    """Pupils named in the call. Even an empty answer says something about them, so they count as seen."""
    named = []
    if tool == "search":
        named = [arguments["query"].strip().upper()]
    elif tool in {"pupil", "write"}:
        named = [arguments.get("pupil_id")]
    elif tool == "draft":
        named = arguments.get("pupil_ids", [])
    return {p for p in named if isinstance(p, str) and (tool != "search" or PUPIL_ID.fullmatch(p))}


def learned(tool: str, arguments: dict, result) -> dict:
    """What an answer told the agent: whose data, which columns, how many rows. Never the values."""
    if tool == "aggregate":
        columns = [*arguments["group_by"], arguments["measure"]]
        return {"pupils": [], "columns": sorted(columns), "rows": len(result)}
    if tool == "write":
        return {"pupils": sorted(asked_about(tool, arguments)), "columns": [str(arguments["column"])], "rows": 1}
    rows = result if isinstance(result, list) else [result] if isinstance(result, dict) else []
    rows = [r for r in rows if isinstance(r, dict)]
    if tool == "draft":
        rows = [{volume.PUPIL_KEY: r.get(volume.PUPIL_KEY), "DisplayName": ""} for r in rows]  # the letter is the name
    pupils = {r[volume.PUPIL_KEY] for r in rows if r.get(volume.PUPIL_KEY)}
    columns = {c for r in rows for c in r} if not str(arguments.get("path", "")).endswith(".json") else set()
    return {"pupils": sorted(pupils), "columns": sorted(columns), "rows": len(rows)}


def write_record(decision: Decision, req: Request, source: str, seen: dict | None = None) -> None:
    """One entry per call. Nothing from a request with no genuine mandate is kept but the refusal itself."""
    claims = decision.claims
    event = {"decision": decision.decision, "reason": decision.reason_code, "source": source, "principal": NOBODY}
    if claims:
        event |= {
            "principal": safe_text(str(claims["delegator"]["principal"])),
            "jti": claims["jti"],
            "root": claims.get("root", claims["jti"]),
            "agent_id": safe_text(str(claims.get("agent_id"))),
            "tool": safe_text(f"{req.server}.{req.tool}"),
            "args": safe_arguments(req.arguments),
        }
    state["record"].append(**event, **(seen or {"pupils": [], "columns": [], "rows": 0}))


async def run_tool(client: Client, req: Request, grant: Grant) -> tuple[object, dict, dict]:
    """The call itself, under every limit that looks at the answer. Returns (result, what it told the agent, extra)."""
    tool, arguments, extra = req.tool, grant.arguments, {}
    spend(grant, asked_about(tool, arguments))  # before the call: a correction cannot be taken back
    if tool in volume.GOVERNED_TOOLS:
        result, summary = await governed_call(client, tool, grant)
        extra = {"volume": summary} if summary else {}
    elif tool == "aggregate" and disclosure.counts_pupils(arguments):
        rows = (await client.call_tool(tool, disclosure.by_pupil(arguments))).data
        result, note = disclosure.suppress(rows, arguments["group_by"])
        extra = {"disclosure": note}
    else:
        result = (await client.call_tool(tool, arguments)).data

    seen = learned(tool, arguments, result)
    spend(grant, set(seen["pupils"]))
    if tool in volume.GOVERNED_TOOLS and isinstance(result, list):
        result = policy.see_only(result, grant.clearance, grant.labels)
        seen["columns"] = [c for c in seen["columns"] if grant.labels.column(c) <= grant.clearance]
    return result, seen, extra


def spend(grant: Grant, pupils: set[str]) -> None:
    """Between the answer and its release, in one transaction: either there was room for all of it, or it stays here."""
    try:
        state["store"].spend(policy.budgets(grant.claims, grant.person, time.strftime("%Y-%m-%d")), pupils)
    except Full as e:
        raise Reject("BUDGET_EXCEEDED", e.detail) from e


def connect(req: Request) -> Client:
    target = MCP_SERVERS.get(req.server)
    if target is None:
        raise Reject("NO_SUCH_SERVER", f"no MCP server configured for {req.server!r}")
    return Client(target)


def refuse(decision, code: str, detail: str = ""):
    decision.decision, decision.reason_code, decision.detail = "DENY", code, detail
    return decision


async def handle(body: CallBody, source: str) -> tuple[int, dict]:
    """Decide, run, record, release: in that order. Returns (HTTP status, reply)."""
    req = Request(**body.model_dump())
    refresh_revocations()
    decision = state["gateway"].decide(req)
    result, extra, status, seen = None, {}, 403, None
    if decision.decision == "ALLOW" and req.server == OWN_SERVER:
        return collect(decision, req, source)
    if decision.decision != "DENY":
        try:
            async with connect(req) as client:
                grant = await check_policy(client, req, decision.claims, decision.arguments)
                if decision.decision == "STEP_UP":
                    extra, status = {"hold_id": hold(decision, body)}, 202
                else:
                    result, seen, extra = await run_tool(client, req, grant)
                    status = 200
        except Reject as r:
            refuse(decision, r.code, r.detail)
        except ToolError as e:
            status, extra = 502, {"error": str(e)}
        except Exception:
            log.exception("refused a call that could not be completed")
            refuse(decision, "MALFORMED_REQUEST")
            status = 403
    try:
        write_record(decision, req, source, seen)
    except Exception:
        log.exception("the record could not be written, so nothing is released")
        return 403, {"decision": refuse(decision, "RECORD_UNAVAILABLE").to_dict()}
    reply = {"decision": decision.to_dict(), **extra}
    return status, reply | ({"result": result} if status == 200 else {})  # noqa: PLR2004


# ---------------------------------------------------------------- calls that wait for a person (question 9)


def hold(decision: Decision, body: CallBody) -> str:
    claims = decision.claims
    try:
        return state["store"].hold(
            body.model_dump(),
            principal=claims["delegator"]["principal"],
            agent_id=claims["agent_id"],
            root=claims["root"],
            until=claims["exp"],
        )
    except Full as e:
        raise Reject("TOO_MANY_WAITING", e.detail) from e


def collect(decision: Decision, req: Request, source: str) -> tuple[int, dict]:
    """The agent asks after its own held call. Its result is given once and then forgotten."""
    found = state["store"].get_hold(req.arguments["id"])
    claims = decision.claims
    if found is None or (found["agent_id"], found["root"]) != (claims["agent_id"], claims["root"]):
        return 403, {"decision": refuse(decision, "OUT_OF_SCOPE", "no such call of yours").to_dict()}
    reply = {"decision": decision.to_dict(), "held": {"state": found["state"], "reason": found["reason"]}}
    if found["state"] == "done" and found["result"] is not None:
        decision.reason_code = "COLLECTED"
        try:
            write_record(decision, req, source)
            state["store"].forget_result(found["id"])
        except Exception:
            log.exception("the record could not be written, so nothing is released")
            return 403, {"decision": refuse(decision, "RECORD_UNAVAILABLE").to_dict()}
        reply["result"] = found["result"]
    return 200, reply


class PersonBody(BaseModel):
    """Signed by a person's own key. Who they are comes from the signature: there is no 'whose' to change."""

    principal: str = Field(max_length=128)
    nonce: str = Field(min_length=1, max_length=128)
    ts: int
    sig: str = Field(max_length=128)
    hold: str | None = Field(default=None, max_length=128)
    answer: str | None = Field(default=None, max_length=16)
    names: bool | None = None
    root: str | None = Field(default=None, max_length=256)
    seq: int | None = None
    urn: str | None = Field(default=None, max_length=16)
    year: int | None = None


def verify_person(body: PersonBody, do: str, code: str, *fields: str) -> dict:
    """The person, or Reject(code). A signature is good once, for one kind of thing, for five minutes."""
    try:
        person = people().get(body.principal) or {}
        given = {f: getattr(body, f) for f in fields if getattr(body, f) is not None}
        message = person_message(body.principal, do, body.nonce, body.ts, given)
        now = time.time()
        good = (
            int(state["started"]) <= body.ts
            and now - FRESH <= body.ts <= now + CLOCK_SKEW
            and "jwk" in person
            and verify_bytes(jwk_to_pub(person["jwk"]), message, body.sig)
            and state["store"].use_nonce(f"person:{body.principal}", body.nonce)
        )
    except Exception as e:
        raise Reject(code, "could not be checked") from e
    if not good:
        raise Reject(code, "not signed by that person just now")
    if person.get("status") != "active":
        raise Reject("PERSON_PAUSED", f"{body.principal} is {person.get('status', 'not active')}")
    return person


def person_error(r: Reject) -> JSONResponse:
    return JSONResponse({"reason_code": r.code, "detail": r.detail}, status_code=403)


async def preview(found: dict) -> dict:
    """What the person is being asked to agree to, worked out from the stored request and not from the agent."""
    req = Request(**found["body"])
    try:
        claims = state["gateway"].verify(req.mandate)
        arguments = state["gateway"].check_scope(req, claims)[3]
        async with connect(req) as client:
            await check_policy(client, req, claims, arguments)
            if req.tool == "draft":
                return {"letters": (await client.call_tool("draft", arguments)).data}
            if req.tool == "write":
                ask = {"pupil_id": arguments["pupil_id"], "urn": arguments["urn"]}
                now = (await client.call_tool("pupil", ask)).data
                return {"name": now.get("DisplayName"), "now": now.get(arguments["column"])}
    except (Reject, ToolError) as e:
        return {"problem": getattr(e, "code", "this could not be prepared")}
    return {}


@app.post("/holds")
async def holds(body: PersonBody):
    """Everything waiting for this person, and nobody else's."""
    try:
        verify_person(body, "holds", "APPROVER_NOT_VERIFIED")
    except Reject as r:
        return person_error(r)
    refresh_revocations()
    out = []
    for found in state["store"].waiting_for(body.principal):
        req = found["body"]
        out.append(
            {k: found[k] for k in ("id", "created", "expires", "agent_id", "root")}
            | {"tool": req["tool"], "arguments": req["arguments"], "preview": await preview(found)}
        )
    return {"holds": out}


@app.post("/holds/answer")
async def answer_hold(body: PersonBody, http: HttpRequest):
    store, source = state["store"], http.client.host if http.client else "unknown"
    try:
        verify_person(body, "answer", "APPROVER_NOT_VERIFIED", "hold", "answer")
        found = store.get_hold(body.hold or "")
        if found is None or found["principal"] != body.principal:
            raise Reject("HOLD_NOT_WAITING")  # the same answer whether or not it exists
        if body.answer not in {"approve", "refuse"}:
            raise Reject("ANSWER_NOT_CLEAR", "approve or refuse")
        if found["state"] != "waiting":
            raise Reject("HOLD_NOT_WAITING", found["state"])
    except Reject as r:
        return person_error(r)
    req = Request(**found["body"])
    if body.answer == "refuse":
        if not store.leave_waiting(found["id"], "refused", "the person said no"):
            return person_error(Reject("HOLD_NOT_WAITING"))
        store.forget_result(found["id"])
        note(found, req, source, ("DENY", "REFUSED_BY_PERSON"))
        return {"state": "refused"}
    return await release(found, req, source)


def note(found: dict, req: Request, source: str, outcome: tuple[str, str], seen: dict | None = None) -> None:
    """A record entry about a held call, under the person and job it was held for."""
    claims = {"delegator": {"principal": found["principal"]}, "jti": found["root"], "root": found["root"]}
    claims["agent_id"] = found["agent_id"]
    entry = Decision(*outcome, policy_version="", mandate_hash="", request_hash="", agent_id=None, ts=0)
    entry.claims = claims
    write_record(entry, req, source, seen)


async def release(found: dict, req: Request, source: str):
    """Approved. Every check runs again, since anything may have changed while it waited, and then it runs once."""
    store, gateway, hold_id = state["store"], state["gateway"], found["id"]
    refresh_revocations()
    taken = started = False
    try:
        claims = gateway.verify(req.mandate)
        decision, code, detail, arguments = gateway.check_scope(req, claims)
        if decision == "DENY":
            raise Reject(code, detail)
        async with connect(req) as client:
            grant = await check_policy(client, req, claims, arguments)
            taken = store.leave_waiting(hold_id, "running")
            if not taken:
                raise Reject("HOLD_NOT_WAITING")
            note(found, req, source, ("HELD", "RELEASING"))  # recorded before anything happens
            started = True
            result, seen, _ = await run_tool(client, req, grant)
        note(found, req, source, ("ALLOW", "APPROVED_BY_PERSON"), seen)
        store.finish(hold_id, "done", result)
    except Reject as r:
        if r.code != "HOLD_NOT_WAITING":
            store.finish(hold_id, "blocked", reason=r.code) if taken else store.leave_waiting(
                hold_id, "blocked", r.code
            )
            store.forget_result(hold_id)
            note(found, req, source, ("DENY", r.code))
        return person_error(r)
    except ToolError:
        store.finish(hold_id, "failed", reason="the data server refused it")
        return person_error(Reject("FAILED", "the data server refused it"))
    except Exception:
        log.exception("a held call could not be completed")
        if taken:
            store.finish(hold_id, "unknown" if started else "blocked", reason="it could not be recorded")
        return person_error(Reject("UNKNOWN" if started else "RECORD_UNAVAILABLE", "nothing more will be tried"))
    return {"state": "done", "result": result}


# ---------------------------------------------------------------- a person's own view (questions 14 and 16)

SHOWN = ("seq", "ts", "decision", "reason", "tool", "args", "agent_id", "source", "pupils", "columns", "rows", "root")


async def own_data(tool: str, arguments: dict):
    """Something the person may see for themselves, fetched for them and for no agent."""
    async with Client(MCP_SERVERS["pupil-data"]) as client:
        return (await client.call_tool(tool, arguments)).data


@app.post("/log")
async def read_log(body: PersonBody):
    """What was done in this person's name. Opened by their own key: an agent's key or a mandate opens nothing."""
    try:
        person = verify_person(body, "log", "LOG_READER_NOT_VERIFIED", "names", "root", "seq")
    except Reject as r:
        return person_error(r)
    record: Record = state["record"]
    everything = record.entries()
    mine = [e for e in everything if e["principal"] == body.principal and body.root in (None, e.get("root"))]
    labels = policy.Labels(await own_data("classification", {}))
    reply = {
        "entries": [{k: e.get(k) for k in SHOWN} for e in mine],
        "summary": records.summary(everything, body.principal, labels.columns, body.root),
        "check": records.check(record.path, record.key.public_key()),
        "head": {"seq": record.last["seq"], "hash": record.last["hash"]},
    }
    if body.seq is not None:
        reply["hash_at"] = next((e["hash"] for e in everything if e["seq"] == body.seq), None)
    if body.names and person.get("clearance", 1) >= labels.column("DisplayName"):
        wanted = {p for e in mine for p in e.get("pupils", [])}
        path = "synthetic/synthetic_display_names.csv"
        rows = await own_data("get", {"path": path, "limit": volume.EVERY_ROW})
        reply["names"] = {r[volume.PUPIL_KEY]: r["DisplayName"] for r in rows if r[volume.PUPIL_KEY] in wanted}
    return reply


@app.post("/person/schools")
async def person_schools(body: PersonBody):
    """The schools this person covers: public information, kept to their own."""
    try:
        person = verify_person(body, "schools", "PERSON_NOT_VERIFIED")
    except Reject as r:
        return person_error(r)
    rows = await own_data("get", {"path": "synthetic/synthetic_schools.csv"})
    covers = person.get("urns", [])
    return {"schools": {r["URN"]: r["SchoolName"] for r in rows if covers == "*" or r["URN"] in covers}}


@app.post("/person/class")
async def person_class(body: PersonBody, http: HttpRequest):
    """A class list, so that the person can tick pupils and no agent has to be given the list. Recorded."""
    try:
        person = verify_person(body, "class", "PERSON_NOT_VERIFIED", "urn", "year")
        if not isinstance(body.urn, str) or not URN.fullmatch(body.urn) or body.year not in (10, 11):
            raise Reject("OUT_OF_SCOPE", "a school and year group are needed")
        claims = {"delegator": {"principal": body.principal}}
        ask = {"urn": body.urn, "year_group": body.year, **THIS_TERM}
        labels = policy.Labels(await own_data("classification", {}))
        need = policy.needed_level("roster", ask, labels)
        policy.check_person(people(), claims, "roster", ask, need)
        policy.check_clearance(person.get("clearance", 1), need)
        rows = await own_data("roster", ask)
        state["record"].append(
            decision="ALLOW",
            reason="PERSON_LOOKUP",
            source=http.client.host if http.client else "unknown",
            principal=body.principal,
            root=None,
            agent_id=None,
            tool="pupil-data.roster",
            args=ask,
            pupils=sorted(r[volume.PUPIL_KEY] for r in rows),
            columns=["DisplayName", volume.PUPIL_KEY],
            rows=len(rows),
        )
    except Reject as r:
        return person_error(r)
    except Exception:
        log.exception("a lookup could not be completed")
        return person_error(Reject("RECORD_UNAVAILABLE"))
    return {"pupils": {r[volume.PUPIL_KEY]: r["DisplayName"] for r in rows}}


@app.post("/tools/call")
async def tools_call(body: CallBody, http: HttpRequest):
    status, reply = await handle(body, http.client.host if http.client else "unknown")
    return JSONResponse(reply, status_code=status)


try:
    # here, at the end: demo imports main lazily
    from gateway.demo import demo_enabled
    from gateway.demo import router as demo_router
except ModuleNotFoundError as e:
    # The production image leaves gateway/demo.py out (.dockerignore, ADR-0001), so no setting can switch it on
    if e.name != "gateway.demo":
        raise
    demo_router = None

    def demo_enabled() -> bool:
        return False


@app.middleware("http")
async def demo_off_means_absent(request: HttpRequest, call_next):
    """With the demo off, /demo/* answers exactly as a path that does not exist, for any method and any body.

    The router's own check runs after the body has been read as JSON, so a body that is not JSON got a 422, which
    told a caller the route was there.
    """
    path = request.url.path
    if (path == "/demo" or path.startswith("/demo/")) and not demo_enabled():
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return await call_next(request)


if demo_router is not None:
    app.include_router(demo_router)
