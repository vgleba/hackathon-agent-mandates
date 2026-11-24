## Context

[RED_TEAM_REPORT.md](../../../RED_TEAM_REPORT.md) audited `c1572f9`. RT-01 and RT-02 still reproduce on `vlod`:
- [docker-compose.yaml](../../../docker-compose.yaml) sets `GATEWAY_DEMO=1`.
- [gateway_verify.py](../../../gateway/lib/gateway_verify.py) refuses only when `exp < now - CLOCK_SKEW`.

Commit `26125b3` already makes switched-off `/demo/*` routes look absent: a middleware answers 404 before routing, and the routes are left out of `/openapi.json`. Since that commit, `gateway/main.py` imports both `demo_enabled` and `router` from `gateway/demo.py`.

The organisers deploy the gateway to AWS (the repo comes from the i-dot-ai `webapp-ecs` template), and the config is hidden from the team. We do not know:
- whether `docker-compose.yaml` is read;
- how `gateway/state/` reaches the container;
- how many tasks run;
- whether storage survives a restart;
- what sits in front of the gateway.

What we hand over is the image that `gateway/Dockerfile` builds from this repo. Today that image copies all of `gateway/`, including `demo.py` and every file in `gateway/state/`, because [.dockerignore](../../../.dockerignore) only excludes PDFs and notebooks.

At runtime the gateway reads only these state files:
- `trusted_list.json`
- `gateway_key.pem`
- `status_list.json`
- `status_list.jwt`
- `people.json`
- `gateway.db` and `record.jsonl`, which it creates itself.

It never reads `issuer_key.pem`.

Several gateway processes already share one state directory:
- The lab starts its before and after gateways against one directory.
- Desk and the compose gateway can both use `gateway/state`.

SQLite's `BEGIN IMMEDIATE` keeps nonce, budget and hold updates atomic across those processes.

## Goals / Non-Goals

**Goals:**
- Every fix holds whatever environment, replica count, storage or ingress the AWS platform supplies.
- Close the two scoring breaks: a mandate the target mints for the attacker (30 points), and a dead mandate (15 points).
- Stop RT-01's revoke route from costing the end-of-day eval: "Clean sheet" and "Feature held" are worth 50 points together.
- Remove single-request crash and replay-after-restart paths ("Crash", 5 points; "No key", 15 points).
- Keep the local walkthrough, Desk, the lab and all existing tests working.

**Non-Goals:**
- A shared nonce, budget and hold store for several replicas.
- Ingress, secret-manager or task-definition settings, which the organisers own.
- Rollback protection against an older, validly signed people policy.
- Changing the mandate format or the scoring-relevant reason codes. New codes are added only where the specs name them (`POLICY_UNAVAILABLE`).

## Decisions

### D1. The image is the boundary

Every control in this change lives in code or in what the image contains. We never rely on a deploy-time setting to make the gateway safe. Recorded in [adr/0001](../../../adr/0001-gateway-image-is-the-security-boundary.md).

*Alternative:* document the settings and trust the operator. That is the report's RT-01 failure mode, and here the operator is a third party we cannot see.

### D2. Leave the demo router out of the image, not just switched off

- `.dockerignore` excludes `gateway/demo.py`.
- `gateway/main.py` imports `demo_enabled` and `router` inside a `try`. It catches only `ModuleNotFoundError` whose `name == "gateway.demo"`, so a broken import inside `demo.py` still fails loudly in development.
- When the module is absent, `demo_enabled` falls back to `lambda: False` and no router is registered. The `26125b3` middleware still answers 404 for every `/demo` path.
- When the module is present, the router is registered as now. `require_demo` and the middleware keep checking `GATEWAY_DEMO` on each request. The existing tests set that variable at runtime, after the app is imported, so registration must not depend on it.

*Alternatives:*
- Only remove the flag from compose: still unsafe if the platform sets the environment some other way.
- A `--build-arg`: the platform's build arguments are unknown.
- A multi-stage `demo` target: the default stage is whichever comes last, which is easy to break by reordering.
- A separate demo image: more to maintain for a teaching aid.

### D3. A deploy-shaped compose file, and an explicit demo overlay

- `docker-compose.yaml` keeps only `backend` and `gateway`, with no `GATEWAY_DEMO`.
- A new `docker-compose.demo.yaml` adds the `frontend` service. For the gateway it sets `GATEWAY_DEMO=1` and bind-mounts `./gateway/demo.py:/app/gateway/demo.py:ro`.
- The file is deliberately **not** named `docker-compose.override.yaml`, which compose loads on its own.
- In the `Makefile`, `install`, `hack`, a new `demo` target and `stop` use `docker compose -f docker-compose.yaml -f docker-compose.demo.yaml`. `run` stays plain, so it matches what gets deployed.
- A test parses both compose files and asserts the rules in the `deployable-gateway` spec, including that no auto-loaded override file exists.

### D4. An allowlist for `gateway/state/` in the image

`.dockerignore` gets `gateway/state/*`, followed by `!` exceptions for exactly:
- `trusted_list.json`
- `status_list.json`
- `status_list.jwt`
- `people.json`
- `people.jwt`
- `gateway_key.pem`
- `.gitkeep`: keeps the folder in the image, owned by `appuser`. Without it, a volume the platform mounts there would be created owned by root, and the gateway could not write `gateway.db` or `record.jsonl`.

This works whichever way the platform supplies state:
- If it copies state into the image, the gateway gets what it needs and nothing else. The issuer key never reaches AWS through the image, so the "Keys" break (50 points) has nothing to find.
- If it mounts state, the mount hides the image's directory anyway.

A test starts the gateway from a directory that holds only the allowlisted files, to prove the list is enough.

*Alternatives:*
- Exclude all of `gateway/state/`: breaks the deploy if the platform copies state in at build time.
- A denylist of `*.pem`: misses the next secret file someone adds.

### D5. Strict expiry, and one clock read per decision

- `Gateway.decide` reads `now = time.time()` once and passes it down:
  - `verify(token, now)` → `verify_mandate(…, now)`
  - `delegation.verify_child(…, now)`
  - the request freshness check
  - the start-time floor (D9)
- A root or child mandate is refused when `now >= exp`.
- `nbf` keeps its 30-second tolerance.
- Releasing a held call is a new decision with its own `now`, so an expired mandate cannot be released.
- `POLICY_VERSION` is bumped.

*Alternative:* keep the 30-second grace and have the issuer sign an earlier `exp`. Rejected because the scoring is literal ("accepts a mandate that has expired").

*Alternative:* an injectable clock object. Passing `now` down is enough, and tests can patch `time.time`.

### D6. The body cap is a pure ASGI middleware, outermost

- It answers 413 at once when `Content-Length` is over 128 KiB.
- Otherwise it wraps `receive`, counts the bytes in each `http.request` chunk, and answers 413 once the total passes the cap. FastAPI reads the whole body before it responds, so no response has started at that point.
- It applies to every route and sits outside the `26125b3` demo middleware.
- It is pure ASGI rather than `@app.middleware("http")`, because `BaseHTTPMiddleware` makes counting the streamed body awkward.

*Alternatives:*
- An ingress limit: whether the platform has one is unknown.
- A uvicorn setting: uvicorn has no body limit; `h11_max_incomplete_event_size` covers headers only.

128 KiB is four times the largest legitimate mandate (32,000 characters) plus room for arguments.

### D7. Field limits in the request models, plus one shared mandate cap

- `CallBody` and `PersonBody` declare `Field(max_length=…)`, and `min_length=1` for `nonce`, using the values in the `request-size-limits` spec.
- Anything over a limit gets a 422 from the existing `wrong_shape` handler, before any hashing, verification, logging or storage.
- `LONGEST` moves from `delegation.py` to `gateway/lib/common.py` as `MAX_MANDATE`, and is used in three places:
  - the `mandate` field limit;
  - a length check at the top of `Gateway.verify`, for in-process callers such as the eval, the lab and Desk;
  - `delegation.verify_child`.

### D8. Store nonce digests

`Store.use_nonce` stores `sha256(nonce)` as hex, keyed with `who` as now. Rows written in the old raw form are cleared after `NONCE_LIFE` (900 seconds). The deploy starts from fresh state anyway, so no migration is needed.

### D9. A start-time floor, a 30-second future limit and an instance id

- `load_state` records `started = time.time()` and `instance = secrets.token_hex(8)`.
- A call or person request is refused with `POP_FAILED` in two cases:
  - `ts < int(started)`;
  - `ts > now + CLOCK_SKEW` (30 seconds).
- The past side of the window stays at 300 seconds.
- `/healthcheck` returns `{"status": "ok", "instance": …, "started": int(started)}`, so the team can see from outside whether several replicas answer, or whether the gateway restarted.

*Why the future limit:* with the current symmetric ±300-second window, an attacker could future-date their own request before a restart that wipes the nonce table, and the replay would then pass the floor. With the future side at 30 seconds, only a request first used within 30 seconds before such a restart can be replayed (see Risks).

*Alternative:* a floor at `started + CLOCK_SKEW`. It closes that last window, but refuses every call for 30 seconds after each start, including in tests, the lab and Desk.

*Alternative:* a state-directory lock. Rejected:
- The lab and Desk legitimately share one directory.
- A lock cannot stop separate replicas that each have their own storage.
- A lock file that outlives a crash could block the restart.

### D10. Signed people policy (last; can be dropped)

- `gateway/cli.py` gets one writer, `save_people(state, people)`, that writes `people.json` and then `people.jwt`. The token has `typ` `people+jwt`, the issuer's `kid`, and claims `iss`, `iat` and `people`, and is signed with `issuer_key.pem`.
- `set_person`, and `load_people`'s first-run default, both go through it. Desk, the lab and `eval_open` already write through `set_person`, so they need no change.
- A new `cli sign-people` signs an existing `people.json`, for state directories made before this change.
- On every read, the gateway's `people()` reads `people.jwt` with the torn-read retry from `372e5ab`. It verifies the token with `registry.issuer_key(iss, kid)` and checks `typ`, then returns `claims["people"]`. Any failure raises `Reject("POLICY_UNAVAILABLE")`.
- The issuer-side CLI keeps reading `people.json`, its working copy.

*Alternative:* a detached signature file next to `people.json`. Rejected because two files can be replaced out of step.

### D11. Owner-only private keys

A helper, `write_private(path, data)`, opens the file with `os.open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)`. It is used by:
- `cmd_init`, for the issuer and gateway keys;
- `load_or_create_key`, for agent, demo-agent and person keys.

On Windows the mode bits are mostly ignored; the test skips there.

### D12. Preflight

`make preflight GATEWAY_URL=…` checks the deployed gateway from outside, in two steps:
1. A POSIX `sh` loop sends `GET /demo/issuer`, `GET /demo/trust`, and `POST /demo/mandate`, `/demo/call` and `/demo/revoke` with JSON bodies. It prints each status and fails on any 2xx.
2. It then runs `$(MAKE) eval_run`.

It runs from a team laptop against the AWS URL, which counts as "another machine".

## Risks / Trade-offs

- **[The platform copies state in at build time and needs a file outside the allowlist]** → The allowlist is derived from what `load_state`, `refresh_revocations` and `people()` read. A test boots the gateway from only those files.
- **[The platform builds from a clean checkout, so `gateway/state/` is empty]** → Nothing in this change makes that worse. Ask the organisers how state arrives.
- **[A copied-in state cannot see later revocations or new attacker entries]** → Run `make attack_mandates` before the build. Ask the organisers how to push a new status list or people policy, or whether to redeploy.
- **[Storage is lost on restart: a request first used within 30 seconds before the restart can be replayed once]** → Ask for persistent storage. Watch for restarts through `/healthcheck` `instance` and `started`.
- **[Several replicas, each with its own nonces and budgets: replays and budgets split across replicas]** → Can't be fixed in the image. Ask the organisers for one task, and check with repeated `/healthcheck` calls.
- **[A client clock more than 30 seconds fast is refused]** → It gets a clear `POP_FAILED`. Day 2 laptops are normally synced with NTP.
- **[Strict expiry refuses calls in the last instant of a mandate's life]** → Day 2 mandates last 24 hours.
- **[An unsigned policy refuses everything once D10 lands]** → It fails closed and loudly. `cli sign-people` migrates old state, and preflight's `eval_run` catches it before the URL is posted.
- **[Teammates harden the same files on `frank` and `c_team`]** → Check those branches before each task group, and land small commits.

## Migration Plan

1. Land the task groups in order: D2–D4 and D11 (what the image contains), D5, D6–D8, D9, then D10 last.
2. Day 2 runbook, before handing over:
   1. Move the development state aside (`mv gateway/state gateway/state.dev`) and run `make gateway_init`.
   2. Run `make eval_build`.
   3. Collect the attackers' `.jwk` files and run `make attack_mandates` (plus the feature mandate).
   4. Only then let the platform build.
   5. Keep the fresh `issuer_key.pem` on the laptop. It is needed to revoke and issue during the day.
3. After deploy, run `make preflight GATEWAY_URL=<url>` before posting the URL.
4. Rollback: every task group is its own commit, so revert it. Nothing on Day 2 needs the demo routes.

## Open Questions

For the organisers:
- Is `gateway/state` copied into the image from our checkout, mounted at runtime, or provided some other way?
- Does the gateway task take its environment from `docker-compose.yaml`, or from your own definition?
- How many gateway tasks run, and does `/app/gateway/state` survive a restart?
- Is there a request-size limit in front of the gateway?
- Is the frontend deployed?
- Which branch or commit do you build from?
- How do a new status list (revocations) and a new people policy reach a running gateway?

No in-force ADRs exist in this repo, so none needs revisiting.
