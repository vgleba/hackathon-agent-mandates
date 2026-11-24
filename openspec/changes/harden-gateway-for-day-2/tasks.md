## 1. Before starting

- [ ] 1.1 Send the design's open questions to the organisers: how state arrives, whether compose environment is read, task count and storage, ingress limit, whether the frontend is deployed, which branch they build from, and how new revocations reach the gateway. Record the answers under Open Questions in design.md
- [ ] 1.2 Check `fork/frank`, `fork/c_team` and `frank-before-rebase` for changes to `gateway/main.py`, `gateway_verify.py`, `store.py`, `docker-compose.yaml` or `Makefile` that overlap a group below, and note what to reuse

## 2. What the image contains (RT-01, RT-05 key files; D2, D3, D4, D11)

- [x] 2.1 Add `gateway/tests/test_deployment.py` with failing tests:
  - `docker-compose.yaml` has no `GATEWAY_DEMO` and no frontend service;
  - no `docker-compose.override.*` or `compose.override.*` file exists;
  - `.dockerignore` ignores `gateway/demo.py`, and everything in `gateway/state/` except the six allowed files and `.gitkeep`
- [x] 2.2 In `.dockerignore`, exclude `gateway/demo.py`, then `gateway/state/*` with `!` exceptions for `.gitkeep`, `trusted_list.json`, `status_list.json`, `status_list.jwt`, `people.json`, `people.jwt` and `gateway_key.pem`
- [x] 2.3 In `gateway/main.py`, import `demo_enabled` and `router` from `gateway.demo` inside a `try`:
  - catch only `ModuleNotFoundError` whose `name` is `gateway.demo`;
  - when it is caught, fall back to `demo_enabled = lambda: False` and register no router;
  - keep the `26125b3` middleware
- [x] 2.4 Add a test that blocks `gateway.demo` from importing and starts the app in a fresh interpreter (`gateway/tests/image_probe.py`). With `GATEWAY_DEMO=1` the app starts, all five `/demo/*` routes answer 404, and a valid `/tools/call` is allowed
- [x] 2.5 Cut `docker-compose.yaml` down to `backend` and `gateway`, with no `GATEWAY_DEMO`. Add `docker-compose.demo.yaml` with the `frontend` service, `GATEWAY_DEMO=1` on the gateway, and `./gateway/demo.py:/app/gateway/demo.py:ro`
- [x] 2.6 In the `Makefile`, add a `COMPOSE_DEMO` variable for the two-file compose command and use it in `install`, `hack`, a new `demo` target and `stop`. Leave `run` on the plain compose file
- [x] 2.7 Add a test that boots the gateway from a state directory holding only the six allowed files, and gets `ALLOW` for an eval-valid call
- [x] 2.8 Add `write_private(path, data)` with mode `0o600`, and use it in `cmd_init` and `load_or_create_key`. Test the mode, skipping on Windows
- [x] 2.9 In the README, replace "Remove that line before you deploy" with the overlay (`make hack` / `make demo` for the walkthrough, `make run` matches the deploy). Update the RT-01 fix text in `lab/server.py` to say the routes are left out of the image
- [x] 2.10 Build the gateway image and list `gateway/` and `gateway/state/` inside it: there should be no `demo.py` and no `issuer_key.pem`. Run it with the state mounted and `GATEWAY_DEMO=1`, and confirm `POST /demo/mandate` answers 404
- [x] 2.11 Run `make hack` and confirm the walkthrough at `localhost:8081/demo` still issues, calls and revokes

## 3. Strict expiry (RT-02; D5)

- [ ] 3.1 Add failing tests with a frozen `time.time`:
  - root mandate at `exp - 1` (accepted), `exp` and `exp + 5` (both `EXPIRED`);
  - child mandate at its `exp`;
  - expired parent under a live child;
  - `nbf` at +20 seconds (accepted) and +40 seconds (`NOT_YET_VALID`);
  - the clock passing `exp` during a decision;
  - a held call approved after its mandate's `exp`
- [ ] 3.2 Read `now` once in `Gateway.decide`, and pass it through `verify`, `_verify_root`, `verify_mandate`, `delegation.verify_child` and the freshness check
- [ ] 3.3 Refuse when `now >= exp` for root and child mandates. Keep `CLOCK_SKEW` for `nbf` only, and bump `POLICY_VERSION`
- [ ] 3.4 Run `make test` and the in-process questions 0–5 eval, and confirm the red-team test "expired by five seconds returns 200" now gets `EXPIRED`

## 4. Size limits (RT-03; D6, D7, D8)

- [ ] 4.1 Add failing tests:
  - a body of exactly 128 KiB minus one byte (decided as usual) and one over 128 KiB (413);
  - a chunked body past the cap (413);
  - an oversized body on each person route (413);
  - a nonce of 129 characters (422) and an empty nonce (422);
  - all fields at their limits (decided as usual);
  - a root mandate of 32,001 characters (4xx, not decoded);
  - a 64-character stored nonce digest;
  - arguments nested 5,000 deep (4xx), with the next request still answered
- [ ] 4.2 Add a pure ASGI body-cap middleware, outermost: refuse at once when `Content-Length` is over the cap, and count streamed `http.request` bytes otherwise
- [ ] 4.3 Move `LONGEST` to `gateway/lib/common.py` as `MAX_MANDATE`. Use it for the `CallBody.mandate` limit, a length check at the top of `Gateway.verify`, and `delegation.verify_child`
- [ ] 4.4 Add `Field` length limits to `CallBody` and `PersonBody`, with the values from the `request-size-limits` spec
- [ ] 4.5 Store `sha256(nonce)` as hex in `Store.use_nonce`
- [ ] 4.6 Run `gateway/tests/test_fail_closed.py` and the full suite, and confirm no case answers 500

## 5. Restarts and replicas (RT-04; D9)

- [ ] 5.1 Add failing tests:
  - a request accepted before a restart and replayed after it, on the same state and with `gateway.db` deleted (`POP_FAILED`);
  - `ts` at +31 seconds (`POP_FAILED`) and +20 seconds (accepted);
  - `ts` 290 seconds old but after start (accepted);
  - a `/holds/answer` signed before start (refused, nothing approved);
  - `/healthcheck` returns the same instance within one process and a different one after a restart;
  - two app instances on one state directory refuse each other's nonces
- [ ] 5.2 Record `started` and `instance` in `load_state`
- [ ] 5.3 Apply the start-time floor (`ts < int(started)`) and the 30-second future limit in `Gateway.decide` and `verify_person`. The past side of the window stays at 300 seconds
- [ ] 5.4 Have `/healthcheck` return `instance` and `started`. Add a README line on spotting replicas and restarts, by calling it a few times from outside

## 6. Signed people policy (RT-05 policy; D10; last, can be dropped)

- [ ] 6.1 Add failing tests:
  - `cli person` writes a `people.jwt` that verifies against the trusted list;
  - a hand-edited `people.json` does not change what the gateway applies;
  - a policy signed by an untrusted key, a missing `people.jwt` and a truncated `people.jwt` each give `POLICY_UNAVAILABLE` with a 4xx status;
  - after the truncated case, the next request is still answered
- [ ] 6.2 Add `save_people(state, people)` in `gateway/cli.py`. It writes `people.json`, then a `people+jwt` token signed with the issuer key. Route `set_person` and `load_people`'s default creation through it, and add `cli sign-people`
- [ ] 6.3 Have `people()` in `gateway/main.py` read and verify `people.jwt` on every call, with the torn-read retry from `372e5ab`. Raise `Reject("POLICY_UNAVAILABLE")` on any failure, and make sure person routes answer it with a 4xx
- [ ] 6.4 Run the Desk, lab and `eval_open` tests. Migrate local state with `cli sign-people`. Add `people.jwt` to the README's key and state table
- [ ] 6.5 If this group is dropped for Day 2, note it in design.md and leave `people.json` in the image allowlist

## 7. Preflight and Day 2 runbook (D12, Migration Plan)

- [ ] 7.1 Add `make preflight GATEWAY_URL=…`. It requests the five `/demo/*` routes, prints each status and fails on any 2xx, then runs `$(MAKE) eval_run`
- [ ] 7.2 Check preflight locally: it passes against `make run`, and fails against `make demo` naming each open route
- [ ] 7.3 Add a Day 2 section to the README:
  1. Move the development state aside, then run `make gateway_init`.
  2. Run `make eval_build`.
  3. Run `make attack_mandates` before the image is built.
  4. Keep the issuer key on the laptop.
  5. Run preflight before posting the URL.
- [ ] 7.4 On the final commit, run `make test`, `make lint`, `make eval_run` and `make eval_open`
- [ ] 7.5 Add a status line per RT item at the end of `RED_TEAM_REPORT.md`, with the commit that addressed it
- [ ] 7.6 After the organisers deploy, run `make preflight GATEWAY_URL=<aws url>` from a laptop, and call `/healthcheck` several times to confirm one instance before posting the URL
