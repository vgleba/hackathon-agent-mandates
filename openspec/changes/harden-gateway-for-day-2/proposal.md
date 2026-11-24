## Why

The Day 2 red-team report ([RED_TEAM_REPORT.md](../../../RED_TEAM_REPORT.md)) reproduced two scoring breaks on our gateway:
- **RT-01:** anonymous `/demo/*` routes are switched on by the committed `docker-compose.yaml`. Anyone can have the gateway mint a mandate, sign a call with it, and revoke other mandates.
- **RT-02:** the gateway accepts a mandate for 30 seconds after it expires.

The report also lists three hardening gaps (RT-03 to RT-05). The organisers deploy the gateway to AWS, and we cannot see that config. That means environment variables, replica count, storage, ingress and restarts are all outside our control. Every fix must therefore hold inside the image built from this repo.

## What Changes

- **The image cannot mint (RT-01).**
  - The production gateway image leaves out the demo router.
  - The committed compose file runs only the backend and the gateway.
  - The walkthrough UI, `GATEWAY_DEMO=1` and the demo router move to an opt-in `docker-compose.demo.yaml`, which `make hack` and a new `make demo` use. **BREAKING** for the local workflow: `make run` no longer starts the frontend or the demo routes.
- **The image carries only what the gateway reads (RT-05, first part).** From `gateway/state/`, the image gets only the gateway's runtime files: trusted list, status list, people policy and the gateway's own key. The issuer key, agent keys, demo files, person keys and mandates never enter it. Private key files are written owner-only.
- **Strict expiry (RT-02).** A root or child mandate is refused from its `exp` second onwards. Clock tolerance remains for `nbf` only. Each decision reads the clock once. **BREAKING:** the 30-second grace after `exp` is gone.
- **Size limits (RT-03).**
  - Request bodies over a fixed cap are refused with 413 before parsing. The cap counts streamed bytes rather than trusting `Content-Length`.
  - Call and person request fields get length limits.
  - Root mandates get the same length cap as child mandates.
  - Nonces are stored as fixed-size hashes.
- **Restarts and replicas: survivable and visible (RT-04).**
  - The gateway refuses calls signed before the process started, which closes replay after a restart that lost the nonce table.
  - It refuses requests dated more than 30 seconds ahead, down from 300, so a future-dated request cannot pass that floor. **BREAKING** for clients whose clock is more than 30 seconds fast.
  - It shows an instance id and start time on `/healthcheck`, so the team can spot several replicas or restarts from outside.
  - There is no state-directory lock. Several processes on one local SQLite file are already safe, and the lab relies on that. A lock would not stop separate replicas, each with its own state.
- **Signed people policy (RT-05, second part; last, and can be dropped).** The issuer signs the people policy. The gateway verifies that signature against its trusted list and refuses calls when the policy is missing or unsigned. **BREAKING:** an unsigned or hand-edited `people.json` no longer works on the gateway.
- **Preflight before posting the URL.** `make preflight GATEWAY_URL=…` checks that every `/demo/*` route returns 404 and that questions 0 to 5 pass. It is meant to run from a machine other than the deploy host.

## Capabilities

### New Capabilities
- `deployable-gateway`: what the production gateway image serves and carries (no demo routes, only runtime state files, owner-only keys), the split between deployable and demo compose files, and the preflight check.
- `mandate-expiry`: when a root or child mandate stops being accepted, and how clock tolerance applies.
- `request-size-limits`: the request body cap and the per-field limits on calls, person requests, mandates and stored nonces.
- `gateway-instance`: what one gateway process guarantees about itself. Calls signed before it started are refused, and it reports its identity and start time on `/healthcheck`.
- `signed-people-policy`: the people policy is signed by the issuer and verified by the gateway, which refuses calls when the policy is missing or unsigned.

### Modified Capabilities
None. `openspec/specs/` has no specs yet.

## Impact

- **Gateway code:**
  - `gateway/main.py`: demo router loading, body cap, field limits, `/healthcheck`, people policy reading.
  - `gateway/lib/gateway_verify.py`: expiry, one clock read per decision, start-time floor.
  - `gateway/lib/delegation.py`: child expiry; the shared length cap.
  - `gateway/lib/store.py`: nonce hashes.
  - `gateway/cli.py`: signed people policy, owner-only key files.
- **Deployment files:**
  - `docker-compose.yaml`; new `docker-compose.demo.yaml`.
  - `.dockerignore`: the allowlist for `gateway/state/`, and `gateway/demo.py` left out of the image.
  - `Makefile`: `hack`, new `demo` and `preflight` targets.
- **Docs and lab:** README (local demo and deploy notes), the RT-01 fix text in `lab/server.py`.
- **Tests:** new boundary and regression tests under `gateway/tests/`. The existing demo tests keep working in-process.
- **Day 2 runbook:**
  - Deploy from freshly initialised state, so anything minted through `/demo` during development dies with the old issuer key.
  - Build the eval pack and the attack mandates from that state before the image is built.
  - Ask the organisers how state reaches the container, whether compose environment variables are read, how many tasks run and whether storage survives a restart.
- **Builds on two recent commits:**
  - `26125b3` makes switched-off `/demo/*` routes look absent: a middleware answers 404 before routing, and the routes are left out of `/openapi.json`. It also caps refusal `detail`.
  - `372e5ab` re-reads a torn status list.
  - Neither touches the compose flag, expiry, size limits or what the image carries. Other teammates harden on their own branches (`frank`, `c_team`), so check those before starting a task, to avoid duplicate work.
- **Not in scope:**
  - A shared nonce and budget store for several replicas.
  - Ingress or secret-manager configuration, which the organisers own.
  - Rollback protection for an older signed people policy.
