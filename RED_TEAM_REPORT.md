# Day 2 red-team report

Target: `fork/questions-1-to-16` at `c1572f9`  
Reviewed: 2026-11-23  
Scope: the public gateway and its documented Docker deployment, using only synthetic data

## Executive summary

The core `/tools/call` verifier is considerably stronger than the starter. Scope entries are kept separate, paths are
canonicalised before forwarding, returned columns are filtered by clearance, search cannot infer hidden columns,
nonces and pupil budgets persist in SQLite, aggregate answers are suppressed, and child mandates are checked against
their parent on every call.

Two scoring attacks were reproduced:

1. **Critical deployment backdoor:** the committed Docker deployment enables anonymous demo routes that mint mandates
   and sign calls. An attacker can retrieve sensitive data outside both mandates supplied for Day 2 and can revoke
   other mandates.
2. **Expired mandate accepted:** the gateway accepts a mandate for 30 seconds after its signed expiry. This is a
   reproducible “Dead mandate” break under the scoring language.

The first issue should be fixed before deployment. With it enabled, most of the otherwise strong controls can be
bypassed through an intentionally trusted server-side agent.

## Confirmed findings

### RT-01 — Anonymous demo routes are enabled in the deployment

Severity: **Critical**  
Confidence: **Confirmed with an end-to-end test**  
Likely score: level 3 data (20) plus forged mandate (30); arbitrary revocation also enables denial of service

`docker-compose.yaml` publishes port 8082 and sets `GATEWAY_DEMO=1`. The `/demo/mandate` route uses the issuer private
key to mint a mandate for a server-held agent key. `/demo/call` then signs and submits a call using that same key.
Neither endpoint authenticates the caller when demo mode is enabled.

Reproduction against a deployment made from the committed compose file:

```bash
curl -sS -X POST http://TARGET:8082/demo/mandate \
  -H 'content-type: application/json' \
  -d '{"urn":"SCH04","tools":["search"],"deny":[],"ttl":3600}'

curl -sS -X POST http://TARGET:8082/demo/call \
  -H 'content-type: application/json' \
  -d '{"tool":"search","arguments":{"query":"P0011","urn":"SCH04"}}'
```

The reproduced second response had outer HTTP status 200 and contained a nested gateway response with
`decision.decision = "ALLOW"`, `Psuedo ID = "P0011"`, `URN = "SCH04"`, and `FSMeligible`. Level-4 columns were
correctly stripped because the demo mandate has legacy clearance 3, but the level-3 flag is already outside the Day 2
default mandate.

The route also exposes unauthenticated revocation:

```bash
curl -sS -X POST http://TARGET:8082/demo/revoke \
  -H 'content-type: application/json' \
  -d '{"idx":0}'
```

An attacker can enumerate issuance/revocation state through `/demo/trust`, then revoke default, feature, or other
teams' mandates by index.

Why the existing safeguard is insufficient: the application defaults demo mode off, and tests verify that default,
but the actual committed Docker deployment explicitly turns it on. The README warning relies on a manual step at the
most failure-prone point: deployment.

Fix options:

- **Best:** do not register the demo router in the production image at all. Build a separate demo application/image.
- Remove `GATEWAY_DEMO=1` from `docker-compose.yaml`; use a local-only compose override for the walkthrough.
- Add a production startup guard that exits if demo mode is enabled while binding to a non-loopback address or when
  `ENVIRONMENT` is not `local`.
- If the demo must be remotely accessible, put it behind real staff authentication and a separate demo-only issuer,
  state directory, gateway, and synthetic environment. Do not let it share production issuer keys or status lists.
- Add a deployment regression test that starts the shipped container configuration and asserts every `/demo/*` route
  returns 404.
- Rotate the issuer key and recreate mandates if a gateway was ever exposed with demo mode enabled; merely disabling
  the routes does not undo mandates already minted.

### RT-02 — Thirty-second post-expiry acceptance window

Severity: **Medium**  
Confidence: **Confirmed with an end-to-end test**  
Likely score: Dead mandate bonus (15)

`verify_mandate` rejects only when `exp < now - CLOCK_SKEW`, where `CLOCK_SKEW` is 30 seconds. A correctly signed
mandate issued with an expiry five seconds in the past successfully performed a search and returned HTTP 200 with
`decision = "ALLOW"`.

Clock tolerance is normal in distributed token systems, but the Day 2 definition is literal: a gateway break occurs
when it accepts a mandate that has expired. Attackers know the expiry from the readable JWT and can prepare a signed
request for the boundary.

Fix options:

- For the hackathon, enforce expiry strictly: reject when `now >= exp`.
- Keep leeway only for `nbf` if operational clock skew must be tolerated; do not extend the authority past `exp`.
- Use one captured `now` value per decision and add tests for `exp == now`, `exp == now - 1`, and `exp == now + 1`.
- Synchronise deployment clocks with NTP. If business requirements demand expiry leeway, encode the intended grace
  period into the signed expiry at issuance instead of silently extending it at verification.

## Additional hardening opportunities

These were identified from code/configuration review but were not demonstrated as scoring data exfiltration.

### RT-03 — No explicit HTTP or field-size limits

Severity: **Medium (availability)**  
Confidence: **Design gap; crash not reproduced**

Root mandates, nonces, signatures, server/tool names, and the JSON request body have no application-level maximum.
A valid caller can make the gateway parse a very large body; a large unique nonce is also persisted in SQLite.
Child mandates have a 32 KB limit, but root mandates do not. This creates a plausible single-request memory/disk
exhaustion path and increases the impact of malformed inputs.

Fix options:

- Enforce a request-body limit at the ingress proxy and ASGI layer (for example 64–128 KB for `/tools/call`).
- Add strict Pydantic length limits: nonce, server, tool, signature, mandate, string argument values, list sizes, and
  nesting depth. Reject before hashing, logging, or database writes.
- Give root and child mandates the same defensible compact-token limit.
- Store a fixed-size hash of the nonce rather than attacker-controlled nonce text.
- Add one-request boundary tests just below and above every limit.

### RT-04 — Persistent security state assumes one gateway process and one local filesystem

Severity: **Medium when deployment topology changes**  
Confidence: **Architectural limitation**

SQLite transactions correctly protect nonces, budgets, and approvals inside the current single-process deployment.
The source itself states that one gateway process owns the file. Running multiple replicas with separate state
volumes would let a replay hit another replica and would split pupil budgets and approval state. Sharing the SQLite
file over an unsuitable network filesystem is also unsafe.

Fix options:

- For Day 2, deploy exactly one gateway process/replica and persist its state directory.
- Add a startup/deployment assertion documenting and enforcing one worker.
- For scaling, move nonce, budget, and hold state to one transactional shared store; use uniqueness constraints and
  atomic compare-and-set operations. Test replay and budget races across two live gateway instances.

### RT-05 — Status and people files are trusted mutable control-plane files

Severity: **Operational**  
Confidence: **Architectural limitation**

Revocation refresh fails closed, which is good. However, `people.json` is unsigned local policy, and issuer,
gateway, demo-agent, and person private keys all live in the mounted state directory. Compromise or accidental
publication of that volume defeats mandate controls. The hackathon rules already warn against publishing PEM files,
but the deployment should make this harder to do accidentally.

Fix options:

- Mount private keys read-only from a secret manager; separate issuer operation from the public gateway.
- Do not copy or expose the entire state directory as a deployment artifact.
- Use restrictive filesystem permissions and run the gateway as a non-root user.
- Sign/version the people policy or place it in an authenticated control-plane store with an audit trail.
- Add secret scanning for `gateway/state/*.pem`, `demo_agent.pem`, person keys, database files, and records.

## What resisted the attempted attacks

- Edited claims and untrusted issuers are rejected by Ed25519 verification and the trusted issuer list.
- Calls signed by the wrong key, stale requests, and nonce replays are rejected; nonce state persists across restart.
- Scope entries cannot be combined to borrow constraints from each other.
- Path aliases are cleaned before both comparison and forwarding; traversal spellings are rejected.
- Search is performed only over columns visible at the effective clearance, preventing hidden-column search oracles.
- Result volume is capped, cumulative pupil budgets are transactional, and empty per-pupil lookups still spend budget.
- Aggregates restrict dimensions/filters and apply small-cell suppression plus rounding.
- Delegated mandates are signed by the parent key, remain within both parent and child scopes, share the parent budget,
  and stop when the parent or helper slot is revoked.
- Approval requests are rechecked at release time and collected only by the same agent and root mandate.
- The unauthenticated MCP backend is not published by the committed Docker Compose network.

## Verification performed

- Audited commit `c1572f9` in an isolated worktree; the existing dirty `vlod` checkout was not altered.
- Ran all gateway tests: **666 passed**.
- Strengthened the in-process official-eval assertion temporarily: **questions 0–5 all passed**.
- Added temporary red-team regression tests in the isolated worktree only:
  - anonymous demo mint + signed call returns the SCH04/P0011 level-3 flag;
  - a mandate expired by five seconds returns 200/ALLOW.
- Ran Bandit over `gateway/`: no high-severity findings. Its URL-opening findings are CLI/eval client behaviour, not a
  remotely reachable gateway SSRF.

## Recommended pre-deployment order

1. Remove or physically separate the demo routes and rotate keys if they were exposed.
2. Make `exp` strict and add expiry-boundary regression tests.
3. Confirm only port 8082 is public; keep backend port 8080 private.
4. Deploy one gateway worker/replica with persistent state.
5. Add body/field limits at ingress and application layers.
6. Run `make eval_run`, `make test`, and `make lint` against the exact deployable commit and container configuration.
7. From another machine, verify `/demo/issuer`, `/demo/mandate`, `/demo/call`, `/demo/revoke`, and `/demo/trust` all
   return 404 before posting the gateway URL.
