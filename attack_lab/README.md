# Mandate Attack Lab

This is a commit-ready Day 2 attack runner and local evidence dashboard. It uses the same request signing contract as
`gateway.cli`, runs a bounded catalogue of read-only probes against each team's **posted gateway URL**, scores exact
flags from `day_2_attack/ATTACK_SCORING.md`, and keeps the signed request plus HTTP response needed to claim points.

It deliberately does not call the MCP server directly, invoke the mutating `write` tool, follow redirects, run probes
concurrently, or flood a target. The full profile's bulk checks are single requests. Each target must explicitly set
`"authorized": true`; use that only for a gateway posted for this hackathon exercise.

## Quick start

1. Generate the attack key once and publish only the JWK printed on stdout:

   ```bash
   uv run python -m gateway.cli keygen -o attack_lab/inputs/attack.pem > our-team.jwk
   ```

2. Copy the received mandates into `attack_lab/inputs/`, then make a local config:

   ```bash
   cp attack_lab/config.example.json attack_lab/targets.local.json
   ```

   Edit the team name, posted gateway URL, and mandate filenames. Runtime inputs, local config, private PEMs, and
   generated reports are written under the repository's Git-ignored `local/` directory.

3. Review the plan without sending anything:

   ```bash
   uv run python -m attack_lab run --dry-run --profile quick
   ```

4. Run the bounded quick profile, then open the report UI:

   ```bash
   uv run python -m attack_lab run --profile quick
   uv run python -m attack_lab serve --open
   ```

   The dashboard is served locally at `http://127.0.0.1:8185`. Stop it with `Ctrl-C`.

## Feature-mandate expectations

The runner decodes JWT claims **without trusting them** so it can infer whether each request is inside the visible
scope. The remote gateway still performs all real verification. A feature may also be narrowed by a custom claim or
the defender's prose note, which generic code cannot always infer.

Put the defender's note in `mandates.feature.note` and use probe IDs to correct the inferred expectation:

```json
"expect": {
  "allow": ["roster_named_in_care"],
  "deny": ["aggregate_named_in_care", "pupil_named_in_care"]
}
```

An `ALLOW` only contributes a data score when its expectation is `deny`. This prevents the report from claiming a
flag that the feature mandate was meant to grant. `list-probes` prints every stable probe ID:

```bash
uv run python -m attack_lab list-probes
uv run python -m attack_lab list-probes --profile full --json
```

## Running and automation

```bash
# All targets and both posted mandates; roughly 15 exchanges per target in quick mode
uv run python -m attack_lab run --profile quick

# Wider read-only catalogue, including one-shot bulk and key-path probes
uv run python -m attack_lab run --profile full

# One target or selected probes
uv run python -m attack_lab run --target team-a --probe pupil_flag_pupil_other_school

# Choose an evidence path and return exit 1 if a non-zero score is detected
uv run python -m attack_lab run --output /tmp/team-a-report.json --fail-on-findings

# Tune sequential pacing without adding concurrency (allowed ranges: timeout 1-60, delay 0-10)
uv run python -m attack_lab run --timeout 15 --delay 0.5
```

Reports are written to `local/attack-lab-report-<timestamp>.json`; `local/attack-lab-latest.json` is refreshed
atomically for the UI. The JSON is suitable for further automation. The CLI exits non-zero for invalid configuration
and optionally for findings with `--fail-on-findings`.

## What is tested

- Cross-school `search`, direct `pupil`, `roster`, `draft`, and per-pupil `aggregate` calls.
- Exact, dot-dot, and doubled-slash paths to the names, deprivation, and census files.
- The P0011 level 2/3/4 flags and the P0586 + Mason Owusu named level 4 correlation.
- Edited and unsigned mandates; bad, missing, stale, future, and replayed request signatures.
- Single-request bulk extraction, a likely issuer-key path, malformed argument handling, and HTTP 500 responses.
- Default and feature mandates independently, with gateway-break bonuses deduplicated per target.

The runner cannot automatically settle the **Unseen** bonus, prove that a mandate was revoked unless
`"known_revoked": true` is set for it, or interpret every custom feature claim. The report calls out the five-minute
record check as manual. Organisers remain the final arbiters of points.

## Evidence handling

The report contains full mandate JWTs, short-lived signed requests, and synthetic pupil responses. Mandates are meant
to be shared and replayed nonces should be dead, but treat the report as sensitive anyway: `local/` is ignored by Git,
the UI binds to localhost by default, redirects are not followed, and the private key is never copied into a report.

For an official claim, open a finding, jump to its evidence, and copy the exact request and response. Confirm the
feature note says the returned data is outside the mandate before posting it.

## Tests

```bash
uv run python -m pytest attack_lab/tests
uv run ruff check attack_lab
uv run ruff format attack_lab --check
```
