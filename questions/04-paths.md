# Question 4: "The file's at ./synthetic/synthetic_schools.csv, open that."

Constraints compare strings exactly. `./synthetic/synthetic_schools.csv` and `synthetic//synthetic_schools.csv` are
the allowed file, and the gateway refuses both. That is safe, but it blocks a legitimate request.

**Cases** (`BUILD` in `gateway/eval.py`): both spellings must be allowed, and
`synthetic/../synthetic/synthetic_display_names.csv` (every pupil's name) must still be denied.

**One way:** normalise `path` before comparing it (`posixpath.normpath`), and refuse anything that still starts with
`..` or `/`. The MCP server resolves paths itself (`get` in `mcp_server/api/routes_mcp.py`), so whatever the gateway
compares has to name the same file the server will open.

**Think about:** an allowed folder rather than an allowed file (`synthetic/*.json`). What can a glob match that you
did not mean?

## What we did

In `check_request` (`gateway/lib/gateway_verify.py`), a `path` argument goes through `posixpath.normpath` before it
is compared with the mandate's allowed list. The allowed list is still matched exactly and the reason codes are
unchanged. There is no separate rule for `..` or `/`: a path that still starts with either after normalising
cannot equal an allowed relative path, so it is refused by the same comparison.

`make eval_run` passes question 4 with questions 0 to 3 still passing. The test is `test_path_spellings` in
`gateway/tests/test_gateway.py`.

## The mandate

The default mandate from `make gateway_issue`, unchanged: `get` on `synthetic/synthetic_schools.csv` and
`synthetic/synthetic_manifest.json` only. Its claims are in the [worked example](02-worked-example.md#the-mandate).

## Requests it allows

The allowed file, written with a `./` prefix:

```bash
uv run python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \
  --tool get --args '{"path": "./synthetic/synthetic_schools.csv", "limit": 2}'
```

```text
200
{
  "decision": {"decision": "ALLOW", "reason_code": "IN_SCOPE", "detail": "", ...},
  "result": [{"URN": "SCH01", "SchoolName": "Ashfield Academy", "SchoolLA": "SYN"},
             {"URN": "SCH02", "SchoolName": "Brookmere High School", "SchoolLA": "SYN"}]
}
```

`synthetic//synthetic_schools.csv` is allowed the same way.

## Requests it denies

Every pupil's name, reached through `..`:

```bash
uv run python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \
  --tool get --args '{"path": "synthetic/../synthetic/synthetic_display_names.csv"}'
```

```text
403
{"decision": {"decision": "DENY", "reason_code": "CONSTRAINT_VIOLATED",
              "detail": "path='synthetic/../synthetic/synthetic_display_names.csv'", ...}}
```

The allowed file as an absolute path. It names the right file, and is refused anyway:

```bash
uv run python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \
  --tool get --args '{"path": "/synthetic/synthetic_schools.csv"}'
```

```text
403
{"decision": {"decision": "DENY", "reason_code": "CONSTRAINT_VIOLATED",
              "detail": "path='/synthetic/synthetic_schools.csv'", ...}}
```

## Still unresolved

The gateway checks the normalised path but forwards the agent's own spelling, so the check is only as good as the
gateway and the MCP server agreeing on what a path means. They agree while the data directory has no symlinks.
Forwarding the normalised path would remove the dependence. Only the argument named `path` is normalised, and globs
(`synthetic/*.json`) are not handled at all.
