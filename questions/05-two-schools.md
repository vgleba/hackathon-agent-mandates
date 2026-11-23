# Question 5: "I've given it Brookmere too now. Look up their spring census."

This time the issuer really did grant a second school, as a second `search` entry in the scope rather than a wider
first one. The gateway uses the first scope entry that lists the tool and never tries the next one, so `SCH02` is
refused.

**Cases** (`BUILD` in `gateway/eval.py`, mandate `eval_pack/two_schools.jwt`): searches in `SCH01` and `SCH02` must be
allowed, and a search in `SCH03` must still be denied.

**One way:** in `check_request` (`gateway/lib/gateway_verify.py`), allow the call if *any* entry that lists the tool
accepts every constrained argument. Deny with the most useful reason when none does.

**Think about:** two entries that each constrain a different argument. Can a request mix and match, taking `urn`
from one and `path` from the other?

## What we did

`check_request` (`gateway/lib/gateway_verify.py`) now tries every scope entry that lists the tool, and allows the
call if any one entry accepts every argument it constrains. Each entry is judged whole, so a request cannot take
`urn` from one entry and `path` from another. When no entry accepts the call, the reason reported is the first
matching entry's, which keeps the question 2 reason codes as they were. The question 3 limits and the step-up check
run only once an entry has accepted the call.

`make eval_run` passes all of questions 0 to 5. The test is `test_any_scope_entry_may_allow_but_entries_do_not_mix`
in `gateway/tests/test_gateway.py`.

## The mandate

The eval's two-school mandate, `eval_pack/two_schools.jwt`, used with the eval's agent key. Decode it with
`uv run python -m gateway.cli decode eval_pack/two_schools.jwt`. Its scope is two `search` entries, one per school:

```json
{
  "scope": [
    {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH01"]}},
    {"server": "pupil-data", "tools": ["search"], "constraints": {"urn": ["SCH02"]}}
  ],
  "deny": ["*.write", "pii.*"]
}
```

## A request it allows

"Look up their spring census." Brookmere (`SCH02`), which only the second entry grants:

```bash
uv run python -m gateway.cli call --mandate eval_pack/two_schools.jwt --agent-key eval_pack/agent.pem \
  --tool search --args '{"query": "SPR", "urn": "SCH02", "limit": 1}'
```

```text
200
{"decision": {"decision": "ALLOW", "reason_code": "IN_SCOPE", "detail": "", ...}, "result": [...]}
```

## A request it denies

A third school, which neither entry grants:

```bash
uv run python -m gateway.cli call --mandate eval_pack/two_schools.jwt --agent-key eval_pack/agent.pem \
  --tool search --args '{"query": "SPR", "urn": "SCH03"}'
```

```text
403
{"decision": {"decision": "DENY", "reason_code": "CONSTRAINT_VIOLATED", "detail": "urn='SCH03'", ...}}
```

## Still unresolved

Entries now add up, so the widest entry for a tool decides what that tool may do: one entry with no constraints
allows every school, whatever the entries beside it say. The gateway cannot tell an issuer who meant that from one
who added a loose entry by mistake. The denial reason is also only the first entry's, so it may not name the entry
the caller was aiming at.
