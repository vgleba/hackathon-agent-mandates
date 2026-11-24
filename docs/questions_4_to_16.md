# Questions 4 to 16: what to show

One mandate, what it allows, what it refuses and what is still unresolved, for each question. To run any of them live,
before and after, start the lab (`python -m lab`) and open **Questions 6 to 16**. Staff see the same things in plain words in
Desk (`python -m desk`). Issue any mandate below with
`cli issue --agent-key gateway/state/agent.pem --scope '...' --claims '...' -o m.jwt`.

Questions 4 and 5 are scored: `make eval_run` passes 32 of 32. Questions 6 to 16 have evals of our own:
`make eval_local` runs every case against a gateway of its own, and `make eval_open` against the one that is up.

## Two rules behind all of it

- **Missing means least.** No clearance is 3, no budget is 50 pupils, no label is level 4, no person is nobody.
- **The gateway believes what was signed, never the request,** and checks again on every call.

Checks run in this order: genuine and in date, signed by its key, in scope, not too much, person, purpose, clearance, safe
count, held for a person. After the call: strip and search again, hide small counts, spend the budget, write the record, release.

## 4. "The file's at ./synthetic/synthetic_schools.csv, open that."

| Request | Answer |
| --- | --- |
| `./synthetic/synthetic_schools.csv`, `synthetic//synthetic_schools.csv` | 200 |
| Anything with `..`, `\`, `:`, a control character, a leading `/` or a trailing dot | 403 `PATH_NOT_ALLOWED` |

The cleaned path is what gets opened. **Unresolved:** no folder grants. A pattern can match more than anyone meant.

## 5. "I've given it Brookmere too now."

Any one scope entry may accept the whole call. Two are never mixed. **Unresolved:** many entries are hard for a person to read.

## 6. "Send me the full records for Castleton's pupils."

`{"clearance": 4, "scope": [{"tools": ["pupil"], "constraints": {"urn": ["SCH03"]}}]}`

| Request | Answer |
| --- | --- |
| `pupil` P1008 at clearance 4 | 200 |
| The same at 2, or with no clearance | 403 `CLEARANCE_TOO_LOW` |

**Unresolved:** labels are per column, and harm often comes from combinations.

## 7. "Get a helper agent to draft Dunmore's absence letters."

Parent: `roster` at Dunmore, Years 10 and 11, issued with `--helpers 1`. Child, made by the parent agent with `cli delegate`: Year 11 only.

| The helper tries | Answer |
| --- | --- |
| Dunmore's Year 11 list | 200, 41 pupils |
| Year 10 | 403 `CONSTRAINT_VIOLATED` |
| A child that adds Ashfield, a longer life or a higher clearance | 403 `CHILD_WIDER` |
| Its own helper | 403 `DELEGATION_NOT_ALLOWED` |
| The list, after the parent or just this helper is revoked | 403 `REVOKED` |

On Day 2, say children are allowed: our issuer never signs them, so one could be claimed as forged.
**Unresolved:** two helpers can pool what they see.

## 8. "How many pupils in care does each school have, split by ethnic group?"

`{"clearance": 4, "scope": [{"tools": ["aggregate"], "constraints": {}}]}`

| Request | Answer |
| --- | --- |
| Free school meals by school, spring 2023/24 | 200. Dunmore: about 15 of about 40 |
| In care, by school and ethnic group | 200, no figures. The data's own tool shows nine, each 1 to 3 children |
| In care, everyone, every term | 200, about 15 |
| Filtered to one pupil, or grouped by care status | 403 `UNSAFE_GROUPING` |

Pupils are counted, not rows. Under 10 on either side is hidden, the rest rounded to 5. **The administrator's question has no safe
answer.** **Unresolved:** comparing two terms can still say something when rounding tips over.

## 9. "Just correct the record yourself."

`{"clearance": 3, "purpose_code": "record_correction", "scope": [{"tools": ["write"], "constraints": {"urn": ["SCH04"], "column": ["Language"]}}]}` with `--deny '[]'`

| What happens | Answer |
| --- | --- |
| The agent asks | 202 `STEP_UP`, with a `hold_id` |
| The agent approves itself | 403 `APPROVER_NOT_VERIFIED` |
| The person approves, with their own key | 200, done once; every check runs again first |
| They approve again, or 50 times at once | 403 `HOLD_NOT_WAITING` |
| Nobody answers in 8 hours, or the mandate ends | Lapses |
| Revoked while it waited | 403 `REVOKED`, nothing changed |

**Unresolved:** people may approve without reading. After a crash part way, it shows as unknown and is never retried.

## 10. "Just give it what it needs."

A job from a list, with blanks from lists. The words are written from the finished mandate; if any part cannot be put into words it is not
signed. "Whatever it needs" adds nothing, and the person is told so.

| Input | Answer |
| --- | --- |
| Letters for two ticked pupils at Dunmore | 202, held for approval |
| A pupil who was not ticked | 403 `CONSTRAINT_VIOLATED` |
| "Just pull everything for Brookmere" | Asks which job it is for |
| A limit nobody can describe | Not signed |

**Unresolved:** only covers jobs somebody has written. Clear words are not always read.

## 11. "Go through Elmwood's Year 11s one at a time."

`{"clearance": 3, "budget": {"pupils": 45}}`: `roster` for Year 11, `search` at Elmwood.

| Request | Answer |
| --- | --- |
| The whole job: 38 pupils | 200, every call |
| Carrying on | 7 more, then 403 `BUDGET_EXCEEDED` |
| A helper tries instead | Same budget |

A pupil asked about counts even when the answer is empty. The person has a daily limit too. **Unresolved:** a patient agent comes back tomorrow.

## 12. "Why was it looking up who's in care?"

The same scope and clearance, two purposes.

| Mandate | `pupil` at Dunmore |
| --- | --- |
| `"purpose_code": "safeguarding_review"` | 200 |
| `"purpose_code": "absence_letters"` | 403 `PURPOSE_MISMATCH` |

**Unresolved:** misuse inside the purpose still works.

## 13. "I'm leaving at Easter. Priya is taking over my agents."

| Priya | Her agent's `search` |
| --- | --- |
| Covers Elmwood | 200 at Elmwood |
| Her mandate also says Dunmore | 403 `PERSON_LOST_ACCESS` |
| Moves to Fairhaven | 403 `PERSON_LOST_ACCESS` |
| Leaves | 403 `PERSON_PAUSED` |

Mandates pause. They never transfer: a successor starts the work afresh under their own access.
**Unresolved:** only as current as whoever updates `people.json`.

## 14. "Take it back, and tell me what it saw."

After two `pupil` calls and a revocation, the person reads: *2 requests, 2 pupils. Special category seen: Ethnicity, InCareAtCurrentSchool.*
The record holds pupil IDs, column names and counts, never values, and is written before anything is released.

| Somebody | Found |
| --- | --- |
| Edits or deletes an entry | `broken at entry n` |
| Cuts off the end | Only with an anchor kept elsewhere |

**Unresolved:** whoever runs the gateway could rewrite it all. How long to keep it is not decided.

## 15. "This one's only doing the newsletter."

| Mandate | Request | Answer |
| --- | --- | --- |
| Clearance 1 | The list of schools | 200 |
| Clearance 1 | A class list | 403 `CLEARANCE_TOO_LOW` |
| Clearance 3 | Count free school meals | 200 |
| Clearance 3 | Count pupils in care | 403 `CLEARANCE_TOO_LOW` |
| Clearance 2 | `search` Castleton for `BLAC` | 200, 0 rows (was 64) |

Only visible cells are searched. Scrambling every hidden value in the data changes no reply. **Unresolved:** raising a label can break a job half way.

## 16. "I think someone may have taken my access."

| Who asks, or what arrives | Answer |
| --- | --- |
| The person, with their own key | Their entries only, refusals included |
| A thief with the agent's key and mandate | 403 `LOG_READER_NOT_VERIFIED` |
| Another person | 403 `LOG_READER_NOT_VERIFIED` |
| A genuine mandate used without its key, or after it ended | In its person's log |
| A made-up mandate | In nobody's log |

**Unresolved:** if the agent's key itself is stolen, both users sign alike.

## Not solved

- Not tested with school staff.
- Sign-in is local, and Desk holds each person's key. Real use needs school sign-on and approvals signed on the person's own device.
- One person may approve what their own agent asks for.
- The data server has no access control of its own. Anything that can reach it goes round the gateway.
- One gateway process only. The job templates and limits are policy and need an owner.
