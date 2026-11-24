## ADDED Requirements

### Requirement: A root mandate is refused from its expiry second
The gateway MUST refuse a root mandate with reason code `EXPIRED` when the decision time is at or after the mandate's `exp`, with no grace period.

#### Scenario: One second before expiry
- **WHEN** a correctly signed call arrives and the decision time is `exp - 1`
- **THEN** the mandate passes the expiry check

#### Scenario: At expiry
- **WHEN** a correctly signed call arrives and the decision time equals `exp`
- **THEN** the gateway answers `DENY` with reason code `EXPIRED`

#### Scenario: Five seconds after expiry
- **WHEN** a correctly signed call arrives and the decision time is `exp + 5`
- **THEN** the gateway answers `DENY` with reason code `EXPIRED`

### Requirement: A child mandate is refused from its expiry second
The gateway MUST refuse a helper's child mandate with reason code `EXPIRED` when the decision time is at or after the child's `exp`.
The parent's expiry is still checked as for any root mandate.

#### Scenario: Child at expiry
- **WHEN** a helper calls with a child mandate and the decision time equals the child's `exp`
- **THEN** the gateway answers `DENY` with reason code `EXPIRED`

#### Scenario: Child that ends with its parent
- **WHEN** a helper calls with a child mandate whose `exp` equals its parent's (a child can never outlive its parent), and the decision time is that `exp`
- **THEN** the gateway answers `DENY` with reason code `EXPIRED`, from the check on the parent

### Requirement: Clock tolerance applies only to the start of validity
The gateway SHALL accept a mandate whose `nbf` is up to 30 seconds after the decision time, and SHALL NOT extend any mandate past its `exp`.
The gateway's own checks are the only time checks on a mandate. The JWT library does not judge `iat`, `nbf` or `exp` with its own clock.

#### Scenario: Issuer clock slightly ahead
- **WHEN** a mandate's `iat` and `nbf` are 20 seconds after the decision time
- **THEN** the mandate passes the validity checks

#### Scenario: Not yet valid
- **WHEN** a mandate's `nbf` is 40 seconds after the decision time
- **THEN** the gateway answers `DENY` with reason code `NOT_YET_VALID`

### Requirement: One decision reads the clock once
Every time check within one decision MUST use the same instant, read once when the decision starts.
This covers mandate `nbf` and `exp`, child `exp`, request freshness and the start-time floor.

#### Scenario: Clock passes expiry during a decision
- **WHEN** a decision starts at `exp - 1` and the clock reaches `exp` before the decision finishes
- **THEN** every check in that decision uses `exp - 1`, and the mandate passes the expiry check

### Requirement: Held calls are released only while the mandate is valid
A call waiting for a person's approval MUST NOT run once its mandate's `exp` has passed.
The hold lapses at the mandate's `exp`, and release checks the mandate's expiry again.

#### Scenario: Approved after the mandate expired
- **WHEN** a person approves a held call at or after the mandate's `exp`
- **THEN** the approval is refused with reason code `HOLD_NOT_WAITING`, because the hold has lapsed, and the call is not run
- **AND** the agent collecting it with that mandate gets `DENY` with reason code `EXPIRED`

### Requirement: A status list is judged at the decision's time
The gateway MUST judge a status list's freshness against the decision's one reading of the clock.
It allows a publisher clock up to 30 seconds fast, treats the list as stale from `iat + ttl`, and refuses an index that is negative or out of range.

#### Scenario: Publisher clock thirty seconds fast
- **WHEN** a status list's `iat` is 30 seconds after the decision time
- **THEN** the list is accepted

#### Scenario: Publisher clock more than thirty seconds fast
- **WHEN** a status list's `iat` is 31 seconds after the decision time
- **THEN** the list is refused as unreadable, and calls that need it get `STATUS_UNAVAILABLE`

#### Scenario: Stale at its time-to-live
- **WHEN** the decision time reaches the list's `iat + ttl`
- **THEN** the list is refused as stale

### Requirement: A torn status-list read never replaces a good one
The gateway MUST verify a newly read status list's signature before it replaces the list in use.
It reads the file again when the signature fails.

#### Scenario: Complete-looking read with a torn signature
- **WHEN** a read of `status_list.jwt` still decodes and decompresses but its signature does not verify, and a mandate in it is revoked
- **THEN** the gateway reads the file again and answers `REVOKED`, not `STATUS_UNAVAILABLE`
