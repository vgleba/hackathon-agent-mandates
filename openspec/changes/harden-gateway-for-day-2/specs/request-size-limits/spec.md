## ADDED Requirements

### Requirement: Request bodies have a fixed cap
The gateway MUST refuse, with status 413, any request whose body is larger than 128 KiB. The body is not parsed.
The cap counts the bytes actually received, whether or not `Content-Length` is sent and whatever it says.

#### Scenario: Body just under the cap
- **WHEN** a `POST /tools/call` body is 128 KiB minus one byte
- **THEN** the gateway parses it and decides it as usual

#### Scenario: Body over the cap with honest length
- **WHEN** a `POST /tools/call` declares `Content-Length` of 128 KiB plus one byte
- **THEN** the gateway answers 413 without reading the body

#### Scenario: Chunked body over the cap
- **WHEN** a body with no `Content-Length` streams past 128 KiB
- **THEN** the gateway stops reading and answers 413

#### Scenario: Person routes are capped too
- **WHEN** a body over 128 KiB is sent to `/holds`, `/holds/answer`, `/log`, `/person/schools` or `/person/class`
- **THEN** the gateway answers 413

### Requirement: Request fields have length limits
The gateway MUST refuse, with status 422, a call or person request whose string fields exceed their limits.
This happens before any hashing, signature check, logging or database write.
The limits are:
- `server` and `tool`: 64 characters
- `nonce`: 1 to 128 characters
- `sig`: 128 characters
- `principal`: 128 characters
- `mandate`: 32,000 characters
- on person requests, `hold`: 128, `answer`: 16, `root`: 256 and `urn`: 16 characters

#### Scenario: Long nonce
- **WHEN** a call carries a 129-character nonce
- **THEN** the gateway answers 422 and stores nothing for that nonce

#### Scenario: Empty nonce
- **WHEN** a call carries an empty nonce
- **THEN** the gateway answers 422

#### Scenario: Fields at their limits
- **WHEN** a field is exactly at its limit
- **THEN** the gateway decides the call as usual, without a 422

#### Scenario: Person name one over its limit
- **WHEN** a person request carries a 129-character `principal`
- **THEN** the gateway answers 422

### Requirement: Root and child mandates share one length cap
The gateway SHALL refuse a root mandate longer than 32,000 characters without decoding it, as it already does for a child mandate.

#### Scenario: Oversized root mandate
- **WHEN** a call carries a 32,001-character root mandate
- **THEN** the gateway refuses it with a 4xx status and does not decode it

### Requirement: Stored nonces have a fixed size
The gateway MUST store a fixed-size digest of each nonce, never the nonce text itself.
A digest of the same nonce from the same caller is a replay.

#### Scenario: Replay of a long nonce
- **WHEN** a caller reuses a 128-character nonce inside the freshness window
- **THEN** the gateway answers `DENY` with reason code `POP_FAILED`
- **AND** the stored record for that nonce is 64 hex characters long

### Requirement: Malformed input never yields a server error
Any request the gateway cannot parse or decide MUST be answered with a 4xx status, never with 500.
Deeply nested JSON inside the size cap is included.

#### Scenario: Deeply nested arguments
- **WHEN** a call's `arguments` nest lists 5,000 levels deep inside the 128 KiB cap
- **THEN** the gateway answers with a 4xx status and keeps answering later requests
