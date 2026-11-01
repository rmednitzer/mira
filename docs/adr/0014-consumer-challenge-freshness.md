# ADR 0014: consumer-challenge freshness for signed captures

Status: **Accepted**, 2026-11-01 (proposed and reviewed the same day). **Stage 1 (Rust CLI) is implemented**; guide: [signatures](../signatures.md#freshness-answer-a-challenge). Stage 2 (comparator, schemas and validators) is outstanding.

## Context

[ADR 0010](0010-capture-timeline-and-freshness.md) split freshness into three questions and answered two of them: intra-capture skew (Q1) and same-boot order (Q2). It left Q3, **age at consumption** ("is this evidence from today?"), explicitly unanswered "until a separate trusted-time decision". [ADR 0011](0011-host-identity-and-capture-integrity.md) added signatures and states their limit: "A valid old document stays valid. Signatures add no freshness."

So today a consumer holding a verified capture knows who signed it, but not when it was taken. The only times in it are the host's wall-clock readings, which a misconfigured, restored or compromised host reports however it likes. Every record says `freshness: "unknown"` and `clock_trust: "unverified"`.

The phrase "trusted time" suggests that the host must obtain a trusted clock. But Q3 is asked by the **consumer**, and the consumer already has a clock it trusts: its own. What the consumer lacks is a way to tie the capture to a moment on that clock. Two bounds are needed:

| Bound | Meaning | What establishes it |
|---|---|---|
| Upper bound on creation | "taken no later than T" | Possession: the consumer received it at T |
| **Lower bound on creation** | "taken no earlier than T" | Something the producer could not have known before T |

The upper bound is free: a consumer always knows when it received a document. The lower bound is the missing half, and it is the half that freshness depends on. A replayed old capture fails exactly here.

## Criteria

- Give a consumer an upper bound on a capture's age, measured on the consumer's own clock, without trusting the host's clock.
- Make replay of an older signed capture detectable.
- Offline: no network, no hosted service, no certificate or timestamp authority (as ADR 0011).
- No elevation, no hardware requirement, no persistence on the host, no new Rust crate; `unsafe` stays forbidden.
- Existing outputs (capture-v1, capture-v2, comparison-v1 to v3, evidence and investigation formats) unchanged by default.
- Never claim more than the mechanism shows. The bound is on when a key holder produced the document, not on whether its measurements are true.

## Alternatives

| Option | Lower bound on creation | Consequence |
|---|---|---|
| A. Status quo | No | Honest; Q3 stays unanswered |
| B. Trust the host wall clock already in each record | Only if the host is honest and synchronized | The clock is exactly what is untrusted; steps, VM restores and forgery are invisible |
| C. Report host time-sync status (`/run/systemd/timesync/synchronized`, `adjtimex` state) | No | Unauthenticated, says nothing about the clock value, covers only some daemons, and `adjtimex` is not reachable without `libc` or `unsafe` |
| D. MIRA fetches authenticated time (NTS, Roughtime) | Only if the host is honest | A new network path and availability dependency; a compromised host still reports any time it likes |
| E. RFC 3161 timestamp authority token over the signed capture | No: proves only "existed no later than T" | Network, CA trust and CMS parsing, and it answers the upper bound, which the consumer already has. Useful for archival non-repudiation, not freshness |
| F. TPM quote over a consumer nonce | Yes | Hardware-bound, but needs TPM access (root or `tss`) and is absent on many hosts; ADR 0011 already set it aside |
| G. Separate signed statement over (capture hash, nonce) | Only for the endorsement | A key holder can endorse an old capture with a new nonce, so it does not show the capture was collected after the challenge |
| H. **Consumer-issued challenge read before collection, embedded in the capture and covered by the ADR 0011 signature; age measured on the consumer's clock** | Yes, against the key holder running MIRA | No host clock, network or hardware trust; reuses the existing signature path |

## Decision (option H)

### 1. Issuing a challenge (consumer side)

```sh
mira challenge > challenge.json
```

prints a **challenge-v1** document and nothing else:

```json
{"challenge_version":1,"challenge":"<64 lowercase hex>","issued_unix_ms":1793520000000}
```

- `challenge` is 32 bytes read from `/dev/urandom` and hex-encoded. A short read or any error exits 4 with a fixed diagnostic and no output. A consumer may also generate the value with any other cryptographic generator; MIRA only checks the syntax.
- `issued_unix_ms` is the **issuing machine's** wall clock. It is meaningful only to that machine's operator, who trusts that clock. It is never sent to the host being captured.
- The consumer keeps `challenge.json`. Anyone who can edit it can widen the age bound, so it needs the same protection as `allowed_signers`. MIRA keeps no state.

### 2. Answering a challenge (host side): capture-v3

```sh
mira capture LABEL [--pressure] [--bind-boot] --challenge HEX --signature PATH --sign-with KEY > capture.json
```

- `--challenge HEX` must be exactly 64 lowercase hex characters. Anything else is a usage error (exit 2) before any acquisition.
- `--challenge` **requires** `--signature`/`--sign-with`. An unsigned challenge can be pasted into any old file, so it would imply freshness it cannot show. The combination without signing is a usage error (exit 2).
- `--challenge` implies `--timeline`. It emits **capture-v3**: capture-v2 with one added member, placed immediately after the version so the bytes have a fixed prefix:

  ```json
  {"capture_version":3,"challenge":"<64 hex>","capture_scope":...,"collection":{...},"timeline":[...],"records":[...]}
  ```

  Everything after `challenge` is exactly as capture-v2, including optional boot binding. Records are unchanged.
- Order of operations: validate the challenge, start the ADR 0010 monotonic window, collect, build the document, sign it (ADR 0011), then print. The challenge is in memory before the first acquisition, so every source was read after the host received it.
- The challenge value is random and carries no host data. It links the capture to the consumer's request, which is its purpose.

### 3. Checking the bound (consumer side)

```sh
mira verify FILE --signature SIG --allowed-signers SIGNERS --principal NAME [--revocations KRL] \
    --challenge-file challenge.json --max-age-ms N
```

The `--challenge-file` and `--max-age-ms` options are given together. After the ADR 0011 signature check succeeds, MIRA:

1. reads `challenge.json` (bounded to 4 KiB) and requires exactly the challenge-v1 byte layout above, with a trailing newline;
2. requires FILE to begin with the fixed bytes `{"capture_version":3,"challenge":"` followed by the same 64 hex characters and `",`;
3. reads its own wall clock once and computes `age_bound_ms = now − issued_unix_ms`;
4. requires `0 ≤ age_bound_ms ≤ N`.

A fixed-prefix check is enough here, so `mira verify` needs no JSON parser. The bytes are already authenticated by the signature, and a key holder who signs a malformed document, for example one with a second `challenge` key, could equally sign a false one. The independent Python tooling parses with duplicate-key rejection, as the comparator already does.

Results: exit 0 prints a fixed line naming the principal and `age_bound_ms`. Exit 1 means not verified, with one fixed reason: `signature`, `challenge_mismatch`, `not_challenged` (not capture-v3), `issued_in_future` (the verifier clock is earlier than the issue time) or `older_than_policy`. Exit 2 is usage, and exit 4 a tool or read failure, as in ADR 0011. Without the new options, `mira verify` is unchanged, and it also verifies capture-v3 signatures without a freshness check.

`issued_in_future` covers a verifier clock that stepped backwards, or a challenge issued on another machine whose clock runs ahead. It is never treated as age zero.

### 4. Comparator and independent validators (stage 2)

`scripts/compare_evidence.py` accepts capture-v3 wherever it accepts capture-v2, with identical timing and same-boot semantics, and ignores `challenge` unless asked. With `--before-challenge FILE --after-challenge FILE --max-age-ms N` (allowed only together with the ADR 0011 signature options), it applies the same checks to each side. It adds `freshness: {"status": "within_policy", "before_age_bound_ms": ..., "after_age_bound_ms": ...}` and exits 2 on any failure. It also requires the two challenges to differ, so one answer cannot stand in for two captures. The capture validator gains a capture-v3 schema check and a live `challenge` group, and `schemas/capture-v3.schema.json` and `schemas/challenge-v1.schema.json` are closed schemas.

### Not adopted

Investigation reports are not challenged in this decision. They embed evidence-v1/v2 records rather than a capture timeline, and adding a member to the investigation envelope touches every template's schema. It can be a later decision with the same mechanism. Options C to F are not adopted; F stays open alongside ADR 0011's TPM option.

## Trust, privacy and failure analysis

- **What a passing check means.** A key listed for the principal signed a capture-v3 document containing a challenge the consumer issued `age_bound_ms` ago on its own clock, and MIRA reads that challenge before collecting. So, assuming the key holder ran an unmodified MIRA, every source was read no earlier than the issue time and no later than verification. It does not mean the measurements are true, that the host's clock is right, or that the host is uncompromised. A key holder running modified software can sign current-looking documents with old values, as ADR 0011 already states.
- **Replay.** An old capture carries an old challenge or none, so it fails as `challenge_mismatch` or `not_challenged`. Reusing one challenge for several captures is the consumer's choice and detected only by the comparator's distinct-challenge rule; consumers should issue one challenge per capture.
- **Pre-computation.** The challenge is 256 bits from the kernel CSPRNG, so a host cannot answer it before receiving it. A short or predictable value is refused only by syntax, so a consumer who supplies its own value owns its quality.
- **Clocks.** Only the consumer's clock is trusted, and only when one machine issues and verifies. If two machines are used, the bound is wrong by their offset; `issued_in_future` catches only an offset in one direction. Suspend or a clock step on the verifier between issue and check changes the bound; the bound uses the wall clock because challenge-v1 must survive the issuer's reboots.
- **Transport.** The challenge goes to the host over whatever channel the operator uses. It is not secret: an observer who learns it can only make a capture answer it if they also hold the signing key.
- **Disclosure.** The challenge links a capture to one request and to the consumer's `challenge.json`. It carries no host or consumer identifier; `issued_unix_ms` never leaves the consumer.
- **Availability.** A missing `ssh-keygen` already fails signing (exit 4). Without `/dev/urandom`, `mira challenge` fails with exit 4 and no output.
- **Vocabulary.** Output says `age_bound_ms` and `within_policy`, never fresh, current or verified time. Record-level `freshness: "unknown"` stays, because records are not changed.

## Acceptance for implementation

Stage 1 (Rust CLI):

- `mira challenge`: output exactly matches the challenge-v1 layout and closed schema; two runs differ; a failed read (through a test-only fixture path) exits 4 with no stdout.
- `capture --challenge`: capture-v3 for host and pressure profiles, with and without `--bind-boot`; the fixed prefix; bytes after `challenge` identical in structure to capture-v2; usage errors for a malformed challenge (wrong length, uppercase, non-hex, a trailing newline) and for `--challenge` without signing, each before any acquisition and with no output or signature file.
- `verify --challenge-file --max-age-ms`, with throwaway keys and the real `ssh-keygen`:
  - passes on a fresh signed capture-v3
  - each fixed failure reason: a modified challenge byte, a different challenge file, capture-v2 and capture-v1 input, an issue time in the future and an age above policy, through an injectable verifier clock
  - malformed or oversized challenge files, and a challenge file without its options partner, as usage errors
  - every ADR 0011 refusal still refuses first, as `signature`
- Unchanged output without the new options, including byte-identical capture-v1 and capture-v2.

Stage 2 (Python tooling): closed `capture-v3` and `challenge-v1` schemas; comparator acceptance of v3 as v2; the freshness checks per side, including distinct challenges and duplicate-key rejection; a capture validator `challenge` group run by the qualification runner, gated on `ssh_keygen`.

## Consequences and rollback

Blast radius:
- one new `challenge` subcommand
- one opt-in capture option and the capture-v3 format it selects
- two opt-in `verify` options
- comparator options and two schemas in stage 2

No default output changes, and signatures remain separate files. Removing the feature leaves every capture-v1 and v2 document valid; capture-v3 documents stay verifiable as signed documents under the existing capture namespace. No operational state requires rollback.

## Review decisions

1. **Signing is required.** A challenge is never accepted without `--signature`/`--sign-with`, because an unsigned document cannot show that the challenge was answered rather than pasted in.
2. **Fixed syntax:** exactly 32 bytes as 64 lowercase hex characters. A fixed length keeps the capture-v3 prefix check byte-exact.
3. **Investigation reports are out of scope.** Challenging them is a later decision with the same mechanism.

## Primary references

- [random(4): /dev/urandom](https://man7.org/linux/man-pages/man4/random.4.html)
- [RFC 3161: Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161)
- [RFC 8915: Network Time Security](https://www.rfc-editor.org/rfc/rfc8915)
- [Roughtime (IETF draft)](https://datatracker.ietf.org/doc/draft-ietf-ntp-roughtime/)
- [TPM 2.0 Part 3: TPM2_Quote qualifyingData](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
