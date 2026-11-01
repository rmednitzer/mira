# ADR 0001: Evidence-bound read-only service investigation

Status: accepted, 2026-10-30. **Implemented**; guide: [investigations](../investigations.md). Runtime and release qualification remain bounded by the checks below. Representative host qualification follows [ADR 0013](0013-host-qualification-protocol.md).

## Context and acceptance criteria

Phase 1 requires a useful offline investigation template before intent, UI or AI integration. Existing collectors already provide bounded observations, provenance and unavailable states. A template must add an explicit operator expectation, not rename an observation as health or create operational authority.

Criteria: reuse the existing fixed-argument collector; preserve raw evidence separately from assessment; reject unknown templates and invalid scope before dispatch; represent unknown/transitioning/unavailable states explicitly; use deterministic Rust without new dependencies; preserve evidence JSON v1; validate the public CLI and independently check the new wire contract.

## Options and decision

| Option | Value | Cost or failure behavior | Decision |
|---|---|---|---|
| No change: inspect raw service state only | Keeps the smallest CLI | Leaves expectation and machine-readable assessment to every caller | Retain existing command, add an opt-in template |
| General workflow/plugin engine | Broad future flexibility | Adds dispatch, persistence and authority mechanisms without a current need | Defer |
| Threshold-driven host-health verdict | Could summarize resource observations | Universal thresholds and application health are not established by present evidence | Defer |
| Closed, versioned service expectation | Directly supports checking an explicitly selected service and later task-oriented views | Narrow outcome; cannot diagnose a root cause | Select |

Implement only `mira investigate service-active UNIT.service [--json]`, identified as `service-active/v1`. A closed Rust enum admits the template. There are no arbitrary commands, dynamic plugins, retries, service discovery, remote targets or model calls. The operator explicitly selects the expectation; selecting it grants no new OS permissions.

## Assessment semantics

Assess systemd's reported activation state, not application health:

- `active`, `reloading`, `refreshing`: satisfied; these are active states under the documented systemd semantics.
- `inactive`, `failed`, `maintenance`: not satisfied for this explicit expectation; intentional inactivity is still possible.
- `activating`, `deactivating`: indeterminate while transition is in progress.
- Unrecognized states, unavailable evidence, unexpected source or invalid service identity: indeterminate.

LoadState is orthogonal to ActiveState. A masked or otherwise unloaded definition does not negate an observed active state. SubState remains literal evidence; no application-health or root-cause inference follows. Keep aliases bound through the collector's requested-name/Names validation; do not require the requested alias to equal the canonical Id.

The report preserves its requested scope and embeds the unchanged evidence-v1 service record. Its assessment references `#/evidence`; this is a local JSON Pointer, not authenticated provenance. Outcome and reason derive from one enum, preventing contradictory combinations. Error reasons are fixed codes, not backend exception messages. Recording timestamps remain unverified and freshness unknown.

## Compatibility, authority and recovery

The investigation report has its own versioned JSON Schema. Existing inspect/service output and evidence-v1 semantics remain unchanged. JSON is export-only; schema validity cannot admit an operation. CLI exits are 0 satisfied, 1 not satisfied, 3 indeterminate and 2 rejected invocation. Invalid invocation emits no report and does not dispatch collection.

Blast radius: one opt-in read-only command, pure assessment logic, a report schema and synthetic/native validation. No migration, stored-state rewrite, new dependency, service installation or privilege change. Reverting the introducing PR removes the new command; existing evidence consumers remain compatible. Coordinate new report consumers if rollback removes the command.

## Pattern fit and deferred mechanisms

Adopt explicit observation/assessment separation, named dispositions, static failure reasons, scope-bound references and negative-path validation. Current source status must determine the disposition; absence must never become a successful empty result. Preserve existing byte/deadline rejection instead of presenting truncated evidence as complete.

Durable leases, outboxes, content-addressed storage, audit chains, transport authentication, command classifiers and background supervisors are not needed for this single-shot, read-only template. Reconsider only when a documented persistence, remote-effect or process-lifetime requirement exists. Hashes do not establish truth or authorization. Fixed dispatch is not an authenticated identity service or OS sandbox.

## Validation and remaining uncertainty

Before merge: pure state-table and unavailable/source/identity tests; alias and masked-active cases; native public-CLI tests for satisfied/not-satisfied/indeterminate/rejected invocations and subprocess failures; independent schema fixtures including semantic contradictions; live unprivileged systemd comparison on both native CI architectures; existing evidence/history, packaging, Clippy, CodeQL and exact-head reviews.

The oracle is the documented reported-state expectation, not a learned health label. Tests establish behavior for the admitted cases, not fleet-wide compatibility, source authenticity, stable host identity, freshness, application health or vulnerability applicability. No inference benchmark or production-readiness claim is made.

## Primary contracts checked before implementation

- [systemd 262 Unit properties](https://www.freedesktop.org/software/systemd/man/262/org.freedesktop.systemd1.html): ActiveState, orthogonal LoadState and extensible SubState.
- [systemd 262 systemctl state vocabulary](https://www.freedesktop.org/software/systemd/man/262/systemctl.html): reported high-level states and extension caveats.
- [JSON Schema draft 2020-12](https://json-schema.org/draft/2020-12): report structure validation; semantic equality and assessment checks remain explicit tests.
