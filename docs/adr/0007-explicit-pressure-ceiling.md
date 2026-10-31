# ADR 0007: explicit pressure-ceiling expectation

Status: accepted for implementation, 2026-10-31. Native integration qualification remains required.

## Context and criteria

The primary use case is investigating host instability. Pressure stall information (PSI) is the kernel's direct report of time lost to CPU, memory and IO contention. MIRA already collects bounded PSI `some avg10` values for all three resources: CPU through `inspect` and captures, memory and IO through `capture --pressure`. An operator can read those numbers, but has no machine-readable way to ask whether one resource stayed at or below a ceiling they chose, with the evidence bound to the answer. ADR 0005 rejected a universal PSI health threshold. It did not reject an explicit operator criterion, which is the design it accepted for memory.

Criteria: reuse the existing bounded PSI collector and parser, require an explicit resource and an explicit integer ceiling, preserve evidence/assessment separation, keep unavailable evidence indeterminate, introduce no command execution, new source or runtime dependency, and leave existing commands, reports and schemas byte-for-byte unchanged.

## Alternatives and decision

| Option | Consequence |
|---|---|
| No change; read PSI from `inspect`/`capture` | Lowest scope, but every caller must build its own threshold logic, evidence binding and unknown handling |
| Default or learned stall threshold | Unsupported across workloads; a percentage that is normal for a batch host is an incident on a latency-sensitive one |
| Assess `full`, avg60/avg300 or totals as well | Larger contract. System-level CPU `full` is undefined, and the longer windows are not exported today. Defer until a requirement exists |
| Per-cgroup PSI | Different source, path discovery and scope semantics; would need its own decision |
| Explicit ceiling on one resource's `some avg10` | Chosen: one bounded deterministic expectation over an observation MIRA already collects |

Add `mira investigate pressure-ceiling --resource RESOURCE --max-some-avg10-basis-points N [--json]`.

- RESOURCE is exactly `cpu`, `memory` or `io`. Anything else is a usage error before acquisition.
- N is an ASCII decimal integer of at most five digits, from 0 to 10000 inclusive, in the basis points already used by evidence (10000 = 100.00%). Signs, fractions, exponents, whitespace and out-of-range values are usage errors before acquisition. Leading zeros may be normalized. Zero is valid: it expects no measured stall.
- Read only `/proc/pressure/RESOURCE` through the existing 16 KiB bounded reader and the ASCII-only PSI parser.
- `some avg10 <= N` is satisfied (`within_ceiling`, exit 0). `some avg10 > N` is not satisfied (`above_ceiling`, exit 1). A missing, inaccessible, oversized or malformed source is indeterminate (`evidence_unavailable`, exit 3). An invalid invocation exits 2 with no report.
- The `full` value is exported as evidence but not assessed.

## Semantics and limits

`some avg10` is the kernel's exponentially weighted share of roughly the last 10 seconds in which at least one runnable task was stalled on the resource. It is a smoothed, lagging indicator. A satisfied result does not show that no stall occurred in that window, that a workload is healthy, that latency targets are met or what caused contention. A not-satisfied result does not identify a root cause or justify remediation. On a kernel without PSI (`CONFIG_PSI=n`, or booted with `psi=0`) the file is missing and the outcome is indeterminate, never satisfied. Inside a container, `/proc/pressure` usually reports system-wide pressure rather than the container's cgroup. The `local/procfs` scope names the interface visible to this process, not an authenticated host or cgroup.

## Contract, trust and validation

A separate pressure-ceiling-v1 schema identifies template `pressure-ceiling/v1`, scope `local/procfs`, the explicit expectation (resource and maximum), a fixed reason/outcome and `evidence_ref: "#/evidence"`. The evidence is one unchanged evidence-v2 pressure record with null scope. evidence-v2 is used because evidence-v1 does not admit the memory and IO PSI sources, and new contracts already use v2 (ADR 0002). The schema binds the evidence source to the chosen resource and reason to outcome, and requires `evidence_unavailable` exactly when evidence is unavailable. A separate validator checks the value-versus-ceiling relationship that the schema cannot express. Timestamps remain unverified and freshness unknown. Existing service, memory, evidence and capture contracts are unchanged.

Before merge: native synthetic tests per resource for below, equal and above the ceiling, the 0 and 10000 bounds, a high `full` value with low `some`, source isolation between resources, missing, oversized and malformed sources, and refused criteria/resources/invocations; frozen JSON for one report; independent valid/invalid schema and semantic fixtures; actual CLI exit/evidence agreement on both native architectures; packaging checks; exact-head review and post-merge checks.

## Consequences, reversibility and rollback

Blast radius: one opt-in template, a report schema, documentation and tests. No new source, privilege, persistence, network path or automatic action. The module is separate from the service and memory reports, so existing consumers are unaffected. Revert the command, module, schema, validator and packaged files together; exported reports keep their version and need consumer coordination if the command is removed. No operational state requires rollback.

Primary semantic basis: [Linux PSI documentation](https://docs.kernel.org/accounting/psi.html).
