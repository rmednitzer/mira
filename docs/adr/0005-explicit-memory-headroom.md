# ADR 0005: explicit memory-headroom expectation

Status: accepted for implementation, 2026-10-30. Native integration qualification remains required.

## Context and criteria

The offline investigator exposes MemAvailable but has only one activation expectation. An operator needs a machine-readable check of whether procfs reports at least an explicitly chosen amount of available memory. The Linux value is an estimate, not an allocation guarantee, cgroup budget or application-health verdict.

Criteria: reuse the existing bounded memory collector, require an explicit positive integer KiB threshold, preserve evidence/assessment separation, keep unavailable evidence indeterminate, introduce no command execution or runtime dependency and preserve existing schemas/commands.

## Alternatives and decision

| Option | Consequence |
|---|---|
| No change; inspect memory values manually | Lowest scope, but every caller must assemble its own threshold outcome and evidence binding |
| Universal percentage/PSI health threshold | Unsupported across workloads; would overstate the existing observations |
| Generic rule engine or cgroup diagnosis | Larger contracts and scope without a current requirement; defer |
| Explicit minimum over the existing observation | Chosen: bounded deterministic expectation with an operator-supplied criterion |

Add `mira investigate memory-headroom --min-available-kib N [--json]`. N is an ASCII decimal integer of at most 20 digits in 1..=u64::MAX; signs, fractions, exponents, zero and overflow are usage errors before acquisition. Leading zeros may be normalized. A threshold above total memory is valid and simply not met by available memory.

Read only /proc/meminfo. Available >= N is satisfied (exit 0); available < N is not_satisfied (exit 1); collection/parser failures are indeterminate (exit 3). Invalid invocation exits 2 with no report. Do not infer security, root cause, future allocation success, application health or workload/cgroup headroom. Caller-selected criteria are not policy authorization.

## Contract, trust and validation

A separate memory-headroom-v1 schema identifies template memory-headroom/v1, scope local/procfs, the explicit expectation, fixed reason/outcome and evidence_ref #/evidence. Embed unchanged evidence-v1 memory evidence with null evidence scope. Local/procfs identifies a collection interface, not an authenticated host. Preserve unverified time and unknown freshness. Existing service investigation-v1, captures and evidence records remain unchanged.

Before merge: native synthetic below/equal/above/extreme/malformed/missing-source tests, CLI argument refusal, independent valid/invalid schema and semantic fixtures, actual CLI exit/evidence consistency, both native packaging matrices, exact-head review and post-merge checks. MemAvailable may change immediately after reading; fixtures do not establish representative host or workload assurance.

## Consequences, reversibility and rollback

Blast radius: one opt-in template, a report/schema, documentation and tests. No new source, privilege, persistence, network path or automatic action. Keep the implementation separate from the service report so existing consumers are unaffected. Revert the new command/module/schema/validator together; exported reports retain their original version and need consumer coordination if the command is removed. No operational state requires rollback.

Primary semantic basis: [Linux procfs MemAvailable documentation](https://docs.kernel.org/filesystems/proc.html). The estimate concerns available memory without swapping; it is not a promise that a future workload allocation will succeed.
