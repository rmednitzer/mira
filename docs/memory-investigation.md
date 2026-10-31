# Explicit memory-headroom investigation

```sh
mira investigate memory-headroom --min-available-kib 1048576
mira investigate memory-headroom --min-available-kib 1048576 --json
```

The example criterion is 1 GiB in KiB, not a universal recommendation. The operator must choose a positive ASCII integer, at most 20 digits, fitting u64. Leading zeros are normalized. There is no default or learned health threshold. Invalid, signed, fractional, exponent, zero and overflowing criteria exit 2 before reading evidence and emit no report. Missing, reordered or extra arguments also exit 2 with the template's own usage line; they are never treated as an unknown template or a service scope.

Only /proc/meminfo is read through the existing bounded collector. No systemctl, package database, other procfs source, network, model or privileged helper is required. The scope local/procfs names the interface visible to this process; it is not authenticated host identity.

| Observation | Outcome | Reason | Exit |
|---|---|---|---|
| MemAvailable >= requested minimum | satisfied | minimum_met | 0 |
| MemAvailable < requested minimum | not_satisfied | below_minimum | 1 |
| Missing, inaccessible, oversized, malformed or inconsistent memory evidence | indeterminate | evidence_unavailable | 3 |

A minimum above MemTotal is a valid unmet expectation. The kernel's MemAvailable is an estimate of memory available for starting applications without swapping. It may change immediately. This does not assess a workload's cgroup constraints, guarantee allocation success, establish application health or explain a root cause.

## Report and compatibility

JSON emits one memory-headroom/v1 report with investigation_version 1, scope local/procfs, expectation.minimum_available_kib, fixed assessment outcome/reason and evidence_ref #/evidence. application_health and root_cause remain not_assessed. Evidence is an unchanged evidence-v1 memory record with null scope, unverified clock and unknown freshness; unavailable evidence exports only the error kind, not backend messages. Human output includes the criterion, memory values when available and recording-time limits.

The [dedicated schema](../schemas/memory-headroom-v1.schema.json) references repository-local [evidence-v1](../schemas/evidence-v1.schema.json). Consumers must also check memory consistency and the relationship between criterion, observation and assessment. The JSON pointer is a local data reference, not authentication or authority. Existing service investigation-v1 and capture/evidence versions are unchanged. Reports are not accepted as captures by the history comparator.

The package installs this guide and schema. Native fixtures cover below/equal/above/extreme criteria, invalid and missing memory; independent fixtures and actual CLI contract checks run on both native architectures. See [ADR 0005](adr/0005-explicit-memory-headroom.md), [testing](testing.md), and [kernel semantics](https://docs.kernel.org/filesystems/proc.html).
