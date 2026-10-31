# Explicit pressure-ceiling investigation

```sh
mira investigate pressure-ceiling --resource memory --max-some-avg10-basis-points 500
mira investigate pressure-ceiling --resource io --max-some-avg10-basis-points 1000 --json
```

The question is: did the kernel report that, over roughly the last 10 seconds, tasks stalled on one resource for no more than a share of time the operator chose? The examples allow 5.00% for memory and 10.00% for IO. They are illustrations, not recommendations. There is no default or learned threshold, because a stall share that is normal on a batch host can be an incident on a latency-sensitive one.

## Invocation

- `--resource` is exactly `cpu`, `memory` or `io`.
- `--max-some-avg10-basis-points` is an ASCII integer of at most five digits from 0 to 10000. 10000 means 100.00%, the same unit evidence records already use. Leading zeros are normalized. 0 is valid and expects no measured stall.
- Signs, fractions, exponents, whitespace, values above 10000 and unknown resources exit 2 before any evidence is read, with a fixed diagnostic and no report.
- Missing, reordered or extra arguments exit 2 with the template's own usage line; they are never treated as an unknown template or a service scope.

Only `/proc/pressure/RESOURCE` is read, through the existing 16 KiB bounded reader and ASCII-only PSI parser used by `inspect` and `capture --pressure`. No systemctl, package database, other procfs file, network, model or privileged helper is involved.

## Outcomes

| Observation | Outcome | Reason | Exit |
|---|---|---|---|
| `some avg10` <= ceiling | satisfied | within_ceiling | 0 |
| `some avg10` > ceiling | not_satisfied | above_ceiling | 1 |
| Missing, inaccessible, oversized or malformed PSI | indeterminate | evidence_unavailable | 3 |

Only the `some` line decides. It counts time in which at least one runnable task was stalled. The `full` value (time in which all non-idle tasks were stalled) is kept as evidence but not assessed; system-wide CPU `full` is undefined and reported as zero by recent kernels.

## What a result does not mean

`avg10` is an exponentially weighted moving average, so it smooths and lags. A satisfied result does not show that no stall occurred, that a workload is healthy or that a latency objective is met. A not-satisfied result names no cause and authorizes no action. Neither establishes freshness: the value can change immediately after it is read.

A kernel built without PSI, or booted with `psi=0`, has no pressure files. The outcome is then indeterminate with `failure_reason: not_found`, never satisfied. Inside a container, `/proc/pressure` usually reports system-wide pressure rather than the container's cgroup; per-cgroup PSI is a different source and is not read. The `local/procfs` scope names the interface visible to this process, not an authenticated host.

## Report and compatibility

`--json` emits one report with `investigation_version: 1`, `template: "pressure-ceiling/v1"`, `scope: "local/procfs"`, `expectation.resource`, `expectation.max_some_avg10_basis_points`, a fixed outcome/reason and `evidence_ref: "#/evidence"`. `application_health` and `root_cause` are `not_assessed`. The evidence is one unchanged evidence-v2 pressure record with null scope, monotonic `elapsed_ms`, a fixed `failure_reason` when unavailable, an unverified clock and unknown freshness. Backend error messages are never exported. evidence-v2 is used because evidence-v1 does not admit memory or IO PSI.

The [dedicated schema](../schemas/pressure-ceiling-v1.schema.json) references the repository-local [evidence-v2 schema](../schemas/evidence-v2.schema.json). It binds the evidence source to the selected resource, the reason to the outcome, and `evidence_unavailable` to unavailable evidence in both directions. Consumers must still check the value-versus-ceiling relation, which JSON Schema cannot express. Existing service, memory-headroom, evidence and capture formats are unchanged. The history comparator does not accept these reports as captures.

The Debian package installs this guide and the schema. See [ADR 0007](adr/0007-explicit-pressure-ceiling.md), [testing](testing.md) and the [kernel PSI documentation](https://docs.kernel.org/accounting/psi.html).
