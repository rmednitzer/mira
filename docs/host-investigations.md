# Explicit uptime-minimum and kernel-release investigations

```sh
mira investigate uptime-minimum --min-uptime-seconds 3600
mira investigate kernel-release --expect 6.17.0-5-generic --json
```

Two small read-only checks that come up early in host-instability work:

- **uptime-minimum** answers "has this host been up for at least N seconds?". A not-satisfied result means the kernel reports booting less than N seconds ago, which separates an unexpected restart from a long-running degradation.
- **kernel-release** answers "is the running kernel exactly the release I expect?", for example to confirm that a patch reboot picked up the new kernel.

Neither has a default. The operator supplies the criterion.

## uptime-minimum/v1

- `--min-uptime-seconds` is an ASCII integer of at most 20 digits from 1 to 18446744073709551615. Leading zeros are normalized. Zero, signs, fractions, exponents, whitespace and overflow exit 2 before evidence is read.
- Only `/proc/uptime` is read, through the existing 64 KiB reader and integer parser that validates both fields and keeps whole seconds without floating point. Truncation is exact here: for an integer minimum N, the whole seconds reach N exactly when the real uptime does.

| Observation | Outcome | Reason | Exit |
|---|---|---|---|
| Whole uptime >= minimum | satisfied | minimum_met | 0 |
| Whole uptime < minimum | not_satisfied | below_minimum | 1 |
| Missing, inaccessible, oversized or malformed uptime | indeterminate | evidence_unavailable | 3 |

`/proc/uptime` counts time since boot, including suspend. A long uptime does not show that no service or container restarted, that no kernel or hardware fault occurred without a reboot, or that any clock is trustworthy. A short uptime names no cause. Inside a container, `/proc/uptime` usually reports the host's boot time unless a time namespace offsets it.

## kernel-release/v1

- `--expect` is 1–256 characters from `A-Za-z0-9._+-`, the same rule the collector applies to the observed release, starting with a letter or digit. It is not trimmed. Surrounding whitespace, other characters and option-shaped values such as `--json` exit 2 before evidence is read, so a forgotten value cannot become the criterion.
- Only `/proc/sys/kernel/osrelease` is read, through the existing 16 KiB reader and ASCII-only parser.
- The comparison is exact byte equality. There is no version ordering, prefix or case folding: `6.17.0-5` does not match `6.17.0-5-generic`.

| Observation | Outcome | Reason | Exit |
|---|---|---|---|
| Observed release equals the expected release | satisfied | release_matches | 0 |
| Observed release differs | not_satisfied | release_differs | 1 |
| Missing, inaccessible, oversized or malformed release | indeterminate | evidence_unavailable | 3 |

The release string names the running kernel's release only. Two builds can share a release, and the build string (`uname -v`) is not compared. A match does not show that livepatches are applied, that the matching package is installed, or anything about vulnerability exposure. It is not a patch-compliance verdict.

## Reports and compatibility

Missing, reordered or extra arguments exit 2 with each template's own usage line; they are never treated as an unknown template or a service scope.

`--json` emits one report with `investigation_version: 1`, `template` (`uptime-minimum/v1` or `kernel-release/v1`), `scope: "local/procfs"`, the expectation (`minimum_uptime_seconds` or `release`), a fixed outcome/reason and `evidence_ref: "#/evidence"`. `application_health` and `root_cause` are `not_assessed`. The evidence is one unchanged evidence-v2 record for the single source, with null scope, monotonic `elapsed_ms`, a fixed `failure_reason` when unavailable, an unverified clock and unknown freshness. Backend error messages are never exported. `local/procfs` names the interface visible to this process, not an authenticated host.

The dedicated [uptime-minimum](../schemas/uptime-minimum-v1.schema.json) and [kernel-release](../schemas/kernel-release-v1.schema.json) schemas reference the repository-local [evidence-v2 schema](../schemas/evidence-v2.schema.json). They bind the source, reason to outcome, and `evidence_unavailable` to unavailable evidence in both directions. Consumers must still check the uptime-versus-minimum relation and exact release equality, which JSON Schema cannot express. Existing formats are unchanged, and the history comparator does not accept these reports.

The Debian package installs this guide and both schemas. See [ADR 0009](adr/0009-explicit-uptime-and-kernel-release.md), [host evidence](host-evidence.md) and [testing](testing.md).
