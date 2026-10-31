# ADR 0009: explicit uptime-minimum and kernel-release expectations

Status: accepted for implementation, 2026-10-31. Native integration qualification remains required.

## Context and criteria

Two questions recur early in host-instability work. "Has this host rebooted recently?" separates an unexpected restart from a long-running degradation. "Is the running kernel the release I expect?" confirms that a patch reboot actually picked up the new kernel, or that a fleet member is not on an outlier. MIRA already collects bounded whole-second uptime and the validated kernel release for `inspect` and captures, but only as raw values. The operator must compare them by hand, without an evidence-bound answer or unknown handling.

Criteria: reuse the existing bounded collectors and parsers, require an explicit operator criterion, keep evidence and assessment separate, keep unavailable evidence indeterminate, add no command execution, source or runtime dependency, and leave existing commands, reports and schemas byte-for-byte unchanged. The two questions are small and share one design, so one decision covers both. Each still gets its own template, schema and exit semantics.

## Alternatives and decision

| Option | Consequence |
|---|---|
| No change; read `inspect` output | Lowest scope; every caller rebuilds comparison, evidence binding and unknown handling |
| Default "recent reboot" window | No universal value: minutes matter for a crash loop, days for a maintenance audit |
| Kernel version ordering (`>=`) or prefix matching | Kernel release strings are vendor-defined (`6.17.0-5-generic`); ordering invites "patched/vulnerable" readings that the string cannot support. Defer to Phase 2 |
| Compare against installed kernel packages | Needs package-to-release mapping and boot-loader knowledge; a separate decision |
| Explicit minimum uptime and exact release equality | Chosen: deterministic expectations over observations MIRA already collects |

### uptime-minimum/v1

`mira investigate uptime-minimum --min-uptime-seconds N [--json]`

- N is an ASCII decimal integer of at most 20 digits in 1..=u64::MAX. Zero, signs, fractions, exponents, whitespace and overflow exit 2 before acquisition. Leading zeros may be normalized.
- Read only `/proc/uptime` through the existing 64 KiB reader and integer parser, which validates both fields and retains whole seconds without floating point.
- Whole uptime >= N is satisfied (`minimum_met`, exit 0). Whole uptime < N is not satisfied (`below_minimum`, exit 1), meaning the kernel reports booting less than N seconds ago. Unavailable or malformed evidence is indeterminate (`evidence_unavailable`, exit 3).
- Truncation is exact for this comparison: for integer N, `floor(uptime) >= N` holds exactly when `uptime >= N`.

### kernel-release/v1

`mira investigate kernel-release --expect RELEASE [--json]`

- RELEASE is 1–256 characters from `A-Za-z0-9._+-`, the lexical rule the collector applies to `/proc/sys/kernel/osrelease`, and must start with a letter or digit. The leading rule keeps a forgotten value from turning an option such as `--json` into the criterion, as for capture labels. Anything else, including surrounding whitespace, exits 2 before acquisition. The criterion is not trimmed.
- Read only `/proc/sys/kernel/osrelease` through the existing 16 KiB reader and ASCII-only parser.
- An exactly equal release is satisfied (`release_matches`, exit 0). A different release is not satisfied (`release_differs`, exit 1). Unavailable or malformed evidence is indeterminate (`evidence_unavailable`, exit 3).

## Semantics and limits

`/proc/uptime` counts time since boot including suspend. A long uptime does not show that no service or container restarted, that no kernel or hardware fault occurred without a reboot, or that any clock is trustworthy. A short uptime names no cause. Inside a container, `/proc/uptime` usually reports the host's boot time unless a time namespace offsets it.

The release string identifies the running kernel's release name only. It does not identify the build: two builds can share a release, and `uname -v` is not compared. It does not prove that livepatches are applied, that the matching package is installed, or anything about vulnerability exposure. A satisfied release match is not a patch-compliance verdict.

Both scopes are `local/procfs`: the interface visible to this process, not an authenticated host.

## Contract, trust and validation

Two separate schemas, uptime-minimum-v1 and kernel-release-v1, each identify their template, scope `local/procfs`, the explicit expectation, a fixed outcome/reason and `evidence_ref: "#/evidence"`, with `application_health` and `root_cause` not assessed. Each embeds one unchanged evidence-v2 record with null scope, bound to its single source. The schemas bind reason to outcome and `evidence_unavailable` to unavailable evidence in both directions. A shared validator re-derives each outcome: the uptime-versus-minimum relation, and exact release equality, which JSON Schema cannot express. It also compares live CLI results with independent direct reads.

Before merge: native synthetic tests at, below and above the minimum, both u64 bounds, fractional uptime at the boundary, an exact release match, case and suffix differences, malformed and missing sources, and refused criteria and invocations; frozen JSON for each report; independent valid/invalid fixtures; live CLI agreement on both native architectures; packaging checks; exact-head review and post-merge checks.

## Consequences, reversibility and rollback

Blast radius: two opt-in templates, two report schemas, one guide, tests and a validator. No new source, privilege, persistence, network path or automatic action. Revert both commands, modules, schemas and packaged files together, or either template alone. Exported reports keep their version. No operational state requires rollback.

Primary semantic basis: [Linux procfs documentation](https://docs.kernel.org/filesystems/proc.html).
