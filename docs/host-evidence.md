# Host evidence contract

MIRA's `inspect` command creates an in-process, read-only `Snapshot` containing four allowlisted Linux observations: `/proc/meminfo`, `/proc/uptime`, `/proc/sys/kernel/osrelease`, and `/proc/pressure/cpu`.

Each typed `Evidence<T>` records the logical source path, an optional wall-clock recording time in Unix milliseconds, and either an observed value or a structured unavailable/error result. Errors are never coerced into healthy or secure findings.

## Boundaries

- This is a sequence of reads, not an atomic host snapshot. `collected_unix_ms` is recorded after each collector returns, not a trusted source timestamp.
- Host clocks are not independently authenticated. Linux files might be unavailable, maliciously altered, or stale.
- The injectable procfs root exists for fixtures, not as a sandbox boundary. The CLI uses the fixed `/proc` root.
- Human-readable output is the default; `--json` exports versioned records under the [JSON contract](evidence-json.md).
- Absence of evidence means *unknown*, never *healthy*, *not affected* or *secure*.
- There is no vulnerability assessment, agent authority, remote target, service discovery, persistent storage or external inference.

## Uptime parsing

Both `/proc/uptime` fields must be unsigned decimal seconds with whole parts that fit `u64`. Integers are accepted; a decimal point requires a nonempty digit-only fraction. MIRA retains whole uptime seconds without floating-point conversion. The second field is aggregate CPU idle time and may exceed uptime; it is validated but not exported. Missing/extra fields, signs, exponents, nonfinite values, malformed fractions and overflow produce unavailable evidence. Existing byte bounds remain in force.

The [Linux producer](https://github.com/torvalds/linux/blob/v6.17/fs/proc/uptime.c) emits two decimal-second fields and sums idle across CPUs. This parser is not proof of source authenticity or freshness.

## Validation

`tests/host_evidence.rs` reads a synthetic procfs directory with the same collector used by the CLI. Unit tests cover malformed source content, both uptime fields, multicore idle time, integer limits and missing data. A malformed-idle regression verifies unavailable uptime, preserved memory and redacted JSON output. Mandatory x64/ARM64 Ubuntu 26.04 CI runs Rust tests and release builds.

## Next criteria

Versioned JSON Lines, a formal JSON Schema and independent contract checks are implemented. Independent source timestamps/freshness, host identity, cross-source consistency and authenticated stored-trace integrity remain separate design and validation work. See [development and validation](testing.md).
