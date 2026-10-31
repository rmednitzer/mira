# Host evidence contract

MIRA's `inspect` command creates an in-process, read-only `Snapshot` containing four allowlisted Linux observations: `/proc/meminfo`, `/proc/uptime`, `/proc/sys/kernel/osrelease`, and `/proc/pressure/cpu`.

Each typed `Evidence<T>` records the logical source path, an optional wall-clock recording time in Unix milliseconds, and either an observed value or a structured unavailable/error result. Errors are never coerced into healthy or secure findings.

## Boundaries

- This is a sequence of reads, not an atomic host snapshot. `collected_unix_ms` is recorded immediately after each individual acquisition returns, not a trusted source timestamp.
- Host clocks are not independently authenticated. Linux files might be unavailable, maliciously altered, or stale.
- The injectable procfs root exists for fixtures, not as a sandbox boundary. The CLI uses the fixed `/proc` root.
- Human-readable output is the default; `--json` exports versioned records under the [JSON contract](evidence-json.md).
- Absence of evidence means *unknown*, never *healthy*, *not affected* or *secure*.
- There is no vulnerability assessment, agent authority, remote target, service discovery, persistent storage or external inference.

## Acquisition byte budgets

| Source | Maximum input bytes |
|---|---|
| /proc/meminfo and /proc/uptime | 65,536 each (64 KiB) |
| Kernel release and each selected PSI source | 16,384 each (16 KiB) |
| /var/lib/dpkg/status | 33,554,432 (32 MiB); see [package provenance](package-provenance.md) |

These are whole-source acquisition limits, including whitespace and line endings. Valid input exactly at the limit is admitted; one extra byte produces limit_exceeded. Invalid UTF-8 within the budget produces malformed_data. Acquisition reads at most the budget plus one byte to detect overflow. A byte budget is not a filesystem I/O deadline.

## Memory parsing

The retained MemTotal and MemAvailable fields require unsigned ASCII decimal integers fitting u64, ASCII whitespace separators and exactly the kB unit. Signs, decimal points, exponents, non-ASCII digits/separators, duplicate retained fields, overflow, zero total and available greater than total produce unavailable evidence. Zero available is valid. Other meminfo fields are not interpreted. This is lexical and value validation, not source authentication.

The [Linux producer](https://github.com/torvalds/linux/blob/v6.17/fs/proc/meminfo.c) emits these fields as unsigned decimal KiB counts. Malformed memory remains unavailable in inspect/capture and indeterminate in a memory expectation; independent sources remain available.

## Uptime parsing

Both `/proc/uptime` fields must be unsigned decimal seconds with whole parts that fit `u64`. Integers are accepted; a decimal point requires a nonempty digit-only fraction. MIRA retains whole uptime seconds without floating-point conversion. The second field is aggregate CPU idle time and may exceed uptime; it is validated but not exported. Missing/extra fields, signs, exponents, nonfinite values, malformed fractions and overflow produce unavailable evidence. Existing byte bounds remain in force.

The [Linux producer](https://github.com/torvalds/linux/blob/v6.17/fs/proc/uptime.c) emits two decimal-second fields and sums idle across CPUs. This parser is not proof of source authenticity or freshness.

## PSI and kernel release parsing

PSI lines must be ASCII, as the kernel producer emits them, and are split only on ASCII whitespace. Any non-ASCII byte makes the source malformed before tokenization, so a Unicode separator cannot hide a field, such as a duplicate `avg10`, inside an otherwise ignored token. Each line must start with `some` or `full` and carry exactly one `avg10` with at most two decimal places within 0–100.00. A Unicode separator such as U+00A0 or U+2003 yields malformed evidence instead of being treated as a field boundary. The kernel release is trimmed of ASCII whitespace only and must then consist of ASCII letters, digits and `.-_+`; leading or trailing Unicode whitespace is rejected rather than silently removed. The meminfo, uptime, PSI and kernel-release parsers therefore all apply the same ASCII framing rule.

The opt-in [capture command](captures.md) retains monotonic per-source elapsed time and fixed failure reasons in evidence-v2, and can add bounded memory/IO PSI through a closed profile. Existing inspect output stays evidence-v1. The [uptime-minimum and kernel-release investigations](host-investigations.md) compare these uptime and kernel-release observations with explicit operator criteria.

## Validation

`tests/host_evidence.rs` reads a synthetic procfs directory with the same collector used by the CLI. Unit tests cover malformed source content, both uptime fields, multicore idle time, integer limits and missing data. A malformed-idle regression verifies unavailable uptime, preserved memory and redacted JSON output. The default native source-boundary matrix exercises all seven pressure-profile sources at their exact byte budgets, one byte over and with invalid UTF-8 through complete captures. It checks the selected unavailable record, preservation of six independent observations and completion. Mandatory x64/ARM64 Ubuntu 26.04 CI runs Rust tests and release builds. The optional independent `--live-procfs` evidence-validator check is mandatory in native CI: direct reads surround MIRA, kernel/total-memory endpoint values must agree with the report, and whole uptime must fall within the direct interval. Changed endpoints fail as inconclusive. Dynamic available memory and PSI are not bounded by endpoint samples. This does not authenticate procfs or establish representative host qualification.

## Next criteria

Versioned JSON Lines, a formal JSON Schema and independent contract checks are implemented. Trusted source timestamps/freshness, authenticated host identity, cross-source consistency and authenticated stored-trace integrity remain separate design and validation work. See [development and validation](testing.md).
