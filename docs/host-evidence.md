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

## Validation

`tests/host_evidence.rs` reads a synthetic procfs directory with the same collector used by the CLI. Unit tests cover malformed source content and missing data. Mandatory x64/ARM64 Ubuntu 26.04 CI runs Rust tests and release builds.

## Next criteria

Versioned JSON Lines, a formal JSON Schema and independent contract checks are implemented. Independent source timestamps/freshness, host identity, cross-source consistency and authenticated stored-trace integrity remain separate design and validation work. See [development and validation](testing.md).
