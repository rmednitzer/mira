# ADR 0013: representative host qualification protocol

Status: **Proposed**, 2026-10-31. Design only; no code, script or CLI change is made by this record. Implementation would follow in a separate PR after review.

## Context

Phase 1's exit criterion is "a representative Ubuntu 26.04 investigation works without elevation, external inference or system mutation, with reproducible fixtures and explicit evidence gaps". The roadmap, testing guide and every ADR state that controlled CI runner checks do not satisfy it. Today the only live evidence comes from two GitHub-hosted runners and one WSL2 development host.

The live checks already exist:
- **procfs:** the evidence, host-investigation and capture validators
- **systemd:** the evidence and investigation validators with `--live-systemd`
- **dpkg:** the package validator
- **journal:** the journal validator
- **boot binding:** the capture validator
- **signatures:** the comparator and capture validator, through `ssh-keygen`

They were written for CI, though, and have three limits:
- **No evidence leaves the host.** A passing run prints one line and nothing durable.
- **Missing infrastructure is a failure.** A host without systemd, journal access or PSI fails the run instead of recording that the check does not apply.
- **The checkout's own build only.** They test `target/debug/mira`, never the binary an operator actually installed.

## Criteria

- Exercise the real CLI on real hosts as an **unprivileged** user, with no mutation, network or inference beyond what the checks already do.
- Distinguish **passed**, **failed** and **not applicable** (with a fixed reason), so that evidence gaps are explicit rather than hidden or counted as failures.
- Produce a small, durable **receipt** that contains no host-identifying data and can be published as qualification evidence.
- Keep the independent validators independent: the receipt reports their results; it does not replace them with checks inside MIRA.
- Run against either the checkout's build or an installed `/usr/bin/mira`, so that packaged binaries are qualified too.
- Never install packages, change configuration or require root on the host being qualified.

## Alternatives

| Option | Consequence |
|---|---|
| A. Status quo | Exit criterion stays unmet; "works on real hosts" stays a claim |
| B. A built-in `mira self-check` | Convenient, but MIRA would be validating itself, which loses the independence the Python validators provide. It would also ship validation logic in the package |
| C. Ask operators to run each validator by hand | No common record; missing infrastructure looks like failure; results are not comparable |
| D. **A qualification runner in the source checkout that runs the existing validators against a chosen binary, classifies each as passed / failed / not applicable, and writes a privacy-reviewed receipt** | Reuses existing, reviewed checks; explicit gaps; a comparable, publishable record |
| E. Remote collection from enrolled hosts | A network, credential and fleet boundary; out of Phase 1 scope (ADR 0004) |

## Proposed decision (option D)

### Runner

`scripts/qualify_host.py --host-class CLASS --receipt NEW_FILE [--binary PATH]` runs from a clean source checkout with the hash-locked schema environment (`requirements-schema.txt`, as for every validator). It:

1. **Refuses root**, refuses an existing receipt path, and refuses a dirty checkout, so that the receipt binds a known source.
2. Uses `--binary` (default `target/debug/mira` after a locked build) for every check. The validators gain one `MIRA_BINARY` environment input, replacing the hard-coded `target/debug/mira` path; that is the only validator change.
3. **Probes preconditions** with read-only checks before each validator:
   - systemd as PID 1, and `systemctl` present
   - `journalctl` present, and a visible PID 1 sentinel
   - `/proc/pressure` present
   - `dpkg` status readable
   - `ssh-keygen` present
   - the `/proc/sys/kernel/random/boot_id` file present
4. Runs every applicable validator once, with a bounded timeout, and records **passed** or **failed**. Inconclusive results (a live value changed during a comparison) are retried at most twice, then recorded as failed with reason `inconclusive`.
5. Records each check whose precondition is absent as **not applicable** with a fixed reason (`no_systemd`, `no_journal_access`, `no_psi`, `no_dpkg`, `no_ssh_keygen`, `no_boot_id`), and never runs it.

### Receipt

The runner writes one JSON receipt (`qualification-receipt-v1`), created exclusively:

| Field | Content |
|---|---|
| `receipt_version` | `1` |
| `source_commit`, `source_tree` | the clean checkout being qualified |
| `binary_sha256`, `binary_origin` | the tested binary; `checkout-build` or `installed` |
| `host_class` | operator-declared, from a closed set (below); not verified |
| `os` | only `ID` and `VERSION_ID` from `/etc/os-release` |
| `architecture` | `dpkg --print-architecture` |
| `systemd_version` | the major version number, or null |
| `capabilities` | the probe results: booleans only |
| `checks` | for each validator: name, result (`passed`, `failed` or `not_applicable`), a fixed reason, and duration |
| `started_unix_ms`, `duration_ms` | unverified wall-clock start and monotonic duration |

The receipt never contains a host name, machine ID, boot ID, user name, IP or MAC address, kernel release string, package list, unit names or any sampled value. Validator output is not copied in; only the exit status and fixed reason are kept. The validators already print only fixed lines and error types.

### Host classes and the Phase 1 exit

| Class | Description | Required for the Phase 1 exit |
|---|---|---|
| `physical-amd64` | bare-metal Ubuntu 26.04 server, amd64 | yes |
| `physical-arm64` | bare-metal Ubuntu 26.04, arm64 | yes |
| `vm` | a full virtual machine with systemd | yes |
| `container` | a container without systemd as PID 1 | yes; most checks expected `not_applicable` |
| `wsl` | WSL2 with systemd enabled | no; recorded when available |
| `ci-runner` | GitHub-hosted runner (already covered by CI) | no |

The proposal is that Phase 1 exits when each required class has one receipt with no **failed** check, every `not_applicable` result matches the class's expected gaps, and the receipts are reviewed. A receipt is evidence about one host at one time, not a fleet guarantee; this is the qualification the existing docs say is missing, not production readiness.

### Expected gaps per class

The protocol documents, per class, which checks are expected to be `not_applicable`. For example, a container is expected to show `no_systemd` and, typically, `no_journal_access`. An unexpected `not_applicable` result, such as `no_psi` on a physical host, is reported as a finding rather than silently accepted.

## Trust, privacy and failure analysis

- **No new runtime boundary.** The runner executes only the existing validators and read-only probes, as the invoking unprivileged user. Nothing is installed, enabled or written outside the new receipt file.
- **Disclosure.** The field list above is closed and reviewed. The OS identity is limited to distribution and version, and the architecture is coarse. The kernel release is deliberately excluded because it can identify patch levels; the systemd major version is kept because preconditions depend on it.
- **Operator assertion.** `host_class` is the operator's claim. The receipt does not prove the host is physical, and reviewers should treat it as declared.
- **Receipt integrity.** A receipt is unsigned unless signed separately. Signing receipts would need a third MIRA signature namespace (ADR 0011) and is an open question.
- **Not applicable versus failed.** A probe that wrongly reports a capability as absent could hide a failure. Probes are read-only and simple, the expected gaps per class are documented, and any unexpected `not_applicable` result is flagged in review.

## Acceptance for implementation

- **Runner tests:** a fake binary and fake probes cover passed, failed, inconclusive-then-retried, and every `not_applicable` reason. They also cover refusal as root, refusal of an existing receipt path, and refusal of a dirty checkout.
- **Receipt checks:** a receipt schema, plus a test that the receipt contains no forbidden data. The test runs the runner on a host-like fixture and scans the receipt for the host name, machine ID, boot ID and user name.
- **`MIRA_BINARY` in every validator,** with CI running the runner against both the checkout build and the extracted package binary. CI publishes its receipt as `ci-runner` evidence.
- **Docs:** a qualification guide covering how to run it, the classes and expected gaps, how to submit a receipt, and what a receipt does not prove.

## Consequences and rollback

Blast radius: one script, one environment input in each validator, a receipt schema, a guide and CI wiring. The runtime package and CLI are unchanged. Reverting removes only tooling. Receipts already published remain historical evidence.

## Open questions for review

1. **Where qualification runs:** from a source checkout with the hash-locked Python environment, as proposed, or as something packaged?
2. **Required classes:** are physical amd64, physical arm64, VM and container the right set for the Phase 1 exit?
3. **Receipt contents:** is the closed field list right? In particular, should the kernel release be excluded, as proposed, or included for compatibility analysis?
4. **Publication and signing:** should receipts be committed to the repository as qualification evidence, and should they be signable under a third namespace?

## Primary references

- [os-release(5)](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)
- [docs/roadmap.md Phase 1 exit](../roadmap.md) and [docs/testing.md](../testing.md)
