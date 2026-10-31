# ADR 0013: representative host qualification protocol

Status: **Accepted**, 2026-10-31 (proposed and reviewed the same day, through three review rounds). Design only; no code, script or CLI change is made by this record. Implementation follows in a separate PR with its own review.

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

## Decision (option D)

### Runner

`scripts/qualify_host.py --host-class CLASS --receipt NEW_FILE [--binary PATH]` runs from a clean source checkout with the hash-locked schema environment (`requirements-schema.txt`, as for every validator). It:

1. **Refuses root**, refuses an existing receipt path, and refuses a dirty checkout, so that the receipt binds a known source.
2. Uses `--binary` (default `target/debug/mira` after a locked build) for every check. The validators gain a four-part contract and change in no other way:
   - **Binary input:** a `MIRA_BINARY` environment input replaces the hard-coded `target/debug/mira` path.
   - **Inconclusive status:** today a comparison spoiled by a changing live value raises the same `ValueError` as wrong evidence and exits 1. A shared `Inconclusive` exception (in `scripts/validation_status.py`) is raised instead wherever a validator detects that a live sample changed mid-comparison, and the top-level handlers map it to **exit 4**. The exit codes become 0 passed, 1 failed, 4 inconclusive. The message stays the fixed exception type, so no sampled value is printed.
   - **Check groups:** each validator declares fixed group names (`--list-groups`) and runs only the selected ones with `--only GROUP[,GROUP]`. For example, the capture validator splits into `schema`, `cli`, `compare`, `live-boot` and `signed-compare`. A missing `ssh-keygen` then makes only `signed-compare` not applicable, and a missing boot ID only `live-boot`; the other capture groups still run. Without `--only`, every group runs, as today.
   - **Observation gaps:** a validator can pass while MIRA correctly reported a source as unavailable. For example, the pressure validator accepts an unavailable PSI file with exit 3. When `MIRA_QUALIFICATION_STATUS` names a new file, each validator writes the unavailable observations it saw there: only fixed source identifiers (such as `/proc/pressure/io` or `journal/system`) with their fixed `failure_reason`, and never values. A passing group can therefore still carry gaps.
3. **Probes preconditions** with read-only checks before each check group:
   - systemd as PID 1, and `systemctl` present
   - `journalctl` present; separately, a visible PID 1 sentinel (only for groups that need readable journal events, see below)
   - `/proc/pressure` present
   - `dpkg` status readable
   - `ssh-keygen` present
   - the `/proc/sys/kernel/random/boot_id` file present
4. Runs each applicable check group once (`--only GROUP`), with a bounded timeout. Exit 0 is **passed** and exit 1 is **failed**. Exit 4 (**inconclusive**) is retried at most twice, then recorded as failed with reason `inconclusive`. Any other exit status, a timeout, or a validator that cannot start is failed with reason `runner_error`.
5. Records each check group whose precondition is absent as **not applicable** with a fixed reason (`no_systemd`, `no_journal_access`, `no_psi`, `no_dpkg`, `no_ssh_keygen`, `no_boot_id`), and never runs it.
6. **Denial paths stay applicable.** A precondition never gates the check that validates MIRA's own handling of that missing capability. The journal validator therefore splits into `live-visibility`, which needs only `journalctl` and compares MIRA's `journal_visible` and `journal_access_complete` answers with the validator's independent ones, including when they are false, and `live-counts`, which additionally needs a visible sentinel. On the `restricted-user` run, `live-visibility` is expected to **pass** with `journal_not_visible` or `journal_access_incomplete` confirmed, and only `live-counts` is `not_applicable` (`no_journal_access`). Missing access is thus tested, not merely recorded. The same rule applies to any later denial-path check.

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
| `kernel_series` | only the kernel `major.minor` (for example `6.17`), from `/proc/sys/kernel/osrelease`; never the full release string |
| `capabilities` | the probe results: booleans only |
| `checks` | for each validator check group: validator, group, result (`passed`, `failed` or `not_applicable`), a fixed reason, duration, and `observation_gaps`, the unavailable source identifiers with their fixed failure reasons as reported through `MIRA_QUALIFICATION_STATUS` |
| `started_unix_ms`, `duration_ms` | unverified wall-clock start and monotonic duration |

The receipt never contains a host name, machine ID, boot ID, user name, IP or MAC address, full kernel release string, package list, unit names or any sampled value. Validator output is not copied in; only the exit status and fixed reason are kept. The validators already print only fixed lines and error types.

### Host classes and the Phase 1 exit

| Class | Description | Required for the Phase 1 exit |
|---|---|---|
| `physical-amd64` | bare-metal Ubuntu 26.04 server, amd64 | yes |
| `physical-arm64` | bare-metal Ubuntu 26.04, arm64 | yes |
| `vm` | a full virtual machine with systemd | yes |
| `container` | a container without systemd as PID 1 | yes; most checks expected `not_applicable` |
| `restricted-user` | not a host type but a second run, on any required host, as a user outside `adm` and `systemd-journal` | yes; exercises `journal_not_visible` / `journal_access_incomplete` on a real host |
| `wsl` | WSL2 with systemd enabled | no; recorded when available |
| `ci-runner` | GitHub-hosted runner (already covered by CI) | no |

Phase 1 exits when each required class (including the `restricted-user` run) has one receipt with no **failed** check group, every `not_applicable` result matches the class's expected gaps, and the receipts are reviewed. A receipt is evidence about one host at one time, not a fleet guarantee; this is the qualification the existing docs say is missing, not production readiness.

### Expected gaps per class

The protocol documents, per class, which check groups are expected to be `not_applicable` and which observation gaps are expected. For example, a container is expected to show `no_systemd` and, typically, `no_journal_access`; a kernel without PSI is expected to show `/proc/pressure/*` gaps. Review applies equally to both: an unexpected `not_applicable` group, or an unexpected observation gap inside a **passed** group, such as `/proc/pressure/io` unavailable on a physical host, is a finding. The Phase 1 exit requires both kinds to match the class's expected list, not just the absence of failed groups.

## Trust, privacy and failure analysis

- **No new runtime boundary.** The runner executes only the existing validators and read-only probes, as the invoking unprivileged user. Nothing is installed, enabled or written outside the new receipt file.
- **Disclosure.** The field list above is closed and reviewed. The OS identity is limited to distribution and version, and the architecture is coarse. Only the kernel series (`major.minor`) is kept, because PSI and other preconditions depend on it; the full release string is excluded because it can identify patch levels. The systemd major version is kept for the same reason as the kernel series.
- **Operator assertion.** `host_class` is the operator's claim. The receipt does not prove the host is physical, and reviewers should treat it as declared.
- **Receipt integrity.** A receipt is unsigned unless signed separately. Signing receipts would need a third MIRA signature namespace (ADR 0011) and is an open question.
- **Not applicable versus failed.** A probe that wrongly reports a capability as absent could hide a failure. Probes are read-only and simple, the expected gaps per class are documented, and any unexpected `not_applicable` result is flagged in review.

## Acceptance for implementation

- **Validator contract tests:** for each validator with a live comparison, a forced mid-comparison change exits 4 and wrong evidence still exits 1. These cover procfs, systemd, dpkg, uptime/kernel, journal and boot binding.
- **Runner tests:** a fake binary and fake probes cover passed, failed, inconclusive-then-retried, and every `not_applicable` reason. They also cover refusal as root, refusal of an existing receipt path, and refusal of a dirty checkout.
- **Denial-path test:** with `journalctl` present but no visible sentinel, the runner runs `live-visibility`, which must pass and confirm `journal_not_visible`, and records only `live-counts` as `not_applicable`.
- **Group and gap tests:** each validator lists its groups, and `--only` runs exactly the selected ones. A capture run without `ssh-keygen` still passes its other groups. A pressure run with one unreadable PSI file passes and reports that source in `observation_gaps`, and the runner flags it as unexpected for a physical-host class.
- **Receipt checks:** a receipt schema, plus a test that the receipt contains no forbidden data. The test runs the runner on a host-like fixture and scans the receipt for the host name, machine ID, boot ID and user name.
- **`MIRA_BINARY` in every validator,** with CI running the runner against both the checkout build and the extracted package binary. CI publishes its receipt as `ci-runner` evidence.
- **Docs:** a qualification guide covering how to run it, the classes and expected gaps, how to submit a receipt, and what a receipt does not prove.

## Consequences and rollback

Blast radius: one script and a four-part contract in each validator (binary input, inconclusive exit, selectable groups, observation-gap report), a receipt schema, a guide and CI wiring. The runtime package and CLI are unchanged. Reverting removes only tooling. Receipts already published remain historical evidence.

## Review decisions

1. **Where qualification runs:** from a clean source checkout with the hash-locked Python environment. This keeps the validators independent of the `mira` binary and keeps the runtime package Python-free. Qualification is an occasional engineering task, not part of every installation.
2. **Required classes:** `physical-amd64`, `physical-arm64`, `vm` and `container`, plus a `restricted-user` run on one of them as a user outside `adm` and `systemd-journal`. That run exercises the journal visibility and access gaps on a real host, not only through the fixture.
3. **Receipt fields:** the closed list, with the kernel limited to `kernel_series` (`major.minor`). The full release string stays excluded.
4. **Publication and signing:** reviewed receipts are committed under `docs/qualification/receipts/`, each in its own PR, so review and git history provide custody. Receipts are not signed for now. Signing would need a third ADR 0011 namespace and a standalone `mira sign` command, which is deferred until receipts come from contributors other than the maintainers.

## Primary references

- [os-release(5)](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)
- [docs/roadmap.md Phase 1 exit](../roadmap.md) and [docs/testing.md](../testing.md)
