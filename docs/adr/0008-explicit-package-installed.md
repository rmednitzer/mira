# ADR 0008: explicit package-installed expectation

Status: accepted for implementation, 2026-10-31. Native integration qualification remains required.

## Context and criteria

During an investigation an operator often has to confirm whether a specific package is present before reasoning further: is the agent, the daemon or the fixed build installed on this host? MIRA already reads and validates the bounded dpkg status database, but exports only an installed-package count. It deliberately does not export the package inventory. The operator therefore has no machine-readable, evidence-bound answer for one named package, and no way to tell "not installed" apart from "half-installed" or "needs reinstall".

Criteria: reuse the existing bounded dpkg reader and its validation of the whole database, require one explicitly named package (optionally architecture-qualified), keep evidence and assessment separate, keep unavailable and incomplete states indeterminate, export only the records for that one name, introduce no command execution or new source, and leave existing commands, reports and schemas byte-for-byte unchanged. The result must not be presentable as a vulnerability-exposure finding (SEC-03).

## Alternatives and decision

| Option | Consequence |
|---|---|
| No change; ask dpkg or apt directly | Works interactively, but mixes command execution into evidence, has no fixed contract and no unknown handling |
| Export the full inventory in evidence | Large disclosure and a large contract for a one-package question; the evidence contract deliberately excludes it |
| Version comparison (`>=`, `<<`) | Needs dpkg version ordering and invites "fixed/affected" readings that package versions alone cannot support (backports). Defer to Phase 2 advisory work |
| Treat every non-`installed` state as not installed | Hides half-installed, unpacked and reinstall-required packages, which are exactly the cases worth flagging |
| Explicit presence check for one name, exporting only its records | Chosen: narrow disclosure, deterministic, keeps incomplete states indeterminate |

Add `mira investigate package-installed PACKAGE[:ARCH] [--json]`.

- PACKAGE follows Debian policy syntax: at least two characters from `a-z0-9+.-`, starting with a letter or digit, at most 128 characters. ARCH is 1–32 characters from `a-z0-9-`, starting with a letter or digit. Uppercase, whitespace, path characters, an empty or repeated qualifier, and anything else exit 2 before acquisition.
- Read only `/var/lib/dpkg/status` through the existing 32 MiB bounded reader. The whole database is validated as it is today, so a malformed stanza anywhere makes the evidence unavailable.
- Matching records are those whose `Package` equals PACKAGE exactly and, when ARCH is given, whose `Architecture` equals ARCH exactly. `name:all` is an exact match too; there is no `any`, wildcard or `native` resolution.
- A record counts as installed only when its state is `installed` and its error flag is `ok`.

| Matching records | Outcome | Reason | Exit |
|---|---|---|---|
| At least one installed with flag `ok` | satisfied | reported_installed | 0 |
| None installed; at least one in `half-installed`, `unpacked`, `half-configured`, `triggers-awaited`, `triggers-pending`, or flagged `reinstreq` | indeterminate | incomplete_installation_state | 3 |
| None, or only `not-installed`/`config-files` | not_satisfied | reported_not_installed | 1 |
| Database missing, inaccessible, oversized or malformed; more than 16 matches | indeterminate | evidence_unavailable | 3 |

Selection words (`install`, `hold`, `deinstall`, `purge`, `unknown`) are exported literally but do not decide the outcome, consistent with the existing rule that selection must not hide installed provenance.

## Contract, trust and validation

A separate package-installed-v1 schema identifies template `package-installed/v1`, scope `local/dpkg`, the expectation (package, optional architecture), a fixed outcome/reason and `evidence_ref: "#/evidence"`. `application_health`, `vulnerability_exposure` and `root_cause` are all `not_assessed`.

The evidence is a report-local dpkg record projection, not an evidence-v1/v2 record. Those contracts fix the dpkg value to `installed_count`, and widening them would change existing consumers. It carries the same envelope as evidence-v2 (source, unverified recording time, unknown freshness, monotonic elapsed time, status, error kind, fixed failure reason) and, when observed, at most 16 records with package, architecture, version, selection, flag and state. Version and architecture may be null for sparse non-installed records. Strings are literal, attacker-influenceable database text: JSON escapes them and human output prints them escaped. The history comparator does not accept these reports.

The schema checks structure, selector-to-record matching, reason-to-outcome and availability agreement. A separate validator re-derives the outcome from the records, and compares live CLI reports with its own independent bounded parse of the status file.

Before merge: native synthetic tests for every state and flag, multiarch with and without a qualifier, `all`, sparse records, exact-name matching (prefixes, superstrings, case), malformed and oversized databases and the match limit; refused selectors and invocations; frozen JSON for one report; independent valid/invalid fixtures; live CLI agreement with the independent parse on both native architectures; packaging checks; exact-head review and post-merge checks.

## Limits

An installed record is dpkg's local bookkeeping, not proof that the files are intact, the binary runs or the service is enabled. A version string is not a vulnerability verdict: Ubuntu backports fixes without changing upstream versions, and applicability depends on configuration and runtime. The database can be stale or attacker-influenced. `local/dpkg` names the interface visible to this process, not an authenticated host.

## Consequences, reversibility and rollback

Blast radius: one opt-in template, a report schema, documentation and tests, plus an internal refactor that lets the existing parser visit each validated record. Existing `packages::parse_status` behaviour and the installed-count evidence are unchanged and stay covered by their tests. No new source, privilege, persistence, network path or automatic action. Revert the command, module, schema, validator and packaged files together. No operational state requires rollback.

Primary references: [Debian Policy 5.6.7 Package](https://www.debian.org/doc/debian-policy/ch-controlfields.html#package) and [dpkg(1) package states](https://manpages.debian.org/dpkg.1).
