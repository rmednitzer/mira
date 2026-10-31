# Explicit package-installed investigation

```sh
mira investigate package-installed openssh-server
mira investigate package-installed libc6:arm64 --json
```

The question is: does the local dpkg database record this one package as installed and in good order? It helps confirm a precondition during an investigation, for example that an agent, daemon or rebuilt package is actually present. It is not a vulnerability check.

## Invocation

- `PACKAGE` follows Debian policy name syntax: 2–128 characters from `a-z0-9+.-`, starting with a letter or digit.
- An optional `:ARCH` (1–32 characters from `a-z0-9-`, starting with a letter or digit) restricts matching to that exact `Architecture` value. `:all` matches `Architecture: all` only. There is no `any`, wildcard or native-architecture resolution.
- Uppercase, whitespace, path characters, an empty or repeated qualifier and anything else exit 2 before the database is opened, with a fixed diagnostic and no report. Missing or extra arguments exit 2 with the template's usage line.

Only `/var/lib/dpkg/status` is read, through the existing 32 MiB bounded reader. The whole database is validated as `inspect` validates it, so one malformed stanza anywhere makes the evidence unavailable rather than partially trusted. No dpkg, apt, shell, network, model or privileged helper is run.

## Outcomes

Matching records are stanzas whose `Package` equals the name exactly (and whose `Architecture` equals the qualifier, when given). A record counts as installed only when its state is `installed` and its error flag is `ok`.

| Matching records | Outcome | Reason | Exit |
|---|---|---|---|
| At least one installed with flag `ok` | satisfied | reported_installed | 0 |
| None installed; one or more `half-installed`, `unpacked`, `half-configured`, `triggers-awaited`, `triggers-pending`, or flagged `reinstreq` | indeterminate | incomplete_installation_state | 3 |
| None, or only `not-installed` / `config-files` | not_satisfied | reported_not_installed | 1 |
| Database missing, inaccessible, oversized or malformed, or more than 16 matching records | indeterminate | evidence_unavailable | 3 |

Without a qualifier, one installed architecture of a multiarch package is enough. Selection words (`install`, `hold`, `deinstall`, `purge`, `unknown`) are exported but never decide the outcome: a package on hold is still installed, and a package selected for removal stays installed until dpkg removes it.

## What a result does not mean

An installed record is dpkg's bookkeeping. It does not prove that the files are intact, that a binary runs, or that a service is enabled or healthy. A version string is not a vulnerability verdict: Ubuntu backports security fixes without changing upstream versions, and applicability depends on configuration and runtime. The report therefore carries `vulnerability_exposure: "not_assessed"` alongside `application_health` and `root_cause`. The database can be stale or attacker-influenced, and `local/dpkg` names the interface visible to this process, not an authenticated host.

## Report and compatibility

`--json` emits one report with `investigation_version: 1`, `template: "package-installed/v1"`, `scope: "local/dpkg"`, the expectation (`package`, `architecture` or null), a fixed outcome/reason and `evidence_ref: "#/evidence"`.

The evidence is a report-local dpkg record projection, not an evidence-v1/v2 record: those contracts fix the dpkg value to `installed_count`. It has the evidence-v2 envelope (source, the selector, unverified recording time, unknown freshness, monotonic `elapsed_ms`, status, error kind and fixed failure reason). When observed, `value.records` lists at most 16 matching stanzas in database order, each with `package`, `architecture`, `version`, `selection`, `flag` and `state`. Architecture and version may be null for sparse non-installed stanzas. Database strings are literal and attacker-influenceable: JSON escapes them, and human output prints them escaped. Only the selected package's records are exported, never the rest of the inventory. Backend error messages are never exported.

The [dedicated schema](../schemas/package-installed-v1.schema.json) checks structure, vocabularies, the record limit, that installed records carry an architecture and version, reason-to-outcome agreement and `evidence_unavailable` exactly for unavailable evidence. Consumers must also check that the evidence selector equals the expectation, that every record matches it, and that the reason follows from the records; JSON Schema cannot express those. Existing evidence, capture and investigation formats are unchanged. The history comparator does not accept these reports.

The Debian package installs this guide and the schema. See [ADR 0008](adr/0008-explicit-package-installed.md), [package provenance](package-provenance.md) and [testing](testing.md).
