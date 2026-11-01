# Development and validation

## Dependency boundaries

The Rust CLI has no external Rust crate dependencies. Normal builds and the CLI-only Debian package require no Python. The non-default `test-support` Cargo feature admits only a native subprocess fixture binary; it adds no runtime capability to MIRA. The package installs only `mira`, never the fixture.

Python and `jsonschema` are separate developer tooling for independent JSON Schema validation, the optional offline comparison script and the host qualification runner. They are not CLI runtime dependencies. The complete dependency closure is pinned by version and wheel SHA-256 in `requirements-schema.txt`. Installations require hashes and binary wheels; source builds are refused. Capture and investigation validation reuse its existing referencing dependency to register the local evidence schema without network retrieval.

## Rust checks

Use the repository toolchain from `rust-toolchain.toml`:

```sh
rustup install
cargo fmt --all -- --check
cargo clippy --all-targets --features test-support --locked -- -D warnings
cargo test --all-targets --features test-support --locked
cargo build --release --locked
```

`cargo test --all-targets --locked` remains a Python-free core suite. Enable `test-support` for the full native subprocess integration suite. Cargo builds its fixture and supplies `CARGO_BIN_EXE_*` paths to integration tests; no ad-hoc compiler invocation, shell or global environment mutation is used. `default-run = "mira"` keeps ordinary `cargo run -- ...` unambiguous.

The tests replace `systemctl` only in a per-child PATH pointing at a newly created temporary directory. The fixture verifies the production argument vector and exercises valid large output, oversized/malformed/non-UTF-8 output, failed exit, execution timeout and inherited stdout. Its inherited writer exits after five seconds; this tests the collector's three-second deadline, not arbitrary descendant containment. Fixture directories are removed by their owning test. Investigation cases additionally exercise closed template admission, three outcomes, unavailable evidence, aliases, independent load/active semantics and escaped human output.

The default native CLI suite also supplies non-UTF-8 command, scope, option and argv[0] bytes. Each must return usage exit 2 with empty stdout and a fixed diagnostic, before collector or demo dispatch; no Python fixture is involved.

Host parser regressions validate both uptime fields, malformed/overflow inputs and legitimate aggregate idle time above uptime. The source-to-JSON regression preserves independent memory evidence when uptime is malformed.

The retained coordination simulation has an exhaustive arbitration matrix in `tests/arbitration.rs`. It covers all 720 combinations of the four modes, six human inputs, six agent inputs and five grants. The inputs are absent, current safe, current unsafe, past, future and mislabeled; the grants are absent, expiring now, valid, unbounded and human-labelled. Each case is checked against an authored policy table and against invariants that are stated independently of the implementation: human precedence, the conditions under which state may move, the paths by which an agent may act, mislabeled-equals-absent, grants mattering only in Delegated mode, and determinism. A further test fixes goal-over-timeout precedence and terminal immutability. These tests pin arbitration behavior for caller-supplied data; they do not authenticate actors or grants.

## Independent evidence checks

```sh
python3 -m venv .schema-venv
.schema-venv/bin/python -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements-schema.txt
.schema-venv/bin/python -m pip check
.schema-venv/bin/python scripts/test_schema_lock.py
cargo build --locked
.schema-venv/bin/python scripts/test_live_procfs.py
.schema-venv/bin/python scripts/validate_evidence_schema.py
.schema-venv/bin/python scripts/test_compare_evidence.py
.schema-venv/bin/python scripts/validate_investigation_schema.py
.schema-venv/bin/python scripts/validate_capture_schema.py
.schema-venv/bin/python scripts/validate_memory_investigation.py
.schema-venv/bin/python scripts/validate_pressure_investigation.py
.schema-venv/bin/python scripts/validate_package_investigation.py
.schema-venv/bin/python scripts/validate_host_investigations.py
.schema-venv/bin/python scripts/validate_journal_investigation.py
.schema-venv/bin/python scripts/validate_session.py
.schema-venv/bin/python scripts/test_validation_contract.py
.schema-venv/bin/python scripts/test_qualify_host.py
```

On an unprivileged Ubuntu 26.04 host with a system bus and `systemd-journald.service`, add `--live-systemd` to both evidence and investigation validators. CI requires this live comparison on both native architectures; local synthetic checks do not require systemd. Direct state is sampled before and after MIRA; changing fixture state makes the comparison inconclusive and fails the check. This validates one host service, not application health or fleet-wide compatibility.

On an unprivileged Linux host with readable procfs, add `--live-procfs` to the evidence validator. Native CI requires it on both architectures. Independent bounded direct reads surround `mira inspect --json`: kernel release and MemTotal endpoint samples must agree and match MIRA, while whole uptime must fall inclusively between direct whole-second samples. Changed endpoints or reversed uptime make the check inconclusive and fail; required unavailable observations also fail. No retry hides a disagreement. Tests demonstrate that schema-valid but wrong values are refused and that valid interval endpoints and fluctuating available memory pass.

The direct uptime parser uses integer whole seconds, including values above 2^53, without float conversion. MemAvailable and PSI fluctuate non-monotonically, so direct endpoint values cannot bound their intermediate samples; their existing schema, range and synthetic source checks remain separate. Package counts are not directly compared here. The check emits a fixed success line and disagreement diagnostics without sampled values; it does not upload captures or authenticate the host, clock or source. This controlled CI comparison does not close representative physical-host or fleet qualification.

## Packaging checks

Native Ubuntu 26.04 amd64/arm64 CI builds and inspects the package, checks checksums, executes the extracted CLI, exercises isolated dpkg install/reinstall/remove/purge, and runs lintian. It checks evidence-v1/v2, investigation-v1/v2, memory-headroom-v1, pressure-ceiling-v1, package-installed-v1, uptime-minimum-v1, kernel-release-v1, journal-events-v1, capture-v1/v2/v3, challenge-v1, session-v1 and session-request-v1 schemas and their packaged guides, rejects systemd units, maintainer scripts and the native test helper in the package, and asserts package-root/document permissions. Archive metadata must advertise exactly `Suggests: systemd, default-dbus-system-bus | dbus-system-bus, openssh-client` and no `Recommends`; native ELF requirements remain generated in `Depends`. See the [runtime relationship rationale](debian-packaging.md#runtime-package-relationships).

Repeated assembly compares the same binary under ordinary and restrictive (`077`) invoking umasks. The builder normalizes its own umask to `022`; source timestamps use exported `SOURCE_DATE_EPOCH`. This verifies archive assembly under those conditions. A separate fresh-build test compiles twice from independent git archives and target directories, varies source/target paths, timezone and umask, and compares raw binaries and full packages against the selected artifacts. Its scope is one native runner/compiler/system dependency environment, not independent-host or hermetic compilation. The isolated dpkg root bypasses dependency enforcement. A separate native disposable Ubuntu 26.04 container installs the exact package through apt without bypassing dependencies, checks installed binary bytes and runs the installed demo/capture contract. Its receipt binds source commit/tree, package/binary digests and container image identity. This is container loader/dependency evidence; clean physical-host behavior, genuine upgrades/downgrades and signed release provenance remain release gates.

The release binary must not contain any test-only override string (`MIRA_TEST_SSH_KEYGEN`, `MIRA_TEST_JOURNALCTL`, `MIRA_TEST_JOURNAL_DIRS`, `MIRA_TEST_PROC_ROOT`, `MIRA_TEST_RANDOM_SOURCE`), which shows the overrides are compiled out without `test-support`.

Generated /target, /.schema-venv, /dist and /package-extract trees and Python bytecode are ignored by Git. These rules do not protect arbitrary captures or secret-bearing files; keep evidence custody in an operator-controlled private directory.

## Review and CI

CI runs on PRs and pushes to `main`, avoiding duplicate branch-push builds. New work on the same workflow/ref cancels obsolete runs. CI tokens retain least-privilege permissions and actions remain SHA-pinned. Inspect exact-head Codex review receipts, formal reviews and inline threads before merge; green checks alone are insufficient. Confirm post-merge source identity and CI.

## Primary guidance

- [Cargo targets and binary integration fixtures](https://doc.rust-lang.org/cargo/reference/cargo-targets.html)
- [Cargo test target selection](https://doc.rust-lang.org/cargo/commands/cargo-test.html)
- [Reproducible Builds: environment variations and permissions](https://reproducible-builds.org/docs/env-variations/)

## Investigation-specific acceptance

The [decision record](adr/0001-read-only-service-investigation.md) precedes the implementation. Native unit and CLI fixtures cover the supported state table and negative paths; `tests/fixtures/investigation-v1.json` and `tests/fixtures/investigation-v2.json` contain independent valid and deliberately invalid reports. The v2 fixtures include not-found contradictions in both directions and version/template mismatches; the v2 schema alone rejects each v2-specific contradiction. Unit tests freeze the v1 JSON byte for byte and check the full v2 rule table. The live check additionally queries a deliberately undefined unit name and requires v1 `reported_not_active` and v2 `unit_not_found`. Its validator checks structure, source/scope identity, evidence binding, assessment semantics and exit-code agreement. Unknown/error/transient cases cannot become satisfied results. Existing evidence-v1 compatibility is checked separately. The live sample compares both embedded state and assessment with stable direct systemctl observations, not application health.

## Capture acceptance and authored matrix

`tests/capture.rs` freezes eight source/availability cases before execution: complete host, complete pressure, malformed memory, malformed uptime, missing CPU PSI, missing memory PSI, malformed IO PSI and unavailable optional IO outside the host profile. Results come from the actual collectors. `tests/fixtures/capture-v1.json` supplies nine valid and twenty-two invalid independent documents for structural and semantic admission. These authored synthetic cases are not a representative fleet benchmark.

`tests/fixtures/evidence-v1.json` and the capture fixtures also exercise the producer's lexical contract for observed strings. The negative cases are kernel releases with a space, a trailing newline, an escape sequence, empty or 257 characters; unit IDs that are not `.service`, start with `-`, have a truncated `\x` escape or end in a newline; non-ASCII, newline-terminated, empty or overlong states; an observed scope with a space; and capture kernel/scope values ending in a newline or U+00A0. Each was confirmed to pass the previous schemas, so each one tests the tightening. A literal state containing an escape sequence remains a valid case, matching the native fixture that requires it to be observed and escaped in human output.

Timeline (capture-v2) acceptance: unit tests fix the wall-clock rule at both tolerance regimes (the 50 ms floor and 1% of a 10 s window, each one millisecond either side), backwards steps and missing edges. They also freeze capture-v1 and capture-v2 rendering for one synthetic capture. `tests/capture.rs` checks, for both profiles, that timeline sources equal the profile order, that offsets never decrease and stay within the window, and that capture-v2 equals capture-v1 with only the version changed and timing members inserted before byte-identical records. `tests/cli_arguments.rs` checks that `--timeline` is opt-in, that the option order is fixed, that repeated options are refused and that `--timeline` cannot become a label. `tests/fixtures/capture-v2.json` holds ten valid and thirty-one invalid documents, including the future boot-binding shapes. `scripts/validate_capture_schema.py` requires nineteen invalid documents to fail the schema and exactly twelve to fail only the semantic timeline checks (order, elapsed agreement, offset bounds, the wall-clock rule recomputed independently, boot-window order and availability). It also checks live `--timeline` captures, that the boot ID is never collected without a request, and value comparison of capture-v2 alone and mixed with capture-v1.

Boot binding acceptance: parser unit tests cover strict boot-ID syntax (case, missing or extra newline, missing or misplaced hyphens, wrong length, non-hex and non-ASCII bytes). They also check that centisecond uptime keeps kernel resolution, truncates extra digits, accepts exactly u64::MAX centiseconds and refuses one more, while whole-second parsing is unchanged. A pure `bind_boot` test covers agreeing samples, a changed ID, a reversed window and first-failure precedence. `tests/capture.rs` checks that no binding is attempted without a request. With a request it checks a missing file (`not_found`), malformed and unterminated IDs (`malformed_data`), an oversized file (`limit_exceeded`), and malformed uptime, which makes both the uptime record and the binding unavailable. It checks that binding failure never changes `all_available` and that the boot ID never reaches capture-v1. CLI tests cover `--bind-boot` implying the timeline, fixed order, repeated options and option-shaped labels. The live check in `scripts/validate_capture_schema.py` reads the boot ID and centisecond uptime directly before and after three bound captures. It requires the exported ID to equal the direct read and the uptime window to sit inside the direct interval, and fails as inconclusive if the boot changes. It also checks that `--bind-boot` alone and `--timeline --bind-boot` give the same shape.

Comparison-v3 acceptance: `scripts/test_compare_evidence.py` covers every row of the ordering table. That includes strictly separated windows in both directions, a one-centisecond gap, touching, nested and identical windows (all `overlapping`), different boot IDs, unrequested and unavailable bindings, and the absence of any freshness claim in `timing`. It also checks the window policy on both sides and when unset, identical value rows against the comparison-v2 result for the same records, the policy refused for mixed or legacy input, and inconsistent timelines (a reversed boot window, a mislabeled wall clock) refused before comparison. CLI tests cover reported timing and refused negative, non-integer and fractional policies with exit 2 and no output. The live capture check compares two consecutive bound captures and requires `same_boot_reported`, an order that is never reversed, and both windows within a 60 s policy.

Signing acceptance ([ADR 0011](adr/0011-host-identity-and-capture-integrity.md)): `tests/signature.rs` runs the real `/usr/bin/ssh-keygen` with throwaway keys. It signs capture-v1, capture-v2 (pressure and boot-bound) and every investigation template's JSON output, and verifies each with `mira verify` and independently with `ssh-keygen -Y verify` over the printed bytes. Verification refuses a modified byte, the other kind's namespace, a signature for another file, an unknown key, a key listed for another principal, an expired `valid-before`, a revoked key, a garbage signature, invalid principal syntax and unknown leading bytes; two keys for one principal both verify. Signing with an encrypted key and no terminal or agent, with a missing key, or onto an existing path exits 4 with no stdout and no signature, and never overwrites an existing file. Signing human, JSONL or demo output and malformed `verify` invocations are usage errors. A FIFO or device given as the document is refused without blocking. Two fixture tests cover the staged self-check. One reproduces the reported attack: during a failing self-check, the output's parent is swapped for a symlink into a victim directory, and the victim file must survive. The other checks that the self-check read a staged copy, not the output path, from a mode-0700 `mira-signature-*` directory that no longer exists afterwards. Both fail against the earlier in-place check. `scripts/test_compare_evidence.py` covers comparator verification. Verified captures report `integrity`. A modified byte, a missing signature, the other kind's namespace and the wrong principal are each refused, as are legacy input, invalid principal syntax and a missing `ssh-keygen`. Mixing verified and unverified sides is refused. A race test replaces the file at the moment verification runs and requires the comparison to use the verified bytes. CLI tests require both trust options together and fail closed. The live capture check signs two real captures with `mira` and verifies them through the comparator. `tests/signature_process.rs` (test-support) points MIRA at the native fixture, which checks the exact argv of `-Y sign`, `-Y check-novalidate` and `-Y verify` (with and without `-r`). It confirms that refusal, unarmored or oversized output, a failed self-check, an argv mismatch and a missing tool each exit 4 with nothing printed and no signature left, and that verification trusts only the exit status. The refactored `systemctl` runner still passes every `tests/systemd_process.rs` case.

Challenge acceptance ([ADR 0014](adr/0014-consumer-challenge-freshness.md)): unit tests in `src/challenge.rs` fix the challenge syntax (exactly 64 lowercase hex), strict decimals (1–16 digits, no sign or leading zero), the exact challenge-v1 layout and every outcome of the freshness check: within policy at both boundaries, `older_than_policy` one millisecond over, `issued_in_future`, `challenge_mismatch` for another or truncated value, and `not_challenged` for capture-v1, capture-v2 and investigation prefixes. `src/capture.rs` checks that capture-v3 equals capture-v2 with only the version changed and the challenge inserted after it. `tests/challenge.rs` runs the real `ssh-keygen` with throwaway keys. It checks that two `mira challenge` runs differ and match the fixed layout, and that challenged captures for both profiles, with and without boot binding, verify with an age bound and also as plain signed documents. Each fixed failure reason is reachable: another challenge, capture-v2 and capture-v1 input, an issue time in the future, an old issue time, a modified byte and a wrong signature, with a signature refusal reported before a malformed challenge file. Malformed challenges and unsigned, misplaced or repeated `--challenge` exit 2 with no output or signature file. Oversized, unterminated or non-regular challenge files, bad `--max-age-ms` values and a freshness option without its partner exit 2, a missing challenge file exits 4, and a FIFO challenge file is refused without blocking. A test-support test points the random source at a short file and a missing path and requires exit 4 with no output. Stage 2: `scripts/test_compare_evidence.py` checks that capture-v3 compares like capture-v2, alone and mixed, and that answered challenges report both age bounds through an injected clock. It refuses an issue time in the future, an age over policy, a capture answering another challenge, one challenge for both sides, a missing side, a challenge without verification, freshness without integrity, capture-v2 input, and a challenge moved away from the fixed prefix. A signed document with a second `challenge` key is refused as a duplicate. Challenge files must have the exact layout: no newline, two newlines, spacing, uppercase, a leading zero, a sign, seventeen digits, an extra member, another version, an oversized file and a FIFO are all refused. CLI tests require the three freshness options together and with trust, and refuse bad policies and swapped or shared challenge files. `scripts/validate_capture_schema.py` derives capture-v3 cases from every capture-v2 fixture. It refuses a missing, malformed or non-string challenge and a capture-v2 document carrying one, keeps every semantic capture-v2 refusal for v3, and checks the closed challenge-v1 schema. Its live `challenge` group (gated on `ssh-keygen` by the qualification runner) answers two `mira challenge` values in signed captures and checks freshness through both the comparator and `mira verify`.

`tests/source_bounds.rs` adds a default-suite acquisition matrix: seven fixed sources, valid input exactly at the documented limit, one byte over, and invalid UTF-8 within the limit. It exercises the real capture path and checks that only the selected source fails, the six other observations remain available and completion is preserved. The dpkg case includes an actual 32 MiB input; this is boundary regression evidence, not a throughput or hostile-filesystem deadline claim.

The comparator suite covers duplicate keys at nested levels, nonfinite/overflow numbers, decimal/exponent encodings that previously lost precision, invalid Unicode, excess depth, empty input, FIFO replacement at open, symlink compatibility and files growing after descriptor inspection. Importer regressions exercise both legacy JSONL and complete captures, preserve exact adjacent integers above 2^53, and require CLI refusal with no comparison output. Failure-reason tests reject specifically mapped kinds under io_failure while preserving generic Other and future I/O kinds. The actual CLI capture is checked independently for exact sources, exit status, scope binding, mixed-format refusal and preserved completion. Schemas do not establish source authenticity.

Run `bash packaging/test-clean-install.sh dist/mira_VERSION_ARCH.deb dist/clean-install-receipt.json` only with Docker, the schema venv and a clean committed checkout. It pulls a native Ubuntu 26.04 image, records its immutable identity, uses apt repositories for real dependency resolution and removes the container. The receipt must be a new file. It contains no captured host values, credentials or user identities. It is an unsigned integrity/test receipt, not independent provenance or a release attestation. No retained distinct-version release baseline is available in this foundation; same-version reinstall must not be relabeled as upgrade qualification.

Successful native CI retains the installation receipt for 30 days as a separate artifact; no host capture values are uploaded. PR receipts can identify GitHub’s synthetic merge checkout rather than the branch tip. The receipt remains unsigned and does not establish independent provenance.

## Tooling lock and fresh compilation

[ADR 0003](adr/0003-locked-tooling-and-fresh-builds.md) records the design, alternatives and limits. The lock admits standard-ABI CPython 3.12/3.14 glibc-Linux x86_64/aarch64 wheels. Native CI runs Python 3.14; local Python 3.12 checks are separate evidence. Other interpreters, free-threaded ABIs and source distributions are not admitted. The runtime package still requires no Python or external Rust crates.

Maintain the complete dependency closure together. Obtain exact-version metadata and candidate wheels from the publisher's PyPI records, verify downloaded SHA-256 values, inspect dependency markers and retain hashes for each intended native profile. Review version and hash changes in one PR and run the complete native matrix. Do not accept a new digest merely because a hash mismatch prints it. `test_schema_lock.py` acquires the admitted closure, changes a wheel locally and requires pip's hash-mismatch refusal without installing it. This does not audit the publisher or eliminate index/mirror availability dependencies.

`bash packaging/test-rebuild.sh PACKAGE.deb NEW_RECEIPT.json` requires a clean committed checkout, the pinned Rust toolchain and native Debian tools. It uses two fresh git archives and independent Cargo target directories, compares their raw binaries and complete `.deb` files with the selected artifacts, and emits a new source/toolchain/artifact-bound receipt only after byte equality. No normalization hides a difference. The compiler, system libraries and package metadata are shared on that runner; different-host/compiler reproduction is not established. Both receipts are retained in each native CI artifact for 30 days.

Successful native CI retains the tested candidate `.deb` and its checksum with both validation receipts for 30 days. This preserves real prior package bytes for a future genuinely different version, without publishing a release or fabricating an upgrade. Retention is temporary; durable release archival and provenance need their own reviewed policy.

The schema lock covers the validation libraries and their transitive wheels. It does not lock the Python interpreter, pip bootstrap, rustup distribution or apt repository state. Those remain separate build-environment trust and availability dependencies.

## Memory expectation acceptance

[ADR 0005](adr/0005-explicit-memory-headroom.md) defines an explicit positive KiB minimum, not a default health threshold. Native tests use only a synthetic meminfo file for below/equal/above/zero-available/above-total/u64-limit cases, malformed and missing evidence, and refused CLI criteria. Seven valid and fourteen invalid independent reports exercise schema, value consistency and assessment binding. The independent validator checks actual CLI report/exit agreement for minimum 1 and u64::MAX; these are consistency checks on current evidence, not promises of a particular live outcome or workload allocation.

Memory-source regressions reject signed, fractional, exponent and non-ASCII numeric text in both retained meminfo fields. They check that a positive memory criterion remains indeterminate with InvalidData. Capture regressions additionally reject Unicode separators and verify six independent observations plus collection completion remain preserved. Ordinary ASCII whitespace and zero available remain valid; these tests do not authenticate the source.

PSI, kernel-release and dpkg Status regressions apply the same rule: Unicode separators (U+00A0, U+2003, U+3000, U+0085) inside PSI lines or Status words, and Unicode whitespace around a kernel release, produce malformed evidence. A PSI `avg10` hidden behind a Unicode separator is not admitted, and a duplicate `avg10` hidden inside an ignored field after a valid one is rejected rather than ignored. ASCII spaces and tabs remain valid. Each regression was confirmed to fail against the previous Unicode-aware splitting and trimming.

## Pressure expectation acceptance

[ADR 0007](adr/0007-explicit-pressure-ceiling.md) defines an explicit per-resource ceiling on PSI `some avg10` in basis points, not a default stall threshold. `tests/pressure_investigation.rs` uses synthetic pressure files for each of cpu, memory and io: zero, below, equal and above the ceiling, both 0 and 10000 bounds, and a high `full` value with a low `some` value that must still be within the ceiling. It checks that a malformed or extreme file for one resource cannot affect another, and that malformed, duplicated, Unicode-separated, hidden-duplicate, oversized and missing sources stay indeterminate with the matching failure reason even under the widest ceiling. CLI cases refuse eleven malformed ceilings, six unknown resources and eight malformed invocations with exit 2 and no stdout. A unit test freezes one report byte for byte.

`tests/fixtures/pressure-ceiling-v1.json` holds eight valid and twenty invalid independent reports. `scripts/validate_pressure_investigation.py` requires eighteen of the invalid reports to fail the schema itself (template, version, scope, resource, ceiling range, source/resource binding, evidence scope and version, reason/outcome and availability agreement, closed fields and value range), and exactly two to pass the schema but fail the independent value-versus-ceiling check. It also runs the actual CLI for each resource at ceilings 0 and 10000 and checks report/exit agreement, criterion echo and source binding against whatever live PSI the runner reports. These are consistency checks, not a promise of a particular live outcome.

## Package expectation acceptance

[ADR 0008](adr/0008-explicit-package-installed.md) defines an explicit presence check for one named package, not a vulnerability or version check. `tests/package_investigation.rs` writes synthetic status databases. It covers all eight dpkg states, the `reinstreq` flag on installed and config-files records, and all selection words; a unit test covers every state with both flags. Matching cases cover multiarch with and without a qualifier, `all`, a sparse stanza without architecture, and exact matching against prefixes, superstrings and different case. It checks that no other package's name appears in the report. Malformed status words, a duplicate installed identity, a missing installed version, a non-field line, a Unicode separator and seventeen matches stay indeterminate with the matching failure reason. Exactly sixteen matches is admitted, and a missing file gives not_found. CLI cases refuse thirteen malformed selectors and five malformed invocations with exit 2 and no stdout. Unit tests freeze one report byte for byte and check that database text containing control characters, quotes and backslashes is escaped.

`tests/fixtures/package-installed-v1.json` holds ten valid and twenty-nine invalid reports. `scripts/validate_package_investigation.py` requires twenty of the invalid reports to fail the schema and exactly nine to pass it but fail the semantic checks: selector equality, record matching, duplicate installed identity and the derived reason. Its live check parses `/var/lib/dpkg/status` with its own bounded stanza reader, independent of the Rust parser. It requires MIRA's exported records for `dpkg`, `dpkg:<native arch>`, an absent architecture, `libc6` and an absent package to equal that parse exactly, with matching exit codes. The status file is sampled before and after; any change makes the comparison inconclusive and fails it. This compares one runner's database, not representative hosts.

## Uptime and kernel-release expectation acceptance

[ADR 0009](adr/0009-explicit-uptime-and-kernel-release.md) defines an explicit minimum uptime and an exact expected release, with no defaults and no version ordering. `tests/host_investigations.rs` writes synthetic procfs files. Uptime cases sit just below, at and above the minimum (59.99, 60.00 and 60.01 seconds against 60), at fractional values around one second, and at both sides of u64::MAX. Malformed, single-field, signed, exponent, Unicode-separated, overflowing, oversized and missing uptime stays indeterminate even against a minimum of 1. Kernel cases cover exact matches with and without a trailing newline, case, prefix, suffix and adjacent-number differences, and malformed, oversized and empty sources. CLI cases refuse nine malformed minimums, nine malformed or option-shaped releases (including `--json`, which earlier development showed could otherwise become the criterion) and eight malformed invocations with exit 2 and no stdout. Unit tests freeze one report of each template byte for byte.

`tests/fixtures/uptime-minimum-v1.json` holds six valid and sixteen invalid reports, and `tests/fixtures/kernel-release-v1.json` five valid and seventeen invalid. `scripts/validate_host_investigations.py` requires fourteen invalid reports of each to fail the schema, and exactly two (uptime) and three (kernel) to pass it but fail the independent value checks. Its live check reads `/proc/uptime` and `/proc/sys/kernel/osrelease` directly before and after MIRA. MIRA's uptime must fall within the direct whole-second interval, and the minimum equal to the first direct sample must be met. The expected release equal to the direct sample must match, and the same release with a suffix must differ. Changed kernel endpoints or reversed uptime make the comparison inconclusive and fail it.

## Journal events acceptance

[ADR 0012](adr/0012-bounded-journal-events.md) defines text-free, producer-bound journal evidence. Unit tests in `src/journal.rs` cover:
- class and boot parsing, and the exact sentinel and class argv (bare `--boot`, never offset 0)
- the producer bindings, and the absence of the backtrace ID
- the journal-wide unit validator for every unit type, and export parsing that keeps only allowed fields and rejects binary framing
- producer binding against decoys and defects, the window rule (one valid entry is conclusive; a full window of decoys is unavailable), the unit cap, and the coredump cgroup and unit-field mapping
- the full outcome precedence, and the crash-handler check

`tests/journal_process.rs` (test-support) drives the real CLI through a native `journalctl` fixture. The fixture writes the expected argv out independently and exits 64 on any deviation. The tests cover:
- every outcome row, for both boots, including the handler change between boots
- recorded units and times, and the absence of message text, PIDs, cursors and the boot ID
- call order, proving that `-b -1` never runs when the running boot is not visible
- mixed file permissions (an unreadable archive gives `journal_access_incomplete`; recorded events stay conclusive), and no system journal files at all
- decoy, wrong-origin, backtrace, missing-field, binary, invalid-unit, oversized, failing and missing-tool cases
- eleven refused invocations that never start `journalctl`

`scripts/validate_journal_investigation.py` checks the fixtures with its own outcome-precedence implementation. Its live check derives visibility, file access, per-class producer-valid counts and the crash handler with its own `journalctl` queries and parser, before and after MIRA. It requires agreement and fails as inconclusive if the journal changed in between.

## Session acceptance (ADR 0015 stage 1a)

Unit tests in `src/session.rs`:
- every entry kind round-trips through its canonical bytes
- the parser refuses non-canonical input: spacing, a missing newline, leading zeros, signs, exponents and fractions, quoted numbers, another version, an uppercase session ID, duplicate or extra keys, nested values, `\u` escapes above C0, `\/`, and missing fields
- invalid directive field combinations are refused
- notes refuse C0, DEL, C1, bidirectional characters and more than 1 KiB, also when reading a canonically encoded entry
- records split into the entry line and an armored signature, refusing a missing or malformed signature
- the state machine covers every directive, delegation expiry at its last covered entry, `stop`, roles (an agent directive or a collector question is refused), close counts, nothing after the close, the header only at entry 0 with three distinct valid principals, and `based_on` earlier than the entry in the same session

`tests/session.rs` runs the real `ssh-keygen` with throwaway operator, agent and collector keys and an unlisted stranger key:
- **Valid sessions:** a full session verifies, and each entry also verifies independently with `ssh-keygen`.
- **State:** `show` and its JSON state follow directives, delegation lapses, and `stop` takes precedence.
- **Closing:** a closed session refuses every append. Removing its close entry passes plain `verify` but fails against the receipt, and another session's receipt never matches.
- **Detection:** `verify` reports each of these with its fixed reason:
  - a changed byte
  - an entry re-signed by an unlisted key
  - an agent-signed operator directive
  - a missing entry, or a record without its signature
  - a renamed entry
  - an unexpected file
  - a validly signed entry copied from another session
- **Forgery:** an agent that signs a complete session naming itself operator verifies only for a verifier who expects that agent as operator. It fails for the real operator, and the operator's key cannot append to it.
- **Concurrency:** while six writers append, repeated `show` calls always see a complete log. The writers get distinct, contiguous sequence numbers and leave no pending files, and files left by an interrupted writer block nothing.
- **Receipts and output:** receipts are refused inside the session, directly or through a symbolic link, over an existing file, or in a missing directory, and the session stays open. No command prints the session ID.
- **Refusals that write nothing:** a start with an unlisted key (nothing left behind); an existing directory, never reused or removed; the agent's key writing as the operator; and malformed invocations.

`scripts/validate_session.py`:
- checks the closed `session-v1` schema, canonical layout and state rules with its own implementation
- builds a real session through the CLI, re-admits each entry, recomputes the state, compares it with `show --json`, verifies each signature with `ssh-keygen` directly, checks the receipt, and requires both a changed byte and a verifier expecting another operator to fail

Stage 1b (broker):
- **Unit tests:**
  - every capability's fixed argument vector, and refusal of anything outside the set, option-shaped, mis-spaced or oversized
  - the exit-status-to-outcome table
  - request records round-trip, refuse non-canonical input, and are never admissible as log entries
  - each admission decision: budget, level, `superseded_by_directive`, `operator_only`, capability, stale, session mismatch, replay, and questions by level
  - fold rules: the agent never writes the log; budget is charged once per relayed action; results must answer a pending action with the mapped outcome; request IDs are used once
- **`tests/session_broker.rs`** (real `ssh-keygen`):
  - an admitted request runs once, and its collector-signed document verifies with plain `mira verify`
  - refusals by autonomy, budget, `operator_only` and directive precedence, and admission under delegation
  - forged, out-of-set, option-shaped and garbage requests never run; non-request files are ignored; replays are discarded
  - operator `act` with no budget, a recorded template refusal, and refusal of the agent's key as collector or broker
  - `verify` rejects an edited or re-signed stored request, an edited, agent-re-signed or missing document
  - a closed session stops the broker and refuses requests
  - invalid requests are usage errors before signing, and other keys never reach the inbox
  - `separate_user` modes and group, and the refusal of inbox files owned by the broker's own user
- **Review regressions:**
  - a genuine collector-signed document swapped for another is detected
  - files stay 0640 under `umask 077`
  - a stored request with no log entry is resumed, and a differing stored copy is refused
  - backslash-escaped unit names are admitted and schema-valid
  - close refuses pending actions, and `--abandon-pending` finalizes them
  - 1a operator questions keep their signed layout
  - results claim a document signature exactly when they have a document
  - decisions use the level of the entry being written
  - every agent-attributable entry costs budget, and the operator's reserve is never charged; with no budget left, a flood of requests is dropped unrecorded while stop and close still work
  - signature files are not group-writable under `umask 002`
  - relay and document checks run on the authenticated snapshot, even after the result on disk is replaced by an unsigned abandon
  - close receipts are 0600 under umask 022 and 077
  - the broker's guard refuses a replaced directory (an exact copy at the same path), a rolled-back prefix and an entry signed by an unlisted key; a `separate_user` session under a parent writable by others without the sticky bit is refused, and a sticky parent is accepted
  - an inbox flood (junk files, directories, stale and fresh pending files, and 70 request-shaped files) is handled in passes of at most 64 and purged, leaving only the agent's fresh pending file and its non-empty directory
- **`scripts/validate_session.py`:** restates the capability table, outcome mapping and fold rules. It runs a real broker flow (request, admission, refusal, operator capture, close) and checks every entry, stored request and document signature with `ssh-keygen` directly.

## Representative host qualification

The live checks above run on two GitHub-hosted runners and the development host. [ADR 0013](adr/0013-host-qualification-protocol.md) and the [qualification guide](qualification.md) define how they run on real hosts. `scripts/qualify_host.py` runs every validator's check groups against the checkout build or an installed binary and records passed, failed or not applicable per group, with fixed reasons such as `no_systemd`. It writes a `qualification-receipt-v1` receipt free of host identifiers.

All eight validators share the contract in `scripts/validation_status.py`:
- the binary from `MIRA_BINARY`
- exit 0 passed, 1 failed, 4 inconclusive
- fixed groups through `--list-groups` and `--only`
- observation gaps reported through `MIRA_QUALIFICATION_STATUS`

Without `--only` each validator runs as before.

`scripts/test_validation_contract.py` forces a mid-comparison change and a schema-valid wrong value into each live comparison: procfs, systemd evidence, the service investigation, dpkg, uptime and kernel release, journal visibility and counts, and boot binding. Each forced change exits 4 and each wrong value exits 1, with only the fixed exception type printed. It also checks that a default journal run without a visible journal still passes, while an explicit `--only live-counts` exits 4, and that a source unavailable only in a later timeline capture, a journal class unavailable only during `live-visibility`, or incomplete journal access seen only by `live-counts`, is still reported as a gap.

`scripts/test_qualify_host.py` drives the runner with fake validators and probes. It covers:
- passed, failed, inconclusive retried at most twice, runner errors (unknown exit, missing or malformed gap report, timeout), and every not-applicable reason without executing the group
- a validator's descendants killed with its process group on timeout, after a normal exit and when the runner is interrupted
- a container whose journal denial (`journal/system` gap, `live-counts` not applicable) qualifies without findings
- a container without a boot ID, where `live-boot` is not applicable and `signed-compare` reports the boot-ID gap, qualifies without findings
- refusal as root, of an existing receipt, of a non-executable binary, of an untracked or modified file, and of a binary replaced during the run
- the denial path: with `journalctl` present and no visible sentinel, `live-visibility` runs and `live-counts` alone is `no_journal_access`; a `restricted-user` receipt without the confirmed `journal/system` gap is a finding
- a missing `ssh-keygen` gating only the signing groups, `signed-compare` and `challenge`
- a real pressure validator run against a wrapper binary with one unreadable PSI file, which passes and reports the gap; the runner flags it as unexpected for `physical-amd64`
- the receipt schema, thirteen refused mutations, every committed receipt, and a run on the real host scanned for the host name, machine ID, boot ID, user name and full kernel release
- every validator's `--list-groups` equal to the runner's table, and `--only` running exactly the selected groups

CI runs the runner as `ci-runner` against the checkout build and against the extracted package binary, and keeps both receipts. These runner receipts are not representative-host qualification. The Phase 1 exit needs reviewed receipts from the required classes in the guide; only an optional `wsl` receipt is committed so far.
