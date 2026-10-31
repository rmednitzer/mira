# Development and validation

## Dependency boundaries

The Rust CLI has no external Rust crate dependencies. Normal builds and the CLI-only Debian package require no Python. The non-default `test-support` Cargo feature admits only a native subprocess fixture binary; it adds no runtime capability to MIRA. The package installs only `mira`, never the fixture.

Python and `jsonschema` are separate developer tooling for independent JSON Schema validation and the optional offline history-comparison script. They are not CLI runtime dependencies. The complete dependency closure is pinned by version and wheel SHA-256 in `requirements-schema.txt`. Installations require hashes and binary wheels; source builds are refused. Capture and investigation validation reuse its existing referencing dependency to register the local evidence schema without network retrieval.

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
```

On an unprivileged Ubuntu 26.04 host with a system bus and `systemd-journald.service`, add `--live-systemd` to both evidence and investigation validators. CI requires this live comparison on both native architectures; local synthetic checks do not require systemd. Direct state is sampled before and after MIRA; changing fixture state makes the comparison inconclusive and fails the check. This validates one host service, not application health or fleet-wide compatibility.

On an unprivileged Linux host with readable procfs, add `--live-procfs` to the evidence validator. Native CI requires it on both architectures. Independent bounded direct reads surround `mira inspect --json`: kernel release and MemTotal endpoint samples must agree and match MIRA, while whole uptime must fall inclusively between direct whole-second samples. Changed endpoints or reversed uptime make the check inconclusive and fail; required unavailable observations also fail. No retry hides a disagreement. Tests demonstrate that schema-valid but wrong values are refused and that valid interval endpoints and fluctuating available memory pass.

The direct uptime parser uses integer whole seconds, including values above 2^53, without float conversion. MemAvailable and PSI fluctuate non-monotonically, so direct endpoint values cannot bound their intermediate samples; their existing schema, range and synthetic source checks remain separate. Package counts are not directly compared here. The check emits a fixed success line and disagreement diagnostics without sampled values; it does not upload captures or authenticate the host, clock or source. This controlled CI comparison does not close representative physical-host or fleet qualification.

## Packaging checks

Native Ubuntu 26.04 amd64/arm64 CI builds and inspects the package, checks checksums, executes the extracted CLI, exercises isolated dpkg install/reinstall/remove/purge, and runs lintian. It checks evidence-v1/v2, investigation-v1, memory-headroom-v1 and capture-v1 schemas and their packaged guides, rejects systemd units, maintainer scripts and the native test helper in the package, and asserts package-root/document permissions. Archive metadata must advertise exactly `Suggests: systemd, default-dbus-system-bus | dbus-system-bus` and no `Recommends`; native ELF requirements remain generated in `Depends`. See the [runtime relationship rationale](debian-packaging.md#runtime-package-relationships).

Repeated assembly compares the same binary under ordinary and restrictive (`077`) invoking umasks. The builder normalizes its own umask to `022`; source timestamps use exported `SOURCE_DATE_EPOCH`. This verifies archive assembly under those conditions. A separate fresh-build test compiles twice from independent git archives and target directories, varies source/target paths, timezone and umask, and compares raw binaries and full packages against the selected artifacts. Its scope is one native runner/compiler/system dependency environment, not independent-host or hermetic compilation. The isolated dpkg root bypasses dependency enforcement. A separate native disposable Ubuntu 26.04 container installs the exact package through apt without bypassing dependencies, checks installed binary bytes and runs the installed demo/capture contract. Its receipt binds source commit/tree, package/binary digests and container image identity. This is container loader/dependency evidence; clean physical-host behavior, genuine upgrades/downgrades and signed release provenance remain release gates.

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

`tests/capture.rs` freezes eight source/availability cases before execution: complete host, complete pressure, malformed memory, malformed uptime, missing CPU PSI, missing memory PSI, malformed IO PSI and unavailable optional IO outside the host profile. Results come from the actual collectors. `tests/fixtures/capture-v1.json` supplies nine valid and nineteen invalid independent documents for structural and semantic admission. These authored synthetic cases are not a representative fleet benchmark.

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

PSI, kernel-release and dpkg Status regressions apply the same rule: Unicode separators (U+00A0, U+2003, U+3000, U+0085) inside PSI lines or Status words, and Unicode whitespace around a kernel release, produce malformed evidence. A PSI `avg10` hidden behind a Unicode separator is not admitted. ASCII spaces and tabs remain valid. Each regression was confirmed to fail against the previous Unicode-aware splitting and trimming.
