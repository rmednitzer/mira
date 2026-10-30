# Development and validation

## Dependency boundaries

The Rust CLI has no external Rust crate dependencies. Normal builds and the CLI-only Debian package require no Python. The non-default `test-support` Cargo feature admits only a native subprocess fixture binary; it adds no runtime capability to MIRA. The package installs only `mira`, never the fixture.

Python and `jsonschema` are separate developer tooling for independent JSON Schema validation and the optional offline history-comparison script. They are not CLI runtime dependencies. The direct validator version is pinned in CI; transitive Python dependencies are not yet hash-locked. Investigation validation reuses its existing referencing dependency to register the local evidence schema without network retrieval.

## Rust checks

Use the repository toolchain from `rust-toolchain.toml`:

```sh
rustup install
cargo fmt --all -- --check
cargo clippy --all-targets --features test-support -- -D warnings
cargo test --all-targets --features test-support --locked
cargo build --release --locked
```

`cargo test --all-targets --locked` remains a Python-free core suite. Enable `test-support` for the full native subprocess integration suite. Cargo builds its fixture and supplies `CARGO_BIN_EXE_*` paths to integration tests; no ad-hoc compiler invocation, shell or global environment mutation is used. `default-run = "mira"` keeps ordinary `cargo run -- ...` unambiguous.

The tests replace `systemctl` only in a per-child PATH pointing at a newly created temporary directory. The fixture verifies the production argument vector and exercises valid large output, oversized/malformed/non-UTF-8 output, failed exit, execution timeout and inherited stdout. Its inherited writer exits after five seconds; this tests the collector's three-second deadline, not arbitrary descendant containment. Fixture directories are removed by their owning test. Investigation cases additionally exercise closed template admission, three outcomes, unavailable evidence, aliases, independent load/active semantics and escaped human output.

## Independent evidence checks

```sh
python3 -m venv .schema-venv
.schema-venv/bin/python -m pip install --disable-pip-version-check jsonschema==4.25.1
cargo build --locked
.schema-venv/bin/python scripts/validate_evidence_schema.py
.schema-venv/bin/python scripts/test_compare_evidence.py
.schema-venv/bin/python scripts/validate_investigation_schema.py
```

On an unprivileged Ubuntu 26.04 host with a system bus and `systemd-journald.service`, add `--live-systemd` to both evidence and investigation validators. CI requires this live comparison on both native architectures; local synthetic checks do not require systemd. Direct state is sampled before and after MIRA; changing fixture state makes the comparison inconclusive and fails the check. This validates one host service, not application health or fleet-wide compatibility.

## Packaging checks

Native Ubuntu 26.04 amd64/arm64 CI builds and inspects the package, checks checksums, executes the extracted CLI, exercises isolated dpkg install/reinstall/remove/purge, and runs lintian. It checks both evidence/investigation schemas and the investigation guide, rejects systemd units, maintainer scripts and the native test helper in the package, and asserts package-root/document permissions.

Repeated assembly compares the same binary under ordinary and restrictive (`077`) invoking umasks. The builder normalizes its own umask to `022`; source timestamps use exported `SOURCE_DATE_EPOCH`. This verifies archive assembly under those conditions, not independently reproducible compilation. The isolated dpkg root bypasses dependency enforcement; clean-system dependency resolution, genuine upgrades/downgrades and signed release provenance remain release gates.

## Review and CI

CI runs on PRs and pushes to `main`, avoiding duplicate branch-push builds. New work on the same workflow/ref cancels obsolete runs. CI tokens retain least-privilege permissions and actions remain SHA-pinned. Inspect exact-head Codex review receipts, formal reviews and inline threads before merge; green checks alone are insufficient. Confirm post-merge source identity and CI.

## Primary guidance

- [Cargo targets and binary integration fixtures](https://doc.rust-lang.org/cargo/reference/cargo-targets.html)
- [Cargo test target selection](https://doc.rust-lang.org/cargo/commands/cargo-test.html)
- [Reproducible Builds: environment variations and permissions](https://reproducible-builds.org/docs/env-variations/)

## Investigation-specific acceptance

The [decision record](adr/0001-read-only-service-investigation.md) precedes the implementation. Native unit and CLI fixtures cover the supported state table and negative paths; `tests/fixtures/investigation-v1.json` contains independent valid and deliberately invalid reports. Its validator checks structure, source/scope identity, evidence binding, assessment semantics and exit-code agreement. Unknown/error/transient cases cannot become satisfied results. Existing evidence-v1 compatibility is checked separately. The live sample compares both embedded state and assessment with stable direct systemctl observations, not application health.
