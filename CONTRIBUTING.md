# Contributing

Target Rust 2024 and native Ubuntu 26.04 amd64/arm64 using `rust-toolchain.toml`. Keep evidence collection read-only, bounded and independent of inference. Preserve the retained coordination fixture's deterministic invariants. Add focused regressions for substantive defects and update comments, schemas and affected documentation with behavior changes.

Before opening a PR:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --features test-support --locked -- -D warnings
cargo test --all-targets --features test-support --locked
cargo build --release --locked
```

The native subprocess suite needs `test-support`; normal builds and core tests do not need Python. Independent schema validation and the optional Python history utility have separate tooling dependencies. See [development and validation](docs/testing.md) for exact commands, live-systemd preconditions, packaging checks and remaining release gates.

Use a PR for material changes. Inspect Codex code/security reviews and all inline threads on the final head before merging. Resolve valid findings with regression evidence; explain findings that do not apply. Keep source, architecture, requirements and roadmap aligned; distinguish implemented behavior from planned capability and observed CI from real-host assurance. Do not weaken checks to obtain a green build.

For capture changes, follow [ADR 0002](docs/adr/0002-complete-captures-and-admission.md), preserve v1 compatibility and validate exact source coverage, completion/availability separation and operator-asserted scope. The authored availability matrix and strict decoder negatives must pass.

For investigation changes, preserve evidence/assessment separation, template version and scope, and fixed failure codes. Validate the independent report schema and semantic fixtures as well as the native CLI. Follow the [service investigation decision](docs/adr/0001-read-only-service-investigation.md); additional infrastructure mechanisms require an actual MIRA requirement and a separate decision.
