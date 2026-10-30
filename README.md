# MIRA — Mixed-Initiative Reasoning and Autonomy

**Security-first, intent-driven Linux and infrastructure operations.**

MIRA is a local-first Rust project for evidence-backed Linux diagnostics, security exposure analysis, and controlled human–AI cooperation. The goal is to help operators understand system state, choose proportionate actions and verify outcomes without granting AI implicit operational authority.

**Status:** Early development. Implemented capabilities include bounded procfs and dpkg collection, explicitly selected systemd service observations, timestamped evidence, versioned JSON Lines with a JSON Schema, an optional offline comparison utility and experimental CLI-only Debian packaging. A deterministic coordination fixture and in-memory replay verifier remain for research. It is not yet a functioning AIOps application, vulnerability scanner, adaptive UI or secure remote-operations controller.

## Primary use case

A Linux/platform engineer investigates host instability or potential security exposure. MIRA collects bounded evidence, distinguishes facts from uncertain findings, and provides contextual investigative views. The MVP must be useful entirely offline and without a model.

See [vision](docs/vision.md), [architecture](docs/architecture.md), [requirements](docs/requirements.md), [roadmap](docs/roadmap.md), and [threat model](docs/threat-model.md).

## Ubuntu 26.04 LTS

Rust 2024; pinned toolchain is specified in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --features test-support -- -D warnings
cargo test --all-targets --features test-support --locked
cargo run --locked -- inspect
cargo run --locked -- demo
cargo run --locked -- service ssh.service
```

`inspect` reports memory, uptime, kernel release, CPU pressure and installed package count. `service UNIT.service` independently observes one explicitly named systemd service. Add `--json` for versioned JSON Lines; unavailable evidence remains explicit and returns exit code 1. Local timestamps are unverified, collection is non-atomic and freshness is unknown. Package metadata does not establish vulnerability exposure, and systemd state does not establish application health.

The Rust CLI and native tests do not require Python. Enable `test-support` for the complete native subprocess suite; its fixture is excluded from normal builds and packages. Python remains separate tooling for independent schema checks and the optional [history comparison](docs/evidence-history.md). See [development and validation](docs/testing.md), [host evidence](docs/host-evidence.md), [service evidence](docs/systemd-evidence.md), [JSON contract](docs/evidence-json.md), and [Debian packaging](docs/debian-packaging.md).

The `demo` subcommand retains the original grid fixture. There is no privileged collector daemon, network service, external model call or automated remediation.

## Security and sovereignty

Read-only by default. Hosted inference is optional and never a source of authority. No unapproved mutation, silent fallback to cloud inference, or unsupported vulnerability applicability claims. This is not a safety-certified or production authorization system.

## License

Apache-2.0; see [LICENSE](LICENSE).
