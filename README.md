# MIRA — Mixed-Initiative Reasoning and Autonomy

**Security-first, intent-driven Linux and infrastructure operations.**

MIRA is a local-first Rust project for evidence-backed Linux diagnostics, security exposure analysis, and controlled human–AI cooperation. The goal is to help operators understand system state, choose proportionate actions and verify outcomes without granting AI implicit operational authority.

**Status:** Early development. Current source includes a deterministic coordination fixture, in-memory replay verification and an initial bounded, read-only Linux procfs evidence collector. It is not yet a functioning AIOps application, vulnerability scanner, adaptive UI or secure remote-operations controller.

## Primary use case

A Linux/platform engineer investigates host instability or potential security exposure. MIRA collects bounded evidence, distinguishes facts from uncertain findings, and provides contextual investigative views. The MVP must be useful entirely offline and without a model.

See [vision](docs/vision.md), [architecture](docs/architecture.md), [requirements](docs/requirements.md), [roadmap](docs/roadmap.md), and [threat model](docs/threat-model.md).

## Ubuntu 26.04 LTS

Rust 2024; pinned toolchain is specified in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets --locked
cargo run --locked -- inspect
cargo run --locked -- demo
```

The `inspect` command prints a bounded read-only report from `/proc/meminfo` and `/proc/uptime`. Missing or invalid sources are shown as unknown; exit code 1 indicates incomplete evidence. The `demo` subcommand retains the original grid control fixture. There is no privileged collector daemon, network service, external model call, or automated remediation.

## Security and sovereignty

Read-only by default. Hosted inference is optional and never a source of authority. No unapproved mutation, silent fallback to cloud inference, or unsupported vulnerability applicability claims. This is not a safety-certified or production authorization system.

## License

Apache-2.0; see [LICENSE](LICENSE).
