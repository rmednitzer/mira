# MIRA — Mixed-Initiative Reasoning and Autonomy

**Security-first, intent-driven Linux and infrastructure operations.**

MIRA is a local-first Rust project for evidence-backed Linux diagnostics, security exposure analysis, and controlled human–AI cooperation. The goal is to help operators understand system state, choose proportionate actions and verify outcomes without granting AI implicit operational authority.

**Status:** Early development. Implemented capabilities include bounded procfs and dpkg collection, explicitly selected systemd service observations, opt-in activation, memory-headroom, pressure-ceiling, package-installed, uptime-minimum and kernel-release investigations, per-source timing, versioned JSON Lines and complete scoped captures with JSON Schemas, an optional offline comparison utility and experimental CLI-only Debian packaging. A deterministic coordination fixture and in-memory replay verifier remain for research. It is not yet a functioning AIOps application, vulnerability scanner, adaptive UI or secure remote-operations controller.

## Primary use case

A Linux/platform engineer investigates host instability or potential security exposure. MIRA collects bounded evidence, distinguishes facts from uncertain findings, and provides contextual investigative views. The MVP must be useful entirely offline and without a model.

See [vision](docs/vision.md), [architecture](docs/architecture.md), [requirements](docs/requirements.md), [roadmap](docs/roadmap.md), and [threat model](docs/threat-model.md).

## Ubuntu 26.04 LTS

Rust 2024; pinned toolchain is specified in `rust-toolchain.toml`.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --features test-support --locked -- -D warnings
cargo test --all-targets --features test-support --locked
cargo run --locked -- inspect
cargo run --locked -- demo
cargo run --locked -- service ssh.service
cargo run --locked -- investigate service-active ssh.service --json
cargo run --locked -- investigate pressure-ceiling --resource memory --max-some-avg10-basis-points 500
cargo run --locked -- investigate package-installed openssh-server
cargo run --locked -- investigate uptime-minimum --min-uptime-seconds 3600
```

`capture LABEL [--pressure] [--timeline]` emits a complete scoped JSON document with per-source timing/failure reasons; explicit `--pressure` adds memory and IO stalls, `--timeline` emits capture-v2 with one monotonic collection window and per-source offsets, and opt-in `--bind-boot` adds the reported boot ID and boot-relative window. See [capture contracts](docs/captures.md). `inspect` reports memory, uptime, kernel release, CPU pressure and installed package count. `service UNIT.service` independently observes one explicitly named systemd service. Add `--json` for versioned JSON Lines; unavailable evidence remains explicit and returns exit code 1. Local timestamps are unverified, collection is non-atomic and freshness is unknown. Package metadata does not establish vulnerability exposure, and systemd state does not establish application health.

The opt-in [service-active investigation](docs/investigations.md) evaluates an explicit activation expectation; explicit `service-active/v2` additionally reports `unit_not_found` for a unit with no loadable definition. The [memory-headroom investigation](docs/memory-investigation.md) compares the procfs estimate with an operator-supplied positive KiB minimum. The [pressure-ceiling investigation](docs/pressure-investigation.md) compares one resource's PSI `some avg10` with an operator-supplied ceiling in basis points. The [package-installed investigation](docs/package-investigation.md) reports whether dpkg records one named package as installed, keeping transitional and reinstall-required states indeterminate; it does not assess vulnerability exposure. The [uptime-minimum and kernel-release investigations](docs/host-investigations.md) compare whole seconds since boot with an explicit minimum, and the running release name with an exact expected string. All six preserve supporting evidence. Their satisfied/not-satisfied/indeterminate outcomes are separate from application health and root cause.

The Rust CLI and native tests do not require Python. Enable `test-support` for the complete native subprocess suite; its fixture is excluded from normal builds and packages. Python remains separate tooling for independent schema checks and the optional [history comparison](docs/evidence-history.md). See [development and validation](docs/testing.md), [host evidence](docs/host-evidence.md), [service evidence](docs/systemd-evidence.md), [JSON contract](docs/evidence-json.md), and [Debian packaging](docs/debian-packaging.md).

The [platform roadmap](docs/platform-integrations.md) plans conditional Kubernetes and Talos observation adapters; neither is implemented or a runtime dependency.

The `demo` subcommand retains the original grid fixture. There is no privileged collector daemon, network service, external model call or automated remediation.

## Security and sovereignty

Read-only by default. Hosted inference is optional and never a source of authority. No unapproved mutation, silent fallback to cloud inference, or unsupported vulnerability applicability claims. This is not a safety-certified or production authorization system.

## License

Apache-2.0; see [LICENSE](LICENSE).
