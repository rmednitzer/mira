# MIRA — Mixed-Initiative Reasoning and Autonomy

**Security-first, mixed-initiative Linux and infrastructure operations.**

MIRA is a local-first Rust project. Its goal is a shared workspace in which a human operator and an AI agent both act on an investigation, as a real mixed-initiative system: either party can gather evidence, raise findings, ask or propose, and each contributes what it does best. The agent's autonomy is explicit, set per function, bounded and revocable, and MIRA enforces it, not the model. Decisions stay with the operator, and every claim is grounded in cited, signed evidence. See the [vision](docs/vision.md), the [workspace design](docs/adr/0015-shared-mixed-initiative-workspace.md) (accepted, not yet implemented) and its [research basis](docs/research/mixed-initiative.md).

The foundation built so far is the evidence layer both parties will share.

**Status:** Early development (Phase 1, offline Linux investigator). Implemented:

- bounded, read-only collection from procfs, the dpkg status database, one explicitly named systemd service and text-free journal event classes
- versioned evidence JSON Lines, and complete scoped captures: capture-v1, capture-v2 with a collection timeline and opt-in boot binding, and capture-v3 answering a consumer challenge
- seven closed, read-only investigation templates that keep the operator's expectation separate from the evidence: service-active, memory-headroom, pressure-ceiling, package-installed, uptime-minimum, kernel-release and journal-events
- detached OpenSSH signatures on captures and investigation reports, made and checked by `mira` itself, and a consumer-challenge age bound for signed captures that never trusts the host clock
- independent Python tooling: JSON Schema and semantic validators, an offline capture comparator, and a host qualification runner that writes host-identifier-free receipts
- experimental CLI-only Debian packaging

A deterministic coordination fixture and in-memory replay verifier remain for research. MIRA is not yet an AIOps application, vulnerability scanner, adaptive UI or remote-operations controller.

## Primary use case

A Linux/platform engineer investigates host instability or potential security exposure. MIRA collects bounded evidence, distinguishes facts from uncertain findings, and provides contextual investigative views. The MVP must be useful entirely offline and without a model.

See [vision](docs/vision.md), [architecture](docs/architecture.md), [requirements](docs/requirements.md), [roadmap](docs/roadmap.md), and [threat model](docs/threat-model.md).

## Build and use (Ubuntu 26.04 LTS)

Rust 2024, with the toolchain pinned in `rust-toolchain.toml`. The primary targets are native Ubuntu 26.04 amd64 and arm64.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --features test-support --locked -- -D warnings
cargo test --all-targets --features test-support --locked
cargo run --locked -- inspect
cargo run --locked -- service ssh.service
cargo run --locked -- capture incident-a --pressure --timeline
cargo run --locked -- investigate service-active ssh.service --json
cargo run --locked -- investigate memory-headroom --min-available-kib 1048576
cargo run --locked -- investigate pressure-ceiling --resource memory --max-some-avg10-basis-points 500
cargo run --locked -- investigate package-installed openssh-server
cargo run --locked -- investigate uptime-minimum --min-uptime-seconds 3600
cargo run --locked -- investigate kernel-release --expect "$(uname -r)"
cargo run --locked -- investigate journal-events --absent oom-kill,unit-failure
cargo run --locked -- demo
```

### Evidence

`inspect` reports memory, uptime, kernel release, CPU pressure and the installed package count. `service UNIT.service` observes one explicitly named systemd service. Add `--json` for versioned JSON Lines ([JSON contract](docs/evidence-json.md)). Unavailable evidence stays explicit and returns exit 1. Record times are unverified local clock readings, collection is not atomic and record-level freshness is unknown. Package metadata does not establish vulnerability exposure, and systemd state does not establish application health. See [host evidence](docs/host-evidence.md), [service evidence](docs/systemd-evidence.md) and [package provenance](docs/package-provenance.md).

`capture LABEL [--pressure] [--timeline] [--bind-boot] [--challenge HEX]` emits one complete, scoped JSON document with per-source timing and fixed failure reasons ([capture contracts](docs/captures.md)):
- `--pressure` adds memory and IO pressure stalls.
- `--timeline` emits capture-v2 with one monotonic collection window and per-source offsets.
- `--bind-boot` also records the reported boot ID and a boot-relative window, so two captures from one boot can be ordered.
- `--challenge HEX` emits capture-v3 answering a consumer's challenge, and requires signing.

The label is an operator assertion, never authenticated host identity. The [offline comparator](docs/evidence-history.md) compares two captures, orders same-boot captures, and can verify their signatures and challenge age bounds.

### Investigations

Each template answers one narrow, explicit question and reports satisfied (exit 0), not satisfied (1) or indeterminate (3), with the supporting evidence embedded. None assesses application health or root cause.

| Template | Question | Guide |
|---|---|---|
| `service-active` (`/v1`, `/v2`) | Does one named service report an active state? v2 also reports `unit_not_found` | [investigations](docs/investigations.md) |
| `memory-headroom` | Is MemAvailable at least an explicit KiB minimum? | [memory](docs/memory-investigation.md) |
| `pressure-ceiling` | Is one resource's PSI `some avg10` within an explicit ceiling? | [pressure](docs/pressure-investigation.md) |
| `package-installed` | Does dpkg record one named package as installed? Not a vulnerability check | [package](docs/package-investigation.md) |
| `uptime-minimum`, `kernel-release` | Has the host been up at least N seconds? Is the running release exactly the expected one? | [host](docs/host-investigations.md) |
| `journal-events` | Were no catalog OOM-kill, unit-failure or core-dump events recorded in this or the previous retained boot? Reads no message text | [journal](docs/journal-investigation.md) |

### Signatures and freshness

`--signature PATH --sign-with KEY` signs a capture or `investigate ... --json` report through `/usr/bin/ssh-keygen`, and `mira verify` checks it against an `allowed_signers` file. A signature shows that a listed key signed the exact bytes, not that the evidence is true. `mira challenge` issues a random challenge, `capture --challenge` answers it in a signed capture-v3, and `mira verify --challenge-file C --max-age-ms N` bounds the capture's age on the verifier's own clock. See [signatures](docs/signatures.md).

### Shared sessions

`mira session` records an investigation as a signed, append-only log of entries, each naming its principal ([sessions](docs/sessions.md)). The operator starts, directs and closes a session. An agent submits signed requests, and `mira session run`, a broker the operator starts, admits or refuses each one under the operator's autonomy level and budget, runs admitted actions and records collector-signed results. Findings are checked against those results before they are recorded, proposals wait for the operator's decision, and a deterministic scripted agent exercises the whole flow. A local model can act as the agent through an optional stdio MCP adapter and client host ([agent harness](agent/README.md)), which pin the adapter's tool definitions in the session header and accept no other MCP server. Hostile host-content fixtures check that injected evidence never widens what the agent can do; adaptive rounds with people follow the [red-team protocol](docs/red-team.md).

### Qualification

`scripts/qualify_host.py` runs the independent validators against one binary as an unprivileged user and writes a receipt that records passed, failed and not-applicable checks with explicit evidence gaps, without host identifiers. See [host qualification](docs/qualification.md) and the [committed receipts](docs/qualification/receipts/README.md).

### Tooling

The Rust CLI and native tests do not require Python. Enable `test-support` for the complete native subprocess suite; its fixture is excluded from normal builds and packages. Python, with a hash-locked `jsonschema` closure, is separate tooling for the independent validators, the comparator and the qualification runner. See [development and validation](docs/testing.md), [Debian packaging](docs/debian-packaging.md) and the [decision records](docs/adr/README.md).

The [platform roadmap](docs/platform-integrations.md) plans conditional Kubernetes and Talos observation adapters; neither is implemented or a runtime dependency.

The `demo` subcommand retains the original grid fixture. There is no privileged collector daemon, network service, external model call or automated remediation. The only programs `mira` runs are fixed-argument, shell-free calls to `systemctl`, `/usr/bin/journalctl` and `/usr/bin/ssh-keygen`, each only when a command needs it, and it writes files only when signing is requested: the signature file and a self-check copy in a private temporary directory that is removed afterwards.

## Security and sovereignty

Read-only by default. Hosted inference is optional and never a source of authority. No unapproved mutation, silent fallback to cloud inference, or unsupported vulnerability applicability claims. This is not a safety-certified or production authorization system. Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0; see [LICENSE](LICENSE).
