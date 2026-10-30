# MIRA — Mixed-Initiative Reasoning and Autonomy

An open-source, local-first project for human–autonomy coordination, shared control and inspectable decisions.

**Status:** Early Rust bootstrap. Not a safety-certified controller or a production authorization system.

## First use case

A deterministic, offline grid rover with human and agent movement proposals. Four illustrative authority modes are available: manual, advisory, assisted, and delegated. The kernel records each decision and transition.

## Ubuntu 26.04 LTS

Install Rust 1.93.1 with rustup and run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets --locked
cargo run --locked
```

The core has no external crate dependencies or hosted-service requirement.

## Architecture and limitations

See [project scope](docs/PROJECT.md) and [security guidance](SECURITY.md). Actor labels are unverified caller inputs, and delegation is illustrative. No physical actuator integration is supported.

## Planned integration

GitHub Models and locally hosted inference will be optional external participant adapters. Model responses must pass the same arbitration checks as scripted responses.

## License

Apache-2.0 (license file pending on this bootstrap branch).
