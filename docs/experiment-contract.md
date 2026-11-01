# Experiment contract (v1)

MIRA currently provides an in-process, typed Rust experiment contract in `src/experiment.rs`.

## Objective
Compare proposed actions, arbitration decisions and resulting state transitions using identical, explicit simulation inputs. The core has no network or model dependencies.

## Contract
- `Frame`: control mode, optional human proposal, optional agent proposal, and optional grant.
- `Record`: one submitted frame and the exact resulting `Event`.
- `Trace`: protocol version, original scenario, ordered records, and final outcome.
- `run()`: executes a bounded sequence of frames through the existing `Engine::step`.
- `verify()`: re-executes recorded inputs and compares transitions and final outcome.

All proposals are **data**, not authority. Caller-supplied actor labels and grants are not authenticated. The deterministic replay verifier detects inconsistencies in a supplied trace but cannot establish origin, detect coordinated rewriting of the scenario and events, or prove model-output reproducibility.

## Explicit boundaries
This first increment does **not** implement on-disk storage, canonical serialization, cryptographic digests, model calls, a browser UI, scoped delegation, revocation or identity verification. Those require separate protocol and security decisions. `PROTOCOL_VERSION` is the in-memory contract version, not a stable external wire format.

## Future provider interface
AI providers, including optional GitHub Models and local inference, should receive a versioned, bounded observation and return a structured proposal. Their outputs must enter the same arbitration path as scripted or human proposals. No hosted service is required for Rust CI. The operations-domain form of this interface is the shared workspace session ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md)), in which the agent is a key-holding principal acting only through `mira`'s closed read-only capabilities.

## Verification
`cargo test --all-targets --locked` includes replay equality, tampered transition detection, tampered outcome detection, unknown version rejection, terminal-state immutability and rejected delegated action tests.

Any future serialized wire format must define canonical encoding, numerical constraints, version negotiation and data-size limits before being treated as a durable public contract.
