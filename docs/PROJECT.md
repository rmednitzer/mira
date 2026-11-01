# Project scope

The authoritative project definition is maintained in [vision.md](vision.md), [architecture.md](architecture.md), [requirements.md](requirements.md), and [roadmap.md](roadmap.md).

The existing grid simulation is a retained regression fixture, not the product's primary use case. Its arbitration semantics (modes, expiring grants, human precedence, staleness, terminal immutability) are the basis of the shared workspace's autonomy rules ([ADR 0015](adr/0015-shared-mixed-initiative-workspace.md)). See [experiment-contract.md](experiment-contract.md) for its implementation and limitations, and the [research basis](research/mixed-initiative.md) for the mixed-initiative design rules.

Current implementation and validation boundaries are summarized in the [requirements matrix](requirements.md) and [development checks](testing.md). Keep all overview/status text synchronized with collector, schema, history and packaging changes.

Complete scoped collection and strict admission are specified in [captures](captures.md) and [ADR 0002](adr/0002-complete-captures-and-admission.md).

The closed investigation templates are specified in [investigations](investigations.md) and the per-template guides linked from it. Every material decision has a record in the [decision index](adr/README.md).
