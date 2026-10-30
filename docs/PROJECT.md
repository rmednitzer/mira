# Project scope

MIRA studies mixed-initiative coordination between human and artificial participants.

## First use case
A deterministic grid rover. Human and scripted agent submit timestamped movement proposals. The coordination kernel enforces four illustrative control modes and records transitions.

## Boundaries
The current actor identity is caller-supplied and untrusted. Delegation has expiration but no revocation or scoped capability model. Results are educational simulations, not evidence of safety in physical systems.

## Milestones
1. Verified Rust baseline and CI on Ubuntu 26.04 LTS.
2. Versioned observations, decisions, event persistence and independently verifiable replay.
3. Browser interface for interactive human control.
4. Optional local inference and GitHub Models evaluation, with only synthetic inputs.
5. More rigorous authority model and comparative experiments.

## Non-goals for v0.1
Physical actuation, production authorization, cloud dependencies, general-purpose agent orchestration, or claims about human cognition.
