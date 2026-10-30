# Security policy

## Supported versions
MIRA is pre-1.0 experimental research software. Security fixes currently target the latest `main` branch; no stable releases or long-term security-support guarantees exist. This is not a safety-certified, authenticated or production-ready control system.

## Reporting vulnerabilities
Use GitHub's **private vulnerability reporting** for this repository when enabled, rather than opening a public issue. If the private reporting option is unavailable, contact the maintainer privately using a contact method published on the maintainer's GitHub profile. Do not publish exploit details, credentials or private data in issues or pull requests.

Provide a minimal reproducible case, affected revision, expected versus observed behavior, impact and safe reproduction steps. Do not attack third-party services or systems while testing. There is no promised response-time SLA.

## Security and safety boundaries
- Current actor identifiers are caller-supplied enum values, **not identities**.
- Delegation is illustrative and does **not** provide authenticated, scoped or revocable authorization.
- Simulated collision and state checks must not be interpreted as real-world physical safety controls.
- Do not connect MIRA to real robots, actuators, industrial systems or production infrastructure.
- Do not put secrets or private infrastructure details into scenarios, CI artifacts, issues or model prompts.
- GitHub Models and other externally hosted inference backends are optional future integrations; submit only synthetic/public data unless separate controls and authorization are established.

See [the threat model](docs/threat-model.md) for assets, trust boundaries, assumptions, threats and residual risks.

## Dependencies, verification and disclosure
CI runs Rust formatting, Clippy, tests and a release build on Ubuntu 26.04 x64 and ARM64. Passing checks are not a substitute for security review. Coordinated fixes should include regression tests and appropriate advisories for issues affecting published versions.
