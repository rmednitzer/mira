# Security policy

## Supported versions
MIRA is pre-1.0 experimental research software. Security fixes currently target the latest `main` branch; no stable releases or long-term security-support guarantees exist. This is not a safety-certified, authenticated or production-ready control system.

## Reporting vulnerabilities
Use GitHub's **private vulnerability reporting** for this repository when enabled, rather than opening a public issue. If the private reporting option is unavailable, contact the maintainer privately using a contact method published on the maintainer's GitHub profile. Do not publish exploit details, credentials or private data in issues or pull requests.

Provide a minimal reproducible case, affected revision, expected versus observed behavior, impact and safe reproduction steps. Do not attack third-party services or systems while testing. There is no promised response-time SLA.

## Security and safety boundaries
- Read-only template selection admits only registered operations under caller permissions; it is not authentication, model authority or an OS sandbox. Investigation outcomes concern only the explicit expectation each template names (service activation, memory, pressure, package presence, uptime, kernel release, journal events); unavailable, transitional or unrecognized evidence remains indeterminate.
- Linux evidence is untrusted observation, not authenticated provenance, a health verdict or a vulnerability finding. Run the CLI under ordinary caller permissions; no elevation or automatic remediation is implemented.
- MIRA runs only fixed-argument, shell-free `systemctl` and `/usr/bin/journalctl` read queries and, when signing or verification is requested, `/usr/bin/ssh-keygen`; arbitrary command adapters remain out of scope.
- A verified signature shows that a listed key signed the exact bytes, not that the evidence is true; a consumer-challenge age bound assumes the key holder ran an unmodified `mira`.
- In the retained simulation, actor identifiers are caller-supplied enum values, **not identities**.
- Delegation is illustrative and does **not** provide authenticated, scoped or revocable authorization.
- Simulated collision and state checks must not be interpreted as real-world physical safety controls.
- Do not connect the retained simulation to real robots, actuators or industrial control paths. Any production use of the experimental read-only CLI requires separately established validation and authorization.
- Do not put secrets or private infrastructure details into scenarios, CI artifacts, issues or model prompts.
- GitHub Models and other externally hosted inference backends are optional future integrations; submit only synthetic/public data unless separate controls and authorization are established.

See [the threat model](docs/threat-model.md) for assets, trust boundaries, assumptions, threats and residual risks.

## Dependencies, verification and disclosure
CI runs Rust formatting, Clippy, tests and a release build on Ubuntu 26.04 x64 and ARM64. The Rust CLI has no external crate dependencies; native subprocess fixtures are opt-in test support and are excluded from packages. Python/jsonschema are separate schema-validation and optional history tooling, with a complete version/wheel-hash lock and source builds refused. CI also checks versioned evidence, capture and report contracts, strict capture admission, live unprivileged systemd, procfs, dpkg and journal comparisons, signing against the real `ssh-keygen`, and experimental Debian packaging with real dependency resolution in disposable containers. Capture labels and completion markers are not authenticated provenance. Runtime package relationships are generated ELF dependencies plus optional suggestions (`systemd`, a system bus, `openssh-client`). See [validation](docs/testing.md). Passing checks are not a substitute for security review. Coordinated fixes should include regression tests and appropriate advisories for issues affecting published versions.
