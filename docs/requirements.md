# Requirements and verification matrix

Statuses are **implemented** only where code and tests currently exist. Design intent is not implementation evidence.

| ID | Requirement | Acceptance / verification | Status |
|---|---|---|---|
| OPS-01 | Linux host observation is read-only | Collect supported procfs evidence without execution, mutation, privilege escalation or network access | Initial collector implemented; full runtime assurance pending |
| OPS-02 | Evidence is bounded and parsed strictly | Reject invalid values, oversized input and absent fields using fixture tests | Initial meminfo/uptime implementation |
| OPS-03 | Findings cite observed sources and freshness | Each result records source, timestamp, scope and missing data | Planned |
| OPS-04 | Read-only investigation template | Operator obtains health/security report on Ubuntu 26.04 with no AI | Planned |
| SEC-01 | No proposal grants itself authority | Forged identity and grant attempts are rejected by an independent gate | Not satisfied by current simulation API |
| SEC-02 | No silent external inference | Offline runs generate no external model requests | Architectural constraint; integration tests planned |
| SEC-03 | Vulnerability applicability is evidence-bound | Advisory/backport and installed package revision required; unknown is explicit | Planned |
| SEC-04 | UI cannot add operational capabilities | Only registered components/actions can render and execute | Planned |
| INT-01 | Operator intent selects a declared workflow | Ambiguous intent cannot invoke undeclared operations | Planned |
| UI-01 | Task-oriented views improve usability without dynamic code | Same scenarios benchmarked with fixed and adaptive views | Research hypothesis |
| EVA-01 | Reproducible synthetic experiments | Versioned inputs and repeatable traces; future external canonical format | In-process replay implemented |
| REL-01 | Change verification and rollback | Approved changes verify postconditions and offer recovery | Deferred; no write capability in MVP |

Release gates: passing Rust CI on Ubuntu 26.04 x64/ARM64, threat-model review for new boundaries, synthetic fixture coverage, and operator-visible limitations. Human or model claims must not be treated as evidence without an independently observed result.
