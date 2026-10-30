# Operational evidence

Package and systemd observations use the same typed `Evidence<T>` contract as procfs evidence: a logical source identifier, optional local wall-clock recording time, and either `Observed(T)` or `Unavailable` with an error kind and message.

## Capabilities
- `collect_packages(path)` reads a bounded dpkg status database; the path is injectable for synthetic tests.
- `collect_service(unit)` inspects exactly one explicitly named system service using the existing fixed-argument systemctl adapter.
- `collect_operations(path, unit)` is an optional composite collector; it does not provide an atomic snapshot.
- `mira inspect` and `mira service` do not depend on each other's data sources.

## Trust and safety
This is an observation API, not vulnerability determination or application-health certification. The host clock is not trusted provenance. The `systemd/system` source is a logical collector identifier; the requested unit and canonical ID are included in the returned state only on success. An unavailable result can include untrusted OS error text. Neither the service collector nor the package parser authenticates the host or the source. No privilege escalation or remediation is attempted.

## Remaining
A stable, versioned machine-readable schema, bounded error redaction, independent source freshness checks, package advisory correlation, and live Ubuntu systemd integration tests remain future work.
