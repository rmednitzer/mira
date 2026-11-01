# Operational evidence

Package and systemd observations use the same typed `Evidence<T>` contract as procfs evidence: a logical source identifier, optional local wall-clock recording time, and either `Observed(T)` or `Unavailable` with an error kind and message.

## Capabilities
- `collect_packages(path)` reads a bounded dpkg status database; the path is injectable for synthetic tests.
- `collect_service(unit)` inspects exactly one explicitly named system service using the existing fixed-argument systemctl adapter.
- `collect_operations(path, unit)` is an optional composite collector; it does not provide an atomic snapshot.
- `mira inspect` and `mira service` do not depend on each other's data sources.

- `investigation::run(Template::ServiceActive, unit)` reuses the service collector and returns a separate versioned expectation report; it does not change the observation contract. See [investigations](investigations.md).

## Trust and safety
This is an observation API, not vulnerability determination or application-health certification. The host clock is not trusted provenance. The `systemd/system` source is a logical collector identifier; the requested unit and canonical ID are included in the returned state only on success. An unavailable result can include untrusted OS error text. Neither the service collector nor the package parser authenticates the host or the source. No privilege escalation or remediation is attempted.

## Remaining
JSON Lines v1 and its JSON Schema are implemented; exported errors use kind labels without raw OS messages. Native Ubuntu CI includes one unprivileged live systemd comparison. Signed captures and reports ([signatures](signatures.md)) name a key holder, and consumer challenges bound a capture's age. Authenticated source identity, representative host receipts ([qualification](qualification.md)) and package advisory correlation remain future work. See [JSON contract](evidence-json.md) and [validation](testing.md).

The [memory-headroom investigation](memory-investigation.md) reads only meminfo and assesses an explicit minimum. It neither requires nor adds package/service queries.
