# Debian/Ubuntu package provenance

`mira inspect` reads `/var/lib/dpkg/status` with a 32 MiB byte limit and parses declared package name, version, architecture and installed status. `tests/package_status.rs` exercises a synthetic fixture. It is read-only and does not invoke dpkg, apt, a shell or a network service.

**Limitations:** This is a snapshot of dpkg's local status database, not an authenticated SBOM, proof of running code, full dependency graph, or vulnerability finding. The database may be inaccessible, inconsistent, stale or attacker-influenced. The CLI currently reports only the installed-record count; it does not expose a stable export protocol. Installed version strings alone cannot establish Ubuntu vulnerability exposure because vendor security backports and specific advisory applicability must be evaluated separately.

Service health is deliberately deferred: a file marker or enabled-unit file alone would not establish systemd runtime state. A future bounded, read-only D-Bus adapter must define identity, scope, timeout and errors before claiming service-health evidence.
