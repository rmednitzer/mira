# systemd service-state evidence

Run `mira service ssh.service` to inspect **one explicitly named system service**. This feature does not enumerate units, manage services, or evaluate service health globally.

MIRA executes `systemctl --system --no-pager --no-ask-password show --property=Id,LoadState,ActiveState,SubState -- UNIT.service` using a fixed argument vector, without a shell. The query is unprivileged and read-only, bounded by a 3-second timeout and 8 KiB stdout limit. Unit names undergo syntax checks before invocation.

The observation contains `Id`, `LoadState`, `ActiveState`, and `SubState`. A reported `active` state is not proof of application health or security. Failed/inactive/not-found states are retained without automatic diagnosis.

**Evidence and limits:** Unlike procfs sources, systemd state currently uses a separate CLI path rather than the unified timestamped `Snapshot`. This limitation is explicit: structured, time-stamped service observations require a subsequent common evidence-contract extension. The response may change between retrieval and display. The system bus might be unavailable, access restricted, or systemctl missing. Error conditions are reported as unknown, never healthy. No privileged fallback or automatic remediation is attempted.

Tests cover accepted and rejected unit names, malformed/mismatched properties, and duplicate fields. They do **not** substitute for live systemd integration testing. An optional live test should run on an Ubuntu 26.04 systemd host under a non-privileged user, against a known fixture unit, without modifying its state.
