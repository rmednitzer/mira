# systemd service-state evidence

Run `mira service ssh.service` to inspect **one explicitly named system service**. This feature does not enumerate units, manage services, or evaluate service health globally.

MIRA executes `systemctl --system --no-pager --no-ask-password show --property=Id,Names,LoadState,ActiveState,SubState -- UNIT.service` using a fixed argument vector, without a shell. The query is unprivileged and read-only, bounded by a 3-second timeout and 8 KiB stdout limit. Unit names undergo syntax checks before invocation.

The observation checks that both the requested unit name and the canonical `Id` occur in `Names`, permitting genuine systemd aliases and escaped instance names. It contains `Id`, `Names` (for identity validation), `LoadState`, `ActiveState`, and `SubState`. A reported `active` state is not proof of application health or security. Failed/inactive/not-found states are retained without automatic diagnosis.

**Evidence and limits:** Service state uses the common timestamped `Evidence<T>` contract and is available as versioned JSONL through `mira service UNIT.service --json`. Collection is independently requested rather than included in the host `Snapshot`. Timestamps are untrusted and freshness remains unknown. The response may change between retrieval and display. The system bus might be unavailable, access restricted, or systemctl missing. Error conditions are reported as unknown, never healthy. No privileged fallback or automatic remediation is attempted.

Tests cover accepted and rejected unit names, malformed/mismatched properties, and duplicate fields. They do **not** substitute for live systemd integration testing. An optional live test should run on an Ubuntu 26.04 systemd host under a non-privileged user, against a known fixture unit, without modifying its state.

The subprocess collector drains stdout concurrently with exit monitoring using a nonblocking local socket. One deadline covers child execution and EOF; output above 8 KiB is rejected and the direct child is killed/reaped on failure. Synthetic Python helpers test large output, timeouts and inherited stdout; they do not validate a real system bus. Python is a test dependency only.
