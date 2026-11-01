# Host qualification

[ADR 0013](adr/0013-host-qualification-protocol.md) defines how MIRA is qualified on representative hosts. `scripts/qualify_host.py` runs the independent validators' check groups against one MIRA binary as an unprivileged user and writes a `qualification-receipt-v1` receipt ([schema](../schemas/qualification-receipt-v1.schema.json)). A receipt is evidence about one host at one time. It is not a fleet guarantee, production readiness or signed provenance.

## Running it

From a clean checkout of the commit being qualified, as a user who is not root:

```bash
python3 -m venv .schema-venv
.schema-venv/bin/python -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements-schema.txt
cargo build --locked
.schema-venv/bin/python scripts/qualify_host.py --host-class vm --receipt /tmp/mira-vm.json
```

To qualify an installed or packaged binary instead of the checkout build, add `--binary /usr/bin/mira`. The receipt records `binary_origin` as `checkout-build` for a binary under this checkout's `target/` directory and `installed` for any other binary, including an extracted package. It also records the binary's SHA-256.

The runner refuses to run as root, refuses an existing receipt path and refuses a checkout with any modified or untracked file, so the receipt binds a known source commit and tree. It hashes the binary before the first group and refuses to write a receipt if the binary or the checkout changed by the end. It installs nothing, changes no configuration and writes only the receipt. It discards validator output; only exit statuses, fixed reasons and fixed gap identifiers reach the receipt.

Exit status: 0 when every group passed or was expectedly not applicable with only expected gaps; 1 when any group failed; 2 on refusal or a usage error; 3 when nothing failed but the receipt deviates from the class's expected gaps. The runner prints one fixed line per group and per deviation.

## What runs

Each validator declares fixed check groups (`--list-groups`) and runs a selection with `--only GROUP[,GROUP]`. Without `--only` a validator runs as before, so CI's existing invocations are unchanged. In particular, a default journal run on a host without a visible journal still passes on its denial-path check and skips the count comparison; only an explicit `--only live-counts`, which the runner selects after probing a visible sentinel, treats a missing sentinel as inconclusive. Every capture invocation, not only the first, reports its unavailable sources and an unavailable boot binding. The validators take the binary from `MIRA_BINARY`. They exit 0 passed, 1 failed (wrong evidence) or 4 inconclusive (a live value changed during the comparison). The runner retries an inconclusive group at most twice and then records it as failed with reason `inconclusive`. Any other exit status, a timeout or a validator that cannot start is failed with reason `runner_error`. Each validator runs in its own session, and its whole process group is killed when it exits, times out or the runner is interrupted, so no work it started outlives its group.

| Validator | Groups | Gated on |
|---|---|---|
| evidence | `fixtures`, `cli`, `live-procfs`, `live-systemd` | `live-systemd`: systemd as init and `systemctl` (`no_systemd`) |
| investigation | `fixtures`, `cli`, `live-systemd` | `live-systemd`: `no_systemd` |
| capture | `schema`, `cli`, `compare`, `live-boot`, `signed-compare`, `challenge` | `live-boot`: the boot ID file (`no_boot_id`); `signed-compare` and `challenge`: `/usr/bin/ssh-keygen` (`no_ssh_keygen`) |
| memory | `fixtures`, `cli` | none |
| pressure | `fixtures`, `cli` | none; an unavailable PSI file is accepted and reported as a gap |
| package | `fixtures`, `cli`, `live-dpkg` | `live-dpkg`: a readable dpkg status file (`no_dpkg`) |
| host | `fixtures`, `cli`, `live` | none |
| journal | `fixtures`, `cli`, `live-visibility`, `live-counts` | `live-visibility`: `journalctl` (`no_journal_access`); `live-counts`: also a visible PID 1 sentinel (`no_journal_access`) |

Denial paths are never gated. A precondition never skips the check that validates MIRA's handling of that missing capability:
- `journal live-visibility` compares MIRA's `journal_visible` and `journal_access_complete` answers with the validator's own, including when they are false.
- `evidence cli` checks that a service query without systemd as init stays explicitly unavailable.
- `package cli` checks that an unreadable dpkg database stays explicitly unavailable.
- `pressure cli` accepts an unavailable PSI file.

The `no_psi` reason exists in the receipt vocabulary but no current group is gated on PSI, because every PSI check is itself the denial path.

## Observation gaps

A group can pass while MIRA correctly reported a source as unavailable. Through `MIRA_QUALIFICATION_STATUS` each validator reports those sources: only fixed identifiers (such as `/proc/pressure/io`, `systemd/system` or `journal/system`) with their fixed failure reason (such as `not_found` or `journal_not_visible`), never a value. The runner admits only the closed source set and drops a malformed report as `runner_error`.

## Host classes and expected gaps

`host_class` is the operator's declaration and is not verified.

| Class | Required for Phase 1 | Expected not applicable | Expected gaps |
|---|---|---|---|
| `physical-amd64` | yes | none | none |
| `physical-arm64` | yes | none | none |
| `vm` | yes | none | none |
| `container` | yes | `no_systemd`, `no_journal_access`, `no_ssh_keygen`, `no_boot_id` | `systemd/system`, `journal/system`, `/proc/sys/kernel/random/boot_id` |
| `restricted-user` | yes | `no_journal_access` (only `live-counts`) | `journal/system`, which is also **required** |
| `wsl` | no | none | none |
| `ci-runner` | no | none | none |

`restricted-user` is a second run on a required host as a user outside `adm` and `systemd-journal`. It must show the `journal/system` gap (`journal_not_visible` or `journal_access_incomplete`) from a passing `live-visibility` group. Without it the run did not exercise the denial path and does not count.

Review treats both kinds of deviation equally. An unexpected `not_applicable` group, or an unexpected gap inside a passing group (for example `/proc/pressure/io` unavailable on a physical host), is a finding to investigate, not a pass. Changing this table is a reviewed change to the protocol.

Phase 1 exits when each required class, including the `restricted-user` run, has one reviewed receipt with no failed group and no deviation from this table.

## Receipt contents

The receipt holds only the fields listed in ADR 0013:
- the source commit and tree, and the binary's SHA-256 and origin
- the declared host class
- the `os-release` `ID` and `VERSION_ID`, the dpkg architecture, the systemd major version and the kernel `major.minor` series
- the capability booleans
- per group: validator, group, result, fixed reason, duration and observation gaps
- an unverified wall-clock start and a monotonic duration

It never contains a host name, machine ID, boot ID, user name, address, full kernel release, package or unit name, or any sampled value. The schema's closed properties enforce that. The runner tests also run it on the real host and scan the receipt for the host name, machine ID, boot ID, user name and full kernel release.

## Submitting a receipt

Commit each reviewed receipt under [`qualification/receipts/`](qualification/receipts/) in its own pull request, named `<host-class>-<YYYY-MM-DD>.json`. State the host's hardware or virtualization type in the description. The runner tests validate every committed receipt against the schema. Receipts are unsigned: review and git history provide custody. Signing would need a third ADR 0011 namespace and is deferred.

CI runs the runner as `ci-runner` against both the checkout build and the extracted package binary, and keeps both receipts with the workflow artifacts. GitHub-hosted runners are not a required class.

## What a receipt does not prove

- That the host is of the declared class, or that it is physical.
- That the same results hold on another host, another boot or another day.
- Anything the validators do not check, such as performance, upgrade behaviour or the absence of vulnerabilities.
- That the receipt was not edited after it was written. Only review and the commit history bind it.
