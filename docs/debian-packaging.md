# Debian package foundation (experimental)

`packaging/build-deb.sh` stages the already compiled release binary into a CLI-only Debian package. It installs `/usr/bin/mira`, the Apache-2.0 license, evidence/investigation documentation and both versioned schemas. It includes no maintainer scripts, systemd units, timers, daemon, user creation, configuration mutations or install-time activation.

Build on native Ubuntu 26.04 amd64 and arm64 with `cargo build --release --locked`, then `bash packaging/build-deb.sh`. Native `dpkg-dev` and binutils are required: `dpkg-shlibdeps` derives versioned runtime ABI requirements from the compiled binary and the build distribution metadata. The package script supports `SOURCE_DATE_EPOCH` for normalized file timestamps, uses root-owned package metadata, and writes a SHA-256 file. This is an initial binary packaging path, **not** a Debian source package, signed release or verified bit-for-bit reproducible build.

CI must inspect the archive for unexpected paths, validate metadata, extract and execute the CLI and test installation/removal in an isolated disposable environment before promotion. Release signing, dependency scanning, hermetic compilation, build provenance, clean-system upgrade/downgrade and apt repository publishing are later gates. Package contents should not expose host configuration or private infrastructure.

## Optional collector: design only

Do not install or enable a unit yet. An eventual systemd oneshot + timer requires a bounded output sink, retention and atomic-write design, verified IPC access for the systemd query, explicit enablement, dynamic-user/filesystem constraints and failure/restart tests. It should be a separate `mira-collector` package if justified by a documented unattended collection requirement. Neither `ProtectSystem=strict` nor `DynamicUser=yes` alone proves sandbox isolation; validate behavior on target hosts.

## Repeatable assembly boundary

CI assembles the same compiled binary twice in separate staging directories under ordinary and restrictive invoking umasks, then compares the resulting `.deb` bytes. The builder sets umask 022 so package permissions do not inherit the caller's mask. Native test helpers are never installed. `SOURCE_DATE_EPOCH` is exported to archive tools as well as used for file timestamps. This checks deterministic archive assembly only: independent clean Rust compilations, source-path independence, actual dependency resolution and version-to-version upgrades remain outstanding release gates.

On hosted amd64 runners, dpkg-shlibdeps reports the distribution's libc6 merged-/usr loader diversion. Keep that warning visible; the native dependency metadata is not a replacement for clean-system installation and loader validation before release.
