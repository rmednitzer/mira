# Debian package foundation (experimental)

`packaging/build-deb.sh` stages the already compiled release binary into a CLI-only Debian package. It installs `/usr/bin/mira`, the Apache-2.0 license, evidence/investigation/capture documentation and all four versioned schemas. It includes no maintainer scripts, systemd units, timers, daemon, user creation, configuration mutations or install-time activation.

Build on native Ubuntu 26.04 amd64 and arm64 with `cargo build --release --locked`, then `bash packaging/build-deb.sh`. Native `dpkg-dev` and binutils are required: `dpkg-shlibdeps` derives versioned runtime ABI requirements from the compiled binary and the build distribution metadata. The package script supports `SOURCE_DATE_EPOCH` for normalized file timestamps, uses root-owned package metadata, and writes a SHA-256 file. This is an initial binary packaging path, **not** a Debian source package, signed release or verified bit-for-bit reproducible build.

CI must inspect the archive for unexpected paths, validate metadata, extract and execute the CLI and test installation/removal in an isolated disposable environment before promotion. Release signing, dependency scanning, hermetic compilation, build provenance, genuine version-to-version upgrade/downgrade and apt repository publishing are later gates. Package contents should not expose host configuration or private infrastructure.

## Optional collector: design only

Do not install or enable a unit yet. An eventual systemd oneshot + timer requires a bounded output sink, retention and atomic-write design, verified IPC access for the systemd query, explicit enablement, dynamic-user/filesystem constraints and failure/restart tests. It should be a separate `mira-collector` package if justified by a documented unattended collection requirement. Neither `ProtectSystem=strict` nor `DynamicUser=yes` alone proves sandbox isolation; validate behavior on target hosts.

## Repeatable assembly boundary

CI assembles the same compiled binary twice in separate staging directories under ordinary and restrictive invoking umasks, then compares the resulting `.deb` bytes. The builder sets umask 022 so package permissions do not inherit the caller's mask. Native test helpers are never installed. `SOURCE_DATE_EPOCH` is exported to archive tools as well as used for file timestamps. This checks deterministic archive assembly only: physical-host behavior and version-to-version upgrades remain outstanding release gates; the separate fresh-build test compares independent source/target compilations within one runner environment.

On hosted amd64 runners, dpkg-shlibdeps reports the distribution's libc6 merged-/usr loader diversion. Keep that warning visible; the native dependency metadata is not a replacement for clean-system installation and loader validation before release.

## Real dependency-resolution check

`packaging/test-clean-install.sh` installs the exact built archive into a fresh native Ubuntu 26.04 container through apt, without `--force-depends`. It compares the installed binary with the archive bytes and runs the installed demo and independently validated pressure capture. A new receipt binds the clean source commit/tree, package version/architecture/hash, installed binary hash and container image identity. The image is pulled by release tag then executed by immutable local image ID; apt repository state is current, not hermetically frozen. CI trust, registry availability and package repositories remain dependencies. No release upload or signing is performed. Clean physical hosts, real upgrades/downgrades, independent-host compilation and signed provenance remain unqualified.

Successful native CI retains the installation receipt for 30 days as a separate artifact; no host capture values are uploaded. PR receipts can identify GitHub’s synthetic merge checkout rather than the branch tip. The receipt remains unsigned and does not establish independent provenance.

## Fresh compilation comparison

`packaging/test-rebuild.sh` creates two fresh archives of the exact source revision and compiles into separate target directories under varied source/target paths, timezones and umasks. It compares unstripped release binaries, assembled archives and the selected production binary/package. Equality produces a separate new receipt bound to source commit/tree, source epoch, compiler version and artifact hashes. No successful receipt is emitted on mismatch. The compiler and native system dependencies are shared, so this closes only the stated same-runner variation check. It does not establish arbitrary-host or hermetic reproduction, signing or genuine upgrade behavior. See [ADR 0003](adr/0003-locked-tooling-and-fresh-builds.md).
