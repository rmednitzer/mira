#!/usr/bin/env bash
set -euo pipefail
# Package modes must not depend on the invoking user's umask.
umask 022
cd "$(dirname "$0")/.."
export LC_ALL=C
version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)"
test -n "$version"
arch="$(dpkg --print-architecture)"
case "$arch" in amd64|arm64) ;; *) echo "unsupported architecture: $arch" >&2; exit 2;; esac
test -x target/release/mira || { echo "build target/release/mira first" >&2; exit 2; }
out="${1:-dist}"
mkdir -p "$out"
out="$(realpath "$out")"
build_root="$(mktemp -d)"
trap 'rm -rf "$build_root"' EXIT
stage="$build_root/debian/mira"
mkdir -p "$stage/DEBIAN"
chmod 755 "$stage"
install -Dm755 target/release/mira "$stage/usr/bin/mira"
strip --strip-unneeded "$stage/usr/bin/mira"
mkdir -p "$stage/usr/share/doc/mira"
cat > "$stage/usr/share/doc/mira/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: MIRA
Source: https://github.com/rmednitzer/mira

Files: *
Copyright: 2026 MIRA contributors
License: Apache-2.0
 On Debian systems the complete Apache License, Version 2.0,
 is available at /usr/share/common-licenses/Apache-2.0.
EOF
cat <<EOF | gzip -n -9 > "$stage/usr/share/doc/mira/changelog.Debian.gz"
mira (${version}-1) unstable; urgency=medium

  * Experimental CLI-only package.

 -- MIRA Project <noreply@github.com>  Fri, 30 Oct 2026 12:00:00 +0000
EOF
mkdir -p "$stage/usr/share/man/man1"
cat <<'EOF' | gzip -n -9 > "$stage/usr/share/man/man1/mira.1.gz"
.TH MIRA 1 "2026-10-30" "MIRA" "User Commands"
.SH NAME
mira \- read-only Linux evidence CLI
.SH SYNOPSIS
.B mira inspect [--json]
.br
.B mira service UNIT.service [--json]
.br
.B mira demo
.SH DESCRIPTION
Experimental read-only host evidence inspection. No remediation or background service.
EOF
install -Dm644 docs/evidence-json.md "$stage/usr/share/doc/mira/evidence-json.md"
install -Dm644 schemas/evidence-v1.schema.json "$stage/usr/share/mira/schemas/evidence-v1.schema.json"
# Derive versioned ABI dependencies from the native binary and distro metadata.
printf 'Source: mira\nSection: admin\nPriority: optional\nMaintainer: MIRA Project <noreply@github.com>\n\nPackage: mira\nArchitecture: any\nDescription: Read-only Linux evidence CLI\n' > "$build_root/debian/control"
depends="$(cd "$build_root" && dpkg-shlibdeps -O -edebian/mira/usr/bin/mira)"
case "$depends" in shlibs:Depends=?*) depends="${depends#shlibs:Depends=}" ;; *) echo "missing ELF dependency metadata" >&2; exit 2 ;; esac
cat >"$stage/DEBIAN/control" <<EOF
Package: mira
Version: ${version}-1
Architecture: $arch
Maintainer: MIRA Project <noreply@github.com>
Section: admin
Priority: optional
Depends: $depends
Homepage: https://github.com/rmednitzer/mira
Description: Read-only Linux infrastructure evidence CLI
 Local-first experimental Linux inspection and structured evidence reporting.
 No background service or automatic remediation is installed.
EOF
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
find "$stage" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
dpkg-deb --root-owner-group --build "$stage" "$out/mira_${version}-1_${arch}.deb"
(cd "$out" && sha256sum "mira_${version}-1_${arch}.deb" > "mira_${version}-1_${arch}.deb.sha256")
