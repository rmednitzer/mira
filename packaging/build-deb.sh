#!/usr/bin/env bash
set -euo pipefail
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
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
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
printf 'mira (%s-1) unstable; urgency=medium\\n\\n  * Experimental CLI-only package.\\n\\n -- MIRA Project <noreply@github.com>  Fri, 30 Oct 2026 12:00:00 +0000\\n' "$version" | gzip -n -9 > "$stage/usr/share/doc/mira/changelog.Debian.gz"
mkdir -p "$stage/usr/share/man/man1"
printf '.TH MIRA 1 "2026-10-30" "MIRA" "User Commands"\\n.SH NAME\\nmira \\- read-only Linux evidence CLI\\n.SH SYNOPSIS\\n.B mira inspect [--json]\\n.br\\n.B mira service UNIT.service [--json]\\n.br\\n.B mira demo\\n.SH DESCRIPTION\\nExperimental read-only host evidence inspection. No remediation or background service.\\n' | gzip -n -9 > "$stage/usr/share/man/man1/mira.1.gz"
install -Dm644 docs/evidence-json.md "$stage/usr/share/doc/mira/evidence-json.md"
install -Dm644 schemas/evidence-v1.schema.json "$stage/usr/share/mira/schemas/evidence-v1.schema.json"
mkdir -p "$stage/DEBIAN"
cat >"$stage/DEBIAN/control" <<EOF
Package: mira
Version: ${version}-1
Architecture: $arch
Maintainer: MIRA Project <noreply@github.com>
Section: admin
Priority: optional
Depends: libc6, libgcc-s1
Homepage: https://github.com/rmednitzer/mira
Description: Read-only Linux infrastructure evidence CLI
 Local-first experimental Linux inspection and structured evidence reporting.
 No background service or automatic remediation is installed.
EOF
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
find "$stage" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
dpkg-deb --root-owner-group --build "$stage" "$out/mira_${version}-1_${arch}.deb"
(cd "$out" && sha256sum "mira_${version}-1_${arch}.deb" > "mira_${version}-1_${arch}.deb.sha256")
