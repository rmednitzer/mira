#!/usr/bin/env bash
# Disposable native Ubuntu container; never installs on the invoking host.
set -euo pipefail
trap 'echo "clean-install check failed at line $LINENO" >&2' ERR
cd "$(dirname "$0")/.."
deb="$(realpath "${1:?package.deb required}")"
receipt="${2:?new receipt path required}"
test -f "$deb"
test ! -e "$receipt"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
source_commit="$(git rev-parse HEAD)"
source_tree="$(git rev-parse 'HEAD^{tree}')"
if test -n "$(git status --porcelain --untracked-files=no)"; then
  echo "source checkout changed before clean-install validation" >&2
  git diff --name-status HEAD -- >&2
  git diff -- Cargo.lock >&2
  exit 1
fi
package_sha="$(sha256sum "$deb" | cut -d' ' -f1)"
package_version="$(dpkg-deb -f "$deb" Version)"
package_arch="$(dpkg-deb -f "$deb" Architecture)"
# Verify actual installed bytes, rather than relying on optional dpkg md5 metadata.
dpkg-deb -x "$deb" "$work/extracted"
binary_sha="$(sha256sum "$work/extracted/usr/bin/mira" | cut -d' ' -f1)"
docker pull ubuntu:26.04 >&2
image_id="$(docker image inspect ubuntu:26.04 --format '{{.Id}}')"
image_digest="$(docker image inspect ubuntu:26.04 --format '{{index .RepoDigests 0}}')"
cat > "$work/inside.sh" <<'CONTAINER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >&2
apt-get install -y --no-install-recommends /tmp/mira.deb >&2
test "$(dpkg --print-architecture)" = "$EXPECTED_ARCH"
test "$(dpkg-query -W -f='${Version}' mira)" = "$EXPECTED_VERSION"
printf '%s  /usr/bin/mira\n' "$EXPECTED_BINARY_SHA" | sha256sum -c - >&2
/usr/bin/mira demo >/dev/null
set +e
/usr/bin/mira capture synthetic-clean-install --pressure > /tmp/capture.json
capture_exit=$?
set -e
test "$capture_exit" = 0 -o "$capture_exit" = 1
test -s /tmp/capture.json
# Stdout contains only the report; apt/log output goes to stderr.
cat /tmp/capture.json
CONTAINER
chmod 644 "$work/inside.sh"
docker run --rm --network bridge \
  -e "EXPECTED_ARCH=$package_arch" -e "EXPECTED_VERSION=$package_version" \
  -e "EXPECTED_BINARY_SHA=$binary_sha" \
  --mount "type=bind,src=$deb,dst=/tmp/mira.deb,readonly" \
  --mount "type=bind,src=$work/inside.sh,dst=/task.sh,readonly" \
  "$image_id" bash /task.sh > "$work/installed-capture.json"
PYTHONPATH=scripts .schema-venv/bin/python - "$work/installed-capture.json" "$receipt" \
  "$source_commit" "$source_tree" "$package_sha" "$package_version" "$package_arch" \
  "$binary_sha" "$image_id" "$image_digest" <<'PY'
import json, sys
from pathlib import Path
from capture_contract import check_capture
from compare_evidence import strict_json
capture, output, commit, tree, digest, version, arch, binary, image, repository_digest = sys.argv[1:]
check_capture(strict_json(Path(capture).read_bytes()))
receipt = {
    'receipt_version': 1, 'source_commit': commit, 'source_tree': tree,
    'package_sha256': digest, 'package_version': version, 'architecture': arch,
    'installed_binary_sha256': binary, 'container_image_id': image,
    'container_repository_digest': repository_digest,
    'dependency_resolution': 'passed', 'installed_demo': 'passed',
    'installed_capture_contract': 'passed',
    'scope': 'disposable native Ubuntu container; no physical-host or upgrade qualification',
}
with Path(output).open('x') as handle:
    json.dump(receipt, handle, sort_keys=True, indent=2)
    handle.write('\n')
print('clean-container dependency resolution, installed bytes and CLI contract passed')
PY
