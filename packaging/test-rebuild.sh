#!/usr/bin/env bash
# Recompile in two fresh trees; compare the selected binary and complete archives.
set -euo pipefail
trap 'echo "independent rebuild failed at line $LINENO" >&2' ERR
cd "$(dirname "$0")/.."
selected_deb="$(realpath "${1:?selected package required}")"
receipt="${2:?new receipt path required}"
test -f "$selected_deb"
test ! -e "$receipt"
if test -n "$(git status --porcelain --untracked-files=no)"; then
  echo "source checkout is modified" >&2
  exit 1
fi
source_commit="$(git rev-parse HEAD)"
source_tree="$(git rev-parse 'HEAD^{tree}')"
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export LC_ALL=C
export CARGO_INCREMENTAL=0
# No caller-supplied flags may silently change this comparison profile.
test -z "${RUSTFLAGS:-}"
test -z "${CARGO_ENCODED_RUSTFLAGS:-}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
first="$work/first"
second="$work/different-length-parent/second-source"
mkdir -p "$first" "$second"
for destination in "$first" "$second"; do
  git archive --format=tar "$source_commit" | tar -xf - -C "$destination"
done
(
  umask 022
  cd "$first"
  export TZ=UTC
  cargo build --release --locked --target-dir target
  bash packaging/build-deb.sh output
)
(
  umask 077
  cd "$second"
  export TZ=Europe/Vienna
  cargo build --release --locked --target-dir different-target
  # The package builder has a fixed target/release input contract.
  mkdir -p target/release
  cp different-target/release/mira target/release/mira
  bash packaging/build-deb.sh output
)
cmp "$first/target/release/mira" "$second/different-target/release/mira"
cmp target/release/mira "$first/target/release/mira"
first_deb="$(find "$first/output" -maxdepth 1 -name '*.deb' -print -quit)"
second_deb="$(find "$second/output" -maxdepth 1 -name '*.deb' -print -quit)"
test -n "$first_deb"
test -n "$second_deb"
cmp "$first_deb" "$second_deb"
cmp "$selected_deb" "$first_deb"
python3 - "$receipt" "$source_commit" "$source_tree" "$SOURCE_DATE_EPOCH" \
  target/release/mira "$selected_deb" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
output, commit, tree, epoch, binary, archive = sys.argv[1:]
def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
rust = subprocess.check_output(['rustc', '-Vv'], text=True)
receipt = {
    'receipt_version': 1, 'source_commit': commit, 'source_tree': tree,
    'source_date_epoch': int(epoch), 'binary_sha256': digest(binary),
    'package_sha256': digest(archive), 'rustc': rust.strip(),
    'cargo': subprocess.check_output(['cargo', '-V'], text=True).strip(),
    'fresh_source_trees': 2, 'fresh_target_directories': 2,
    'environment_variations': ['source_path', 'target_path', 'umask', 'timezone'],
    'raw_binary_comparison': 'identical', 'package_comparison': 'identical',
    'selected_artifact_comparison': 'identical',
    'scope': 'two fresh compilations on one native runner with one compiler/system dependency environment; not independent-host or hermetic-build proof',
}
with Path(output).open('x') as handle:
    json.dump(receipt, handle, sort_keys=True, indent=2)
    handle.write('\n')
print('fresh source/target builds and selected binary/package bytes are identical')
PY
