#!/usr/bin/env python3
"""Exercise pip hash refusal against a changed wheel without installing its code."""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    lock = Path(__file__).resolve().parents[1] / 'requirements-schema.txt'
    with tempfile.TemporaryDirectory(prefix='mira-schema-lock-') as temp:
        root = Path(temp)
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'download', '--disable-pip-version-check',
             '--require-hashes', '--only-binary=:all:', '-r', str(lock), '-d', str(root)],
            capture_output=True, timeout=120, check=False,
        )
        if result.returncode:
            raise ValueError('locked wheel acquisition failed')
        candidates = list(root.glob('jsonschema-*.whl'))
        if len(candidates) != 1:
            raise ValueError('expected one jsonschema wheel')
        wheel = candidates[0]
        original = wheel.read_bytes()
        expected = hashlib.sha256(original).hexdigest()
        # One extra byte keeps a valid ZIP wheel but changes its admitted identity.
        wheel.write_bytes(original + b'\0')
        requirement = root / 'changed.txt'
        requirement.write_text(f'{wheel.as_uri()} --hash=sha256:{expected}\n')
        refused = subprocess.run(
            [sys.executable, '-m', 'pip', 'download', '--disable-pip-version-check',
             '--no-index', '--no-deps', '--no-cache-dir', '--require-hashes',
             '--only-binary=:all:', '-r', str(requirement), '-d', str(root / 'refused')],
            capture_output=True, text=True, timeout=30, check=False,
        )
        # Require the actual hash diagnostic; an unrelated install failure is insufficient.
        if refused.returncode == 0 or 'DO NOT MATCH THE HASHES' not in refused.stderr:
            raise ValueError('changed wheel was not refused by hash verification')
    print('locked wheel acquisition passed; modified wheel refused before installation')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'schema lock check failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
