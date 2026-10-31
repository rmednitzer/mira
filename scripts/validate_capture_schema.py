#!/usr/bin/env python3
"""Independent capture schema, exact-source-set and CLI checks."""
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from capture_contract import ROOT, check_capture
from compare_evidence import load, compare, strict_json


def main():
    fixtures = json.loads((ROOT / 'tests/fixtures/capture-v1.json').read_text())
    for case in fixtures['valid']:
        check_capture(case)
    for case in fixtures['invalid']:
        try:
            check_capture(case)
        except (ValueError, ValidationError):
            pass
        else:
            raise ValueError('invalid capture admitted')
    # The producer now requires a leading letter or digit, but capture-v1
    # admission is unchanged so previously produced documents stay comparable.
    earlier = copy.deepcopy(fixtures['valid'][0])
    earlier['capture_scope'] = '-earlier-producer-label'
    check_capture(earlier)
    legacy =json.loads((ROOT / 'schemas/evidence-v1.schema.json').read_text())
    validator = Draft202012Validator(legacy)
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'capture'
        for pressure in (False, True):
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                     *(['--pressure'] if pressure else [])],
                                    capture_output=True, timeout=15, check=False)
            document = check_capture(strict_json(result.stdout))
            if result.returncode != (0 if document['all_available'] else 1):
                raise ValueError('capture exit mismatch')
            if len(document['records']) != (7 if pressure else 5):
                raise ValueError('capture source count mismatch')
            path.write_bytes(result.stdout)
            admitted = load(path, validator)
            report = compare(admitted, admitted)
            if report['comparison_version'] != 2 or not report['collection_complete']:
                raise ValueError('completion lost during comparison')
            if any(row['outcome'] not in ('unchanged', 'indeterminate') for row in report['changes']):
                raise ValueError('self-comparison mismatch')
            altered = copy.copy(admitted)
            altered.scope = 'another-scope'
            try:
                compare(admitted, altered)
            except ValueError:
                pass
            else:
                raise ValueError('scope mismatch admitted')
            altered.profile = 'another-profile'
            altered.scope = admitted.scope
            try:
                compare(admitted, altered)
            except ValueError:
                pass
            else:
                raise ValueError('profile mismatch admitted')
            try:
                compare(admitted, {})
            except ValueError:
                pass
            else:
                raise ValueError('mixed capture formats admitted')
        for label in ('', 'private path', 'x' * 65, 'x\x1b', '--pressure', '-', '.hidden'):
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', label],
                                    capture_output=True, timeout=5, check=False)
            if result.returncode != 2 or result.stdout:
                raise ValueError('invalid capture label dispatched')
    print('capture-v1 and evidence-v2 schema, semantic fixtures and CLI validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'capture validation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
