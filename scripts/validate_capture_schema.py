#!/usr/bin/env python3
"""Independent capture schema, exact-source-set and CLI checks."""
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from capture_contract import ROOT, VALIDATOR_V2, check_capture
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
    timeline = json.loads((ROOT / 'tests/fixtures/capture-v2.json').read_text())
    for case in timeline['valid']:
        check_capture(case)
    semantic_only = 0
    for case in timeline['invalid']:
        try:
            VALIDATOR_V2.validate(case)
        except ValidationError:
            continue
        semantic_only += 1
        try:
            check_capture(case)
        except ValueError:
            continue
        raise ValueError('invalid capture-v2 admitted')
    if semantic_only != timeline['semantic_only']:
        raise ValueError('unexpected number of schema-valid invalid capture-v2 fixtures')
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
        for pressure in (False, True):
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                     *(['--pressure'] if pressure else []), '--timeline'],
                                    capture_output=True, timeout=15, check=False)
            document = check_capture(strict_json(result.stdout))
            if document['capture_version'] != 2:
                raise ValueError('timeline capture is not capture-v2')
            if result.returncode != (0 if document['all_available'] else 1):
                raise ValueError('timeline capture exit mismatch')
            if document['collection']['boot'] != {'binding': 'not_requested'}:
                raise ValueError('boot identifier collected without request')
            path.write_bytes(result.stdout)
            current = load(path, validator)
            report = compare(current, current)
            if report['comparison_version'] != 2:
                raise ValueError('capture-v2 value comparison changed version')
            # Mixed capture-v1/v2 input with matching scope and profile compares values.
            plain = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                    *(['--pressure'] if pressure else [])],
                                   capture_output=True, timeout=15, check=False)
            path.write_bytes(plain.stdout)
            mixed = compare(load(path, validator), current)
            if mixed['comparison_version'] != 2 or len(mixed['changes']) != len(document['records']):
                raise ValueError('mixed capture versions not compared by value')
        for arguments in (['--timeline', '--pressure'], ['--timeline', '--timeline']):
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                     *arguments], capture_output=True, timeout=5, check=False)
            if result.returncode != 2 or result.stdout:
                raise ValueError('malformed timeline invocation dispatched')
        for label in ('', 'private path', 'x' * 65, 'x\x1b', '--pressure', '--timeline', '-', '.hidden'):
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', label],
                                    capture_output=True, timeout=5, check=False)
            if result.returncode != 2 or result.stdout:
                raise ValueError('invalid capture label dispatched')
    print('capture-v1/v2 and evidence-v2 schema, semantic fixtures, timeline and CLI validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'capture validation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
