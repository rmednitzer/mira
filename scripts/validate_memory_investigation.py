#!/usr/bin/env python3
"""Independent explicit-memory expectation schema, semantics and CLI checks."""
import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource
from compare_evidence import strict_json

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = json.loads((ROOT / 'schemas/evidence-v1.schema.json').read_text())
SCHEMA = json.loads((ROOT / 'schemas/memory-headroom-v1.schema.json').read_text())
Draft202012Validator.check_schema(SCHEMA)
REGISTRY = Registry().with_resource(EVIDENCE['$id'], Resource.from_contents(EVIDENCE))
VALIDATOR = Draft202012Validator(SCHEMA, registry=REGISTRY)


def check_report(report):
    VALIDATOR.validate(report)
    evidence = report['evidence']
    if evidence['status'] == 'unavailable':
        expected = 'indeterminate', 'evidence_unavailable', 3
    else:
        value = evidence['value']
        if not 0 <= value['available_kib'] <= value['total_kib'] <= 2 ** 64 - 1:
            raise ValueError('invalid memory values')
        if value['available_kib'] >= report['expectation']['minimum_available_kib']:
            expected = 'satisfied', 'minimum_met', 0
        else:
            expected = 'not_satisfied', 'below_minimum', 1
    if (report['assessment']['outcome'], report['assessment']['reason']) != expected[:2]:
        raise ValueError('assessment contradicts memory evidence')
    return expected[2]


def check_fixtures():
    cases = json.loads((ROOT / 'tests/fixtures/memory-headroom-v1.json').read_text())
    for report in cases['valid']:
        check_report(report)
    for report in cases['invalid']:
        try:
            check_report(report)
        except (ValueError, ValidationError):
            pass
        else:
            raise ValueError('invalid memory fixture admitted')


def main():
    check_fixtures()
    binary = str(ROOT / 'target/debug/mira')
    for minimum in ('1', '18446744073709551615'):
        result = subprocess.run([binary, 'investigate', 'memory-headroom',
                                 '--min-available-kib', minimum, '--json'],
                                capture_output=True, timeout=10, check=False)
        report = strict_json(result.stdout)
        if result.returncode != check_report(report):
            raise ValueError('memory exit mismatch')
        if report['expectation']['minimum_available_kib'] != int(minimum):
            raise ValueError('memory criterion changed')
    for minimum in ('', '0', '-1', '+1', '1.0', '1e3', '18446744073709551616',
                    '000000000000000000001'):
        result = subprocess.run([binary, 'investigate', 'memory-headroom',
                                 '--min-available-kib', minimum, '--json'],
                                capture_output=True, timeout=5, check=False)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid memory criterion dispatched')
    print('memory-headroom schema, semantic fixtures and CLI validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'memory investigation validation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
