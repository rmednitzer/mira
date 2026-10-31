#!/usr/bin/env python3
"""Independent explicit pressure-ceiling schema, semantics and CLI checks."""
import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource
from compare_evidence import strict_json

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = json.loads((ROOT / 'schemas/evidence-v2.schema.json').read_text())
SCHEMA = json.loads((ROOT / 'schemas/pressure-ceiling-v1.schema.json').read_text())
Draft202012Validator.check_schema(SCHEMA)
REGISTRY = Registry().with_resource(EVIDENCE['$id'], Resource.from_contents(EVIDENCE))
VALIDATOR = Draft202012Validator(SCHEMA, registry=REGISTRY)
RESOURCES = ('cpu', 'memory', 'io')
# Fixture indexes that are schema-valid and refused only by the semantic check.
SEMANTIC_ONLY = 2
OPTION = '--max-some-avg10-basis-points'


def expected_assessment(report):
    """Derive the assessment from evidence and criterion, independent of Rust."""
    evidence = report['evidence']
    if evidence['status'] == 'unavailable':
        return 'indeterminate', 'evidence_unavailable', 3
    some = evidence['value']['some_avg10_basis_points']
    if some <= report['expectation']['max_some_avg10_basis_points']:
        return 'satisfied', 'within_ceiling', 0
    return 'not_satisfied', 'above_ceiling', 1


def check_report(report):
    VALIDATOR.validate(report)
    expected = expected_assessment(report)
    if (report['assessment']['outcome'], report['assessment']['reason']) != expected[:2]:
        raise ValueError('assessment contradicts pressure evidence')
    return expected[2]


def check_fixtures():
    cases = json.loads((ROOT / 'tests/fixtures/pressure-ceiling-v1.json').read_text())
    for report in cases['valid']:
        check_report(report)
    semantic_only = 0
    for report in cases['invalid']:
        try:
            VALIDATOR.validate(report)
        except ValidationError:
            continue
        semantic_only += 1
        try:
            check_report(report)
        except ValueError:
            continue
        raise ValueError('invalid pressure fixture admitted')
    if semantic_only != SEMANTIC_ONLY:
        raise ValueError('unexpected number of schema-valid invalid fixtures')


def run(arguments, timeout):
    return subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate', 'pressure-ceiling',
                           *arguments], capture_output=True, timeout=timeout, check=False)


def check_cli():
    for resource in RESOURCES:
        for maximum in ('0', '10000'):
            result = run(['--resource', resource, OPTION, maximum, '--json'], 10)
            report = strict_json(result.stdout)
            if result.returncode != check_report(report):
                raise ValueError('pressure exit mismatch')
            expectation = report['expectation']
            if (expectation['resource'], expectation['max_some_avg10_basis_points']) != (
                    resource, int(maximum)):
                raise ValueError('pressure criterion changed')
            if report['evidence']['source'] != f'/proc/pressure/{resource}':
                raise ValueError('pressure source does not match resource')
    for maximum in ('', '-1', '+1', '1.5', '1e3', '10001', '000000', ' 1'):
        result = run(['--resource', 'cpu', OPTION, maximum, '--json'], 5)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid pressure ceiling dispatched')
    for resource in ('', 'CPU', 'irq', '../io'):
        result = run(['--resource', resource, OPTION, '1', '--json'], 5)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid pressure resource dispatched')


def main():
    check_fixtures()
    check_cli()
    print('pressure-ceiling schema, semantic fixtures and CLI validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Reports can contain sampled host values; print only the error type.
        print(f'pressure investigation validation failed: {type(error).__name__}',
              file=sys.stderr)
        sys.exit(1)
