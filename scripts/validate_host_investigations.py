#!/usr/bin/env python3
"""Independent uptime-minimum and kernel-release schema, semantic and live procfs checks."""
import json
import re
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource
from compare_evidence import strict_json

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = json.loads((ROOT / 'schemas/evidence-v2.schema.json').read_text())
REGISTRY = Registry().with_resource(EVIDENCE['$id'], Resource.from_contents(EVIDENCE))
U64 = 2 ** 64 - 1


def validator(name):
    schema = json.loads((ROOT / f'schemas/{name}.schema.json').read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=REGISTRY)


UPTIME = validator('uptime-minimum-v1')
KERNEL = validator('kernel-release-v1')


def check_uptime(report):
    UPTIME.validate(report)
    evidence = report['evidence']
    if evidence['status'] == 'unavailable':
        expected = 'indeterminate', 'evidence_unavailable', 3
    elif evidence['value'] >= report['expectation']['minimum_uptime_seconds']:
        expected = 'satisfied', 'minimum_met', 0
    else:
        expected = 'not_satisfied', 'below_minimum', 1
    if (report['assessment']['outcome'], report['assessment']['reason']) != expected[:2]:
        raise ValueError('assessment contradicts uptime evidence')
    return expected[2]


def check_kernel(report):
    KERNEL.validate(report)
    evidence = report['evidence']
    if evidence['status'] == 'unavailable':
        expected = 'indeterminate', 'evidence_unavailable', 3
    elif evidence['value'] == report['expectation']['release']:
        expected = 'satisfied', 'release_matches', 0
    else:
        expected = 'not_satisfied', 'release_differs', 1
    if (report['assessment']['outcome'], report['assessment']['reason']) != expected[:2]:
        raise ValueError('assessment contradicts kernel evidence')
    return expected[2]


def check_fixtures(name, schema, check):
    cases = json.loads((ROOT / f'tests/fixtures/{name}.json').read_text())
    for report in cases['valid']:
        check(report)
    semantic_only = 0
    for report in cases['invalid']:
        try:
            schema.validate(report)
        except ValidationError:
            continue
        semantic_only += 1
        try:
            check(report)
        except ValueError:
            continue
        raise ValueError(f'invalid {name} fixture admitted')
    if semantic_only != cases['semantic_only']:
        raise ValueError(f'unexpected number of schema-valid invalid {name} fixtures')


def read(path, limit):
    """Independent bounded direct read; it does not reuse the Rust parsers."""
    with Path(path).open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('direct procfs sample exceeds budget')
    return data.decode('ascii')


def direct_uptime():
    match = re.fullmatch(r'([0-9]+)(?:\.[0-9]+)?[ \t]+[0-9]+(?:\.[0-9]+)?\n?',
                         read('/proc/uptime', 65536))
    if match is None:
        raise ValueError('invalid direct uptime sample')
    return int(match.group(1))


def direct_kernel():
    kernel = read('/proc/sys/kernel/osrelease', 16384).removesuffix('\n')
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+\-]{0,255}', kernel) is None:
        raise ValueError('invalid direct kernel sample')
    return kernel


def run(arguments, timeout=10):
    return subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate', *arguments],
                          capture_output=True, timeout=timeout, check=False)


def check_live():
    before = direct_uptime()
    reports = []
    for minimum in (max(before, 1), U64):
        result = run(['uptime-minimum', '--min-uptime-seconds', str(minimum), '--json'])
        report = strict_json(result.stdout)
        if result.returncode != check_uptime(report):
            raise ValueError('uptime exit mismatch')
        if report['expectation']['minimum_uptime_seconds'] != minimum:
            raise ValueError('uptime criterion changed')
        reports.append(report)
    after = direct_uptime()
    if before > after:
        raise ValueError('live uptime went backwards; comparison inconclusive')
    for report in reports:
        if report['evidence']['status'] != 'observed':
            raise ValueError('live uptime evidence unavailable')
        if not before <= report['evidence']['value'] <= after:
            raise ValueError('MIRA uptime outside direct procfs interval')
    if before >= 1 and reports[0]['assessment']['outcome'] != 'satisfied':
        raise ValueError('uptime at the directly observed minimum was not met')

    kernel = direct_kernel()
    for expected, outcome in ((kernel, 'satisfied'), (kernel + '-mira-differs', 'not_satisfied')):
        result = run(['kernel-release', '--expect', expected, '--json'])
        report = strict_json(result.stdout)
        if result.returncode != check_kernel(report):
            raise ValueError('kernel exit mismatch')
        if report['expectation']['release'] != expected:
            raise ValueError('kernel criterion changed')
        if report['evidence'].get('value') != kernel or report['assessment']['outcome'] != outcome:
            raise ValueError('MIRA kernel release disagrees with direct procfs')
    if direct_kernel() != kernel:
        raise ValueError('live kernel release changed; comparison inconclusive')

    for minimum in ('', '0', '-1', '1.0', '18446744073709551616'):
        result = run(['uptime-minimum', '--min-uptime-seconds', minimum, '--json'], 5)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid uptime minimum dispatched')
    for release in ('', ' 6.17', '6.17 ', '--json', '6.17/0'):
        result = run(['kernel-release', '--expect', release, '--json'], 5)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid kernel release dispatched')


def main():
    check_fixtures('uptime-minimum-v1', UPTIME, check_uptime)
    check_fixtures('kernel-release-v1', KERNEL, check_kernel)
    check_live()
    print('uptime-minimum and kernel-release schemas, semantic fixtures and live procfs validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Reports contain sampled host values; print only the error type.
        print(f'host investigation validation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
