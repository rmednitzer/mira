#!/usr/bin/env python3
"""Independent investigation-v1 shape, scope and reported-state contract checks."""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = json.loads((ROOT / 'schemas/evidence-v1.schema.json').read_text())
SCHEMA = json.loads((ROOT / 'schemas/investigation-v1.schema.json').read_text())
Draft202012Validator.check_schema(EVIDENCE)
Draft202012Validator.check_schema(SCHEMA)
# Register the exact local evidence schema; no remote reference retrieval.
REGISTRY = Registry().with_resource(EVIDENCE['$id'], Resource.from_contents(EVIDENCE))
VALIDATOR = Draft202012Validator(SCHEMA, registry=REGISTRY)
UNIT = re.compile(r'(?!-)(?:[A-Za-z0-9._@:-]|\\x[0-9A-Fa-f]{2})+\.service')


def expected(active):
    if active in ('active', 'reloading', 'refreshing'):
        return 'satisfied', 'reported_active', 0
    if active in ('inactive', 'failed', 'maintenance'):
        return 'not_satisfied', 'reported_not_active', 1
    if active in ('activating', 'deactivating'):
        return 'indeterminate', 'transition_in_progress', 3
    return 'indeterminate', 'unrecognized_active_state', 3


def check_report(report):
    VALIDATOR.validate(report)
    evidence = report['evidence']
    if UNIT.fullmatch(report['scope']) is None or evidence['scope'] != report['scope']:
        raise ValueError('invalid or mismatched scope')
    if evidence['status'] == 'observed':
        unit = evidence['value']['id']
        if not 9 <= len(unit) <= 200 or UNIT.fullmatch(unit) is None:
            raise ValueError('invalid service identity')
        outcome, reason, code = expected(evidence['value']['active_state'])
    else:
        outcome, reason, code = 'indeterminate', 'evidence_unavailable', 3
    if report['assessment']['outcome'] != outcome or report['assessment']['reason'] != reason:
        raise ValueError('assessment disagrees with evidence')
    return code


def cli(unit):
    result = subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate',
                             'service-active', unit, '--json'],
                            capture_output=True, text=True, timeout=15, check=False)
    report = json.loads(result.stdout)
    if result.returncode != check_report(report):
        raise ValueError('exit status disagrees with assessment')
    return report


def live():
    if os.geteuid() == 0:
        raise ValueError('live check requires an unprivileged user')
    unit = 'systemd-journald.service'
    argv = ['systemctl', '--system', '--no-pager', '--no-ask-password', 'show',
            '--property=Id,Names,LoadState,ActiveState,SubState', '--', unit]

    def direct():
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5, check=True)
        return dict(line.split('=', 1) for line in result.stdout.splitlines())

    before = direct()
    report = cli(unit)
    after = direct()
    if before != after:
        raise ValueError('live fixture changed; comparison inconclusive')
    value = {'id': before['Id'], 'load_state': before['LoadState'],
             'active_state': before['ActiveState'], 'sub_state': before['SubState']}
    if unit not in before['Names'].split() or report['scope'] != unit:
        raise ValueError('live scope mismatch')
    if report['evidence']['status'] != 'observed' or report['evidence']['value'] != value:
        raise ValueError('live evidence mismatch')
    print('unprivileged live investigation contract validated')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-systemd', action='store_true')
    args = parser.parse_args()
    cases = json.loads((ROOT / 'tests/fixtures/investigation-v1.json').read_text())
    for record in cases['valid']:
        check_report(record)
    for record in cases['invalid']:
        try:
            check_report(record)
        except Exception as error:
            from jsonschema import ValidationError
            if not isinstance(error, (ValueError, ValidationError)):
                raise
        else:
            raise ValueError('invalid fixture accepted')
    for template, unit in [('restart', 'ssh.service'), ('service-active', '--user.service'),
                           ('service-active', 'x'), ('service-active', 'x' * 300 + '.service')]:
        result = subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate',
                                 template, unit, '--json'],
                                capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid invocation dispatched or emitted a report')
    if args.live_systemd:
        live()
    print('investigation-v1 schema, semantic fixtures and CLI admission validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # A fixed diagnostic class, never record values or backend errors.
        print(f'investigation validation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
