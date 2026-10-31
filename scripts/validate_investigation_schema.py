#!/usr/bin/env python3
"""Independent service-active v1/v2 shape, scope and reported-state contract checks."""
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
Draft202012Validator.check_schema(EVIDENCE)
# Register the exact local evidence schema; no remote reference retrieval.
REGISTRY = Registry().with_resource(EVIDENCE['$id'], Resource.from_contents(EVIDENCE))
VALIDATORS = {}
for _version in (1, 2):
    _schema = json.loads((ROOT / f'schemas/investigation-v{_version}.schema.json').read_text())
    Draft202012Validator.check_schema(_schema)
    VALIDATORS[_version] = Draft202012Validator(_schema, registry=REGISTRY)
TEMPLATES = {'service-active': 1, 'service-active/v1': 1, 'service-active/v2': 2}
UNIT = re.compile(r'(?!-)(?:[A-Za-z0-9._@:-]|\\x[0-9A-Fa-f]{2})+\.service')


def expected(active, load='loaded', version=1):
    # v2 adds exactly one rule: the not-found/inactive stub of an undefined name.
    if version == 2 and load == 'not-found' and active == 'inactive':
        return 'not_satisfied', 'unit_not_found', 1
    if active in ('active', 'reloading', 'refreshing'):
        return 'satisfied', 'reported_active', 0
    if active in ('inactive', 'failed', 'maintenance'):
        return 'not_satisfied', 'reported_not_active', 1
    if active in ('activating', 'deactivating'):
        return 'indeterminate', 'transition_in_progress', 3
    return 'indeterminate', 'unrecognized_active_state', 3


def check_report(report):
    version = report.get('investigation_version') if isinstance(report, dict) else None
    if type(version) is not int or version not in VALIDATORS:
        raise ValueError('unsupported investigation version')
    VALIDATORS[version].validate(report)
    evidence = report['evidence']
    if UNIT.fullmatch(report['scope']) is None or evidence['scope'] != report['scope']:
        raise ValueError('invalid or mismatched scope')
    if evidence['status'] == 'observed':
        unit = evidence['value']['id']
        if not 9 <= len(unit) <= 200 or UNIT.fullmatch(unit) is None:
            raise ValueError('invalid service identity')
        value = evidence['value']
        outcome, reason, code = expected(value['active_state'], value['load_state'], version)
    else:
        outcome, reason, code = 'indeterminate', 'evidence_unavailable', 3
    if report['assessment']['outcome'] != outcome or report['assessment']['reason'] != reason:
        raise ValueError('assessment disagrees with evidence')
    return code


def cli(unit, template='service-active'):
    result = subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate',
                             template, unit, '--json'],
                            capture_output=True, text=True, timeout=15, check=False)
    report = json.loads(result.stdout)
    if result.returncode != check_report(report):
        raise ValueError('exit status disagrees with assessment')
    if report['investigation_version'] != TEMPLATES[template]:
        raise ValueError('template selected the wrong report version')
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

    def compare(unit, templates):
        argv[-1] = unit
        before = direct()
        reports = [cli(unit, template) for template in templates]
        after = direct()
        if before != after:
            raise ValueError('live fixture changed; comparison inconclusive')
        value = {'id': before['Id'], 'load_state': before['LoadState'],
                 'active_state': before['ActiveState'], 'sub_state': before['SubState']}
        if unit not in before['Names'].split():
            raise ValueError('live scope mismatch')
        for report in reports:
            if report['scope'] != unit:
                raise ValueError('live scope mismatch')
            if report['evidence']['status'] != 'observed' or report['evidence']['value'] != value:
                raise ValueError('live evidence mismatch')
        return before, reports

    compare(unit, ('service-active', 'service-active/v2'))
    # Querying an undefined name is read-only; systemd collects its transient stub.
    before, (v1, v2) = compare('mira-undefined-validation-unit.service',
                               ('service-active', 'service-active/v2'))
    if (before['LoadState'], before['ActiveState']) != ('not-found', 'inactive'):
        raise ValueError('expected an undefined live unit')
    if v1['assessment']['reason'] != 'reported_not_active':
        raise ValueError('v1 semantics changed for an undefined unit')
    if v2['assessment']['reason'] != 'unit_not_found':
        raise ValueError('v2 did not identify an undefined unit')
    print('unprivileged live investigation contract validated')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-systemd', action='store_true')
    args = parser.parse_args()
    for version in (1, 2):
        cases = json.loads((ROOT / f'tests/fixtures/investigation-v{version}.json').read_text())
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
                           ('service-active', 'x'), ('service-active', 'x' * 300 + '.service'),
                           ('service-active/v3', 'ssh.service'), ('service-active/', 'ssh.service'),
                           ('service-active/V2', 'ssh.service'),
                           ('service-active/v2', '--user.service')]:
        result = subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate',
                                 template, unit, '--json'],
                                capture_output=True, text=True, timeout=5, check=False)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid invocation dispatched or emitted a report')
    if args.live_systemd:
        live()
    print('investigation-v1/v2 schemas, semantic fixtures and CLI admission validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # A fixed diagnostic class, never record values or backend errors.
        print(f'investigation validation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
