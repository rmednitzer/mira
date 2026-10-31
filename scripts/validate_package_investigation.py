#!/usr/bin/env python3
"""Independent explicit package-installed schema, semantics and live dpkg checks."""
import json
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from compare_evidence import strict_json

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'schemas/package-installed-v1.schema.json').read_text())
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)
STATUS = Path('/var/lib/dpkg/status')
MAX_STATUS_BYTES = 32 * 1024 * 1024
ABSENT = 'mira-validation-absent-package'


def expected_assessment(report):
    """Derive the assessment from the exported records, independent of Rust."""
    evidence = report['evidence']
    if evidence['status'] == 'unavailable':
        return 'indeterminate', 'evidence_unavailable', 3
    records = evidence['value']['records']
    if any(r['state'] == 'installed' and r['flag'] == 'ok' for r in records):
        return 'satisfied', 'reported_installed', 0
    if any(r['flag'] == 'reinstreq' or r['state'] not in ('not-installed', 'config-files')
           for r in records):
        return 'indeterminate', 'incomplete_installation_state', 3
    return 'not_satisfied', 'reported_not_installed', 1


def check_report(report):
    VALIDATOR.validate(report)
    expectation = report['expectation']
    evidence = report['evidence']
    if evidence['selector'] != expectation:
        raise ValueError('evidence selector differs from expectation')
    if evidence['status'] == 'observed':
        installed = set()
        for record in evidence['value']['records']:
            if record['package'] != expectation['package']:
                raise ValueError('record outside the selected package')
            if (expectation['architecture'] is not None
                    and record['architecture'] != expectation['architecture']):
                raise ValueError('record outside the selected architecture')
            if record['state'] == 'installed':
                identity = record['package'], record['architecture']
                if identity in installed:
                    raise ValueError('duplicate installed identity')
                installed.add(identity)
    expected = expected_assessment(report)
    if (report['assessment']['outcome'], report['assessment']['reason']) != expected[:2]:
        raise ValueError('assessment contradicts package records')
    return expected[2]


def check_fixtures():
    cases = json.loads((ROOT / 'tests/fixtures/package-installed-v1.json').read_text())
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
        raise ValueError('invalid package fixture admitted')
    if semantic_only != cases['semantic_only']:
        raise ValueError('unexpected number of schema-valid invalid fixtures')


def read_status():
    """Independent bounded stanza parse; it does not reuse the Rust parser."""
    with STATUS.open('rb') as handle:
        data = handle.read(MAX_STATUS_BYTES + 1)
    if len(data) > MAX_STATUS_BYTES:
        raise ValueError('dpkg status exceeds budget')
    stanzas = []
    for block in data.decode('utf-8').split('\n\n'):
        fields = {}
        for line in block.split('\n'):
            if not line or line[0] in ' \t' or ':' not in line:
                continue
            key, value = line.split(':', 1)
            if key in ('Package', 'Version', 'Architecture', 'Status'):
                fields[key] = value[1:] if value.startswith(' ') else value
        if 'Package' in fields:
            selection, flag, state = fields['Status'].split(' ')
            stanzas.append({'package': fields['Package'],
                            'architecture': fields.get('Architecture'),
                            'version': fields.get('Version'),
                            'selection': selection, 'flag': flag, 'state': state})
    return data, stanzas


def selected(stanzas, package, architecture):
    return [s for s in stanzas if s['package'] == package
            and (architecture is None or s['architecture'] == architecture)]


def run(arguments, timeout):
    return subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate', 'package-installed',
                           *arguments], capture_output=True, timeout=timeout, check=False)


def check_live():
    before, stanzas = read_status()
    dpkg = selected(stanzas, 'dpkg', None)
    if len(dpkg) != 1 or dpkg[0]['state'] != 'installed':
        raise ValueError('expected one installed dpkg record on the validation host')
    native = dpkg[0]['architecture']
    cases = [('dpkg', None), ('dpkg', native), ('dpkg', 'mira-absent-arch'),
             ('libc6', None), (ABSENT, None)]
    for package, architecture in cases:
        selector = package if architecture is None else f'{package}:{architecture}'
        result = run([selector, '--json'], 15)
        report = strict_json(result.stdout)
        if result.returncode != check_report(report):
            raise ValueError('package exit mismatch')
        if report['expectation'] != {'package': package, 'architecture': architecture}:
            raise ValueError('package selector changed')
        if report['evidence']['status'] != 'observed':
            raise ValueError('live dpkg evidence unavailable')
        if report['evidence']['value']['records'] != selected(stanzas, package, architecture):
            raise ValueError('MIRA package records disagree with the independent parse')
    after, _ = read_status()
    if before != after:
        raise ValueError('dpkg status changed during validation; comparison inconclusive')
    for selector in ('', 'a', 'Dpkg', 'dpkg:', ':amd64', 'dpkg:x:y', '../dpkg', 'dpkg_x'):
        result = run([selector, '--json'], 5)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid package selector dispatched')


def main():
    check_fixtures()
    check_live()
    print('package-installed schema, semantic fixtures and live dpkg comparison validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Reports and the status file describe the host; print only the error type.
        print(f'package investigation validation failed: {type(error).__name__}',
              file=sys.stderr)
        sys.exit(1)
