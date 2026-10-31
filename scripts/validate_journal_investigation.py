#!/usr/bin/env python3
"""Independent journal-events/v1 schema, semantic and live journal checks (ADR 0012)."""
import json
import os
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from compare_evidence import strict_json

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'schemas/journal-events-v1.schema.json').read_text())
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)
JOURNALCTL = '/usr/bin/journalctl'
SYSTEMD = '/usr/lib/systemd/systemd'
COREDUMP = '/usr/lib/systemd/systemd-coredump'
SLICE = 'system-systemd\\x2dcoredump.slice'
# Written out independently of the Rust implementation.
PRODUCERS = {
    'oom-kill': [('fe6faa94e7774663a0da52717891d8ef', 'manager'),
                 ('d989611b15e44c9dbf31e3c81256e4ed', 'manager')],
    'unit-failure': [('d9b373ed55a64feb8242e02dbe79a49c', 'manager'),
                     ('be02cf6855d2428ba40df7e9d022f03d', 'manager')],
    'coredump': [('fc2e22bc6ee647b6b90729ab34a250b1', 'coredump')],
}
BOOT_ARGS = {'current': ['--boot'], 'previous_retained': ['-b', '-1']}


def decide(evidence, absent):
    """Independent restatement of the ADR's outcome precedence."""
    if evidence['journal_visible'] is None:
        return 'evidence_unavailable'
    if evidence['journal_visible'] is False:
        return 'journal_not_visible'
    statuses = [c['status'] for c in evidence['classes']]
    if 'recorded' in statuses:
        return 'events_recorded'
    if 'unavailable' in statuses or 'not_queried' in statuses:
        return 'evidence_unavailable'
    if 'coredump' in absent:
        handler = evidence['crash_handler']
        if handler == 'unknown_for_boot':
            return 'crash_handler_unknown_for_boot'
        if handler != 'systemd-coredump':
            return 'crash_handler_not_systemd_coredump'
    if evidence['journal_access_complete'] is not True:
        return 'journal_access_incomplete'
    return 'none_recorded'


def check_report(report):
    VALIDATOR.validate(report)
    expectation, evidence = report['expectation'], report['evidence']
    absent = expectation['absent']
    if absent != sorted(absent, key=list(PRODUCERS).index):
        raise ValueError('expectation classes not in canonical order')
    if [c['class'] for c in evidence['classes']] != absent:
        raise ValueError('evidence classes differ from expectation')
    if evidence['boot'] != expectation['boot']:
        raise ValueError('evidence boot differs from expectation')
    if evidence['journal_visible'] is not True:
        if any(c['status'] != 'not_queried' for c in evidence['classes']):
            raise ValueError('classes reported without a visible journal')
        if evidence['journal_access_complete'] is not None or evidence['crash_handler'] is not None:
            raise ValueError('access or handler reported without a visible journal')
    else:
        wants_handler = 'coredump' in absent
        if (evidence['crash_handler'] is None) == wants_handler:
            raise ValueError('crash handler presence contradicts selected classes')
        if wants_handler and ((evidence['crash_handler'] == 'unknown_for_boot')
                              != (expectation['boot'] == 'previous_retained')):
            raise ValueError('crash handler contradicts boot scope')
    if report['assessment']['reason'] != decide(evidence, absent):
        raise ValueError('assessment contradicts journal evidence')
    return {'satisfied': 0, 'not_satisfied': 1, 'indeterminate': 3}[report['assessment']['outcome']]


def check_fixtures():
    cases = json.loads((ROOT / 'tests/fixtures/journal-events-v1.json').read_text())
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
        raise ValueError('invalid journal fixture admitted')
    if semantic_only != cases['semantic_only']:
        raise ValueError('unexpected number of schema-valid invalid journal fixtures')


def journalctl(args):
    result = subprocess.run([JOURNALCTL, '--system', '--no-pager', '--quiet', *args],
                            capture_output=True, timeout=30, check=False)
    return result.returncode, result.stdout


def parse_export(data):
    """Minimal independent export parser; binary fields make the sample invalid."""
    entries, entry = [], {}
    for line in data.split(b'\n'):
        if not line:
            if entry:
                entries.append(entry)
            entry = {}
            continue
        if b'=' not in line:
            raise ValueError('binary export field in live sample')
        key, value = line.split(b'=', 1)
        entry[key.decode('ascii')] = value.decode('utf-8', 'replace')
    return entries


def producer_valid(kind, entry):
    if kind == 'manager':
        return entry.get('_UID') == '0' and entry.get('_EXE') == SYSTEMD
    unit = entry.get('_SYSTEMD_UNIT', '')
    return (entry.get('_EXE') == COREDUMP and entry.get('_SYSTEMD_SLICE') == SLICE
            and unit.startswith('systemd-coredump@') and unit.endswith('.service'))


def independent(absent, boot):
    """Derive the expected visibility, access, per-class counts and handler directly."""
    code, out = journalctl(['--boot', '-n', '1', '-o', 'export', '--output-fields=_PID', '_PID=1'])
    visible = code == 0 and b'\n_PID=1\n' in b'\n' + out
    if visible and boot == 'previous_retained':
        code, out = journalctl(['-b', '-1', '-n', '1', '-o', 'export', '--output-fields=_PID', '_PID=1'])
        visible = code == 0 and b'\n_PID=1\n' in b'\n' + out
    if not visible:
        return {'visible': False, 'counts': None, 'access': None, 'handler': None}
    access, found = True, 0
    for root in ('/var/log/journal', '/run/log/journal'):
        if not os.path.isdir(root):
            continue
        for machine in os.listdir(root):
            path = os.path.join(root, machine)
            if len(machine) != 32 or not os.path.isdir(path):
                continue
            for name in os.listdir(path):
                if name == 'system.journal' or (name.startswith('system@') and
                                                name.endswith(('.journal', '.journal~'))):
                    try:
                        os.close(os.open(os.path.join(path, name), os.O_RDONLY | os.O_NONBLOCK))
                        found += 1
                    except FileNotFoundError:
                        pass
                    except OSError:
                        access = False
    counts = {}
    fields = ('--output-fields=MESSAGE_ID,UNIT,USER_UNIT,COREDUMP_UNIT,COREDUMP_USER_UNIT,'
              '_UID,_EXE,_SYSTEMD_UNIT,_SYSTEMD_SLICE')
    for name in absent:
        matches = []
        for index, (message_id, kind) in enumerate(PRODUCERS[name]):
            if index:
                matches.append('+')
            matches.append(f'MESSAGE_ID={message_id}')
            matches += (['_UID=0', f'_EXE={SYSTEMD}'] if kind == 'manager'
                        else [f'_EXE={COREDUMP}', f'_SYSTEMD_SLICE={SLICE}'])
        code, out = journalctl([*BOOT_ARGS[boot], '-o', 'export', fields, '-n', '1001', *matches])
        if code != 0:
            raise ValueError('independent class query failed')
        entries = parse_export(out)
        kinds = dict(PRODUCERS[name])
        counts[name] = min(sum(1 for e in entries
                               if producer_valid(kinds.get(e.get('MESSAGE_ID')), e)), 1000)
    handler = None
    if 'coredump' in absent:
        pattern = Path('/proc/sys/kernel/core_pattern').read_text()
        handler = ('unknown_for_boot' if boot == 'previous_retained'
                   else 'systemd-coredump' if pattern.startswith(f'|{COREDUMP}') else 'other')
    return {'visible': True, 'counts': counts, 'access': access and found > 0, 'handler': handler}


def check_live():
    for absent, boot, flag in ((['oom-kill', 'unit-failure', 'coredump'], 'current', 'current'),
                               (['oom-kill', 'unit-failure'], 'previous_retained', 'previous-retained')):
        before = independent(absent, boot)
        result = subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate', 'journal-events',
                                 '--absent', ','.join(absent), '--boot', flag, '--json'],
                                capture_output=True, timeout=60, check=False)
        report = strict_json(result.stdout)
        after = independent(absent, boot)
        if before != after:
            raise ValueError('live journal changed during validation; comparison inconclusive')
        if result.returncode != check_report(report):
            raise ValueError('journal exit mismatch')
        evidence = report['evidence']
        if evidence['journal_visible'] != before['visible']:
            raise ValueError('MIRA journal visibility disagrees with direct journalctl')
        if before['visible']:
            if evidence['journal_access_complete'] != before['access']:
                raise ValueError('MIRA journal access disagrees with direct file checks')
            if evidence['crash_handler'] != before['handler']:
                raise ValueError('MIRA crash handler disagrees with direct core_pattern')
            for entry in evidence['classes']:
                expected = before['counts'][entry['class']]
                if (entry['count'] or 0) != expected:
                    raise ValueError('MIRA journal counts disagree with direct journalctl')
    for args in (['--absent', 'watchdog'], ['--absent', 'oom-kill,oom-kill'],
                 ['--absent', 'oom-kill', '--boot', '-1'], ['--boot', 'current']):
        result = subprocess.run([str(ROOT / 'target/debug/mira'), 'investigate', 'journal-events',
                                 *args, '--json'], capture_output=True, timeout=10, check=False)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid journal invocation dispatched')


def main():
    check_fixtures()
    check_live()
    print('journal-events schema, semantic fixtures and live journal comparison validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Reports and journal samples describe the host; print only the error type.
        print(f'journal investigation validation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
