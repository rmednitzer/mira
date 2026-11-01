#!/usr/bin/env python3
"""Independent capture schema, exact-source-set and CLI checks."""
import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from capture_contract import ROOT, VALIDATOR_V2, VALIDATOR_V3, check_capture
from compare_evidence import (CAPTURE_NAMESPACE, CHALLENGE_DOCUMENT, Trust, load, compare,
                              read_challenge, strict_json)
from validation_status import Inconclusive, mira_binary, note_gap, note_record
import validation_status

LEGACY = Draft202012Validator(json.loads((ROOT / 'schemas/evidence-v1.schema.json').read_text()))
CHALLENGE = Draft202012Validator(
    json.loads((ROOT / 'schemas/challenge-v1.schema.json').read_text()))
HEX = '0123456789abcdef' * 4


def challenged(document, challenge=HEX):
    rest = {key: value for key, value in document.items() if key != 'capture_version'}
    return {'capture_version': 3, 'challenge': challenge, **rest}


def refused(check, document):
    try:
        check(document)
    except (ValueError, ValidationError):
        return
    raise ValueError('invalid document admitted')


def capture(*arguments, timeout=15, **options):
    return subprocess.run([mira_binary(), 'capture', *arguments], capture_output=True,
                          timeout=timeout, check=False, **options)


def admit(result):
    """Admit one capture and report every unavailable source it carries, boot ID included."""
    document = check_capture(strict_json(result.stdout))
    for record in document['records']:
        note_record(record)
    boot = document.get('collection', {}).get('boot', {})
    if boot.get('binding') == 'unavailable':
        note_gap('/proc/sys/kernel/random/boot_id', boot['failure_reason'])
    return document


def direct_boot():
    """Independent bounded reads of the boot ID and centisecond uptime."""
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_bytes()[:65].decode('ascii')
    if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n', boot_id) is None:
        raise ValueError('invalid direct boot ID sample')
    uptime = Path('/proc/uptime').read_bytes()[:65537].decode('ascii')
    match = re.fullmatch(r'([0-9]+)\.([0-9]{2})[ \t]+[0-9]+\.[0-9]{2}\n', uptime)
    if match is None:
        raise ValueError('invalid direct uptime sample')
    return boot_id.removesuffix('\n'), int(match.group(1)) * 100 + int(match.group(2))


def check_live_boot():
    shapes = []
    for options in (['--bind-boot'], ['--timeline', '--bind-boot'],
                    ['--pressure', '--timeline', '--bind-boot']):
        before_id, before_cs = direct_boot()
        result = capture('synthetic-ci', *options)
        after_id, after_cs = direct_boot()
        document = admit(result)
        if result.returncode != (0 if document['all_available'] else 1):
            raise ValueError('boot-bound capture exit mismatch')
        boot = document['collection']['boot']
        if before_id != after_id or before_cs > after_cs:
            raise Inconclusive('live boot changed during validation')
        if boot['binding'] != 'observed' or boot['boot_id'] != before_id:
            raise ValueError('MIRA boot ID disagrees with direct procfs')
        if not before_cs <= boot['started_uptime_cs'] <= boot['ended_uptime_cs'] <= after_cs:
            raise ValueError('MIRA boot window outside direct uptime interval')
        shapes.append((document['capture_version'], sorted(boot), len(document['timeline'])))
    # Two consecutive bound captures report the same boot and never the reverse order.
    with tempfile.TemporaryDirectory() as temp:
        paths = []
        for name in ('first', 'second'):
            result = capture('synthetic-ci', '--bind-boot')
            admit(result)
            path = Path(temp) / name
            path.write_bytes(result.stdout)
            paths.append(path)
        timing = compare(load(paths[0], LEGACY), load(paths[1], LEGACY), 60000)['timing']
        if timing['boot_relation'] != 'same_boot_reported':
            raise ValueError('consecutive captures did not report the same boot')
        if timing['order'] not in ('before_precedes_after', 'overlapping'):
            raise ValueError('consecutive captures ordered backwards')
        if not (timing['before']['window_within_policy'] and timing['after']['window_within_policy']):
            raise ValueError('live capture window exceeded a 60 s policy')
    # --bind-boot implies --timeline: both spellings give the same shape.
    if shapes[0] != shapes[1]:
        raise ValueError('--bind-boot does not imply --timeline')


def check_live_signed_comparison():
    """mira signs two live captures; the comparator verifies the bytes it compares."""
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        key = temp / 'host-a'
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'host-a',
                        '-f', str(key)], check=True, stdin=subprocess.DEVNULL)
        public = ' '.join(key.with_suffix('.pub').read_text().split()[:2])
        signers = temp / 'signers'
        signers.write_text(f'host-a namespaces="{CAPTURE_NAMESPACE}" {public}\n')
        paths = []
        for name in ('first.json', 'second.json'):
            path = temp / name
            result = capture('synthetic-ci', '--bind-boot', '--signature', f'{path}.sig',
                             '--sign-with', str(key), timeout=30, stdin=subprocess.DEVNULL)
            if result.returncode not in (0, 1) or not result.stdout:
                raise ValueError('signed live capture failed')
            admit(result)
            path.write_bytes(result.stdout)
            paths.append(path)
        trust = Trust(signers, 'host-a')
        report = compare(load(paths[0], LEGACY, trust), load(paths[1], LEGACY, trust))
        if report.get('integrity', {}).get('principal') != 'host-a':
            raise ValueError('signed live captures not verified by the comparator')
        paths[1].write_bytes(paths[1].read_bytes().replace(b'synthetic-ci', b'synthetic-cj'))
        try:
            load(paths[1], LEGACY, trust)
        except ValueError:
            pass
        else:
            raise ValueError('modified signed capture admitted')


def check_live_challenge():
    """mira answers two challenges; the comparator and mira verify bound their age."""
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        key = temp / 'host-a'
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'host-a',
                        '-f', str(key)], check=True, stdin=subprocess.DEVNULL)
        public = ' '.join(key.with_suffix('.pub').read_text().split()[:2])
        signers = temp / 'signers'
        signers.write_text(f'host-a namespaces="{CAPTURE_NAMESPACE}" {public}\n')
        issued, paths = [], []
        for name in ('first', 'second'):
            result = subprocess.run([mira_binary(), 'challenge'], capture_output=True,
                                    timeout=5, check=False)
            match = CHALLENGE_DOCUMENT.fullmatch(result.stdout)
            if result.returncode != 0 or match is None:
                raise ValueError('mira challenge output is not challenge-v1')
            CHALLENGE.validate(strict_json(result.stdout))
            challenge_file = temp / f'{name}.challenge'
            challenge_file.write_bytes(result.stdout)
            issued.append(read_challenge(challenge_file))
            path = temp / f'{name}.json'
            result = capture('synthetic-ci', '--challenge', match[1].decode(), '--signature',
                             f'{path}.sig', '--sign-with', str(key), timeout=30,
                             stdin=subprocess.DEVNULL)
            if result.returncode not in (0, 1) or not result.stdout:
                raise ValueError('challenged live capture failed')
            document = admit(result)
            if document['capture_version'] != 3 or document['challenge'] != match[1].decode():
                raise ValueError('challenged capture is not capture-v3 with the challenge')
            path.write_bytes(result.stdout)
            paths.append(path)
        if issued[0].challenge == issued[1].challenge:
            raise ValueError('mira challenge repeated a value')
        trust = Trust(signers, 'host-a')
        report = compare(load(paths[0], LEGACY, trust, issued[0]),
                         load(paths[1], LEGACY, trust, issued[1]), max_age_ms=600000)
        if report.get('freshness', {}).get('status') != 'within_policy':
            raise ValueError('answered challenges not within policy')
        try:
            load(paths[0], LEGACY, trust, issued[1])
        except ValueError:
            pass
        else:
            raise ValueError('capture admitted for another challenge')
        base = [mira_binary(), 'verify', str(paths[0]), '--signature', f'{paths[0]}.sig',
                '--allowed-signers', str(signers), '--principal', 'host-a', '--challenge-file']
        for challenge_file, code, reason in ((temp / 'first.challenge', 0, b'age_bound_ms='),
                                             (temp / 'second.challenge', 1,
                                              b'(challenge_mismatch)')):
            result = subprocess.run([*base, str(challenge_file), '--max-age-ms', '600000'],
                                    capture_output=True, timeout=15, check=False)
            if result.returncode != code or reason not in result.stdout:
                raise ValueError('mira verify freshness result mismatch')
        result = capture('synthetic-ci', '--challenge', issued[0].challenge, timeout=5)
        if result.returncode != 2 or result.stdout:
            raise ValueError('unsigned challenge dispatched')


def check_schema():
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
    # capture-v3 (ADR 0014) is capture-v2 plus the challenge, with the same semantics.
    for case in timeline['valid']:
        check_capture(challenged(case))
        missing = challenged(case)
        del missing['challenge']
        extra = dict(case, challenge=HEX)
        for bad in (missing, challenged(case, HEX.upper()), challenged(case, HEX[:63]),
                    challenged(case, HEX + '\n'), challenged(case, 7), extra):
            refused(check_capture, bad)
    for case in timeline['invalid']:
        try:
            VALIDATOR_V2.validate(case)
        except ValidationError:
            continue
        refused(check_capture, challenged(case))
    VALIDATOR_V3.validate(challenged(timeline['valid'][0]))
    document = {'challenge_version': 1, 'challenge': HEX, 'issued_unix_ms': 1793520000000}
    CHALLENGE.validate(document)
    for bad in (dict(document, challenge_version=2), dict(document, challenge=HEX.upper()),
                dict(document, issued_unix_ms=-1), dict(document, issued_unix_ms=10 ** 16),
                dict(document, issued_unix_ms='1'), dict(document, extra=1),
                {'challenge_version': 1, 'challenge': HEX}):
        refused(CHALLENGE.validate, bad)


def check_cli():
    for pressure in (False, True):
        result = capture('synthetic-ci', *(['--pressure'] if pressure else []))
        document = admit(result)
        if result.returncode != (0 if document['all_available'] else 1):
            raise ValueError('capture exit mismatch')
        if len(document['records']) != (7 if pressure else 5):
            raise ValueError('capture source count mismatch')
        result = capture('synthetic-ci', *(['--pressure'] if pressure else []), '--timeline')
        document = admit(result)
        if document['capture_version'] != 2:
            raise ValueError('timeline capture is not capture-v2')
        if result.returncode != (0 if document['all_available'] else 1):
            raise ValueError('timeline capture exit mismatch')
        if document['collection']['boot'] != {'binding': 'not_requested'}:
            raise ValueError('boot identifier collected without request')
    for arguments in (['--timeline', '--pressure'], ['--timeline', '--timeline'],
                      ['--bind-boot', '--timeline'], ['--bind-boot', '--pressure']):
        result = capture('synthetic-ci', *arguments, timeout=5)
        if result.returncode != 2 or result.stdout:
            raise ValueError('malformed timeline invocation dispatched')
    for label in ('', 'private path', 'x' * 65, 'x\x1b', '--pressure', '--timeline',
                  '--bind-boot', '-', '.hidden'):
        result = capture(label, timeout=5)
        if result.returncode != 2 or result.stdout:
            raise ValueError('invalid capture label dispatched')


def check_compare():
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp) / 'capture'
        for pressure in (False, True):
            result = capture('synthetic-ci', *(['--pressure'] if pressure else []))
            admit(result)
            path.write_bytes(result.stdout)
            admitted = load(path, LEGACY)
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
            result = capture('synthetic-ci', *(['--pressure'] if pressure else []), '--timeline')
            document = admit(result)
            path.write_bytes(result.stdout)
            current = load(path, LEGACY)
            report = compare(current, current)
            if report['comparison_version'] != 3 or report['timing']['boot_relation'] != 'unknown':
                raise ValueError('unbound capture-v2 pair not compared as comparison-v3')
            # Mixed capture-v1/v2 input with matching scope and profile compares values.
            plain = capture('synthetic-ci', *(['--pressure'] if pressure else []))
            admit(plain)
            path.write_bytes(plain.stdout)
            mixed = compare(load(path, LEGACY), current)
            if mixed['comparison_version'] != 2 or len(mixed['changes']) != len(document['records']):
                raise ValueError('mixed capture versions not compared by value')


def main(argv=None):
    validation_status.run(
        'capture validation',
        {'schema': check_schema, 'cli': check_cli, 'compare': check_compare,
         'live-boot': check_live_boot, 'signed-compare': check_live_signed_comparison,
         'challenge': check_live_challenge},
        'capture-v1/v2/v3, challenge-v1 and evidence-v2 schema, semantic fixtures, timeline, '
        'live boot binding, signed comparison, challenge freshness and CLI validated', argv)


if __name__ == '__main__':
    main()
