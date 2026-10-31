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
from capture_contract import ROOT, VALIDATOR_V2, check_capture
from compare_evidence import CAPTURE_NAMESPACE, Trust, load, compare, strict_json


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
        result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                 *options], capture_output=True, timeout=15, check=False)
        after_id, after_cs = direct_boot()
        document = check_capture(strict_json(result.stdout))
        if result.returncode != (0 if document['all_available'] else 1):
            raise ValueError('boot-bound capture exit mismatch')
        boot = document['collection']['boot']
        if before_id != after_id or before_cs > after_cs:
            raise ValueError('live boot changed during validation; comparison inconclusive')
        if boot['binding'] != 'observed' or boot['boot_id'] != before_id:
            raise ValueError('MIRA boot ID disagrees with direct procfs')
        if not before_cs <= boot['started_uptime_cs'] <= boot['ended_uptime_cs'] <= after_cs:
            raise ValueError('MIRA boot window outside direct uptime interval')
        shapes.append((document['capture_version'], sorted(boot), len(document['timeline'])))
    # Two consecutive bound captures report the same boot and never the reverse order.
    with tempfile.TemporaryDirectory() as temp:
        paths = []
        for name in ('first', 'second'):
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                     '--bind-boot'], capture_output=True, timeout=15, check=False)
            path = Path(temp) / name
            path.write_bytes(result.stdout)
            paths.append(path)
        legacy = Draft202012Validator(json.loads((ROOT / 'schemas/evidence-v1.schema.json').read_text()))
        timing = compare(load(paths[0], legacy), load(paths[1], legacy), 60000)['timing']
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
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                     '--bind-boot', '--signature', f'{path}.sig',
                                     '--sign-with', str(key)],
                                    capture_output=True, timeout=30, check=False,
                                    stdin=subprocess.DEVNULL)
            if result.returncode not in (0, 1) or not result.stdout:
                raise ValueError('signed live capture failed')
            path.write_bytes(result.stdout)
            paths.append(path)
        legacy = Draft202012Validator(json.loads((ROOT / 'schemas/evidence-v1.schema.json').read_text()))
        trust = Trust(signers, 'host-a')
        report = compare(load(paths[0], legacy, trust), load(paths[1], legacy, trust))
        if report.get('integrity', {}).get('principal') != 'host-a':
            raise ValueError('signed live captures not verified by the comparator')
        paths[1].write_bytes(paths[1].read_bytes().replace(b'synthetic-ci', b'synthetic-cj'))
        try:
            load(paths[1], legacy, trust)
        except ValueError:
            pass
        else:
            raise ValueError('modified signed capture admitted')


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
            if report['comparison_version'] != 3 or report['timing']['boot_relation'] != 'unknown':
                raise ValueError('unbound capture-v2 pair not compared as comparison-v3')
            # Mixed capture-v1/v2 input with matching scope and profile compares values.
            plain = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                    *(['--pressure'] if pressure else [])],
                                   capture_output=True, timeout=15, check=False)
            path.write_bytes(plain.stdout)
            mixed = compare(load(path, validator), current)
            if mixed['comparison_version'] != 2 or len(mixed['changes']) != len(document['records']):
                raise ValueError('mixed capture versions not compared by value')
        check_live_boot()
        check_live_signed_comparison()
        for arguments in (['--timeline', '--pressure'], ['--timeline', '--timeline'],
                          ['--bind-boot', '--timeline'], ['--bind-boot', '--pressure']):
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', 'synthetic-ci',
                                     *arguments], capture_output=True, timeout=5, check=False)
            if result.returncode != 2 or result.stdout:
                raise ValueError('malformed timeline invocation dispatched')
        for label in ('', 'private path', 'x' * 65, 'x\x1b', '--pressure', '--timeline', '--bind-boot', '-', '.hidden'):
            result = subprocess.run([str(ROOT / 'target/debug/mira'), 'capture', label],
                                    capture_output=True, timeout=5, check=False)
            if result.returncode != 2 or result.stdout:
                raise ValueError('invalid capture label dispatched')
    print('capture-v1/v2 and evidence-v2 schema, semantic fixtures, timeline, live boot binding, signed comparison and CLI validated')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'capture validation failed: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
