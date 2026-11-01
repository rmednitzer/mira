#!/usr/bin/env python3
"""Independent session-v1 schema, layout, state and signature checks (ADR 0015 stage 1a)."""
import copy
import json
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from compare_evidence import strict_json
from validation_status import mira_binary
import validation_status

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'schemas/session-v1.schema.json').read_text())
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)
NAMESPACE = 'mira-session-v1@rmednitzer.github.io'
COMMON = ['session_version', 'session_id', 'seq', 'kind', 'principal', 'based_on']
FIELDS = {
    'header': ['operator', 'agent', 'collector', 'separation', 'autonomy', 'budget'],
    'question': [],
    'directive': ['directive', 'level', 'budget', 'until_seq'],
    'close': ['entry_count'],
}
ID = '0123456789abcdef' * 4


def canonical(entry):
    """The exact bytes MIRA writes: fixed key order, compact, newline-terminated."""
    order = COMMON + FIELDS[entry['kind']] + ['note']
    if list(entry) != order:
        raise ValueError('entry keys out of canonical order')
    return (json.dumps(entry, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


ARMOR = b'-----BEGIN SSH SIGNATURE-----\n'


def split_record(record):
    """A record is the entry line, newline included, then its armored signature."""
    end = record.index(b'\n') + 1
    data, signature = record[:end], record[end:]
    if not signature.startswith(ARMOR):
        raise ValueError('record has no signature')
    return data, signature


def admit(data):
    entry = strict_json(data)
    VALIDATOR.validate(entry)
    if canonical(entry) != data:
        raise ValueError('entry is not in canonical layout')
    return entry


def fold(state, entry):
    """Restate the stage 1a rules independently of the Rust implementation."""
    seq = entry['seq']
    if state is None:
        names = {entry['operator'], entry['agent'], entry['collector']}
        if entry['kind'] != 'header' or seq != 0 or len(names) != 3 \
                or entry['principal'] != entry['operator']:
            raise ValueError('first entry is not a valid operator header')
        return {'id': entry['session_id'], 'roles': entry, 'entries': 1,
                'level': entry['autonomy'], 'budget': entry['budget'],
                'until': None, 'closed': False}
    if entry['session_id'] != state['id']:
        raise ValueError('entry from another session')
    if state['closed']:
        raise ValueError('entry after close')
    if entry['based_on'] is not None and entry['based_on'] >= seq:
        raise ValueError('based_on does not precede the entry')
    state = dict(state)
    if state['until'] is not None and seq > state['until']:
        state['level'], state['until'] = 'assisted', None
    operator = entry['principal'] == state['roles']['operator']
    kind = entry['kind']
    if kind == 'question' and (operator or entry['principal'] == state['roles']['agent']):
        pass
    elif kind == 'directive' and operator:
        directive = entry['directive']
        if directive == 'stop':
            state['level'], state['until'] = 'manual', None
        elif directive == 'set_level':
            state['level'], state['until'] = entry['level'], None
        elif directive == 'set_budget':
            state['budget'] = entry['budget']
        elif entry['until_seq'] > seq:
            state['level'], state['until'] = 'delegated', entry['until_seq']
        else:
            raise ValueError('delegation must end after its own entry')
    elif kind == 'close' and operator:
        if entry['entry_count'] != seq + 1:
            raise ValueError('close count does not match')
        state['closed'] = True
    else:
        raise ValueError('principal lacks the role for this kind')
    state['entries'] = seq + 1
    return state


def entry(kind, seq, principal='operator', **fields):
    note = fields.pop('note', '')
    base = {'session_version': 1, 'session_id': ID, 'seq': seq, 'kind': kind,
            'principal': principal, 'based_on': None if seq == 0 else seq - 1}
    base.update(fields)
    base['note'] = note
    return base


HEADER = entry('header', 0, operator='operator', agent='agent', collector='collector',
               separation='same_user', autonomy='assisted', budget=5)


def refused(check, document):
    try:
        check(document)
    except (ValueError, ValidationError):
        return
    raise ValueError('invalid session entry admitted')


def check_fixtures():
    valid = [
        HEADER,
        entry('question', 1, 'agent', note='Is "web" up? \\ ok'),
        entry('directive', 2, directive='stop', level=None, budget=None, until_seq=None),
        entry('directive', 3, directive='set_level', level='advisory', budget=None, until_seq=None),
        entry('directive', 4, directive='set_budget', level=None, budget=0, until_seq=None),
        entry('directive', 5, directive='delegate', level=None, budget=None, until_seq=9),
        entry('close', 6, entry_count=7),
    ]
    state = None
    for item in valid:
        admit(canonical(item))
        state = fold(state, item)
    if state != {'id': ID, 'roles': HEADER, 'entries': 7, 'level': 'delegated', 'budget': 0,
                 'until': 9, 'closed': True}:
        raise ValueError('fixture state mismatch')
    for mutate in (
        lambda e: e.update(session_version=2),
        lambda e: e.update(session_id=ID.upper()),
        lambda e: e.update(autonomy='delegated'),
        lambda e: e.update(budget=-1),
        lambda e: e.update(separation='shared'),
        lambda e: e.update(operator='-bad'),
        lambda e: e.update(note='line\nbreak'),
        lambda e: e.update(note='esc\u001b[2J'),
        lambda e: e.update(note='bidi‮'),
        lambda e: e.update(note='a' * 1025),
        lambda e: e.update(extra=1),
        lambda e: e.pop('budget'),
    ):
        bad = copy.deepcopy(HEADER)
        mutate(bad)
        refused(VALIDATOR.validate, bad)
    for bad in (
        entry('directive', 1, directive='stop', level='manual', budget=None, until_seq=None),
        entry('directive', 1, directive='set_level', level='delegated', budget=None, until_seq=None),
        entry('directive', 1, directive='halt', level=None, budget=None, until_seq=None),
        entry('close', 1, entry_count=0),
        entry('result', 1),
    ):
        refused(VALIDATOR.validate, bad)
    # Layout: valid JSON with spacing or reordered keys is still refused.
    header = canonical(HEADER)
    for bad in (header.replace(b',', b', ', 1), header[:-1],
                json.dumps(dict(reversed(list(HEADER.items()))), separators=(',', ':')).encode() + b'\n'):
        refused(admit, bad)
    # State rules, independent of the schema.
    started = fold(None, HEADER)
    for bad in (
        entry('directive', 1, 'agent', directive='stop', level=None, budget=None, until_seq=None),
        entry('question', 1, 'collector'),
        entry('directive', 1, directive='delegate', level=None, budget=None, until_seq=1),
        entry('close', 1, entry_count=5),
        dict(entry('question', 1), session_id='1' * 64),
        dict(entry('question', 1), based_on=1),
    ):
        refused(lambda e: fold(started, e), bad)
    refused(lambda e: fold(fold(started, entry('close', 1, entry_count=2)), e), entry('question', 2))
    refused(lambda e: fold(None, e), dict(HEADER, principal='agent'))


def keys(temp):
    signers = []
    for name in ('operator', 'agent', 'collector'):
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', name,
                        '-f', str(temp / name)], check=True, stdin=subprocess.DEVNULL)
        public = ' '.join((temp / f'{name}.pub').read_text().split()[:2])
        signers.append(f'{name} namespaces="{NAMESPACE}" {public}\n')
    (temp / 'signers').write_text(''.join(signers))


def mira(*arguments):
    return subprocess.run([mira_binary(), 'session', *arguments], capture_output=True,
                          timeout=60, check=False)


def check_cli():
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        keys(temp)
        session = temp / 'session'
        trust = ['--allowed-signers', str(temp / 'signers'), '--key', str(temp / 'operator')]
        steps = [
            ['start', str(session), *trust, '--operator', 'operator', '--agent', 'agent',
             '--collector', 'collector', '--budget', '3', '--question', 'Why did "web" restart?'],
            ['ask', str(session), *trust, '--text', 'Journal visible?'],
            ['direct', str(session), *trust, '--delegate-until', '3'],
            ['direct', str(session), *trust, '--budget', '1'],
            ['direct', str(session), *trust, '--stop', '--text', 'pausing'],
            ['close', str(session), *trust, '--conclusion', 'no OOM', '--receipt', str(temp / 'receipt')],
        ]
        for step in steps:
            result = mira(*step)
            if result.returncode != 0:
                raise ValueError(f'session {step[0]} failed')
        state = None
        names = sorted(path.name for path in (session / 'entries').iterdir())
        if names != [f'{seq:06}.entry' for seq in range(6)]:
            raise ValueError('unexpected session files')
        for seq in range(6):
            data, signature = split_record((session / 'entries' / f'{seq:06}.entry').read_bytes())
            item = admit(data)
            if item['seq'] != seq:
                raise ValueError('entry seq disagrees with its file')
            state = fold(state, item)
            # Each signature verifies independently for the principal the entry names.
            (temp / 'entry.sig').write_bytes(signature)
            check = subprocess.run(
                ['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(temp / 'signers'), '-I',
                 item['principal'], '-n', NAMESPACE, '-s', str(temp / 'entry.sig')],
                input=data, capture_output=True, timeout=10, check=False)
            if check.returncode != 0:
                raise ValueError('entry signature not verified independently')
        if (state['level'], state['budget'], state['closed'], state['entries']) != ('manual', 1, True, 6):
            raise ValueError('independent state disagrees with the steps')
        shown = json.loads(mira('show', str(session), '--json').stdout)
        if shown != {'session_version': 1, 'entries': 6, 'closed': True,
                     'autonomy': 'manual', 'budget': 1, 'delegated_until': None}:
            raise ValueError('mira session show disagrees with the independent state')
        if (temp / 'receipt').read_bytes() != (session / 'entries' / '000005.entry').read_bytes():
            raise ValueError('receipt is not the close record')
        verified = mira('verify', str(session), '--allowed-signers', str(temp / 'signers'),
                        '--operator', 'operator', '--expect-close', str(temp / 'receipt'))
        if verified.returncode != 0:
            raise ValueError('mira session verify refused a valid session')
        # One changed byte must be refused by mira and by ssh-keygen alike.
        path = session / 'entries' / '000001.entry'
        path.write_bytes(path.read_bytes().replace(b'visible', b'vis1ble', 1))
        # The verifier names the operator; a header naming anyone else is refused.
        if mira('verify', str(session), '--allowed-signers', str(temp / 'signers'),
                '--operator', 'agent').returncode != 1:
            raise ValueError('session verified for an operator the header does not name')
        if mira('verify', str(session), '--allowed-signers', str(temp / 'signers'),
                '--operator', 'operator').returncode != 1:
            raise ValueError('modified entry verified')


def main(argv=None):
    validation_status.run(
        'session validation',
        {'fixtures': check_fixtures, 'cli': check_cli},
        'session-v1 schema, canonical layout, independent state and signatures validated', argv)


if __name__ == '__main__':
    main()
