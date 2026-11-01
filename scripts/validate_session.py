#!/usr/bin/env python3
"""Independent session-v1 schema, layout, state, relay and signature checks (ADR 0015 stages 1a-1b)."""
import copy
import json
import re
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from compare_evidence import strict_json
from validation_status import mira_binary
import validation_status

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / 'schemas/session-v1.schema.json').read_text())
REQUEST_SCHEMA = json.loads((ROOT / 'schemas/session-request-v1.schema.json').read_text())
for schema in (SCHEMA, REQUEST_SCHEMA):
    Draft202012Validator.check_schema(schema)
VALIDATOR = Draft202012Validator(SCHEMA)
REQUEST_VALIDATOR = Draft202012Validator(REQUEST_SCHEMA)
NAMESPACE = 'mira-session-v1@rmednitzer.github.io'
DOCUMENT_NAMESPACES = {'capture': 'mira-capture-v1@rmednitzer.github.io',
                       'investigation': 'mira-investigation-v1@rmednitzer.github.io'}
ARMOR = b'-----BEGIN SSH SIGNATURE-----\n'
COMMON = ['session_version', 'session_id', 'seq', 'kind', 'principal', 'based_on']
FIELDS = {
    'header': ['operator', 'agent', 'collector', 'separation', 'autonomy', 'budget'],
    'question': ['request_id'],
    'directive': ['directive', 'level', 'budget', 'until_seq'],
    'action': ['request_id', 'capability', 'arguments'],
    'result': ['action_seq', 'exit_status', 'outcome', 'document_signature'],
    'abandon': ['action_seq'],
    'refusal': ['request_id', 'reason'],
    'close': ['entry_count'],
}
REQUEST_ORDER = ['session_version', 'session_id', 'kind', 'request_id', 'principal', 'based_on',
                 'request', 'capability', 'arguments', 'note']
ID = '0123456789abcdef' * 4
TOKEN = re.compile(r'[A-Za-z0-9._:+@,/=\\][A-Za-z0-9._:+@,/=\\-]{0,255}')
SIGNATURE = '-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n'
DOCUMENT_OUTCOMES = {'satisfied', 'not_satisfied', 'indeterminate', 'complete_available',
                     'complete_unavailable'}
INVESTIGATIONS = {
    'service-active': 1, 'service-active/v1': 1, 'service-active/v2': 1,
    'memory-headroom': 1, 'pressure-ceiling': 2, 'package-installed': 1,
    'uptime-minimum': 1, 'kernel-release': 1,
}


def plan(capability, arguments):
    """Restate the closed capability table: (family, operator_only) or None."""
    tokens = arguments.split(' ') if arguments else []
    if any(TOKEN.fullmatch(token) is None for token in tokens):
        return None
    if capability == 'capture':
        if tokens[:1] in (['host'], ['host-pressure']) and tokens[1:] in ([], ['bind-boot']):
            return 'capture', tokens[1:] == ['bind-boot']
        return None
    if capability == 'journal-events' and len(tokens) in (1, 2):
        return 'investigation', False
    if INVESTIGATIONS.get(capability) == len(tokens):
        return 'investigation', False
    return None


def outcome(family, status):
    if status == 2:
        return 'refused_arguments'
    if status == 4:
        return 'signing_failed'
    table = {('investigation', 0): 'satisfied', ('investigation', 1): 'not_satisfied',
             ('investigation', 3): 'indeterminate', ('capture', 0): 'complete_available',
             ('capture', 1): 'complete_unavailable'}
    return table.get((family, status), 'runner_error')


def canonical(entry, order):
    if list(entry) != order:
        raise ValueError('keys out of canonical order')
    return (json.dumps(entry, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def fields(entry):
    # Stage 1a operator questions had no request_id; that layout stays valid.
    if entry['kind'] == 'question' and 'request_id' not in entry:
        return []
    return FIELDS[entry['kind']]


def admit(data):
    entry = strict_json(data)
    VALIDATOR.validate(entry)
    if canonical(entry, COMMON + fields(entry) + ['note']) != data:
        raise ValueError('entry is not in canonical layout')
    return entry


def admit_request(data):
    request = strict_json(data)
    REQUEST_VALIDATOR.validate(request)
    if canonical(request, REQUEST_ORDER) != data:
        raise ValueError('request is not in canonical layout')
    return request


def split_record(record):
    """A record is the entry line, newline included, then its armored signature."""
    end = record.index(b'\n') + 1
    data, signature = record[:end], record[end:]
    if not signature.startswith(ARMOR):
        raise ValueError('record has no signature')
    return data, signature


def fold(state, entry):
    """Restate the stage 1a and 1b rules independently of the Rust implementation."""
    seq = entry['seq']
    if state is None:
        names = {entry['operator'], entry['agent'], entry['collector']}
        if entry['kind'] != 'header' or seq != 0 or len(names) != 3 \
                or entry['principal'] != entry['operator']:
            raise ValueError('first entry is not a valid operator header')
        return {'id': entry['session_id'], 'roles': entry, 'entries': 1,
                'level': entry['autonomy'], 'budget': entry['budget'], 'until': None,
                'closed': False, 'last_directive': None, 'pending': {}, 'requests': set()}
    if entry['session_id'] != state['id']:
        raise ValueError('entry from another session')
    if state['closed']:
        raise ValueError('entry after close')
    if entry['based_on'] is not None and entry['based_on'] >= seq:
        raise ValueError('based_on does not precede the entry')
    state = copy.deepcopy(state)
    if state['until'] is not None and seq > state['until']:
        state['level'], state['until'] = 'assisted', None
    roles = state['roles']
    operator = entry['principal'] == roles['operator']
    collector = entry['principal'] == roles['collector']
    kind = entry['kind']

    def fresh(request_id):
        if request_id in state['requests']:
            raise ValueError('request ID used twice')
        state['requests'].add(request_id)

    if kind == 'question':
        if entry.get('request_id') is None and operator:
            pass
        elif entry['request_id'] is not None and collector and state['level'] != 'manual':
            fresh(entry['request_id'])
        else:
            raise ValueError('question without the role or level for it')
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
        state['last_directive'] = seq
    elif kind == 'action':
        planned = plan(entry['capability'], entry['arguments'])
        if planned is None:
            raise ValueError('action outside the closed capability set')
        if entry['request_id'] is None and operator:
            pass
        elif entry['request_id'] is not None and collector:
            allowed = state['level'] == 'delegated' or (state['level'] == 'assisted' and not planned[1])
            if not allowed or state['budget'] == 0:
                raise ValueError('agent action beyond autonomy or budget')
            state['budget'] -= 1
            fresh(entry['request_id'])
        else:
            raise ValueError('action without the role for it')
        state['pending'][seq] = planned[0]
    elif kind == 'result' and collector:
        family = state['pending'].pop(entry['action_seq'], None)
        if family is None or outcome(family, entry['exit_status']) != entry['outcome']:
            raise ValueError('result without a pending action or with another outcome')
        if (entry['outcome'] in DOCUMENT_OUTCOMES) != (entry['document_signature'] is not None):
            raise ValueError('document signature present exactly when there is a document')
    elif kind == 'abandon' and operator:
        if state['pending'].pop(entry['action_seq'], None) is None:
            raise ValueError('abandoned action is not pending')
    elif kind == 'refusal' and collector:
        fresh(entry['request_id'])
    elif kind == 'close' and operator:
        if entry['entry_count'] != seq + 1 or state['pending']:
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
               separation='same_user', autonomy='assisted', budget=1)
REQ = '11' * 32


def refused(check, document):
    try:
        check(document)
    except (ValueError, ValidationError):
        return
    raise ValueError('invalid session document admitted')


def check_fixtures():
    valid = [
        HEADER,
        entry('question', 1, request_id=None, note='Is "web" up? \\ ok'),
        entry('action', 2, 'collector', request_id=REQ, capability='memory-headroom', arguments='1024'),
        entry('result', 3, 'collector', action_seq=2, exit_status=0, outcome='satisfied',
              document_signature=SIGNATURE),
        entry('refusal', 4, 'collector', request_id='22' * 32, reason='budget'),
        entry('action', 5, request_id=None, capability='capture', arguments='host bind-boot'),
        entry('result', 6, 'collector', action_seq=5, exit_status=None, outcome='runner_error',
              document_signature=None),
        # A stage 1a operator question: no request_id field at all.
        entry('question', 7),
        entry('directive', 8, directive='stop', level=None, budget=None, until_seq=None),
        entry('directive', 9, directive='set_level', level='advisory', budget=None, until_seq=None),
        entry('directive', 10, directive='set_budget', level=None, budget=0, until_seq=None),
        entry('question', 11, 'collector', request_id='33' * 32),
        entry('action', 12, request_id=None, capability='service-active', arguments='a@b\\x2dc.service'),
        entry('abandon', 13, action_seq=12),
        entry('directive', 14, directive='delegate', level=None, budget=None, until_seq=19),
        entry('close', 15, entry_count=16),
    ]
    state = None
    for item in valid:
        admit(canonical(item, COMMON + fields(item) + ['note']))
        state = fold(state, item)
    if (state['entries'], state['level'], state['budget'], state['closed'], state['pending']) \
            != (16, 'delegated', 0, True, {}):
        raise ValueError('fixture state mismatch')
    for mutate in (
        lambda e: e.update(session_version=2),
        lambda e: e.update(session_id=ID.upper()),
        lambda e: e.update(autonomy='delegated'),
        lambda e: e.update(budget=-1),
        lambda e: e.update(note='line\nbreak'),
        lambda e: e.update(note='bidi‮'),
        lambda e: e.update(note='a' * 1025),
        lambda e: e.update(extra=1),
    ):
        bad = copy.deepcopy(HEADER)
        mutate(bad)
        refused(VALIDATOR.validate, bad)
    for bad in (
        entry('action', 1, request_id=None, capability='inspect', arguments=''),
        entry('action', 1, request_id=None, capability='memory-headroom', arguments='--json'),
        entry('action', 1, request_id=None, capability='memory-headroom', arguments='1  2'),
        entry('result', 1, 'collector', action_seq=0, exit_status=0, outcome='satisfied'),
        entry('result', 1, 'collector', action_seq=1, exit_status=0, outcome='healthy'),
        entry('refusal', 1, 'collector', request_id=REQ, reason='bribe'),
        entry('question', 1, request_id='short'),
        entry('directive', 1, directive='stop', level='manual', budget=None, until_seq=None),
    ):
        refused(VALIDATOR.validate, bad)
    started = fold(None, HEADER)
    acted = fold(started, entry('action', 1, 'collector', request_id=REQ,
                                capability='uptime-minimum', arguments='1'))
    for state_, bad in (
        (started, entry('action', 1, 'agent', request_id=REQ, capability='uptime-minimum', arguments='1')),
        (started, entry('action', 1, 'collector', request_id=REQ, capability='capture', arguments='host bind-boot')),
        (acted, entry('action', 2, 'collector', request_id='44' * 32, capability='uptime-minimum', arguments='1')),
        (acted, entry('refusal', 2, 'collector', request_id=REQ, reason='budget')),
        (acted, entry('result', 2, 'collector', action_seq=1, exit_status=0, outcome='complete_available',
                      document_signature=SIGNATURE)),
        (acted, entry('result', 2, 'operator', action_seq=1, exit_status=0, outcome='satisfied',
                      document_signature=SIGNATURE)),
        (acted, entry('result', 2, 'collector', action_seq=1, exit_status=0, outcome='satisfied',
                      document_signature=None)),
        (acted, entry('close', 2, entry_count=3)),
        (acted, entry('abandon', 2, 'collector', action_seq=1)),
        (started, entry('question', 1, 'collector', request_id=None)),
        (started, entry('question', 1, request_id=REQ)),
        (started, dict(entry('question', 1, request_id=None), session_id='1' * 64)),
    ):
        refused(lambda e, s=state_: fold(s, e), bad)
    stopped = fold(started, entry('directive', 1, directive='stop', level=None, budget=None, until_seq=None))
    refused(lambda e: fold(stopped, e), entry('question', 2, 'collector', request_id=REQ))
    request = {'session_version': 1, 'session_id': ID, 'kind': 'request', 'request_id': REQ,
               'principal': 'agent', 'based_on': 0, 'request': 'action',
               'capability': 'memory-headroom', 'arguments': '1', 'note': 'n'}
    admit_request(canonical(request, REQUEST_ORDER))
    for mutate in (
        lambda r: r.update(kind='action'),
        lambda r: r.update(request='close'),
        lambda r: r.update(request='question'),
        lambda r: r.update(capability='inspect'),
        lambda r: r.update(arguments='-x'),
    ):
        bad = dict(request)
        mutate(bad)
        refused(REQUEST_VALIDATOR.validate, bad)


def keys(temp):
    signers = []
    documents = ','.join(DOCUMENT_NAMESPACES.values())
    for name in ('operator', 'agent', 'collector'):
        subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', name,
                        '-f', str(temp / name)], check=True, stdin=subprocess.DEVNULL)
        public = ' '.join((temp / f'{name}.pub').read_text().split()[:2])
        namespaces = f'{NAMESPACE},{documents}' if name == 'collector' else NAMESPACE
        signers.append(f'{name} namespaces="{namespaces}" {public}\n')
    (temp / 'signers').write_text(''.join(signers))


def mira(*arguments):
    return subprocess.run([mira_binary(), 'session', *arguments], capture_output=True,
                          timeout=120, check=False)


def ssh_verify(temp, data, signature, principal, namespace):
    (temp / 'check.sig').write_bytes(signature)
    return subprocess.run(
        ['/usr/bin/ssh-keygen', '-Y', 'verify', '-f', str(temp / 'signers'), '-I', principal,
         '-n', namespace, '-s', str(temp / 'check.sig')],
        input=data, capture_output=True, timeout=10, check=False).returncode == 0


def check_cli():
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        keys(temp)
        session = temp / 'session'
        trust = ['--allowed-signers', str(temp / 'signers')]
        operator = [*trust, '--key', str(temp / 'operator')]
        steps = [
            ['start', str(session), *operator, '--operator', 'operator', '--agent', 'agent',
             '--collector', 'collector', '--budget', '1', '--question', 'Why did "web" restart?'],
            ['request', str(session), *trust, '--key', str(temp / 'agent'),
             '--capability', 'uptime-minimum', '--arguments', '1', '--text', 'up long?'],
            ['run', str(session), *trust, '--key', str(temp / 'collector'), '--once'],
            ['request', str(session), *trust, '--key', str(temp / 'agent'),
             '--capability', 'uptime-minimum', '--arguments', '1', '--text', 'again'],
            ['run', str(session), *trust, '--key', str(temp / 'collector'), '--once'],
            ['act', str(session), *operator, '--collector-key', str(temp / 'collector'),
             '--capability', 'capture', '--arguments', 'host'],
            ['act', str(session), *operator, '--collector-key', str(temp / 'collector'),
             '--capability', 'service-active', '--arguments', 'mira-absent@a\\x2db.service'],
            ['ask', str(session), *operator, '--text', 'Journal visible?'],
            ['close', str(session), *operator, '--conclusion', 'no restart', '--receipt', str(temp / 'receipt')],
        ]
        for step in steps:
            if mira(*step).returncode != 0:
                raise ValueError(f'session {step[0]} failed')
        state, kinds = None, []
        names = sorted(path.name for path in (session / 'entries').iterdir())
        for seq, name in enumerate(names):
            if name != f'{seq:06}.entry':
                raise ValueError('unexpected session files')
            data, signature = split_record((session / 'entries' / name).read_bytes())
            item = admit(data)
            state = fold(state, item)
            kinds.append(item['kind'])
            if not ssh_verify(temp, data, signature, item['principal'], NAMESPACE):
                raise ValueError('entry signature not verified independently')
            request_id = item.get('request_id')
            if request_id is not None and item['kind'] in ('action', 'question'):
                stored, stored_signature = split_record(
                    (session / 'requests' / f'{request_id}.request').read_bytes())
                request = admit_request(stored)
                if not ssh_verify(temp, stored, stored_signature, 'agent', NAMESPACE):
                    raise ValueError('stored agent request not verified independently')
                expected = (item['session_id'], request_id, 'agent', item['based_on'], item['note'])
                if (request['session_id'], request['request_id'], request['principal'],
                        request['based_on'], request['note']) != expected:
                    raise ValueError('relayed entry differs from the agent request')
            if item['kind'] == 'result' and item['outcome'] not in (
                    'refused_arguments', 'signing_failed', 'runner_error'):
                document = (session / 'documents' / f'{item["action_seq"]:06}.json').read_bytes()
                # The result commits to the document through its exact signature.
                document_signature = item['document_signature'].encode()
                if (session / 'documents' / f'{item["action_seq"]:06}.json.sig').read_bytes() \
                        != document_signature:
                    raise ValueError('document signature file differs from the committed one')
                family = 'capture' if document.startswith(b'{"capture_version":') else 'investigation'
                if not ssh_verify(temp, document, document_signature, 'collector',
                                  DOCUMENT_NAMESPACES[family]):
                    raise ValueError('result document not signed by the collector')
        if kinds != ['header', 'action', 'result', 'refusal', 'action', 'result', 'action', 'result',
                     'question', 'close']:
            raise ValueError(f'unexpected entry sequence {kinds}')
        if (state['budget'], state['closed'], state['pending']) != (0, True, {}):
            raise ValueError('independent state disagrees with the steps')
        shown = json.loads(mira('show', str(session), '--json').stdout)
        if shown != {'session_version': 1, 'entries': 10, 'closed': True, 'autonomy': 'assisted',
                     'budget': 0, 'delegated_until': None}:
            raise ValueError('mira session show disagrees with the independent state')
        verified = mira('verify', str(session), *trust, '--operator', 'operator',
                        '--expect-close', str(temp / 'receipt'))
        if verified.returncode != 0:
            raise ValueError('mira session verify refused a valid session')
        if mira('verify', str(session), *trust, '--operator', 'agent').returncode != 1:
            raise ValueError('session verified for an operator the header does not name')
        # Alter the request the first action relays (refused requests are stored too,
        # but no entry references them).
        stored = next(path for path in (session / 'requests').iterdir()
                      if b'up long?' in path.read_bytes())
        stored.write_bytes(stored.read_bytes().replace(b'up long?', b'up long!', 1))
        if mira('verify', str(session), *trust, '--operator', 'operator').returncode != 1:
            raise ValueError('altered agent request verified')


def main(argv=None):
    validation_status.run(
        'session validation',
        {'fixtures': check_fixtures, 'cli': check_cli},
        'session-v1 and request schemas, canonical layout, independent state, relays and signatures validated',
        argv)


if __name__ == '__main__':
    main()
