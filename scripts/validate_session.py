#!/usr/bin/env python3
"""Independent session-v1 schema, layout, state, claim, relay and signature checks (ADR 0015 stage 1)."""
import contextlib
import copy
import json
import re
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from compare_evidence import strict_json
from validation_status import mira_binary
import scripted_agent
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
    'result': ['action_seq', 'exit_status', 'outcome', 'reason', 'document_signature'],
    'finding': ['request_id', 'claim', 'confidence', 'cites'],
    'proposal': ['request_id', 'capability', 'arguments'],
    'decision': ['target_seq', 'verdict'],
    'assessment': ['target_seq', 'claim', 'confidence'],
    'abandon': ['action_seq'],
    'refusal': ['request_id', 'reason'],
    'close': ['entry_count'],
}
REQUEST_HEAD = ['session_version', 'session_id', 'kind', 'request_id', 'principal', 'based_on',
                'request']
REQUEST_FIELDS = {'action': ['capability', 'arguments'], 'question': ['capability', 'arguments'],
                  'proposal': ['capability', 'arguments'], 'finding': ['claim', 'confidence', 'cites']}
MAX_OPEN_PROPOSALS = 8
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
    # Stage 1a operator questions had no request_id, and stage 1b results no
    # reason; those layouts stay valid.
    if entry['kind'] == 'question' and 'request_id' not in entry:
        return []
    if entry['kind'] == 'header':
        return FIELDS['header'] + [name for name in ('agent_tools', 'own_assessment') if name in entry]
    if entry['kind'] == 'directive' and 'until_unix_ms' in entry:
        return FIELDS['directive'] + ['until_unix_ms']
    if entry['kind'] == 'result' and 'reason' not in entry:
        return [name for name in FIELDS['result'] if name != 'reason']
    return FIELDS[entry['kind']]


def request_order(request):
    return REQUEST_HEAD + REQUEST_FIELDS[request['request']] + ['note']


def cites(text):
    return [int(item) for item in text.split(',')] if text else []


def supports(state, claim, confidence, cited):
    """Restate the claim check: only recorded collector results count."""
    if any(seq not in state['results'] for seq in cited):
        return False
    facts = [state['results'][seq] for seq in cited]
    outcomes = [fact['outcome'] for fact in facts]
    if claim == 'expectation_satisfied':
        return bool(facts) and all(outcome == 'satisfied' for outcome in outcomes)
    if claim == 'expectation_not_satisfied':
        return 'not_satisfied' in outcomes
    if claim == 'expectation_indeterminate':
        return 'indeterminate' in outcomes
    if claim == 'evidence_unavailable':
        return any(fact['outcome'] == 'complete_unavailable'
                   or fact['reason'] == 'evidence_unavailable' for fact in facts)
    if claim == 'hypothesis':
        return confidence is not None
    return confidence is None and not facts


def stale(state, capability, arguments, based_on):
    return any(seq > based_on and fact['capability'] == capability
               and fact['arguments'] == arguments for seq, fact in state['results'].items())


def admit(data):
    entry = strict_json(data)
    VALIDATOR.validate(entry)
    if canonical(entry, COMMON + fields(entry) + ['note']) != data:
        raise ValueError('entry is not in canonical layout')
    return entry


def admit_request(data):
    request = strict_json(data)
    REQUEST_VALIDATOR.validate(request)
    if canonical(request, request_order(request)) != data:
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
                'closed': False, 'last_directive': None, 'pending': {}, 'requests': set(),
                'results': {}, 'open': {}, 'assessed': set(),
                'forcing': entry.get('own_assessment') == 'required', 'last_assessment': None}
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

    def charge():
        # Every agent-attributable entry costs budget and stays out of the
        # operator's reserve of the last 64 entries.
        if state['budget'] == 0 or seq >= 4096 - 64:
            raise ValueError('agent entry without budget or inside the reserve')
        state['budget'] -= 1

    if kind == 'question':
        if entry.get('request_id') is None and operator:
            pass
        elif entry['request_id'] is not None and collector and state['level'] != 'manual':
            charge()
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
            if not allowed:
                raise ValueError('agent action beyond autonomy')
            charge()
            fresh(entry['request_id'])
        else:
            raise ValueError('action without the role for it')
        state['pending'][seq] = (entry['capability'], entry['arguments'], planned[0])
    elif kind == 'result' and collector:
        pending = state['pending'].pop(entry['action_seq'], None)
        if pending is None or outcome(pending[2], entry['exit_status']) != entry['outcome']:
            raise ValueError('result without a pending action or with another outcome')
        document = entry['outcome'] in DOCUMENT_OUTCOMES
        if document != (entry['document_signature'] is not None):
            raise ValueError('document signature present exactly when there is a document')
        reason = entry.get('reason', 'unrecorded')
        if reason is None:
            fits = pending[2] == 'capture' or not document
        elif reason == 'unrecorded':
            fits = True
        else:
            fits = pending[2] == 'investigation' and document \
                and (reason != 'evidence_unavailable' or entry['outcome'] == 'indeterminate')
        if not fits:
            raise ValueError('result reason does not fit its family and outcome')
        state['results'][seq] = {'capability': pending[0], 'arguments': pending[1],
                                 'outcome': entry['outcome'], 'reason': reason}
    elif kind == 'finding':
        if not supports(state, entry['claim'], entry['confidence'], cites(entry['cites'])):
            raise ValueError('finding not supported by its cited results')
        if entry['request_id'] is None and operator:
            pass
        elif entry['request_id'] is not None and collector and state['level'] != 'manual':
            charge()
            fresh(entry['request_id'])
            state['open'][seq] = ('finding',)
        else:
            raise ValueError('finding without the role or level for it')
    elif kind == 'proposal' and collector:
        open_proposals = sum(1 for item in state['open'].values() if item[0] == 'proposal')
        if plan(entry['capability'], entry['arguments']) is None or state['level'] == 'manual' \
                or seq >= 4096 - 64 or open_proposals >= MAX_OPEN_PROPOSALS:
            raise ValueError('proposal outside the closed set, the level or its bound')
        # A proposal costs no budget.
        fresh(entry['request_id'])
        state['open'][seq] = ('proposal', entry['capability'], entry['arguments'], entry['based_on'])
    elif kind == 'decision' and operator:
        target = state['open'].pop(entry['target_seq'], None)
        verdict = entry['verdict']
        if target is None:
            raise ValueError('decision on nothing open')
        if target[0] == 'finding':
            fits = verdict in ('accept', 'reject', 'uncertain') \
                and (not state['forcing'] or entry['target_seq'] in state['assessed'])
        else:
            is_stale = stale(state, target[1], target[2], target[3])
            # Approval copies the proposal's arguments into an operator action,
            # so under the forcing flag it waits until they are released.
            unassessed = any(item == ('finding',) and seq_ not in state['assessed']
                             for seq_, item in state['open'].items())
            last = state['last_assessment']
            withheld = state['forcing'] and (unassessed or last is None
                                             or last < entry['target_seq'])
            fits = verdict == 'reject' or (verdict == 'approve' and not is_stale and not withheld) \
                or (verdict == 'approve_despite_stale' and is_stale and not withheld)
        if not fits:
            raise ValueError('verdict does not fit its target')
    elif kind == 'assessment' and operator:
        target = entry['target_seq']
        labelled = {'hypothesis': entry['confidence'] is not None,
                    'no_finding': entry['confidence'] is None}.get(entry['claim'], True)
        # Target 0, the session question, may be assessed again and again.
        if not labelled or (target != 0 and (state['open'].get(target) != ('finding',)
                                             or target in state['assessed'])):
            raise ValueError('assessment of nothing open, twice, or without its labels')
        if target != 0:
            state['assessed'].add(target)
        state['last_assessment'] = seq
    elif kind == 'abandon' and operator:
        if state['pending'].pop(entry['action_seq'], None) is None:
            raise ValueError('abandoned action is not pending')
    elif kind == 'refusal' and collector:
        charge()
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
               separation='same_user', autonomy='assisted', budget=3)
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
              reason='minimum_met', document_signature=SIGNATURE),
        entry('refusal', 4, 'collector', request_id='22' * 32, reason='capability'),
        entry('action', 5, request_id=None, capability='capture', arguments='host bind-boot'),
        entry('result', 6, 'collector', action_seq=5, exit_status=None, outcome='runner_error',
              document_signature=None),
        # A stage 1b result without reason, and a stage 1a operator question
        # without request_id.
        entry('question', 7),
        entry('directive', 8, directive='stop', level=None, budget=None, until_seq=None),
        entry('directive', 9, directive='set_level', level='advisory', budget=None, until_seq=None),
        entry('directive', 10, directive='set_budget', level=None, budget=1, until_seq=None),
        entry('question', 11, 'collector', request_id='33' * 32),
        entry('action', 12, request_id=None, capability='service-active', arguments='a@b\\x2dc.service'),
        entry('abandon', 13, action_seq=12),
        entry('directive', 14, directive='delegate', level=None, budget=None, until_seq=19),
        entry('finding', 15, request_id=None, claim='expectation_satisfied', confidence=None, cites='3'),
        # A proposal costs no budget, so it is admitted at zero.
        entry('proposal', 16, 'collector', request_id='77' * 32, capability='capture', arguments='host'),
        entry('directive', 17, directive='set_budget', level=None, budget=1, until_seq=None),
        entry('finding', 18, 'collector', request_id='88' * 32, claim='hypothesis', confidence='low',
              cites=''),
        entry('decision', 19, target_seq=16, verdict='reject'),
        entry('decision', 20, target_seq=18, verdict='accept'),
        entry('close', 21, entry_count=22),
    ]
    state = None
    for item in valid:
        admit(canonical(item, COMMON + fields(item) + ['note']))
        state = fold(state, item)
    if (state['entries'], state['level'], state['budget'], state['closed'], state['pending']) \
            != (22, 'assisted', 0, True, {}) or state['open']:
        raise ValueError('fixture state mismatch')
    pinned = dict(HEADER)
    pinned['agent_tools'] = 'ab' * 32
    pinned['note'] = pinned.pop('note')
    admit(canonical(pinned, COMMON + fields(pinned) + ['note']))
    for mutate in (
        lambda e: e.update(agent_tools='AB' * 32),
        lambda e: e.update(agent_tools=None),
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
        entry('result', 1, 'collector', action_seq=1, exit_status=0, outcome='satisfied',
              reason='Minimum', document_signature=SIGNATURE),
        entry('finding', 1, request_id=None, claim='certain', confidence=None, cites=''),
        entry('finding', 1, request_id=None, claim='hypothesis', confidence='sure', cites=''),
        entry('finding', 1, request_id=None, claim='hypothesis', confidence='low', cites='02'),
        entry('finding', 1, request_id=None, claim='hypothesis', confidence='low', cites='1,'),
        entry('proposal', 1, 'collector', request_id=None, capability='capture', arguments='host'),
        entry('decision', 1, target_seq=1, verdict='overrule'),
    ):
        refused(VALIDATOR.validate, bad)
    started = fold(None, HEADER)
    acted = fold(dict(started, budget=1), entry('action', 1, 'collector', request_id=REQ,
                                                capability='uptime-minimum', arguments='1'))
    for state_, bad in (
        (started, entry('action', 1, 'agent', request_id=REQ, capability='uptime-minimum', arguments='1')),
        (started, entry('action', 1, 'collector', request_id=REQ, capability='capture', arguments='host bind-boot')),
        (acted, entry('action', 2, 'collector', request_id='44' * 32, capability='uptime-minimum', arguments='1')),
        (acted, entry('refusal', 2, 'collector', request_id=REQ, reason='capability')),
        (acted, entry('refusal', 2, 'collector', request_id='55' * 32, reason='capability')),
        (dict(started, budget=5, entries=4032),
         entry('question', 4032, 'collector', request_id='66' * 32)),
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
    refused(lambda e: fold(stopped, e), entry('proposal', 2, 'collector', request_id=REQ,
                                             capability='capture', arguments='host'))
    # Claims, verdicts and staleness, over a satisfied result at 2.
    measured = fold(fold(started, entry('action', 1, request_id=None, capability='memory-headroom',
                                        arguments='1')),
                    entry('result', 2, 'collector', action_seq=1, exit_status=0, outcome='satisfied',
                          reason='minimum_met', document_signature=SIGNATURE))
    for bad in (
        entry('finding', 3, request_id=None, claim='expectation_not_satisfied', confidence=None, cites='2'),
        entry('finding', 3, request_id=None, claim='expectation_satisfied', confidence=None, cites='1'),
        entry('finding', 3, request_id=None, claim='evidence_unavailable', confidence=None, cites='2'),
        entry('finding', 3, request_id=None, claim='hypothesis', confidence=None, cites=''),
        entry('finding', 3, request_id=None, claim='no_finding', confidence=None, cites='2'),
        entry('decision', 3, target_seq=2, verdict='accept'),
        entry('result', 3, 'collector', action_seq=1, exit_status=3, outcome='indeterminate',
              reason='evidence_unavailable', document_signature=SIGNATURE),
    ):
        refused(lambda e: fold(measured, e), bad)
    proposed = fold(measured, dict(entry('proposal', 3, 'collector', request_id=REQ,
                                         capability='memory-headroom', arguments='1'), based_on=0))
    refused(lambda e: fold(proposed, e), entry('decision', 4, target_seq=3, verdict='approve'))
    forcing = dict(HEADER, own_assessment='required')
    forcing['note'] = forcing.pop('note')
    admit(canonical(forcing, COMMON + fields(forcing) + ['note']))
    found = fold(fold(None, forcing), entry('finding', 1, 'collector', request_id=REQ, claim='hypothesis',
                                             confidence='low', cites=''))
    refused(lambda e: fold(found, e), entry('decision', 2, target_seq=1, verdict='accept'))
    refused(lambda e: fold(found, e), entry('assessment', 2, target_seq=1, claim='hypothesis',
                                            confidence=None))
    assessed = fold(found, entry('assessment', 2, target_seq=1, claim='no_finding', confidence=None))
    refused(lambda e: fold(assessed, e), entry('assessment', 3, target_seq=1, claim='no_finding',
                                               confidence=None))
    fold(assessed, entry('decision', 3, target_seq=1, verdict='reject'))
    fold(fold(assessed, entry('assessment', 3, target_seq=0, claim='no_finding', confidence=None)),
         entry('assessment', 4, target_seq=0, claim='hypothesis', confidence='low'))
    proposed_blind = fold(fold(None, forcing), dict(entry('proposal', 1, 'collector', request_id=REQ,
                                                          capability='capture', arguments='host'),
                                                    based_on=0))
    refused(lambda e: fold(proposed_blind, e), entry('decision', 2, target_seq=1, verdict='approve'))
    fold(proposed_blind, entry('decision', 2, target_seq=1, verdict='reject'))
    released = fold(proposed_blind, entry('assessment', 2, target_seq=0, claim='no_finding', confidence=None))
    fold(released, entry('decision', 3, target_seq=1, verdict='approve'))
    timed = entry('directive', 1, directive='delegate', level=None, budget=None, until_seq=4096,
                  until_unix_ms=1800000000000)
    timed['note'] = timed.pop('note')
    admit(canonical(timed, COMMON + fields(timed) + ['note']))
    if fold(fold(None, HEADER), timed)['level'] != 'delegated':
        raise ValueError('timed delegation not applied')
    refused(VALIDATOR.validate, dict(entry('directive', 1, directive='stop', level=None, budget=None,
                                           until_seq=None), until_unix_ms=5))
    refused(lambda e: fold(proposed, e), entry('decision', 4, target_seq=3, verdict='accept'))
    fold(proposed, entry('decision', 4, target_seq=3, verdict='approve_despite_stale'))
    unavailable = fold(fold(started, entry('action', 1, request_id=None, capability='service-active',
                                           arguments='a.service')),
                       entry('result', 2, 'collector', action_seq=1, exit_status=3,
                             outcome='indeterminate', reason='transition_in_progress',
                             document_signature=SIGNATURE))
    fold(unavailable, entry('finding', 3, request_id=None, claim='expectation_indeterminate',
                            confidence=None, cites='2'))
    refused(lambda e: fold(unavailable, e), entry('finding', 3, request_id=None,
                                                  claim='evidence_unavailable', confidence=None,
                                                  cites='2'))
    request = {'session_version': 1, 'session_id': ID, 'kind': 'request', 'request_id': REQ,
               'principal': 'agent', 'based_on': 0, 'request': 'action',
               'capability': 'memory-headroom', 'arguments': '1', 'note': 'n'}
    admit_request(canonical(request, request_order(request)))
    finding = {'session_version': 1, 'session_id': ID, 'kind': 'request', 'request_id': REQ,
               'principal': 'agent', 'based_on': 2, 'request': 'finding',
               'claim': 'expectation_satisfied', 'confidence': None, 'cites': '2,5', 'note': 'n'}
    admit_request(canonical(finding, request_order(finding)))
    proposal = dict(request, request='proposal', capability='capture', arguments='host bind-boot')
    admit_request(canonical(proposal, request_order(proposal)))
    for base, mutate in (
        (request, lambda r: r.update(kind='action')),
        (request, lambda r: r.update(request='close')),
        (request, lambda r: r.update(request='question')),
        (request, lambda r: r.update(capability='inspect')),
        (request, lambda r: r.update(arguments='-x')),
        (request, lambda r: r.update(claim='hypothesis')),
        (finding, lambda r: r.update(capability='capture')),
        (finding, lambda r: r.update(cites='5,2,')),
        (finding, lambda r: r.update(claim='certain')),
        (finding, lambda r: r.pop('confidence')),
        (proposal, lambda r: r.update(capability=None)),
    ):
        bad = dict(base)
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


def check_relay(temp, session, item):
    """A relayed entry matches the agent's stored, agent-signed request."""
    stored, stored_signature = split_record(
        (session / 'requests' / f"{item['request_id']}.request").read_bytes())
    request = admit_request(stored)
    if not ssh_verify(temp, stored, stored_signature, 'agent', NAMESPACE):
        raise ValueError('stored agent request not verified independently')
    expected = (item['session_id'], item['request_id'], 'agent', item['based_on'], item['note'],
                item['kind'])
    if (request['session_id'], request['request_id'], request['principal'],
            request['based_on'], request['note'], request['request']) != expected:
        raise ValueError('relayed entry differs from the agent request')
    for name in REQUEST_FIELDS[request['request']]:
        if item['kind'] != 'question' and request[name] != item[name]:
            raise ValueError('relayed entry differs from the agent request')


def check_document(temp, session, item):
    """A result's document is collector-signed and states the recorded reason."""
    document = (session / 'documents' / f"{item['action_seq']:06}.json").read_bytes()
    # The result commits to the document through its exact signature.
    document_signature = item['document_signature'].encode()
    if (session / 'documents' / f"{item['action_seq']:06}.json.sig").read_bytes() \
            != document_signature:
        raise ValueError('document signature file differs from the committed one')
    report = strict_json(document)
    family = 'capture' if 'capture_version' in report else 'investigation'
    if not ssh_verify(temp, document, document_signature, 'collector',
                      DOCUMENT_NAMESPACES[family]):
        raise ValueError('result document not signed by the collector')
    stated = report['assessment']['reason'] if family == 'investigation' else None
    if item.get('reason', stated) != stated:
        raise ValueError('result reason differs from its signed report')
    return report


def check_entries(temp, session):
    """Admit, fold and verify every entry independently; return the state and entries."""
    state, items = None, []
    names = sorted(path.name for path in (session / 'entries').iterdir())
    for seq, name in enumerate(names):
        if name != f'{seq:06}.entry':
            raise ValueError('unexpected session files')
        data, signature = split_record((session / 'entries' / name).read_bytes())
        item = admit(data)
        state = fold(state, item)
        items.append(item)
        if not ssh_verify(temp, data, signature, item['principal'], NAMESPACE):
            raise ValueError('entry signature not verified independently')
        if item.get('request_id') is not None and item['kind'] in (
                'action', 'question', 'finding', 'proposal'):
            check_relay(temp, session, item)
        if item['kind'] == 'result' and item['outcome'] in DOCUMENT_OUTCOMES:
            check_document(temp, session, item)
    return state, items


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
        state, items = check_entries(temp, session)
        kinds = [item['kind'] for item in items]
        # The second request finds no budget left and is dropped unrecorded.
        if kinds != ['header', 'action', 'result', 'action', 'result', 'action', 'result',
                     'question', 'close']:
            raise ValueError(f'unexpected entry sequence {kinds}')
        if (state['budget'], state['closed'], state['pending']) != (0, True, {}):
            raise ValueError('independent state disagrees with the steps')
        shown = json.loads(mira('show', str(session), '--json').stdout)
        if shown != {'session_version': 1, 'entries': 9, 'closed': True, 'autonomy': 'assisted',
                     'budget': 0, 'delegated_until': None, 'delegated_until_unix_ms': None,
                     'open_proposals': [],
                     'open_findings': []}:
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


def check_scripted_agent():
    """The deterministic agent against the real broker, then the operator decides."""
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        keys(temp)
        session = temp / 'session'
        trust = ['--allowed-signers', str(temp / 'signers')]
        operator = [*trust, '--key', str(temp / 'operator')]
        if mira('start', str(session), *operator, '--operator', 'operator', '--agent', 'agent',
                '--collector', 'collector', '--budget', '3',
                '--question', 'Is memory the problem?').returncode != 0:
            raise ValueError('session start failed')
        agent = [*trust, '--key', str(temp / 'agent'), '--mira', mira_binary()]
        for _ in range(12):
            with tempfile.TemporaryFile('w+') as output, contextlib.redirect_stdout(output):
                code = scripted_agent.main([str(session), *agent])
                output.seek(0)
                said = output.read()
            if code != 0:
                raise ValueError('scripted agent request not accepted')
            if said == 'scripted agent: idle\n':
                break
            if mira('run', str(session), *trust, '--key', str(temp / 'collector'),
                    '--once').returncode != 0:
                raise ValueError('broker pass failed')
        else:
            raise ValueError('scripted agent never became idle')
        state, items = check_entries(temp, session)
        kinds = [item['kind'] for item in items]
        if kinds != ['header', 'action', 'result', 'finding', 'proposal', 'question']:
            raise ValueError(f'unexpected entry sequence {kinds}')
        # Recompute the agent's claim from the signed report alone.
        result, finding = items[2], items[3]
        report = strict_json((session / 'documents' / f"{result['action_seq']:06}.json").read_bytes())
        expected = scripted_agent.claim_for({'outcome': report['assessment']['outcome'],
                                             'reason': report['assessment']['reason']})[0]
        if finding['claim'] != expected or not supports(state, finding['claim'],
                                                        finding['confidence'], cites(finding['cites'])):
            raise ValueError('agent finding not supported by the signed report')
        if sorted(state['open']) != [3, 4] or state['budget'] != 0:
            raise ValueError('independent state disagrees with the agent run')
        for target, verdict in (('3', '--accept'), ('4', '--reject')):
            if mira('decide', str(session), *operator, '--target', target, verdict).returncode != 0:
                raise ValueError('operator decision failed')
        if mira('close', str(session), *operator, '--conclusion', 'memory is fine',
                '--receipt', str(temp / 'receipt')).returncode != 0:
            raise ValueError('session close failed')
        state, items = check_entries(temp, session)
        if [item['kind'] for item in items[6:]] != ['decision', 'decision', 'close'] \
                or state['open'] or not state['closed']:
            raise ValueError('decisions or close disagree with the independent state')
        shown = json.loads(mira('show', str(session), '--json').stdout)
        if (shown['open_proposals'], shown['open_findings'], shown['budget']) != ([], [], 0):
            raise ValueError('mira session show disagrees with the independent state')
        if mira('verify', str(session), *trust, '--operator', 'operator',
                '--expect-close', str(temp / 'receipt')).returncode != 0:
            raise ValueError('mira session verify refused a valid session')


def main(argv=None):
    validation_status.run(
        'session validation',
        {'fixtures': check_fixtures, 'cli': check_cli, 'scripted-agent': check_scripted_agent},
        'session-v1 and request schemas, canonical layout, independent state, claims, relays and signatures validated',
        argv)


if __name__ == '__main__':
    main()
