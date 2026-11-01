#!/usr/bin/env python3
"""A deterministic scripted agent for MIRA sessions (ADR 0015 stage 1).

Test tooling, not a model: each run reads the session as the agent can and
takes at most one fixed step through `mira session request`, signed with the
agent's key. Nothing it writes is trusted; the broker checks every request.

Policy, in order: request one capability; once its result is recorded, post
the finding that result supports, citing it; propose an operator-only
capture; ask the operator a question; then stay idle. While a request of its
own waits in the inbox, or an admitted action has no result yet, it waits.

Exit status: 0 after a step or when idle or waiting, 1 when the request was
not accepted by `mira`, 2 on usage error.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

CAPABILITY = ('memory-headroom', '1')
PROPOSAL = ('capture', 'host bind-boot')


def entries(session):
    """Each entry's canonical line; signatures are the broker's and verify's concern."""
    items = []
    for path in sorted((session / 'entries').glob('[0-9]' * 6 + '.entry')):
        line = path.read_bytes().split(b'\n', 1)[0]
        items.append(json.loads(line))
    return items


def claim_for(result):
    """The claim a collector result supports, with its confidence label."""
    outcome = result['outcome']
    if outcome == 'satisfied':
        return 'expectation_satisfied', None
    if outcome == 'not_satisfied':
        return 'expectation_not_satisfied', None
    if outcome == 'indeterminate':
        if result.get('reason') == 'evidence_unavailable':
            return 'evidence_unavailable', None
        return 'expectation_indeterminate', None
    if outcome == 'complete_unavailable':
        return 'evidence_unavailable', None
    return 'hypothesis', 'low'


def next_step(session, header):
    """The one request to make now, as `mira session request` arguments, or a status word."""
    if any((session / 'inbox').glob('*.request')):
        return 'waiting'
    log = entries(session)
    relayed = [item for item in log
               if item['principal'] == header['collector'] and item.get('request_id')]
    kinds = {item['kind'] for item in relayed}
    actions = [item for item in relayed if item['kind'] == 'action']
    if not actions:
        capability, arguments = CAPABILITY
        return ['--capability', capability, '--arguments', arguments,
                '--text', 'scripted agent: check the expectation first']
    results = {item['action_seq']: item for item in log if item['kind'] == 'result'}
    if 'finding' not in kinds:
        result = results.get(actions[0]['seq'])
        if result is None:
            return 'waiting'
        claim, confidence = claim_for(result)
        step = ['--claim', claim]
        if confidence is None:
            step += ['--cites', str(result['seq'])]
        else:
            step += ['--confidence', confidence]
        return step + ['--text', 'scripted agent: what the result shows']
    if 'proposal' not in kinds:
        capability, arguments = PROPOSAL
        return ['--propose', '--capability', capability, '--arguments', arguments,
                '--text', 'scripted agent: bind the capture to this boot']
    if 'question' not in kinds:
        return ['--question', '--text', 'scripted agent: anything else to check?']
    return 'idle'


def main(argv=None):
    parser = argparse.ArgumentParser(description='deterministic scripted MIRA session agent')
    parser.add_argument('session', type=Path)
    parser.add_argument('--allowed-signers', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--mira', default='mira')
    args = parser.parse_args(argv)
    header = entries(args.session)[0]
    step = next_step(args.session, header)
    if isinstance(step, str):
        print(f'scripted agent: {step}')
        return 0
    result = subprocess.run(
        [args.mira, 'session', 'request', str(args.session),
         '--allowed-signers', args.allowed_signers, '--key', args.key, *step],
        capture_output=True, timeout=60, check=False)
    print(f"scripted agent: requested {' '.join(step[:2])}")
    return 0 if result.returncode == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
