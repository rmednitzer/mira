#!/usr/bin/env python3
"""Live two-user containment test for `separate_user` sessions (ADR 0015).

Creates an operator user, an agent user and their shared group, runs the
operator's commands and the broker as the operator and every agent step as
the agent, and checks what the agent can and cannot do. It must run as root
on a disposable host (CI sets MIRA_DISPOSABLE_HOST=1), refuses if any of its
users or paths already exist, and removes everything it created.

Exit status: 0 every check passed, 1 a check failed, 2 refused to run.
"""
import argparse
import grp
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
from pathlib import Path

OPERATOR = 'mira-test-op'
AGENT = 'mira-test-agent'
GROUP = 'mira-test-agents'
INSTALL = Path('/usr/local/libexec/mira-test')
WORK = Path('/srv/mira-test')
NAMESPACE = 'mira-session-v1@rmednitzer.github.io'
DOCUMENTS = 'mira-capture-v1@rmednitzer.github.io,mira-investigation-v1@rmednitzer.github.io'
ROOT = Path(__file__).resolve().parents[1]
RUNUSER = shutil.which('runuser') or '/usr/sbin/runuser'


class Run:
    def __init__(self, mira):
        self.mira = mira
        self.failures = []
        self.home = {name: Path('/home') / name for name in (OPERATOR, AGENT)}
        self.session = WORK / 'op' / 'session'
        self.signers = INSTALL / 'signers'

    def check(self, name, condition):
        print(f"{'passed' if condition else 'FAILED'}: {name}")
        if not condition:
            self.failures.append(name)

    def run(self, user, *argv, environ=None, input_bytes=None):
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(self.home[user]), 'LANG': 'C.UTF-8'}
        env.update(environ or {})
        # The minimal PATH is the user's; runuser itself is found from root's.
        return subprocess.run([RUNUSER, '-u', user, '--', *argv], env=env, cwd='/',
                              capture_output=True, timeout=300, check=False, input=input_bytes)

    def mira_as(self, user, *argv, **kwargs):
        return self.run(user, str(INSTALL / 'mira'), 'session', *argv, **kwargs)

    def fails(self, user, *argv):
        return self.run(user, *argv).returncode != 0

    # Setup and teardown.

    def setup(self):
        subprocess.run(['groupadd', GROUP], check=True)
        for user in (OPERATOR, AGENT):
            subprocess.run(['useradd', '--create-home', '--user-group', '--groups', GROUP,
                            '--shell', '/bin/sh', user], check=True)
            self.home[user].chmod(0o700)
        INSTALL.mkdir(mode=0o755, parents=True)
        shutil.copy2(self.mira, INSTALL / 'mira')
        (INSTALL / 'mira').chmod(0o755)
        shutil.copytree(ROOT / 'agent', INSTALL / 'agent',
                        ignore=shutil.ignore_patterns('__pycache__', 'test_*'))
        for path in [INSTALL / 'agent', *(INSTALL / 'agent').rglob('*')]:
            path.chmod(0o755 if path.is_dir() else 0o644)
        keys = {OPERATOR: ('operator', 'collector'), AGENT: ('agent',)}
        lines = []
        for user, names in keys.items():
            for name in names:
                key = self.home[user] / name
                made = self.run(user, '/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                                '-C', name, '-f', str(key))
                assert made.returncode == 0, made
                public = ' '.join(key.with_suffix('.pub').read_text().split()[:2])
                namespaces = f'{NAMESPACE},{DOCUMENTS}' if name == 'collector' else NAMESPACE
                lines.append(f'{name} namespaces="{namespaces}" {public}\n')
        self.signers.write_text(''.join(lines))
        self.signers.chmod(0o644)
        WORK.mkdir(mode=0o755)
        (WORK / 'op').mkdir(mode=0o755)
        os.chown(WORK / 'op', pwd.getpwnam(OPERATOR).pw_uid, pwd.getpwnam(OPERATOR).pw_gid)

    def teardown(self):
        for user in (OPERATOR, AGENT):
            subprocess.run(['pkill', '-u', user], capture_output=True, check=False)
            subprocess.run(['userdel', '--remove', user], capture_output=True, check=False)
        subprocess.run(['groupdel', GROUP], capture_output=True, check=False)
        shutil.rmtree(WORK, ignore_errors=True)
        shutil.rmtree(INSTALL, ignore_errors=True)

    # The checks.

    def operator(self, *argv):
        return self.mira_as(OPERATOR, *argv[:1], str(self.session), '--allowed-signers', str(self.signers),
                            *argv[1:])

    def broker(self):
        ran = self.operator('run', '--key', str(self.home[OPERATOR] / 'collector'), '--once')
        return ran.returncode, ran.stdout.decode()

    def request(self, *argv):
        return self.mira_as(AGENT, 'request', str(self.session), '--allowed-signers', str(self.signers),
                            '--key', str(self.home[AGENT] / 'agent'), *argv)

    def main(self):
        tools = subprocess.run([sys.executable, str(INSTALL / 'agent/mira_agent_mcp.py'), '--tools-hash'],
                               capture_output=True, text=True, check=True).stdout.strip()
        started = self.operator('start', '--key', str(self.home[OPERATOR] / 'operator'),
                                '--operator', 'operator', '--agent', 'agent', '--collector', 'collector',
                                '--separation', 'separate_user', '--agent-group', GROUP,
                                '--agent-tools', tools, '--question', 'Is memory the problem?')
        self.check('the operator starts a separate_user session', started.returncode == 0)
        if started.returncode != 0:
            print(started.stdout.decode(), started.stderr.decode())
            return
        gid = grp.getgrnam(GROUP).gr_gid
        modes = {path: os.stat(self.session / path) for path in ('.', 'entries', 'documents', 'requests', 'inbox')}
        self.check('the layout belongs to the agent group with the documented modes',
                   all(item.st_gid == gid for item in modes.values())
                   and [stat.S_IMODE(modes[path].st_mode) for path in modes]
                   == [0o750, 0o2750, 0o2750, 0o2750, 0o2770])
        entry = self.session / 'entries/000000.entry'
        self.check('entries are 0640', stat.S_IMODE(os.stat(entry).st_mode) == 0o640)

        # What the agent can read.
        self.check('the agent reads the log', self.run(AGENT, 'cat', str(entry)).returncode == 0)
        self.check('the agent reads the signers file', self.run(AGENT, 'cat', str(self.signers)).returncode == 0)

        # What the agent cannot touch.
        for place in ('entries', 'documents', 'requests', '.'):
            self.check(f'the agent cannot create files in {place}',
                       self.fails(AGENT, 'touch', str(self.session / place / 'forged')))
        self.check('the agent cannot remove an entry', self.fails(AGENT, 'rm', '-f', str(entry)))
        self.check('the agent cannot append to an entry',
                   self.fails(AGENT, 'sh', '-c', f'echo x >> {entry}'))
        self.check('the agent cannot rename the session',
                   self.fails(AGENT, 'mv', str(self.session), str(WORK / 'op/elsewhere')))
        self.check('the agent cannot replace the session parent',
                   self.fails(AGENT, 'touch', str(WORK / 'op/forged')))
        self.check('the agent cannot change the signers file',
                   self.fails(AGENT, 'sh', '-c', f'echo x >> {self.signers}'))
        for key in ('operator', 'collector'):
            self.check(f"the agent cannot read the {key}'s key",
                       self.fails(AGENT, 'cat', str(self.home[OPERATOR] / key)))
        # Operator-side commands with the agent's key write nothing.
        before = sorted(os.listdir(self.session / 'entries'))
        own = str(self.home[AGENT] / 'agent')
        self.check('the agent cannot direct the session',
                   self.mira_as(AGENT, 'direct', str(self.session), '--allowed-signers', str(self.signers),
                                '--key', own, '--level', 'manual').returncode != 0)
        self.check('the agent cannot run the broker with its own key',
                   self.mira_as(AGENT, 'run', str(self.session), '--allowed-signers', str(self.signers),
                                '--key', own, '--once').returncode != 0)
        self.check('nothing was written by those attempts',
                   sorted(os.listdir(self.session / 'entries')) == before)

        # The agent's requests, and one the broker's own user put there.
        self.check('the agent submits a request',
                   self.request('--capability', 'memory-headroom', '--arguments', '1',
                                '--text', 'headroom first').returncode == 0)
        inbox = sorted((self.session / 'inbox').glob('*.request'))
        self.check('the inbox file belongs to the agent',
                   len(inbox) == 1 and os.stat(inbox[0]).st_uid == pwd.getpwnam(AGENT).pw_uid)
        self.check('the agent submits a second request',
                   self.request('--question', '--text', 'Is the journal visible?').returncode == 0)
        planted = next(path for path in (self.session / 'inbox').glob('*.request') if path not in inbox)
        record = planted.read_bytes()
        planted.unlink()
        moved = self.run(OPERATOR, 'sh', '-c', f'cat > {planted}', input_bytes=record)
        self.check('the operator can place a copy of an agent request', moved.returncode == 0)
        code, output = self.broker()
        self.check('the broker admits the agent request and refuses the operator-owned copy',
                   code == 0 and sorted(line.split(' as ')[0] for line in output.splitlines())
                   == ['MIRA session: admitted request', 'MIRA session: refused request (owner)'])
        documents = sorted((self.session / 'documents').glob('*.json'))
        self.check('the result document exists, and the agent reads it',
                   len(documents) == 1 and self.run(AGENT, 'cat', str(documents[0])).returncode == 0)
        self.check('the agent cannot change the document or its signature',
                   self.fails(AGENT, 'sh', '-c', f'echo x >> {documents[0]}')
                   and self.fails(AGENT, 'sh', '-c', f'echo x >> {documents[0]}.sig'))

        # A model agent through the harness, entirely as the agent's user.
        replay = self.home[AGENT] / 'replay.json'
        calls = [{'type': 'function', 'function': {'name': 'ask', 'arguments': json.dumps(
            {'question': 'Anything else to check?'})}}]
        self.run(AGENT, 'sh', '-c', f'cat > {replay}', input_bytes=json.dumps(
            [{'choices': [{'message': {'role': 'assistant', 'tool_calls': calls}}]}]).encode())
        hosted = self.run(AGENT, sys.executable, str(INSTALL / 'agent/mira_agent_host.py'),
                          '--session', str(self.session), '--allowed-signers', str(self.signers),
                          '--key', own, '--mira', str(INSTALL / 'mira'), '--turn-delay', '0',
                          '--replay', str(replay), '--record', str(self.home[AGENT] / 'transcript'))
        self.check('the client host runs as the agent user', hosted.returncode == 0)
        code, output = self.broker()
        self.check('the broker admits the harness request',
                   code == 0 and output.startswith('MIRA session: admitted request'))

        # The operator verifies and closes; the receipt stays private.
        receipt = self.home[OPERATOR] / 'receipt'
        closed = self.operator('close', '--key', str(self.home[OPERATOR] / 'operator'),
                               '--conclusion', 'memory is fine', '--receipt', str(receipt))
        self.check('the operator closes with a receipt', closed.returncode == 0)
        verified = self.operator('verify', '--operator', 'operator', '--expect-close', str(receipt))
        self.check('the session verifies against the receipt', verified.returncode == 0)
        self.check('the agent cannot read the receipt', self.fails(AGENT, 'cat', str(receipt)))
        self.check('the agent cannot submit after close',
                   self.request('--question', '--text', 'still there?').returncode != 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description='live separate_user containment test')
    parser.add_argument('--mira', default=str(ROOT / 'target/debug/mira'))
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or os.environ.get('MIRA_DISPOSABLE_HOST') != '1':
        print('refused: run as root on a disposable host with MIRA_DISPOSABLE_HOST=1; '
              'this creates and removes users', file=sys.stderr)
        return 2
    existing = []
    for user in (OPERATOR, AGENT):
        try:
            pwd.getpwnam(user)
            existing.append(user)
        except KeyError:
            pass
    try:
        grp.getgrnam(GROUP)
        existing.append(GROUP)
    except KeyError:
        pass
    if existing or WORK.exists() or INSTALL.exists():
        print('refused: test users, group or paths already exist', file=sys.stderr)
        return 2
    run = Run(args.mira)
    try:
        run.setup()
        run.main()
    finally:
        run.teardown()
    if run.failures:
        print(f'{len(run.failures)} containment checks failed', file=sys.stderr)
        return 1
    print('separate_user containment checks passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
