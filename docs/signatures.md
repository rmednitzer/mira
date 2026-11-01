# Signed captures and investigation reports

`mira` can sign its own JSON output and verify it later, using detached OpenSSH signatures made by `/usr/bin/ssh-keygen` (package `openssh-client`). MIRA contains no cryptography of its own. See [ADR 0011](adr/0011-host-identity-and-capture-integrity.md) for the design and its limits.

## Sign

```sh
mira capture incident-a --timeline --signature incident-a.json.sig --sign-with ~/.ssh/mira_ed25519 > incident-a.json
mira investigate pressure-ceiling --resource io --max-some-avg10-basis-points 1000 --json \
  --signature report.json.sig --sign-with ~/.ssh/mira_ed25519.pub > report.json
```

- `--signature PATH --sign-with KEY` come last, together, and only on JSON output: any `capture`, or `investigate ... --json`. Human-readable output, `inspect --json` and `service --json` cannot be signed (exit 2).
- KEY is a private key file, or a public key whose private half is held in `ssh-agent` or on a FIDO2 security key. Passphrase and touch prompts appear on the terminal. Without a terminal or agent, an encrypted key fails cleanly.
- MIRA signs the exact bytes it prints, including the trailing newline. Keep stdout byte-for-byte, for example by redirecting it to a file; any change, even a reformatted JSON file, no longer verifies.
- Steps, in order:
  1. Build the document in memory.
  2. Sign it through `ssh-keygen` on stdin.
  3. Self-check it with `ssh-keygen -Y check-novalidate` over the same bytes, using a copy in a fresh private directory (mode 0700) that is removed afterwards.
  4. Create PATH exclusively (an existing file or symlink is never overwritten or followed), with a mode of at most 0644 whatever the umask, and write the signature.
  5. Only then print the document.
- If any step fails, MIRA prints nothing and exits **4**. A failed check never leaves a signature at PATH, because PATH is created only after the check passes. MIRA never deletes PATH by name; if writing it fails after creation, MIRA empties it through its own open file. Exit codes 0, 1 and 3 keep their usual meaning when signing succeeds.

Each document kind has its own namespace, so a signature for one kind is never accepted for another:

| Document | Namespace |
|---|---|
| capture-v1, capture-v2 and capture-v3 | `mira-capture-v1@rmednitzer.github.io` |
| every investigation report | `mira-investigation-v1@rmednitzer.github.io` |
| every [session](sessions.md) entry | `mira-session-v1@rmednitzer.github.io` |

## Verify

Keep an `allowed_signers` file listing trusted keys per principal, restricted to MIRA's namespaces:

```text
host-a namespaces="mira-capture-v1@rmednitzer.github.io,mira-investigation-v1@rmednitzer.github.io" ssh-ed25519 AAAA...
```

```sh
mira verify incident-a.json --signature incident-a.json.sig --allowed-signers allowed_signers --principal host-a
mira verify report.json --signature report.json.sig --allowed-signers allowed_signers --principal host-a --revocations revoked.krl
```

- MIRA opens the document nonblocking and requires a regular file (a FIFO or device is not verified, rather than hanging), reads it once (at most 1 MiB) and picks the namespace from its leading bytes: `{"capture_version":` or `{"investigation_version":`. Anything else is not verified.
- It runs `/usr/bin/ssh-keygen -Y verify` with a fixed argument list and no shell, trusting only the exit status.
- The principal must be 1–128 characters from `A-Za-z0-9._@+-`, starting with a letter or digit.
- Exit codes: **0** verified, with one line naming the namespace and principal; **1** not verified, with no tool output passed through; **2** usage; **4** `ssh-keygen` unavailable.
- `allowed_signers` options such as `valid-before`/`valid-after` apply, and a revocation list (`ssh-keygen -k`) is honoured through `--revocations`. One principal may list several keys, for example during rotation; each then verifies as that principal.

## What a verified signature means

A key listed for that principal signed these exact bytes, for this document kind. It does **not** mean:
- that the measurements are true
- that the host was uncompromised
- that the evidence is fresh
- that the key lives on the machine its principal names

A compromised host can sign anything. A valid old document stays valid, because signatures add no freshness on their own; [answer a challenge](#freshness-answer-a-challenge) for that. The private key must be usable by the capturing user and protected from everyone else; a copied key signs as its principal. Principal names and key fingerprints identify operators or hosts, so treat `allowed_signers` and verification output accordingly.

## Freshness: answer a challenge

A signature shows who signed a capture, not when. To bound its age without trusting the host's clock ([ADR 0014](adr/0014-consumer-challenge-freshness.md)), the consumer issues a challenge, the host answers it in a signed capture, and the consumer checks the answer on its own clock:

```sh
# consumer
mira challenge > challenge.json
# host, given the 64-hex "challenge" value from challenge.json
mira capture incident-a --challenge HEX --signature incident-a.json.sig --sign-with ~/.ssh/mira_ed25519 > incident-a.json
# consumer, on the machine that issued the challenge
mira verify incident-a.json --signature incident-a.json.sig --allowed-signers allowed_signers --principal host-a \
  --challenge-file challenge.json --max-age-ms 600000
```

- `mira challenge` prints `{"challenge_version":1,"challenge":"<64 hex>","issued_unix_ms":N}`: 32 bytes from `/dev/urandom` and the issuing machine's wall clock. A failed read exits 4 with no output. Keep `challenge.json` where only you can write it: anyone who can edit it can widen the bound. Only the challenge value goes to the host, never the issue time. Issue one challenge per capture.
- `--challenge` requires signing and emits [capture-v3](captures.md#challenged-captures-capture-v3). MIRA reads the challenge before collecting anything, so every source was read after the host received it.
- `--challenge-file` and `--max-age-ms` (1–16 digits) come together, after any `--revocations`. The signature is checked first. Then MIRA requires the challenge file's exact layout (a regular file of at most 4 KiB, opened nonblocking), checks that the capture begins `{"capture_version":3,"challenge":"` followed by the same value, and computes `age_bound_ms = now - issued_unix_ms` on its own clock.
- Exit **0** prints the usual line plus `age_bound_ms=N`. Exit **1** prints `not verified (REASON)` with one reason: `signature` for any signature-stage refusal, `challenge_mismatch`, `not_challenged` (capture-v1 or v2), `issued_in_future` (the verifier clock is earlier than the issue time) or `older_than_policy`. A malformed, oversized or non-regular challenge file, or a bad `--max-age-ms`, exits 2; an unreadable challenge file exits 4.
- Without these options capture-v3 verifies like any other capture.

The comparator checks both sides of a comparison the same way, on the bytes it compares:

```sh
.schema-venv/bin/python scripts/compare_evidence.py before.json after.json \
  --allowed-signers allowed_signers --principal host-a \
  --before-challenge before.challenge --after-challenge after.challenge --max-age-ms 600000
```

The three freshness options go together and require the trust options. Each challenge file must have the exact challenge-v1 layout and pass its [closed schema](../schemas/challenge-v1.schema.json), each capture must answer its own challenge at the fixed prefix, and the parsed `challenge` member must agree. The two challenges must differ, so one answer cannot stand in for two captures. The comparator reads its clock once and requires `0 ≤ now − issued ≤ N` for both sides. Output gains `freshness: {"status": "within_policy", "max_age_ms": N, "before_age_bound_ms": ..., "after_age_bound_ms": ...}`; any failure exits 2 with no output.

A pass means a key listed for the principal signed a capture answering your challenge, at most `age_bound_ms` after you issued it. It assumes the key holder ran an unmodified `mira`, and it does not make the measurements true. Use one machine to issue and verify: across two machines, their clock offset enters the bound.

## Verify while comparing

`mira verify` reports on the bytes it read at that moment. Anything that later reopens the path, including the comparator, may read different bytes if someone else can write to that path. So **do not verify and then compare as two steps.** Let the comparator verify the exact bytes it compares:

```sh
.schema-venv/bin/python scripts/compare_evidence.py before.json after.json \
  --allowed-signers allowed_signers --principal host-a [--revocations revoked.krl]
```

- It reads each capture once and verifies those in-memory bytes against `INPUT.sig` (for example `before.json.sig`) under the capture namespace, with the same fixed `ssh-keygen` command and no shell. Then it parses and compares the same bytes. Replacing a file after the check cannot change what is compared.
- Both captures must verify as the given principal. The output gains `integrity: {"status": "verified", "principal": ..., "namespace": ...}`.
- Any failure exits 2 with no output: a missing signature, a refusal, a missing `ssh-keygen`, an invalid principal, or a non-capture input such as legacy JSONL. `--allowed-signers` and `--principal` must be given together.
- Without these options, comparison output is unchanged and carries no integrity claim.

Keep captures in a directory only you can write to anyway: verification makes forgery detectable, but it cannot protect files you later open with other tools.
