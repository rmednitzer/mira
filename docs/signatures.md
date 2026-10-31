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
  3. Create PATH exclusively (an existing file is never overwritten) and write the signature.
  4. Self-check it with `ssh-keygen -Y check-novalidate` over the same bytes.
  5. Only then print the document.
- If any step fails, MIRA removes the signature it wrote, prints nothing and exits **4**. Exit codes 0, 1 and 3 keep their usual meaning when signing succeeds.

Each document kind has its own namespace, so a signature for one kind is never accepted for another:

| Document | Namespace |
|---|---|
| capture-v1 and capture-v2 | `mira-capture-v1@rmednitzer.github.io` |
| every investigation report | `mira-investigation-v1@rmednitzer.github.io` |

## Verify

Keep an `allowed_signers` file listing trusted keys per principal, restricted to MIRA's namespaces:

```text
host-a namespaces="mira-capture-v1@rmednitzer.github.io,mira-investigation-v1@rmednitzer.github.io" ssh-ed25519 AAAA...
```

```sh
mira verify incident-a.json --signature incident-a.json.sig --allowed-signers allowed_signers --principal host-a
mira verify report.json --signature report.json.sig --allowed-signers allowed_signers --principal host-a --revocations revoked.krl
```

- MIRA reads the document once (at most 1 MiB) and picks the namespace from its leading bytes: `{"capture_version":` or `{"investigation_version":`. Anything else is not verified.
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

A compromised host can sign anything. A valid old document stays valid, because signatures add no freshness. The private key must be usable by the capturing user and protected from everyone else; a copied key signs as its principal. Principal names and key fingerprints identify operators or hosts, so treat `allowed_signers` and verification output accordingly.

Verifying captures inside the offline comparator is a later stage of ADR 0011; until then, verify each capture with `mira verify` before comparing.
