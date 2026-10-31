# ADR 0011: host identity and document integrity

Status: **Accepted**, 2026-10-31 (proposed and reviewed the same day). **Stage 1 (CLI signing and `mira verify`) is implemented**; stage 2 (comparator verification) is not. User guide: [signatures](../signatures.md).

## Context

A capture's scope is an operator-typed label (`scope_trust: "operator_asserted"`). The comparator refuses mismatched labels, but equal labels do not show that two captures came from the same machine, and nothing shows that a file is the one MIRA wrote. ADR 0010 added reported same-boot ordering and states its limit: anyone who can write a capture file can forge a consistent timeline and boot binding. Investigation reports have the same gap, and they are what automation acts on, through their exit codes and assessments. "Host identity" covers two different needs:

| Need | Question | What would answer it |
|---|---|---|
| N1. **Correlation** | Do these two documents come from the same machine? | A stable machine identifier, which is not authenticated |
| N2. **Authenticity and integrity** | Did a host I trust produce exactly these bytes? | A signature by a key the verifier already trusts |

N1 without N2 is a convenience that a forger can copy. N2 answers N1 as a side effect, as far as the signing key is bound to the machine.

## Criteria

- Detect modification of a capture or investigation report between production and use, and name the key holder that produced it.
- **Self-contained:** the `mira` binary signs and verifies its own documents. Operators never run a separate signing command, and Python is not required.
- Keep MIRA free of hand-written or vendored cryptography and of new Rust crates (`unsafe` stays forbidden).
- Offline: no network, no hosted service, no certificate authority.
- No elevation: signing must not require reading root-only keys.
- Works on hosts without a TPM.
- Opt-in, and existing outputs unchanged by default.
- Never claim more than the mechanism shows: a signature proves possession of a key, not truthful measurements, freshness or hardware identity.

## Alternatives

| Option | N1 | N2 | Consequence |
|---|---|---|---|
| A. Status quo | No | No | Honest; labels remain the only scope |
| B. Export `/etc/machine-id` (opt-in) | Yes, unauthenticated | No | Readable without privilege, but cloned images often share it, containers vary, and it is a stable, highly linkable identifier. Copyable by any forger |
| C. SSH host key: fingerprint plus signature | Yes | Yes | Signing needs the root-only host private key (elevation). Many hosts, including the development host, run no sshd |
| D. **Operator-chosen signing key; detached OpenSSH SSHSIG signatures produced and verified by `mira` through `ssh-keygen`** | Via the key | Yes | No crypto in MIRA; passphrase, `ssh-agent` and FIDO2 keys all work; key custody is the operator's |
| D'. Same format, implemented natively with Rust crypto crates | Via the key | Yes | Needs MIRA's first external crates (Ed25519, SHA-2, the OpenSSH key format), encrypted-key support (bcrypt-pbkdf, AES), the agent protocol, and re-implementations of `allowed_signers` and revocation-list rules. FIDO2 is out of reach. In practice it would favour unencrypted keys, and any divergence from OpenSSH would accept or reject the wrong signatures |
| E. TPM attestation (AK quote) | Yes, hardware-bound | Yes | Strongest binding, but absent on many hosts, needs TPM access (root or the tss group), and has vendor variance |
| F. Hand-written Ed25519 | — | — | Rejected |
| G. Signature inside the JSON document | — | — | Rejected: needs a canonical encoding to sign, and breaks byte-for-byte compatibility of existing formats |

## Evaluation of the self-contained options

OpenSSH 10.2 on the development host was tested directly before this decision:

| Test | Result | Consequence |
|---|---|---|
| `ssh-keygen -Y sign -f KEY -n NS` with data on stdin | Signature written to stdout; nothing written to disk | MIRA can sign the exact bytes it is about to print, with no write-then-sign race |
| Passphrase-protected key held in `ssh-agent`, signed via its public key file | Signs and verifies | Encrypted keys work; nothing pushes operators towards unencrypted keys |
| Passphrase-protected key, no terminal and no agent | Exit 255, empty signature | Failure is detectable; MIRA must treat an empty signature as failure |
| `ssh -Q key` | `sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com` present | FIDO2 security keys give hardware-backed signing on hosts without a TPM |
| `-Y check-novalidate -n NS -s SIG` on a fresh signature | Exit 0; exit 255 for different data or namespace | MIRA can check its own signature before writing it |
| `-Y verify`: modified bytes, wrong namespace, key listed only for another principal, revoked key (`-r`), garbage signature | Exit 255 each | Fails closed |
| `-Y verify`: two keys listed for one principal | Both verify | Key rotation is the `allowed_signers` file's decision |
| A principal containing `;touch pwned`, passed as one argument with no shell | Exit 255; nothing executed | No shell injection through argument values |

D' was assessed from what it would require, not prototyped; the requirements listed in the table above rule it out against the criteria.

## Decision (option D)

### Format and namespaces

A signature is a **detached** SSHSIG file covering the exact document bytes, including the trailing newline MIRA prints. There is one namespace per document kind, so a signature for one kind can never be accepted as another, or replayed from git or another tool:

| Document kind | Namespace |
|---|---|
| Capture (capture-v1 and capture-v2) | `mira-capture-v1@rmednitzer.github.io` |
| Investigation report (every template) | `mira-investigation-v1@rmednitzer.github.io` |

Document formats are unchanged, and unsigned documents stay valid.

### Signing (stage 1)

```sh
mira capture LABEL [--pressure] [--timeline] [--bind-boot] --signature PATH --sign-with KEY > capture.json
mira investigate TEMPLATE ... --json --signature PATH --sign-with KEY > report.json
```

- `--signature PATH --sign-with KEY` are given together, as the last options, and only on JSON output (`capture`, or `investigate ... --json`); human output is never signed. KEY is a private key file, or a public key whose private half is in `ssh-agent` or on a FIDO2 token.
- Order of operations:
  1. Build the document in memory.
  2. Run `/usr/bin/ssh-keygen -Y sign -f KEY -n NAMESPACE`, with the bytes on stdin and the signature read from stdout.
  3. Create PATH exclusively, never overwriting, and write and sync the signature.
  4. Self-check it with `-Y check-novalidate` over the same bytes.
  5. Only then print the document.

  Implementation note: `check-novalidate` reads the signature from a file (`-s`), so the self-check runs after the exclusive write rather than before it. A failed write or self-check removes the file again, so no unchecked signature remains.
- If any step fails (a missing `ssh-keygen`, a non-zero exit, an empty or oversized signature, a failed self-check, or an existing PATH), MIRA prints no document, writes no signature and exits **4** with a fixed diagnostic. Partial or unsigned output is never presented as signed.
- `ssh-keygen` inherits the terminal's stderr and the environment (`SSH_AUTH_SOCK`), so passphrase and FIDO2 touch prompts reach the operator. Signing has a bounded but interactive timeout. Without a terminal or agent, an encrypted key fails cleanly (exit 4).
- Investigation exit codes 0, 1 and 3 keep their meaning when signing succeeds.

### Verification (stage 1)

```sh
mira verify FILE --signature SIG --allowed-signers SIGNERS --principal NAME [--revocations KRL]
```

- MIRA reads FILE once (bounded to 1 MiB) and selects the namespace from its leading bytes: `{"capture_version":` gives the capture namespace and `{"investigation_version":` the investigation namespace. Anything else is refused. It then runs `/usr/bin/ssh-keygen -Y verify -f SIGNERS -I NAME -n NAMESPACE -s SIG [-r KRL]` with those bytes on stdin, trusting only the exit status.
- Exit 0 means verified, printing a fixed line with the namespace and principal. Exit 1 means not verified, with no detail from `ssh-keygen` passed through. Exit 2 is a usage error, and exit 4 means the tool is missing or failed to run.
- NAME is checked against a conservative principal syntax before use.

### Comparator verification (stage 2)

`scripts/compare_evidence.py before after --allowed-signers FILE --principal NAME [--revocations KRL]` verifies both captures with the same fixed command and namespace before comparing. Both must verify as the same principal, which answers N1 through N2. Output gains `integrity: {"status": "verified", "principal": NAME, "namespace": ...}`. Any failure exits 2, and output is unchanged without the options. This keeps an independent, non-Rust verification path for the offline tooling.

### Not adopted

`machine-id` export (option B) is not adopted: an unauthenticated stable identifier adds linkability without integrity. TPM attestation (option E) stays a possible later decision; FIDO2 keys already give hardware-backed signing where a token is available.

## Trust, privacy and failure analysis

- **What a verified signature means.** The holder of a key listed in `allowed_signers` for that principal signed these exact bytes for this document kind. It does not mean the measurements are true, that the host is uncompromised, that the evidence is fresh, or that the key lives on the machine its principal names. A compromised host can sign whatever it likes.
- **Replay.** A valid old document stays valid. Signatures add no freshness. ADR 0010 same-boot ordering helps only for captures from one boot, and a replayed pair orders as it did originally.
- **Key custody.** The capturing user must be able to use the key, through a file, the agent or a token, and others must not. A copied key signs as its principal. Rotation and revocation go through `allowed_signers` (`valid-before`/`valid-after`, namespace restrictions) and OpenSSH revocation lists.
- **New execution boundary (TB7).** The `mira` CLI and the comparator execute `ssh-keygen`. Mitigations:
  - an absolute path, a fixed argument vector and no shell
  - document bytes passed on stdin, and file paths as single arguments
  - only exit status and bounded signature bytes trusted, never parsed text
  - principal syntax validated before use
  - a bounded runtime
  This follows the fixed `systemctl show` pattern (ADR 0001). The operator's environment (`SSH_AUTH_SOCK`, `SSH_ASKPASS`) is deliberately inherited for signing, because it belongs to the same user.
- **New write path.** The signature file is MIRA's first file write. It is created exclusively, never overwriting, never followed through an existing name, and contains only the public signature.
- **Disclosure.** Principal names and key fingerprints identify operators or hosts. They appear only when signing or verification is requested.
- **Availability.** A missing `ssh-keygen`, or one without `-Y` support, is a hard failure (exit 4, or 2 in the comparator), never an unsigned pass. `openssh-client` becomes a package suggestion, not a dependency.

## Acceptance for implementation

Stage 1 (Rust CLI), with tests run against the real `ssh-keygen` and throwaway keys in temporary directories:

- **Signing** for capture-v1, capture-v2 and every investigation template's JSON output. The signature must verify with `mira verify` and independently with `ssh-keygen -Y verify`.
- **Signing failures**, each giving exit 4 with no stdout and no signature file:
  - an encrypted key without a terminal or agent
  - a missing key
  - an existing signature path
  - a missing `ssh-keygen` (through a test-only fixture, as with the systemctl fixture)
- **Verification refusals:**
  - one modified byte
  - the other kind's namespace
  - a signature for a different file
  - an unknown key
  - a key listed only for another principal
  - an expired `valid-before`
  - a revoked key
  - unknown leading bytes
  - principal syntax refusals
  - a garbage signature
- **Unchanged output** without the new options.
- **Fixed-argv checks** through the test fixture.
- **Packaging:** `Suggests` gains `openssh-client`.

Stage 2 (comparator): the same verification matrix through `compare_evidence.py`, both inputs under one principal, and unchanged output without the options.

CI covers both native architectures; `openssh-client` is present on the runners.

## Consequences and rollback

Blast radius:
- opt-in signing options on `capture` and `investigate`
- one new `verify` subcommand
- one new exit code (4) that occurs only when signing or verification is requested
- one comparator option

Existing formats and outputs are unchanged. Signatures are separate files, so removing the feature leaves every document valid. No operational state requires rollback.

## Review decisions

1. **Mechanism:** OpenSSH SSHSIG, because a TPM is not always available. FIDO2 keys provide hardware-backed signing where a token exists.
2. **Self-contained:** `mira` signs and verifies its own documents through `ssh-keygen`. Operators never run a separate signing command, and Python is not required. A native implementation (D') was evaluated and rejected against the criteria above.
3. **Namespace:** `mira-capture-v1@rmednitzer.github.io` for captures.
4. **Investigation reports are signable**, under the separate namespace `mira-investigation-v1@rmednitzer.github.io`, so a signature for one document kind can never be accepted for the other.

## Primary references

- [OpenSSH PROTOCOL.sshsig](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
- [ssh-keygen(1): -Y sign, verify, check-novalidate; ALLOWED SIGNERS](https://man.openbsd.org/ssh-keygen)
- [machine-id(5)](https://www.freedesktop.org/software/systemd/man/latest/machine-id.html)
