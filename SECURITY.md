# Security Policy

envault is a secrets tool, so its security posture *is* the product. This covers
what it defends, what it deliberately doesn't, and how to report a flaw.

## What envault is for

envault keeps secrets **out of a coding agent's context and out of your files.**
Agents work only with names and age-encrypted ciphers; plaintext exists only
inside a process envault launches, and that process's output is masked. This
defeats the realistic, everyday threat: prompt-leakage, a key pasted into chat, a
secret committed to a repo, or a prompt-injected-but-cooperative agent reading a
credential it shouldn't.

## What envault does NOT protect against

Being honest about the boundary is part of being trustworthy:

- **A genuinely malicious process running as your user, at runtime.** Anything
  that can run `envault run -- …` as you can obtain and *use* a secret exactly the
  way your real program does — and then do anything with it, including send it
  over the network. No local secrets manager (1Password included) can stop code
  running as *you* from using a key you have authorized. envault does not sandbox
  the child process.
- **A fully compromised machine.** An attacker who controls your account can stop
  or delete the audit log going forward; the HMAC hash-chain makes *past*
  tampering evident, not impossible.
- **Deliberate runtime exfiltration** from inside a command you chose to run.

If your threat model includes a hostile process already executing as your user,
envault is the wrong control — that needs OS-level isolation (a sandbox, a
separate user, a VM). **envault raises the cost of leaking a secret; it is not a
runtime sandbox.**

For the full picture see the README's
[security model](README.md#security-model--the-safety-boundary) and
[`docs/how-it-works.md`](docs/how-it-works.md).

## Identity migration and revocation

Each vault carries a public, stable `identity-id` file and uses it to select a
separate OS credential account. Moving the complete vault directory therefore
keeps its identity association. The private key remains only in the credential
store.

On first access, envault migrates a matching canonical-path credential to the
stable account and removes the obsolete path-based copy. A matching legacy
shared credential is copied but retained temporarily because another unmigrated
vault may still depend on it. `envault rotate` removes every stored copy that
matches the retired identity, including that legacy slot; users with multiple
legacy vaults sharing one identity should access each vault to migrate it before
rotating any of them. A mismatching credential is never adopted or deleted.

If identity metadata survives but `vault.json` does not, initialization fails
closed instead of replacing the private key. Restore the vault file from backup
before retrying.

## Supported versions

envault is pre-1.0; only the latest release line receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.7.x   | ✅        |
| < 0.7   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub security advisories:

> **https://github.com/MildyNora/envault/security/advisories/new**

Include what you found, how to reproduce it, the impact, and any suggested fix.
You'll get an acknowledgement and then a fix or a reasoned decision as soon as is
practical. If a report falls within the documented boundary above (e.g. runtime
misuse by a process already running as you), we'll say so rather than treat it as
a vulnerability.
