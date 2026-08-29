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
