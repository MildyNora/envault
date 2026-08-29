<div align="center">

# 🔐 envault

**A local, encrypted secrets vault for agentic coding — your AI agents work with your keys, but never see them.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange)
![Status](https://img.shields.io/badge/status-beta-yellow)

</div>

---

envault is a free, local secrets manager built for the age of coding agents. You
store API keys, tokens, and passwords once; your agent refers to them **by name**
and runs commands through envault — but the plaintext only ever exists inside the
process envault launches. It never reaches the model's context, a `.env` file, or
your chat history.

Think of it as a 1Password-style vault whose whole job is to keep secrets out of
your agent's "brain" while still letting the agent get real work done.

```console
$ envault add openrouter --label "OpenRouter API key"
Value for 'openrouter' (input hidden): ••••••••••••••••

$ envault ls                       # names only — safe to show an agent
ALIAS        LABEL                CREATED
openrouter   OpenRouter API key   2026-08-29

$ envault link OPENROUTER_API_KEY openrouter   # writes names, never secrets
$ envault run -- python app.py     # value injected as an env var, masked in output
```

The agent sees `openrouter` and an encrypted blob. It never sees `sk-or-...`.

---

## Contents

- [Why envault](#why-envault)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands](#commands)
- [How it works](#how-it-works)
- [Security model & the safety boundary](#security-model--the-safety-boundary)
- [Configuration](#configuration)
- [Works with your agent](#works-with-your-agent)
- [Platform support](#platform-support)
- [Status & limitations](#status--limitations)
- [License](#license)

---

## Why envault

- **Agents never see plaintext.** They work with aliases (names) and age-encrypted
  ciphers. The only place a secret is decrypted is inside a process envault starts.
- **Masked output.** `envault run` injects secrets as environment variables and
  scrubs them out of the command's stdout/stderr — so a leaked log stays clean.
- **No plaintext-emitting command exists.** There is deliberately no way to ask
  envault to print a secret to the terminal for an agent to read.
- **Your OS keychain holds the key.** The private key lives in the macOS Keychain,
  Windows Credential Manager, or Linux Secret Service — never on disk in the clear.
- **Optional Touch ID / Windows Hello and a tamper-evident audit log**, both gated
  so an agent can't silently turn them off.
- **Works across agents.** One Agent Skill teaches Claude Code, Codex, and opencode
  the same names-only workflow — loaded only when a task needs a secret.

## Install

```bash
git clone https://github.com/MildyNora/envault.git
cd envault
./install.sh            # Windows: .\install.ps1
```

The installer builds the binary, creates your vault (if you don't have one), and
installs the agent skill. Re-run it any time to upgrade.

Prefer to do it by hand?

```bash
cargo install --path .   # build & install the binary
envault init             # create the vault + keypair
envault skill install    # teach your agents the workflow
```

Requires [Rust](https://rustup.rs). macOS 11+, Windows 10+, or a Linux desktop
with a Secret Service backend (e.g. GNOME Keyring / KWallet).

## Quick start

```console
# 1. Store a secret (you, once)
$ envault add stripe --label "Stripe live key"

# 2. Point an environment variable at it (names only — commit this safely)
$ envault link STRIPE_API_KEY stripe

# 3. Run anything with secrets injected and masked
$ envault run -- npm run deploy

# 4. Open the dashboard (human-only, colorful TUI)
$ envault
```

When an agent needs a secret you haven't stored yet, it doesn't ask you to paste
one into chat — it requests it, and a small window pops up for you:

```console
$ envault request stripe --reason "the deploy needs the live key" --agent "Claude Code"
```

You paste the value (the agent never sees it) or decline with a note. The agent
receives only the outcome.

## Commands

| Command | Who | What it does |
|---|---|---|
| `envault init` | human | Create the vault and generate the keypair |
| `envault add <name>` | human | Store a secret (hidden prompt or `--stdin`) |
| `envault ls [--json]` | agent-safe | List secret **names** — never values |
| `envault link <ENV_VAR> <name>` | agent-safe | Map an env var to a name in `envault.toml` |
| `envault run -- <cmd>` | agent-safe | Run a command with secrets injected + output masked |
| `envault request <name>` | agent-safe | Ask you (in a pop-up) for a secret it doesn't have |
| `envault fill <name>` | agent-safe | Type a secret into a browser field over CDP (opt-in) |
| `envault import <.env>` | human | Encrypt a dotenv file into the vault |
| `envault rotate` | human | Re-key the whole vault and revoke keychain grants |
| `envault audit` | human | View the tamper-evident access log (gated) |
| `envault config [set …]` | human | View or change settings (gated) |
| `envault skill install` | human | Install the agent skill for Claude Code / Codex / opencode |
| `envault` | human | Open the interactive dashboard |

## How it works

**Data model.** The vault (`~/.envault/vault.json`) is a list of entries — each a
name plus an [age](https://age-encryption.org)-encrypted cipher. No plaintext is
stored anywhere in it. The age **private key lives in your OS keychain**, never on
disk in the clear; the public key is what secrets are encrypted to.

**One choke point.** Every operation that needs the private key —
`run` / `reveal` / `copy` / `fill` / `rotate` — goes through a single function that
(1) prompts for Touch ID if you enabled it, (2) loads the key from the keychain,
and (3) records the access to the audit log if enabled. There's no side door.

**Where plaintext is allowed to exist.** Exactly two runtime paths, each contained:

- **`envault run`** decrypts into a child process's environment and masks the
  values out of everything the child prints.
- **`envault fill`** types a value straight into a browser field over the DevTools
  protocol — opt-in, loopback-only, and pinned to the secret's registered origin.

Everywhere else, secrets stay encrypted.

## Security model & the safety boundary

envault is honest about what it does and doesn't do. It raises the cost of leaking
a secret; it is **not a sandbox.**

**✅ envault protects against**

- Secrets reaching the model's context or prompt (agents only ever get names + ciphers).
- Secrets landing in a file, a log, or your chat history (no plaintext-emitting command; `run` masks output).
- An agent silently disabling the audit log or Touch ID (settings are keychain-authoritative, fail closed, and gated).
- An agent tampering with the public key to re-encrypt your secrets to its own (the recipient is derived from your keychain identity).
- Accidental exfiltration, and a non-interactive agent triggering a destructive re-key.

**❌ envault does *not* protect against**

- **A malicious program running as you, at runtime.** Anything that can run
  `envault run -- …` as your user can use a secret exactly the way your real
  program does — and then do anything with it. No local secrets manager (1Password
  included) can stop code running as *you* from *using* a key you've authorized.
- **Deliberate network exfiltration** from inside a command you chose to run. envault
  doesn't sandbox the child process's network.
- **A fully compromised machine**, which can stop the audit log going forward. The
  log makes *past* tampering evident, not impossible.

In one line: **envault stops a secret from leaking into your agent's brain or your
files — it does not stop a program you've authorized to use a secret from misusing
it at runtime.** That's the boundary.

**Reporting a vulnerability.** Please open a private security advisory on the
repository rather than a public issue.

## Configuration

Settings live in your vault and are **gated** — changing them requires Touch ID /
Windows Hello, so an agent can't quietly weaken your setup.

| Setting | Default | Effect |
|---|---|---|
| `touch-id` | off | Prompt for Touch ID / Windows Hello before every decryption |
| `audit-log` | off | Record every secret access to a tamper-evident, HMAC-chained log |
| `fill` | off | Allow `envault fill` browser form-fill (loopback-only, origin-pinned) |

```bash
envault config              # show current settings
envault config set touch-id on
envault config set audit-log on
```

## Works with your agent

The names-only workflow ships as a single **Agent Skill** that loads lazily — only
when a task actually involves a secret, so it costs almost nothing until it's
needed. `envault skill install` writes it where each agent looks:

- **Claude Code** — `~/.claude/skills/`
- **Codex** — `~/.agents/skills/`
- **opencode** — reads both of the above

For anything else, `envault skill print` emits the skill so you can drop it into
whatever instructions file your agent reads. On Claude Code, an additional hook
actively blocks agents from the human-only surfaces; on other agents, those same
actions are still protected inside the binary.

## Platform support

| OS | Keychain backend | Biometric gate |
|---|---|---|
| macOS 11+ | Keychain | Touch ID |
| Windows 10+ | Credential Manager | Windows Hello |
| Linux | Secret Service (GNOME Keyring / KWallet) | — (fails closed) |

## Status & limitations

envault is **beta**. It's usable day-to-day, but a few things are worth knowing:

- The security model assumes a **trusted human and a semi-trusted agent** — see
  [the boundary above](#security-model--the-safety-boundary).
- The keychain-authoritative settings and biometric prompts should be verified on
  your own hardware; they behave differently across OSes.
- Key rotation is not yet fully crash-safe (a crash mid-re-key leaves a small
  recovery window). Back up before rotating on a machine you don't trust to stay up.

## License

[MIT](LICENSE).
