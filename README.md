# envault

Local secrets vault for agentic coding. Agents see **aliases** and **ciphers** —
plaintext exists only inside the process that needs it.

**Platforms:** macOS (Keychain), Windows (Credential Manager), and Linux
(Secret Service). The dashboard, `run`, and rotation work on all three; the
`request` popup opens a Terminal window on macOS, a Windows Terminal/PowerShell
window on Windows, and a terminal emulator on Linux.

## Quickstart

    envault init                          # keypair -> OS secret store
    envault add openrouter                # value typed at a hidden prompt
    envault link OPENROUTER_API_KEY openrouter
    envault run -- npm start              # injected + masked

- `envault ls --json` — names only; the only read an agent needs.
- `envault import .env` — encrypt an existing dotenv file, then delete it.
- Output of `envault run` is masked: injected values (and their base64/URL
  forms) print as `[envault:<alias>]`.
- `envault rotate` — re-encrypt the whole vault to a brand-new keypair. The
  Keychain item is deleted and recreated, so macOS asks for authorization
  again (re-grant "Always Allow") — intentional: rotation revokes every
  previously trusted binary. Human-only; the plugin blocks agents from it.
- `envault fill <alias> --selector '#password'` — type a secret straight into
  a browser page over CDP (launch the browser with
  `--remote-debugging-port=9222`). The agent driving the browser never sees
  the value; if the secret has a `url`, filling on a different host is
  refused. Don't screenshot right after filling a visible (non-password)
  field — password inputs render masked, plain text fields don't.
- The `envault` dashboard **live-updates**: if a secret is added while it's
  open (e.g. a granted `envault request`), it reloads within ~500ms.
- `envault config set audit-log on` — record every decryption (time, name,
  action, calling command) to a small, hash-chained, tamper-evident log.
  View it with `envault audit`. Both are human-only and gated behind a
  system (Touch ID / password) prompt, so an agent can neither read the log
  nor silently disable it.
- `envault config set touch-id on` — require a Touch ID / Windows Hello /
  password prompt before every decryption. Opt-in; off by default for
  smoothness. (macOS/Windows; not available on Linux yet.)
- Both toggles are also in the dashboard's `:` command palette (`:audit`,
  `:touchid`), and the current on/off state shows in `?` help.

## Agent integration (Claude Code plugin)

This repo doubles as a plugin marketplace. Install:

    claude plugin marketplace add /path/to/this/repo   # or the GitHub repo slug
    claude plugin install envault@envault

What it does:

- **Skill**: teaches Claude the aliases-only workflow — discover names with
  `envault ls --json`, wire projects via `envault link` / `envault.toml`, run
  everything through `envault run --`, ask *you* to add missing secrets in
  your own terminal, and offer `envault import` when it spots a plaintext
  `.env`. Claude never asks you to paste a value into chat.
- **Guard hooks** (PreToolUse): block agent access to `~/.envault/` and to the
  bare `envault` TUI (human-only). Everything else — `ls`, `link`, `run`,
  `import`, `add` — stays frictionless. If the `envault` binary isn't
  installed, the hook fails open and never blocks your session.

## Security model (short form)

Protects against secrets entering an agent's context, transcripts, files, or
logs. Does **not** protect against code that deliberately exfiltrates its own
environment over the network at runtime. Values shorter than 6 characters are
injected but not masked. Full spec: `docs/superpowers/specs/2026-08-26-envault-design.md`.

Note for debug builds: macOS shows a Keychain authorization prompt the first
time a newly built binary reads the identity — click "Always Allow". Tests
never touch the Keychain (they use `ENVAULT_IDENTITY_FILE`).
