# envault

Local secrets vault for agentic coding. Agents see **aliases** and **ciphers** —
plaintext exists only inside the process that needs it.

## Quickstart

    envault init                          # keypair -> macOS Keychain
    envault add openrouter                # value typed at a hidden prompt
    envault link OPENROUTER_API_KEY openrouter
    envault run -- npm start              # injected + masked

- `envault ls --json` — names only; the only read an agent needs.
- `envault import .env` — encrypt an existing dotenv file, then delete it.
- Output of `envault run` is masked: injected values (and their base64/URL
  forms) print as `[envault:<alias>]`.

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
