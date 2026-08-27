---
name: envault
description: Use when a project needs an API key, token, password, or other secret — before asking the user for a value, before writing any .env file, and whenever a command needs credentials injected (e.g. OPENROUTER_API_KEY). Also use when a plaintext .env file is spotted in the repo. Teaches the envault aliases-only workflow: agents handle names and ciphers, never plaintext secrets.
---

# envault: secrets without plaintext

envault is a local vault. You (the agent) work only with **aliases** (names)
and **ciphers** (encrypted blobs). Plaintext values exist solely inside
processes launched by `envault run`. Follow these rules exactly.

## Never do

- Never ask the user to paste a secret value into the chat.
- Never write a plaintext secret into any file (.env, config, code, docs).
- Never try to read `~/.envault/` or open the bare `envault` TUI — both are
  human-only and blocked by hooks.
- Never try to unmask `[envault:<alias>]` text in command output. That marker
  means injection WORKED; it is not an error.

## Workflow

1. **Discover** what exists: `envault ls --json` (names and labels only).
2. **Wire the project**: `envault link ENV_VAR alias` writes the mapping into
   `envault.toml` (safe to read, edit, and commit — names only). Code then
   reads ordinary environment variables (e.g. `process.env.OPENROUTER_API_KEY`).
3. **Run things through the wrapper**: `envault run -- <command>` for anything
   that needs the secrets (dev servers, tests, scripts). Output is masked:
   injected values print as `[envault:<alias>]`.
4. **Missing secret?** If the alias you need is not in `envault ls`, STOP and
   ask the user to add it: they run `envault add <alias>` (hidden prompt) or
   the `envault` dashboard in their own terminal. Wait for their go-ahead,
   then re-check `envault ls --json` and continue.
5. **Plaintext .env in the repo?** Offer to run `envault import .env` (it
   encrypts every entry into the vault and links the manifest), then suggest
   the user delete the file.
6. **envault not installed?** (`command -v envault` fails) Ask the user to
   install it (from this repo: `cargo install --path .`), then `envault init`.

## Command cheat sheet (all agent-safe)

| Need | Command |
|---|---|
| List secret names | `envault ls --json` |
| Map env var to alias | `envault link OPENROUTER_API_KEY openrouter` |
| Run with secrets | `envault run -- npm start` |
| Extra one-off mapping | `envault run --env VAR=alias -- <cmd>` |
| Encrypt an existing .env | `envault import .env` |
