---
name: envault
description: Use whenever a task needs an API key, token, password, or other secret — before asking the user for a value, before writing any .env or hardcoding a key, and whenever a command needs credentials (e.g. OPENROUTER_API_KEY), or when a plaintext .env is present. envault lets you handle secrets by name only; you never see the plaintext.
---

# envault — secrets by name, never plaintext

You work with **names** and **ciphers**; real values exist only inside
processes started by `envault run`. Keep it that way.

## Rules
- Never ask the user to paste a secret into chat; never write a plaintext
  secret to any file.
- Refer to secrets by name only. `[envault:<name>]` in output means masking
  **worked** — not an error; don't try to unmask it.
- Human-only (hooks block you): the bare `envault` dashboard, `envault rotate`,
  `envault request-window`, `envault audit`, `envault config set`, and reading
  `~/.envault/`. Don't attempt them — ask the user instead.

## Workflow
1. **Discover:** `envault ls --json` → names + labels only.
2. **Wire:** `envault link ENV_VAR name` (writes `envault.toml`, names only).
   Code reads ordinary env vars (e.g. `process.env.OPENROUTER_API_KEY`).
3. **Run:** anything needing secrets goes through `envault run -- <cmd>`
   (values injected, output masked).
4. **Missing a secret?** Don't ask for the value — request it:
   `envault request <name> --reason "why" --agent "Claude Code"`.
   A window opens for the user; you get only the exit code:
   **0** granted (now usable via `envault run`) · **3** declined (reason on
   stderr — respect it) · **4** cancelled · **5** timeout · **6** no window.
5. **Plaintext `.env` present?** Offer `envault import .env`, then have the
   user delete the file.
6. **Not installed?** (`command -v envault` fails) Ask the user to install it
   (`cargo install --path .`) and run `envault init`.

## Browser login (value stays hidden from you)
Navigate to the form, then `envault fill <name> --selector '<css>'` — the value
goes vault→browser directly. Don't screenshot right after filling a *visible*
field (password inputs render masked; plain text ones don't). If fill refuses
on a host mismatch, tell the user — don't override.

## Cheat sheet (all agent-safe)
| Need | Command |
|---|---|
| List names | `envault ls --json` |
| Map env var → name | `envault link OPENROUTER_API_KEY openrouter` |
| Run with secrets | `envault run -- npm start` |
| One-off mapping | `envault run --env VAR=name -- <cmd>` |
| Request a missing secret | `envault request <name> --reason "…" --agent "Claude Code"` |
| Import a .env | `envault import .env` |
| Browser fill | `envault fill <name> --selector '#password'` |
