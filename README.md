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

## Security model (short form)

Protects against secrets entering an agent's context, transcripts, files, or
logs. Does **not** protect against code that deliberately exfiltrates its own
environment over the network at runtime. Values shorter than 6 characters are
injected but not masked. Full spec: `docs/superpowers/specs/2026-08-26-envault-design.md`.

Note for debug builds: macOS shows a Keychain authorization prompt the first
time a newly built binary reads the identity — click "Always Allow". Tests
never touch the Keychain (they use `ENVAULT_IDENTITY_FILE`).
