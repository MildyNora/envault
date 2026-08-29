# envault — How It Works & the Safety Boundary

> **Internal draft.** Working notes on the design and — more importantly — the
> exact line between what envault protects and what it deliberately does not.
> This is not the public README. Correct as of **v0.7.0**.

---

## 1. The one-sentence promise

Coding agents only ever see **names** (aliases) and **ciphers** (age-encrypted
blobs). Plaintext secrets exist only inside processes envault itself launches —
never in the model's context, never in a file, never in chat.

---

## 2. Threat model — who is trusted

| Party | Trust | Why |
|---|---|---|
| The human | Trusted | Holds the hardware, unlocks the keychain, approves handoffs. |
| The coding agent | **Semi-trusted; hostile to secrets by assumption** | May be prompt-injected. Assumed to try to read secrets it shouldn't — must be *useful* without ever seeing plaintext. |
| A process running as the user | **Cannot be fully stopped** | Can do anything the user can, including drive the legitimate decryption path. See §8. |

The entire design targets the middle row: keep the agent productive with secrets
while *structurally* denying it the plaintext.

---

## 3. Data model

- **Vault** — `~/.envault/vault.json`: a list of entries, each with `alias`,
  optional `label` / `url` / `notes`, `created_at`, and `cipher` (the
  age-encrypted value). No plaintext anywhere in it. File `0600`, dir `0700`
  (Unix).
- **Identity** — the age X25519 private key. Stored only in the **OS keychain**
  (macOS Keychain, Windows Credential Manager, Linux Secret Service; service
  `envault`). Never written to disk in the clear.
- **Recipient** — the public key, mirrored to `recipient.txt`, but treated as
  advisory only (see §4).

---

## 4. Crypto

- **age** X25519 asymmetric encryption: encrypt-to-recipient, decrypt-with-identity.
- The private identity lives only in the keychain; loading it is what triggers
  the OS authorization (and, if enabled, the Touch ID prompt).
- **The recipient is derived from the identity at encrypt time**
  (`recipient_from_identity()`), not read back from `recipient.txt`. This closes
  a tampering hole: an agent that could rewrite `recipient.txt` — or point
  `ENVAULT_HOME` at a directory it controls — would otherwise get new secrets
  re-sealed to *its* public key. (findings H2/H3)

---

## 5. The single choke point

Every use of the private key flows through one function —
`access::unlock(home, action, detail)`:

1. Load settings.
2. If `touch_id` is on → `biometric::require(...)` (Touch ID / Windows Hello)
   **before** anything else.
3. Load the identity from the keychain.
4. If `audit_log` is on → record the access, **fail-closed**: if the log cannot
   be written, the decryption is refused.

Because `run` / `reveal` / `copy` / `fill` / `rotate` all call `unlock`, the gate
and the audit trail cannot be bypassed by reaching for a different command path.

---

## 6. Where plaintext is allowed to exist — and how it is contained

Four commands touch plaintext. Each one confines it:

- **`envault run -- <cmd>`** — decrypts, injects the secrets as environment
  variables into the child process, and **masks** them out of the child's
  stdout/stderr (GitHub-Actions-style, including hex and base64 encodings of the
  value). The agent that orchestrated the run sees only masked output; the
  plaintext lives only in the child's memory.
- **`envault fill <name>`** — types a value straight into a browser field over
  CDP. **Off by default and fail-closed** (the `fill` setting): its origin guard
  cannot be trusted against a same-user process running its own loopback CDP
  endpoint, so it is opt-in, loopback-only, requires a registered `url`, and
  matches on full origin. (H1 / L2)
- **`envault request <name>`** — the agent→human handoff. Pops a **human-only**
  window (a fresh terminal) showing who is asking and why; the human pastes the
  value (agent never sees it) or declines with a note. The agent receives only an
  exit code: `0` granted · `3` declined · `4` cancelled · `5` timeout · `6`
  no-window.
- **`envault rotate`** — re-keys the whole vault to a fresh keypair and revokes
  every prior keychain "Always Allow" grant. Requires an interactive TTY in
  release builds, so an agent's non-interactive shell can't trigger a destructive
  re-key. (M3)

---

## 7. Defense layers

envault stacks *guidance* (cooperative) and *control* (enforced):

1. **The skill — guidance.** Teaches any agent the names-only workflow. A
   cooperative agent follows it; an injected one may not. Guidance only, never
   relied on for enforcement.
2. **The guard — control.** `envault guard-check` (invoked by the Claude Code
   PreToolUse hook; logic lives in the binary) blocks agent tool-calls that read
   `~/.envault/` or run the human-only surfaces (bare TUI, `rotate`,
   `request-window`, `audit`, `config set`). Enforced on Claude Code.
3. **In-binary human-only enforcement.** `rotate` requires a TTY; `config set`
   and `audit` viewing are biometric-gated; the request window is never
   inline-rendered in release. These hold **even with no hook** — the basis for
   cross-harness safety (§9).
4. **The OS keychain.** The private key never leaves it; using it triggers OS
   authorization.
5. **Biometric gate — optional.** Touch ID / Windows Hello before every
   decryption when enabled. (Linux has no biometric backend; it fails closed.)
6. **The audit log — optional.** HMAC-SHA256 hash-chain keyed by the identity
   (unforgeable without the keychain), with a MAC'd head-anchor so truncation or
   deletion of the tail is *detectable*; size-bounded; fail-closed while enabled.
7. **Settings integrity.** `audit-log` / `touch-id` / `fill` are **fail-closed**
   on corruption and **keychain-authoritative in release**, so editing
   `config.json` cannot silently disable a protection. Changing a setting is
   itself gated.

---

## 8. The safety boundary — what envault does NOT protect against

This is the important part. envault raises the cost of leaking a secret. It is
**not a sandbox.**

**Protected:**

- A secret reaching the model's context / prompt — agents only ever get names +
  ciphers.
- A secret written to a file, a log, or pasted into chat — no plaintext-emitting
  command exists, and `run` masks output.
- An agent silently disabling auditing / Touch ID by editing a file —
  keychain-authoritative, fail-closed, gated.
- An agent tampering with the recipient to re-seal secrets to its own key — the
  recipient is derived from the identity.
- Casual / accidental exfiltration, and a non-interactive agent triggering a
  destructive re-key.

**NOT protected — by design or inherent:**

- **A malicious process running as you, at runtime.** Anything that can run
  `envault run -- …` as your user can obtain the plaintext exactly the way your
  real program does, then do anything with it — including send it over the
  network. No local secrets manager (1Password included) can stop code running as
  you from *using* a secret you have authorized. envault does not sandbox the
  child's network.
- **Deliberate runtime network exfiltration** from inside an `envault run` child
  is explicitly out of scope.
- **A fully compromised machine** can delete or stop the audit log going forward.
  The hash-chain makes *past* tampering evident, not impossible — the same
  limitation every local tool has, 1Password included.
- **No per-use approval prompt.** A deliberate choice for smoothness: protection
  is masking + no-plaintext commands + hooks/keychain, not an allow/deny dialog
  on every access. Turn on Touch ID if you want a per-use gate.

Put plainly: **envault stops a secret from leaking into the agent's brain or your
files. It does not stop a program you have authorized to use a secret from
misusing it at runtime.** That is the boundary.

---

## 9. Cross-harness reach (v0.7.0)

The names-only workflow ships as one **Agent Skill** (`SKILL.md`), lazy-loaded —
its body loads only when a task actually needs a secret. `envault skill install`
writes it to `~/.claude/skills/` (Claude Code) and `~/.agents/skills/` (Codex,
opencode); `envault skill print` emits it for anything else (or an `AGENTS.md`).

The **guard hook is Claude-Code-specific.** On other harnesses you get the skill
(guidance) plus the in-binary controls (§7.3) — but not the PreToolUse block. The
plaintext-never-seen guarantee lives in the binary, so it holds on every harness.

---

## 10. Known gaps / deferred (internal)

- **M2** — rotation is not fully crash-safe: a crash mid-re-key leaves a small
  window that needs a multi-recipient / two-slot bridge to close. (deferred)
- **Guard path-canonicalization** — the hook's path match is best-effort; the
  real enforcement is the in-binary checks.
- **L3 / L4** — session-directory randomness; non-Unix file ACLs.
- **Release-only paths untested from the dev box** — keychain-authoritative
  settings and the Touch ID prompt are compile-verified only; verify on real
  hardware that they actually gate.
