use clap::{Parser, Subcommand};

mod access;
mod audit;
mod biometric;
mod cdp;
mod commands;
mod crypto;
mod manifest;
mod masker;
mod paths;
mod platform;
mod settings;
mod store;
mod tui;

#[derive(Parser)]
#[command(
    name = "envault",
    version,
    about = "Local secrets vault: agents see aliases and ciphers, never plaintext"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Change a setting: `envault config set audit-log on`
    Set { key: String, value: String },
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the vault and generate the keypair
    Init,
    /// Add a secret (value via hidden prompt, or --stdin)
    Add {
        alias: String,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Read the value from stdin (for piping); otherwise prompts on the TTY
        #[arg(long)]
        stdin: bool,
    },
    /// List secret names (never values)
    Ls {
        #[arg(long)]
        json: bool,
    },
    /// View the audit log of secret accesses (human-only; system-prompt gated)
    Audit {
        #[arg(long)]
        json: bool,
    },
    /// Show or change settings (audit-log, touch-id)
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// Map a project env var to a vault alias in envault.toml
    Link { env_var: String, alias: String },
    /// Type a secret into the browser page over CDP (value never shown)
    Fill {
        alias: String,
        /// CSS selector to focus first; omit to use the focused element
        #[arg(long)]
        selector: Option<String>,
        /// DevTools endpoint of the browser
        #[arg(long, default_value = "http://127.0.0.1:9222")]
        cdp: String,
    },
    /// Internal: PreToolUse hook helper (reads hook JSON on stdin)
    #[command(hide = true)]
    GuardCheck,
    /// Encrypt every entry of a dotenv file into the vault and link it
    Import { file: std::path::PathBuf },
    /// Ask the user (in a pop-up window) to add a secret you don't have yet
    Request {
        /// The name the secret will be stored under (agent-chosen)
        name: String,
        #[arg(long)]
        label: Option<String>,
        /// Why you need it — shown to the user so they can decide
        #[arg(long)]
        reason: Option<String>,
        /// Identify yourself, e.g. --agent "Claude Code"
        #[arg(long)]
        agent: Option<String>,
    },
    /// Internal: the human-facing request window (spawned in a new terminal)
    #[command(hide = true)]
    RequestWindow { session: std::path::PathBuf },
    /// Re-encrypt the vault to a brand-new keypair (revokes Keychain grants)
    Rotate,
    /// Run a command with secrets injected and masked out of its output
    Run {
        #[arg(long)]
        manifest: Option<std::path::PathBuf>,
        /// Extra VAR=alias mappings (repeatable)
        #[arg(long)]
        env: Vec<String>,
        #[arg(long)]
        allow_missing: bool,
        /// Everything after `--` is the command to run
        #[arg(last = true)]
        command: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.cmd {
        None => tui::run_tui(),
        Some(Cmd::Init) => commands::init::cmd_init(),
        Some(Cmd::Add {
            alias,
            label,
            url,
            notes,
            stdin,
        }) => commands::add::cmd_add(alias, label, url, notes, stdin),
        Some(Cmd::Ls { json }) => commands::ls::cmd_ls(json),
        Some(Cmd::Audit { json }) => commands::audit::cmd_audit(json),
        Some(Cmd::Config { action }) => match action {
            None => commands::config::cmd_config_show(),
            Some(ConfigAction::Set { key, value }) => commands::config::cmd_config_set(key, value),
        },
        Some(Cmd::Link { env_var, alias }) => commands::link::cmd_link(env_var, alias),
        Some(Cmd::Fill {
            alias,
            selector,
            cdp,
        }) => commands::fill::cmd_fill(alias, selector, cdp),
        Some(Cmd::GuardCheck) => match commands::guard::cmd_guard_check() {
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
        Some(Cmd::Import { file }) => commands::import::cmd_import(file),
        Some(Cmd::Request {
            name,
            label,
            reason,
            agent,
        }) => match commands::request::cmd_request(name, label, reason, agent) {
            Ok(code) => std::process::exit(code),
            Err(e) => Err(e),
        },
        Some(Cmd::RequestWindow { session }) => commands::request::cmd_request_window(session),
        Some(Cmd::Rotate) => commands::rotate::cmd_rotate(),
        Some(Cmd::Run {
            manifest,
            env,
            allow_missing,
            command,
        }) => {
            match commands::run::cmd_run(commands::run::RunArgs {
                manifest,
                env,
                allow_missing,
                command,
            }) {
                Ok(code) => std::process::exit(code),
                Err(e) => Err(e),
            }
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
