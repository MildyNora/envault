use clap::{Parser, Subcommand};

mod commands;
mod crypto;
mod manifest;
mod masker;
mod paths;
mod store;

#[derive(Parser)]
#[command(name = "envault", version, about = "Local secrets vault: agents see aliases and ciphers, never plaintext")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
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
    /// Map a project env var to a vault alias in envault.toml
    Link { env_var: String, alias: String },
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
        None => {
            // Bare `envault` opens the TUI in Milestone 3; until then, show help.
            use clap::CommandFactory;
            Cli::command().print_help().ok();
            Ok(())
        }
        Some(Cmd::Init) => commands::init::cmd_init(),
        Some(Cmd::Add { alias, label, url, notes, stdin }) => {
            commands::add::cmd_add(alias, label, url, notes, stdin)
        }
        Some(Cmd::Ls { json }) => commands::ls::cmd_ls(json),
        Some(Cmd::Link { env_var, alias }) => commands::link::cmd_link(env_var, alias),
        Some(Cmd::Run { manifest, env, allow_missing, command }) => {
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
