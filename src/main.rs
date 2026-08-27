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
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
