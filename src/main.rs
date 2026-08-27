use clap::{Parser, Subcommand};

mod commands;
mod crypto;
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
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
