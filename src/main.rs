use clap::Parser;

mod crypto;
mod paths;
mod store;

#[derive(Parser)]
#[command(name = "envault", version, about = "Local secrets vault: agents see aliases and ciphers, never plaintext")]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    // Bare `envault` opens the TUI in Milestone 3; until then, --help/--version only.
    use clap::CommandFactory;
    Cli::command().print_help().ok();
}
