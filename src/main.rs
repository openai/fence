#![forbid(unsafe_code)]

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use clap_mangen::Man;
use fence::{add, greet, subtract, version_info};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "fence", about = "Fence agent implementation scaffold", version)]
struct Cli {
    /// Who to greet.
    #[arg(short, long, default_value = "world")]
    name: String,

    /// Repeat the greeting N times.
    #[arg(short, long, default_value_t = 1)]
    times: u8,

    /// Uppercase the greeting.
    #[arg(short, long)]
    shout: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Add two numbers.
    Add { a: i32, b: i32 },
    /// Subtract b from a.
    Sub { a: i32, b: i32 },
    /// Print extended version metadata.
    Version,
    /// Emit shell completions to stdout.
    Completions { shell: CompletionShell },
    /// Emit a man page to stdout.
    Man,
}

#[derive(Clone, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

impl CompletionShell {
    fn as_shell(&self) -> Shell {
        match self {
            CompletionShell::Bash => Shell::Bash,
            CompletionShell::Zsh => Shell::Zsh,
            CompletionShell::Fish => Shell::Fish,
            CompletionShell::Powershell => Shell::PowerShell,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let mut stdout = io::stdout();

    match cli.command {
        Some(Commands::Add { a, b }) => println!("{}", add(a, b)),
        Some(Commands::Sub { a, b }) => println!("{}", subtract(a, b)),
        Some(Commands::Version) => println!("{}", version_info().render()),
        Some(Commands::Completions { shell }) => print_completions(shell, &mut stdout),
        Some(Commands::Man) => print_man(&mut stdout),
        None => println!("{}", greet(&cli.name, cli.shout, cli.times)),
    }
}

fn print_completions(shell: CompletionShell, stdout: &mut impl Write) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();

    generate(shell.as_shell(), &mut cmd, name, stdout);
}

fn print_man(stdout: &mut impl Write) {
    let cmd = Cli::command();
    let man = Man::new(cmd);
    man.render(stdout).expect("failed to render man page");
}
