#![forbid(unsafe_code)]

fn main() {
    let output = fence::cli::execute_system(std::env::args_os());
    if output.stderr {
        eprintln!("{}", output.json);
    } else {
        println!("{}", output.json);
    }
    std::process::exit(output.exit_code);
}
