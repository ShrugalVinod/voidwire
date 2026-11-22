//! `voidwire` — VoidWire command-line client.

fn main() {
    std::process::exit(vw_cli::main_entry(std::env::args_os()));
}
