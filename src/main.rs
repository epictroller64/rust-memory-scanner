mod lib;
fn main() {
    let args = Args::parse();
    ProcessOperations::new().scan_process_memory(args.pid as u32, args.pattern);
}

use clap::{Parser, command};

use crate::lib::process_operations::ProcessOperations;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    pid: i32,

    #[arg(short, long)]
    pattern: String,
}
