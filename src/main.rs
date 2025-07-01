mod lib;
use clap::{Parser, command};

use crate::lib::process_operations::ProcessOperations;
fn main() {
    let mut shell_state = ShellState::new();
    loop {
        print!("scanner> ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input: Vec<&str> = input.trim().split(' ').collect();
        match input.first() {
            Some(&"ss") => {
                // Set the search string to the rest of the input (joined by space)
                let search_str = input[1..].join(" ");
                shell_state.set_search_string(search_str);
            }
            Some(&"rescan") => {
                // use state.last_scan_addresses to scan again
            }
            Some(&"scan") => {
                //Scan after setting required parameters
                match shell_state.process_id {
                    Some(p_id) => {
                        let scan_results = shell_state
                            .process_operations
                            .parallel_scan_process_memory(p_id, shell_state.last_pattern.as_str());
                        match scan_results {
                            Ok(results) => shell_state.set_process_results(results),
                            Err(e) => println!("Scan failed: {}", e),
                        }
                    }
                    None => println!("Process id is not set"),
                }
            }
            Some(&"pid") => {
                let pid = input[1];
                let pid_conv = pid.parse::<u32>();
                match pid_conv {
                    Ok(pid) => shell_state.set_pid(pid),
                    Err(e) => println!("Invalid Process ID: {}", e.to_string()),
                }
            }
            Some(&"exit") => break,
            _ => println!("{:?}", input),
        }
    }
}

pub struct ShellState {
    pub last_scan_results: Vec<usize>,
    pub last_pattern: String,
    pub process_id: Option<u32>,
    pub process_operations: ProcessOperations,
}

impl ShellState {
    pub fn new() -> Self {
        Self {
            process_operations: ProcessOperations::new(),
            process_id: None,
            last_scan_results: Vec::new(),
            last_pattern: String::new(),
        }
    }
    pub fn set_search_string(&mut self, str: String) {
        self.last_pattern = str;
    }

    pub fn set_pid(&mut self, pid: u32) {
        self.process_id = Some(pid);
    }

    pub fn set_process_results(&mut self, results: Vec<usize>) {
        self.last_scan_results = results;
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    pid: i32,

    #[arg(short, long)]
    pattern: String,
}
