mod lib;
use clap::{Parser, command};

use crate::lib::{process_operations::ProcessOperations, utils::str_to_bytes};
fn main() {
    let mut shell_state = ShellState::new();
    loop {
        print!("scanner> ");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input: Vec<&str> = input.trim().split(' ').collect();
        match input.first() {
            Some(&"set") => {
                // Set the search string to the rest of the input (joined by space)
                let mode_str = input[1];
                let val = input[2];
                let pattern_bytes = match mode_str {
                    "string" => {
                        let search_str = input[2..].join(" ");
                        let pattern_bytes = str_to_bytes(&search_str);
                        match pattern_bytes {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                println!("Failed to convert pattern to bytes: {}", e);
                                continue;
                            }
                        }
                    }
                    "i32" => match val.parse::<i32>() {
                        Ok(v) => v.to_le_bytes().to_vec(),
                        Err(_) => {
                            println!("Invalid i32 value");
                            continue;
                        }
                    },
                    "f32" => match val.parse::<f32>() {
                        Ok(v) => v.to_le_bytes().to_vec(),
                        Err(_) => {
                            println!("Invalid f32 value");
                            continue;
                        }
                    },
                    "i64" => match val.parse::<i64>() {
                        Ok(v) => v.to_le_bytes().to_vec(),
                        Err(_) => {
                            println!("Invalid i64 value");
                            continue;
                        }
                    },
                    "f64" => match val.parse::<f64>() {
                        Ok(v) => v.to_le_bytes().to_vec(),
                        Err(_) => {
                            println!("Invalid f64 value");
                            continue;
                        }
                    },
                    _ => {
                        println!("Unknown type: {}", mode_str);
                        continue;
                    }
                };
                shell_state.set_pattern_bytes(pattern_bytes);
            }
            Some(&"rescan") => match shell_state.process_id {
                Some(p_id) => {
                    println!(
                        "Rescan with {} previous addresses",
                        shell_state.last_scan_results.len()
                    );
                    let rescan_results = shell_state.process_operations.scan_memory_addresses(
                        &shell_state.last_scan_results,
                        p_id,
                        &shell_state.last_pattern_bytes,
                    );
                    match rescan_results {
                        Ok(results) => {
                            println!("Found {} matches", results.len());
                            shell_state.set_process_results(results)
                        }
                        Err(e) => println!("Rescan failed: {}", e),
                    }
                }
                None => println!("Process id is not set"),
            },
            Some(&"scan") => {
                //Scan after setting required parameters
                match shell_state.process_id {
                    Some(p_id) => {
                        let scan_results = shell_state
                            .process_operations
                            .parallel_scan_process_memory(p_id, &shell_state.last_pattern_bytes);
                        match scan_results {
                            Ok(results) => {
                                println!("Found {} matches", results.len());
                                shell_state.set_process_results(results)
                            }
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
            Some(&"write") => {
                if input.len() < 4 {
                    println!("Usage: write <type> <address> <value>");
                    continue;
                }
                let mode_str = input[1];
                let address_str = input[2];
                let value_str = input[3..].join(" ");
                let address = if address_str.starts_with("0x") || address_str.starts_with("0X") {
                    usize::from_str_radix(
                        address_str
                            .trim_start_matches("0x")
                            .trim_start_matches("0X"),
                        16,
                    )
                } else {
                    address_str.parse::<usize>()
                };
                let address = match address {
                    Ok(addr) => addr,
                    Err(_) => {
                        println!("Invalid address: {}", address_str);
                        continue;
                    }
                };
                let bytes = match mode_str {
                    "string" => match str_to_bytes(&value_str) {
                        Ok(b) => b,
                        Err(e) => {
                            println!("Failed to convert string: {}", e);
                            continue;
                        }
                    },
                    "i32" => match value_str.parse::<i32>() {
                        Ok(v) => v.to_le_bytes().to_vec(),
                        Err(_) => {
                            println!("Invalid i32 value");
                            continue;
                        }
                    },
                    "f32" => match value_str.parse::<f32>() {
                        Ok(v) => v.to_le_bytes().to_vec(),
                        Err(_) => {
                            println!("Invalid f32 value");
                            continue;
                        }
                    },
                    "i64" => match value_str.parse::<i64>() {
                        Ok(v) => v.to_le_bytes().to_vec(),
                        Err(_) => {
                            println!("Invalid i64 value");
                            continue;
                        }
                    },
                    "f64" => match value_str.parse::<f64>() {
                        Ok(v) => v.to_le_bytes().to_vec(),
                        Err(_) => {
                            println!("Invalid f64 value");
                            continue;
                        }
                    },
                    _ => {
                        println!("Unknown type: {}", mode_str);
                        continue;
                    }
                };
                match shell_state.process_id {
                    Some(pid) => {
                        match shell_state
                            .process_operations
                            .write_value_to_address(pid, address, bytes)
                        {
                            Ok(_) => println!("Write successful to address 0x{:X}", address),
                            Err(e) => println!("Write failed: {}", e),
                        }
                    }
                    None => println!("Process id is not set"),
                }
            }
            _ => println!("{:?}", input),
        }
    }
}

pub struct ShellState {
    pub last_scan_results: Vec<usize>,
    pub last_pattern_bytes: Vec<u8>,
    pub process_id: Option<u32>,
    pub process_operations: ProcessOperations,
}

impl ShellState {
    pub fn new() -> Self {
        Self {
            process_operations: ProcessOperations::new(),
            process_id: None,
            last_scan_results: Vec::new(),
            last_pattern_bytes: Vec::new(),
        }
    }

    pub fn set_pattern_bytes(&mut self, bytes: Vec<u8>) {
        self.last_pattern_bytes = bytes;
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
