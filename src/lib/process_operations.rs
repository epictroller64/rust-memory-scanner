use rayon::prelude::*;
use std::num::ParseIntError;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_READONLY, PAGE_READWRITE},
        ProcessStatus::{EnumProcessModules, GetModuleFileNameExA},
        Threading::{
            OpenProcess, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
    },
};

use crate::lib::{memory::MemoryRegion, raw_ptr::ProcessHandle, utils::str_to_bytes};
pub struct ProcessOperations {
    pub last_scan_results: Vec<u8>,
}

impl ProcessOperations {
    pub fn new() -> Self {
        Self {
            last_scan_results: Vec::new(),
        }
    }

    pub fn write_value_to_address(
        &self,
        process_id: u32,
        address: usize,
        bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        unsafe {
            let process_handle = OpenProcess(
                PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                0,
                process_id,
            );
            if process_handle.is_null() {
                return Err(anyhow::anyhow!("Process not found or access denied"));
            }
            let mut bytes_written = 0;
            let mut write_bytes = bytes.clone();
            let write_result = WriteProcessMemory(
                process_handle,
                address as *mut _,
                write_bytes.as_mut_ptr() as _,
                bytes.len(),
                &mut bytes_written,
            );
            let last_error = if write_result == 0 { GetLastError() } else { 0 };
            CloseHandle(process_handle);
            if write_result == 0 {
                println!(
                    "[DEBUG] WriteProcessMemory failed, GetLastError: {}",
                    last_error
                );
                return Err(anyhow::anyhow!(
                    "WriteProcessMemory failed, GetLastError: {}",
                    last_error
                ));
            }
            if bytes_written != bytes.len() {
                println!(
                    "[DEBUG] Not all bytes written ({} of {}), GetLastError: {}",
                    bytes_written,
                    bytes.len(),
                    last_error
                );
                return Err(anyhow::anyhow!(
                    "Not all bytes written ({} of {}), GetLastError: {}",
                    bytes_written,
                    bytes.len(),
                    last_error
                ));
            }
            println!(
                "[DEBUG] WriteProcessMemory succeeded, bytes_written: {}",
                bytes_written
            );
            Ok(())
        }
    }

    fn open_process(&self, process_id: u32) -> anyhow::Result<HANDLE> {
        unsafe {
            let process_handle =
                OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, process_id);
            if process_handle.is_null() {
                return Err(anyhow::anyhow!("Process not found"));
            } else {
                Ok(process_handle)
            }
        }
    }

    pub fn scan_memory_addresses(
        &self,
        addresses: &[usize],
        process_id: u32,
        pattern_bytes: &Vec<u8>,
    ) -> anyhow::Result<Vec<usize>> {
        let mut matches = Vec::new();
        unsafe {
            let process_handle = self.open_process(process_id)?;
            let mut buffer = vec![0u8; pattern_bytes.len()];
            let mut bytes_read = 0;
            for &address in addresses {
                let read = ReadProcessMemory(
                    process_handle,
                    address as *const _,
                    buffer.as_mut_ptr() as _,
                    pattern_bytes.len(),
                    &mut bytes_read,
                );
                if read != 0 && &buffer[..bytes_read] == &pattern_bytes[..] {
                    matches.push(address);
                    println!("Match: {}", address);
                }
            }
            CloseHandle(process_handle);
        }
        Ok(matches)
    }

    pub fn parallel_scan_process_memory(
        &self,
        process_id: u32,
        pattern_bytes: &Vec<u8>,
    ) -> anyhow::Result<Vec<usize>> {
        // Use crayon to speed up scanning
        unsafe {
            let process_handle =
                OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, process_id);
            if process_handle.is_null() {
                println!("Did not find process");
                return Err(anyhow::anyhow!("Process not found"));
            }
            let memory_regions = self.scan_memory_regions(process_handle);
            print!("Mem regions count: {}", memory_regions.len());
            let handle = ProcessHandle(process_handle);
            let matches: Vec<usize> = memory_regions
                .par_iter()
                .filter(|region| region.is_readable && region.is_committed)
                .flat_map(|region| {
                    self.scan_memory_region(handle.clone().0, region, &pattern_bytes)
                        .unwrap_or_default()
                })
                .collect();
            CloseHandle(process_handle);
            Ok(matches)
        }
    }

    fn scan_memory_regions(&self, process_handle: HANDLE) -> Vec<MemoryRegion> {
        let mut memory_regions: Vec<MemoryRegion> = Vec::new();
        unsafe {
            let mut address = 0 as usize;
            let max_address = 0x7FFFFFFFFFFF; // User space max for 64-bit Windows

            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
            loop {
                let result = windows_sys::Win32::System::Memory::VirtualQueryEx(
                    process_handle,
                    address as *const _,
                    &mut mbi,
                    mbi_size,
                );

                if result == 0 {
                    let err = GetLastError();
                    println!(
                        "VirtualQueryEx failed at address {:X}, error {}",
                        address, err
                    );
                    break;
                }

                let is_readable =
                    mbi.Protect & PAGE_READONLY != 0 || mbi.Protect & PAGE_READWRITE != 0;
                let is_committed = mbi.State & MEM_COMMIT != 0;

                memory_regions.push(MemoryRegion {
                    base_address: mbi.BaseAddress as usize,
                    region_size: mbi.RegionSize,
                    is_readable,
                    is_committed,
                });

                if mbi.RegionSize == 0 {
                    println!(
                        "Region size is zero at address {:X}, breaking to avoid infinite loop",
                        address
                    );
                    break; // Prevent infinite loop
                }

                address = mbi.BaseAddress as usize + mbi.RegionSize;
                if address >= max_address {
                    println!("Reached max address {:X}, stopping scan", address);
                    break;
                }
            }
        }
        memory_regions
    }
    fn scan_memory_region(
        &self,
        process_handle: HANDLE,
        region: &MemoryRegion,
        pattern_bytes: &Vec<u8>,
    ) -> Result<Vec<usize>, ParseIntError> {
        let mut matches = Vec::new();
        let mut buffer = vec![0u8; 1024 * 1024]; //1MB
        let mut bytes_read = 0;
        let mut current_address = region.base_address;
        while current_address < region.base_address + region.region_size {
            let remaining_bytes = (region.base_address + region.region_size) - current_address;
            let to_read = std::cmp::min(buffer.len(), remaining_bytes);
            if to_read == 0 {
                break;
            }
            unsafe {
                let memory_read = ReadProcessMemory(
                    process_handle,
                    current_address as *const _,
                    buffer.as_mut_ptr() as _,
                    to_read,
                    &mut bytes_read,
                );
                if memory_read == 0 {
                    println!("Failed to read memory at {:X}", current_address);
                    current_address += to_read;
                    continue;
                }

                for i in 0..bytes_read.saturating_sub(pattern_bytes.len()) {
                    if &buffer[i..i + pattern_bytes.len()] == pattern_bytes {
                        let match_ = current_address + i;
                        matches.push(match_);
                        println!("Match: {}", match_);
                    }
                }
                current_address += to_read;
            }
        }
        Ok(matches)
    }

    pub fn scan_process_memory(&self, process_id: u32, pattern: String) {
        // Scan all memory for the process
        let pattern_bytes = str_to_bytes(pattern.as_str()).unwrap();
        unsafe {
            let process_handle =
                OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, process_id);
            if process_handle.is_null() {
                println!("Did not find process");
                return;
            }
            let memory_regions = self.scan_memory_regions(process_handle);
            print!("Mem regions count: {}", memory_regions.len());
            let mut matches = Vec::new();
            for region in memory_regions {
                if !region.is_readable || !region.is_committed {
                    println!(
                        "Skipping region {:X} because it is not readable or committed",
                        region.base_address
                    );
                    continue;
                }
                //println!(
                //"Base Address: {:X}, Region Size: {:X}",
                //region.base_address, region.region_size
                //);
                if let Ok(found) = self.scan_memory_region(process_handle, &region, &pattern_bytes)
                {
                    matches.extend(found);
                }
            }
            CloseHandle(process_handle);
        }
    }
}
