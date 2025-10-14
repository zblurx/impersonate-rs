use std::slice;
use std::error::Error;

use windows_sys::{
    Win32::System::SystemServices::SECURITY_MANDATORY_MEDIUM_PLUS_RID,
    core::PWSTR
};
pub const FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID: i32 = SECURITY_MANDATORY_MEDIUM_PLUS_RID as i32;

pub fn pwstr_to_string(buffer: PWSTR) -> String{
    let transate  = unsafe {slice::from_raw_parts(buffer, 256)};
    return array_to_string_utf16( transate);
}

pub fn array_to_string_utf16(buffer: &[u16]) -> String {
    let mut string: Vec<u16> = Vec::new();
    for char in buffer.to_vec() {
        if char == 0 {
            break;
        }
        string.push(char);
    }
    String::from_utf16(&string).unwrap()
}

pub fn array_to_string(buffer: [u8; 260]) -> String {
    let mut string: Vec<u8> = Vec::new();
    for char in buffer.to_vec() {
        if char == 0 {
            break;
        }
        string.push(char);
    }
    String::from_utf8(string).unwrap()
}

/// Usefull to get PID only by process name
pub fn _find_pid_by_name(name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    use std::{io, mem::size_of};
    use windows::{ Win32::Foundation::*, Win32::System::SystemServices::*, };
    use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };

    unsafe {
        // Create snapshot (map windows::core::Error -> Box<dyn Error>)
        let snapshot: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| Box::new(e) as Box<dyn Error>)?;

        if snapshot == INVALID_HANDLE_VALUE {
            return Err(Box::new(io::Error::last_os_error()));
        }

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

        // Process32FirstW returns Result<(), windows::core::Error>
        if let Err(e) = Process32FirstW(snapshot, &mut entry) {
            CloseHandle(snapshot);
            return Err(Box::new(e) as Box<dyn Error>);
        }

        loop {
            // Convert wide char buffer to Rust String
            let slice = &entry.szExeFile;
            let len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
            let exe = String::from_utf16_lossy(&slice[..len]);

            if exe.eq_ignore_ascii_case(name) {
                let pid = entry.th32ProcessID;
                CloseHandle(snapshot);        
                println!("[*] Found PID: {:?}",pid);
                return Ok(pid);
            }

            // If Process32NextW returns Err, stop the loop (no more entries or error)
            if let Err(_) = Process32NextW(snapshot, &mut entry) {
                break;
            }
        }

        CloseHandle(snapshot);
        println!("[!] PID not foudn for: {:?}", name);

        Err(Box::new(io::Error::new(
            io::ErrorKind::NotFound,
            format!("No process named '{}'", name),
        )))
    }
}