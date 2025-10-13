use std::io::Error;
use std::ptr::null_mut;

use obfstr::obfstr;
use log::trace;

use windows_sys::{
    Win32::{
        Foundation::{HANDLE, CloseHandle},
        Security::{
            SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES,
            LookupPrivilegeValueW,
            AdjustTokenPrivileges,
        }
    },
};


use windows_sys::Win32::System::{
    SystemServices::SE_IMPERSONATE_NAME,
    SystemServices::SE_DEBUG_NAME,
    Threading::{OpenProcessToken, GetCurrentProcess},
};


/// Function to enable Windows Privilege SeDebugPrivilege
pub fn enabling_sedebug() -> Result<bool, String> {
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

        trace!("[?] SeDebugPrivilege privilege enabled");
        return Ok(true);
    }
}

/// Function to enable Windows Privilege SeAssignPrimaryToken
pub fn enabling_seimpersonate() -> Result<bool, String>{
    unsafe {
        // Enable SeImpersonatePrivilege
        trace!("[?] Trying to enable SeImpersonatePrivilege privilege");

        let mut token_handle:HANDLE = std::mem::zeroed();
        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();
        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle) == 0 {
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        }

        if LookupPrivilegeValueW(null_mut(), SE_IMPERSONATE_NAME, &mut privilege.Privileges[0].Luid) == 0 {
            return Err(format!("{} Error: {}",obfstr!("LookupPrivilegeValueW"), Error::last_os_error()).to_owned());
        }

        if AdjustTokenPrivileges(token_handle as HANDLE, 0, &mut privilege, std::mem::size_of_val(&privilege) as u32, null_mut(), null_mut()) == 0 {
            return Err(format!("{} Error: {}",obfstr!("AdjustTokenPrivileges"), Error::last_os_error()).to_owned());
        }

        if CloseHandle(token_handle as HANDLE) == 0 {
            return Err(format!("{} Error: {}",obfstr!("CloseHandle"), Error::last_os_error()).to_owned());
        }

        trace!("[?] SeImpersonatePrivilege enabled");

        return Ok(true);
    }
}