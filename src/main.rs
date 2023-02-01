pub mod args;
pub mod utils;

use args::*;
use utils::*;

use env_logger::Builder;
use log::{info,debug,error};

fn main() {
    // Get args
    let common_args = extract_args();
    // Build logger
    Builder::new()
        .filter(Some("irs"), common_args.verbose)
        .filter_level(log::LevelFilter::Error)
        .init();

    match common_args.mode {
        Mode::List => {
            // List available Tokens
            let res = se_priv_enable();
            match res {
                Ok(_res) => info!("[+] Privileges enabled"),
                Err(err) => error!("[!] Failed to enable privileges: {err}"),
            }
            let res = enum_token();
            match res {
                Ok(res) => res,
                Err(err) => { error!("[!] Failed to enum tokens: {err}"); false },
            }
        }
        Mode::Exec => {
            // Get PID to impersonate Token and run command
            let res = se_priv_enable();
            match res {
                Ok(_res) => info!("[+] Privileges enabled"),
                Err(err) => error!("[!] Failed to enable privileges: {err}"),
            }
            let res = impersonate(common_args.pid, common_args.cmd);
            match res {
                Ok(res) => { debug!("[+] Process impersonate and command executed"); res },
                Err(err) => { error!("[!] Failed to impersonate process: {err}"); false },
            }
        }
        _ => {
            // Unknown Mode
            error!("[!] Unknown mode, please check usage --help"); false
        }
    };
}