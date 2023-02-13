pub mod args;
pub mod utils;

use args::*;
use utils::*;

use env_logger::Builder;
use log::error;

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
            //se_priv_enable().expect("[!] Failed to run se_priv_enable()");
            let res = se_priv_enable();
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run se_priv_enable(): {err}"),
            }
            //enum_token().expect("[!] [!] Failed to run enum_token()");
            let res = enum_token();
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run enum_token(): {err}"),
            }
        }
        Mode::Exec => {
            // Get PID to impersonate Token and run command
            //se_priv_enable().expect("[!] Failed to run se_priv_enable()");
            let res = se_priv_enable();
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run se_priv_enable(): {err}"),
            }
            //impersonate(common_args.pid, common_args.cmd).expect("[!] Failed to run impersonate()");
            let res = impersonate(common_args.pid, common_args.cmd);
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run impersonate(): {err}"),
            }
        }
        _ => {
            // Unknown Mode
            error!("[!] Unknown mode, please check usage --help");
        }
    };
}