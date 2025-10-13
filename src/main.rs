pub mod args;
pub mod utils;

pub mod impersonate;
pub mod token;

use args::*;
use impersonate::*;
use token::*;

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
            // Enabling SeDebug privilege for analyze current process
            //enabling_sedebug().expect("[!] Failed to run se_priv_enable()");
            let res = enabling_sedebug();
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run enabling_sedebug(): {err}"),
            }
            //enum_token().expect("[!] [!] Failed to run enum_token()");
            let res = enum_token();
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run enum_token(): {err}"),
            }
        }
        Mode::Exec => {
            // Enabling SeImpersonate privilege
            //enabling_seimpersonate().expect("[!] Failed to run enabling_seimpersonate()");
            let res = enabling_seimpersonate();
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run enabling_seimpersonate(): {err}"),
            }
            //run_command(common_args.pid, common_args.cmd).expect("[!] Failed to run run_command()");
            let res = run_command(common_args.pid, common_args.cmd);
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run impersonate::exec::run_command(): {err}"),
            }
        }
        Mode::Spawn => {
            // Enabling SeImpersonate privilege
            //enabling_seimpersonate().expect("[!] Failed to run enabling_seimpersonate()");
            let res = enabling_seimpersonate();
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run enabling_seimpersonate(): {err}"),
            }
            //spawn_process(common_args.pid, common_args.cmd).expect("[!] Failed to run spawn_process()");
            let res = spawn_process(common_args.pid, common_args.cmd);
            match res {
                Ok(_s) => { () },
                Err(err) => error!("[!] Failed to run impersonate::exec::spawn_process(): {err}"),
            }
        }
        _ => {
            // Unknown Mode
            error!("[!] Unknown mode, please check usage --help");
        }
    };
}