//! Parsing arguments
use clap::{Arg, ArgAction, value_parser, Command};

#[derive(Debug)]
pub enum Mode {
    Exec,
    List,
    Unknown,
}

#[derive(Debug)]
pub struct Options {
    pub mode: Mode,
    pub pid: u32,
    pub cmd: String,
    pub verbose: log::LevelFilter,
}

fn cli() -> Command {
    Command::new("irs")
        .about("IRS (Impersonate-RS) It's a windows token impersonation tool written in Rust. zblurx <https://twitter.com/_zblurx>")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .subcommand(Command::new("list")
                .about("List all process PID available to impersonate Tokens")
                .arg(Arg::new("v")
                    .short('v')
                    .help("Set the level of verbosity")
                    .action(ArgAction::Count),
                )
        )
        .subcommand(
            Command::new("exec")
                .about("Execute command line from impersonate PID")
                .arg(Arg::new("pid")
                    .short('p')
                    .long("pid")
                    .help("PID to impersonate")
                    .required(true)
                    .value_parser(value_parser!(u32))
                )
                .arg(Arg::new("command")
                    .short('c')
                    .long("command")
                    .help("Command to execute")
                    .required(true)
                    .value_parser(value_parser!(String))
                )
                .arg(Arg::new("v")
                    .short('v')
                    .help("Set the level of verbosity")
                    .action(ArgAction::Count),
                )
        )
}

/// Function to extract arguments
pub fn extract_args() -> Options {
    
    let matches = cli().get_matches();
    let mut mode = Mode::Unknown;
    let mut pid: u32 = 00000;
    let mut cmd = "no set";
    let mut v =  log::LevelFilter::Info;

    match matches.subcommand() {
        Some(("list", sub_matches)) => {
            mode = Mode::List;
            v = match sub_matches.get_count("v") {
                0 => log::LevelFilter::Info,
                1 => log::LevelFilter::Debug,
                _ => log::LevelFilter::Trace,
            };
        }
        Some(("exec", sub_matches)) => {
            mode = Mode::Exec;
            pid = sub_matches.get_one::<u32>("pid").map(|s| s.to_owned()).unwrap();
            cmd = sub_matches.get_one::<String>("command").map(|s| s.as_str()).unwrap();
            v = match sub_matches.get_count("v") {
                0 => log::LevelFilter::Info,
                1 => log::LevelFilter::Debug,
                _ => log::LevelFilter::Trace,
            };
        }
        _ => {},
    }

    Options {
        mode: mode,
        pid: pid,
        cmd: cmd.to_string(),
        verbose: v,
    }
}