# IRS (Impersonate-RS)

> 💡 IRS is a library version of [https://github.com/zblurx/impersonate-rs](https://github.com/zblurx/impersonate-rs), [zblurx](https://twitter.com/_zblurx)

Reimplementation of [Defte](https://twitter.com/Defte_) [Impersonate](https://github.com/sensepost/impersonate) in plain Rust. For more informations about it, see this [blogpost](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/).

## Summary

- [Build](#build)
- [Usage](#usage)
    - [List process to impersonate](#list)
    - [Exec command](#exec)
    - [Library example](#library)
- [Demo](#demo)

## Build

```bash
# Build it from docker
git clone https://github.com/zblurx/impersonate-rs
cd impersonate-rs
make release

# Or from cargo in your host
make windows

# Build documentation
cargo doc --open --no-deps

# More information
make help
```

## Usage

Like a static binary :

```cmd
X:\>irs.exe --help
IRS (Impersonate-RS) It's a windows token impersonation tool written in Rust. zblurx <https://twitter.com/_zblurx>

Usage: irs.exe <COMMAND>

Commands:
  list  List all process PID available to impersonate Tokens
  exec  Execute command line from impersonate PID
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

```bash
X:\>irs.exe exec --help
Execute command line from impersonate PID

Usage: irs.exe exec [OPTIONS] --pid <pid> --command <command>

Options:
  -p, --pid <pid>          PID to impersonate
  -c, --command <command>  Command to execute
  -v...                    Set the level of verbosity
  -h, --help               Print help
```

### `list`

The `list` command list processes, with their session id, token type and associated user.
```bash
X:\>irs.exe list
                  
[winlogon.exe                    ] [PROCESS: 624  ] [SESSION: 1 ] [TYPE: Primary] [System] [USER: AUTORITE NT\Système         ]
[lsass.exe                       ] [PROCESS: 672  ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\Système         ]
[svchost.exe                     ] [PROCESS: 780  ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\Système         ]
[fontdrvhost.exe                 ] [PROCESS: 788  ] [SESSION: 0 ] [TYPE: Primary] [Low   ] [USER: Font Driver Host\UMFD-0     ]
[fontdrvhost.exe                 ] [PROCESS: 796  ] [SESSION: 1 ] [TYPE: Primary] [Low   ] [USER: Font Driver Host\UMFD-1     ]
[svchost.exe                     ] [PROCESS: 888  ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\SERVICE RÉSEAU  ]
[svchost.exe                     ] [PROCESS: 948  ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\Système         ]
[dwm.exe                         ] [PROCESS: 412  ] [SESSION: 1 ] [TYPE: Primary] [System] [USER: Window Manager\DWM-1        ]
[svchost.exe                     ] [PROCESS: 460  ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\Système         ]
[svchost.exe                     ] [PROCESS: 696  ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\SERVICE LOCAL   ]
(...)
[svchost.exe                     ] [PROCESS: 836  ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\SERVICE LOCAL   ]
[svchost.exe                     ] [PROCESS: 908  ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\SERVICE LOCAL   ]
[svchost.exe                     ] [PROCESS: 1060 ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\SERVICE LOCAL   ]
[svchost.exe                     ] [PROCESS: 1088 ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\SERVICE LOCAL   ]
[svchost.exe                     ] [PROCESS: 1124 ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\Système         ]
[svchost.exe                     ] [PROCESS: 1176 ] [SESSION: 0 ] [TYPE: Primary] [System] [USER: AUTORITE NT\Système         ]
```

### `exec`

The `exec` command open the target process id in the `pid` argument, duplicate its token and execute a command with the new token.

```cmd
X:\>whoami
adcs1\administrator

X:\>irs.exe exec --pid 5540 --command whoami
waza\e.cartman

X:\>irs.exe exec -p 5540 -c whoami
waza\e.cartman 
```

### `library`

Or directly on your **Rust** project like:

```Cargo.toml```:

```bash
[dependencies]
irs = { path = "/data/02-GIT/github/impersonate-rs/", version = "0.2.1" }
```

Or with github repo:

```bash
[dependencies]
irs = { git = "https://github.com/g0h4n/impersonate-rs", version = "0.2.1" }
```

```main.rs```:

```rust
use irs::utils::*;

fn main() {
    impersonate::se_priv_enable().expect("[!] Failed to run se_priv_enable()");
    token::enum_token().expect("[!] Failed to run enum_token()");
}
```

To see all the available functions use the following command to open the **Rust documentation**.

```bash
cargo doc --open --no-deps
```

## Demo

![](./img/demo.gif)

## Contributors

Many thanks to [g0h4n](https://twitter.com/g0h4n_0) for his contribution to the repo (made it a library, added color, clean up the code, ect.)