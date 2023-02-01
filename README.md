# IRS (Impersonate-RS)

> 💡 IRS is a library version of [https://github.com/zblurx/impersonate-rs](https://github.com/zblurx/impersonate-rs)

Reimplementation of [Defte](https://twitter.com/Defte_) [Impersonate](https://github.com/sensepost/impersonate) in plain Rust. For more informations about it, see this [blogpost](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/).

## Disclaimer

I did this in order to learn Rust, so please don't blame my shitty code.

## Build

```bash
# Build it from docker
git clone https://github.com/zblurx/impersonate-rs
cd impersonate-rs
make

# or from cargo in your host
make windows

# build documentation
cargo doc --open --no-deps
```

## Usage

Like a static binary :

```bash
.\impersonate-rs.exe --help
Rusty Impersonate

Usage: impersonate-rs.exe [OPTIONS] <MODE>

Arguments: <MODE>  list or exec

Options:
      --pid <PID>          pid to impersonate
      --command <COMMAND>  command to execute
      -h, --help               Print help
      -V, --version            Print version 
```

### `list`

The `list` command list processes, with their session id, token type and associated user.
```bash
X:\>.\impersonate-rs.exe list
                  
[winlogon.exe]  [PROCESS: 508][SESSION: 1][TYPE: Primary][System] User: NT AUTHORITY\SYSTEM
[lsass.exe]     [PROCESS: 580][SESSION: 0][TYPE: Primary][System] User: NT AUTHORITY\SYSTEM
[svchost.exe]   [PROCESS: 676][SESSION: 0][TYPE: Primary][System] User: NT AUTHORITY\SYSTEM
[fontdrvhost.exe]       [PROCESS: 700][SESSION: 0][TYPE: Primary][Low] User: Font Driver Host\UMFD-0
[fontdrvhost.exe]       [PROCESS: 708][SESSION: 1][TYPE: Primary][Low] User: Font Driver Host\UMFD-1
[svchost.exe]   [PROCESS: 776][SESSION: 0][TYPE: Primary][System] User: NT AUTHORITY\NETWORK SERVICE
[dwm.exe]       [PROCESS: 860][SESSION: 1][TYPE: Primary][System] User: Window Manager\DWM-1
[svchost.exe]   [PROCESS: 940][SESSION: 0][TYPE: Primary][System] User: NT AUTHORITY\NETWORK SERVICE 
(...)
[cmd.exe]       [PROCESS: 1632][SESSION: 1][TYPE: Primary][High] User: ADCS1\Administrator
[conhost.exe]   [PROCESS: 4260][SESSION: 1][TYPE: Primary][High] User: ADCS1\Administrator
[impersonate-rs.exe]    [PROCESS: 3012][SESSION: 1][TYPE: Primary][High] User: ADCS1\Administrator 
```

### `exec`

The `exec` command open the target process id in the `pid` argument, duplicate its token and execute a command with the new token.

```cmd
X:\>whoami
adcs1\administrator

X:\>.\impersonate-rs.exe exec --pid 5540 --command "whoami"
16 bytes read:
waza\e.cartman 
```

### `library`

Or directly on your **Rust** project like:

```Cargo.toml```:

```bash
[dependencies]
irs = { path = "/data/02-GIT/github/impersonate-rs/", version = "0.2.0" }
```

Or

```bash
[dependencies]
irs = { git = "https://github.com/g0h4n/impersonate-rs", version = "0.2.0" }
```

```main.rs```:

```rust
use irs::utils::*;

fn main() {
    token::enum_token().expect("[!] Failed to enumerate tokens");
}
```

To see all the available functions use the following command to open the **Rust documentation**.

```bash
cargo doc --open --no-deps
```