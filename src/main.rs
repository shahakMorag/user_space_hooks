mod memory;
#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "mips",
            any(target_env = "gnu", target_env = "musl")))
))]
mod mips_dlopen;
#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "x86_64",
            any(target_env = "gnu", target_env = "musl")))
))]
mod x86_64_dlopen;

use std::os::raw::c_ulong;
use std::{ fs, error, i64 };

use regex::Regex;

use object::Object;

use nix::unistd::Pid;
use nix::sys::{ ptrace, signal };

use clap::Parser;

#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "x86_64",
            any(target_env = "gnu", target_env = "musl")))
))]
use crate::x86_64_dlopen::remote_run_dlopen;
#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "mips",
            any(target_env = "gnu", target_env = "musl")))
))]
use crate::mips_dlopen::remote_run_dlopen;

fn get_symbol_offset(object_path: &str, symbol: &str) -> Result<c_ulong, Box<dyn error::Error>> {
    let bin_data = fs::read(object_path)?;

    let obj_file = object::File::parse(&*bin_data)?;

    for object_symbol in obj_file.dynamic_symbols() {
        if Some(symbol) == (object_symbol.1.name()) {
            return Ok(object_symbol.1.address().try_into().unwrap());
        }
    }

    Err("libc dlopen not found")?
}

fn get_process_libc(pid: Pid) -> Result<(c_ulong, String), Box<dyn error::Error>> {
    let process_maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;

    let libc_line_regex = Regex::new(r"(?m)^([0-9a-fA-F]+)-.* (/.*\blibc\b.*so)$")?;
    for cap in libc_line_regex.captures_iter(&process_maps) {
        let address = i64::from_str_radix(&cap[1], 16)? as c_ulong;

        return Ok((address, cap[2].to_string()));
    }

    Err("libc wasn't found")?
}

// assume process is stopped for now
fn remote_load_library(pid: Pid, lib_path: String) -> Result<(), Box<dyn error::Error>> {
    let (libc_address, libc_path) = get_process_libc(pid)?;

    let dlopen_offset = get_symbol_offset(&libc_path, "__libc_dlopen_mode")?;
    let dlopen_address = libc_address + dlopen_offset;

    let executeable_address = libc_address + get_symbol_offset(&libc_path, "qsort_r")?;

    remote_run_dlopen(pid, lib_path, executeable_address, dlopen_address)
}

#[derive(Parser)]
struct Arguments {
    #[clap(short)]
    pid: i32,
    #[clap(short)]
    lib_path: String,
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let args: Arguments = Arguments::parse();

    let pid = Pid::from_raw(args.pid);

    ptrace::attach(pid).expect("failed to attach process");

    remote_load_library(pid, args.lib_path)?;

    ptrace::detach(pid, None).expect("failed to detach process");

    signal::kill(pid, signal::SIGCONT)?;

    Ok(())
}