use std::fs;
use std::error;
use std::i64;
use nix::sys::ptrace;
use nix::sys::signal;
use regex::Regex;
use object::Object;
use nix::unistd::Pid;

fn get_symbol_offset(object_path: &str, symbol: &str) -> Result<u64, Box<dyn error::Error>> {
    let bin_data = fs::read(object_path)?;

    let obj_file = object::File::parse(&*bin_data)?;

    for object_symbol in obj_file.dynamic_symbols() {
        if Some(symbol) == (object_symbol.1.name()) {
            return Ok(object_symbol.1.address());
        }
    }

    Err("libc dlopen not found")?
}

fn get_process_libc(pid: Pid) -> Result<(u64, String), Box<dyn error::Error>> {
    let process_maps = fs::read_to_string(format!("/proc/{}/maps", pid))?;

    let libc_line_regex = Regex::new(r"(?m)^([0-9a-fA-F]+)-.* (/.*\blibc\b.*so)$")?;
    for cap in libc_line_regex.captures_iter(&process_maps) {
        let address = i64::from_str_radix(&cap[1], 16)? as u64;

        return Ok((address, cap[2].to_string()));
    }

    Err("libc wasn't found")?
}


fn main() -> Result<(), Box<dyn error::Error>> {
    let pid = Pid::from_raw(1704);

    let (libc_address, libc_path) = get_process_libc(pid)?;

    let dlopen_offset = get_symbol_offset(&libc_path, "__libc_dlopen_mode")?;

    ptrace::attach(pid).expect("failed to attach process");

    signal::kill(pid, signal::SIGSTOP).expect("failed to stop process");

    Ok(())
}