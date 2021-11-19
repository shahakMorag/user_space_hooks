use std::ffi::c_void;
use std::fs;
use std::error;
use std::i64;
use std::mem::size_of;
use std::os::raw::c_long;
use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait;
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

fn read_process_memory(pid: Pid, address: u64, length: u64) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut words_from_memory = Vec::<c_long>::new();

    for i in (0..length).step_by(size_of::<c_long>()) {
        let offset = (i as u64) * (size_of::<c_long>() as u64);
        let current_address = address + offset;

        words_from_memory.push(ptrace::read(pid, current_address as *mut c_void)?);
    }

    Ok(words_from_memory.iter().flat_map(|x| -> [u8; size_of::<c_long>()] { x.to_ne_bytes() }).collect())
}

fn write_process_memory(pid: Pid, address: u64, new_memory: Vec<u8>) -> Result<usize, Box<dyn error::Error>> {
    let mut data = new_memory.clone();
    while data.len() % size_of::<c_long>() != 0 {
        data.push(b'\0');
    }

    let data: Vec<c_long> = data
        .chunks_exact(size_of::<c_long>())
        .map(|chunk| -> c_long {
            let chunk: [u8; size_of::<c_long>()] = chunk.try_into().unwrap();
            c_long::from_ne_bytes(chunk)
        }).collect();

    for (i, value) in data.iter().enumerate() {
        let offset = (i as u64) * (size_of::<c_long>() as u64);
        let current_address = address + offset;

        unsafe { ptrace::write(pid, current_address as *mut c_void, *value as *mut c_void) }?;
    }

    Ok(data.len())
}

// assume process is stopped for now
fn remote_load_library(pid: Pid, lib_path: String) -> Result<(), Box<dyn error::Error>> {
    let (libc_address, libc_path) = get_process_libc(pid)?;

    let dlopen_offset = get_symbol_offset(&libc_path, "__libc_dlopen_mode")?;
    let dlopen_address = libc_address + dlopen_offset;

    let executeable_address = libc_address + get_symbol_offset(&libc_path, "qsort_r")?;

    let process_orignal_regs = ptrace::getregs(pid)?;

    let mut process_current_regs = process_orignal_regs.clone();

    let shellcode: Vec<u8> = vec![ 0xFF, 0xD0, 0xCC ];
    let lib_path: Vec<u8> = lib_path.into_bytes();

    let mut data: Vec<u8> = vec![];
    data.extend(shellcode.iter());
    data.extend(lib_path.iter());
    data.push(0);

    let orignal_memory = read_process_memory(pid, executeable_address, data.len() as u64)?;
    write_process_memory(pid, executeable_address, data)?;

    process_current_regs.rip = executeable_address;
    process_current_regs.rax = dlopen_address;
    process_current_regs.rdi = executeable_address + (shellcode.len() as u64);
    process_current_regs.rsi = 0x80000002;

    ptrace::setregs(pid, process_current_regs)?;

    ptrace::cont(pid, None)?;

    if wait::waitpid(pid, None)? != wait::WaitStatus::Stopped(pid, signal::SIGTRAP) {
        return Err("process didn't stopped correctly")?;
    }

    write_process_memory(pid, executeable_address, orignal_memory)?;

    ptrace::setregs(pid, process_orignal_regs)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let pid = Pid::from_raw(32297);

    ptrace::attach(pid).expect("failed to attach process");

    remote_load_library(pid, "/home/shahak/user_space_hooks/a.so".to_string())?;

    ptrace::detach(pid, None).expect("failed to detach process");

    signal::kill(pid, signal::SIGCONT)?;

    Ok(())
}