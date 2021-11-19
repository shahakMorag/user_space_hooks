use std::ffi::CString;
use std::ffi::c_void;
use std::fs;
use std::error;
use std::i64;
use std::mem::size_of;
use std::os::raw::c_long;
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

fn read_process_memory(pid: Pid, address: u64, length: u64) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut words_from_memory = Vec::<c_long>::new();

    for i in (0..length).step_by(size_of::<c_long>()) {
        let offset = (i as u64) * (size_of::<c_long>() as u64);
        let current_address = address + offset;

        words_from_memory.push(ptrace::read(pid, current_address as *mut c_void)?);
    }

    Ok(words_from_memory.iter().flat_map(|x| -> [u8; size_of::<c_long>()] { x.to_ne_bytes() }).collect())
}

fn write_process_memory(pid: Pid, address: u64, data: &mut Vec<u8>) -> Result<usize, Box<dyn error::Error>> {
    while data.len() % size_of::<c_long>() != 0 {
        data.push(b'\0');
    }

    let data_length = data.len();
    let data = unsafe { CString::from_vec_unchecked(data.to_vec()) };
    let data = data.as_ptr();

    for i in (0..data_length).step_by(size_of::<c_long>()) {
        let offset = (i as u64) * (size_of::<c_long>() as u64);
        let current_address = address + offset;
        let current_data_address = (data as u64) + offset;

        unsafe { ptrace::write(pid, current_address as *mut c_void, current_data_address as *mut c_void) }?;
    }

    Ok(data_length)
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let pid = Pid::from_raw(1704);

    let (libc_address, libc_path) = get_process_libc(pid)?;

    let dlopen_offset = get_symbol_offset(&libc_path, "__libc_dlopen_mode")?;

    ptrace::attach(pid).expect("failed to attach process");

    signal::kill(pid, signal::SIGSTOP).expect("failed to stop process");

    let libc_start_code = read_process_memory(pid, libc_address + dlopen_offset, 10)
        .expect("failed to read process memory");

    for l in libc_start_code.iter() {
        println!("0x{:x}", l);
    }

    Ok(())
}