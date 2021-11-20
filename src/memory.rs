use std::{error, mem::size_of, os::raw::c_ulong};

use libc::c_void;
use nix::{sys::ptrace, unistd::Pid};

pub fn read_process_memory(pid: Pid, address: c_ulong, length: c_ulong) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut words_from_memory = Vec::<c_ulong>::new();

    for i in (0..length).step_by(size_of::<c_ulong>()) {
        let offset = (i as c_ulong) * (size_of::<c_ulong>() as c_ulong);
        let current_address = address + offset;

        words_from_memory.push(ptrace::read(pid, current_address as *mut c_void)? as c_ulong);
    }

    Ok(words_from_memory.iter().flat_map(|x| -> [u8; size_of::<c_ulong>()] { x.to_ne_bytes() }).collect())
}

pub fn write_process_memory(pid: Pid, address: c_ulong, new_memory: Vec<u8>) -> Result<usize, Box<dyn error::Error>> {
    let mut data = new_memory.clone();
    while data.len() % size_of::<c_ulong>() != 0 {
        data.push(b'\0');
    }

    let data: Vec<c_ulong> = data
        .chunks_exact(size_of::<c_ulong>())
        .map(|chunk| -> c_ulong {
            let chunk: [u8; size_of::<c_ulong>()] = chunk.try_into().unwrap();
            c_ulong::from_ne_bytes(chunk)
        }).collect();

    for (i, value) in data.iter().enumerate() {
        let offset = (i as c_ulong) * (size_of::<c_ulong>() as c_ulong);
        let current_address = address + offset;

        unsafe { ptrace::write(pid, current_address as *mut c_void, *value as *mut c_void) }?;
    }

    Ok(data.len())
}