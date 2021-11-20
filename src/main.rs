use std::ffi::c_void;
use std::{mem, ptr};
use std::mem::size_of;
use std::os::raw::c_ulong;
use std::{ fs, error, i64 };

use libc::c_ulonglong;
use regex::Regex;

use object::Object;

use nix::unistd::Pid;
use nix::sys::{ ptrace, signal, wait };

use clap::Parser;

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

fn read_process_memory(pid: Pid, address: c_ulong, length: c_ulong) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut words_from_memory = Vec::<c_ulong>::new();

    for i in (0..length).step_by(size_of::<c_ulong>()) {
        let offset = (i as c_ulong) * (size_of::<c_ulong>() as c_ulong);
        let current_address = address + offset;

        words_from_memory.push(ptrace::read(pid, current_address as *mut c_void)? as c_ulong);
    }

    Ok(words_from_memory.iter().flat_map(|x| -> [u8; size_of::<c_ulong>()] { x.to_ne_bytes() }).collect())
}

fn write_process_memory(pid: Pid, address: c_ulong, new_memory: Vec<u8>) -> Result<usize, Box<dyn error::Error>> {
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

/// Function for ptrace requests that return values from the data field.
/// Some ptrace get requests populate structs or larger elements than `c_long`
/// and therefore use the data field to return values. This function handles these
/// requests.
fn ptrace_get_data<T>(request: ptrace::Request, pid: Pid) -> nix::Result<T> {
    let mut data = mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(request as ptrace::RequestType,
                     libc::pid_t::from(pid),
                     ptr::null_mut::<T>(),
                     data.as_mut_ptr() as *const _ as *const c_void)
    };
    nix::errno::Errno::result(res)?;
    Ok(unsafe{ data.assume_init() })
}

#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "x86_64",
            any(target_env = "gnu", target_env = "musl")))
))]
fn remote_run_dlopen(pid: Pid,
    lib_path: String,
    executeable_address: c_ulong,
    dlopen_address: c_ulong) -> Result<(), Box<dyn error::Error>> {
    let process_orignal_regs = ptrace::getregs(pid)?;

    let mut process_current_regs = process_orignal_regs.clone();

    let shellcode: Vec<u8> = vec![ 0xFF, 0xD0, 0xCC ];
    let lib_path: Vec<u8> = lib_path.into_bytes();

    let mut data: Vec<u8> = vec![];
    data.extend(shellcode.iter());
    data.extend(lib_path.iter());
    data.push(0);

    let orignal_memory = read_process_memory(pid, executeable_address, data.len() as c_ulong)?;
    write_process_memory(pid, executeable_address, data)?;

    process_current_regs.rip = executeable_address;
    process_current_regs.rax = dlopen_address;
    process_current_regs.rdi = executeable_address + (shellcode.len() as c_ulong);
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

#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "mips",
            any(target_env = "gnu", target_env = "musl")))
))]
#[derive(Clone)]
pub struct UserPtRegs {
    pub regs: [c_ulonglong; 32],
	pub lo : c_ulonglong,
	pub hi : c_ulonglong,
	pub cp0_epc : c_ulonglong,
	pub cp0_badvaddr : c_ulonglong,
	pub cp0_status : c_ulonglong,
	pub cp0_cause : c_ulonglong,
}

/// Get user registers, as with `ptrace(PTRACE_GETREGS, ...)`
#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "mips",
            any(target_env = "gnu", target_env = "musl")))
))]
pub fn getregs(pid: Pid) -> nix::Result<UserPtRegs> {
    ptrace_get_data::<UserPtRegs>(ptrace::Request::PTRACE_GETREGS, pid)
}

/// Set user registers, as with `ptrace(PTRACE_SETREGS, ...)`
#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "mips",
            any(target_env = "gnu", target_env = "musl")))
))]
pub fn setregs(pid: Pid, regs: UserPtRegs) -> nix::Result<()> {
    let res = unsafe {
        libc::ptrace(ptrace::Request::PTRACE_SETREGS as ptrace::RequestType,
                     libc::pid_t::from(pid),
                     ptr::null_mut::<c_void>(),
                     &regs as *const _ as *const c_void)
    };
    nix::errno::Errno::result(res).map(drop)
}

#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "mips",
            any(target_env = "gnu", target_env = "musl")))
))]
fn remote_run_dlopen(pid: Pid,
    lib_path: String,
    executeable_address: c_ulong,
    dlopen_address: c_ulong) -> Result<(), Box<dyn error::Error>> {

    let process_orignal_regs = getregs(pid)?;
    let mut process_current_regs = process_orignal_regs.clone();

    // little endian
    let shellcode: Vec<u8> = vec![ 0x09, 0xf8, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00 ];
    let lib_path: Vec<u8> = lib_path.into_bytes();

    let mut data: Vec<u8> = vec![];
    data.extend(shellcode.iter());
    data.extend(lib_path.iter());
    data.push(0);

    let orignal_memory = read_process_memory(pid, executeable_address, data.len() as c_ulong)?;
    write_process_memory(pid, executeable_address, data)?;

    process_current_regs.cp0_epc = executeable_address as u64;
    process_current_regs.regs[2] = dlopen_address as u64;
    process_current_regs.regs[0] = (executeable_address + (shellcode.len() as c_ulong)) as u64;
    process_current_regs.regs[1] = 0x80000002;

    setregs(pid, process_current_regs)?;

    ptrace::cont(pid, None)?;

    if wait::waitpid(pid, None)? != wait::WaitStatus::Stopped(pid, signal::SIGTRAP) {
        return Err("process didn't stopped correctly")?;
    }

    write_process_memory(pid, executeable_address, orignal_memory)?;

    setregs(pid, process_orignal_regs)?;

    Ok(())
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