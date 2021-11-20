use core::ffi::c_void;
use std::{mem, ptr, error, os::raw::c_ulong};

use nix::unistd::Pid;
use nix::sys::{ wait, ptrace, signal };

use libc::c_ulonglong;

use crate::memory;

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
pub fn remote_run_dlopen(pid: Pid,
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

    let orignal_memory = memory::read_process_memory(pid, executeable_address, data.len() as c_ulong)?;
    memory::write_process_memory(pid, executeable_address, data)?;

    process_current_regs.cp0_epc = executeable_address as u64;
    process_current_regs.regs[2] = dlopen_address as u64;
    process_current_regs.regs[0] = (executeable_address + (shellcode.len() as c_ulong)) as u64;
    process_current_regs.regs[1] = 0x80000002;

    setregs(pid, process_current_regs)?;

    ptrace::cont(pid, None)?;

    if wait::waitpid(pid, None)? != wait::WaitStatus::Stopped(pid, signal::SIGTRAP) {
        return Err("process didn't stopped correctly")?;
    }

    memory::write_process_memory(pid, executeable_address, orignal_memory)?;

    setregs(pid, process_orignal_regs)?;

    Ok(())
}