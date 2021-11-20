use nix::unistd::Pid;
use nix::sys::{ wait, ptrace, signal };

use std::{error, os::raw::c_ulong};

use crate::memory;

#[cfg(all(
    target_os = "linux",
    any(all(target_arch = "x86_64",
            any(target_env = "gnu", target_env = "musl")))
))]
pub fn remote_run_dlopen(pid: Pid,
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

    let orignal_memory = memory::read_process_memory(pid, executeable_address, data.len() as c_ulong)?;
    memory::write_process_memory(pid, executeable_address, data)?;

    process_current_regs.rip = executeable_address;
    process_current_regs.rax = dlopen_address;
    process_current_regs.rdi = executeable_address + (shellcode.len() as c_ulong);
    process_current_regs.rsi = 0x80000002;

    ptrace::setregs(pid, process_current_regs)?;

    ptrace::cont(pid, None)?;

    if wait::waitpid(pid, None)? != wait::WaitStatus::Stopped(pid, signal::SIGTRAP) {
        return Err("process didn't stopped correctly")?;
    }

    memory::write_process_memory(pid, executeable_address, orignal_memory)?;

    ptrace::setregs(pid, process_orignal_regs)?;

    Ok(())
}