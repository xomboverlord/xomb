//! System Call Interface for x86-64
//!
//! This module implements system calls using INT 0x80.
//! This is simpler than SYSCALL/SYSRET and uses the existing IDT infrastructure.
//!
//! Syscall Convention:
//! - RAX = syscall number
//! - RDI, RSI, RDX, R10, R8, R9 = arguments
//! - RAX = return value

use core::arch::asm;
use crate::arch::x86_64::gdt;

/// System call interrupt vector
pub const SYSCALL_VECTOR: u8 = 0x80;

/// System call numbers
pub mod numbers {
    pub const EXIT: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const YIELD: u64 = 2;
    pub const GETPID: u64 = 3;
}

/// Initialize the syscall interface
///
/// This adds the INT 0x80 handler to the IDT.
pub fn init() {
    use crate::arch::x86_64::interrupts::{GateType, set_handler};

    // Set up INT 0x80 as a trap gate with DPL 3 (user-callable)
    set_handler(SYSCALL_VECTOR, syscall_entry as *const () as u64, GateType::Trap, 3);
}

/// Syscall entry point
///
/// This is registered as the INT 0x80 handler.
/// Stack on entry (pushed by CPU):
/// - SS, RSP, RFLAGS, CS, RIP (if from ring 3)
/// - Error code (none for INT)
#[unsafe(naked)]
extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // No error code for software interrupts
        // Save all registers
        "push rax",
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Call Rust syscall handler
        // First arg (RDI) = pointer to saved state
        "mov rdi, rsp",
        "call {handler}",

        // Return value is in RAX, save it to the stack frame
        "mov [rsp + 14*8], rax",  // Overwrite saved RAX

        // Restore all registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        "pop rax",

        // Return from interrupt
        "iretq",

        handler = sym syscall_handler_rust,
    );
}

/// Saved register state for syscall
#[repr(C)]
pub struct SyscallFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    // CPU-pushed
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Rust syscall handler
extern "C" fn syscall_handler_rust(frame: &SyscallFrame) -> u64 {
    let num = frame.rax;
    let arg1 = frame.rdi;
    let arg2 = frame.rsi;
    let arg3 = frame.rdx;
    let arg4 = frame.r10;
    let arg5 = frame.r8;

    match num {
        numbers::EXIT => {
            use crate::serial::SerialPort;
            use core::fmt::Write;
            let mut serial = unsafe { SerialPort::new(0x3F8) };
            writeln!(serial, "\n[SYSCALL] exit({})", arg1).ok();

            // For now, just halt. In a real OS, we'd terminate the process
            // and schedule another one.
            loop {
                unsafe { asm!("cli; hlt", options(nostack, nomem)); }
            }
        }

        numbers::WRITE => {
            // write(fd, buf, len) -> bytes_written
            if arg1 == 1 || arg1 == 2 {
                // stdout or stderr -> serial
                use crate::serial::SerialPort;
                let mut serial = unsafe { SerialPort::new(0x3F8) };

                let buf = arg2 as *const u8;
                let len = arg3 as usize;

                // Safety: we trust the user buffer for now
                // In a real OS, we'd validate it's in user memory
                for i in 0..len {
                    let c = unsafe { *buf.add(i) };
                    serial.write_byte(c);
                }

                len as u64
            } else {
                u64::MAX // -1 = error
            }
        }

        numbers::YIELD => {
            // No-op for single process kernel
            0
        }

        numbers::GETPID => {
            // Return current process ID
            crate::process::current().pid as u64
        }

        _ => {
            // Unknown syscall
            use crate::serial::SerialPort;
            use core::fmt::Write;
            let mut serial = unsafe { SerialPort::new(0x3F8) };
            writeln!(serial, "[SYSCALL] Unknown syscall: {}", num).ok();
            u64::MAX
        }
    }
}

/// Make a syscall from user mode (for testing)
#[inline]
pub unsafe fn syscall0(num: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "int 0x80",
            in("rax") num,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[inline]
pub unsafe fn syscall1(num: u64, arg1: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "int 0x80",
            in("rax") num,
            in("rdi") arg1,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}

#[inline]
pub unsafe fn syscall3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "int 0x80",
            in("rax") num,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rax") ret,
            options(nostack)
        );
    }
    ret
}
