//! System Call Interface for x86-64 using SYSCALL/SYSRET
//!
//! This module implements fast system calls using the native x86-64
//! SYSCALL and SYSRET instructions.
//!
//! Syscall Convention (Linux-compatible):
//! - RAX = syscall number
//! - RDI, RSI, RDX, R10, R8, R9 = arguments
//! - RAX = return value
//! - RCX and R11 are clobbered (used by SYSCALL for RIP and RFLAGS)
//!
//! On SYSCALL entry:
//! - RCX = return RIP
//! - R11 = return RFLAGS
//! - CS = kernel code segment (from STAR)
//! - SS = kernel data segment (from STAR)
//! - RSP = unchanged (still user stack!)
//!
//! We use SWAPGS to access per-CPU data containing the kernel stack pointer.

use core::arch::asm;

// ============================================================================
// MSR Definitions
// ============================================================================

/// Extended Feature Enable Register
const IA32_EFER: u32 = 0xC0000080;
/// System Call Extensions enable bit in EFER
const EFER_SCE: u64 = 1 << 0;

/// STAR: Segment selectors for SYSCALL/SYSRET
/// Bits 47:32 = SYSCALL CS (SS = CS + 8)
/// Bits 63:48 = SYSRET CS base (CS = base + 16, SS = base + 8)
const IA32_STAR: u32 = 0xC0000081;

/// LSTAR: Target RIP for SYSCALL (Long Mode)
const IA32_LSTAR: u32 = 0xC0000082;

/// SFMASK: RFLAGS mask for SYSCALL (bits set here are cleared in RFLAGS)
const IA32_SFMASK: u32 = 0xC0000084;

/// GS base for current privilege level
const IA32_GS_BASE: u32 = 0xC0000101;

/// GS base swapped by SWAPGS
const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;

// ============================================================================
// MSR Access
// ============================================================================

/// Read a Model-Specific Register
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nostack, nomem, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Write a Model-Specific Register
#[inline]
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nostack, nomem, preserves_flags)
        );
    }
}

// ============================================================================
// Per-CPU Data
// ============================================================================

/// Per-CPU data structure accessed via GS segment
///
/// This is used by the SYSCALL entry point to get the kernel stack.
/// Fields are at fixed offsets used by assembly code.
#[repr(C)]
pub struct PerCpuData {
    /// Kernel stack pointer (offset 0)
    /// Set to top of kernel stack for this CPU
    pub kernel_rsp: u64,
    /// User stack pointer (offset 8)
    /// Saved here during SYSCALL, restored on SYSRET
    pub user_rsp: u64,
    /// Current process pointer (offset 16)
    pub current_process: u64,
}

/// Static per-CPU data (for single-CPU system)
static mut PER_CPU: PerCpuData = PerCpuData {
    kernel_rsp: 0,
    user_rsp: 0,
    current_process: 0,
};

// ============================================================================
// System Call Numbers
// ============================================================================

pub mod numbers {
    pub const EXIT: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const YIELD: u64 = 2;
    pub const GETPID: u64 = 3;
}

// ============================================================================
// RFLAGS bits to mask on SYSCALL
// ============================================================================

const RFLAGS_IF: u64 = 1 << 9;   // Interrupt enable
const RFLAGS_TF: u64 = 1 << 8;   // Trap flag (single-step)
const RFLAGS_DF: u64 = 1 << 10;  // Direction flag
const RFLAGS_AC: u64 = 1 << 18;  // Alignment check
const RFLAGS_NT: u64 = 1 << 14;  // Nested task

/// Flags to clear on SYSCALL entry
/// We clear IF (disable interrupts), TF (no single-step), DF (clear direction)
const SFMASK_VALUE: u64 = RFLAGS_IF | RFLAGS_TF | RFLAGS_DF | RFLAGS_AC | RFLAGS_NT;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize the SYSCALL/SYSRET mechanism
///
/// This configures the MSRs and sets up per-CPU data.
/// Must be called after GDT is set up with user segments.
pub fn init(kernel_stack: u64) {
    unsafe {
        // Set up per-CPU data via raw pointer
        let per_cpu = &raw mut PER_CPU;
        (*per_cpu).kernel_rsp = kernel_stack;
        (*per_cpu).user_rsp = 0;
        (*per_cpu).current_process = 0;

        // Set GS bases for SWAPGS
        // When in user mode: GS_BASE = user value, KERNEL_GS_BASE = &PER_CPU
        // When in kernel mode: GS_BASE = &PER_CPU, KERNEL_GS_BASE = user value
        // We start in kernel mode, so set GS_BASE to PER_CPU
        let per_cpu_addr = per_cpu as u64;
        wrmsr(IA32_GS_BASE, per_cpu_addr);
        wrmsr(IA32_KERNEL_GS_BASE, 0); // User's GS base (0 for now)

        // Enable System Call Extensions in EFER
        let efer = rdmsr(IA32_EFER);
        wrmsr(IA32_EFER, efer | EFER_SCE);

        // Set up STAR: segment selectors
        // Bits 47:32 = SYSCALL CS and SS (kernel segments)
        // Bits 63:48 = SYSRET CS and SS base (user segments)
        //
        // Our GDT layout:
        //   0x08: Kernel code
        //   0x10: Kernel data
        //   0x18: User data
        //   0x20: User code
        //
        // For SYSCALL: CS = STAR[47:32], SS = STAR[47:32] + 8
        //   We want CS = 0x08, SS = 0x10, so STAR[47:32] = 0x08
        //
        // For SYSRET (64-bit): CS = STAR[63:48] + 16, SS = STAR[63:48] + 8
        //   We want CS = 0x20, SS = 0x18, so STAR[63:48] = 0x10
        let star = (0x10u64 << 48) | (0x08u64 << 32);
        wrmsr(IA32_STAR, star);

        // Set up LSTAR: syscall entry point
        wrmsr(IA32_LSTAR, syscall_entry as *const () as u64);

        // Set up SFMASK: flags to clear on SYSCALL
        wrmsr(IA32_SFMASK, SFMASK_VALUE);
    }
}

/// Update the kernel stack pointer in per-CPU data
pub fn set_kernel_stack(stack: u64) {
    unsafe {
        let per_cpu = &raw mut PER_CPU;
        (*per_cpu).kernel_rsp = stack;
    }
}

// ============================================================================
// SYSCALL Entry Point
// ============================================================================

/// SYSCALL entry point
///
/// On entry:
/// - RCX = user RIP (return address)
/// - R11 = user RFLAGS
/// - RAX = syscall number
/// - RDI, RSI, RDX, R10, R8, R9 = arguments
/// - RSP = user stack (not switched!)
/// - Interrupts are disabled (IF cleared by SFMASK)
///
/// We must:
/// 1. SWAPGS to get access to per-CPU data
/// 2. Save user RSP and load kernel RSP
/// 3. Save registers and call handler
/// 4. Restore registers
/// 5. Load user RSP
/// 6. SWAPGS back
/// 7. SYSRET
#[unsafe(naked)]
extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        // SWAPGS: now GS points to per-CPU data
        "swapgs",

        // Save user stack pointer to per-CPU data
        "mov gs:[8], rsp",

        // Load kernel stack pointer from per-CPU data
        "mov rsp, gs:[0]",

        // Now we're on the kernel stack. Build a stack frame.
        // We need to save enough state to call the handler and return.

        // Push user context (for potential inspection and SYSRET)
        "push gs:[8]",      // User RSP (from per-CPU)
        "push r11",         // User RFLAGS
        "push rcx",         // User RIP

        // Push syscall arguments (callee-saved perspective)
        "push rax",         // Syscall number
        "push rdi",         // arg1
        "push rsi",         // arg2
        "push rdx",         // arg3
        "push r10",         // arg4 (note: r10 instead of rcx which is clobbered)
        "push r8",          // arg5
        "push r9",          // arg6

        // Save remaining callee-saved registers
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        // Call Rust handler with pointer to stack frame
        "mov rdi, rsp",
        "call {handler}",

        // RAX now contains return value

        // Restore callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        // Skip over saved arguments (7 values: rax, rdi, rsi, rdx, r10, r8, r9)
        "add rsp, 7 * 8",

        // Pop user context for SYSRET
        "pop rcx",          // User RIP -> RCX for SYSRET
        "pop r11",          // User RFLAGS -> R11 for SYSRET
        "pop rsp",          // User RSP (direct pop since we're switching stacks)

        // SWAPGS back: restore user's GS base
        "swapgs",

        // Return to user mode
        // SYSRETQ: RIP = RCX, RFLAGS = R11, CS = STAR[63:48]+16, SS = STAR[63:48]+8
        "sysretq",

        handler = sym syscall_handler_rust,
    );
}

// ============================================================================
// Syscall Handler
// ============================================================================

/// Stack frame layout for syscall
#[repr(C)]
pub struct SyscallFrame {
    // Callee-saved (pushed last, at lower addresses)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    // Arguments
    pub r9: u64,        // arg6
    pub r8: u64,        // arg5
    pub r10: u64,       // arg4
    pub rdx: u64,       // arg3
    pub rsi: u64,       // arg2
    pub rdi: u64,       // arg1
    pub rax: u64,       // syscall number
    // User context (for SYSRET)
    pub user_rip: u64,
    pub user_rflags: u64,
    pub user_rsp: u64,
}

/// Rust syscall handler
extern "C" fn syscall_handler_rust(frame: &SyscallFrame) -> u64 {
    let num = frame.rax;
    let arg1 = frame.rdi;
    let arg2 = frame.rsi;
    let arg3 = frame.rdx;
    let _arg4 = frame.r10;
    let _arg5 = frame.r8;

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

// ============================================================================
// User-space syscall wrappers (using SYSCALL instruction)
// ============================================================================

/// Make a syscall with no arguments
#[inline]
pub unsafe fn syscall0(num: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") num,
            lateout("rax") ret,
            out("rcx") _,  // clobbered by SYSCALL
            out("r11") _,  // clobbered by SYSCALL
            options(nostack)
        );
    }
    ret
}

/// Make a syscall with one argument
#[inline]
pub unsafe fn syscall1(num: u64, arg1: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") num,
            in("rdi") arg1,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Make a syscall with three arguments
#[inline]
pub unsafe fn syscall3(num: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") num,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            lateout("rax") ret,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    ret
}
