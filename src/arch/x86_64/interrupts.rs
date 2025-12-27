//! Interrupt Descriptor Table (IDT) and interrupt handling for x86-64
//!
//! This module sets up the IDT and provides handlers for CPU exceptions
//! and hardware interrupts.

use core::arch::asm;
use core::mem::size_of;

/// Number of IDT entries (0-255)
pub const IDT_ENTRIES: usize = 256;

/// IDT Gate types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum GateType {
    /// Interrupt gate - clears IF flag (disables interrupts)
    Interrupt = 0xE,
    /// Trap gate - does not clear IF flag
    Trap = 0xF,
}

/// An entry in the Interrupt Descriptor Table (64-bit mode)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IdtEntry {
    /// Offset bits 0-15
    offset_low: u16,
    /// Code segment selector
    selector: u16,
    /// Bits 0-2: IST index, bits 3-7: reserved (0)
    ist: u8,
    /// Type and attributes: P(1) DPL(2) 0(1) Type(4)
    type_attr: u8,
    /// Offset bits 16-31
    offset_mid: u16,
    /// Offset bits 32-63
    offset_high: u32,
    /// Reserved (must be 0)
    reserved: u32,
}

impl IdtEntry {
    /// Create an empty (not present) IDT entry
    pub const fn empty() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Create a new IDT entry
    ///
    /// # Arguments
    /// * `handler` - Address of the interrupt handler function
    /// * `selector` - Code segment selector (usually 0x08 for kernel code)
    /// * `gate_type` - Type of gate (Interrupt or Trap)
    /// * `dpl` - Descriptor Privilege Level (0-3)
    /// * `ist` - Interrupt Stack Table index (0 = no IST)
    pub const fn new(handler: u64, selector: u16, gate_type: GateType, dpl: u8, ist: u8) -> Self {
        let type_attr = (1 << 7)  // Present bit
            | ((dpl & 0x3) << 5)  // DPL
            | (gate_type as u8);  // Gate type

        Self {
            offset_low: handler as u16,
            selector,
            ist: ist & 0x7,
            type_attr,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }

    /// Set the handler address
    pub fn set_handler(&mut self, handler: u64) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
    }

    /// Check if this entry is present
    pub const fn is_present(&self) -> bool {
        self.type_attr & (1 << 7) != 0
    }
}

/// IDT descriptor for LIDT instruction
#[repr(C, packed)]
pub struct IdtDescriptor {
    /// Size of IDT minus 1
    limit: u16,
    /// Virtual address of the IDT
    base: u64,
}

/// The Interrupt Descriptor Table
#[repr(C, align(16))]
pub struct Idt {
    entries: [IdtEntry; IDT_ENTRIES],
}

impl Idt {
    /// Create a new IDT with all entries empty
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::empty(); IDT_ENTRIES],
        }
    }

    /// Set an interrupt handler
    pub fn set_handler(&mut self, vector: u8, handler: u64, gate_type: GateType) {
        self.entries[vector as usize] = IdtEntry::new(
            handler,
            0x08, // Kernel code segment
            gate_type,
            0,    // DPL 0 (kernel)
            0,    // No IST
        );
    }
}

/// Interrupt stack frame pushed by CPU on interrupt/exception
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InterruptStackFrame {
    /// Instruction pointer
    pub rip: u64,
    /// Code segment
    pub cs: u64,
    /// CPU flags
    pub rflags: u64,
    /// Stack pointer
    pub rsp: u64,
    /// Stack segment
    pub ss: u64,
}

/// Exception vector numbers
pub mod vectors {
    pub const DIVIDE_ERROR: u8 = 0;
    pub const DEBUG: u8 = 1;
    pub const NMI: u8 = 2;
    pub const BREAKPOINT: u8 = 3;
    pub const OVERFLOW: u8 = 4;
    pub const BOUND_RANGE: u8 = 5;
    pub const INVALID_OPCODE: u8 = 6;
    pub const DEVICE_NOT_AVAILABLE: u8 = 7;
    pub const DOUBLE_FAULT: u8 = 8;
    pub const INVALID_TSS: u8 = 10;
    pub const SEGMENT_NOT_PRESENT: u8 = 11;
    pub const STACK_SEGMENT: u8 = 12;
    pub const GENERAL_PROTECTION: u8 = 13;
    pub const PAGE_FAULT: u8 = 14;
    pub const X87_FLOATING_POINT: u8 = 16;
    pub const ALIGNMENT_CHECK: u8 = 17;
    pub const MACHINE_CHECK: u8 = 18;
    pub const SIMD_FLOATING_POINT: u8 = 19;
    pub const VIRTUALIZATION: u8 = 20;
    pub const CONTROL_PROTECTION: u8 = 21;
    pub const HYPERVISOR_INJECTION: u8 = 28;
    pub const VMM_COMMUNICATION: u8 = 29;
    pub const SECURITY: u8 = 30;
}

/// Exception names for debugging
pub fn exception_name(vector: u8) -> &'static str {
    match vector {
        0 => "Divide Error",
        1 => "Debug",
        2 => "Non-Maskable Interrupt",
        3 => "Breakpoint",
        4 => "Overflow",
        5 => "Bound Range Exceeded",
        6 => "Invalid Opcode",
        7 => "Device Not Available",
        8 => "Double Fault",
        9 => "Coprocessor Segment Overrun",
        10 => "Invalid TSS",
        11 => "Segment Not Present",
        12 => "Stack-Segment Fault",
        13 => "General Protection Fault",
        14 => "Page Fault",
        16 => "x87 Floating-Point Exception",
        17 => "Alignment Check",
        18 => "Machine Check",
        19 => "SIMD Floating-Point Exception",
        20 => "Virtualization Exception",
        21 => "Control Protection Exception",
        28 => "Hypervisor Injection Exception",
        29 => "VMM Communication Exception",
        30 => "Security Exception",
        _ => "Unknown Exception",
    }
}

/// Check if an exception pushes an error code
pub const fn has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30)
}

// ============================================================================
// Global IDT and Initialization
// ============================================================================

use core::cell::UnsafeCell;

/// Wrapper for static IDT that can be safely shared (single-threaded init)
#[repr(transparent)]
struct StaticIdt(UnsafeCell<Idt>);

// SAFETY: IDT is only mutated during single-threaded init
unsafe impl Sync for StaticIdt {}

/// Static IDT for loading (must be 'static for LIDT)
static STATIC_IDT: StaticIdt = StaticIdt(UnsafeCell::new(Idt::new()));

/// Initialize the IDT with default exception handlers
pub fn init() {
    use core::fmt::Write;
    use crate::serial::SerialPort;

    let mut serial = unsafe { SerialPort::new(0x3F8) };

    // SAFETY: Single-threaded initialization
    let idt = unsafe { &mut *STATIC_IDT.0.get() };

    // Set up exception handlers (vectors 0-31)
    idt.set_handler(vectors::DIVIDE_ERROR, divide_error_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::DEBUG, debug_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::NMI, nmi_handler as *const () as u64, GateType::Interrupt);
    idt.set_handler(vectors::BREAKPOINT, breakpoint_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::OVERFLOW, overflow_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::BOUND_RANGE, bound_range_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::INVALID_OPCODE, invalid_opcode_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::DEVICE_NOT_AVAILABLE, device_not_available_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::DOUBLE_FAULT, double_fault_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::INVALID_TSS, invalid_tss_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::SEGMENT_NOT_PRESENT, segment_not_present_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::STACK_SEGMENT, stack_segment_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::GENERAL_PROTECTION, general_protection_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::PAGE_FAULT, page_fault_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::X87_FLOATING_POINT, x87_fp_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::ALIGNMENT_CHECK, alignment_check_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::MACHINE_CHECK, machine_check_handler as *const () as u64, GateType::Trap);
    idt.set_handler(vectors::SIMD_FLOATING_POINT, simd_fp_handler as *const () as u64, GateType::Trap);

    // Load the IDT
    // SAFETY: STATIC_IDT lives for 'static
    unsafe {
        load_idt(STATIC_IDT.0.get());
    }

    writeln!(serial, "    IDT initialized with {} entries", IDT_ENTRIES).ok();
}

/// Load IDT from a raw pointer
unsafe fn load_idt(idt: *const Idt) {
    let descriptor = IdtDescriptor {
        limit: (size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
        base: unsafe { (*idt).entries.as_ptr() as u64 },
    };

    unsafe {
        asm!("lidt [{}]", in(reg) &descriptor, options(nostack, preserves_flags));
    }
}

// ============================================================================
// Exception Handlers
// ============================================================================

// Macro to generate exception handler stubs
macro_rules! exception_handler {
    ($name:ident, $vector:expr, no_error_code) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            core::arch::naked_asm!(
                // Push dummy error code for uniform stack frame
                "push 0",
                // Push vector number
                "push {vector}",
                // Jump to common handler
                "jmp {common}",
                vector = const $vector,
                common = sym exception_common,
            );
        }
    };
    ($name:ident, $vector:expr, error_code) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            core::arch::naked_asm!(
                // Error code already on stack
                // Push vector number
                "push {vector}",
                // Jump to common handler
                "jmp {common}",
                vector = const $vector,
                common = sym exception_common,
            );
        }
    };
}

/// Common exception handler - saves state and calls Rust handler
#[unsafe(naked)]
extern "C" fn exception_common() {
    core::arch::naked_asm!(
        // Save all general-purpose registers
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

        // First argument (rdi) = pointer to saved state on stack
        "mov rdi, rsp",
        // Call Rust exception handler
        "call {handler}",

        // Restore all general-purpose registers
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

        // Remove vector number and error code
        "add rsp, 16",

        // Return from interrupt
        "iretq",

        handler = sym rust_exception_handler,
    );
}

/// Saved CPU state during exception
#[repr(C)]
#[derive(Debug)]
pub struct ExceptionState {
    // Pushed by exception_common (in reverse order)
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
    // Pushed by handler stub
    pub vector: u64,
    pub error_code: u64,
    // Pushed by CPU
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Rust exception handler - called from assembly
extern "C" fn rust_exception_handler(state: &ExceptionState) {
    use core::fmt::Write;
    use crate::serial::SerialPort;

    let mut serial = unsafe { SerialPort::new(0x3F8) };

    writeln!(serial, "").ok();
    writeln!(serial, "!!! EXCEPTION: {} (vector {})",
             exception_name(state.vector as u8), state.vector).ok();
    writeln!(serial, "    Error code: {:#x}", state.error_code).ok();
    writeln!(serial, "    RIP: {:#x}  CS: {:#x}", state.rip, state.cs).ok();
    writeln!(serial, "    RSP: {:#x}  SS: {:#x}", state.rsp, state.ss).ok();
    writeln!(serial, "    RFLAGS: {:#x}", state.rflags).ok();
    writeln!(serial, "    RAX: {:#018x}  RBX: {:#018x}", state.rax, state.rbx).ok();
    writeln!(serial, "    RCX: {:#018x}  RDX: {:#018x}", state.rcx, state.rdx).ok();
    writeln!(serial, "    RSI: {:#018x}  RDI: {:#018x}", state.rsi, state.rdi).ok();
    writeln!(serial, "    RBP: {:#018x}  R8:  {:#018x}", state.rbp, state.r8).ok();
    writeln!(serial, "    R9:  {:#018x}  R10: {:#018x}", state.r9, state.r10).ok();
    writeln!(serial, "    R11: {:#018x}  R12: {:#018x}", state.r11, state.r12).ok();
    writeln!(serial, "    R13: {:#018x}  R14: {:#018x}", state.r13, state.r14).ok();
    writeln!(serial, "    R15: {:#018x}", state.r15).ok();

    // For page faults, also print CR2 (faulting address)
    if state.vector == vectors::PAGE_FAULT as u64 {
        let cr2: u64;
        unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nostack, preserves_flags)); }
        writeln!(serial, "    CR2 (fault addr): {:#x}", cr2).ok();
    }

    writeln!(serial, "").ok();
    writeln!(serial, "System halted.").ok();

    // Halt the system
    loop {
        unsafe { asm!("cli; hlt", options(nostack, nomem)); }
    }
}

// Generate exception handlers
exception_handler!(divide_error_handler, 0, no_error_code);
exception_handler!(debug_handler, 1, no_error_code);
exception_handler!(nmi_handler, 2, no_error_code);
exception_handler!(breakpoint_handler, 3, no_error_code);
exception_handler!(overflow_handler, 4, no_error_code);
exception_handler!(bound_range_handler, 5, no_error_code);
exception_handler!(invalid_opcode_handler, 6, no_error_code);
exception_handler!(device_not_available_handler, 7, no_error_code);
exception_handler!(double_fault_handler, 8, error_code);
exception_handler!(invalid_tss_handler, 10, error_code);
exception_handler!(segment_not_present_handler, 11, error_code);
exception_handler!(stack_segment_handler, 12, error_code);
exception_handler!(general_protection_handler, 13, error_code);
exception_handler!(page_fault_handler, 14, error_code);
exception_handler!(x87_fp_handler, 16, no_error_code);
exception_handler!(alignment_check_handler, 17, error_code);
exception_handler!(machine_check_handler, 18, no_error_code);
exception_handler!(simd_fp_handler, 19, no_error_code);
