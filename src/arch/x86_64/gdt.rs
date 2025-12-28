//! Global Descriptor Table (GDT) for x86-64
//!
//! This module provides the GDT with kernel and user segments, plus TSS.
//!
//! GDT Layout:
//! - 0x00: Null descriptor
//! - 0x08: Kernel code segment (ring 0)
//! - 0x10: Kernel data segment (ring 0)
//! - 0x18: User data segment (ring 3)
//! - 0x20: User code segment (ring 3)
//! - 0x28: TSS descriptor (16 bytes, spans 0x28-0x37)

use core::arch::asm;
use core::mem::size_of;

/// Segment selectors
pub mod selectors {
    pub const NULL: u16 = 0x00;
    pub const KERNEL_CODE: u16 = 0x08;
    pub const KERNEL_DATA: u16 = 0x10;
    pub const USER_DATA: u16 = 0x18 | 3;   // RPL 3
    pub const USER_CODE: u16 = 0x20 | 3;   // RPL 3
    pub const TSS: u16 = 0x28;
}

/// GDT entry (segment descriptor) - 8 bytes
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    flags_limit_high: u8,
    base_high: u8,
}

impl GdtEntry {
    /// Create a null descriptor
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            flags_limit_high: 0,
            base_high: 0,
        }
    }

    /// Create a 64-bit kernel code segment
    pub const fn kernel_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x9A,       // Present, DPL 0, code, exec/read
            flags_limit_high: 0xAF, // 64-bit, limit high
            base_high: 0,
        }
    }

    /// Create a kernel data segment
    pub const fn kernel_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x92,       // Present, DPL 0, data, read/write
            flags_limit_high: 0xCF, // 32-bit, 4KB granularity
            base_high: 0,
        }
    }

    /// Create a 64-bit user code segment
    pub const fn user_code() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0xFA,       // Present, DPL 3, code, exec/read
            flags_limit_high: 0xAF, // 64-bit, limit high
            base_high: 0,
        }
    }

    /// Create a user data segment
    pub const fn user_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0xF2,       // Present, DPL 3, data, read/write
            flags_limit_high: 0xCF, // 32-bit, 4KB granularity
            base_high: 0,
        }
    }
}

/// TSS descriptor (16 bytes in 64-bit mode)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TssDescriptor {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    flags_limit_high: u8,
    base_high: u8,
    base_upper: u32,
    reserved: u32,
}

impl TssDescriptor {
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            flags_limit_high: 0,
            base_high: 0,
            base_upper: 0,
            reserved: 0,
        }
    }

    /// Create a TSS descriptor for the given TSS address and size
    pub fn new(base: u64, limit: u32) -> Self {
        Self {
            limit_low: limit as u16,
            base_low: base as u16,
            base_mid: (base >> 16) as u8,
            access: 0x89,       // Present, 64-bit TSS (available)
            flags_limit_high: ((limit >> 16) as u8) & 0x0F,
            base_high: (base >> 24) as u8,
            base_upper: (base >> 32) as u32,
            reserved: 0,
        }
    }
}

/// Task State Segment (TSS) for x86-64
///
/// The TSS is used primarily for:
/// - RSP0: Stack to use when transitioning from ring 3 to ring 0
/// - IST: Interrupt Stack Table for specific interrupts
#[repr(C, packed)]
pub struct Tss {
    reserved0: u32,
    /// Stack pointers for privilege levels 0-2
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    reserved1: u64,
    /// Interrupt Stack Table (IST) entries 1-7
    pub ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// I/O map base address
    pub iopb: u16,
}

impl Tss {
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iopb: size_of::<Tss>() as u16,
        }
    }
}

/// GDT pointer for LGDT instruction
#[repr(C, packed)]
pub struct GdtPointer {
    limit: u16,
    base: u64,
}

/// Combined GDT structure with all entries
#[repr(C, align(16))]
pub struct Gdt {
    null: GdtEntry,
    kernel_code: GdtEntry,
    kernel_data: GdtEntry,
    user_data: GdtEntry,
    user_code: GdtEntry,
    tss: TssDescriptor,
}

impl Gdt {
    pub const fn new() -> Self {
        Self {
            null: GdtEntry::null(),
            kernel_code: GdtEntry::kernel_code(),
            kernel_data: GdtEntry::kernel_data(),
            user_data: GdtEntry::user_data(),
            user_code: GdtEntry::user_code(),
            tss: TssDescriptor::null(),
        }
    }

    /// Set the TSS descriptor
    pub fn set_tss(&mut self, base: u64, limit: u32) {
        self.tss = TssDescriptor::new(base, limit);
    }
}

use core::cell::UnsafeCell;

struct SyncGdt(UnsafeCell<Gdt>);
unsafe impl Sync for SyncGdt {}

struct SyncTss(UnsafeCell<Tss>);
unsafe impl Sync for SyncTss {}

/// Static kernel GDT
static KERNEL_GDT: SyncGdt = SyncGdt(UnsafeCell::new(Gdt::new()));

/// Static kernel TSS
static KERNEL_TSS: SyncTss = SyncTss(UnsafeCell::new(Tss::new()));

/// Initialize the GDT with TSS
///
/// This sets up the full GDT including user segments and TSS,
/// then loads it into the CPU.
pub fn init(kernel_stack: u64) {
    let gdt = unsafe { &mut *KERNEL_GDT.0.get() };
    let tss = unsafe { &mut *KERNEL_TSS.0.get() };

    // Set up TSS with kernel stack for ring 0
    tss.rsp0 = kernel_stack;

    // Update GDT with TSS descriptor
    let tss_addr = tss as *const Tss as u64;
    let tss_limit = (size_of::<Tss>() - 1) as u32;
    gdt.set_tss(tss_addr, tss_limit);

    // Load GDT
    let gdt_size = size_of::<Gdt>();
    let pointer = GdtPointer {
        limit: (gdt_size - 1) as u16,
        base: gdt as *const Gdt as u64,
    };

    unsafe {
        asm!("lgdt [{}]", in(reg) &pointer, options(nostack, preserves_flags));

        // Reload code segment
        asm!(
            "push 0x10",        // SS (kernel data)
            "push rsp",         // RSP
            "add qword ptr [rsp], 8",
            "pushfq",           // RFLAGS
            "push 0x08",        // CS (kernel code)
            "lea rax, [rip + 2f]",
            "push rax",
            "iretq",
            "2:",
            // Reload data segments
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            out("rax") _,
            options(preserves_flags)
        );

        // Load TSS
        asm!(
            "ltr {0:x}",
            in(reg) selectors::TSS,
            options(nostack, preserves_flags)
        );
    }
}

/// Reload the GDT (called before removing identity mapping)
///
/// This is the simpler reload that doesn't reinitialize TSS.
pub fn reload() {
    let gdt = unsafe { &*KERNEL_GDT.0.get() };

    let gdt_size = size_of::<Gdt>();
    let pointer = GdtPointer {
        limit: (gdt_size - 1) as u16,
        base: gdt as *const Gdt as u64,
    };

    unsafe {
        asm!("lgdt [{}]", in(reg) &pointer, options(nostack, preserves_flags));

        // Reload segments
        asm!(
            "push 0x10",
            "push rsp",
            "add qword ptr [rsp], 8",
            "pushfq",
            "push 0x08",
            "lea rax, [rip + 2f]",
            "push rax",
            "iretq",
            "2:",
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            out("rax") _,
            options(preserves_flags)
        );
    }
}

/// Update TSS RSP0 (kernel stack for ring transitions)
pub fn set_kernel_stack(stack: u64) {
    let tss = unsafe { &mut *KERNEL_TSS.0.get() };
    tss.rsp0 = stack;
}

/// Set an IST (Interrupt Stack Table) entry
///
/// IST entries are numbered 1-7 (index 0-6 in the array).
/// These provide dedicated stacks for specific interrupt handlers.
pub fn set_ist(ist_index: u8, stack: u64) {
    if ist_index == 0 || ist_index > 7 {
        return; // Invalid index
    }
    let tss = unsafe { &mut *KERNEL_TSS.0.get() };
    tss.ist[(ist_index - 1) as usize] = stack;
}

/// Get the kernel code segment selector
pub const fn kernel_cs() -> u16 {
    selectors::KERNEL_CODE
}

/// Get the kernel data segment selector
pub const fn kernel_ds() -> u16 {
    selectors::KERNEL_DATA
}

/// Get the user code segment selector
pub const fn user_cs() -> u16 {
    selectors::USER_CODE
}

/// Get the user data segment selector
pub const fn user_ds() -> u16 {
    selectors::USER_DATA
}
