//! Global Descriptor Table (GDT) for x86-64
//!
//! This module provides a kernel-space GDT that can be used after
//! identity mapping is removed.

use core::arch::asm;
use core::mem::size_of;

/// GDT entry (segment descriptor)
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

    /// Create a 64-bit code segment descriptor
    pub const fn code64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x9A,       // Present, ring 0, code, exec/read
            flags_limit_high: 0xAF, // 64-bit, limit high nibble
            base_high: 0,
        }
    }

    /// Create a data segment descriptor
    pub const fn data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: 0x92,       // Present, ring 0, data, read/write
            flags_limit_high: 0xCF, // 32-bit, 4KB granularity
            base_high: 0,
        }
    }
}

/// GDT pointer for LGDT instruction
#[repr(C, packed)]
pub struct GdtPointer {
    limit: u16,
    base: u64,
}

/// Number of GDT entries
const GDT_ENTRIES: usize = 3;

/// Kernel GDT with null, code, and data segments
#[repr(C, align(16))]
pub struct Gdt {
    entries: [GdtEntry; GDT_ENTRIES],
}

impl Gdt {
    pub const fn new() -> Self {
        Self {
            entries: [
                GdtEntry::null(),   // 0x00: Null descriptor
                GdtEntry::code64(), // 0x08: Kernel code segment
                GdtEntry::data(),   // 0x10: Kernel data segment
            ],
        }
    }
}

/// Static kernel GDT (in higher-half memory)
static KERNEL_GDT: Gdt = Gdt::new();

/// Reload the GDT with the kernel-space GDT
///
/// This should be called before removing identity mapping to ensure
/// the GDT is accessible after the low memory is unmapped.
pub fn reload() {
    let pointer = GdtPointer {
        limit: (size_of::<[GdtEntry; GDT_ENTRIES]>() - 1) as u16,
        base: KERNEL_GDT.entries.as_ptr() as u64,
    };

    unsafe {
        // Load new GDT
        asm!("lgdt [{}]", in(reg) &pointer, options(nostack, preserves_flags));

        // Reload code segment by doing a far return
        // Push SS, RSP, RFLAGS, CS, RIP and do IRETQ
        asm!(
            "push 0x10",        // SS
            "push rsp",         // RSP
            "add qword ptr [rsp], 8", // Adjust for the push
            "pushfq",           // RFLAGS
            "push 0x08",        // CS
            "lea rax, [rip + 2f]", // RIP (address of label 2)
            "push rax",
            "iretq",
            "2:",
            // Reload data segments
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            // SS is already set by IRETQ
            out("rax") _,
            options(preserves_flags)
        );
    }
}

/// Get the kernel code segment selector
pub const fn kernel_cs() -> u16 {
    0x08
}

/// Get the kernel data segment selector
pub const fn kernel_ds() -> u16 {
    0x10
}
