//! XOmB - A Rust-based exokernel
//!
//! This library contains the core kernel logic that can be unit-tested
//! on the host system without requiring an emulator.

#![no_std]

// When testing on host, we need std
#[cfg(test)]
extern crate std;

// Compiler-required memory intrinsics for no_std environments
#[cfg(not(test))]
mod intrinsics {
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        let mut i = 0;
        while i < n {
            unsafe {
                *dest.add(i) = *src.add(i);
            }
            i += 1;
        }
        dest
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        if src < dest as *const u8 {
            // Copy backwards to handle overlapping regions
            let mut i = n;
            while i > 0 {
                i -= 1;
                unsafe {
                    *dest.add(i) = *src.add(i);
                }
            }
        } else {
            // Copy forwards
            let mut i = 0;
            while i < n {
                unsafe {
                    *dest.add(i) = *src.add(i);
                }
                i += 1;
            }
        }
        dest
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
        let mut i = 0;
        while i < n {
            unsafe {
                *dest.add(i) = c as u8;
            }
            i += 1;
        }
        dest
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
        let mut i = 0;
        while i < n {
            let a = unsafe { *s1.add(i) };
            let b = unsafe { *s2.add(i) };
            if a != b {
                return a as i32 - b as i32;
            }
            i += 1;
        }
        0
    }
}

// Re-export alloc for heap allocations (available after boot services)
#[cfg(any(feature = "uefi", test))]
extern crate alloc;

pub mod arch;
pub mod boot_info;
pub mod memory;
pub mod process;
pub mod serial;

#[cfg(feature = "multiboot2")]
pub mod boot;

// Re-export boot_info types for convenience
pub use boot_info::{BootInfo, BootMethod, MemoryRegionType};

// Re-export memory types for convenience
pub use memory::{PhysAddr, Frame, VirtAddr};

/// Kernel version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

use core::fmt::Write;
use serial::SerialPort;

/// Initialize the kernel after bootloader handoff
///
/// This is the common entry point for both UEFI and Multiboot2 boot paths.
/// At this point, boot services have been exited and we have full control.
pub fn kernel_init(info: &BootInfo) -> ! {
    // Get serial port for output
    let mut serial = unsafe { SerialPort::new(0x3F8) };

    // CRITICAL: Initialize and remap the PIC first!
    // The legacy PIC's default IRQ0 (timer) maps to vector 0x08, which conflicts
    // with the Double Fault exception. This causes spurious "double faults" when
    // the timer fires. We remap the PIC to vectors 0x20-0x2F and mask all IRQs.
    arch::x86_64::pic::init();

    writeln!(serial, "").ok();
    writeln!(serial, ">>> Entering kernel_init()").ok();
    writeln!(serial, "    PIC remapped and masked").ok();
    writeln!(serial, "    Boot method: {:?}", info.boot_method).ok();

    // Report memory information from boot
    let total_memory = info.memory_map.total_usable_memory();
    writeln!(serial, "    Total usable memory: {} MB", total_memory / (1024 * 1024)).ok();
    writeln!(serial, "    Memory regions: {}", info.memory_map.count).ok();

    // Report framebuffer if available
    if info.framebuffer.is_available() {
        writeln!(serial, "    Framebuffer: {}x{} @ {:#x}",
                 info.framebuffer.width,
                 info.framebuffer.height,
                 info.framebuffer.address).ok();
    }

    // Report ACPI if available
    if info.acpi.is_available() {
        writeln!(serial, "    ACPI RSDP: {:#x}", info.acpi.rsdp).ok();
    }

    // Report command line if present
    if info.cmdline_len > 0 {
        writeln!(serial, "    Command line: {}", info.cmdline_str()).ok();
    }

    // Initialize physical memory allocator
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Initializing physical memory allocator...").ok();
    memory::frame::init(info);

    let (free_mem, total_mem) = memory::frame::memory_stats();
    writeln!(serial, "    Physical memory allocator initialized").ok();
    writeln!(serial, "    Free memory: {} MB / {} MB",
             free_mem / (1024 * 1024),
             total_mem / (1024 * 1024)).ok();

    // Initialize interrupt handling
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Initializing interrupt handling...").ok();
    arch::x86_64::interrupts::init();

    // Initialize process subsystem
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Initializing process subsystem...").ok();
    process::init();
    writeln!(serial, "    Process 0 (kernel) initialized").ok();
    writeln!(serial, "    Active processes: {}", process::count()).ok();

    // Test creating a new process and switching address spaces
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Testing process creation...").ok();
    match process::create() {
        Ok(pid) => {
            writeln!(serial, "    Created process {} (page table: {:#x})",
                     pid, process::get(pid).unwrap().page_table).ok();

            // Test address space switch
            unsafe {
                if process::switch_address_space(pid).is_ok() {
                    writeln!(serial, "    Switched to process {} address space", pid).ok();
                    process::switch_to_kernel();
                    writeln!(serial, "    Returned to kernel address space").ok();
                }
            }
            writeln!(serial, "    Active processes: {}", process::count()).ok();
        }
        Err(e) => {
            writeln!(serial, "    Failed to create process: {:?}", e).ok();
        }
    }

    // Test allocating a few frames
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Testing frame allocator...").ok();

    match memory::frame::allocate_frame() {
        Ok(frame) => {
            writeln!(serial, "    Allocated frame: {} (phys: {:#x})",
                     frame.number(), frame.start_address()).ok();

            // Deallocate it
            if memory::frame::deallocate_frame(frame).is_ok() {
                writeln!(serial, "    Deallocated frame successfully").ok();
            }
        }
        Err(e) => {
            writeln!(serial, "    Failed to allocate frame: {:?}", e).ok();
        }
    }

    // Test allocating a specific frame (e.g., for a device)
    let test_addr = PhysAddr::new(0x200000); // 2MB mark
    match memory::frame::allocate_frame_at(test_addr) {
        Ok(frame) => {
            writeln!(serial, "    Allocated specific frame at {:#x}", frame.start_address()).ok();
            let _ = memory::frame::deallocate_frame(frame);
        }
        Err(e) => {
            writeln!(serial, "    Could not allocate frame at {:#x}: {:?}", test_addr, e).ok();
        }
    }

    let (free_mem_after, _) = memory::frame::memory_stats();
    writeln!(serial, "    Free memory after tests: {} MB", free_mem_after / (1024 * 1024)).ok();

    // Test page table primitives
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Testing page table primitives...").ok();

    // Test 1: Read PML4 entries to verify recursive mapping works
    writeln!(serial, "    Reading PML4 entries via recursive mapping:").ok();
    let pml4_0 = memory::paging::read_pml4(0);
    let pml4_510 = memory::paging::read_pml4(510);
    let pml4_511 = memory::paging::read_pml4(511);
    writeln!(serial, "      PML4[0]   (identity):  {:?}", pml4_0).ok();
    writeln!(serial, "      PML4[510] (recursive): {:?}", pml4_510).ok();
    writeln!(serial, "      PML4[511] (kernel):    {:?}", pml4_511).ok();

    // Test 2: Translate a known address (kernel code)
    let kernel_addr = VirtAddr::new(0xFFFFFFFF80102000); // Kernel .text
    writeln!(serial, "    Translating kernel address {:#x}:", kernel_addr).ok();
    if let Some(phys) = memory::paging::translate(kernel_addr) {
        writeln!(serial, "      -> Physical: {:#x}", phys).ok();
    } else {
        writeln!(serial, "      -> Not mapped (unexpected!)").ok();
    }

    // Test 3: Get mapping info for kernel address
    if let Some((_phys, size, flags)) = memory::paging::get_mapping_info(kernel_addr) {
        writeln!(serial, "      Page size: {:?}, flags: {:#x}", size, flags).ok();
    }

    // Test 4: Map a new 4KB page
    // Use an unmapped address in kernel space - PML4[509] is unused (between user and recursive regions)
    let test_virt = VirtAddr::new(0xFFFFFE8000000000);
    writeln!(serial, "    Mapping new 4KB page at {:#x}:", test_virt).ok();

    // Allocate a physical frame
    match memory::frame::allocate_frame() {
        Ok(frame) => {
            let phys = frame.start_address();
            writeln!(serial, "      Allocated frame at {:#x}", phys).ok();

            // Map with KERNEL_DATA (PRESENT | WRITABLE | NO_EXECUTE)
            let result = memory::paging::map_4kb(test_virt, phys, memory::paging::flags::KERNEL_DATA);
            match result {
                Ok(()) => {
                    writeln!(serial, "      Mapped successfully!").ok();

                    // Verify the mapping
                    if let Some(translated) = memory::paging::translate(test_virt) {
                        writeln!(serial, "      Verified: {:#x} -> {:#x}", test_virt, translated).ok();
                    }

                    // Write to the mapped page to verify it's accessible
                    unsafe {
                        let ptr = test_virt.as_u64() as *mut u64;
                        *ptr = 0xDEADBEEF_CAFEBABE;
                        let read_back = *ptr;
                        writeln!(serial, "      Write/read test: {:#x}", read_back).ok();
                    }

                    // Unmap the page
                    match memory::paging::unmap_4kb(test_virt) {
                        Ok(unmapped_frame) => {
                            writeln!(serial, "      Unmapped, frame: {}", unmapped_frame.number()).ok();
                            let _ = memory::frame::deallocate_frame(unmapped_frame);
                        }
                        Err(e) => {
                            writeln!(serial, "      Unmap failed: {:?}", e).ok();
                        }
                    }
                }
                Err(e) => {
                    writeln!(serial, "      Map failed: {:?}", e).ok();
                    let _ = memory::frame::deallocate_frame(frame);
                }
            }
        }
        Err(e) => {
            writeln!(serial, "      Frame allocation failed: {:?}", e).ok();
        }
    }

    // Initialize GDT with TSS for user mode support
    // We need a kernel stack for ring 0 transitions from ring 3
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Initializing GDT with TSS...").ok();

    // Allocate a kernel stack for syscall/interrupt handling from user mode
    // We'll use 4 pages (16KB) for the kernel stack
    let kernel_stack_base = VirtAddr::new(0xFFFFFE8000010000); // In temp region

    // Allocate and map 4 pages for the kernel stack
    for i in 0..4 {
        let frame = memory::frame::allocate_frame().expect("Failed to allocate kernel stack");
        let page_virt = VirtAddr::new(kernel_stack_base.as_u64() + (i * 0x1000) as u64);
        memory::paging::map_4kb(page_virt, frame.start_address(), memory::paging::flags::KERNEL_DATA)
            .expect("Failed to map kernel stack");
    }

    // Stack grows down, so point to top of the 4-page region
    let kernel_stack_top = kernel_stack_base.as_u64() + 0x4000;
    arch::x86_64::gdt::init(kernel_stack_top);
    writeln!(serial, "    GDT with TSS initialized").ok();
    writeln!(serial, "    Kernel stack at {:#x}", kernel_stack_top).ok();

    // Initialize SYSCALL/SYSRET interface
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Initializing SYSCALL/SYSRET...").ok();
    arch::x86_64::syscall::init(kernel_stack_top);
    writeln!(serial, "    SYSCALL/SYSRET configured").ok();

    // Set up a dedicated stack for double fault handling (IST1)
    // This ensures the double fault handler has a known-good stack even if
    // the main stack is corrupted (e.g., during failed privilege transitions)
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Setting up IST for double fault...").ok();
    let ist1_stack_base = VirtAddr::new(0xFFFFFE8000020000); // Separate from kernel stack
    // Allocate 4 pages (16KB) - must be enough for exception frame + handler execution
    for i in 0..4 {
        let frame = memory::frame::allocate_frame().expect("Failed to allocate IST1 stack");
        let page_virt = VirtAddr::new(ist1_stack_base.as_u64() + (i * 0x1000) as u64);
        memory::paging::map_4kb(page_virt, frame.start_address(), memory::paging::flags::KERNEL_DATA)
            .expect("Failed to map IST1 stack");
    }
    let ist1_stack_top = ist1_stack_base.as_u64() + 0x4000; // 16KB stack
    arch::x86_64::gdt::set_ist(1, ist1_stack_top);
    arch::x86_64::interrupts::set_double_fault_ist(1);
    writeln!(serial, "    IST1 (double fault) stack at {:#x}", ist1_stack_top).ok();

    // Remove identity mapping - no longer needed now that we're in higher-half
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Removing identity mapping...").ok();
    memory::paging::remove_identity_mapping();

    // Verify PML4[0] is now empty
    let pml4_0 = memory::paging::read_pml4(0);
    if pml4_0.is_present() {
        writeln!(serial, "    WARNING: PML4[0] still present!").ok();
    } else {
        writeln!(serial, "    Identity mapping removed (PML4[0] cleared)").ok();
    }

    // Test user-mode execution
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Testing user-mode execution...").ok();

    // Create a new process for user mode test
    let user_pid = process::create().expect("Failed to create user process");
    writeln!(serial, "    Created user process {}", user_pid).ok();

    // Get the process's page table for mapping user pages
    let user_process = process::get(user_pid).unwrap();
    writeln!(serial, "    Process page table: {:#x}", user_process.page_table).ok();

    // Allocate frames for user code and stack
    let user_code_frame = memory::frame::allocate_frame().expect("Failed to allocate user code frame");
    let user_stack_frame = memory::frame::allocate_frame().expect("Failed to allocate user stack frame");

    // User virtual addresses (in low memory, user-accessible)
    let user_code_virt = VirtAddr::new(0x400000);   // 4MB - typical user code location
    let user_stack_virt = VirtAddr::new(0x800000);  // 8MB - user stack base

    // First switch to the user process's address space to set up its mappings
    unsafe { process::switch_address_space(user_pid).expect("Failed to switch to user address space"); }

    // Verify kernel stacks are accessible in user address space
    // (They should be, since we copy kernel PML4 entries during process creation)
    writeln!(serial, "    Verifying kernel stack mappings...").ok();
    if let Some(phys) = memory::paging::translate(VirtAddr::new(kernel_stack_top - 8)) {
        writeln!(serial, "      Kernel stack: {:#x} -> {:#x}", kernel_stack_top - 8, phys).ok();
    } else {
        panic!("Kernel stack not mapped in user address space!");
    }
    if let Some(phys) = memory::paging::translate(VirtAddr::new(ist1_stack_top - 8)) {
        writeln!(serial, "      IST1 stack: {:#x} -> {:#x}", ist1_stack_top - 8, phys).ok();
    } else {
        panic!("IST1 stack not mapped in user address space!");
    }

    // Map user code page (readable, executable, user-accessible)
    memory::paging::map_4kb(user_code_virt, user_code_frame.start_address(), memory::paging::flags::USER_CODE)
        .expect("Failed to map user code");
    writeln!(serial, "    Mapped user code at {:#x}", user_code_virt).ok();

    // Map user stack page (readable, writable, user-accessible)
    memory::paging::map_4kb(user_stack_virt, user_stack_frame.start_address(), memory::paging::flags::USER_DATA)
        .expect("Failed to map user stack");
    writeln!(serial, "    Mapped user stack at {:#x}", user_stack_virt).ok();

    // Write a simple user program that:
    // 1. Calls write(1, "Hello from user mode!\n", 22)
    // 2. Calls exit(0)
    // Uses native SYSCALL instruction (0x0f 0x05) instead of int 0x80
    let user_code_ptr = user_code_virt.as_u64() as *mut u8;
    let message = b"Hello from user mode!\n";
    let message_offset = 64u64; // Place message after code

    unsafe {
        let code: &[u8] = &[
            // mov rax, 1 (WRITE syscall)
            0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
            // mov rdi, 1 (fd = stdout)
            0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
            // mov rsi, message_address (code_base + 64)
            0x48, 0xbe,
            ((user_code_virt.as_u64() + message_offset) & 0xFF) as u8,
            (((user_code_virt.as_u64() + message_offset) >> 8) & 0xFF) as u8,
            (((user_code_virt.as_u64() + message_offset) >> 16) & 0xFF) as u8,
            (((user_code_virt.as_u64() + message_offset) >> 24) & 0xFF) as u8,
            (((user_code_virt.as_u64() + message_offset) >> 32) & 0xFF) as u8,
            (((user_code_virt.as_u64() + message_offset) >> 40) & 0xFF) as u8,
            (((user_code_virt.as_u64() + message_offset) >> 48) & 0xFF) as u8,
            (((user_code_virt.as_u64() + message_offset) >> 56) & 0xFF) as u8,
            // mov rdx, 22 (length)
            0x48, 0xc7, 0xc2, 0x16, 0x00, 0x00, 0x00,
            // syscall
            0x0f, 0x05,
            // mov rax, 0 (EXIT syscall)
            0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,
            // mov rdi, 0 (exit code)
            0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00,
            // syscall
            0x0f, 0x05,
            // hlt (should never reach here)
            0xf4,
        ];

        // Write the code
        for (i, &byte) in code.iter().enumerate() {
            core::ptr::write_volatile(user_code_ptr.add(i), byte);
        }

        // Write the message after the code
        let message_ptr = user_code_ptr.add(message_offset as usize);
        for (i, &byte) in message.iter().enumerate() {
            core::ptr::write_volatile(message_ptr.add(i), byte);
        }
    }
    writeln!(serial, "    Wrote user program ({} bytes code + {} bytes data)", 52, message.len()).ok();

    // User stack pointer (top of stack page)
    let user_stack_top = user_stack_virt.as_u64() + 0x1000;

    // First, let's test that user mode works by running code in kernel
    // that verifies the segments are correct
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Testing IRETQ mechanism with kernel mode...").ok();

    // Test: Do a simple kernel-to-kernel IRETQ to verify the mechanism
    unsafe {
        core::arch::asm!(
            // Push a simple return frame for kernel mode
            "push 0x10",        // SS (kernel data)
            "push rsp",         // RSP (current stack)
            "add qword ptr [rsp], 8",  // Adjust for the push
            "pushfq",           // RFLAGS
            "push 0x08",        // CS (kernel code)
            "lea rax, [rip + 2f]",  // RIP (label 2)
            "push rax",
            "iretq",
            "2:",
            out("rax") _,
            options(nostack)
        );
    }
    writeln!(serial, "    Kernel IRETQ test passed!").ok();

    // Debug: Print the GDT segment descriptor values
    writeln!(serial, "").ok();
    writeln!(serial, ">>> Verifying GDT entries...").ok();
    let user_cs = arch::x86_64::gdt::user_cs();
    let user_ds = arch::x86_64::gdt::user_ds();
    writeln!(serial, "    USER_CS selector: {:#x}", user_cs).ok();
    writeln!(serial, "    USER_DS selector: {:#x}", user_ds).ok();

    // Test loading user data segment while in kernel mode
    // This should work: loading DPL=3 segment with RPL=3 while CPL=0
    writeln!(serial, "    Testing user segment load in kernel mode...").ok();
    unsafe {
        core::arch::asm!(
            "mov ax, {0:x}",
            "mov ds, ax",      // This might fail with GPF if segment is invalid
            "mov ax, 0x10",    // Restore kernel data segment
            "mov ds, ax",
            in(reg) user_ds as u64,
            out("rax") _,
            options(nostack, preserves_flags)
        );
    }
    writeln!(serial, "    User segment load test passed!").ok();

    writeln!(serial, "").ok();
    writeln!(serial, ">>> Jumping to user mode (ring 3)...").ok();
    writeln!(serial, "    Entry: {:#x}, Stack: {:#x}", user_code_virt, user_stack_top).ok();

    // Jump to user mode! (This won't return)
    unsafe {
        process::jump_to_user(user_code_virt.as_u64(), user_stack_top);
    }
}

/// Example function demonstrating testable kernel logic
pub fn add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn test_add_overflow() {
        assert_eq!(add(u64::MAX, 1), 0);
    }

    #[test]
    fn test_version_exists() {
        assert!(!VERSION.is_empty());
    }
}
