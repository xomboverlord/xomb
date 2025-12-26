//! XOmB - A Rust-based exokernel
//!
//! This library contains the core kernel logic that can be unit-tested
//! on the host system without requiring an emulator.

#![no_std]

// When testing on host, we need std
#[cfg(test)]
extern crate std;

// Re-export alloc for heap allocations (available after boot services)
#[cfg(any(feature = "uefi", test))]
extern crate alloc;

pub mod arch;
pub mod boot_info;
pub mod memory;
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

    writeln!(serial, "").ok();
    writeln!(serial, ">>> Entering kernel_init()").ok();
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

    writeln!(serial, "").ok();
    writeln!(serial, "Kernel initialization complete.").ok();
    writeln!(serial, "Halting CPU.").ok();

    // Halt the CPU
    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nostack, nomem));
        }
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
