//! XOmB Multiboot2 Entry Point
//!
//! This is the Rust entry point for multiboot2 boot (used by Bochs/GRUB).
//! The actual entry is in assembly (boot/multiboot2_header.s), which then
//! calls into this code.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::fmt::Write;

// Re-export the library
use xomb::serial::SerialPort;

// Pull in the multiboot2 entry point
pub use xomb::boot::multiboot2::multiboot2_entry;

/// Panic handler for multiboot2 boot
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let mut serial = unsafe { SerialPort::new(0x3F8) };
    let _ = writeln!(serial, "\n!!! KERNEL PANIC !!!");
    let _ = writeln!(serial, "{}", info);

    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nostack, nomem));
        }
    }
}
