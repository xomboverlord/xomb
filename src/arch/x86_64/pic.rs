//! 8259 Programmable Interrupt Controller (PIC) driver
//!
//! The legacy PIC must be properly configured even if we plan to use the APIC,
//! because its default IRQ mappings (0x08-0x0F, 0x70-0x77) conflict with CPU
//! exception vectors:
//!
//! - IRQ0 (Timer) -> Vector 0x08 (Double Fault!)
//! - IRQ1 (Keyboard) -> Vector 0x09
//! - IRQ7 (Spurious) -> Vector 0x0F
//!
//! This module remaps the PICs to vectors 0x20-0x2F and provides control
//! over interrupt masking.

use core::arch::asm;

/// PIC1 (master) command port
const PIC1_CMD: u16 = 0x20;
/// PIC1 (master) data port
const PIC1_DATA: u16 = 0x21;
/// PIC2 (slave) command port
const PIC2_CMD: u16 = 0xA0;
/// PIC2 (slave) data port
const PIC2_DATA: u16 = 0xA1;

/// ICW1: Initialization Command Word 1
const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01; // ICW4 needed

/// ICW4: Initialization Command Word 4
const ICW4_8086: u8 = 0x01; // 8086/88 mode

/// Vector offset for PIC1 IRQs (IRQ0-7 -> vectors 0x20-0x27)
pub const PIC1_OFFSET: u8 = 0x20;
/// Vector offset for PIC2 IRQs (IRQ8-15 -> vectors 0x28-0x2F)
pub const PIC2_OFFSET: u8 = 0x28;

/// IRQ numbers
pub mod irq {
    pub const TIMER: u8 = 0;
    pub const KEYBOARD: u8 = 1;
    pub const CASCADE: u8 = 2; // Used internally for PIC1-PIC2 cascade
    pub const COM2: u8 = 3;
    pub const COM1: u8 = 4;
    pub const LPT2: u8 = 5;
    pub const FLOPPY: u8 = 6;
    pub const LPT1: u8 = 7; // Also spurious IRQ
    pub const RTC: u8 = 8;
    pub const FREE1: u8 = 9;
    pub const FREE2: u8 = 10;
    pub const FREE3: u8 = 11;
    pub const MOUSE: u8 = 12;
    pub const FPU: u8 = 13;
    pub const ATA_PRIMARY: u8 = 14;
    pub const ATA_SECONDARY: u8 = 15;
}

/// Write a byte to an I/O port
#[inline]
unsafe fn outb(port: u16, value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nostack, nomem, preserves_flags)
        );
    }
}

/// Read a byte from an I/O port
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!(
            "in al, dx",
            in("dx") port,
            out("al") value,
            options(nostack, nomem, preserves_flags)
        );
    }
    value
}

/// Small I/O delay for PIC timing requirements
#[inline]
unsafe fn io_wait() {
    // Write to an unused port to create a small delay
    // Port 0x80 is used for POST codes and is safe to write to
    unsafe { outb(0x80, 0); }
}

/// Initialize and remap both PICs
///
/// This remaps:
/// - PIC1 (IRQ 0-7) to vectors 0x20-0x27
/// - PIC2 (IRQ 8-15) to vectors 0x28-0x2F
///
/// After initialization, all IRQs are masked (disabled).
pub fn init() {
    unsafe {
        // Save current masks
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        // ICW1: Start initialization sequence (cascade mode, ICW4 needed)
        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        // ICW2: Set vector offsets
        outb(PIC1_DATA, PIC1_OFFSET);
        io_wait();
        outb(PIC2_DATA, PIC2_OFFSET);
        io_wait();

        // ICW3: Configure cascade
        // Tell PIC1 that PIC2 is at IRQ2 (bit 2 = 0x04)
        outb(PIC1_DATA, 0x04);
        io_wait();
        // Tell PIC2 its cascade identity (IRQ2 = 2)
        outb(PIC2_DATA, 0x02);
        io_wait();

        // ICW4: Set 8086 mode
        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        // Mask all interrupts (we'll unmask specific ones as needed)
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);

        // Note: We intentionally mask all interrupts rather than restoring
        // the old masks, since we want to start with a clean slate
        let _ = (mask1, mask2); // Suppress unused warning
    }
}

/// Disable the PIC entirely by masking all interrupts
///
/// This is useful when transitioning to APIC mode.
pub fn disable() {
    unsafe {
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

/// Mask (disable) a specific IRQ
pub fn mask_irq(irq: u8) {
    let port = if irq < 8 { PIC1_DATA } else { PIC2_DATA };
    let irq_bit = if irq < 8 { irq } else { irq - 8 };

    unsafe {
        let mask = inb(port) | (1 << irq_bit);
        outb(port, mask);
    }
}

/// Unmask (enable) a specific IRQ
pub fn unmask_irq(irq: u8) {
    let port = if irq < 8 { PIC1_DATA } else { PIC2_DATA };
    let irq_bit = if irq < 8 { irq } else { irq - 8 };

    unsafe {
        let mask = inb(port) & !(1 << irq_bit);
        outb(port, mask);
    }

    // If unmasking an IRQ on PIC2, also unmask the cascade IRQ on PIC1
    if irq >= 8 {
        unsafe {
            let mask = inb(PIC1_DATA) & !(1 << irq::CASCADE);
            outb(PIC1_DATA, mask);
        }
    }
}

/// Send End-Of-Interrupt (EOI) signal
///
/// This must be called at the end of an IRQ handler to acknowledge
/// the interrupt and allow further interrupts.
pub fn send_eoi(irq: u8) {
    const EOI: u8 = 0x20;

    unsafe {
        // If IRQ came from PIC2, send EOI to both PICs
        if irq >= 8 {
            outb(PIC2_CMD, EOI);
        }
        outb(PIC1_CMD, EOI);
    }
}

/// Check if an IRQ is a spurious IRQ
///
/// Spurious IRQs (IRQ7 or IRQ15) can occur due to electrical noise
/// or race conditions. They should be checked before handling.
pub fn is_spurious(irq: u8) -> bool {
    const ISR_READ: u8 = 0x0B;

    if irq == 7 {
        // Check PIC1's In-Service Register
        unsafe {
            outb(PIC1_CMD, ISR_READ);
            let isr = inb(PIC1_CMD);
            // If bit 7 is not set, it's spurious
            return (isr & 0x80) == 0;
        }
    } else if irq == 15 {
        // Check PIC2's In-Service Register
        unsafe {
            outb(PIC2_CMD, ISR_READ);
            let isr = inb(PIC2_CMD);
            // If bit 7 is not set, it's spurious
            if (isr & 0x80) == 0 {
                // Still need to send EOI to PIC1 (for cascade)
                outb(PIC1_CMD, 0x20);
                return true;
            }
        }
    }
    false
}

/// Get the current IRQ mask for both PICs
pub fn get_mask() -> u16 {
    unsafe {
        let mask1 = inb(PIC1_DATA) as u16;
        let mask2 = inb(PIC2_DATA) as u16;
        mask1 | (mask2 << 8)
    }
}

/// Set the IRQ mask for both PICs
pub fn set_mask(mask: u16) {
    unsafe {
        outb(PIC1_DATA, mask as u8);
        outb(PIC2_DATA, (mask >> 8) as u8);
    }
}
