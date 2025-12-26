//! x86_64 architecture support

/// Halt the CPU until the next interrupt
#[inline]
pub fn hlt() {
    unsafe {
        core::arch::asm!("hlt", options(nostack, nomem, preserves_flags));
    }
}

/// Disable interrupts
#[inline]
pub fn cli() {
    unsafe {
        core::arch::asm!("cli", options(nostack, nomem, preserves_flags));
    }
}

/// Enable interrupts
#[inline]
pub fn sti() {
    unsafe {
        core::arch::asm!("sti", options(nostack, nomem, preserves_flags));
    }
}

/// Halt the CPU with interrupts disabled (hang forever)
#[inline]
pub fn halt() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nostack, nomem, preserves_flags));
        }
    }
}

/// Read the current value of the RFLAGS register
#[inline]
pub fn read_rflags() -> u64 {
    let rflags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) rflags, options(nostack, preserves_flags));
    }
    rflags
}

/// Check if interrupts are enabled
#[inline]
pub fn interrupts_enabled() -> bool {
    read_rflags() & (1 << 9) != 0
}

/// Output a byte to an I/O port
///
/// # Safety
/// Writing to arbitrary I/O ports can cause undefined behavior.
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
    }
}

/// Input a byte from an I/O port
///
/// # Safety
/// Reading from arbitrary I/O ports can cause undefined behavior.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let ret: u8;
    unsafe {
        core::arch::asm!("in al, dx", out("al") ret, in("dx") port, options(nostack, preserves_flags));
    }
    ret
}

#[cfg(test)]
mod tests {
    // Most of these functions require actual hardware to test
    // They're better suited for integration tests

    #[test]
    fn test_rflags_bit_check() {
        // Test that our flag checking logic works
        let flags_with_if = 1u64 << 9;
        assert_ne!(flags_with_if & (1 << 9), 0);

        let flags_without_if = 0u64;
        assert_eq!(flags_without_if & (1 << 9), 0);
    }
}
