//! Serial port driver for debugging output
//!
//! Provides a simple UART driver for COM1 (0x3F8) that works
//! both during UEFI boot and after ExitBootServices.

use core::fmt::{self, Write};

/// Standard PC serial port (8250/16550 UART)
pub struct SerialPort {
    port: u16,
}

impl SerialPort {
    /// Create a new serial port instance
    ///
    /// # Safety
    /// The caller must ensure the port address is valid and not in use.
    pub const unsafe fn new(port: u16) -> Self {
        Self { port }
    }

    /// Initialize the serial port with standard settings
    /// 115200 baud, 8N1
    pub fn init(&mut self) {
        unsafe {
            // Disable interrupts
            self.outb(self.port + 1, 0x00);

            // Enable DLAB (set baud rate divisor)
            self.outb(self.port + 3, 0x80);

            // Set divisor to 1 (115200 baud)
            self.outb(self.port + 0, 0x01); // Low byte
            self.outb(self.port + 1, 0x00); // High byte

            // 8 bits, no parity, one stop bit (8N1)
            self.outb(self.port + 3, 0x03);

            // Enable FIFO, clear them, with 14-byte threshold
            self.outb(self.port + 2, 0xC7);

            // Enable IRQs, RTS/DSR set
            self.outb(self.port + 4, 0x0B);

            // Set in loopback mode, test the serial chip
            self.outb(self.port + 4, 0x1E);

            // Test serial chip (send byte 0xAE and check if it returns same byte)
            self.outb(self.port + 0, 0xAE);

            // Check if serial is faulty (i.e., not the same byte as sent)
            if self.inb(self.port + 0) != 0xAE {
                return; // Serial port is faulty, but we continue anyway
            }

            // If serial is not faulty, set it in normal operation mode
            // (not loopback, IRQs enabled, OUT#1 and OUT#2 bits enabled)
            self.outb(self.port + 4, 0x0F);
        }
    }

    /// Check if the transmit buffer is empty
    fn is_transmit_empty(&self) -> bool {
        unsafe { self.inb(self.port + 5) & 0x20 != 0 }
    }

    /// Write a single byte to the serial port
    pub fn write_byte(&mut self, byte: u8) {
        // Wait for transmit buffer to be empty
        while !self.is_transmit_empty() {
            core::hint::spin_loop();
        }

        unsafe {
            self.outb(self.port, byte);
        }
    }

    /// Read a single byte from the serial port (blocking)
    pub fn read_byte(&self) -> u8 {
        // Wait for data to be available
        while !self.has_data() {
            core::hint::spin_loop();
        }

        unsafe { self.inb(self.port) }
    }

    /// Check if data is available to read
    pub fn has_data(&self) -> bool {
        unsafe { self.inb(self.port + 5) & 0x01 != 0 }
    }

    /// Try to read a byte without blocking
    pub fn try_read_byte(&self) -> Option<u8> {
        if self.has_data() {
            Some(unsafe { self.inb(self.port) })
        } else {
            None
        }
    }

    #[inline]
    unsafe fn outb(&self, port: u16, val: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
        }
    }

    #[inline]
    unsafe fn inb(&self, port: u16) -> u8 {
        let ret: u8;
        unsafe {
            core::arch::asm!("in al, dx", out("al") ret, in("dx") port, options(nostack, preserves_flags));
        }
        ret
    }
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Global serial port instance for debug logging
///
/// # Safety
/// This is safe to use from a single thread or with proper synchronization.
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut serial = unsafe { $crate::serial::SerialPort::new(0x3F8) };
        write!(serial, $($arg)*).ok();
    }};
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => {{
        $crate::serial_print!($($arg)*);
        $crate::serial_print!("\n");
    }};
}

#[cfg(test)]
mod tests {
    // Serial port tests would require mocking the I/O ports
    // These are better suited for integration tests in the emulator

    #[test]
    fn test_serial_port_creation() {
        // Just verify the struct can be created
        let _port = unsafe { super::SerialPort::new(0x3F8) };
    }
}
