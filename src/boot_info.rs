//! Unified Boot Information
//!
//! This module provides a boot-method-agnostic representation of the
//! information passed from the bootloader to the kernel. Both UEFI and
//! Multiboot2 paths populate this structure before calling kernel_init().

/// Maximum number of memory map entries we support
pub const MAX_MEMORY_REGIONS: usize = 64;

/// Maximum command line length
pub const MAX_CMDLINE_LEN: usize = 256;

/// Boot method used to start the kernel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMethod {
    /// Booted via UEFI firmware
    Uefi,
    /// Booted via Multiboot2-compliant bootloader (e.g., GRUB)
    Multiboot2,
}

/// Memory region type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// Usable RAM - available for kernel use
    Usable,
    /// Reserved by firmware or hardware
    Reserved,
    /// ACPI tables - can be reclaimed after parsing
    AcpiReclaimable,
    /// ACPI Non-Volatile Storage
    AcpiNvs,
    /// Bad/defective memory
    BadMemory,
    /// Bootloader code/data - can be reclaimed
    BootloaderReclaimable,
    /// Kernel code and data
    KernelAndModules,
    /// Framebuffer memory
    Framebuffer,
    /// Unknown/other type
    Unknown(u32),
}

/// A single memory region
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Physical base address
    pub base: u64,
    /// Length in bytes
    pub length: u64,
    /// Region type
    pub region_type: MemoryRegionType,
}

impl MemoryRegion {
    pub const fn empty() -> Self {
        Self {
            base: 0,
            length: 0,
            region_type: MemoryRegionType::Reserved,
        }
    }

    /// Returns true if this region contains usable RAM
    pub fn is_usable(&self) -> bool {
        matches!(self.region_type, MemoryRegionType::Usable)
    }
}

/// Memory map containing all memory regions
#[derive(Debug, Clone, Copy)]
pub struct MemoryMap {
    /// Memory regions (unused entries have length 0)
    pub regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    /// Number of valid entries
    pub count: usize,
}

impl MemoryMap {
    pub const fn empty() -> Self {
        Self {
            regions: [MemoryRegion::empty(); MAX_MEMORY_REGIONS],
            count: 0,
        }
    }

    /// Add a memory region to the map
    pub fn add(&mut self, base: u64, length: u64, region_type: MemoryRegionType) -> bool {
        if self.count >= MAX_MEMORY_REGIONS {
            return false;
        }
        self.regions[self.count] = MemoryRegion {
            base,
            length,
            region_type,
        };
        self.count += 1;
        true
    }

    /// Get an iterator over valid memory regions
    pub fn iter(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions[..self.count].iter()
    }

    /// Calculate total usable memory in bytes
    pub fn total_usable_memory(&self) -> u64 {
        self.iter()
            .filter(|r| r.is_usable())
            .map(|r| r.length)
            .sum()
    }
}

/// Framebuffer information (if available)
#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    /// Physical address of framebuffer
    pub address: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per scanline (pitch)
    pub pitch: u32,
    /// Bits per pixel
    pub bpp: u8,
    /// Framebuffer type (RGB, indexed, etc.)
    pub fb_type: FramebufferType,
}

impl FramebufferInfo {
    pub const fn none() -> Self {
        Self {
            address: 0,
            width: 0,
            height: 0,
            pitch: 0,
            bpp: 0,
            fb_type: FramebufferType::Unknown,
        }
    }

    pub fn is_available(&self) -> bool {
        self.address != 0 && self.width > 0 && self.height > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramebufferType {
    /// Indexed color (palette-based)
    Indexed,
    /// Direct RGB color
    Rgb,
    /// EGA text mode
    EgaText,
    /// Unknown type
    Unknown,
}

/// ACPI information
#[derive(Debug, Clone, Copy)]
pub struct AcpiInfo {
    /// RSDP (Root System Description Pointer) address
    /// This is the ACPI 1.0 RSDP if rsdp_v2 is 0, or ACPI 2.0+ RSDP otherwise
    pub rsdp: u64,
    /// ACPI 2.0+ extended RSDP address (0 if not available)
    pub rsdp_v2: u64,
}

impl AcpiInfo {
    pub const fn none() -> Self {
        Self {
            rsdp: 0,
            rsdp_v2: 0,
        }
    }

    pub fn is_available(&self) -> bool {
        self.rsdp != 0 || self.rsdp_v2 != 0
    }
}

/// Unified boot information structure
///
/// This structure is populated by the boot path (UEFI or Multiboot2) and
/// passed to kernel_init(). It provides a common interface regardless of
/// how the kernel was booted.
#[derive(Debug, Clone, Copy)]
pub struct BootInfo {
    /// How the kernel was booted
    pub boot_method: BootMethod,

    /// Memory map
    pub memory_map: MemoryMap,

    /// Framebuffer information (if available)
    pub framebuffer: FramebufferInfo,

    /// ACPI information
    pub acpi: AcpiInfo,

    /// Command line (null-terminated, may be empty)
    pub cmdline: [u8; MAX_CMDLINE_LEN],
    /// Length of command line (not including null terminator)
    pub cmdline_len: usize,

    /// Physical address where kernel is loaded
    pub kernel_physical_base: u64,

    /// Virtual address where kernel is mapped (for higher-half kernels)
    pub kernel_virtual_base: u64,
}

impl BootInfo {
    /// Create an empty BootInfo with the specified boot method
    pub const fn new(boot_method: BootMethod) -> Self {
        Self {
            boot_method,
            memory_map: MemoryMap::empty(),
            framebuffer: FramebufferInfo::none(),
            acpi: AcpiInfo::none(),
            cmdline: [0u8; MAX_CMDLINE_LEN],
            cmdline_len: 0,
            kernel_physical_base: 0,
            kernel_virtual_base: 0,
        }
    }

    /// Set the command line
    pub fn set_cmdline(&mut self, cmdline: &[u8]) {
        let len = cmdline.len().min(MAX_CMDLINE_LEN - 1);
        self.cmdline[..len].copy_from_slice(&cmdline[..len]);
        self.cmdline[len] = 0; // Null terminate
        self.cmdline_len = len;
    }

    /// Get the command line as a string slice
    pub fn cmdline_str(&self) -> &str {
        // Safety: we only store valid UTF-8 from bootloader strings
        unsafe {
            core::str::from_utf8_unchecked(&self.cmdline[..self.cmdline_len])
        }
    }
}
