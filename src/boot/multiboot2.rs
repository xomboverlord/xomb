//! Multiboot2 Boot Entry Point for XOmB
//!
//! This module handles the kernel entry when booted via a multiboot2-compliant
//! bootloader (e.g., GRUB). It parses the multiboot2 information structure and
//! initializes the kernel.

use core::fmt::Write;
use crate::serial::SerialPort;
use crate::{VERSION, NAME};
use crate::boot_info::{BootInfo, BootMethod, MemoryRegionType, FramebufferInfo, FramebufferType};

/// Multiboot2 magic number (passed in eax by bootloader)
pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36d76289;

/// Multiboot2 tag types
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagType {
    End = 0,
    Cmdline = 1,
    BootLoaderName = 2,
    Module = 3,
    BasicMeminfo = 4,
    Bootdev = 5,
    Mmap = 6,
    Vbe = 7,
    Framebuffer = 8,
    ElfSections = 9,
    Apm = 10,
    Efi32 = 11,
    Efi64 = 12,
    Smbios = 13,
    AcpiOld = 14,
    AcpiNew = 15,
    Network = 16,
    EfiMmap = 17,
    EfiBs = 18,
    Efi32Ih = 19,
    Efi64Ih = 20,
    LoadBaseAddr = 21,
}

/// Multiboot2 information header
#[repr(C)]
pub struct Mb2BootInfo {
    pub total_size: u32,
    pub reserved: u32,
    // Tags follow...
}

/// Multiboot2 tag header
#[repr(C)]
pub struct Tag {
    pub typ: u32,
    pub size: u32,
    // Tag-specific data follows...
}

/// Basic memory information tag
#[repr(C)]
pub struct BasicMeminfoTag {
    pub typ: u32,
    pub size: u32,
    pub mem_lower: u32,  // KB of lower memory (starting at 0)
    pub mem_upper: u32,  // KB of upper memory (starting at 1MB)
}

/// Memory map tag
#[repr(C)]
pub struct MmapTag {
    pub typ: u32,
    pub size: u32,
    pub entry_size: u32,
    pub entry_version: u32,
    // Entries follow...
}

/// Memory map entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MmapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub typ: u32,
    pub reserved: u32,
}

impl MmapEntry {
    pub fn is_usable(&self) -> bool {
        self.typ == 1  // Type 1 = available RAM
    }

    /// Convert multiboot2 memory type to our unified MemoryRegionType
    pub fn to_region_type(&self) -> MemoryRegionType {
        match self.typ {
            1 => MemoryRegionType::Usable,
            2 => MemoryRegionType::Reserved,
            3 => MemoryRegionType::AcpiReclaimable,
            4 => MemoryRegionType::AcpiNvs,
            5 => MemoryRegionType::BadMemory,
            other => MemoryRegionType::Unknown(other),
        }
    }
}

/// Framebuffer tag
#[repr(C)]
pub struct FramebufferTag {
    pub typ: u32,
    pub size: u32,
    pub addr: u64,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub fb_type: u8,
    pub reserved: u16,
}

/// ACPI old RSDP tag (version 1.0)
#[repr(C)]
pub struct AcpiOldTag {
    pub typ: u32,
    pub size: u32,
    // RSDP structure follows (20 bytes for v1)
}

/// ACPI new RSDP tag (version 2.0+)
#[repr(C)]
pub struct AcpiNewTag {
    pub typ: u32,
    pub size: u32,
    // RSDP structure follows (36 bytes for v2)
}

/// Multiboot2 entry point - called from assembly
///
/// # Safety
/// This function is called directly from assembly with raw pointers.
#[unsafe(no_mangle)]
pub extern "C" fn multiboot2_entry(info_ptr: *const Mb2BootInfo, magic: u32) -> ! {
    // Initialize serial port for debug output
    let mut serial = unsafe { SerialPort::new(0x3F8) };
    serial.init();

    writeln!(serial, "").ok();
    writeln!(serial, "================================").ok();
    writeln!(serial, "  {} v{}", NAME, VERSION).ok();
    writeln!(serial, "  Multiboot2 Boot").ok();
    writeln!(serial, "================================").ok();
    writeln!(serial, "").ok();

    // Verify multiboot2 magic
    if magic != MULTIBOOT2_BOOTLOADER_MAGIC {
        writeln!(serial, "ERROR: Invalid multiboot2 magic: {:#x}", magic).ok();
        writeln!(serial, "       Expected: {:#x}", MULTIBOOT2_BOOTLOADER_MAGIC).ok();
        halt();
    }

    writeln!(serial, "Multiboot2 magic verified: {:#x}", magic).ok();
    writeln!(serial, "Boot info at: {:p}", info_ptr).ok();

    // Create unified boot info structure
    let mut boot_info = BootInfo::new(BootMethod::Multiboot2);

    // Set kernel addresses (from linker script)
    boot_info.kernel_physical_base = 0x100000; // Standard multiboot load address
    boot_info.kernel_virtual_base = 0xFFFFFFFF80000000; // Higher-half mapping

    // Parse boot information
    if !info_ptr.is_null() {
        let info = unsafe { &*info_ptr };
        writeln!(serial, "Boot info size: {} bytes", info.total_size).ok();

        // Iterate through tags
        let mut tag_ptr = unsafe { (info_ptr as *const u8).add(8) } as *const Tag;
        let end_ptr = unsafe { (info_ptr as *const u8).add(info.total_size as usize) };

        while (tag_ptr as *const u8) < end_ptr {
            let tag = unsafe { &*tag_ptr };

            if tag.typ == TagType::End as u32 {
                break;
            }

            match tag.typ {
                typ if typ == TagType::BasicMeminfo as u32 => {
                    let meminfo = unsafe { &*(tag_ptr as *const BasicMeminfoTag) };
                    writeln!(serial, "Basic memory: lower={}KB, upper={}KB",
                             meminfo.mem_lower, meminfo.mem_upper).ok();
                }
                typ if typ == TagType::Mmap as u32 => {
                    let mmap = unsafe { &*(tag_ptr as *const MmapTag) };
                    writeln!(serial, "Memory map (entry_size={}):", mmap.entry_size).ok();

                    let entries_start = unsafe { (tag_ptr as *const u8).add(16) };
                    let entries_end = unsafe { (tag_ptr as *const u8).add(mmap.size as usize) };
                    let mut entry_ptr = entries_start;

                    while entry_ptr < entries_end {
                        let entry = unsafe { &*(entry_ptr as *const MmapEntry) };
                        let type_str = match entry.typ {
                            1 => "Available",
                            2 => "Reserved",
                            3 => "ACPI Reclaimable",
                            4 => "ACPI NVS",
                            5 => "Bad Memory",
                            _ => "Unknown",
                        };
                        writeln!(serial, "  {:#016x} - {:#016x} ({} bytes) {}",
                                 entry.base_addr,
                                 entry.base_addr + entry.length,
                                 entry.length,
                                 type_str).ok();

                        // Add to unified memory map
                        boot_info.memory_map.add(
                            entry.base_addr,
                            entry.length,
                            entry.to_region_type(),
                        );

                        entry_ptr = unsafe { entry_ptr.add(mmap.entry_size as usize) };
                    }
                }
                typ if typ == TagType::BootLoaderName as u32 => {
                    let name_ptr = unsafe { (tag_ptr as *const u8).add(8) };
                    let mut len = 0;
                    while unsafe { *name_ptr.add(len) } != 0 && len < 256 {
                        len += 1;
                    }
                    let name = unsafe {
                        core::str::from_utf8_unchecked(core::slice::from_raw_parts(name_ptr, len))
                    };
                    writeln!(serial, "Bootloader: {}", name).ok();
                }
                typ if typ == TagType::Cmdline as u32 => {
                    let cmdline_ptr = unsafe { (tag_ptr as *const u8).add(8) };
                    let mut len = 0;
                    while unsafe { *cmdline_ptr.add(len) } != 0 && len < 256 {
                        len += 1;
                    }
                    let cmdline = unsafe {
                        core::slice::from_raw_parts(cmdline_ptr, len)
                    };
                    boot_info.set_cmdline(cmdline);
                    writeln!(serial, "Command line: {}", boot_info.cmdline_str()).ok();
                }
                typ if typ == TagType::Framebuffer as u32 => {
                    let fb = unsafe { &*(tag_ptr as *const FramebufferTag) };
                    boot_info.framebuffer = FramebufferInfo {
                        address: fb.addr,
                        width: fb.width,
                        height: fb.height,
                        pitch: fb.pitch,
                        bpp: fb.bpp,
                        fb_type: match fb.fb_type {
                            0 => FramebufferType::Indexed,
                            1 => FramebufferType::Rgb,
                            2 => FramebufferType::EgaText,
                            _ => FramebufferType::Unknown,
                        },
                    };
                    writeln!(serial, "Framebuffer: {}x{} @ {:#x} ({}bpp)",
                             fb.width, fb.height, fb.addr, fb.bpp).ok();
                }
                typ if typ == TagType::AcpiOld as u32 => {
                    // RSDP v1 starts at offset 8
                    let rsdp_addr = unsafe { (tag_ptr as *const u8).add(8) } as u64;
                    boot_info.acpi.rsdp = rsdp_addr;
                    writeln!(serial, "ACPI RSDP v1 at: {:#x}", rsdp_addr).ok();
                }
                typ if typ == TagType::AcpiNew as u32 => {
                    // RSDP v2 starts at offset 8
                    let rsdp_addr = unsafe { (tag_ptr as *const u8).add(8) } as u64;
                    boot_info.acpi.rsdp_v2 = rsdp_addr;
                    if boot_info.acpi.rsdp == 0 {
                        boot_info.acpi.rsdp = rsdp_addr;
                    }
                    writeln!(serial, "ACPI RSDP v2 at: {:#x}", rsdp_addr).ok();
                }
                _ => {
                    // Skip unknown tags
                }
            }

            // Move to next tag (8-byte aligned)
            let next_offset = ((tag.size + 7) & !7) as usize;
            tag_ptr = unsafe { (tag_ptr as *const u8).add(next_offset) } as *const Tag;
        }
    }

    let total_memory = boot_info.memory_map.total_usable_memory();
    writeln!(serial, "").ok();
    writeln!(serial, "Total usable memory: {} MB", total_memory / (1024 * 1024)).ok();
    writeln!(serial, "").ok();

    // Transition to common kernel entry point
    crate::kernel_init(&boot_info)
}

/// Halt the CPU
fn halt() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli; hlt", options(nostack, nomem));
        }
    }
}
