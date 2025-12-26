//! XOmB UEFI Entry Point
//!
//! This is the UEFI application entry point. It initializes the kernel
//! environment, collects boot information, exits boot services, and
//! transfers control to the common kernel_init().

#![no_std]
#![no_main]

extern crate alloc;

use core::fmt::Write;
use uefi::prelude::*;
use uefi::boot;
use uefi::mem::memory_map::{MemoryMap, MemoryType as UefiMemoryType};

use xomb::{VERSION, NAME, kernel_init};
use xomb::boot_info::{BootInfo, BootMethod, MemoryRegionType};
use xomb::serial::SerialPort;

/// Convert UEFI memory type to our unified MemoryRegionType
fn uefi_to_region_type(ty: UefiMemoryType) -> MemoryRegionType {
    match ty {
        UefiMemoryType::CONVENTIONAL => MemoryRegionType::Usable,
        UefiMemoryType::LOADER_CODE | UefiMemoryType::LOADER_DATA => {
            MemoryRegionType::BootloaderReclaimable
        }
        UefiMemoryType::BOOT_SERVICES_CODE | UefiMemoryType::BOOT_SERVICES_DATA => {
            MemoryRegionType::BootloaderReclaimable
        }
        UefiMemoryType::RUNTIME_SERVICES_CODE | UefiMemoryType::RUNTIME_SERVICES_DATA => {
            MemoryRegionType::Reserved
        }
        UefiMemoryType::ACPI_RECLAIM => MemoryRegionType::AcpiReclaimable,
        UefiMemoryType::ACPI_NON_VOLATILE => MemoryRegionType::AcpiNvs,
        UefiMemoryType::UNUSABLE => MemoryRegionType::BadMemory,
        UefiMemoryType::RESERVED | UefiMemoryType::MMIO
        | UefiMemoryType::MMIO_PORT_SPACE | UefiMemoryType::PAL_CODE => {
            MemoryRegionType::Reserved
        }
        UefiMemoryType::PERSISTENT_MEMORY => MemoryRegionType::Usable,
        _ => MemoryRegionType::Unknown(ty.0),
    }
}

/// UEFI entry point
#[entry]
fn main() -> Status {
    // Initialize UEFI services (logging, allocator)
    uefi::helpers::init().expect("Failed to initialize UEFI helpers");

    // Get a serial port for debugging output
    let mut serial = unsafe { SerialPort::new(0x3F8) };
    serial.init();

    writeln!(serial, "").ok();
    writeln!(serial, "================================").ok();
    writeln!(serial, "  {} v{}", NAME, VERSION).ok();
    writeln!(serial, "  UEFI Boot").ok();
    writeln!(serial, "================================").ok();
    writeln!(serial, "").ok();

    // Also log to UEFI console
    log::info!("{} v{} starting...", NAME, VERSION);

    // Create unified boot info structure
    let mut boot_info = BootInfo::new(BootMethod::Uefi);

    // Query memory map while boot services are available
    log::info!("Querying memory map...");
    {
        let memory_map = boot::memory_map(boot::MemoryType::LOADER_DATA)
            .expect("Failed to get memory map");

        // Convert UEFI memory map to our unified format
        for desc in memory_map.entries() {
            let base = desc.phys_start;
            let length = desc.page_count * 4096;
            let region_type = uefi_to_region_type(desc.ty);

            boot_info.memory_map.add(base, length, region_type);

            // Log each region
            let type_str = match desc.ty {
                UefiMemoryType::CONVENTIONAL => "Conventional",
                UefiMemoryType::LOADER_CODE => "LoaderCode",
                UefiMemoryType::LOADER_DATA => "LoaderData",
                UefiMemoryType::BOOT_SERVICES_CODE => "BootServicesCode",
                UefiMemoryType::BOOT_SERVICES_DATA => "BootServicesData",
                UefiMemoryType::RUNTIME_SERVICES_CODE => "RuntimeServicesCode",
                UefiMemoryType::RUNTIME_SERVICES_DATA => "RuntimeServicesData",
                UefiMemoryType::RESERVED => "Reserved",
                UefiMemoryType::ACPI_RECLAIM => "ACPIReclaim",
                UefiMemoryType::ACPI_NON_VOLATILE => "ACPINVS",
                UefiMemoryType::MMIO => "MMIO",
                _ => "Other",
            };
            writeln!(serial, "  {:#016x} - {:#016x} ({} bytes) {}",
                     base, base + length, length, type_str).ok();
        }
    }

    let total_memory = boot_info.memory_map.total_usable_memory();
    log::info!("Conventional memory available: {} MB", total_memory / (1024 * 1024));
    writeln!(serial, "Total usable memory: {} MB", total_memory / (1024 * 1024)).ok();

    // Try to find ACPI tables via UEFI configuration table
    log::info!("Looking for ACPI tables...");
    let acpi_guid_v2 = uefi::table::cfg::ACPI2_GUID;
    let acpi_guid_v1 = uefi::table::cfg::ACPI_GUID;

    for entry in uefi::system::with_config_table(|table| table.to_vec()) {
        if entry.guid == acpi_guid_v2 {
            boot_info.acpi.rsdp_v2 = entry.address as u64;
            boot_info.acpi.rsdp = entry.address as u64;
            writeln!(serial, "ACPI RSDP v2 at: {:#x}", entry.address as u64).ok();
            log::info!("Found ACPI 2.0 RSDP at {:#x}", entry.address as u64);
        } else if entry.guid == acpi_guid_v1 && boot_info.acpi.rsdp == 0 {
            boot_info.acpi.rsdp = entry.address as u64;
            writeln!(serial, "ACPI RSDP v1 at: {:#x}", entry.address as u64).ok();
            log::info!("Found ACPI 1.0 RSDP at {:#x}", entry.address as u64);
        }
    }

    // Note: Framebuffer would be obtained via GOP (Graphics Output Protocol)
    // For now, leave it as unavailable - can be added later
    log::info!("Framebuffer: not configured (GOP support TODO)");

    writeln!(serial, "").ok();
    log::info!("Exiting boot services...");
    writeln!(serial, "Exiting UEFI boot services...").ok();

    // Exit boot services - after this, no more UEFI services!
    // This gives us full control of the machine.
    let _memory_map = unsafe {
        boot::exit_boot_services(boot::MemoryType::LOADER_DATA)
    };

    // We're now in a bare-metal environment, similar to post-multiboot2
    // Only serial output works from here on

    writeln!(serial, "Boot services exited successfully.").ok();
    writeln!(serial, "").ok();

    // Transfer to common kernel entry point
    kernel_init(&boot_info)
}

/// Panic handler - required for no_std
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Try to log via UEFI if services are still available
    // This may fail if we've exited boot services
    let _ = log::error!("KERNEL PANIC: {}", info);

    // Always write to serial - this works even after exit_boot_services
    let mut serial = unsafe { SerialPort::new(0x3F8) };
    let _ = writeln!(serial, "\n!!! KERNEL PANIC !!!");
    let _ = writeln!(serial, "{}", info);

    loop {
        unsafe { core::arch::asm!("cli; hlt") };
    }
}
