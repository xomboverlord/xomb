//! Memory Management
//!
//! This module provides physical and virtual memory management for the XOmB exokernel.
//! The kernel multiplexes hardware resources through the virtual memory system,
//! so it needs to track and allocate physical pages for page table entries
//! and resource mappings.
//!
//! ## Modules
//!
//! - `frame`: Physical frame allocator (bitmap-based)
//! - `paging`: Page table manipulation using recursive mapping

pub mod frame;
pub mod paging;

pub use frame::{PhysAddr, Frame, FrameAllocator, FrameAllocatorError};
pub use paging::{VirtAddr, PageTableEntry, PageSize, PagingError};

/// Page size constants
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_2MB: usize = 2 * 1024 * 1024;
pub const PAGE_SIZE_1GB: usize = 1024 * 1024 * 1024;

/// Align an address down to the nearest page boundary
#[inline]
pub const fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

/// Align an address up to the nearest page boundary
#[inline]
pub const fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}
