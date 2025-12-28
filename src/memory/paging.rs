//! Page Table Management
//!
//! This module provides primitives for manipulating x86-64 page tables using
//! the recursive mapping technique. PML4[510] points to the PML4 itself,
//! enabling access to any page table entry through virtual addresses.
//!
//! ## Recursive Mapping
//!
//! With PML4[510] as the self-reference entry:
//! - Recursive region base: 0xFFFF_FF00_0000_0000
//! - Any page table can be accessed by constructing the appropriate virtual address
//!
//! ## Page Table Hierarchy (4-level paging)
//!
//! We use simplified level-based naming (PML4/PML3/PML2/PML1) rather than
//! the x86 architectural names for clarity:
//!
//! ```text
//! PML4 (Page Map Level 4)  - 512 entries, each covers 512 GB  [x86: PML4]
//!   └─► PML3               - 512 entries, each covers 1 GB    [x86: PDPT]
//!         └─► PML2         - 512 entries, each covers 2 MB    [x86: PD]
//!               └─► PML1   - 512 entries, each covers 4 KB    [x86: PT]
//! ```
//!
//! Correspondence to x86 terminology:
//! - PML4 = Page Map Level 4 (same)
//! - PML3 = Page Directory Pointer Table (PDPT)
//! - PML2 = Page Directory (PD)
//! - PML1 = Page Table (PT)

use core::fmt;
use crate::memory::frame::{Frame, PhysAddr, allocate_frame, FrameAllocatorError};

/// Recursive mapping PML4 index (PML4[510] points to itself)
pub const RECURSIVE_INDEX: usize = 510;

/// Base virtual address for recursive mapping region
pub const RECURSIVE_BASE: u64 = 0xFFFF_FF00_0000_0000;

/// Number of entries in a page table (all levels)
pub const ENTRIES_PER_TABLE: usize = 512;

/// Page table entry flags
pub mod flags {
    /// Page is present in memory
    pub const PRESENT: u64 = 1 << 0;
    /// Page is writable (otherwise read-only)
    pub const WRITABLE: u64 = 1 << 1;
    /// Page is accessible from user mode (ring 3)
    pub const USER: u64 = 1 << 2;
    /// Write-through caching
    pub const WRITE_THROUGH: u64 = 1 << 3;
    /// Disable caching for this page
    pub const NO_CACHE: u64 = 1 << 4;
    /// Page has been accessed (set by CPU)
    pub const ACCESSED: u64 = 1 << 5;
    /// Page has been written to (set by CPU)
    pub const DIRTY: u64 = 1 << 6;
    /// Huge page (2MB in PML2, 1GB in PML3)
    pub const HUGE_PAGE: u64 = 1 << 7;
    /// Global page (not flushed on CR3 change)
    pub const GLOBAL: u64 = 1 << 8;
    /// No execute (requires NXE bit in EFER)
    pub const NO_EXECUTE: u64 = 1 << 63;

    /// Mask for the physical address in a page table entry
    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// Default flags for a kernel page table entry (present + writable)
    pub const KERNEL_TABLE: u64 = PRESENT | WRITABLE;
    /// Default flags for a kernel code page (present + no execute disabled)
    pub const KERNEL_CODE: u64 = PRESENT;
    /// Default flags for a kernel data page (present + writable + no execute)
    pub const KERNEL_DATA: u64 = PRESENT | WRITABLE | NO_EXECUTE;
    /// Default flags for user pages
    pub const USER_TABLE: u64 = PRESENT | WRITABLE | USER;
    pub const USER_CODE: u64 = PRESENT | USER;
    pub const USER_DATA: u64 = PRESENT | WRITABLE | USER | NO_EXECUTE;
}

/// A page table entry (64 bits)
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Create an empty (non-present) entry
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create an entry with the given frame and flags
    #[inline]
    pub const fn new(frame: PhysAddr, flags: u64) -> Self {
        Self((frame.as_u64() & flags::ADDR_MASK) | flags)
    }

    /// Get the raw entry value
    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Check if the entry is present
    #[inline]
    pub const fn is_present(self) -> bool {
        self.0 & flags::PRESENT != 0
    }

    /// Check if the entry is writable
    #[inline]
    pub const fn is_writable(self) -> bool {
        self.0 & flags::WRITABLE != 0
    }

    /// Check if the entry is user-accessible
    #[inline]
    pub const fn is_user(self) -> bool {
        self.0 & flags::USER != 0
    }

    /// Check if this is a huge page (2MB or 1GB)
    #[inline]
    pub const fn is_huge(self) -> bool {
        self.0 & flags::HUGE_PAGE != 0
    }

    /// Get the physical address from the entry
    #[inline]
    pub const fn addr(self) -> PhysAddr {
        PhysAddr::new(self.0 & flags::ADDR_MASK)
    }

    /// Get the frame this entry points to
    #[inline]
    pub const fn frame(self) -> Frame {
        Frame::containing_address(self.addr())
    }

    /// Get the flags from the entry
    #[inline]
    pub const fn flags(self) -> u64 {
        self.0 & !flags::ADDR_MASK
    }

    /// Set the flags, preserving the address
    #[inline]
    pub fn set_flags(&mut self, new_flags: u64) {
        self.0 = (self.0 & flags::ADDR_MASK) | new_flags;
    }

    /// Set the address, preserving the flags
    #[inline]
    pub fn set_addr(&mut self, addr: PhysAddr) {
        self.0 = (addr.as_u64() & flags::ADDR_MASK) | (self.0 & !flags::ADDR_MASK);
    }
}

impl fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PTE({:#x}, ", self.addr())?;
        if self.is_present() { write!(f, "P")?; } else { write!(f, "-")?; }
        if self.is_writable() { write!(f, "W")?; } else { write!(f, "-")?; }
        if self.is_user() { write!(f, "U")?; } else { write!(f, "-")?; }
        if self.is_huge() { write!(f, "H")?; } else { write!(f, "-")?; }
        write!(f, ")")
    }
}

/// Virtual address decomposition for 4-level paging
#[derive(Debug, Clone, Copy)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Create a new virtual address
    #[inline]
    pub const fn new(addr: u64) -> Self {
        // Sign-extend from bit 47 for canonical addresses
        Self(((addr << 16) as i64 >> 16) as u64)
    }

    /// Get the raw address value
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Get the PML4 index (bits 39-47)
    #[inline]
    pub const fn pml4_index(self) -> usize {
        ((self.0 >> 39) & 0x1FF) as usize
    }

    /// Get the PML3 index (bits 30-38)
    #[inline]
    pub const fn pml3_index(self) -> usize {
        ((self.0 >> 30) & 0x1FF) as usize
    }

    /// Get the PML2 index (bits 21-29)
    #[inline]
    pub const fn pml2_index(self) -> usize {
        ((self.0 >> 21) & 0x1FF) as usize
    }

    /// Get the PML1 index (bits 12-20)
    #[inline]
    pub const fn pml1_index(self) -> usize {
        ((self.0 >> 12) & 0x1FF) as usize
    }

    /// Get the page offset (bits 0-11)
    #[inline]
    pub const fn page_offset(self) -> usize {
        (self.0 & 0xFFF) as usize
    }

    /// Check if this is a canonical address
    #[inline]
    pub const fn is_canonical(self) -> bool {
        let top_bits = self.0 >> 47;
        top_bits == 0 || top_bits == 0x1FFFF
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

/// Page size variants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    /// 4 KB page (standard, via PML1 entry)
    Small,
    /// 2 MB page (huge page via PML2 entry)
    Large,
    /// 1 GB page (huge page via PML3 entry)
    Huge,
}

impl PageSize {
    /// Get the size in bytes
    pub const fn size(self) -> usize {
        match self {
            PageSize::Small => 4 * 1024,           // 4 KB
            PageSize::Large => 2 * 1024 * 1024,    // 2 MB
            PageSize::Huge => 1024 * 1024 * 1024,  // 1 GB
        }
    }
}

/// Errors that can occur during page table operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PagingError {
    /// Failed to allocate a frame for a new page table
    FrameAllocationFailed,
    /// The virtual address is not canonical
    InvalidAddress,
    /// The page is already mapped
    AlreadyMapped,
    /// The page is not mapped
    NotMapped,
    /// A parent entry is a huge page (can't traverse further)
    HugePageConflict,
}

impl From<FrameAllocatorError> for PagingError {
    fn from(_: FrameAllocatorError) -> Self {
        PagingError::FrameAllocationFailed
    }
}

// ============================================================================
// Recursive Mapping Address Calculations
// ============================================================================

/// Calculate the virtual address to access a PML4 entry via recursive mapping
///
/// Formula: 0xFFFFFF7FBFDFE000 + (pml4_idx * 8)
#[inline]
pub fn pml4_entry_addr(pml4_idx: usize) -> *mut PageTableEntry {
    const PML4_BASE: u64 = 0xFFFF_FF7F_BFDF_E000;
    (PML4_BASE + (pml4_idx as u64) * 8) as *mut PageTableEntry
}

/// Calculate the virtual address to access a PML3 entry via recursive mapping
///
/// Formula: 0xFFFFFF7FBFC00000 + (pml4_idx * 0x1000) + (pml3_idx * 8)
#[inline]
pub fn pml3_entry_addr(pml4_idx: usize, pml3_idx: usize) -> *mut PageTableEntry {
    const PML3_BASE: u64 = 0xFFFF_FF7F_BFC0_0000;
    (PML3_BASE + (pml4_idx as u64) * 0x1000 + (pml3_idx as u64) * 8) as *mut PageTableEntry
}

/// Calculate the virtual address to access a PML2 entry via recursive mapping
///
/// Formula: 0xFFFFFF7F80000000 + (pml4_idx * 0x200000) + (pml3_idx * 0x1000) + (pml2_idx * 8)
#[inline]
pub fn pml2_entry_addr(pml4_idx: usize, pml3_idx: usize, pml2_idx: usize) -> *mut PageTableEntry {
    const PML2_BASE: u64 = 0xFFFF_FF7F_8000_0000;
    (PML2_BASE
        + (pml4_idx as u64) * 0x20_0000
        + (pml3_idx as u64) * 0x1000
        + (pml2_idx as u64) * 8) as *mut PageTableEntry
}

/// Calculate the virtual address to access a PML1 entry via recursive mapping
///
/// Formula: 0xFFFFFF0000000000 + (pml4_idx * 0x40000000) + (pml3_idx * 0x200000)
///          + (pml2_idx * 0x1000) + (pml1_idx * 8)
#[inline]
pub fn pml1_entry_addr(pml4_idx: usize, pml3_idx: usize, pml2_idx: usize, pml1_idx: usize) -> *mut PageTableEntry {
    const PML1_BASE: u64 = 0xFFFF_FF00_0000_0000;
    (PML1_BASE
        + (pml4_idx as u64) * 0x4000_0000
        + (pml3_idx as u64) * 0x20_0000
        + (pml2_idx as u64) * 0x1000
        + (pml1_idx as u64) * 8) as *mut PageTableEntry
}

/// Calculate the virtual address of a PML3 table via recursive mapping
///
/// After PML4[pml4_idx] is set, this address accesses the entire PML3 table.
#[inline]
fn pml3_table_addr(pml4_idx: usize) -> *mut u64 {
    const PML3_BASE: u64 = 0xFFFF_FF7F_BFC0_0000;
    (PML3_BASE + (pml4_idx as u64) * 0x1000) as *mut u64
}

/// Calculate the virtual address of a PML2 table via recursive mapping
///
/// After PML3[pml4_idx][pml3_idx] is set, this address accesses the entire PML2 table.
#[inline]
fn pml2_table_addr(pml4_idx: usize, pml3_idx: usize) -> *mut u64 {
    const PML2_BASE: u64 = 0xFFFF_FF7F_8000_0000;
    (PML2_BASE + (pml4_idx as u64) * 0x20_0000 + (pml3_idx as u64) * 0x1000) as *mut u64
}

/// Calculate the virtual address of a PML1 table via recursive mapping
///
/// After PML2[pml4_idx][pml3_idx][pml2_idx] is set, this address accesses the entire PML1 table.
#[inline]
fn pml1_table_addr(pml4_idx: usize, pml3_idx: usize, pml2_idx: usize) -> *mut u64 {
    const PML1_BASE: u64 = 0xFFFF_FF00_0000_0000;
    (PML1_BASE
        + (pml4_idx as u64) * 0x4000_0000
        + (pml3_idx as u64) * 0x20_0000
        + (pml2_idx as u64) * 0x1000) as *mut u64
}

// ============================================================================
// Page Table Entry Access
// ============================================================================

/// Read a PML4 entry
#[inline]
pub fn read_pml4(pml4_idx: usize) -> PageTableEntry {
    unsafe { core::ptr::read_volatile(pml4_entry_addr(pml4_idx)) }
}

/// Write a PML4 entry
pub fn write_pml4(pml4_idx: usize, entry: PageTableEntry) {
    unsafe {
        let ptr = pml4_entry_addr(pml4_idx);
        core::ptr::write_volatile(ptr, entry);
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

/// Read a PML3 entry (requires PML4 entry to be present)
#[inline]
pub fn read_pml3(pml4_idx: usize, pml3_idx: usize) -> PageTableEntry {
    unsafe { *pml3_entry_addr(pml4_idx, pml3_idx) }
}

/// Write a PML3 entry
#[inline]
pub fn write_pml3(pml4_idx: usize, pml3_idx: usize, entry: PageTableEntry) {
    unsafe { *pml3_entry_addr(pml4_idx, pml3_idx) = entry; }
}

/// Read a PML2 entry (requires PML4 and PML3 entries to be present)
#[inline]
pub fn read_pml2(pml4_idx: usize, pml3_idx: usize, pml2_idx: usize) -> PageTableEntry {
    unsafe { *pml2_entry_addr(pml4_idx, pml3_idx, pml2_idx) }
}

/// Write a PML2 entry
#[inline]
pub fn write_pml2(pml4_idx: usize, pml3_idx: usize, pml2_idx: usize, entry: PageTableEntry) {
    unsafe { *pml2_entry_addr(pml4_idx, pml3_idx, pml2_idx) = entry; }
}

/// Read a PML1 entry (requires PML4, PML3, and PML2 entries to be present)
#[inline]
pub fn read_pml1(pml4_idx: usize, pml3_idx: usize, pml2_idx: usize, pml1_idx: usize) -> PageTableEntry {
    unsafe { *pml1_entry_addr(pml4_idx, pml3_idx, pml2_idx, pml1_idx) }
}

/// Write a PML1 entry
#[inline]
pub fn write_pml1(pml4_idx: usize, pml3_idx: usize, pml2_idx: usize, pml1_idx: usize, entry: PageTableEntry) {
    unsafe { *pml1_entry_addr(pml4_idx, pml3_idx, pml2_idx, pml1_idx) = entry; }
}

// ============================================================================
// TLB Management
// ============================================================================

/// Invalidate a single TLB entry for the given virtual address
#[inline]
pub fn invalidate_page(addr: VirtAddr) {
    unsafe {
        core::arch::asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags));
    }
}

/// Flush the entire TLB by reloading CR3
#[inline]
pub fn flush_tlb() {
    unsafe {
        // Memory barrier to ensure all prior writes are visible
        core::arch::asm!("mfence", options(nostack, preserves_flags));
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
}

/// Remove the identity mapping at PML4[0]
///
/// This should be called after the kernel is fully running in the higher-half
/// and no longer needs the identity mapping set up during boot.
pub fn remove_identity_mapping() {
    // Clear PML4[0]
    write_pml4(0, PageTableEntry::empty());

    // Flush TLB to ensure the change takes effect
    flush_tlb();
}

// ============================================================================
// Page Table Creation and Mapping
// ============================================================================

/// Ensure a PML4 entry exists, creating a PML3 table if necessary
fn ensure_pml4_entry(pml4_idx: usize, page_flags: u64) -> Result<(), PagingError> {
    let entry = read_pml4(pml4_idx);
    if !entry.is_present() {
        let frame = allocate_frame()?;
        let phys = frame.start_address();

        // Link the new PML3 into the PML4 first
        // For user pages, the USER bit must be set in all intermediate entries
        let mut table_flags = flags::PRESENT | flags::WRITABLE;
        if page_flags & flags::USER != 0 {
            table_flags |= flags::USER;
        }
        let new_entry = PageTableEntry::new(phys, table_flags);
        write_pml4(pml4_idx, new_entry);

        // Flush TLB so we can access the new PML3 via recursive mapping
        flush_tlb();

        // Zero the new page table via recursive mapping
        // Now that PML4[pml4_idx] is set, pml3_table_addr gives us access
        zero_page_table(pml3_table_addr(pml4_idx));
    } else if page_flags & flags::USER != 0 && !entry.is_user() {
        // Existing entry needs USER bit added
        let mut updated = entry;
        updated.set_flags(entry.flags() | flags::USER);
        write_pml4(pml4_idx, updated);
    }
    Ok(())
}

/// Ensure a PML3 entry exists, creating a PML2 table if necessary
fn ensure_pml3_entry(pml4_idx: usize, pml3_idx: usize, page_flags: u64) -> Result<(), PagingError> {
    ensure_pml4_entry(pml4_idx, page_flags)?;

    let entry = read_pml3(pml4_idx, pml3_idx);
    if entry.is_huge() {
        return Err(PagingError::HugePageConflict);
    }
    if !entry.is_present() {
        let frame = allocate_frame()?;
        let phys = frame.start_address();

        // Link the new PML2 into the PML3 first
        // For user pages, the USER bit must be set in all intermediate entries
        let mut table_flags = flags::PRESENT | flags::WRITABLE;
        if page_flags & flags::USER != 0 {
            table_flags |= flags::USER;
        }
        let new_entry = PageTableEntry::new(phys, table_flags);
        write_pml3(pml4_idx, pml3_idx, new_entry);

        // Flush TLB so we can access the new PML2 via recursive mapping
        flush_tlb();

        // Zero the new page table via recursive mapping
        zero_page_table(pml2_table_addr(pml4_idx, pml3_idx));
    } else if page_flags & flags::USER != 0 && !entry.is_user() {
        // Existing entry needs USER bit added
        let mut updated = entry;
        updated.set_flags(entry.flags() | flags::USER);
        write_pml3(pml4_idx, pml3_idx, updated);
    }
    Ok(())
}

/// Ensure a PML2 entry exists, creating a PML1 table if necessary
fn ensure_pml2_entry(pml4_idx: usize, pml3_idx: usize, pml2_idx: usize, page_flags: u64) -> Result<(), PagingError> {
    ensure_pml3_entry(pml4_idx, pml3_idx, page_flags)?;

    let entry = read_pml2(pml4_idx, pml3_idx, pml2_idx);
    if entry.is_huge() {
        return Err(PagingError::HugePageConflict);
    }
    if !entry.is_present() {
        let frame = allocate_frame()?;
        let phys = frame.start_address();

        // Link the new PML1 into the PML2 first
        // For user pages, the USER bit must be set in all intermediate entries
        let mut table_flags = flags::PRESENT | flags::WRITABLE;
        if page_flags & flags::USER != 0 {
            table_flags |= flags::USER;
        }
        let new_entry = PageTableEntry::new(phys, table_flags);
        write_pml2(pml4_idx, pml3_idx, pml2_idx, new_entry);

        // Flush TLB so we can access the new PML1 via recursive mapping
        flush_tlb();

        // Zero the new page table via recursive mapping
        zero_page_table(pml1_table_addr(pml4_idx, pml3_idx, pml2_idx));
    } else if page_flags & flags::USER != 0 && !entry.is_user() {
        // Existing entry needs USER bit added
        let mut updated = entry;
        updated.set_flags(entry.flags() | flags::USER);
        write_pml2(pml4_idx, pml3_idx, pml2_idx, updated);
    }
    Ok(())
}

/// Zero a page table at the given virtual address
///
/// The page must already be mapped (accessible via the given address).
/// This writes 512 zero entries (4096 bytes total).
fn zero_page_table(virt_addr: *mut u64) {
    unsafe {
        for i in 0..512 {
            core::ptr::write_volatile(virt_addr.add(i), 0);
        }
    }
}

/// Map a 4KB page
pub fn map_4kb(virt: VirtAddr, phys: PhysAddr, flags: u64) -> Result<(), PagingError> {
    if !virt.is_canonical() {
        return Err(PagingError::InvalidAddress);
    }

    let pml4_idx = virt.pml4_index();
    let pml3_idx = virt.pml3_index();
    let pml2_idx = virt.pml2_index();
    let pml1_idx = virt.pml1_index();

    // Ensure all parent tables exist
    ensure_pml2_entry(pml4_idx, pml3_idx, pml2_idx, flags)?;

    // Check if already mapped
    let existing = read_pml1(pml4_idx, pml3_idx, pml2_idx, pml1_idx);
    if existing.is_present() {
        return Err(PagingError::AlreadyMapped);
    }

    // Create the mapping
    let entry = PageTableEntry::new(phys, flags | flags::PRESENT);
    write_pml1(pml4_idx, pml3_idx, pml2_idx, pml1_idx, entry);

    // Invalidate TLB for this address
    invalidate_page(virt);

    Ok(())
}

/// Map a 2MB huge page
pub fn map_2mb(virt: VirtAddr, phys: PhysAddr, flags: u64) -> Result<(), PagingError> {
    if !virt.is_canonical() {
        return Err(PagingError::InvalidAddress);
    }

    // Virtual address must be 2MB aligned
    if virt.as_u64() & 0x1FFFFF != 0 {
        return Err(PagingError::InvalidAddress);
    }

    let pml4_idx = virt.pml4_index();
    let pml3_idx = virt.pml3_index();
    let pml2_idx = virt.pml2_index();

    // Ensure PML4 and PML3 entries exist
    ensure_pml3_entry(pml4_idx, pml3_idx, flags)?;

    // Check if already mapped
    let existing = read_pml2(pml4_idx, pml3_idx, pml2_idx);
    if existing.is_present() {
        return Err(PagingError::AlreadyMapped);
    }

    // Create the huge page mapping
    let entry = PageTableEntry::new(phys, flags | flags::PRESENT | flags::HUGE_PAGE);
    write_pml2(pml4_idx, pml3_idx, pml2_idx, entry);

    // Invalidate TLB
    invalidate_page(virt);

    Ok(())
}

/// Map a 1GB huge page
pub fn map_1gb(virt: VirtAddr, phys: PhysAddr, flags: u64) -> Result<(), PagingError> {
    if !virt.is_canonical() {
        return Err(PagingError::InvalidAddress);
    }

    // Virtual address must be 1GB aligned
    if virt.as_u64() & 0x3FFFFFFF != 0 {
        return Err(PagingError::InvalidAddress);
    }

    let pml4_idx = virt.pml4_index();
    let pml3_idx = virt.pml3_index();

    // Ensure PML4 entry exists
    ensure_pml4_entry(pml4_idx, flags)?;

    // Check if already mapped
    let existing = read_pml3(pml4_idx, pml3_idx);
    if existing.is_present() {
        return Err(PagingError::AlreadyMapped);
    }

    // Create the huge page mapping
    let entry = PageTableEntry::new(phys, flags | flags::PRESENT | flags::HUGE_PAGE);
    write_pml3(pml4_idx, pml3_idx, entry);

    // Invalidate TLB
    invalidate_page(virt);

    Ok(())
}

/// Unmap a 4KB page, returning the physical frame if it was mapped
pub fn unmap_4kb(virt: VirtAddr) -> Result<Frame, PagingError> {
    if !virt.is_canonical() {
        return Err(PagingError::InvalidAddress);
    }

    let pml4_idx = virt.pml4_index();
    let pml3_idx = virt.pml3_index();
    let pml2_idx = virt.pml2_index();
    let pml1_idx = virt.pml1_index();

    // Walk the page table hierarchy
    let pml4_entry = read_pml4(pml4_idx);
    if !pml4_entry.is_present() {
        return Err(PagingError::NotMapped);
    }

    let pml3_entry = read_pml3(pml4_idx, pml3_idx);
    if !pml3_entry.is_present() {
        return Err(PagingError::NotMapped);
    }
    if pml3_entry.is_huge() {
        return Err(PagingError::HugePageConflict);
    }

    let pml2_entry = read_pml2(pml4_idx, pml3_idx, pml2_idx);
    if !pml2_entry.is_present() {
        return Err(PagingError::NotMapped);
    }
    if pml2_entry.is_huge() {
        return Err(PagingError::HugePageConflict);
    }

    let pml1_entry = read_pml1(pml4_idx, pml3_idx, pml2_idx, pml1_idx);
    if !pml1_entry.is_present() {
        return Err(PagingError::NotMapped);
    }

    let frame = pml1_entry.frame();

    // Clear the entry
    write_pml1(pml4_idx, pml3_idx, pml2_idx, pml1_idx, PageTableEntry::empty());

    // Invalidate TLB
    invalidate_page(virt);

    Ok(frame)
}

/// Translate a virtual address to a physical address
pub fn translate(virt: VirtAddr) -> Option<PhysAddr> {
    if !virt.is_canonical() {
        return None;
    }

    let pml4_idx = virt.pml4_index();
    let pml3_idx = virt.pml3_index();
    let pml2_idx = virt.pml2_index();
    let pml1_idx = virt.pml1_index();
    let offset = virt.page_offset();

    // Walk the page table hierarchy
    let pml4_entry = read_pml4(pml4_idx);
    if !pml4_entry.is_present() {
        return None;
    }

    let pml3_entry = read_pml3(pml4_idx, pml3_idx);
    if !pml3_entry.is_present() {
        return None;
    }
    if pml3_entry.is_huge() {
        // 1GB page
        let base = pml3_entry.addr().as_u64();
        let page_offset = virt.as_u64() & 0x3FFFFFFF; // Lower 30 bits
        return Some(PhysAddr::new(base + page_offset));
    }

    let pml2_entry = read_pml2(pml4_idx, pml3_idx, pml2_idx);
    if !pml2_entry.is_present() {
        return None;
    }
    if pml2_entry.is_huge() {
        // 2MB page
        let base = pml2_entry.addr().as_u64();
        let page_offset = virt.as_u64() & 0x1FFFFF; // Lower 21 bits
        return Some(PhysAddr::new(base + page_offset));
    }

    let pml1_entry = read_pml1(pml4_idx, pml3_idx, pml2_idx, pml1_idx);
    if !pml1_entry.is_present() {
        return None;
    }

    // 4KB page
    let base = pml1_entry.addr().as_u64();
    Some(PhysAddr::new(base + offset as u64))
}

/// Get information about the mapping at a virtual address
pub fn get_mapping_info(virt: VirtAddr) -> Option<(PhysAddr, PageSize, u64)> {
    if !virt.is_canonical() {
        return None;
    }

    let pml4_idx = virt.pml4_index();
    let pml3_idx = virt.pml3_index();
    let pml2_idx = virt.pml2_index();
    let pml1_idx = virt.pml1_index();

    let pml4_entry = read_pml4(pml4_idx);
    if !pml4_entry.is_present() {
        return None;
    }

    let pml3_entry = read_pml3(pml4_idx, pml3_idx);
    if !pml3_entry.is_present() {
        return None;
    }
    if pml3_entry.is_huge() {
        return Some((pml3_entry.addr(), PageSize::Huge, pml3_entry.flags()));
    }

    let pml2_entry = read_pml2(pml4_idx, pml3_idx, pml2_idx);
    if !pml2_entry.is_present() {
        return None;
    }
    if pml2_entry.is_huge() {
        return Some((pml2_entry.addr(), PageSize::Large, pml2_entry.flags()));
    }

    let pml1_entry = read_pml1(pml4_idx, pml3_idx, pml2_idx, pml1_idx);
    if !pml1_entry.is_present() {
        return None;
    }

    Some((pml1_entry.addr(), PageSize::Small, pml1_entry.flags()))
}
