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
//! ```text
//! PML4 (Page Map Level 4)     - 512 entries, each covers 512 GB
//!   └─► PDPT (Page Dir Ptr)   - 512 entries, each covers 1 GB
//!         └─► PD (Page Dir)   - 512 entries, each covers 2 MB
//!               └─► PT (Page Table) - 512 entries, each covers 4 KB
//! ```

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
    /// Huge page (2MB in PD, 1GB in PDPT)
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

    /// Get the PDPT index (bits 30-38)
    #[inline]
    pub const fn pdpt_index(self) -> usize {
        ((self.0 >> 30) & 0x1FF) as usize
    }

    /// Get the PD index (bits 21-29)
    #[inline]
    pub const fn pd_index(self) -> usize {
        ((self.0 >> 21) & 0x1FF) as usize
    }

    /// Get the PT index (bits 12-20)
    #[inline]
    pub const fn pt_index(self) -> usize {
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
    /// 4 KB page (standard)
    Small,
    /// 2 MB page (huge page via PD entry)
    Large,
    /// 1 GB page (huge page via PDPT entry)
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

/// Calculate the virtual address to access a PDPT entry via recursive mapping
///
/// Formula: 0xFFFFFF7FBFC00000 + (pml4_idx * 0x1000) + (pdpt_idx * 8)
#[inline]
pub fn pdpt_entry_addr(pml4_idx: usize, pdpt_idx: usize) -> *mut PageTableEntry {
    const PDPT_BASE: u64 = 0xFFFF_FF7F_BFC0_0000;
    (PDPT_BASE + (pml4_idx as u64) * 0x1000 + (pdpt_idx as u64) * 8) as *mut PageTableEntry
}

/// Calculate the virtual address to access a PD entry via recursive mapping
///
/// Formula: 0xFFFFFF7F80000000 + (pml4_idx * 0x200000) + (pdpt_idx * 0x1000) + (pd_idx * 8)
#[inline]
pub fn pd_entry_addr(pml4_idx: usize, pdpt_idx: usize, pd_idx: usize) -> *mut PageTableEntry {
    const PD_BASE: u64 = 0xFFFF_FF7F_8000_0000;
    (PD_BASE
        + (pml4_idx as u64) * 0x20_0000
        + (pdpt_idx as u64) * 0x1000
        + (pd_idx as u64) * 8) as *mut PageTableEntry
}

/// Calculate the virtual address to access a PT entry via recursive mapping
///
/// Formula: 0xFFFFFF0000000000 + (pml4_idx * 0x40000000) + (pdpt_idx * 0x200000)
///          + (pd_idx * 0x1000) + (pt_idx * 8)
#[inline]
pub fn pt_entry_addr(pml4_idx: usize, pdpt_idx: usize, pd_idx: usize, pt_idx: usize) -> *mut PageTableEntry {
    const PT_BASE: u64 = 0xFFFF_FF00_0000_0000;
    (PT_BASE
        + (pml4_idx as u64) * 0x4000_0000
        + (pdpt_idx as u64) * 0x20_0000
        + (pd_idx as u64) * 0x1000
        + (pt_idx as u64) * 8) as *mut PageTableEntry
}

/// Calculate the virtual address of a PDPT page via recursive mapping
///
/// After PML4[pml4_idx] is set, this address accesses the entire PDPT page.
#[inline]
fn pdpt_table_addr(pml4_idx: usize) -> *mut u64 {
    const PDPT_BASE: u64 = 0xFFFF_FF7F_BFC0_0000;
    (PDPT_BASE + (pml4_idx as u64) * 0x1000) as *mut u64
}

/// Calculate the virtual address of a PD page via recursive mapping
///
/// After PDPT[pml4_idx][pdpt_idx] is set, this address accesses the entire PD page.
#[inline]
fn pd_table_addr(pml4_idx: usize, pdpt_idx: usize) -> *mut u64 {
    const PD_BASE: u64 = 0xFFFF_FF7F_8000_0000;
    (PD_BASE + (pml4_idx as u64) * 0x20_0000 + (pdpt_idx as u64) * 0x1000) as *mut u64
}

/// Calculate the virtual address of a PT page via recursive mapping
///
/// After PD[pml4_idx][pdpt_idx][pd_idx] is set, this address accesses the entire PT page.
#[inline]
fn pt_table_addr(pml4_idx: usize, pdpt_idx: usize, pd_idx: usize) -> *mut u64 {
    const PT_BASE: u64 = 0xFFFF_FF00_0000_0000;
    (PT_BASE
        + (pml4_idx as u64) * 0x4000_0000
        + (pdpt_idx as u64) * 0x20_0000
        + (pd_idx as u64) * 0x1000) as *mut u64
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

/// Read a PDPT entry (requires PML4 entry to be present)
#[inline]
pub fn read_pdpt(pml4_idx: usize, pdpt_idx: usize) -> PageTableEntry {
    unsafe { *pdpt_entry_addr(pml4_idx, pdpt_idx) }
}

/// Write a PDPT entry
#[inline]
pub fn write_pdpt(pml4_idx: usize, pdpt_idx: usize, entry: PageTableEntry) {
    unsafe { *pdpt_entry_addr(pml4_idx, pdpt_idx) = entry; }
}

/// Read a PD entry (requires PML4 and PDPT entries to be present)
#[inline]
pub fn read_pd(pml4_idx: usize, pdpt_idx: usize, pd_idx: usize) -> PageTableEntry {
    unsafe { *pd_entry_addr(pml4_idx, pdpt_idx, pd_idx) }
}

/// Write a PD entry
#[inline]
pub fn write_pd(pml4_idx: usize, pdpt_idx: usize, pd_idx: usize, entry: PageTableEntry) {
    unsafe { *pd_entry_addr(pml4_idx, pdpt_idx, pd_idx) = entry; }
}

/// Read a PT entry (requires PML4, PDPT, and PD entries to be present)
#[inline]
pub fn read_pt(pml4_idx: usize, pdpt_idx: usize, pd_idx: usize, pt_idx: usize) -> PageTableEntry {
    unsafe { *pt_entry_addr(pml4_idx, pdpt_idx, pd_idx, pt_idx) }
}

/// Write a PT entry
#[inline]
pub fn write_pt(pml4_idx: usize, pdpt_idx: usize, pd_idx: usize, pt_idx: usize, entry: PageTableEntry) {
    unsafe { *pt_entry_addr(pml4_idx, pdpt_idx, pd_idx, pt_idx) = entry; }
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

/// Ensure a PML4 entry exists, creating a PDPT if necessary
fn ensure_pml4_entry(pml4_idx: usize, _flags: u64) -> Result<(), PagingError> {
    let entry = read_pml4(pml4_idx);
    if !entry.is_present() {
        let frame = allocate_frame()?;
        let phys = frame.start_address();

        // Link the new PDPT into the PML4 first
        // Use only table flags (PRESENT | WRITABLE) for intermediate entries
        let table_flags = flags::PRESENT | flags::WRITABLE;
        let new_entry = PageTableEntry::new(phys, table_flags);
        write_pml4(pml4_idx, new_entry);

        // Flush TLB so we can access the new PDPT via recursive mapping
        flush_tlb();

        // Zero the new page table via recursive mapping
        // Now that PML4[pml4_idx] is set, pdpt_table_addr gives us access
        zero_page_table(pdpt_table_addr(pml4_idx));
    }
    Ok(())
}

/// Ensure a PDPT entry exists, creating a PD if necessary
fn ensure_pdpt_entry(pml4_idx: usize, pdpt_idx: usize, flags: u64) -> Result<(), PagingError> {
    ensure_pml4_entry(pml4_idx, flags)?;

    let entry = read_pdpt(pml4_idx, pdpt_idx);
    if entry.is_huge() {
        return Err(PagingError::HugePageConflict);
    }
    if !entry.is_present() {
        let frame = allocate_frame()?;
        let phys = frame.start_address();

        // Link the new PD into the PDPT first
        // Use only table flags for intermediate entries
        let table_flags = flags::PRESENT | flags::WRITABLE;
        let new_entry = PageTableEntry::new(phys, table_flags);
        write_pdpt(pml4_idx, pdpt_idx, new_entry);

        // Flush TLB so we can access the new PD via recursive mapping
        flush_tlb();

        // Zero the new page table via recursive mapping
        zero_page_table(pd_table_addr(pml4_idx, pdpt_idx));
    }
    Ok(())
}

/// Ensure a PD entry exists, creating a PT if necessary
fn ensure_pd_entry(pml4_idx: usize, pdpt_idx: usize, pd_idx: usize, flags: u64) -> Result<(), PagingError> {
    ensure_pdpt_entry(pml4_idx, pdpt_idx, flags)?;

    let entry = read_pd(pml4_idx, pdpt_idx, pd_idx);
    if entry.is_huge() {
        return Err(PagingError::HugePageConflict);
    }
    if !entry.is_present() {
        let frame = allocate_frame()?;
        let phys = frame.start_address();

        // Link the new PT into the PD first
        // Use only table flags for intermediate entries
        let table_flags = flags::PRESENT | flags::WRITABLE;
        let new_entry = PageTableEntry::new(phys, table_flags);
        write_pd(pml4_idx, pdpt_idx, pd_idx, new_entry);

        // Flush TLB so we can access the new PT via recursive mapping
        flush_tlb();

        // Zero the new page table via recursive mapping
        zero_page_table(pt_table_addr(pml4_idx, pdpt_idx, pd_idx));
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
    let pdpt_idx = virt.pdpt_index();
    let pd_idx = virt.pd_index();
    let pt_idx = virt.pt_index();

    // Ensure all parent tables exist
    ensure_pd_entry(pml4_idx, pdpt_idx, pd_idx, flags)?;

    // Check if already mapped
    let existing = read_pt(pml4_idx, pdpt_idx, pd_idx, pt_idx);
    if existing.is_present() {
        return Err(PagingError::AlreadyMapped);
    }

    // Create the mapping
    let entry = PageTableEntry::new(phys, flags | flags::PRESENT);
    write_pt(pml4_idx, pdpt_idx, pd_idx, pt_idx, entry);

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
    let pdpt_idx = virt.pdpt_index();
    let pd_idx = virt.pd_index();

    // Ensure PML4 and PDPT entries exist
    ensure_pdpt_entry(pml4_idx, pdpt_idx, flags)?;

    // Check if already mapped
    let existing = read_pd(pml4_idx, pdpt_idx, pd_idx);
    if existing.is_present() {
        return Err(PagingError::AlreadyMapped);
    }

    // Create the huge page mapping
    let entry = PageTableEntry::new(phys, flags | flags::PRESENT | flags::HUGE_PAGE);
    write_pd(pml4_idx, pdpt_idx, pd_idx, entry);

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
    let pdpt_idx = virt.pdpt_index();

    // Ensure PML4 entry exists
    ensure_pml4_entry(pml4_idx, flags)?;

    // Check if already mapped
    let existing = read_pdpt(pml4_idx, pdpt_idx);
    if existing.is_present() {
        return Err(PagingError::AlreadyMapped);
    }

    // Create the huge page mapping
    let entry = PageTableEntry::new(phys, flags | flags::PRESENT | flags::HUGE_PAGE);
    write_pdpt(pml4_idx, pdpt_idx, entry);

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
    let pdpt_idx = virt.pdpt_index();
    let pd_idx = virt.pd_index();
    let pt_idx = virt.pt_index();

    // Walk the page table hierarchy
    let pml4_entry = read_pml4(pml4_idx);
    if !pml4_entry.is_present() {
        return Err(PagingError::NotMapped);
    }

    let pdpt_entry = read_pdpt(pml4_idx, pdpt_idx);
    if !pdpt_entry.is_present() {
        return Err(PagingError::NotMapped);
    }
    if pdpt_entry.is_huge() {
        return Err(PagingError::HugePageConflict);
    }

    let pd_entry = read_pd(pml4_idx, pdpt_idx, pd_idx);
    if !pd_entry.is_present() {
        return Err(PagingError::NotMapped);
    }
    if pd_entry.is_huge() {
        return Err(PagingError::HugePageConflict);
    }

    let pt_entry = read_pt(pml4_idx, pdpt_idx, pd_idx, pt_idx);
    if !pt_entry.is_present() {
        return Err(PagingError::NotMapped);
    }

    let frame = pt_entry.frame();

    // Clear the entry
    write_pt(pml4_idx, pdpt_idx, pd_idx, pt_idx, PageTableEntry::empty());

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
    let pdpt_idx = virt.pdpt_index();
    let pd_idx = virt.pd_index();
    let pt_idx = virt.pt_index();
    let offset = virt.page_offset();

    // Walk the page table hierarchy
    let pml4_entry = read_pml4(pml4_idx);
    if !pml4_entry.is_present() {
        return None;
    }

    let pdpt_entry = read_pdpt(pml4_idx, pdpt_idx);
    if !pdpt_entry.is_present() {
        return None;
    }
    if pdpt_entry.is_huge() {
        // 1GB page
        let base = pdpt_entry.addr().as_u64();
        let page_offset = virt.as_u64() & 0x3FFFFFFF; // Lower 30 bits
        return Some(PhysAddr::new(base + page_offset));
    }

    let pd_entry = read_pd(pml4_idx, pdpt_idx, pd_idx);
    if !pd_entry.is_present() {
        return None;
    }
    if pd_entry.is_huge() {
        // 2MB page
        let base = pd_entry.addr().as_u64();
        let page_offset = virt.as_u64() & 0x1FFFFF; // Lower 21 bits
        return Some(PhysAddr::new(base + page_offset));
    }

    let pt_entry = read_pt(pml4_idx, pdpt_idx, pd_idx, pt_idx);
    if !pt_entry.is_present() {
        return None;
    }

    // 4KB page
    let base = pt_entry.addr().as_u64();
    Some(PhysAddr::new(base + offset as u64))
}

/// Get information about the mapping at a virtual address
pub fn get_mapping_info(virt: VirtAddr) -> Option<(PhysAddr, PageSize, u64)> {
    if !virt.is_canonical() {
        return None;
    }

    let pml4_idx = virt.pml4_index();
    let pdpt_idx = virt.pdpt_index();
    let pd_idx = virt.pd_index();
    let pt_idx = virt.pt_index();

    let pml4_entry = read_pml4(pml4_idx);
    if !pml4_entry.is_present() {
        return None;
    }

    let pdpt_entry = read_pdpt(pml4_idx, pdpt_idx);
    if !pdpt_entry.is_present() {
        return None;
    }
    if pdpt_entry.is_huge() {
        return Some((pdpt_entry.addr(), PageSize::Huge, pdpt_entry.flags()));
    }

    let pd_entry = read_pd(pml4_idx, pdpt_idx, pd_idx);
    if !pd_entry.is_present() {
        return None;
    }
    if pd_entry.is_huge() {
        return Some((pd_entry.addr(), PageSize::Large, pd_entry.flags()));
    }

    let pt_entry = read_pt(pml4_idx, pdpt_idx, pd_idx, pt_idx);
    if !pt_entry.is_present() {
        return None;
    }

    Some((pt_entry.addr(), PageSize::Small, pt_entry.flags()))
}
