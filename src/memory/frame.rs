//! Physical Frame Allocator
//!
//! This module provides a bitmap-based physical frame allocator for tracking
//! free and used physical memory pages. The allocator is initialized from the
//! boot memory map and supports:
//!
//! - Allocating any free frame
//! - Allocating a specific physical frame (for device MMIO, etc.)
//! - Deallocating frames
//!
//! The exokernel design allows applications to request specific physical pages
//! for resources, so the allocator must support targeted allocation.

use core::fmt;
use crate::boot_info::{BootInfo, MemoryMap, MemoryRegionType};
use super::{PAGE_SIZE, align_down, align_up};

/// Physical address wrapper
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Create a new physical address
    #[inline]
    pub const fn new(addr: u64) -> Self {
        // On x86-64, physical addresses are limited to 52 bits
        Self(addr & 0x000F_FFFF_FFFF_FFFF)
    }

    /// Create a physical address without masking (for known-good addresses)
    #[inline]
    pub const fn new_unchecked(addr: u64) -> Self {
        Self(addr)
    }

    /// Get the raw address value
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Check if the address is page-aligned
    #[inline]
    pub const fn is_aligned(self) -> bool {
        self.0 & (PAGE_SIZE as u64 - 1) == 0
    }

    /// Align the address down to the nearest page boundary
    #[inline]
    pub const fn align_down(self) -> Self {
        Self(align_down(self.0, PAGE_SIZE as u64))
    }

    /// Align the address up to the nearest page boundary
    #[inline]
    pub const fn align_up(self) -> Self {
        Self(align_up(self.0, PAGE_SIZE as u64))
    }

    /// Get the frame containing this address
    #[inline]
    pub const fn containing_frame(self) -> Frame {
        Frame::containing_address(self)
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

/// A physical memory frame (4KB page)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Frame {
    /// Frame number (physical address / PAGE_SIZE)
    number: usize,
}

impl Frame {
    /// Create a frame from a frame number
    #[inline]
    pub const fn from_number(number: usize) -> Self {
        Self { number }
    }

    /// Create a frame containing the given physical address
    #[inline]
    pub const fn containing_address(addr: PhysAddr) -> Self {
        Self {
            number: (addr.as_u64() / PAGE_SIZE as u64) as usize,
        }
    }

    /// Create a frame from a page-aligned physical address
    #[inline]
    pub const fn from_start_address(addr: PhysAddr) -> Option<Self> {
        if addr.is_aligned() {
            Some(Self::containing_address(addr))
        } else {
            None
        }
    }

    /// Get the frame number
    #[inline]
    pub const fn number(self) -> usize {
        self.number
    }

    /// Get the start address of this frame
    #[inline]
    pub const fn start_address(self) -> PhysAddr {
        PhysAddr::new_unchecked((self.number as u64) * PAGE_SIZE as u64)
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Frame({})", self.number)
    }
}

/// Errors that can occur during frame allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAllocatorError {
    /// No free frames available
    OutOfMemory,
    /// Requested frame is already allocated
    FrameInUse,
    /// Requested frame is outside valid memory
    InvalidFrame,
    /// Allocator not initialized
    NotInitialized,
}

/// Maximum physical memory we support (16 GB = 4M frames)
/// This determines the size of our bitmap
const MAX_PHYSICAL_MEMORY: u64 = 16 * 1024 * 1024 * 1024;
const MAX_FRAMES: usize = (MAX_PHYSICAL_MEMORY / PAGE_SIZE as u64) as usize;

/// Bitmap size in u64 words (each u64 tracks 64 frames)
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// Bitmap-based physical frame allocator
///
/// Uses a bitmap where each bit represents one 4KB frame:
/// - 0 = frame is free
/// - 1 = frame is allocated or reserved
///
/// The bitmap is stored in kernel BSS, so it's automatically zeroed at boot.
pub struct FrameAllocator {
    /// Bitmap tracking frame usage (1 = used, 0 = free)
    bitmap: [u64; BITMAP_WORDS],
    /// Total number of frames in the system
    total_frames: usize,
    /// Number of free frames
    free_frames: usize,
    /// Whether the allocator has been initialized
    initialized: bool,
    /// Hint for next allocation search (optimization)
    next_free_hint: usize,
}

impl FrameAllocator {
    /// Create a new, uninitialized frame allocator
    pub const fn new() -> Self {
        Self {
            bitmap: [0; BITMAP_WORDS],
            total_frames: 0,
            free_frames: 0,
            initialized: false,
            next_free_hint: 0,
        }
    }

    /// Initialize the allocator from the boot memory map
    ///
    /// This marks all frames as used initially, then frees the usable regions.
    /// This ensures reserved/MMIO regions stay marked as used.
    pub fn init(&mut self, memory_map: &MemoryMap) {
        // Start with all frames marked as used
        for word in self.bitmap.iter_mut() {
            *word = !0u64;
        }

        self.total_frames = 0;
        self.free_frames = 0;

        // Free the usable memory regions
        for region in memory_map.iter() {
            if region.region_type == MemoryRegionType::Usable {
                let start_frame = Frame::containing_address(PhysAddr::new(region.base));
                let end_addr = region.base + region.length;
                let end_frame = Frame::containing_address(PhysAddr::new(end_addr));

                // Align to frame boundaries (conservative: only free complete frames)
                let first_frame = if PhysAddr::new(region.base).is_aligned() {
                    start_frame.number()
                } else {
                    start_frame.number() + 1
                };
                let last_frame = end_frame.number();

                for frame_num in first_frame..last_frame {
                    if frame_num < MAX_FRAMES {
                        self.mark_free(frame_num);
                        self.total_frames += 1;
                        self.free_frames += 1;
                    }
                }
            }
        }

        self.initialized = true;
        self.next_free_hint = 0;
    }

    /// Mark frames used by the kernel as allocated
    ///
    /// This should be called after init() to protect kernel memory.
    /// The kernel spans from kernel_physical_base for some size.
    pub fn reserve_kernel(&mut self, kernel_start: PhysAddr, kernel_size: usize) {
        let start_frame = kernel_start.containing_frame().number();
        let num_frames = (kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;

        for i in 0..num_frames {
            let frame_num = start_frame + i;
            if frame_num < MAX_FRAMES && !self.is_allocated(frame_num) {
                self.mark_used(frame_num);
                if self.free_frames > 0 {
                    self.free_frames -= 1;
                }
            }
        }
    }

    /// Reserve a specific range of physical addresses
    pub fn reserve_range(&mut self, start: PhysAddr, size: usize) {
        self.reserve_kernel(start, size);
    }

    /// Allocate a free frame
    ///
    /// Returns the allocated frame, or an error if no frames are available.
    pub fn allocate(&mut self) -> Result<Frame, FrameAllocatorError> {
        if !self.initialized {
            return Err(FrameAllocatorError::NotInitialized);
        }

        if self.free_frames == 0 {
            return Err(FrameAllocatorError::OutOfMemory);
        }

        // Search for a free frame starting from the hint
        let start_word = self.next_free_hint / 64;

        // Search from hint to end
        for word_idx in start_word..BITMAP_WORDS {
            if self.bitmap[word_idx] != !0u64 {
                // This word has at least one free bit
                let bit = self.find_free_bit(self.bitmap[word_idx]);
                let frame_num = word_idx * 64 + bit;

                self.mark_used(frame_num);
                self.free_frames -= 1;
                self.next_free_hint = frame_num + 1;

                return Ok(Frame::from_number(frame_num));
            }
        }

        // Wrap around and search from beginning to hint
        for word_idx in 0..start_word {
            if self.bitmap[word_idx] != !0u64 {
                let bit = self.find_free_bit(self.bitmap[word_idx]);
                let frame_num = word_idx * 64 + bit;

                self.mark_used(frame_num);
                self.free_frames -= 1;
                self.next_free_hint = frame_num + 1;

                return Ok(Frame::from_number(frame_num));
            }
        }

        Err(FrameAllocatorError::OutOfMemory)
    }

    /// Allocate a specific physical frame
    ///
    /// This is used when an application requests a specific physical page,
    /// such as for device MMIO or DMA buffers.
    pub fn allocate_specific(&mut self, frame: Frame) -> Result<(), FrameAllocatorError> {
        if !self.initialized {
            return Err(FrameAllocatorError::NotInitialized);
        }

        let frame_num = frame.number();

        if frame_num >= MAX_FRAMES {
            return Err(FrameAllocatorError::InvalidFrame);
        }

        if self.is_allocated(frame_num) {
            return Err(FrameAllocatorError::FrameInUse);
        }

        self.mark_used(frame_num);
        self.free_frames -= 1;

        Ok(())
    }

    /// Deallocate a frame
    pub fn deallocate(&mut self, frame: Frame) -> Result<(), FrameAllocatorError> {
        if !self.initialized {
            return Err(FrameAllocatorError::NotInitialized);
        }

        let frame_num = frame.number();

        if frame_num >= MAX_FRAMES {
            return Err(FrameAllocatorError::InvalidFrame);
        }

        if !self.is_allocated(frame_num) {
            // Double-free is a bug, but we'll just ignore it
            return Ok(());
        }

        self.mark_free(frame_num);
        self.free_frames += 1;

        // Update hint if this frame is before the current hint
        if frame_num < self.next_free_hint {
            self.next_free_hint = frame_num;
        }

        Ok(())
    }

    /// Get the number of free frames
    #[inline]
    pub fn free_count(&self) -> usize {
        self.free_frames
    }

    /// Get the total number of usable frames
    #[inline]
    pub fn total_count(&self) -> usize {
        self.total_frames
    }

    /// Get the amount of free memory in bytes
    #[inline]
    pub fn free_memory(&self) -> usize {
        self.free_frames * PAGE_SIZE
    }

    /// Get the total amount of usable memory in bytes
    #[inline]
    pub fn total_memory(&self) -> usize {
        self.total_frames * PAGE_SIZE
    }

    /// Check if a frame is allocated
    #[inline]
    fn is_allocated(&self, frame_num: usize) -> bool {
        let word_idx = frame_num / 64;
        let bit_idx = frame_num % 64;
        (self.bitmap[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Mark a frame as used
    #[inline]
    fn mark_used(&mut self, frame_num: usize) {
        let word_idx = frame_num / 64;
        let bit_idx = frame_num % 64;
        self.bitmap[word_idx] |= 1u64 << bit_idx;
    }

    /// Mark a frame as free
    #[inline]
    fn mark_free(&mut self, frame_num: usize) {
        let word_idx = frame_num / 64;
        let bit_idx = frame_num % 64;
        self.bitmap[word_idx] &= !(1u64 << bit_idx);
    }

    /// Find the first free bit (0) in a word
    #[inline]
    fn find_free_bit(&self, word: u64) -> usize {
        // Find the first zero bit using bitwise NOT and trailing zeros
        (!word).trailing_zeros() as usize
    }
}

// Global frame allocator instance
use spin::Mutex;

/// Global frame allocator, protected by a spinlock
pub static FRAME_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());

/// Initialize the global frame allocator
pub fn init(boot_info: &BootInfo) {
    let mut allocator = FRAME_ALLOCATOR.lock();
    allocator.init(&boot_info.memory_map);

    // Reserve the kernel's physical memory
    // The kernel is loaded at 1MB and spans some amount
    // We conservatively reserve 16MB for the kernel and its data structures
    allocator.reserve_kernel(
        PhysAddr::new(boot_info.kernel_physical_base),
        16 * 1024 * 1024,
    );

    // Reserve the first 1MB (real mode IVT, BIOS data, etc.)
    allocator.reserve_range(PhysAddr::new(0), 1024 * 1024);
}

/// Allocate a physical frame from the global allocator
pub fn allocate_frame() -> Result<Frame, FrameAllocatorError> {
    FRAME_ALLOCATOR.lock().allocate()
}

/// Allocate a specific physical frame
pub fn allocate_frame_at(addr: PhysAddr) -> Result<Frame, FrameAllocatorError> {
    let frame = addr.containing_frame();
    FRAME_ALLOCATOR.lock().allocate_specific(frame)?;
    Ok(frame)
}

/// Deallocate a physical frame
pub fn deallocate_frame(frame: Frame) -> Result<(), FrameAllocatorError> {
    FRAME_ALLOCATOR.lock().deallocate(frame)
}

/// Get current memory statistics
pub fn memory_stats() -> (usize, usize) {
    let allocator = FRAME_ALLOCATOR.lock();
    (allocator.free_memory(), allocator.total_memory())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_info::MemoryMap;

    fn create_test_memory_map() -> MemoryMap {
        let mut map = MemoryMap::empty();
        // Add some usable memory: 1MB to 128MB
        map.add(0x100000, 127 * 1024 * 1024, MemoryRegionType::Usable);
        map
    }

    #[test]
    fn test_phys_addr() {
        let addr = PhysAddr::new(0x1000);
        assert_eq!(addr.as_u64(), 0x1000);
        assert!(addr.is_aligned());

        let unaligned = PhysAddr::new(0x1234);
        assert!(!unaligned.is_aligned());
        assert_eq!(unaligned.align_down().as_u64(), 0x1000);
        assert_eq!(unaligned.align_up().as_u64(), 0x2000);
    }

    #[test]
    fn test_frame() {
        let frame = Frame::from_number(256);
        assert_eq!(frame.number(), 256);
        assert_eq!(frame.start_address().as_u64(), 256 * 4096);

        let frame2 = Frame::containing_address(PhysAddr::new(0x100500));
        assert_eq!(frame2.number(), 0x100);
    }

    #[test]
    fn test_allocator_init() {
        let mut allocator = FrameAllocator::new();
        let map = create_test_memory_map();
        allocator.init(&map);

        assert!(allocator.initialized);
        assert!(allocator.free_frames > 0);
        assert!(allocator.total_frames > 0);
    }

    #[test]
    fn test_allocate_deallocate() {
        let mut allocator = FrameAllocator::new();
        let map = create_test_memory_map();
        allocator.init(&map);

        let initial_free = allocator.free_count();

        // Allocate a frame
        let frame = allocator.allocate().unwrap();
        assert_eq!(allocator.free_count(), initial_free - 1);

        // Deallocate it
        allocator.deallocate(frame).unwrap();
        assert_eq!(allocator.free_count(), initial_free);
    }

    #[test]
    fn test_allocate_specific() {
        let mut allocator = FrameAllocator::new();
        let map = create_test_memory_map();
        allocator.init(&map);

        // Allocate a specific frame in usable memory
        let frame = Frame::from_number(512); // 2MB, should be in usable region
        allocator.allocate_specific(frame).unwrap();

        // Try to allocate it again - should fail
        assert_eq!(
            allocator.allocate_specific(frame),
            Err(FrameAllocatorError::FrameInUse)
        );
    }
}
