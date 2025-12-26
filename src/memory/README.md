# Physical Memory Allocator

This document describes the physical page frame allocator used by the XOmB exokernel to track and allocate physical memory pages.

## Overview

The kernel multiplexes hardware resources through the virtual memory system. To do this, it needs to allocate physical memory pages for:

- Page table entries (PML4, PDPT, PD, PT)
- Resource mappings for applications
- Kernel data structures

The allocator maintains a bitmap tracking which physical pages (frames) are free or in use. Applications may request specific physical pages for resources like device MMIO or DMA buffers.

## Design

### Bitmap Allocator

We use a bitmap-based allocator where each bit represents one 4KB physical frame:

- **0** = frame is free
- **1** = frame is allocated or reserved

The bitmap is stored as an array of `u64` words, where each word tracks 64 frames (256KB of physical memory).

```
Bitmap word 0:  [frame 0-63]
Bitmap word 1:  [frame 64-127]
...
Bitmap word N:  [frame N*64 to N*64+63]
```

### Memory Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `PAGE_SIZE` | 4096 bytes | Standard x86-64 page size |
| `MAX_PHYSICAL_MEMORY` | 16 GB | Maximum supported physical memory |
| `MAX_FRAMES` | 4,194,304 | Maximum number of 4KB frames |
| `BITMAP_WORDS` | 65,536 | Number of u64 words in bitmap |
| Bitmap size | 512 KB | Total bitmap memory footprint |

### Data Structures

#### PhysAddr

A wrapper type for physical addresses with utility methods:

```rust
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn new(addr: u64) -> Self;           // Create with masking
    pub const fn as_u64(self) -> u64;              // Get raw value
    pub const fn is_aligned(self) -> bool;         // Check 4KB alignment
    pub const fn align_down(self) -> Self;         // Round down to page
    pub const fn align_up(self) -> Self;           // Round up to page
    pub const fn containing_frame(self) -> Frame;  // Get containing frame
}
```

Physical addresses on x86-64 are limited to 52 bits. The upper bits are masked on creation.

#### Frame

Represents a single 4KB physical page frame:

```rust
pub struct Frame {
    number: usize,  // Frame number = physical_address / PAGE_SIZE
}

impl Frame {
    pub const fn from_number(number: usize) -> Self;
    pub const fn containing_address(addr: PhysAddr) -> Self;
    pub const fn number(self) -> usize;
    pub const fn start_address(self) -> PhysAddr;
}
```

#### FrameAllocator

The main allocator structure:

```rust
pub struct FrameAllocator {
    bitmap: [u64; BITMAP_WORDS],  // 512KB bitmap
    total_frames: usize,          // Total usable frames
    free_frames: usize,           // Currently free frames
    initialized: bool,            // Initialization flag
    next_free_hint: usize,        // Optimization hint
}
```

## Initialization

The allocator is initialized from the boot memory map in two phases:

### Phase 1: Mark All As Used

```rust
for word in self.bitmap.iter_mut() {
    *word = !0u64;  // All bits set = all frames used
}
```

This ensures any gaps or reserved regions in the memory map remain marked as unavailable.

### Phase 2: Free Usable Regions

```rust
for region in memory_map.iter() {
    if region.region_type == MemoryRegionType::Usable {
        // Free each complete frame in the region
        for frame_num in first_frame..last_frame {
            self.mark_free(frame_num);
        }
    }
}
```

Only frames that fall completely within usable memory regions are marked as free.

### Phase 3: Reserve Kernel Memory

After initialization, we reserve memory used by the kernel:

```rust
// Reserve first 1MB (BIOS, real mode IVT, etc.)
allocator.reserve_range(PhysAddr::new(0), 1024 * 1024);

// Reserve kernel physical memory (16MB from load address)
allocator.reserve_kernel(PhysAddr::new(0x100000), 16 * 1024 * 1024);
```

## Allocation Algorithm

### Allocate Any Frame

The `allocate()` function finds and allocates any free frame:

```rust
pub fn allocate(&mut self) -> Result<Frame, FrameAllocatorError> {
    // Start search from hint position
    let start_word = self.next_free_hint / 64;

    // Search for a word with at least one free bit
    for word_idx in start_word..BITMAP_WORDS {
        if self.bitmap[word_idx] != !0u64 {
            // Find first free bit using: (!word).trailing_zeros()
            let bit = self.find_free_bit(self.bitmap[word_idx]);
            let frame_num = word_idx * 64 + bit;

            self.mark_used(frame_num);
            self.next_free_hint = frame_num + 1;

            return Ok(Frame::from_number(frame_num));
        }
    }

    // Wrap around if needed...
    Err(FrameAllocatorError::OutOfMemory)
}
```

**Complexity**: O(n/64) worst case, but typically O(1) due to the hint optimization.

### Allocate Specific Frame

The `allocate_specific()` function allocates a particular physical frame:

```rust
pub fn allocate_specific(&mut self, frame: Frame) -> Result<(), FrameAllocatorError> {
    let frame_num = frame.number();

    if frame_num >= MAX_FRAMES {
        return Err(FrameAllocatorError::InvalidFrame);
    }

    if self.is_allocated(frame_num) {
        return Err(FrameAllocatorError::FrameInUse);
    }

    self.mark_used(frame_num);
    Ok(())
}
```

This is essential for the exokernel design where applications may request specific physical pages for:
- Device MMIO regions
- DMA buffers with specific alignment
- Shared memory at known addresses

**Complexity**: O(1)

### Deallocate Frame

```rust
pub fn deallocate(&mut self, frame: Frame) -> Result<(), FrameAllocatorError> {
    let frame_num = frame.number();

    self.mark_free(frame_num);

    // Update hint for faster future allocations
    if frame_num < self.next_free_hint {
        self.next_free_hint = frame_num;
    }

    Ok(())
}
```

**Complexity**: O(1)

## Bit Manipulation

The bitmap operations use efficient bitwise operations:

```rust
// Check if frame is allocated
fn is_allocated(&self, frame_num: usize) -> bool {
    let word_idx = frame_num / 64;
    let bit_idx = frame_num % 64;
    (self.bitmap[word_idx] & (1u64 << bit_idx)) != 0
}

// Mark frame as used
fn mark_used(&mut self, frame_num: usize) {
    let word_idx = frame_num / 64;
    let bit_idx = frame_num % 64;
    self.bitmap[word_idx] |= 1u64 << bit_idx;
}

// Mark frame as free
fn mark_free(&mut self, frame_num: usize) {
    let word_idx = frame_num / 64;
    let bit_idx = frame_num % 64;
    self.bitmap[word_idx] &= !(1u64 << bit_idx);
}

// Find first free bit (0) in a word
fn find_free_bit(&self, word: u64) -> usize {
    (!word).trailing_zeros() as usize
}
```

## Global Interface

The allocator is wrapped in a spinlock for thread-safety:

```rust
pub static FRAME_ALLOCATOR: Mutex<FrameAllocator> = Mutex::new(FrameAllocator::new());
```

Convenience functions provide a simple API:

```rust
// Initialize from boot info
pub fn init(boot_info: &BootInfo);

// Allocate a frame
pub fn allocate_frame() -> Result<Frame, FrameAllocatorError>;

// Allocate at specific address
pub fn allocate_frame_at(addr: PhysAddr) -> Result<Frame, FrameAllocatorError>;

// Deallocate a frame
pub fn deallocate_frame(frame: Frame) -> Result<(), FrameAllocatorError>;

// Get statistics
pub fn memory_stats() -> (free_bytes, total_bytes);
```

## Error Handling

```rust
pub enum FrameAllocatorError {
    OutOfMemory,      // No free frames available
    FrameInUse,       // Requested specific frame is already allocated
    InvalidFrame,     // Frame number exceeds MAX_FRAMES
    NotInitialized,   // Allocator not yet initialized
}
```

## Memory Layout Example

After boot on a system with 512MB RAM:

```
Physical Memory Layout:
0x00000000 - 0x00100000  [Reserved: BIOS, real mode]
0x00100000 - 0x01000000  [Reserved: Kernel + 16MB buffer]
0x01000000 - 0x1FFF0000  [Free: ~495MB available]
0x1FFF0000 - 0x20000000  [ACPI Reclaimable]

Frame Allocator State:
  Total frames:  ~131,000 (from usable regions)
  Free frames:   ~126,000 (after kernel reservation)
  Free memory:   ~494 MB
```

## Source Files

| File | Description |
|------|-------------|
| `src/memory/mod.rs` | Module root, constants, alignment functions |
| `src/memory/frame.rs` | PhysAddr, Frame, FrameAllocator implementation |

## Future Considerations

1. **Buddy Allocator**: For contiguous multi-frame allocations (superpages)
2. **NUMA Awareness**: Track which memory node frames belong to
3. **Memory Zones**: Separate low memory (<4GB) for legacy DMA
4. **Statistics**: Track allocation patterns, fragmentation metrics
