//! Process management for XOmB exokernel
//!
//! In XOmB, a process is fundamentally a virtual address space represented
//! by a page table. The kernel maintains minimal state - just enough to
//! securely multiplex hardware resources via paging.
//!
//! Each process owns its page table structure and can map resources into
//! its address space via kernel primitives.

use crate::memory::{PhysAddr, VirtAddr};
use crate::memory::frame::allocate_frame;
use crate::memory::paging::{self, flags};

/// Maximum number of processes supported
pub const MAX_PROCESSES: usize = 64;

/// Process ID type
pub type Pid = u16;

/// Process states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process slot is unused
    Free,
    /// Process is being created
    Creating,
    /// Process is ready to run
    Ready,
    /// Process is currently running
    Running,
    /// Process has exited
    Exited,
}

/// A process in XOmB
///
/// In the exokernel model, a process is primarily its virtual address space.
/// The page table (PML4) is the fundamental data structure representing a process.
#[derive(Debug)]
pub struct Process {
    /// Process ID
    pub pid: Pid,
    /// Current state
    pub state: ProcessState,
    /// Physical address of the PML4 (page table root)
    /// This is what gets loaded into CR3 to switch to this process
    pub page_table: PhysAddr,
    /// Saved stack pointer (for context switching)
    pub rsp: u64,
    /// Saved instruction pointer (for context switching)
    pub rip: u64,
    /// Saved RFLAGS
    pub rflags: u64,
}

impl Process {
    /// Create an empty/free process slot
    pub const fn empty() -> Self {
        Self {
            pid: 0,
            state: ProcessState::Free,
            page_table: PhysAddr::new(0),
            rsp: 0,
            rip: 0,
            rflags: 0,
        }
    }

    /// Check if this process slot is free
    pub fn is_free(&self) -> bool {
        self.state == ProcessState::Free
    }
}

/// The process table
///
/// This is a simple static array of process slots. Process 0 is reserved
/// for the kernel.
pub struct ProcessTable {
    processes: [Process; MAX_PROCESSES],
    /// Number of active processes
    count: usize,
}

impl ProcessTable {
    /// Create a new empty process table
    pub const fn new() -> Self {
        Self {
            processes: [const { Process::empty() }; MAX_PROCESSES],
            count: 0,
        }
    }

    /// Allocate a new process ID
    fn allocate_pid(&mut self) -> Option<Pid> {
        // Find first free slot (skip 0, reserved for kernel)
        for i in 1..MAX_PROCESSES {
            if self.processes[i].is_free() {
                return Some(i as Pid);
            }
        }
        None
    }

    /// Get a process by PID
    pub fn get(&self, pid: Pid) -> Option<&Process> {
        let idx = pid as usize;
        if idx < MAX_PROCESSES && !self.processes[idx].is_free() {
            Some(&self.processes[idx])
        } else {
            None
        }
    }

    /// Get a mutable reference to a process by PID
    pub fn get_mut(&mut self, pid: Pid) -> Option<&mut Process> {
        let idx = pid as usize;
        if idx < MAX_PROCESSES && !self.processes[idx].is_free() {
            Some(&mut self.processes[idx])
        } else {
            None
        }
    }

    /// Create a new process with its own address space
    ///
    /// Returns the PID of the new process, or None if creation failed.
    pub fn create(&mut self) -> Result<Pid, ProcessError> {
        // Allocate a PID
        let pid = self.allocate_pid().ok_or(ProcessError::TooManyProcesses)?;

        // Allocate a frame for the new PML4
        let pml4_frame = allocate_frame().map_err(|_| ProcessError::OutOfMemory)?;
        let pml4_phys = pml4_frame.start_address();

        // Initialize the new page table with kernel mappings
        init_page_table(pml4_phys)?;

        // Note: Frame is Copy and doesn't have a destructor, so it stays
        // allocated. The frame is now owned by the process's page table.

        // Initialize the process
        let process = &mut self.processes[pid as usize];
        process.pid = pid;
        process.state = ProcessState::Creating;
        process.page_table = pml4_phys;
        process.rsp = 0;
        process.rip = 0;
        process.rflags = 0x200; // Interrupts enabled

        self.count += 1;

        Ok(pid)
    }

    /// Mark a process as ready to run
    pub fn set_ready(&mut self, pid: Pid) -> Result<(), ProcessError> {
        let process = self.get_mut(pid).ok_or(ProcessError::InvalidPid)?;
        if process.state != ProcessState::Creating {
            return Err(ProcessError::InvalidState);
        }
        process.state = ProcessState::Ready;
        Ok(())
    }

    /// Mark a process as running
    pub fn set_running(&mut self, pid: Pid) -> Result<(), ProcessError> {
        let process = self.get_mut(pid).ok_or(ProcessError::InvalidPid)?;
        if process.state != ProcessState::Ready {
            return Err(ProcessError::InvalidState);
        }
        process.state = ProcessState::Running;
        Ok(())
    }

    /// Get the number of active processes
    pub fn count(&self) -> usize {
        self.count
    }
}

/// Process-related errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    /// Too many processes already exist
    TooManyProcesses,
    /// Out of memory for process structures
    OutOfMemory,
    /// Invalid process ID
    InvalidPid,
    /// Invalid state transition
    InvalidState,
    /// Page table initialization failed
    PageTableError,
}

/// Temporary virtual address for mapping new page tables during setup
/// Uses an address in the kernel temporary mapping region (PML4[509])
const TEMP_MAP_ADDR: u64 = 0xFFFFFE8000001000;

/// Initialize a new process's page table
///
/// This maps the new PML4 temporarily, clears user-space entries,
/// and copies kernel-space entries from the current page table.
fn init_page_table(pml4_phys: PhysAddr) -> Result<(), ProcessError> {
    let temp_virt = VirtAddr::new(TEMP_MAP_ADDR);

    // Map the new PML4 at our temporary address
    paging::map_4kb(temp_virt, pml4_phys, flags::KERNEL_DATA)
        .map_err(|_| ProcessError::PageTableError)?;

    // Access the new PML4 through the temporary mapping
    let pml4_ptr = temp_virt.as_u64() as *mut u64;

    unsafe {
        // Clear user-space entries (0-255)
        for i in 0..256 {
            core::ptr::write_volatile(pml4_ptr.add(i), 0);
        }

        // Copy kernel-space entries (256-511) from current PML4
        // EXCEPT for entry 510 (recursive mapping) which needs to point to THIS PML4
        for i in 256..512 {
            if i == 510 {
                // Set recursive mapping to point to this new PML4 itself
                // Use PRESENT | WRITABLE flags (same as kernel recursive mapping)
                let self_ref_entry = pml4_phys.as_u64() | flags::PRESENT | flags::WRITABLE;
                core::ptr::write_volatile(pml4_ptr.add(i), self_ref_entry);
            } else {
                let entry = paging::read_pml4(i);
                core::ptr::write_volatile(pml4_ptr.add(i), entry.bits());
            }
        }
    }

    // Unmap the temporary mapping (don't free the frame - it's the new page table!)
    // We need to manually clear the mapping without freeing
    paging::unmap_4kb(temp_virt).map_err(|_| ProcessError::PageTableError)?;

    Ok(())
}

// Global process table
use core::cell::UnsafeCell;

struct SyncProcessTable(UnsafeCell<ProcessTable>);
unsafe impl Sync for SyncProcessTable {}

static PROCESS_TABLE: SyncProcessTable = SyncProcessTable(UnsafeCell::new(ProcessTable::new()));

/// Initialize the process subsystem
///
/// Sets up process 0 as the kernel process using the current page table.
pub fn init() {
    let table = unsafe { &mut *PROCESS_TABLE.0.get() };

    // Process 0 is the kernel - it uses the current page table
    let kernel_process = &mut table.processes[0];
    kernel_process.pid = 0;
    kernel_process.state = ProcessState::Running;

    // Get current CR3 as the kernel's page table
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
    }
    kernel_process.page_table = PhysAddr::new(cr3 & !0xFFF); // Mask off flags

    table.count = 1;
}

/// Create a new process
pub fn create() -> Result<Pid, ProcessError> {
    let table = unsafe { &mut *PROCESS_TABLE.0.get() };
    table.create()
}

/// Get a process by PID
pub fn get(pid: Pid) -> Option<&'static Process> {
    let table = unsafe { &*PROCESS_TABLE.0.get() };
    table.get(pid)
}

/// Get the current process count
pub fn count() -> usize {
    let table = unsafe { &*PROCESS_TABLE.0.get() };
    table.count()
}

/// Get the current running process (for now, always kernel)
pub fn current() -> &'static Process {
    let table = unsafe { &*PROCESS_TABLE.0.get() };
    &table.processes[0]
}

/// Switch to a process's address space by loading its page table
///
/// # Safety
/// The process must have a valid, properly initialized page table.
/// The kernel mappings must be present in the new page table.
pub unsafe fn switch_address_space(pid: Pid) -> Result<(), ProcessError> {
    let table = unsafe { &*PROCESS_TABLE.0.get() };
    let process = table.get(pid).ok_or(ProcessError::InvalidPid)?;

    // Load the new page table into CR3
    let new_cr3 = process.page_table.as_u64();
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) new_cr3,
            options(nostack, preserves_flags)
        );
    }

    Ok(())
}

/// Switch back to the kernel's address space
pub fn switch_to_kernel() {
    let table = unsafe { &*PROCESS_TABLE.0.get() };
    let kernel = &table.processes[0];

    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) kernel.page_table.as_u64(),
            options(nostack, preserves_flags)
        );
    }
}

/// Jump to user mode (ring 3)
///
/// This uses IRETQ to transition from ring 0 to ring 3.
///
/// # Arguments
/// * `entry` - User code entry point
/// * `stack` - User stack pointer
///
/// # Safety
/// The entry point and stack must be valid mapped addresses in user space.
/// The current process's page table must have proper user mappings.
pub unsafe fn jump_to_user(entry: u64, stack: u64) -> ! {
    use crate::arch::x86_64::gdt;
    use crate::serial::SerialPort;
    use core::fmt::Write;

    let user_cs = gdt::user_cs() as u64;
    let user_ds = gdt::user_ds() as u64;

    // Debug: Print what we're about to push
    let mut serial = unsafe { SerialPort::new(0x3F8) };
    writeln!(serial, "    IRETQ frame: SS={:#x} RSP={:#x} RFLAGS=0x202 CS={:#x} RIP={:#x}",
             user_ds, stack, user_cs, entry).ok();

    // Verify the entry point is mapped and accessible
    use crate::memory::paging;
    use crate::memory::VirtAddr;
    let entry_virt = VirtAddr::new(entry);
    if let Some((phys, size, flags)) = paging::get_mapping_info(entry_virt) {
        writeln!(serial, "    Entry mapping: phys={:#x} size={:?} flags={:#x}", phys, size, flags).ok();
    } else {
        writeln!(serial, "    WARNING: Entry point {:#x} is NOT MAPPED!", entry).ok();
    }

    // Verify the stack is mapped
    let stack_virt = VirtAddr::new(stack - 8);  // Stack will be decremented
    if let Some((phys, size, flags)) = paging::get_mapping_info(stack_virt) {
        writeln!(serial, "    Stack mapping: phys={:#x} size={:?} flags={:#x}", phys, size, flags).ok();
    } else {
        writeln!(serial, "    WARNING: Stack {:#x} is NOT MAPPED!", stack).ok();
    }

    // Flush TLB to ensure all page table changes are visible
    // This reloads CR3 which flushes the entire TLB
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }

    // IRETQ expects the stack to contain (top to bottom):
    // [RSP+0]  RIP   - last pushed, first popped
    // [RSP+8]  CS
    // [RSP+16] RFLAGS
    // [RSP+24] RSP
    // [RSP+32] SS    - first pushed, last popped
    //
    // Note: DS/ES/FS/GS must be set to valid user selectors before IRETQ
    // when transitioning to ring 3. Using null (0) is valid in 64-bit mode.
    //
    // IMPORTANT: We must SWAPGS before going to user mode so that:
    // - User mode has GS_BASE = user's TLS (0 for now)
    // - KERNEL_GS_BASE = per-CPU data pointer
    // This way, when SYSCALL happens, SWAPGS in the entry point will
    // give the kernel access to per-CPU data.
    unsafe {
        core::arch::asm!(
            // Set DS/ES to null using r11 - avoid clobbering input registers
            "xor r11d, r11d",
            "mov ds, r11w",
            "mov es, r11w",

            // Memory barrier to ensure all stores are complete
            "mfence",

            // SWAPGS: swap kernel GS with user GS before entering user mode
            // After this: GS_BASE = user's GS (0), KERNEL_GS_BASE = per-CPU data
            "swapgs",

            // Build IRETQ frame on stack
            "push {user_ss}",   // SS
            "push {stack}",     // RSP
            "push 0x202",       // RFLAGS (IF=1, reserved bit 1 = 1)
            "push {user_cs}",   // CS
            "push {entry}",     // RIP

            // Jump to user mode
            "iretq",

            user_cs = in(reg) user_cs,
            user_ss = in(reg) user_ds,  // SS same as DS for user mode
            entry = in(reg) entry,
            stack = in(reg) stack,
            options(noreturn)
        );
    }
}
