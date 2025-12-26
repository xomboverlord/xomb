# Stage 1: Non-Preemptive Single Process Kernel

This document outlines the work required to build the initial XOmB exokernel as described in docs/MAIN.md. Stage 1 focuses on a non-preemptive, single-process kernel to establish the core mechanisms without solving scheduling and preemption problems.

## Goals

- Establish the kernel's page table as the root of the system
- Implement the five core kernel actions (for a single process)
- Demonstrate resource allocation and access control via paging
- Provide a foundation for Library OS development

## Core Kernel Actions to Implement

### 1. Create a Process (Virtual Address Space)

A process is represented as a page table entry at a level below the kernel's root page table. On x86-64 with 5-level paging, this means:

- Kernel owns PML5 (or PML4 on 4-level systems)
- A process is a PML4 (or PML3) entry that the kernel maps into its root

**Tasks:**
- [ ] Define the process data structure (essentially a page table root + metadata)
- [ ] Implement process creation (allocate page table, initialize entries)
- [ ] Map the process into the kernel's address space

### 2. Allocate a Resource

Resources are memory-mapped regions represented as page table structures that can be attached to processes.

**Tasks:**
- [ ] Define resource types (physical memory regions, device MMIO, etc.)
- [ ] Implement resource allocation (create page table entries representing the resource)
- [ ] Track allocated resources (ownership, reference counting?)

### 3. Attach a Resource to a Virtual Address Space

Link a resource's page table entry into a process's page table at a specified virtual address.

**Tasks:**
- [ ] Implement resource attachment (map resource page table into process page table)
- [ ] Handle alignment requirements (superpages: 2MB, 1GB)
- [ ] Set appropriate access flags (read, write, execute, user/supervisor)

### 4. Update Resource Access

Modify the access permissions of an already-attached resource.

**Tasks:**
- [ ] Implement permission updates (modify page table entry flags)
- [ ] Handle TLB invalidation (invlpg, or full flush)
- [ ] Consider cache coherency implications

### 5. Atomically Swap Resource Access

Transfer a resource from one process to another atomically.

**Tasks:**
- [ ] Implement atomic swap (null one entry while setting another)
- [ ] Handle TLB/cache synchronization
- [ ] Note: In single-process Stage 1, this may be simplified

## Infrastructure Required

### Physical Memory Management

**Tasks:**
- [ ] Parse memory map from bootloader (multiboot2/UEFI)
- [ ] Implement physical frame allocator
- [ ] Track free/used physical pages

### Page Table Management

**Tasks:**
- [ ] Implement page table creation and manipulation
- [ ] Support for 4KB, 2MB, and 1GB pages (superpages)
- [x] Kernel mapping strategy: higher-half at 0xFFFFFFFF80000000 with recursive mapping at PML4[510]

### System Call Interface

**Tasks:**
- [ ] Define syscall mechanism (syscall/sysret instruction)
- [ ] Implement syscall handler
- [ ] Define initial syscall ABI for the five core actions

### Initial Process Loading

**Tasks:**
- [ ] Define executable format (ELF?)
- [ ] Load initial process from boot module or embedded binary
- [ ] Transfer control to user mode

## Design Decisions

### Memory Layout

- **Higher-half kernel**: Kernel mapped at 0xFFFFFFFF80000000 (top 2GB, required for kernel code model)
- **4-level paging**: Using standard x86-64 4-level paging (PML4 → PDPT → PD → PT). 5-level paging (LA57) is a future consideration.
- **Self-referencing page table**: PML4[510] points to the PML4 itself, enabling recursive page table access
- **Kernel mapping**: PML4[511] maps the kernel's higher-half address space

#### PML4 Layout

| Index | Purpose | Virtual Address Range |
|-------|---------|----------------------|
| 0 | Identity map (boot only) | 0x0000_0000_0000_0000 - 0x0000_007F_FFFF_FFFF |
| 510 | Recursive mapping | 0xFFFF_FF00_0000_0000 - 0xFFFF_FF7F_FFFF_FFFF |
| 511 | Kernel higher-half | 0xFFFF_FF80_0000_0000 - 0xFFFF_FFFF_FFFF_FFFF |

#### Recursive Mapping Implications

With PML4[510] as the self-reference entry:
- **Recursive region base**: 0xFFFF_FF00_0000_0000
- **PML4 accessible at**: 0xFFFF_FF7F_BFDF_E000
- **Any page table** can be accessed by constructing the appropriate virtual address

The recursive mapping formula for accessing page table entries:
```
PML4:       0xFFFFFF7FBFDFE000 + (pml4_idx * 8)
PDPT:       0xFFFFFF7FBFC00000 + (pml4_idx * 0x1000) + (pdpt_idx * 8)
PD:         0xFFFFFF7F80000000 + (pml4_idx * 0x200000) + (pdpt_idx * 0x1000) + (pd_idx * 8)
PT:         0xFFFFFF0000000000 + (pml4_idx * 0x40000000) + (pdpt_idx * 0x200000) + (pd_idx * 0x1000) + (pt_idx * 8)
```

## Open Questions

The following questions need to be answered before or during implementation:

### Resource Model

1. **Resource granularity**: What's the minimum resource size? A single 4KB page, or always aligned to superpages?

2. **Device resources in Stage 1**: Do we need device MMIO support, or just physical memory? For a minimal kernel, memory-only may suffice.

3. **Resource metadata**: Where do we store resource metadata (size, type, owner)? Separate structures, or encoded in page table entries?

### Process Model

4. **Process metadata location**: Where does process state live? In kernel memory, or in a reserved area of the process's own address space?

5. **Initial process origin**: Is the first process loaded from a multiboot module, embedded in the kernel, or loaded from a filesystem?

### Stage 1 Scope

6. **User mode in Stage 1?**: Does Stage 1 require actual user-mode execution, or can we demonstrate the mechanisms with kernel-mode "processes" first?

7. **Serial/console output from processes**: How do processes output debug information? Direct serial access? Kernel-provided syscall?

## Boot Code Status

The boot assembly (`src/boot/multiboot2_header.asm`) and linker script (`linker-multiboot2.ld`) have been updated:

1. **[DONE] Identity map first 1GB** - PML4[0] → PDPT_LOW → PD (512 x 2MB pages)
2. **[DONE] Map kernel at higher-half** - PML4[511] → PDPT_HIGH → PD at 0xFFFFFFFF80000000
3. **[DONE] Set up recursive mapping** - PML4[510] = physical address of PML4 | flags
4. **[DONE] Jump to higher-half** - Boot code transitions to higher-half stack and calls Rust entry point
5. **[TODO] Unmap identity mapping** - Remove PML4[0] once running in higher-half (can be done in Rust)

## Suggested Implementation Order

1. ~~Update boot code for higher-half + recursive mapping~~ **[DONE]**
2. ~~Update linker script for higher-half kernel~~ **[DONE]**
3. Physical memory allocator (using boot memory map)
4. Page table manipulation primitives (using recursive mapping)
5. Process creation (allocate PML4, map into kernel space)
6. Resource allocation (physical memory regions as page table structures)
7. Resource attachment (map into process address space)
8. Permission updates and TLB management
9. System call interface
10. Initial process loading and user-mode transition
11. Atomic resource swapping

## Success Criteria

Stage 1 is complete when:

- A single process can be created with its own virtual address space
- Physical memory resources can be allocated and mapped into the process
- Access permissions can be set and modified
- The process can execute code in user mode
- Basic syscalls allow the process to request resources from the kernel
