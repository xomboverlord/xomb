; Multiboot2 Header and Boot Stub for XOmB
;
; Sets up higher-half kernel with recursive page table mapping.
; Uses 4-level paging with:
;   - PML4[0]   -> Identity map first 1GB (for boot transition)
;   - PML4[510] -> Recursive mapping (points to PML4 itself)
;   - PML4[511] -> Higher-half kernel at 0xFFFFFFFF80000000

MULTIBOOT2_MAGIC        equ 0xe85250d6
MULTIBOOT2_ARCH_I386    equ 0

; Virtual address layout
; Kernel at top 2GB for kernel code model compatibility
KERNEL_VMA              equ 0xFFFFFFFF80000000  ; Higher-half base (top 2GB)
KERNEL_PML4_IDX         equ 511                 ; PML4 index for kernel
KERNEL_PDPT_IDX         equ 510                 ; PDPT index for kernel (within PML4[511])
RECURSIVE_PML4_IDX      equ 510                 ; PML4 index for recursive mapping

; Physical memory layout for page tables
; Place page tables at 2MB to avoid GRUB's boot info which is usually below 1MB
PML4_TABLE              equ 0x200000
PDPT_LOW                equ 0x201000   ; PDPT for identity mapping (PML4[0])
PDPT_HIGH               equ 0x202000   ; PDPT for kernel mapping (PML4[511])
PD_TABLE                equ 0x203000   ; PD shared by both mappings
; Stack must be ABOVE page tables (0x204000+) to avoid being overwritten
PHYS_STACK_TOP          equ 0x280000   ; Physical stack during boot (512KB above page tables)

; Higher-half addresses (used after paging enabled)
KERNEL_STACK_TOP        equ KERNEL_VMA + PHYS_STACK_TOP

extern __bss_start
extern __bss_end
extern multiboot2_entry

; Multiboot2 header
section .multiboot2_header
align 8
multiboot2_header:
    dd MULTIBOOT2_MAGIC
    dd MULTIBOOT2_ARCH_I386
    dd multiboot2_header_end - multiboot2_header    ; Total header size
    dd -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH_I386 + (multiboot2_header_end - multiboot2_header))
    ; Framebuffer request tag
    align 8
    dw 5, 0                 ; type=5 (framebuffer), flags=0
    dd 20                   ; size=20 bytes
    dd 1024                 ; width
    dd 768                  ; height
    dd 32                   ; depth
    ; End tag
    align 8
    dw 0, 0                 ; type=0 (end), flags=0
    dd 8                    ; size=8 bytes
multiboot2_header_end:

; 32-bit boot code
section .text.boot
bits 32
global _start
_start:
    cli

    ; Verify multiboot magic first (before clobbering eax)
    cmp eax, 0x36d76289
    jne .hang32

    ; Set up stack (physical address during boot)
    mov esp, PHYS_STACK_TOP

    ; Save multiboot values on stack (esp is now valid)
    push dword 0        ; Padding for 8-byte alignment
    push eax            ; magic (will be at [esp+4])
    push dword 0        ; Padding
    push ebx            ; info ptr (will be at [esp])

    ; Zero page tables (PML4 + PDPT_LOW + PDPT_HIGH + PD = 4 pages = 4096 dwords)
    mov edi, PML4_TABLE
    xor eax, eax
    mov ecx, 4096
.zero:
    mov [edi], eax
    add edi, 4
    loop .zero

    ; === Set up PML4 entries ===

    ; PML4[0] -> PDPT_LOW (identity mapping for boot transition)
    mov edi, PML4_TABLE
    mov eax, PDPT_LOW | 3       ; Present + Writable
    mov [edi], eax
    mov dword [edi+4], 0

    ; PML4[510] -> PML4 (recursive mapping)
    mov edi, PML4_TABLE + (RECURSIVE_PML4_IDX * 8)
    mov eax, PML4_TABLE | 3     ; Points to itself
    mov [edi], eax
    mov dword [edi+4], 0

    ; PML4[511] -> PDPT_HIGH (kernel mapping at 0xFFFFFFFF80000000)
    mov edi, PML4_TABLE + (KERNEL_PML4_IDX * 8)
    mov eax, PDPT_HIGH | 3      ; Present + Writable
    mov [edi], eax
    mov dword [edi+4], 0

    ; === Set up PDPT entries ===

    ; PDPT_LOW[0] -> PD (identity maps first 1GB at virtual 0x0)
    mov edi, PDPT_LOW
    mov eax, PD_TABLE | 3       ; Present + Writable
    mov [edi], eax
    mov dword [edi+4], 0

    ; PDPT_HIGH[510] -> PD (maps first 1GB at virtual 0xFFFFFFFF80000000)
    ; Index 510 = offset 510 * 8 = 4080 = 0xFF0
    mov edi, PDPT_HIGH + (KERNEL_PDPT_IDX * 8)
    mov eax, PD_TABLE | 3       ; Present + Writable (same PD as identity map)
    mov [edi], eax
    mov dword [edi+4], 0

    ; === Set up PD entries (512 x 2MB pages = 1GB) ===

    mov edi, PD_TABLE
    mov eax, 0x83               ; Present + Writable + PageSize (2MB page)
    mov ecx, 512
.map:
    mov [edi], eax
    mov dword [edi+4], 0
    add eax, 0x200000           ; Next 2MB
    add edi, 8
    loop .map

    ; CR3 = PML4
    mov eax, PML4_TABLE
    mov cr3, eax

    ; Enable PAE
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax

    ; Enable Long Mode (LME) and No-Execute (NXE)
    ; EFER bits: 8=LME, 11=NXE
    mov ecx, 0xC0000080
    rdmsr
    or eax, 0x100 | 0x800       ; LME | NXE
    wrmsr

    ; Enable paging
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax

    ; Load GDT - use dword to force 32-bit absolute addressing
    lgdt [dword gdt_ptr]

    ; Far jump to 64-bit mode
    jmp dword 0x08:long_mode

.hang32:
    hlt
    jmp .hang32

; GDT pointer
align 4
gdt_ptr:
    dw gdt_end - gdt - 1
    dd gdt

; GDT
align 8
gdt:
    dq 0                        ; Null descriptor
gdt_code:
    dw 0xFFFF                   ; Limit
    dw 0                        ; Base low
    db 0                        ; Base mid
    db 0x9A                     ; Access: code, exec/read
    db 0xAF                     ; Flags: 64-bit, limit high
    db 0                        ; Base high
gdt_data:
    dw 0xFFFF
    dw 0
    db 0
    db 0x92                     ; Access: data, read/write
    db 0xCF                     ; Flags: 32-bit
    db 0
gdt_end:

; 64-bit entry point (still running at identity-mapped address)
bits 64
long_mode:
    ; Set up data segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Enable SSE (required by x86-64 ABI for floating-point)
    ; 1. Clear CR0.EM (bit 2) and set CR0.MP (bit 1)
    mov rax, cr0
    and ax, 0xFFFB        ; Clear EM (bit 2)
    or ax, 0x2            ; Set MP (bit 1)
    mov cr0, rax
    ; 2. Set CR4.OSFXSR (bit 9) and CR4.OSXMMEXCPT (bit 10)
    mov rax, cr4
    or ax, (1 << 9) | (1 << 10)
    mov cr4, rax

    ; Set up higher-half stack (using high address now that paging is on)
    mov rsp, KERNEL_STACK_TOP

    ; Zero BSS (linker provides higher-half addresses)
    mov rdi, __bss_start
    mov rcx, __bss_end
    sub rcx, rdi
    jz .skip_bss              ; Skip if BSS is empty
    shr rcx, 3
    xor rax, rax
    rep stosq
.skip_bss:

    ; Restore multiboot values from stack (still at physical address)
    ; Stack layout at PHYS_STACK_TOP: [info_ptr, 0, magic, 0]
    mov edi, [PHYS_STACK_TOP - 16]   ; info ptr
    mov esi, [PHYS_STACK_TOP - 8]    ; magic

    ; Jump to higher-half kernel entry point
    mov rax, multiboot2_entry
    call rax

.hang64:
    cli
    hlt
    jmp .hang64

; Stack
section .bss.stack nobits alloc write
align 16
    resb 65536
