/* Linker script for XOmB multiboot2 kernel (higher-half) */

ENTRY(_start)

/* Physical load address (standard location for multiboot) */
KERNEL_PHYS = 0x100000;

/* Virtual address base (top 2GB for kernel code model compatibility) */
KERNEL_VIRT = 0xFFFFFFFF80000000;

SECTIONS
{
    /* ===== Boot sections at physical addresses ===== */
    /* These run before paging maps the higher-half */

    . = KERNEL_PHYS;
    _kernel_phys_start = .;

    /* Multiboot2 header must be in the first 32KB of the file */
    .multiboot2_header : ALIGN(8)
    {
        KEEP(*(.multiboot2_header))
    }

    /* Boot code (32-bit startup and 64-bit trampoline) */
    /* Must be at physical address for initial execution */
    .text.boot : ALIGN(4096)
    {
        *(.text.boot)
    }

    /* Record end of low-memory boot sections */
    . = ALIGN(4096);
    _boot_end_phys = .;

    /* ===== Kernel sections at higher-half virtual addresses ===== */

    /* Calculate physical address where higher-half sections will be loaded */
    _higher_half_phys = .;

    /* Switch to higher-half virtual addresses */
    . = KERNEL_VIRT + _higher_half_phys;

    /* Main kernel code */
    .text : AT(_higher_half_phys)
    {
        _text_start = .;
        *(.text .text.*)
        _text_end = .;
    }

    /* Read-only data - use ALIGN to ensure proper separation */
    . = ALIGN(4096);
    .rodata : AT(_higher_half_phys + (. - (KERNEL_VIRT + _higher_half_phys)))
    {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
    }

    /* Initialized data */
    . = ALIGN(4096);
    .data : AT(_higher_half_phys + (. - (KERNEL_VIRT + _higher_half_phys)))
    {
        _data_start = .;
        *(.data .data.*)
        _data_end = .;
    }

    /* BSS (uninitialized data) */
    . = ALIGN(4096);
    .bss (NOLOAD) : AT(_higher_half_phys + (. - (KERNEL_VIRT + _higher_half_phys)))
    {
        _bss_start = .;
        __bss_start = .;
        *(.bss .bss.*)
        *(.bss.stack)
        *(COMMON)
        __bss_end = .;
        _bss_end = .;
    }

    /* Kernel end markers */
    . = ALIGN(4096);
    _kernel_virt_end = .;
    _kernel_phys_end = _higher_half_phys + (. - (KERNEL_VIRT + _higher_half_phys));

    /* Discard unnecessary sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
