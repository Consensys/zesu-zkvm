/* OpenVM zkVM linker script.
 *
 * Memory layout (from openvm-platform/src/memory.rs):
 *   STACK_TOP  = 0x00200400  (stack grows down from here)
 *   TEXT_START = 0x00200800  (ELF loaded here)
 *   MEM_SIZE   = 0x20000000  (512 MB, upper bound for heap)
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
    . = 0x00200800;

    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    .data : ALIGN(8) {
        *(.data .data.*)
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.sdata .sdata.*)
    }

    .bss : ALIGN(8) {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    }

    /* Heap starts immediately after BSS. */
    _end = ALIGN(8);

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.debug*)
    }
}
