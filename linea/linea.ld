/* Linea zkVM linker script.
 *
 * Memory layout:
 *   PROGRAM  0x00000000  128 MiB  code + rodata + data + bss
 *   STACK    0x08000000    8 MiB  grows downward from _stack_start (0x08800000)
 *   IN       0x08800000    1 GiB  memory-mapped input (_input_start)
 */

OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
    PROGRAM (rx) : ORIGIN = 0x00000000, LENGTH = 0x8000000
    STACK   (rw) : ORIGIN = 0x08000000, LENGTH = 0x800000
    IN      (r)  : ORIGIN = 0x08800000, LENGTH = 0x40000000
}

SECTIONS {
    . = ORIGIN(PROGRAM);

    .text : {
        KEEP(*(.text._start))
        *(.text .text.*)
    } > PROGRAM

    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > PROGRAM

    .data : ALIGN(8) {
        *(.data .data.*)
        PROVIDE(__global_pointer$ = . + 0x800);
        *(.sdata .sdata.*)
    } > PROGRAM

    .bss : ALIGN(8) {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    } > PROGRAM

    /* Heap starts immediately after BSS; grows up to stack bottom. */
    _end = ALIGN(8);

    /* Stack grows downward from the top of the STACK region. */
    _stack_start = ORIGIN(STACK) + LENGTH(STACK);

    /* Memory-mapped input region. */
    _input_start = ORIGIN(IN);

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.debug*)
    }
}
