/* Linea zkVM guest entry point.
 * Placed in .text._start so the linker script's KEEP(*(.text._start))
 * forces it to the very first instruction at PROGRAM origin (0x00000000).
 */
	.section .text._start,"ax",@progbits
	.global _start
	.type   _start, @function
_start:
	la   sp, _stack_start
	call linea_init_heap
	call main
	unimp
	.size _start, . - _start
