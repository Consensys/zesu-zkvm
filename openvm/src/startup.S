/* OpenVM guest entry point.
 * Placed in .text._start so the linker script's KEEP(*(.text._start))
 * forces it to the very first instruction at TEXT_START (0x00200800).
 */
	.section .text._start,"ax",@progbits
	.global _start
	.type   _start, @function
_start:
	li   sp, 0x00200400
	call main
	unimp
	.size _start, . - _start
