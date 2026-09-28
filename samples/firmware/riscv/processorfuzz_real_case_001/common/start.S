/* RV64 M-mode entry for an ELF image loaded into RAM at 0x80000000. */
    .section .text.boot, "ax", @progbits
    .align 2
    .globl _start
    .type _start, @function
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    la sp, __stack_top
    .option pop

    /* Keep the benchmark independent of a board-specific interrupt source. */
    csrwi mie, 0
    csrci mstatus, 8
    la t0, _trap
    csrw mtvec, t0

    la t0, __bss_start
    la t1, __bss_end
1:
    bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 1b
2:
    call main
3:
    wfi
    j 3b
    .size _start, .-_start

    .align 2
    .type _trap, @function
_trap:
    j _trap
    .size _trap, .-_trap
