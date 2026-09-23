/* Synthetic RV32 firmware for deterministic static analysis only. */
.section .text
.globl _start
.type _start, @function
_start:
    jal ra, main
idle:
    j idle
.size _start, .-_start

.globl main
.type main, @function
main:
    lui t0, 0x40000
    li t1, 1
    sw t1, 0(t0)
    lw t2, 0(t0)
    jal ra, helper
    beq t2, zero, finished
    fence
finished:
    ret
.size main, .-main

.globl helper
.type helper, @function
helper:
    csrr t3, mstatus
    ret
.size helper, .-helper
