/* Synthetic 32-bit big-endian PowerPC firmware for static analysis only. */
.section .text
.globl _start
.type _start, @function
_start:
    bl main
idle:
    b idle
.size _start, .-_start

.globl main
.type main, @function
main:
    lis 3, 0x4000
    li 4, 1
    stw 4, 0(3)
    lwz 5, 0(3)
    bl helper
    cmpwi 5, 0
    beq finished
    sync
finished:
    blr
.size main, .-main

.globl helper
.type helper, @function
helper:
    mfspr 6, 8
    blr
.size helper, .-helper
