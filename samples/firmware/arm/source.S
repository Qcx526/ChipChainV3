/* Synthetic Cortex-M3 firmware for deterministic static analysis only. */
.syntax unified
.cpu cortex-m3
.thumb
.section .text
.global _start
.type _start, %function
_start:
    bl main
idle:
    b idle
.size _start, .-_start

.global main
.type main, %function
main:
    push {lr}
    movw r0, #0x0000
    movt r0, #0x4000
    movs r1, #1
    str r1, [r0]
    ldr r2, [r0]
    bl helper
    cmp r2, #0
    beq finished
    dmb sy
finished:
    pop {pc}
.size main, .-main

.global helper
.type helper, %function
helper:
    mrs r3, primask
    bx lr
.size helper, .-helper
