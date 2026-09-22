/* Controlled apparatus only. Same source/recipe; command immediate is the only variant. */
#ifndef COMMAND_VALUE
#error COMMAND_VALUE must be explicit
#endif
.option norvc
.option norelax
.section .vectors,"ax",@progbits
.org 0x80
.global _start
_start:
  lui t0, 0x40
  addi t1, zero, 1
.global enable_site
enable_site:
  sw t1, 0(t0)
  addi t1, zero, COMMAND_VALUE
.global command_site
command_site:
  sw t1, 4(t0)
.global status_site
status_site:
  lw t2, 8(t0)
  lui t3, %hi(result_slot)
  addi t3, t3, %lo(result_slot)
.global result_site
result_site:
  sw t2, 0(t3)
  lui t0, 0x20
  addi t1, zero, 1
  sw t1, 8(t0)
1:
  wfi
  j 1b
.section .data,"aw",@progbits
.balign 4
.global result_slot
result_slot:
  .word 0
