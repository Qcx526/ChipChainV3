OUTPUT_ARCH(riscv)
ENTRY(_start)

/* A harness loads the ELF PT_LOAD contents into 256 KiB of RAM. */
MEMORY {
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 256K
}

PHDRS {
    code PT_LOAD FLAGS(5); /* readable, executable */
    data PT_LOAD FLAGS(6); /* readable, writable */
}

SECTIONS {
    . = ORIGIN(RAM);

    .text : ALIGN(16) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } > RAM :code

    .rodata : ALIGN(16) {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } > RAM :code

    .data : ALIGN(16) {
        __data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        __data_end = .;
    } > RAM :data

    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } > RAM :data

    . = ALIGN(16);
    __image_end = .;
    PROVIDE(__global_pointer$ = __data_start + 0x800);

    /* The upper 16 KiB is reserved for the M-mode stack. */
    __stack_bottom = ORIGIN(RAM) + LENGTH(RAM) - 16K;
    __stack_top = ORIGIN(RAM) + LENGTH(RAM);
    ASSERT(__image_end <= 0x80010000, "firmware overlaps the staged physical page")
    ASSERT(__image_end <= __stack_bottom, "firmware overlaps the M-mode stack")
    ASSERT(ADDR(.text) == ORIGIN(RAM), "_start must be at RAM origin")

    /DISCARD/ : {
        *(.comment)
        *(.note.GNU-stack)
        *(.eh_frame .eh_frame.*)
    }
}
