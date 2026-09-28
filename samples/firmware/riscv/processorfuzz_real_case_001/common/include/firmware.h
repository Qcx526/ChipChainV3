#ifndef BENCH_FIRMWARE_H
#define BENCH_FIRMWARE_H

#include <stdint.h>

#define MAILBOX_CAPACITY 8U
#define PAGE_SLOTS 512U
#define SERVICE_VA_BASE UINT64_C(0x40000000)
#define SERVICE_VA_LIMIT UINT64_C(0x40200000)

enum command_opcode {
    CMD_MAP = 1,
    CMD_UNMAP = 2,
    CMD_QUERY = 3,
    CMD_HEALTH = 4,
    CMD_STOP = 5
};

enum service_status {
    STATUS_BOOT = 0,
    STATUS_READY = 1,
    STATUS_APPLIED = 2,
    STATUS_REJECTED = 3,
    STATUS_DONE = 4
};

typedef struct {
    uint32_t opcode;
    uint32_t sequence;
    uint64_t virtual_address;
    uint64_t physical_address;
    uint32_t flags;
    uint32_t checksum;
} Command;

typedef struct {
    volatile uint32_t producer;
    volatile uint32_t consumer;
    volatile uint32_t status;
    volatile uint32_t error_count;
    volatile uint64_t last_result;
    volatile Command commands[MAILBOX_CAPACITY];
} Mailbox;

typedef struct {
    uint32_t phase;
    uint32_t processed;
    uint32_t rejected;
    uint32_t last_sequence;
    uint64_t last_page;
} Controller;

extern volatile Mailbox g_mailbox;
extern Controller g_controller;

/* Buffer/command helpers. */
uint32_t command_checksum(const Command *command);
int command_validate(const Command *command);

/* Memory-backed command driver. The symbols are exposed for a future harness. */
void platform_init(void);
int platform_poll(Command *command);
void platform_publish(uint32_t status, uint64_t result);
void platform_idle(void);

/* Application state machine. */
void controller_init(Controller *controller);
int controller_step(Controller *controller);
void app_run(void);

/* Staged Sv39 page-table service; no active SATP/runtime assertion. */
void pager_init(void);
int pager_apply(const Command *command, uint64_t *result);
int pager_commit(uint32_t slot, uint64_t value);
int pager_lookup(uint64_t virtual_address, uint64_t *result);

/* RISC-V privileged helpers. */
uint64_t arch_hart_id(void);
void arch_memory_order(void);
void arch_translation_sync(void);

#endif
