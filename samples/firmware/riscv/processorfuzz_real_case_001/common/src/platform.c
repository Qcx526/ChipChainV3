#include "firmware.h"

#define BOOT_COMMAND_COUNT 5U
#define BOOT_PHYSICAL_PAGE UINT64_C(0x80010000)
#define BOOT_PAGE_FLAGS UINT32_C(0x6)

/* Kept as a global symbol so an external harness can inspect and populate
 * the command ring before the controller consumes it. */
volatile Mailbox g_mailbox;

static void mailbox_write_command(uint32_t index, const Command *command)
{
    volatile Command *slot = &g_mailbox.commands[index];

    slot->opcode = command->opcode;
    slot->sequence = command->sequence;
    slot->virtual_address = command->virtual_address;
    slot->physical_address = command->physical_address;
    slot->flags = command->flags;
    slot->checksum = command->checksum;
}

static void stage_command(uint32_t index, uint32_t opcode, uint64_t virtual_address,
                          uint64_t physical_address, uint32_t flags)
{
    Command command;

    command.opcode = opcode;
    command.sequence = index + 1U;
    command.virtual_address = virtual_address;
    command.physical_address = physical_address;
    command.flags = flags;
    command.checksum = command_checksum(&command);
    mailbox_write_command(index, &command);
}

void platform_init(void)
{
    Command empty = {0};
    uint32_t index;

    g_mailbox.producer = 0U;
    g_mailbox.consumer = 0U;
    g_mailbox.status = STATUS_BOOT;
    g_mailbox.error_count = 0U;
    g_mailbox.last_result = 0U;
    for (index = 0U; index < MAILBOX_CAPACITY; ++index) {
        mailbox_write_command(index, &empty);
    }

    stage_command(0U, CMD_MAP, SERVICE_VA_BASE, BOOT_PHYSICAL_PAGE,
                  BOOT_PAGE_FLAGS);
    stage_command(1U, CMD_QUERY, SERVICE_VA_BASE, 0U, 0U);
    stage_command(2U, CMD_UNMAP, SERVICE_VA_BASE, 0U, 0U);
    stage_command(3U, CMD_HEALTH, 0U, 0U, 0U);
    stage_command(4U, CMD_STOP, 0U, 0U, 0U);

    /* A producer publishes fully written slots only after the data fence. */
    arch_memory_order();
    g_mailbox.producer = BOOT_COMMAND_COUNT;
}

int platform_poll(Command *command)
{
    uint32_t producer;
    uint32_t consumer;
    uint32_t index;
    volatile Command *slot;

    if (command == 0) {
        return -1;
    }

    producer = g_mailbox.producer;
    consumer = g_mailbox.consumer;
    if (producer == consumer) {
        return 0;
    }
    if ((uint32_t)(producer - consumer) > MAILBOX_CAPACITY) {
        /* An invalid producer window must not allow a stale ring slot to be
         * interpreted as a new command or trap the service in a retry loop. */
        g_mailbox.consumer = producer;
        return -1;
    }

    arch_memory_order();
    index = consumer % MAILBOX_CAPACITY;
    slot = &g_mailbox.commands[index];
    command->opcode = slot->opcode;
    command->sequence = slot->sequence;
    command->virtual_address = slot->virtual_address;
    command->physical_address = slot->physical_address;
    command->flags = slot->flags;
    command->checksum = slot->checksum;
    arch_memory_order();
    g_mailbox.consumer = consumer + 1U;
    return 1;
}

void platform_publish(uint32_t status, uint64_t result)
{
    g_mailbox.last_result = result;
    if (status == STATUS_REJECTED) {
        g_mailbox.error_count++;
    }
    arch_memory_order();
    g_mailbox.status = status;
}

void platform_idle(void)
{
    arch_memory_order();
}
