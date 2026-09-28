#include "firmware.h"

#define PAGE_BYTES UINT64_C(4096)
#define PAGE_MASK (PAGE_BYTES - UINT64_C(1))
#define PAGE_READ UINT32_C(0x2)
#define PAGE_WRITE UINT32_C(0x4)
#define PAGE_EXECUTE UINT32_C(0x8)
#define PAGE_PERMISSIONS (PAGE_READ | PAGE_WRITE | PAGE_EXECUTE)

/* FNV-style word-wise checksum over seven 32-bit fields, in a fixed order. It
 * not depend on C structure padding or the machine's byte order. */
static uint32_t checksum_word(uint32_t hash, uint32_t word)
{
    return (hash ^ word) * UINT32_C(16777619);
}

uint32_t command_checksum(const Command *command)
{
    uint32_t hash = UINT32_C(2166136261);

    if (command == 0) {
        return 0U;
    }
    hash = checksum_word(hash, command->opcode);
    hash = checksum_word(hash, command->sequence);
    hash = checksum_word(hash, (uint32_t)command->virtual_address);
    hash = checksum_word(hash, (uint32_t)(command->virtual_address >> 32));
    hash = checksum_word(hash, (uint32_t)command->physical_address);
    hash = checksum_word(hash, (uint32_t)(command->physical_address >> 32));
    return checksum_word(hash, command->flags);
}

static int service_page_valid(uint64_t address)
{
    return address >= SERVICE_VA_BASE && address < SERVICE_VA_LIMIT &&
           (address & PAGE_MASK) == 0U;
}

int command_validate(const Command *command)
{
    if (command == 0 || command->sequence == 0U ||
        command->checksum != command_checksum(command)) {
        return 0;
    }

    switch (command->opcode) {
    case CMD_MAP:
        if (!service_page_valid(command->virtual_address) ||
            command->physical_address == 0U ||
            (command->physical_address & PAGE_MASK) != 0U ||
            (command->flags & ~PAGE_PERMISSIONS) != 0U ||
            (command->flags & (PAGE_READ | PAGE_EXECUTE)) == 0U ||
            ((command->flags & PAGE_WRITE) != 0U &&
             (command->flags & PAGE_READ) == 0U)) {
            return 0;
        }
        return 1;
    case CMD_QUERY:
    case CMD_UNMAP:
        return service_page_valid(command->virtual_address) &&
               command->physical_address == 0U && command->flags == 0U;
    case CMD_HEALTH:
    case CMD_STOP:
        return command->virtual_address == 0U &&
               command->physical_address == 0U && command->flags == 0U;
    default:
        return 0;
    }
}
