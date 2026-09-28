#include "firmware.h"

#include <stddef.h>
#include <stdint.h>

/* This service stages Sv39 tables. It does not install them in satp. */
#define PAGE_SHIFT 12U
#define PAGE_SIZE (UINT64_C(1) << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - UINT64_C(1))
#define VPN_MASK UINT64_C(0x1ff)
#define PTE_PPN_SHIFT 10U
#define PTE_FLAG_MASK UINT64_C(0x3ff)
#define PHYSICAL_RAM_BASE UINT64_C(0x80000000)
#define PHYSICAL_RAM_LIMIT UINT64_C(0x80040000)

#define PTE_V UINT64_C(0x001)
#define PTE_R UINT64_C(0x002)
#define PTE_W UINT64_C(0x004)
#define PTE_X UINT64_C(0x008)
#define PTE_A UINT64_C(0x040)
#define PTE_D UINT64_C(0x080)
#define MAP_PERMISSIONS (PTE_R | PTE_W | PTE_X)

enum pager_error {
    PAGER_OK = 0,
    PAGER_BAD_ARGUMENT = -1,
    PAGER_OUT_OF_RANGE = -2,
    PAGER_BAD_ALIGNMENT = -3,
    PAGER_BAD_PERMISSIONS = -4,
    PAGER_NOT_MAPPED = -5,
    PAGER_ALREADY_MAPPED = -6,
    PAGER_NOT_READY = -7,
    PAGER_BAD_OPCODE = -8
};

/* VA 0x40000000..0x40200000 occupies root VPN[2]=1, middle VPN[1]=0. */
static volatile uint64_t root_table[PAGE_SLOTS] __attribute__((aligned(4096)));
static volatile uint64_t middle_table[PAGE_SLOTS] __attribute__((aligned(4096)));
static volatile uint64_t leaf_table[PAGE_SLOTS] __attribute__((aligned(4096)));
static uint32_t tables_initialized;

static uint32_t root_index(void)
{
    return (uint32_t)((SERVICE_VA_BASE >> 30) & VPN_MASK);
}

static uint32_t middle_index(void)
{
    return (uint32_t)((SERVICE_VA_BASE >> 21) & VPN_MASK);
}

static uint64_t table_pointer_pte(const volatile uint64_t *table)
{
    uint64_t address = (uint64_t)(uintptr_t)table;
    return ((address >> PAGE_SHIFT) << PTE_PPN_SHIFT) | PTE_V;
}

static int tables_ready(void)
{
    if (tables_initialized == 0U) {
        return 0;
    }
    if (root_table[root_index()] != table_pointer_pte(middle_table)) {
        return 0;
    }
    if (middle_table[middle_index()] != table_pointer_pte(leaf_table)) {
        return 0;
    }
    return 1;
}

static int page_slot(uint64_t virtual_address, uint32_t *slot)
{
    if (slot == NULL) {
        return PAGER_BAD_ARGUMENT;
    }
    if (virtual_address < SERVICE_VA_BASE || virtual_address >= SERVICE_VA_LIMIT) {
        return PAGER_OUT_OF_RANGE;
    }
    *slot = (uint32_t)((virtual_address - SERVICE_VA_BASE) >> PAGE_SHIFT);
    return PAGER_OK;
}

static uint64_t pte_physical_page(uint64_t pte)
{
    return (pte >> PTE_PPN_SHIFT) << PAGE_SHIFT;
}

static int leaf_pte_valid(uint64_t pte)
{
    uint64_t flags = pte & PTE_FLAG_MASK;
    uint64_t physical_page = pte_physical_page(pte);

    if ((flags & PTE_V) == 0U || (flags & (PTE_R | PTE_X)) == 0U) {
        return 0;
    }
    if ((flags & PTE_W) != 0U && (flags & PTE_R) == 0U) {
        return 0;
    }
    if ((flags & ~(PTE_V | MAP_PERMISSIONS | PTE_A | PTE_D)) != 0U) {
        return 0;
    }
    if (physical_page < PHYSICAL_RAM_BASE || physical_page >= PHYSICAL_RAM_LIMIT) {
        return 0;
    }
    return 1;
}

static int pager_encode(uint64_t physical_address, uint32_t flags, uint64_t *pte)
{
    uint64_t permission_bits = (uint64_t)flags;

    if (pte == NULL) {
        return PAGER_BAD_ARGUMENT;
    }
    if ((physical_address & PAGE_MASK) != 0U) {
        return PAGER_BAD_ALIGNMENT;
    }
    if (physical_address < PHYSICAL_RAM_BASE || physical_address >= PHYSICAL_RAM_LIMIT) {
        return PAGER_OUT_OF_RANGE;
    }
    if ((permission_bits & ~MAP_PERMISSIONS) != 0U ||
        (permission_bits & (PTE_R | PTE_X)) == 0U ||
        ((permission_bits & PTE_W) != 0U && (permission_bits & PTE_R) == 0U)) {
        return PAGER_BAD_PERMISSIONS;
    }

    /* A/D are preset so the staged leaf does not require software faults. */
    *pte = ((physical_address >> PAGE_SHIFT) << PTE_PPN_SHIFT) |
           PTE_V | permission_bits | PTE_A |
           (((permission_bits & PTE_W) != 0U) ? PTE_D : UINT64_C(0));
    return PAGER_OK;
}

void pager_init(void)
{
    uint32_t index;

    tables_initialized = 0U;
    for (index = 0U; index < PAGE_SLOTS; ++index) {
        root_table[index] = 0U;
        middle_table[index] = 0U;
        leaf_table[index] = 0U;
    }
    root_table[root_index()] = table_pointer_pte(middle_table);
    middle_table[middle_index()] = table_pointer_pte(leaf_table);
    arch_memory_order();
    tables_initialized = 1U;
}

int pager_commit(uint32_t slot, uint64_t value)
{
    if (slot >= PAGE_SLOTS) {
        return PAGER_OUT_OF_RANGE;
    }
    if (!tables_ready()) {
        return PAGER_NOT_READY;
    }
    if (value != 0U && !leaf_pte_valid(value)) {
        return PAGER_BAD_PERMISSIONS;
    }

    leaf_table[slot] = value;
    arch_memory_order();
    arch_translation_sync();
    return PAGER_OK;
}

int pager_lookup(uint64_t virtual_address, uint64_t *result)
{
    uint32_t slot;
    uint64_t pte;
    int status;

    if (result == NULL) {
        return PAGER_BAD_ARGUMENT;
    }
    *result = 0U;
    if (!tables_ready()) {
        return PAGER_NOT_READY;
    }
    status = page_slot(virtual_address, &slot);
    if (status != PAGER_OK) {
        return status;
    }

    pte = leaf_table[slot];
    if (!leaf_pte_valid(pte)) {
        return PAGER_NOT_MAPPED;
    }
    *result = pte_physical_page(pte) | (virtual_address & PAGE_MASK);
    return PAGER_OK;
}

int pager_apply(const Command *command, uint64_t *result)
{
    uint32_t slot;
    uint64_t pte;
    int status;

    if (command == NULL || result == NULL) {
        return PAGER_BAD_ARGUMENT;
    }
    *result = 0U;
    if (command->opcode == CMD_QUERY) {
        return pager_lookup(command->virtual_address, result);
    }
    if (command->opcode != CMD_MAP && command->opcode != CMD_UNMAP) {
        return PAGER_BAD_OPCODE;
    }
    if (!tables_ready()) {
        return PAGER_NOT_READY;
    }
    status = page_slot(command->virtual_address, &slot);
    if (status != PAGER_OK) {
        return status;
    }
    if ((command->virtual_address & PAGE_MASK) != 0U) {
        return PAGER_BAD_ALIGNMENT;
    }

    pte = leaf_table[slot];
    if (command->opcode == CMD_UNMAP) {
        if (!leaf_pte_valid(pte)) {
            return PAGER_NOT_MAPPED;
        }
        status = pager_commit(slot, 0U);
        if (status == PAGER_OK) {
            *result = pte_physical_page(pte);
        }
        return status;
    }

    if (leaf_pte_valid(pte)) {
        return PAGER_ALREADY_MAPPED;
    }
    status = pager_encode(command->physical_address, command->flags, &pte);
    if (status != PAGER_OK) {
        return status;
    }
    status = pager_commit(slot, pte);
    if (status == PAGER_OK) {
        *result = command->physical_address;
    }
    return status;
}
