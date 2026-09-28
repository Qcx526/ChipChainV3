#include "firmware.h"
#include "config.h"

uint64_t arch_hart_id(void)
{
    uint64_t hart;
    __asm__ volatile ("csrr %0, mhartid" : "=r"(hart));
    return hart;
}

void arch_memory_order(void)
{
    __asm__ volatile ("fence rw,rw" ::: "memory");
}

void arch_translation_sync(void)
{
#if BENCH_TLB_INVALIDATE == 1
    __asm__ volatile ("sfence.vma x0,x0" ::: "memory");
#elif BENCH_TLB_INVALIDATE == 0
    __asm__ volatile ("fence rw,rw" ::: "memory");
#else
#error "BENCH_TLB_INVALIDATE must be 0 or 1"
#endif
}
