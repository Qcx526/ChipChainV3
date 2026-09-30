/* SPDX-License-Identifier: GPL-2.0-or-later
 * Architecture-neutral, bounded, pre-instruction QEMU callback observations.
 * No decoder, register inference, instruction retirement, or hardware claim.
 */
#include "qemu-plugin-v7.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    uint64_t pc;
    size_t size;
    char bytes[129];
} Instruction;

static FILE *stream;
static uint64_t count, maximum, successors, target_pc, target_sequence;
static bool has_target, seen_target;

static void fail(const char *message)
{
    fprintf(stderr, "ChipChain trace rejected: %s\n", message);
    if (stream) {
        fflush(stream);
    }
    exit(70);
}

static uint64_t number(const char *text)
{
    char *end;
    unsigned long long result;
    if (!text[0] || text[0] == '-' || text[0] == '+') {
        fail("invalid integer argument");
    }
    errno = 0;
    result = strtoull(text, &end, 10);
    if (errno || *end) {
        fail("invalid integer argument");
    }
    return (uint64_t)result;
}

static void finish(const char *reason)
{
    fprintf(stream, "{\"record\":\"end\",\"stop_reason\":\"%s\","
            "\"event_count\":%" PRIu64 ",\"target_sequence\":", reason, count);
    if (seen_target) {
        fprintf(stream, "%" PRIu64, target_sequence);
    } else {
        fputs("null", stream);
    }
    fputs("}\n", stream);
    if (fflush(stream) || ferror(stream) || fclose(stream)) {
        stream = NULL;
        fail("cannot finish trace");
    }
    stream = NULL;
    /* Like upstream contrib/plugins/stoptrigger.c, terminate from the callback.
     * This sentinel callback is NOT included in the recorded event prefix. */
    exit(0);
}

static void observe(unsigned int vcpu, void *userdata)
{
    const Instruction *instruction = userdata;
    if (vcpu != 0) {
        fail("only single-vCPU observations are supported");
    }
    if (seen_target && count >= target_sequence + successors + 1) {
        finish("target_window_complete");
    }
    if (count >= maximum) {
        finish("event_bound");
    }
    fprintf(stream, "{\"record\":\"event\",\"sequence\":%" PRIu64
            ",\"vcpu\":%u,\"pc\":%" PRIu64 ",\"instruction_bytes\":\"%s\","
            "\"instruction_size\":%zu}\n", count, vcpu, instruction->pc,
            instruction->bytes, instruction->size);
    if (ferror(stream)) {
        fail("cannot write event");
    }
    if (has_target && !seen_target && instruction->pc == target_pc) {
        seen_target = true;
        target_sequence = count;
    }
    count++;
}

static void translate(struct qemu_plugin_tb *tb, void *userdata)
{
    (void)userdata;
    const size_t length = qemu_plugin_tb_n_insns(tb);
    for (size_t index = 0; index < length; index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        Instruction *copy = calloc(1, sizeof(*copy));
        unsigned char bytes[64];
        if (!copy) {
            fail("out of memory");
        }
        copy->pc = qemu_plugin_insn_vaddr(insn);
        copy->size = qemu_plugin_insn_size(insn);
        if (!copy->size || copy->size > sizeof(bytes) ||
            qemu_plugin_insn_data(insn, bytes, copy->size) != copy->size) {
            fail("instruction bytes unavailable or oversized");
        }
        for (size_t n = 0; n < copy->size; n++) {
            snprintf(copy->bytes + 2 * n, 3, "%02x", bytes[n]);
        }
        /* Query handles expire after translation. Keep owned copies until
         * bounded process exit; translated blocks can execute multiple times. */
        qemu_plugin_register_vcpu_insn_exec_cb(insn, observe,
                                               QEMU_PLUGIN_CB_NO_REGS, copy);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
    const qemu_info_t *info, int argc, char **argv)
{
    if (!info->system_emulation || info->system.smp_vcpus != 1 ||
        info->version.cur != QEMU_PLUGIN_VERSION || argc != 5 ||
        strncmp(argv[0], "trace=", 6) || strncmp(argv[1], "target=", 7) ||
        strncmp(argv[2], "successors=", 11) || strncmp(argv[3], "maximum=", 8) ||
        strncmp(argv[4], "run_id=qemu-runtime-run:", 24)) {
        return -1;
    }
    const char *run_id = argv[4] + 7;
    if (strlen(run_id) != 17 + 64 ||
        strspn(run_id + 17, "0123456789abcdef") != 64) {
        return -1;
    }
    /* Whitelist target strings before embedding an upstream value in JSON. */
    const char *targets[] = {"arm", "aarch64", "riscv32", "riscv64", "ppc", "ppc64"};
    bool valid_target = false;
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        valid_target |= strcmp(info->target_name, targets[i]) == 0;
    }
    if (!valid_target) {
        return -1;
    }
    has_target = strcmp(argv[1] + 7, "none") != 0;
    if (has_target) {
        target_pc = number(argv[1] + 7);
    }
    successors = number(argv[2] + 11);
    maximum = number(argv[3] + 8);
    if (!maximum || maximum > 1000000 || successors >= maximum ||
        (!has_target && successors != 0)) {
        return -1;
    }
    stream = fopen(argv[0] + 6, "wx");
    if (!stream) {
        return -1;
    }
    fprintf(stream, "{\"record\":\"header\",\"schema\":\"chipchain-qemu-trace/v1\","
            "\"run_id\":\"%s\",\"target\":\"%s\",\"vcpu_count\":1,\"api_version\":7,\"policy\":{"
            "\"kind\":\"%s\",\"target_pc\":", run_id, info->target_name,
            has_target ? "target_then_successors" : "event_prefix");
    if (has_target) {
        fprintf(stream, "%" PRIu64, target_pc);
    } else {
        fputs("null", stream);
    }
    fprintf(stream, ",\"successor_events\":%" PRIu64 ",\"max_events\":%" PRIu64
            "}}\n", successors, maximum);
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate, NULL);
    return 0;
}
