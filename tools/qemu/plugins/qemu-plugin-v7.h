/*
 * Minimal declarations extracted from QEMU 11.1.1
 * include/plugins/qemu-plugin.h (API 7).
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019, Linaro
 * SPDX-License-Identifier: GPL-2.0-or-later
 * See README.md in this directory for exact upstream provenance.
 */
#ifndef CHIPCHAIN_QEMU_PLUGIN_V7_H
#define CHIPCHAIN_QEMU_PLUGIN_V7_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define QEMU_PLUGIN_EXPORT __attribute__((visibility("default")))
#define QEMU_PLUGIN_VERSION 7
typedef uint64_t qemu_plugin_id_t;
typedef struct qemu_info_t {
    const char *target_name;
    struct { int min; int cur; } version;
    bool system_emulation;
    union { struct { int smp_vcpus; int max_vcpus; } system; };
} qemu_info_t;
struct qemu_plugin_tb;
struct qemu_plugin_insn;
enum qemu_plugin_cb_flags {
    QEMU_PLUGIN_CB_NO_REGS,
    QEMU_PLUGIN_CB_R_REGS,
    QEMU_PLUGIN_CB_RW_REGS,
    QEMU_PLUGIN_CB_RW_REGS_PC,
};
typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(struct qemu_plugin_tb *, void *);
typedef void (*qemu_plugin_vcpu_udata_cb_t)(unsigned int, void *);
void qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t,
                                          qemu_plugin_vcpu_tb_trans_cb_t, void *);
void qemu_plugin_register_vcpu_insn_exec_cb(struct qemu_plugin_insn *,
    qemu_plugin_vcpu_udata_cb_t, enum qemu_plugin_cb_flags, void *);
size_t qemu_plugin_tb_n_insns(struct qemu_plugin_tb *);
struct qemu_plugin_insn *qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *, size_t);
uint64_t qemu_plugin_insn_vaddr(const struct qemu_plugin_insn *);
size_t qemu_plugin_insn_size(const struct qemu_plugin_insn *);
size_t qemu_plugin_insn_data(const struct qemu_plugin_insn *, void *, size_t);
#endif
