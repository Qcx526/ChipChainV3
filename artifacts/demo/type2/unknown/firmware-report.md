# Firmware Analysis Report

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:73203833226424dd68b57b9686bc5f3373bb9e4cec548c943e1e05b660cc5ec4` |
| architecture | `riscv` |
| bit_width | `32` |
| endianness | `little` |
| elf_sha256 | `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641` |
| arm_profile | `not applicable` |
| arm_cpu_name | `not established` |
| entry_address | `0x100080` |
| function_count | `1` |
| basic_block_count | `6` |
| instruction_count | `14` |
| cfg_edge_count | `6` |
| direct_call_count | `0` |
| indirect_call_count | `0` |
| unresolved_call_count | `0` |
| memory_load_count | `1` |
| memory_store_count | `4` |
| mmio_read_count | `0` |
| mmio_write_count | `0` |
| system_register_read_count | `0` |
| system_register_write_count | `0` |
| barrier_count | `0` |
| atomic_count | `0` |
| exception_return_count | `0` |
| unsupported_count | `1` |
| unresolved_address_count | `0` |
| ambiguous_ownership_count | `0` |
| ghidra_language | `RISCV:LE:32:default` |
| ghidra_version | `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` |

### Evidence-backed behavior examples

| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |
|---|---|---|---|---|---|---|---|
| `0x100088` | `entry` | `sw t1,0x0(t0)` | MEMORY_STORE | 0x40000 | 1 | `fwbehavior:1c0127d778646c63b5102d2ce3ebbce75d0d281ad2938ab6b860756ae4028678` | supported |
| `0x100090` | `entry` | `sw t1,0x4(t0)` | MEMORY_STORE | 0x40004 | 165 | `fwbehavior:54abb5eb0f2ffed568ba4cacc8d2a1ba16d95b27212b3d5906bb7fe9ffc44bed` | supported |
| `0x100094` | `entry` | `lw t2,0x8(t0)` | MEMORY_LOAD | 0x40008 | not established | `fwbehavior:d29d69d4de440df92a87251b2747399123c33d82fe49ad5c57156830d3b2c26a` | supported |
| `0x1000a0` | `entry` | `sw t2,0x0(t3)` | MEMORY_STORE | 0x101000 | not established | `fwbehavior:07720fcbcff184dc30e9600d9599680f718b02049aa55cf61c5878c788fa0452` | supported |
| `0x1000ac` | `entry` | `sw t1,0x8(t0)` | MEMORY_STORE | 0x20008 | 1 | `fwbehavior:f12bd5d4ec8dc60725feb982e579b5141295be4c517d638e9ef08be9d3812b7b` | supported |
| `0x1000b0` | `entry` | `wfi` | UNKNOWN | not established | not established | `fwbehavior:005d59c2f4de2c0c364b41570971cd51a23b0c4200d24827d6987d0f870e3290` | unsupported |
| `0x1000b4` | `entry` | `j 0x001000b0` | DIRECT_BRANCH | 0x1000b0 | not established | `fwbehavior:29d5657174b47ee982c819417e8841d98d8eb921baa80df30fb3e5357fdb5e12` | supported |

## 2. Binary / Architecture Identity

ELF SHA256 `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641`；RISCV 32-bit little；入口 `0x100080`。
PT_LOAD 段 2 个；节 7 个。

## 3. Program Structure

识别 1 个函数、6 个基本块、14 条指令和 6 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x100080` | `entry` | 0x100080–0x1000b7 | `fwfunction:5bf06a362652937bd9d57e214f9ae5cb1bf0405a64b99d211d76f1c39a18216b` |

## 5. Basic Blocks and CFG

| 基本块 | 结束 | 所属函数数 | 出边数 |
|---|---:|---:|---:|
| `0x100080` | `0x100087` | 1 | 1 |
| `0x100088` | `0x10008f` | 1 | 1 |
| `0x100090` | `0x100093` | 1 | 1 |
| `0x100094` | `0x10009f` | 1 | 1 |
| `0x1000a0` | `0x1000af` | 1 | 1 |
| `0x1000b0` | `0x1000b7` | 1 | 1 |

## 6. Call Analysis

| 调用点 | 类型 | 目标 | 解析状态 |
|---|---|---|---|

## 7. Memory Access Analysis

普通 LOAD/STORE 保留为内存行为；没有硬件资源目录时不升级为 MMIO。

| PC | 指令 | 行为 | 地址 | 已知值 | 状态 |
|---|---|---|---|---|---|
| `0x100088` | `sw t1,0x0(t0)` | MEMORY_STORE | 0x40000 | 1 | supported |
| `0x100090` | `sw t1,0x4(t0)` | MEMORY_STORE | 0x40004 | 165 | supported |
| `0x100094` | `lw t2,0x8(t0)` | MEMORY_LOAD | 0x40008 | not established | supported |
| `0x1000a0` | `sw t2,0x0(t3)` | MEMORY_STORE | 0x101000 | not established | supported |
| `0x1000ac` | `sw t1,0x8(t0)` | MEMORY_STORE | 0x20008 | 1 | supported |

## 8. Hardware-facing Behaviors

当前分析没有硬件资源目录，MMIO 计数为 0。已解析内存地址仍需资源绑定，才能被解释为硬件寄存器访问。

## 9. System/Register/Barrier/Atomic Behaviors

| PC | 所属函数 | 指令 | 行为 | 寄存器 | 证据 ID |
|---|---|---|---|---|---|

## 10. Unresolved / Unsupported Facts

- Unsupported instructions/semantics: 1
- Unresolved call targets: 0
- Unknown memory addresses: 0
- Ambiguous ownership: 0
- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.

Unresolved ≠ nonexistent. Unsupported ≠ safe.

- `0x1000b0` `73005010` `wfi` → UNKNOWN, unsupported; Unsupported mnemonic wfi; `fwbehavior:005d59c2f4de2c0c364b41570971cd51a23b0c4200d24827d6987d0f870e3290`

## 11. Provenance and Toolchain

Analysis `firmware-static:73203833226424dd68b57b9686bc5f3373bb9e4cec548c943e1e05b660cc5ec4`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `RISCV:LE:32:default` 导出结构；每条指令 bytes 与 SHA256 为 `42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
