# Firmware Analysis Report

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:39e6085995dae6913299962133e95a8b561457e36624cb2a3b5c6c7b581a751e` |
| architecture | `riscv` |
| bit_width | `32` |
| endianness | `little` |
| elf_sha256 | `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920` |
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
| tlb_invalidate_count | `0` |
| exception_return_count | `0` |
| unsupported_count | `1` |
| unresolved_address_count | `0` |
| ambiguous_ownership_count | `0` |
| ghidra_language | `RISCV:LE:32:default` |
| ghidra_version | `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` |
| producer | `{'analyzer': 'chipchain-general-firmware/v2', 'ghidra': '12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093', 'exporter_sha256': 'b006cc85631d9ef7f9232a03dbc05ce418296f885f427b9e2bd2762f46b9cbbe', 'semantics': 'chipchain-three-isa-semantics/r1', 'semantics_sha256': '0454ca318a5af7dd42e71e7f3b0e92f11424ffe035184b88f90d2ec92d3532ca'}` |

### Evidence-backed behavior examples

| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |
|---|---|---|---|---|---|---|---|
| `0x100088` | `entry` | `sw t1,0x0(t0)` | MEMORY_STORE | 0x40000 | 1 | `fwbehavior:75b980ab59a1f6354847cc285284e12e8e34f96a8aeeb4016728b073ebbe9cf9` | supported |
| `0x100090` | `entry` | `sw t1,0x4(t0)` | MEMORY_STORE | 0x40004 | 164 | `fwbehavior:efcaea7c8bf40d08a633374ce178fe02676bdbece578b272bd63f98f62110a5d` | supported |
| `0x100094` | `entry` | `lw t2,0x8(t0)` | MEMORY_LOAD | 0x40008 | not established | `fwbehavior:1cef7c68d25779d31e8423ac561b8f1b7f2aba4c6bc93794fd16c6697f10b5d7` | supported |
| `0x1000a0` | `entry` | `sw t2,0x0(t3)` | MEMORY_STORE | 0x101000 | not established | `fwbehavior:6fa5cb2715de5d198125ff30de98fecb7439e8986d6884b869d048202c10e0be` | supported |
| `0x1000ac` | `entry` | `sw t1,0x8(t0)` | MEMORY_STORE | 0x20008 | 1 | `fwbehavior:01f7d8e8eba1e241ef2aaddddef546cba5db265349843a57011168015a949327` | supported |
| `0x1000b0` | `entry` | `wfi` | UNKNOWN | not established | not established | `fwbehavior:e3c3e76483055ea46fa95c7de76c74fd31dbeba58b178c7de53a78ce141019f3` | unsupported |
| `0x1000b4` | `entry` | `j 0x001000b0` | DIRECT_BRANCH | 0x1000b0 | not established | `fwbehavior:d1973d48ac8ba02cb098e8abfb38f6cc085a532003f226ed518cd1f44d6fef38` | supported |

## 2. Binary / Architecture Identity

ELF SHA256 `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920`；RISCV 32-bit little；入口 `0x100080`。
PT_LOAD 段 2 个；节 7 个。

## 3. Program Structure

识别 1 个函数、6 个基本块、14 条指令和 6 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x100080` | `entry` | 0x100080–0x1000b7 | `fwfunction:2d214da7afffab27703167328ad29a2e9c8f95af8501b1e864dd0d1353dcfe1e` |

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
| `0x100090` | `sw t1,0x4(t0)` | MEMORY_STORE | 0x40004 | 164 | supported |
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

- `0x1000b0` `73005010` `wfi` → UNKNOWN, unsupported; Unsupported mnemonic wfi; `fwbehavior:e3c3e76483055ea46fa95c7de76c74fd31dbeba58b178c7de53a78ce141019f3`

## 11. Provenance and Toolchain

Analysis `firmware-static:39e6085995dae6913299962133e95a8b561457e36624cb2a3b5c6c7b581a751e`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `RISCV:LE:32:default` 导出结构；每条指令 bytes 与 SHA256 为 `d2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
