# Firmware Analysis Report

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:8e9301294297c74edab9c6c4fed5138acf4bdec404dc2500a12427f9c667575b` |
| architecture | `arm` |
| bit_width | `32` |
| endianness | `little` |
| elf_sha256 | `f518c3ef4088c16e992b50b59d3624aed5325829364919b57ae08cbaa92d03f9` |
| arm_profile | `M` |
| arm_cpu_name | `Cortex-M3` |
| entry_address | `0x10001` |
| function_count | `3` |
| basic_block_count | `6` |
| instruction_count | `15` |
| cfg_edge_count | `7` |
| direct_call_count | `2` |
| indirect_call_count | `0` |
| unresolved_call_count | `0` |
| memory_load_count | `1` |
| memory_store_count | `1` |
| mmio_read_count | `0` |
| mmio_write_count | `0` |
| system_register_read_count | `1` |
| system_register_write_count | `0` |
| barrier_count | `1` |
| atomic_count | `0` |
| tlb_invalidate_count | `0` |
| exception_return_count | `0` |
| unsupported_count | `0` |
| unresolved_address_count | `0` |
| ambiguous_ownership_count | `0` |
| ghidra_language | `ARM:LE:32:Cortex` |
| ghidra_version | `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` |
| producer | `{'analyzer': 'chipchain-general-firmware/v2', 'ghidra': '12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093', 'exporter_sha256': 'b006cc85631d9ef7f9232a03dbc05ce418296f885f427b9e2bd2762f46b9cbbe', 'semantics': 'chipchain-three-isa-semantics/r1', 'semantics_sha256': '700f47a2faca4c699fa752d61c3f0e6099c49739644914a22f94bdf92a1d2138'}` |

### Evidence-backed behavior examples

| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |
|---|---|---|---|---|---|---|---|
| `0x10000` | `_start` | `bl 0x00010006` | DIRECT_CALL | 0x10006 | not established | `fwbehavior:ece5348a80e80f2dc49cb33d4c32abcda5ff148377ae2aadda97f1a8b07442d6` | supported |
| `0x10004` | `_start` | `b 0x00010004` | DIRECT_BRANCH | 0x10004 | not established | `fwbehavior:c4a91a2cc5c44547429b23a5332fc9ff4c333e0e2445d2eddee09e5ec9a78c36` | supported |
| `0x10012` | `main` | `str r1,[r0,#0x0]` | MEMORY_STORE | 0x40000000 | 1 | `fwbehavior:f2f497512261a950e0cadefdb712d04aa9ba629a8a354707f8454aa60b2e9ca4` | supported |
| `0x10014` | `main` | `ldr r2,[r0,#0x0]` | MEMORY_LOAD | 0x40000000 | not established | `fwbehavior:ab2dada59d70f8e5e0fee1d001a06201322a5ab356a1b2e94dc1ca37d8776a72` | supported |
| `0x10016` | `main` | `bl 0x00010024` | DIRECT_CALL | 0x10024 | not established | `fwbehavior:39471f20848f33964921bce75f1c5b2b806354a641b78a613546ebb7c9154e70` | supported |
| `0x1001c` | `main` | `beq 0x00010022` | CONDITIONAL_BRANCH | 0x10022 | not established | `fwbehavior:8ad89d9ba78f810f77c4d7b095c1d3ea44caa7521b17714d9c16a56ce9b04188` | supported |
| `0x1001e` | `main` | `dmb #0x1f` | MEMORY_BARRIER | not established | not established | `fwbehavior:279c73ee906daf1724f0d610bf651c3a16dca38e0b5104883d8e7f5af0310297` | supported |
| `0x10022` | `main` | `pop {pc}` | RETURN | not established | not established | `fwbehavior:9826fbb303218c76ec2f054411249d76766658da10177aaacba96243989d9afa` | supported |
| `0x10024` | `helper` | `mrs r3,primask` | SYSTEM_REGISTER_READ | primask | not established | `fwbehavior:bc941601e9f84aa4b0baf29f0365bd3e17f5e5dd034762ffc126ab7eaf2203c1` | supported |
| `0x10028` | `helper` | `bx lr` | RETURN | not established | not established | `fwbehavior:106d4a51b5da37b365149f4f8cd06e9296053a832c0816a3da67b64ecda2727d` | supported |

## 2. Binary / Architecture Identity

ELF SHA256 `f518c3ef4088c16e992b50b59d3624aed5325829364919b57ae08cbaa92d03f9`；ARM 32-bit little；入口 `0x10001`。
PT_LOAD 段 2 个；节 8 个。

ARM ELF entry 的最低位表示 Thumb 状态；首条指令的映射 PC 去掉该状态位。

## 3. Program Structure

识别 3 个函数、6 个基本块、15 条指令和 7 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x10000` | `_start` | 0x10000–0x10005 | `fwfunction:cff5f321a96f5c9134f9d74d2d0c173494344151427972b6d9570c9610e004d0` |
| `0x10006` | `main` | 0x10006–0x10023 | `fwfunction:c97a6955510286de59177a902d6c98b0308fab6e14b030b0ebdc0933314b01a5` |
| `0x10024` | `helper` | 0x10024–0x10029 | `fwfunction:790d426cd7ac2169ffcecf22f5a31b23ba0bc57481429b48c07fc619ed4e269e` |

## 5. Basic Blocks and CFG

| 基本块 | 结束 | 所属函数数 | 出边数 |
|---|---:|---:|---:|
| `0x10000` | `0x10003` | 1 | 2 |
| `0x10004` | `0x10005` | 1 | 1 |
| `0x10006` | `0x1001d` | 1 | 3 |
| `0x1001e` | `0x10021` | 1 | 1 |
| `0x10022` | `0x10023` | 1 | 0 |
| `0x10024` | `0x10029` | 1 | 0 |

## 6. Call Analysis

| 调用点 | 类型 | 目标 | 解析状态 |
|---|---|---|---|
| `0x10000` | direct | 0x10006 | resolved |
| `0x10016` | direct | 0x10024 | resolved |

## 7. Memory Access Analysis

普通 LOAD/STORE 保留为内存行为；没有硬件资源目录时不升级为 MMIO。

| PC | 指令 | 行为 | 地址 | 已知值 | 状态 |
|---|---|---|---|---|---|
| `0x10012` | `str r1,[r0,#0x0]` | MEMORY_STORE | 0x40000000 | 1 | supported |
| `0x10014` | `ldr r2,[r0,#0x0]` | MEMORY_LOAD | 0x40000000 | not established | supported |

## 8. Hardware-facing Behaviors

当前分析没有硬件资源目录，MMIO 计数为 0。已解析内存地址仍需资源绑定，才能被解释为硬件寄存器访问。

## 9. System/Register/Barrier/Atomic Behaviors

| PC | 所属函数 | 指令 | 行为 | 寄存器 | 证据 ID |
|---|---|---|---|---|---|
| `0x1001e` | `main` | `dmb #0x1f` | MEMORY_BARRIER | — | `fwbehavior:279c73ee906daf1724f0d610bf651c3a16dca38e0b5104883d8e7f5af0310297` |
| `0x10024` | `helper` | `mrs r3,primask` | SYSTEM_REGISTER_READ | primask | `fwbehavior:bc941601e9f84aa4b0baf29f0365bd3e17f5e5dd034762ffc126ab7eaf2203c1` |

## 10. Unresolved / Unsupported Facts

- Unsupported instructions/semantics: 0
- Unresolved call targets: 0
- Unknown memory addresses: 0
- Ambiguous ownership: 0
- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.

Unresolved ≠ nonexistent. Unsupported ≠ safe.


## 11. Provenance and Toolchain

Analysis `firmware-static:8e9301294297c74edab9c6c4fed5138acf4bdec404dc2500a12427f9c667575b`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `ARM:LE:32:Cortex` 导出结构；每条指令 bytes 与 SHA256 为 `f518c3ef4088c16e992b50b59d3624aed5325829364919b57ae08cbaa92d03f9` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
