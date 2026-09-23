# Firmware Analysis Report

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:79a684cf6f658a94700b2467d5ca5ece2a62afea6cfcc65b17a661d9e66758bb` |
| architecture | `riscv` |
| bit_width | `32` |
| endianness | `little` |
| elf_sha256 | `cc6d4dd0b9d83a60103bda0e7fe60f876762c04dd76ec257deeb995ebcc90a95` |
| arm_profile | `not applicable` |
| arm_cpu_name | `not established` |
| entry_address | `0x10000` |
| function_count | `3` |
| basic_block_count | `6` |
| instruction_count | `12` |
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
| exception_return_count | `0` |
| unsupported_count | `0` |
| unresolved_address_count | `0` |
| ambiguous_ownership_count | `0` |
| ghidra_language | `RISCV:LE:32:default` |
| ghidra_version | `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` |

### Evidence-backed behavior examples

| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |
|---|---|---|---|---|---|---|---|
| `0x10000` | `_start` | `jal ra,0x00010008` | DIRECT_CALL | 0x10008 | not established | `fwbehavior:7ab2ad7a2a76386661fbaf0bcf7e9bc923e2ad74caf437f5481210825fae3d29` | supported |
| `0x10004` | `_start` | `j 0x00010004` | DIRECT_BRANCH | 0x10004 | not established | `fwbehavior:9b40cf57b4df74fd4c8e1fdaa11d2ea515286fa387b84f478c2cd4a080ee1b02` | supported |
| `0x10010` | `main` | `sw t1,0x0(t0)` | MEMORY_STORE | 0x40000000 | 1 | `fwbehavior:53d43a4bde803b29eb52e063185eace3676af0072426bd93a8750b7e372ca2d2` | supported |
| `0x10014` | `main` | `lw t2,0x0(t0)` | MEMORY_LOAD | 0x40000000 | not established | `fwbehavior:c2118c82c14141ad0caa8b722bee2b052d5b91bede8b66390b21d37400f01349` | supported |
| `0x10018` | `main` | `jal ra,0x00010028` | DIRECT_CALL | 0x10028 | not established | `fwbehavior:fd146848cccd03cf1ab65bebddc46424f09419ac5c1d24e95dd15bd09e6ca4ce` | supported |
| `0x1001c` | `main` | `beq t2,zero,0x00010024` | CONDITIONAL_BRANCH | 0x10024 | not established | `fwbehavior:9643e09f9a7d2a931caef5cb1180809eb02184a83d704a7eabeb9a876580d275` | supported |
| `0x10020` | `main` | `fence 0xf,0xf` | MEMORY_BARRIER | not established | not established | `fwbehavior:f41d33a3b2ff096874e761321897be0eac329c0a4296581f98db644853adaa0c` | supported |
| `0x10024` | `main` | `ret` | RETURN | not established | not established | `fwbehavior:8342f67c003235c230bb48a4a335668f16e3f86875cc40496a2297ddb57a3350` | supported |
| `0x10028` | `helper` | `csrr t3,0x0300` | SYSTEM_REGISTER_READ | 0x0300 | not established | `fwbehavior:e3bdd6f9942a43c1f599b28af07b684d0a74a736d5c2bfc3d28668dadf76ef5e` | supported |
| `0x1002c` | `helper` | `ret` | RETURN | not established | not established | `fwbehavior:8c9edfc078271f57fe65440de7b9614caf91d69317b1a966712c7350ba3ce6f9` | supported |

## 2. Binary / Architecture Identity

ELF SHA256 `cc6d4dd0b9d83a60103bda0e7fe60f876762c04dd76ec257deeb995ebcc90a95`；RISCV 32-bit little；入口 `0x10000`。
PT_LOAD 段 1 个；节 6 个。

## 3. Program Structure

识别 3 个函数、6 个基本块、12 条指令和 7 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x10000` | `_start` | 0x10000–0x10007 | `fwfunction:e297c0b091c67fef1dff1b0426baa1c6b8656bb01b0ea1e0e027a33b2ecc1621` |
| `0x10008` | `main` | 0x10008–0x10027 | `fwfunction:b624169b7c29eb7940a2790dc1840cfb423b8f9cd68e09d6cda59162baa80a20` |
| `0x10028` | `helper` | 0x10028–0x1002f | `fwfunction:859fa59fa75575ef746b3ca9dba4b77eca2b54d2363414a0224e48527549aa12` |

## 5. Basic Blocks and CFG

| 基本块 | 结束 | 所属函数数 | 出边数 |
|---|---:|---:|---:|
| `0x10000` | `0x10003` | 1 | 2 |
| `0x10004` | `0x10007` | 1 | 1 |
| `0x10008` | `0x1001f` | 1 | 3 |
| `0x10020` | `0x10023` | 1 | 1 |
| `0x10024` | `0x10027` | 1 | 0 |
| `0x10028` | `0x1002f` | 1 | 0 |

## 6. Call Analysis

| 调用点 | 类型 | 目标 | 解析状态 |
|---|---|---|---|
| `0x10000` | direct | 0x10008 | resolved |
| `0x10018` | direct | 0x10028 | resolved |

## 7. Memory Access Analysis

普通 LOAD/STORE 保留为内存行为；没有硬件资源目录时不升级为 MMIO。

| PC | 指令 | 行为 | 地址 | 已知值 | 状态 |
|---|---|---|---|---|---|
| `0x10010` | `sw t1,0x0(t0)` | MEMORY_STORE | 0x40000000 | 1 | supported |
| `0x10014` | `lw t2,0x0(t0)` | MEMORY_LOAD | 0x40000000 | not established | supported |

## 8. Hardware-facing Behaviors

当前分析没有硬件资源目录，MMIO 计数为 0。已解析内存地址仍需资源绑定，才能被解释为硬件寄存器访问。

## 9. System/Register/Barrier/Atomic Behaviors

| PC | 所属函数 | 指令 | 行为 | 寄存器 | 证据 ID |
|---|---|---|---|---|---|
| `0x10020` | `main` | `fence 0xf,0xf` | MEMORY_BARRIER | — | `fwbehavior:f41d33a3b2ff096874e761321897be0eac329c0a4296581f98db644853adaa0c` |
| `0x10028` | `helper` | `csrr t3,0x0300` | SYSTEM_REGISTER_READ | 0x0300 | `fwbehavior:e3bdd6f9942a43c1f599b28af07b684d0a74a736d5c2bfc3d28668dadf76ef5e` |

## 10. Unresolved / Unsupported Facts

- Unsupported instructions/semantics: 0
- Unresolved call targets: 0
- Unknown memory addresses: 0
- Ambiguous ownership: 0
- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.

Unresolved ≠ nonexistent. Unsupported ≠ safe.


## 11. Provenance and Toolchain

Analysis `firmware-static:79a684cf6f658a94700b2467d5ca5ece2a62afea6cfcc65b17a661d9e66758bb`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `RISCV:LE:32:default` 导出结构；每条指令 bytes 与 SHA256 为 `cc6d4dd0b9d83a60103bda0e7fe60f876762c04dd76ec257deeb995ebcc90a95` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
