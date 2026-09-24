# Firmware Analysis Report

## 1. Analysis Summary

本报告只说明 ELF 中的静态结构和指令语义；不证明任何指令曾实际执行。

| 指标 | 结果 |
|---|---:|
| analysis_id | `firmware-static:802b12767a48dfb28a00f0c5d50a728c892a3374e407837b073e946ef0f7e42b` |
| architecture | `powerpc` |
| bit_width | `32` |
| endianness | `big` |
| elf_sha256 | `704b3058b324c9267c8d6e9aa4c69ff72e9ad100d7bdd1411df9fd22aaf15d51` |
| arm_profile | `not applicable` |
| arm_cpu_name | `not established` |
| entry_address | `0x10000` |
| function_count | `3` |
| basic_block_count | `6` |
| instruction_count | `13` |
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
| ghidra_language | `PowerPC:BE:32:default` |
| ghidra_version | `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` |
| producer | `{'analyzer': 'chipchain-general-firmware/v2', 'ghidra': '12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093', 'exporter_sha256': 'b006cc85631d9ef7f9232a03dbc05ce418296f885f427b9e2bd2762f46b9cbbe', 'semantics': 'chipchain-three-isa-semantics/r1', 'semantics_sha256': 'e0732c4a0aeee858c65e11eaf3f661eba92d3659cae11757253fc91bc391addd'}` |

### Evidence-backed behavior examples

| PC | Function | Instruction | Behavior Kind | Target / Address / Register | Known Value | Evidence / Provenance | Status |
|---|---|---|---|---|---|---|---|
| `0x10000` | `_start` | `bl 0x00010008` | DIRECT_CALL | 0x10008 | not established | `fwbehavior:9219a5f2187820891517ea898d7995768cef385a2ddb921a6c4f3899cb67cf65` | supported |
| `0x10004` | `_start` | `b 0x00010004` | DIRECT_BRANCH | 0x10004 | not established | `fwbehavior:8bfb6c0bed0f6595ff80c14930040780ce6c2400ceb0db9e264d9cc11b2474c9` | supported |
| `0x10010` | `main` | `stw r4,0x0(r3)` | MEMORY_STORE | 0x40000000 | 1 | `fwbehavior:16b478a6cbc52b5d672f2ea84deeee4565dd818a85720b5e6d13905771a6e229` | supported |
| `0x10014` | `main` | `lwz r5,0x0(r3)` | MEMORY_LOAD | 0x40000000 | not established | `fwbehavior:80ca8e6da5aaaeeffbd6924bd211fc011126b8181fd4f7e7daabf30b8da4f07a` | supported |
| `0x10018` | `main` | `bl 0x0001002c` | DIRECT_CALL | 0x1002c | not established | `fwbehavior:abea6ea3d2a2595355ab5b78199ace120649d1184504144ff6568e6aabc52013` | supported |
| `0x10020` | `main` | `beq 0x00010028` | CONDITIONAL_BRANCH | 0x10028 | not established | `fwbehavior:f084ad0c37c0efcd246cc765eb3462645efc10a8ccae5e656fa4699e4af48a92` | supported |
| `0x10024` | `main` | `sync 0x0` | MEMORY_BARRIER | not established | not established | `fwbehavior:0d7ebcf8e25ed656a9f7a5665e42e4e59fb4ebbe5512ceccd5c68e8ab9981ee4` | supported |
| `0x10028` | `main` | `blr` | RETURN | not established | not established | `fwbehavior:5c1f40d9213eecccbce9600a3b4aab0d7ea7950e95fdd5a128cebd21948c82b0` | supported |
| `0x1002c` | `helper` | `mfspr r6,LR` | SYSTEM_REGISTER_READ | lr | not established | `fwbehavior:307909766720bdef4ad4fe47b005ce270503e2bd0784a3e3170f2b22b5a6c73a` | supported |
| `0x10030` | `helper` | `blr` | RETURN | not established | not established | `fwbehavior:88dd1113ad4c8e1d8c4529d70f9e171a81af66c9675aaf9b6d568c79fb4e10c6` | supported |

## 2. Binary / Architecture Identity

ELF SHA256 `704b3058b324c9267c8d6e9aa4c69ff72e9ad100d7bdd1411df9fd22aaf15d51`；POWERPC 32-bit big；入口 `0x10000`。
PT_LOAD 段 1 个；节 5 个。

## 3. Program Structure

识别 3 个函数、6 个基本块、13 条指令和 7 条 CFG 边。静态 CFG 边不等于可行运行路径。

## 4. Functions

| 入口 | 名称 | 范围 | ID |
|---|---|---|---|
| `0x10000` | `_start` | 0x10000–0x10007 | `fwfunction:10984ab35218a80cc80d7f17cd5580749c788bc22c55576534aa4678803e53d5` |
| `0x10008` | `main` | 0x10008–0x1002b | `fwfunction:a815b6c8dc1b3b05e08f29251480bca5f566c36d334fa4117d6a1f76fd51cf06` |
| `0x1002c` | `helper` | 0x1002c–0x10033 | `fwfunction:49ee86ca41fcbd3d9a719d2cd8b5575e3867aa0c1a48bf8b70ec247d1556c0ec` |

## 5. Basic Blocks and CFG

| 基本块 | 结束 | 所属函数数 | 出边数 |
|---|---:|---:|---:|
| `0x10000` | `0x10003` | 1 | 2 |
| `0x10004` | `0x10007` | 1 | 1 |
| `0x10008` | `0x10023` | 1 | 3 |
| `0x10024` | `0x10027` | 1 | 1 |
| `0x10028` | `0x1002b` | 1 | 0 |
| `0x1002c` | `0x10033` | 1 | 0 |

## 6. Call Analysis

| 调用点 | 类型 | 目标 | 解析状态 |
|---|---|---|---|
| `0x10000` | direct | 0x10008 | resolved |
| `0x10018` | direct | 0x1002c | resolved |

## 7. Memory Access Analysis

普通 LOAD/STORE 保留为内存行为；没有硬件资源目录时不升级为 MMIO。

| PC | 指令 | 行为 | 地址 | 已知值 | 状态 |
|---|---|---|---|---|---|
| `0x10010` | `stw r4,0x0(r3)` | MEMORY_STORE | 0x40000000 | 1 | supported |
| `0x10014` | `lwz r5,0x0(r3)` | MEMORY_LOAD | 0x40000000 | not established | supported |

## 8. Hardware-facing Behaviors

当前分析没有硬件资源目录，MMIO 计数为 0。已解析内存地址仍需资源绑定，才能被解释为硬件寄存器访问。

## 9. System/Register/Barrier/Atomic Behaviors

| PC | 所属函数 | 指令 | 行为 | 寄存器 | 证据 ID |
|---|---|---|---|---|---|
| `0x10024` | `main` | `sync 0x0` | MEMORY_BARRIER | — | `fwbehavior:0d7ebcf8e25ed656a9f7a5665e42e4e59fb4ebbe5512ceccd5c68e8ab9981ee4` |
| `0x1002c` | `helper` | `mfspr r6,LR` | SYSTEM_REGISTER_READ | lr | `fwbehavior:307909766720bdef4ad4fe47b005ce270503e2bd0784a3e3170f2b22b5a6c73a` |

## 10. Unresolved / Unsupported Facts

- Unsupported instructions/semantics: 0
- Unresolved call targets: 0
- Unknown memory addresses: 0
- Ambiguous ownership: 0
- Unbound hardware resources: all ordinary memory facts in this catalog-free analysis.

Unresolved ≠ nonexistent. Unsupported ≠ safe.


## 11. Provenance and Toolchain

Analysis `firmware-static:802b12767a48dfb28a00f0c5d50a728c892a3374e407837b073e946ef0f7e42b`。Ghidra `12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093` / `PowerPC:BE:32:default` 导出结构；每条指令 bytes 与 SHA256 为 `704b3058b324c9267c8d6e9aa4c69ff72e9ad100d7bdd1411df9fd22aaf15d51` 的 ELF PT_LOAD 可执行映射逐条比对。事实 ID 由内容计算，不含本机路径、时间或随机数。

## 12. Scientific Limitations

静态函数、CFG、指令和值传播不证明运行可达、运行顺序、外部控制、硬件触发、偏差或漏洞。已知写值只表示当前局部常量传播能证明的静态值；跨分支和调用的值可能未知。Ghidra 与 ELF byte 一致不构成独立语义解码。
