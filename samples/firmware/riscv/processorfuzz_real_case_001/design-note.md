# 设计依据与证据边界

此文档是合成固件的设计记录，不是硬件行为契约，也不是漏洞证据。

| 项目 | 从 `processorfuzz/real_case_001` 已建立的事实 |
| --- | --- |
| A. ISA | 包内触发测试 ELF 是小端 RISC-V RV64；入口 `0x80000000`。 |
| B. 测试结构 | 原始 `.input_1.S` 有启动初始化、CSR 设置、模糊测试前缀和测试主体；SI 是 `p-m` 模式的测试描述，解析出 368 条源指令，不是执行记录。 |
| C. 指令/资源 | SI 中两处 `sfence.vma`；包内 ELF 经 Ghidra 和 ELF 字节核对后的静态 IR 在 `0x8000065c`、`0x80000758` 各有一处，均分类为 `TLB_INVALIDATE`。原 ELF 另有 CSR、原子操作、异常返回和普通 `fence`。 |
| D. SI 操作 | SI 两处分别为 `sfence.vma x28,x16` 和 `sfence.vma x18,x5`，前面有地址及立即数准备。SI→ELF 的构建绑定为 `UNKNOWN`，不能把 SI 行和 ELF PC 认定为同一操作实例。 |
| E. 运行观察 | 已解析 RTL trace 有 326 条受表头约束的前六列记录，其中 321 条与原 ELF 局部字节匹配；ISA 参考 CSV 有 293 条匹配记录。已解析观察中没有上述两处 `sfence.vma` PC/编码。 |
| F. 签名差异 | RTL/ISA 的原始 128 位签名在索引 37、44、48 不同；差异正式状态为 `UNKNOWN`，寄存器归属和因果均未建立。 |
| G. 来源/绑定 | 交付包明确归类为硬件团队触发验证包；包内 ELF 不是客户固件。RTL/ISA trace→ELF 仅 `PARTIAL_BYTE_MATCH`；signature 同次执行、同固件、同测试例均未建立。`note.log` 未绑定；`disassembly.asm` 与 ELF 有 278 处映射字节冲突。 |
| H. 未知事实 | 真实硬件触发条件、两处 `sfence.vma` 是否执行、与签名差异的关系、完整 RTL 版本、可信非 MMIO HardwareBehaviorContract、物理硅片适用性均未知。 |

因此本项目定义独立的 `SyntheticBenchmarkContract`：在合成页表维护服务的
`arch_translation_sync` 助手中，`positive` 编译出 `sfence.vma x0,x0`，`negative_trigger` 在同一位置
编译出 `fence rw,rw`。二者共用其他源码和调用链；这是一项静态基准要求，
不声称原始硬件测试的真实触发条件，也不继承原包运行证据。

原始依据：`samples/processorfuzz/real_case_001/README.md`、
`expected/processorfuzz-report.md`、`expected/processorfuzz-si.json`、
`expected/firmware-analysis.json`、`expected/firmware-summary.json`、
`expected/architectural-differential.json`、
`expected/processorfuzz-case-manifest.json` 及 ZIP 内只读 `.input_1.S`。
