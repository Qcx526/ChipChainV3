# ProcessorFuzz real_case_001 的 RV64 合成固件基准

本目录提供同一嵌入式项目的 `positive`（简称 FW-POS）和 `negative_trigger`（简称 FW-NEG-TRIGGER）两份**真实风格合成固件**。这些名称与 `examples/type2_*` 中受控 Type-II verifier 的黄金案例身份分开。硬件团队交付的 `samples/processorfuzz/real_case_001/` 没有与之配对的客户生产固件，因此这里构造可复现、可做静态对照的固件输入。它不是客户生产镜像、已验证漏洞固件或物理芯片漏洞证明。

## 证据边界与基准条件

真实材料是硬件团队的 ProcessorFuzz 触发验证包。其测试描述 SI 与经过 ELF 字节校验的静态 IR 分别记录了两处 `sfence.vma`；原包还包含 RTL/ISA trace 和三个不同的原始签名 word。SI→ELF 绑定为 `UNKNOWN`，签名同次执行绑定为 `UNKNOWN`，已解析 trace 未记录那两处 `sfence.vma`；这些材料不建立可信的真实硬件触发条件。细节见 [设计记录](design-note.md) 和原样本的 `expected/processorfuzz-report.md`。

本目录的 [SyntheticBenchmarkContract](benchmark-contract.json) 只要求：合成固件的页表项更新路径调用 `arch_translation_sync`，`positive` 的该助手包含 `sfence.vma x0,x0`，`negative_trigger` 在同一位置包含 `fence rw,rw`。后者因此违反一项选定的**静态基准条件**。选择 `sfence.vma` 是因为原样本的 SI 和静态 ELF 均客观记录该指令类别；不把它推断为原包的漏洞触发因素。

唯一有意的 `positive`→`negative_trigger` 源码差异是 `positive/config.h:3` 与 `negative_trigger/config.h:3` 中 `BENCH_TLB_INVALIDATE` 值 `1`→`0`。共享的 [架构助手](common/src/arch_riscv.c) 第 16–25 行据此编译一条不同指令。预期调用链为 `_start → main → app_run → controller_step → controller_dispatch → pager_apply → pager_commit → arch_translation_sync`；它是静态可见的调用关系，不能代表实际运行路径。

两份 ELF、应用逻辑、驱动、控制状态机、页表结构和构建工具相同。`main` 初始化平台、页表和控制器；内存邮箱预置 MAP→QUERY→UNMAP→HEALTH→STOP 命令；控制器校验命令并处理状态/错误；页表服务维护三级 Sv39 staged table，写叶项后经过通用内存栅栏和目标同步助手。它没有安装 `satp`，也没有连接特定板级外设。邮箱符号 `g_mailbox` 可供未来测试环境检查；实际硬件运行、加载协议及外部输入绑定须另行建立。

| 模块 | 文件 | 职责 |
| --- | --- | --- |
| 启动与内存布局 | `common/start.S`、`common/linker.ld` | M-mode 入口、栈、BSS 初始化、256 KiB RAM 边界 |
| 应用 | `common/src/main.c`、`controller.c` | 初始化、命令状态机、错误处理 |
| 输入与校验 | `common/src/platform.c`、`command.c` | 内存邮箱、队列、缓冲复制、校验和 |
| 页表 | `common/src/pager.c` | 三级 Sv39 表、映射/查询/解除、PTE 校验 |
| 架构助手 | `common/src/arch_riscv.c` | hart ID、内存栅栏、变体同步指令 |

## 构建与分析

从仓库根目录运行。`build.py` 检查项目本地工具链可执行文件的固定 SHA256，使用 GCC 10.2.0 / GNU ld 2.35，`-march=rv64ima_zicsr -mabi=lp64 -mcmodel=medany`，无标准库启动文件，以 `_start` / `0x80000000` 为入口。完整编译与链接参数、输入哈希、PT_LOAD 和 ELF 哈希记录在两份 `build-metadata.json` 中。对象文件放在被忽略的 `output/firmware-build/`。

```bash
python3 samples/firmware/riscv/processorfuzz_real_case_001/build.py
./scripts/setup_ghidra.sh --verify-only
.venv/bin/python -m chipchain.cli firmware analyze \
  --elf samples/firmware/riscv/processorfuzz_real_case_001/positive/firmware.elf \
  --output output/processorfuzz-synthetic-positive
.venv/bin/python -m chipchain.cli firmware analyze \
  --elf samples/firmware/riscv/processorfuzz_real_case_001/negative_trigger/firmware.elf \
  --output output/processorfuzz-synthetic-negative-trigger
```

CLI 输出目录须为新的或空目录。本目录 `expected/{positive,negative_trigger}/` 中四类分析文件（`ghidra-export.json`、`firmware-analysis.json`、`firmware-summary.json`、`firmware-report.md`）由同一 `chipchain firmware analyze` 命令直接生成；它们不是手写的静态分析结果。

| 项目 | FW-POS (`positive`) | FW-NEG-TRIGGER (`negative_trigger`) |
| --- | --- | --- |
| ELF SHA256 | `35f9fff9c00e6a93bb9e6884b8604cd3d36dd35f7fdea408412633c5b7ae9fe4` | `2b6275ffb203f5ffc5411bb9200f5eafaab61fe6615a403697ecabace469e7cd` |
| 入口 / 位宽 | `0x80000000` / 64 | `0x80000000` / 64 |
| 函数 / 基本块 / 指令 | 33 / 164 / 858 | 33 / 164 / 858 |
| CFG 边 / 直接调用 | 252 / 71 | 252 / 71 |
| `arch_translation_sync`，`0x80000064` | `sfence.vma zero,zero`；`TLB_INVALIDATE` | `fence 0x3,0x3`；`MEMORY_BARRIER` |
| TLB invalidate / memory barrier | 1 / 1 | 0 / 2 |
| 合成基准预期 | `SATISFIES_SYNTHETIC_BENCHMARK_CONTRACT` | `CONTRADICTS_SYNTHETIC_BENCHMARK_CONTRACT` |

两份 ELF 的函数名与入口、调用关系、指令数保持一致；ELF 字节比较只有 `0x80000064` 这条四字节指令中的三字节不同。两次独立构建各自得到相同的 ELF SHA256。

## 不作出的结论

`positive` 与 `negative_trigger` 均未独立执行；其 `runtime_execution_status`、`real_hardware_trigger_status`、`hardware_deviation_status`、`type2_verification_status` 和物理硅片适用性均为 `NOT_ESTABLISHED`。原始 `real_case_001` 的 RTL trace、ISA trace 与签名属于原包测试程序，**不属于**这两个新 ELF。静态满足合成条件不等于硬件触发、偏差或 Type-II 验证；`negative_trigger` 违反合成条件也不证明硬件安全。本任务没有生成 HardwareBehaviorContract 或跨层 verifier 结论。

当前仅实现并验证 `positive` 与 `negative_trigger`。
