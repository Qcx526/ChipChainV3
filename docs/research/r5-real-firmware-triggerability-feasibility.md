# R5-A/C：真实固件行为溯源与硬件缺陷候选筛选

**阶段结论。** 已从未修改的 OpenSBI v1.7 源码构建可运行的 RV64 固件，并在真实 ELF 中找到正常启动所需的 PMP 粒度探测、保护域配置、SBI 刷新服务、模式切换和异常处理指令。CVA6 的 [PMP 地址读回修复 #2469](https://github.com/openhwgroup/cva6/pull/2469)与其中一条启动行为存在具体的指令及 CSR 交集，值得下一阶段做同配置 RTL 对照。当前并没有观察到 OpenSBI 在那个 CVA6 revision 上执行，也没有看到异常读回影响保护决策；**硬件触发、硬件偏差、安全影响与 Type-II 链均未建立**。

本报告是研究判断，不创建 HardwareBehaviorContract 或正式 Runtime Evidence。机器清单在 [真实固件输出](../../output/r5-real-firmware/report.md)和[候选索引](../../output/r5-hardware-candidates/hardware-candidates.json)；所有第三方源码、工具链及运行日志都留在被 Git 忽略的 `output/`。本轮没有修改上游固件、原始样本或冻结的科学核心。

## 第一章：为什么从合成固件转向真实固件

先前 FW-POS 是项目作者为受控基准编写的现实化合成程序，其中 `arch_translation_sync()` 和 `sfence.vma` 的出现由实验设计保证。它证明工具能识别和连接预设行为，不能回答普通固件在维护处理器时是否自然产生相应操作。ProcessorFuzz 包里的 ELF 则是硬件部门的 trigger-test 程序，不能代表客户固件。

R4 已把 `real_case_001` 的三处签名差异解释到两个实现选项：word 37、44 是 FS/SD 状态处理，word 48 是非法指令 `mtval` 报告。真实控制实验支持 `CONFIGURATION_MISMATCH` 诊断，正式 `architectural_differential=UNKNOWN`、`hardware_trigger=NOT_ESTABLISHED`、`hardware_deviation=NOT_ESTABLISHED`、`full_type2_chain=NOT_VERIFIED`。R5 的新固件和硬件案例独立于这组三处负结果，不把它们改判为 Rocket 漏洞。原有结论见 [R4 调查](rocket-rtl-differential-root-cause-v1.md)。

本次把两个问题分开核查：正常开源固件到底做了什么；公开硬件修复究竟需要什么前态。只有软件操作与全部必要条件、目标配置、同次运行和有依据的异常观测同时成立，才可能进入正式跨层验证。

## 第二章：真实 OpenSBI 实验环境

源码来自[上游 OpenSBI v1.7](https://github.com/riscv-software-src/opensbi/tree/a32a91069119e7a5aa31e6bc51d5e00860be3d80)，固定 commit `a32a91069119e7a5aa31e6bc51d5e00860be3d80`，上游 annotated tag object `242542438402e2b310a82b131c5cabfc2e2f027a`。源码 checkout 构建前后 tracked 状态为空。隔离目录中的 Ubuntu GCC 12.3.0 RISC-V Linux 交叉工具链、binutils 2.38 和已固定的 DTC 1.6.1 完成构建；没有安装到系统全局环境。工具精确路径、下载身份和构建命令在 [build-audit](../../output/r5-real-firmware/build-audit/virt-o2-build/result.json)。

按照[对应版本的构建说明](https://github.com/riscv-software-src/opensbi/blob/a32a91069119e7a5aa31e6bc51d5e00860be3d80/README.md)，先尝试已有裸机工具链，真实失败于 OpenSBI 的 PIE 链接器检查；第一次 Linux 工具链构建还因隔离库搜索路径缺失失败。这两次 stderr 均保留。后来 Linux 工具链构建成功，但主机继承 `DEBUG=release`，上游 Makefile 把任何非空 DEBUG 当作调试构建，因此实际为 `-g -O0`。首次默认链接地址为 0 的 PIE ELF 在 Ghidra 加载时被放到 `0x100000`，现有字节与地址检查以 `Address 0x100000 is not uniquely file-backed in ELF` 明确拒绝。没有绕过 validator。

最终重新使用同一份干净源码、同一工具链、独立输出目录，显式设置上游支持的 `FW_TEXT_START=0x80000000`、`DEBUG=`（空值），实际编译命令为 `-g -O2`。此参数选择 QEMU virt 的固件物理入口，不修改架构功能或插入目标指令。构建退出 0，耗时约 10.10 秒；完整 stdout/stderr 及参数在 [最终构建记录](../../output/r5-real-firmware/build-audit/virt-o2-build/result.json)。

所选 `fw_dynamic.elf` 的 SHA256 为 `b2bfbc70295254e31bad07cb205b386f8fa658bb7079ebfb781f8daead3fb8d4`；它是 ELF64、小端、`EM_RISCV`、`ET_EXEC`，入口 `0x80000000`。可执行 `PT_LOAD` 起于 `0x80000000`，另有 RW 段起于 `0x80040000`；含符号表和 DWARF 行号。这个类型是**最终显式地址构建的实际结果**；第一次默认地址构建的 ELF 是另一份 `ET_DYN`，哈希和失败记录独立保存。最终同次构建的 `fw_dynamic.bin` 与上游原有 `payloads/test.bin` 也分别有哈希，不能把 ELF、BIN 和其他构建目录按 basename 混用。

## 第三章：真实固件的架构行为

项目既有 `.venv/bin/python -m chipchain.cli firmware analyze --elf <上述实际 ELF> --output output/r5-real-firmware/opensbi-static` 在最终 ELF 上退出 0，耗时约 96.97 秒。Ghidra 12.3_DEV 分析得到 762 个函数、45,363 条指令、2,049 个直接调用位置、976 个系统寄存器读取事实、1,001 个写入事实、6 个 TLB invalidate 和 6 个异常返回。每条导出的指令字节都由现有 frontend 与同一 ELF 可执行段逐一核对；[汇总](../../output/r5-real-firmware/opensbi-static/firmware-summary.json)可复核。25,237 个行为事实仍为 `UNKNOWN`；这些数字不证明所有程序路径或 ISA 语义已解码。普通 load/store 没有独立 MMIO 资源绑定，本次 MMIO 读写事实均为零。

**PMP 粒度探测。** 上游 `sbi_hart_init()` 调用 `hart_detect_features()`；编译优化将 `hart_pmp_get_allowed_addr()` 内联。它先写 `pmpcfg0=OFF`，再向 `pmpaddr0` 写地址掩码，最后读回。若 CSR 可用且访问未陷入异常，读回值用于计算 `pmp_log2gran` 与地址位数。这样做是正常启动时适配硬件保护单元：固件须先知道最小保护区域，再布置不同执行域。对应的真实 ELF PC 分别是 `0x8000ec30`、`0x8000ec56`、`0x8000ec74`；其小端字节和源码行见下一章及[行为清单](../../output/r5-real-firmware/real-firmware-behavior-analysis.md)。[固定源码 `sbi_hart.c`](https://github.com/riscv-software-src/opensbi/blob/a32a91069119e7a5aa31e6bc51d5e00860be3d80/lib/sbi/sbi_hart.c#L774-L793)直接给出这个顺序。RISC-V 的[固定特权规范文本](https://github.com/riscv/riscv-isa-manual/blob/98964261c931d51884f733664b22efe43de93033/src/machine.tex)也描述同样的粒度探测方法，并规定较粗粒度下 OFF/TOR 的相关 `pmpaddr` 低位读零。

**保护域配置。** `sbi_init()` 的静态直接调用进入 `sbi_hart_pmp_configure()`；`pmp_set()` 对选中的配置项通过 `csr_read_num`/`csr_write_num` 更新 PMP CSR。保护域区域、条目数与硬件特性影响所走分支。若实现 S-mode，源码在 PMP 更新后执行 `sfence.vma`；ELF 中 `0x8000e564` 的字节 `73000012` 与上游第 592 行相符。它用于同步 PMP 与地址转换缓存，符合特权规范的要求。存在该指令不表示某次启动确实经过这一分支。

**远程刷新与指令缓存。** `sbi_ecall_rfence_handler()` 的直接调用位置 `0x8000ac36` 通向 `sbi_tlb_request()`；队列处理函数 `tlb_entry_local_process()` 依据请求类型及范围调用局部刷新逻辑。优化后多个分支在同一函数内含 `sfence.vma`：`0x800064a6`、`0x800064d8`、`0x80006552`、`0x80006558`；`0x8000646c` 是 `fence.i`。这服务于正常 SBI RFENCE 请求，而非为了本研究植入的指令。服务调用、目标 hart、ASID 和范围是必要运行上下文；当前 smoke 未观察到这些具体请求。[上游实现](https://github.com/riscv-software-src/opensbi/blob/a32a91069119e7a5aa31e6bc51d5e00860be3d80/lib/sbi/sbi_tlb.c)。

**模式切换、异常及中断。** `sbi_hart_switch_mode()` 在 `0x80010d80` 读 `mstatus`，在 `0x80010db8` 写 MPP/MPIE 后的状态，在 `0x80010dbc` 写 `mepc`，最终于 `0x80010dcc` 执行 `mret`，将运行交给后续模式。`_trap_handler` 通过 `0x80000470` 的静态调用进入 `sbi_trap_handler()` 并在 `0x800004f0` 返回；实际返回须有相应异常运行事件。`sbi_hart_reinit()` 另在 `0x8000ea50` 将 `mie` 清零，以避免初始化期间处理未准备的中断。写零不构成对 CVA6 “无 S-mode 时错误保留 supervisor 中断位”问题的有效测试。

## 第四章：从功能到指令的来源链

机器层沿一条明确的链核对：**官方 commit 与干净源码 → 完整 build 命令及编译器 → ELF SHA/段 → canonical Ghidra IR → 同一 ELF 的 DWARF 行表 → 原 checkout 的源码文件字节**。最终复现命令和 5,069 条选定函数指令记录在[源码映射](../../output/r5-real-firmware/source-grounding-004/source-to-instruction-mapping.json)。这 5,069 条的 `SUPPORTED_STATIC` 只表示 ELF 指令字节、唯一函数归属及编译行号/源文件字节都可核对；其中可能仍有共享语义 `UNKNOWN`，绝不等于执行或触发。

| 正常功能及上层关系 | ELF PC / 小端字节 | 静态指令 | 原源码位置 | 当前证据等级 |
|---|---|---|---|---|
| `sbi_init → sbi_hart_init`，PMP 配置先置 OFF | `0x8000ec30` / `7390053a` | `csrw pmpcfg0,a1` | `lib/sbi/sbi_hart.c:779` | 静态指令与 DWARF 来源成立；运行 PC 未观测 |
| 同一功能写 PMP 地址掩码 | `0x8000ec56` / `7310053b` | `csrw pmpaddr0,a0` | 同文件 `:783` | 同上；运行写值未观测 |
| 同一功能读回 PMP 地址 | `0x8000ec74` / `f325003b` | `csrr a1,pmpaddr0` | 同文件 `:785` | 同上；运行读值未观测 |
| SBI RFENCE 请求的刷新分支 | `0x800064a6` / `73000712` | `sfence.vma a4,zero` | `lib/sbi/sbi_tlb.c:94` | 静态分支成立；请求和运行未观测 |
| PMP 更新后的同步 | `0x8000e564` / `73000012` | `sfence.vma zero,zero` | `lib/sbi/sbi_hart.c:592` | 静态分支成立；运行未观测 |
| 切换到后续模式 | `0x80010dcc` / `73002030` | `mret` | `lib/sbi/sbi_hart.c:1145` | 静态函数归属成立；运行 PC 未观测 |

这里的源码行是编译器提供的行号，优化或内联会把辅助函数的代码合并进 `sbi_hart_init()`；它不是动态调用记录。调用图里确认的直接边，如 `sbi_init → sbi_hart_init` 与 `sbi_init → sbi_hart_pmp_configure`，只证明相应调用指令存在。队列 callback 之间不是完整直接调用链，报告不会把它们强行连成一次执行。可疑的多重归属、缺失行号或不在 checkout 中的路径由[研究辅助工具](../../experiments/firmware/source_grounding.py)明确输出 `AMBIGUOUS`/`UNKNOWN`。

上游 `REPRODUCIBLE=y` 使用 `-ffile-prefix-map=<source-root>=`，DWARF 中出现 `/lib/sbi/...` 这样的虚拟路径。工具只有在显式传入 `/=.` 且核对实际编译命令确有上述 prefix map 时，才把它反向关联到固定 checkout；没有通过 basename 猜测来源。首次未显式提供映射的调查保留 UNKNOWN；正确映射的最终结果保留单独 ID 和命令记录。这个地址重定位和 RISC-V CSR 语义解释都留在本次研究输入，没有进入架构中立共享判定。

## 第五章：运行可行性

项目固定 QEMU 11.1.1 具有 `riscv64` 和 `virt`。依据[OpenSBI 的 QEMU virt 文档](https://github.com/riscv-software-src/opensbi/blob/a32a91069119e7a5aa31e6bc51d5e00860be3d80/docs/platform/qemu_virt.md)及 `FW_DYNAMIC` 的启动信息约定，实际使用同一次最终构建的 `fw_dynamic.bin` 作 `-bios`，上游原有 `payloads/test.bin` 作 `-kernel`，显式 `-M virt -m 256M -smp 1 -accel tcg -nographic`。本机真实 stdout 先打印 `OpenSBI v1.7` 和 QEMU 平台、域及 PMP 摘要，随后打印 `Test payload running`。8 秒后 watchdog 向 QEMU 发 SIGTERM，退出码为 0，**停止原因为 watchdog**；测试 payload 自身进入等待，不把该退出码写作正常完成。完整[命令、版本、输入 SHA 和原始日志](../../output/r5-real-firmware/runtime-smoke/result.json)可查。

这表明所选固件 BIN 可以在 QEMU virt 中启动并交接到随 OpenSBI 上游构建的测试 payload。日志不是逐 PC 事件；不能据此证明上述 PMP 探测指令或 RFENCE 分支已经运行。既有 `riscv64-fw-feasibility` canonical Runtime Evidence profile 面向独立合成 ELF、`bios=none` 及 identity load；当前 BIOS、ROM、动态启动信息和 next-stage payload 与它的契约不同。若进入下一阶段，需要经审查的新启动/重定位及 payload 来源绑定、指令回调与 ELF bytes 关联、覆盖窗口，并把 QEMU 诊断同 RTL 证据保持分离。[运行边界详单](../../output/r5-real-firmware/runtime-feasibility.md)。

## 第六章：真实硬件 Bug 候选调查

[HWE-Bench 固定代码](https://github.com/pku-liang/hwe-bench/tree/10c78a87e1f92695d78d15b1464a6107dcac8837)的 README 声称总计 417 项。本次只下载并核对固定数据集 commit `82a42e0a05719366a326e09ddc668ea0d46c91f6` 的 Rocket、CVA6、Ibex 三个 JSONL，共 **102 项**（32+35+35）；没有声称审查其他 315 项。五个入围案例的 Git first-fix commit/parent 对由官方 Git 对象复核，公开 patch 的 blob 前后哈希也与精确 revision 源文件匹配。HWE 数据记录的 `TEST=FAIL`、`FIX=PASS` 是发布方的 fail-to-pass 信息；本机没有下载巨大 Docker 镜像或执行这五个 RTL 测试。代码、补丁和记录见[候选比较](../../output/r5-hardware-candidates/hardware-case-selection.md)。

**CVA6 #2469，PMP 地址读回：`PROMISING_FOR_CROSS_LAYER`。** [上游 issue #2465](https://github.com/openhwgroup/cva6/issues/2465)给出 `pmpcfg0=OFF → pmpaddr0 写满 → 读回` 的真实问题；[PR #2469](https://github.com/openhwgroup/cva6/pull/2469)把读回低位约束到地址匹配模式。旧源码在 OFF 分支可直接返回存储低位，新源码使 OFF/TOR 的最低位读零。HWE 以 `pmpaddr_off_mode_readback` 做 CSR 模块测试；发布方记录先失败后通过。OpenSBI 的启动探测恰好具有同样的指令及 CSR 顺序，这个关联比“都涉及 PMP”更强。但所选 HWE 测试配置为 CV32A65X，当前 ELF 为 RV64，且我们没有执行 CVA6 buggy/fixed RTL 上的这份固件。特定 CVA6 配置的 PMP 粒度、entry 锁定状态、读回值及后续保护决策均未知；因此只有**研究优先级**成立，触发性仍 UNKNOWN。任何安全或保护绕过后果还需要单独观测。

**CVA6 #2330，PMPCFG 写索引：`HARDWARE_ONLY`。** [Issue #2326](https://github.com/openhwgroup/cva6/issues/2326)描述 CV32A65X 的 `pmpcfg1` 写入高字节错误；[PR #2330](https://github.com/openhwgroup/cva6/pull/2330)把索引 `index+i` 修正为 `index*4+i`。这是明确的 RTL 修复及模块级 fail-to-pass 案例。OpenSBI 确会在正常内存保护配置中写 PMPCFG，但**本次发布的复现条件是 RV32 的 `pmpcfg1`**，不能拿当前 RV64 ELF 的普通 PMPCFG 写指令冒充该次触发。RV64 其他 bank 是否受同一计算影响，需要对应配置、条目数和读回差异的独立验证。

**CVA6 #2017，MIE/MIP S 中断位：`HARDWARE_ONLY`。** [Issue #2004](https://github.com/openhwgroup/cva6/issues/2004)和[PR #2017](https://github.com/openhwgroup/cva6/pull/2017)聚焦没有 S 扩展时仍能修改 supervisor 中断相关位。修复在 CSR 寄存器模块中增加 `RVS` 条件来约束 MIE/MIP 的写掩码；HWE 的 `csr_mie_embedded_mask` 在 CV32 embedded 配置记录 fail-to-pass。OpenSBI 的 `mie=0` 是正常启动操作，却不会给这些保留位写入有区别的置位值；当前 QEMU smoke 还需要 S-mode 交接，与修复的 `RVS=false` 配置相反。不能根据一次 `mie` 写入认定软硬件触发。

**Rocket #1761，tvec 初值仿真：`SPECIALIZED_TEST_ONLY`。** [PR 作者](https://github.com/chipsalliance/rocket-chip/pull/1761)明确把问题界定为第一次 tvec 写入前随机初始化造成的仿真悲观性，并说明综合结果不变；补丁把位约束从写侧移到读侧。HWE 的 `csr-tvec-uninitialized-alignment` 是有价值的定向仿真回归，但没有证据表明正常 OpenSBI 在第一次安装 trap vector 以前发生可观察的读/异常，也没有把这个上游 Chisel revision 绑定到用户给的 RocketTile RTL。它尤其不能重新解释 R4 的三个签名差异。

**Ibex #104，trap 合规修复：`HARDWARE_ONLY`。** [PR #104](https://github.com/lowRISC/ibex/pull/104)包含 exception 与 interrupt vector 选择、`mcause`/`mtval`/`mscratch` 和未对齐访问等多项修复；该 PR 有多个提交，首个 commit 只验证了局部修复的祖先关系。HWE `csr_trap_csrs` 测试覆盖其 CSR 子面，不能代表全部 trap/AGU 情况。OpenSBI 的异常处理确有真实指令，但本轮 ELF 为 RV64 并要求 S-mode；不能在 RV32 Ibex 上以此 ELF 验证。未来若有合适 RV32 正常固件，应先缩小到一个规范版本、一个异常前态及一个具体的 buggy/fixed 观测。

## 第七章：固件与硬件的初步关联

| 必要条件 | CVA6 #2469 与本次 OpenSBI | 判断 |
|---|---|---|
| ISA/权限 | OpenSBI 为 RV64；探测在 M-mode，CVA6 修复位于 PMP CSR 模块 | 操作类型相符；HWE 测试的 CV32 配置与当前 ELF 不同 |
| 精确指令顺序 | `0x8000ec30` 写 OFF；`0x8000ec56` 写地址掩码；`0x8000ec74` 读回 | 同一真实 ELF 中静态顺序与上游源码相符，未有逐 PC 运行证据 |
| 硬件前态 | 需适用的 G/粒度、未锁 PMP0、写入成功及某个 buggy revision | **UNKNOWN**；QEMU banner 不是 CVA6 状态 |
| 规范预期 | 较粗粒度 OFF/TOR 下相应地址位应读零 | 有固定 RISC-V 规范依据，仍需确定目标配置究竟是哪一级粒度 |
| 错误读回、后续使用及安全后果 | 需同次运行的 CSR 返回值、固件基于该值的决策、实际保护观察 | **UNKNOWN / NOT_ESTABLISHED** |

因此“OpenSBI 自然产生所需 PMP CSR 序列”已有静态证据；“所选固件在有缺陷的 CVA6 上触发错误读回”及“错误造成可观察保护偏差”均未建立。CVA6 #2330 的已发表 RV32 `pmpcfg1` 前态和 #2017 的无 S-mode 前态与本次 RV64 S-mode 软件配置不合。其他案例的表面 CSR/异常词汇重合不构成软硬件可触发性。

## 第八章：当前研究结论

已完成实际 OpenSBI v1.7 构建、现有 Ghidra CLI 静态分析、按同一 ELF/源码的字节与行号溯源，以及 QEMU virt 的上游测试 payload 启动。PMP 探测和 RFENCE 等操作有可审查的软件功能解释。公开硬件方面筛选出五项有来源的修复，其中 CVA6 #2469 与 PMP 粒度探测的交集最明确。

这些事实支持选择下一轮的**验证对象**，没有产生已验证漏洞。HWE 发布的 fail-to-pass 测试是定向硬件模块测试，不自动代表正常固件；QEMU 启动成功不是 CVA6/Rocket RTL 运行；静态顺序不是运行顺序；正常 OpenSBI 行为也不是攻击者可控输入。

## 第九章：能力边界与冻结保护

本轮分层状态为：OpenSBI 静态行为和源码关系 **SUPPORTED_STATIC**；QEMU 上软件启动及测试 payload 输出 **OBSERVED_BOOT_DIAGNOSTIC**；上述选定 PC 的 canonical runtime **NOT_ESTABLISHED**；CVA6 目标 revision 上的触发 **UNKNOWN**；客观硬件偏差、安全影响及 Type-II 链 **NOT_ESTABLISHED / NOT_VERIFIED**。没有将 QEMU 记录重标为 RTL 证据，也没有由公开补丁自动生成 HardwareBehaviorContract。现有 CAP0 `SourceKind` 对一般真实 Ghidra 源码没有诚实的来源值，本轮使用独立研究映射，避免借 `synthetic_fixture` 冒充真实固件能力。ARM 和 PowerPC 前端及科学核心保持原状。

受保护初始快照有 40,077 个文件或链接。逐项 SHA/链接目标核对后，原有字节仅 README 的本轮说明发生预期变化；全部受保护 R3/R4 输出、真实 ProcessorFuzz 样本、QEMU 证据和六个冻结核心文件一致，保护目录无新增文件。ChipChain HEAD 仍为 `8bf7c85528e6cd50efd5a2184e912d0d43b51810`；`v3-rocket-rtl-differential-r4-stable` tag object 仍为 `81b1f5464aadd71021f8a8a9c1169e96853ca0dc`，其他 stable tag 引用也未变。P1/N1/N2/U1 黄金 ID 已从原集成入口实际重放并保持不变；详见[冻结核心与黄金 ID 对照](../../output/r5-real-firmware/validation/frozen-core-and-goldens.json)和[保护审计](../../output/r5-real-firmware/audit/protection-result.json)。完整回归 `677 passed in 81.45s (0:01:21)`；`pip check`、`compileall` 和 `git diff --check` 均通过。没有运行 HWE Docker，也没有把第三方源树、测试固件或大体量产物加入 Git。

## 第十章：下一阶段最小建议

优先为 **CVA6 #2469 的 PMP 读回** 做一个单独、受审查的实验：固定一个支持相关 PMP 粒度的 CVA6 RV64 配置及其第一修复提交的 parent/fix；先用原始 HWE CSR 模块测试确认读回差异，再验证 OpenSBI 在该平台正常启动时是否到达上述三个 PC，记录写入成功、`pmpcfg0` 模式、`pmpaddr0` 实际返回值和后续粒度计算。若只能启动 QEMU 或只重复模块级 fail-to-pass，结果继续是 UNKNOWN。若出现来源绑定的 buggy/fixed 读回差异，再审查它是否导致保护区配置偏差；届时才讨论正式 RTL evidence/HBC 接口。

这个提案仍停在 R5-A/C 的选择阶段。实际 CVA6 启动与客观保护差异未完成之前，不进入 R5-B canonical runtime、R5-D Type-II 验证，不将 OpenSBI 临时塞入现有 RocketTile testbench。
