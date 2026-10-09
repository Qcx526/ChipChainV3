# R4：ProcessorFuzz 签名差异的根因调查

本次调查解释了 R3 复现的三处签名差异。它们来自两个模型的两种状态处理选择：Rocket 把非零浮点状态请求归一为 Dirty，而参考模型保留 Initial；ProcessorFuzz 修改版 Spike 把非法指令异常的 `mtval` 清零，而所选 Rocket 保存指令编码。源码、原始运行轨迹和真实单条件实验相互支持这一解释。

这是一项成功的差异排查。当前证据不支持把这三处差异认定为 Rocket 设计漏洞。原始签名仍然不同；研究诊断归为 `CONFIGURATION_MISMATCH`，正式架构偏差仍为 `UNKNOWN`，硬件触发和偏差尚未建立，完整 Type-II 链尚未验证。

## 第一章：为什么调查这三个差异

硬件部门提供的 ProcessorFuzz 包包含用于检查硬件行为的测试程序。这里分析的是该包的 trigger-test ELF，不是客户或生产固件，也不是项目独立编写的 FW-POS。目录名称不能让这些程序共享运行证据。

R3 使用用户提供的 `RocketTile_latest.v`，通过 Verilator 和官方 ProcessorFuzz TileLink 驱动真实运行原始测试 ELF。两次 RTL 运行的 trace 和 signature 逐字节相同，且与交付包的 RTL signature 相同；固定修改版 Spike 产生的 signature 也与交付包 ISA signature 相同。254 个 128 位数据单元中，只有索引 37、44、48 不同。

R4 要回答的是：这三个单元保存了什么，哪些指令写入它们，模型为什么产生不同值，以及这些差异是否具备漏洞验证所需的依据。对当前证据的解释不能替代尚未取得的规范违反证据。

冻结基线为 `f0514b7b3ea5f5333a430b57acb906d96cd52c4c`，annotated tag 为 `v3-rocket-rtl-feasibility-v1-stable`，tag object 为 `57c03f4b8195c38133de7a4af48b1e3c2c30e782`。本轮开始时工作区干净，没有移动 HEAD 或 stable tag。

## 第二章：实验输入、环境和身份

| 输入或工具 | 实际选择 | 来源范围 |
| --- | --- | --- |
| 处理器 | 用户 ZIP 中的 `RocketTile_latest.v`，top=`RocketTile` | 精确 Verilog 文件；生成它的 Chisel/FIRRTL 历史尚未认证 |
| 测试程序 | `real_case_001` 原始 ELF/HEX | 硬件部门 trigger-test；ELF 字节核对后的静态 IR |
| RTL 驱动 | 官方 ProcessorFuzz commit `2d08d0d8b4563212175212f9db0e69f6e68c9619` | 官方 TileLink/host 驱动及 R3 显式兼容 wrapper |
| RTL 仿真 | Verilator 5.008、cocotb 1.9.2、cocotb-bus 0.2.1 | 复用 R3 隔离工具环境 |
| Python/C++ | Python 3.12.14、G++ 11.4.0 | 同一实验环境；没有修改系统全局安装 |
| 原参考模型 | ProcessorFuzz `riscv-isa-sim-all-csr` commit `3343b9d07ae02b3aee5b3e6137cadb55b6d732ff`，Spike 1.0.1-dev | 固定修改仓库，不等于标准 Spike |
| 原运行 | R3 `run-latest-009`、`run-latest-010`、`spike-reference` | 重新验证实际 manifest、输入、模型 binary、日志及签名哈希 |
| 新控制运行 | R4 一个重新构建的 RTL 运行、三个成功的 Spike 控制运行 | 每项具有独立输入/配置、命令、stdout/stderr、退出状态和原始输出 |

完整输入索引在 [run-input-index.json](../../output/rtl-differential-r4/analysis-003/run-input-index.json)，控制运行索引在 [control-results.json](../../output/rtl-differential-r4/control-results.json)。这些是研究诊断产物，没有创建正式 HardwareRuntimeEvidence。

R3 manifest 中的旧采集脚本 SHA 对应各自 `raw/run-tool.py` 的原始快照。R4 为同一采集器增加了显式 `--output-root`，将新构建写入 R4 工作区；重放 R3 时验证旧快照，不把现在的脚本冒充当时执行的脚本。其他采集语义没有更改。

## 第三章：观察到的差异是什么

索引从 0 开始。每行左边 16 个十六进制字符是较高地址的 64 位值，右边 16 个字符是较低地址的 64 位值。

| 索引 | Rocket RTL 原始单元 | 修改版 Spike 原始单元 | 实际不同的数据 |
| --- | --- | --- | --- |
| 37 | `80000002000460000000000000000000` | `00000002000420000000000000000000` | 高半部：`sstatus_output` |
| 44 | `000000000000b1098000000a00046000` | `000000000000b1090000000a00042000` | 低半部：`mstatus_output` |
| 48 | `00000000141416730000000000000002` | `00000000000000000000000000000002` | 高半部：`mtval_output` |

另外的半部没有变化：word 37 的 `fcsr` 为 0，word 44 的 `medeleg` 为 `0xb109`，word 48 的 `mcause` 为 2。两个模型均记录非法指令异常；第三个单元的不同不能解释成“只有 Rocket 发生异常”。完整计算结果在 [signature-differential.json](../../output/rtl-differential-r4/analysis-003/signature-differential.json)。

## 第四章：从签名追溯到写入指令

### 地址和字节序怎样确定

ELF 的 `begin_signature=0x80002000`、`end_signature=0x800023e0` 给出主区的 62 个单元。官方 host 后续写出六个 `_random_dataN` 到 `_end_dataN` 区间，每个区间 512 字节、32 个单元，合计 254。区间数量由所选 host/HTIF 源码和实际 ELF 符号共同确定，没有将某个样本的单元索引写成通用规则。

官方 `RTLSim/host.py::save_signature` 先输出 `memory[i+8]`，后输出 `memory[i]`；固定 Spike 的 `fesvr/htif.cc` 按 16 字节小端数据反向输出字符。两者对当前布局一致。地址、分区及每个半部的小端内存字节保存在 [signature-word-mapping.json](../../output/rtl-differential-r4/analysis-003/signature-word-mapping.json)。

`csr_dump` 在 `0x80000118` 的 AUIPC 与 `0x8000011c` 的 ADDI 建立 x1=`0x80002200`。字节验证后的 CSR 读取和 64 位 store 在同一连续基本块中形成以下关系。原始 IR 的助记符或外部 `disassembly.asm` 不作为独立权威；实际 ELF 指令字节必须相符。

| 保存内容 | 半部地址 | CSR 读取 PC / 小端字节 | Store PC / 小端字节 | 运行证据位置 |
| --- | --- | --- | --- | --- |
| `sstatus_output` | `0x80002258` | `0x80000120` / `73210010` | `0x80000124` / `23bc2004` | RTL 191/192 行；Spike 327/329 行，store commit 330 行 |
| `mstatus_output` | `0x800022c0` | `0x8000017c` / `73210030` | `0x80000180` / `23b0200c` | RTL 214/215 行；Spike 373/375 行，store commit 376 行 |
| `mtval_output` | `0x80002308` | `0x800001c4` / `73213034` | `0x800001c8` / `23b42010` | RTL 232/233 行；Spike 409/411 行，store commit 412 行 |

所有三个读取的目的寄存器均为 x2，store 使用 x2 及 x1 基址。Rocket 读取监视值、store 时的内部 x2/基址样本、Spike 读取提交值、Spike 内存写提交，以及各自最终签名值一致；指令、hart、权限和先后顺序也一致。逐项核对在 [signature-origin-analysis.json](../../output/rtl-differential-r4/analysis-003/signature-origin-analysis.json)。

这里建立的是当前有依据的读取—store 诊断关系。静态工具只覆盖识别出的连续块，不认证程序所有可能写入；Rocket 监视器也不是独立总线写事务记录。因此不能声称已经证明“所有执行路径上的唯一最终写入”。

### Word 37：保存的是 supervisor 状态

原始高半部差异位于 `0x80002258`。`csrr x2,sstatus` 在 `0x80000120` 返回 Rocket 的 `0x8000000200046000` 和 Spike 的 `0x0000000200042000`，下一条 store 将它们保存到 `sstatus_output`。这不是 TLB 内容或访问地址。

FS 表示浮点状态的保存需求：Initial 表示初始状态，Dirty 表示需要按已修改状态处理；SD 是 Dirty 状态的摘要。Rocket 将非零 FS 请求保守地归为 Dirty，Spike 保留 Initial，因而 FS 高位和 SD 位不同，精确 XOR 为 `0x8000000000004000`。该标志差异本身不表示浮点计算结果错误。

改变晚期状态初始化使两边都请求 FS=Dirty 后，真实参考运行只改变 word 37/44；真实新 RTL 运行保留原 RTL 签名。word 37 的机制受到实验支持，诊断为配置/实现选项不一致。尚未认证所选 RTL 的完整规范版本和所有 writer，但当前证据不支持将它提升为规范违反。

### Word 44：保存的是 machine 状态，同一机制再次出现

差异低半部位于 `0x800022c0`。`csrr x2,mstatus` 在 `0x8000017c` 读取 Rocket 的 `0x8000000a00046000` 和 Spike 的 `0x0000000a00042000`，`0x80000180` 的 store 写入 `mstatus_output`。它与 word 37 同样只在 FS 高位和 SD 位不同。

两份签名中的高半部 `medeleg=0xb109` 一致。sstatus 反映了同一 machine 状态中 supervisor 可见的相关字段，所以 word 37 和 word 44 是一个较早 FS 状态选择的两次保存，不是两个独立硬件故障。单条件 FS 实验使这两个单元同时一致，word 48 保留差异。诊断同为 `CONFIGURATION_MISMATCH`，没有证明 mstatus 的其他行为整体等价。

### Word 48：保存的是非法指令异常的辅助信息

差异高半部位于 `0x80002308`。`csrr x2,mtval` 在 `0x800001c4` 读取 Rocket 的 `0x14141673` 和 Spike 的 0，下一条 store 写入 `mtval_output`。两个模型的低半部 `mcause=2` 均表示非法指令。

相关非法指令位于 `0x800004b8`，编码 `0x14141673`，即 `csrrw x12,sepc,x8`，在 U 模式尝试访问 supervisor CSR。Rocket 将指令编码记录为异常值；修改版 Spike 的异常对象也携带这个编码，但其 `processor.cc:921–927` 明确为 BOOM 兼容将 cause=2 的 mtval/mtval2 写为 0。异常诊断日志的 tval 不等于随后可读的 mtval CSR。

只改变复制参考模型的这个报告分支并重新构建后，原始 ELF 的 word 48 高半部变成 `0x14141673`，其余 253 个单元保持原参考值。这直接支持报告选项解释，诊断为 `CONFIGURATION_MISMATCH`。没有更改非法指令判定，也没有证明所有异常路径均与 Rocket 等价。

## 第五章：执行经过与首次可比较差异

Rocket 的旧 trace header 不足以解释扩展字段。新解析器从所选 RTL 的实际 `$fwrite` 表达式恢复 120 个字段及数值基数；异常行的 `EXCEPTION` 标记单独处理。整数寄存器数组的索引由 RTL 的五位补码地址赋值确定，不能将数组下标直接当作寄存器号。

Rocket CSR/寄存器快照是在 posedge active region、非阻塞赋值更新前采样；正常指令的写回值与这个快照有不同语义。异常行不是普通指令成功完成记录。延迟结果没有可靠 PC 关联时保持未知。

Spike 的 CSR 快照由 `disasm()` 在 `execute_insn()` 前输出，提交记录则保存执行后的写值；连续相同 PC 可能不再输出完整快照。异常对象、提交和 CSR 快照分别保存，跨 hart、重复 PC 或缺失快照不自动合并。

轨迹按 hart、权限模式、PC、ELF 指令字节、事件类型及单调顺序关联，得到 291 个唯一匹配。末尾循环在 Rocket 中有 29 个相同身份事件、Spike 中有 4,856 个，继续标为歧义；不能按行号强行一一对齐。异常指令没有可认证的 Spike 权限提交时，也不自动填补。结果在 [trace-alignment.json](../../output/rtl-differential-r4/analysis-003/trace-alignment.json)。

| 执行位置 | 客观观察 | 对最终差异的意义 |
| --- | --- | --- |
| ELF 入口 `0x80000000` | MISA、DCSR 快照已不同 | 模型配置并不完全相同；不能把后面的 FS 变化称为全局第一次差异 |
| `0x80000404` | 较早浮点初始化使两个模型 FS 都为 Dirty | 不能把根因实验错误放到这条指令 |
| `0x80000458` | `csrrw a4,mstatus,a0` 输入 `0x63400`，请求 FS=Initial | Rocket 非零 FS 归为 3；Spike 保留 1 |
| 下一条 `0x8000045c` | 首次可比较的 mstatus 快照：RTL `8000000a00066000`，Spike `0000000a00062000` | 支持当前 trace 中 FS 差异的出现位置，不认证全局最早物理状态变化 |
| `0x8000046c` | `mret` 后进入低权限测试 | FS 差异保留；之后被 dump 保存 |
| `0x800004b8` | U 模式 sepc 访问非法，两边进入 handler | 异常后的 mtval 报告方式不同 |
| handler `0x80000118` 起 | 读取、保存各 CSR | 三个保存值与最终签名相符 |
| `0x800001cc`、`0x800001d0` | mip 读取为 RTL 0 / Spike `0x80`；随后 `andi x2,x2,-0x81` 清除该位 | 有额外运行读取差异，却没有对应最终签名差异 |

Rocket 原 trace 第 188 行的异常记录仍含更新前状态，189 行的 handler 快照才观察到新 mcause/mtval。Spike 第 319 行记录目标指令，320/321 行记录异常和 tval，323 行的 handler 快照显示 mtval=0。不能按不同模型的采样位置直接断言因果。

原 ELF 中存在两条 `sfence.vma`，PC 为 `0x8000065c` 和 `0x80000758`，本次执行记录没有观察到它们；程序先在 `0x800004b8` 陷入异常。静态存在该指令不构成执行证明，更不构成真实 TLB 漏洞根因。全局首次差异继续为 `UNKNOWN`，见 [first-divergence-analysis.json](../../output/rtl-differential-r4/analysis-003/first-divergence-analysis.json)。

## 第六章：配置等价性和规范核查

| 项目 | 所选 Rocket RTL | 原修改版 Spike | 判断及适用范围 |
| --- | --- | --- | --- |
| XLEN/标准扩展 | RV64；MISA 有 A/C/D/F/I/M/S/U，另有 X 位 | RV64IMAFDC，MSU；无 X 位 | 标准字母部分对应，非标准扩展身份未等价 |
| FS/SD | 非零 FS 写入成为 Dirty，SD 随之置位 | 保留 Initial/Clean/Dirty，再计算 SD | 明确不同，直接解释 word 37/44 |
| 非法指令 mtval | 保存指令位 | 修改分支强制写 0 | 明确不同，直接解释 word 48 |
| PMP | 8 项 | 16 项，reset 默认 PMP0 放行 | 不等价；当前程序设置 PMP0，未建立它导致这三处差异 |
| MMU | Bare/Sv39，ASID 0，PPN 保留低 20 位 | Bare/Sv39/Sv48 | 不等价；当前观察为 Bare，没有建立地址转换因果 |
| 启动路径 | reset vector `0x10000`，官方 boot ROM 跳到 ELF | `0x1000` 参考启动路径，再到 ELF | 启动路径不同，所加载程序字节已核对 |
| 中断 | driver 不注入，RTL 中断逻辑保留 | 修改版 `take_interrupt` 无条件返回 | 不等价；本次未观察中断，不用于认证中断行为 |
| 其他 CSR/reset | 用户 RTL 实际实现 | mcause 与 15、scause 与 31 掩码；初态 MPP=3 | 已记录差异，cause=2 不受该 mcause 掩码影响 |
| 完整规范/生成版本 | 尚未认证 | 修改仓库没有已认证的完整 spec 声明 | 未知；不能从运行成功推出全配置等价 |

官方历史 [Privileged ISA 1.11](https://raw.githubusercontent.com/riscv/riscv-isa-manual/f467e5dfd4acb4391870b8bfcfd687a0e5d8eddc/src/machine.tex) 和 [1.12](https://raw.githubusercontent.com/riscv/riscv-isa-manual/98964261c931d51884f733664b22efe43de93033/src/machine.tex) 都允许实现只跟踪 Off/Dirty，并把写入 Initial/Clean 转成 Dirty；非法指令异常的指令位报告是可选功能，不提供时 mtval 为 0。原文按固定提交保留在 R4 config-audit。

因此，“两个模型值不同”不自动等于“某一方违反规范”。这两个具体选择有历史规范依据；这不认证用户 RTL 的生成年代、完整符合性或其余配置。

修改版 Spike 仓库只有一个无 parent 的提交，无法从 ancestry 恢复其 fork-base。本次以官方 Spike v1.1.0 的固定 commit `530af85d83781a3dae31a4ace84a573ec255fefa` 做源码对照，但没有把它称为已证明祖先或完整补丁基线。更完整的源码定位和限制见 [configuration-analysis.md](../../output/rtl-differential-r4/config-audit/configuration-analysis.md)。

## 第七章：根因假设如何受到真实实验支持

### 实验一：只改变非法指令 mtval 报告选项

假设是：word 48 来自参考模型的 BOOM 兼容清零分支，而非不同异常类型。依据是两边 cause=2、故障编码一致以及修改版源码的显式分支。

复制 R3 Spike 的源码和 build 到 R4，无硬链接；只移除该分支，保留异常对象的 mtval/mtval2。仅重新编译 `processor.o`、替换静态 archive 成员并重新链接，其他源码和既有 object 均未改变。原 R3 binary 保持不变，补丁和构建命令保存在 [source-delta.patch](../../output/rtl-differential-r4/spike-mtval-control/source-delta.patch) 及同目录日志中。

用原始测试 ELF 实际运行这个独立参考配置后，退出 0，耗时约 0.034 秒。只有 word 48 改变，word 37/44 的差异保留。假设获得支持。这不是对“标准正确答案”的认证，也没有重写原参考运行。

第一次启动因为 PATH 缺少 R3 隔离 dtc 而退出 1，没有成功执行测试程序。失败保留在 `spike-mtval-control/attempt-001-missing-dtc/`；使用原 R3 dtc 的 PATH 后，`run-002` 正常完成，没有修改系统安装。

### 实验二：只把晚期 FS 请求从 Initial 改成 Dirty

假设是：若两个模型都明确请求 Dirty，word 37/44 应一致，而 word 48 仍不同。为检验它，在新的派生 ELF 中把 `0x80000440` 的 `addi x14,x0,3` 改为 `addi x14,x0,7`。这使后续写入 mstatus 的输入从 `0x63400` 变成 `0x67400`，只改变 FS 请求；原 ELF 其他文件字节不变，实际只有文件偏移 5186 的一个字节不同。

新 ELF/HEX 均具有独立 SHA，预测先于运行保存在 [derivation.json](../../output/rtl-differential-r4/fs-dirty-control/derivation.json)。它不是原始 case 的同一次运行，也不以项目 FW-POS 替代原测试。

同一派生 ELF/HEX 在原样 Rocket 上重新通过 Verilator 构建和 cocotb 执行：构建 61.849 秒，运行 1.987 秒，两者退出 0；1,394 个 clock rising edges 后观察到 tohost 并完成驱动 drain。仿真时间为 2,786,000 ns，coverage_counter=667 不解释成时钟周期。得到真实 trace 和 signature，新 signature 与原 Rocket signature 逐字节相同。

未修改的 R3 Spike 在该派生 ELF 上实际运行，退出 0，约 0.017 秒。相对原参考只改变 word 37/44，与新 RTL 只剩 word 48 不同。预先记录的单条件预测成立。

### 实验三：组合两个已分别检验的条件

同一 FS=Dirty 派生 ELF 在 mtval 报告控制参考 binary 上真实运行，退出 0，约 0.017 秒。结果与新 Rocket 运行的全部 254 个单元一致。三个变化刚好是两个单条件机制的叠加。

| 对照 | 改变的条件 | 参考签名相对原参考改变 | 与对应 RTL 剩余差异 |
| --- | --- | --- | --- |
| 原始 R3 | 无 | 无 | 37、44、48 |
| mtval 单条件 | 参考异常值报告分支 | 48 | 37、44 |
| FS 单条件 | 派生程序明确请求 Dirty，两模型实际执行 | 37、44 | 48 |
| 组合条件 | FS 派生程序 + mtval 报告分支 | 37、44、48 | 无，254 个单元全部一致 |

最终比较由实际输出字节计算，见 [control-results.json](../../output/rtl-differential-r4/control-results.json)。这些控制支持两个具体机制，也反驳了“必须用一个共同 TLB 故障解释这三个签名值”的假设；它们没有排除 Rocket 在其他程序、配置或路径上的其他问题。

### 可复核的证据链

| 关系 | 依据 | 已建立的范围 |
| --- | --- | --- |
| mstatus 写输入 → FS/SD 差异 | ELF 精确指令、trace 输入/后续快照、CSRFile 与 Spike CSR 源码 | 当前路径及所选模型，真实 FS 控制支持 |
| FS/SD 状态 → sstatus/mstatus 读取 | 两条精确 CSR 指令的运行返回值 | 当前唯一关联的监视/提交事件 |
| CSR 读取 → x2 → signature store | 字节验证的连续块、Rocket 内部寄存器/基址样本、Spike 内存提交 | 诊断关联成立；不是独立 RTL 总线写认证 |
| U 模式 sepc 访问 → illegal trap → mtval 报告 | 精确故障编码、异常记录、handler 状态、两份实现源码 | 当前异常路径；单条件参考控制支持 |
| store 保存值 → 最终三个槽位 | ELF 符号、写出规则、签名值及运行 store 核对 | 当前运行观察一致；所有可能 writer 未认证 |
| 差异 → 规范违反 → 漏洞/攻击链 | 当前没有这类证据 | 未建立，不能画成已成立关系 |

## 第八章：是否足以进入正式硬件与跨层验证

| 所需事实 | 当前情况 |
| --- | --- |
| 精确程序和 RTL 选择、真实执行来源 | 已验证当前采集的文件/命令/driver/binary/输出绑定 |
| 目标 CSR 操作和存储数据 | 当前路径有来源约束的监视、提交及签名诊断关系 |
| 硬件 trigger 前态与完整时间窗口 | 没有规范化且完整认证的 trigger 定义与窗口 |
| 有依据的预期架构行为及违反 | 两个目标选项均有允许依据，没有建立违反 |
| 独立观测和完整状态更新/总线语义 | 当前 trace 含内部观测，但缺少相应正式独立观测契约 |
| 合格的 Reference/Variant | 本轮是参考选项和测试输入控制，不是已认证的硬件 Reference/Variant 对 |
| 客户固件含触发行为、外部控制 | 没有证明；本输入是硬件测试程序 |
| FPGA/硅片适用性 | 未建立，Verilator 结果限于所选 RTL 仿真 |

已有 HardwareBehaviorContract 能描述 typed 前态、trigger、deviation、observation 和 scope；但它不能用内部枚举或模型差异制造缺失的规范。冻结 Type-II Verifier 的具体后端仍是受控 Ibex MMIO，对当前 Rocket CSR 诊断不适用。

本轮不新增 HBC 或正式 Hardware Evidence Adapter。将来有客观需要时，最小接口应分别绑定 RTL revision/build、测试输入与 reset/load 配置、事件采样阶段、CSR 读写/异常语义、观测覆盖范围、实现选项 profile 和独立预期依据。配置允许的差异必须与规范违反分开；QEMU RuntimeEvidence 不能冒充 RTL 证据。完整缺口索引在 [provenance-gaps.json](../../output/rtl-differential-r4/provenance-gaps.json)。

## 第九章：工程能力、研究结论与保护范围

新增 [signature_analysis.py](../../experiments/rtl/rocket/signature_analysis.py) 复用现有 ElfImage 和 canonical static IR：输入精确 ELF、IR、签名写出范围和字节，输出地址/半部映射及有限基本块来源候选。内存布局和比较部分不依赖 ISA；RV64 CSR/store 解码留在此实验 adapter。

新增 [trace_analysis.py](../../experiments/rtl/rocket/trace_analysis.py) 接收实际 trace、精确 RTL/参考源码和 ELF，输出带字段来源与阶段的事件。唯一事件关联核心不包含 case_id、特定 word 或 sfence 规则；其他架构没有伪造后端。

新增 [analyze_rocket_differential.py](../../scripts/rtl/analyze_rocket_differential.py) 显式核对采集输入、保存快照、输出哈希、ELF 字节及第三方 checkout，生成地址、来源、normalized trace、alignment、first-divergence 和中文 signature 分析。它只读重放，不启动仿真器，不调用 LLM，不生成 HBC，也不调用 Type-II Verifier。丢失/矛盾输入会失败并保存 BLOCKED 诊断；缺少 coverage 或配置等价不会得到验证成功。

R4 的新增能力是把“有三行不同”缩小到“两个具体实现选择、相应 CSR 指令和保存位置，并有真实单条件实验支持”。各项研究状态及关联记录在 [root-cause-analysis.json](../../output/rtl-differential-r4/root-cause-analysis.json)。正式结论保持：

```text
architectural_differential = UNKNOWN
hardware_trigger = NOT_ESTABLISHED
hardware_deviation = NOT_ESTABLISHED
full_type2_chain = NOT_VERIFIED
```

原始 ZIP、RTL、ELF、SI、原始签名、R3 输出和 ProcessorFuzz expected 均受本轮前后 SHA 清单检查。没有改变 frozen core、QEMU 契约和 P1/N1/N2/U1，也没有提交用户 RTL、第三方完整源码或大型实验产物。

## 第十章：下一阶段最小建议

优先做可比较的实现选项 profile：明确 ISA/权限版本、FS/SD 与异常值报告、PMP/MMU/reset/中断设置，以及每个观测字段的采样阶段。保留原始差异，另行给出“允许选项差异”“未知配置差异”和“具有违反依据的差异”，不能静默屏蔽 CSR 差异来让比较通过。

这个阶段先以本轮负候选作回归，再选一个有独立预期行为依据的新硬件案例。只有出现规范或 reviewed hardware specification 不允许的、来源绑定的客观偏差，才设计对应 RTL Evidence Adapter 和 HBC。当前案例无需为了阶段名称而强行生成漏洞。

后续不应自动展开 ARM/PowerPC RTL、外部 UART、FPGA 或攻击链。本轮到可审查的差异解释和控制实验为止，等待人工 review。

## 附录：输入与复现命令

| 对象 | SHA256 |
| --- | --- |
| 用户 `Benchmarks.zip` | `987d8f81bd36567418afa9473864c54dba34532e979fcae35d99428c7bc97287` |
| 所选 `RocketTile_latest.v` | `508717f1a3af02f235633f20d274048e19bbb89d702d5d736cc7c1dc181ea188` |
| 原硬件包 `testis.zip` | `c0fe4e328be70238cfd7383fe3cc9b58267eeafc0795d1dbb8b4b074ad69df34` |
| 原测试 ELF | `649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86` |
| 原测试 HEX | `88ac462ff45e59eba9006792de9a0b7400a7e09e0fd38ceb2fb53189923177bf` |
| 原 RTL signature | `e14bcb08de2e6d62ee0368aa4d244375ca1e64178392b39f5b4866d25f577513` |
| 原 ISA signature | `3f9463d3d49f73942396edc67223269ab004e05042e58579c51805f797f80a37` |
| FS 控制 ELF | `527d1c49cad6d893e5fe16f891ba15c923278071ee0162377dc74c0eb8124822` |
| FS 控制 HEX | `7b29f51c11f8e494902f9f4f69eaebf9281f09f9458cd305ed6341e562b8ac0e` |
| 原 Spike binary | `401349af31a6239331c1cf88b61238243c72a275ca4a31e542bf87820b6242b8` |
| mtval 控制 Spike binary | `111580eb1d4287c3527069bfaed61dab49650c499cb54a952b6a8825d4fe4991` |

关键源码定位均针对以上实际固定文件：用户 RTL 的 CSR FS 输入/归一在 59798、59806、60817–60834 行；mstatus/sstatus 写选择在 59198/59219 行；illegal tval/cause 路径在 18994–19007、19227、61732–61748 行。修改版 Spike 的 FS/SD 处理在 `riscv/csrs.cc:353–378,456–473`，illegal mtval 兼容分支在 `riscv/processor.cc:921–927`。这些实际文件在 R3 checkout 和输入目录，完整 source SHA 在机器索引中。

只读分析命令如下；复现时选用一个新的 R4 子目录，已有目录会被拒绝以保护之前结果：

```bash
.venv/bin/python scripts/rtl/analyze_rocket_differential.py \
  --rtl-run output/rtl-rocket-feasibility/run-latest-009/rtl-run-manifest.json \
  --rtl-repeat output/rtl-rocket-feasibility/run-latest-010/rtl-run-manifest.json \
  --spike-run output/rtl-rocket-feasibility/spike-reference/run-summary.json \
  --elf output/rtl-rocket-feasibility/program/input.elf \
  --rtl output/rtl-rocket-feasibility/input/Benchmarks/Verilog/RocketTile_latest.v \
  --static-analysis samples/processorfuzz/real_case_001/expected/firmware-analysis.json \
  --upstream output/rtl-rocket-feasibility/upstream/ProcessorFuzz \
  --spike-source output/rtl-rocket-feasibility/upstream/spike-all-csr \
  --output output/rtl-differential-r4/analysis-new
```

新 RTL 运行的完整两阶段 `make` argv、构建参数、时间、退出状态及二进制 SHA 保存在 [rtl-run-manifest.json](../../output/rtl-differential-r4/fs-dirty-control/rtl-run-001/rtl-run-manifest.json)。参数为 `-DPRINTF_COND=0 -DSTOP_COND=0 -Wno-PINMISSING -Wno-fatal`、seed=0、max_cycles=6000、top=RocketTile。原始 build/simulation stdout/stderr、`rtl_0.log`、`rtl-signature.txt` 都在该目录 `raw/`。

三个参考控制的完整 argv、cwd、binary/ELF/dtc SHA、PATH、30 秒限制及实际输出分别在 [mtval invocation](../../output/rtl-differential-r4/spike-mtval-control/run-002/invocation.json)、[FS invocation](../../output/rtl-differential-r4/fs-dirty-spike-control/invocation.json) 和 [组合 invocation](../../output/rtl-differential-r4/combined-reference-control/invocation.json)。均使用 `--isa=RV64IMAFDC -m0x80000000:0x800000 -l --log-commits`，日志和签名目的路径及输入 ELF 显式指定，不凭 basename 绑定。

本机 ignored output 需要保留才能打开以上实验链接；它们不会随 Git 分发。本文本身包含完整解释，不要求验收者阅读 JSON 才能理解当前结论。最终回归、确定性重放与保护检查记录如下。


## 附录：最终验证与冻结保护

实际执行：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests scripts experiments
git diff --check
```

最终 pytest：**`643 passed in 65.94s (0:01:05)`**。新增 53 个 unit cases：signature/来源 23 个，trace 30 个；全部使用小型合成数据，普通 pytest 不调用大型 RTL/Spike 构建或网络。覆盖地址/字节序、错误 ELF/指令/布局、重复 PC、跨 hart、缺失事件、异常阶段、未知配置、签名相同或不同均不能推断漏洞，以及人类报告中的缺失条件说明。

pip check：`No broken requirements found.`；compileall exit 0，无输出；`git diff --check` exit 0，无输出。两个最终只读分析重放的 9 个产物逐字节一致，见 [deterministic-replay.json](../../output/rtl-differential-r4/deterministic-replay.json)。跨 hart 和来源检查修正前后的真实单 hart 数据也一致。

前后清单核对 34,101 个原文件/链接。R3 工作区的 33,724 个文件/链接完全相同，没有新增或删除；两个 ProcessorFuzz case 各 18 个文件、原 RTL 输入 1 个文件、独立项目固件目录 27 个文件均不变。所有既有 `src/` 文件保持不变，涵盖冻结 QEMU 科学契约。两份 ProcessorFuzz 原始 expected 没有重新生成。完整 before/after 记录在 [protection-check.json](../../output/rtl-differential-r4/audit/protection-check.json)。

六个冻结核心的 before/after SHA256 完全相同：

| 文件 | before = after SHA256 |
| --- | --- |
| `src/chipchain/firmware/mmio_grounding.py` | `6730a03a96ccf7d60ae2cbf5349836f6d71c4ba4098a35d16b848af11c8982d2` |
| `src/chipchain/firmware/mmio_execution_bridge.py` | `fdad3d8fcb23535098bac13367f9794ba200fd435893f1db0d4bea8dfed04fdb` |
| `src/chipchain/firmware/capability.py` | `9162e11f5b0f60ea288bad63ebc873d6531447df1154776d82eebd16849941a3` |
| `src/chipchain/firmware/mmio_capability.py` | `5e2a35811ce1f5153ebb5adf9140de644287db520f66e135b07b91689b70ec11` |
| `src/chipchain/hardware/behavior_contract.py` | `1038f67d10c4eeb97e88fba46cce5e0cc1f698e003342606464d360bdf6918c2` |
| `src/chipchain/cross_layer/type2_verifier.py` | `a8caeed8533826a4aa3a72bab537934a5755845899e54b3891ebee5434a89d2b` |

完整回归实际包含黄金结果重放断言，四个 ID 保持：

| Case | Golden ID |
| --- | --- |
| P1 | `type2-verification:9c7ef89582f89727fcacdb6b8bb7334ba79733c4182a6e7b341ba324e2fa6b82` |
| N1 | `type2-verification:7dc13746b7067f7ce4adf6cc11ba8eeeb01a3b2582b7a2456b005704772477e7` |
| N2 | `type2-reference-control:2d1ae9b25f06e6009e54b2081253ad93da1b3f8c1d91e942fd4ef6ed7dea28ab` |
| U1 | `type2-verification:21db55b0e4ddb2f545e57ebb731f09bd7bd1b6b465dbe4c63f4c49bd07dd526a` |

实际变更文件：

- `README.md`：增加 R4 研究入口及结论边界。
- `scripts/rtl/run_rocket_reproduction.py`：唯一采集器改动为显式研究输出根目录；默认 R3 路径和行为保留。
- `experiments/rtl/rocket/signature_analysis.py`：新增地址/字节序及有界来源分析。
- `experiments/rtl/rocket/trace_analysis.py`：新增 source-defined trace 解析和唯一事件关联。
- `scripts/rtl/analyze_rocket_differential.py`：新增只读来源核验与诊断产物生成。
- `tests/unit/test_rocket_signature_analysis.py`、`tests/unit/test_rocket_trace_analysis.py`：新增 53 个测试。
- 本文：完整中文研究报告；同步本机 ignored `output/rtl-differential-r4/report.md`。

`git diff --stat` 对已跟踪文件为 `2 files changed, 10 insertions(+), 2 deletions(-)`。此外有上述 6 个未跟踪新增文件，未暂存；Git 默认 diff stat 不计入它们。最终状态：

```text
 M README.md
 M scripts/rtl/run_rocket_reproduction.py
?? docs/research/rocket-rtl-differential-root-cause-v1.md
?? experiments/rtl/rocket/signature_analysis.py
?? experiments/rtl/rocket/trace_analysis.py
?? scripts/rtl/analyze_rocket_differential.py
?? tests/unit/test_rocket_signature_analysis.py
?? tests/unit/test_rocket_trace_analysis.py
```

HEAD 和全部 tag 不变。原始包/源码、新的大型构建、第三方复制源码和运行日志均在 ignored 路径；LLM 调用 0。没有执行 git add、commit、push 或 tag。本阶段停止于 root-cause review。

## 附录：本轮实际构建和运行的完整命令

下面直接从已记录的 argv 生成，不省略构建参数或输入/输出路径。环境和 watchdog 配置见相应 manifest。

派生程序 Rocket 构建：

```bash
make -f /home/qcx/ChipChainV3/output/rtl-differential-r4/fs-dirty-control/rtl-run-001/Makefile SIM=verilator VERILATOR_BIN_DIR=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/environment/verilator/install/bin TOPLEVEL_LANG=verilog TOPLEVEL=RocketTile VERILOG_SOURCES=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/input/Benchmarks/Verilog/RocketTile_latest.v MODULE=reproduction_test COCOTB_HDL_TIMEUNIT=1us COCOTB_HDL_TIMEPRECISION=1us BUILD_ARGS=-j2 'PLUSARGS=+DEBUG=0 +TRACE=/home/qcx/ChipChainV3/output/rtl-differential-r4/fs-dirty-control/rtl-run-001/raw/' PYTHON_BIN=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/environment/venv/bin/python PYTHONHOME=/usr sim_build/Vtop
```

派生程序 Rocket 仿真：

```bash
make -f /home/qcx/ChipChainV3/output/rtl-differential-r4/fs-dirty-control/rtl-run-001/Makefile SIM=verilator VERILATOR_BIN_DIR=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/environment/verilator/install/bin TOPLEVEL_LANG=verilog TOPLEVEL=RocketTile VERILOG_SOURCES=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/input/Benchmarks/Verilog/RocketTile_latest.v MODULE=reproduction_test COCOTB_HDL_TIMEUNIT=1us COCOTB_HDL_TIMEPRECISION=1us BUILD_ARGS=-j2 'PLUSARGS=+DEBUG=0 +TRACE=/home/qcx/ChipChainV3/output/rtl-differential-r4/fs-dirty-control/rtl-run-001/raw/' PYTHON_BIN=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/environment/venv/bin/python PYTHONHOME=/usr sim
```

原 ELF 的 mtval 单条件参考：

```bash
/home/qcx/ChipChainV3/output/rtl-differential-r4/spike-mtval-control/build/spike --isa=RV64IMAFDC -m0x80000000:0x800000 -l --log=/home/qcx/ChipChainV3/output/rtl-differential-r4/spike-mtval-control/run-002/isa-trace.log --log-commits +signature=/home/qcx/ChipChainV3/output/rtl-differential-r4/spike-mtval-control/run-002/isa-signature.txt /home/qcx/ChipChainV3/output/rtl-rocket-feasibility/spike-reference/original-trigger-test.elf
```

派生 ELF 的 FS 单条件参考：

```bash
/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/spike-build/spike --isa=RV64IMAFDC -m0x80000000:0x800000 -l --log=/home/qcx/ChipChainV3/output/rtl-differential-r4/fs-dirty-spike-control/isa-trace.log --log-commits +signature=/home/qcx/ChipChainV3/output/rtl-differential-r4/fs-dirty-spike-control/isa-signature.txt /home/qcx/ChipChainV3/output/rtl-differential-r4/fs-dirty-control/input.elf
```

派生 ELF 的组合参考：

```bash
/home/qcx/ChipChainV3/output/rtl-differential-r4/spike-mtval-control/build/spike --isa=RV64IMAFDC -m0x80000000:0x800000 -l --log=/home/qcx/ChipChainV3/output/rtl-differential-r4/combined-reference-control/isa-trace.log --log-commits +signature=/home/qcx/ChipChainV3/output/rtl-differential-r4/combined-reference-control/isa-signature.txt /home/qcx/ChipChainV3/output/rtl-differential-r4/fs-dirty-control/input.elf
```
