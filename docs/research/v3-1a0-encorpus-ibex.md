# V3-1A0 — EnCorpus Ibex Sample Reconnaissance

调查日期：2026-09-11。基线：`v3-r0-stable`。范围：外部 Ibex corpus 的只读勘察；本报告中的 ingestion 和 schema 均为建议，未实现 V3-1A1。

## A. EnCorpus Ibex Overview

这份本地 EnCorpus Ibex 数据是 **30 个 RTL 注入变异及其形式验证 witness 的集合**。它不是 30 个可直接运行的 ELF testcase。可以确定性提取变异差分、信号序列、寄存器差异和历史 cover 结果；尚不能从这些材料得到一个已独立复现、具有完整环境约束的通用硬件 trigger。

用户指定根目录为 `/home/qcx/ChipChainV3_res/hardware/encorpus/ibex`，实际数据多嵌套一层。下文 `B/` 一律表示：

```text
/home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/
```

全量文件清点：150 个普通文件，238,445,554 bytes；`du -sh` 为 228M。扩展名计数为 60 VCD、46 RTLIL、32 log、8 Tcl、4 Verilog。没有发现独立的 JSON/YAML manifest、README、汇编、ELF、BIN、hex 程序、ISA retirement trace 或 seed 文件。这个结论仅适用于本地快照。

生成日志记录 Yosys 0.37，git SHA `92cabdf7a`；验证日志记录 Jasper Apps 2022.09p001。注入日志日期为 2024-07-17，所检查 witness 日期为 2024-07-18。它们是历史工具记录，不是本轮运行的工具版本或验证结果。没有可据以确认上游发布版本、完整性或筛选准则的 manifest。

## B. Corpus Directory Structure

```text
B/
├── reference.v
├── cascade_receptor.v
├── processorfuzz_receptor.v       # 0 bytes
├── difuzzrtl_receptor.v           # 0 bytes
├── inject_driver.{tcl,log}
├── inject_multiplexer.{tcl,log}
├── prepare_driver.tcl
├── prepare_multiplexer.tcl
├── miter.tcl
├── instrument.tcl
├── export.tcl
├── export_difuzzrtl_reference.tcl
├── driver/<id>/                   # 15 个目录，每个恰好 5 个文件
│   ├── host_driver.rtlil
│   ├── reference_driver.rtlil
│   ├── proof.vcd
│   ├── proof_optimized.vcd
│   └── verify.log
└── multiplexer/
    ├── reference.rtlil            # 全部 multiplexer 样本共享
    └── <id>/                      # 15 个目录，每个恰好 4 个文件
        ├── host_amt.rtlil
        ├── proof.vcd
        ├── proof_optimized.vcd
        └── verify.log
```

样本目录 ID 全集：

| Family | IDs |
| --- | --- |
| driver | 39, 254, 293, 394, 526, 565, 619, 743, 779, 820, 858, 945, 963, 974, 1198 |
| multiplexer | 491, 527, 540, 732, 746, 763, 800, 807, 844, 904, 984, 1003, 1010, 1019, 1028 |

`file` 检查显示所抽查 RTLIL、VCD、log、Tcl、Verilog 均为 ASCII 文本；两个空 receptor 不能视作已有 ProcessorFuzz/DifuzzRTL 集成或复现结果。

| 材料 | 已核实语义 |
| --- | --- |
| `reference.v` | 694,463 bytes 的聚合 Verilog；注入脚本以它为输入，top 为 `cellift_ibex_top`。它不是原始 Ibex Git 源码树。 |
| `cascade_receptor.v` | 677,088 bytes 的聚合 Verilog，首行注明 morty-0.9.0 编译；没有配套运行结果。不能仅从文件名认定 fuzz reproduction。 |
| `inject_*.tcl` | `read_verilog -sv`、hierarchy、去掉 `always_comb` attribute、`proc -norom`，然后执行自定义 `inject_driver` / `inject` pass。路径为历史 `/scratch/...`，本轮未执行。 |
| `inject_*.log` | 综合与导出记录；含本地未保留的其他 ID，故不能把日志中的导出数量当作可用样本数。 |
| `prepare_driver.tcl` | 分别读本样本 host/reference RTLIL，flatten，写 `host.rtlil` / `reference.rtlil`。 |
| `prepare_multiplexer.tcl` | host 从本目录读取，golden 从 `../reference.rtlil` 读取；两者执行 `inject_map` 后 flatten。 |
| `miter.tcl` | host/reference 模块重命名后调用 `create_miter -observable gen_regfile_ff.register_file_i.rf_reg`。[脚本][miter] |
| `export.tcl` | 从 `../host.rtlil` 导出 `host.v`。 |
| `instrument.tcl` | 读 `../host.rtlil`，调用 `difuzzrtl_instrument`，导出 `host.v`；存在脚本不代表运行完成。 |
| `export_difuzzrtl_reference.tcl` | 对 `../reference.rtlil` 做同类 instrumentation/export。 |

未发现样本的中间 `host.rtlil`、flatten 后 `reference.rtlil`、`miter.v`、`host.v`、Jasper 工程目录、`v_miter.sva`、`sequence.rst`；这里的缺失不包括已列出的共享 `multiplexer/reference.rtlil`。

## C. Definition of One Bug Sample

一个 sample 是 **family + 数字目录 ID + 相应 golden/host 关系 + 保存的 witness/log**。推荐 importer identity 为 `encorpus:ibex:driver:743` 等；数字 ID 不能脱离 processor/family 使用，也不应按目录排列生成序号。

| 组成 | 当前快照 | 最小 ingestion 的必要性 |
| --- | --- | --- |
| driver host/reference pair | 每例都有；综合/注入生成物 | 判断 driver 变异时二者必需 |
| multiplexer host + 共享 reference | 每例 host 都有，共用一个 golden | 判断 AMT 变异时二者必需 |
| `proof.vcd` | 每例都有；形式工具导出的派生 witness | 提取输入、状态或 divergence 时必需 |
| `verify.log` | 每例都有；工具运行记录 | 声称历史 cover 命中时必需 |
| `proof_optimized.vcd` | 每例都有；后续保存的 trace | 最小 ingestion 可选；不能视作独立复验 |
| `reference.v`、Tcl、注入日志 | corpus 共享材料 | 原始源行解释、生成关系与 harness 意图的补充证据 |
| 独立 patch、bug JSON、汇编程序 | 未提供 | RTLIL 对比可导出 patch；不要编造缺失文件 |

“必需”是按所要支持的 claim 定义的 importer 契约建议，并非发现了 corpus 官方 required-files schema。缺失输入应降低可支持的结论并记录缺口，不应自动判为“无 bug”。

## D. Bug Ground Truth Representation

全量 host/reference 文本差分检查显示：15 个 driver 样本均增加 `attribute \buggy "buggy"` 并替换一个 `connect` 的驱动来源；15 个 multiplexer 样本均在目标 wire/cell 标记 `buggy`，并修改一个 `$amt` cell 的 `STATE_TABLE`。属性是 corpus 的注入标记；**实际 golden/host 差分**才是变异内容的直接依据。

driver 位置覆盖 mult/div、prefetch、IF、EX、WB、counter、register file、fetch FIFO、controller、core、CSR。multiplexer 覆盖 controller、mult/div、LSU。不能将所有 driver 变异统称为 stuck-at：有信号替换、位选择替换，也有常量替换。

RTLIL 提供 module、cell/wire、connect/parameter 和 `src` attribute。`src` 指向生成时的 `/scratch/mboelcskei/thesis/final/ibex/reference.v`，部分位置为 `0.0-0.0` 或复合 span。应保留原始 locator，并在有相应内容时映射至本地 `B/reference.v`；不得把生成文件行号改称原始 Ibex upstream `.sv` 行号。自定义注入/`inject_map` pass 的实现源码未提供，不能凭 `$amt` 名称推断完整状态表编码语义。

这些差分可用作带证据的 `HardwareFinding` anchor，也可作为将来评估 `RootLocationCandidate` 的 ground truth。它们不应由 LLM 重新猜测，也不能伪装成 Agent 自己推理出的 root candidate。当前 `RootLocationCandidate` 是候选契约，没有独立的 typed ground-truth location；本轮只记录这一点。

## E. Trigger Representation

存在的是 **formal witness VCD**：输入总线、握手、部分内部状态和 cover 信号。不存在可直接运行的 testcase 程序文件。VCD 使用 `1 ns` timescale，选定样本每 5 个时间单位保存一次时间点，时钟周期为 10 个单位。时间点数量、cover cycles、输入总线变化次数、译码窗口数、退休指令数必须分别记录。

### 具体序列：driver/743

在输入 `in_instr_rdata_i` 中，t=0 为 `0xffffffff`，t=20/30/40 分别给出以下三个字；host 的 `instr_rdata_alu_id_o` 在 t=30/40/50 出现同样三个字。对应 `instr_valid_id_q=1`、`instr_executing=1`，`instr_is_compressed_id_o=0`。输入和 ID-stage 信号共同支持“有效 ID 窗口中的三条 32-bit 指令编码”，不支持把每一个 VCD timestamp 算成一条指令。[输入与 ID 波形][d743-vcd-id]

| 首次输入时间 | 首次 ID 时间 / PC | 编码 | 确定性解码 | operands / immediate |
| --- | --- | --- | --- | --- |
| 20 | 30 / `0x0` | `0x00130e13` | `addi x28, x6, 1` | rd=28, rs1=6, signed imm=1 |
| 30 | 40 / `0x4` | `0x00001537` | `lui x10, 0x1` | rd=10，U immediate 的值为 `0x1000`；无 rs1/rs2 |
| 40 | 50 / `0x8` | `0x007e2503` | `lw x10, 7(x28)` | rd=10, rs1=28, signed imm=7，word load |

这是三个不同的有效指令窗口；最终窗口可保持/重复使用，完整退休序列和退休总数没有在本轮重建。`0xffffffff` 是初始总线值，不能冒充第四条已执行指令。位域检查使用 opcode、funct3、rd/rs1、I/U immediate；与本地 [decoder 中相应 opcode 的处理][decoder] 核对。ISA 描述可确定为该 Ibex 上的 RV32 指令子集，不据此猜测完整 ISA extension 配置。

三条编码无 branch/jump；所见 ID PC 为 0→4→8，随后 t=70 到 `0xc`。这不足以构成完整 CFG。x6 初始为 0，reference 在 t=50 将 x28 写成 1；host x28 保持 0。于是后续 `lw` 的基址状态不同，是可进一步做确定性依赖分析的具体材料；仅凭这一点不能认定完整传播机制已证明。

初始约束与状态：VCD t=0 已有 `in_rst_ni=1`，两个 packed GPR bank 为 0；host/reference `priv_lvl_q=3`（RISC-V M-mode 编码）保持不变，内部 6-bit `u_mstatus_csr.rdata_q=0x0c`。**该 6-bit 内部表示不是整个 architectural mstatus CSR 等于 0x0c。** 日志明确记录 non-resettable flops 初始化为 0，以及对两侧这个内部 mstatus 寄存器的 `abstract -init_value` 和 `assume -bound 1 ... ==6'b001100`。[reset/assumption 记录][d743-reset]

`sequence.rst` 缺失；日志警告透露部分 reset 输入，但不能恢复所有 reset 时序、SVA 环境约束、内存模型和输入合法性。witness 中 rvalid/gnt 并非完整软件执行环境。因此最小 parser 输出应称为“历史形式 witness 中的指令/状态观察”，不能导出未经说明的可运行汇编 reproducer。

## F. Observation / Propagation Representation

有三个需要保留的层次：变异锚点的局部差异、architectural register bank 的差异、formal harness 的 `c_propagated`。它们的首次出现时间可能不同。

`miter.tcl` 将 `gen_regfile_ff.register_file_i.rf_reg` 声明为 observable。VCD 同时存在：

- `miter.host_observables` / `miter.reference_observables`：1024 bits；
- `miter.i_miter.host_observables` / `miter.i_miter.reference_observables`：32 bits；
- 两侧 `gen_regfile_ff.register_file_i.rf_reg_q`：992 bits，range `[1023:32]`；
- `miter.i_miter.c_propagated`：1 bit。

**必须以完整 hierarchy 和位范围定位。** 不能按短名合并两个 `host_observables`，不能把 `[1023:32]` 的最低 word 当作 x0。本地 [寄存器文件源代码][regfile-source] 支持 xN 对应 packed bit `[32*N+31:32*N]`；x0 不在 `rf_reg_q` 中。

全 30 个 `proof.vcd` 都有 `c_propagated=1`，且 inner 32-bit host/reference observables 出现已知二进制值不等。这证明保存的 waveform 中存在此类 divergence。详细检查的三个样本还可直接定位具体 GPR 差异（H 节）。没有证据把这些结果概括为 PC、memory、CSR、exception 全部得到差分验证。

inner 32-bit observable 与整个 GPR bank 的选择关系未完整恢复，不能只凭 inner 的同名信号认定它固定就是 x10。H 节的 x10/x28 数值来自明确 range 的 `rf_reg_q`，独立于这个未知 selector。

`Observation != Causality`：t=50 的 x28 mismatch 与 t=70 的 cover 可以共同支持一个传播分析，但时间先后本身不证明唯一原因。`Trigger != Observable propagation`：driver/820 的 debug 状态先分歧，直到 t=580 才出现本例 GPR mismatch。

## G. Verification Semantics

全量日志都报告对 `miter.i_miter.c_propagated` 的 cover 命中，SUMMARY 中是 1 cover、0 assertions。cycles 分布：6 cycles ×3，7 ×15，8 ×11，59 ×1。**covered 是给定 formal setup 下的存在性 witness，不是所有输入正确性的证明，也不是本轮独立验证。**

| 要区分的 claim | 当前材料支持的范围 |
| --- | --- |
| known bug exists | host/golden 的实际变异差分及注入标记支持“存在注入变异”；不能据此宣称存在自然硅片漏洞或安全影响。 |
| bug trigger found | 历史 cover 命中和相应保存 VCD 支持“工具找到该属性的 witness”。 |
| trigger reaches bug | 需要被标记节点/相关逻辑的取值、使能和局部差异；三个样本提供不同程度佐证，见 H。不能由 sample ID 或 cover 名字单独推出。 |
| bug propagates | waveform 中内部状态/输出差异支持观察到传播现象；完整因果路径及属性公式仍需缺失的 harness。 |
| architectural mismatch observed | 三个详细样本的 GPR bank 解包值不同，且 Tcl 指定 GPR observable；可称“该保存形式 trace 中的 architectural register mismatch”。不能升级为真实硬件或软件 replay 通过。 |

每份日志还都有 `ERROR (EVS053): No trace satisfying these configurations exists for any max_length.`，发生在已报 covered、保存 trace 后的后续可视化/重绘流程；最后进程状态为 0。应**分别记录 cover 成功、后续 trace 操作错误、进程 exit 状态**。不能只看 exit 0 忽略错误，也不能用后续错误抹掉已有 cover 与 VCD 事实。[743 日志][d743-cover]、[820 日志][d820-cover]、[1019 日志][m1019-cover]

日志警告 trace 只包含目标 COI（cone of influence），并有 synthesis/simulation `parallel_case` 警告。三例 `host_output`/`reference_output` 端口还分别出现 actual width 5/1/3 与 formal width 32 不同的警告；这是 output 端口警告，不能与前述两个层次的 `observables` 混为一谈。[示例宽度警告][d743-width]

30 对 VCD 中 8 对字节完全相同，其余 22 对仅首行 `$date` 不同；全部 30 对去掉首行后完全相同。所以 `proof_optimized.vcd` 不提供第二次独立 witness 或成功最小化的证据。

本地未发现 simulation differential run、fuzz reproduction、ProcessorFuzz campaign 的独立结果。本轮没有执行 formal、simulation、综合或 fuzz。

## H. Three Representative Samples

选择依据是全量 RTLIL 差分的 module/变异类型及全部日志的 cover 长度，不是随机抽取前三个目录。

### H1. driver/743 — register-file 比较输入常量替换

module 为 `cellift_ibex_register_file_ff` 的参数化实例。目标是 `$auto$inject_driver.cc:83:expose_cells$64337`：golden 驱动为 `\waddr_a_i`，host 为 `5'00100`。该 wire 是 x28 写入比较器的 A 输入，B 连接 `5'11100`，对应源 `reference.v:8077`。因此 **4 与 28 比较恒假，影响 x28 写使能译码**；不是把整个 CPU 的 write address 都重定向到 x4。[host 修改][d743-host]、[golden][d743-golden]、[比较器][d743-eq]

输入序列见 E。t=40 的写回地址为 28、数据为 1，t=50 reference x28=1 而 host x28=0。t=60 两侧 x10 都为 `0x1000`，t=70 host x10 保持 `0x1000`、reference x10=0，此时 `c_propagated` 置 1。局部写入效果、GPR 分歧与 cover 的时间并不相同。日志报告 8 cycles / 46.19 s；VCD 有 17 个时间点，范围 0–80。

| Evidence | Source artifact / location | Observation | Epistemic status |
| --- | --- | --- | --- |
| D743-A | host RTLIL line 3438；golden line 3437；host cell line 2045 | driver 来源被换为常量；比较器 B=28。原始文本为 observed；“x28 比较恒假”为 derived。 | observed / derived 分开建记录 |
| D743-B | `proof.vcd`：rf_reg_q 声明 lines 1630/2110；reference t=50 更新 line 7987，host 从 line 4752 延续全 0；写回地址 line 7490 | x28 host=0 / reference=1；不是仅有注入标签。 | derived（按声明位范围解包） |
| D743-C | `proof.vcd`：t=70 reference bank line 8598，host bank 最近值 line 8263；inner/cover lines 8437–8438；`verify.log:371` | x10 host=`0x1000` / reference=0；cover 命中记录。两个 artifact 用两条 EvidenceRef。 | derived mismatch；observed 日志/标志 |

### H2. driver/820 — controller debug feedback 信号替换

module 为 `cellift_ibex_controller`，`WritebackStage=1`、`BranchPredictor=0`。目标 `$auto$inject_driver.cc:83:expose_cells$66325` 从 `\debug_mode_q` 换成 `\ebrk_insn`，接到 `$procmux$48201` 的 B 输入。cell 的 `src` 为聚合 `reference.v:1265` 及复合 span，不能定位成唯一原始 `.sv` 行。[host][d820-host]、[golden][d820-golden]、[cell/source span][d820-cell]

该 witness 长 59 cover cycles，119 个 VCD 时间点，0–590；输入 instruction word 有 59 个变化值，rvalid/gnt 反复变化，不能当作 59 条已执行指令。`in_debug_req_i` 在 t=20 首次变为 1；两侧 debug_mode_q 在 t=50 变成 1，host 在 t=100 回到 0，reference 继续为 1。reference 的 `ebrk_insn` 保持 0；不能因变异信号名含 ebrk 就宣称触发程序执行了 EBREAK。

t=580 reference x10=`0x378`，host x10=0，inner observable 同时不等、cover 置 1。日志报告 59 cycles / 1.11 s。未恢复完整指令控制流、debug 转换因果链或最小 trigger。

| Evidence | Source artifact / location | Observation | Epistemic status |
| --- | --- | --- | --- |
| D820-A | host RTLIL line 96504；golden line 96503；host cell line 90610 | mux B 驱动 debug_mode_q→ebrk_insn。 | derived（两份文本比较） |
| D820-B | `proof.vcd`：debug-mode 定义 lines 1888/2367；host t=100 line 9637，reference 最近赋值 t=50 line 7578 | debug state 0 vs 1，早于 architectural register divergence。不能当作已经证明 bug-site 的唯一激活条件。 | observed waveform；derived comparison |
| D820-C | `proof.vcd`：reference bank t=580 line 27328，host bank 初值 line 4721；cover line 27126；`verify.log:518` | x10 0 vs `0x378`；历史 cover=covered。 | derived GPR difference；observed formal result |

### H3. multiplexer/1019 — LSU AMT state-table 变异

module 为 `cellift_ibex_load_store_unit`，`src` module span 为聚合 `reference.v:6452.1-6777.10`。目标 `$amt$$procmux$47171_Y$49652` 的 `STATE_TABLE` 为 320-character payload；两个 `buggy` attributes 指向此 wire/cell。host line 75329 与共享 golden line 75327 的表不同；输出 `$procmux$47171_Y` 接到 `ls_fsm_ns`。这是 next-state 表变异，不应在没有自定义 pass 规范时杜撰“翻转第几号 ISA 条件”。[host table][m1019-host]、[golden table][mux-golden]、[next-state 连接][m1019-ns]

VCD 在 t=20/30 输入 `0x8432e513` / `0x7d452523`，t=30/40 出现在有效 ID 窗口：可解码为 `ori x10,x5,-1981` 与 `sw x20,1994(x10)`。t=40 两侧 `lsu_req_i=1`，reference `ls_fsm_ns=1` 而 host 为 0；t=50 reference `ls_fsm_cs=1`、host 为 0。同一时刻两侧 x10=`0xfffff843`，t=60 host x10 变为 0、reference 保持不变，cover 置 1。

这提供局部 LSU 差异和后续 GPR 差异；并不证明外部 memory 内容已被成功写入，尤其输入 gnt/rvalid 的合法性受未提供的环境约束影响。日志报告 7 cycles / 4.96 s；VCD 有 15 个时间点，0–70。

| Evidence | Source artifact / location | Observation | Epistemic status |
| --- | --- | --- | --- |
| M1019-A | host RTLIL lines 75326–75332；共享 reference line 75327；host line 78732 | `buggy` 标记、AMT 表变动和 next-state 连接。 | observed 文本；derived difference |
| M1019-B | `proof.vcd`：LSU ns 定义 lines 2219/2697；reference t=40 line 7989，host 初值 line 5472；reference cs t=50 line 8297 | next-state 0 vs 1，然后 current-state 0 vs 1；是局部状态分歧。 | derived comparison |
| M1019-C | `proof.vcd`：host bank t=60 line 8404，reference 最近赋值 t=50 line 8272；cover line 8370；`verify.log:366` | x10 0 vs `0xfffff843`，随后记录 cover 已命中。 | derived GPR difference；observed formal result |

代表性 artifact SHA-256（只读计算，未复制文件）：

| Artifact | SHA-256 |
| --- | --- |
| `driver/743/host_driver.rtlil` | `7dcbdecb5021559e0fe5a0a1a1bcdc26aa752aed7dd60b75eacfdfd448234c6f` |
| `driver/743/reference_driver.rtlil` | `c28e6586880f3df441c15053b7fc952b3481930ccf72d5c587d6809dc7097b49` |
| `driver/743/proof.vcd` | `f6be33b33c557cc1f8d849da580b7a0ce7d7646a3eadbff7d0d3c06a159e66e8` |
| `driver/820/host_driver.rtlil` | `83020baca73527fbbae21f71b6b5dae56a5f5961fa8e714142f51efd589b4e3f` |
| `driver/820/reference_driver.rtlil` | `761b44919c4654d85f2b39391b42eb52bc77a6549445f8c41dece243d267c362` |
| `driver/820/proof.vcd` | `eb365fb5b72305e09cc205e5b8de6dcf04f12cc3bcbcecfed96b3ebd7e00d0e7` |
| `multiplexer/1019/host_amt.rtlil` | `23c10184ab3a63f74f6dcf234cb9ea7a4e1017eec3a97a6c0b7ace91649c6dbf` |
| `multiplexer/reference.rtlil` | `f82ca9fd4bdbce4f16c8a1078db6e4641e3c952f9df78bce6da64b4a63393050` |
| `multiplexer/1019/proof.vcd` | `8671374cce44bb41c9d5284f1ad4720642c3233549d13b03b61af5f18e920363` |
| `reference.v` | `5dd48aac4eb82d93f1884de2e1f0963cd3785173c36d591a98ad902865675197` |

## I. Mapping to EvidenceRef

结论：**partially sufficient**。现有 [EvidenceRef / EvidenceLocation](../../src/chipchain/domain/evidence.py) 足以引用文件行、寄存器名和已有状态标签；不充分支持可机器查询的 RTL hierarchy、VCD 时间/位范围和验证 claim 分类。

现有字段可这样使用：raw artifact 摘录用 `source_type=artifact`；确定性解包、对比或解码用 `deterministic_analyzer`，并填 analyzer ID。每个 `artifact_id` 对应一个原始文件，保留现有 SHA/size fingerprint 和外部路径。行号是所引用 artifact 的实际行号，不是把 VCD 行号换成 RTL 行号。

```json
{
  "evidence_id": "d743-reference-x28-t50",
  "source_type": "deterministic_analyzer",
  "artifact_id": "d743-proof",
  "analyzer": "proposed-encorpus-ibex-reader",
  "location": {"line": 7987, "register": "x28"},
  "summary": "At VCD time 50 ns, reference rf_reg_q[927:896] decodes to x28=1; declaration line 2110 establishes range [1023:32].",
  "epistemic_status": "derived"
}
```

这是契约映射示例，不是本轮生成的 runtime result。host 比较值应另建 EvidenceRef，指向其最后一次赋值行，并在 observation 中关联两侧证据。VCD 持续值不一定在比较时刻重新打印，必须 carry-forward；时间定位同时保留定义行、赋值行、比较时刻。不能只用“附近一行”的文本搜索推断当前状态。

不应把 RTL module 填入 `function`，也不应把 VCD 时间填入 `address` 或 `instruction_index`。`register` 可准确表示已映射的 x28，无法替代任意 RTL signal path。最小建议是增加可选的 signal/time/range locator，或先在 N 节的 typed observation payload 保留这些信息；无需现在全面重构 EvidenceLocation。

Epistemic status 描述认识依据，不描述 claim 类别。“变异存在”“witness 到达变异”“architectural divergence”都可能是 observed/derived；现有 enum 无法把三者自动区分。不要简单把来自形式工具的所有证据设为 `verified`。

## J. Mapping to Processor Behavior IR

driver/743 的实际链条可以无 LLM 地做如下有限映射：

```text
proof.vcd:7008，host instr_rdata_alu_id_o = 0x00130e13
  + 同时刻 instr_valid_id_q=1、instr_executing=1、PC=0
  → 位域解码：ADDI，rd=x28，rs1=x6，imm=1
  → ProcessorBehavior(kind=instruction, architecture=riscv, origin=hardware,
       epistemic_status=derived,
       attributes={encoding: "0x00130e13", mnemonic: "addi", rd: 28,
         rs1: 6, immediate: 1, pc: 0, observation_stage: "id",
         time_value: 30, time_unit: "ns"})

proof.vcd:7490 / 7491，writeback address=28 / data=1
  + rf_reg_q host/reference t=50 解包结果 0 / 1
  → register_access：观察写入相关信号及其结果差异
  → 使用独立 evidence 保留 host/reference 和各自时间定位
```

`observation_stage="id"` 明确表示译码阶段观察，退休状态保持未判定。

`ProcessorBehavior.attributes` 的 scalar-map 可承载上述小型字段；behavior_id 可以按 sample、signal/stage、time 稳定生成。mutation anchor 和 formal cover 不是 processor 行为，不要硬塞为 `instruction`。IR 是有限语义投影，原始 observations 必须保留。

| BehaviorKind | 本地材料支持程度 / 边界 |
| --- | --- |
| instruction | 可以确定性解码已知且有效的 instruction word；不能用所有 bus word 充当执行序列。 |
| register_access | 写回信号、packed register bank 可映射读写关联与差异；仅看值变化不足以完整重建所有访问。 |
| csr_access | 有 CSR 层级信号；需访问使能/地址/操作配套后才能说发生 CSR access，不能由 `u_mstatus_csr` 名称直接推出访问。 |
| memory_access | `lw`/`sw` 编码与 LSU 请求可表达 load/store 请求；完成状态、返回值及外部内存更新需要相应握手/模型。 |
| mmio_access | 没有可用 memory map 支持把某地址归为 MMIO；保持未判定。 |
| privilege | priv_lvl_q 可表述采样到的模式；不能泛化成权限提升。 |
| control_transfer | 需要 PC/有效阶段、branch/jump/exception 信号；顺序 PC 增长本身不是 branch evidence。 |
| exception / interrupt | 有相关 RTL/input 名称；需要 event/acceptance 与状态证据，不能把 irq 输入出现等价为异常进入。 |
| data_dependency | x28 定义、后续 lw 读取 x28 支持局部寄存器依赖候选；需处理重复执行/kill/版本才能形成动态依赖。 |
| control_dependency | 未重建 CFG/控制谓词；本阶段不填充因果边。 |

## K. Mapping to HardwareAnalysisReport

| 现有类型 / 字段 | 可确定性填充 | Agent reasoning / 后续 verification |
| --- | --- | --- |
| `HardwareFinding` | finding_id、差分/不匹配的 summary、evidence、已建立 behavior IDs、observed/derived status | “这是安全缺陷”“可利用”的解释不能由 corpus label 自动得出。 |
| `HardwareTriggerHypothesis` | 可以引用已有 finding/behavior/evidence；**直接给出的 witness 应先保留为事实观察** | 最小/充分/必要触发条件、对其他输入的泛化才是 hypothesis；不要强行塞入 verified witness。 |
| `TriggerConstraint` | 可表达描述性的 `rs1 == 28` 等采样/编码条件 | 当前没有时间顺序、solver、necessity/sufficiency 语义；采样值不是已经证明的触发约束。 |
| `AbnormalState` | 描述特定 trace 时刻 host/reference 状态差异，附 evidence / finding IDs | 没有结构化 expected/actual/time 字段；完整原因、影响需要进一步分析。 |
| `HardwareAnalysisReport` | case_id、事实 findings、有限 IR refs、unresolved_questions；可让 trigger_hypotheses 保持空 | 不需要 LLM 才能保留事实；当前 Agent 路径不是本轮研究的执行入口。 |

`HardwareTriggerHypothesis` 和 `RootLocationCandidate` 使用 CandidateStatus，只允许 inferred/hypothesized/refuted/unknown；禁止为了容纳历史 formal result 而放宽为 verified。已知变异应是确定性 observation / evaluation anchor，不是需要“提升置信度”的候选。

现有 `CaseBundle.ground_truth_label` 是 cross-layer label，不是硬件 bug oracle。保持当前 ground-truth isolation：将 oracle/mutation 标签与盲评分析输入区分；不能把它们藏到 observation.summary 后绕过保护。当前 hardware_context 会发送传入的 observations，而不会自动识别 summary 中的 oracle 信息。V3-1A1 的只读 importer 不接任何模型；以后接入 Agent 前，必须明确选择可见 observation 视图。这里没有改变 CaseBundle、context 或任何 workflow。

## L. Existing Schema Gaps

### Blocking

对“先读取文件并给出带行号的确定性摘要”这一最小 V3-1A1 目标，**没有必须先重构 domain 才能开始的 blocker**。

但若要求无损、机器可查询的正式 hardware observation contract，以下信息目前只有自由文本位置，属于该更强目标的 contract blocker：

1. 缺少 claim kind / evidence role，无法结构化区分 mutation fact、局部 activation 佐证与 architectural mismatch；EpistemicStatus 不能代替它。
2. 缺少 signal hierarchy、timescale、timestamp、bit range、两侧四态值、formal property/method/result、assumption 依赖与结果阶段的 typed payload。把全部内容塞 summary 会丢掉自动校验能力。

完整 verified trigger/reproducer 的 blocker 首先是**数据缺失**：SVA、reset sequence、实际生成 miter 和自定义 pass 语义；增加 schema 字段不会恢复这些事实。源码到 waveform 节点的映射也未完整恢复。

### Non-blocking

- CaseBundle/ArtifactRef 已支持外部路径、format、SHA/size，不需新 Batch domain 或固定 samples 根目录。
- instruction/register_access 的小型 scalar attributes 已可表达第一批 IR；不需新增 BehaviorKind。
- 正式 SourceSpan、RTL module/cell locator 可先留在 adapter-local payload，待用例稳定再决定是否扩展 EvidenceLocation。
- 没有必要先做全套 architectural state、CFG、因果图、完整 RISC-V decoder、ARM/PowerPC decoder、root-location ground truth domain。
- 当前 Agent context 有 128 item / 64,000 character 边界；全 VCD 不应直接进入上下文。先保留外部 artifact，抽取少量相关事件。它不是本轮无需调用 Agent 的阻塞项。

## M. EnCorpus-specific vs RISC-V-specific vs Architecture-neutral

| 层次 | 本例内容 | 复用于 ARM / PowerPC 的边界 |
| --- | --- | --- |
| EnCorpus-specific | family/ID 布局、host/golden 命名、buggy attribute、`$amt`/inject pass、`c_propagated`、Jasper log 解析、reference 路径关系 | 换 corpus 时需独立 adapter；Rocket/BOOM 也未在本轮验证兼容性。 |
| Ibex implementation-specific | `cellift_*` module、rf_reg_q packing、pipeline 信号别名、内部 6-bit mstatus、具体 debug/LSU encoding | 不能当作全部 RISC-V CPU 都通用，更不能用于 ARM/PowerPC。 |
| RISC-V-specific | RV32 指令位域/长度、x0–x31、CSR 地址/含义、privilege 编码、load/store 操作 | 必须替换 ISA decoder/register/privilege 映射。 |
| Architecture-neutral | artifact identity/fingerprint、证据、四态 waveform 值、差分、时间/来源、指令/寄存器访问/异常/控制转移等 IR 类别 | 可以复用；但具体 signal 到统一概念的绑定仍需目标适配器。 |

只简单观察到 EnCorpus 父目录还有 rocket、boom 目录；没有深入其样本、编写或提出已验证通用 parser。

## N. Proposed HardwareObservation Contract

建议在现有 `DeterministicObservation` 的 id/summary/evidence/behaviors/status 外，先设计**一个可选、带 discriminator 的 details payload**，只有三种已被本地数据支持的记录形状。可先定义在 EnCorpus adapter 内，不必立即修改所有 domain model：

| details.kind | 最小字段建议 | 实际依据 |
| --- | --- | --- |
| `mutation_anchor` | family、module、node、变动字段 connect/STATE_TABLE、golden/host 原始文本值、各自 EvidenceRef IDs、source span（可缺失） | driver 单 connect 变异、AMT 表变异 |
| `waveform_observation` | signal path、declared width/range、time_value/time_unit、raw four-state value；可选 peer signal/value、semantic_stage（input/id/local_state/register_state）、register/encoding 映射、比较结论 | 32/992/1024-bit 同名信号、input/ID word、debug/LSU/GPR 差异 |
| `formal_result` | tool/version、property、property_kind=cover、result=covered、reported_cycles、phase、assumption/reset artifact refs 或 missing 标志；后续 error 单独记录 | covered 与 EVS053 同时存在的日志 |

跨形状保留 evidence role，例如 `analysis_input` / `evaluation_oracle`，但它只是可见性分类，**不是自动授权把 oracle 发给模型**。mutation 标签默认进入评估视图。需要记录的是“证据支持哪个 claim、依据和限制是什么”，不是再设计一个无依据的 verified_trigger 布尔值。

waveform 中的 `x/z` 必须保留；unknown bits 不按 0 比较。timestamp 属于该 trace，自定义 clock-cycle index 需要显式 clock/edge 规则。给 `formal_result` 的 status 仍可用 observed（观测到工具如此报告）；给解码/比较用 derived。不存在的记录不是 refuted，而是 unknown/缺证据。

首个低风险 importer 可以用现有 `HardwareObservations` 输出带证据的摘要，将上述信息在内部保真；一旦要序列化并查询这些细节，再给共享 contract 增加可选 typed details。没有必要现在增加 instruction/register/exception 等十几种 observation class。

## O. Proposed V3-1A1 Deterministic Ingestion Pipeline

**第一阶段只支持 driver family，先以 driver/743 验收。** 它的 mutation 是稳定的一个 connect 差分，witness 短，有可核对的寄存器行为，避开尚未核实的 AMT 语义。

第一个 production reader 的精确主要输入：

1. `B/driver/743/host_driver.rtlil`；
2. `B/driver/743/reference_driver.rtlil`；
3. `B/driver/743/proof.vcd`；
4. `B/driver/743/verify.log`。

共享 `B/reference.v` 与 `B/miter.tcl` 作为显式绑定的 source/layout/observable provenance；先使用本报告已核对的有限 Ibex layout adapter，不执行 Tcl、不实现通用 Verilog parser。`proof_optimized.vcd` 可选，仅用于一致性检查；不重复计算 witness。暂不把 inject.log、receptor.v、multiplexer AMT 或全 corpus 都塞进首个 parser。

```text
caller 显式指定外部 driver sample 路径及共享参考
  ↓
枚举允许的 artifacts → ArtifactRef + 现有 fingerprint helper
  ↓
只读 adapter：
  RTLIL 单 connect 差分 / module + src anchor
  verify.log property 结果、阶段、错误、缺失约束
  VCD 声明 + carry-forward values + 指定相关时间窗口
  ↓
HardwareObservations（facts + source evidence + unresolved_questions）
  ├─ evaluation 视图：已知 mutation anchors，保留作 oracle
  └─ analysis 视图：允许使用的 witness/state facts
         ↓
有限、确定性的 RV32 word 解码 / GPR 映射
         ↓
ProcessorBehaviorIR
         ↓
HardwareAnalysisReport 的事实输入
（hypotheses 可空；不调用模型，不声称自动得到完整 causality）
```

最小生产代码变更建议：新增一个局部 `EnCorpusIbexDriverAnalyzer` adapter，实现现有 `HardwareAnalyzer.analyze(...) -> HardwareObservations` 协议；内部使用小型 reader 和有限 IR projector。不改 CaseBundle/AnalysisRun/provenance/workflow routing，不在本阶段自动接入 workflow。若要持久化 typed observations，再单独添加 N 节所述可选 details；这是契约增强，非启动四文件读取的前提。

未来验收应使用手写极小 synthetic RTLIL/VCD/log fixtures，检查 malformed/missing input、unknown 值、同名不同 scope、packed range、carry-forward、covered 后 error、artifact/evidence/IR 一致性；真实 corpus 验收通过显式本地路径运行，不提交真实样本。必要时对输入大小/解析资源设技术边界，但不把约 10 个 Case 的 operational expectation 重新变成 domain 数量上限。

所有解析 read-only、无隐式输出。显式导出时使用调用方选择的路径，推荐 `output/<case_id>/<run_id>/`；domain 不依赖该目录。不复制真实 corpus 到 samples/examples/tests。此节仅为下一阶段建议，本轮没有实现。

## P. Files Added / Modified

仅新增本报告：`docs/research/v3-1a0-encorpus-ibex.md`。未修改 README、生产代码、测试、依赖、workspace 目录策略或任何外部原始样本。

另在 `/tmp/chipchain_ibex_inspect.py` 使用了一次性只读 VCD 检查脚本（不在 repository 中），用于 scope/width/时间值读取和人工核对；没有把探索代码作为 production parser 提交。

## Q. Commands Executed

实际使用的命令类型和代表性调用如下。`B` 为本文的路径缩写，实际读取时使用外部绝对路径。

```bash
git status --short --untracked-files=all
find /home/qcx/ChipChainV3_res/hardware/encorpus/ibex -maxdepth 3 -type d
du -sh /home/qcx/ChipChainV3_res/hardware/encorpus/ibex
find /home/qcx/ChipChainV3_res/hardware/encorpus -maxdepth 2 -type f
find /home/qcx/ChipChainV3_res/hardware/encorpus/ibex -maxdepth 2 -type f -printf '%P %s bytes\n'
rg --files /home/qcx/ChipChainV3_res/hardware/encorpus/ibex
file /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/* /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/39/*
.venv/bin/python /tmp/chipchain_ibex_inspect.py driver/743 driver/820 multiplexer/1019
PATH="$PWD/.venv/bin:$PATH" pytest -q
PATH="$PWD/.venv/bin:$PATH" python -m pip check
git diff --check
git status --short --untracked-files=all
```

此外，用 `cat`/`head`/`tail`/`sed`/`rg -n` 阅读 Tcl、RTL、log、VCD 声明和 ChipChain 契约；使用 `.venv/bin/python` inline 标准库脚本完成全量文件/字节清点、30 对 RTLIL 差分、module/buggy attribute 定位、log cover/error 汇总、30 对 VCD 的首行以外比较、已知值 mismatch 检查、指令位域提取、SHA-256 计算及文档检查。没有执行 corpus 中的任何 Tcl、Verilog 或其他实验脚本。

环境处理：系统 PATH 的 `python` 不存在，一次调用失败后改用已有 `.venv`；对不存在的 `src/chipchain/cases/*.py` 和尚未创建的 `docs/research` 的探索性 `rg` 返回找不到路径，随后使用实际文件路径。没有安装或更新包，没有联网获取材料。

## R. Existing Test Results

使用现有 `.venv`（Python 3.12.13）：

```text
pytest -q
130 passed in 1.30s

python -m pip check
No broken requirements found.
```

本轮没有生产代码变更，未新增测试。`git diff --check` 通过；新增报告尚未跟踪，另对其进行完整空白检查，避免仅靠默认 diff 忽略 untracked 文件。

## S. Risks / Unknowns

1. 缺失 `v_miter.sva`、`sequence.rst`、生成 `miter.v` 及自定义 pass 实现；无法完整解释属性公式、约束、位宽转换或重新证明可复现性。
2. 保存 trace 是 COI 视图，有后续 EVS053、端口位宽和 synthesis/simulation 警告。应保存异常与正向结果各自的证据，不能统一归为 verified/failed。
3. 未确认 corpus upstream version、筛选准则和自然 bug 身份；目录非连续，不代表全体注入候选，也不证明 30 个互不等价的设计缺陷。
4. instruction bus word 不等于 retired instruction；未重建完整内存模型、全部执行/退休事件、控制流、异常、动态依赖或最小 trigger。
5. 当前三个 GPR divergence 是历史形式 witness 中的观察；未得到真实硅片、仿真 replay、外部 memory mismatch 或安全 exploit 结论。
6. ground truth facts 若直接进入现有 observations context，会泄露盲评答案；未来接入时需明确输入视图，本轮完全未调用模型。
7. 本报告 artifact 路径与行号绑定当前本地快照；选定文件指纹辅助核对。没有将历史 `/scratch` 或 `/data` 路径视作本机可访问文件。

## T. Git Status

调查开始时工作树干净。完成时：

```text
?? docs/research/v3-1a0-encorpus-ibex.md
```

没有执行 `git add`、`git commit`、`git push`、`git tag`。没有创建 `.env`、安装 `langchain-deepseek`、调用 DeepSeek 或其他真实模型。停在 V3-1A0。

## 最后八个问题

1. **V3-1A1 先读什么？** driver/743 的 `host_driver.rtlil`、`reference_driver.rtlil`、`proof.vcd`、`verify.log`；共享 `reference.v`/`miter.tcl` 提供显式绑定依据。先不解 AMT、不执行实验。
2. **trigger 可以无 LLM 映射为 ProcessorBehavior 吗？** 可以映射其中有证据的指令/寄存器/请求行为，不能把整个 formal environment 或完整触发因果语义压成 IR，也不能把总线字当退休程序。
3. **什么证明 bug exists？** host/golden 的真实 RTLIL 变异差分、buggy 标记和源/生成关系；严格说证明注入变异存在，非天然安全漏洞。
4. **什么证明被触发？** 保存 witness 中与变异相关的有效操作和局部效果（例如 x28 写入被抑制、LSU next-state 分歧），加上历史 cover 记录；通用“已验证 trigger”仍受缺失 harness 限制。
5. **什么证明 architectural observable effect？** 正确按位范围解包的 GPR host/reference 值差异，加上 miter 的 register observable 配置；三个具体样本均有此证据，但只适用于保存的形式 trace。
6. **schema 不能区分哪项？** 三项事实都能写成带 evidence 的文字，但缺少类型化的 claim/验证范围，不能机器区分“变异存在 / 局部触发 / architectural propagation”。EpistemicStatus 与候选类型不能充当这一分类。
7. **最小 production change？** 新增使用现有 ArtifactRef/HardwareAnalyzer/HardwareObservations 的 driver 只读 adapter 和有限 IR 投影；typed details 是随后保真查询所需的小型契约增强建议，不需重构现有 domain 或 workflow。
8. **需要真实 LLM 吗？** 不需要。本阶段与下一步确定性 ingestion 都不依赖模型；真实 Agent LLM 接入仍留给 V3-1B。

[miter]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/miter.tcl:5
[decoder]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/reference.v:3826
[regfile-source]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/reference.v:8064
[d743-host]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743/host_driver.rtlil:3438
[d743-golden]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743/reference_driver.rtlil:3437
[d743-eq]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743/host_driver.rtlil:2045
[d743-vcd-id]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743/proof.vcd:7008
[d743-reset]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743/verify.log:226
[d743-width]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743/verify.log:214
[d743-cover]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743/verify.log:371
[d820-host]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/820/host_driver.rtlil:96504
[d820-golden]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/820/reference_driver.rtlil:96503
[d820-cell]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/820/host_driver.rtlil:90609
[d820-cover]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/820/verify.log:518
[m1019-host]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/multiplexer/1019/host_amt.rtlil:75329
[mux-golden]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/multiplexer/reference.rtlil:75327
[m1019-ns]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/multiplexer/1019/host_amt.rtlil:78732
[m1019-cover]: /home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/multiplexer/1019/verify.log:366
