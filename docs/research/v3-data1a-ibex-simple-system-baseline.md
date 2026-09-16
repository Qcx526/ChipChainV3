# V3-DATA1A-R1 — Baseline Recovery

## R1 Summary

**DATA1A 已完成真实 paired firmware–RTL baseline，XL0 `eligible`，reasons=[]。**
这是带有 `build_metadata_compatibility_shim` 的基线：同一个 Ibex commit、small config、
同树原始 hello firmware 和两次一致的 Verilator RTL execution；不是 pristine metadata tree。
没有 HDL / firmware 修改、mutation、HardwareTriggerCondition 或 CrossLayerTriggerCandidate。
没有 DeepSeek 或 Security Agent 调用，没有进入 DATA1B。

[成功快照](data1/ibex-simple-system-baseline.json)保存身份、命令、工具版本、全部配置值与产物 hash。
[Attempt 1 blocked record](data1/ibex-simple-system-blocked.json)保留为 `attempt_1 / blocked`，
追加 R1 resolution provenance。本文后半完整保留第一次失败报告与当时 68 项回答；其中未运行、
未配对和 NO-GO 描述属于 **Attempt 1 历史状态**，不代表当前 R1 结果。

## Root Cause and PR #2492

本地重新核实 `python-requirements.txt` 指定 FuseSoC 2.4.3；这个版本不是错误选型。
`util/ibex_config.py::Config.known_fields` 包含 BaseIsa，原 Simple System `.core` 却不暴露它。
顶层 `ibex_simple_system.sv` 消费 `BASE_ISA` 宏，其默认是 BaseIsaRV32IorCHERIoT，
而 small 要求 BaseIsaRV32I。此前参数解析错误与后续宏名不一致是两个分别需要检查的问题。

[上游 PR #2492](https://github.com/lowRISC/ibex/pull/2492)：`[simple_system] Add BaseIsa parameter`。
本轮 API 核实 state=`open`、merged=`false`；未合并。

```text
head SHA: f51bc6c2c92a1cde5e5237786200c3239ce13f42
base SHA: 34b0705760ef3dfa00e99637432473d2be8f22f3
patch SHA256: dafb0b3afd98e9707afa7dfc52339018f1c9c5d9231d6a49d900b9314038a7de
```

精确 head 的 patch URL：
[commit patch](https://github.com/lowRISC/ibex/commit/f51bc6c2c92a1cde5e5237786200c3239ce13f42.patch)。
API 元数据和 patch 原文分别归档为 `provenance/pr2492.json`、`provenance/pr2492.patch`。
PR 没有被视为已经证明语义正确。

## Disposable Worktree and PR Semantic Audit

原始 checkout `/home/qcx/ChipChainV3_res/platforms/ibex` 始终保持 clean，
HEAD=`405c6d1d8220a18b2f9196141167a5875422dee4`。

```bash
git -C /home/qcx/ChipChainV3_res/platforms/ibex worktree add --detach /home/qcx/ChipChainV3_res/worktrees/ibex-simple-system-data1a-r1 405c6d1d8220a18b2f9196141167a5875422dee4
git -C /home/qcx/ChipChainV3_res/worktrees/ibex-simple-system-data1a-r1 apply /home/qcx/ChipChainV3_res/cache/data1a-r1/pr2492.patch
```

先只应用 PR、执行 `--setup`，退出码 0，EDAM、`.vc`、Makefile 生成。
`.vc` 中实际是 `-DBaseIsa=ibex_pkg::BaseIsaRV32I`。
随后使用 Verilator 4.210 `-E` 对实际 file list/options 预处理：
`pr-preprocessed.sv` 顶层参数仍是 BaseIsaRV32IorCHERIoT。
所以 PR 的结果是 `parser_fix_only / semantic_config_not_proven`，没有用它原样构建模拟器。

第一次预处理因官方预编译包的安装布局在外部目录重定位而找不到 launcher，退出 127；
仅在解包的用户空间工具目录建立两个相对 symlink，重试预处理退出 0。
精确命令、失败与修正记录均保留，没有系统安装或工具源码修改。

## Compatibility Shim and Effective Source Identity

只修改 worktree 的 `examples/simple_system/ibex_simple_system.core`，
总 diff 是 PR 的 7 行加以下 3 行，仅作用于 sim target 的 Verilator options：

```yaml
# DATA1A-R1: fixed small configuration, Verilator metadata only.
# The wrapper consumes BASE_ISA, not the PR's BaseIsa macro.
- '-DBASE_ISA=ibex_pkg::BaseIsaRV32I'
```

该机制先由已安装 Edalize 的实际实现与生成 `.vc`/config.mk 核实：vlogdefine 输出 `-D`，
vlogparam 输出 `-G`，Verilator options 原样传递。随后由工具预处理、XML 和生成 C++ 验证，
不是靠命令行 token 推测。这个 shim 固定用于 **small / Verilator**；不宣称支持其他配置或后端。

```text
label = build_metadata_compatibility_shim
base commit = 405c6d1d8220a18b2f9196141167a5875422dee4
shim diff SHA256 = 2e69217b12c796389c2962ecf83973a08d69bf0fb11c0b78348ee2d81cd03dd7
```

SHA 对 `git diff --binary` 的精确 UTF-8 bytes 计算。完整 diff 嵌入成功快照，
原始文件为 `provenance/compatibility-shim.patch`。
有效 source identity 是 **base commit + shim diff SHA256**，不能写成 pristine 405c6d1。
`*.sv`、`*.v`、firmware C/ASM、link.ld、ibex_configs.yaml、ibex_config.py 均未修改。
现有 UNOPTFLAT waiver 已在冻结源码中核实，未添加任何 waiver。

## 19-Field Configuration Equivalence

**small_config_equivalence = PASS**。在 firmware/simulator build 之前，
Verilator `--xml-only` 成功生成 elaborated XML，没有 fatal warning。
顶层 `ibex_simple_system` 的 19 个 parameter 都有确定常量，逐项与 YAML 及
`ibex_pkg.sv` 中 enum 数值核对。没有依靠 wrapper default 猜测；所有字段均显式传递，
BaseIsa 通过额外的正确命名宏传入。

| 字段 | small expected | transport | elaborated XML constant | 状态 |
| --- | --- | --- | --- | --- |
| `BaseIsa` | `ibex_pkg::BaseIsaRV32I` | Verilator-only vlogdefine BASE_ISA (BaseIsa PR macro unused) | `32'sh0` | PASS |
| `RV32E` | `0` | vlogparam | `1'h0` | PASS |
| `RV32M` | `ibex_pkg::RV32MFast` | vlogdefine | `32'sh2` | PASS |
| `RV32B` | `ibex_pkg::RV32BNone` | vlogdefine | `32'sh0` | PASS |
| `RV32ZC` | `ibex_pkg::RV32Zca` | vlogdefine | `32'sh0` | PASS |
| `RegFile` | `ibex_pkg::RegFileFF` | vlogdefine | `32'sh0` | PASS |
| `BranchTargetALU` | `0` | vlogparam | `1'h0` | PASS |
| `WritebackStage` | `0` | vlogparam | `1'h0` | PASS |
| `ICache` | `0` | vlogparam | `1'h0` | PASS |
| `ICacheECC` | `0` | vlogparam | `1'h0` | PASS |
| `ICacheScramble` | `0` | vlogparam | `1'h0` | PASS |
| `BranchPredictor` | `0` | vlogparam | `1'h0` | PASS |
| `DbgTriggerEn` | `0` | vlogparam | `1'h0` | PASS |
| `SecureIbex` | `0` | vlogparam | `1'h0` | PASS |
| `PMPEnable` | `0` | vlogparam | `1'h0` | PASS |
| `PMPGranularity` | `0` | vlogparam | `32'sh0` | PASS |
| `PMPNumRegions` | `4` | vlogparam | `32'h4` | PASS |
| `MHPMCounterNum` | `0` | vlogparam | `32'sh0` | PASS |
| `MHPMCounterWidth` | `40` | vlogparam | `32'h28` | PASS |

```text
canonical small SHA256: db8a13294c8c468a40e402893b6ecfbc80cc641027c420a6fc17983cc8e9289c
elaborated XML SHA256: 7112f4377ef02a207bbdce6791b44b83b81ee70e10f86502d86985e4c5254ce6
```

证据：`provenance/small-equivalence.json`、`provenance/shim-elaborated.xml`、
`provenance/shim-preprocess.stdout.log` 和 EDAM/VC/config.mk。
后续成功 build 的 `Vibex_simple_system__Trace__Slow.cpp` 第 72 行声明顶层 BaseIsa trace slot 1736，
第 9059 行写入 `fullIData(oldp+1736,(0U),32)`；enum table 区分 RV32I=0 和 dual=1。
这提供与最终模拟器编译产物直接对应的额外证据。

## Tools and Environment Recovery

既有 host GCC 11.4.0、Make 4.3、4 CPU、约 7.8 GiB 可用 RAM 足以完成本次构建。
工具全部位于 `/home/qcx/ChipChainV3_res/`，没有 sudo、系统安装、全局 PATH 或项目 `.venv` 包修改。

| 工具 | 实际版本 / 安装 |
| --- | --- |
| FuseSoC | 2.4.3，`envs/ibex-simple-system` |
| Edalize | 0.6.8 |
| Python | 3.12.13 |
| Verilator | 4.210，冻结 CI 指定的预编译包，`toolchains/verilator-ci/v4.210` |
| RISC-V compiler | GCC 10.2.0，crosstool-NG 1.24.0.498_5075e1f，官方 release 20220210-1 |
| libelf | 0.186-1ubuntu0.1，download 两个 Ubuntu 包，再用 dpkg-deb -x 解包到 `toolchains/libelf-0.186` |
| 新增 Python 依赖 | packaging==26.3，仅专用环境；用于冻结的 pre_build 检查工具 |

工具 URL、archive SHA/size、解包位置、symlink、依赖 freeze 和过程修正见成功快照的
`tool_installation` / `archives`；原始 `pip-freeze.txt` 与下载日志保留。
Verilator 设置 `VERILATOR_ROOT=<prefix>/share/verilator`；同目录 bin 下两个相对 symlink
分别指向 `../../../bin/verilator` 和 `../../../bin/verilator_bin`。
外部 libelf 通过 `CPLUS_INCLUDE_PATH`、`LIBRARY_PATH`、`LD_LIBRARY_PATH` 提供，未修改 firmware CFLAGS。

## Recovered Firmware Build and ELF Identity

cwd 为一次性 worktree。实际命令：

```bash
make -C examples/sw/simple_system/hello_test hello_test.elf hello_test.bin hello_test.dis
```

构建通过，无 Zicsr error。采用源码预期的官方 legacy toolchain，保持
`-march=rv32imc -mabi=ilp32` 及原 common.mk flags，不修改 ARCH/CFLAGS/源码。
生成 ELF、BIN、disassembly；未生成 VMEM，未安装可选 srecord。

```text
compiler: riscv32-unknown-elf-gcc 10.2.0
ELF size: 15856 bytes
ELF SHA256: 44ac617845e3a99e36b419c028349f86c7bb64d2b33cc6d9711623281a61625c
ELF: ELF32 / RISC-V / little endian / EXEC
entry: 0x100080
attributes: rv32i2p0_m2p0_c2p0
ABI: ilp32, soft-float
```

source SHA 包括 hello C、Makefile、common C/header、common.mk、link.ld、crt0.S。
`file`、readelf header/sections/program headers/attributes、objdump disassembly 和命令记录均保留。
ELF 含 debug 信息；本轮验证执行可复现，不证明换目录/主机构建 ELF 字节一致。

## Recovered Simulator Build and Identity

配置等价 PASS、ELF build PASS 之后才执行：

```bash
/home/qcx/ChipChainV3_res/envs/ibex-simple-system/bin/fusesoc --config /home/qcx/ChipChainV3_res/cache/data1a-r1/fusesoc.conf --monochrome --cores-root=. run --target=sim --build lowrisc:ibex:ibex_simple_system --BaseIsa=ibex_pkg::BaseIsaRV32I --RV32E=0 --RV32M=ibex_pkg::RV32MFast --RV32B=ibex_pkg::RV32BNone --RV32ZC=ibex_pkg::RV32Zca --RegFile=ibex_pkg::RegFileFF --BranchTargetALU=0 --WritebackStage=0 --ICache=0 --ICacheECC=0 --ICacheScramble=0 --BranchPredictor=0 --DbgTriggerEn=0 --SecureIbex=0 --PMPEnable=0 --PMPGranularity=0 --PMPNumRegions=4 --MHPMCounterNum=0 --MHPMCounterWidth=40
```

FuseSoC 的 build 路径也执行 setup；最终生成文件保持相同参数语义。
使用 `MAKEFLAGS=-j2` 限制主机编译并行度，不改变仿真模型或实验运行方式。
pre_build 工具检查通过；没有新增 fatal warning 或 source patch。
完整 argv、cwd、受控环境、stdout/stderr 见 `provenance/simulator-build.*`。

```text
simulator: Vibex_simple_system
size: 8003040 bytes
SHA256: d30710114df80a253d57e95f70bf8a3c9772a6293d0cea8b91a82cc7fe0fdeb7
Verilator: 4.210
FuseSoC: 2.4.3
```

## Run 1 / Run 2 / Reproducibility

先写入 `experiment-freeze.json` 固定源码/config/shim/ELF/simulator/tool versions/run command，
随后分别在 `output/paired/ibex-simple-system/data1a-r1/run1/` 和 `run2/` 执行相同命令：

```bash
/home/qcx/ChipChainV3_res/worktrees/ibex-simple-system-data1a-r1/build/lowrisc_ibex_ibex_simple_system_0/sim-verilator/Vibex_simple_system -t --meminit=ram,/home/qcx/ChipChainV3_res/worktrees/ibex-simple-system-data1a-r1/examples/sw/simple_system/hello_test/hello_test.elf
```

运行之间没有源码、工具、config 变更。两次均启用上游 `-t`，没有第三次调参重跑。
每次 exit=0，stdout 明确记录 software request 与 Verilog `$finish`；最后 trace 记录
`0x20008 <- 1` 的 halt store。ASCII 输出均为：

```text
Hello simple system
DEADBEEF
BAADF00D
Tick!
Tock!
Tick!
Tock!
Tick!
```

| 比较项 | Run 1 | Run 2 | 分类 |
| --- | --- | --- | --- |
| Executed cycles | 13268 | 13268 | deterministic_equal |
| Trace records | 1183 | 1183 | deterministic_equal，完整 trace bytes 相同 |
| Firmware ASCII output | 68 字节 | 68 字节 | deterministic_equal |
| pcount Cycles | 477 | 477 | deterministic_equal |
| pcount Instructions Retired | 261 | 261 | deterministic_equal |
| stderr | 空 | 空 | deterministic_equal |
| FST | 546032 字节 | 546032 字节 | 本轮 bytes 相同，不要求跨运行环境必然相同 |
| PID / wallclock / simulation speed | 各自 host 值 | 各自 host 值 | expected_nondeterministic |

忽略 stdout 中仅这三类 host 字段后全文相同；unexpected_difference=[]。
trace SHA256=`21748f4370611590e76926ed47a659dbf94ad78d208b1c3ed8db70c09f4ec4b9`。
所有文件的两次 hash 与规范化范围见 `reproducibility.json`。
性能计数器仅覆盖 Hello 输出窗口：firmware 随后关闭 pcount 再进入 timer loop，
所以 261 不等于全程的 1183 条 trace，也不等于全程 13268 个周期。

## Trace Semantics and Register/MMIO Observability

本轮 trace 来自 `rvfi_valid && trace_log_enable` 门控。冻结 core 在 WritebackStage=0 时，
输出 stage 在 ID/EX 完成后的周期有效，源码明确标注 retirement。
因此这是 RTL 仿真的 RVFI architectural retirement/event 记录，强于 EnCorpus 的编码观察。
日志还可包含 trap 标记，不能对任意 trap entry 直接声称指令正常提交；
本轮 trap 标记 0 条、interrupt 标记 6 条。

实际字段包括 simulation time、cycle、PC、16/32-bit encoding、mnemonic、
按需出现的 source register read、destination/writeback、memory PA/load/store。
日志没有独立 rvfi_valid/rvfi_order 列，retirement 来源于门控和生产端源码语义。
没有复用或修改 A3 typed relation。

寄存器是逐事件读值/写回，**不是 full GPR snapshot**。打印 `x0=0` 也不代表 x0 可变。
Memory 观察来自 `trace_core_00000000.log` 的 PA/load/store，ASCII 与 halt 另有程序输出和终止记录支持：

| MMIO | 地址 | reads | writes | Run 1 trace 行号范围（非连续集合） |
| --- | --- | --- | --- | --- |
| ascii_out | `0x00020000` | 0 | 68 | 142–1088 |
| halt | `0x00020008` | 0 | 1 | 1184–1184 |
| mtime | `0x00030000` | 7 | 0 | 418–1123 |
| mtimeh | `0x00030004` | 14 | 0 | 417–1124 |
| mtimecmp | `0x00030008` | 0 | 14 | 429–1136 |
| mtimecmph | `0x0003000c` | 0 | 7 | 430–1135 |

详细实例、精确首末行见 `trace-audit.json`。这些是仿真的 architectural memory 观察；
没有额外声称已独立验证每条总线 handshake，也没有创建 MMIO relation。
FST 已保存，额外总线信号可供后续检查；本轮结论不依赖尚未审计的波形信号。

## Platform Identity and XL0 Pair

```text
platform identity: ibex-simple-system:6e7ba1a16803af4942efe44ebcd65d853efd3c45d5bccf086a22bab6a20bdec2
firmware case: ibex-simple-system:hello-test:firmware
hardware case: ibex-simple-system:small:hardware
pair manifest SHA256: dbc7c3d0e50dc4d5c1d9aa51c8e9eddbe21cb4eb25a428403534517a84460a36
pair descriptor SHA256: df274238ae167a9c1483f64a108a28d9b1b7cf9e8e3f98d6e65d55a87088d953
eligibility: eligible
reasons: []
```

平台 canonical inputs 包含 upstream URL、base commit/tree、shim SHA、small config SHA、top、
firmware source/build/ELF SHA 和官方 toolchain archive/version；不含 timestamp、UUID 或本地路径。
内容 hash 可受构建产物变化影响；这里没有宣称不同机器/目录产出相同 binary。

两侧 TargetDescriptor 为 `riscv / rv32imc / 32 / little`，processor_id=`ibex-simple-system:small`；
Firmware 额外 firmware_id=`hello_test`。ISA 依据编译命令、ELF attributes、XML small 参数和成功执行，
不是仅依据 repo 共址。CaseBundle 保持 unlabeled，没有漏洞 ground truth。

六条 content-addressed pairing evidence 分别覆盖同 revision+shim、同 top、同 small、
同 firmware build、同 ELF 实际加载到同 simulator、同冻结执行 family。
`CrossLayerPairManifest` 使用 `explicit_manifest`，两侧 identity 精确相等、case IDs 精确绑定。
使用冻结 `build_cross_layer_pair()` 及 canonical serializer/SHA，round-trip 校验通过。
两份字节相同 trace 使用不同 run reference artifact IDs，content SHA 保持相同；没有复制样本建立跨层目录。

## Preservation, Validation and DATA1B Readiness

原始 Ibex clean；worktree diff 仅 `.core` 的 10 行。
256 个既有历史文件和 Attempt 1 的 12 个归档文件 SHA 全部不变。
reviewed、DOC-1、XL0、Hardware B2、Firmware B3/A5、DATA0 均未修改。
仅更新 README 当前阶段摘要、本文和 blocked record，新增成功快照。
全部 ELF/BIN/disassembly/simulator/trace/FST、build 与 cache 位于 ignored output 或外部资源目录。
没有将一次性实验编排脚本加入产品代码，因此没有新增 helper/tests；使用冻结合同做了显式 round-trip/hash 校验。

本轮验证：

```text
pytest -q: 1064 passed, 27 skipped in 27.54s
python -m pip check: No broken requirements found.
python -m compileall -q src tests: PASS
git diff --check: PASS
```

使用项目 `.venv/bin/python`；专用工具环境 pip check 也通过。

最终 Git status：

```text
 M README.md
?? docs/research/data1/ibex-simple-system-baseline.json
?? docs/research/data1/ibex-simple-system-blocked.json
?? docs/research/v3-data1a-ibex-simple-system-baseline.md
```

未执行 git add、commit、push、tag。

**DATA1B readiness: GO（仅表示 clean baseline 前置条件具备，待本轮人工审核/冻结）。**
本轮没有进入 DATA1B。未来 controlled mutation 仍须单独授权与固定实验设计。
最大的后续工作是定义 golden/mutant 对比与 typed trigger evidence；本轮结果不证明任何硬件或跨层漏洞。

## R1 Explicit Questions (1–43)

| # | 问题 | 回答 |
| --- | --- | --- |
| 1 | FuseSoC 2.4.3 错误？ | 否，符合冻结 requirements。 |
| 2 | 准确源不一致？ | config 工具输出 BaseIsa，Simple System core 未暴露；wrapper 又消费 BASE_ISA 大写宏。 |
| 3 | PR #2492？ | [simple_system] Add BaseIsa parameter，解析接口修复。 |
| 4 | 已合并？ | 否，API state=open / merged=false。 |
| 5 | 评估 head？ | f51bc6c2c92a1cde5e5237786200c3239ce13f42 |
| 6 | PR 修复解析？ | 是，setup exit 0，EDAM/VC 生成。 |
| 7 | PR 单独证明正确 BaseIsa？ | 否，预处理顶层仍为 dual=1。 |
| 8 | 最终 BaseIsa 确定性证据？ | XML top 常量 0、预处理 RV32I；最终 C++ trace slot 1736 的参数值 0U。 |
| 9 | 19 字段审计？ | 是，全部字段有 XML effective value 和 transport。 |
| 10 | equivalence PASS？ | 是。 |
| 11 | 修改 HDL？ | NO。 |
| 12 | 修改 firmware source？ | NO。 |
| 13 | 修改 ibex_configs.yaml？ | NO。 |
| 14 | 修改 ibex_config.py？ | NO。 |
| 15 | 使用 metadata shim？ | 是，build_metadata_compatibility_shim。 |
| 16 | 修改文件？ | 仅 disposable worktree 的 examples/simple_system/ibex_simple_system.core。 |
| 17 | shim diff SHA？ | 2e69217b12c796389c2962ecf83973a08d69bf0fb11c0b78348ee2d81cd03dd7 |
| 18 | original checkout clean？ | 是，前后 clean / exact 405c6d1。 |
| 19 | ELF build？ | PASS。 |
| 20 | compiler/toolchain？ | official lowRISC 20220210-1，riscv32-unknown-elf-gcc 10.2.0。 |
| 21 | ELF SHA？ | 44ac617845e3a99e36b419c028349f86c7bb64d2b33cc6d9711623281a61625c |
| 22 | simulator build？ | PASS。 |
| 23 | simulator SHA？ | d30710114df80a253d57e95f70bf8a3c9772a6293d0cea8b91a82cc7fe0fdeb7 |
| 24 | run1？ | PASS，exit 0 / software halt。 |
| 25 | run2？ | PASS，exit 0 / software halt。 |
| 26 | architectural reproducibility？ | PASS，输出/trace/counters 相同，无 unexpected difference。 |
| 27 | trace collected？ | 两次各 1183 条。 |
| 28 | trace semantics？ | RVFI-valid architectural retirement/event observations；异常标记需区分，非 full GPR state。 |
| 29 | real platform identity？ | 是，见 Platform Identity。 |
| 30 | 包含 shim？ | 是，canonical platform inputs 与 binding evidence 均包含 shim SHA。 |
| 31 | pair manifest？ | 是，explicit_manifest。 |
| 32 | pair descriptor？ | 是，通过冻结 builder。 |
| 33 | XL0 eligible？ | 是，reasons=[]。 |
| 34 | HardwareTriggerCondition？ | NO。 |
| 35 | CrossLayerTriggerCandidate？ | NO。 |
| 36 | mutation？ | NO。 |
| 37 | DATA1A complete？ | YES，with build_metadata_compatibility_shim。 |
| 38 | DATA1B GO/NO-GO？ | GO：baseline 前置条件具备，待审核/冻结；未进入 DATA1B。 |
| 39 | next blocker？ | 没有剩余 DATA1A 技术阻塞；不宣称其他配置/后端兼容。 |
| 40 | pytest？ | 1064 passed, 27 skipped in 27.54s |
| 41 | pip check？ | PASS，项目与专用环境均无 broken requirements。 |
| 42 | compileall？ | PASS。 |
| 43 | diff check？ | PASS。 |

---

# Attempt 1 — Historical Blocked Report

## Executive Summary

**DATA1A PARTIAL / BLOCKED。尚未建立 real paired firmware–RTL baseline。**

ChipChain 与 Ibex 的冻结身份检查通过。唯一一次官方 simulator setup/build 尝试，使用
仓库指定的 FuseSoC 2.4.3 和由真实 `small` 配置生成的全部参数，在 backend 参数解析时失败：

```text
exit code: 2
fusesoc run lowrisc_ibex_ibex_simple_system_0: error: unrecognized arguments: --BaseIsa=ibex_pkg::BaseIsaRV32I
```

这不是 Verilator 编译报错：Verilator 尚未执行。`small` 声明 BaseIsa，配置工具会输出它，
但 Simple System `.core` 的 sim target 没有暴露它。RTL 的 `BASE_ISA` 默认值还是
`ibex_pkg::BaseIsaRV32IorCHERIoT`，与要求的 `ibex_pkg::BaseIsaRV32I` 不同。
删除这个参数不能视为保持 exact `small`。没有尝试删参数、额外宏覆盖、改 `.core` 或 RTL。

任务第 20、53 节明确要求：若冻结的官方构建路径需要 source patch，则 STOP。
本轮在复现这个阻塞后停止平台工作；仅完成失败归档、文档与 ChipChain 回归验证。
没有 firmware build、simulator binary、execution、eligible pair 或触发候选。

小型可审阅记录为 [blocked record](data1/ibex-simple-system-blocked.json)。
没有创建成功专用的 `ibex-simple-system-baseline.json` 或 `paired-baseline/v1` manifest。
忽略目录中的原始记录位于
`output/paired/ibex-simple-system/data1a-setup-blocked-405c6d1/`。

## Frozen Inputs

| 输入 | 本地重新核对的身份 |
| --- | --- |
| ChipChain tag | `v3-data0-stable` |
| ChipChain HEAD / tag dereference | `f3ec8d840d72559474a03dca2e13f7058dd192e4` |
| ChipChain tree | `37d81214433f9cd38386a7e80402e5b56cb4f278` |
| ChipChain before | `git status`: clean |
| Ibex origin | `https://github.com/lowRISC/ibex.git` |
| Ibex HEAD | `405c6d1d8220a18b2f9196141167a5875422dee4` |
| Ibex tree | `3e54f2a830939234932ec153cdde6c1a5b7d13b9` |
| Ibex branch | `master` |
| Ibex shallow | `false` |
| Ibex before / after | clean / clean；仅忽略的 `build/` 产品 |

资源根为 `/home/qcx/ChipChainV3_res`，Ibex 在 `platforms/ibex`。
没有 pull、checkout、reset、clean 或 submodule update。
以下 SHA256 本轮从本地重算，不沿用 DATA0 缓存：

| 文件（相对 Ibex 根） | SHA256 |
| --- | --- |
| `ibex_configs.yaml` | `75b4e848face7fa31e1bc227aaa7a83cb2a8f45aa1fc0bd4fe2e2800f6caac28` |
| `examples/simple_system/README.md` | `1bc428e57c4480d5f8c750d63484dc7ce24079ee0df160c952310f5537b32ab6` |
| `examples/simple_system/ibex_simple_system.core` | `f7c8aeacb12587354f38391f27f92785f18863963c4ec9fb08000dda63f9e501` |
| `examples/simple_system/ibex_simple_system_core.core` | `f4313230a1a4107ffec641d3b9d5f3259c808045a87b55d81c954fa807cda755` |
| `examples/simple_system/rtl/ibex_simple_system.sv` | `684ef6b8bc3acab88ed9abbe6a003fd0b82ddd537ed72461bb19079582c76d66` |
| `examples/sw/simple_system/hello_test/hello_test.c` | `fbea61084e54dc66eb2c7d6a05d3d46a37fc8af5bff69e902089943bd3b464df` |
| `examples/sw/simple_system/hello_test/Makefile` | `149963538f4bfb41770e9b53cdf6af838393125d8cd89df59d3524e7b27e7ff8` |
| `examples/sw/simple_system/common/common.mk` | `30d263fd5f96fcafd58b94603e85db5fac55e547736db4f265287aa9714679cd` |
| `examples/sw/simple_system/common/link.ld` | `318b9ed40edb2cd0e329e5617f58cacad59d8137f12e550260be29c33f824068` |
| `examples/sw/simple_system/common/crt0.S` | `b0117f2e94ab0f65eb54806c67c727cd54142713a15422d5bc81e8431d853b9f` |
| `rtl/ibex_tracer.sv` | `6241602443ec15517914fc3231e9c860229aea52dc571b5a94769a0510963925` |
| `util/ibex_config.py` | `640bb21187d84f48eed8ae8e2f7709e607b873e492ac5176176708b7312f09cd` |
| `python-requirements.txt` | `51097dd014d9a8e3804e392fe868c962802776908bdd22959eeca849517d301d` |
| `ci/vars.env` | `db5863954c71b591ef31e6897a5f9f6582ef90c6638fe8592709bc570105baa6` |
| `ibex_top_tracing.core` | `796927d172b4a5a0e2c6db80b7b95ad76540311faaaa900c885249167ce37dfc` |

## Environment

检查发生在安装前；完整 stdout/stderr/exit code 见忽略目录的 `environment-before.json`。

| 工具 / 资源 | 结果 |
| --- | --- |
| 系统 Python | 3.10.12 |
| 专用环境 Python | 3.12.13，使用既有 ChipChain Python 创建独立 venv |
| CMake | 3.22.1 |
| GNU Make | 4.3 |
| host GCC / G++ | GCC 11.4.0；g++ 存在 |
| Verilator / FuseSoC | 安装前 PATH 均未找到 |
| riscv32-unknown-elf-gcc / objdump | 未找到 |
| srec_cat | 未找到；仅影响可选 VMEM 路径 |
| libelf | 有系统 `libelf.so.1`；无 `libelf.h`、`gelf.h`、pkg-config libelf |
| libelf1 包 | 0.186-1ubuntu0.1；libelf-dev 未安装 |
| zlib | 系统 header 和 shared library 存在 |
| 构建辅助工具 | bison、flex、autoconf、g++、perl 存在；help2man 未找到 |
| 工作卷空间 | 73 GiB 可用 |
| RAM / swap | RAM 11 GiB，总可用约 7.8 GiB；swap 2 GiB |
| CPU | `nproc` = 4 |

额外文件扫描找到既有容器 overlay 内的 Verilator 文件；它们没有被选择、运行或安装。
不能把这个发现视为宿主已有可用的兼容 Verilator。
没有读取 `.env`，没有导出完整环境或保存凭证。仅记录受控的工具信息与 PATH/XDG overrides。

## Toolchain

唯一新增工具安装在 `envs/ibex-simple-system/`，下载 cache 在 `cache/data1a/`：

```bash
/home/qcx/ChipChainV3/.venv/bin/python -m venv /home/qcx/ChipChainV3_res/envs/ibex-simple-system
/home/qcx/ChipChainV3_res/envs/ibex-simple-system/bin/python -m pip --cache-dir /home/qcx/ChipChainV3_res/cache/data1a/pip install 'fusesoc==2.4.3' 'pyyaml==6.0.3'
```

这是用于检查参数路径的最小依赖环境，未安装完整 Ibex DV/lint 依赖。
FuseSoC 版本来自冻结 `python-requirements.txt`；Edalize 0.6.8 是本轮解析结果，
并非 Ibex 文件指定的精确 pin。完整 `pip freeze` 如下，专用环境 `pip check` 通过：

```text
argcomplete==3.7.2
attrs==26.1.0
babel==2.18.0
edalize==0.6.8
fastjsonschema==2.22.2
fusesoc==2.4.3
Jinja2==3.1.6
jsonschema2md==1.7.0
Markdown==3.10.3
MarkupSafe==3.0.3
okonomiyaki==3.0.0
pyparsing==3.3.2
PyYAML==6.0.3
simplesat==0.9.2
six==1.17.0
```

没有修改 ChipChain `.venv` 的包，没有系统安装、sudo、`/usr`、`/opt` 或 shell startup 修改。
`ci/vars.env` 指向 `lowrisc-toolchain-gcc-rv32imcb` release `20220210-1` 和
Verilator `v4.210`。它们只是未获取的 CI 参考版本；**本轮未使用任何 RISC-V compiler 或 Verilator**。
没有 toolchain archive、archive SHA 或 simulator SHA。环境缺项仍然存在，
但本轮实际失败点早于这些工具的调用。

## RTL Configuration

配置名称 `small`；以下是已读取、已提交给 FuseSoC 参数解析的值，**不是成功构建后的配置证明**：

```json
{
  "BaseIsa": "ibex_pkg::BaseIsaRV32I",
  "RV32E": 0,
  "RV32M": "ibex_pkg::RV32MFast",
  "RV32B": "ibex_pkg::RV32BNone",
  "RV32ZC": "ibex_pkg::RV32Zca",
  "RegFile": "ibex_pkg::RegFileFF",
  "BranchTargetALU": 0,
  "WritebackStage": 0,
  "ICache": 0,
  "ICacheECC": 0,
  "ICacheScramble": 0,
  "BranchPredictor": 0,
  "DbgTriggerEn": 0,
  "SecureIbex": 0,
  "PMPEnable": 0,
  "PMPGranularity": 0,
  "PMPNumRegions": 4,
  "MHPMCounterNum": 0,
  "MHPMCounterWidth": 40
}
```

Canonical rule：对 `small` 的完整字段映射执行
`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`，
UTF-8 编码，无末尾换行，再做 SHA256。保留 YAML 中的整数类型，不转成布尔值。

```text
configuration SHA256 = db8a13294c8c468a40e402893b6ecfbc80cc641027c420a6fc17983cc8e9289c
```

canonical JSON 也保存在 blocked record 中。它不含时间或路径。

## Firmware Build

未执行。为了先排除源树配置路径错误，本轮先进行了 simulator setup 参数检查；
发现 STOP 条件后没有继续下载编译器或构建 firmware。

冻结 `common.mk` 的声明默认值为 `ARCH ?= rv32imc`、`-mabi=ilp32`、
`CC = riscv32-unknown-elf-gcc`，默认 CFLAGS 为：

```text
-march=$(ARCH) -mabi=ilp32 -static -mcmodel=medany -Wall -g -Os
-fvisibility=hidden -nostdlib -nostartfiles -ffreestanding $(PROGRAM_CFLAGS)
```

linker script：`examples/sw/simple_system/common/link.ld`；
CRT：`examples/sw/simple_system/common/crt0.S`。它们及 hello source 的 SHA 见 Frozen Inputs。
这些是源码声明，不是 actual compiler invocation。
没有为了缺失的 `srec_cat` 改 Makefile。未来可采用官方已有的 `hello_test.elf` 目标。

## Firmware ELF Identity

未生成 ELF/BIN/VMEM/disassembly。ELF SHA、class、machine、endianness、entry、
sections、program headers 均 **NOT MEASURED**。没有根据期望目标伪造 `file` / readelf 输出。

## Simulator Build

先在冻结 Ibex 工作目录，用专用环境调用未修改的配置工具：

```bash
util/ibex_config.py --config_filename ibex_configs.yaml small fusesoc_opts
```

成功返回全部 19 个配置字段。唯一一次实际 setup/build 命令如下：

```bash
/home/qcx/ChipChainV3_res/envs/ibex-simple-system/bin/fusesoc --config /home/qcx/ChipChainV3_res/cache/data1a/fusesoc.conf --monochrome --cores-root=. run --target=sim --setup --build lowrisc:ibex:ibex_simple_system --BaseIsa=ibex_pkg::BaseIsaRV32I --RV32E=0 --RV32M=ibex_pkg::RV32MFast --RV32B=ibex_pkg::RV32BNone --RV32ZC=ibex_pkg::RV32Zca --RegFile=ibex_pkg::RegFileFF --BranchTargetALU=0 --WritebackStage=0 --ICache=0 --ICacheECC=0 --ICacheScramble=0 --BranchPredictor=0 --DbgTriggerEn=0 --SecureIbex=0 --PMPEnable=0 --PMPGranularity=0 --PMPNumRegions=4 --MHPMCounterNum=0 --MHPMCounterWidth=40
```

cwd 为 `platforms/ibex`。`fusesoc.conf` 只有 `[main]` 和专用 `cache_root`；
XDG cache/data/config 指向 `cache/data1a`，进程 PATH 仅包含专用 venv 和 `/bin:/usr/bin`，
移除了 `IBEX_CONFIG_FILE` 环境覆盖，并显式选择 `ibex_configs.yaml`。
精确 argv、cwd、环境覆盖、退出码见 `simulator-build-attempt.json`。

FuseSoC 已解析 vendor core 依赖、导出忽略目录下的源文件副本，随后 argparse 拒绝 BaseIsa。
未调用 Verilator，无 simulator binary。记录在 `simulator-build.stderr.log`，stdout 为空。

根因可在冻结源码直接检查：

- [small 配置](https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/ibex_configs.yaml#L19) 声明 BaseIsaRV32I。
- [配置工具](https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/util/ibex_config.py#L132) 为所有 known fields 生成 CLI 参数。
- [Simple System core](https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/examples/simple_system/ibex_simple_system.core#L15) 没有 BaseIsa 参数定义或 sim target 暴露。
- [顶层 RTL](https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/examples/simple_system/rtl/ibex_simple_system.sv#L29) 用 `BASE_ISA` 宏，默认 BaseIsaRV32IorCHERIoT。
- `ibex_top_tracing.core` 虽定义 BaseIsa，但 default target 仅激活 RVFI；其 lint target 定义不能替代 Simple System sim 参数。

实际调用输出也确认可接受参数列表没有 `--BaseIsa`。仅安装 Verilator/compiler 不能消除这个已复现的参数错误。
本轮没有尝试任何 source patch 或配置语义 workaround。

## Run 1

NOT RUN。没有冻结成功的 ELF、simulator 或执行命令。

## Run 2

NOT RUN。没有第二次运行，也没有重试调参。

## Reproducibility Comparison

NOT EVALUATED。firmware output、instruction trace、pcount、cycles/instructions 均无实测值。
`deterministic_equal`、`expected_nondeterministic`、`unexpected_difference` 列表均为空，
不能将“没有运行”报告为“两次一致”。没有 FST 或 host timing 差异可比较。

## Instruction Trace Semantics

收集记录数 **0**，原因是没有执行；这不是“运行成功但 trace 为空”。
没有当前实验的 trace，因而没有 retirement 证明。

仅从冻结 `rtl/ibex_tracer.sv` 做静态检查：
打印路径由 `rvfi_valid && trace_log_enable` 门控（1149–1167 行），
格式包含 `$time`、cycle、`rvfi_pc_rdata`、原始 instruction encoding、decoded text；
根据 decoded access flags 输出 register 和 memory 字段。
这提示未来可研究 RVFI 退休事件语义，但必须结合真实运行和 RVFI 生产端核实异常等边界。
没有将其自动转换成 EnCorpus A3 `instruction_encoding_observed` 或新增 typed relation。

## Register Observability

没有本轮实测 register 证据。源码打印逻辑在 RD access flag 有效时输出
`rvfi_rd_addr` / `rvfi_rd_wdata`；RS1/RS2 等使用相应读值。
这些候选字段是逐事件 read/writeback 信息，不能当作 full GPR snapshot。
本轮 full architectural GPR state 不可用，也未尝试通过零散写回重建它。

## MMIO Observability

没有本轮实测 MMIO transactions。
冻结 Simple System README 的 memory map 列出 ASCII `0x20000`、halt `0x20008`、
mtime `0x30000`、mtimeh `0x30004`、mtimecmp `0x30008`、mtimecmph `0x3000c`。
源码 tracer 的 MEM 路径可输出 `PA:`、`load:`、`store:`，
顶层还有 host/device req/address/we/byte-enable/data 等信号。
这些只是候选证据来源；未生成 runtime log/FST，不能宣称观察到上述事务，也没有创建 MMIO relations。

## Pairing Evidence

没有生成 pairing evidence records。相同 repo/config 的静态出处已经记录，
但尚缺 actual firmware build、同一 ELF 的 simulator load、成功执行和两次一致性证据。
不把源树共址或文档兼容性当作实际 pairing 成功。

没有构造 platform identity、firmware/hardware case ID 或 TargetDescriptor。
将来仍须由真实 build/ELF 确认 ISA、字长和端序，并将固定源码/config、
firmware build、toolchain 等身份纳入无路径/时间/随机数的 canonical identity。

## XL0 Pair Manifest

未构造 `CrossLayerPairManifest`。manifest SHA、descriptor SHA 均为 null；
未使用 `synthetic_test_fixture` 代替真实证据，也未复制 XL0 逻辑。

## XL0 Eligibility Result

**not_evaluated**，不是 XL0 `eligible`、`ineligible` 或 `unknown` 的一次 builder 结果。
没有调用 builder，因为本轮未满足实际 build/load/run 证据前提。
XL0 合同与 matcher 完全未修改。未构造 HardwareTriggerCondition 或 CrossLayerTriggerCandidate。

## Scientific Boundaries

明确限制：

```text
no_hardware_mutation
no_hardware_vulnerability
no_hardware_trigger
no_cross_layer_candidate
no_attack_chain
no_attacker_control_claim
no_path_feasibility_claim
baseline_execution_only
baseline_execution_not_reached
```

`baseline_execution_only` 是授权范围，`baseline_execution_not_reached` 是本轮结果。
没有 RTL/firmware 修改或 controlled mutation；没有 DeepSeek 或任何 Security Agent 调用。
不声称漏洞、trigger、attacker control、path feasibility 或 attack chain。

## Open Problems

首要阻塞是**冻结 revision 的 Simple System 参数接口与 exact small 不一致**。
在当前 no-patch / no-revision-change 授权内无法继续该官方路径。没有自动修补或换版本。
将来需先解决并重新冻结这一源码/config 接口，再补充兼容 RISC-V toolchain、Verilator、
libelf development files 和所需构建依赖；实际 build/run 才能暴露其他兼容性问题。
本轮没有证明只修一个参数就一定能完成 build。

依赖应优先用户空间安装；目前没有证据证明必须 root 安装，因此未执行或要求系统修改。
上游 CI 版本仅是后续选型依据，不能替代本地验证。

## DATA1B Readiness

**NO-GO**。尚无可冻结的 DATA1A clean paired baseline。
最大缺口是先恢复冻结平台的 exact-small 构建路径并完成实际 build/load/two-run 证明。
没有进入 DATA1B 或进行 mutation、golden/mutant 对比、trigger 构造、firmware fact ingestion、XL0 matching。

## Historical Preservation and Validation

修改前已对 256 个既有文件保存 SHA256，覆盖所有源码、tests、历史 output、DOC-1、
DATA0 registry 和调研正文。其中特别包含 8 个 XL0 源文件、81 个历史 output 文件
（含 12 个 reviewed）、9 个 DOC-1 文件。**所有 256 个文件均保持不变。**
这也覆盖 Hardware B2 与 Firmware B3/A5 的 source/output。
源树比对同时确认 Ibex commit/tree/受控文件仍干净；忽略 `build/` 是本次 setup 导出产品。

本轮没有新增生产 helper/script 或测试代码，仅添加失败记录和文档，因此不新增 helper 测试。
默认 pytest 没有调用 Verilator 或真实模型。验证完成：

```text
pytest -q: 1064 passed, 27 skipped in 26.93s
python -m pip check: No broken requirements found.
python -m compileall -q src tests: PASS
git diff --check: PASS
```

以上 Python 命令使用项目 `.venv/bin/python`。pytest 完整日志保存在忽略的失败归档目录。

最终 `git status --short --untracked-files=all`：

```text
 M README.md
?? docs/research/data1/ibex-simple-system-blocked.json
?? docs/research/v3-data1a-ibex-simple-system-baseline.md
```

Git 不执行 add、commit、push、tag。可审阅变更仅 README 当前研究阶段摘要、本文和 blocked JSON。
大型 logs/cache/build 不纳入 Git；没有新的 ELF、trace、FST 或 simulator binary。

## Requested Final Questions (1–68)

| # | 问题 | 本轮精确回答 |
| --- | --- | --- |
| 1 | Ibex commit | `405c6d1d8220a18b2f9196141167a5875422dee4` |
| 2 | 执行前 Ibex clean？ | 是；更准确地说是 setup 尝试前，未进入 execution。 |
| 3 | 执行后 Ibex clean？ | 是；setup 后 clean，仅 ignored build products。 |
| 4 | exact small values？ | 见 RTL Configuration 的全部 19 项；提交给解析器后被拒绝，尚未用于成功仿真。 |
| 5 | canonical config SHA256？ | `db8a13294c8c468a40e402893b6ecfbc80cc641027c420a6fc17983cc8e9289c` |
| 6 | 实际 compiler？ | 无。源码声明 riscv32-unknown-elf-gcc。 |
| 7 | compiler version？ | 未使用、未测得。 |
| 8 | 实际 -march？ | 无实际构建；源码默认 rv32imc。 |
| 9 | 实际 ABI？ | 无实际构建；源码默认 ilp32。 |
| 10 | hello_test.elf SHA256？ | 未生成，null。 |
| 11 | ELF machine/class/endianness？ | 未测得。 |
| 12 | ELF entry？ | 未测得。 |
| 13 | exact simulator build command？ | 见 Simulator Build 完整命令及 simulator-build-attempt.json argv。 |
| 14 | Verilator version used？ | 未调用。CI 引用 v4.210 不等于实际使用版本。 |
| 15 | FuseSoC version used？ | 2.4.3（Edalize 0.6.8）。 |
| 16 | simulator SHA256？ | 未生成，null。 |
| 17 | exact run command？ | 未执行 runtime 命令。 |
| 18 | run 1 normal termination？ | N/A，NOT RUN。 |
| 19 | run 2 normal termination？ | N/A，NOT RUN。 |
| 20 | firmware outputs equal？ | 未比较。 |
| 21 | instruction traces equal？ | 未比较。 |
| 22 | deterministic counters equal？ | 未比较。 |
| 23 | expected nondeterminism？ | 没有运行差异可分类。 |
| 24 | trace record count？ | 0；没有运行，不是成功运行的空 trace。 |
| 25 | trace proves retirement？ | 本轮没有 trace，不能证明；源码 RVFI 门控仅作静态语义记录。 |
| 26 | trace PC？ | 无实测；源码格式包含 rvfi_pc_rdata。 |
| 27 | trace encoding？ | 无实测；源码格式包含 rvfi_insn。 |
| 28 | decoded instruction？ | 无实测；源码格式包含 decoded text。 |
| 29 | destination register？ | 无实测；源码在 RD flag 有效时打印 rvfi_rd_addr。 |
| 30 | writeback value？ | 无实测；源码在 RD flag 有效时打印 rvfi_rd_wdata。 |
| 31 | full GPR state？ | 不可用。 |
| 32 | actual register semantics？ | 无 runtime 观察；候选格式为逐事件读值/写回，非 full snapshot。 |
| 33 | observed MMIO transactions？ | 无。ASCII/halt/timer 是待验证候选。 |
| 34 | exact MMIO evidence source？ | 本轮无 runtime evidence；静态来源见 memory map、ibex_simple_system.sv 和 ibex_tracer.sv。 |
| 35 | platform identity？ | 未构造，null。 |
| 36 | identity inputs？ | 尚未形成完整输入；未来需 repo/commit/tree/config/top/firmware build/toolchain 的固定身份。 |
| 37 | firmware case ID created？ | 无。 |
| 38 | hardware case ID created？ | 无。 |
| 39 | TargetDescriptors used？ | 无。 |
| 40 | ISA compatibility established？ | 未由实际 ELF/RTL execution 建立。 |
| 41 | explicit pairing evidence created？ | 无；只有源身份和失败 setup provenance。 |
| 42 | pair manifest SHA256？ | null，未构造。 |
| 43 | pair descriptor SHA256？ | null，未构造。 |
| 44 | XL0 eligible？ | 没有 descriptor；状态为 not_evaluated。 |
| 45 | why eligible？ | 不适用，未获得 eligible 结果。 |
| 46 | what missing？ | exact-small build path、ELF/compiler、simulator、实际 load/run 与两次一致性证据。 |
| 47 | HardwareTriggerCondition created？ | NO。 |
| 48 | CrossLayerTriggerCandidate created？ | NO。 |
| 49 | RTL modified？ | NO。 |
| 50 | firmware source modified？ | NO。 |
| 51 | controlled mutation introduced？ | NO。 |
| 52 | DeepSeek called？ | NO。 |
| 53 | Agent called？ | NO。 |
| 54 | privileged/system installations？ | NO。 |
| 55 | source patches required？ | 官方参数路径存在需修复的源接口不一致，按 STOP 条件停止；未实施任何 patch，也未验证 patch 后构建。 |
| 56 | new runtime artifacts？ | 没有执行产物；新增环境/源身份/setup 失败日志、依赖 freeze、preservation 和 pytest 记录。 |
| 57 | intentionally untracked artifacts？ | output/paired 下全部原始记录、外部 cache/envs、Ibex ignored build exports；无 ELF/FST/trace。 |
| 58 | reviewed unchanged？ | YES，12 文件。 |
| 59 | DOC-1 unchanged？ | YES，9 文件。 |
| 60 | XL0 contracts unchanged？ | YES，8 源文件。 |
| 61 | DATA0 unchanged？ | YES，registry 与研究正文。 |
| 62 | final pytest？ | 1064 passed, 27 skipped in 26.93s |
| 63 | pip check？ | PASS，No broken requirements found. |
| 64 | compileall？ | PASS。 |
| 65 | git diff --check？ | PASS。 |
| 66 | largest gap before DATA1B？ | 先解决冻结平台 exact-small 接口阻塞，完成 DATA1A 实际 paired baseline。 |
| 67 | scientifically real paired baseline？ | NO，目前只有可复现的 setup 阻塞。 |
| 68 | cross-layer vulnerability？ | NO。 |
