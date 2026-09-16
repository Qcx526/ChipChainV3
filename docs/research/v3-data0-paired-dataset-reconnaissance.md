# V3-DATA0 — Paired Cross-Layer Dataset Reconnaissance & Acquisition Planning

基线：`v3-xl0-stable` / `b743984d60f4cb0a489fdcd2170484252bcab348`。调查日期：2026-09-15。
本报告只记录源码/元数据调研和未来命令计划。没有 acquisition execution、工具安装、RTL/firmware build、仿真、变异注入或模型调用。

## Executive summary

**PRIMARY：lowRISC Ibex Simple System，使用本地 Ibex commit `405c6d1d8220a18b2f9196141167a5875422dee4` 的 `small` 配置。**
同一源码树已经同时包含可运行固件框架、明确内存布局、Ibex RTL、ELF loader 与 Verilator target；不需要先移植 EnCorpus 变异。
**SECONDARY：lowRISC Ibex Demo System，commit `d37beb753e19482eb054aefac73a27289bf72e47`，vendored Ibex `594ea976c9dad793f87edf91ec1c4c1df447e6dc`。**
它提供更多 UART/GPIO/SPI/timer/debug 接口，适合主平台正常运行后扩展真实外设路径。
两者当前都是 **Class C** 源码级平台候选，计划后续构造 **Class B** controlled mutation benchmark；尚未接入 ChipChain、生成正式 pair 或验证漏洞。

OpenTitan、PULPissimo、Chipyard Rocket/BOOM 和 EnCorpus 复用进入 backup。推荐顺序是研究判断，不是测试过的性能排名。
Simple System 的明确执行路线来自 [固定 revision 的官方 README][simple-readme]；Demo System 的内核绑定来自 [vendor lock][demo-lock]，运行路线来自 [官方 README][demo-readme]。

## Current data problem

XL0 的规则要求架构兼容，还要有具体 platform/session binding。Heat_Press ARM/SAM3X 与 EnCorpus Ibex RISC-V 仍不能配对。
同样，“EnCorpus Ibex + 任意 Ibex firmware”没有自动资格：需要完整 source revision、参数、wrapper、memory、loader 和执行环境的一致性。
数据集的关键缺口是可审计的 **同一目标固件 → 同一 RTL 的执行证据**，而不是再增加一份 LLM 报告。

DATA0 不创建 CrossLayerPairDescriptor。下文 `likely_eligible` 等仅为研究预判，不能代替 XL0 runtime eligibility。
高 pairing_confidence 表示源码层的身份绑定有充分资料；不表示构建成功、运行成功或 trigger 已验证。

## Existing local inventory

实际只读检查根目录 `/home/qcx/ChipChainV3_res`。没有修改其中任何仓库。
四个 Git repo 均 clean、非 shallow，remote/HEAD/branch 已实际查询；未假定与先前记忆一致。

两份固件repo的当前README与目录也已读取：Fuzzware按实验划分为access-modeling、P2IM/uEmu比较、new-targets和crash-analysis；
P2IM包含Heat_Press等源码目录、binary和deps。P2IM还明确其固件包含fuzzing用的aflCall约定；这进一步说明不能将这些二进制未经目标/环境核对直接当成真实RTL可运行固件。

| Local path | Remote URL | Commit | Branch | State | Shallow |
| --- | --- | --- | --- | --- | --- |
| `/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments` | https://github.com/fuzzware-fuzzer/fuzzware-experiments.git | `1b03b728ea660b777571bf2a6c1ecfa9072f0bf5` | main | clean | false |
| `/home/qcx/ChipChainV3_res/firmware/p2im-real_firmware` | https://github.com/RiS3-Lab/p2im-real_firmware.git | `d4c7456574ce2c2ed038e6f14fea8e3142b3c1f7` | master | clean | false |
| `/home/qcx/ChipChainV3_res/platforms/ibex` | https://github.com/lowRISC/ibex.git | `405c6d1d8220a18b2f9196141167a5875422dee4` | master | clean | false |
| `/home/qcx/ChipChainV3_res/platforms/opentitan` | https://github.com/lowRISC/opentitan.git | `16e86c9e031d52760780ac4efddaab2389bdb94b` | master | clean | false |

| 已有材料 | 实际内容/大小 | 可复用范围 |
| --- | --- | --- |
| platforms/ibex | `du -sh` 94M；rtl、examples/simple_system、examples/sw、vendor、DV/formal、配置和依赖文件 | 首选配对源码与最小固件；不代表已装工具 |
| platforms/opentitan | 512M；hw、sw、Bazel MODULE/lock、Earlgrey/Darjeeling/Englishbreakfast、vendor | 安全 SoC backup；需锁定一个 top，不能混用 |
| firmware/fuzzware-experiments | 109M；现有 Fuzzware 固件/实验材料 | 保留 Heat_Press 单侧分析；没有目标 Ibex RTL 绑定 |
| firmware/p2im-real_firmware | 128M；固件侧 corpus | 当前没有可证明的开源 RTL 对应关系 |
| hardware/encorpus/ibex/ibex | 150 文件，238,445,554 bytes；15 driver + 15 multiplexer | 聚合 RTL、RTLIL、witness、日志与 Tcl；无本地 ELF/firmware manifest |
| hardware/encorpus/rocket/rocket | 150 文件，223,894,028 bytes；15 + 15 | 同类 netlist mutation corpus |
| hardware/encorpus/boom/boom | 150 文件，1,213,739,591 bytes；15 + 15 | 同类 corpus，体积最大 |

三份非 Git corpus 均为 8 Tcl、4 Verilog、32 log、46 RTLIL、60 VCD。每份共享 `reference.v`、注入/导出脚本和日志，
每个 driver 目录保存 host/golden RTLIL、proof/proof_optimized VCD 与 verify.log。未发现对应 ELF、BIN、汇编种子或依赖 lock。
代表文件 SHA256/bytes 在 [machine-readable registry](data0/paired-platform-candidates.json) 的 `local_corpus_identities` 中；
关键平台文件 hash、固定 revision URL 位于 `local_source_identities`。没有复制 RTL、二进制或 runtime outputs 到本仓库。
已有 743/820 的 A3 catalog/B1 hashes 仍见 [Hardware A3 历史文档](v3-1a3-hardware-typed-relations.md)，本轮没有重算分析结果。

检查当前 PATH：gcc、g++、make 存在；verilator、fusesoc、bender、bazel、riscv32/64-unknown-elf-gcc、vsim 未找到。
这是 PATH 可用性检查，不等于证明机器其他目录没有安装。没有安装或运行这些工具。

### Upstream pin observations

GitHub unauthenticated commit API 返回 403 rate limit，后改用 `git ls-remote HEAD` 获得 immutable commit，再读取小型 raw 源文件。
部分 GitHub tree 页面不可访问，因此 Chipyard generator gitlinks、PULPissimo runtime gitlink 保留 UNKNOWN；没有用独立仓库 HEAD 冒充父项目依赖版本。

| Upstream repo | 观测 commit | 含义 |
| --- | --- | --- |
| [cascade-artifacts-designs/cascade-chipyard](https://github.com/cascade-artifacts-designs/cascade-chipyard/tree/727a99a3f917f61d7de818de5100f905f31d7bc8) | `727a99a3f917f61d7de818de5100f905f31d7bc8` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [chipsalliance/rocket-chip](https://github.com/chipsalliance/rocket-chip/tree/ece7b9ad544b07df39cd13b6fd7236562a26355d) | `ece7b9ad544b07df39cd13b6fd7236562a26355d` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [comsec-group/encarsia](https://github.com/comsec-group/encarsia/tree/b8fd17d9e72b052ed6dfd127956239b49c8fb3a1) | `b8fd17d9e72b052ed6dfd127956239b49c8fb3a1` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [encarsia-artifacts/encarsia-ibex](https://github.com/encarsia-artifacts/encarsia-ibex/tree/bd823812cd5bd925f7671c49f3f6a7a63d2ace4b) | `bd823812cd5bd925f7671c49f3f6a7a63d2ace4b` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [encarsia-artifacts/encarsia-meta](https://github.com/encarsia-artifacts/encarsia-meta/tree/756ba14fbd9cbe29df00a157da29eee424f3c64a) | `756ba14fbd9cbe29df00a157da29eee424f3c64a` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [lowRISC/ibex-demo-system](https://github.com/lowRISC/ibex-demo-system/tree/d37beb753e19482eb054aefac73a27289bf72e47) | `d37beb753e19482eb054aefac73a27289bf72e47` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [pulp-platform/pulp-runtime](https://github.com/pulp-platform/pulp-runtime/tree/3b48b0c6872cc01ba169a2c9c886ebb815d22cdc) | `3b48b0c6872cc01ba169a2c9c886ebb815d22cdc` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [pulp-platform/pulpissimo](https://github.com/pulp-platform/pulpissimo/tree/bfc3d9a1ef72443464509a22d948f0a6f5b65b4c) | `bfc3d9a1ef72443464509a22d948f0a6f5b65b4c` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [riscv-boom/riscv-boom](https://github.com/riscv-boom/riscv-boom/tree/58ef2720eae13be26b3008c02b5a74ce29c61c44) | `58ef2720eae13be26b3008c02b5a74ce29c61c44` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |
| [ucb-bar/chipyard](https://github.com/ucb-bar/chipyard/tree/371ab92dd09917b6ab05d58bf762b173c52f4224) | `371ab92dd09917b6ab05d58bf762b173c52f4224` | 调研时 HEAD，不自动等于 corpus 生成版本或上层 gitlink |

## Ibex Simple System deep dive — PRIMARY

同一 [Ibex source tree][ibex-tree] 内的 `examples/simple_system` 与 `examples/sw/simple_system` 是自然配套源码。
硬件 top `ibex_simple_system` 实例化 `ibex_top_tracing`，通过 RAM 同时提供 instruction/data；固件 common.mk、crt0.S、link.ld 使用同一平台布局。
具体 source files 与 SHA 可在 registry 核查。[RTL][simple-rtl]、[firmware Makefile][simple-make]。

锁定 `small` 的实际参数：BaseIsaRV32I、RV32E=0、RV32MFast、RV32BNone、RV32Zca、RegFileFF；
BranchTargetALU=0、WritebackStage=0、ICache=0、DbgTriggerEn=0、SecureIbex=0、PMPEnable=0。
PMPNumRegions=4 是关闭 PMP 时保留的参数，不代表开启了 4 个区域。软件编译默认 `rv32imc/ilp32`；
现代编译器对 CSR/扩展命名的行为需在 DATA1 实测，不能用成功链接替代 ISA 一致性检查。[配置][simple-config]。

内存图：RAM `0x100000–0x1fffff`，入口 `0x100080`、异常基址 `0x100000`；
ASCII output `0x20000`、halt `0x20008`；timer `mtime/mtimeh/mtimecmp/mtimecmph` 为 `0x30000/04/08/0c`。
这里是 RAM-loaded firmware，没有 OpenTitan 的 ROM/OTP/secure flash boot。[memory map][simple-readme]。

第一份固件选 `examples/sw/simple_system/hello_test/hello_test.elf`，从同 revision C/ASM 构建。
实际 `hello_test.c` 含打印、timer_enable(2000)、wfi/计时循环，能作为正常 MMIO 与 interrupt baseline；
它不是外部 UART 收包服务，更不是已知漏洞 PoC。[源码][simple-hello]。

官方流程给出 FuseSoC + Verilator、`--meminit=ram,<ELF>`，`-t` 开启波形，并输出 `trace_core_00000000.log`、ASCII log、性能计数。
tracer 输入有 RVFI rd address/write data、memory address/mask/data，可记录写回与内存观察。
这不保证每周期完整 GPR 文件已导出，DATA1 必须明确 snapshot 与 retirement 对齐策略。[tracer source][simple-tracer]。

来源可复用但 parser 不能直接复用：A2 RV32 decoder、EvidenceRef、XL0 typed contracts 可沿用；
现有 EnCorpus parser 只接受它自己的 artifacts，Heat_Press analyzer 是 ARM 特定入口，不能喂入此 ELF 假装已接入。
DATA1 应先保存原始 deterministic artifacts 与 manifest，再限定后续 adapter 工作量。

## Ibex Demo System deep dive — SECONDARY

[Demo revision][demo-tree] 包含 RTL、C/Rust firmware、Verilator testbench 和 vendor。
[Ibex lock][demo-lock] 明确 core commit `594ea976c9dad793f87edf91ec1c4c1df447e6dc`；
[PULP debug lock][demo-debug-lock] 明确 `138d74bcaa90c70180c12215db3776813d2a95f2`。
应使用父 commit 中实际 vendored 文件，不能替换为本地 `405c...` Ibex 后仍沿用旧 pairing identity。

[系统源码][demo-rtl] 配置 RV32MFast、RV32BNone，RAM 起始 `0x00100000`，boot base 同值，
GPIO `0x80000000`、debug `0x1a110000`、UART `0x80001000`、timer `0x80002000`、PWM `0x80003000`、SPI `0x80004000`、sim control `0x20000`。
[软件 header][demo-header] 与这些资源同树；[CMake/toolchain][demo-toolchain] 明确 RV32IMC、ILP32 和 linker script 路径。
[顶层 CMake][demo-cmake] 提供 `SIM_CTRL_OUTPUT` 选择，可将字符串输出送往 simulator control；外围输入仍须单独定义刺激。

推荐第一固件是官方 hello-world 构建产物 `sw/c/build/demo/hello_world/demo`（无 `.elf` 扩展名不代表非 ELF）。
README 给出 CMake build 与 `Vtop_verilator --meminit=ram,...`。本轮未取得所有 hello-world translation units，DATA1 必须核对实际构建目标。
FuseSoC sim target 带 trace/trace-structs/trace-max-array 选项；与 Simple System 的 top/logger 不同，不能承诺现成 instruction log。
可先收 UART/MMIO/波形，后续明确 RVFI或寄存器采集接口。[sim target][demo-core]。

Verilator-only 路线不要求 Vivado/FPGA/商业 simulator。README 的 FPGA 路线另需 Vivado，不能把那个成本混入最小仿真路线。
环境存在 flake.lock；pip 示例却使用 lowRISC FuseSoC/edalize 的浮动 `ot` 分支，必须在 DATA1 固定解析结果。
不应运行 `nix flake update` 后仍声称复现该 pin。[依赖][demo-pyreq]。

## OpenTitan deep dive — BACKUP

本地 `16e86c9e031d52760780ac4efddaab2389bdb94b` 同时提供 hw/sw。`hw/vendor/lowrisc_ibex.vendor.hjson` 中 master 仅为更新来源；
真正 vendor lock 是 `8b8ee086aef72e0833b7f0493d9d33f1e4d3c8e2`，还须保留映射与 patches、父 commit 中的实际文件。
[lock][ot-lock]、[vendor mapping][ot-vendor]。

选定讨论 top 为 `top_earlgrey`，Verilator wrapper 为 `chip_earlgrey_verilator`。实际 top 参数包含 SecureIbex=1、PMPEnable=1、16 PMP regions、
RV32MSingleCycle、RV32BOTEarlGrey、RV32ZcaZcbZcmp、WritebackStage=1、ICache/ECC/scramble=1、DbgTriggerEn=1、4 hardware breakpoints。
该 revision 还出现 CHERIoT-capable 配置；不能将 README 中较旧“RV32IMCB”的概括当作完整 ISA/配置锁。[top source][ot-top]。

sw/device 下存在 silicon_creator ROM、ROM_EXT、owner/test stages、drivers 以及 uart_smoketest。
Bazel target/exec_env 绑定 RTL 与软件，源级能够为相同 top 构建；是否在这台机器成功尚未验证。
UART/peripheral MMIO、PMP、lockstep、icache 等测试可用于未来 trigger studies，但 UVM sequence 的存在不代表它可在 Verilator 执行。
例如本地有 lockstep glitch vseq，仅视为研究入口，不视为已验证的公开自然漏洞。[tests BUILD][ot-tests]。

boot 与 memory 必须按 pin 解读。旧 [Verilator guide][ot-verilator] 描述 ROM→flash、OTP/RMA、Bazel uart_smoketest；
当前 top 文件已显示 ROM `0x00040000`、main SRAM `0x10000000`、secondary SRAM `0x10020000` 等较新布局。
因此本报告不把旧 guide 的 flash 模型和地址强行套到当前 top。DATA1 若选此 backup，先核对 exec_env 实际 ROM/flash/OTP 镜像规则与命令，再构建。
保留 ROM/test-ROM/ROM_EXT 各阶段区别、OTP/lifecycle 状态、debug 开关和 memory model，不将 test ROM 当生产 secure boot。

可以在开放 RTL 的隔离实验副本做未来 controlled mutation，但 SecureIbex lockstep/ECC 等防护可能先产生 alert，
不能预设一定得到未被检测的架构寄存器错误。候选效果包括 alert、trap、MMIO差异或GPR差异，必须实测分类。
本地还发现历史 tag `earlgrey_silver_release_v5` → `ed044fc9760bdf9fc075d0015ba1db07fa075355`，vendor Ibex `71a8763553a25b90394de92f3f97e56b1009030b`；
仅作为可追溯历史备选，未切换 checkout，未混入当前推荐，旧文件布局与工具要求也不同。

## PULPissimo deep dive — BACKUP

固定候选 PULPissimo `bfc3d9a1ef72443464509a22d948f0a6f5b65b4c`。
[Bender.lock][pulp-lock] 的 Ibex 是 PULP fork `b18f7ef178ed07f5085051f96042c670a919fd5c`，pulp_soc `bf65372aab4edd404160170e2a4d2c63b27ab5f2`（5.0.1）。
不能只固定 PULPissimo master，也不能用 lowRISC latest 替换 fork。

[tb_pulp][pulp-tb] 明确 CORE_TYPE=1 为 Ibex RV32IMC，2 为 RV32EC；默认0为另一个core。
实际仿真计划必须显式 CORE_TYPE=1、USE_FPU=0，并保存 elaborated 参数；只运行 runtime config 不会改变 RTL。
runtime 候选 HEAD `3b48b0c6872cc01ba169a2c9c886ebb815d22cdc` 的 [配置脚本][pulp-runtime-config] 设置 PULPRT_TARGET/PULPRUN_TARGET=pulpissimo、USE_IBEX=1。
父仓库 `.gitmodules` 声明 `sw/pulp-runtime`，但其实际 gitlink commit 本次尚未取得，当前 runtime HEAD 不是经证明的匹配版本。
因此 firmware/compiler flags 与完整 Bender 状态仍需补齐。

公开组件包含 L2、boot、uDMA UART/SPI/I2C/GPIO 等外围接口；测试平台支持 JTAG L2 预加载与其他 boot 刺激。
精确 MMIO offsets 应取锁定 pulp_soc + runtime headers，README 自己提示 datasheet 可能过期，因此本报告不填猜测地址。
[README][pulp-readme] 明确相关 RTL flow 支持 Questa/Xcelium，Verilator 尚未完成；Intel FPGA ModelSim 不在该流程支持范围。
测试平台还标注某 SPI flash model 非开源，最低成本测试应避免把它当成默认可得依赖。
可以采 instruction/register/MMIO 波形，但商业 simulator 与模型依赖显著降低本研究的搭建优先级。

## Can existing EnCorpus be reused for paired experiments?

**不能直接复用为已配对的固件–硬件实验；可条件性复用 mutation 定义/差分，先补来源与 wrapper 绑定，再重新验证。**
这里的 `reuse_mutation_only` 是“允许保留为后续移植研究材料”，不是说已经得到可用 patch 或完成等价性证明。

本轮额外核对了官方 [Encarsia artifact repo][encarsia]。它明确提供 corpus、独立注入 pass、Jasper/Yosys verification 和 fuzzer wrappers。
[Dockerfile][encarsia-docker] 与设计映射把 Ibex 指向 `encarsia-artifacts/encarsia-ibex/cellift`，Rocket/BOOM 指向 Cascade Chipyard。
但关键 design clones 不固定 commit，随后还有源码修改和 config-mixins 覆盖；当前 fork HEAD 不能反推 2024 年 corpus 生成时的 commit。
本轮未下载 corpus archives、Docker image 或完整源码仓库，也未执行上游命令。[design mapping][encarsia-designs]。

| CPU | 本地 top / observed data width | 实际可见刺激与 observability | 原始 provenance / compatibility | 复用结论 |
| --- | --- | --- | --- | --- |
| Ibex | `cellift_ibex_top` / 32-bit | instruction/data req–gnt–rvalid接口、boot/debug/IRQ；miter观察 `gen_regfile_ff.register_file_i.rf_reg` | 原 lowRISC commit UNKNOWN；与本地 `small` 和当前 OpenTitan 参数确定不同；fork lineage有来源，完整一致性仍UNKNOWN | `reuse_mutation_only`，条件性；非直接运行 |
| Rocket | `Rocket` / 64-bit GPR | core I-cache response instruction、D-cache/FPU response接口；miter观察 `rf[10]` | 原 Rocket/Chipyard commits、elaboration Config UNKNOWN；不是最新 RocketConfig 的证明 | `reuse_mutation_only`，条件性 |
| BOOM | `BoomCore` / 64-bit integer、65-bit FP路径 | fetchpacket/uop、LSU response等内部接口；miter指定integer read port，upstream SVA还观察FP内部数据 | 原 BOOM commit/config UNKNOWN；物理寄存器/读端口不等同完整架构GPR；不是当前 SmallBoomV3Config | `reuse_mutation_only`，条件性 |

所有本地 reference.v、miter.tcl、inject_driver.tcl/log 的具体 hash 见 registry。Rocket `reference.v` 为8,849,106 bytes、BOOM为14,594,300 bytes，
虽都包含 ChipTop/DigitalTop/Tile 等聚合模块，**实际 mutation/formal top 分别只是 Rocket/BoomCore**。有 ChipTop 文本不代表保存了可用 SoC firmware flow。
core 请求/响应输入和程序在完整内存系统中执行是不同 abstraction。

### Ibex source/configuration comparison

本地 reference.v 是 morty 聚合产物，记录 morty-0.9.0/2024-07-14；RTLIL header记录 Yosys0.37、git `92cabdf7a`，不是Ibex源码SHA。
所检查743 host core实例参数为 RV32E=0、RV32M数值3、RV32B=0、BranchTargetALU=1、WritebackStage=1、ICache=0、DbgTriggerEn=1、PMPEnable=0、SecureIbex=0。
数值枚举不能直接跨 Ibex revision 比较名字。与当前 Simple System `small` 在 WB/branch/debug 上已经不同，与 OpenTitan 在 PMP/security/cache 等处不同。

| 比较对象 | 分类 | 依据与缺口 |
| --- | --- | --- |
| 本地 Ibex `405c...` + small | `incompatible`，针对所选配置 | 明确参数不同；core源码revision也未恢复 |
| OpenTitan `16e86...` / vendor `8b8e...` | `incompatible`，针对所选配置 | SecureIbex/PMP/cache/extensions/memory integration不同 |
| Demo `d37b...` / vendor `594e...` | `unknown` | 没有本地netlist→该core的source/config绑定，不能以名称判兼容 |
| 官方 encarsia-ibex fork `bd823812cd5bd925f7671c49f3f6a7a63d2ace4b` | `unknown`，但有明确恢复线索 | Docker/design map支持来源路线；缺该SHA到本地reference.v的生成/等价证据 |

没有任何比较被判 `exact-match` 或完整 `compatible-with-evidence`。
[fork Makefile][encarsia-ibex-make] 给出 `cellift_rv_core_ibex_mem_top` / `Vibex_tiny_soc`，是与 formal core-top 不同的内存wrapper；
还依赖 CellIFT和OpenTitan环境、FuseSoC、转换与重命名。要接入 ELF，必须固定这条生成链与loader，而不是把任意 firmware直接灌到proof.vcd输入线上。

### Formal assumptions 与程序可执行性

本地三种 verify.log 均记录 Jasper Apps 2022.09p001，并引用外部 `v_miter.sva` 和 reset sequence，原文件不在本地 corpus。
本轮从官方 encarsia-meta `756ba14fbd9cbe29df00a157da29eee424f3c64a` 读取到这些文件的上游候选版本；
**找回当前上游文件不等于证明它与当年本地 witness 完全相同**，此版本绑定仍UNKNOWN。

- [Ibex SVA][encarsia-ibex-sva] 约束 data_rdata、boot address、hart ID为0，cover只观察差异；没有真实RAM固件装载约束。
- [Rocket SVA][encarsia-rocket-sva] 将部分D-cache/FPU返回数据限制为0，并引用imem response instruction；不等同整个SoC的合法cache/memory交易。
- [BOOM SVA][encarsia-boom-sva] 对LSU数据、debug instruction/PC、bad address等作限制；fetchpacket/uop接口需要完整前端/LSU环境恢复。

因此不能从这些外部输入 witness 自动推出某个 ELF 可执行同一路径。上游 Yosys路线可以产生 `yosys_proof.S`，
但它不在这三份本地快照中，也不是 DATA0 的运行结果。其验证能力不能直接继承到当前ChipChain候选。

### Rocket/BOOM 与 Chipyard 的关联

上游 Cascade fork候选为 `727a99a3f917f61d7de818de5100f905f31d7bc8`：
[Rocket wrapper][cascade-rocket] 用 `MyBigVMRocketConfig` / `rocket_mem_top`；
[BOOM wrapper][cascade-boom] 用 `MyMediumBoomConfigTracing` / `boom_mem_top`。
Encarsia Dockerfile还修改BOOM supervisor/FPU行为，并覆盖config-mixins。因此“同为RV64”远不足以与当前Chipyard直接对齐。
原generator SHA、Config mixins、patch集、生成RTL哈希、wrapper/boot/memory/工具版本都必须重建绑定；当前只确认恢复路线。

未来移植必须保存原golden/host差分、目标源码patch、对应信号语义与参数、修改后RTL hash，并重新运行同ELF下的golden/mutant对照。
新平台上的变异要分配新的sample ID，原743/820等只作为来源引用，不能改写其历史结论。
如无法恢复同一变异语义，放弃“同一bug复用”的主张，改做独立受控mutation benchmark。

## Chipyard Rocket / BOOM deep dive — BACKUP

候选父commit `371ab92dd09917b6ab05d58bf762b173c52f4224`。官方 [simulation guide][chipyard-sim] 提供Verilator、RV64 bare-metal ELF、
`tests/hello.riscv`、run-binary和debug波形路线。ELF由仿真serial/HTIF机制装载，也可使用LOADMEM；不能将其等同Ibex的RAM loader。
[Rocket config][chipyard-rocket-config] 显示当前 `RocketConfig` 使用单个WithNHugeCores；另有RV32RocketConfig，故不能仅凭“Rocket”默认所有配置XLEN相同。
[BOOM config][chipyard-boom-config] 当前同时区分V3等系列，建议备选小配置 `SmallBoomV3Config`，不沿用旧文档可能出现的SmallBoomConfig名字。

独立Rocket HEAD `ece7b9ad544b07df39cd13b6fd7236562a26355d`、BOOM HEAD `58ef2720eae13be26b3008c02b5a74ce29c61c44` 已观测，
**它们不是已核实的Chipyard submodule pins**。当前父commit的generator gitlinks仍UNKNOWN；需用git tree元数据补齐，不能直接checkout这些独立HEAD。

可通过commit/trace/debug和总线波形研究instruction、register、MMIO；BOOM需特别区分rename/physical状态与architectural retirement。
controlled mutation可在generator或生成RTL上做，但必须冻结生成参数、源码patch和产物哈希，不可把旧core-levelwitness视作SoC复验。
Chipyard路线依赖JDK/Scala/Chisel、子模块、RISC-V工具链、Verilator和C++工具，官方guide记录Rocket elaboration约6.5GB主存，
这只是上游参考，不是本次机器测量或所有配置上限。盘占用UNKNOWN，规划上远高于单核Simple System，不推荐DATA1同时搭建。

## Candidate scoring matrix

分数为0–3：0=没有支持/不可用或当前不现实；1=部分线索或障碍较大；2=源码支持但仍需补工作；3=明确强来源。
不是运行成功概率。O setup cost反向记分：3表示低成本，0表示高成本/许可障碍。N=复用现有接口能力，不代表adapter已完成。
A–O每一个分数的独立理由在registry `scores.<dimension>.rationale`，文末也给出逐平台理由。

| Dimension | Meaning |
| --- | --- |
| A | exact_processor_identity |
| B | exact_rtl_revision_pinning |
| C | exact_firmware_target_binding |
| D | firmware_source_availability |
| E | rtl_source_availability |
| F | build_reproducibility |
| G | open_source_simulation |
| H | instruction_observability |
| I | register_observability |
| J | mmio_observability |
| K | controlled_mutation_feasibility |
| L | hardware_trigger_definability |
| M | firmware_input_control |
| N | chipchain_reuse |
| O | setup_cost |

| Candidate | A | B | C | D | E | F | G | H | I | J | K | L | M | N | O | Total /45 | Confidence | Current→planned class | Role |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| ibex-simple-system | 3 | 3 | 3 | 3 | 3 | 2 | 3 | 3 | 2 | 3 | 2 | 2 | 2 | 2 | 3 | 39 | high | C→B | PRIMARY |
| ibex-demo-system | 3 | 3 | 3 | 3 | 3 | 2 | 3 | 2 | 2 | 3 | 2 | 2 | 3 | 2 | 2 | 38 | high | C→B | SECONDARY |
| opentitan-earlgrey | 3 | 3 | 3 | 3 | 3 | 1 | 3 | 2 | 2 | 3 | 2 | 2 | 2 | 2 | 1 | 35 | high | C→B | BACKUP |
| pulpissimo-ibex | 3 | 3 | 2 | 3 | 3 | 1 | 0 | 2 | 2 | 2 | 2 | 2 | 2 | 2 | 0 | 29 | medium | C→B | BACKUP |
| encorpus-ibex-compatible-firmware | 1 | 1 | 0 | 1 | 2 | 0 | 1 | 1 | 2 | 0 | 2 | 1 | 0 | 3 | 1 | 16 | unknown | X→B | BACKUP |
| chipyard-rocket | 3 | 2 | 2 | 3 | 3 | 1 | 3 | 2 | 2 | 2 | 2 | 2 | 2 | 1 | 0 | 30 | medium | C→B | BACKUP |
| chipyard-boom | 3 | 2 | 2 | 3 | 3 | 1 | 3 | 2 | 2 | 2 | 2 | 2 | 2 | 1 | 0 | 30 | medium | C→B | BACKUP |

Class A需要真实自然配对且有公开已知硬件安全问题；本轮没有候选达到该声明。Class B是计划的受控缺陷实验；Class C是未选缺陷的真实源码平台；Class D仅synthetic；Class X表示目前缺可绑定配对或已不兼容。EnCorpus行的X是当前数据状态，不是永远无法复用的判断。

高置信度行均有源码+manifest/lock或本地仓库证据，不由inference单独支撑；所有构建与执行仍未验证。PULP/Chipyard缺依赖绑定或现实执行路线，降低confidence，不能只看总分。

## Firmware input / execution 与 trigger sources

| Candidate | 实验入口与可构造路径 | HardwareTriggerCondition 来源计划 |
| --- | --- | --- |
| Simple System | RAM-loaded ELF、boot、固定指令/寄存器产生路径、ASCII MMIO、timer IRQ；hello_test有真实timer代码 | 首先定义一个受控局部RTL缺陷，配套typed annotation和golden/mutant witness；不是从LLM波形猜测 |
| Demo System | RAM ELF、UART/GPIO/SPI、timer/debug；C/Rust firmware | 主平台验证方法成立后，在同一vendor revision上定义局部缺陷/条件并复验 |
| OpenTitan | test-ROM/ROM_EXT/test firmware、UART/SPI/GPIO、interrupt；需固定OTP/lifecycle/boot环境 | 经确认支持相应sim route的security regression或新受控注释；现有test名字不证明自然漏洞 |
| PULPissimo | boot、L2/JTAG loader、uDMA/MMIO与IRQ；需要受支持商业sim flow | 局部RTL变异和确定性差分；不能把接口存在当输入可控性证明 |
| EnCorpus Ibex | 已有formal instruction/data输入；无本地可执行firmware；上游wrapper仅是恢复路线 | 原host/golden netlist差分和mutation witness，恢复绑定后人工typed annotation |
| Chipyard Rocket | tests/hello.riscv、serial/HTIF或LOADMEM、特定RV64序列、MMIO/IRQ | 固定Config上的新受控变异；旧EnCorpus witness不可直接复用 |
| Chipyard BOOM | 同类ELF入口，加上乱序/rename/commit约束 | 新变异或经语义映射的旧mutation；需架构retirement证据 |

表中输入是实验者的执行控制能力，不等于攻击者可达/可控。串口、SPI、debug或interrupt接口存在，不自动产生攻击路径。
控制程序、初始RAM、reset、IRQ timing等必须记录到实验manifest，实验只能对记录的环境条件负责。

## Top-two recommendation 与具体实验草案

### PRIMARY：Simple System

计划链路（尚未执行）：

```text
同revision的 hello_test.elf 正常运行
  → 锁定small RTL + ELF loader + RAM/reset/config
  → 独立、极小的寄存器产生测试固件
  → golden RTL / 一个受控RTL variant，使用完全相同ELF与初始条件
  → typed instruction/register/stage前置条件
  → 对齐retirement后的rd/寄存器或MMIO结果差异
  → 原始trace、ELF、RTL/patch/config哈希和session manifest
  → 后续ChipChain确定性adapter / XL0引用
```

第一份 artifact 是原样 `hello_test.elf`，先证明系统正常启动、打印、timer路径和结束；这一步没有缺陷，不声称trigger。
第二个计划程序才包含固定的 `addi x10,x0,7` 等最小寄存器产生序列与自检。
初始受控缺陷策略是：在明确选定的译码/结果写回条件下，局部扰动结果的一个位；其具体patch、stage、完整必要条件必须在后续实现时审核并冻结。
**DATA0未写patch，也没有断言该instruction本身是trigger。** 对照预期是正常x10=7与条件性错误写回（例如6）；实际是否出现、在哪个stage出现均待仿真确认。
先从可清晰表达的instruction atom与寄存器条件开始，再补ordering/hardware-state要求；不要用部分条件冒充充分trigger。

这类样本必须标记 `mutation benchmark / controlled injected defect / not naturally occurring CVE / not automatically a vulnerability`。
目标是评价检测方法，不把人为错误包装成真实产品漏洞。

### SECONDARY：Demo System

计划链路（尚未执行）：

```text
同父commit构建 sw/c/build/demo/hello_world/demo
  → --meminit=ram 进入该revision的demo_system RTL
  → 保存UART/sim-control正常输出与总线波形
  → 隔离受控variant与相同ELF/输入对照
  → typed instruction或MMIO access条件（精确register offset待源码核验）
  → rd写回或UART/MMIO可观测差异
  → 可追溯firmware/hardware artifacts与pairing manifest
```

优先复用主平台的最小寄存器实验方式；外设研究随后增加固定UART输入和中断刺激。
UART起始地址已知不等于每个offset的语义已知，DATA1不得仅凭base地址构造“发送寄存器写入”事实。
首先完成无缺陷demo执行；不要一开始同时移植743、820或改debug/PMP行为。

## Exact DATA1 acquisition plan — PRIMARY

以下均为**未来命令计划，DATA0没有执行**。仓库URL为 `https://github.com/lowRISC/ibex.git`。
现有本地完整repo可用于创建独立工作副本，避免再次下载完整历史；原仓库保持只读。

1. 固定源码：commit `405c6d1d8220a18b2f9196141167a5875422dee4`，保留vendor内容和lock、所有被引用`.core`文件、rtl、examples/simple_system、examples/sw/simple_system、util与依赖文件。
2. 固定配置：使用该commit `ibex_configs.yaml` 的 `small`；保存解析后全部参数和FuseSoC实际source list，不只保存配置名。
3. 固定环境：独立工具环境，不能修改ChipChain `.venv`。源码要求FuseSoC **2.4.3**，Verilator最低 **4.210**；它们是声明要求，不是已验证的完整组合。
   Verilator **v5.006**可作为已有官方Encarsia环境使用过的候选，但对本次较新Ibex的兼容性仍UNKNOWN，必须先确认再安装/锁定。
   RISC-V compiler要求支持RV32IMC/ILP32、裸机链接、libgcc和必要CSR扩展；工具链release/二进制SHA、最终compiler版本当前UNKNOWN。
   不把floating“latest”写进最终manifest；选定包、版本、下载大小与哈希后，再按DATA1授权获取。
4. 主机依赖：C/C++编译器、make、Python/FuseSoC依赖、libelf headers/libs；只构建ELF目标时不需要srecord的VMEM转换。
5. 首次只做一个无缺陷firmware+RTL baseline。确认可重建/装载/结束后，才建立一份受控变异研究计划或在后续明确范围中实施一个变异。

```bash
# DATA1 PLAN ONLY — 以下命令未在 DATA0 执行
# 先确保目标目录不存在；不修改原平台repo。
git clone --no-hardlinks /home/qcx/ChipChainV3_res/platforms/ibex \
  /home/qcx/ChipChainV3_res/data1/ibex-simple-system
git -C /home/qcx/ChipChainV3_res/data1/ibex-simple-system checkout --detach \
  405c6d1d8220a18b2f9196141167a5875422dee4

# 在独立、已锁定工具环境中；不要在 ChipChain .venv 安装这些依赖。
cd /home/qcx/ChipChainV3_res/data1/ibex-simple-system
fusesoc --cores-root=. run --target=sim --setup --build \
  lowrisc:ibex:ibex_simple_system $(util/ibex_config.py small fusesoc_opts)
make -C examples/sw/simple_system/hello_test hello_test.elf
./build/lowrisc_ibex_ibex_simple_system_0/sim-verilator/Vibex_simple_system \
  -t --meminit=ram,examples/sw/simple_system/hello_test/hello_test.elf
```

命令形状来自该pin官方README和Makefile，尚未在本机验证。若编译器/CSR ISA flags不匹配，应记录并修正独立实验配置，
不能静默换ISA或修改原repo。缺工具、锁依赖失败、完整参数冲突或baseline无法重现时停止扩张范围，不继续注入缺陷。

磁盘：本地源码94M已实际测量；**增量工具+构建+少量trace规划预留5–10GiB是估算，不是下载/构建实测**。
精确压缩包大小、依赖缓存和trace增长UNKNOWN。一次运行限制在一个小程序和有界cycle窗口，先记录实际占用再扩大。
单机不需要FPGA/Questa/Vivado，主流程可以全部使用开源软件。

DATA1首批产物：ELF与source/linker/disassembly identity、父commit与vendor hashes、完整RTL文件清单及内容hash、
参数/source-list/编译日志、simulator版本和构建参数、RAM加载与reset/IRQ配置、instruction log、waveform、ASCII output、结束状态、run/session ID。
原始文件放在推荐 `samples/`/`output/` 工作区或外部路径，由调用方显式写入；不改domain路径规则、不提交真实binary/runtime输出。

### XL0 pairing metadata to construct

manifest必须关联firmware case与hardware case，使用同一个明确 `platform_build_identity`（父commit + resolved dependency/configuration/source hash），
并引用build/config/loader证据IDs。golden/mutant另记录各自RTL SHA及patch SHA，以variant身份区分，不能隐藏修改后仍冒充相同RTL。
同一平台且架构/ISA/字长/字节序一致只是开始，还要保存相同ELF、memory map、reset、输入、工具与session关系。
实际CrossLayerPairManifest中的identity/evidence IDs应指向这些文件；DATA0未生成虚假的runtime pair或伪造成功记录。

## Secondary acquisition plan — Demo System

repo `https://github.com/lowRISC/ibex-demo-system.git`；父commit `d37beb753e19482eb054aefac73a27289bf72e47`。
DATA1若选择次选，先估算下载容量，做非recursive checkout；保留vendor/lowrisc_ibex、pulp_riscv_dbg、rtl、dv/verilator、
sw/c、sw/common、`.core`、flake.lock/poetry.lock/工具配置，核对实际dependency closure。
core必须是vendor lock `594ea976c9dad793f87edf91ec1c4c1df447e6dc`，debug是 `138d74bcaa90c70180c12215db3776813d2a95f2`。
使用sim目标并记录RegFile与所有未显式覆盖的vendor默认参数；不可仅锁RV32MFast/RV32BNone就称配置完整。

```bash
# DATA1 SECONDARY PLAN ONLY — 未执行；先审核下载与环境预算。
git init /home/qcx/ChipChainV3_res/data1/ibex-demo-system
git -C /home/qcx/ChipChainV3_res/data1/ibex-demo-system remote add origin \
  https://github.com/lowRISC/ibex-demo-system.git
git -C /home/qcx/ChipChainV3_res/data1/ibex-demo-system fetch --depth=1 origin \
  d37beb753e19482eb054aefac73a27289bf72e47
git -C /home/qcx/ChipChainV3_res/data1/ibex-demo-system checkout --detach FETCH_HEAD

# 独立工具环境、依赖已锁定后运行；不更新vendor或flake。
cd /home/qcx/ChipChainV3_res/data1/ibex-demo-system
cmake -S sw/c -B sw/c/build
cmake --build sw/c/build --target demo
fusesoc --cores-root=. run --target=sim --tool=verilator --setup --build \
  lowrisc:ibex:demo_system
./build/lowrisc_ibex_demo_system_0/sim-verilator/Vtop_verilator \
  -t --meminit=ram,sw/c/build/demo/hello_world/demo
```

已读取该pin的`sw/c/demo/hello_world/CMakeLists.txt`，确认target为`demo`、源文件为`main.c`并链接`common`；这仍不是执行成功说明。
CMake toolchain依赖 `riscv32-unknown-elf-*`，linker脚本位于 `sw/common/link.ld`，不是此前探测返回404的`sw/c/common/link.ld`。
选择Nix锁环境或手动锁闭Python工具其中一条，不运行浮动分支更新；确切resolved工具版本与可获取性仍需DATA1确认。
不下载Docker image，不编FPGA bitstream。完整repo大小UNKNOWN；共享工具后仍建议为增量checkout/build/trace预留5–15GiB，属于估算。
验收产物与PRIMARY相同，额外记录UART/GPIO/SPI stimulus、resource register map和debug/reset配置；不把debug访问自动视为攻击者权限。

## XL0 eligibility preview

| Candidate | Architecture / processor | Revision binding | Platform/session | DATA1后预期 |
| --- | --- | --- | --- | --- |
| Simple System | 同一RV32 Ibex/small | 父commit和vendor内容已可固定 | 尚无build/run manifest | `likely_eligible`，取得实际一致build/loader证据后 |
| Demo System | 同一RV32 vendored Ibex | 父commit+Ibex/debug locks明确 | 尚无checkout/build/session | `likely_eligible`，先完成锁闭与baseline |
| OpenTitan | 同一RV32 SecureIbex/Earlgrey | 父commit+vendor+patch+top参数 | 需明确boot/memory/OTP/session | `likely_eligible`，不代表旧guide可直接执行 |
| PULPissimo | 同一RV32IMC Ibex fork | RTL lock已知，runtime gitlink未知 | 需sim/license/config/run绑定 | `requires_more_binding_data` |
| EnCorpus Ibex +新firmware | 架构可同为RV32，但processor配置未证明一致 | corpus生成revision未知 | 缺loader/harness/程序证据 | `requires_more_binding_data`；与所选small/OpenTitan配置直接配对为`likely_ineligible` |
| Chipyard Rocket | 固定RV64 RocketConfig | 父commit已知，generator pins未知 | 缺生成RTL与ELF session | `requires_more_binding_data` |
| Chipyard BOOM | 固定RV64 SmallBoomV3Config | 父commit已知，generator pins未知 | 缺生成RTL与ELF session | `requires_more_binding_data` |

研究预判不改变XL0：UNKNOWN不当match；不同架构不自动eligible；同架构同名字不能跳过manifest。
还未生成真实positive candidate，更未证明path feasibility、runtime trigger、attacker controllability、exploitability或vulnerability。

## Risks 与 scientific limitations

最大的实际阻塞已从“找不到候选源码平台”收敛为 **PRIMARY尚无锁闭工具环境和可重现的同目标firmware/RTL baseline**。
源码身份可以固定，但compiler/Verilator版本兼容与产物一致性需DATA1执行证明。
如果研究目标限定“必须原样复用EnCorpus 743/820”，最大阻塞则是原生成revision/config/harness与可执行程序之间的身份链缺失。
不要让这项未决问题阻塞第一组独立受控Class B方法实验，也不要将独立变异伪称EnCorpus复现。

评分和空间成本为有来源的工程判断，未进行性能/工具兼容benchmark。high confidence不是运行验证。
本报告没有挑选已确认的自然CVE，没有将fault/alert/difference等同可利用漏洞。
firmware执行某指令、观察到寄存器差异、同名MMIO接口都不足以完成安全因果链；要区分必要条件、充分条件、runtime witness与可控性。

推荐DATA1范围：**一个平台、一个原样hello baseline、一个完整pairing manifest和确定性原始输出包**；
如DATA1明确包含受控实验，再增加一个最小程序和一个单点variant，保留正常/变异对照。默认不同时接入次选，不重跑EnCorpus fuzz，不进入A6或Cross-Layer Agent。

## Validation / preservation

使用本地`.venv/bin/python`完成要求的检查，生产与测试代码均未修改，因此数量与XL0基线保持一致：

```text
.venv/bin/python -m pytest -q
1064 passed, 27 skipped in 26.75s

.venv/bin/python -m pip check
No broken requirements found.

.venv/bin/python -m compileall -q src tests
exit 0

git diff --check
exit 0
```

额外做了research JSON解析、七候选必填字段/15维评分/总分一致性、唯一PRIMARY/SECONDARY、引用链接定义、
所有记录的本地source hash与新增文件空白检查；没有为文档修改新增生产或单元测试。
阶段开始保存所有tracked文件和output文件的SHA256清单，完成后核对：104个既有src文件（含XL0八模块）、
55个tests文件、81个output文件、12个reviewed文件、DOC-1九文件均字节不变；XL0文档/合同与旧架构文档也不变。
output没有新增/删除文件。四个外部Git repo的HEAD、clean状态和已记录来源文件hash再次核对通过。

轻量获取的成功raw源码/metadata响应共276,502 bytes（含重复小文件请求，不含网页导航和git ref协议流量）；
没有完整repo、archive/corpus、binary release、Docker image或工具链下载，没有build、simulation、formal/fuzz、mutation或DeepSeek调用。
Git只有`M README.md`、新增本研究文档及`data0/paired-platform-candidates.json`；未git add/commit/push/tag。
DATA0完成后停止，没有修改XL0、进入A6、Cross-Layer Agent或报告渲染层。

## 每项分数的解释

以下与registry相同；每格解释该候选的分数，不以总分代替论证。

### ibex-simple-system

| 维度 | 分数 | 依据/待补工作 |
| --- | ---: | --- |
| A | 3 | 同一仓库的 ibex_top_tracing 与 simple-system target 明确绑定。 |
| B | 3 | 本地完整 Git commit 与 vendor locks 可固定。 |
| C | 3 | 同树 hello_test、crt0、link.ld、RAM ELF loader。 |
| D | 3 | hello_test 和 common C/ASM 源码已本地读取。 |
| E | 3 | 完整 RTL 已本地存在。 |
| F | 2 | 配置与工具要求明确；没有工具链/构建成功记录，依赖仍需锁闭。 |
| G | 3 | 官方 simple-system sim target 为 Verilator。 |
| H | 3 | tracer 和官方说明明确 instruction log。 |
| I | 2 | RVFI rd write-data 可见；完整 GPR snapshot 仍需额外采集策略。 |
| J | 3 | 源码内存图及 RVFI memory fields，可结合总线 trace 检查 MMIO。 |
| K | 2 | 小核可在隔离 checkout 受控修改；没有实施。 |
| L | 2 | 可设计固定指令/寄存器条件，但必须通过未来 golden/mutant 差分验证。 |
| M | 2 | ELF和RAM初始化由实验者控制，timer IRQ 可构造；不是远程攻击者控制。 |
| N | 2 | 复用 RISC-V decode/XL0/evidence合同；Simple System trace importer 尚缺。 |
| O | 3 | 已有94MiB仓库，单核小系统；O高分表示低成本。 |

### ibex-demo-system

| 维度 | 分数 | 依据/待补工作 |
| --- | ---: | --- |
| A | 3 | 系统源码直接实例化 vendored Ibex；不是仅凭名称。 |
| B | 3 | vendor/lowrisc_ibex.lock.hjson 固定内核 SHA。 |
| C | 3 | CMake、GCC toolchain file、common MMIO header 与同一 system RTL 对应。 |
| D | 3 | 官方 C/Rust firmware sources；DATA0只读取小型文件。 |
| E | 3 | 官方 repo含 rtl、vendor；vendored checkout内容受父commit约束。 |
| F | 2 | 有flake.lock，但pip示例使用浮动ot分支，需选定并锁闭一种环境。 |
| G | 3 | 官方明确 FuseSoC Verilator sim target；无需FPGA Vivado。 |
| H | 2 | 可采波形；没有将该top误认成Simple System的现成instruction logger。 |
| I | 2 | 寄存器可通过锁定版本的内部trace/debug采集；未验证snapshot路径。 |
| J | 3 | RTL/header明确 UART/GPIO/SPI/timer地址。 |
| K | 2 | 小型开放RTL可做隔离受控变异，尚未实施。 |
| L | 2 | 固定instruction/MMIO条件可定义，效果待验证。 |
| M | 3 | UART、GPIO、timer与ELF装载可作实验输入；不自动等于attacker control。 |
| N | 2 | 复用RV32/XL0合同，需demo专用采集adapter。 |
| O | 2 | 需要新repo和依赖；预计小于完整安全SoC，实际大小未测。 |

### opentitan-earlgrey

| 维度 | 分数 | 依据/待补工作 |
| --- | ---: | --- |
| A | 3 | 同树 Earlgrey top 与 rv_core_ibex 明确连接。 |
| B | 3 | 本地commit+Ibex vendor lock+patch mapping。 |
| C | 3 | sw/device targets通过Bazel exec_env绑定同一top。 |
| D | 3 | ROM、ROM_EXT、tests与drivers源码本地存在。 |
| E | 3 | 完整 hw/vendor 与 top RTL 本地存在。 |
| F | 1 | 新版top配置与旧文档ROM/flash流程有漂移，锁文件不等于已可重建。 |
| G | 3 | 存在 chip_earlgrey_verilator 和 sim_verilator规则。 |
| H | 2 | 可采core trace/波形，具体目标开关待确认。 |
| I | 2 | RVFI/内部信号可检查；secure lockstep影响解释。 |
| J | 3 | 明确TL-UL资源图、UART等软件drivers。 |
| K | 2 | 可修改RTL但lockstep、ECC、scrambling增加干扰项。 |
| L | 2 | 可选security regression或人工条件，未验证任何自然漏洞。 |
| M | 2 | boot/UART/GPIO/SPI测试输入；OTP/lifecycle与权限需固定。 |
| N | 2 | Ibex与XL0语义可复用，但完整SoC输入适配尚缺。 |
| O | 1 | 本地512MiB源树；Bazel、交叉工具链、ROM/OTP/flash成本高于simple。 |

### pulpissimo-ibex

| 维度 | 分数 | 依据/待补工作 |
| --- | ---: | --- |
| A | 3 | tb_pulp CORE_TYPE=1明确Ibex RV32IMC。 |
| B | 3 | Bender.lock固定Ibex与pulp_soc。 |
| C | 2 | runtime USE_IBEX明确，但当前runtime HEAD不是已核实的父repo gitlink。 |
| D | 3 | pulp-runtime官方源码可得。 |
| E | 3 | PULPissimo及锁定IP源码可得。 |
| F | 1 | Bender+runtime+商业模拟器完整环境未验证。 |
| G | 0 | 该pin README明确Verilator未完成；支持Questa/Xcelium。 |
| H | 2 | RTL仿真可采instruction内部信号，当前路线需商业工具。 |
| I | 2 | 内部寄存器波形可采但没有现成ChipChain适配。 |
| J | 2 | uDMA UART/SPI/I2C等存在；精确map需锁定pulp_soc headers。 |
| K | 2 | 开源RTL允许受控变异，但商业模拟器限制复验。 |
| L | 2 | instruction/MMIO条件可研究，不等于现有验证。 |
| M | 2 | JTAG预加载L2、boot与外设输入可控制；部分flash模型非开源。 |
| N | 2 | 可复用RV32/XL0；PULP具体格式仍需新adapter。 |
| O | 0 | 许可与环境是主要成本，不适合本轮低成本主线。 |

### encorpus-ibex-compatible-firmware

| 维度 | 分数 | 依据/待补工作 |
| --- | ---: | --- |
| A | 1 | 识别到具体cellift top和参数，但原lowRISC源码commit UNKNOWN。 |
| B | 1 | 本地聚合RTL有SHA；没有生成时source commit/config manifest。 |
| C | 0 | 本地没有对应firmware/ELF或平台manifest。 |
| D | 1 | 上游wrapper有软件运行线索，本地corpus无firmware。 |
| E | 2 | 本地聚合Verilog/RTLIL存在，原始映射不完整。 |
| F | 0 | 缺生成工具锁、原formal文件绑定和运行程序。 |
| G | 1 | 官方另有Yosys/Verilator路线；本地历史结果来自Jasper，未复验。 |
| H | 1 | 采样instruction bus/ID encoding不是retirement trace。 |
| I | 2 | 现有GPR差异可以复用，仍非完整执行状态证明。 |
| J | 0 | core formal接口不是具体SoC MMIO映射。 |
| K | 2 | 可从golden/host差分研究变异，移植需要逐点验证。 |
| L | 1 | 保存的witness可供人工typed条件研究，不能自动当已验证trigger。 |
| M | 0 | formal输入不是具备loader/memory consistency的固件输入。 |
| N | 3 | 既有743/820 ingestion/A3/B2可读历史证据。 |
| O | 1 | 原文件已有但追溯和转换成本不确定。 |

### chipyard-rocket

| 维度 | 分数 | 依据/待补工作 |
| --- | ---: | --- |
| A | 3 | 命名Config明确选择处理器generator。 |
| B | 2 | 父commit已固定；generator gitlink SHA因metadata访问限制未核实。 |
| C | 2 | tests/hello.riscv与模拟器loader有官方绑定路线，需固定全部generator和工具链。 |
| D | 3 | 官方bare-metal tests源码可得。 |
| E | 3 | 公开Chisel generators及生成RTL路线。 |
| F | 1 | 需要JDK/Scala/依赖、工具链、submodule锁；尚未构建。 |
| G | 3 | 官方Verilator执行兼容RV64 ELF。 |
| H | 2 | 支持commit/trace/debug波形路线，需固定配置。 |
| I | 2 | 内部寄存器和commit状态可采，未实现adapter。 |
| J | 2 | SoC总线与外设可观测，但当前EnCorpus core harness没有同一映射。 |
| K | 2 | 可修改generator或受控RTL，重新生成和配置成本高。 |
| L | 2 | 可定义受控指令条件，需真正差分执行验证。 |
| M | 2 | bare-metal ELF、内存、interrupt/test harness输入可控，不证明远程可控。 |
| N | 1 | XL0合同可复用，RV64及Rocket/BOOM证据adapter尚缺。 |
| O | 0 | 完整Chipyard工具链/生成系统昂贵；非DATA1首选。 |

### chipyard-boom

| 维度 | 分数 | 依据/待补工作 |
| --- | ---: | --- |
| A | 3 | 命名Config明确选择处理器generator。 |
| B | 2 | 父commit已固定；generator gitlink SHA因metadata访问限制未核实。 |
| C | 2 | tests/hello.riscv与模拟器loader有官方绑定路线，需固定全部generator和工具链。 |
| D | 3 | 官方bare-metal tests源码可得。 |
| E | 3 | 公开Chisel generators及生成RTL路线。 |
| F | 1 | 需要JDK/Scala/依赖、工具链、submodule锁；尚未构建。 |
| G | 3 | 官方Verilator执行兼容RV64 ELF。 |
| H | 2 | 支持commit/trace/debug波形路线，需固定配置。 |
| I | 2 | 内部状态可采；BOOM物理寄存器不可直接等同架构寄存器。 |
| J | 2 | SoC总线与外设可观测，但当前EnCorpus core harness没有同一映射。 |
| K | 2 | 可修改generator或受控RTL，重新生成和配置成本高。 |
| L | 2 | 可定义受控指令条件，需真正差分执行验证。 |
| M | 2 | bare-metal ELF、内存、interrupt/test harness输入可控，不证明远程可控。 |
| N | 1 | XL0合同可复用，RV64及Rocket/BOOM证据adapter尚缺。 |
| O | 0 | 完整Chipyard工具链/生成系统昂贵；非DATA1首选。 |

## Source index

正文链接均固定到所检查commit，避免master漂移。registry保存本地文件及已获取raw metadata的大小/哈希/URL和失败探测；不保存网页全文或实际研究样本。

[ibex-tree]: https://github.com/lowRISC/ibex/tree/405c6d1d8220a18b2f9196141167a5875422dee4
[simple-readme]: https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/examples/simple_system/README.md
[simple-rtl]: https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/examples/simple_system/rtl/ibex_simple_system.sv
[simple-make]: https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/examples/sw/simple_system/common/common.mk
[simple-config]: https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/ibex_configs.yaml
[simple-hello]: https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/examples/sw/simple_system/hello_test/hello_test.c
[simple-tracer]: https://github.com/lowRISC/ibex/blob/405c6d1d8220a18b2f9196141167a5875422dee4/rtl/ibex_tracer.sv
[demo-tree]: https://github.com/lowRISC/ibex-demo-system/tree/d37beb753e19482eb054aefac73a27289bf72e47
[demo-lock]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/vendor/lowrisc_ibex.lock.hjson
[demo-readme]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/README.md
[demo-debug-lock]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/vendor/pulp_riscv_dbg.lock.hjson
[demo-rtl]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/rtl/system/ibex_demo_system.sv
[demo-header]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/sw/c/common/demo_system.h
[demo-toolchain]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/sw/c/gcc_toolchain.cmake
[demo-cmake]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/sw/c/CMakeLists.txt
[demo-core]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/ibex_demo_system.core
[demo-pyreq]: https://github.com/lowRISC/ibex-demo-system/blob/d37beb753e19482eb054aefac73a27289bf72e47/python-requirements.txt
[ot-lock]: https://github.com/lowRISC/opentitan/blob/16e86c9e031d52760780ac4efddaab2389bdb94b/hw/vendor/lowrisc_ibex.lock.hjson
[ot-vendor]: https://github.com/lowRISC/opentitan/blob/16e86c9e031d52760780ac4efddaab2389bdb94b/hw/vendor/lowrisc_ibex.vendor.hjson
[ot-top]: https://github.com/lowRISC/opentitan/blob/16e86c9e031d52760780ac4efddaab2389bdb94b/hw/top_earlgrey/data/top_earlgrey.hjson
[ot-tests]: https://github.com/lowRISC/opentitan/blob/16e86c9e031d52760780ac4efddaab2389bdb94b/sw/device/tests/BUILD
[ot-verilator]: https://github.com/lowRISC/opentitan/blob/16e86c9e031d52760780ac4efddaab2389bdb94b/doc/getting_started/setup_verilator.md
[pulp-lock]: https://github.com/pulp-platform/pulpissimo/blob/bfc3d9a1ef72443464509a22d948f0a6f5b65b4c/Bender.lock
[pulp-tb]: https://github.com/pulp-platform/pulpissimo/blob/bfc3d9a1ef72443464509a22d948f0a6f5b65b4c/target/sim/tb/tb_pulp.sv
[pulp-readme]: https://github.com/pulp-platform/pulpissimo/blob/bfc3d9a1ef72443464509a22d948f0a6f5b65b4c/README.md
[pulp-runtime-config]: https://github.com/pulp-platform/pulp-runtime/blob/3b48b0c6872cc01ba169a2c9c886ebb815d22cdc/configs/pulpissimo_ibex.sh
[encarsia]: https://github.com/comsec-group/encarsia/blob/b8fd17d9e72b052ed6dfd127956239b49c8fb3a1/Readme.md
[encarsia-docker]: https://github.com/comsec-group/encarsia/blob/b8fd17d9e72b052ed6dfd127956239b49c8fb3a1/Dockerfile
[encarsia-designs]: https://github.com/comsec-group/encarsia/blob/b8fd17d9e72b052ed6dfd127956239b49c8fb3a1/cascade_design_repos.json
[encarsia-ibex-make]: https://github.com/encarsia-artifacts/encarsia-ibex/blob/bd823812cd5bd925f7671c49f3f6a7a63d2ace4b/cellift/Makefile
[encarsia-ibex-sva]: https://github.com/encarsia-artifacts/encarsia-meta/blob/756ba14fbd9cbe29df00a157da29eee424f3c64a/jasper/ibex/v_miter.sva
[encarsia-rocket-sva]: https://github.com/encarsia-artifacts/encarsia-meta/blob/756ba14fbd9cbe29df00a157da29eee424f3c64a/jasper/rocket/v_miter.sva
[encarsia-boom-sva]: https://github.com/encarsia-artifacts/encarsia-meta/blob/756ba14fbd9cbe29df00a157da29eee424f3c64a/jasper/boom/v_miter.sva
[cascade-rocket]: https://github.com/cascade-artifacts-designs/cascade-chipyard/blob/727a99a3f917f61d7de818de5100f905f31d7bc8/cascade-rocket/Makefile
[cascade-boom]: https://github.com/cascade-artifacts-designs/cascade-chipyard/blob/727a99a3f917f61d7de818de5100f905f31d7bc8/cascade-boom/Makefile
[chipyard-sim]: https://github.com/ucb-bar/chipyard/blob/371ab92dd09917b6ab05d58bf762b173c52f4224/docs/Simulation/Software-RTL-Simulation.rst
[chipyard-rocket-config]: https://github.com/ucb-bar/chipyard/blob/371ab92dd09917b6ab05d58bf762b173c52f4224/generators/chipyard/src/main/scala/config/RocketConfigs.scala
[chipyard-boom-config]: https://github.com/ucb-bar/chipyard/blob/371ab92dd09917b6ab05d58bf762b173c52f4224/generators/chipyard/src/main/scala/config/BoomConfigs.scala
