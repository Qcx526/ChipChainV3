# R3 — Rocket RTL Reproduction & Evidence Feasibility V1

本阶段从 `41441e79fa7d38cc4b103738eafd5eae38ac3419` /
`v3-qemu-runtime-evidence-v1-stable` 开始；annotated tag object 为
`e2ea7c237e117769c8f8ad2555c5adef629c1159`。开始时唯一 untracked 输入为
`samples/rtl-input/Benchmarks.zip`，已先添加忽略保护。没有重置工作区或修改 stable tags。

所有以下 JSON/log/第三方源码/仿真 binary 均在 ignored
`output/rtl-rocket-feasibility/`，只是 feasibility/diagnostic artifacts，
不是新的 HardwareRuntimeEvidence、HardwareBehaviorContract 或 verified chain。

## A. 输入及源码审查

用户 ZIP SHA256：
`987d8f81bd36567418afa9473864c54dba34532e979fcae35d99428c7bc97287`。
每个成员在使用前核对原始解压字节 SHA，原 ZIP 未修改或重新打包。

| 成员 | SHA256 | modules / textual top ports |
| --- | --- | --- |
| RocketTile_latest.v | `508717f1a3af02f235633f20d274048e19bbb89d702d5d736cc7c1dc181ea188` | 68 / 94 |
| RocketTile_new.v | `403e40fcc7a76862df7c3c73554b080c79d94824894d02b214fa245c0830119d` | 68 / 91 |
| RocketTile_state.v | `77f8abcf13b64642d24142fa58c227362c3d1ee274cded9028f82d5fec10055c` | 79 / 75 |

三份 top 均为 `RocketTile`。ports 数是未展开 preprocessor 的源码 inventory，
不是 elaborated pin 数。包含 TileLink A–E、32-bit address / 64-bit data、reset vector、
interrupt/hart ID 及插桩控制。latest/new 有 cmt_instr/eos；state 接口不同，不能直接互换驱动。
它们是 RocketTile 加内部模块和插桩，未提供完整 SoC/UART 外部输入。
源码有 CSR/TLB/PTW/FPU 线索，但没有可认证的完整 Chisel/FIRRTL generation 配方、
处理器参数 manifest 或历史 run revision。不能从文件名 latest 推断实际硬件版本。

官方 ProcessorFuzz checkout 固定为
`2d08d0d8b4563212175212f9db0e69f6e68c9619`：
[upstream](https://github.com/bu-icsg/ProcessorFuzz/tree/2d08d0d8b4563212175212f9db0e69f6e68c9619)。
用户 new/state 与对应 upstream 文件字节相同；用户 latest 与 upstream latest
（SHA `198b3f10933d64b16a5b4d2502a55cc663d667d1a012cffa4dbed61f40aa3c8c`）不同。
四个文本差异块增加八个 PMP-config wire/assign 和普通/exception `$fwrite` 的
CSR/PMP/GPR/FPR payload。此差异审查不等于已证明 elaborated 行为等价。
选择用户提供的 latest，未替换成网上同名材料，未更改 processor logic。

只读 inventory/比较记录：
`input/input-inventory.json`、`input/official-rtl-comparison.json`。

## B. 原始程序和装载策略

原硬件包 `samples/processorfuzz/real_case_001/raw/testis.zip` SHA：
`c0fe4e328be70238cfd7383fe3cc9b58267eeafc0795d1dbb8b4b074ad69df34`。
本轮使用其 `testis/out/tests/.input_1.elf`，SHA：
`649da678efb42c1224e1ddb1b37c43561b56ba522d75b2ac5b77a06d5b0cbc86`。
它是 hardware-supplied trigger-test firmware，不是客户固件；没有用独立合成 FW-POS 替代。

原 native HEX 按 64-bit little-endian words、基址 `0x80000000` 解码后，与全部八个
PT_LOAD file-backed ELF 范围精确匹配。原 symbols 与 ELF symtab 一致；SI 的 384 个 data
words 与六个 ELF random-data 区域一致。这只验证这些字节关系，完整 SI assembly→ELF
build provenance 仍 UNKNOWN。

复用官方 `RTLSim.host.rvRTLhost` 和完整 TileLink adapter，独立 wrapper 绕过随机生成、
Spike transition gating 及成功后删除产物的 fuzz outer loop。代码由 native HEX 装载，
symbols/random data 从实际 ELF 读取。BootROM 为 driver 的固定 64 bytes、位于 `0x10000`，
跳转至 `0x80000000`。signature/tohost 初始清零，六个 random-data 区域使用 ELF 字节，
测试中不注入 interrupts。原 SI 输入不被当成 UART/网络用户输入。

入口 `_start=0x80000000`；`_end_main=0x80000ae0`。upstream loop 的 stop 参数为
`_end_main+36=0x80000b04`，8-byte 装载实际到 `0x80000b07`，exclusive end 为
`0x80000b08`。tohost=`0x80001000`；signature=`0x80002000..0x800023e0`。
helper 要求 PT_LOAD physical/virtual identity，记录 top inputs 初值、reset 两段各五周期、
max_cycles、random seed、精确源码及 generated model binary。

## C. Trace 的可解释范围与 ChipChain 对接

latest trace 打印 HartID、mode、PC、instruction、conditional WDATA 以及扩展内部状态。
短 header 仍写 `HartID mode PC INSTR WDATA COV`，但第六 token 是 `mstatus_wire`，
真实 coverage 在后面；没有 cycle index。必须按选定 RTL 的打印表达式解释字段，不能按
这个旧 header 给 CSR 状态重命名，也不能把 row index 当作 cycle。

普通记录在 posedge clock、`coreMonitorBundle_valid & ~core.reset` 下产生。
该 valid 通过 CSR trace 连到 core retire 信号并排除 exception；exception 使用独立分支。
这是指定 monitor 的 RTL 观测，不等于独立验证了每条指令的全部完成效果。
状态打印读取该 edge active-region 的值，不能自动称为 NBA 更新后的 CSR snapshot。
WDATA 可为零/DEADBEEF sentinel，delayed/FP writes 需要独立解释。

| 对接步骤 | 当前客观来源 | 缺口/允许结论 |
| --- | --- | --- |
| RTL raw observation | 原始 monitor trace/signature、exact RTL bytes、实际 simulator/driver | 只限本轮新运行及打印 scope |
| source/revision binding | RTL SHA、driver commit、loader policy、binary、reset/seed/bounds | 原包历史 RTL revision 仍 UNKNOWN |
| trigger requirements | HBC 已能表达指令/CSR/order/privilege/pre-state | 本案具体 trigger 及其 specification 来源未建立 |
| deviation observation | 原始 signature words 和条件性 ELF 输出槽 | reference configuration 等价、值采样绑定、规范预期缺失 |
| Type-II verification | 冻结 controlled-Ibex MMIO golden path | 不适用于当前 Rocket 数据，不能自动调用获得链条 |

未来最小 RTL evidence adapter 必须明确 run/reset epoch/cycle、normal/exception kind、
sampling phase、对应信号/CSR/内存事务、完整有效窗口和 independently bound reference。
保持共享科学模型中立，在 Rocket backend/profile 中解释这些信号。QEMU callback 类型不能
包装 RTL 来源；本轮不增加 ARM/PPC 假后端，也不修改 CAP0/MMIO/Type-II/QEMU 科学契约。

## D. Spike 实际参考执行

官方 submodule 指定的 all-CSR modified Spike 固定 commit：
`3343b9d07ae02b3aee5b3e6137cadb55b6d732ff`，版本 `1.0.1-dev`：
[source](https://github.com/sammy17/riscv-isa-sim-all-csr/tree/3343b9d07ae02b3aee5b3e6137cadb55b6d732ff)。
source 未改动。缺少 dtc/Boost headers，通过配置好的 Ubuntu archive 下载 `.deb` 并在
output sysroot 解包；没有 sudo/global install。初始 -O0 导致旧 static-constexpr ODR 链接
问题，只将 processor.cc 按 upstream optimization 以 -O2 重编后链接成功，保留失败日志。
完整配置、构建命令和 package/binary SHA 在 `spike-build/build-manifest.json`。

两次真实执行 exact original ELF，exit 0，用时 `0.030034s` / `0.033116s`。
Trace 5472 行、367677 bytes，SHA：
`580ab70b7c680ceeab3d8eacbe01944161921988be33428504fe1138a84d66d8`。
Signature 254 行、8382 bytes，SHA：
`3f9463d3d49f73942396edc67223269ab004e05042e58579c51805f797f80a37`。
两次 trace/signature/stdout/stderr 逐字节一致，新 signature 与原包 ISA signature 完全相同。
这不认证历史 Spike revision 或历史同次运行。该 modified reference 存在 CSR/trap/interrupt
行为改动，Rocket 与 reference 的 architecture configuration 等价仍待验证。

实际命令（完整绝对 argv 在 invocation.json）：

```bash
output/rtl-rocket-feasibility/spike-build/spike --isa=RV64IMAFDC \
  -m0x80000000:0x800000 -l \
  --log=output/rtl-rocket-feasibility/spike-reference/isa-trace.log \
  --log-commits \
  +signature=output/rtl-rocket-feasibility/spike-reference/isa-signature.txt \
  output/rtl-rocket-feasibility/spike-reference/original-trigger-test.elf
```

## E. 本轮执行记录

实际 Rocket 构建、执行和剩余缺口按同目录 `rtl-run-manifest.json` /
`rtl-run-summary.json` 分开记录。编译成功不能替代 clocked testbench execution；
非空/header-only trace 不能替代 ELF-entry byte binding；prefix 观测和正常完成分字段表达。
运行失败、trace 缺失或 source conflict 都不会生成已验证硬件结论。

## F. 实际 Rocket RTL 构建与执行

最初检测到本机 Verilator 4.210，尝试与 cocotb 1.9.2 配合时，生成的 C++
harness 调用了该版本模型没有的 `eventsPending` API。切换旧版 cocotb 后虽可编译，
但未完成测试输入执行，故没有将这些尝试标为成功。失败日志保留在 `run-latest-001` 至
`run-latest-005`。之后从 Verilator 官方源码固定 `v5.008` / commit
`21093fd1bd36fed8943f67868ddc8f75f41e4488`，在 output 内构建安装；
helper 初次受环境中的 `VERILATOR_ROOT` 干扰，修正为使用安装 wrapper 自带路径。
没有修改用户 RTL、官方 driver 源码或全局工具环境。

有效环境：Verilator `5.008`（可执行文件 SHA
`cd091236fa07f55cd0865af5eee1e2c47d14e3e83aa9ff43ac2ab816bcecf894`）、
Python `3.12.14`、cocotb `1.9.2`、cocotb-bus `0.2.1`、GCC/G++ `11.4.0`。
Verilator 构建记录在 `environment/verilator/build-manifest.json`；
运行环境在 `simulator-environment.json`。所需旧版 `help2man` 及 Spike 的 dtc/Boost
只提取到 output sysroot，均未用 sudo 安装。

最终两次完整独立复跑 `run-latest-009` / `run-latest-010` 分别构建实际模型、启动
cocotb、驱动 TileLink 并运行同一原始 trigger-test ELF。每次的完整绝对 build/run
argv 在对应 `rtl-run-manifest.json` 的 `commands`；可复跑的显式 CLI 参数在
[实验说明](../../experiments/rtl/rocket/README.md)。009 的构建/运行 argv 对应如下
shell 命令；010 仅将输出目录改为 `run-latest-010`：

```bash
cd /home/qcx/ChipChainV3/output/rtl-rocket-feasibility/run-latest-009
make -f /home/qcx/ChipChainV3/output/rtl-rocket-feasibility/run-latest-009/Makefile \
  SIM=verilator \
  VERILATOR_BIN_DIR=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/environment/verilator/install/bin \
  TOPLEVEL_LANG=verilog TOPLEVEL=RocketTile \
  VERILOG_SOURCES=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/input/Benchmarks/Verilog/RocketTile_latest.v \
  MODULE=reproduction_test COCOTB_HDL_TIMEUNIT=1us COCOTB_HDL_TIMEPRECISION=1us \
  BUILD_ARGS=-j2 \
  'PLUSARGS=+DEBUG=0 +TRACE=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/run-latest-009/raw/' \
  PYTHON_BIN=/home/qcx/ChipChainV3/output/rtl-rocket-feasibility/environment/venv/bin/python \
  PYTHONHOME=/usr sim_build/Vtop
# 相同参数，在同一工作目录再次调用，以 sim 替代 sim_build/Vtop。
```

Makefile 中的确切
编译参数为 `-DPRINTF_COND=0 -DSTOP_COND=0 -Wno-PINMISSING -Wno-fatal`。

| 实际运行 | BUILD_PASSED | SIMULATION_EXECUTED | SOURCE_BOUND_EXECUTION | build / simulation wall time | 正常停止 |
| --- | --- | --- | --- | --- | --- |
| 009 | yes | yes | yes（仅限本轮指定来源） | 72.337s / 2.087s | tohost observed, adapter drained; exit 0 |
| 010 | yes | yes | yes（仅限本轮指定来源） | 72.095s / 2.136s | 同上；exit 0 |

两次均通过 cocotb 1 个 test，clock 上升沿计数 1394，仿真时间 2,786,000 ns，
coverage counter 667。相同的 source-defined monitor 共 325 条普通指令记录、
1 条 exception 记录、35 条 header/不透明记录，原始 trace 总计 361 行、533,144 bytes；
其中正常记录的 ELF entry PC 与确切指令字节匹配。`raw/driver-result.json` 记录
tohost 正常完成，`raw/simulation.{stdout,stderr}.log` 保留全部过程和警告。
trace 不能因行数推断全部指令完成，exception 和 CSR/WDATA 列仍须按 RTL 源码解释。

两次从零构建的模型 SHA 同为
`b7ecff6e30a07df245fe46ba43ae55392ef8c6016b7825a3101c7f60eeaff669`；
trace SHA 同为 `9d544798195d86791643c3b3e7c58efd75798229b2a52d0debd7a873e2ac93f9`；
RTL signature 均为 254 行、8,382 bytes，SHA 同为
`e14bcb08de2e6d62ee0368aa4d244375ca1e64178392b39f5b4866d25f577513`。
运行工具源码、test wrapper 与 driver status 也逐字节一致。相同输入得到相同的
**诊断配置身份** `rocket-feasibility:4faea5a11f78fa56b36e32d025b7d5cadccad58b541e638ab91a1f2dd8c65f26`；
009/010 仍是不同的实际执行，其独立 raw 文件及 argv 分别保存，不能把配置身份
误作同一次物理运行的 ID。

## G. real_case_001 复现结果及科学边界

新生成的 RTL signature 与原包 `.rtl_sig_0.txt` **逐字节相同**；新 Spike signature
与原包 `.isa_sig_0.txt` **逐字节相同**。把本轮新 RTL 与新 Spike 的 254 个
128-bit raw words 按索引比较，仍恰有 37、44、48 三个不同，索引和值均与原包一致：

| word index | RTL raw | Spike raw |
| --- | --- | --- |
| 37 | `80000002000460000000000000000000` | `00000002000420000000000000000000` |
| 44 | `000000000000b1098000000a00046000` | `000000000000b1090000000a00042000` |
| 48 | `00000000141416730000000000000002` | `00000000000000000000000000000002` |

这些是**真实运行得到的 raw signature 差异复现**，并非单元测试或 expected JSON
回放。然而原包内部的 RTL revision SHA、原始构建配置、Spike revision、
reset/interrupt/random-data 同次来源仍未认证；本轮选定 Verilator/Spike 的处理器配置
等价及规范预期也没有建立。因此 `architectural_differential = UNKNOWN`，
`hardware_trigger = NOT_ESTABLISHED`、`hardware_deviation = NOT_ESTABLISHED`，
ProcessorFuzz Type-II 为 `NOT_VERIFIED`。不由这些 raw 差异推断 TLB bug、
`sfence.vma` 因果、客户固件可触发性、攻击者控制、FPGA 或硅片行为。

原包 `note.log` 继续 UNBOUND；`disassembly.asm` 与 ELF 指令字节冲突，
继续拒绝作为权威来源。条件性的输出槽符号映射见 `evidence-audit.json`，
不能倒推出原包历史 run 的来源绑定。原 SI 的随机数据与 ELF 字节有关联，
但完整 SI→ELF 构建链仍 UNKNOWN。新 run 的来源级别仅为指定用户 RTL 字节、
所记录的驱动/编译配置、实际 ELF/HEX 与其正常执行记录；没有给历史包补造 provenance。

## H. 验证、冻结保护与下一步

新增的 synthetic 单测覆盖 ZIP 路径/成员/哈希安全、显式 RTL 选择和歧义、
ELF/HEX identity、缺 trace/错误入口/异常记录、执行与完成状态分离、
raw 差异不升级为科学结论、失败报告及 case-name 独立性。离线 pytest 不启动大仿真，
上述两个 Verilator smoke 是另行显式执行的。

冻结科学对象和 golden IDs 保持不变。P1、N1、N2、U1 分别是：

```text
P1 type2-verification:9c7ef89582f89727fcacdb6b8bb7334ba79733c4182a6e7b341ba324e2fa6b82
N1 type2-verification:7dc13746b7067f7ce4adf6cc11ba8eeeb01a3b2582b7a2456b005704772477e7
N2 type2-reference-control:2d1ae9b25f06e6009e54b2081253ad93da1b3f8c1d91e942fd4ef6ed7dea28ab
U1 type2-verification:21db55b0e4ddb2f545e57ebb731f09bd7bd1b6b465dbe4c63f4c49bd07dd526a
```

只有 `.gitignore`、根 README 及本阶段独立的 research/experiment/script/test 文件变化；
没有更改冻结 Type-II、CAP0、MMIO、QEMU 或 ProcessorFuzz sample/expected。
最终 `CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q` 为
**`590 passed in 68.08s (0:01:08)`**。`pip check` 输出
`No broken requirements found.`；`compileall -q src tests scripts experiments/rtl/rocket`
和 `git diff --check` 均 exit 0、无输出。

`audit/protected-result-final.json` 对开工时保存的 261 个原始/科学输入 SHA
重新核对：**0 个改变**；369 个原 tracked 文件基线中只有预期的根 README 改变
（`.gitignore` 的 ignore 行在该快照前已建立，单独由 Git diff 核对）。
原 ZIP `Benchmarks.zip` 与 ProcessorFuzz `testis.zip` SHA 分别仍为
`987d8f81bd36567418afa9473864c54dba34532e979fcae35d99428c7bc97287`
和 `c0fe4e328be70238cfd7383fe3cc9b58267eeafc0795d1dbb8b4b074ad69df34`。
`git diff --stat` 对 tracked 内容只有 `.gitignore` 3 行、README 2 行；
新增 research/experiment/script/test 文件仍 untracked。没有执行 git add/commit/push/tag。

下一阶段优先做 **RTL source-binding hardening**：获取并认证原硬件部门历史 RTL
revision、build/testbench/Spike 配置与同次采集清单，再为新执行定义明确的
reset epoch、cycle、采样阶段、CSR/内存字段及独立 reference 配对。做到这些且有规范
支撑的 deviation predicate 后，才评估是否创建正式 RTL Hardware Evidence。
当前可以保留这个可复现的负边界，不生成 HardwareBehaviorContract 或 verified chain。
