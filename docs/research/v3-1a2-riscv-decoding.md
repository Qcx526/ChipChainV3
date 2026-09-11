# V3-1A2 — Deterministic RISC-V Instruction Decoding

本阶段在 `v3-1a1-stable` 上增加确定性解码；只读使用已有 EnCorpus Ibex driver 材料。
743 的三条已识别 host instruction encoding 全部成功解码，820 仍为零条。
没有调用模型、读取 `.env`、安装 provider、重跑 formal/fuzz、重建 Ibex 或执行 synthesis。
本轮在 A2 停止，未实现 V3-1B，也不新增 A3。

## Backend 与依赖

采用 [Capstone 5.0.9 stable release](https://github.com/capstone-engine/capstone/releases/tag/5.0.9)，
项目依赖为 `capstone>=5.0.9,<6`。没有自行实现完整 decoder，没有启用 6.x prerelease。
adapter 使用公开的 `Cs`、`CS_ARCH_RISCV`、`CS_MODE_RISCV32` 和 RISC-V operand enums；
`detail=True` 在 5.0.9 下可以稳定提取本阶段所需的 register/immediate/memory operands。
运行时另拒绝低于 5.0.9、6.x 和 prerelease，以免已有错误环境绕过项目安装约束。

本机和 fresh venv 的 distribution metadata 均为 **5.0.9**。该 wheel 的
`capstone.__version__` 实际返回 **5.0.7**，`capstone.cs_version()` 返回 `(5, 0, 1280)`。
因此 ToolDescriptor 使用 `importlib.metadata.version("capstone")` 记录实际安装发行版，
不把旧模块常量误报为 resolver 结果，也不把 native API tuple 解释成 patch 版本。
Capstone metadata 的 `Requires-Python` 为 `>=3.8`；项目仍要求 Python `>=3.11`。
本轮实测 Python **3.12.13**；没有声称测试过所有允许的 Python 版本。

## ISA、stage 与 compressed 边界

当前仅声明 **Ibex / RV32**。共享 `ibex/ibex/reference.v` 的 core 参数
（1425–1427 行的 RV32E/RV32M/RV32B）和 A1 核对的 32 位 GPR 布局支持 RV32 假设。
这些源码包含多处可覆盖参数；本轮不建立完整 elaboration/configuration resolver，
不把默认参数当成每个 mutant 已启用的完整扩展列表，不对外固定 `RV32IMC`。
三个实测 word 均属于基础整数指令；解码成功不证明目标实现启用了 backend 认识的每个扩展。

本轮直接核对共享 RTL 的 6294–6373 行：

- `compressed_decoder_i` 将 `if_instr_rdata` 转换为 `instr_decompressed`。
- `instr_out` 选择 `instr_decompressed`，或在启用 dummy 配置时选择 `dummy_instr_data`。
- `instr_rdata_id_o` 与 `instr_rdata_alu_id_o` 均锁存 `instr_out`。
- 原始低 16 bits 另存于 `instr_rdata_c_id_o`，原始 compressed 标志另存于
  `instr_is_compressed_id_o`；它们不是 A1 当前 instruction observation 的输入。

因此 A1 两个 ID alias 标注 `encoding_representation=decompressed_word`，表示解压之后的
pipeline word 路径（不声称每条原始指令都是 compressed，也不识别 dummy 来源）。
`instruction_width_bits=32` 是当前被解释的表示宽度，**原始 fetch 长度仍未知**。
不启用 `CS_MODE_RISCVC`，不尝试对 32 位信号拆半、扫描或恢复原始 C encoding。
测试中的 16 位 compressed word 只用于验证明确拒绝，不代表正式支持 C。

A1 原有提取条件完全保留：known 32-bit encoding/PC、`instr_valid_id_q=1`、
`instr_executing=1`，仍按既有规则报告 ID-stage encoding changes。
signal、time、stage、valid/executing/PC 的原 EvidenceRef 均保留。
信号名中的 executing 与有效门控仍不足以证明这条指令完成执行、提交或退休。
decoder 解释的是给定编码，不增加 executed/committed/retired/triggered/caused-divergence 结论。

## 输入与架构边界

```text
A1 EnCorpus ingestion identifies a host instruction observation
→ InstructionEncoding (architecture-neutral)
→ RiscVInstructionDecoder (tool adapter; Capstone lives here)
→ DecodedInstruction
→ enrich the existing instruction ProcessorBehavior
```

decoder 不读取 VCD/RTL，不猜测 signal，也不读取 oracle。
通用 `decode(InstructionEncoding)` 可供其他已经建立编码身份和表示的 RISC-V producer 使用。
Ibex typed observation 的转换位于 tool adapter；domain 不含 Capstone classes。
未创建 ARM/PowerPC 空实现或通用多架构框架，未来 backend 不由 domain 锁定。
当前 adapter 只归一化整数 GPR，不支持浮点寄存器或完整 ISA AST。

## 字节序

VCD 文本是 MSB-first bit-vector。先按二进制整数解释，再用
`to_bytes(4, byteorder="little", signed=False)` 交给 Capstone。
依据 [RISC-V instruction-length encoding / instruction parcels](https://docs.riscv.org/reference/isa/v20250508/unpriv/intro.html)，
指令流按 little-endian 16-bit parcels 排列，低编号 instruction bits 位于低地址；
这与目标数据访问端序是不同属性。不能直接把 VCD 的十六进制显示顺序当成 memory bytes。

| Word | 传给 backend 的 bytes |
| --- | --- |
| `0x00130e13` | `13 0e 13 00` |
| `0x00001537` | `37 15 00 00` |
| `0x007e2503` | `03 25 7e 00` |

转换函数有 rationale 注释和独立 known-answer tests；宽度不匹配或含 x/z 不进行字节转换。
使用 PC=0 做单条解码，不计算 runtime branch target；branch immediate 保留 backend 的 offset 含义。

## 合同、operands 与 identity

`InstructionEncoding` 保存 observation ID、architecture、原 MSB-first bits、width、representation、
source stage 和 evidence。长度校验只约束 bit-vector 自洽，不验证文件或推断硬件执行。

`DecodedInstruction` 保存 observation ID、architecture、raw encoding、表示宽度、representation、
source stage、status/reason、mnemonic、canonical operand text、backend display text、
最小 ordered operands、ToolDescriptor、decoder mode 和原 EvidenceRef。
新结果的 epistemic status 为 `derived`，仅指编码解释；原 observation/behavior status 不改变。

稳定 operand detail 足以实现 register、immediate、memory 三种形状。
Python/默认 JSON 字段 `register_name` 存放 canonical identity；构造时亦接受 `register` alias。
整数寄存器始终使用 `x0`–`x31`，memory 使用 canonical base + signed displacement；
立即数为整数，canonical display 使用十进制。`backend_operand_text` 单独保留 ABI 名称显示，
例如 `a0, 7(t3)` 对应 `x10, 7(x28)`，不会创建第二个寄存器 identity。

这些是 backend 的 ordered operands，不是隐式寄存器全集或 read/write effect 列表。
保留 Capstone 的 instruction aliases：例如 `nop` 没有 operands，某些 `jal` 显示省略隐式 x1。
LUI 的 immediate `1` 表示编码中的 upper immediate field，不是最终写入值 `1`；对应移位值为 `0x1000`。
不从这些 operands 生成 memory access/control transfer behavior、CFG、SSA、读写集或 trigger hypothesis。

后续匹配可以使用 architecture + representation + width + raw encoding，以及 canonical GPR identity。
observation/behavior ID 标识的是已有观察事件，同编码在不同时间仍可有不同 identity。
不能单独用 mnemonic 字符串证明语义等价；原始 C 指令和解压 word 的跨表示匹配、alias 统一、
隐式 operand/访问语义不属于当前保证。

## 失败与 enrichment

| Status | 当前含义 |
| --- | --- |
| decoded | 配置 backend 解出完整 32-bit word，所需 operands 可归一化 |
| unsupported | 当前 architecture/width/operand/backend 不支持；不能据此断言 ISA 全局非法 |
| invalid | 可确定的格式冲突，例如 illegal all-zero 或宣称解压后的 word 却不具备 32-bit 前缀 |
| unknown | 原始 bits 含 x/z，或 producer 尚未建立 representation |

失败保留 raw encoding、observation ID、EvidenceRef、stage/width、工具版本和 reason；
没有 mnemonic/operands 的猜测，也不丢掉原 instruction observation。
旧 A1 JSON 缺少 representation 时默认 unknown；不会为了得到 mnemonic 而按信号名称猜测。

`enrich` 深拷贝 batch，只把 decoded result 附着于已有 instruction behavior；
behavior ID、attributes、summary、evidence、role 和 epistemic status 保留。重复 enrich 不增加 behavior。
若输入 instruction observation 缺少唯一对应 behavior、架构不符或已有 raw encoding 冲突，
明确抛出合同错误，不静默选一个行为；原 batch 不被改动。这不同于合法输入的 decode failure status。
A1 unresolved questions 保留为 ingestion 阶段限制，文案明确限定为 A1 alone。

## 显式调用

```python
from pathlib import Path
from chipchain.domain.behavior import ProcessorBehaviorIR
from chipchain.tools.architecture import RiscVInstructionDecoder
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer

sample = Path("/path/to/ibex/ibex/driver/743")
ingested = EnCorpusIbexDriverAnalyzer().ingest(sample)
decoder = RiscVInstructionDecoder()
host = decoder.enrich(ingested.observations)
ir = ProcessorBehaviorIR(
    case_id=host.case_id,
    behaviors=[behavior for obs in host.observations for behavior in obs.behaviors],
)
```

原 `ingested` 保持不变；`host` 与 `ir` 是调用方明确选择的 enriched 输出。
不自动把 oracle 合并到 host，不自动调用 Agent/workflow，不自动写文件。
如需 AnalysisRun 的 tools provenance，调用方可传入 `decoder.descriptor`；
每条 decoded result 已携带该 descriptor 和 mode，不需要改变 RunProvenance 合同。

## 真实 driver/743 结果与交叉检查

三条指令均为 `decoded`，`width=32`、`representation=decompressed_word`。
evidence 均来自 `driver/743/proof.vcd` 的 host 信号
`miter.\host.u_ibex_core.if_stage_i.instr_rdata_alu_id_o`，保留 VCD 原时间单位 ns。

| Raw encoding | Width | Mnemonic | Canonical operands | Backend display | Evidence time (ns) | Encoding 行 |
| --- | --- | --- | --- | --- | --- | --- |
| `0x00130e13` | 32 | addi | `x28, x6, 1` | `t3, t1, 1` | 30 | 7008 |
| `0x00001537` | 32 | lui | `x10, 1` | `a0, 1` | 40 | 7483 |
| `0x007e2503` | 32 | lw | `x10, 7(x28)` | `a0, 7(t3)` | 50 | 7969 |

每条保留四个原 EvidenceRef：encoding、valid、executing、PC。
工具身份单独为 `capstone / 5.0.9 / instruction_decoder`，mode 为
`RV32; 32-bit instruction words; C disabled; instruction bytes little-endian`。
decoder version 不作为 EvidenceRef，shared RTL 的表示调查也不取代原始 waveform evidence。

独立使用官方 [riscv-opcodes 的 rv_i 定义](https://github.com/riscv/riscv-opcodes/blob/cddb89cd6bdc5889af184690c5b5e99342b0baab/extensions/rv_i)
（固定 commit `cddb89cd6bdc5889af184690c5b5e99342b0baab`），按 opcode/funct3 mask 和字段位置检查：

| Word | Mask / match | rd | rs1 | Immediate field |
| --- | --- | --- | --- | --- |
| `00130e13` | `707f / 0013` | 28 | 6 | 1 |
| `00001537` | `007f / 0037` | 10 | — | 1 |
| `007e2503` | `707f / 2003` | 10 | 28 | 7 |

三个 cross-check tests 不调用 Capstone，其余 known-answer tests 单独检验 backend 输出。
该检查是针对这三个 word 的确定性核对，不是另写完整 decoder，也不使用 LLM 作 correctness oracle。

## driver/820

重新执行 ingestion + enrichment，host instruction observation、decoded instruction 和 host IR
均为 **0**。原有 mutation/formal/local-effect/architectural-propagation oracle 检查继续通过。
decoder 不能补偿缺失的有效 instruction observation；未扫描其他信号、未引用 reference 指令补齐 host。

## 验证

默认新增 39 项 synthetic tests，覆盖 arithmetic、reg-reg、reg-imm、load/store、branch/jump、
alias、字节序、x10/a0 与 x28/t3、失败状态、版本 guard、JSON、证据保留、非原地 enrichment、
重复调用、无新 behavior/trigger、旧 representation unknown、空输入及独立 opcode 核对。
原 181 项测试保留；原 2 项 optional real tests 保留，并新增 743/820 各一项 decode integration test。
默认 pytest 不读取外部真实 corpus；测试均不连接模型服务。

创建独立临时环境 `/tmp/chipchain-v3-1a2-fresh-lxpexk7q`，通过
`bin/python -m pip install '.[test]'` 从本仓库 pyproject 构建并安装 wheel（非 editable）。
以 `python -I` 从 `/tmp` 成功 import Capstone 和已安装的 ChipChain decoder，
确认 module 来自该环境的 `site-packages`。完整测试另使用 `-o pythonpath=`，
关闭仓库 pytest 配置中的 `src` 注入，以检验安装后的 package。

| Fresh resolved dependency | Version |
| --- | --- |
| Python | 3.12.13 |
| capstone | 5.0.9 |
| pydantic | 2.13.5 |
| langchain | 1.2.10 |
| langchain-core | 1.6.2 |
| langgraph | 1.0.10 |
| langgraph-prebuilt | 1.0.8 |
| pytest | 9.1.1 |

默认验证和显式真实验证分别执行：

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
git status --short --untracked-files=all

/tmp/chipchain-v3-1a2-fresh-lxpexk7q/bin/python -m pytest -q -o pythonpath=
/tmp/chipchain-v3-1a2-fresh-lxpexk7q/bin/python -m pip check
CHIPCHAIN_ENCORPUS_IBEX_ROOT=/home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex \
  /tmp/chipchain-v3-1a2-fresh-lxpexk7q/bin/python -m pytest -q -o pythonpath= tests/integration/test_encorpus_local.py
```

最终当前环境结果：`220 passed, 4 skipped in 1.66s`。
最终 fresh 安装包结果：`220 passed, 4 skipped in 1.69s`；
fresh 显式 local 结果：`4 passed in 1.03s`。
现有与 fresh 环境的 `pip check` 均为 `No broken requirements found.`；
compileall、git diff --check 通过。最终文案调整后已重新构建安装 wheel 并完成 fresh 验证。
首次 fresh local 命令曾把环境变量误设到 `driver/`，造成 `driver/driver/743` 等不存在路径、
4 项失败；修正为上述 corpus root 后全部通过，没有为此放宽 analyzer 或更改 tests 路径合同。

## 完成边界

现有 CaseBundle、AnalysisRun、workflow routing、ground-truth/oracle 隔离、workspace 设计保留。
没有真实 sample/runtime output 纳入 Git，也未执行 git add/commit/push/tag。
当前没有发现阻止以这些 host observations 开始有边界 V3-1B 集成的新增 deterministic blocker。
这不意味着已有足够证据证明漏洞、trigger causality 或退休行为；formal harness 不完整、
820 无有效 instruction observation、原始 compressed identity 未恢复等限制继续成立。
这些缺失必须保持 unknown，不能由模型补成确定性事实。本轮未进入 V3-1B。
