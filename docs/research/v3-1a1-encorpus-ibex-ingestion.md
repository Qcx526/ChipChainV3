# V3-1A1 — EnCorpus Ibex Deterministic Hardware Ingestion

实施日期：2026-09-11。稳定基线：`v3-r0-stable`；调查依据：[V3-1A0](v3-1a0-encorpus-ibex.md)。本阶段只消费已有 corpus 文件，不调用模型或执行硬件实验。

## A. Implementation Summary

实现 `EnCorpusIbexDriverAnalyzer`：从显式指定的 Ibex `driver/<numeric-id>` 目录只读提取有限 RTLIL driver 差分、VCD 状态/编码和历史 formal 结果。没有将样本 743 写入生产代码。

两个入口有明确不同的输出：

```text
ingest(sample_directory)
  → EnCorpusIngestionResult
      ├── observations                host 分析观察
      ├── processor_behavior_ir       仅从 host 分析观察产生
      ├── oracle
      │   ├── observations            变异、局部比较、GPR 比较、formal 结果
      │   ├── processor_behavior_ir   比较结果对应的独立 IR
      │   └── limitations
      ├── artifacts                   四个读取文件的 ArtifactRef + SHA/size
      └── artifact_roles              六类文件的角色说明

analyze(case_id=..., target=..., artifacts=...)
  → HardwareObservations              仅 host 分析观察，无 oracle
```

`ingest` 不返回 HardwareTriggerHypothesis，不模拟 Agent reasoning。分析与 oracle 均使用原有 ProcessorBehaviorIR；没有为 benchmark 新增 CaseBundle ground-truth model。

## B. Files Changed

| 文件 | 变更 |
| --- | --- |
| `src/chipchain/domain/evidence.py` | optional signal/time/bit_range 定位 |
| `src/chipchain/tools/contracts.py` | typed hardware observation、kind/role、三个 details 类型；兼容旧 observation |
| `src/chipchain/agents/contracts.py` | 拒绝 typed benchmark oracle 进入 Agent input |
| `src/chipchain/agents/context.py` | 保留合法 typed observation 的 details，不在序列化时降成旧基类 |
| `src/chipchain/tools/hardware/__init__.py` | hardware package |
| `src/chipchain/tools/hardware/encorpus/__init__.py` | 公共 adapter/result/error 导出 |
| `src/chipchain/tools/hardware/encorpus/models.py` | adapter-local oracle、角色和输出边界 |
| `src/chipchain/tools/hardware/encorpus/readers.py` | 有界 RTLIL、log、VCD 子集读取 |
| `src/chipchain/tools/hardware/encorpus/ibex_driver.py` | 显式 ingestion、host 投影、比较与有限 IR |
| `tests/unit/test_encorpus_ingestion.py` | 51 项 synthetic 单元测试，含参数化案例 |
| `tests/integration/test_encorpus_local.py` | 2 项显式启用的真实样本测试 |
| `README.md`、`docs/architecture/v3-r0.md` | 当前阶段、兼容扩展及文档入口 |
| 本文 | 格式边界、结果、验证与限制 |

没有修改 A0 报告、CaseBundle、AnalysisRun、artifact fingerprint 契约、workflow routing、依赖或 workspace Git policy。

## C. Supported EnCorpus Scope

正式支持的目标为 **Ibex / RISC-V / driver family 的下述文本子集**；本轮实际验证 `driver/743` 和 `driver/820`，不宣称所有 15 个 driver 样本都已验证。

本机实际根目录为：

```text
/home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex
```

目录由调用方显式指定。数字 ID 不硬编码，synthetic 测试使用 `driver/901`。入口拒绝非 `driver/<numeric-id>` 布局；`analyze` 还要求显式 `processor_id=ibex`、`architecture=riscv`，字长为 32 或未指定。

不支持 multiplexer/AMT、Rocket、BOOM、通用 RTLIL 或完整 VCD。共享 `reference.v`、`miter.tcl` 只分类和说明；生产 extraction 不读取它们，Ibex GPR 布局使用 A0 已核对的有限目标映射。

## D. Hardware Observation Contract

`HardwareObservation` 扩展旧 `DeterministicObservation`，保留 id、summary、evidence、behaviors、epistemic_status，增加：

| Kind | 语义 | A1 默认位置 |
| --- | --- | --- |
| `MUTATION_PRESENT` | 一个 host/golden driver 连接存在差分 | oracle |
| `LOCAL_EFFECT_OBSERVED` | 所选择局部状态的 host/reference 已知值不等 | oracle |
| `ARCHITECTURAL_PROPAGATION_OBSERVED` | 所支持 GPR 布局中的 host/reference 值不等 | oracle |
| `FORMAL_RESULT` | 日志记录的 cover 命中或 trace error | oracle |
| `INSTRUCTION_ENCODING_OBSERVED` | host 有效 ID-stage 中观察到编码变化 | analysis |

`kind` 表示 claim 含义，`epistemic_status` 表示认识依据；没有修改 EpistemicStatus。连接比较、位范围解包和编码投影使用 derived；formal observation 使用 observed，表示观察到日志报告该结果，不等于本轮验证成功。

三个带 discriminator 的 details：

- `MutationAnchorDetails`：module、signal、两侧 connection、可获得的 source location；拒绝相同 connection。
- `WaveformObservationDetails`：time、host、可选 reference、register_name、observation_stage；值保存完整四态位串、width、range、hierarchical signal、host/reference role、声明行。
- `FormalResultDetails`：category、raw_result、property/cycles 或 error_code、interpretation_boundary；cover/error 字段不能混用。

比较记录要求两侧宽度相同、已知且不等；unknown 值不能构成已观察差异。GPR state 记录必须有寄存器标识。角色默认是 benchmark oracle，A1 只允许 host instruction kind 声明为 analysis input。这是当前安全可见性子集，不是给未来所有硬件分析场景设计的永久分类全集。

`HardwareObservations.observations` 兼容 `HardwareObservation | DeterministicObservation`。原有 R0 JSON 与测试继续可用；typed JSON 往返不会丢失 kind、role 或 details。

## E. Evidence Schema Changes

EvidenceLocation 仅增加三个 optional 字段：

```json
{
  "line": 7987,
  "signal": "miter.\\reference.gen_regfile_ff.register_file_i.rf_reg_q",
  "time": {"value": 50, "unit": "ns"},
  "bit_range": {"msb": 927, "lsb": 896}
}
```

`EvidenceTime` 表示非负整数物理时间及 s/ms/us/ns/ps/fs 单位；VCD timescale 倍数已乘入 value。`BitRange` 表示非负 descending range。解析器不支持 ascending VCD range，因此显式拒绝。

赋值行与比较时刻分别保存：若值由更早的赋值延续，`line` 指向那次赋值，`time` 指向观察时刻，details 另存声明行。GPR slice 的 bit_range 是原始 packed bank 中的绝对范围；例如 x28 为 `[927:896]`，不是相对于已切片字符串的 `[31:0]`。

没有将 module 填到 function，也没有将时间塞到 address/instruction_index。字段名均为通用定位概念，没有加入 EnCorpus ID、buggy 等专用字段。原有 register alias 及旧字段保持兼容。

## F. Oracle / Analysis Input Boundary

`EnCorpusOracle` 保持在 adapter namespace。连接 ground truth、所有 reference 比较、已知 propagation 和 formal 结果连同其 IR 均在 `result.oracle`，不自动写进 CaseBundle。

`result.analysis_input()` 显式构造已有 `HardwareAgentInput` DTO，不运行 Agent；它只包含 host instruction observations/IR 的源 VCD provenance，不包含 golden RTL、mutation location 或 verify.log。`HardwareAgentInput` 会拒绝 typed oracle observation，包括从 JSON 恢复后传入的 oracle。

`analyze(...)` 只读取 `proof.vcd` 的 host 投影，即使调用方 artifact 列表还列出了 reference/log，也不会读取这些文件。单元测试删除另外三个文件后，该入口仍给出相同 host 观察。提供了 SHA/size 时会核对 VCD 身份。

隔离测试同时改变 golden driver 名称、cover cycles 和 reference 波形值（包括 unknown），确认：

```text
oracle changes
analysis observations unchanged
analysis IR unchanged
hardware_context(result.analysis_input()) unchanged
```

边界说明：原始 VCD 是 **mixed-role artifact**，它包含 reference 和 cover 信息。分析 DTO 中的路径仅为 host 提取结果提供来源，未授予 raw-file tool；原始文件指纹随文件内容变化是正确的 provenance 行为，当前 context 不包含该指纹。未来若允许 Agent 读取原始路径，必须提供 host-only 内容投影或继续施加角色边界，不能把本文的 context 隔离误称为文件访问沙箱。

此外，witness 是 benchmark 生成的输入，host 投影不能消除 witness 选择本身的实验偏差；不得把这个投影声称为完全盲评、普通测试输入或已复现软件程序。

## G. Artifact Role Classification

| Artifact | Roles | 依据及实际可见性 |
| --- | --- | --- |
| `host_driver.rtlil` | ANALYSIS_INPUT + BENCHMARK_ORACLE | 是 host design，但包含 `buggy` 标签；本阶段不把 raw RTL 放进默认分析投影。 |
| `reference_driver.rtlil` | BENCHMARK_ORACLE | 提供已知 golden 连接，供变异差分使用。 |
| `proof.vcd` | VERIFICATION_EVIDENCE + BENCHMARK_ORACLE + ANALYSIS_INPUT | 历史 formal witness，同时包含 host/reference；只有选定 host ID facts 进入 analysis。 |
| `verify.log` | VERIFICATION_EVIDENCE + BENCHMARK_ORACLE | 已知 cover/传播结果与后续错误；全部排除于分析 context。 |
| `reference.v` | SUPPORTING_CONTEXT + BENCHMARK_ORACLE | A0 核对的共享 golden 源；本次不读取。 |
| `miter.tcl` | SUPPORTING_CONTEXT + VERIFICATION_EVIDENCE | 描述 observable 构建意图；不解析或执行。 |

后两项仅有 ClassifiedArtifact 角色记录，不会因分类而要求文件存在或产生额外 ArtifactRef。四个实际读取文件的 SHA-256/size 在读取的同一 bytes buffer 上计算，使用既有 ArtifactRef 字段；避免再读一遍后给解析内容配上另一个时刻的指纹。

## H. RTLIL Driver Mutation Parser

支持 A0 所观察的 Yosys `proc` 后 export 结构。忽略空行、整行注释、首尾缩进；其余非 buggy 行必须一一对应。支持 module/cell/end 的结构平衡，以及 export 中的 autoidx、attribute、parameter、wire、memory、connect 文本。

变异子集严格限定为：一个 host `attribute \\buggy "buggy"`，标记同 module 的目标 wire；恰好一个 module-level `connect` RHS 不同，LHS 相同。RHS 只支持单个命名 signal、可选 bit selection 或整数/bit-string constant；不处理 concat、任意表达式、多处差分、process、AMT 或 cell 内连接变异。

这不是对整个 RTLIL 语言的语义验证：未变动 body 作为同布局文本比较；不执行参数求值、RTL 综合或 driver 因果分析。源位置从明确标注的 wire 或消费该 wire 的 cell 的 `src` 获取；没有注解时返回 None，测试保证不借用附近不相关 wire 的 src。

没有差分且没有 buggy 标记时返回 None，ingestion 不生成 mutation observation 并记录 limitation；buggy 标记却没有差分、缺失标记、多差分、布局变化、不支持构造和结构错误均抛出 `IngestionError`。不返回伪造结果或 silent fallback。

743 的自动提取结果是 `\\waddr_a_i → 5'00100`，module 为 register file，src 为聚合 `reference.v:8077.20-8077.47`。它没有自动推广为“安全漏洞”或“已验证 trigger”。A0 的“与 28 比较恒假”解释仍在研究报告，A1 不执行完整 RTL 逻辑求值。

## I. verify.log Parser

只提取主 property `miter.i_miter.c_propagated` 的稳定 `The cover property ... was covered in N cycles in T s.` 记录，以及完整 `ERROR (EVS053): ...` 行。保留源行号、raw_result、category 和解释限制；忽略 auxiliary cover（例如 `:live`）与普通综合/proof 进度文本。

命中的 cover 和后续 trace error 产生两条记录，互不覆盖。exit 0 不用作成功证据。已识别 marker 格式错误、其他 ERROR 或完全缺少支持的结果均报错；仅有 EVS053 时可记录 error，但另外说明没有 cover hit。

每个 formal result 明确保留：缺失完整 SVA/reset harness、未独立 replay、不能确认 verified trigger/security impact。本阶段不提取完整 assumptions/工具运行图，也不判断 EVS053 的安全含义。

## J. proof.vcd Extraction

环境检查未发现已安装的 `vcd`/`pyvcd` 读取器，也没有 Capstone；使用 stdlib 内部 bounded subset，不新增依赖。

VCD 支持：module scope/upscope、wire/reg、scalar 和 descending vector range、相同 code 的同宽 alias、date/version/comment、timescale（1/10/100 × s/ms/us/ns/ps/fs）、enddefinitions、单调非递减整数时间、0/1/x/z scalar 与 b/B vector、dumpvars/dumpall。缩短 vector 按其最高位是否 x/z 做四态或零扩展；同一 timestamp 处理完全部变化后再取观察，未更新值 carry-forward。

所有声明和 value changes 均做子集检查，即使未选择的信号也不能使用不支持的 real 值或错误 width。只保留需要的 signal snapshots。相同短名必须以完整 scope/escaped signal 区分；不把 `miter.host_observables` 与 `miter.i_miter.host_observables` 合并。

资源边界：每文件 16 MiB、每行 64 KiB、最多 20,000 signal declarations、单信号 width 65,536、10,000 timestamp frames、1,000,000 retained snapshot values、4,096 条 waveform observations。超过边界整体失败，不截断。这些是 reader 的资源限制，不是 Case 数量或 domain 上限。

拒绝未知关键 directive、dumpoff/dumpon、real/string value、不支持 scope、ascending/conflicting range、未知 code、错误 scalar/vector width、倒退时间和不完整 header/body。

目标绑定：

- host ID 编码按显式 alias 顺序选择 `instr_rdata_id_o`，不存在时使用 `instr_rdata_alu_id_o`；要求 32 bits，并存在 `instr_valid_id_q`、`instr_executing`、32-bit `pc_id_o`。
- 仅当 selected word/PC 已知且 valid=executing=1 时提取编码。连续有效期间编码相同会合并，即使 PC 改变也不当作新指令；失效窗口后重新开始。计数是编码观察片段，不是执行次数。
- local comparison 仅选择成对的 controller `debug_mode_q`、LSU `ls_fsm_cs` / `ls_fsm_ns`。允许部分对不存在，但至少一对存在；单边缺失或两侧 width/range 不匹配报错。
- architectural comparison 必须是两侧 992-bit `rf_reg_q[1023:32]`，按 x1–x31 的 32-bit 范围逐个比较。未知 slice 不产生 mismatch；没有读取 x0 或猜测其他 packing。
- 仅发出新出现或两侧值发生变化的不等 pair；连续相同不等 pair 合并，相等后再次不等可再次产生记录。没有发出记录不表示该设计已证明无差异。

local difference 是选定状态分歧，不自动表示变异节点被到达或证明因果；architectural propagation kind 严格限定于这个保存 witness 中的 GPR mismatch。

## K. ProcessorBehavior Mapping

host 编码观察映射为 `BehaviorKind.INSTRUCTION`，attributes 只有 encoding、PC、ID stage、time。无可信 decoder 时不填写 mnemonic、rd/rs1、操作数、retired 或 CFG。

GPR mismatch 映射为 `REGISTER_ACCESS` 的 state-related behavior，summary 明确 access direction unknown，attributes 指明 `observation=register_state_difference`、register、两侧值、time。这些 behaviors 只在 oracle IR，不能借已有 REGISTER_ACCESS 枚举暗示观察到 read/write 事件。

所有生成 behavior 均有 EvidenceRef、hardware origin、riscv architecture 和 derived status。输出校验确保分析 IR 与分析 observations 一致、oracle IR 与 oracle observations 一致、证据引用属于输入 artifacts；不允许无 evidence 的生成 behavior。

## L. HardwareAnalyzer Integration

```python
from pathlib import Path
from chipchain.tools.hardware.encorpus import EnCorpusIbexDriverAnalyzer

analyzer = EnCorpusIbexDriverAnalyzer()
result = analyzer.ingest(Path(
    "/home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex/driver/743"
))

print(result.observations.model_dump_json(indent=2))  # host facts
print(result.oracle.model_dump_json(indent=2))        # explicit benchmark access

# 只构建 DTO；不会调用模型。
agent_input = result.analysis_input()
host_observations = analyzer.analyze(
    case_id=agent_input.case.case_id,
    target=agent_input.case.target,
    artifacts=agent_input.case.hardware_artifacts,
)
```

`analyze` 实现已有 HardwareAnalyzer Protocol，没有修改协议签名。没有自动插入任何 workflow，没有新增 scheduler、数据库或 retry。构造 result 或运行 analyzer 不写文件；调用方需要保存时再显式使用 JSON 序列化及自行选择输出路径，推荐 workspace 仍为 `output/<case_id>/<run_id>/`。

## M. driver/743 Real Results

实际读取 `encorpus:ibex:driver:743` 四个原始文件，直接使用 repository 外部路径。读取后的 SHA/size 与现有 fingerprint helper 交叉检查一致。

| 结果类别 | 数量 |
| --- | ---: |
| mutation observations | 1 |
| formal observations | 2（主 cover + EVS053） |
| waveform observations 合计 | 8 |
| 其中 instruction encoding | 3 |
| 其中 local effect | 3 |
| 其中 architectural propagation | 2 |
| ProcessorBehavior 合计 | 5（analysis 3 + oracle 2） |
| 唯一 EvidenceRef | 26（按 evidence_id 去重；behavior 复用 observation evidence） |

下面五条是实际结果的结构化摘录，为阅读省略部分字段；不是完整 model JSON，也不是新增测试 fixture。完整结果由本轮显式诊断命令写入 `/tmp/chipchain-v3-1a1-743.json`，没有自动持久化或提交 Git。

```json
[
  {
    "kind": "mutation_present",
    "role": "benchmark_oracle",
    "epistemic_status": "derived",
    "details": {
      "signal": "$auto$inject_driver.cc:83:expose_cells$64337",
      "reference_connection": "\\waddr_a_i",
      "host_connection": "5'00100",
      "source_location": "/scratch/mboelcskei/thesis/final/ibex/reference.v:8077.20-8077.47"
    },
    "source_lines": {"host_driver.rtlil": 3438, "reference_driver.rtlil": 3437}
  },
  {
    "kind": "formal_result",
    "role": "benchmark_oracle",
    "epistemic_status": "observed",
    "details": {
      "category": "cover_hit",
      "property_name": "miter.i_miter.c_propagated",
      "cycles": 8
    },
    "source_lines": {"verify.log": 371}
  },
  {
    "kind": "local_effect_observed",
    "role": "benchmark_oracle",
    "details": {
      "time": {"value": 50, "unit": "ns"},
      "host": {"signal": "miter.\\host.u_ibex_core.load_store_unit_i.ls_fsm_ns", "value": "010"},
      "reference": {"signal": "miter.\\reference.u_ibex_core.load_store_unit_i.ls_fsm_ns", "value": "000"}
    },
    "assignment_lines": {"host": 7975, "reference": 5661}
  },
  {
    "kind": "architectural_propagation_observed",
    "role": "benchmark_oracle",
    "details": {
      "time": {"value": 50, "unit": "ns"},
      "register_name": "x28",
      "host": {"signal": "miter.\\host.gen_regfile_ff.register_file_i.rf_reg_q", "width": 32,
               "bit_range": {"msb": 927, "lsb": 896}, "value": "00000000000000000000000000000000"},
      "reference": {"signal": "miter.\\reference.gen_regfile_ff.register_file_i.rf_reg_q", "width": 32,
                    "bit_range": {"msb": 927, "lsb": 896}, "value": "00000000000000000000000000000001"}
    },
    "assignment_lines": {"host": 4752, "reference": 7987}
  },
  {
    "kind": "instruction_encoding_observed",
    "role": "analysis_input",
    "details": {
      "time": {"value": 30, "unit": "ns"},
      "observation_stage": "id",
      "host": {"signal": "miter.\\host.u_ibex_core.if_stage_i.instr_rdata_alu_id_o",
               "value": "00000000000100110000111000010011"}
    },
    "assignment_lines": {"encoding": 7008, "valid": 7010, "executing": 6991, "pc": 5168}
  }
]
```

其余两条 encoding 为 t=40 `0x00001537`、t=50 `0x007e2503`，与 A0 一致。第二条 GPR 差异为 t=70 x10 host=`0x1000` / reference=0；第一条为 t=50 x28 host=0 / reference=1。local observations 为 LSU ns 在 t=50、cs 在 t=60、ns 在 t=70 的不等 pair。EVS053 独立记录指向 `verify.log:464`。

这些结果没有自动生成指令解码、x28 写使能的逻辑证明、通用触发条件或安全影响；后者仍需额外确定性语义/验证材料。

## N. Second Driver Sanity Check

实际读取 `driver/820`，不是改名后的 743 fixture。

| 结果类别 | 数量 |
| --- | ---: |
| mutation | 1（debug_mode_q → ebrk_insn） |
| formal | 2（59-cycle cover + EVS053） |
| waveform 合计 | 7 |
| local effect | 6（debug_mode_q 的不等 pair） |
| architectural propagation | 1（t=580 x10 host=0 / reference=`0x378`） |
| instruction encoding / analysis IR | 0 |
| oracle IR | 1 |
| 唯一 EvidenceRef | 18 |

源码位置为聚合 `reference.v:1265` 的复合 span；首个 local mismatch 在 t=100，早于 GPR mismatch。结果也显式记录没有提取有效 host ID encoding。

**not yet extracted：820 指令片段。** 该 trace 的 host 侧未同时满足当前 known encoding/PC、valid=1、instr_executing=1 的提取条件。本实现没有放宽条件、把 59 个总线变化值称为 59 条指令，或从 reference 指令补齐 host IR。sanity check 验证了另一种 mutation/module 和较长 waveform 的读取，不等于覆盖全部 driver 变体。

## O. What Was NOT Automatically Extracted

- 完整 RV32/C decoder、mnemonic、operands、retirement ordering、重复同编码指令的执行次数、CFG、动态依赖。
- bug-site activation 的完整追踪和 mutation→local→GPR 因果链；目前 local 的含义是选定状态差异。
- 独立重放、formal property 完整公式、reset/assumptions、内存模型、验证结果阶段图或 EVS053 根因。
- MMIO、CSR/exception/interrupt 的语义观察、external memory mismatch、安全漏洞或 HardwareTriggerHypothesis。
- AMT、multiplexer、Rocket、BOOM；通用 Yosys/VCD 语法与架构映射。

## P. Tests Added / Modified

原有 130 项测试文件没有修改。新增 51 项 synthetic 单元测试，覆盖：四种 claim 加 instruction kind、status 正交、details 匹配、RTLIL 差分/无差分/错误/源位置、formal 正负结果分离、VCD scalar/vector/hierarchy/时间/四态/alias/carry-forward/错误/资源限制、GPR packing、Evidence JSON、IR 来源、context typed serialization、oracle 变更隔离、Agent oracle 拒绝、协议安全投影、fingerprint 和只读行为。

新增 2 项 optional/local 集成测试，仅在显式设置 `CHIPCHAIN_ENCORPUS_IBEX_ROOT` 后读取真实资源；默认 pytest 不需要本机路径。环境变量应指向包含 `driver/` 的实际内层根目录，不自动猜测双层结构。启用后资源错误会失败，不会伪装为 skip。

```bash
CHIPCHAIN_ENCORPUS_IBEX_ROOT=/home/qcx/ChipChainV3_res/hardware/encorpus/ibex/ibex \
  .venv/bin/pytest -q tests/integration/test_encorpus_local.py
```

synthetic fixtures 在 pytest 临时目录生成，没有复制真实 RTLIL/VCD/log。现有 autouse fixture 继续禁止网络和外部子进程。

## Q. Exact Test Results

使用现有 `.venv`，最终生产代码验证记录：

```text
pytest -q
181 passed, 2 skipped in 1.58s

# 显式启用真实 743 / 820 测试
pytest -q tests/integration/test_encorpus_local.py
2 passed in 0.57s

python -m pip check
No broken requirements found.

python -m compileall -q src tests
exit 0, no output
```

`git diff --check` 通过；另检查所有新增文件的尾随空白和文件结尾，避免 untracked 文件未包含在默认 diff 中。真实读取后的原始文件 SHA/size 与 ingestion result 一致；没有向 corpus 写入 cache/临时文件。

命令通过 `PATH="$PWD/.venv/bin:$PATH"` 或 `.venv/bin/...` 选择现有环境。另用只读 inline Python 检查真实 VCD construct 分布、已安装 parser/decoder、结果计数和序列化；诊断结果仅由显式命令保存至 `/tmp/chipchain-v3-1a1-743.json`、`/tmp/chipchain-v3-1a1-820.json`。

## R. Dependencies

未增加、安装或更新任何依赖；只使用现有 Pydantic、项目契约与 Python stdlib。没有 provider 包、`.env`、模型调用或 tracing 配置修改。没有为了运行 ingestion 引入 LangChain Agent execution。

## S. Documentation

新增本文；README 更新当前阶段和 adapter 入口；R0 架构文档末尾补充 V3-1A1 的兼容扩展。A0 调查报告保留为当时的研究记录。

## T. Architecture Deviations / Concerns

增加第五种 instruction kind，是为了把正常 host encoding 观察与 oracle local/GPR 比较分开，避免将普通 instruction 错标为 local-effect difference。没有增加十几种 observation class。

`analyze` 遵守旧协议，返回安全观察；`ingest` 才显式提供丰富 benchmark result。这避免改变所有 analyzer 或 workflow 的返回类型。Agent contract/context 的两处小改动分别用于拒绝 oracle 和避免 typed details 丢失。

当前 GPR 与 ID-stage signal 绑定是 Ibex implementation-specific；kind、evidence time/range、ProcessorBehaviorIR 仍为架构无关契约。reader 没有把文件路径限制在 repository workspace。

当前 role 规则有意只开放 host instruction observation；扩大可见性需要新的证据和投影规则。typed 角色校验不承诺识别任意人工重写的旧 summary 中是否暗藏 oracle，也不替代未来 raw-tool 的文件内容访问控制。

## U. Deferred Work

**单个最重要的下一项确定性能力：可信、阶段感知的 RISC-V 指令解码适配器。** 它应将有明确有效性来源的编码转成可核对的 opcode/operand 事实，处理不同 ID-stage 表示，避免让 Hardware Agent 重新猜测位域。它不应顺带声称得到了退休序列或 verified trigger。

完整因果/触发验证还受缺失 harness 和 bug-site/source mapping 限制；AMT/multiplexer 留待 V3-1A2 或之后，真实模型接入留待 V3-1B。本轮没有进入这些阶段。

## V. Git Status

开始时工作树干净。最终状态：

```text
 M README.md
 M docs/architecture/v3-r0.md
 M src/chipchain/agents/context.py
 M src/chipchain/agents/contracts.py
 M src/chipchain/domain/evidence.py
 M src/chipchain/tools/contracts.py
?? docs/research/v3-1a1-encorpus-ibex-ingestion.md
?? src/chipchain/tools/hardware/__init__.py
?? src/chipchain/tools/hardware/encorpus/__init__.py
?? src/chipchain/tools/hardware/encorpus/ibex_driver.py
?? src/chipchain/tools/hardware/encorpus/models.py
?? src/chipchain/tools/hardware/encorpus/readers.py
?? tests/integration/test_encorpus_local.py
?? tests/unit/test_encorpus_ingestion.py
```

没有执行 git add/commit/push/tag。

## 最后九个问题

1. **743 能否无 LLM ingestion？** 能，真实读取与本地集成测试均通过。
2. **三层 claim 能否机器区分？** 能，mutation/local effect/architectural propagation 是不同 kind，且与 EpistemicStatus 分离。
3. **oracle 默认能进入 Hardware Agent input 吗？** 不能；默认分析投影排除，typed oracle 直接传入会被拒绝。原始混合 VCD 路径仍须受未来 raw-tool 边界约束。
4. **每个生成 behavior 有确定性证据吗？** 有，输出校验和测试均保证。
5. **是否针对 743 写死？** 否；driver ID 由路径读取，synthetic 901 与真实 820 均验证。
6. **是否支持完整 VCD/RTLIL？** 否；支持和拒绝子集及资源限制已明确。
7. **是否重跑 formal/fuzz？** 否，只读取历史 artifacts。
8. **是否使用真实 LLM？** 否，也未创建 `.env` 或安装 provider。
9. **最重要的缺失能力？** 可信、阶段感知的 RISC-V instruction decoder；完整验证仍另需 harness 和因果证据。
