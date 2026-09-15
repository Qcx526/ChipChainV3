# ChipChain V3

大模型协同的芯片固件—硬件跨层漏洞攻击链路检测研究工程。

中文入门：[如何阅读 Hardware / Firmware 分析报告](docs/tutorials/report-walkthrough/README.md)。
通过真实 Hardware 743 与历史 Firmware Heat_Press 报告，学习逐字段追踪 support、relation、evidence 与结论边界。
教学快照不代表 reviewed truth；Firmware 例子明确保留已知语义缺陷。

当前阶段：**V3-1B2 — Structured Hardware Relation Claims & Support-Gated Hardware Agent**。
Hardware A3 已冻结；Hardware B2 实现、离线验证及两次预定真实实验已完成，待人工审核。
743/820 均 machine-valid；820 x10 hypothesis 的 host-side write/update 猜测仍有语义审核问题。
新增显式 supported 路径、prompt v3、model-only support schema 和安全诊断：每个 referenced support
必须通过冻结 A3 checker；orphan 全部求值但不支撑报告 item。支持事实不证明 trigger hypothesis 正确。
旧 Hardware invoke、prompt v2、domain report 和历史运行保留；本轮不自动 reviewed-export。
设计、冻结身份与真实结果见 [Hardware B2 文档](docs/research/v3-1b2-structured-hardware-support.md)。
A3 合同与 743/820 的 10/9 条 deterministic relations 见
[Hardware A3 文档](docs/research/v3-1a3-hardware-typed-relations.md)。
以下为已冻结 Firmware A5 的实现说明；B3 保留为可解释的真实负结果。
新增 optional `angr==9.3.4`（Python 3.12+），基础 Python 要求仍为 >=3.11。
真实样本得到 62/1122 个 bounded static function paths；静态路径不证明 feasibility、runtime 或漏洞。
环境、完整 binding/comparison/site 表及复现命令见 [A5 文档](docs/research/v3-2a5-angr-static-reachability.md)。
以下保留 B3 的设计和历史结果说明。
新增显式 `relation_v3` context、Firmware prompt v2 和 model-only structured support claims；
每个非空 Firmware claim 必须引用通过确定性检查的 support。旧 v1/v2 调用路径保留。
设计、验证和真实实验记录见 [B3 文档](docs/research/v3-2b3-structured-relation-claims.md)。
structured support 合法仍不保证自由文本语义完整，需要人工审核；与 B2 的比较不是单变量实验。
本轮唯一一次 deepseek-flash 调用在 schema gate 被拒绝，未进入 support gate；输出达到 8192-token 上限，
具体解析失败原因尚未确认。未重试，也未接受或 reviewed-export 任何 B3 报告。
B3-R1 新实验仅将 relation_v3 输出预算提高到 16384：schema 已通过，实际输出 14112 tokens，
随后因 `unused_support_claim` 被 support gate 拒绝，未重试。详见
[B3-R1 输出完整性记录](docs/research/v3-2b3-r1-output-completeness.md)。
B3-R2 评估并保留孤立 support 为诊断，仅被引用的 support 必须 supported；新增 support artifact v2，
v1 校验兼容保留。输入/prompt/schema/provider 设置不变。本轮唯一一次真实调用通过 schema，
随后因 referenced `incompatible_relation_claim` 被拒绝，未生成 accepted canonical report，未重试。
详见 [B3-R2 孤立 support 政策与实验记录](docs/research/v3-2b3-r2-orphan-support-policy.md)。
B3-R3 保持接受政策和模型输入不变，新增 bounded typed failure diagnostic。
本轮唯一一次真实调用 schema 通过，但 37 个 referenced supports incompatible，报告拒绝；
已保存完整安全错误索引，没有 accepted canonical report、重试或 reviewed export。
详见 [B3-R3 安全诊断与逐项错误记录](docs/research/v3-2b3-r3-referenced-support-diagnostics.md)。

V3-2A4 — Typed Static Relation Semantics & Claim-Support Contracts 已冻结。
独立确定性关系层区分 direct call、direct branch、unresolved、MMIO 与静态向量绑定，
用显式 typed claims 检查证据支持范围；本阶段不调用模型、不接入 Agent。
实现、真实计数与 12 个站点分类见 [A4 静态关系文档](docs/research/v3-2a4-typed-static-relations.md)。
B2 单次 deepseek-flash 实验为 machine-valid / human-reviewed / mixed semantic result，
存在错误的 Reset→SystemInit confirmed-call 推断，未 reviewed-export；
历史记录见 [B2 实验与逐条 claim 审计](docs/research/v3-2b2-enriched-firmware-agent.md)。
Firmware R1 真实基线仍为 **machine-valid / human-rejected / NOT reviewed**。
已完成 **R0-B.1 dependency reproducibility patch**；版本边界由 `pyproject.toml` 管理。
保留已冻结的 R0-A/R0-A.1 Case-first、多架构合同与 workflow。

`CaseBundle` 表示研究样本，`CaseWorkflowState` 是临时编排状态，`AnalysisRun` 是一次执行的
独立结果与 provenance。相同 Case 可产生多个 run，动态执行信息不会写回 Case。
**100+ 样本是长期累计的评估数据集规模，不是单次 batch 大小。**
典型分析是一个硬件样本配一个固件样本；通常每次执行约 1–10 个 case。
这是实际工作量预期，不是 domain 硬上限。

三个 Security Agent 支持注入 LangChain ChatModel，通过官方 structured output 返回
Pydantic 报告；不注入模型时保留离线 stub。**尚不具备真实漏洞检测、攻击链搜索或触发验证能力。**

已增加 EnCorpus Ibex **driver family** 的只读确定性 adapter，实测 `driver/743` 和 `driver/820`。
`ingest(sample_directory)` 返回 host 分析观察、ProcessorBehaviorIR 及独立 benchmark oracle；
`analyze(...)` 实现现有 HardwareAnalyzer 协议，仅返回 host 分析观察。
没有自动接入 workflow，也不调用 LLM 或重跑 formal/fuzz。用法、格式边界与实测结果见
[V3-1A1 ingestion 文档](docs/research/v3-1a1-encorpus-ibex-ingestion.md)。

V3-1A2 增加独立 `RiscVInstructionDecoder`，使用稳定 Capstone 5（`>=5.0.9,<6`），
显式 enrich A1 已识别的 host instruction observation，保留原 behavior identity 和 EvidenceRef。
743 的三条编码得到 `addi x28, x6, 1`、`lui x10, 1`、`lw x10, 7(x28)`；820 仍为空。
当前仅解释 RV32 ID-stage 解压路径的 32 位表示，不推断原始 compressed 长度、执行、退休或 trigger。
架构中立合同、字节序、失败状态、调用方法和 fresh environment 验证见
[V3-1A2 decoding 文档](docs/research/v3-1a2-riscv-decoding.md)。A1/A2 工具本身不调用模型。

V3-1B 通过官方 `langchain-deepseek` 将 `ChatDeepSeek` 注入既有 HardwareSecurityAgent，
使用 `function_calling` structured output 和 hardware prompt v2；仅处理 A1/A2 的 host 分析投影。
真实 743/820 已生成并保存经过校验的报告，均未产生 trigger hypothesis 或 abnormal state。
首次结果较保守，不能据此宣称已具备可靠漏洞检测或 trigger 推理能力。
实测报告、失败尝试、token usage 和人工审核问题见
[V3-1B DeepSeek 文档](docs/research/v3-1b-deepseek-hardware-agent.md)。

V3-1B.1 将既有确定性 local/GPR divergence 和 formal tool results 纳入运行证据投影，
精确 injected mutation location/connection、benchmark root cause 和 raw RTL 继续隐藏。
投影集中在 `build_hardware_analysis_projection`，不扩展 parser；hardware prompt 保持 v2。
配置原样接受 `deepseek-flash` 与版本化模型名，运行无需模型名 workaround。
规则、诊断及与旧报告的比较见 [V3-1B.1 文档](docs/research/v3-1b1-operational-evidence.md)。

V3-2A1 新增 `FuzzwareHeatPressScenarioAnalyzer`：显式提供四个带 fingerprint 的
ELF/BIN/YAML/opaque input ArtifactRef，得到 typed FirmwareObservation 和静态/configuration IR。
真实 Heat_Press scenario 13 为 23 个指令 site、32 个 MMIO model、2 个环境输入 observations；
没有 replay、runtime observation、crash 或外部输入可达性结论。只调用无模型 Firmware Agent 验证合同。
支持子集、离线调用示例、依赖和边界见
[V3-2A1 ingestion 文档](docs/research/v3-2a1-fuzzware-heat-press-ingestion.md)。

V3-2A1.1 将固件模型输入独立为版本化的 `firmware-analysis-projection/v1`：
隐藏本地路径/display name，以 evidence、behavior catalogs 去重，canonical observations/IR 保持不变。
真实 context 从 62,793 降至 39,438 字符，仍保留全部 57 observations、55 behaviors 和 57 EvidenceRefs。
Firmware Agent 输出新增 exact EvidenceRef 和 finding-reference grounding gate，使用 fake model 离线验证。
身份策略、实验结果和 B 阶段边界见
[V3-2A1.1 projection 文档](docs/research/v3-2a1-1-firmware-agent-projection.md)。

V3-2B 增加显式 Firmware runner 和 reviewed exporter 支持；两次 v4-pro 调用保留为
pre-baseline rejected pilot runs，存在模型偏好不符且无 accepted report，记录见
[V3-2B pilot 文档](docs/research/v3-2b-deepseek-firmware-agent.md)。

V3-2B-R1 将 DeepSeek 默认统一为 `deepseek-flash`，模型只输出 evidence IDs，由 deterministic hydration
构造完整 canonical EvidenceRefs，再执行原 exact grounding 和 IR 校验；prompt v1/projection v1 均不变。
一次 corrected real run 已通过校验并保存 8 findings、4 paths、6 unknown reachability、3 anchors，**不是漏洞确认**。
人工审查已发现 SystemInit 读写方向错误、outbound path 分类和 IRQ 关联过强等问题；未重跑或 reviewed-export。
完整运行身份、文件链接、claim audit 与限制见 [R1 报告](docs/research/v3-2b-r1-evidence-binding.md)。

V3-2A2 增加独立、显式的 Ghidra headless 静态结构提取，使用本机已有安装，
不下载工具、不读取 `.env`、不调用模型。结果包含函数、经 ELF/Capstone 核对的直接调用边、
未解决调用点和有界 Cortex-M 向量映射；完整结构不进入 FirmwareObservations 或 Agent context。
Heat_Press 实测 183 函数、238 条已确认直接调用边；23 个 MMIO PC 中 20 个映射到 10 个函数，
另 3 个保留为缺失归属。详情、全部 site 表和限制见
[V3-2A2 静态结构文档](docs/research/v3-2a2-ghidra-static-structure.md)。

```bash
CHIPCHAIN_GHIDRA_HOME=/explicit/path/to/ghidra \
  .venv/bin/python -m chipchain.tools.firmware.ghidra \
  --elf /explicit/path/to/Heat_Press.elf
```

该命令只接受本阶段冻结 fingerprint 的 ELF，在临时目录分析并清理 Ghidra project；
成功后显式写入新的 `output/<case_id>/<uuid>/`，不覆盖历史运行。
Python `extract_heat_press_structure` API 返回独立结果，不自动写持久化文件。

V3-2A3 新增独立 `FirmwareRelevantStaticStructure`：MMIO/向量 handler seeds 的完整一跳确认调用，
以及相关 unresolved calls、23 个 MMIO site 和 compact vector groups。真实 Heat_Press 投影为
34 functions、22 confirmed calls、12 unresolved calls、14 handler groups；可逆去重后 16,631 字符，
172 个 EvidenceRefs 可精确还原。没有接入 Agent、修改 prompt/projection v1 或创建运行可达性结论。
选择规则、具名列式 JSON、精确 hash、测试和 B2 catalog/item-budget 限制见
[V3-2A3 相关静态结构文档](docs/research/v3-2a3-relevant-static-structure.md)。

长期计划面向约 5 种处理器架构，当前重点为 **ARM、RISC-V、PowerPC**；其他未来架构尚未冻结。
PowerPC 使用一等枚举值 `powerpc`。架构专用提取结果统一进入架构中立的
Processor Behavior IR，共用 Case-first pipeline。Target 可选描述 ISA variant、字长和已知端序，
不会据此分裂 workflow。R0 跨层 eligibility 仅表示路由准入，不表示证据充分或验证成功。

使用 Python >= 3.11，推荐独立虚拟环境：

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
pytest -q
```

安装需要可用的软件包源；离线安装可在 pip 命令中加入
`--no-index --find-links /path/to/wheels --no-build-isolation`，前提是已经安装
`setuptools>=68`，且 wheel 目录包含所有依赖。当前工作区已准备好 `.venv`。

运行一个 synthetic case（不需要 API key 或真实二进制）：

```python
from pathlib import Path

from chipchain.domain.case import CaseBundle
from chipchain.workflows import build_case_workflow
from chipchain.workflows.state import CaseWorkflowState

case = CaseBundle.model_validate_json(Path("examples/cases/paired.json").read_text())
result = CaseWorkflowState.model_validate(build_case_workflow().invoke({"case": case}))
print(result.model_dump_json(indent=2))
```

需要独立 run ID、UTC 时间、阶段状态和运行环境记录时：

```python
from chipchain.execution import run_case, run_cases

run = run_case(case)
print(run.model_dump_json(indent=2))
runs = run_cases([case, case])  # 顺序执行；每次生成不同 UUID。
```

`run_cases` 是小集合顺序执行 convenience，不设 case 数量硬上限；空 Sequence 返回空列表，
一个 case 分析失败不终止后续 case。它不面向大规模 batch 吞吐优化。

`run_case(..., workflow=injected_workflow, provenance=...)` 可复用注入模型的工作流。
自定义模型/tool/prompt descriptor 由调用方显式提供；未提供时记录 unknown，不读取模型配置或密钥。
`fingerprint_artifact(path)` 位于 `chipchain.tools.artifacts`，仅显式调用时流式读取本地文件。
ArtifactRef 的可选 `sha256`/`size_bytes` 不会在构造时自动计算；Case schema version 默认 `1.0`。

工作区约定：

| 目录 | 用途 |
| --- | --- |
| `samples/hardware/` | 真实硬件输入工作区 |
| `samples/firmware/` | 真实固件输入工作区 |
| `output/` | 分析结果工作区，推荐 `<case_id>/<run_id>/` |
| `examples/`、`tests/` | 仅小型 synthetic examples/test data |

样本及运行输出默认忽略 Git，目录 README 用于说明与占位。paired CaseBundle 通过两侧 artifact refs
复用材料，不复制到 `samples/cross_layer/`。外部只读 artifact 路径也合法；工作区约定不属于 domain validation。
workflow/run helper 不自动写文件；持久化由调用方显式触发，domain 不依赖 `output/` 路径。

V3-1B.2 增加 `output/reviewed/` 作为唯一明确的 reviewed snapshot 区域：已人工接受的真实运行
通过显式 exporter 校验后可提交，普通 runtime output 仍被忽略。快照原样保留结构化 report/context，
附文件哈希 manifest；用法和当前 743/820 快照见 [output/README.md](output/README.md)。

模型由调用方显式注入，三个 Agent 可以使用不同实例：

```python
from langchain_core.language_models import BaseChatModel
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.cross_layer import CrossLayerSecurityAgent

def workflow_with_models(hw: BaseChatModel, fw: BaseChatModel, cross: BaseChatModel):
    return build_case_workflow(
        hardware_agent=HardwareSecurityAgent(model=hw),
        firmware_agent=FirmwareSecurityAgent(model=fw),
        cross_layer_agent=CrossLayerSecurityAgent(model=cross),
    )
```

`Security Agent != Model`：ChipChain 负责领域职责、prompt、上下文和数据合同；LangChain
负责模型抽象、调用、structured output 与 provider interoperability。领域 Agent 不创建 provider、
读取 API key 或自动读取 artifact 内容。R0-B 使用 `BaseChatModel.with_structured_output`
完成单次结构化报告；`create_agent` 已通过兼容性 smoke import，当前 runtime 不需要它，
未来有主动工具编排需求时再评估。

已验证基线为 LangChain 1.2.10 / LangGraph 1.0.10 / bundled prebuilt 1.0.8。
项目仅为阻止已知依赖解析问题显式约束 prebuilt，不调用其 API。
依赖升级后应同时执行 `python -m pip check` 和完整 `pytest -q`；测试包含 public API
smoke import，以捕获元数据校验无法发现的运行时不兼容。范围与验证版本见架构文档。

默认 stub 完全本地运行。测试使用 `tests/fakes.py` 或 provider generation stub 替代外部模型，
实际经过 LangChain structured-output parser；禁用 tracing 并阻止网络/外部进程。
R0 不进行真实模型调用，请勿为本阶段启用外部 LangSmith tracing。

显式真实 Hardware Agent 运行（从 repository root 执行）：

1. 首次配置时将 `.env.example` 复制为 `.env`，在本地填写 `DEEPSEEK_API_KEY`，不要覆盖已有配置。
2. 使用下方明确 opt-in 命令；默认 pytest 即使已有 key 或 `.env` 也不访问 API。
3. 检查终端给出的 `output/<case_id>/<run_id>/`，其中必须存在
   `analysis_run.json` 和 `hardware_analysis_report.json`，再人工审核结论。

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 \
  .venv/bin/python -m chipchain.integrations.deepseek_hardware \
  --env-file .env --sample /path/to/ibex/ibex/driver/743
```

随后可将 sample 改为 `driver/820`。默认原样使用 `.env` 的 `CHIPCHAIN_HARDWARE_MODEL`；
如需 override，可在命令前显式设置同名环境变量。文件只在显式入口读取，
不修改进程环境，也不启用调用许可。模型名在 integration config 中注入，Agent 不绑定 DeepSeek。
命令关闭 tracing、transport logging 和自动重试；每次保存 `invocation_attempts.jsonl` 的开始及终态记录，
包含模型、prompt、context hash 和安全失败类别；失败不保存响应正文，成功必须写入
validated report。每次使用新 UUID，既有 run directory 不会被覆盖。真实输出及 `.env` 均被 Git 忽略。

Firmware 使用独立 opt-in 入口和 `CHIPCHAIN_FIRMWARE_MODEL`，不回退到 Hardware 模型变量。
未配置时使用 `deepseek-flash`；`.env.example` 两侧模型示例均为 `deepseek-flash`。
入口为 `python -m chipchain.integrations.deepseek_firmware --env-file .env --corpus-root /path/to/fuzzware-experiments`，
仍需命令环境中显式 `CHIPCHAIN_ENABLE_REAL_LLM=1`；corrected Firmware runner 要求最终模型为 `deepseek-flash`。
真实结果须人工审核，不自动重跑或 reviewed-export。
R0-C 已完成 Architecture Reset；当前未进入 Cross-Layer 集成。

架构边界、准入条件、状态语义和后续扩展点见
[docs/architecture/v3-r0.md](docs/architecture/v3-r0.md)。
