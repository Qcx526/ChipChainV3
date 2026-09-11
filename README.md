# ChipChain V3

大模型协同的芯片固件—硬件跨层漏洞攻击链路检测研究工程。
当前阶段：**V3-1A2 — Deterministic RISC-V Instruction Decoding**。
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
[V3-1A2 decoding 文档](docs/research/v3-1a2-riscv-decoding.md)。本轮在 A2 停止，未接入真实 LLM。

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
负责模型抽象、调用、structured output 与 provider interoperability。项目不创建 provider、
读取 API key 或自动读取 artifact 内容。R0-B 使用 `BaseChatModel.with_structured_output`
完成单次结构化报告；`create_agent` 已通过兼容性 smoke import，当前 runtime 不需要它，
未来有主动工具编排需求时再评估。

已验证基线为 LangChain 1.2.10 / LangGraph 1.0.10 / bundled prebuilt 1.0.8。
项目仅为阻止已知依赖解析问题显式约束 prebuilt，不调用其 API。
依赖升级后应同时执行 `python -m pip check` 和完整 `pytest -q`；测试包含 public API
smoke import，以捕获元数据校验无法发现的运行时不兼容。范围与验证版本见架构文档。

默认 stub 完全本地运行。测试以 `tests/fakes.py` 的确定性模型替代全部外部模型，
实际经过 LangChain structured-output parser；禁用 tracing 并阻止网络/外部进程。
R0 不进行真实模型调用，请勿为本阶段启用外部 LangSmith tracing。

R0-C 已完成 Architecture Reset；当前 V3-1A2 仅增加确定性解码，未进入 V3-1B Hardware Security Agent 集成。

架构边界、准入条件、状态语义和后续扩展点见
[docs/architecture/v3-r0.md](docs/architecture/v3-r0.md)。
