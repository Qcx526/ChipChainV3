# ChipChain V3

大模型协同的芯片固件—硬件跨层漏洞攻击链路检测研究工程。
当前阶段：**V3-R0-B — LangChain Agent Infrastructure**。
已完成 **R0-B.1 dependency reproducibility patch**；版本边界由 `pyproject.toml` 管理。
保留已冻结的 R0-A/R0-A.1 Case-first、多架构合同与 workflow。

三个 Security Agent 支持注入 LangChain ChatModel，通过官方 structured output 返回
Pydantic 报告；不注入模型时保留离线 stub。**尚不具备真实漏洞检测、攻击链搜索或触发验证能力。**

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
R0-B 不进行真实模型调用，请勿为本阶段启用外部 LangSmith tracing。

架构边界、准入条件、状态语义和后续扩展点见
[docs/architecture/v3-r0.md](docs/architecture/v3-r0.md)。
