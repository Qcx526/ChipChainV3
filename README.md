# ChipChain V3

大模型协同的芯片固件—硬件跨层漏洞攻击链路检测研究工程。
当前阶段：**V3-R0-A — Foundation Skeleton**。
已补充 **V3-R0-A.1 — Multi-Architecture Foundation Patch**，仍属于 R0 基础合同阶段。

本阶段提供 Case-first Pydantic 数据合同、独立的三 Agent stub 和 LangGraph
工作流骨架。**尚不具备真实漏洞检测、攻击链搜索或触发验证能力。**

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

默认执行完全本地化。请勿为 R0 运行启用外部 LangSmith tracing；测试会禁用 tracing、
移除常见 API key，并阻止网络访问和外部进程启动。

架构边界、准入条件、状态语义和后续扩展点见
[docs/architecture/v3-r0.md](docs/architecture/v3-r0.md)。
