# ChipChain V3 — Current State

本文件是“现在项目做到哪里”的唯一 current-state 入口。历史阶段文档保留各自实验、负结果和验收语境，不代表全工程的当前状态。

## Current Frozen Baseline

| 基线 | Tag / commit | 含义 |
| --- | --- | --- |
| V3-R1-A frozen | `v3-r1a-audit-stable` / `a9c7e3d96e7bcf78b7c669b5abb5d47e4b5e9294` | Architecture audit snapshot；没有修改 A6 生产语义 |
| A6 frozen | `v3-fw-a6-stable` / `39e72ee3a5cc1dd2eb1bb3db10ed218b93894c5e` | 当前 deterministic firmware grounding scientific baseline |

R1.1 是 **behavior-preserving architecture cleanup**：明确此状态入口，并将纯中文 renderer 移入 reporting 层、保留旧 import。它不是新检测能力，也不是新科学实验；未创建新的 stable tag。

## Current Real Paired Entry

在 repository root、激活项目 `.venv` 且本地 `.env` 和冻结样本准备完毕后，真实入口为：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=1 \
python -m chipchain.integrations.paired_baseline \
  --env-file .env \
  --firmware-grounding
```

这是调用模型服务并运行固定 Ibex baseline 的显式入口；R1.1 本身没有执行此命令。

`--firmware-grounding` **目前不是无条件默认行为**。不带 flag 的 legacy/generic paired path 仍存在，尚未弃用。无参数的通用 workflow/Agent 仍保留 R0 offline stub；它与上述显式真实入口不同。

当前 paired integration 专用于本地 Ibex Simple System + hello_test、既有 DATA1A freeze 和 pair identity，尚不是通用跨平台 paired runner。真实 samples/output 默认被 Git 忽略，clone 不会自动获得完整运行材料。

## Current Mainline

```text
Frozen pair / target identity（含 XL0 pair eligibility）
→ Ibex ELF + trace ingestion
→ deterministic observations
→ A6 control-flow grounding catalog
→ A4/A5 compatibility preflight when supplied
→ Hardware Agent
→ Grounded Firmware Agent
→ deterministic typed-claim validation
→ Unified IR aggregation
→ Cross-Layer Agent
→ reference validation
→ canonical JSON artifacts
→ human-readable reporting
```

- XL0 **pair eligibility 被使用**；XL0 trigger atom matcher 当前 paired run **未执行**。
- Hardware paired path 仍使用 **generic ID-bound Hardware Agent**，不是 Hardware B2 typed-support pipeline。
- Cross-Layer Agent 使用 ID/reference binding；这不等于完成对所有自然语言因果声明的确定性校验。
- A4/A5 对传入的同源 catalog 做 compatibility preflight；当前 paired regression 没有同源 catalog 时为 **not_comparable**，不能写成 agree 或“已运行 A4/A5 全流程”。
- A6 检查选定 Firmware target/owner typed claims；错误或未获支持的声明不进入规范固件报告。原始摘要始终仅供诊断，即使对应 typed proposition 获支持也不直接复制其文字。
- A6 catalog **不等于完整 firmware CFG/capability**。IR 汇合现有 behaviors，不自动容纳所有 A6 facts 或 runtime events。
- RTL trace 先于模型产生并作为证据输入；不能把此顺序写成 LLM 之后才运行 RTL 来证明全部声明。

单侧 EnCorpus、Heat_Press、Hardware B2、Firmware B3、A4/A5 与 reviewed-export 路径保留用于各自研究与回放，不代表全部都在 paired runtime 中执行。

## Scientific Boundaries

| 已有概念 | 不能等同于 |
| --- | --- |
| Typed proposition supported | raw LLM prose fully correct |
| Static target | runtime taken edge |
| Function ownership | reachability |
| Runtime retirement | external-input controllability |
| Cross-layer candidate | verified attack chain |
| 0 candidate | platform safe |
| Analysis capability | target input capability |

当前仍缺失或未建立：

- indirect runtime target resolution；complete function ownership。
- path feasibility；external input controllability。
- 完整 FirmwareCapability 与 HardwareBehaviorContract 抽象。
- controlled RTL differential；physical-board validation。

既有 XL0 trigger contract 不等于未来完整 HardwareBehaviorContract。研究字段 `paired_rtl_runtime_regression` 不自动提升每条声明的验证等级；全局 E0–E4 schema 尚未实现。A6 保留 unknown/missing/ambiguous；分析者能读 ELF/trace 不代表目标用户能控制 PC、寄存器或任意调用。

## Evidence and Validation Index

- [A6 scientific baseline 与真实回归](docs/research/v3-fw-a6-evidence-validation.md)：target/owner gate、原始文字错误、accepted canonical facts 的边界。
- [R1-A architecture audit](docs/research/v3-r1-architecture-audit.md)：116 个生产模块；58 CORE、6 KEEP_RELOCATE、51 RESEARCH_COMPATIBILITY、0 ARCHIVE、0 DELETE、1 UNKNOWN。
- [R1.1 renderer 迁移与验证](docs/research/v3-r1-1-boundary-refactor.md)：冻结旧 renderer 的 synthetic parity oracle、兼容导出、精确测试结果。
- [DATA1A paired baseline](docs/research/v3-data1a-ibex-simple-system-baseline.md)：保留 blocked attempt、恢复过程和平台身份。
- [历史配对 LLM pilot](docs/research/ibex-paired-llm-pilot.md)：包含真实语义错误，不因 A6 而改写。
- [人工验收资料](docs/reports/acceptance/README.md)与[教学快照](docs/tutorials/report-walkthrough/README.md)：各自保留原验收范围，不能统称最新 accepted truth。

离线验证入口：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests
git diff --check
```

R1.1 仅调整展示层位置，不改变 prompt、schema、support、facts、CLI defaults 或跨层逻辑。没有批量删除、历史整理、RTL mutation、真实 LLM 回归或新能力实现；后续阶段须另行确定范围。
