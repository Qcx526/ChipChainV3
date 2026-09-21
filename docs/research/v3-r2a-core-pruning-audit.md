# V3-R2-A：Core 主线审计与 pruning gate

状态：**AUDIT / DESIGN ONLY，等待人工审核；没有删除或修改 production code/tests。**

起始基线 `Qcx526/ChipChainV3`，`main`，HEAD `6278fb7bf550d08b4976a5eeb444c70130a80c13`，exact tag `v3-xl2-stable`；起始工作区干净。
本轮只新增本文、两份逐文件 inventory、[SYN-E2E1 设计](v3-syn-e2e1-controlled-type2-design.md)和 [gap matrix](v3-syn-e2e1-gap-matrix.json)，共五份文档。

## 1. 结论与分类口径

未来主线建议保留：原始证据 → 确定性事实 → 两侧能力/要求 → 兼容性 → 独立运行/RTL 验证 → 可核验结果 → 人类报告。
LLM 保留为可选 reasoning/hypothesis 层；当前真实 paired entry 仍依赖它，不能声称已经实现无模型端到端验证。

| Production 分类 | 数量 | 解释 |
|---|---:|---|
| CORE_REQUIRED | 25 | 科学对象、事实/身份/来源、边界校验、规范报告、当前真实配对身份 |
| CORE_SUPPORT | 62 | 当前 paired 编排/Agent/CLI、适配器、共享数据类型与包边界；未来可拆分但当前不能直接拔掉 |
| HISTORICAL_COMPATIBILITY | 40 | 单侧旧实验、旧格式/adapter、公开重放接口；仍可能有 production importers |
| DELETE_AFTER_GOLDEN_REGRESSION | 0 | 未找到同时满足无主线 caller、无唯一边界保护、无其他入口义务的已证明删除项 |
| UNKNOWN_REQUIRES_REVIEW | 0 | 在此次有限目标下均可给出角色分类；不表示外部 API 消费者或未来泛化需求已被证明不存在 |
| **总计** | **127** | `src/chipchain/**/*.py`，包含 22 个 `__init__.py` 与 1 个 `__main__.py`（计数在下述方法中核验） |

分类是角色判断，不是删除授权。尤其 HISTORICAL_COMPATIBILITY 不等于 unused；需先解除其生产 callers、CLI、exports 和科学边界义务。
未来的 aggressive pruning 应降低阶段性编排与重复维护面，不设强制减到某个模块数的指标。

[production inventory](v3-r2a-core-module-inventory.json) 每个模块恰好一条，包含当前显式/隐式 importers、语法可解析 callsites、test callers、公开 exports、CLI guard、docs 引用、源码 SHA、runtime 观察、replacement、删除前置条件与可恢复 tag/blob。
没有依据文件名自动判 delete。

## 2. 两条主线、静态 closure 与实际调用

### 真实 paired entry

当前实际入口：`python -m chipchain.integrations.paired_baseline --firmware-grounding`（真实运行另需显式 opt-in/env；本轮未执行真实调用）。
`run_paired_baseline` 固定 DATA1A freeze、hello ELF 和模拟器身份，经 XL0 eligible/hash gate 后建立事实，执行三 Agent + A6 支持校验、IR 合并、跨层引用校验并写报告。
CLI 没有被迁到其他目录，也不是通用 controlled experiment runner；不能给它换一个 ELF 就假定获得 SYN-E2E1。

`--firmware-grounding` 仍是 opt-in。paired path 使用 BoundHardwareAgent、GroundedFirmwareAgent、BoundCrossLayerAgent；Hardware B2 supported pipeline 和 XL0 atom matching 都不是该运行的业务步骤。
`deepseek_hardware.validate_real_report` 是共享真实 caller，不能把整个 deepseek_hardware 模块按单侧旧 runner 删除。

### Typed scientific path

两条来源分支汇入比较，**不是 CAP0 顺序调用 XL1**：

```text
ELF + frozen trace → A6 catalog → materialize_a6 → FirmwareCapability
existing explicit XL0 condition + sources → materialize_xl0 → HardwareBehaviorContract
                         两个对象 → XL2 → deterministic Chinese reports
```

这些目前是显式 API 和文档预览，没有集成进 paired workflow。
CAP0/XL1 的 materializer 即使没有 production importer，也有测试、文档复现和真实 preview 消费者；应保留 CORE_REQUIRED。

| 入口/探针 | static import closure | runtime 命名函数所在模块 | Python code 所在模块（含初始化） |
|---|---:|---:|---:|
| paired_baseline + A6 离线回放 | 106 | 33 | 46 |
| A6/CAP0/XL1/XL2 typed rebuild/replay | 38 | 15 | 15 |

静态 closure 递归展开所有 AST imports（包含函数局部/条件分支）、`from package import submodule` 与父包初始化；它是保守依赖集合，不是“106 个模块都被业务运行”。
`cross_layer.__init__` eagerly export matcher/facts，导致旧 XL0 和 A4/A5 类型被加载；观测到 class/module body 也不表示 `match_trigger_condition` 被调用。
`grounding_compatibility` 在本回放只做 absent A4/A5 → not_comparable preflight，不能写成 Ghidra/angr 已执行。

Runtime 采用 `sys.setprofile`，以 AST FunctionDef/AsyncFunctionDef 的首行（含 decorator）过滤真实命名函数，排除 module/class/comprehension body。
集合只说明某次离线路径出现过的 Python 调用；不覆盖其他 CLI flags、失败分支、provider 内部、native 后端或全部动态 dispatch。未观察到的模块不能自动删除。
JSON 分别保留原 code-module 集合、filtered named functions、call edges 和静态 closure；direct_callers 仅做 import alias 的语法解析，不声称完整调用图。

### 本轮安全运行的两个 probe

1. **Paired replay**：复用 R1-A 已有离线 probe 方法。读取冻结 run `100fcbb2-6ac4-4eb5-821c-09a688957a51` 的 trace/诊断；三次模型 transport 全部用 LangChain fake，配置工厂替换为 placeholder，subprocess.run 只复制冻结 trace 到 TemporaryDirectory。网络和 Popen 阻断，不读取 `.env`，不启动模拟器，产物退出即清理。结果 completed，三 fake invocation。它是控制流审计，不是新的真实实验。
2. **Typed replay**：从同一 ELF/trace 重建 A6，catalog SHA 与冻结记录相同；重新 materialize 所选 A6 fact，CAP0 canonical bytes 相同；从保存的 selected_xl0_condition 重新 materialize XL1，canonical bytes 相同；比较并 replay 校验 XL2，JSON 与既有 preview 字节完全相同；三个 renderer 在内存中执行。未写 repository output。

真实 XL2 保持：

- FW `fwcap:a7d884ec659e96b689a69266e5b43ef99f05d5f07340e7fc5def431a9aedc749`
- HW `hwbehavior:48dba3c5ba26c30d65fba23d8293c7689443bbd362a0616e698a19c4492b197c`
- Result `xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded`，**UNKNOWN**
- 架构一致；platform/processor/scope 信息不足；DIRECT_CONTROL_TRANSFER 无 instruction trigger mapping。没有扩大映射或改历史结果。

这个完整 real UNKNOWN 的 byte replay 当前是本次只读 probe；现有 committed tests 保护大量 synthetic XL2 边界和 A6 的小型真实回归值，但没有独立 committed test 自动连接上述三个 ignored preview。未来 pruning gate 必须补一个显式本地 real replay regression，缺本地输入则 gate BLOCKED，不能用 pytest skip 冒充保持。

## 3. 十个优先评审的未来退役候选

以下按审查顺序排列，**全部仍是 HISTORICAL_COMPATIBILITY，当前不满足删除条件**。
每行还必须满足第 6 节全部 gate；表中 replacement 是目标，不代表已经实现。

| # | Module（src/chipchain/ 下） | 当前 obligations | Replacement / 额外前提 |
|---|---|---|---|
| 1 | `integrations/angr_static_reachability.py` | 无显式 production importer；有 python -m CLI；1 direct test callers；docs/public replay 需迁移 | 独立 optional A5 invocation 或按 v3-2a5-stable 复现；主线不提供同名自动替代；从 CLI/docs 和 integrations 用户面退役 A5 fresh preparation |
| 2 | `integrations/deepseek_firmware.py` | callers: execution/reviewed_output.py, integrations/angr_static_reachability.py, integrations/firmware_relations.py；有 python -m CLI；10 direct test callers；docs/public replay 需迁移 | 未来 optional reasoning runner + 保留输入/失败持久化边界；旧 Heat_Press replay 用 tag；先断开 reviewed_output/firmware_relations/angr_static_reachability 的环状调用 |
| 3 | `integrations/deepseek_hardware_supported.py` | 无显式 production importer；有 python -m CLI；2 direct test callers；docs/public replay 需迁移 | optional typed reasoning adapter；旧 B2 preflight 由 v3-hw-b2-stable 复现；退役单侧 B2 CLI 并保留 referenced-support 拒绝与安全诊断回归 |
| 4 | `integrations/firmware_relations.py` | callers: execution/reviewed_output.py, integrations/angr_static_reachability.py, integrations/deepseek_firmware.py；3 direct test callers；docs/public replay 需迁移 | 按 tag 的 B3 preparation；核心事实留 A6/CAP0；移除 DeepSeek firmware/A5/reviewed 的调用；绝不能删 A4 scientific evidence |
| 5 | `integrations/hardware_typed_relations.py` | callers: integrations/deepseek_hardware_supported.py；有 python -m CLI；2 direct test callers；docs/public replay 需迁移 | 显式 read-only hardware fact API；保留 relation_builder/relations；先迁移 supported runner 调用及 real 743 fact identity 回归 |
| 6 | `tools/firmware/ghidra/__main__.py` | 无显式 production importer；有 python -m CLI；0 direct test callers；docs/public replay 需迁移 | optional backend 命令或 tag CLI；不会由 synthetic bus parser 等价替代；CLI/doc/public usage 退出；保留 backend isolation/timeout 校验若仍使用 Ghidra |
| 7 | `tools/firmware/angr_cfg.py` | callers: integrations/angr_static_reachability.py；有 python -m CLI；1 direct test callers；docs/public replay 需迁移 | tag 上的 optional CFGFast backend；保留 static_reachability schema；A5 runner 退役；审查 future CFG 需求及唯一 no-execution-proof regression |
| 8 | `agents/projections/firmware_envelope_v3.py` | callers: agents/firmware.py, execution/reviewed_output.py, integrations/deepseek_firmware.py, integrations/firmware_relations.py；2 direct test callers；docs/public replay 需迁移 | optional reasoning envelope 统一入口（尚未实现），旧精确 wire replay 用 tag；先处理 FirmwareSecurityAgent/deepseek/reviewed/B3 callers 和 lossless-evidence 保护 |
| 9 | `execution/reviewed_output.py` | callers: integrations/deepseek_firmware.py；有 python -m CLI；5 direct test callers；docs/public replay 需迁移 | 独立 read-only snapshot validator（尚未实现）；exporter CLI 仅 tag；迁移 main callers、保留 snapshots/negative records/manifest hashes/secret filtering，旧结果可验证 |
| 10 | `firmware/grounding_report.py` | 无显式 production importer；2 direct test callers；docs/public replay 需迁移 | 现有 chipchain.reporting.firmware_grounding.render_report；迁移 test imports 和重放文档、确认无外部 old-import consumers，renderer parity 保护保留 |

这些文件的当前 exact blob 都可从 `v3-xl2-stable` 恢复。更早阶段 tag 不一定与当前 blob 相同；逐文件 `same_blob_stable_tags` 给出精确证明，不能把“文件存在”当“版本相同”。

## 4. Tests inventory 与最小 regression proposal

[test inventory](v3-r2a-test-inventory.json) 覆盖 `tests/**/*.py` 全部 68 文件，含 60 个 test-bearing 文件和 8 个 package/helper/conftest 文件。
不把 helper 算成“测试用例”；参数化后的本次总 case 数为 1385（1358 pass、27 skip）。

| 分类 | 所有 tests Python 文件 | 其中 test-bearing |
|---|---:|---:|
| CORE_REGRESSION | 25 | 17 |
| SCIENTIFIC_BOUNDARY_REGRESSION | 19 | 19 |
| HISTORICAL_PHASE_REGRESSION | 24 | 24 |
| REDUNDANT_AFTER_GOLDEN | 0 | 0 |
| UNKNOWN_REQUIRES_REVIEW | 0 | 0 |

Inventory 记录每个 test 函数名/行号、assert 数量、production imports、其他 tests 使用其 helper 的关系、保护主题和 exact-blob tags。
函数体 AST 去名字/位置信息后相等的组数为 **0**；这不证明没有语义重复。反过来，若出现相同 AST，也要比较 fixture、参数、版本与断言对象，不能自动删除。
fixture 隐式依赖（尤其 `conftest.offline_only`）不在 direct importers 中，始终保留。

重点 overlap 与风险：

| 组 | 可考虑缩减的重复维护面 | 不能丢的独有语义 |
|---|---|---|
| CAP0 / XL1 / XL2 codec、identity、report tests | 共用测试 harness/参数化 duplicate-key、tamper、set-order checks | 每个 schema 的 identity payload、规则版本、ordered vs set-like 集合不同；CAP0 materializer 还要重解码字节 |
| `test_domain` / `test_run_contracts` / `test_case_lifecycle` | 重复 round-trip setup | Case 不含 run 动态信息、独立 provenance、失败隔离和 empty/11-case semantics |
| `test_agents` / `test_langchain_agents` / `test_workflows` / `test_langchain_workflows` / paired tests | fake model/setup 和 happy path 可集中 | 离线 stub、真实 LangChain parser、LangGraph failure isolation、真实入口 binding 并不互相替代 |
| Firmware v1/v2 envelopes / B3 support / orphan / diagnostics / output capacity | 旧 transport 的同类 schema-valid setup 与 serialized catalog registry | v1/v2 acceptance policy不同；orphan 可诊断而 referenced 必须支持；安全错误不泄露 raw prose；截断/必填字段保护 |
| XL0 matcher vs XL2 compatibility | 部分 architecture / UNKNOWN / exact constraint fixtures | fact binding 与 capability-domain containment 语义不同，不能“升级后删旧边界” |
| renderer facade / canonical report tests | 未来旧 import facade 退出后可去旧 import assert | 原 renderer oracle parity、raw text 与 canonical fact 隔离、HTML/Markdown escaping 仍保留 |
| reviewed exporter vs report persistence | manifest/hash/来源一致性 setup 可复用 | 人工审核许可、失败状态拒绝、字段允许列表、保密信息清理、历史快照可验证性 |

**建议的最终 Core regression 责任集**（逻辑组，非本轮改名/合并文件）：

| 责任组 | 当前必须保留的测试来源 | future golden 需补 |
|---|---|---|
| Identity/provenance + target | `test_artifact_identity`、`test_domain`、`test_architecture`、`test_run_contracts`、`test_cross_layer_eligibility` | controlled build/run/input identity 与 GT firewall |
| Firmware deterministic grounding | `test_firmware_a6`、`test_firmware_a6_evidence`、`test_firmware_a6_workflow` | MMIO ELF known-answer、unknown propagation；不替代 RV32 signed/compressed target 与 owner 边界 |
| FirmwareCapability | 三份 `test_firmware_capability*` | MMIO facts→CAP materializer 与 literal address/value/width/conditions |
| HardwareBehaviorContract | 三份 `test_hardware_behavior_contract*`、`test_cross_layer_contracts` 中 trigger/codec 保护 | controlled contract来源、requirement/actual 分离 |
| Compatibility | 两份 `test_capability_compatibility*` | 多事件 state/revision 版本化语义后另测；frozen v1 UNKNOWN 保持 |
| Real Ibex inputs | `test_encorpus_ingestion`、`test_encorpus_projection`、`test_riscv_decoding`、`test_hardware_typed_relations`、`test_paired_baseline` | 真实 A6/CAP0/XL1/XL2 内容哈希与 UNKNOWN byte replay；ignored 数据显式 gate |
| Controlled runtime verification | 尚无等价测试 | request/response/byte-enable/reset/order/state/trace completeness；错误/缺失证据 adversarial cases |
| Controlled differential + E2E | 尚无等价测试 | P1/N1/N2/U1；firmware/config/input不一致拒绝；负结果不能因 trace 缺失通过 |
| Reporting/evidence preservation | capability/contract/compatibility reports、`test_reporting_compatibility`、`test_reviewed_output` 边界子集 | 四-case 状态解释、一屏可读、GT 不进入分析事实 |
| Optional reasoning & lifecycle | `test_firmware_grounding`、`test_firmware_model_outputs`、`test_langchain_agents/workflows`、case lifecycle、A6 workflow | 仅在继续支持 Agent 时保留其引用/拒绝/提示投影/失败隔离；不让模型成为 deterministic oracle |

实际 prune 前须建立“旧 assertion/nodeid → survivor nodeid/明确退役理由”的矩阵，特别保护唯一 negative/unknown 断言。
一个 P1 happy path 无法覆盖 serialization corruption、错误 binding、模型输出污染或条件含混；不能用 golden 四例替代全部单元测试。
24 份 HISTORICAL_PHASE_REGRESSION 主要覆盖单侧 Heat_Press/Ghidra/A3–A5、Firmware B2/B3、Hardware B2 和旧 XL0 matching；角色分类不许可删除仍支持功能的唯一回归。

## 5. Git 历史恢复与研究记录保护

不建议 `legacy/`、`archive/`、`old/`。已真正退役的实现将来可从 main 删除，通过 Git tag 恢复；搬目录只增加另一层维护。
这不适用于研究证据的销毁。raw LLM outputs、负/UNKNOWN 实验、DATA1A blocked attempt、reviewed snapshots、scientific reports 应独立保留。

代码和依赖声明可以在 stable tag 上读取/重建；ignored 样本、真实 ELF、工具安装、模型服务和 runtime output **不在 tag 中自动恢复**。必须另有本地/长期 artifact manifest/hash 与环境保存。
历史模型 replay 也不保证外部服务能产生相同输出，应保留原始已审核/拒绝结果。

本地已验证存在的关键恢复锚点：

| 阶段 | Stable tag | Commit |
|---|---|---|
| A6 | `v3-fw-a6-stable` | `39e72ee3a5cc1dd2eb1bb3db10ed218b93894c5e` |
| XL0 | `v3-xl0-stable` | `b743984d60f4cb0a489fdcd2170484252bcab348` |
| XL1 | `v3-xl1-stable` | `34f6629475b5bdc224a8b2d9a5017145b8a2f291` |
| FW-CAP0 | `v3-fw-cap0-stable` | `6acfbd25ab0db5293c1385927cb6b24b5c60a67d` |
| XL2 | `v3-xl2-stable` | `6278fb7bf550d08b4976a5eeb444c70130a80c13` |
| R1 audit | `v3-r1a-audit-stable` | `a9c7e3d96e7bcf78b7c669b5abb5d47e4b5e9294` |
| R1.1 | `v3-r1-1-boundary-refactor-stable` | `ec02a117e414f26e32043a7d9c0bd3964c6485ea` |
| DATA1A | `v3-data1a-stable` | `408710140df9bd275e6b4d07883a8cde1e4354de` |

可只读使用 `git show <tag>:<path>` 查看，或以后按审核决定在独立 checkout 恢复；本轮未 checkout、创建/移动 tag 或提交。
CURRENT_STATE.md 仍保留 R1.1 的阶段性表述（含当时“缺完整能力/合同”的文字），与之后已冻结 CAP0/XL1/XL2 不完全同步。本次只新增五文件，因此记录这个文档债，不修改历史/状态入口，也不据它否定实际存在的模块。

## 6. R2-B pruning gate

**SYN-E2E1 完整 golden regression 尚不存在，当前 R2-B BLOCKED。**
未来删除一个 module/test 必须同时满足：

1. 不属于 CORE_REQUIRED；若想替换核心实现，另行审查，不属于本 pruning 授权。
2. 没有当前 production caller；CLI、公开 exports、动态加载、文档复现和外部 API 消费者也已迁移或明确退役。删除整组模块需按最终剩余图证明闭包，不允许先断 import 再声称无人使用。
3. 不是科学边界唯一 regression；旧 assertion 到 survivor 映射已审核。
4. P1/N1/N2/U1 均按各自 expected outcome 通过，包含 GT firewall、trace完整性与未知传播；不是四个都返回 positive。
5. Real Ibex 的 A6/CAP0/XL1 及 XL2 UNKNOWN result identity/reasons/bytes 保持，缺 ignored 输入会阻塞 gate。
6. exact blob stable tag、依赖/环境与必要 local artifacts 可恢复；tag 仅存在还不够。
7. docs/research、reviewed/negative/raw artifacts、blocked DATA1A 记录不丢失。

未来目标可以观测为：阶段性 CLI 数减少、provider projection/support 分支与循环依赖减少、typed mainline import surface 变小、tests setup 复用。但没有为凑比例设删除配额。
最优先消除维护耦合包括 `deepseek_firmware ↔ reviewed_output/firmware_relations`，以及 `cross_layer.__init__` 导入旧 matcher/facts 扩大 typed closure；先迁移依赖，后评估文件删除。

## 7. 可复核方法与本轮验证

方法在临时目录 `/tmp/chipchain-r2a/` 执行，helper 不作为 production/test 提交；inventory 是冻结 HEAD 的文档快照。

- `git ls-files` 起始全集做逐文件 SHA256 保护；记录 HEAD 和 `git show-ref --tags`。
- 对排序后的 `src/chipchain/**/*.py` / `tests/**/*.py` 使用 Python `ast.parse`。所有 `Import`/`ImportFrom`（包括局部/条件分支）按 package/level 解析；`from x import y` 若 `x.y` 是模块则同时记录；closure 显式纳入父 `__init__.py`。
- 逆向边产生 importers/test callers；Call 的 Name/Attribute 按当前文件 import aliases 语法解析，动态/receiver 未解析部分保留限制。扫描 `import_module`/`__import__`：本次 production 未找到，tests 发现 4 个 reporting compatibility sites（见 inventory）。
- 读取 `pyproject.toml`：无 `[project.scripts]`；扫描 `__main__` guards、`__all__`、tracked docs/scripts/examples/reviewed/samples metadata 中完整模块名/路径引用。引用检索是文本证据，不表示所有语义消费者都可静态发现。清单按文档分组，每组保存前 8 个示例行、总匹配行数和 truncated 标记；历史 audit JSON 的自引用不算 runtime caller。
- tests 扫全部 test 函数、assert、imports、helper importers；AST 函数体归一化只作为 duplicate lead。重复保护的最终判断检查版本/fixture/预期拒绝原因，未证明任何 whole-file redundant。
- `git ls-tree -r <tag>` 的 blob ID 与 HEAD 对照，逐文件输出 exact-blob stable tags；不把首次同名文件视为语义相同。
- Paired probe 源方法位于既有 [R1 audit methods](v3-r1-audit-methods.md) 的 `replay.py` block；本轮只改变临时输出路径并额外阻断 sendto/getaddrinfo/Popen。模型与模拟调用替换规则相同。
- Typed probe 使用 CAP0/XL1 文档已有 materialization API 重建相同对象。独立根集合为 grounding_catalog、两个 materializers、三个 reports、XL2 matcher；静态集合与实际调用数据完全分列。
- 所有 machine-readable 清单按 path 排序；嵌套集合/边/引用排序，无时间/UUID。固定采集输入再次生成 inventory 应逐字节一致。

可独立重做最关键 typed real replay（只读）如下；完整 runtime 函数/边已保存在 production inventory，不依赖 `/tmp` 长期存在：

```python
from pathlib import Path
from chipchain.firmware.control_flow_grounding import parse_catalog
from chipchain.firmware.grounding_catalog import build_catalog
from chipchain.firmware.capability import parse_firmware_capability, serialize_firmware_capability
from chipchain.firmware.capability_materialization import materialize_a6
from chipchain.hardware.behavior_contract import parse_hardware_behavior_contract, serialize_hardware_behavior_contract
from chipchain.hardware.behavior_contract_materialization import materialize_xl0
from chipchain.cross_layer.trigger import parse_hardware_trigger_condition
from chipchain.cross_layer.capability_compatibility import compare_capability_contract, serialize_compatibility_result, validate_compatibility_replay

base = Path('output/ibex-simple-system:hello-test:paired-workspace')
run = base / '100fcbb2-6ac4-4eb5-821c-09a688957a51'
hdir = Path('output/encorpus:ibex:driver:743/xl1-48dba3c5ba26c30d')
catalog = parse_catalog((run / 'firmware_control_flow_grounding.json').read_text())
rebuilt = build_catalog(case_id=catalog.case_id,
    elf_path=Path('samples/firmware/ibex-simple-system/hello-test/hello_test.elf'),
    trace_path=run / 'simulation/trace_core_00000000.log',
    target=catalog.target, trace_semantics='ibex_rvfi_retirement')
assert rebuilt.catalog_sha256 == catalog.catalog_sha256
fw = parse_firmware_capability((base / 'fw-cap0-a7d884ec659e96b6/firmware_capability.json').read_text())
fact = next(f for f in rebuilt.transfer_facts if f.instruction_pc == 0x100080)
assert serialize_firmware_capability(materialize_a6(rebuilt, fact_id=fact.fact_id)) == serialize_firmware_capability(fw)
hw = parse_hardware_behavior_contract((hdir / 'hardware_behavior_contract.json').read_text())
xl0 = parse_hardware_trigger_condition((hdir / 'selected_xl0_condition.json').read_text())
source_id = next(s.artifact_id for s in hw.source_artifacts if s.source_kind == 'xl0_trigger')
copy = materialize_xl0(xl0, platform=hw.platform, source_artifacts=hw.source_artifacts,
    evidence=hw.evidence, xl0_artifact_id=source_id)
assert serialize_hardware_behavior_contract(copy) == serialize_hardware_behavior_contract(hw)
result = compare_capability_contract(fw, hw)
validate_compatibility_replay(result, fw, hw)
assert result.overall_result == 'unknown'
assert serialize_compatibility_result(result) == (base / 'xl2-34bfee41ac1fc6b4/compatibility_result.json').read_text()
```

验证：

```text
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
1358 passed, 27 skipped in 32.72s

.venv/bin/python -m pip check
No broken requirements found.

.venv/bin/python -m compileall -q src tests
exit 0

git diff --check
exit 0
```

27 项 skip 不代表真实 tool/LLM 验证通过。runtime audit 的 3 次 fake invocation 也不计入真实调用。
本次没有新增 tests，没有修改 production/test 文件，没有运行真实模型、编译/运行新 RTL 或 firmware。
最终验证：280 个原有 tracked 文件 SHA256、HEAD 和全部 tag refs 均保持不变；两个 inventory 和 gap matrix 在固定采集输入下再次生成，逐字节相同；127/68 个文件均恰好覆盖一次，64 项答复齐全，JSON、文档链接、排序和空白检查通过。

`git diff --name-status` 为空；普通 diff 不包含 untracked，故额外检查了全部新文件。实际 Git status：

```text
?? docs/research/v3-r2a-core-module-inventory.json
?? docs/research/v3-r2a-core-pruning-audit.md
?? docs/research/v3-r2a-test-inventory.json
?? docs/research/v3-syn-e2e1-controlled-type2-design.md
?? docs/research/v3-syn-e2e1-gap-matrix.json
```

## 8. 完成报告：64 项答复

| # | 答复 |
|---|---|
| 1 | main / `6278fb7bf550d08b4976a5eeb444c70130a80c13` / `v3-xl2-stable`，起始干净。 |
| 2 | Production Python modules 127，含包初始化和 CLI module。 |
| 3 | tests Python 文件 68；其中 60 test-bearing，8 support/config/package；不是 68 个测试用例。 |
| 4 | CORE_REQUIRED 25。 |
| 5 | CORE_SUPPORT 62。 |
| 6 | HISTORICAL_COMPATIBILITY 40。 |
| 7 | DELETE_AFTER_GOLDEN_REGRESSION 0；没有凑删除数字。 |
| 8 | UNKNOWN_REQUIRES_REVIEW 0（有限主线目标下角色可分）；外部消费者/未来泛化的未知仍写在 risk/gates。 |
| 9 | `chipchain.integrations.paired_baseline` CLI / run_paired_baseline，A6 需 `--firmware-grounding`；本轮只做 fake transport 冻结 trace 回放。 |
| 10 | ELF/trace→A6→CAP0；独立 XL0 typed input→XL1；两侧→XL2→reports；尚非单一 integrated CLI。 |
| 11 | Static 是全分支/父包初始化的可能依赖：106/38；本次 offline named-function observed 是 33/15；不能推导全 runtime 必需/无用。 |
| 12 | 十候选见第 3 节完整列表，均暂列 historical，不是当前获准删除项。 |
| 13 | 每项 replacement 在第 3 节与 module inventory；唯一现成 facade 替代为 reporting.firmware_grounding；其余共用组件迁移/旧 tag replay/optional runner 均需审核。 |
| 14 | 无 production/CLI/export/docs consumer、非唯一科学边界、四 golden + real UNKNOWN、tag/blob/environment 可恢复、证据不删。 |
| 15 | 全部当前文件可由 v3-xl2-stable 精确恢复；A6/XL0/XL1/CAP0/R1 tags commit 见第 5 节；逐文件 same_blob_stable_tags。 |
| 16 | identity/provenance、A6 与 workflow gate、CAP0/XL1 materialization/schema/report、XL2、paired ingestion 和 oracle firewall；第 4 节有实际文件映射。 |
| 17 | 24 个 HISTORICAL_PHASE_REGRESSION test-bearing 文件。 |
| 18 | 0 组完全相同归一化 test body；同主题 serialization/setup/旧 wire/support policy 有合并空间，但整文件 REDUNDANT 证据不足，计 0。 |
| 19 | 十个责任组见第 4 节；保留单位级 negative/unknown 断言，新增 MMIO/runtime/differential/GT firewall 和真实 UNKNOWN gate；本轮不合并/改名。 |
| 20 | 不建议 legacy/。 |
| 21 | 真正 obsolete 的代码由 Git tag 恢复；搬旧目录不降低维护成本；研究证据另行保留。 |
| 22 | pinned Ibex Simple System small 加独立 synthetic MMIO peripheral，新的实验 target identity。 |
| 23 | 是，复用 bus、RAM、harness、软件构建基础；不覆盖原冻结样本。 |
| 24 | wrapper 的 device enum/NrDevices/base-mask/设备接线、core fileset、新外设与共同 monitor；同一 C++ Verilator harness 配置。 |
| 25 | 不适用；若未来该 snapshot 无法可靠重建则先记录 BLOCKED，不偷偷换平台。 |
| 26 | proposed BASE=0x40000；ENABLE +0、COMMAND +4、STATUS +8；32-bit full-word；窗口 1 KiB。 |
| 27 | 与 pinned SimCtrl 0x20000/1KiB、Timer 0x30000/1KiB、RAM 0x100000/1MiB 不重叠；未来仍需 elaborated map 验证。 |
| 28 | Reference 正常保存 ENABLE/COMMAND；STATUS reset 后保持 0，非法访问不改状态。 |
| 29 | Variant 在 COMMAND=0xa5 的完整合法写且旧 ENABLE=1 时把 STATUS 置 0xdead，直到 reset。 |
| 30 | reference/variant 仅该 STATUS next-state 更新语义不同；共同 wrapper/monitor/软件/输入/配置相同。 |
| 31 | P1 正常例程写 ENABLE=1、COMMAND=0xa5、读 STATUS、保存结果并退出；与 N2 的 ELF 完全相同；本轮未写固件。 |
| 32 | 最终目标八层通过→verified controlled synthetic chain；当前 P1 未实现且完整 frozen XL2 因 revision/state 等缺口 UNKNOWN。 |
| 33 | N1 COMMAND=0xa4；明确值冲突或 runtime trigger 不成立；完整窗口无受控偏差。不能把缺 trace 当 PASS。 |
| 34 | N2 同 P1 固件但 Reference；trigger 实际发生而 STATUS=0，停止于 deviation 层；不混绑 variant 合同。 |
| 35 | U1 故意缺 observation→run/RTL/config binding，已有数字值不能弥补；verification/final UNKNOWN。 |
| 36 | evaluation-only controlled-ground-truth/v1-proposed：case、synthetic、两 RTL/firmware/input identities、patch、expected behavior/trigger/deviation/observation/outcome；本阶段未生成实例。 |
| 37 | neutral analysis IDs、artifact allowlist、独立 evaluator 目录/API、分析先固定哈希；改变/删除 GT 不改变分析输出；无 GT→matcher/Agent 流。 |
| 38 | 完整 Platform/Preconditions/Trigger/Deviation/Observation/Scope；ENABLE write 是事件，ENABLE at COMMAND 是状态条件；不为 matcher 随便分类。 |
| 39 | normal_behavior；MMIO_WRITE ENABLE/COMMAND、MMIO_READ STATUS；exact constraints/ordering/evidence/conditions；control not_established；normal origin 与 synthetic_only scope 不能非法混用。 |
| 40 | 没有 Ibex deterministic MMIO→CAP producer；A6 materialize_a6 仅 transfer；Heat_Press 配置与 RVFI raw text 不等价。 |
| 41 | 有界 RV32 ELF MMIO facts + byte/source/constant-propagation binding → 显式 CAP materializer；独立 bus-event producer，保留未知条件。 |
| 42 | MMIO resource/direction/address/eq-value/width、平台 exact、已映射端点 ordering；数值包含方向 FW⊇HW。 |
| 43 | RTL revision/ISA语义、外设 state/reset、多 primitive precondition context、未建立路径条件、范围量词等；详见 14-row gap matrix。 |
| 44 | proposed synthetic peripheral bus-event monitor；RVFI 辅助，不从 encoding 或文本猜实际 MMIO。 |
| 45 | 设备接受的 req + 下一周期无错 response、address/we/be/wdata、reset/identity；只见 CPU store 不够。 |
| 46 | 单 reset epoch 下 cycle/phase/sequence/transaction IDs，ENABLE 在 COMMAND 前且无覆盖/reset；状态快照验证，不按数组位置猜。 |
| 47 | internal RTL STATUS post-update，另用 bus-visible STATUS read response 交叉验证。 |
| 48 | 独立 HardwareDeviationObservation，绑定 requirement、run/RTL/config/ELF/input/trace hash、采样点和值；与 XL1 ObservationRequirement 分开。 |
| 49 | 两构建同源基础、same firmware/input/harness/engine/toolchain/config/reset/seed/初始RAM；只允许 reviewed RTL patch，分别记录派生 executable hash。 |
| 50 | ControlledHardwareDifferential：两run/RTL/executable hashes、固定输入、allowed patch、完整窗口、比较信号域、first divergence、expected/observed、source/trace refs、UNKNOWN原因。 |
| 51 | P1 1–8 层均成立且同组身份绑定无缺口，所有未解决 requirement 保持阻塞；当前并未满足。 |
| 52 | N1 analyzer 不提升为链，明确非触发命令，complete-window 无偏差；evaluator expected-negative 通过。 |
| 53 | N2 trigger 满足而 reference 偏差不发生，binding正确、完整窗口，不能输出 verified chain。 |
| 54 | U1 缺失 binding 精确定位并传播 UNKNOWN，不能用 GT 或另一个 run 补值。 |
| 55 | LLM 不是必需组件，也不是 pass/fail oracle。 |
| 56 | 确定性 golden 固定后，比较 without LLM / with candidate reasoning；共享相同 raw inputs/verifier/GT firewall，比较候选帮助、错误和成本。 |
| 57 | 同一四-case 模板：结论、固件行为、硬件要求、兼容性版本、runtime trigger、实际 STATUS、reference/variant对照、缺口与 synthetic 边界。 |
| 58 | MMIO facts、run/target binding、bus events、applicability、trigger satisfaction、actual observation、deviation verification、controlled differential/chain、GT/evaluation；全部仅提案。 |
| 59 | A6/XL0/XL1/FW-CAP0/XL2 frozen schemas 与当前 matcher、Agent/prompt/workflow 均未改。 |
| 60 | 完整 SYN-E2E1 golden regression 存在且七项 pruning gates 满足后，才允许另行审核 R2-B。 |
| 61 | P1/N1/N2/U1、GT isolation、真实 Ibex UNKNOWN exact replay、对应 identity/provenance/negative/unit boundaries、retained paired routing/optional Agent guards。 |
| 62 | 建议先做 SYN-E2E1，以 reference/variant客观日志闭环为第一个小步骤，再接 producer/verification。 |
| 63 | 不建议同时删除 production code/tests。 |
| 64 | 最小 proposal 见设计文档第 10 节：隔离构建与 MMIO monitor/固件→同源差分记录→producer/firewall→单独审核 matcher/适用性缺口→四 golden；本轮未执行。 |

## 9. 下一步与本轮结束

建议人工先审核两个决定：使用 `0x40000` synthetic 外设及同源 reference/variant 对照；接受当前 frozen XL2 对完整要求仍 UNKNOWN，并将 revision/state 的后续接口设计单独列入阶段。
这不是要求本轮额外批准动作；本轮已按 audit/design 范围完成并停止。

没有 git add / commit / push / tag，没有 production/tests/历史材料修改；新增文件尚待人工 review。
