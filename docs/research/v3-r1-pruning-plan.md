# V3-R1 / R1-A — Pruning Proposal (NOT EXECUTED)

Baseline: `39e72ee3a5cc1dd2eb1bb3db10ed218b93894c5e` / `v3-fw-a6-stable`。
本文件是未来行动提案，不是执行许可。当前生产代码、tests、README、历史artifact和tag保持原样。
逐模块分类与八项删除gate见 [inventory](v3-r1-module-inventory.json)；事实依据见 [audit](v3-r1-architecture-audit.md)。

## KEEP

- 58 个 CORE_MAINLINE 模块：domain contracts、workflow/run lifecycle、共享runtime/context、A6 facts/support等。分类不是“已完全解耦”的认可。
- 51 个 RESEARCH_COMPATIBILITY：冻结阶段工具、支持策略、投影、prompt、XL0与corpus适配；保留历史重放，而非宣称都进入paired主线。
- 6 个 KEEP_RELOCATE 在未批准迁移前也必须原位保留。
- `tools/artifacts.py` 为 UNKNOWN_REQUIRES_REVIEW，仍保留。不能用“只有testsimport”跳过public API gate。
- 所有原始run、rejected报告、B3负例、DATA1A blocked/success、A6新旧回归、reviewed与tutorial snapshots、oracle separation记录、samples metadata、stable tags全部KEEP。
- R0 stub分支仍是可到达公共API；没有批准离线workflow替代方案前不能删除。

## RELOCATE

六个候选表示未来目标，不代表六个本批都迁移。

| 现有文件 | 未来目的 | 本批？ | 原则 |
| --- | --- | --- | --- |
| `src/chipchain/firmware/grounding_report.py` | `src/chipchain/reporting/firmware_grounding.py` | **仅此文件列最小迁移候选** | 旧文件保留re-export facade；输出字节不改 |
| `src/chipchain/firmware/grounded_agent.py` | `src/chipchain/agents/firmware_grounded.py` | 否 | 需Agent class/import身份、runtime继承和A6上下文等价性专项检查 |
| `src/chipchain/integrations/paired_agents.py` | 未来 `agents/paired_binding.py` | 否 | 当前主线执行generic绑定，不做schema/name变动 |
| `src/chipchain/tools/paired/ibex.py` | 未来 `adapters/ibex_simple_system.py` | 否 | 同时输出HW/FW，不按目录草案拆成重复ingestion |
| `src/chipchain/integrations/paired_baseline.py` | 保留CLI，未来抽workflow和platform runner | 否 | 固定工作区/IO/记录需要设计，不是机械移动 |
| `src/chipchain/execution/reviewed_output.py` | 未来 `reporting/reviewed_output.py` | 否 | 保留CLI和所有旧schema gates；历史replay优先 |

### R1.1 最小文件级批次

建议次序是**先文档定界，再单个低耦合展示模块迁移；不先删除**。

| 次序 | 文件 | 拟议具体操作 | 验收 |
| --- | --- | --- | --- |
| 1 | `CURRENT_STATE.md`（新增） | 记录A6 baseline/tag、paired带flag与不带flag两条路径、真实CLI、门禁强度、能力缺口、测试/历史索引 | 所有current声明能指向source或冻结记录；无“安全已证明”措辞 |
| 2 | `README.md` | 修正 :5/:19/:280 的当前状态矛盾，历史说明保留但加阶段限定，链接CURRENT_STATE | 不修改任何历史run/docs中的原始结论；不更改命令默认语义 |
| 3 | `src/chipchain/reporting/__init__.py`（新增） | 最小reporting package，无初始化副作用 | import smoke，无provider工具创建 |
| 4 | `src/chipchain/reporting/firmware_grounding.py`（新增） | 从现有renderer搬入同一个render_report实现；不重写文字、不美化表格、不顺便去重 | 固定合成run输入渲染字节与A6 baseline函数完全一致 |
| 5 | `src/chipchain/firmware/grounding_report.py`（保留） | 改为导出同一render_report对象的兼容facade；保留public调用路径 | old.render_report is new.render_report；原import可用 |
| 6 | `src/chipchain/integrations/paired_baseline.py` | 仅render_report import改指新reporting路径，或首批维持旧facade；其它代码不动 | 无prompt/schema/context/support/默认flag变化 |
| 7 | `tests/unit/test_firmware_a6_evidence.py` | 现有报告测试保留旧路径兼容断言；新增新路径identity/output测试 | evidence/status/unknown/raw分离断言保持 |
| 8 | `tests/unit/test_reporting_compatibility.py`（拟新增） | 最小synthetic run树，对照从A6 git blob离线加载的旧renderer，逐字节比较；禁真实fixture与API | 成功、有拒绝、缺少报告三种呈现分支；fixture不照搬实现 |
| 9 | 新的R1.1研究文档 | 记录迁移范围、source SHA变化、行为不变证据与历史保护 | 不改写本R1-A快照，不移动tag |

一次实际迁移最多上述renderer一组，**0 个生产文件删除**。如果旧renderer加载需要导入其它可变源，先隔离其纯函数依赖再确认对比有效；不能只有“新旧别名相等”就声称行为等价。

不将 `domain/` 批量改名为 `core/`，不创建空 capability/behavior_contract，暂不拆support文件、改canonical codec、改枚举、改证据source semantics、删除stub、改变publicagent基类或把A6设为默认。

### R1.1 检查与停止条件

- 基线重新核对HEAD/tag及工作区；保护历史文件SHA。生产文件将因批准迁移改变，但只允许明确列出的文件，不能再要求这些修改文件SHA与A6完全一样。
- 完整pytest、pip check、compileall、diff check；report byte parity；新旧import兼容；现有A6 known wrong/right regressions继续通过。
- 不新增真实LLM调用。可用与本次同样的offline injected workflow验证路径；不得把fake probe记成真实运行。
- 旧output与implementation_manifest不改；新代码manifest发生变化是迁移事实，需另记，不能伪造旧hash。
- 若需变更support/schema/prompt或发现import副作用不可隔离，停止该迁移，将问题记REVIEW_REQUIRED。
- 回退粒度为这一组renderer文件；本阶段不执行任何回退/迁移/git操作。

## ARCHIVE

生产源代码 ARCHIVE_CANDIDATE = **0**。未证明任一旧pipeline完全不被replay/public API需要。
研究历史不属于“可归档后删除”范围：未来可增加分类索引，但现在不移动、不压缩、不去重、不合并历史JSON。建议分类索引位置见architecture audit的Protected Research History。

## DELETE

DELETE_CANDIDATE = **0**。没有文件通过八项同时满足的gate。

| 必须回答的问题 | 当前审计证据 | 为什么仍不能删 |
| --- | --- | --- |
| 谁import | AST正反图＋隐式package边 | 外部使用与反射不在闭包内 |
| 谁call | AST qualified call expressions＋offline函数profile | 单条成功路径不穷尽所有callbacks/CLI |
| paired是否reachable | 105模块static closure、33具名函数模块执行 | 不在paired仍可用于单侧研究/重放 |
| 哪些tests覆盖 | direct-import图＋per-test execution map | 执行不等于assertion/branch充分性 |
| 哪些历史artifact/docs引用 | tracked文档明确路径引用、Git/tags、历史保护索引 | 文档未提到不代表用户无依赖 |
| 哪个实现替代 | 无已证明等价的替代 | 类似serializer不等于相同bytes/hash |
| 删除是否改public API | 外部消费者UNKNOWN | 保留facade之前不可删除 |
| frozen regression能否重放 | 保留原代码已可回归；删除后的证明UNKNOWN | 不能把未来检查填PASS |

任何UNKNOWN都阻止DELETE分类。无importer的Ghidra `__main__`是CLI；空 `__init__`是package结构；它们均不是删除候选。

## REVIEW_REQUIRED

- `src/chipchain/tools/artifacts.py`：只有test direct caller；fingerprint public API用途与各adapter的hash helper替代关系UNKNOWN。保留，调查消费者，不删除测试来制造“无覆盖”。
- 4文件/5名字的potential unused imports：仅静态提示，import副作用/API输出范围需逐项确认；本批不做。
- `agents/relation_support.py` v1：v2和reviewed exporter仍依赖，不因后缀旧而删除。
- 不带`--firmware-grounding`的paired路径：仍可CLI到达；弃用/默认变化需单独产品与科研语义决策。
- `tools` → `agents.contracts/firmware_evidence`：确定性层反向依赖；先设计输入DTO，不改冻结schema作为pruning附带动作。
- 广泛package re-export是否惰性化：public导入/API风险，需import/load专项测试；不纳入renderer小批。
- Hardware B2与paired HW/Cross generic support如何统一：不具备语义等价证明，留后续架构设计。

**GO结论：仅对上述狭窄R1.1提案建议有条件GO；对批量删除、schema/support合并或历史清理为NO-GO。等待用户后续指导，本轮停止。**
