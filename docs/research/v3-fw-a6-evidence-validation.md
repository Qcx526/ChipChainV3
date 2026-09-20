# V3-FW-A6 — Deterministic Firmware Control-Flow Grounding & Evidence Validation

本补充对应新版 A6 要求；初版实现与回归见 [原 A6 记录](v3-fw-a6-control-flow-grounding.md)。旧记录、旧模型输出、旧中文报告都保留原字节，不用新解释覆盖历史。

## 两个真实错误与确定性来源

旧配对运行 `d362bd15-c924-46af-bcae-12aa960afa50` 中，Firmware Agent 将 PC `0x100080` 的 JAL 目标写为 `0x1002c6`，并关联 timer handler。源指令字为 `0x2c60006f`，地址序字节为 `6f00602c`。J 型立即数重建、符号扩展得到 `+0x2c6`，加源 PC 得到 `0x100346`。目的寄存器为 `x0`；顺序地址 `0x100084` 不是该无条件跳转的备选执行结果。目标的 reset_handler 标签没有可靠 sized STT_FUNC 区间，因此不能用标签替代唯一 owner。

旧模型将 `0x1000a0` 归入 puthex。ELF 的 puts 区间是 `[0x100090, 0x1000a4)`；puthex 从 `0x1000a4` 开始，正确 owner 是 puts。函数边界、目标计算都由确定性工具完成，没有 LLM 参与。最小回归值见 `tests/data/firmware_a6/paired_regression.json`。

## 契约与构造

`firmware-control-flow-grounding/v1` 保留架构 RISCV、ARM、POWERPC、X86、UNKNOWN。事实具有稳定内容 ID、case、架构、source artifact ID/SHA、evidence ID 和 provenance。控制转移记录 PC、地址序编码、位宽、助记符、操作数、kind/status、直接目标、顺序地址、decoder backend/version/mode、resolution method。JAL 额外记录有符号立即数、目的寄存器和顺序地址语义。Capstone 提供展示文本，小型 RV32 I+C 适配器从编码计算目标；JAL/B/CJ/CB 之外的未支持项不编造结果。

Kinds：direct_call、direct_jump、conditional_branch、indirect_call、indirect_jump、return、other_control_transfer。Statuses：resolved_direct、indirect、ambiguous、unsupported、invalid。B 型记录 target 与 not-taken fallthrough，不决定实际分支结果。JALR、返回和依赖寄存器的跳转保留 indirect/null；不使用相邻 trace PC 伪造静态目标。

函数归属以可靠 ELF sized STT_FUNC 半开区间为首选，显式静态结构和 CFG 区间为后备。unique / ambiguous / missing 分开；重叠不选择一个，未知大小不延伸到下一个符号。名字只展示，支持判定使用 function ID 和确定性范围。当前 ELF ingestion 不自动导入任意外部 CFG；后备区间通过已有 typed resolver 输入。

Catalog 含 target、transfer/ownership facts、functions、source artifacts、evidence registry、capabilities、limitations 和独立 runtime observations。所有路径来自调用方，domain 不限定 samples/。

## 退休事件与静态事实分离

配对 runner 显式声明 `trace_semantics=ibex_rvfi_retirement`；依据本地冻结 RTL `ibex_tracer.sv` 的 rvfi_valid 输出门控。每个事件存 retired=true、PC/编码、cycle、行号、source stage、trace SHA 和 observed evidence。ELF 字节逐项匹配后才允许建立静态事实。未经显式声明的 trace 只用于选址，不自动产生退休断言；历史 EnCorpus ID-stage 语义不变。

退休事件、PC 的直接目标、源位置 owner、目标位置 owner 是独立对象；不创建运行时 taken-edge 或具体间接目标。函数 containment 不等于可达性。

## 序列化与 projection

集合性质列表按稳定 ID 排序；键稳定排序；无 UUID/时间戳进入 fact identity。`catalog_sha256` 是排除自身字段后的规范 JSON UTF-8 SHA256，文件自身 SHA 由 artifact manifest 单独记录。解析时校验内容哈希；排序不同不改变 hash。新版必需字段是本次未冻结 v1 的补齐，不自动迁移或重写之前的初版 A6 产物。

投影版本 `firmware-control-flow-grounding-projection/v1`，限制 48 条事实 / 28,000 字符；当前 7 条 transfer、8 条 ownership，24,090 字符。它仅选当前报告位置及直接目标 owner，带证据、target、限制、catalog hash；不转储完整函数目录、CFG 或 1,183 个退休事件。完整固件 envelope 44,258 字符，小于 64,000 上限。新增契约字段使旧 24,000 上限超出 90 字符，故在真实调用前调整预算；未扩大事实选择或调优模型结果。

## 精确支持与报告边界

Firmware Agent 输出 control_transfer_target / function_ownership typed claims，必须引用实际投影 fact ID。正确直接目标 supported；不同目标 incompatible/control_transfer_target_mismatch；间接或未解析目标 unsupported。唯一 owner ID 相符 supported，不符 incompatible/function_ownership_mismatch；ambiguous/missing 不支持唯一 owner。

支持链：claim ID → support result → fact ID → 指令/函数源 → artifact/evidence。泛化 ELF 引用不能替代精确关系。通过 gate 的模型结构化值仅用于判定，canonical report 的每句事实都从 catalog 渲染。所有 raw_model_summary（即使同条结构化值正确）以及模型 diagnostic_questions 均仅诊断，不复制到跨层上下文；这不是修写原模型回答。

文件层次：`firmware_model_claims.diagnostic.json`（schema-valid 模型声明）、`firmware_support_validation.json`（确定性校验）、`firmware_analysis_report.json`（接受的规范报告）、`report-zh.md`（中文验收）。当前安全持久化不保存 provider 原始 response body；保留模型声明、prompt/input、调用元数据。中文表格分模型声明、事实、状态/原因、规范解释、证据来源，并分别标明未知信息与跨层候选。

## A4/A5 兼容性与阻断

只读比较输出 agree / not_comparable / conflict。paired runner 在构建/调用模型前执行 preflight，持久化 `firmware_grounding_compatibility.json`；任一冲突抛出明确错误并停止，不让新事实覆盖冻结事实。调用方可通过 `a4_catalog` / `a5_cfg` 提供同源冻结对象。当前 Ibex 无同源冻结 A4/A5，记录 not_comparable，不冒称一致。

独立 ARM Heat_Press 复核在 `output/firmware-a6-compatibility/89080fd0-8107-4f42-a4e1-717c1892f8f1/`：A4 20 agree、111 not_comparable；A5 34 agree。A4 冻结内容 hash `fc4f1af1737813210ae58daa80b258813eb9e13591024d936c31fd6fe6634902`。A6 ARM transfer 23 项 unsupported；不以此声称完整 ARM 解码或 CFG 等价。A5 只比较 exact entry identity，不将 ownership 提升为 reachability。

## 未来接入点与证据层级（本阶段不实现）

- HardwareBehaviorContract = Platform + Preconditions + Trigger + Deviation + Observation + Scope。A6 可提供固件执行位置/关系证据，但不能独自确认 Trigger 已满足。
- FirmwareCapability = Entry + Condition + Primitive + Constraints + Evidence。A6 将提供 Entry、Condition 和执行关系的确定性引用，不从分析者可访问 ELF/调试器推导目标输入能力。
- AnalysisCapability ≠ TargetInputCapability。能读 trace、反汇编、读寄存器不等于目标用户能控制 PC、寄存器、内存或任意函数调用。
- 未来等级：E0 candidate association；E1 model/static feasibility；E2 abstract/model replay；E3 matching implementation/RTL validation；E4 physical board validation。
- 本次研究字段 `validation_context: paired_rtl_runtime_regression` 与 fact epistemic status 正交。运行在匹配 RTL 上，不会自动把所有声明或候选提升到 E3；未改全局冻结 schema。

A6 不引入受控 RTL 变体、固件修改、定向搜索/fuzzing、符号输入求解。supports_indirect_runtime_resolution / path_feasibility / external_input_controllability / runtime_reachability_from_interface / security_impact 均保持 false。

下一阶段建议 V3-XL1：先建立显式 HardwareBehaviorContract，尤其是可观察的 Deviation、Trigger 与 Scope；目前正常基线运行缺少这样的连接对象，先补这个抽象比先扩展固件能力或创建 RTL 变体更能约束下一次配对实验。此建议不自动启动新阶段。


## 唯一一次新版真实回归结果

运行：`output/ibex-simple-system:hello-test:paired-workspace/100fcbb2-6ac4-4eb5-821c-09a688957a51/`。
Hardware / Firmware / IR / Cross-Layer 均 completed。没有失败后的重复调用或 prompt 调优。

- ELF SHA：`44ac617845e3a99e36b419c028349f86c7bb64d2b33cc6d9711623281a61625c`。
- Simulator SHA：`d30710114df80a253d57e95f70bf8a3c9772a6293d0cea8b91a82cc7fe0fdeb7`。
- Catalog SHA（排除 hash 字段）：`3c1cb735faa96d41b031df6198179407dfbd7f9f504dcf76710ed127e1648596`；重建规范字节完全相同。
- 1,183 个独立退休事件；308 个 transfer 记录：32 resolved_direct、10 indirect、266 unsupported；308 个 ownership：257 unique、51 missing。
- 32 个直接目标与冻结 objdump 全部一致。
- Hardware：4 findings，0 abnormal_states，0 trigger_hypotheses。
- Firmware：6 claims（1 target、5 owner），6 supported、0 rejected；accepted target mismatch = 0，accepted ownership mismatch = 0。
- IR：14 behaviors；Cross-Layer：0 candidates，9 missing constraints。没有候选不等于安全。

**模型原文仍有错误。** c2 把 puts end 写成 0x100094，正确是 0x1000a4；c3/c4 把 timer_read end 写成 0x100246，正确是 0x10024e。结构化 owner ID 均正确。支持 gate 并未逐句校验摘要；它把所有摘要隔离为诊断，由事实渲染规范内容。实际跨层输入与规范固件报告完全对应，未含任何 raw summary 或 diagnostic question。不能把 6 supported 宣称为模型全文正确。

硬件及跨层 prompt 与前次保持相同；本轮 cross 模型仍有“缺少独立译码”等过度概括，此类模型叙述不替代 A6 catalog。硬件/跨层全面的自然语言支持校验不属于本阶段。

| Agent | Input | Output | Total | Requested / Returned | Finish | Retries |
| --- | ---: | ---: | ---: | --- | --- | ---: |
| Hardware | 6048 | 1144 | 7192 | deepseek-flash / deepseek-flash | tool_calls | 0 |
| Firmware | 14110 | 1297 | 15407 | deepseek-flash / deepseek-flash | tool_calls | 0 |
| Cross-Layer | 9095 | 1185 | 10280 | deepseek-flash / deepseek-flash | tool_calls | 0 |

共 3 次调用，32,879 tokens。调用元数据保留在各 agent invocation JSON；原始声明、支持审计、规范报告、上下文和 prompt 分文件保存。新增核对文档不改写 runner 产物，另有 a6_review_manifest.json 覆盖全部补充文件。

## 最终验证与历史保护

`pytest -q`：**1163 passed, 27 skipped in 28.65s**（A6 相关 87 项）。
`python -m pip check`：No broken requirements found.
`python -m compileall -q src tests`：exit 0。
`git diff --check`：exit 0。

本次开始时保护快照中的 **4,148 个文件 SHA 均未改变**，覆盖历史 output/samples/research/tutorials/reports 以及 frozen agents/domain/tools/cross_layer 模块。Hardware A3/B2、Firmware A4/A5、XL0、DATA0/DATA1A、DOC-1 及既有 reviewed exports 未修改。真实输出仍被 Git 忽略，未新增真实测试 fixture，未执行 add/commit/push/tag。
