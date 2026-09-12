# V3-2A1.1 — Neutral & Compact Firmware Agent Projection + Grounding Gate

基线：`v3-2a1-stable` / `fafbdc6919ff7c099583717f459ee2a84228f838`。
本阶段完成显式固件模型投影和通用 evidence/finding grounding；没有调用真实模型，没有进入 V3-2B。

## A. Implementation Summary

```text
canonical FirmwareAgentInput / deterministic IR（不修改）
  → build_firmware_analysis_projection(inputs)
  → firmware-analysis-projection/v1
  → serialize_firmware_analysis_projection(projection)
  → firmware_context(inputs) / 模型 HumanMessage

报告输出
  → validate_firmware_evidence(report, inputs)
  → 原有 FirmwareAgentOutput / _validate_report_ir
```

完整 evidence 与 behavior 各只保存一次，observations 通过 ID 引用。投影不读文件、不修改 canonical state；运行前和报告返回后使用同一套三层 supplied-evidence 收集规则。

## B. Files Changed

| 文件 | 修改 |
| --- | --- |
| `src/chipchain/agents/projections/__init__.py` | 新增模型投影包 |
| `src/chipchain/agents/projections/firmware.py` | 新增 v1 projection schema、allowlist、catalog、serializer、hash |
| `src/chipchain/agents/firmware_evidence.py` | 新增供 projection 和 grounding 共用的 canonical evidence registry |
| `src/chipchain/agents/context.py` | firmware_context 转调独立模块；移除 compact_firmware_evidence 分支 |
| `src/chipchain/agents/firmware.py` | 增加输入 evidence 冲突检查与输出 grounding gate |
| `tests/unit/test_firmware_projection.py` | 新增投影、敏感性、身份和硬件 context 回归测试 |
| `tests/unit/test_firmware_grounding.py` | 新增 fake-model grounding 测试 |
| `tests/unit/test_fuzzware_ingestion.py` | 调整旧 context schema 断言；canonical ingestion 测试保留 |
| `tests/unit/test_langchain_agents.py` | 区分新的 firmware catalog 与不变的 hardware 嵌套结构 |
| `tests/integration/test_fuzzware_local.py` | 增加真实 catalogs、<=40k、determinism/hash 和泄漏检查 |
| `README.md`、本文 | 最小阶段更新与完整实现报告 |

无 dependency、domain schema、A1 analyzer/ARM decoder、YAML subset、ELF/BIN consistency、prompt 或 workflow 改动。

## C. Why A1 Context Was Too Large

A1 的 **62,793** 字符已经做过部分 nested EvidenceRef 去重，距离 64,000 只剩 **1,207**。继续 minify 无法给后续静态结构/约束提供空间。

重复还来自 MMIO observation details 与 behavior.attributes 的相同 PC/address/size、instruction site 与 DecodedInstruction 的相同 raw bytes/width/mode、每个 record 的重复架构和固定摘要。A1.1 改为显式模型投影，压缩这些等价表达，所有 canonical facts/objects 仍保留在原输入。

## D. Projection Architecture

独立入口位于 `agents/projections/firmware.py`：

```python
projection = build_firmware_analysis_projection(inputs)
text = serialize_firmware_analysis_projection(projection)
context_hash = firmware_projection_sha256(projection)
```

`firmware_context(inputs)` 返回同一 text；Hardware 和 Cross-Layer 沿用原有 `_serialize()`。不再向 `_serialize()` 增加 firmware 特殊开关。

`FirmwareAnalysisProjection` 是单独的 Pydantic contract，带明确 Literal version。模型投影不是 canonical input 的序列化备份；落盘/审计仍使用 canonical 模型。tests 对比 projection 前后 `inputs.model_dump_json()`，并验证修改返回的 projection 不会反向修改输入。

## E. Neutral Artifact Policy

artifact catalog 只投送 `artifact_id/artifact_type/format`；不包含 path、filename、metadata 或完整 artifact fingerprint。Case 只保留 case_id 和 target，省略 Case.name、metadata、benchmark labels。Target 保留 architecture、processor_id、firmware_id、isa_variant、word_size_bits、endianness 中已提供的值。

**EvidenceRef 必须保持 exact，所以不在 projection 内 remap artifact_id。** 本版采用 fail-closed 的中性 ID namespace：

- `elf/bin/yaml/opaque`，可加 `-`、`_`、`:` 分隔的纯数字后缀；
- `artifact-1`、`fw-artifact-1`、`firmware-artifact-1` 等相同前缀加数字形式；
- 保留 R0 的 `synthetic:firmware:artifact`，可加数字后缀。

真实四个 ID `elf/bin/yaml/opaque` 直接保留。其他任意 caller label（包括看似普通但未被此规则覆盖的 label）显式拒绝；调用方应在构造 artifact/evidence 前选择中性 ID。canonical ArtifactRef 不重写，domain 也没有添加此限制。

保护机制首先是显式字段 allowlist 与受限 artifact identity；另对实际将投送的字符串做保守 guard：出现斜杠/反斜杠或 CVE-/known root cause/expected crash/exploitability/crash-analysis/crashing_input 标记时拒绝。固定 projection version 的 `/v1` 不属于输入数据。此 guard 会拒绝某些合法但含路径式字符串的未来事实，不尝试自动清洗或静默修改 exact evidence。

字符串 guard 不是判断所有自然语言 oracle 的完备分类器。未来新 target/新字段需要审查 projection policy；本阶段不宣称任意 corpus prose 已经安全。artifact paths 与 display labels 在进入 guard 前已被 allowlist 排除，因此修改它们不改变 JSON，也不会因为隐藏路径含标记而误拒绝当前 case。

## F. Projection Schema

```text
projection_version: firmware-analysis-projection/v1
case: {case_id, target}
artifacts: [{artifact_id, artifact_type, format}]
evidence_catalog: [exact EvidenceRef]
observations: [{observation_id, kind, scope, epistemic_status,
                summary?, details, evidence_ids, behavior_ids}]
behaviors: [{behavior_id, kind, summary, epistemic_status,
             attributes, architecture?, evidence_ids, decoded_instruction?}]
unresolved_questions: [...]
```

所有 references 在 serialize 前验证可解析；catalog 重复 ID 不选择 winner。列表上限保持 128，evidence/behavior catalogs 同样有界；序列化总长仍不能超过既有 64,000。真实 Heat_Press 的额外验收线 <=40,000 放在真实 integration test，不改变全局常量。

canonical roles 不删除；projection builder 只接受 ANALYSIS_INPUT typed observations，所以本版模型投影中省略恒定 role 字段。generic DeterministicObservation 仍支持，模型 kind=generic、scope=unknown，不把 generic 自动标成 runtime。

## G. Evidence Catalog

`collect_firmware_evidence(inputs)` 对 typed 和 generic observations 统一收集：

1. observation.evidence；
2. behavior.evidence；
3. decoded_instruction.evidence。

相同 ID 的完整对象相等时只保留一份 deep copy；不同对象时立即拒绝。artifact membership 也在这三层统一检查，因此只在 generic decoded_instruction 中出现的 evidence 同样可用且受约束。

catalog 保留 evidence_id、artifact_id、source_type、analyzer、location、summary、epistemic_status 的原始语义和值。JSON 只省略 None；重新 `EvidenceRef.model_validate` 后与 canonical 完全相等。behavior/decoded/observation 只带 evidence_ids，不再重复完整对象。真实仍有 **57 个 exact entries**。

如果 exact EvidenceRef 本身含不允许的路径/答案标记，拒绝整份 projection；不改写摘要、ID 或 location 来绕过规则。output grounding 也不信任模型返回的“同 ID 但不同内容”。

## H. Behavior Catalog

每个 canonical behavior ID 恰好对应 catalog 中一项；真实 **55 个**，无截断、top-k 或随机选择。重复 canonical behavior ID 显式失败，与既有 IR 的唯一性要求一致。

behavior summary、epistemic_status 和证据引用保留。相同 architecture 从 Case.target 继承，若 generic behavior 与 target 不同，则在该 behavior 单独保存 architecture；所有合法 input behaviors 的 origin 仍由既有 FirmwareAgentInput layer contract 约束为 firmware。

行为是否在报告中有合法引用，仍由既有 `_validate_report_ir` 负责。新 evidence gate 不另建报告 behavior registry。

## I. Observation Projection

真实 57 个 observation ID 全部保留，按 ID 稳定排序。typed kind/scope/epistemic_status 与 reasoning details 保留；behavior_ids 引用独立 catalog。

只省略 A1 四种固定重复摘要（Confirmed Thumb site、MMIO model configuration、Opaque environment input artifact、Configured environment trigger），它们的语义已经由 kind/details/scope 表示。不同摘要和 generic summary 原样保留，不能丢掉 generic observation 唯一的事实文本。

file offsets、raw symbol state、config key 等定位辅助信息仍留 canonical；model 的 instruction location/function、MMIO PC/address/size/parameters 和 exact evidence 足以解释当前 facts。没有删 canonical observation，也没有修改 A1 的产生规则。

## J. Instruction Projection

STATIC observation details 保留 VA 和可用 function；其 behavior 的 decoded_instruction 保留 status、reason（如有）、mnemonic、operand_text、instruction_width_bits、raw_encoding、representation、decoder_mode、evidence_ids。raw encoding 仍是 memory-order hex。

当 site details 与 decoded result 的 bytes/width/mode/representation 完全一致时只投送 decoded 的一份；若调用方提供不同值，保留双方差异，不凭任选一份抹去不一致。structured operands/backend alias/tool descriptor 等完整 decode 信息保留 canonical，模型使用 operand_text 这一明确 display representation。

STATIC scope 经 observation → behavior_ids 关联，仍不能推导 executed、covered、external-input reachable 或 crash path。

## K. MMIO Projection

32 条 observation details 各保留 PC、MMIO address、access_size_bytes、model_kind、parameters；scope=configuration。对应 MMIO_ACCESS behavior 保留 identity、direction、summary、epistemic_status 和 evidence IDs。

仅在 behavior.attributes 中的重复 PC/address/size/scope 与所有引用它的 observation 完全相等时移除模型侧副本；不一致时保留。direction 的 ELF evidence 仍能从 catalog 解析。constant.val、passthrough.init_val、set.vals、bitextract 参数仍是模型配置，不是运行值。

## L. Environment Input Projection

opaque input 保留 input_kind=opaque、artifact_id、size_bytes、sha256、scope=artifact 和 evidence ID。该 hash **只保留一次**，用于区分相同长度的不同 input 身份，并保证 input hash 改变时 context/hash 随之改变；其他完整 artifact fingerprints 对本轮模型推理无新增作用，省略。

interrupt trigger 保留 input_kind、every_nth_tick、fuzz_mode、tick_unit、configuration scope 和 evidence ID。不产生 runtime interrupt。没有 input 原始 6009 bytes、文件名或 crash outcome。

## M. Context Determinism / Hash

artifact/evidence/observation/behavior catalogs 及引用 IDs 明确排序，JSON 使用 `sort_keys=True`、紧凑 separators、UTF-8；unresolved_questions 保留调用方有意义的顺序。不依赖 set/dict 的偶然迭代顺序，不生成随机 ID/时间。

`firmware_projection_sha256()` hash 的是 `serialize_firmware_analysis_projection()` 返回的**真实模型 HumanMessage JSON**，不 hash canonical 全量 input 或另一份摘要；hash 不写进其自身，避免自引用。

当前真实 case：

```text
projection_version = firmware-analysis-projection/v1
projection_sha256 = 48bd361548509e25be7ad9b1e3e15519f1bb49f9702fb334846d3f2407a63803
```

这个 hash 对应 integration 中的明确 case/target/ID 和当前完整事实；调用方改变 operational facts、ID 或问题时会相应变化。路径/display-name 修改不影响它。未来 B provenance 应记录此 version 与真正发送 text 的 SHA-256。

## N. Firmware Evidence Grounding Gate

`validate_firmware_evidence(report, inputs)` 验证以下四类报告对象的每个 EvidenceRef：

- FirmwareFinding；
- ExternalInputPath；
- ReachableBehavior；
- FirmwareIssueAnchor。

要求 evidence_id 存在且完整 EvidenceRef 相等；invented ID、改 location/summary/artifact_id/epistemic_status 都拒绝，抛 AgentStructuredOutputError。Agent 在模型返回后、原有 output/IR gate 之前调用它。模型调用前及无模型 stub 路径也检查输入三层 evidence 冲突与 membership。

这只证明引用来自输入，**不证明模型 prose 被证据蕴含**。空 evidence 的合法对象不新增强制证据策略，也不提前禁止 finding 的 VERIFIED；provider-specific epistemic policy 留给 B。本轮没有假装仅靠 grounding 就能确认漏洞或 runtime 行为。

## O. Finding Reference Validation

FirmwareIssueAnchor.firmware_finding_ids 必须是 report.findings[].finding_id 的子集。未知 ID 拒绝。使用统一的 firmware_finding_ids 属性检查方式，以便将来其他报告对象提供同类引用时适用。

behavior references、case/IR 一致性和 finding_id 唯一性仍由原有 FirmwareAgentOutput / `_validate_report_ir` 处理；该函数本轮未修改。

## P. Oracle / Path Leakage Tests

无关数据敏感性：改 ArtifactRef.path、本地父目录、Case.name、case/artifact metadata 中的 oracle 文字，projection JSON 保持完全一致。

操作事实敏感性：改 MMIO address/PC/access size/parameter、decoded mnemonic/operand_text、instruction VA/raw bytes、opaque input size/hash、interrupt ticks，JSON 改变。catalog/evidence equality 和全部 IDs 仍单独核验。

对真实与 synthetic text 扫描 CVE-/known root cause/expected crash/exploitability/crash-analysis/crashing_input 和 `/home/` 均不存在；另测试不安全 artifact IDs 被身份 policy 拒绝、前向字段中的 path-like/reference 内容被拒绝且 canonical state 不被清洗。字符串检查是回归补充，不能代替 field allowlist 和 exact registry。

## Q. Real Heat_Press Before vs After

真实 input fingerprint 和 A1 输出语义未改变：

| 项目 | A1 | A1.1 |
| --- | ---: | ---: |
| canonical observations | 57 | 57 |
| static / MMIO model / environment facts | 23 / 32 / 2 | 23 / 32 / 2 |
| canonical behaviors | 55 | 55 |
| canonical unique EvidenceRefs | 57 | 57 |
| runtime observations | 0 | 0 |
| model observation catalog | 嵌套结构 57 | 57 |
| model behavior catalog | observations 内 55 | 独立 55 |
| model evidence catalog | 分散在 observations 内 | 独立 exact 57 |
| context characters | **62,793** | **39,438** |
| remaining headroom under 64,000 | 1,207 | **24,562** |

减少 **23,355 字符，37.193636%（约 37.19%）**。达到 <=40,000 的本阶段硬验收线，没有提高 64k，也没有减少 32 MMIO model entries。

统计来自显式运行：

```bash
CHIPCHAIN_FUZZWARE_ROOT=/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
  .venv/bin/python -m pytest -q -s tests/integration/test_fuzzware_local.py
```

测试还核对 canonical JSON 前后相同、多次 serialize/hash 一致、evidence catalog 对象与 canonical registry 完全一致。没有保存任何真实 Firmware report。

## R. Fake-Model Grounding Tests

使用现有 StructuredFakeChatModel，经真实 LangChain structured parser 返回 synthetic report：

| 测试 | 结果 |
| --- | --- |
| 四类报告对象引用 exact evidence | 接受；IR 完全来自 deterministic input |
| 四类对象各自 invented evidence ID | 拒绝 |
| 四类对象各自修改 location/summary/artifact/status | 拒绝 |
| anchor 指向未知 finding | 拒绝 |
| report 指向未知 behavior | 原有 IR gate 拒绝 |
| generic observation / behavior-only / decoded-only evidence | 合法 exact 引用接受 |
| 输入跨层重复 ID 但不同对象 | 模型调用前、stub 路径均拒绝 |
| 合法 finding 的 VERIFIED | 通用 grounding 不新增 B 的 provider-specific 禁令 |

Fake report 中的 path/finding 是 synthetic gate fixture，不是对真实 Heat_Press 得出的安全结果。

## S. Hardware Regression

HardwareAgent、hardware projection/analyzer/decoder 和 prompts 未改。`hardware_context` 仍走原有嵌套 serializer；新增 literal baseline JSON 对照，已有 Hardware fake-model / reviewed-output 回归保留。

`output/reviewed/v3-1b1/` 共 12 个 tracked 文件已逐文件与 HEAD 原始字节比较，一致。firmware prompt 仍为 `firmware-security-agent v1`；A1 analyzer、YAML/ELF/BIN/Thumb semantics 和依赖声明与 HEAD 无差异。

## T. Exact Test Results

```text
完整默认离线 suite：
431 passed, 7 skipped in 5.07s

显式真实 Heat_Press integration：
1 passed in 0.36s

python -m pip check：
No broken requirements found.

python -m compileall -q src tests：
exit 0; no output

git diff --check：
exit 0; no output
```

相对 A1 的 371 passed / 7 skipped，新增 60 个默认离线测试实例。真实 integration 仍显式 opt-in，默认测试不依赖外部 corpus。无 dependency 改动，所以本轮不重建 fresh wheel cache；现有声明依赖、pip check 和离线 suite 已验证。

## U. Security Checks

本轮没有读取 `.env`、API key，没有网络/DeepSeek/真实模型调用，没有 QEMU/Fuzzware replay、Ghidra、angr 或 fuzzing。测试保留 socket/DNS/subprocess 隔离；只读本地真实 artifacts 的 opt-in integration 不运行模拟器。没有生成 firmware_analysis_report.json 或 reviewed firmware snapshot。

投影防止路径字段进入 context，grounding 防止模型伪造/改写 evidence；两者不替代后续对 reasoning 正确性的审查，也不将静态 MMIO 配置提升为运行事实。

## V. Architecture Impact

canonical state 与 model analysis view 已有明确边界，policy version/hash 可供未来 provenance 使用。新模块只依赖既有 Pydantic/domain/agent contracts，没有引入 dependency 或通用压缩框架。硬件 context 不迁移到这套模型 catalog。

中性 artifact namespace 属于 model-facing policy，不是 domain ArtifactRef validator；拒绝未来不支持 label 是可审查失败，不能 remap exact evidence。额外路径式字符串 guard 较保守，未来合法符号文本如包含 `/` 需显式版本化处理，不能默默替换 canonical 内容。

## W. Remaining V3-2B Blockers

A1 遗留的“路径投影不安全”和“context 空间不足”已由本 patch 处理；真实 Heat_Press 没有新增 deterministic ingestion 前置 blocker。

首个真实 Firmware Agent 调用仍属于 B：需要实现并显式启用 provider/run 入口、使用本版 context/hash/version 记录 invocation provenance、制定真实 run 的额外 epistemic 检查、按要求持久化 analysis_run/report，并在得到真实结果后人工评估质量。本轮不读取 provider 配置、不试调用、不升级 prompt。

独立 runtime/MMIO consumption/coverage/reachability evidence 仍缺失；这是作出 runtime、input→behavior 或 crash 结论的证据缺口，**不是开展首次受限静态事实 reasoning 的强制前提**。新 target 或不合规身份还需上游中性 artifact IDs 和相应证据审查；不能把当前单样本验证泛化为任意 corpus 支持。

## X. Git Status

本轮无 git add/commit/push/tag。修改与新增文件列表如下：

```text
 M README.md
 M src/chipchain/agents/context.py
 M src/chipchain/agents/firmware.py
 M tests/integration/test_fuzzware_local.py
 M tests/unit/test_fuzzware_ingestion.py
 M tests/unit/test_langchain_agents.py
?? docs/research/v3-2a1-1-firmware-agent-projection.md
?? src/chipchain/agents/firmware_evidence.py
?? src/chipchain/agents/projections/__init__.py
?? src/chipchain/agents/projections/firmware.py
?? tests/unit/test_firmware_grounding.py
?? tests/unit/test_firmware_projection.py
```

## 最后 16 个明确回答

1. **Canonical FirmwareAgentInput 是否不变？是，projection 前后 JSON 完全一致。**
2. **本地路径能否进入新 model context？path 字段不投送；其他前向字段含路径式内容则拒绝。**
3. **artifact paths 能否带入 crash-analysis/crashing_input？不能，改路径也不影响 context。**
4. **57 observations 是否全部表示？是。**
5. **55 behaviors 是否全部表示？是。**
6. **57 unique EvidenceRefs 是否全部可用？是，exact catalog。**
7. **每份完整 EvidenceRef 是否只出现一次？是，其他位置只有 IDs。**
8. **新字符数？39,438。**
9. **是否 <=40,000？是。**
10. **比 62,793 小多少？37.19%，减少 23,355 字符。**
11. **模型能否伪造新 EvidenceRef 通过？不能。**
12. **能否改写既有 EvidenceRef 通过？不能，即便 ID 相同。**
13. **anchor 能否引用未知 finding？不能。**
14. **Hardware behavior/reviewed output 是否变化？没有；12 个 reviewed 文件逐字节一致。**
15. **是否真实 LLM/network/emulation/fuzzing？全部没有。**
16. **首次真实调用还剩什么 blocker？B 的 opt-in provider/run 入口、真实 invocation provenance 和持久化/验证流程；本轮不进入 B。**
