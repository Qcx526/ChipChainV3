# Firmware Capability Adapter — Type-II Core

本次适配完成于冻结基线 `5b1b3a60f0c8ad7f7efc8ac77ad80faf3276eccd` / `v3-syn-e2e1-bridge1-stable`。本文是临时验收记录；没有进行 README consolidation，也没有创建新的 phase schema、CLI、renderer 或 workflow。

## 实际得到什么

从已冻结的 `output/syn-e2e1-bridge1/joint-e358hh72/` 只读重放四组来源绑定证据，得到以下正常固件行为。未重新运行 simulator，未调用 LLM。

| 固件（验收名称） | 正常固件 capability | 四组实际执行证据 | 控制权限 |
|---|---|---|---|
| P1 / A5 | WRITE `0x40000=1`；WRITE `0x40004=0xA5`；READ `0x40008` | Reference、Variant 各三个 primitive 的源指令与事务已观测 | `not_established` |
| N1 / A4 | WRITE `0x40000=1`；WRITE `0x40004=0xA4`；READ `0x40008` | Reference、Variant 各三个 primitive 的源指令与事务已观测 | `not_established` |

所有 primitive 宽度为 32 bits，origin 为 `normal_behavior`。这里的 capability 表示指定固件和地址映射下的静态指令行为；附加执行证据表明它在引用的那次运行中确实执行。它不表明外部用户能控制指令、地址或写值，不推断未来输入下的执行可达性。

Reference 的 STATUS 读值 `0` 与 P1 Variant 的 `0xDEAD` 保留在原始 runtime observation 中，通过 ID 可以追溯；capability 的静态 READ 不带 value 约束。不把 A5 判为满足 trigger，不把 A4 判为 trigger mismatch，也不把 DEAD 判为 deviation。

本地结果已由调用方显式保存至 [local-manifest.json](../../output/mmio-capability/adapter-l2ix1eun/local-manifest.json)，不提交 Git：

- `static/`：6 份 JSON，两份 ELF 各三个静态 capability。
- `execution/`：12 份 JSON，四个 joint runs 各三个带证据上下文的 capability。
- manifest：索引现有 fwcap IDs、来源 joint/bridge IDs，以及本次 adapter/CAP0 源码 SHA；不构成新的 domain schema。

示例：[P1 COMMAND 静态 capability](../../output/mmio-capability/adapter-l2ix1eun/static/19843c1d97183ad25eba72c2894540c5170f5dfc1522927faf4dc7880c9734a8.json)、[同一指令的 Reference 执行证据版本](../../output/mmio-capability/adapter-l2ix1eun/execution/577e808e3c013888e1be84a5be54f00d7a7f5054aac38aed6a2ab54caf0df11b.json)。链接依赖本机 ignored output。

## 复用 CAP0 的决定及修改范围

CAP0 已有 MMIO_READ/MMIO_WRITE、resource/address/access_width/value constraints、Origin、Entry、Scope、Evidence 和 RetirementEvidence，能够表达本阶段内容，无须新 capability schema。

CAP0 只允许一个 Entry，primitive 的 source PC 必须等于 Entry PC。因此返回每个 PC 一个 `FirmwareCapability`，不是把三个不同 PC 强装进一个对象。每份 ELF 有三个静态能力。同一 ELF 的 Reference/Variant primitive、constraints、origin、scope 完全相同；各自 Entry 和 Evidence 携带不同运行上下文，完整 fwcap ID 因而不同。这符合既有 CAP0 identity 规则，不把它解释成四种不同静态行为。

新增文件：

- [mmio_capability.py](../../src/chipchain/firmware/mmio_capability.py)：唯一新增生产模块；`materialize_mmio()` 无 IO、无隐式持久化。
- [test_mmio_capability.py](../../tests/unit/test_mmio_capability.py)：22 个 unit cases。
- [test_mmio_capability_local.py](../../tests/integration/test_mmio_capability_local.py)：3 个只读真实集成 cases。
- 本临时文档。

唯一原有文件改动是 [capability.py](../../src/chipchain/firmware/capability.py)：在 `SourceKind` Literal 增加 `firmware_mmio_static`，使用本任务明确允许的最小 additive change。已有来源名称无法准确代表 B1 静态 MMIO catalog；不冒充 A6，也不把确定性分析结果标成人工输入。没有改动 CAP0 的字段结构、validator、canonicalization、ID recipe 或既有来源行为。

没有修改冻结 Bridge/B1/A、hardware contracts、XL1/XL2。历史核对为：301 个原 tracked 文件中仅上述 CAP0 一行变化，其余 300 个一致；62,268 个原 samples/output 文件 SHA256 全部一致；HEAD/tags 不变。

## 静态映射与执行证据

`materialize_mmio(static, elf_bytes=...)` 重新从实际 ELF bytes 提取 catalog，要求与传入对象精确一致。仅 `scope_status=in_target` 且 `address_status=resolved_exact` 的事实进入能力。

| 静态事实 | CAP0 映射 |
|---|---|
| WRITE | `MMIO_WRITE`，resource=mmio，exact address，access_width=32；已解析静态 value 才增加 exact value constraint |
| unresolved WRITE value | 保留 `partially_formalized`，省略 value constraint；不利用 runtime 值补全 |
| READ | `MMIO_READ`，resource=mmio，exact address，access_width=32；没有 value constraint |
| unresolved address / 非目标访问 | 不生成 capability |
| 控制权限 | 始终 `not_established`，没有 controlled dimensions |
| origin | 始终 `normal_behavior`，没有 finding 或 vulnerability-derived 标签 |

primitive 的 `basis=static_instruction`，其本体、control、conditions、constraints、scope 始终只引用静态来源。路径 condition 保留 unknown；既不推断外部入口，也不创建跨 primitive ordering。

需要附加执行证据时，调用方必须同时提供 BridgeSet 与 frozen materializer 所需的实际 bytes/runtime/platform/inputs。Adapter 重新解析验证 ELF、processor/bus/stdout/stderr，调用冻结 Bridge materializer 重建整个 BridgeSet，并要求结果与传入对象精确一致。缺少 replay 输入、错误 static/joint ref、篡改字节或重新计算 ID 后仍不符合 replay 的对象均拒绝。

只有 `overall_status=bound` 才附加：

- Entry：`execution_status=source_instruction_retired`，引用 ProcessorMemoryObservation ID。
- RetirementEvidence：CAP0 已有的最小 PC/encoding/cycle/line 记录及来源引用，不复制完整 processor 对象。
- EvidenceRef：明确区分源指令运行已观测、accepted/completed MMIO 事务已观测，以及 joint/binding 来源引用。

CAP0 要求 primitive 一旦包含 retirement IDs 就必须改用 retirement basis。为保持 static primitive 精确不变，本适配把 retirement 放在它共享的 Entry 和 capability 的 retirement_evidence 中；primitive 的 basis 仍然明确为 static_instruction。

UNKNOWN/NOT_SAME 对应的 primitive 不附加任何 execution evidence，返回与 static-only 调用完全相同的 capability。`static_only` 只表示该对象没有获准附加的执行证据，不表示已证明“没有执行”。原 bridge 的否定/未知原因仍在原对象中，不被改写。

## Provenance 与身份

每个 capability 可通过稳定引用追溯：

```text
FirmwareCapability
  → StaticMmioAccessFact ID / static catalog ID / ELF artifact ID
  → Entry.retirement_observation_ids / ProcessorMemoryObservation ID
  → EvidenceRef / underlying RuntimeMmioObservation ID
  → attested bus observation ID
  → AttestedMmioExecutionBinding ID
  → JointRun ID / BridgeSet ID
```

静态来源 registry 绑定 ELF SHA 与 catalog 的确切序列化 bytes SHA；后者使用现有 `hash_kind=file_bytes`，不是误用 catalog 内部 payload hash。执行来源 registry 绑定原 processor/bus trace artifact ID 和 SHA。Provenance 使用已有 source_ids；不内嵌完整 static/bridge/joint 对象，也不在 capability 中复制 runtime read value。

平台/source-tree/simulator 的实际文件检查沿用冻结 `collector.prepare()`，本地集成明确执行这些只读检查；adapter 本身的输入契约要求调用方先验证这些外部来源，不能把任意构造的 platform 对象当作来源认证。Adapter 的 bytes 重放验证与外部 artifact pin 检查共同构成验收链。

继续使用 `build_firmware_capability()`、`serialize_firmware_capability()` 和 `parse_firmware_capability()`，ID 为既有 `fwcap:<canonical payload SHA256>`。不另建 static capability ID 系统。Primitive/Entry/constraint 的引用名称沿用 CAP0 adapter 的 fact-ID 派生惯例。

完整 CAP0 ID 包含 evidence context，因此同 ELF 的两份执行 capability 可以不同。静态 capability 序列化与 static primitive/constraints 则相同。输入不包含 host path、timestamp、run UUID、P1/N1 label 或 LLM text；额外 metadata 不能作为 replay 参数进入科学对象。

## 验证

新增 25 个测试：22 unit + 3 integration，覆盖 A5/A4 WRITE、READ 不带运行值、BOUND/UNKNOWN/NOT_SAME、错误 static/joint 引用、字节篡改、缺失 replay、静态未解析地址/写值、控制权限、origin、完整 provenance、CAP0 确定序列化、同 ELF 静态语义一致和旧结果回归。测试套件的既有 offline guard 禁止网络连接和外部工具进程；本轮没有撤销该 guard。

实际执行：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q tests/unit/test_mmio_capability.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q tests/integration/test_mmio_capability_local.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests experiments
git diff --check
```

结果：

- unit：`22 passed in 1.75s`。
- 本地真实集成：`3 passed in 13.00s`，实际文件存在，未 skip，四组 frozen runs 都已重放。缺少冻结 collection 时，新集成及其回归入口明确 BLOCKED/skip。
- 最终代码全套：**`1511 passed, 29 skipped in 54.98s`**。全套包含最终 bus EvidenceLocation 调整：总线证据位置为 MMIO address，处理器证据位置为 source PC。之后又显式只读重放并导出上面的能力 JSON。
- pip：`No broken requirements found.`。
- compileall：exit 0，无输出。
- `git diff --check`：exit 0，无输出；新增 untracked 文件另做 whitespace 检查。
- BRIDGE1：12 BOUND，精确重放冻结结果。
- 旧 B1：12 UNKNOWN，旧 preview 精确重放。
- 旧 XL2：UNKNOWN，固定结果 ID 及序列化保持一致。
- simulator 新运行 0；build 0；LLM 0；Git add/commit/push/tag 均未执行。

## 能力边界与下一步提案

现在可以把“该固件在这个 PC 有什么确定的 MMIO 行为”与“引用的运行是否观测到该源指令及事务”一起交给现有 capability 消费者。两者仍分字段表达。

它不证明 trigger、deviation、外部控制、漏洞或 attack chain，也没有证明任意路径/输入上的行为。

下一步 Type-II Runtime Verifier 的最小提案，须另行审核：

- 输入：已验证的 FirmwareCapability、原始 joint/bridge/runtime 证据引用，以及明确目标 revision 的 HardwareBehaviorContract。只有提出 differential 判断时，才额外提供显式 reference/variant 配对和对应观测。
- 输出：每个硬件条件的 supported / contradicted / unknown，以及具体证据 ID、缺失信息和适用范围。先定义前态、时序、完整窗口及目标一致性的检验规则；运行读值本身不能自动充当 deviation 判据。
- 控制权限继续独立保留；normal firmware behavior 不能自动升级为攻击者控制。

**停止线：本轮只完成 Firmware Capability Adapter。未实现 Trigger verifier、Deviation verifier、attack chain、CLI、pruning 或 README consolidation，等待人工审核。**
