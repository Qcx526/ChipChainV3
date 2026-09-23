# Type-II Runtime Verifier：受控合成黄金链

冻结起点：`main` / `b8ba6cd5d6d49952fde317504dc93e5f72da2f3e` / `v3-type2-fw-capability-adapter-stable`。本轮只增加一个验证模块、两组测试和本文。结果是一个独立的 `controlled-type2-verification/v1` 对象；历史 XL2 `xlcompat:34bfee41ac1fc6b44fe6233bfaae8c540f8fdce5deb6ffbaf37fd80f71538ded` 仍是 UNKNOWN。

## 给验收者的结果

| 案例 | 固件和 RTL | 判断 | 为什么 |
|---|---|---|---|
| P1 | A5 Variant，A5 Reference 对照 | **`verified_controlled_type2_chain`** | Variant 的 ENABLE→COMMAND 满足 typed 条件和前态；STATUS 内部稳定采样及总线读值均为 `0xDEAD`；同源 Reference 执行同样触发并读到预期 `0`；冻结差分只改变受控外设源文件 |
| N1 | A4 Variant，A4 Reference | **`trigger_contradicted`** | 完整运行窗口证明实际执行了 COMMAND=A4，明确与合约要求 A5 冲突；不是把“没见到 A5”当反证 |
| N2 | P1 的 Reference 控制分支 | 触发执行支持、预期行为支持；`deviation_observed=false` | ENABLE 前态和 A5 写入成立，内部 STATUS 与总线读值都为 `0`。Reference 不冒充 Variant 合约的 target |
| U1 | P1 的 Variant 值，但移除显式 ObservationBinding | **`unknown`** | 即使看见 `0xDEAD`，缺少观测值与 joint run / RTL / map 的显式链接，也不从邻近文件或标签回填 |

[一页中文验收报告](../../output/type2-verifier/review-njtac3br/report-zh.md)和[本地结果索引](../../output/type2-verifier/review-njtac3br/local-manifest.json)可直接打开。合约与来源：[实际 HBC](../../output/type2-verifier/review-njtac3br/contract.json)、[StateBinding](../../output/type2-verifier/review-njtac3br/state-binding.json)。完整对象：[P1](../../output/type2-verifier/review-njtac3br/p1-type2.json)、[N1](../../output/type2-verifier/review-njtac3br/n1-type2.json)、[N2](../../output/type2-verifier/review-njtac3br/n2-reference-control.json)、[U1](../../output/type2-verifier/review-njtac3br/u1-type2.json)。这些运行产物位于 Git 忽略的 `output/`，科学 ID 不包含该目录名。

P1 的最终 `type2-verification` ID、HBC ID、每个 condition 的状态、reason code、evidence IDs、缺失项与 scope 全部保存在 JSON。正文只给判断及关键证据，便于人工复核。

## 现有 HardwareBehaviorContract 的实际内容

集成测试调用冻结的 `build_hardware_behavior_contract()`。合约来源是冻结 Reference 的 `synthetic_mmio.sv` 原始字节，`SourceArtifact.source_kind=synthetic_fixture`，Deviation 的 `specification_ref` 绑定该 artifact。`scope.applicability=synthetic_only`，architecture=RISC-V，platform ID 是受审查的目标 MMIO map ID；`rtl_identity`、`rtl_revision` 及 scope 只允许 Variant RTL tree：

```text
805480e150a838026c0b47dfe375a0548064381a4b175d79f9ea6bf02089b440
```

合约的两个 formalized MMIOTriggerAtom 分别要求 full-word WRITE `0x40000=1` 和 WRITE `0x40004=0xA5`。OrderingTriggerAtom 的两个端点引用上述两个 condition ID。Precondition 要求在 COMMAND 被接受**之前** `SyntheticPeripheral.ENABLE == 1`。Deviation 是 `wrong_value`，affected component `SyntheticPeripheral.STATUS`，Reference 规格预期 `0`，受控 Variant 偏离值 `0xDEAD`。ObservationRequirement 要求 post-update internal STATUS sample 和 bus-visible STATUS read response **同时存在并一致**。

StateBinding 很窄：它把 ENABLE/STATUS subject、MMIO address 与 reset value 绑定到同一个 Reference synthetic spec artifact 的 SHA 和 ID。验证器不从 P1/N1 标签猜测地址。现有 HBC/CAP0/Trigger schema 足以表达这些要求；没有新增平行合约，也没有修改冻结模型。

## 验证规则与证据边界

输入采用现有 FirmwareCapability、HardwareBehaviorContract、BRIDGE1 BridgeSet、B1 RuntimeMmioObservationSet、原始 ELF/processor/bus/stdout/stderr bytes、单 CoreD platform proof、显式 ObservationBinding，以及冻结的 controlled source delta。入口先重放 CAP0 适配器和 Bridge materializer，重算实际字节哈希、解析完整 bus 窗口及检查内容 ID。对象或原始文件被篡改时拒绝；有效输入缺少选择性来源链接时返回 UNKNOWN。

Verifier 通过 primitive kind、resource、exact address、access width、已解析 write value 和 Entry 的退休状态查找当前 run 的能力，再经 BOUND binding 定位 completed RuntimeMmioObservation。只有静态能力或 UNKNOWN bridge 不构成执行支持。明确冲突要求当前完整窗口中存在已执行的唯一竞争事务；缺候选或多个候选保留 UNKNOWN。所有负面判断都依赖冻结 B1/BRIDGE1 对 footer、reset epoch、accepted request、completed response 与 joint attestation 的严格重放。

ENABLE 前态从同一 reset epoch 的 accepted request 流重建：reset→0，后续已完成的 ENABLE write 更新值；遇到 COMMAND request 前截取状态，并要求曾有较早的 ENABLE 写且中间无覆盖／重置。ordering 由两笔绑定事务的 request cycle、transaction identity 和 reset epoch 判断。capability 在参数列表中的顺序不参与匹配。未建立共享时间单位的 order time bound 不擅自支持。

STATUS 取 COMMAND request 所在 cycle 的冻结 apparatus **negedge post-update stable sample**，再与随后完成的 STATUS read response 对照。内部/总线值冲突、read 没有 BOUND capability、缺 sample 或缺显式 ObservationBinding，均为 UNKNOWN。`0xDEAD` 只有与 formalized `expected=0 / deviating=0xDEAD` 合约相比后才支持 deviation；内部和总线观测缺一不可。Reference 的双重观测为 `0`，因此 N2 是“已执行触发，但未观测到偏离”的对照。

受控差分读取冻结 A 的 `controlled-source-delta.json`、两棵 source manifest、两个 `synthetic_mmio.sv` bytes 和固定 SHA 的 `variant.patch`。它要求 Reference/Variant 整树 manifest 哈希精确匹配已审查版本，文件集合一致且仅该外设文件变化，monitor 段一致，patch SHA 是 `acd5a0b8eebe1bf47f739a82ce212d605df01a17ecbabf598db7c312d3d86272`。集成入口还通过冻结 `prepare()` 对**整个实际 source tree**、ELF、simulator 和 recipe 重新校验。两侧必须有相同 firmware/input/execution context/map，接受的目标事务行为相同；允许 RTL tree/simulator 因受控改动不同，STATUS 则需 Reference=`0`、Variant=`0xDEAD`。

Reference 仅在 ReferenceControlVerification 中评价触发和预期行为；Variant 合约的 target scope 必须匹配 Variant tree。替换 Reference 固件、修改 revision、移除 differential proof 都不会得到 positive。结果的 `ConditionVerification` 使用 `supported / contradicted / unknown`，包括 requirement ID、状态、证据 ID、reason code、missing requirements、scope；没有 confidence。最终 `verified_controlled_type2_chain` 只有 scope、全部 trigger、ENABLE 前态、ordering、deviation、observation、Reference 控制与受控差分均 supported 才产生。必要项 UNKNOWN 导致 final UNKNOWN；target scope/source 正式成立时，明确 trigger 冲突才导致 `trigger_contradicted`；scope 不匹配时即使某事务字段冲突也保留 final UNKNOWN。触发成立且内部/总线观测一致地得到规格预期值时，目标偏差可判 `deviation_contradicted`，不依赖缺失的 positive differential 证明。

## 实现与回归

新增文件仅四个：

- [type2_verifier.py](../../src/chipchain/cross_layer/type2_verifier.py)：一个模块内定义条件、触发、偏差、Reference、差分与最终结果，使用冻结 canonical content hash 生成确定性 ID。
- [test_type2_verifier.py](../../tests/unit/test_type2_verifier.py)：纯合成对抗单元测试。
- [test_type2_golden.py](../../tests/integration/test_type2_golden.py)：只读重放四个冻结 joint runs，构造实际 synthetic HBC 并评价 P1/N1/N2/U1。
- 本临时研究文档。

没有修改 `mmio_grounding.py`、`mmio_execution_bridge.py`、`mmio_capability.py`、CAP0、XL1、XL2、Trigger 或 SYN-E2E1 A 的任何文件；没有新 Agent、workflow、CLI、matcher package 或 report module。P1/N1/N2/U1 名称仅在集成评价、验收文件名及本报告中使用。Verifier API、HBC 实际构造的科学字段、条件匹配和结果 ID 都不接受这些标签、host path、timestamp、run UUID 或 LLM 文字。

新增 17 项测试（11 unit、6 integration），覆盖 A5 支持、A4/错误地址/错误宽度明确冲突；static-only/UNKNOWN bridge 不升级；能力列表置换不影响结果；ENABLE 覆写/重置使前态失效；STATUS 内部/总线冲突为 UNKNOWN；Reference=0 与 Variant=DEAD；缺来源/Reference/RTL binding、合约缺失排序要求为 UNKNOWN；篡改原始 trace/patch 为错误；deterministic result ID。重置对抗例检验独立状态重建器；冻结 B1 parser 对本实验不支持的第二 reset epoch 会先行拒绝。

真实 integration 打印并保存：P1 trigger/deviation/observation/differential 全 supported，最终 positive；N1 trigger contradicted；N2 trigger/expected supported、deviation false；U1 UNKNOWN。BRIDGE1 仍为 12 BOUND，旧 B1 为 12 UNKNOWN，旧 XL2 为 UNKNOWN。`output/mmio-capability/adapter-l2ix1eun/` 中的 P1/N1 静态与执行 capability ID 均逐项读取、重放及保持不变。

执行的门禁命令：

```bash
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q tests/unit/test_type2_verifier.py tests/integration/test_type2_golden.py
CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m compileall -q src tests experiments
git diff --check
```

针对性测试：`17 passed in 16.12s`。pip check：`No broken requirements found.`；compileall 与 `git diff --check`：exit 0，无输出。完整 pytest：**`1528 passed, 29 skipped in 77.11s`**。

本轮新增 simulation 0、build 0、LLM calls 0。没有执行 git add/commit/push/tag。起始与结束 HEAD/tag 均为 `b8ba6cd5d6d49952fde317504dc93e5f72da2f3e` / `v3-type2-fw-capability-adapter-stable`；62,268 个原有 samples/output 文件的 SHA256 没有变化，Git 状态仅四个新增文件。Type-II 受控合成链结果不等于真实 Ibex 漏洞、硅片漏洞或攻击者控制；FirmwareCapability 的 `control_authority=not_established` 保持不变。

四个 golden cases 满足预期后，本阶段停止科研功能扩展。下一步须先人工审核并冻结；通过后可规划 Core Consolidation，统一工作流与文档、清理历史冗余。本轮没有进入整合、删减、Type I/III 或新 Agent 阶段。
