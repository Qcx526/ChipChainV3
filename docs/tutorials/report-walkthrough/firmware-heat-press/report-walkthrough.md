# Firmware Heat_Press：读懂历史报告，也读懂为什么它后来被质疑

> **这是教学用的历史报告。HISTORICAL / NOT REVIEWED / KNOWN SEMANTIC DEFECTS。**
> 它曾通过较早 pipeline 的机器检查，但后续语义审阅发现了不受支持的解释。
> **不要把它当作 reviewed truth。** 本教程故意保留错误，帮助你学会发现错误。

我们读同一个 case `fuzzware:heat-press:scenario-13` 的两次不同运行：

| 文件 | Source run | 身份 |
| --- | --- | --- |
| [firmware_analysis_report.json](firmware_analysis_report.json) | `104a5332-3cf3-4263-b988-8b5b0b82f14e` | 历史 Firmware B2 canonical report；historical_machine_valid，语义有缺陷 |
| [firmware_relation_support_failure.json](firmware_relation_support_failure.json) | `db343655-ddd8-4b69-8dec-4d0149e38abf` | 后来的 Firmware B3-R3 support gate 拒绝诊断 |

[Manifest](manifest.json) 在 `files[]` 中分别记录两个 run。R3 没有被接受的 canonical report，
也不保存 rejected prose；**不能拿历史 B2 的 summary 给 R3 的 F-direct-calls 等 IDs 补内容**。
这里的前后对照是检查能力的演进，不是对同一份模型响应重新打分。

## 第一层：case_id

`case_id=fuzzware:heat-press:scenario-13` 说明报告针对哪个案例，不是漏洞编号、函数名或物理设备序列号。
Run 身份在 manifest/source path 中，canonical report 本身没有 run_id。

实际顶层字段是：

```text
case_id
findings
external_input_paths
reachable_behaviors
processor_behavior_ids
issue_anchors
unresolved_questions
```

没有 `reachable_functions`。实际 JSON 字段与对象应是你的依据；不能因为教程需求写“函数可达”就替换 contract。
下面按读者容易理解的顺序，把顶层 behavior 索引放到最后解释。

## 第二层：findings（6 项）

每项包含 finding_id、summary、evidence、processor_behavior_ids、epistemic_status。
下面是**存在已知错误的** `f-reset-systeminit-mmio` 字段节选；`evidence` 只展示其中真实 `call-80f88` 引用，
完整数组有 18 项，不能把这个节选当成完整 report。


```json
{
  "finding_id": "f-reset-systeminit-mmio",
  "summary": "Reset_Handler (f80f34, vector 1) is statically bound; SystemInit (f80eac) is a one-hop confirmed callee of Reset_Handler and contains MMIO read sites s80eba/s80eca/s80ed2/s80eda/s80ee6/s80ef2/s80efe/s80f0a with models m16/m2/m3/m12/m4/m0/m5/m6. Static containment and call edges are established; runtime execution is not.",
  "evidence": [
    {
      "evidence_id": "call-80f88",
      "source_type": "deterministic_analyzer",
      "artifact_id": "elf",
      "analyzer": "ghidra-headless + pyelftools + capstone",
      "location": {
        "address": 528264,
        "function": null,
        "basic_block": null,
        "line": null,
        "instruction_index": null,
        "register_name": null,
        "signal": null,
        "time": null,
        "bit_range": null
      },
      "summary": "Static callsite from Ghidra, cross-checked against ELF bytes",
      "epistemic_status": "derived"
    }
  ],
  "processor_behavior_ids": [
    "s80eba",
    "s80eca",
    "s80ed2",
    "s80eda",
    "s80ee6",
    "s80ef2",
    "s80efe",
    "s80f0a",
    "m16",
    "m2",
    "m3",
    "m12",
    "m4",
    "m0",
    "m5",
    "m6"
  ],
  "epistemic_status": "derived"
}
```


| 字段 | 怎么读 |
| --- | --- |
| finding_id | 本报告内的发现 ID，不是确认了一个 SystemInit 漏洞。 |
| summary | 模型声称 Reset 的 one-hop confirmed callee 是 SystemInit；**这部分错误**，下文会追 call-80f88。 |
| evidence | 确实存在 `call-80f88` 不意味着它是模型所说的那条 direct call。看 EvidenceRef.summary 会看到边界。 |
| processor_behavior_ids | MMIO instruction sites（s...）和配置模型（m...）的索引；这些不是执行次数。 |
| epistemic_status=derived | 模型使用了这个标签，但标签不能把错误目标解释变真。 |

人话：报告把“证据 ID 确实存在”和“该证据证明 Reset 直接调用 SystemInit”混在了一起。
即使结尾写了 runtime execution is not established，**前面的静态调用解释仍可能错误**。

另一个 finding `f-opaque-input-unlinked` 指出存在 6009-byte opaque input，但没有记录它如何被 MMIO 消费、
没有 runtime state/failure outcome，也没有到函数的确定性链接。不要把“有 input 文件”直接读成“它能触达漏洞”。

## 第三层：external_input_paths（3 项）

以 UART candidate 为例，以下是原对象除 evidence 数组外的完整字段；原 evidence 数组有 12 项：


```json
{
  "path_id": "eip-uart-irq",
  "entry_point": "UART_Handler (f80abc, vector 24 / external IRQ 8)",
  "summary": "UART/USART interrupt vector entries (UART_Handler f80abc, USART0/1/3_Handler f80ad0/f80adc/f80ae8) are statically bound to vector slots. Their bodies contain unresolved computed/ambiguous call sites (call-80abe, call-80ad2, call-80ade, call-80aea) targeting 529828 (IrqHandler f815a4), which contains MMIO sites s815aa (m20) and s815b0 (m1). This is a candidate external-input path, but vector binding does not establish interrupt occurrence and the call targets are unresolved.",
  "processor_behavior_ids": [
    "s815aa",
    "s815b0",
    "m20",
    "m1"
  ],
  "epistemic_status": "inferred"
}
```


- `path_id` 是候选路径条目 ID，供 reachable behavior 的 `external_input_path_ids` 引用。
- `entry_point` 是模型文字标签，不是一条已验证的物理输入路线。
- `summary` 必须连同 inferred 状态和 unresolved callsite 边界阅读。
- `processor_behavior_ids` 与 `evidence` 给出所讨论 MMIO sites/models 及静态结构依据。
- `epistemic_status=inferred`：模型作了候选关联，不能据此声称中断已经发生。

另两项是 `eip-opaque-input` 与 `eip-interrupt-trigger`，均 unknown。配置里有 round_robin/1000 ticks，
不等于已建立 config→vector→handler execution 的 deterministic 链接。
这些历史文字也未自动升级为后来 A4 的结论；例如后续 A4 将四个 UART b.w 分类为 direct_branch，不能当成 direct_call。

## 第四层：reachable_behaviors（10 项，不是 reachable_functions）

下面是 `rb-uart-irq-mmio` 除 evidence 数组外的全部字段，原数组有 6 项：


```json
{
  "reachability_id": "rb-uart-irq-mmio",
  "processor_behavior_id": "m20",
  "external_input_path_ids": [
    "eip-uart-irq"
  ],
  "reachability_kind": "unknown",
  "epistemic_status": "hypothesized"
}
```


| 字段 | 解释 |
| --- | --- |
| reachability_id | 本条可达性记录的 ID。 |
| processor_behavior_id | **单数**，本例 m20；关联的是 behavior，不是返回一个完整 function 对象。 |
| external_input_path_ids | 指向本报告已有 input-path 条目，本例 eip-uart-irq。 |
| reachability_kind | 实际 enum 是 static/runtime/unknown。本例 unknown。 |
| evidence | 这项断言引用什么记录，不自动证明它可达。 |
| epistemic_status | 本例 hypothesized，表示尚未确立。 |

本报告另有 8 项 Reset/SystemInit 相关记录标为 static/derived、没有 external input path IDs。
**这不表示 runtime 可达，也不洗掉其依赖的历史静态解释缺陷。** 要逐条核对其 evidence 与模型说法。
`external_input_path_ids=[]` 表示这项没有引用输入路径，不代表所有外部输入都能到达它。

## 第五层：issue_anchors（5 项）

Issue anchor 是进一步研究的定位线索。以 `a-reset-systeminit` 为例（本段省略其 18 项 evidence 数组）：


```json
{
  "anchor_id": "a-reset-systeminit",
  "firmware_finding_ids": [
    "f-reset-systeminit-mmio"
  ],
  "processor_behavior_ids": [
    "s80eba",
    "s80eca",
    "s80ed2",
    "s80eda",
    "s80ee6",
    "s80ef2",
    "s80efe",
    "s80f0a",
    "m16",
    "m2",
    "m3",
    "m12",
    "m4",
    "m0",
    "m5",
    "m6"
  ],
  "summary": "Reset-path anchor: Reset_Handler -> SystemInit with MMIO read sites and constant/set models. Static containment and call edges established; runtime execution not established.",
  "epistemic_status": "derived"
}
```


`firmware_finding_ids` 回指 `f-reset-systeminit-mmio`；`processor_behavior_ids` 定位 MMIO sites/models；
`summary` 再次复述 Reset→SystemInit。**复制一个错误 finding 到 anchor 不会产生新的证据。**
Anchor 不是已经存在可利用漏洞的位置，也不是 physical attack surface 的验证记录。

## 第六层：unresolved_questions（8 条）

它们不是可忽略的附注，而是解释报告时必须带上的条件。例如原文包含：

> Static sites and configuration associations do not establish execution or input reachability; runtime reachability of all MMIO behaviors remains unestablished.

> Function/symbol names (e.g., PIO_SetPeripheral, SystemInit, UARTClass::IrqHandler) are static labels, not verified physical-interface semantics.


注意两点：一是明确承认 runtime/input reachability 未建立；二是即使列出若干正确限制，
报告正文仍可能出现 `one-hop confirmed callee` 这样的错误。不能用“它写了免责声明”替代核对关系。

## 第七层：processor_behavior_ids（55 个）

顶层数组汇总报告引用的 behavior IDs，例如 `s80eba` 是静态 instruction site 相关行为、`m16` 是 MMIO 模型相关行为。
这里不嵌入完整 ProcessorBehaviorIR，也不是 55 个函数、漏洞或 runtime MMIO events。
Report 的 IDs 需要回到同一 run 的 deterministic IR 理解，不能仅按名称猜物理外设含义。

历史 Firmware B2 canonical report 没有 `support_claims` 或 `support_claim_ids`；当时还没有后来的 B3 typed support gate。
教学 snapshot 不补造这些字段。现在转到 deterministic 层看它为什么出错。

## 错误追踪：call-80f88 不等于 Reset→SystemInit direct call

在历史 finding `f-reset-systeminit-mmio` 中，模型写：**“SystemInit ... is a one-hop confirmed callee of Reset_Handler”**。
它引用了 `call-80f88`。以下对照来自冻结 [A4 文档](../../../research/v3-2a4-typed-static-relations.md)
与 [A5 文档](../../../research/v3-2a5-angr-static-reachability.md)，不是我们新跑分析得出的结论。

| 对象 | 确定性分类/字段 | 可表达的结论 |
| --- | --- | --- |
| call-80f88 | source=f80f34；kind=control_transfer_unresolved；status=unresolved；transfer_kind=indirect_call；mnemonic=blx | 这个位置有间接控制转移，A4 不能将其视为 confirmed direct call。 |
| call-80f88 的目标相关记录 | A4 保留原 A2 endpoint f816cc（0x816cc），decoded_target_address=null、call_semantics=false；A5 后续 CFGFast successor 为 0x816cc / Ijk_Call | 保留 endpoint 不代表 A4 通过 direct-call 语义验证；目标也不是 f80eac。 |
| call-80afa | source=f80af4（init）、target=f80eac（SystemInit）；kind=direct_call；status=confirmed_static | 这才是 confirmed incoming SystemInit 的那条局部直接调用边。 |

三种名字不能混淆：`call-80f88` 是 relation/callsite 身份；`f80f34` 是 Reset 函数身份；
`f80eac` 是 SystemInit 函数身份。一个引用存在，不保证模型写出的 source/target 对得上。
A4 的 unresolved 是**工具语义边界**，不是宣称“这里没有任何可能的路径”。

## A5 的新视角：局部 relation 与整条静态路径

后来冻结的 angr CFGFast 结果提供了这条 `reachable_static` witness：

```mermaid
flowchart LR
    R[Reset / f80f34] --> M[f816cc]
    M --> I[init / f80af4]
    I --> S[SystemInit / f80eac]
```

以下对象完整摘自现有 A5 runtime artifact
`output/fuzzware:heat-press:scenario-13/47bbd6a0-4b54-4e80-9340-90e575377f03/firmware_static_reachability.json`，
本轮只读，没有重跑 angr：


```json
{
  "capabilities": {
    "supports_hardware_trigger": false,
    "supports_input_reachability": false,
    "supports_interrupt_occurrence": false,
    "supports_path_feasibility": false,
    "supports_runtime_reachability": false,
    "supports_static_reachability": true
  },
  "limitations": [
    "static_only"
  ],
  "path_edge_count": 3,
  "source_function_id": "f80f34",
  "status": "reachable_static",
  "target_function_id": "f80eac",
  "witness_edge_ids": [
    "fc-80f34-816cc",
    "fc-816cc-80af4",
    "fc-80af4-80eac"
  ],
  "witness_function_addresses": [
    528180,
    530124,
    527092,
    528044
  ]
}
```


`witness_function_addresses` 使用十进制整数，转换成 hex 才得到图中的地址。
`witness_edge_ids` 是 A5 function-CFG 边 ID（fc-...），不是 A4 call-... ID。

| 层级 | 回答的问题 | 没有证明什么 |
| --- | --- | --- |
| A4 local relation | 这个具体 callsite/向量/MMIO containment 的类型与端点是什么？ | 不自动寻找更长路径；unresolved 不等于不可达。 |
| A5 static path | CFGFast 恢复的静态图里是否有满足当前有界规则的路径见证？ | 不证明 path feasible、runtime executed、external input reachable、interrupt occurred。 |

这条 **3-edge** 路径既没有把 `call-80f88` 提升为 direct_call，也没有把旧模型的 **one-hop** 解释变正确。
`supports_static_reachability=true` 与 `supports_runtime_reachability=false` 等 capability 必须一起读。
静态 path 是图中的 witness，不是执行日志；即使启动函数名称很熟悉，也不能跳过当前证据边界。

## R3：如何阅读 support failure diagnostic

现在切换到另一次 R3 运行的 [failure JSON](firmware_relation_support_failure.json)。它没有 canonical accepted report。


```json
{
  "failure_reason_code": "incompatible_relation_claim",
  "generated_support_claim_count": 106,
  "orphan_incompatible_count": 2,
  "orphan_support_claim_count": 3,
  "orphan_supported_count": 1,
  "orphan_unsupported_count": 0,
  "referenced_incompatible_count": 37,
  "referenced_support_claim_count": 103,
  "referenced_supported_count": 66,
  "referenced_unsupported_count": 0,
  "schema_version": "firmware-relation-support-failure/v1"
}
```


字段应这样读：

| 字段 | 含义 |
| --- | --- |
| schema_version | `firmware-relation-support-failure/v1`；失败诊断合同，不是 canonical report 版本。 |
| failure_reason_code | 本次为 incompatible_relation_claim，指出 referenced typed claims 与 deterministic facts 冲突。 |
| generated_support_claim_count | 共生成 106 个 supports，不是 106 个 findings。 |
| referenced_support_claim_count / orphan_support_claim_count | 103 被 items 引用，3 未被引用。 |
| referenced_supported / incompatible / unsupported | 66 / 37 / 0；只要一个 referenced support 失败就拒绝报告，不是按多数票通过。 |
| orphan_supported / incompatible / unsupported | 1 / 2 / 0；orphan 全部求值，但这两个 orphan 错误不是本次整份报告被拒绝的理由。 |
| failed_referenced_supports | 37 项，仅放被引用的失败 supports；没有通过项、没有 orphan 错误项。 |

Counts 实际是顶层各个 `*_count` 字段，**没有叫 `counts` 的嵌套对象**。
106 = 103 + 3；103 = 66 + 37 + 0；3 = 1 + 2 + 0。

每个 failed entry 保存 support_claim_id、claim_type、usage_status、result、reason_code、relation_ids、
referencing_firmware_claims、expected、actual_relations、mismatch_detail。
`expected` 是模型提交的预期断言，不是 oracle；`actual_relations` 是 checker 对照的 deterministic snapshot。
`mismatch_detail=null` 不代表匹配成功，应读 `result` 和两侧字段。
只记引用 item 的 collection/claim_id，不保存其被拒绝的 summary、raw AIMessage 或 provider body。

### 例 1：direct-call target mismatch

以下为真实 `sc-call-80bd2` 的完整失败条目：


```json
{
  "actual_relations": [
    {
      "actual": {
        "attributes": {
          "call_semantics": true,
          "detail_type": "control_transfer",
          "mnemonic": null,
          "original_reason": null,
          "transfer_kind": "direct_call"
        },
        "kind": "direct_call",
        "relation_id": "call-80bd2",
        "source": {
          "entity_id": "f80af4",
          "entity_type": "function"
        },
        "status": "confirmed_static",
        "target": {
          "entity_id": "f81052",
          "entity_type": "function"
        }
      },
      "relation_id": "call-80bd2"
    }
  ],
  "claim_type": "relation_fact",
  "expected": {
    "claim_type": "relation_fact",
    "expected_binding_status": null,
    "expected_direction": null,
    "expected_kind": "direct_call",
    "expected_source_entity_id": "f80af4",
    "expected_status": "confirmed_static",
    "expected_target_entity_id": "f8106c",
    "expected_transfer_kind": "direct_call",
    "expected_vector_index": null,
    "relation_id": "call-80bd2"
  },
  "mismatch_detail": null,
  "reason_code": "relation_fact_mismatch",
  "referencing_firmware_claims": [
    {
      "claim_id": "F-direct-calls",
      "collection": "findings"
    }
  ],
  "relation_ids": [
    "call-80bd2"
  ],
  "result": "incompatible",
  "support_claim_id": "sc-call-80bd2",
  "usage_status": "referenced"
}
```


人话：source f80af4、direct_call、confirmed_static 都写对了，但模型把 target 写成 **f8106c**，
实际是 **f81052**。因此 relation ID 正确也仍然 incompatible，reason=relation_fact_mismatch。
引用它的 R3 finding ID 为 `F-direct-calls`，不能映射成历史 B2 的 `f-reset-systeminit-mmio`。
这个例子也不是 call-80f88 本身；两者展示的是不同的真实错误。

### 例 2：MMIO containment mismatch

以下为真实 `sc-mmio-cont-815aa`：


```json
{
  "actual_relations": [
    {
      "actual": {
        "attributes": {
          "detail_type": "mmio_containment"
        },
        "kind": "mmio_function_containment",
        "relation_id": "mmio-containment-815aa",
        "source": {
          "entity_id": "mmio-815aa",
          "entity_type": "mmio_site"
        },
        "status": "confirmed_static",
        "target": {
          "entity_id": "f815a4",
          "entity_type": "function"
        }
      },
      "relation_id": "mmio-containment-815aa"
    }
  ],
  "claim_type": "relation_fact",
  "expected": {
    "claim_type": "relation_fact",
    "expected_binding_status": null,
    "expected_direction": null,
    "expected_kind": "mmio_function_containment",
    "expected_source_entity_id": "mmio-815aa",
    "expected_status": "missing",
    "expected_target_entity_id": null,
    "expected_transfer_kind": null,
    "expected_vector_index": null,
    "relation_id": "mmio-containment-815aa"
  },
  "mismatch_detail": null,
  "reason_code": "relation_fact_mismatch",
  "referencing_firmware_claims": [
    {
      "claim_id": "F-mmio-containment",
      "collection": "findings"
    }
  ],
  "relation_ids": [
    "mmio-containment-815aa"
  ],
  "result": "incompatible",
  "support_claim_id": "sc-mmio-cont-815aa",
  "usage_status": "referenced"
}
```


人话：模型声称 `mmio-815aa` 的 containment **missing / target=null**，
而 actual 是 **confirmed_static / target=f815a4**。实际缺证时不能猜函数，但实际已经有确定性函数归属时，
反过来说“缺失”也会和事实冲突。它由 R3 `F-mmio-containment` 引用，所以拒绝。

### 例 3：vector target mismatch

以下为真实 `sc-vec-33`：


```json
{
  "actual_relations": [
    {
      "actual": {
        "attributes": {
          "binding_status": "function_entry",
          "detail_type": "vector_dispatch",
          "vector_index": 33
        },
        "kind": "vector_dispatch",
        "relation_id": "vector-33",
        "source": {
          "entity_id": "vector-33",
          "entity_type": "vector_entry"
        },
        "status": "confirmed_static",
        "target": {
          "entity_id": "f80ad0",
          "entity_type": "function"
        }
      },
      "relation_id": "vector-33"
    }
  ],
  "claim_type": "relation_fact",
  "expected": {
    "claim_type": "relation_fact",
    "expected_binding_status": "function_entry",
    "expected_direction": null,
    "expected_kind": "vector_dispatch",
    "expected_source_entity_id": "vector-33",
    "expected_status": "confirmed_static",
    "expected_target_entity_id": "f80abc",
    "expected_transfer_kind": null,
    "expected_vector_index": 33,
    "relation_id": "vector-33"
  },
  "mismatch_detail": null,
  "reason_code": "relation_fact_mismatch",
  "referencing_firmware_claims": [
    {
      "claim_id": "F-vec-table",
      "collection": "findings"
    },
    {
      "claim_id": "A-vec-uart",
      "collection": "issue_anchors"
    }
  ],
  "relation_ids": [
    "vector-33"
  ],
  "result": "incompatible",
  "support_claim_id": "sc-vec-33",
  "usage_status": "referenced"
}
```


人话：vector_index=33、binding_status=function_entry 正确，但 target 写成 **f80abc**，actual 为 **f80ad0**。
由 `F-vec-table` 和 `A-vec-uart` 引用。向量绑定是静态入口映射，不表示此中断发生过。
不能靠相邻 vector 或相近函数地址“差不多”匹配，也不要从 symbol label 推定外部物理输入已经可达。

## 我可以相信什么？

| 字段/结论 | 可以直接相信？ | 为什么？ | 还需要什么？ |
| --- | --- | --- | --- |
| 本地 snapshot 与 source SHA 一致 | 可用于来源/复制核对 | 原样复制与 manifest | 不能据此证明正文语义 |
| 历史 report 的 machine-valid | 只说明早期 gates 曾通过 | 当时没有当前 typed support 检查能力 | 审阅每条解释，尤其已知缺陷 |
| f-reset-systeminit-mmio 的 one-hop claim | 不可以 | call-80f88 不是这条 confirmed direct call | 区分 call-80afa 和 A5 多跳路径 |
| A4 call-80afa | 有 confirmed_static local relation 支持 | 精确 source/target/类型 | 仍不证明实际执行 |
| A5 Reset→SystemInit witness | 在 CFGFast 静态抽象内可用 | 三个明确图边和 static capability | feasibility、runtime、external input 证据缺失 |
| external_input_paths / issue_anchors | 候选研究线索 | inferred/unknown 和已知缺口 | 真实消费链路、控制条件、运行验证 |
| R3 result=incompatible | 可定位是哪项 typed assertion 冲突 | expected 与 actual 同列 | 不等于证明系统安全或存在漏洞 |
| runtime reachability / verified vulnerability | 本例没有建立 | 静态能力不足且报告历史有缺陷 | 对应证据与独立审核 |

关于 supported / unsupported / incompatible 以及 observed/derived/inferred/hypothesized/verified，
见[共用状态教程](../README.md)。本历史 report 实际出现 observed、derived、inferred、hypothesized、unknown，
没有 verified。R3 的 confirmed_static、unresolved 属于 relation status，不是 epistemic_status。

## 阅读练习

已知 A5 给出 `f80f34 → f816cc → f80af4 → f80eac`，status=reachable_static，3 edges。
**能否声称“这个输入在 runtime 到达了 SystemInit”，或“Reset 直接调用 SystemInit 已证实”？**

<details>
<summary>展开答案</summary>

都不能。前者缺少 input consumption、可行性和实际运行证据；后者把三跳路径误写成单跳关系。
可准确说：“冻结 A5 的 CFGFast 图存在 Reset→SystemInit 的三边静态 witness。”
A4 `call-80f88` 仍是 unresolved/indirect_call，confirmed incoming edge 是 init 的 `call-80afa`。

</details>

最后按[十步阅读流程](../README.md#固定的十步-json-阅读流程)复查。历史 report 的 support 不存在时就明确说不存在，
转向相关版本的 deterministic 记录；不要把另一个 R3 run 的 supports 接过来补齐。
