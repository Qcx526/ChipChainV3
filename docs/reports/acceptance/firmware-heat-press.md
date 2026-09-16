# 固件 Heat_Press：发现静态分析线索，但部分调用路径解释有误

[返回验收入口](README.md) · [浏览器阅读/打印](index.html#firmware-heat-press)

## 一分钟结论

**这份固件报告找到了串口中断和外设访问的静态线索，也暴露了分析缺口；但它把一条尚未确认的调用关系写成了确定路径，因此整份报告不能按“路径已证实”验收。**

本文主要解释历史 B2 运行。后来的 R3 是另一轮运行，报告被支持检查拒绝；两轮不能混成一份通过验收的报告。

| 验收问题 | 本次答案 |
| --- | --- |
| 分析对象是什么？ | ARM Heat_Press 固件与 Fuzzware scenario 13 的输入配置 |
| 做了真实固件执行吗？ | 这里所解释的报告基于静态结构与配置，没有证明输入被固件实际消费 |
| 找到了什么？ | 候选串口相关入口、外设访问位置、缺失的函数归属和未建立的输入连接 |
| 原模型报告通过了吗？ | 历史 B2 通过机器检查，但后续语义审查发现错误；不是 reviewed 成果 |
| 建议验收结论？ | 接受可核对的局部结构事实和缺项清单；退回错误路径解释 |

## 六项主要发现，分别意味着什么

| 原始发现 | 给验收者的解释 | 应如何处理 |
| --- | --- | --- |
| 串口中断线索 | 静态向量表中有 UART/USART 处理函数，也找到了相关外设读取位置。这些可作为继续调查的入口。 | 保留为候选。函数之间是否属于确定调用、实际是否进入中断，都尚未证明 |
| Reset → SystemInit | 模型称复位处理函数直接调用初始化函数，并据此串起外设访问路径。已有静态证据不支持这条确定调用边。 | **退回这项路径结论**，不能当成已经证实的初始化链路 |
| 三个 PIO 位置缺少归属 | 三个外设访问位置存在，但 Ghidra 没有确认它们属于哪个函数体。 | 可以验收为分析缺口；符号名称不能代替函数归属证据 |
| 11 项外设模型未定义行为 | 配置里的 m21–m31 没有提供确定的外设返回值规则。 | 保留为环境建模缺口，不等于真实硬件异常 |
| 6009 字节输入未建立联系 | 有输入文件，但没有证据说明哪个函数或外设读取了它、引发了什么结果。 | 不把文件名或文件存在当作 crash/可达性证明 |
| 中断配置未建立联系 | 有“每 1000 个模拟器 tick 轮转触发”的配置，但未连接到具体处理函数的真实执行。 | 不把配置等同于中断实际发生；tick 也不能直接换成物理时间 |

外设访问（MMIO）指固件通过读写特定地址与外围设备交互。
静态向量表说明“如果相应事件发生，将使用哪个处理入口”，不是事件确实发生的运行记录。

## 必须纠正的三处表述

**1. 不能把 Reset → SystemInit 写成已确认的直接调用。**
原报告使用 call-80f88 支持这句话，但该位置属于未解决的调用，记录的目标是 0x816cc。
已确认指向 SystemInit 的边是 init → SystemInit（call-80afa），不能拿它替代 Reset 的调用证据。
“局部外设访问位置存在”与“从复位入口能沿确定路径到达那里”是两个不同结论。
原报告依赖这条路径的八条 reachable_behaviors 和对应 issue anchor，也不能直接接受。

**2. 串口相关的未确定关系，不应一概说成目标地址不知道。**
四个 UART/USART 转移位置的记录原因是解码器意见不一致（decoder_disagreement），
已记录静态目标 0x815a4，但其“直接调用”分类没有被确认。
原文写成 computed/ambiguous 会掩盖实际问题；应明确到底缺的是哪一种证明。

**3. SystemInit 外设模型不是只有 constant/set。**
原报告的概括漏掉 m0 的 bitextract 和 m12 的 passthrough。
这属于摘要不完整；本历史 B2 报告已把八个位置描述为读取，不应再误说它在此处把读写方向写反。

以上纠正来自既有 B2 逐条语义审查。原始 JSON 没有被改写，避免把新解释冒充历史模型输出。

## “输入路径”“可达行为”“问题线索”如何验收

- 三条输入路径：串口路径是待验证候选；opaque input 与中断配置两条均未建立实际消费路径。
- 十条可达行为：两条串口行为原本就标记为 unknown；其余八条与 Reset/SystemInit 相关的路径依据不足，不能因写了 static 就视为证实。
- 五个问题线索：它们是对已有发现的归组，不是五个漏洞。串口线索和三个缺项分组可以指导后续研究；Reset 路径分组需修正。
- 55 个 processor_behavior_ids 是被引用的行为条目集合，不代表已执行 55 个动作，也不是 55 个漏洞。

## 后来被拒绝的 R3 报告，意味着什么

R3 run 为 `db343655-ddd8-4b69-8dec-4d0149e38abf`，与上面的 B2 run 不同。
它引用的 103 个支持条目中，66 个通过、37 个与确定性事实冲突，因而没有 accepted canonical report。
这 37 个失败包含 34 个事实字段不一致和 3 个断裂的显式路径。

通俗地说，程序发现“模型用于支撑结论的话，与已有事实对不上”，所以没有接受报告。
这是报告质量与证据支持问题，不是检测到了 37 个漏洞，也不是证明固件没有漏洞。
R3 诊断没有保存完整被拒绝正文，本版不据此重建模型没有留下的故事。
R3 的错误也不能当作 B2 的同一次支持审计来使用。

## 建议验收意见与下一步

**建议：局部静态事实和分析缺项可作为阶段材料，确定路径结论需退回修正；当前没有可验收的跨层漏洞结论。**
下一步优先核对调用/分支分类，再取得实际输入消费与中断执行证据。
若只是撰写阶段报告，可明确交付“识别到候选入口及证据缺口”，不要交付“已证实外部输入到达目标函数”。
此 Heat_Press 是 ARM 固件，不能因为项目里另有 Ibex 硬件报告，就自动形成同目标跨层配对。

## 报告身份与证据附录

此处用于复核；首次阅读可以先跳过。本版是助手编写的中文解读与验收建议，不是原模型新增输出，不赋予 reviewed 状态。

- Case：`fuzzware:heat-press:scenario-13`
- Source run：`104a5332-3cf3-4263-b988-8b5b0b82f14e`
- [原始报告 JSON](../../../output/fuzzware:heat-press:scenario-13/104a5332-3cf3-4263-b988-8b5b0b82f14e/firmware_analysis_report.json)，SHA256：`1e593db5a363ef9c4b956788d43f5898ac471052bce3fa295fe6fdefae04b316`
- [既有技术审查](../../../docs/research/v3-2b2-enriched-firmware-agent.md)

<details>
<summary>展开全部条目对应关系（技术复核用）</summary>

### 发现

| 原始 ID | 中文含义及审查提示 | 证据编号 / 支持条目 |
| --- | --- | --- |
| `f-uart-irq-mmio` | 串口相关候选入口；原文对 unresolved 原因描述有误。 | `vector-24`、`vector-33`、`vector-34`、`vector-36`、`call-80abe`、`call-80ad2`、`call-80ade`、`call-80aea`、`s815aa`、`s815b0`、`m20`、`m1` |
| `f-reset-systeminit-mmio` | Reset→SystemInit 确定路径缺少支持，需纠正。 | `vector-1`、`call-80f88`、`s80eba`、`s80eca`、`s80ed2`、`s80eda`、`s80ee6`、`s80ef2`、`s80efe`、`s80f0a`、`m16`、`m2`、`m3`、`m12`、`m4`、`m0`、`m5`、`m6` |
| `f-pio-missing-containment` | 三个 PIO 位置没有确认函数归属。 | `s80d4e`、`s80d50`、`s80d5a`、`m7`、`m8`、`m9`、`m10`、`m11`、`containment-m7`、`containment-m8`、`containment-m9`、`containment-m10`、`containment-m11` |
| `f-unmodeled-mmio` | 11 项外设模型缺少确定值规则。 | `m21`、`m22`、`m23`、`m24`、`m25`、`m26`、`m27`、`m28`、`m29`、`m30`、`m31`、`s80e16`、`s80e1c`、`s80e3a`、`s80e4e`、`s80e7e` |
| `f-opaque-input-unlinked` | 6009 字节输入未连接到具体消费行为。 | `input` |
| `f-trigger-unlinked` | 中断配置未连接到实际 handler 执行。 | `trigger` |

### 输入路径

| 原始 ID | 中文含义及审查提示 | 证据编号 / 支持条目 |
| --- | --- | --- |
| `eip-uart-irq` | 串口路径是候选，未证明实际输入可达。 | `vector-24`、`vector-33`、`vector-34`、`vector-36`、`call-80abe`、`call-80ad2`、`call-80ade`、`call-80aea`、`s815aa`、`s815b0`、`m20`、`m1` |
| `eip-opaque-input` | opaque input 消费路径未知。 | `input` |
| `eip-interrupt-trigger` | 中断配置与执行路径关系未知。 | `trigger` |

### 可达行为

| 原始 ID | 中文含义及审查提示 | 证据编号 / 支持条目 |
| --- | --- | --- |
| `rb-uart-irq-mmio` | 串口 m20 可达性未知。 | `m20`、`s815aa`、`call-80abe`、`call-80ad2`、`call-80ade`、`call-80aea` |
| `rb-uart-irq-mmio-2` | 串口 m1 可达性未知。 | `m1`、`s815b0`、`call-80abe`、`call-80ad2`、`call-80ade`、`call-80aea` |
| `rb-reset-systeminit` | SystemInit 局部位置存在，但所宣称 Reset 路径依据不足。 | `vector-1`、`s80eba`、`m16` |
| `rb-reset-systeminit-2` | SystemInit 局部位置存在，但所宣称 Reset 路径依据不足。 | `vector-1`、`s80eca`、`m2` |
| `rb-reset-systeminit-3` | SystemInit 局部位置存在，但所宣称 Reset 路径依据不足。 | `vector-1`、`s80ed2`、`m3` |
| `rb-reset-systeminit-4` | SystemInit 局部位置存在，但所宣称 Reset 路径依据不足。 | `vector-1`、`s80ee6`、`m4` |
| `rb-reset-systeminit-5` | SystemInit 局部位置存在，但所宣称 Reset 路径依据不足。 | `vector-1`、`s80efe`、`m5` |
| `rb-reset-systeminit-6` | SystemInit 局部位置存在，但所宣称 Reset 路径依据不足。 | `vector-1`、`s80f0a`、`m6` |
| `rb-reset-systeminit-7` | SystemInit 局部位置存在，但所宣称 Reset 路径依据不足。 | `vector-1`、`s80ef2`、`m0` |
| `rb-reset-systeminit-8` | SystemInit 局部位置存在，但所宣称 Reset 路径依据不足。 | `vector-1`、`s80eda`、`m12` |

### 研究线索

| 原始 ID | 中文含义及审查提示 | 证据编号 / 支持条目 |
| --- | --- | --- |
| `a-uart-irq-input` | 串口调查线索，非确认入口。 | `vector-24`、`vector-33`、`vector-34`、`vector-36`、`call-80abe`、`call-80ad2`、`call-80ade`、`call-80aea`、`s815aa`、`s815b0`、`m20`、`m1` |
| `a-reset-systeminit` | Reset 路径线索需纠正，模型还漏述两类配置模型。 | `vector-1`、`call-80f88`、`s80eba`、`s80eca`、`s80ed2`、`s80eda`、`s80ee6`、`s80ef2`、`s80efe`、`s80f0a`、`m16`、`m2`、`m3`、`m12`、`m4`、`m0`、`m5`、`m6` |
| `a-pio-containment-gap` | 函数归属缺口，非漏洞。 | `s80d4e`、`s80d50`、`s80d5a`、`m7`、`m8`、`m9`、`m10`、`m11` |
| `a-unmodeled-mmio` | 外设建模缺口，非漏洞。 | `m21`、`m22`、`m23`、`m24`、`m25`、`m26`、`m27`、`m28`、`m29`、`m30`、`m31` |
| `a-input-trigger-unlinked` | 输入与中断配置没有建立执行连接。 | `input`、`trigger` |

</details>

原报告的未决问题已归入正文“缺项/下一步”；行为 ID 列表是索引，不额外翻译成独立发现。

R3 独立来源：[失败诊断](../../../output/fuzzware:heat-press:scenario-13/db343655-ddd8-4b69-8dec-4d0149e38abf/firmware_relation_support_failure.json)、[逐项诊断说明](../../research/v3-2b3-r3-referenced-support-diagnostics.md)。
