# 硬件 820：看到了调试状态差异，模型的写寄存器解释证据不足

[返回验收入口](README.md) · [浏览器阅读/打印](index.html#hardware-820)

## 一分钟结论

**已有波形显示：被分析版本与参考版本的调试状态在六个采样点不同，之后 x10 的值也不同。尚无证据证明两者存在触发关系。**

特别需要注意：模型猜测“被分析版可能执行了参考版没有执行的 x10 写入”。这个方向不能从现有数值差异推出，不能作为验收结论。

| 验收问题 | 本次答案 |
| --- | --- |
| 分析了什么？ | EnCorpus Ibex driver 820 的历史波形与日志 |
| 确认了哪些现象？ | 六个调试状态采样差异、一个 x10 采样差异 |
| 能定位触发指令吗？ | 不能；本次没有提取到符合条件的指令编码，不代表程序没有执行指令 |
| 程序检查通过了吗？ | 9 个被引用支持条目通过；检查的是结构化事实，未证明模型解释 |
| 建议如何验收？ | 保留观察结果；不接受“哪侧多写了 x10”的方向性解释 |

## 发现了什么

| 观察位置 | 被分析版本 | 参考版本 | 能说明什么 |
| --- | --- | --- | --- |
| 100、230、330、410、490、540 ns 的 debug_mode_q | 0 | 1 | 在这六个时刻，调试模式状态位不同；不能说两个时刻之间一直如此 |
| 580 ns 的 x10 | 0 | 0x378（十进制 888） | 寄存器内容不同；不知道各自经历了什么读写操作 |

调试模式可以理解为处理器供调试使用的一种运行状态。这里的状态位不同，并不自动证明存在调试绕过或权限问题。
原报告的两条 abnormal_states 只是汇总这些观察，不是另一轮实验结果。

## 两个猜测分别如何看待

| 模型猜测 | 中文解释 | 验收处理建议 |
| --- | --- | --- |
| debug_mode_divergence | 差异可能和进入或退出调试模式的条件有关 | 可保留为调查方向；没有具体指令、连续状态和因果证据 |
| x10_divergence | 被分析版本可能做了参考版本没有做的写入或更新 | 证据不足，不能接受这个方向性说法；也可能是参考版更新、被分析版未更新，或其他过程，当前不能选择其中一种 |

第二行列举其他可能性只是解释为什么原猜测不能成立，不是新增确定结论。
对本例最稳妥的表述是：“x10 在指定时间的值不同，具体写回过程未知。”

## 历史日志与缺项

历史 verify.log 记录 cover 在 59 个周期内到达，也记录了 EVS053 轨迹错误。
完整验证环境不足，不能将这两项直接解释成漏洞被证明或某一条指令触发了差异。

还缺三类关键材料：指令最终完成的记录、x10 的写回事件、调试进入/退出的完整控制过程。
此外，调试状态和 x10 是不同信号，不能把两者拼成一条连续因果链。

## 建议验收意见与下一步

**建议验收为：观察可追溯，模型对写入方向的解释暂不采纳，触发条件未确认。** 本版没有执行人工签字或 reviewed 导出。
后续应先补足可定位的执行/写回证据，再比较触发过程；不建议围绕已有方向性猜测直接写最终论文结论。
本结果也不能直接与 ARM Heat_Press 的线索拼成跨层攻击链。

## 报告身份与证据附录

此处用于复核；首次阅读可以先跳过。本版是助手编写的中文解读与验收建议，不是原模型新增输出，不赋予 reviewed 状态。

- Case：`encorpus:ibex:driver:820`
- Source run：`05660d2d-c2e7-480d-9758-6d75f0b9ff9b`
- [原始报告 JSON](../../../output/encorpus:ibex:driver:820/05660d2d-c2e7-480d-9758-6d75f0b9ff9b/hardware_analysis_report.json)，SHA256：`74ba7a5b60771b1cff625f3df38f8b3f8ddc2bf135e3206c7fa43eb6e9c87cc5`
- [既有技术审查](../../../docs/research/v3-1b2-structured-hardware-support.md)

- [同一次运行的支持检查](../../../output/encorpus:ibex:driver:820/05660d2d-c2e7-480d-9758-6d75f0b9ff9b/hardware_relation_support.json)：9/9 个引用支持通过。

<details>
<summary>展开全部条目对应关系（技术复核用）</summary>

### 发现

| 原始 ID | 中文含义及审查提示 | 证据编号 / 支持条目 |
| --- | --- | --- |
| `hwfind:local:debug_mode_q:100` | 100 ns 调试状态位不同；不是连续区间证明。 | `sc:rel:local:100` |
| `hwfind:local:debug_mode_q:230` | 230 ns 调试状态位不同；不是连续区间证明。 | `sc:rel:local:230` |
| `hwfind:local:debug_mode_q:330` | 330 ns 调试状态位不同；不是连续区间证明。 | `sc:rel:local:330` |
| `hwfind:local:debug_mode_q:410` | 410 ns 调试状态位不同；不是连续区间证明。 | `sc:rel:local:410` |
| `hwfind:local:debug_mode_q:490` | 490 ns 调试状态位不同；不是连续区间证明。 | `sc:rel:local:490` |
| `hwfind:local:debug_mode_q:540` | 540 ns 调试状态位不同；不是连续区间证明。 | `sc:rel:local:540` |
| `hwfind:reg:x10:580` | 580 ns x10 值不同；写回方向未知。 | `sc:rel:reg:x10:580` |
| `hwfind:formal:cover:c_propagated` | 旧日志记录 59 周期 cover 命中。 | `sc:rel:formal:cover` |
| `hwfind:formal:trace_error:evs053` | 旧日志记录 EVS053 轨迹错误。 | `sc:rel:formal:error` |

### 触发猜测

| 原始 ID | 中文含义及审查提示 | 证据编号 / 支持条目 |
| --- | --- | --- |
| `hwtrig:debug_mode_divergence` | 调试状态差异可能与进入/退出调试有关：待验证。 | `sc:rel:local:100`、`sc:rel:local:230`、`sc:rel:local:330`、`sc:rel:local:410`、`sc:rel:local:490`、`sc:rel:local:540` |
| `hwtrig:x10_divergence` | 猜测被分析版额外写 x10：方向无证据，不采纳。 | `sc:rel:reg:x10:580` |

### 状态归纳

| 原始 ID | 中文含义及审查提示 | 证据编号 / 支持条目 |
| --- | --- | --- |
| `hwstate:debug_mode_q_host_ref_divergence` | 汇总六个调试状态采样点。 | `sc:rel:local:100`、`sc:rel:local:230`、`sc:rel:local:330`、`sc:rel:local:410`、`sc:rel:local:490`、`sc:rel:local:540` |
| `hwstate:x10_host_ref_divergence` | 汇总一个 x10 寄存器采样差异。 | `sc:rel:reg:x10:580` |

</details>

原报告的未决问题已归入正文“缺项/下一步”；行为 ID 列表是索引，不额外翻译成独立发现。
