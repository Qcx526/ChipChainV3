# ChipChain Type-II 验证报告

**结论：触发条件与观测证据矛盾。**

已执行的 MMIO 访问与合同的触发值冲突；不能把后续读值解释为这条触发链的偏差。

- 硬件触发：与证据矛盾（contradicted）
- 行为偏差：尚不能判定（unknown）
- 客观观测：尚不能判定（unknown）
- Reference/Variant 对照：尚不能判定（unknown）

## 触发条件逐项

| 条件 | 判定 | 依据或阻断原因 |
| --- | --- | --- |
| `type2:target-scope` | 有证据支持（supported） | 目标、RTL 修订和合成来源吻合 |
| `type2:enable-write` | 有证据支持（supported） | 源指令与精确 MMIO 事务已绑定 |
| `type2:command-write` | 与证据矛盾（contradicted） | 已执行访问与要求的值冲突 |
| `type2:write-order` | 尚不能判定（unknown） | 缺少满足条件的两个顺序端点 |
| `type2:enable-prestate` | 尚不能判定（unknown） | 缺少满足条件的 COMMAND 端点 |

触发已被反证；后续偏差与对照保持未判定，不表示每项上游证据都缺失。

## Reference 对照运行

- 触发：尚不能判定（unknown）
- 预期行为：尚不能判定（unknown）
- 观测到偏差：未判定

## 如何理解

supported 表示所需证据成立；contradicted 表示证据与条件矛盾；unknown 表示尚不能判定。
该结论仅适用于已固定的合成 RTL、固件和执行证据；不证明真实芯片存在漏洞，
也不证明外部用户能控制固件执行路径。

验证对象：`type2-verification:7dc13746b7067f7ce4adf6cc11ba8eeeb01a3b2582b7a2456b005704772477e7`。详细条件、证据 ID 和缺失项见 `verification.json`。
