# ChipChain Type-II 验证报告

**结论：受控合成 Type-II 链条已验证。**

触发条件、偏差、客观观测和 Reference/Variant 对照均有证据支持。Reference 触发同一条件后表现为预期值，未观测到偏差。

- 硬件触发：有证据支持（supported）
- 行为偏差：有证据支持（supported）
- 客观观测：有证据支持（supported）
- Reference/Variant 对照：有证据支持（supported）

## 触发条件逐项

| 条件 | 判定 | 依据或阻断原因 |
| --- | --- | --- |
| `type2:target-scope` | 有证据支持（supported） | 目标、RTL 修订和合成来源吻合 |
| `type2:enable-write` | 有证据支持（supported） | 源指令与精确 MMIO 事务已绑定 |
| `type2:command-write` | 有证据支持（supported） | 源指令与精确 MMIO 事务已绑定 |
| `type2:write-order` | 有证据支持（supported） | 同一 reset epoch 中的访问顺序成立 |
| `type2:enable-prestate` | 有证据支持（supported） | COMMAND 前的 ENABLE 状态成立 |

## Reference 对照运行

- 触发：有证据支持（supported）
- 预期行为：有证据支持（supported）
- 观测到偏差：否

## 如何理解

supported 表示所需证据成立；contradicted 表示证据与条件矛盾；unknown 表示尚不能判定。
该结论仅适用于已固定的合成 RTL、固件和执行证据；不证明真实芯片存在漏洞，
也不证明外部用户能控制固件执行路径。

验证对象：`type2-verification:9c7ef89582f89727fcacdb6b8bb7334ba79733c4182a6e7b341ba324e2fa6b82`。详细条件、证据 ID 和缺失项见 `verification.json`。
