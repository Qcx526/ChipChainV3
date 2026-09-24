# Cross-Layer Candidate Report

硬件合同 `hwbehavior:d16acb6603bdff18aed64b4a19e549db0fdc5fd3f8359ba571d0e36d651955b7`；静态相容性 **SUPPORTED**。
这只是候选匹配，不是硬件触发、偏差或漏洞验证。

## Hardware contract summary

架构 `riscv`；触发要求 3 项，前态要求 1 项，偏差要求 1 项，观测要求 1 项。目标平台、RTL 修订和观测来源仍需运行验证器核对。

## Firmware behaviors considered

13 份 FirmwareCapability，13 个待绑定 primitive。

| PC | 行为 | 地址 / CSR | 已知写值 | 资源 | 静态绑定 |
|---|---|---|---|---|---|
| `0x100080` | INSTRUCTION_EXECUTION | not established | not established | unbound | NOT_APPLICABLE |
| `0x100084` | INSTRUCTION_EXECUTION | not established | not established | unbound | NOT_APPLICABLE |
| `0x100088` | MMIO_WRITE | 0x40000 | 0x1 | ENABLE | SUPPORTED |
| `0x10008c` | INSTRUCTION_EXECUTION | not established | not established | unbound | NOT_APPLICABLE |
| `0x100090` | MMIO_WRITE | 0x40004 | 0xa5 | COMMAND | SUPPORTED |
| `0x100094` | MMIO_READ | 0x40008 | not established | STATUS | SUPPORTED |
| `0x100098` | INSTRUCTION_EXECUTION | not established | not established | unbound | NOT_APPLICABLE |
| `0x10009c` | INSTRUCTION_EXECUTION | not established | not established | unbound | NOT_APPLICABLE |
| `0x1000a0` | MEMORY_WRITE | 0x101000 | not established | unbound | UNKNOWN |
| `0x1000a4` | INSTRUCTION_EXECUTION | not established | not established | unbound | NOT_APPLICABLE |
| `0x1000a8` | INSTRUCTION_EXECUTION | not established | not established | unbound | NOT_APPLICABLE |
| `0x1000ac` | MEMORY_WRITE | 0x20008 | 0x1 | unbound | UNKNOWN |
| `0x1000b4` | DIRECT_CONTROL_TRANSFER | not established | not established | unbound | NOT_APPLICABLE |

## Hardware resource bindings

| 固件 primitive | 硬件资源 | 绑定方式 | 状态 | 理由 |
|---|---|---|---|---|
| `primitive:fwbehavior:02577f31ce747a08003b6397802e8ce636dc632c1cdf1dabcf6464176ccacbb7` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:07720fcbcff184dc30e9600d9599680f718b02049aa55cf61c5878c788fa0452` | not established | unknown | UNKNOWN | No catalog resource contains the exact identity |
| `primitive:fwbehavior:16634b2a320fd5c18086710675cdea5faeb2856bfaca713f85c1b2a4a4d29968` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:1c0127d778646c63b5102d2ce3ebbce75d0d281ad2938ab6b860756ae4028678` | ENABLE (`hwresource:c90486fa66c10e388ac35c3aace5e63171d76e7a60a80f67c0451493cc79c3b5`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:fwbehavior:2981b04bb57455a676a138e5c48ed7543a6d76899a26b82cf5094f5d76dd10b4` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:29d5657174b47ee982c819417e8841d98d8eb921baa80df30fb3e5357fdb5e12` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:303441afc6b8944808d84a814105ad01954b696d1803a83d1f8f0bec8950d0ee` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:54abb5eb0f2ffed568ba4cacc8d2a1ba16d95b27212b3d5906bb7fe9ffc44bed` | COMMAND (`hwresource:cae3b62eba4c7e20e6acff3d38a882c572545ec14aaed5436bed55491f1ec53a`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:fwbehavior:891c60fc546ecdabc669cb2c92f6a1b910ae49380fd295626ef5063cd873fba1` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:b885eb4a5e2b6f20f54a3b6262c580e37e040a71f3df2d7eacbb58305bebaeff` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:d29d69d4de440df92a87251b2747399123c33d82fe49ad5c57156830d3b2c26a` | STATUS (`hwresource:f7313f358ec9e513cf5de1c6bbd08aeec375a40297c427e1be10f4179006b76c`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:fwbehavior:f12bd5d4ec8dc60725feb982e579b5141295be4c517d638e9ef08be9d3812b7b` | not established | unknown | UNKNOWN | No catalog resource contains the exact identity |
| `primitive:fwbehavior:fbce972cb029c3b1d8f1eaa60e510e9427fe7203e72b0497a85d8f3e64cff611` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |

## Requirement-by-requirement matching

| Requirement | Capability IDs | Binding IDs | 静态状态 | 理由 |
|---|---|---|---|---|
| hbc:platform-and-scope (`hbc:platform-and-scope`) | — | — | UNKNOWN | 架构和资源目录一致，但尚未证明平台、固件及 RTL 修订范围 |
| Accepted COMMAND=A5 full-word write (`type2:command-write`) | `fwcap:b1f01cce077a877673f01963e31b42e1ef84bb71ec213456453f7e87ce599f5c` | `hwbind:6842cafb5e9b9da547d8ff96782c348ee02586e3e4f202116aad2d38d3407901` | SUPPORTED | 资源、访问方向、位宽和已知值与合同一致 |
| ENABLE is 1 immediately before accepted COMMAND (`type2:enable-prestate`) | — | — | UNKNOWN | 此条件必须由运行证据验证 |
| Accepted ENABLE=1 full-word write (`type2:enable-write`) | `fwcap:677cb4cd658605f74895d9b4ee1bfbbf649cc37becc3dc060915b53c49a9bb98` | `hwbind:1817ed8188b3e7560524bb1a0e7d6f22c420860282e6d2040179fe34c61e123d` | SUPPORTED | 资源、访问方向、位宽和已知值与合同一致 |
| Controlled STATUS wrong value after A5 trigger (`type2:status-deviation`) | — | — | UNKNOWN | 此条件必须由运行证据验证 |
| Post-update internal STATUS sample and bus-visible response must agree (`type2:status-observation`) | — | — | UNKNOWN | 此条件必须由运行证据验证 |
| ENABLE write precedes COMMAND in same reset epoch (`type2:write-order`) | — | — | UNKNOWN | 前态或顺序必须由运行证据确认，静态指令排列不足以证明 |

## Supported static conditions

- `type2:command-write`: 资源、访问方向、位宽和已知值与合同一致
- `type2:enable-write`: 资源、访问方向、位宽和已知值与合同一致

## Contradicted static conditions

- 无。

## Unknown / ambiguous conditions

- `hbc:platform-and-scope`: 架构和资源目录一致，但尚未证明平台、固件及 RTL 修订范围
- `type2:enable-prestate`: 此条件必须由运行证据验证
- `type2:status-deviation`: 此条件必须由运行证据验证
- `type2:status-observation`: 此条件必须由运行证据验证
- `type2:write-order`: 前态或顺序必须由运行证据确认，静态指令排列不足以证明

## Verification requirements

- deviation_requires_runtime_evidence
- observation_requires_runtime_evidence
- prestate_requires_runtime_evidence
- runtime_order_or_state_evidence
- runtime_platform_and_source_binding

Candidate != verified chain. 静态次序不等于运行次序；资源绑定不等于触发，正常固件行为不等于攻击者控制。

Candidate 来自 General Firmware Frontend 的静态能力；capability-continuity.json 逐项核对 frozen runtime capability。冻结 Type-II verifier 仍使用原始 runtime evidence。
