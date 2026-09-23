# Cross-Layer Candidate Report

硬件合同 `hwbehavior:d16acb6603bdff18aed64b4a19e549db0fdc5fd3f8359ba571d0e36d651955b7`；静态相容性 **SUPPORTED**。
这只是候选匹配，不是硬件触发、偏差或漏洞验证。

## Hardware contract summary

架构 `riscv`；触发要求 3 项，前态要求 1 项，偏差要求 1 项，观测要求 1 项。目标平台、RTL 修订和观测来源仍需运行验证器核对。

## Firmware behaviors considered

3 份 FirmwareCapability，3 个待绑定 primitive。

| PC | 行为 | 地址 / CSR | 已知写值 | 资源 | 静态绑定 |
|---|---|---|---|---|---|
| `0x100088` | MMIO_WRITE | 0x40000 | 0x1 | ENABLE | SUPPORTED |
| `0x100090` | MMIO_WRITE | 0x40004 | 0xa5 | COMMAND | SUPPORTED |
| `0x100094` | MMIO_READ | 0x40008 | not established | STATUS | SUPPORTED |

## Hardware resource bindings

| 固件 primitive | 硬件资源 | 绑定方式 | 状态 | 理由 |
|---|---|---|---|---|
| `primitive:mmio-static:72d9eee963f5fe246380f959c72e20d16b1a4dbb6090152fca2753632b969a21` | STATUS (`hwresource:f7313f358ec9e513cf5de1c6bbd08aeec375a40297c427e1be10f4179006b76c`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:mmio-static:d02ec676264734ee5cc6980a4f866cda07553756ea063091cfa30dc9a5372713` | COMMAND (`hwresource:cae3b62eba4c7e20e6acff3d38a882c572545ec14aaed5436bed55491f1ec53a`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:mmio-static:eba41bb7fd8b3caa8444557637f50ab73397e6c493772d2aa40b60fc1be5f513` | ENABLE (`hwresource:c90486fa66c10e388ac35c3aace5e63171d76e7a60a80f67c0451493cc79c3b5`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |

## Requirement-by-requirement matching

| Requirement | Capability IDs | Binding IDs | 静态状态 | 理由 |
|---|---|---|---|---|
| hbc:platform-and-scope (`hbc:platform-and-scope`) | — | — | UNKNOWN | 架构和资源目录一致，但尚未证明平台、固件及 RTL 修订范围 |
| Accepted COMMAND=A5 full-word write (`type2:command-write`) | `fwcap:fecf7028d3058179846096d4cb27e35c3c398955119a4e69a6d1b677f962f556` | `hwbind:da06839f88c0171f0e766ee428f5e17589b6019fb8ddc47b24bd25bff1b76036` | SUPPORTED | 资源、访问方向、位宽和已知值与合同一致 |
| ENABLE is 1 immediately before accepted COMMAND (`type2:enable-prestate`) | — | — | UNKNOWN | 此条件必须由运行证据验证 |
| Accepted ENABLE=1 full-word write (`type2:enable-write`) | `fwcap:6283d93781354945c8c638ae133f310aabfac7962bb55c51efe60f5102246e01` | `hwbind:80b79d55574cae7129a567be6d345aeb2807e4f3e07de6c4b41ec25c1ae33b5b` | SUPPORTED | 资源、访问方向、位宽和已知值与合同一致 |
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

General Ghidra static facts and frozen CAP0 MMIO facts are distinct evidence streams. This candidate uses frozen CAP0 constraints; the accompanying static-resource-bindings and static-capabilities show which generic memory facts independently resolved to the catalog. Newly projected static capabilities are not substituted into the frozen runtime verifier.
