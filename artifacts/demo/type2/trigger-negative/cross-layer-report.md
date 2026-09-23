# Cross-Layer Candidate Report

硬件合同 `hwbehavior:d16acb6603bdff18aed64b4a19e549db0fdc5fd3f8359ba571d0e36d651955b7`；静态相容性 **CONTRADICTED**。
这只是候选匹配，不是硬件触发、偏差或漏洞验证。

## Hardware contract summary

架构 `riscv`；触发要求 3 项，前态要求 1 项，偏差要求 1 项，观测要求 1 项。目标平台、RTL 修订和观测来源仍需运行验证器核对。

## Firmware behaviors considered

3 份 FirmwareCapability，3 个待绑定 primitive。

| PC | 行为 | 地址 / CSR | 已知写值 | 资源 | 静态绑定 |
|---|---|---|---|---|---|
| `0x100088` | MMIO_WRITE | 0x40000 | 0x1 | ENABLE | SUPPORTED |
| `0x100090` | MMIO_WRITE | 0x40004 | 0xa4 | COMMAND | SUPPORTED |
| `0x100094` | MMIO_READ | 0x40008 | not established | STATUS | SUPPORTED |

## Hardware resource bindings

| 固件 primitive | 硬件资源 | 绑定方式 | 状态 | 理由 |
|---|---|---|---|---|
| `primitive:mmio-static:54beb478580e5ac5a79b32a0eb28fc1ae0e9f88126ed267ed41467d5bd621be2` | ENABLE (`hwresource:c90486fa66c10e388ac35c3aace5e63171d76e7a60a80f67c0451493cc79c3b5`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:mmio-static:cb96295c0c684bc12ca81416acd63333487bde7ac75c23e34356729742b42d7f` | STATUS (`hwresource:f7313f358ec9e513cf5de1c6bbd08aeec375a40297c427e1be10f4179006b76c`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:mmio-static:d0ea5824f9de9ff8d7e5243e46ef1fa23d165d8f7d4d7e7def74f9f025129796` | COMMAND (`hwresource:cae3b62eba4c7e20e6acff3d38a882c572545ec14aaed5436bed55491f1ec53a`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |

## Requirement-by-requirement matching

| Requirement | Capability IDs | Binding IDs | 静态状态 | 理由 |
|---|---|---|---|---|
| hbc:platform-and-scope (`hbc:platform-and-scope`) | — | — | UNKNOWN | 架构和资源目录一致，但尚未证明平台、固件及 RTL 修订范围 |
| Accepted COMMAND=A5 full-word write (`type2:command-write`) | `fwcap:02371d93bab08f10140ae6b681c87726c0d4e9b9f193144e2946b523227a4e22` | `hwbind:15a8612c79f2beb8b1a6395a60dc9b9ddeab6fee48ca7d48f3246752040f6ab5` | CONTRADICTED | 该地址的已知访问与要求的值、位宽或权限冲突；请对照上表实际值 |
| ENABLE is 1 immediately before accepted COMMAND (`type2:enable-prestate`) | — | — | UNKNOWN | 此条件必须由运行证据验证 |
| Accepted ENABLE=1 full-word write (`type2:enable-write`) | `fwcap:7e756deb16930bc7ace19c8ebaacab4f0ba435ebf9b96c317b3816b351e2684c` | `hwbind:ac1294786f30dcc6a1c05a56d39f9e48694004eaf1542c7029ddbca49a2a834a` | SUPPORTED | 资源、访问方向、位宽和已知值与合同一致 |
| Controlled STATUS wrong value after A5 trigger (`type2:status-deviation`) | — | — | UNKNOWN | 此条件必须由运行证据验证 |
| Post-update internal STATUS sample and bus-visible response must agree (`type2:status-observation`) | — | — | UNKNOWN | 此条件必须由运行证据验证 |
| ENABLE write precedes COMMAND in same reset epoch (`type2:write-order`) | — | — | UNKNOWN | 前态或顺序必须由运行证据确认，静态指令排列不足以证明 |

## Supported static conditions

- `type2:enable-write`: 资源、访问方向、位宽和已知值与合同一致

## Contradicted static conditions

- `type2:command-write`: 该地址的已知访问与要求的值、位宽或权限冲突；请对照上表实际值

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
