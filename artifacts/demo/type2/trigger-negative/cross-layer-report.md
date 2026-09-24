# Cross-Layer Candidate Report

硬件合同 `hwbehavior:d16acb6603bdff18aed64b4a19e549db0fdc5fd3f8359ba571d0e36d651955b7`；静态相容性 **CONTRADICTED**。
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
| `0x100090` | MMIO_WRITE | 0x40004 | 0xa4 | COMMAND | SUPPORTED |
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
| `primitive:fwbehavior:01f7d8e8eba1e241ef2aaddddef546cba5db265349843a57011168015a949327` | not established | unknown | UNKNOWN | No catalog resource contains the exact identity |
| `primitive:fwbehavior:177430176b4fd1a73dab766f06384cd2475a5e8e6f878ada0164b349e5385ed3` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:1cef7c68d25779d31e8423ac561b8f1b7f2aba4c6bc93794fd16c6697f10b5d7` | STATUS (`hwresource:f7313f358ec9e513cf5de1c6bbd08aeec375a40297c427e1be10f4179006b76c`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:fwbehavior:1ded0829d2f5f25a25c603badda23c3121e1d013bf970b3d749ff476f90a73bb` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:282b8b9f8b9467b98dd1fae420d4032777069e63259c7fcc44be5d8d7f3c3745` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:4cb7e2d7128c3079a216a923b891a474a87017564cfe6b9b7eaa1def03f72fab` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:668036448131a59156b4acf9188c884263c8eb2ccc0aff706cf1721d92e6ea1c` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:6fa5cb2715de5d198125ff30de98fecb7439e8986d6884b869d048202c10e0be` | not established | unknown | UNKNOWN | No catalog resource contains the exact identity |
| `primitive:fwbehavior:75b980ab59a1f6354847cc285284e12e8e34f96a8aeeb4016728b073ebbe9cf9` | ENABLE (`hwresource:c90486fa66c10e388ac35c3aace5e63171d76e7a60a80f67c0451493cc79c3b5`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |
| `primitive:fwbehavior:d1973d48ac8ba02cb098e8abfb38f6cc085a532003f226ed518cd1f44d6fef38` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:dfe15666fe775dfaf792f85081c88260ecacff0d759fd851bb04b12d6e89bb15` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:edf93ee1fb5833c6a65e471c3bed4cbcb6373b024c9c228b1626af750081da58` | not established | unknown | NOT_APPLICABLE | No current typed resource requirement for this behavior |
| `primitive:fwbehavior:efcaea7c8bf40d08a633374ce178fe02676bdbece578b272bd63f98f62110a5d` | COMMAND (`hwresource:cae3b62eba4c7e20e6acff3d38a882c572545ec14aaed5436bed55491f1ec53a`) | exact_address | SUPPORTED | 地址或寄存器身份唯一且精确匹配 |

## Requirement-by-requirement matching

| Requirement | Capability IDs | Binding IDs | 静态状态 | 理由 |
|---|---|---|---|---|
| hbc:platform-and-scope (`hbc:platform-and-scope`) | — | — | UNKNOWN | 架构和资源目录一致，但尚未证明平台、固件及 RTL 修订范围 |
| Accepted COMMAND=A5 full-word write (`type2:command-write`) | `fwcap:2d617d770c34817cffb5c70c92193f2c6df08863d845c8b4b9ee6e30b01f33b3` | `hwbind:5ddbd03a65a2d622ead000f8d7a948e020b0796b14281532ac6898e8cebca443` | CONTRADICTED | 该地址的已知访问与要求的值、位宽或权限冲突；请对照上表实际值 |
| ENABLE is 1 immediately before accepted COMMAND (`type2:enable-prestate`) | — | — | UNKNOWN | 此条件必须由运行证据验证 |
| Accepted ENABLE=1 full-word write (`type2:enable-write`) | `fwcap:b883872e3b9be86c62a96d9986d234e9d0309fac113591abf20439ed71775a87` | `hwbind:b2e9adf5adcbe768f4c336a7055cef052e9032e5852e351b7cc80768da431dab` | SUPPORTED | 资源、访问方向、位宽和已知值与合同一致 |
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

Candidate 来自 General Firmware Frontend 的静态能力；capability-continuity.json 逐项核对 frozen runtime capability。冻结 Type-II verifier 仍使用原始 runtime evidence。
