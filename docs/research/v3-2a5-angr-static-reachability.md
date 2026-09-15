# V3-2A5 — angr CFGFast Static Reachability Baseline

基线：`v3-2b3-r3-stable` / `4fa5d0f6317c896a4c739ff33de71030cf58fffe`。
B3 冻结为可解释的负实验结果。A5 是独立确定性工具研究，不调整 B3 以获得模型 PASS。

## 科学边界

本阶段只恢复静态 CFG、函数级有界路径和 owner entry→instruction site 的静态见证。
CFGFast 的静态图可能包含启发式恢复、遗漏或错误边，不能证明路径可满足、外部输入可达、
运行时执行、中断发生、硬件触发或漏洞成立。没有 CFGEmulated、SimulationManager、explore、
用户创建的符号输入或路径约束求解，也没有 DeepSeek/Firmware Agent 调用。
依赖中安装 claripy/z3 是 angr 的依赖要求，不代表本阶段进行了符号路径分析。

使用 CFGFast 而非 CFGEmulated，是为了建立独立静态基线；
[angr 官方 CFG 文档](https://docs.angr.io/en/latest/analyses/cfg.html) 区分两者，并说明 FakeRet 的返回假设。
这里的具体选项以已安装 9.3.4 的 CFGFast API signature 为准。

## 依赖与环境

`requires-python = ">=3.11"` 保持；新增 optional extra `angr = ["angr==9.3.4"]`，
该 extra 在 Python 3.12+ 使用，不在基础依赖中。
[angr 9.3.4 发布元数据](https://pypi.org/pypi/angr/9.3.4/json) 要求 Python >=3.12、Capstone==5.0.9。
安装前将全部既有包版本作为临时 constraints 做 resolver dry-run，然后在同一约束下安装 `-e '.[angr]'`。
已有包版本变化数量为 **0**，没有降级 Capstone、调整 pyelftools 或升级 LangChain stack。

| 组件 | 运行版本 |
|---|---|
| Python | 3.12.13 |
| angr | 9.3.4 |
| cle | 9.3.4 |
| pyvex | 9.3.4 |
| archinfo | 9.3.4 |
| capstone | 5.0.9 |
| pyelftools | 0.33 |
| pydantic | 2.13.4 |

`requirements/angr-9.3.4-py312.txt` 记录本环境 optional stack 的精确版本约束。
复现安装：`.venv/bin/python -m pip install -c requirements/angr-9.3.4-py312.txt -e '.[angr]'`。
此文件针对 CPython 3.12/Linux，不作为所有未来平台的无条件锁文件。
网络仅用于本轮明确授权的依赖安装与官方文档核实；测试/实际分析的网络调用为 0，DeepSeek 为 0。

## 工具与输入边界

新工具模块 `tools/firmware/angr_cfg.py` / `static_reachability.py` 不导入 DeepSeek、Agent、prompt
或 model output schema；仅使用输入合同和冻结工具合同。
显式传入 FirmwareAgentInput、A2、A3、A4 和 ELF path，重验 case IDs、同一 ELF artifact/path、
size/SHA256、A2 的原有递归排序 semantic hash、A3→A4 identity，真实 Heat_Press 额外固定 A3/A4 hashes。
ELF 未修改，A4 永不由 angr 覆盖。

integration helper 复用现有 frozen deterministic preparation 函数；虽位于历史 integration 模块，
调用的只是四 artifacts→A1、fresh Ghidra→A2/A3/A4 及输入 hash 校验，不实例化 Agent 或 provider。
每次测试从真实原始文件开始，不把历史 output、saved A4 或 saved CFG 当作事实。

## CFGFast 配置与资源界限

```python
angr.Project(explicit_elf_path, auto_load_libs=False)
CFGFast(
    normalize=True,
    resolve_indirect_jumps=True,
    force_complete_scan=False,
    force_smart_scan=False,
    function_prologues=False,
    symbols=False,
    start_at_entry=False,
    eh_frame=False,
    exceptions=False,
    function_starts=[canonical_a3_entry + 1 for each selected function],
)
```

先验证 Thumb policy，才转换 function_starts。禁用额外 symbol/prologue/entry/扫描 seeds，
严格以 A3 34 functions 为 starting set，允许 CFGFast 沿静态控制转移发现其他函数。
保留 angr recovered callgraph 作为函数路径依据，不以符号名决定 identity 或调用关系。

公开 API 在独立 subprocess 执行 CFGFast，默认 timeout=60 秒，拒绝 >120 秒；超时会终止 worker。
worker 禁用网络并移除继承的 credential 环境变量，不保存 angr/NetworkX 对象 repr。
恢复结果限 20000 nodes、4096 functions，超限报错；仅序列化 selected owners 的节点、相关 site
节点及 transfer comparison 必需的 successor endpoints。callgraph 允许保留非 selected 中间函数。

函数 BFS 最多 16 edges；site BFS 最多 256 edges。邻居按 canonical address/稳定 node identity 排序，
不依赖 NetworkX insertion order。not_found 仅表示当前图与 bound 内未发现，不是 unreachable。

## Thumb 与 loader 实测

loader 实测：architecture=ARMCortexM，32-bit little endian（Iend_LE），entry=0x80f35，
mapped range=0x80000–0x200711c3。
三个按数值地址匹配的 ELF function symbols 与 lifted block 的 Thumb 标志：

| Canonical entry | Loader raw entry | Block thumb |
|---|---|---|
| f80f34 / 0x80f34 | 0x80f35 | true |
| f80eac / 0x80eac | 0x80ead | true |
| f80af4 / 0x80af4 | 0x80af5 | true |

因此当前 adapter 仅在已验证 Cortex-M executable ranges 内清除 code address 的 LSB。
数据/外部地址不盲目掩码。保留 node raw/canonical address，稳定 ID 基于 canonical code identity；
通用结果合同不命名为 ThumbReachability，未来其他 architecture adapter 可提供同一合同。

### 样本 loader diagnostics

`.relocate` section 被 ELF 标为 SHT_REL（sh_link=0、sh_info=0、size=2204），
使用 .symtab 的 881 symbols 检查时，其中 **139** 个 relocation symbol indices 越界。
pyelftools 0.33 单独解析也复现，证据指向样本 section metadata，不是已确认的 dependency conflict。
不重写该节、不修改 loader、不忽略 A4 identity 来绕过。

CLE 输出 140 次 ELF ERROR 和一次 relocation WARNING；import angr 另报告可选 Unicorn 不可用。
这些计数明确保存在 CFG artifact。Unicorn 不用于 CFGFast，本阶段没有安装或运行 Unicorn emulation。
每次 worker 强制比较原 ELF executable sections 与 loader memory：`.text` 22684 bytes 和
`.relocate` 2204 bytes 均逐字节一致，否则拒绝分析。
因此继续开展受此 loader limitation 限制的静态基线，不能把“生成图”写成 loader 无警告。

## 合同、见证与分歧政策

- `firmware-angr-cfg/v1`：source identity、实际版本/config、loader 信息/日志计数、34 bindings、
  bounded CFG nodes/edges、recovered function edges、34 transfer comparisons。
- `firmware-static-reachability/v1`：相同 provenance 与 CFG SHA、路径界限、1122 ordered selected
  function pairs、57 relevant sites。

每个函数 binding 是 exact/missing/conflict；不从候选中任意挑选冲突地址。
每个 CFG edge 保留 jumpkind 并规范为 call/branch/return/fakeret/syscall/unknown。
Ijk_Boring 仅表示 branch-like static edge，不把它当 call 或可执行证明。

Transfer comparison 用 edge 的 instruction address 对齐 A4 site，排除 FakeRet/return 作为调用目标证据。
未映射 site 为 site_not_mapped；无恢复代码目标为 angr_unresolved；已确认 A4 的 target/kind 完全一致
才 agree。A4 unresolved 若被 angr 恢复 target，记录 disagree（两工具恢复精度/结论不同），
不宣布 A4 resolved 或 angr 更权威；无 majority vote。

函数 witness 可经过 non-selected 函数；仅 selected endpoints 参与查询。
site owner 仅来自 A4 containment/caller。缺失 owner 保持 owner_mapping_missing，angr 推测 owner
只另存 angr_owner_addresses。必须存在确切 instruction boundary 才把节点视为包含 site。

Site 查询先找不含 FakeRet 的 owner 内 branch path，再允许 FakeRet，得到不同 status。
含 FakeRet 必须 uses_fakeret=true 和 assumes_callee_returns limitation；不能等价于无 FakeRet 证据。
函数路径只声称 recovered callgraph 连通，并不承诺某个调用 site 在函数内可达；两级证据分开。

所有 positives 仅 supports_static_reachability=true；runtime/path-feasibility/input/interrupt/hardware-trigger
capabilities 永远 false。没有任何 A5 fact 修改 FirmwareAnalysisReport 或 ProcessorBehaviorIR。

## Codec / evidence

两个合同均提供 serialize、parse 和 SHA256。排序覆盖 functions、nodes、edges、comparisons、queries/sites。
paths 保留顺序，parse 验证 CFG hash、完整 ordered-pair coverage、见证首尾、逐边连接、owner 和 FakeRet。
构造结果本身也采用 codec canonical order，修正了开发中首次真实 roundtrip 的对象列表顺序差异。

本阶段 A5 catalog 自身是独立、可验证 deterministic artifact，不新建 EvidenceRef，
不复用 A4 evidence IDs 证明 angr path，不修改 A1/A3 的 174-entry registry。
未来 reasoning 接入时可按 CFG/A5 artifact hash + fact identity 派生额外 evidence IDs，必须显式 union，
并继续保留 analyzer/config/ELF provenance。

## 真实 Heat_Press 结果

真实集成：**1 passed in 16.64s**，不是 skip。
测试中的两个独立 worker 均 fresh CFGFast，CFG/A5 两份文件逐字节相同。
随后通过显式 CLI 的 `--output-root output` 执行一次新的 fresh preparation/CFGFast 并保存，
结果与集成测试的两次构建逐字节一致；没有把测试输出当作下一次分析的输入。

本轮开发另执行过三 seed 的 loader/CFG API 探测，以及第一次对象顺序断言失败的集成；
这些不是 LLM retry。第一次集成的两个 CFG/A5 字节比较已通过，失败仅在返回对象的 list order；
修正与测试已记录，不隐瞒该开发结果。

| 指标 | 值 |
|---|---:|
| A3 selected functions | 34 |
| exact / missing / conflict | 34 / 0 / 0 |
| CFG total functions | 82 |
| CFG total nodes / edges | 544 / 778 |
| serialized relevant nodes / edges | 216 / 284 |
| serialized recovered function edges | 87 |
| function pair queries | 1122 |
| reachable_static | 62 |
| not_found_within_bound | 1060 |
| source/target mapping missing | 0 / 0 |
| site queries | 57 |
| reachable_static_no_fakeret | 40 |
| reachable_static_with_fakeret | 14 |
| owner_mapping_missing | 3 |
| other site statuses | 0 |

A4 preflight 保持 A1/A3/A4 SHA pins 及 131 relations 的 22/6/6/23/23/51 分类。

### 全部 34 个函数 binding

Raw 为 canonical+1，所有 status exact。

| Function ID | Expected entry | angr raw entry | angr canonical entry | Status |
|---|---|---|---|---|
| f80148 | 0x80148 | 0x80149 | 0x80148 | exact |
| f804a4 | 0x804a4 | 0x804a5 | 0x804a4 | exact |
| f80abc | 0x80abc | 0x80abd | 0x80abc | exact |
| f80ad0 | 0x80ad0 | 0x80ad1 | 0x80ad0 | exact |
| f80adc | 0x80adc | 0x80add | 0x80adc | exact |
| f80ae8 | 0x80ae8 | 0x80ae9 | 0x80ae8 | exact |
| f80af4 | 0x80af4 | 0x80af5 | 0x80af4 | exact |
| f80db0 | 0x80db0 | 0x80db1 | 0x80db0 | exact |
| f80e14 | 0x80e14 | 0x80e15 | 0x80e14 | exact |
| f80e28 | 0x80e28 | 0x80e29 | 0x80e28 | exact |
| f80e6c | 0x80e6c | 0x80e6d | 0x80e6c | exact |
| f80eac | 0x80eac | 0x80ead | 0x80eac | exact |
| f80f34 | 0x80f34 | 0x80f35 | 0x80f34 | exact |
| f80fac | 0x80fac | 0x80fad | 0x80fac | exact |
| f81044 | 0x81044 | 0x81045 | 0x81044 | exact |
| f81052 | 0x81052 | 0x81053 | 0x81052 | exact |
| f8106c | 0x8106c | 0x8106d | 0x8106c | exact |
| f81084 | 0x81084 | 0x81085 | 0x81084 | exact |
| f81094 | 0x81094 | 0x81095 | 0x81094 | exact |
| f810cc | 0x810cc | 0x810cd | 0x810cc | exact |
| f81104 | 0x81104 | 0x81105 | 0x81104 | exact |
| f8113c | 0x8113c | 0x8113d | 0x8113c | exact |
| f81174 | 0x81174 | 0x81175 | 0x81174 | exact |
| f81176 | 0x81176 | 0x81177 | 0x81176 | exact |
| f8117a | 0x8117a | 0x8117b | 0x8117a | exact |
| f8117e | 0x8117e | 0x8117f | 0x8117e | exact |
| f81194 | 0x81194 | 0x81195 | 0x81194 | exact |
| f81234 | 0x81234 | 0x81235 | 0x81234 | exact |
| f8133c | 0x8133c | 0x8133d | 0x8133c | exact |
| f813ac | 0x813ac | 0x813ad | 0x813ac | exact |
| f813e6 | 0x813e6 | 0x813e7 | 0x813e6 | exact |
| f81478 | 0x81478 | 0x81479 | 0x81478 | exact |
| f8152c | 0x8152c | 0x8152d | 0x8152c | exact |
| f815a4 | 0x815a4 | 0x815a5 | 0x815a4 | exact |

### 全部 34 个 A4 transfer comparisons

22 direct calls 全部 agree；6 direct branches 全部 agree。
6 个 A4 unresolved sites 中，1 个恢复代码目标而记录 disagree，5 个仍 angr_unresolved。
`0x20100050` 在 ELF code ranges 外，是 unresolved 外部 successor，不是恢复的固件函数目标。
所有 addresses 为 canonical；raw 在 node artifact 中保留。

| Relation ID | Site | A4 kind/status | angr successors | Jumpkinds | Comparison |
|---|---|---|---|---|---|
| call-80172 | 0x80172 | direct_call/confirmed_static | 0x81234 | Ijk_Call | agree |
| call-804aa | 0x804aa | direct_call/confirmed_static | 0x81234 | Ijk_Call | agree |
| call-804b2 | 0x804b2 | direct_call/confirmed_static | 0x81234 | Ijk_Call | agree |
| call-804ba | 0x804ba | direct_call/confirmed_static | 0x81234 | Ijk_Call | agree |
| call-804c2 | 0x804c2 | direct_call/confirmed_static | 0x81234 | Ijk_Call | agree |
| call-80abe | 0x80abe | direct_branch/confirmed_static | 0x815a4 | Ijk_Boring | agree |
| call-80ad2 | 0x80ad2 | direct_branch/confirmed_static | 0x815a4 | Ijk_Boring | agree |
| call-80ade | 0x80ade | direct_branch/confirmed_static | 0x815a4 | Ijk_Boring | agree |
| call-80aea | 0x80aea | direct_branch/confirmed_static | 0x815a4 | Ijk_Boring | agree |
| call-80afa | 0x80afa | direct_call/confirmed_static | 0x80eac | Ijk_Call | agree |
| call-80bb6 | 0x80bb6 | direct_call/confirmed_static | 0x80e28 | Ijk_Call | agree |
| call-80bc4 | 0x80bc4 | direct_call/confirmed_static | 0x80fac | Ijk_Call | agree |
| call-80bd2 | 0x80bd2 | direct_call/confirmed_static | 0x81052 | Ijk_Call | agree |
| call-80bdc | 0x80bdc | direct_call/confirmed_static | 0x81044 | Ijk_Call | agree |
| call-80f88 | 0x80f88 | control_transfer_unresolved/unresolved | 0x816cc | Ijk_Call | disagree |
| call-8108c | 0x8108c | control_transfer_unresolved/unresolved | 0x20100050 | Ijk_Call | angr_unresolved |
| call-810b2 | 0x810b2 | control_transfer_unresolved/unresolved | 0x20100050 | Ijk_Call | angr_unresolved |
| call-810ea | 0x810ea | control_transfer_unresolved/unresolved | 0x20100050 | Ijk_Call | angr_unresolved |
| call-81122 | 0x81122 | control_transfer_unresolved/unresolved | 0x20100050 | Ijk_Call | angr_unresolved |
| call-8115a | 0x8115a | control_transfer_unresolved/unresolved | 0x20100050 | Ijk_Call | angr_unresolved |
| call-81180 | 0x81180 | direct_call/confirmed_static | 0x81194 | Ijk_Call | agree |
| call-81186 | 0x81186 | direct_call/confirmed_static | 0x813ac | Ijk_Call | agree |
| call-8118e | 0x8118e | direct_branch/confirmed_static | 0x81728 | Ijk_Boring | agree |
| call-8125a | 0x8125a | direct_call/confirmed_static | 0x8106c | Ijk_Call | agree |
| call-812a8 | 0x812a8 | direct_call/confirmed_static | 0x80e28 | Ijk_Call | agree |
| call-812b6 | 0x812b6 | direct_call/confirmed_static | 0x80db0 | Ijk_Call | agree |
| call-812d4 | 0x812d4 | direct_call/confirmed_static | 0x80e28 | Ijk_Call | agree |
| call-812e2 | 0x812e2 | direct_call/confirmed_static | 0x80db0 | Ijk_Call | agree |
| call-8130c | 0x8130c | direct_call/confirmed_static | 0x80db0 | Ijk_Call | agree |
| call-81328 | 0x81328 | direct_branch/confirmed_static | 0x80e6c | Ijk_Boring | agree |
| call-8135c | 0x8135c | direct_call/confirmed_static | 0x81234 | Ijk_Call | agree |
| call-8137a | 0x8137a | direct_call/confirmed_static | 0x80e14 | Ijk_Call | agree |
| call-81536 | 0x81536 | direct_call/confirmed_static | 0x80e28 | Ijk_Call | agree |
| call-815b6 | 0x815b6 | direct_call/confirmed_static | 0x813e6 | Ijk_Call | agree |

### 高价值函数路径

- **Reset f80f34 → SystemInit f80eac：reachable_static**，3 edges。
  Witness：`0x80f34 → 0x816cc → 0x80af4 → 0x80eac`。
  Edge IDs：`fc-80f34-816cc`、`fc-816cc-80af4`、`fc-80af4-80eac`。
  中间 `0x816cc` 不必属于 A3 selected endpoint set。
- **init f80af4 → SystemInit f80eac：reachable_static**，1 edge。
  Witness：`0x80af4 → 0x80eac`；edge `fc-80af4-80eac`。

`call-80f88` 的 angr successor 为 raw 0x816cd / canonical 0x816cc，jumpkind=Ijk_Call，
是 CFGFast heuristic/static recovery。A4 仍为 control_transfer_unresolved/unresolved/indirect_call/blx，
没有被提升为 confirmed direct_call，更没有出现 Reset→SystemInit 的单条直接边。

`call-80afa`：canonical successor=0x80eac、Ijk_Call，与 A4 agree。
四个 UART b.w site 0x80abe/0x80ad2/0x80ade/0x80aea 都得到 0x815a4、Ijk_Boring，
保持 branch-like；没有将它们归类为 call。

### 全部 23 MMIO entry→site 查询

路径长度表示 block edges；0 表示 site 就在 entry block，不表示没有指令。
A4 containment 不随 angr 的独立 owner 恢复变化。

| PC | A4 containment | Deterministic owner | A5 status | FakeRet | Path edges |
|---|---|---|---|---|---:|
| 0x80d4e | missing | None | owner_mapping_missing | false | 0 |
| 0x80d50 | missing | None | owner_mapping_missing | false | 0 |
| 0x80d5a | missing | None | owner_mapping_missing | false | 0 |
| 0x80e16 | confirmed_static | f80e14 | reachable_static_no_fakeret | false | 0 |
| 0x80e1c | confirmed_static | f80e14 | reachable_static_no_fakeret | false | 1 |
| 0x80e3a | confirmed_static | f80e28 | reachable_static_no_fakeret | false | 2 |
| 0x80e4e | confirmed_static | f80e28 | reachable_static_no_fakeret | false | 2 |
| 0x80e7e | confirmed_static | f80e6c | reachable_static_no_fakeret | false | 2 |
| 0x80eba | confirmed_static | f80eac | reachable_static_no_fakeret | false | 0 |
| 0x80eca | confirmed_static | f80eac | reachable_static_no_fakeret | false | 2 |
| 0x80ed2 | confirmed_static | f80eac | reachable_static_no_fakeret | false | 2 |
| 0x80eda | confirmed_static | f80eac | reachable_static_no_fakeret | false | 3 |
| 0x80ee6 | confirmed_static | f80eac | reachable_static_no_fakeret | false | 4 |
| 0x80ef2 | confirmed_static | f80eac | reachable_static_no_fakeret | false | 6 |
| 0x80efe | confirmed_static | f80eac | reachable_static_no_fakeret | false | 8 |
| 0x80f0a | confirmed_static | f80eac | reachable_static_no_fakeret | false | 10 |
| 0x81022 | confirmed_static | f80fac | reachable_static_no_fakeret | false | 3 |
| 0x81044 | confirmed_static | f81044 | reachable_static_no_fakeret | false | 0 |
| 0x81054 | confirmed_static | f81052 | reachable_static_no_fakeret | false | 0 |
| 0x8131c | confirmed_static | f81234 | reachable_static_with_fakeret | true | 5 |
| 0x8147c | confirmed_static | f81478 | reachable_static_no_fakeret | false | 0 |
| 0x815aa | confirmed_static | f815a4 | reachable_static_no_fakeret | false | 0 |
| 0x815b0 | confirmed_static | f815a4 | reachable_static_no_fakeret | false | 1 |

三个 missing owner sites 0x80d4e/0x80d50/0x80d5a 的 angr_owner_addresses 都为 [0x80d3e]；
这作为独立 disagreement diagnostic 保留，未填入 A4 owner，查询保持 owner_mapping_missing。

SystemInit 八 sites 0x80eba/80eca/80ed2/80eda/80ee6/80ef2/80efe/80f0a 全部
reachable_static_no_fakeret；路径长度分别 0、2、2、3、4、6、8、10。
A4 ldr/read 未重判。MMIO 中仅 0x8131c 的见证需要 FakeRet。

### 全部 34 transfer entry→site 查询

| Site | Caller | A4 kind/status | Entry→site status | FakeRet | Path edges |
|---|---|---|---|---|---:|
| 0x80172 | f80148 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 4 |
| 0x804aa | f804a4 | direct_call/confirmed_static | reachable_static_no_fakeret | false | 0 |
| 0x804b2 | f804a4 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 1 |
| 0x804ba | f804a4 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 2 |
| 0x804c2 | f804a4 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 3 |
| 0x80abe | f80abc | direct_branch/confirmed_static | reachable_static_no_fakeret | false | 0 |
| 0x80ad2 | f80ad0 | direct_branch/confirmed_static | reachable_static_no_fakeret | false | 0 |
| 0x80ade | f80adc | direct_branch/confirmed_static | reachable_static_no_fakeret | false | 0 |
| 0x80aea | f80ae8 | direct_branch/confirmed_static | reachable_static_no_fakeret | false | 0 |
| 0x80afa | f80af4 | direct_call/confirmed_static | reachable_static_no_fakeret | false | 0 |
| 0x80bb6 | f80af4 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 13 |
| 0x80bc4 | f80af4 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 14 |
| 0x80bd2 | f80af4 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 15 |
| 0x80bdc | f80af4 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 16 |
| 0x80f88 | f80f34 | control_transfer_unresolved/unresolved | reachable_static_no_fakeret | false | 4 |
| 0x8108c | f81084 | control_transfer_unresolved/unresolved | reachable_static_no_fakeret | false | 1 |
| 0x810b2 | f81094 | control_transfer_unresolved/unresolved | reachable_static_no_fakeret | false | 3 |
| 0x810ea | f810cc | control_transfer_unresolved/unresolved | reachable_static_no_fakeret | false | 3 |
| 0x81122 | f81104 | control_transfer_unresolved/unresolved | reachable_static_no_fakeret | false | 3 |
| 0x8115a | f8113c | control_transfer_unresolved/unresolved | reachable_static_no_fakeret | false | 3 |
| 0x81180 | f8117e | direct_call/confirmed_static | reachable_static_no_fakeret | false | 0 |
| 0x81186 | f8117e | direct_call/confirmed_static | reachable_static_with_fakeret | true | 2 |
| 0x8118e | f8117e | direct_branch/confirmed_static | reachable_static_with_fakeret | true | 3 |
| 0x8125a | f81234 | direct_call/confirmed_static | reachable_static_no_fakeret | false | 2 |
| 0x812a8 | f81234 | direct_call/confirmed_static | reachable_static_no_fakeret | false | 5 |
| 0x812b6 | f81234 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 6 |
| 0x812d4 | f81234 | direct_call/confirmed_static | reachable_static_no_fakeret | false | 6 |
| 0x812e2 | f81234 | direct_call/confirmed_static | reachable_static_with_fakeret | true | 7 |
| 0x8130c | f81234 | direct_call/confirmed_static | reachable_static_no_fakeret | false | 4 |
| 0x81328 | f81234 | direct_branch/confirmed_static | reachable_static_with_fakeret | true | 6 |
| 0x8135c | f8133c | direct_call/confirmed_static | reachable_static_no_fakeret | false | 2 |
| 0x8137a | f8133c | direct_call/confirmed_static | reachable_static_no_fakeret | false | 2 |
| 0x81536 | f8152c | direct_call/confirmed_static | reachable_static_no_fakeret | false | 0 |
| 0x815b6 | f815a4 | direct_call/confirmed_static | reachable_static_no_fakeret | false | 1 |

34 transfers 中 13 个 entry→site 见证使用 FakeRet；加上 1 个 MMIO，总计 14。
使用 FakeRet 的事实均带 assumes_callee_returns，不等价于 no-fakeret；即使 no-fakeret 也不证明路径可满足。

### 输出身份与显式持久化

Run ID：`47bbd6a0-4b54-4e80-9340-90e575377f03`。

| Artifact | 字符数/字节数（UTF-8 ASCII） | SHA256 |
|---|---:|---|
| [firmware_angr_cfg.json](../../output/fuzzware:heat-press:scenario-13/47bbd6a0-4b54-4e80-9340-90e575377f03/firmware_angr_cfg.json) | 145875 | `23a3d370534e25d1b04e5ddc9c47a1c8efb31f978d8a7fb3d015c8443a2f4f03` |
| [firmware_static_reachability.json](../../output/fuzzware:heat-press:scenario-13/47bbd6a0-4b54-4e80-9340-90e575377f03/firmware_static_reachability.json) | 556588 | `4f170725b43ad2419f8464343812ff3b8d35a9b05b1b539e8a8fd2afb502f5f6` |

另外保存 a5_summary.json 便于审阅。两次集成 fresh builds 与一次显式持久化 fresh build 的上述 artifacts
全部 byte-identical、SHA-identical；没有 timestamps/run IDs/临时路径混入语义序列化。
这些文件位于默认 Git 忽略的 output 下，未加入 reviewed。

## 研究解释与下一步

A5 提供此前 A4 局部事实之外的独立证据：recovered function graph 中的多跳静态见证、
entry→site 的 block 见证，以及工具分歧和 FakeRet 假设。它支持未来把函数路径、具体 MMIO site
和硬件 typed trigger 条件显式对齐，但当前未实施 Cross-Layer。

62 positives 不是 62 条可执行路径，1060 not_found 不是 1060 个不可达证明。
A5 不能说明外部输入如何影响分支、MMIO 值约束是否可满足、中断是否发生或某条路径是否运行。
A6 的 constrained/symbolic analysis 可以在明确环境模型与约束下研究 feasibility；即使 A6 SAT，
也仍不能自动声称真实设备执行、中断发生或硬件漏洞已验证。

当前结果没有暴露需要立即修正 A4/B3 的事实。建议人工审核 A5 loader limitation 与路径见证后，
若研究目标是约束可达性，则下一阶段规划 **A6 bounded constrained reachability**，优先明确
MMIO/初始化/返回假设。若目标是跨层条件匹配，还需要硬件侧 typed trigger semantics；
本轮不自动进入两者，也不把 A5 当成修复 B3 模型重述错误的手段。

## 最终验证与历史保全

```text
新增纯离线 A5 单元测试：27 passed in 0.63s
最终全量 pytest -q：828 passed, 13 skipped in 24.88s
pip check：No broken requirements found.
compileall -q src tests：exit 0
git diff --check：exit 0
显式真实 A5 集成：1 passed in 16.64s
```

默认全量 suite 的 13 skips 是 opt-in 本地/真实集成边界；A5 已另行显式执行并 PASS。
运行命令：

```bash
.venv/bin/python -m pip check
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q src tests
git diff --check
CHIPCHAIN_GHIDRA_HOME=/home/qcx/fuzz/gdbfuzz/dependencies/ghidra \
CHIPCHAIN_FUZZWARE_ROOT=/home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
.venv/bin/python -m pytest -q -s tests/integration/test_angr_static_reachability_local.py
```

显式持久化命令：

```bash
.venv/bin/python -m chipchain.integrations.angr_static_reachability \
  --corpus-root /home/qcx/ChipChainV3_res/firmware/fuzzware-experiments \
  --ghidra-home /home/qcx/fuzz/gdbfuzz/dependencies/ghidra \
  --output-root output
```

64 个既有 output 文件逐字节不变，reviewed 仍只有 v3-1b1。
所有既有 Python 源码、测试及研究文档均未修改；受 Git 跟踪的既有文件只改 README.md 与 pyproject.toml。
安装 optional extra 后被 Git 忽略的 egg-info 元数据随之更新，非源码变更。
新增 output 仅本轮显式保存的三文件。没有改 B3、没有 DeepSeek/Agent 调用、没有 symbolic exploration、
没有 reviewed export，没有 git add/commit/push/tag。所有更改等待人工审核。
