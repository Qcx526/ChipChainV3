"""Concise customer presentation of an existing Type-II case assembly.

Only validated static facts and already-computed assembly statuses are used.
The chosen display operation is a presentation focus, not a scientific rank.
"""
from __future__ import annotations

from collections import deque

from chipchain.firmware.static_ir import FirmwareStaticAnalysis


KIND_LABELS = {
    "TLB_INVALIDATE": "地址转换/TLB 相关缓存失效请求",
    "MEMORY_BARRIER": "内存访问顺序屏障",
    "INSTRUCTION_BARRIER": "指令获取/同步屏障",
    "ATOMIC_LOAD": "原子读取操作",
    "ATOMIC_STORE": "原子写入操作",
    "EXCEPTION_RETURN": "异常返回操作",
    "MMIO_WRITE": "内存映射寄存器写入",
    "MMIO_READ": "内存映射寄存器读取",
    "SYSTEM_REGISTER_WRITE": "系统寄存器写入",
    "SYSTEM_REGISTER_READ": "系统寄存器读取",
}
# Presentation ordering only. It does not alter association statuses.
DISPLAY_ORDER = {
    "TLB_INVALIDATE": 0, "MMIO_WRITE": 1, "SYSTEM_REGISTER_WRITE": 2,
    "MMIO_READ": 3, "SYSTEM_REGISTER_READ": 4,
    "ATOMIC_STORE": 5, "ATOMIC_LOAD": 6,
    "EXCEPTION_RETURN": 7, "INSTRUCTION_BARRIER": 8, "MEMORY_BARRIER": 9,
}


def _within(function, address: int) -> bool:
    return any(part.start <= address < part.end for part in function.ranges)


def _static_paths(analysis: FirmwareStaticAnalysis) -> tuple[dict[str, object], dict[str, tuple[str, ...]]]:
    functions = {item.fact_id: item for item in analysis.functions}
    edges: dict[str, set[str]] = {item.fact_id: set() for item in analysis.functions}
    for call in analysis.calls:
        target = functions.get(call.target_function_id) if call.direct else None
        if target is None or call.target != target.entry:
            continue
        for caller_id in call.caller_function_ids:
            caller = functions.get(caller_id)
            if caller is not None and _within(caller, call.pc):
                edges[caller_id].add(target.fact_id)

    entry_functions = sorted((item for item in analysis.functions
                              if _within(item, analysis.artifact.entry)
                              or item.entry == analysis.artifact.entry),
                             key=lambda item: (item.entry, item.name, item.fact_id))
    if not entry_functions:
        return functions, {}

    def walk(start: str) -> dict[str, tuple[str, ...]]:
        paths = {start: (start,)}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for target in sorted(edges[current],
                                 key=lambda key: (functions[key].entry, functions[key].name, key)):
                if target not in paths:
                    paths[target] = (*paths[current], target)
                    queue.append(target)
        return paths

    entry_paths = walk(entry_functions[0].fact_id)
    main = sorted((item for item in analysis.functions
                   if item.name == "main" and item.fact_id in entry_paths),
                  key=lambda item: (item.entry, item.fact_id))
    root = main[0].fact_id if main else entry_functions[0].fact_id
    return functions, walk(root)


def _operations(analysis: FirmwareStaticAnalysis, chain: dict) -> list[dict]:
    functions, paths = _static_paths(analysis)
    behaviors = {item.fact_id: item for item in analysis.behaviors}
    instructions = {item.fact_id: item for item in analysis.instructions}
    rows = []
    for relation in chain["stages"][4]["outputs"]["relations"]:
        if relation["status"] != "SUPPORTED_CANDIDATE":
            continue
        for fact in relation["firmware_facts"]:
            behavior = behaviors.get(fact["fact_id"])
            instruction = instructions.get(behavior.instruction_id) if behavior else None
            if instruction is None:
                rows.append({"kind": relation["kind"], "instruction": None,
                             "function": None, "path": None, "behavior": behavior})
                continue
            path_options = [paths[owner] for owner in instruction.function_ids if owner in paths]
            selected = min(path_options, key=lambda path: (-len(path),
                           tuple(functions[item].name for item in path))) if path_options else None
            owner = selected[-1] if selected else next(
                (key for key in instruction.function_ids if key in functions), None)
            rows.append({
                "kind": relation["kind"], "instruction": instruction,
                "function": functions[owner].name if owner else None,
                "path": tuple(functions[item].name for item in selected) if selected else None,
                "behavior": behavior,
            })
    rows.sort(key=lambda row: (
        DISPLAY_ORDER.get(row["kind"], 100),
        -(len(row["path"]) if row["path"] else 0),
        -(row["instruction"].pc if row["instruction"] else 0),
        row["function"] or "", row["kind"],
    ))
    return rows


def _instruction_text(instruction) -> str:
    if instruction is None:
        return "具体指令未能从规范静态事实回溯"
    return instruction.text or " ".join((instruction.mnemonic, *instruction.operands))


def _operation_values(row: dict) -> list[str]:
    instruction, behavior = row["instruction"], row["behavior"]
    values = []
    if instruction is not None and instruction.operands:
        values.append("指令操作数：" + ", ".join(instruction.operands))
    if behavior is not None:
        if behavior.address_status == "exact" and behavior.address is not None:
            values.append(f"静态解析地址：0x{behavior.address:x}")
        if behavior.known_value is not None:
            values.append(f"静态解析数值：0x{behavior.known_value:x}")
        if behavior.system_register:
            values.append("系统寄存器：" + behavior.system_register)
    return values


def _human_relation(kind: str, status: str) -> str:
    if status == "SUPPORTED_CANDIDATE":
        return "发现同类软件静态操作（仅为候选）"
    if status == "NO_STATIC_KIND_MATCH":
        return "未发现同类受支持的软件静态操作"
    return "现有静态材料无法判断"


def render_customer_report(*, firmware: FirmwareStaticAnalysis, chain: dict,
                           association: dict, readiness: dict,
                           runtime_projection: dict | None = None) -> str:
    """Render one case without revealing internal IDs or inventing a runtime path."""
    relations = chain["stages"][4]["outputs"]["relations"]
    operations = _operations(firmware, chain)
    primary = operations[0] if operations else None
    primary_kind = primary["kind"] if primary else None
    same_kind = [item for item in operations if item["kind"] == primary_kind]
    focus = min(relations, key=lambda item: (DISPLAY_ORDER.get(item["kind"], 100),
                                            item["kind"])) if relations else None
    if focus is None:
        focus_summary = "现有材料没有可比较的硬件测试程序静态操作"
    elif focus["status"] == "SUPPORTED_CANDIDATE":
        focus_summary = f"发现与硬件测试程序中 {focus['kind']} 同类的软件静态操作"
    else:
        focus_summary = f"当前固件静态分析未发现与硬件测试程序中 {focus['kind']} 同类的受支持操作"
    primary_text = _instruction_text(primary["instruction"]) if primary else "尚无可展示的同类指令"
    runtime_fact = next((row for row in runtime_projection["firmware_facts"]
                         if primary and primary["behavior"] and row["static_behavior_id"]
                         == primary["behavior"].fact_id), None) if runtime_projection else None
    primary_observed = runtime_fact is not None and runtime_fact["status"] == "SUPPORTED"
    runtime_summary = (
        "关键指令已在该固件的来源绑定 QEMU 环境中观察到指令执行回调"
        if primary_observed else
        "当前有界 QEMU 运行未建立展示重点指令的执行支持"
    ) if runtime_projection is not None else "尚未获得所给固件的实际执行路径"
    path = " → ".join(primary["path"]) if primary and primary["path"] else "未建立完整静态调用路径"
    operands = ("、".join(primary["instruction"].operands)
                if primary and primary["instruction"] and primary["instruction"].operands
                else "未从规范静态指令得到")
    target = primary["function"] if primary else None
    hardware_relation = next((item for item in relations if item["kind"] == primary_kind), None)
    hardware_instructions = sorted({
        item["source_instruction"]["mnemonic"] + (
            " " + ", ".join(item["source_instruction"]["operands"])
            if item["source_instruction"]["operands"] else "")
        for item in hardware_relation["hardware_capabilities"]
        if item["source_instruction"] is not None
    }) if hardware_relation else []
    source_runtime = association["runtime_binding_status"]
    if runtime_projection is not None:
        source_runtime = runtime_projection["runtime_binding_status"]
    trigger = association["hardware_trigger_status"]
    raw_differences = chain["stages"][6]["outputs"]["raw_differing_word_count"]
    differential = association["hardware_differential_status"]
    differential_bindings = chain["stages"][6]["outputs"]
    bound_comparison = all(differential_bindings[field] == "BOUND" for field in (
        "same_testcase_binding", "same_firmware_binding", "same_execution_context_binding"))
    difference_line = (
        f"- 硬件包内原始签名有 {raw_differences} 处数值差异；"
        + ("本报告未建立其与所给固件的来源关系。" if bound_comparison else
           "测试、固件和执行上下文的绑定尚未建立。")
        if raw_differences else "- 当前硬件包未记录原始签名数值差异。")
    lines = [
        "# ChipChain Type-II 跨层攻击链分析报告", "",
        "## 1. 结论摘要", "",
        (f"**{focus_summary}；软件侧静态候选得到 QEMU 运行时执行支持；"
         "完整 Type-II 攻击链尚未验证。**" if primary_observed else
         f"**{focus_summary}；完整 Type-II 攻击链尚未验证。**"),
        "", "| 项目 | 结果 |", "| --- | --- |",
        "| 输入/前置条件 | 外部输入值及实际分支条件未建立 |",
        f"| 关键调用路径 | {path}（静态连通，非运行记录） |",
        f"| 关键指令/操作 | {primary_text} |",
        (f"| 硬件参考重点 | {focus['kind']}：{_human_relation(focus['kind'], focus['status'])} |"
         if focus else "| 硬件参考重点 | 无可比较的静态参考种类 |"),
        (f"| 软件侧敏感行为 | {primary_kind}：{KIND_LABELS.get(primary_kind, '静态操作')}；"
         "仅为静态候选 |" if primary else
         "| 软件侧敏感行为 | 现有规范分析中未找到可展示的同类受支持操作 |"),
        f"| 运行时执行 | {runtime_summary} |",
        "| 真实硬件触发 | 当前材料尚未建立 |",
        "| 异常后果 | 尚不能确定本固件是否产生硬件异常 |",
        "| 攻击链状态 | 完整 Type-II 链条未验证 |", "",
        "**可读链条（静态候选；缺失环节如实标明）**", "",
        "```text", "外部输入 / 前置条件：未建立", "↓",
        f"静态调用：{path}", "↓", f"关键操作数：{operands}", "↓",
        f"固件关键操作：{primary_text}", "↓",
        "权威硬件触发条件：未建立", "↓", "本固件的异常后果：未建立",
        "```", "",
        "## 2. 触发输入与前置条件", "",
        "- 外部输入值：当前分析材料未建立。",
        "- 具体分支条件及运行时状态：当前分析材料未建立。",
        "- 静态程序中的指令操作数可见，但不能把它们当作外部用户可控制的输入。", "",
        "## 3. 软件执行路径", "",
        "**静态调用路径**（规范静态分析中直连调用的可达路径，未证明运行时实际经过）：", "",
    ]
    if primary and primary["path"]:
        path_lines = [part for index, name in enumerate(primary["path"])
                      for part in ((["↓"] if index else []) + [name])]
        lines += ["```text", *path_lines, "```", ""]
    else:
        lines += ["无法从现有直连调用事实建立完整路径。", ""]
    lines += [(
        "**运行时指令观测**：" + runtime_summary + "。本阶段记录指令观测及其顺序，"
        "没有据此重建完整函数调用栈；上方调用路径仍为静态路径。"
        if runtime_projection is not None else
        "**运行时实际执行路径**：当前没有该固件的来源绑定运行证据。"
        if source_runtime == "UNKNOWN" else
        "**运行时实际执行路径**：现有报告输入没有可呈现的来源绑定函数路径。"
    ), ""]
    if runtime_projection is not None:
        lines += ["| 固件静态操作 | PC | 声明的 QEMU 运行中的执行支持 |",
                  "| --- | --- | --- |"]
        for row in runtime_projection["firmware_facts"]:
            result = ("已观察，指令字节与来源 ELF 精确匹配"
                      if row["status"] == "SUPPORTED" else
                      "此有界运行中未观察到；不能推断不可执行"
                      if row["reason"] == "NOT_OBSERVED_IN_THIS_RUN" else
                      "尚未建立受支持的语义对应；不能推断不可执行")
            lines.append(f"| {row['kind']} | `0x{row['pc']:x}` | {result} |")
        lines += ["", "- SUPPORTED 仅表示该静态事实具有来源绑定、解码兼容的 QEMU 指令执行回调观测；不证明指令或内存副作用完成，也不代表目标硬件执行或物理退休。",
                  "- 相同 vCPU 的事件序号仅表示本次声明运行中观测到的先后；"
                  "不能推广为所有输入下的顺序，也不是硬件时序。"]
        for row in runtime_projection["candidate_kind_support"]:
            if row["reason"] == "NO_SUPPORTED_STATIC_KIND_FACT":
                lines.append(f"- `{row['kind']}`：尚未建立该固件运行中对应行为的执行支持；"
                             "这不证明行为不可能发生，也不证明硬件安全。")
        lines.append("")
    lines += ["## 4. 关键函数与关键操作", ""]
    if operations:
        lines += ["| 静态函数 | 规范指令 | 软件语义 |", "| --- | --- | --- |"]
        for row in operations:
            lines.append(f"| `{row['function'] or '函数归属未建立'}` | "
                         f"`{_instruction_text(row['instruction'])}` | "
                         f"{KIND_LABELS.get(row['kind'], row['kind'])} |")
        lines += ["", f"- 展示重点：`{target or '函数归属未建立'}` 中的 "
                  f"`{primary_text}`。这是展示顺序，不是唯一操作或执行证明。"]
        if len(same_kind) > 1:
            lines.append(f"- 同类操作共有 {len(same_kind)} 处；上方表格均已列出。")
        for value in _operation_values(primary):
            lines.append("- " + value + "（来自规范静态指令/事实）。")
    else:
        lines.append("- 现有静态关联中没有可呈现的同类受支持操作。")
    lines += ["", "## 5. 硬件敏感操作", "",
              "硬件侧参考是硬件团队提供的触发测试 ELF 的**静态指令**，"
              "不是已验证的硬件行为，也不是客户固件。", ""]
    if primary:
        lines.append(f"- 软件侧展示操作：`{primary_text}`；作用："
                     f"{KIND_LABELS.get(primary_kind, primary_kind)}。")
        if hardware_instructions:
            lines.append("- 测试程序中的同类静态指令："
                         + "、".join(f"`{item}`" for item in hardware_instructions) + "。")
    lines += ["", "| 硬件测试材料的操作种类 | 与所给固件静态分析的关系 |",
              "| --- | --- |"]
    for item in relations:
        lines.append(f"| {item['kind']} | {_human_relation(item['kind'], item['status'])} |")
    lines += ["", "相同操作种类并不证明操作数、资源实例、执行顺序或硬件版本相同。", "",
              "## 6. 硬件触发条件", "",
              ("- 软件侧：静态行为种类候选及其 QEMU 执行支持见上表。"
               if runtime_projection is not None else
               "- 软件侧：上表仅给出静态行为种类的候选关系。"),
              "- 真实硬件触发条件：当前材料尚未建立权威硬件行为契约。",
              "- 因此尚未验证所给固件会触发真实硬件条件。", "",
              "## 7. 可能或已观察后果", "",
              difference_line,
              "- 包内原始数值比较不能自动归因于所给固件，也不能单独确认硬件异常。",
              "- 本固件的硬件异常或安全后果：当前材料尚不能确定。", "",
              "## 8. 当前验证状态", "",
              (f"- {focus_summary}；QEMU 支持仅适用于上表中已观察到的固件指令，"
               "不证明硬件触发或硬件安全。" if runtime_projection is not None else
               f"- {focus_summary}；这不证明实际执行、硬件触发或硬件安全。"),
              ("- " + runtime_summary + "。" if runtime_projection is not None else
               "- 尚未获得所给固件的来源绑定运行证据。" if source_runtime == "UNKNOWN"
               else "- 运行来源状态已更新；本报告仍未获得可呈现的实际执行路径。"),
              ("- 尚未验证真实硬件触发。" if trigger == "NOT_ESTABLISHED"
               else "- 硬件触发状态需以科学关联产物为准。"),
              ("- 原始签名差异的正式差异判定仍未建立。" if differential == "UNKNOWN"
               else "- 硬件差异判定需以科学关联产物为准。"),
              ("- 当前证据不足以完成 Type-II 验证；冻结的受控 Ibex MMIO verifier "
               "不适用于此硬件测试材料。" if not readiness["ready"] else
               "- 准备度状态已更新；是否形成验证结果仍以独立 verifier 输出为准。"),
              "- 本报告是展示投影。详细来源、事实及对象标识保留在同目录的科学产物中。", ""]
    if runtime_projection is not None:
        lines += ["- 固件运行支持详见新增 `runtime-projection.json`；原有装配产物保留"
                  "不含运行输入的基线结果及案例身份。整体验证准备度仍为不足。", ""]
    return "\n".join(lines)
