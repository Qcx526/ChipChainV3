"""Deterministic Chinese acceptance view. No model calls or inferred attack powers."""
import html

from .capability import (
    FirmwareCapability, IdentityConstraint, NumericConstraint, OrderingConstraint,
    ResourceConstraint, TargetSetConstraint, formalization_summary,
    parse_firmware_capability, serialize_firmware_capability,
)

_ORIGINS = {'normal_behavior': '正常固件行为', 'vulnerability_derived': '漏洞衍生的显式能力声明',
            'manual_research_input': '人工研究输入', 'synthetic_fixture': '合成测试（test-only）', 'unknown': 'UNKNOWN'}
_CONTROL = {'not_established': 'NOT ESTABLISHED（未建立）', 'unknown': 'UNKNOWN',
            'firmware_determined': '固件自身决定', 'input_influenced': '输入影响；不等于外部可控',
            'bounded_external_control': '限定范围内的外部控制声明', 'full_external_control': '仅声明维度内的完整外部控制',
            'vulnerability_derived_control': '带独立支持的漏洞衍生控制声明'}
_KINDS = {
    'INSTRUCTION_EXECUTION': '指令执行', 'DIRECT_CONTROL_TRANSFER': '直接控制转移',
    'INDIRECT_CONTROL_TRANSFER': '间接控制转移', 'MEMORY_READ': '内存读取', 'MEMORY_WRITE': '内存写入',
    'MMIO_READ': '内存映射外设读取', 'MMIO_WRITE': '内存映射外设写入',
    'CSR_READ': '控制/状态寄存器读取', 'CSR_WRITE': '控制/状态寄存器写入',
    'EXCEPTION_RETURN': '异常返回', 'INTERRUPT_HANDLING': '中断处理', 'READ_OOB': '越界读取',
    'WRITE_OOB': '越界写入', 'WRITE_BOUNDED': '范围受限的写入', 'PARTIAL_ADDRESS_CONTROL': '部分地址控制',
    'PARTIAL_VALUE_CONTROL': '部分值控制', 'LENGTH_CONTROL': '长度控制',
    'CONTROL_FLOW_INFLUENCE': '控制流影响', 'CONTROL_FLOW_HIJACK': '控制流劫持',
    'CALLBACK_INFLUENCE': '回调影响', 'DENIAL_OF_SERVICE': '拒绝服务', 'OTHER': '其他行为', 'UNKNOWN': 'UNKNOWN',
}


def _text(value):
    return 'UNKNOWN' if value is None else html.escape(str(value), quote=False).replace('\n', ' ').replace('\r', ' ').replace('|', '&#124;').replace('`', '&#96;')


def _address(value):
    return 'UNKNOWN' if value is None else hex(value)


def _constraint(item):
    if isinstance(item, ResourceConstraint):
        return f'资源：{_text(item.resource_kind)} / {_text(item.identity)}'
    if isinstance(item, NumericConstraint):
        labels = {'address': '地址', 'value': '值', 'access_width': '访问位宽（bit）', 'length': '长度（byte）'}
        d = item.domain
        fmt = _address if item.kind == 'address' else _text
        parts = []
        if d.exact is not None:
            parts.append('固定为 ' + fmt(d.exact))
        if d.minimum is not None:
            parts.append(f'范围 {fmt(d.minimum)} 至 {fmt(d.maximum)}（含端点）')
        if d.mask is not None:
            parts.append(f'掩码 {_address(d.mask)}，要求掩码后的值为 {_address(d.masked_value)}')
        if d.controlled_bits is not None:
            parts.append(f'声明的控制位掩码 {_address(d.controlled_bits)}，位宽 {d.bit_width}；实际控制依据另列')
        return labels[item.kind] + '：' + '；'.join(parts)
    if isinstance(item, IdentityConstraint):
        return f'{_text(item.kind)}：{_text(item.identity)}'
    if isinstance(item, TargetSetConstraint):
        return '静态目标限制：' + '、'.join(hex(x) for x in item.targets) + '（不表示运行时边已被取用）'
    if isinstance(item, OrderingConstraint):
        return f'顺序：{_text(item.before_primitive_id)} → {_text(item.after_primitive_id)}；最大事件间隔 {_text(item.max_gap_events)}'
    raise TypeError('Unknown constraint type')


def render_firmware_capability(value: FirmwareCapability) -> str:
    value = parse_firmware_capability(serialize_firmware_capability(value))
    refs = {c.constraint_id: c for c in value.constraints}
    statuses = {p.control.status for p in value.primitives}
    established = bool(statuses & {'bounded_external_control', 'full_external_control', 'vulnerability_derived_control'})
    lines = ['# 固件能力说明', '', '## 先看结论', '',
             f'来源类型：**{_ORIGINS[value.origin.kind]}**。', '',
             '当前记录：' + ('、'.join(_KINDS[p.kind] for p in value.primitives) or '尚无行为原语（missing）') + '。', '',
             '**外部控制：存在来源绑定的控制声明，范围与维度见下文；不表示任意控制。**' if established else
             '**外部控制：NOT ESTABLISHED（未建立）。不能把“固件包含这种行为”读成“攻击者能迫使固件执行它”。**', '',
             '本说明记录带条件和限制的能力；静态事实与来源声明并不自动证明路径可行、运行时可重复触发或安全影响。', '',
             '## 当前已建立', '', f'- 入口类型：{_text(value.entry.entry_kind)}；源 PC：{_address(value.entry.pc)}',
             f'- 函数上下文：{_text(value.entry.function_name or value.entry.function_id)}；归属状态 {_text(value.entry.ownership_status)}',
             f'- 外部接口：{_text(value.entry.interface_id)}；可达性状态：{_text(value.entry.reachability_status)}']
    if value.entry.execution_status == 'source_instruction_retired':
        lines.append(f'- 已有 {len(value.entry.retirement_observation_ids)} 条源指令退休记录；不证明跳转边被取用或外部入口可达。')
    else:
        lines.append('- 源指令退休：未建立；当前执行状态 ' + _text(value.entry.execution_status))
    for index, primitive in enumerate(value.primitives, 1):
        lines += ['', f'### 行为 {index}：{_KINDS[primitive.kind]}', '',
                  f'- 建模状态：{primitive.formalization_status}；依据类型：{primitive.basis}',
                  f'- 源位置：{_address(primitive.source_pc)}；目标状态：{primitive.target_status}']
        if primitive.kind == 'INDIRECT_CONTROL_TRANSFER':
            lines.append('- 具体目标：UNKNOWN；没有补造地址。')
        lines += ['- ' + _constraint(refs[i]) for i in primitive.constraint_ids]
        if not primitive.constraint_ids:
            lines.append('- 资源及数值约束：missing。')
    lines += ['', '## 控制能力', '']
    for p in value.primitives:
        lines += [f'- {_KINDS[p.kind]}：{_CONTROL[p.control.status]}。',
                  f'  声明维度：{_text("、".join(p.control.dimensions)) or "未建立"}；依据 {_text(p.control.support_basis)}。']
    lines += ['', '输入影响不等于外部可控；8 位值控制不等于完整地址或任意写控制。', '', '## 条件', '']
    if not value.conditions:
        lines.append('missing：尚未提供成立条件，不表示无条件成立。')
    for c in value.conditions:
        lines.append(f'- [{c.formalization_status}] {_text(c.description)}')
        if c.predicate:
            lines.append(f'  结构要求：{_text(c.predicate.subject)} {_text(c.predicate.operator)} '
                         + '、'.join(_text(x) for x in c.predicate.operands))
    lines += ['', '## 当前缺口', '',
              '- 外部入口到达该位置的路径、输入限制与权限：除显式列出的声明外，均未由本报告证明。',
              '- 静态目标不是运行时取边记录；历史源指令退休不是未来输入可触发性的保证。',
              '- 实际安全影响及与硬件合同的兼容性：未评估。', '', '## 适用范围', '',
              f'- 架构：{value.architecture}；处理器：{_text(value.scope.target.processor_id)}；平台：{_text(value.scope.platform_id)}',
              f'- 固件：{_text("、".join(value.scope.firmware_artifact_ids))}',
              f'- 范围类型：{value.scope.applicability}；位置：' + ('、'.join(hex(x) for x in value.scope.site_pcs) or 'UNKNOWN')]
    if value.scope.applicability == 'synthetic_only':
        lines.append('- **仅用于 synthetic / test-only；不是真实漏洞证据。**')
    for label, items in [('假设', value.scope.assumptions), ('未建模', value.scope.unmodeled_aspects),
                         ('限制', [*value.scope.known_limitations, *value.limitations])]:
        lines += [f'- {label}：{_text(x)}' for x in items]
    lines += ['', '## 建模完整性', '', '仅统计结构化程度，不是能力成立概率、可利用性置信度或风险分数。', '',
              '| 部分 | 总数 | 完整 | 部分 | 未形式化 | UNKNOWN | 缺失 |', '|---|---:|---:|---:|---:|---:|---|']
    for name, count in formalization_summary(value).items():
        lines.append(f'| {name} | {count.total} | {count.formalized} | {count.partially_formalized} | '
                     f'{count.unformalized} | {count.unknown} | {"是" if count.missing else "否"} |')
    lines += ['', '## 科学边界', '',
              'Firmware fact ≠ Firmware capability；Memory write ≠ arbitrary write。', '',
              'Runtime retirement ≠ external-input controllability；Analysis capability ≠ TargetInputCapability。', '',
              '本阶段未匹配硬件行为合同，未调用 LLM。', '', '## 追溯信息', '',
              f'- 能力 ID：{value.capability_id}', f'- 内容 SHA-256：{value.capability_sha256}',
              f'- Case：{_text(value.source_case_id)}']
    for source in value.source_artifacts:
        lines.append(f'- 来源 {_text(source.artifact_id)}：{source.source_kind} / {source.hash_kind} / {source.sha256}')
    for ref in value.evidence:
        lines.append(f'- 证据 {_text(ref.evidence_id)} → {_text(ref.artifact_id)}；'
                     f'地址 {_address(ref.location.address)}；行 {_text(ref.location.line)}；{ref.epistemic_status}')
    return '\n'.join(lines) + '\n'
