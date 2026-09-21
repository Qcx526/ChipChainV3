"""Chinese view of typed XL2 comparison records; no new claims or evidence."""
import html

from .capability_compatibility import (
    Outcome, parse_compatibility_result, serialize_compatibility_result,
)

_LABEL = {'compatible': 'COMPATIBLE（已检查字段兼容）',
          'incompatible': 'INCOMPATIBLE（存在明确字段冲突）', 'unknown': 'UNKNOWN（当前无法完成判断）'}
_REASON = {
    'EXACT_MATCH': '双方明确字段一致。', 'EXPLICIT_VALUE_CONFLICT': '双方明确字段存在冲突。',
    'MISSING_TYPED_VALUE': '缺少可比较的明确字段，不能按相同或不同处理。',
    'PLATFORM_IDENTITY_MISSING': '平台身份不足；同架构不能代替同平台。',
    'PLATFORM_IN_SCOPE': '固件声明的平台位于硬件适用范围内。', 'PLATFORM_OUTSIDE_SCOPE': '明确的平台身份不在硬件适用范围内。',
    'PROCESSOR_IDENTITY_EQUAL': '处理器身份字符串相同。',
    'PROCESSOR_IDENTITY_NOT_COMPARABLE': '尚不能确认两个处理器名称属于同一可比较的平台身份范围。',
    'APPLICABILITY_UNKNOWN': '输入的适用范围仍为 UNKNOWN。',
    'SYNTHETIC_SCOPE_NOT_SHARED': '硬件合同仅用于合成样例，固件未声明相同范围。',
    'DECLARED_SCOPE_KIND_COMPARABLE': '已声明的适用范围类型可以比较。',
    'ISA_VARIANT_SEMANTICS_UNSUPPORTED': '当前未实现 ISA 变体语义比较。',
    'FW_REVISION_FIELD_UNAVAILABLE': 'CAP0 没有对应的硬件修订或 RTL 身份字段。',
    'NO_SUPPORTED_MAPPING': '当前没有该固件原语与硬件触发要求之间的安全映射；不能因名字或指令字节相似而匹配。',
    'WHITELIST_MAPPING': '原语与触发类型命中明确白名单。',
    'EXPLICIT_RESOURCE_CLASS_CONFLICT': '明确的资源类别冲突，例如普通内存写入不能替代 CSR 访问。',
    'HW_REQUIREMENT_NOT_FORMALIZED': '硬件要求尚未结构化。', 'FW_PRIMITIVE_NOT_FORMALIZED': '固件原语尚未结构化。',
    'FW_CONSTRAINT_NOT_MODELED': '相关固件约束尚未结构化。', 'HW_INSTRUCTION_MISSING': '硬件指令要求缺失。',
    'FW_TYPED_INSTRUCTION_FIELD_UNAVAILABLE': 'CAP0 缺少对应的类型化指令字段；不从字符串序列猜测编码、助记符或操作数。',
    'HW_ACCESS_MISSING': '缺少硬件访问的具体要求。',
    'ACCESS_DIRECTION_ALLOWED': '读写方向符合要求。', 'ACCESS_DIRECTION_CONFLICT': '读写方向明确冲突。',
    'FW_NUMERIC_CSR_ADDRESS_UNAVAILABLE': 'CAP0 的 CSR identity 不等同于数字 CSR 地址；不做别名猜测。',
    'MISSING_NUMERIC_DOMAIN': '缺少数值域。', 'MISSING_NUMERIC_BOUNDS': '缺少明确数值边界。',
    'REQUIRED_DOMAIN_CONTAINED': '固件提供域包含硬件要求域。',
    'REQUIRED_DOMAIN_NOT_CONTAINED': '固件提供域不能覆盖硬件要求域。',
    'MASK_DOMAIN_NOT_SUPPORTED': '当前没有实现掩码域比较。',
    'RANGE_QUANTIFIER_UNSPECIFIED': '范围要求没有说明是满足任意值还是覆盖全部值，不能猜测。',
    'VALUE_OPERATOR_UNSUPPORTED': '当前不支持该值约束操作。', 'NUMERIC_WIDTH_UNSUPPORTED': '数值宽度超出当前比较器支持范围。',
    'FW_CONDITION_NOT_MODELED': '固件行为所依赖的条件仍缺少明确模型。',
    'NO_FW_PRIMITIVES': '固件没有提供可比较的原语。',
    'HW_PRECONDITION_MISSING': '硬件前置条件缺少明确结构。',
    'NO_UNAMBIGUOUS_TRIGGER_CONTEXT': '尚未确定单一的固件触发上下文；不跨不同原语或执行时刻推断全局前置状态。',
    'CONTROL_PREDICATE_UNSUPPORTED': '控制要求不属于当前支持的显式类型化谓词。',
    'EXPLICIT_CONTROL_DECLARATION': '对应维度有显式外部控制声明；这里只比较声明，不新增控制证据。',
    'EXTERNAL_CONTROL_NOT_ESTABLISHED': '要求的外部控制未建立；输入影响或退休记录都不能替代它。',
    'PRECONDITION_OPERATOR_UNSUPPORTED': '前置条件操作符或单位暂不支持。',
    'PRECONDITION_SUBJECT_UNSUPPORTED': '前置条件的字段含义未在白名单中定义。',
    'CONTRADICTORY_FW_STATE_REQUIREMENTS': '固件同一状态有相互矛盾的声明，当前不求解。',
    'PRECONDITION_KIND_UNSUPPORTED': '当前不支持该前置条件类型。',
    'HW_ORDERING_MISSING': '顺序要求缺失或未结构化。',
    'ORDER_ENDPOINT_MAPPING_NOT_ESTABLISHED': '顺序端点尚未建立唯一且兼容的语义映射。',
    'ORDER_OCCURRENCES_OR_DECLARATIONS_AMBIGUOUS': '事件发生次数或顺序声明存在歧义。',
    'MAPPED_DECLARED_ORDER_EQUAL': '已映射端点的声明顺序一致；不代表观察到了运行顺序。',
    'ORDER_DEFINITION_NOT_MODELED': '顺序定义尚未结构化。',
    'DECLARED_ORDER_BOUND_SUFFICIENT': '声明的最大事件间隔不超过硬件要求。',
    'ORDER_BOUND_INSUFFICIENT': '缺少足够强的顺序上界；不能把可能超限当成必然冲突。',
    'TIME_ORDER_BOUND_UNSUPPORTED': '时间单位与时间间隔比较暂不支持。',
    'MAPPED_DECLARED_ORDER_REVERSED': '已映射端点的明确顺序要求相反。',
    'NO_DECLARED_ORDER_FOR_MAPPED_ENDPOINTS': '未找到映射端点之间的明确顺序声明。',
    'NO_HW_TRIGGER_REQUIREMENTS': '没有硬件触发要求可检查；零冲突不能变成兼容。',
    'UNCLASSIFIED_HW_REQUIREMENT': '硬件仍有未分类要求，不能忽略。',
}


def _text(value):
    return html.escape(str(value), quote=False).replace('\n', ' ').replace('\r', ' ').replace('|', '&#124;').replace('`', '&#96;')


def render_capability_compatibility(value) -> str:
    value = parse_compatibility_result(serialize_compatibility_result(value))
    rows = [value.platform_result, *value.requirement_results]
    checks = [(r, '', c) for r in rows for c in r.checks]
    checks += [(r, a.firmware_primitive_id, c) for r in rows for a in r.alternatives for c in a.checks]
    meaning = {Outcome.COMPATIBLE: '在已支持的字段范围内完成了比较，未发现冲突。未评估部分仍保留在下文。',
               Outcome.INCOMPATIBLE: '本次输入对象存在明确字段冲突；这不证明整个固件不存在其他能力，也不证明漏洞不可利用。',
               Outcome.UNKNOWN: '当前信息或规则不足，无法证明兼容，也无法证明不兼容。'}
    reasons = list(dict.fromkeys(c.reason for row, _, c in checks
                                 if row.outcome != Outcome.COMPATIBLE and c.outcome == row.outcome))
    lines = ['# 跨层兼容性说明', '', '## 先看结论', '', f'当前结果：**{_LABEL[value.overall_result]}**', '',
             meaning[value.overall_result], '',
             '**这份报告没有证明硬件触发、实际执行、偏差、漏洞或攻击链成立。**', '', '主要原因：', '']
    if reasons:
        lines += ['- ' + _REASON.get(r, _text(r)) for r in reasons[:5]]
    else:
        lines.append('- 所有已要求的匹配项都有足够信息，并在当前比较规则下兼容。')
    lines += ['', '## 已检查与尚不能检查的字段', '',
              '| 要求 | 固件原语（如有） | 字段 | 结果 | 原因 |', '|---|---|---|---|---|']
    for row, primitive, check in checks:
        icon = {Outcome.COMPATIBLE: '✓', Outcome.INCOMPATIBLE: '✗', Outcome.UNKNOWN: '?'}[check.outcome]
        lines.append(f'| {_text(row.section + ":" + row.requirement_id)} | {_text(primitive or "—")} | {_text(check.dimension)} | '
                     f'{icon} {check.outcome.value} | {_REASON.get(check.reason, _text(check.reason))} |')
    lines += ['', '## 明确冲突', '']
    # An incompatible alternative need not invalidate a requirement with another compatible offer.
    conflicts = [r for r in rows if r.outcome == Outcome.INCOMPATIBLE]
    lines += ([f'- {_text(r.requirement_id)}：所有已声明的可比较选择均冲突，或该必需字段有明确冲突。' for r in conflicts]
              or ['本次没有形成要求级的明确冲突结论。这不等于整体兼容。'])
    lines += ['', '## 缺失信息与未支持规则', '']
    blockers = [r for r in rows if r.outcome == Outcome.UNKNOWN]
    lines += ([f'- {_text(r.section)} / {_text(r.requirement_id)}：仍为 UNKNOWN。' for r in blockers]
              or ['当前要求级比较没有 UNKNOWN；未评估的科学问题仍见下文。'])
    lines += ['', '## 尚未评估', '', '- 硬件 Deviation 与 Observation 不参与固件兼容性判断。']
    for d in value.downstream_verification_requirements:
        lines.append(f'- {d.section}：' + ('合同缺项（missing）。' if d.state == 'missing' else
                     f'保留 {len(d.requirement_ids)} 项下游验证要求，未验证是否发生或可观察。'))
    lines += [f'- {_text(s)}' for s in value.unassessed_contract_sections if s not in ('deviation', 'observation')]
    lines += ['', '## 科学边界', '',
              '**compatibility ≠ satisfiability ≠ reachability ≠ runtime trigger ≠ deviation ≠ vulnerability ≠ attack chain。**', '',
              '这是来源绑定的确定性字段比较记录，不是新增的执行证据。未出现外部控制要求时，也不会替研究者增加这种要求。', '',
              '## 追溯信息', '', f'- 规则版本：{_text(value.matcher_version)}',
              f'- FirmwareCapability：{value.firmware_capability_id}', f'- HardwareBehaviorContract：{value.hardware_contract_id}',
              f'- 结果 ID：{value.result_id}', f'- 结果 SHA-256：{value.result_sha256}',
              '- provenance：derived_from_typed_contracts']
    for s in value.source_references:
        lines.append(f'- {_text(s.side)} 来源 {_text(s.identity)}：{s.sha256}（{_text(s.hash_kind)}）')
    for e in value.evidence_references:
        lines.append(f'- {_text(e.side)} 既有证据 {_text(e.identity)} → {_text(e.artifact_id)}')
    return '\n'.join(lines) + '\n'
