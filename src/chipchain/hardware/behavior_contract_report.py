"""Deterministic Chinese acceptance view; no generated scientific conclusions."""
import html
import json

from .behavior_contract import (
    HardwareBehaviorContract, formalization_summary,
    parse_hardware_behavior_contract, serialize_hardware_behavior_contract,
)

_STATUS = {'formalized': '✓ 已结构化', 'partially_formalized': '△ 部分结构化',
           'unformalized': '✗ 未结构化', 'unknown': '? UNKNOWN'}
_SECTIONS = {'preconditions': '前置条件', 'trigger': '触发要求', 'deviation': '预期偏差',
             'observation': '观察要求', 'scope': '适用边界', 'unclassified_atoms': '未分类条件'}
_OPERATORS = {'eq': '等于', 'neq': '不等于', 'masked_eq': '按掩码比较（值、掩码）',
              'in_range': '范围内（下限、上限）', 'present': '应出现', 'before': '先于'}


def _text(value):
    if value is None:
        return 'UNKNOWN'
    return html.escape(str(value), quote=False).replace('\n', ' ').replace('\r', ' ').replace('|', '&#124;').replace('`', '&#96;')


def _relation(value):
    if value is None:
        return 'UNKNOWN'
    operands = '，'.join(_text(x) for x in value.operands)
    return f'{_text(value.subject)} {_OPERATORS[value.operator]} {operands}' + (f'（{_text(value.unit)}）' if value.unit else '')


def render_hardware_behavior_contract(value: HardwareBehaviorContract) -> str:
    value = HardwareBehaviorContract.model_validate(value.model_dump(mode='json'))
    # Reuse canonical transport order so equivalent set permutations render equally.
    value = parse_hardware_behavior_contract(serialize_hardware_behavior_contract(value))
    summary = formalization_summary(value)
    missing = [label for key, label in _SECTIONS.items() if key != 'unclassified_atoms' and summary[key].missing]
    lines = ['# 硬件行为合同说明', '', '## 先看结论', '',
             '这是一份“什么条件下需要检查什么硬件偏差”的要求说明。它不是实验成功报告。', '',
             f'已录入 {len(value.trigger)} 项触发要求、{len(value.deviation)} 项偏差定义、'
             f'{len(value.observation)} 项观察要求；另有 {len(value.unclassified_atoms)} 项尚未分类。', '',
             '当前缺项：' + ('、'.join(missing) if missing else '六部分均有条目，仍须分别检查未知字段与实验依据') + '。', '',
             '**实际偏差观测：未在本合同中记录；不得据此认定异常发生或漏洞成立。**', '',
             '## 目标平台', '',
             f'- 架构：{_text(value.architecture)}；处理器：{_text(value.platform.target.processor_id)}',
             f'- 平台：{_text(value.platform.platform_id)}；ISA：{_text(value.platform.target.isa_variant)}',
             f'- 位宽：{_text(value.platform.target.word_size_bits)}；字节序：{_text(value.platform.target.endianness)}',
             f'- RTL：{_text(value.platform.rtl_identity)}；RTL 修订：{_text(value.platform.rtl_revision)}',
             f'- 芯片修订：{_text(value.platform.silicon_revision)}', '']
    for key in ('preconditions', 'trigger', 'deviation', 'observation'):
        lines += [f'## {_SECTIONS[key]}', '']
        items = getattr(value, key)
        if not items:
            lines += ['尚未提供（missing）；不等于不存在或无需检查。', '']
        for index, item in enumerate(items, 1):
            lines += [f'### 第 {index} 项{_SECTIONS[key]} · {_STATUS[item.formalization_status]}', '',
                      _text(item.description), '', f'- 条件编号：{_text(item.condition_id)}']
            if key == 'preconditions':
                lines += [f'- 必须预先满足：{_relation(item.required_relation)}']
            elif key == 'trigger':
                for index, instruction in enumerate(item.instructions, 1):
                    encoding = hex(instruction.encoding) if instruction.encoding is not None else 'UNKNOWN'
                    lines += [f'- 指令 {index}：{_text(instruction.mnemonic)}；编码 {encoding}；'
                              f'架构 {_text(instruction.architecture)}；表示 {_text(instruction.representation)}；'
                              f'阶段 {_text(instruction.stage_requirement)}；编码掩码 {_text(hex(instruction.encoding_mask) if instruction.encoding_mask is not None else None)}']
                    if instruction.operand_pattern:
                        operands = instruction.operand_pattern
                        parts = []
                        if operands.destination_register:
                            parts.append(f'目标寄存器 {_text(operands.destination_register)}')
                        if operands.source_registers:
                            parts.append('源寄存器（按位置）' + '、'.join(_text(x) for x in operands.source_registers))
                        if operands.base_register:
                            parts.append(f'基址寄存器 {_text(operands.base_register)}')
                        if operands.immediate_exact is not None:
                            parts.append(f'立即数 {operands.immediate_exact}')
                        if operands.immediate_range:
                            parts.append(f'立即数范围 {operands.immediate_range.minimum} 至 {operands.immediate_range.maximum}')
                        lines += ['- 操作数要求：' + '；'.join(parts)]
                if item.access:
                    address = getattr(item.access, 'address', None)
                    identity = hex(address) if address is not None else (item.access.csr_identity or item.access.csr_address)
                    lines += [f'- 访问：{_text(item.access.kind)} / {_text(identity)} / {_text(item.access.access)}',
                              f'- 完整访问约束：{_text(json.dumps(item.access.model_dump(mode="json", exclude_none=True), ensure_ascii=False))}']
                if item.ordering:
                    lines += [f'- 顺序：{_text(item.ordering.before_atom_id)} → {_text(item.ordering.after_atom_id)}',
                              f'- 最大间隔：{_text(item.ordering.max_gap_events)} 个事件；'
                              f'{_text(item.ordering.max_gap_time)} {_text(item.ordering.time_unit)}']
                if item.required_relation:
                    lines += [f'- 状态或事件要求：{_relation(item.required_relation)}']
                if not any((item.instructions, item.access, item.ordering, item.required_relation)):
                    lines += ['- 机器可检查的具体要求：UNKNOWN']
            elif key == 'deviation':
                lines += [f'- 影响对象：{_text(item.affected_component)}',
                          f'- 正常应当：{_relation(item.expected_behavior)}',
                          f'- 待检查偏差：{_relation(item.deviating_behavior)}',
                          f'- 规格依据：{_text(item.specification_ref)}',
                          f'- 首个分歧位置要求：{_text(item.first_divergence_point)}；约束定义状态：{_text(item.hardware_constraint_status)}',
                          '- 证据状态：以上是偏差定义，不是偏差发生记录。']
            else:
                lines += [f'- 需要观察：{_text(item.observable_target)}',
                          f'- 对应偏差：{_text(", ".join(item.deviation_ids))}',
                          f'- 所需工具或后端：{_text(item.required_backend)}',
                          f'- 正常判据：{_relation(item.expected_observation)}',
                          f'- 偏差判据：{_relation(item.deviation_observation)}',
                          f'- 所需证据：{_text(item.evidence_requirement)}',
                          '- 实际测量证据：本模型仅保存观察要求（observation_required / evidence_missing）。']
            lines += [f'- 要求来源：{_text(", ".join(item.source_artifact_ids))}',
                      f'- 支持要求定义的证据引用数：{len(item.evidence_ids)}（不代表实际观测数量）', '']
    lines += ['## 适用边界', '',
              f'- 范围类型：{_text(value.scope.applicability)}；来源权威：{_text(value.scope.source_authority)}',
              '- 仅用于合成测试，不是真实漏洞证据。' if value.scope.applicability == 'synthetic_only' else '- 本合同不推断实机适用性。',
              f'- 适用架构：{_text(", ".join(value.scope.applicable_architectures)) or "UNKNOWN"}',
              f'- 适用平台：{_text(", ".join(value.scope.applicable_platforms)) or "UNKNOWN"}',
              f'- RTL 修订限制：{_text(", ".join(value.scope.rtl_revisions)) or "UNKNOWN"}',
              f'- 芯片适用性：{_text(value.scope.silicon_applicability)}',
              f'- 芯片修订限制：{_text(", ".join(value.scope.silicon_revisions)) or "UNKNOWN"}']
    for label, items in [('假设', value.scope.assumptions), ('未建模', value.scope.unmodeled_aspects),
                         ('观察盲区', value.scope.observation_blind_spots),
                         ('已知限制', value.scope.known_limitations), ('合同限制', value.limitations)]:
        lines += [f'- {label}：{_text(item)}' for item in items]
    if value.unclassified_atoms:
        lines += ['', '## 尚不能分类的条件', '']
        reasons = {'state_timing_unknown': '状态出现的时间角色未知',
                   'ordering_endpoint_unclassified': '顺序端点尚未归类为触发事件',
                   'verification_metadata': '仅用于验证说明，不是触发要求'}
        lines += [f'- {_text(x.atom.atom_id)}：{reasons[x.reason]}。' for x in value.unclassified_atoms]
    lines += ['', '## 建模完整性', '', '这里统计结构化程度，不是置信度、风险分数或攻击成功率。', '',
              '| 部分 | 总数 | 已结构化 | 部分结构化 | 未结构化 | UNKNOWN | 缺项 |',
              '|---|---:|---:|---:|---:|---:|---|']
    for key, count in summary.items():
        lines.append(f'| {_SECTIONS[key]} | {count.total} | {count.formalized} | {count.partially_formalized} | '
                     f'{count.unformalized} | {count.unknown} | {"是" if count.missing else "否"} |')
    lines += ['', '## 验收前还需要补什么', '']
    if not value.deviation:
        lines.append('- 补充正常行为和待检查异常的具体差异，并绑定规格来源。')
    if not value.observation:
        lines.append('- 明确应观察哪个寄存器、信号或事件，以及正常与异常的区分方法。')
    if value.scope.applicability == 'unknown':
        lines.append('- 补充适用平台与修订边界；目前不能推断实机适用性。')
    lines.append('- 即使要求全部结构化，仍需独立验证条件与实际测量；本合同不记录这些实验结果。')
    lines += ['', '## 核心边界', '',
              '**固件满足触发要求 ≠ 硬件偏差发生 ≠ 偏差已被客观观察。**', '',
              '分析工具能分析某种输入，不代表目标上的外部输入可控。本阶段未执行固件匹配或实机验证。', '',
              '## 追溯信息', '', f'- 合同：{_text(value.contract_id)}',
              f'- 合同 SHA-256：{value.contract_sha256}', f'- 来源 Case：{_text(value.source_case_id)}']
    for source in value.source_artifacts:
        lines.append(f'- 来源 {_text(source.artifact_id)}：{source.source_kind}；SHA-256 {source.sha256}')
    for ref in value.evidence:
        lines.append(f'- 证据 {_text(ref.evidence_id)} → {_text(ref.artifact_id)}（{ref.epistemic_status}）；'
                     f'定位 {_text(json.dumps(ref.location.model_dump(mode="json", exclude_none=True), ensure_ascii=False))}')
    return '\n'.join(lines) + '\n'
