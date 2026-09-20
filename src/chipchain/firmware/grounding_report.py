"""Chinese rendering with explicit separation of model text, facts and acceptance."""
import json
from pathlib import Path


def render_report(directory: Path):
    def read(name):
        path=directory/name
        return json.loads(path.read_text()) if path.exists() else None
    def cell(value):
        return str(value).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('|','\\|').replace('\n',' ')
    run=read('analysis_run.json'); audit=read('firmware_support_validation.json')
    raw=read('firmware_model_claims.diagnostic.json')
    context=read('research_validation.json')
    text=['# A6 配对工作流：确定性固件事实校验', '',
        f"工作流状态：**{run['status']}**。这表示工程运行状态，不是漏洞验证结果。", '',
        '本轮使用原有 ELF、模拟器和平台配置；没有受控 RTL 变体。', '',
        f"研究验证上下文：{context['validation_context'] if context else '未记录'}。静态事实与系统验证层级分别记录。", '',
        '| 阶段 | 状态 |', '| --- | --- |']
    for stage in run['stages']:
        text.append(f"| {stage['stage']} | {stage['status']} |")
    text += ['', '## 模型声明与确定性事实', '',
        '模型原文保留在诊断文件；下表中的规范表述由 A6 事实生成。被拒绝的声明不会进入固件报告或跨层输入。', '',
        '| 声明 ID | Raw Model Claim（结构化值） | Deterministic Fact | Validation Status | Corrected/Canonical Interpretation | 证据来源 |',
        '| --- | --- | --- | --- | --- | --- |']
    if audit and raw:
        claims={c['claim_id']:c for c in raw['claims']}
        for result in audit['results']:
            claim=claims[result['claim_id']]
            statement=(f"{claim['instruction_pc']:#x} → {claim['claimed_target_pc']:#x}" if claim['claim_type']=='control_transfer_target'
                       else f"{claim['site_pc']:#x} 属于 {claim['owner_function_id']}")
            actual=result['canonical_interpretation'] or '没有可绑定的确定性事实'
            canonical_text=actual if result['status']=='supported' else '声明被拒绝；独立事实仅供对照，不改写为模型原意'
            text.append('| '+' | '.join(map(cell,[claim['claim_id'],statement,actual,
                result['status']+'：'+result['reason_code'],canonical_text,
                '; '.join(e['artifact_id']+' / '+e['evidence_id']+' / '+str(e.get('location',{})) for e in result['evidence']) or '缺少可绑定证据']))+' |')
        text += ['', '### 原始模型叙述（仅诊断，不作为规范结论）', '']
        for claim in raw['claims']:
            text.append(f"- {cell(claim['claim_id'])}：{cell(claim['raw_model_summary'])}")
        text += ['', f"接受 {len(audit['accepted_claim_ids'])} 条，拒绝 {len(audit['rejected_claim_ids'])} 条。",
                 '任何模型叙述，即使同一条结构化声明被支持，也不会被直接复制进 canonical report。']
    else:
        text += ['', '未产生可用的 A6 声明校验结果；查看阶段失败记录。']
    cross=read('cross_layer_analysis_report.json')
    text += ['', '## 跨层结果', '']
    if cross is None:
        text.append('跨层报告不可用；不将阻塞或失败解释为没有候选。')
    elif not cross['candidates']:
        text.append('本轮没有提出候选。不能据此声称平台安全或不存在跨层问题。')
    else:
        text.append(f"本轮提出 {len(cross['candidates'])} 个候选；仍需独立验证。")
    text += ['', '## 调用记录', '', '| 阶段 | 请求模型 | 返回模型 | Input | Output | Total | Finish reason | Retries |', '| --- | --- | --- | --- | --- | --- | --- | --- |']
    calls=total=0
    for role in ('hardware','firmware','cross_layer'):
        invocation=read(role+'_invocation.json')
        if not invocation:continue
        calls+=1; usage=invocation.get('usage',{});total+=usage.get('total_tokens',0)
        metadata=invocation.get('response_metadata',{})
        text.append('| '+' | '.join(map(cell,[role,invocation['model'],metadata.get('model_name',metadata.get('model','unknown')),
                    usage.get('input_tokens','unknown'),usage.get('output_tokens','unknown'),usage.get('total_tokens','unknown'),metadata.get('finish_reason','unknown'),0]))+' |')
    text += ['',f'调用记录 {calls} 条，已记录总用量 {total} tokens；无自动重试。', '',
        '## 验收边界', '',
        '确定性事实：A6计算指令直接目标与函数包含关系；RVFI退休事件单独保存。',
        '模型解释：原始叙述仅供诊断。被拒绝声明：在表中保留状态和原因，不进入规范结论。',
        '未知 / 缺少证据：间接目标、缺失或重叠的函数归属不补猜；分支实际采取、路径可行、外部输入可控性和安全影响未建立。',
        '跨层候选：单独列出，候选存在或缺席都不改变上述事实边界。',
        '函数名只是展示信息。未知大小不补造区间，重叠归属不猜测。', '',
        '[确定性事实](firmware_control_flow_grounding.json) · [支持校验](firmware_support_validation.json) · '
        '[模型声明诊断](firmware_model_claims.diagnostic.json) · [规范固件报告](firmware_analysis_report.json) · [运行记录](analysis_run.json)']
    return '\n'.join(text)+'\n'
