from tests.unit.test_capability_compatibility import compare, inputs, instruction_inputs
from chipchain.cross_layer.capability_compatibility_report import render_capability_compatibility


def test_positive_report_keeps_scientific_boundary():
    value=compare();text=render_capability_compatibility(value)
    assert text==render_capability_compatibility(compare())
    assert 'COMPATIBLE（已检查字段兼容）' in text
    assert '没有证明硬件触发' in text
    assert '未验证是否发生或可观察' in text
    assert 'derived_from_typed_contracts' in text


def test_negative_report_is_scoped_to_input_not_whole_firmware():
    fw,hw=inputs();fw['constraints'][1]['identity']='wrong'
    text=render_capability_compatibility(compare(fw,hw))
    assert 'INCOMPATIBLE（存在明确字段冲突）' in text
    assert '不证明整个固件不存在其他能力' in text


def test_unknown_report_has_no_false_success_or_false_negative():
    fw,hw=instruction_inputs('DIRECT_CONTROL_TRANSFER');fw['scope']['platform_id']=None
    text=render_capability_compatibility(compare(fw,hw))
    first_screen=text.split('## 已检查')[0]
    assert 'UNKNOWN（当前无法完成判断）' in first_screen
    assert '平台身份不足' in first_screen
    assert '没有该固件原语' in first_screen
    assert '无法证明兼容，也无法证明不兼容' in text
    assert 'compatibility ≠ satisfiability' in text


def test_unused_conflicting_alternative_is_not_reported_as_overall_conflict():
    import copy
    fw,hw=inputs()
    other=copy.deepcopy(fw['primitives'][0]);other.update(primitive_id='other',constraint_ids=['resource','other-csr','value','width'])
    fw['primitives'].append(other)
    csr=copy.deepcopy(fw['constraints'][1]);csr.update(constraint_id='other-csr',identity='wrong')
    fw['constraints'].append(csr)
    text=render_capability_compatibility(compare(fw,hw))
    assert '存在冲突' not in text.split('## 已检查')[0]
    assert '没有形成要求级的明确冲突' in text
