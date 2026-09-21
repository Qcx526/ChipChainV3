from chipchain.hardware.behavior_contract_report import render_hardware_behavior_contract
from tests.unit.test_hardware_behavior_contract import build, complete_input
from tests.unit.test_hardware_behavior_contract_materialization import arguments, xl0
from chipchain.hardware.behavior_contract_materialization import materialize_xl0


def test_complete_report_is_readable_and_not_observation_claim():
    value = build()
    report = render_hardware_behavior_contract(value)
    assert report == render_hardware_behavior_contract(build())
    for text in ['先看结论', '前置条件', '触发要求', '预期偏差', '观察要求', '适用边界',
                 '建模完整性', '追溯信息', '仅用于合成测试', '不是实验成功报告',
                 '正常应当：result 等于 0', '待检查偏差：result 不等于 0',
                 'observation_required / evidence_missing', '固件满足触发要求 ≠ 硬件偏差发生']:
        assert text in report
    assert 'confidence =' not in report


def test_partial_report_does_not_invent_missing_components():
    value = xl0()
    report = render_hardware_behavior_contract(materialize_xl0(value, **arguments(value)))
    assert '当前缺项：前置条件、预期偏差、观察要求。' in report
    assert '4 项触发要求、0 项偏差定义、0 项观察要求' in report
    assert '状态出现的时间角色未知' in report
    assert '异常已发生' not in report


def test_report_normalizes_sets_and_escapes_markup():
    data = complete_input()
    data['scope']['assumptions'] = ['z', 'a']
    data['preconditions'][0]['description'] = '<script>bad</script>\n| next'
    first = render_hardware_behavior_contract(build(data))
    data['scope']['assumptions'].reverse()
    assert first == render_hardware_behavior_contract(build(data))
    assert '<script>' not in first
    assert '&#124;' in first
