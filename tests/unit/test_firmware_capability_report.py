from tests.unit.test_firmware_capability import build, synthetic_input
from tests.unit.test_firmware_capability_materialization import catalog, convert
from chipchain.firmware.capability_report import render_firmware_capability


def test_realistic_a6_report_leads_with_normal_behavior_and_no_external_control():
    value = convert(catalog())
    text = render_firmware_capability(value)
    assert text == render_firmware_capability(convert(catalog()))
    first_screen = text.split('## 当前已建立')[0]
    assert '正常固件行为' in first_screen
    assert 'NOT ESTABLISHED' in first_screen
    assert '0x100080' in text and '0x100346' in text
    assert '不证明跳转边被取用' in text
    assert '## 当前缺口' in text
    assert '源指令退休不是未来输入可触发性的保证' in text


def test_synthetic_report_keeps_bounds_and_control_dimensions():
    text = render_firmware_capability(build())
    assert 'test-only' in text and '不是真实漏洞证据' in text
    assert '0x20000000 至 0x2000000f' in text
    assert '控制位掩码 0xff' in text
    assert '范围受限的写入' in text
    assert '不表示任意控制' in text


def test_input_influenced_report_does_not_claim_external_control():
    data = synthetic_input()
    data['primitives'][0]['control']['status'] = 'input_influenced'
    text = render_firmware_capability(build(data))
    assert '外部控制：NOT ESTABLISHED' in text
    assert '输入影响；不等于外部可控' in text


def test_indirect_unknown_report_and_markup_escaping():
    text = render_firmware_capability(convert(catalog(indirect=True)))
    assert '具体目标：UNKNOWN' in text
    data = synthetic_input()
    data['conditions'][0]['description'] = '<script>raw</script> | newline\ntext'
    text = render_firmware_capability(build(data))
    assert '<script>' not in text and '&#124;' in text


def test_report_is_stable_across_set_permutations():
    data = synthetic_input()
    data['scope']['assumptions'] = ['z', 'a']
    first = render_firmware_capability(build(data))
    data['scope']['assumptions'].reverse()
    assert render_firmware_capability(build(data)) == first
