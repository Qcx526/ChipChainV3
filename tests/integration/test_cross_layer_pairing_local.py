"""Read existing local target metadata only; no ingest, tools, agents or new runs."""
import json
import os
from pathlib import Path

import pytest

from chipchain.cross_layer import PairNotEligible, build_cross_layer_pair, cross_layer_pair_sha256, match_trigger_condition
from chipchain.domain.case import TargetDescriptor

FIRMWARE_RUN = '104a5332-3cf3-4263-b988-8b5b0b82f14e'
HARDWARE_RUNS = {'743': 'e4636d59-ef13-42d3-ab19-acedb3b60143',
                 '820': '05660d2d-c2e7-480d-9758-6d75f0b9ff9b'}


@pytest.mark.parametrize('sample', ['743', '820'])
def test_real_heat_press_ibex_pair_is_ineligible(sample):
    root = Path(os.environ.get('CHIPCHAIN_XL0_OUTPUT_ROOT', Path(__file__).resolve().parents[2] / 'output'))
    firmware = root / 'fuzzware:heat-press:scenario-13' / FIRMWARE_RUN / 'analysis_input.json'
    hardware = root / f'encorpus:ibex:driver:{sample}' / HARDWARE_RUNS[sample] / 'analysis_input.json'
    if not firmware.is_file() or not hardware.is_file():
        pytest.skip('Existing local B2 analysis_input snapshots required; no analysis is launched')
    fw = json.loads(firmware.read_text())['firmware_projection']['case']
    hw = json.loads(json.loads(hardware.read_text())['b1_context'])['case']
    assert fw['target']['architecture'] == 'arm' and hw['target']['architecture'] == 'riscv'
    pair = build_cross_layer_pair(firmware_case_id=fw['case_id'], hardware_case_id=hw['case_id'],
        firmware_target=TargetDescriptor.model_validate(fw['target']),
        hardware_target=TargetDescriptor.model_validate(hw['target']))
    assert pair.eligibility == 'ineligible'
    assert pair.reasons == ['architecture_mismatch', 'target_identity_unbound']
    assert pair.board_or_processor_identity is None
    # Deliberately no condition or fact resolver: pair gate must run first.
    with pytest.raises(PairNotEligible, match='architecture_mismatch'):
        match_trigger_condition(pair=pair, condition=None, sources=None)
    print(f'{sample}: {pair.eligibility}; {pair.reasons}; descriptor SHA256={cross_layer_pair_sha256(pair)}')
