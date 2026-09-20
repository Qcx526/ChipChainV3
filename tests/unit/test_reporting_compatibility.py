"""Synthetic output oracles from the immutable A6 renderer, not the new facade.

Golden SHA256 covers the complete UTF-8 output, including whitespace and links.
Generated before relocation from v3-fw-a6-stable (39e72ee3a5cc1dd2eb1bb3db10ed218b93894c5e).
Do not regenerate to accommodate a refactor failure; investigate baseline parity.
No Git checkout, local real artifacts or provider are needed to run these tests.
"""
import hashlib
import json
import builtins
import importlib
import io
import os
import sys

import pytest


# Generated once by executing the renderer from the frozen Git object.
BASELINE_ORACLES = {'supported_rejected': {'bytes': 2968,
                        'sha256': '7557f14a99085fe74a7781366565f62fa5cd94d85b67fe4cdb3122fb5484948b'},
 'missing_validation': {'bytes': 1952,
                        'sha256': 'e05a9b47f7340b682863f4ada842e51257d322ecd59cd3e67a7a19f6f068e0e7'},
 'candidate_exists': {'bytes': 2240,
                      'sha256': 'e7353e594c5170f5585afe6c0fd918cf95eabd7399ac3158aea134ce5c65c949'}}


def synthetic_artifacts(scenario):
    """Small renderer-input documents; no real provider responses or paths."""
    artifacts = {
        'analysis_run.json': {
            'status': 'completed',
            'stages': [{'stage': 'hardware', 'status': 'completed'},
                       {'stage': 'firmware', 'status': 'completed'},
                       {'stage': 'cross_layer', 'status': 'completed'}],
        },
    }
    if scenario == 'missing_validation':
        artifacts['analysis_run.json'] = {
            'status': 'failed', 'stages': [{'stage': 'firmware', 'status': 'failed'}],
        }
        return artifacts
    artifacts.update({
        'research_validation.json': {'validation_context': 'synthetic_renderer_parity'},
        'firmware_model_claims.diagnostic.json': {'claims': []},
        'firmware_support_validation.json': {
            'results': [], 'accepted_claim_ids': [], 'rejected_claim_ids': [],
        },
        'cross_layer_analysis_report.json': {'candidates': []},
    })
    if scenario == 'candidate_exists':
        artifacts['cross_layer_analysis_report.json']['candidates'] = [{'candidate_id': 'synthetic-candidate'}]
        artifacts['cross_layer_invocation.json'] = {
            'model': 'synthetic-request', 'response_metadata': {'model': 'synthetic-return'},
        }
        return artifacts
    assert scenario == 'supported_rejected'
    artifacts['firmware_model_claims.diagnostic.json']['claims'] = [
        {'claim_id': 'supported', 'claim_type': 'control_transfer_target',
         'instruction_pc': 0x1000, 'claimed_target_pc': 0x1004,
         'raw_model_summary': '模型原文<&|>\n仅诊断'},
        {'claim_id': 'rejected', 'claim_type': 'function_ownership',
         'site_pc': 0x2004, 'owner_function_id': 'wrong-owner',
         'raw_model_summary': '错误归属原文：保留，不改写'},
    ]
    artifacts['firmware_support_validation.json'] = {
        'results': [
            {'claim_id': 'supported', 'status': 'supported',
             'reason_code': 'exact_control_transfer_target',
             'canonical_interpretation': '确定性目标为 0x1004；静态事实。',
             'evidence': [{'artifact_id': 'synthetic-elf', 'evidence_id': 'ev-target',
                           'location': {'address': 0x1000}}]},
            {'claim_id': 'rejected', 'status': 'incompatible',
             'reason_code': 'function_ownership_mismatch',
             'canonical_interpretation': '确定性归属为 synthetic-owner，区间 [0x2000,0x2008)。',
             'evidence': [{'artifact_id': 'synthetic-elf', 'evidence_id': 'ev-owner',
                           'location': {'address': 0x2004, 'function': 'synthetic_owner'}}]},
        ],
        'accepted_claim_ids': ['supported'], 'rejected_claim_ids': ['rejected'],
    }
    for role in ('hardware', 'firmware'):
        artifacts[role + '_invocation.json'] = {
            'model': 'synthetic-request',
            'usage': {'input_tokens': 10, 'output_tokens': 3, 'total_tokens': 13},
            'response_metadata': {'model_name': 'synthetic-return', 'finish_reason': 'tool_calls'},
        }
    return artifacts


def write_synthetic_artifacts(directory, scenario):
    for name, value in synthetic_artifacts(scenario).items():
        (directory / name).write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')


@pytest.mark.parametrize('scenario', ['supported_rejected', 'missing_validation', 'candidate_exists'])
def test_frozen_a6_renderer_output_parity(tmp_path, scenario):
    from chipchain.reporting.firmware_grounding import render_report

    write_synthetic_artifacts(tmp_path, scenario)
    text = render_report(tmp_path)
    encoded = text.encode('utf-8')
    expected = BASELINE_ORACLES[scenario]
    assert len(encoded) == expected['bytes']
    assert hashlib.sha256(encoded).hexdigest() == expected['sha256']
    if scenario == 'supported_rejected':
        for value in ('Raw Model Claim', 'Deterministic Fact', 'Validation Status',
                      'Corrected/Canonical Interpretation', 'supported：exact_control_transfer_target',
                      'incompatible：function_ownership_mismatch', 'synthetic-elf / ev-target',
                      '模型原文&lt;&amp;\\|&gt; 仅诊断', '错误归属原文：保留，不改写',
                      '不能据此声称平台安全', '调用记录 2 条，已记录总用量 26 tokens'):
            assert value in text
    elif scenario == 'missing_validation':
        assert '未产生可用的 A6 声明校验结果' in text
        assert '跨层报告不可用；不将阻塞或失败解释为没有候选。' in text
    else:
        assert '本轮提出 1 个候选；仍需独立验证。' in text
        assert 'synthetic-return' in text and 'unknown' in text


def test_old_and_new_renderer_imports_are_identical():
    from chipchain.firmware.grounding_report import render_report as old
    from chipchain.reporting.firmware_grounding import render_report as new

    assert old is new
    assert new.__module__ == 'chipchain.reporting.firmware_grounding'


def test_reporting_import_has_no_provider_or_write_side_effects(monkeypatch):
    # Respect the suite's no-subprocess boundary. Evict only the reporting modules;
    # intercept provider imports even if other tests already cached those providers.
    names = ('chipchain.reporting', 'chipchain.reporting.firmware_grounding',
             'chipchain.firmware.grounding_report')
    missing = object()
    saved_modules = {name: sys.modules.get(name, missing) for name in names}
    parents = [(importlib.import_module('chipchain'), 'reporting'),
               (importlib.import_module('chipchain.firmware'), 'grounding_report')]
    saved_attributes = [(parent, name, getattr(parent, name, missing)) for parent, name in parents]
    original_import = builtins.__import__
    forbidden_prefixes = ('chipchain.agents', 'chipchain.integrations', 'langchain',
                          'langchain_core', 'langchain_deepseek', 'langgraph', 'openai', 'httpx', 'logging')

    def guarded_import(name, *args, **kwargs):
        assert not any(name == prefix or name.startswith(prefix + '.')
                       for prefix in forbidden_prefixes), name
        return original_import(name, *args, **kwargs)

    def read_only(original):
        def guarded(file, mode='r', *args, **kwargs):
            assert not any(flag in mode for flag in 'wax+'), 'import attempted file write'
            return original(file, mode, *args, **kwargs)
        return guarded

    def forbidden(*args, **kwargs):
        raise AssertionError('Import attempted filesystem mutation')

    with monkeypatch.context() as guard:
        guard.setattr(sys, 'dont_write_bytecode', True)
        guard.setattr(builtins, '__import__', guarded_import)
        guard.setattr(builtins, 'open', read_only(builtins.open))
        guard.setattr(io, 'open', read_only(io.open))
        for name in ('mkdir', 'remove', 'unlink', 'rename', 'replace', 'rmdir', 'chmod'):
            guard.setattr(os, name, forbidden)
        for name in names:
            sys.modules.pop(name, None)
        try:
            new = importlib.import_module('chipchain.reporting.firmware_grounding')
            old = importlib.import_module('chipchain.firmware.grounding_report')
            assert old.render_report is new.render_report
        finally:
            for name, value in saved_modules.items():
                sys.modules.pop(name, None)
                if value is not missing:
                    sys.modules[name] = value
            for parent, name, value in saved_attributes:
                if value is missing:
                    if hasattr(parent, name):
                        delattr(parent, name)
                else:
                    setattr(parent, name, value)
