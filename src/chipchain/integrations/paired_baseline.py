"""Explicit Ibex baseline simulation -> observations -> three real model stages.

Experimental generic evidence binding, not typed relation-support certification.
No mutation, retry loop, reviewed export, or automatic calls from normal workflows.
"""

import argparse
from collections import Counter
from dataclasses import replace
import hashlib
import json
import logging
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from pydantic import ValidationError

from langsmith import tracing_context

from chipchain.agents.context import hardware_context, firmware_context, cross_layer_context
from chipchain.integrations.paired_agents import BoundHardwareAgent, BoundCrossLayerAgent
from chipchain.agents.firmware import FirmwareSecurityAgent
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.agents.prompts import hardware, firmware, cross_layer
from chipchain.domain.case import CaseBundle
from chipchain.domain.provenance import AgentRole, ToolDescriptor
from chipchain.execution.provenance import capture_provenance
from chipchain.execution.runner import run_case, utc_now
from chipchain.integrations.deepseek import load_deepseek_config, build_deepseek_chat_model, require_real_opt_in
from chipchain.integrations.deepseek_hardware import validate_real_report
from chipchain.tools.paired.ibex import prepare_inputs, VERSION
from chipchain.workflows.case import build_case_workflow


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_cross_references(report, inputs):
    """Exact binding only. It cannot establish prose entailment or causality."""
    behavior_ids = {b.behavior_id for b in inputs.processor_behavior_ir.behaviors}
    evidence = {}
    for b in inputs.processor_behavior_ir.behaviors:
        for ref in b.evidence:
            evidence[ref.evidence_id] = ref
    for side in (inputs.hardware_report, inputs.firmware_report):
        for field in type(side).model_fields:
            value = getattr(side, field)
            if isinstance(value, list):
                for item in value:
                    for ref in getattr(item, 'evidence', []):
                        if ref.evidence_id in evidence and evidence[ref.evidence_id] != ref:
                            raise AgentStructuredOutputError('Conflicting cross-layer evidence')
                        evidence[ref.evidence_id] = ref
    groups = [report.candidates, report.attack_chain_candidates, report.trigger_features, report.root_location_candidates]
    for group, id_field in zip(groups, ['candidate_id', 'candidate_id', 'feature_id', 'candidate_id']):
        ids = [getattr(item, id_field) for item in group]
        if len(ids) != len(set(ids)):
            raise AgentStructuredOutputError('Duplicate cross-layer item ID')
        for item in group:
            if not item.evidence or any(evidence.get(e.evidence_id) != e for e in item.evidence):
                raise AgentStructuredOutputError('Unbound cross-layer evidence')
            refs = getattr(item, 'processor_behavior_ids', getattr(item, 'ordered_processor_behavior_ids', []))
            if not set(refs) <= behavior_ids:
                raise AgentStructuredOutputError('Unbound cross-layer behavior')
    candidate_ids = {c.candidate_id for c in report.candidates}
    for item in report.candidates:
        if (not set(item.hardware_finding_ids) <= {f.finding_id for f in inputs.hardware_report.findings}
                or not set(item.firmware_finding_ids) <= {f.finding_id for f in inputs.firmware_report.findings}):
            raise AgentStructuredOutputError('Unbound cross-layer finding')
    for item in report.attack_chain_candidates:
        if not set(item.cross_layer_candidate_ids) <= candidate_ids:
            raise AgentStructuredOutputError('Unbound attack-chain candidate')
    for item in report.trigger_features:
        if not set(item.candidate_ids) <= candidate_ids:
            raise AgentStructuredOutputError('Unbound trigger candidate')


class RecordedAgent:
    def __init__(self, role, agent, config, directory, write):
        self.role, self.agent, self.config, self.directory, self.write = role, agent, config, directory, write

    def invoke(self, inputs):
        context = (self.agent.context(inputs) if hasattr(self.agent, 'context') else
                   {'hardware': hardware_context, 'firmware': firmware_context,
                    'cross_layer': cross_layer_context}[self.role](inputs))
        self.write(f'{self.role}_analysis_input.json', context)
        record = dict(role=self.role, model=self.config.model, provider='deepseek',
                      started_at=utc_now().isoformat(), status='started', max_retries=0,
                      temperature=self.config.temperature, max_tokens=self.config.max_tokens,
                      timeout=self.config.timeout, context_characters=len(context),
                      context_sha256=hashlib.sha256(context.encode()).hexdigest())
        self.write(f'{self.role}_invocation_started.json', record)
        before = inputs.model_dump_json()
        try:
            output = self.agent.invoke(inputs)
            if inputs.model_dump_json() != before:
                raise AgentStructuredOutputError('Deterministic input changed')
            if self.role == 'hardware':
                validate_real_report(output)
            elif self.role == 'firmware':
                for group in ('findings', 'external_input_paths', 'reachable_behaviors', 'issue_anchors'):
                    for item in getattr(output.report, group):
                        if not item.evidence or item.epistemic_status == 'verified':
                            raise AgentStructuredOutputError('Firmware claim lacks evidence or asserts verification')
            else:
                validate_cross_references(output.report, inputs)
            record['status'] = 'succeeded'
            self.write(f'{self.role}_analysis_report.json', output.report.model_dump_json(indent=2))
            return output
        except Exception as exc:
            cause = exc
            seen = set()
            while cause is not None and id(cause) not in seen:
                seen.add(id(cause))
                if isinstance(cause, ValidationError):
                    record['validation_error_types'] = dict(Counter(e['type'] for e in
                        cause.errors(include_input=False, include_context=False, include_url=False)))
                    break
                cause = cause.__cause__
            record.update(status='failed', error_type=type(exc).__name__,
                          failure_category=getattr(exc, 'failure_category', 'agent_execution'))
            raise
        finally:
            runtime = self.agent._runtime
            record.update(finished_at=utc_now().isoformat(), usage=runtime.last_usage,
                          response_metadata=runtime.last_response_metadata, parse_stage=runtime.last_parse_stage)
            self.write(f'{self.role}_invocation.json', record)


def run_paired_baseline(*, root: Path, env_file: Path, output_root: Path, enabled: bool, firmware_grounding: bool = False, a4_catalog=None, a5_cfg=None) -> Path:
    require_real_opt_in(enabled)
    root = root.resolve()
    hw_config = replace(load_deepseek_config(os.environ, env_file=env_file), max_tokens=16384)
    fw_config = replace(load_deepseek_config(os.environ, env_file=env_file, agent_role=AgentRole.FIRMWARE), max_tokens=16384)
    # Explicitly use hardware model configuration for the cross-layer pilot.
    configs = {'hardware': hw_config, 'firmware': fw_config, 'cross_layer': hw_config}
    freeze_path = root / 'output/paired/ibex-simple-system/data1a-r1/experiment-freeze.json'
    freeze = json.loads(freeze_path.read_text())
    template = CaseBundle.model_validate_json((root / 'samples/firmware/ibex-simple-system/hello-test/paired-case.json').read_text())
    elf = root / 'samples/firmware/ibex-simple-system/hello-test/hello_test.elf'
    sim = root / 'samples/hardware/ibex-simple-system/bin/Vibex_simple_system'
    for path, key in [(elf, 'elf'), (sim, 'simulator')]:
        if digest(path) != freeze[key]['sha256'] or path.stat().st_size != freeze[key]['size_bytes']:
            raise ValueError('Local baseline artifact differs from frozen identity')
    from chipchain.cross_layer.eligibility import parse_cross_layer_pair, cross_layer_pair_sha256
    pair = parse_cross_layer_pair((freeze_path.parent / 'cross_layer_pair_descriptor.json').read_text())
    if pair.eligibility != 'eligible' or cross_layer_pair_sha256(pair) != template.metadata['frozen_pair_descriptor_sha256']:
        raise ValueError('Frozen pair eligibility or identity mismatch')
    run_id = uuid4(); out = output_root.resolve() / template.case_id / str(run_id)
    out.mkdir(parents=True, exist_ok=False)

    def write(name, data):
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False, indent=2)
        if any(config.api_key.get_secret_value() in text for config in configs.values()):
            raise ValueError('Secret detected in output')
        with (out / name).open('x') as f:
            f.write(text + '\n')

    command = [str(sim), '-t', '--meminit=ram,' + str(elf)]
    write('execution_plan.json', dict(run_id=str(run_id), command=command, elf_sha256=digest(elf),
        simulator_sha256=digest(sim), freeze_sha256=digest(freeze_path),
        models={role: cfg.model for role, cfg in configs.items()}, retries=0,
        cross_layer_model_configuration='same as hardware',
        relation_support='A6 firmware target and ownership gate' if firmware_grounding else 'generic evidence binding only',
        environment_overrides=freeze['environment_overrides']))
    simulation = out / 'simulation'; simulation.mkdir()
    env = dict(os.environ); env.update(freeze['environment_overrides'])
    with (simulation / 'stdout.log').open('x') as stdout, (simulation / 'stderr.log').open('x') as stderr:
        process = subprocess.run(command, cwd=simulation, env=env, stdout=stdout, stderr=stderr, timeout=120)
    write('simulation_invocation.json', dict(exit_code=process.returncode, command=command))
    if process.returncode != 0:
        raise ValueError('Baseline simulation failed; no model invoked')
    case, hw, fw, audit = prepare_inputs(template, elf_path=elf,
        trace_path=simulation / 'trace_core_00000000.log', stdout_path=simulation / 'stdout.log',
        ascii_path=simulation / 'ibex_simple_system.log')
    write('case.json', case.model_dump_json(indent=2))
    write('hardware_observations.json', hw.model_dump_json(indent=2))
    write('firmware_observations.json', fw.model_dump_json(indent=2))
    write('input_audit.json', audit)
    write('implementation_manifest.json', [{'path': str(p.relative_to(root)), 'sha256': digest(p)}
        for p in sorted((root / 'src/chipchain').rglob('*.py'))])
    a6_catalog = None
    if firmware_grounding:
        from chipchain.firmware.grounding_catalog import build_catalog
        from chipchain.firmware.control_flow_grounding import serialize_catalog
        a6_catalog = build_catalog(case_id=case.case_id, elf_path=elf,
            trace_path=simulation / 'trace_core_00000000.log', target=case.target,
            trace_semantics='ibex_rvfi_retirement')
        write('firmware_control_flow_grounding.json', serialize_catalog(a6_catalog))
        from chipchain.firmware.grounding_compatibility import compatibility_preflight
        compatibility_preflight(a6_catalog, write=write, a4=a4_catalog, a5=a5_cfg)
        write('research_validation.json', dict(validation_context='paired_rtl_runtime_regression',
            fact_epistemic_status='deterministically_derived_static_facts_with_separate_observed_retirement',
            validation_level_policy='research-only; no global E0-E4 schema or automatic claim-level upgrade',
            analysis_access_is_not_target_input_controllability=True))
    original_inputs = (case.model_dump_json(), hw.model_dump_json(), fw.model_dump_json())
    old_logging = logging.root.manager.disable
    try:
        logging.disable(logging.CRITICAL)
        with tracing_context(enabled=False):
            agents = {}
            for role, cls in [('hardware', BoundHardwareAgent), ('firmware', FirmwareSecurityAgent),
                              ('cross_layer', BoundCrossLayerAgent)]:
                if role == 'firmware' and firmware_grounding:
                    from chipchain.firmware.grounded_agent import GroundedFirmwareAgent
                    sites = {e.location.address for o in fw.observations for b in o.behaviors for e in b.evidence
                             if e.location.address is not None}
                    agent = GroundedFirmwareAgent(model=build_deepseek_chat_model(configs[role]),
                        catalog=a6_catalog, selected_sites=sites, write=write)
                    write('firmware_control_flow_grounding_projection.json', agent.projection)
                else:
                    agent = cls(model=build_deepseek_chat_model(configs[role]), structured_output_method='function_calling')
                write(f'{role}_prompt.txt', agent._runtime.system_prompt)
                write(f'{role}_output_schema.json', agent._runtime.schema.model_json_schema())
                agents[role] = RecordedAgent(role, agent, configs[role], out, write)
            provenance = capture_provenance(
                prompts=[hardware.PROMPT_DESCRIPTOR.model_copy(update={'prompt_version': 'paired-binding-v1'}),
                         firmware.PROMPT_DESCRIPTOR.model_copy(update={'prompt_version': 'a6-grounded-v1'})
                         if firmware_grounding else firmware.PROMPT_DESCRIPTOR,
                         cross_layer.PROMPT_DESCRIPTOR.model_copy(update={'prompt_version': 'paired-binding-v1'})],
                models=[configs[role.value].descriptor(role) for role in AgentRole],
                tools=[ToolDescriptor(tool_name=VERSION, tool_role='paired_baseline_observer', tool_version='1'),
                       *([ToolDescriptor(tool_name='firmware-control-flow-grounding', tool_version='v1',
                            tool_role='firmware_deterministic_grounding')] if firmware_grounding else [])])
            workflow = build_case_workflow(hardware_agent=agents['hardware'], firmware_agent=agents['firmware'],
                cross_layer_agent=agents['cross_layer'], hardware_observer=lambda _: hw.model_copy(deep=True),
                firmware_observer=lambda _: fw.model_copy(deep=True))
            run = run_case(case, workflow=workflow, provenance=provenance, run_id_factory=lambda: run_id)
    finally:
        logging.disable(old_logging)
    if original_inputs != (case.model_dump_json(), hw.model_dump_json(), fw.model_dump_json()):
        raise ValueError('Input mutation detected')
    for artifact in [*case.hardware_artifacts, *case.firmware_artifacts]:
        if digest(Path(artifact.path)) != artifact.sha256:
            raise ValueError('Input artifact changed during analysis')
    write('analysis_run.json', run.model_dump_json(indent=2))
    if run.processor_behavior_ir is not None:
        write('processor_behavior_ir.json', run.processor_behavior_ir.model_dump_json(indent=2))
    if firmware_grounding:
        from chipchain.reporting.firmware_grounding import render_report
        write('report-zh.md', render_report(out))
    write('artifact_manifest.json', [{'path':str(p.relative_to(out)), 'sha256':digest(p), 'size_bytes':p.stat().st_size}
                                   for p in sorted(out.rglob('*')) if p.is_file()])
    print(json.dumps({'directory':str(out), 'status':run.status,
                      'stages':{s.stage:s.status for s in run.stages}}, ensure_ascii=False), flush=True)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--env-file', type=Path, default=Path('.env'))
    parser.add_argument('--output-root', type=Path, default=Path('output'))
    parser.add_argument('--firmware-grounding', action='store_true', help='Enable deterministic A6 firmware fact gate')
    args = parser.parse_args()
    try:
        directory = run_paired_baseline(root=args.root, env_file=args.env_file, output_root=args.output_root,
                                       enabled=os.environ.get('CHIPCHAIN_ENABLE_REAL_LLM') == '1', firmware_grounding=args.firmware_grounding)
        return 0 if json.loads((directory / 'analysis_run.json').read_text())['status'] == 'completed' else 1
    except Exception as error:
        print(json.dumps({'status':'failed', 'error_type':type(error).__name__,
                          'message':'Paired baseline run failed; inspect reserved output artifacts.'}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
