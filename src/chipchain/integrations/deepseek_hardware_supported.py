"""Predetermined Hardware B2 experiment: one attempt per case, no retries/tuning."""
import argparse
from dataclasses import dataclass, replace
import json
import logging
import os
from pathlib import Path
from uuid import uuid4

from langsmith import tracing_context

from chipchain.agents.contracts import HardwareAgentInput
from chipchain.agents.hardware import HardwareSecurityAgent
from chipchain.agents.hardware_support import HardwareSupportError, revalidate_hardware_support_artifact
from chipchain.agents.hardware_support_diagnostics import serialize_hardware_support_failure
from chipchain.agents.model_outputs.hardware_v2 import hardware_model_schema_sha256
from chipchain.agents.prompts.hardware_v3 import PROMPT_DESCRIPTOR, PROMPT_SHA256
from chipchain.agents.projections.hardware_relations import (
    HardwareRelationProjection, build_hardware_relation_projection, serialize_hardware_relation_projection, hardware_relation_projection_sha256,
)
from chipchain.agents.projections.hardware_envelope import HardwareAnalysisEnvelopeV2, build_hardware_envelope, serialize_hardware_envelope
from chipchain.agents.runtime import AgentStructuredOutputError
from chipchain.domain.provenance import AgentRole
from chipchain.execution.provenance import capture_provenance
from chipchain.execution.runner import analysis_run_from_state, utc_now
from chipchain.integrations.deepseek import (
    DeepSeekConfig, DeepSeekConfigurationError, build_deepseek_chat_model, load_deepseek_config, require_real_opt_in,
)
from chipchain.integrations.deepseek_hardware import _check_secret
from chipchain.integrations.hardware_typed_relations import prepare_local_catalog
from chipchain.tools.hardware.relations import HardwareRelationCatalog, canonical_json, sha256_text, hardware_relation_catalog_sha256, serialize_hardware_relation_catalog
from chipchain.workflows.state import CaseWorkflowState

HARDWARE_B2_RELATION_MAX_TOKENS = 16384
FROZEN_A3 = {
    '743': (29316, 'e9f0da2fea7df21b9a028c38b685292895d160ad3b521b77e4bd568cace23753'),
    '820': (18257, '5715a6e9a2ad6611c4f8c03767a7da89490ca471cad1030a47fca56de1311dda'),
}


@dataclass
class PreparedHardwareB2:
    inputs: HardwareAgentInput
    catalog: HardwareRelationCatalog
    projection: HardwareRelationProjection
    envelope: HardwareAnalysisEnvelopeV2

    def identities(self):
        context = serialize_hardware_envelope(self.envelope)
        return dict(case_id=self.inputs.case.case_id, prompt_id=PROMPT_DESCRIPTOR.prompt_id,
            prompt_version=PROMPT_DESCRIPTOR.prompt_version, prompt_sha256=PROMPT_SHA256,
            schema_sha256=hardware_model_schema_sha256(),
            b1_context_sha256=self.envelope.bindings.b1_context_sha256,
            a3_catalog_sha256=hardware_relation_catalog_sha256(self.catalog),
            projection_version=self.projection.schema_version,
            projection_characters=len(serialize_hardware_relation_projection(self.projection)),
            projection_sha256=hardware_relation_projection_sha256(self.projection),
            envelope_version=self.envelope.schema_version, envelope_characters=len(context),
            envelope_sha256=sha256_text(context))


def prepare_supported_hardware(sample: Path):
    inputs, catalog = prepare_local_catalog(sample)
    expected = FROZEN_A3.get(sample.name)
    if expected != (len(serialize_hardware_relation_catalog(catalog)), hardware_relation_catalog_sha256(catalog)):
        raise ValueError('Frozen A3 catalog preflight failed')
    projection = build_hardware_relation_projection(catalog)
    target = 18000 if sample.name == '743' else 14000
    if len(serialize_hardware_relation_projection(projection)) > target:
        raise ValueError('Real relation projection exceeds target')
    envelope = build_hardware_envelope(inputs, catalog, projection)
    return PreparedHardwareB2(inputs, catalog, projection, envelope)


def source_snapshot(root: Path):
    paths = [p for folder in ('src', 'tests', 'scripts') for p in (root / folder).rglob('*')
             if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py', '.java', '.json', '.toml')]
    paths += [root / 'pyproject.toml']
    return {str(p.relative_to(root)): sha256_text(p.read_text()) for p in sorted(paths)}


def _write_documents(directory, documents, config):
    # Validate all content before writing any accepted file. Roll back only files
    # exclusively created by this call on IO failure; never remove older outputs.
    for value in documents.values():
        _check_secret(value, config)
    if any((directory / name).exists() for name in documents):
        raise FileExistsError('Output already exists')
    created = []
    try:
        for name, value in documents.items():
            path = directory / name
            with path.open('x', encoding='utf-8') as handle:
                created.append(path)
                handle.write(value)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def run_supported_hardware(prepared, *, config: DeepSeekConfig, enabled: bool, output_root: Path):
    require_real_opt_in(enabled)
    if config.model != 'deepseek-flash' or config.temperature != 0 or config.timeout != 180:
        raise DeepSeekConfigurationError('Hardware B2 requires deepseek-flash, temperature 0, timeout 180')
    config = replace(config, max_tokens=HARDWARE_B2_RELATION_MAX_TOKENS)
    # Full binding and schema/projection identity checks BEFORE reserving/calling.
    expected_context = serialize_hardware_envelope(build_hardware_envelope(
        prepared.inputs, prepared.catalog, prepared.projection))
    if expected_context != serialize_hardware_envelope(prepared.envelope):
        raise ValueError('Prepared envelope drift')
    _check_secret(expected_context, config)
    identities = prepared.identities()
    before = prepared.inputs.model_dump_json()
    stub_ir = HardwareSecurityAgent().invoke(prepared.inputs).processor_behavior_ir
    case_id = prepared.inputs.case.case_id
    if case_id in ('.', '..') or any(c in case_id for c in '/\\\x00'):
        raise ValueError('Unsafe output case ID')
    run_id = uuid4()
    directory = output_root / case_id / str(run_id)
    directory.mkdir(parents=True, exist_ok=False)
    started = utc_now()
    base = dict(**identities, run_id=str(run_id), requested_model=config.model, attempt_index=1,
        max_tokens=config.max_tokens, temperature=config.temperature, timeout_seconds=config.timeout,
        max_retries=0, thinking='disabled', structured_output_method='function_calling', strict=False)
    def record(data):
        text = canonical_json(data)
        _check_secret(text, config)
        with (directory / 'invocation_attempts.jsonl').open('a', encoding='utf-8') as handle:
            handle.write(text + '\n')
    record({**base, 'status': 'started', 'timestamp': started.isoformat()})
    agent = None
    phase = 'provider_setup'
    previous_logging = logging.root.manager.disable
    accepted_names = ('analysis_run.json', 'hardware_analysis_report.json', 'hardware_relation_support.json',
                      'analysis_input.json', 'invocation.json')
    try:
        logging.disable(logging.CRITICAL)
        with tracing_context(enabled=False):
            model = build_deepseek_chat_model(config)
            agent = HardwareSecurityAgent(model=model, structured_output_method='function_calling')
            phase = 'provider_execution'
            output, support = agent.invoke_supported(prepared.inputs, relation_catalog=prepared.catalog,
                                                     relation_projection=prepared.projection)
        phase = 'provider_identity'
        returned = agent.last_response_metadata.get('model_name', agent.last_response_metadata.get('model'))
        if returned != config.model:
            raise ValueError('Provider model identity mismatch')
        phase = 'deterministic_integrity'
        if prepared.inputs.model_dump_json() != before or output.processor_behavior_ir != stub_ir:
            raise ValueError('Deterministic IR/input drift')
        revalidate_hardware_support_artifact(support, output.report, prepared.inputs, prepared.catalog)
        provenance = capture_provenance(prompts=[PROMPT_DESCRIPTOR], models=[config.descriptor(AgentRole.HARDWARE)],
            tools=[prepared.catalog.source.operational_projection, *prepared.catalog.source.decoder_descriptors])
        state = CaseWorkflowState(case=prepared.inputs.case, hardware_status='completed',
                                  hardware_report=output.report, processor_behavior_ir=output.processor_behavior_ir)
        run = analysis_run_from_state(state, run_id=run_id, started_at=started, finished_at=utc_now(), provenance=provenance)
        counts = {k: getattr(support, k) for k in type(support).model_fields if k.endswith('_count')}
        invocation = {**base, 'returned_model': returned, 'usage': agent.last_usage,
            'finish_reason': agent.last_response_metadata.get('finish_reason'), 'stub_ir_equal': True,
            'structured_parsing': 'passed', 'support_validation': 'passed', **counts}
        phase = 'persistence'
        _write_documents(directory, {
            'analysis_run.json': run.model_dump_json(indent=2),
            'hardware_analysis_report.json': output.report.model_dump_json(indent=2),
            'hardware_relation_support.json': support.model_dump_json(indent=2),
            'analysis_input.json': expected_context,
            'invocation.json': canonical_json(invocation),
        }, config)
        record({**base, 'status': 'succeeded', 'timestamp': utc_now().isoformat(),
                'returned_model': returned, 'usage': agent.last_usage,
                'finish_reason': agent.last_response_metadata.get('finish_reason')})
        return dict(directory=str(directory), status='succeeded', stop_experiment=False)
    except Exception as exc:
        # No provider/parser exception messages, chained inputs, or model prose.
        category = exc.failure_category if isinstance(exc, AgentStructuredOutputError) else phase
        reason = exc.reason_code if isinstance(exc, HardwareSupportError) else (
            'schema_or_tool_response' if category == 'structured_output_parsing' else 'execution_or_persistence')
        metadata = agent.last_response_metadata if agent else {}
        returned = metadata.get('model_name', metadata.get('model'))
        stop = phase in ('provider_setup', 'provider_identity', 'deterministic_integrity', 'persistence')
        if returned is not None and returned != config.model:
            stop = True
        diagnostic = getattr(exc, 'failure_diagnostic', None)
        diagnostic_text = None
        if diagnostic is not None:
            try:
                diagnostic_text = serialize_hardware_support_failure(diagnostic)
                _check_secret(diagnostic_text, config)
            except Exception:
                diagnostic_text = None
                # Byte cap is an anticipated omission. Secret safety stops the experiment.
                try:
                    _check_secret(diagnostic.model_dump_json(), config)
                except Exception:
                    stop = True
        failure = {**base, 'status': 'failed', 'timestamp': utc_now().isoformat(),
            'failure_category': category, 'reason_code': reason,
            'usage': agent.last_usage if agent else {}, 'finish_reason': metadata.get('finish_reason'),
            'returned_model': returned, 'parse_stage': agent.last_parse_stage if agent else None,
            'diagnostic_persisted': diagnostic_text is not None,
            'diagnostic_sha256': sha256_text(diagnostic_text) if diagnostic_text is not None else None,
            'failed_referenced_count': getattr(exc, 'failed_count', 0), 'stop_experiment': stop}
        # If persistence failed after accepted writes, remove only this new run's
        # accepted files; no partial canonical success may survive an exception.
        for name in accepted_names:
            (directory / name).unlink(missing_ok=True)
        documents = {'failure.json': canonical_json(failure)}
        if diagnostic_text is not None:
            documents['hardware_relation_support_failure.json'] = diagnostic_text
        _write_documents(directory, documents, config)
        record(failure)
        return dict(directory=str(directory), status='failed', stop_experiment=stop)
    finally:
        logging.disable(previous_logging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus-root', type=Path, required=True)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--freeze-manifest', type=Path, required=True,
                        help='Previously reviewed local source and prepared identity manifest')
    args = parser.parse_args()
    require_real_opt_in(os.environ.get('CHIPCHAIN_ENABLE_REAL_LLM') == '1')
    frozen = json.loads(args.freeze_manifest.read_text())
    root = Path.cwd()
    prepared = [prepare_supported_hardware(args.corpus_root / 'driver' / sample) for sample in ('743', '820')]
    if frozen['source'] != source_snapshot(root) or frozen['identities'] != [p.identities() for p in prepared]:
        raise ValueError('Pre-call source/model-visible identity freeze mismatch')
    config = load_deepseek_config(os.environ, agent_role=AgentRole.HARDWARE, env_file=args.env_file)
    for item in prepared:
        if frozen['source'] != source_snapshot(root):
            raise ValueError('Source drift; experiment stopped')
        result = run_supported_hardware(item, config=config, enabled=True, output_root=Path('output'))
        print(canonical_json(result), flush=True)
        if frozen['source'] != source_snapshot(root) or result['stop_experiment']:
            raise ValueError('Integrity/safety failure; experiment stopped')


if __name__ == '__main__':
    main()
