"""Explicit A5 fresh preparation and optional persistence, with no model invocation."""
import argparse
from collections import Counter
import json
from pathlib import Path
from uuid import uuid4

from chipchain.tools.firmware.angr_cfg import recover_firmware_angr_cfg, relevant_sites
from chipchain.tools.firmware.static_reachability import (
    build_static_reachability, serialize_firmware_angr_cfg, serialize_firmware_static_reachability,
    firmware_angr_cfg_sha256, firmware_static_reachability_sha256,
)


def prepare_a5(corpus_root,ghidra_home):
    # Reuse only frozen deterministic preparation functions, never construct an Agent.
    from chipchain.integrations.deepseek_firmware import prepare_firmware_input
    from chipchain.integrations.firmware_relations import prepare_relation_context
    inputs=prepare_firmware_input(Path(corpus_root))
    relevant,source,a4,*_=prepare_relation_context(inputs,Path(ghidra_home))
    return inputs,source,relevant,a4


def run_a5(inputs,source,relevant,a4):
    elf=next(a for a in inputs.case.firmware_artifacts if a.artifact_id==a4.source_identities.elf_artifact_id)
    cfg=recover_firmware_angr_cfg(inputs,source,relevant,a4,elf_path=Path(elf.path))
    reach=build_static_reachability(cfg,relevant_sites(a4))
    return cfg,reach


def summary(cfg,reach):
    return dict(case_id=cfg.identities.case_id,versions=cfg.identities.versions,loader=cfg.loader,
        loader_diagnostics=cfg.loader_diagnostics,selected_functions=len(cfg.function_bindings),
        bindings=dict(Counter(b.binding_status for b in cfg.function_bindings)),
        cfg_functions=cfg.total_function_count,cfg_nodes=cfg.total_node_count,cfg_edges=cfg.total_edge_count,
        selected_nodes=len(cfg.nodes),selected_edges=len(cfg.edges),function_edges=len(cfg.function_edges),
        transfer_comparisons={kind:dict(Counter(c.comparison_status for c in cfg.transfer_comparisons if c.a4_kind==kind))
            for kind in ('direct_call','direct_branch','control_transfer_unresolved')},
        pair_queries=len(reach.function_reachability),function_statuses=dict(Counter(f.status for f in reach.function_reachability)),
        site_queries=len(reach.site_reachability),site_statuses=dict(Counter(f.status for f in reach.site_reachability)),
        cfg_characters=len(serialize_firmware_angr_cfg(cfg)),cfg_sha256=firmware_angr_cfg_sha256(cfg),
        reachability_characters=len(serialize_firmware_static_reachability(reach)),reachability_sha256=firmware_static_reachability_sha256(reach))


def main():
    p=argparse.ArgumentParser(description='Fresh deterministic A5; no LLM or symbolic exploration')
    p.add_argument('--corpus-root',type=Path,required=True);p.add_argument('--ghidra-home',type=Path,required=True)
    p.add_argument('--output-root',type=Path,help='Explicitly persist both catalogs under case/new run UUID')
    a=p.parse_args()
    inputs,source,relevant,a4=prepare_a5(a.corpus_root,a.ghidra_home)
    cfg,reach=run_a5(inputs,source,relevant,a4)
    metrics=summary(cfg,reach)
    if a.output_root:
        directory=a.output_root/inputs.case.case_id/str(uuid4());directory.mkdir(parents=True,exist_ok=False)
        (directory/'firmware_angr_cfg.json').write_text(serialize_firmware_angr_cfg(cfg))
        (directory/'firmware_static_reachability.json').write_text(serialize_firmware_static_reachability(reach))
        (directory/'a5_summary.json').write_text(json.dumps(metrics,sort_keys=True,indent=2)+'\n')
        print('Output:',directory)
    print(json.dumps(metrics,sort_keys=True))


if __name__=='__main__':main()
