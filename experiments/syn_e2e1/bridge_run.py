"""Explicit offline joint collection using frozen A binaries; never rebuild A."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tempfile

from chipchain.firmware import mmio_grounding as b1
from chipchain.firmware import mmio_execution_bridge as bridge

FIRMWARE_SHAS = ('42fe38fb5c106242c81797ece513b5ef86fc453d2ef63299514d1e98e9c06641',
                 'd2d845e6b0395ae28e156d6e9b60d1afc32ac99124fb84d4b17741edfa1af920')
SIMULATOR_SHAS = dict(zip(bridge.APPROVED_TREES, (
    '92348a7a075602e6299d59e0f854ac8117856c0480813356173e0a8f667f0196',
    'e5c3cf4c5870c9c5f0ca9bbab501454e6bbf052e110f7f783d96ceb8a95d4b6c')))


def write(path, value):
    with Path(path).open('x') as f:
        f.write(value if isinstance(value, str) else b1.canonical(value)+'\n')


def prepare(root, upstream_manifest):
    root=Path(root).resolve();workspace=root/'output/syn-e2e1-a/experiment-tn2kt3tu'
    manifest_path=b1._local(workspace,upstream_manifest)
    manifest=b1.read_json(manifest_path.read_bytes());identity=manifest['identity_inputs']
    b1.require(identity['firmware_sha256'] in FIRMWARE_SHAS and identity['rtl_tree_sha256'] in bridge.APPROVED_TREES,'UNFROZEN_INPUT')
    static,runtime,_,map_source=b1.load_apparatus_run(workspace,upstream_manifest,
        base_source=root/'samples/hardware/ibex-simple-system/source',expected_base_sha=bridge.BASE_SHA,
        expected_rtl_sha=identity['rtl_tree_sha256'],expected_firmware_sha=identity['firmware_sha256'])
    name=('a','b')[bridge.APPROVED_TREES.index(identity['rtl_tree_sha256'])]
    platform=bridge.verify_platform(workspace/'sources'/name,(workspace/(name+'-source-files.json')).read_bytes(),map_source)
    elf=b1._local(workspace,manifest['firmware_path']);sim=b1._local(workspace,manifest['simulator_path'])
    b1.require(b1.file_sha(sim)==SIMULATOR_SHAS[identity['rtl_tree_sha256']],'UNFROZEN_SIMULATOR')
    recipe=b1.read_json((workspace/'build-recipe.json').read_bytes())
    b1.require(b1.digest(recipe)=='4807dacf3cf2ff3c901a8d31ee26fb91099e1fb41f05e95e849cfd202ebf3c91','UNFROZEN_RECIPE')
    b1.require(identity['input_sha256']=='86b6b68191083af8b0f4ea28fd864af23a470a2a17341406a49ca440d718a681','UNFROZEN_SOFTWARE_INPUT')
    b1.require(recipe['runtime_options']==['+verilator+seed+1','+verilator+rand+reset+0','--term-after-cycles=10000'], 'UNFROZEN_RUNTIME_OPTIONS')
    inputs={k:getattr(runtime.run_binding,k) for k in ('firmware_sha256','rtl_tree_sha256','simulator_sha256',
                                                      'input_sha256','execution_context_sha256')}
    return dict(workspace=workspace,manifest=manifest,static=static,map_source=map_source,platform=platform,
                elf=elf,sim=sim,recipe=recipe,inputs=inputs)


def consume_run(prepared, folder):
    """Re-read real files, including attestation, and re-materialize deterministically."""
    folder=Path(folder);p=prepared
    bus=(folder/'synthetic-mmio.jsonl').read_bytes();processor=(folder/'trace_core_00000000.log').read_bytes()
    stdout=(folder/'process.stdout.log').read_bytes();stderr=(folder/'process.stderr.log').read_bytes()
    b1.require(b1.file_sha(p['elf'])==p['inputs']['firmware_sha256'] and b1.file_sha(p['sim'])==p['inputs']['simulator_sha256'],'INPUT_CHANGED')
    runtime=b1.materialize_runtime(manifest_bytes=(folder/'b1-compat-manifest.json').read_bytes(),
        binding_bytes=(folder/'b1-trace-binding.json').read_bytes(),raw_trace_bytes=bus,
        parsed_trace_bytes=(folder/'parsed-bus-trace.json').read_bytes(),firmware=p['static'].firmware_artifact,
        map_source=p['map_source'],rtl_tree_sha256=p['inputs']['rtl_tree_sha256'],
        simulator_sha256=p['inputs']['simulator_sha256'],input_sha256=p['inputs']['input_sha256'],recipe=p['recipe'],
        stdout_bytes=stdout,stderr_bytes=stderr)
    joint=bridge.JointRun.model_validate_json((folder/'joint-run.json').read_text())
    result=bridge.materialize_bridge(joint=joint,static=p['static'],runtime=runtime,platform=p['platform'],inputs=p['inputs'],
        elf_bytes=p['elf'].read_bytes(),bus_bytes=bus,processor_bytes=processor,stdout_bytes=stdout,stderr_bytes=stderr)
    return joint,runtime,result


def execute(root):
    root=Path(root).resolve();workspace=root/'output/syn-e2e1-a/experiment-tn2kt3tu'
    parent=root/'output/syn-e2e1-bridge1';parent.mkdir(exist_ok=True)
    out=Path(tempfile.mkdtemp(prefix='joint-',dir=parent))
    try:
        items=b1.read_json((workspace/'apparatus-result.json').read_bytes())['runs']
        # All pins/trees/bindings checked before the first process starts.
        prepared=[prepare(root,item['manifest']) for item in items]
        b1.require({(p['inputs']['firmware_sha256'],p['inputs']['rtl_tree_sha256']) for p in prepared}
                   =={(f,t) for f in FIRMWARE_SHAS for t in bridge.APPROVED_TREES} and len(prepared)==4,'INPUT_SET')
        records=[]
        env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C',
             'LD_LIBRARY_PATH':'/home/qcx/ChipChainV3_res/toolchains/libelf-0.186/usr/lib/x86_64-linux-gnu',
             'LANGSMITH_TRACING':'false','LANGCHAIN_TRACING_V2':'false'}
        for item,p in zip(items,prepared):
            folder=out/b1.digest(p['inputs']);folder.mkdir()
            args=[str(p['sim']),'--meminit=ram,'+str(p['elf']),*p['recipe']['runtime_options']]
            write(folder/'local-command.json',args)
            with (folder/'process.stdout.log').open('xb') as stdout,(folder/'process.stderr.log').open('xb') as stderr:
                process=subprocess.run(args,cwd=folder,env=env,stdout=stdout,stderr=stderr,timeout=60)
            b1.require(process.returncode==0,'SIMULATION_FAILED')
            # Verify scientific inputs again after collection, before attesting.
            fresh=prepare(root,item['manifest']);b1.require(fresh['inputs']==p['inputs'],'INPUT_CHANGED_DURING_RUN')
            bus=(folder/'synthetic-mmio.jsonl').read_bytes();processor=(folder/'trace_core_00000000.log').read_bytes()
            stdout=(folder/'process.stdout.log').read_bytes();stderr=(folder/'process.stderr.log').read_bytes()
            joint=bridge.make_joint_run(inputs=p['inputs'],static=p['static'],elf_bytes=p['elf'].read_bytes(),platform=p['platform'],
                bus_bytes=bus,processor_bytes=processor,stdout_bytes=stdout,stderr_bytes=stderr,process_returncode=process.returncode)
            write(folder/'joint-run.json',b1.serialize(joint))
            parsed=b1.parse_apparatus_trace(bus.decode());write(folder/'parsed-bus-trace.json',parsed)
            # New-run B1 compatibility projection, NOT a retroactive A manifest.
            old=p['manifest'];compat={k:v for k,v in old.items() if k not in ('raw_trace_sha256','parsed_trace_sha256','stdout_sha256','stderr_sha256')}
            compat.update(raw_trace_sha256=b1.bytes_sha(bus),parsed_trace_sha256=b1.digest(parsed),
                          stdout_sha256=b1.bytes_sha(stdout),stderr_sha256=b1.bytes_sha(stderr),normal_exit=True,trace_complete=True)
            write(folder/'b1-compat-manifest.json',compat)
            binding={k:compat[k] for k in ('run_case_neutral_id','raw_trace_sha256','parsed_trace_sha256')}
            binding.update({k:p['inputs'][k] for k in ('firmware_sha256','rtl_tree_sha256')})
            write(folder/'b1-trace-binding.json',binding)
            joint,runtime,result=consume_run(p,folder)
            for filename,obj in (('static-mmio.json',p['static']),('runtime-mmio.json',runtime),('execution-bridges.json',result)):
                write(folder/filename,b1.serialize(obj))
            write(folder/'processor-observations.json',[o.model_dump(mode='json') for o in result.processor_observations])
            write(folder/'report-bridge1-zh.md',bridge.render_report(result,p['static']))
            records.append({'directory':folder.name,'upstream_manifest':item['manifest'],'joint_run_id':joint.joint_run_id,
                            'bridge_set_id':result.set_id,'inputs':p['inputs']})
        write(out/'local-reproduction-manifest.json',{'schema_version':'bridge1-local-reproduction/v1',
            'upstream_workspace':str(workspace),'collector_source_sha256':b1.file_sha(Path(__file__)),
            'producer_source_sha256':b1.file_sha(root/'src/chipchain/firmware/mmio_execution_bridge.py'),
            'real_simulations':len(records),'simulator_builds':0,'llm_calls':0,'records':records})
        return out
    except Exception as exc:
        write(out/'blocked.json',{'status':'BLOCKED','error_type':type(exc).__name__,'reason':str(exc),'no_fallback':True})
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if not args.run:parser.error('--run required for four real offline simulations')
    print(execute(Path(__file__).resolve().parents[2]))
