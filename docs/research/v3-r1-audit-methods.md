# R1-A audit methods and reproducibility

本文件保存本轮使用的 audit-only 脚本作为文档代码块，不安装为项目运行模块。所有 probe/helper 文件放 `/tmp/chipchain-r1-audit/`；只输出新增 audit 文档/数据，不修改 src/tests/既有 docs/samples/output。无需安装依赖、不联网、没有 provider API 调用。

## Inputs and scope

- 必须先确认冻结 HEAD/tag `39e72ee3a5cc1dd2eb1bb3db10ed218b93894c5e` / `v3-fw-a6-stable`。
- `git ls-files` 是基线全集。当前结果为 250 tracked、116 production Python。未来提交本审计文件后不要在另一 HEAD 直接重跑并声称计数还是原基线；应使用保留本地sample/output访问的独立审计副本或显式按冻结Git树取清单。
- Local samples/output 只做哈希保护和既有 trace 只读回放；不把真实数据复制进 tracked audit JSON。
- AST 捕获所有静态 import，包括 function-local分支。relative import按当前module/package解析。父包初始化单列。from module import symbol并不意味着symbol函数被调用。
- AST direct-call字段只解析语法alias，不追踪运行时receiver、反射、LangGraph注册、Pydantic生成代码。没有找到动态import语句不代表所有动态dispatch已知。
- module的responsibility保留原docstring并列出实际public API；docstring若含历史描述不作为当前状态证明。行为差异以主线审计表为准。
- Git first-containing-tag按祖先commit数量排序，是文件首次出现身份，不是推测的语义引入阶段。explicit frozen document refs作为补充。
- Python call probe先保留raw代码对象事件，再按AST FunctionDef/AsyncFunctionDef（含decorator首行）区分实际具名函数与class/modulebody。
- tests关联同时提供直接import和setup/call/teardown期间code执行；它不是覆盖率报告，更不能单独证明断言充分。
- 不产生自动DELETE决定；classification是审计提案。UNKNOWN外部consumer/API/替代/历史重放阻止删除。

## Execution order

1. 将下面四个脚本代码块分别提取为 `/tmp/chipchain-r1-audit/replay.py`、`r1_profile.py`、`generate.py`、`finalize.py`。
2. 创建冻结文件保护快照（下面首个代码块），然后 collection。
3. 使用 `.venv/bin/python /tmp/chipchain-r1-audit/replay.py` 执行离线probe。它只在临时目录生成fake运行产物，退出时删除；不是新真实实验，不能引用其mode字段作为真实调用证明。
4. `PYTHONPATH=/tmp/chipchain-r1-audit CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q -p r1_profile > /tmp/chipchain-r1-audit/pytest.txt`，得到模块关联数据。
5. `CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q > /tmp/chipchain-r1-audit/pytest-final.txt` 执行不带probe的正常要求检查。
6. `.venv/bin/python -m pip check > /tmp/chipchain-r1-audit/pip-check.txt`；`compileall -q src tests`；`git diff --check`。
7. 先运行generate.py，再运行finalize.py；它们只写新增R1 inventory/validation JSON。finalize断言所有初始tracked/真实history未变。
8. 本次将最后两步重复执行，对比inventory JSON SHA完全一致。它证明在固定采集输入下输出deterministic；不承诺不同平台/环境或不同执行trace生成完全相同环境元数据。

## Snapshot and collection

```python
from pathlib import Path
import subprocess, json, hashlib
root=Path('/tmp/chipchain-r1-audit');root.mkdir(exist_ok=True)
tracked=subprocess.check_output(['git','ls-files','-z']).decode().split('\0')[:-1]
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
snapshot={p:h(Path(p)) for p in tracked}
history={str(p):h(p) for name in ('output','samples') for p in sorted(Path(name).rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
(root/'protection.json').write_text(json.dumps({'tracked':snapshot,'local_history':history},sort_keys=True))
with (root/'collection.txt').open('w') as stream:
    subprocess.run(['.venv/bin/pytest','--collect-only','-q'],stdout=stream,check=True)
```

## replay.py

```python
"""Offline audit probe: frozen simulation files + deterministic fake transports.
No subprocess execution, network connection, .env access or repository output write.
"""
import sys,threading,json,socket,shutil,tempfile
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
ROOT=Path.cwd(); sys.path.insert(0,str(ROOT))
from chipchain.integrations import paired_baseline as runner
from chipchain.integrations.deepseek import DeepSeekConfig
from pydantic import SecretStr
from chipchain.integrations.paired_agents import HardwareBinding,CrossLayerBinding
from chipchain.firmware.grounding_support import GroundedFirmwareModelReport
from tests.fakes import fake_model
old=ROOT/'output/ibex-simple-system:hello-test:paired-workspace/100fcbb2-6ac4-4eb5-821c-09a688957a51'
caseid='ibex-simple-system:hello-test:paired-workspace'
hw={name:[] for name in HardwareBinding.model_fields};hw['case_id']=caseid
cross={name:[] for name in CrossLayerBinding.model_fields};cross['case_id']=caseid
fw=json.loads((old/'firmware_model_claims.diagnostic.json').read_text())
models=[fake_model(HardwareBinding,hw),fake_model(GroundedFirmwareModelReport,fw),fake_model(CrossLayerBinding,cross)]
iterator=iter(models);records=set();edges=set();events=[]
prefix=str(ROOT/'src/chipchain')+'/'
def profile(frame,event,arg):
 if event!='call' or not frame.f_code.co_filename.startswith(prefix):return
 path=str(Path(frame.f_code.co_filename).relative_to(ROOT));name=frame.f_code.co_qualname
 row=(path,name,frame.f_code.co_firstlineno);records.add(row)
 if len(events)<3000 and (not events or events[-1]!=row):events.append(row)
 caller=frame.f_back
 if caller and caller.f_code.co_filename.startswith(prefix):
  edges.add((str(Path(caller.f_code.co_filename).relative_to(ROOT)),caller.f_code.co_qualname,path,name))
def deny(*args,**kwargs):raise RuntimeError('R1 audit network forbidden')
def simulation(*args,**kwargs):
 for name in ('trace_core_00000000.log','stdout.log','ibex_simple_system.log'):
  shutil.copyfile(old/'simulation'/name,Path(kwargs['cwd'])/name)
 return SimpleNamespace(returncode=0)
with tempfile.TemporaryDirectory(prefix='chipchain-r1-probe-') as temp:
 with patch.object(runner,'load_deepseek_config',return_value=DeepSeekConfig(api_key=SecretStr('audit-local-placeholder'))),patch.object(runner,'build_deepseek_chat_model',side_effect=lambda _:next(iterator)),patch.object(runner.subprocess,'run',side_effect=simulation),patch.object(socket.socket,'connect',side_effect=deny),patch.object(socket.socket,'connect_ex',side_effect=deny):
  sys.setprofile(profile);threading.setprofile(profile)
  try:out=runner.run_paired_baseline(root=ROOT,env_file=Path(temp)/'nonexistent.env',output_root=Path(temp),enabled=True,firmware_grounding=True)
  finally:sys.setprofile(None);threading.setprofile(None)
  status=json.loads((out/'analysis_run.json').read_text())['status']
  assert status=='completed'
  assert [len(m.seen_messages) for m in models]==[1,1,1]
 result={'method':'sys.setprofile + threading.setprofile; offline replay using frozen trace and fake model transport','simulation_executed':False,'api_calls':0,'env_file_read':False,'run_status':status,'fake_invocations':3,'source_trace_run_id':old.name,'limitations':['One successful A6 branch, not exhaustive coverage','Provider construction/config and simulator execution replaced; their internals only statically audited','Runtime import/class definitions before profiling are not counted as executed functions'], 'functions':[{'path':p,'function':f,'line':l} for p,f,l in sorted(records)],'call_edges':[{'caller_path':a,'caller_function':b,'callee_path':c,'callee_function':d} for a,b,c,d in sorted(edges)],'first_events':[{'path':p,'function':f,'line':l} for p,f,l in events[:100]]}
 Path('/tmp/chipchain-r1-audit/replay.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
 print('Observed function modules:',len({p for p,f,l in records}),'functions',len(records))
```

## r1_profile.py

```python
"""Audit-only pytest execution probe. Module calls are not branch coverage."""
import sys,threading,json
from pathlib import Path
import pytest
ROOT=Path.cwd();prefix=str(ROOT/'src/chipchain')+'/'
current=None;seen={};cache={}
def profile(frame,event,arg):
 if event!='call' or current is None:return
 filename=frame.f_code.co_filename
 if filename not in cache:cache[filename]=str(Path(filename).relative_to(ROOT)) if filename.startswith(prefix) else None
 path=cache[filename]
 if path:seen.setdefault(current,set()).add(path)
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item,nextitem):
 global current
 current=item.nodeid
 sys.setprofile(profile);threading.setprofile(profile)
 try:yield
 finally:
  sys.setprofile(None);threading.setprofile(None);current=None
def pytest_sessionfinish(session,exitstatus):
 Path('/tmp/chipchain-r1-audit/test-execution.json').write_text(json.dumps({'method':'Python call profiling during setup/call/teardown; not line/branch coverage','exit_code':int(exitstatus),'tests':{k:sorted(v) for k,v in sorted(seen.items())}},sort_keys=True,indent=2)+'\n')
```

## generate.py

```python
"""Deterministic R1 inventory from Git, AST and offline call observations.
Run from repository root after the two audit probes; writes audit JSON only.
"""
import ast,hashlib,json,subprocess,sys,platform
from pathlib import Path
from collections import Counter,defaultdict
from importlib import metadata
ROOT=Path.cwd();TMP=Path('/tmp/chipchain-r1-audit');OUT=ROOT/'docs/research'
def git(*args):return subprocess.check_output(['git',*args]).decode().strip()
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
tracked=git('ls-files').splitlines();production=[p for p in tracked if p.startswith('src/chipchain/') and p.endswith('.py')]
python_files=[p for p in tracked if p.endswith('.py')]
def module(p):
 x=p.removeprefix('src/').removesuffix('.py').replace('/','.')
 return x.removesuffix('.__init__')
by_module={module(p):p for p in python_files}; trees={p:ast.parse(Path(p).read_text()) for p in python_files}
imports={};calls={};unused={};dynamic={};public={}
for p,tree in trees.items():
 edges=[];aliases={};mod=module(p);package=mod if p.endswith('__init__.py') else mod.rpartition('.')[0]
 for node in ast.walk(tree):
  if isinstance(node,ast.Import):
   for a in node.names:
    edges.append(dict(module=a.name,line=node.lineno,kind='import',names=[a.name]))
    aliases[a.asname or a.name.split('.')[0]]=a.name if a.asname else a.name.split('.')[0]
  elif isinstance(node,ast.ImportFrom):
   base=node.module or ''
   if node.level:base='.'.join(package.split('.')[:len(package.split('.'))-node.level+1]+([base] if base else []))
   edges.append(dict(module=base,line=node.lineno,kind='from',names=[a.name for a in node.names]))
   for a in node.names:
    aliases[a.asname or a.name]=base+'.'+a.name
    if base+'.'+a.name in by_module:edges.append(dict(module=base+'.'+a.name,line=node.lineno,kind='from_submodule',names=[a.name]))
 imports[p]=sorted(edges,key=lambda x:(x['line'],x['module'],x['kind']))
 def dotted(node):
  if isinstance(node,ast.Name):return node.id
  if isinstance(node,ast.Attribute):
   prefix=dotted(node.value);return prefix+'.'+node.attr if prefix else None
  return None
 calls[p]=[];dynamic[p]=[]
 for n in ast.walk(tree):
  if not isinstance(n,ast.Call):continue
  name=dotted(n.func)
  if name:
   first,*rest=name.split('.')
   if first in aliases:calls[p].append(dict(line=n.lineno,expression=name,resolved_symbol='.'.join([aliases[first],*rest]),certainty='syntactic alias only; receiver/dynamic dispatch not proven'))
   if name.endswith('import_module') or name=='__import__':dynamic[p].append(dict(line=n.lineno,expression=ast.unparse(n),status='UNKNOWN'))
 load={n.id for n in ast.walk(tree) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load)}
 exports={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)}
 unused[p]=sorted(a for a in aliases if a not in load and a not in exports) if not p.endswith('__init__.py') else []
 pub=[]
 for n in tree.body:
  if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)) and not n.name.startswith('_'):
   pub.append(dict(name=n.name,kind=type(n).__name__,line=n.lineno,methods=[m.name for m in n.body if isinstance(m,(ast.FunctionDef,ast.AsyncFunctionDef)) and not m.name.startswith('_')] if isinstance(n,ast.ClassDef) else []))
 public[p]=pub
adj={p:sorted({by_module[e['module']] for e in imports[p] if e['module'] in by_module and by_module[e['module']].startswith('src/')}) for p in python_files}
reverse={p:sorted(q for q in python_files if p in adj[q]) for p in production}
# Python also executes parent package __init__ when importing a submodule.
package_users=defaultdict(set)
for p in python_files:
 for e in imports[p]:
  parts=e['module'].split('.')
  for i in range(1,len(parts)):
   parent=by_module.get('.'.join(parts[:i]))
   if parent and parent.endswith('__init__.py') and parent!=p:package_users[parent].add(p)
def closure(start):
 seen=set();queue=[start]
 while queue:
  x=queue.pop()
  if x in seen:continue
  seen.add(x);queue.extend(adj.get(x,[]))
  for e in imports.get(x,[]):
   for i in range(1,len(e['module'].split('.'))):
    q=by_module.get('.'.join(e['module'].split('.')[:i]))
    if q and q.startswith('src/'):queue.append(q)
 return sorted(seen)
entry='src/chipchain/integrations/paired_baseline.py';reachable=closure(entry)
replay=json.loads((TMP/'replay.json').read_text());observed=defaultdict(list)
for r in replay['functions']:observed[r['path']].append(r)
test_run=json.loads((TMP/'test-execution.json').read_text());test_execution=defaultdict(set)
for node,paths in test_run['tests'].items():
 for p in paths:test_execution[p].add(node.split('::')[0])
tags=git('tag','--list').splitlines();tagsets={t:set(git('ls-tree','-r','--name-only',t).splitlines()) for t in tags};tagrank={t:int(git('rev-list','--count',t)) for t in tags}
resources=[p for p in tracked if p.startswith(('docs/','scripts/','samples/','output/','tests/','examples/')) or p in ('README.md','pyproject.toml')]
texts={p:Path(p).read_text(errors='replace') for p in resources if Path(p).suffix in ('.md','.json','.py','.toml','.java','.txt','.html')}
refs={p:[] for p in production}
for p in production:
 needles=(p,module(p)) if not p.endswith('/__main__.py') else (p,module(p),module(p).removesuffix('.__main__'))
 for resource,text in texts.items():
  if resource.startswith('tests/'):continue
  for i,line in enumerate(text.splitlines(),1):
   if any(n in line for n in needles):refs[p].append(dict(path=resource,line=i))
relocate={
 'src/chipchain/firmware/grounded_agent.py':('src/chipchain/agents/firmware_grounded.py','Provider-facing agent currently lives beside deterministic firmware facts; keep old import facade in R1.1.'),
 'src/chipchain/firmware/grounding_report.py':('src/chipchain/reporting/firmware_grounding.py','Human presentation can move independently of fact and support semantics; preserve old import facade.'),
 'src/chipchain/integrations/paired_agents.py':('KEEP in R1.1; future agents/paired_binding.py','Called in current mainline despite pilot label; separate only after binding contract tests.'),
 'src/chipchain/tools/paired/ibex.py':('KEEP in R1.1; future adapters/ibex_simple_system.py','Platform-specific paired IO must remain an adapter, not universal core.'),
 'src/chipchain/integrations/paired_baseline.py':('KEEP in R1.1; later split workflows/paired_analysis.py and platform runner','Entry mixes configuration, simulation IO, agents, validation, persistence; extracting now is high risk.'),
 'src/chipchain/execution/reviewed_output.py':('KEEP; future reporting/reviewed_output.py with facade','Research export validator is replay-critical, not a disposable experiment script.')}
core_prefix=('src/chipchain/domain/','src/chipchain/workflows/')
core_exact={f'src/chipchain/{x}' for x in ['agents/contracts.py','agents/context.py','agents/runtime.py','agents/hardware.py','agents/firmware.py','agents/cross_layer.py','agents/firmware_evidence.py','agents/projections/firmware.py','agents/prompts/hardware.py','agents/prompts/firmware.py','agents/prompts/cross_layer.py','execution/provenance.py','execution/runner.py','tools/contracts.py','tools/artifacts.py','graphs/contracts.py','integrations/deepseek.py','cross_layer/eligibility.py','cross_layer/codec.py','firmware/control_flow_grounding.py','firmware/grounding_catalog.py','firmware/grounding_compatibility.py','firmware/grounding_support.py','firmware/riscv_control_flow.py']}
entries=[]
for p in production:
 intro=git('log','--diff-filter=A','--format=%H %s','--',p).splitlines()[-1]
 present=sorted([t for t in tags if p in tagsets[t]],key=lambda t:(tagrank[t],t))
 imp=reverse[p];prod=[q for q in imp if q.startswith('src/')];test=[q for q in imp if q.startswith('tests/')]
 research=[q for q in imp if q.startswith(('scripts/','docs/'))]
 if p in relocate:classification='KEEP_RELOCATE';destination,reason=relocate[p]
 elif p.startswith(core_prefix) or p in core_exact:
  classification='CORE_MAINLINE';destination='KEEP';reason='Typed contract/lifecycle or explicit A6 paired function dependency. Retain current API; branch-level legacy use distinguished below.'
 elif p.endswith('__init__.py'):
  classification='CORE_MAINLINE' if p in reachable else 'RESEARCH_COMPATIBILITY';destination='KEEP';reason='Package initialization/public exports; implicit import dependencies forbid treating empty package modules as dead code.'
 else:
  classification='RESEARCH_COMPATIBILITY';destination='KEEP; preserve phase-specific replay paths'
  reason='Separate single-side research, typed-support, tooling or XL0 capability; static/test/history dependencies do not establish safe deletion.'
 if not prod and not test and not research and not package_users[p] and not refs[p] and not p.endswith('__init__.py'):
  classification='UNKNOWN_REQUIRES_REVIEW';destination='REVIEW_REQUIRED';reason='No known static importer/reference; external CLI/public API and reflective callers UNKNOWN; delete gate incomplete.'
 direct_callers=sorted({q for q in calls for call in calls[q] if call['resolved_symbol'].startswith(module(p)+'.')})
 roles=[]
 if prod:roles.append('production importer')
 if test and not prod:roles.append('test-only importer')
 if research and not prod:roles.append('research-only importer')
 if not imp:roles.append('no known explicit importer')
 if package_users[p]:roles.append('implicit package importer')
 runtime_codes=observed[p]
 function_locations={(n.name,l) for n in ast.walk(trees[p]) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) for l in [n.lineno,*[d.lineno for d in n.decorator_list]]}
 functions=[r for r in runtime_codes if (r['function'].split('.')[-1],r['line']) in function_locations]
 if p=='src/chipchain/tools/artifacts.py':
  classification='UNKNOWN_REQUIRES_REVIEW';destination='REVIEW_REQUIRED; keep public API until fingerprint consolidation decision';reason='Direct callers only in tests; fingerprint_artifact public utility and overlapping adapter hashing exist, but replacement equivalence and external API consumers UNKNOWN.'
 if functions:execution='observed_function_execution_offline_paired_replay'
 elif runtime_codes:execution='observed_module_or_class_initialization_only; no business function call observed'
 elif p in reachable:execution='static_import_reachable_only; branch execution UNKNOWN or inactive in probe'
 else:execution='not_in_static_paired_import_closure; external/dynamic use UNKNOWN'
 docs=refs[p];docstr=ast.get_docstring(trees[p])
 entries.append(dict(path=p,module=module(p),sha256=digest(p),responsibility=(docstr or 'Package initialization / public API exports; see declarations').split('\n')[0],responsibility_evidence='module docstring + declarations; historical wording is not runtime proof',major_public_classes_functions=public[p],imports=imports[p],imported_production_modules=adj[p],importers=imp,importer_roles=roles,implicit_package_importers=sorted(package_users[p]),syntactically_resolved_callers=direct_callers,syntactically_resolved_calls=calls[p],dynamic_imports=dynamic[p],potential_unused_import_names=unused[p],workflows_using_it=[q for q in sorted(production) if (q.startswith('src/chipchain/workflows/') or (q.startswith('src/chipchain/integrations/') and any(isinstance(n,ast.If) and '__name__' in ast.unparse(n.test) for n in trees[q].body))) and p in closure(q)],workflow_usage_precision='static import transitive superset, includes unexecuted optional branches and package initialization',tests_directly_importing=test,tests_observed_executing_functions=sorted(test_execution[p]),coverage_limit='Observed Python calls during setup/test/teardown, not branch coverage or proof of adequate assertions; absent execution UNKNOWN',git_introduction=intro,first_tag_containing_path=present[0] if present else 'UNKNOWN',tags_containing_path=sorted(present),frozen_phase_references=docs,phase_attribution_limit='Git first presence and explicit document references, not a guessed phase label; semantic dependency requires listed tests/history',current_paired_workflow_use=execution,paired_observed_functions=functions,paired_observed_python_code=runtime_codes,classification=classification,classification_reason=reason,public_entrypoints=([module(p).removesuffix('.__main__')] if p.endswith('/__main__.py') else [module(p)] if any(isinstance(n,ast.If) and '__name__' in ast.unparse(n.test) for n in trees[p].body) else []),proposed_destination_action=destination,migration_risk='high: frozen schema/hash/replay dependencies' if 'domain/' in p or 'relations' in p or 'support' in p or 'grounding' in p else 'medium: import/API/CLI/replay compatibility',dependent_modules_tests=sorted(set(imp)|test_execution[p]),delete_gate=dict(importers=imp,callers=direct_callers,reachable_from_paired=p in reachable,tests=sorted(set(test)|test_execution[p]),historical_references=docs,replacement='NONE proposed' if classification!='KEEP_RELOCATE' else destination,public_api_removal_effect='UNKNOWN until external imports/CLI/re-export contract reviewed',frozen_replay_after_deletion='UNKNOWN; deletion not authorized',eligible=False)))
counts=Counter(e['classification'] for e in entries)
for c in ('CORE_MAINLINE','KEEP_RELOCATE','RESEARCH_COMPATIBILITY','ARCHIVE_CANDIDATE','DELETE_CANDIDATE','UNKNOWN_REQUIRES_REVIEW'):counts.setdefault(c,0)
repo=[]
for p in resources:
 kind='test-only helper/fixture' if p.startswith('tests/') else 'synthetic example' if p.startswith('examples/') else 'sample metadata' if p.startswith('samples/') else 'protected reviewed research artifact' if p.startswith('output/') else 'deterministic tool script' if p.startswith('scripts/') else 'research/reporting/documentation artifact'
 repo.append(dict(path=p,sha256=digest(p),kind=kind))
collection=(TMP/'collection.txt').read_text();nodeids=sorted(x for x in collection.splitlines() if '::' in x and x.startswith('tests/'))
result=dict(schema_version='chipchain-r1-module-inventory/v1',baseline=dict(head=git('rev-parse','HEAD'),branch=git('branch','--show-current'),describe=git('describe','--tags','--always'),stable_tag_commit=git('rev-parse','v3-fw-a6-stable^{commit}'),initial_git_status='clean',environment=dict(python=sys.version,executable=sys.executable,platform=platform.platform(),packages={n:metadata.version(n) for n in ['pip','pytest','pydantic','capstone','pyelftools','langchain','langgraph','langchain-deepseek']})),counts=dict(tracked_files=len(tracked),production_python_files=len(production),test_tracked_files=sum(p.startswith('tests/') for p in tracked),test_python_files=sum(p.startswith('tests/') and p.endswith('.py') for p in tracked),collected_test_cases=len(nodeids),docs_research_tracked_files=sum(p.startswith('docs/research/') for p in tracked),docs_tracked_files=sum(p.startswith('docs/') for p in tracked),scripts_tracked_files=sum(p.startswith('scripts/') for p in tracked),samples_tracked_metadata_files=sum(p.startswith('samples/') for p in tracked),reviewed_tracked_files=sum(p.startswith('output/reviewed/') for p in tracked),classifications=dict(sorted(counts.items()))),methodology=['Tracked-file baseline from git ls-files; no ignored sample contents in inventory','Observed class/module initialization is explicitly separated from callable function execution',
'Python AST all static imports, relative imports resolved, function-local imports included','Explicit edges separated from implicit package initialization','AST call expressions are syntactic alias resolution, not a whole-program dispatch proof','Offline paired replay patches simulator/provider/config, uses existing local trace; NO API invocation','Per-test Python call profiling is not statement or branch coverage','No importer is not deletion evidence; CLI, public exports, historical replay and reflective callers remain review gates','Output ordering stable; no timestamps or run UUID added to canonical inventory identities'],modules=entries,dependency_graph=dict(module_to_imported_modules={p:adj[p] for p in production},module_to_importers=reverse,workflow_entry_to_static_reachable_modules={p:closure(p) for p in production if p.startswith(('src/chipchain/workflows/','src/chipchain/integrations/')) and not p.endswith('__init__.py')},tests_to_direct_imported_modules={p:adj[p] for p in python_files if p.startswith('tests/')},tests_to_observed_executed_modules=test_run['tests']),paired_execution_probe=replay,repository_artifacts=repo,stable_tags=[dict(tag=t,commit=git('rev-parse',t+'^{commit}'),ancestor_of_head=subprocess.run(['git','merge-base','--is-ancestor',t,'HEAD'],capture_output=True).returncode==0) for t in sorted(tags)],collected_test_nodeids=nodeids,limitations=['No static analysis can certify absence of dynamic/external callers','No new provider/API invocation; runtime probe uses fake report transport','No RTL simulator execution; prior trace replay only','Production body execution observed only for one successful A6 path; failure branches belong to tests','Non-import CLI shell references captured separately by explicit docs references; no guessed dynamic imports'])
(OUT/'v3-r1-module-inventory.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
print(json.dumps(result['counts'],ensure_ascii=False,indent=2))
print('Explicit no importer:',[e['path'] for e in entries if not e['importers']])
print('Test-only:',[e['path'] for e in entries if 'test-only importer' in e['importer_roles']])
print('Unused candidates:',{e['path']:e['potential_unused_import_names'] for e in entries if e['potential_unused_import_names']})
```

## finalize.py

```python
"""Add audit-only documentation/resource review and verify frozen bytes."""
from pathlib import Path
import json,hashlib,subprocess
ROOT=Path.cwd();TMP=Path('/tmp/chipchain-r1-audit');OUT=ROOT/'docs/research'
p=OUT/'v3-r1-module-inventory.json';x=json.loads(p.read_text());before=json.loads((TMP/'protection.json').read_text())
def h(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
tracked_changed=[p for p,d in before['tracked'].items() if not Path(p).is_file() or h(p)!=d]
history_changed=[p for p,d in before['local_history'].items() if not Path(p).is_file() or h(p)!=d]
production=[]
for e in x['modules']:
 baseline=hashlib.sha256(subprocess.check_output(['git','show','39e72ee3a5cc1dd2eb1bb3db10ed218b93894c5e:'+e['path']])).hexdigest()
 production.append(dict(path=e['path'],a6_commit_sha256=baseline,worktree_sha256=h(e['path']),unchanged=baseline==h(e['path'])))
assert not tracked_changed and not history_changed and all(e['unchanged'] for e in production)
x['local_sample_metadata']=[dict(path=str(p),sha256=h(p),tracked=str(p) in before['tracked'],policy='local ignored metadata; contents unchanged and not copied into audit') for p in sorted(Path('samples').rglob('*.json')) if p.name in ('local-manifest.json','case.json','paired-case.json','heat-press-case.json')]
x['documentation_review']=[]
for r in x['repository_artifacts']:
 path=r['path']
 if not (path.startswith('docs/') or path=='README.md'):continue
 if path=='README.md':status='contradictory statement';reason='Multiple current-stage headings and line 280 contradict active paired CLI and frozen A6.'
 elif path=='docs/research/v3-fw-a6-evidence-validation.md':status='current statement';reason='Frozen A6 phase record agrees with source contracts and preserved historical regression; not a new run.'
 else:status='historical statement';reason='Phase/scenario-scoped research or teaching/acceptance snapshot; not a global current-state source. Do not rewrite.'
 x['documentation_review'].append(dict(path=path,status=status,reason=reason,action='KEEP unchanged; future CURRENT_STATE links with explicit scope'))
x['static_layer_crossings']=[dict(source=e['path'],imports=q,interpretation='tools depends on agent-side contract/projection; review dependency direction without changing frozen semantics') for e in x['modules'] if e['path'].startswith('src/chipchain/tools/') for q in e['imported_production_modules'] if q.startswith('src/chipchain/agents/')]
x['deletion_gate_policy']='No file qualifies for deletion; absence of importer is insufficient. Unknown external/API/replay answers block DELETE_CANDIDATE.'
x['classification_semantics']='Retention/proposed placement decisions, not runtime coverage. CORE_MAINLINE includes contracts/package surface; import-only and executed-function status recorded separately.'
x['probe_summary']=dict(static_paired_reachable_modules=len(x['dependency_graph']['workflow_entry_to_static_reachable_modules']['src/chipchain/integrations/paired_baseline.py']),observed_python_code_modules=sum(bool(e['paired_observed_python_code']) for e in x['modules']),observed_named_function_modules=sum(bool(e['paired_observed_functions']) for e in x['modules']),observed_module_or_class_initialization_only=sum(bool(e['paired_observed_python_code']) and not e['paired_observed_functions'] for e in x['modules']))
p.write_text(json.dumps(x,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
validation=dict(baseline_head=x['baseline']['head'],baseline_tag='v3-fw-a6-stable',tag_commit=x['baseline']['stable_tag_commit'],production_sha_checks=production,tracked_protection=dict(count=len(before['tracked']),changed=tracked_changed),local_samples_output_protection=dict(count=len(before['local_history']),changed=history_changed),pytest_command='CHIPCHAIN_ENABLE_REAL_LLM=0 .venv/bin/pytest -q',pytest_result=(TMP/'pytest-final.txt').read_text().strip().splitlines()[-1],pytest_profile_result=(TMP/'pytest.txt').read_text().strip().splitlines()[-1],pytest_collection_result=(TMP/'collection.txt').read_text().strip().splitlines()[-1],pip_check=(TMP/'pip-check.txt').read_text().strip(),compileall_exit_code=subprocess.run(['.venv/bin/python','-m','compileall','-q','src','tests'],capture_output=True).returncode,git_diff_check_exit_code=subprocess.run(['git','diff','--check'],capture_output=True).returncode,llm_api_calls=0,real_simulator_runs=0,fake_model_invocations_in_probe=3,production_source_modified=False,existing_tracked_files_modified=False,real_history_modified=False,next_phase_executed=False)
(OUT/'v3-r1-validation.json').write_text(json.dumps(validation,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
print(json.dumps({'checks':len(production),'historical_files':len(before['local_history']),'counts':x['counts']['classifications'],'probe':x['probe_summary'],'pytest':validation['pytest_result']},ensure_ascii=False))
```

