#!/usr/bin/env python3
"""One bounded Exact37 preparation and four fixed copied-caller state cohorts."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
PROFILE = 'exact37-accuracy-copied-state-v1'
SCHEMA = 'exact37-accuracy-native-public-v1'
COHORTS = ('seed0-lengths01-32','seed0-lengths33-64','seed1-lengths01-32','seed1-lengths33-64')
SEEDS = (0x1234567887654320,0xfedcba9801234567)
OUTPUT = 'exact37-accuracy-pair.csv'
HEADER = 'profile,k,seed,function_id,length,status,children,comparisons,visits,original_steps,candidate_steps,result,outer_rax,instructions,conditional_branches,taken_branches,input_reads,return_reads,return_read_bytes,ret_offset,decoded_heads,observed_heads,caller_bytes,caller_heads,call_offset,continuation_offset,outer_ret_offset,subject_rsp_delta,target_calls,target_returns,outer_returns,normal_reaps\n'
PREFIX = 'oracle::native_ordinary::normal_caller::exact_accuracy::'
RUST_CONTROLS = tuple(PREFIX+'tests::'+name for name in (
    'exact_accuracy_keys_cover_all_lengths_and_reject_noncanonical_or_foreign_cases',
    'exact_accuracy_wire_binds_version_key_function_policy_and_complete_payload',
    'exact_accuracy_ready_refuses_incomplete_or_aliasing_source_and_boundary_owners',
    'exact_accuracy_trace_covers_every_loop_visit_and_all_128_keys',
    'exact_accuracy_trace_refuses_wrong_itinerary_input_scalar_stack_xstate_and_counts',
    'exact_accuracy_row_requires_exact_completion_reaps_counts_and_return_identity'))+(
    'exact_accuracy_check::tests::exact_accuracy_batch_joins_identity_rank_sequence_and_all_journal_words',
    'exact_accuracy_check::tests::exact_accuracy_history_report_and_bank_reclaim_require_complete_state')
PYTHON_CONTROLS = (
    'test_full_population_four_cohorts_and_exact_independent_answers',
    'test_key_shape_missing_duplicate_unknown_reordered_and_retry_refuse',
    'test_all_32_columns_terminal_and_step_bounds_refuse_mutation',
    'test_all_eight_release_controls_are_mandatory_without_changing_legacy',
    'test_owner_grammar_exact_cli_and_unchanged_limits',
    'test_actual_page_and_complete_caller_instructions_require_identity',
    'test_geometry_requires_external_acceptance_and_all_source_joins',
    'test_record_rejects_owner_source_environment_and_closure_mutants',
    'test_dispatch_records_failures_and_stops_uncertain_custody',
    'test_collector_replays_all_128_rows_and_retains_failures',
    'test_collector_rejects_missing_duplicate_unknown_mutated_and_wrong_owner',
    'test_build_recipe_is_exact_and_no_profile_relaxes_legacy')
STATUS = {'exact-prepare':'EXACT37_PREPARATION_PASS','exact-cohort':'EXACT37_COHORT_STATE_PASS',
          'exact-collect':'EXACT37_128_STATE_PASS'}
SCOPE = ('Finite Exact37 copied-machine-caller accuracy callback state, two fixed payload patterns and all lengths 1..64; '
    'one manually armed K10 bank, interval-bank reclaim only, executable owners process-lived; '
    'no original-address/Rust ABI, full SDK, unsampled calls, exhaustion, cadence, PMU accuracy, strict 2ms or performance qualification.')

def load(name,path):
    spec = importlib.util.spec_from_file_location(name,path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module

def sha(raw): return hashlib.sha256(raw).hexdigest()
def reference(args,name):
    return dict(path=str(getattr(args,name.replace('-','_'))),sha256=getattr(args,(name+'-sha').replace('-','_')))
def uint(value):
    assert type(value) is str and re.fullmatch('0|[1-9][0-9]*',value)
    n = int(value); assert n < 2**64; return n
def qualifications(): return dict(pmu_metric=False,cadence=False,performance=False)

def keys(cohort=None):
    assert cohort is None or cohort in COHORTS
    answer = [dict(k=10,seed=seed,function_id=41,length=length) for i,seed in enumerate(SEEDS)
        for length in range(1,65) if cohort is None or COHORTS[2*i+(length>32)] == cohort]
    assert len(answer) == (128 if cohort is None else 32)
    return answer

def checked_key(key):
    assert type(key) is dict and set(key) == {'k','seed','function_id','length'}
    assert all(type(value) is int for value in key.values()) and key in keys()
    return key

def expected_fields(key):
    checked_key(key); length = key['length']; index = SEEDS.index(key['seed'])
    value = sum((((37*j+11+index)&255)^0x5a) for j in range(length)) ^ 0x9e3779b97f4a7c15
    visits = 6*length+5
    fields = dict(profile=PROFILE,status='PASS',**{k:str(v) for k,v in key.items()})
    fields.update({k:str(v) for k,v in dict(children=2,comparisons=visits+10,visits=visits,
        result=value,outer_rax=value,instructions=visits,conditional_branches=length,taken_branches=length-1,
        input_reads=length,return_reads=1,return_read_bytes=8,ret_offset=36,decoded_heads=11,observed_heads=11,
        caller_bytes=20,caller_heads=9,call_offset=13,continuation_offset=15,outer_ret_offset=19,
        subject_rsp_delta=16,target_calls=2,target_returns=2,outer_returns=2,normal_reaps=2).items()})
    return fields

def terminal(key,comparisons):
    checked_key(key); assert type(comparisons) is int and comparisons == 6*key['length']+15
    return (f'native-exact37-accuracy:profile={PROFILE}:k=10:seed={key["seed"]}:function=41:length={key["length"]}'
        f':required=1:pairs=1:children=2:comparisons={comparisons}:target-calls=2:target-returns=2:'
        'real-outer-ret=2:normal-reaps=2:scope=copied-body-only:complete\n').encode('ascii')

def pair_output(raw,stdout,stderr,key):
    assert stderr == b'' and type(raw) is bytes and 0 < len(raw) <= MIB
    assert raw.startswith(HEADER.encode()) and raw.endswith(b'\n') and b'\r' not in raw
    lines = raw.splitlines(keepends=True); assert len(lines) == 2 and len(lines[1]) <= 768
    assert all(byte == 10 or 32 <= byte < 127 for byte in raw)
    fields = lines[1][:-1].decode('ascii').split(','); columns = HEADER.strip().split(',')
    assert len(fields) == len(columns) == 32
    row = dict(zip(columns,fields)); expected = expected_fields(key)
    assert set(row) == set(expected)|{'original_steps','candidate_steps'}
    assert {name:row[name] for name in expected} == expected
    for name in ('original_steps','candidate_steps'):
        assert uint(row['comparisons']) <= uint(row[name]) <= 20000
    assert stdout == terminal(key,uint(row['comparisons']))
    return row

def initial_rows(cohort=None): return [dict(key=key,status='UNRUN',attempts=0) for key in keys(cohort)]
def population(rows,cohort=None):
    assert type(rows) is list and [r['key'] for r in rows] == keys(cohort)
    for row in rows:
        checked_key(row['key']); assert row['status'] in ('UNRUN','FAILED','PASS')
        assert type(row['attempts']) is int and row['attempts'] == (0 if row['status'] == 'UNRUN' else 1)
    return all(row['status'] == 'PASS' for row in rows)

def inventory(names):
    assert len(names) == len(set(names))
    selected = [n for n in names if n.startswith((PREFIX,'exact_accuracy_check::'))]
    assert set(selected) == set(RUST_CONTROLS) and len(selected) == 8
    return RUST_CONTROLS

def evidence(result):
    result['qualification'] = qualifications()
    result['callback_state'] = 'PASS' if result['phase'] == 'exact-collect' and result['status'] == STATUS['exact-collect'] else 'HELD'

def projection(result):
    return dict(schema=SCHEMA,profile=PROFILE,phase=result['phase'],revision=result['revision'],status=result['status'],
        rows=len(result['rows']),passed=sum(r['status']=='PASS' for r in result['rows']),
        failed=sum(r['status']=='FAILED' for r in result['rows']),unrun=sum(r['status']=='UNRUN' for r in result['rows']),
        custody_closed=result['custody_closed'],retention_verified=result['retention_verified'],
        callback_state=result['callback_state'],qualification=result['qualification'])

def record(run,recipe,driver,adapter,result_ref,owner_ref,phase,allow_failed=False):
    assert set(result_ref) == set(owner_ref) == {'path','sha256'}
    result = driver.read_json(run,recipe,Path(result_ref['path']),result_ref['sha256'],32*MIB)
    directory = Path(result_ref['path']).parent
    assert result['schema'] == SCHEMA and result['profile'] == PROFILE and result['phase'] == phase
    assert result['revision'] == run.a.revision and result['scope'] == SCOPE
    assert result['status'] in ((STATUS[phase],'FAILED') if allow_failed else (STATUS[phase],))
    expected = dict(result); evidence(expected)
    assert result['callback_state'] == expected['callback_state'] and result['qualification'] == qualifications()
    assert all(value is False for value in result['qualification'].values())
    assert result['custody_closed'] is True and result['retention_verified'] is True and result['source_unchanged'] is True
    assert result['environment'] == run.env and result['hardware'] == run.a.hardware and result['cpus'] == run.cpus
    owner = driver.read_json(run,recipe,Path(owner_ref['path']),owner_ref['sha256'])
    recipe.normal_closed(owner['closed'])
    assert owner['closed']['exit_code'] == (0 if result['status'] == STATUS[phase] else 1)
    assert owner['base'] == run.a.revision and owner['working_source_sha256'] == {} and owner['source_unchanged'] is True
    assert owner['reserved_cpus'] == run.cpus and owner['attempts'] == 1 and owner['log_archived'] is True
    assert owner['wall_limit_seconds'] == 1200 and owner['output_limit_bytes'] == 8*MIB
    options = dict(result['arguments'],owner=owner_ref['path'])
    assert options['raw'] == str(directory) and options['phase'] == phase
    for name in ('revision','reservation-tag','toolchain','user-home','cargo-home','hardware'):
        assert options[name] == str(getattr(run.a,name.replace('-','_')))
    assert owner['hardware'] == run.a.hardware
    public = owner['public_owner']; invocation,child = adapter.commands(options,str(run.tools['python']),public['invocation'][2])
    assert public == dict(schema=adapter.SCHEMA,phase=phase,revision=run.a.revision,
        recipe='evaluation/ordinary-selected-session/exact_state_owner.py',
        recipe_sha256=run.sources[str(HERE/'exact_state_owner.py')]['sha256'],invocation=invocation)
    assert owner['command'] == child == result['invocation'] and owner['env'] == adapter.environment(options)
    raw = driver.raw_pin(run,recipe,Path(owner_ref['path']).with_suffix('.log'),cap=8*MIB)
    assert sha(raw) == owner['closed']['private_log_sha256'] and json.loads(raw) == projection(result)
    for name in ('sources-before.json','sources-after.json'):
        assert driver.read_json(run,recipe,directory/name,cap=16*MIB) == run.sources
    assert result['evidence_budget']['exceeded'] is False and result['evidence_budget']['reservation_active'] is False
    for name,pin in result['retained'].items(): driver.raw_pin(run,recipe,Path(name),pin,512*MIB)
    for name,pin in result['tool_pins'].items():
        driver.raw_pin(run,recipe,Path(name),pin,512*MIB)
        if name in run.tool_pins: assert run.tool_pins[name] == pin
        else: run.tool_pins[name] = pin
    return result

def preparation_commands(directory,tools):
    t = {k:str(v) for k,v in tools.items()}
    return (
        [t['gcc'],'-O2','-fPIC','-shared','-nostdlib','-fno-builtin','-fno-stack-protector','-fomit-frame-pointer',
         '-fno-tree-vectorize','-fno-tree-slp-vectorize','-fno-asynchronous-unwind-tables','-fno-unwind-tables',
         '-fcf-protection=none','-Wl,-z,now','-Wl,-z,noexecstack',str(ROOT/'tools/rapid-profiler/exact-work/exact_work.S'),
         '-o',str(directory/'exact-final.so')],
        [t['readelf'],'--wide','--file-header','--program-headers','--section-headers','--symbols','--dynamic','--relocs',str(directory/'exact-final.so')],
        [t['objdump'],'-d','-M','intel','--insn-width=16','--disassemble=exact_work_nonempty',str(directory/'exact-final.so')])

def fixed_population():
    return dict(profile=PROFILE,keys=keys(),cohorts=list(COHORTS),attempts_per_key=1,
        cpu_seconds=20,wall_seconds=30,pair_seconds=15,steps_per_child=20000)


def prepare(run,recipe,driver,builder,sdk,fixture,geometry,build,binary):
    run.freeze(run.raw/'population.json',fixed_population(),MIB)
    commands = preparation_commands(run.raw,run.tools)
    run.result['preparation_commands'] = commands
    for index,(name,argv) in enumerate(zip(('exact-assembly','exact-elf','exact-disassembly'),commands)):
        generated = ((run.raw/'exact-final.so',MIB),) if index == 0 else ()
        out,err = run.stage(name,argv,generated=generated); assert err == b''
        if index == 0:
            assert out == b''
            raw = driver.raw_pin(run,recipe,run.raw/'exact-final.so',cap=MIB)
            selection,_,_ = geometry.source_page(raw,fixture)
            builder.copy_product(run,recipe,run.raw/'exact-final.so',run.raw/'exact-candidate.so')
            run.freeze(run.raw/'selection.json',dict(selection,revision=run.a.revision))
    facts = geometry.facts(run,recipe,driver,fixture,build,binary,run.raw)
    run.freeze(run.raw/'geometry-facts.json',facts); run.result['facts'] = facts
    test_binary = binary['products']['frontend-native-calibrations']['path']
    out,err = run.stage('exact-list',[test_binary,'--list'])
    names = run.m['census'].census(out,err); wanted = inventory(names)
    # Retain the inherited selected inventory's exact old eight names too.
    sdk.inventory(names)
    run.result.update(inventory=names,rust_required=list(wanted))
    out,err = run.stage('exact-rust',[test_binary,*wanted,'--exact','--test-threads=1'])
    run.result['rust'] = run.m['census'].controls(out,err,wanted,names)
    out,err = run.stage('exact-python',[run.tools['python'],'-B',HERE/'exact_state_controls.py','-v'])
    run.owners.reuse_python_controls(out,err,PYTHON_CONTROLS)
    run.result.update(python_required=list(PYTHON_CONTROLS),status=STATUS['exact-prepare'])

def read_preparation(run,recipe,driver,sdk,adapter,fixture,geometry,build,binary):
    r = record(run,recipe,driver,adapter,reference(run.a,'preparation'),reference(run.a,'preparation-owner'),'exact-prepare')
    assert r['rows'] == []
    assert r['inputs'] == {name:reference(run.a,name) for name in
        ('build','build-owner','sdk-build','sdk-build-owner','sdk-controls','sdk-controls-owner')}
    directory = run.a.preparation.parent
    assert driver.read_json(run,recipe,directory/'population.json') == fixed_population()
    commands = preparation_commands(directory,run.tools)
    assert r['preparation_commands'] == [list(argv) for argv in commands]
    assert [row['name'] for row in r['stages']] == ['exact-assembly','exact-elf','exact-disassembly','exact-list','exact-rust','exact-python']
    for index,(name,argv) in enumerate(zip(('exact-assembly','exact-elf','exact-disassembly'),commands)):
        code,out,err = sdk.replay_stage(run,recipe,driver,r,name,argv)
        assert code == 0 and err == b''
        if index == 0: assert out == b''
    facts = geometry.facts(run,recipe,driver,fixture,build,binary,directory)
    assert r['facts'] == facts == driver.read_json(run,recipe,directory/'geometry-facts.json')
    test_binary = binary['products']['frontend-native-calibrations']['path']
    code,out,err = sdk.replay_stage(run,recipe,driver,r,'exact-list',[test_binary,'--list']); assert code == 0
    names = run.m['census'].census(out,err); wanted = inventory(names); sdk.inventory(names)
    assert names == r['inventory'] and r['rust_required'] == list(wanted)
    code,out,err = sdk.replay_stage(run,recipe,driver,r,'exact-rust',[test_binary,*wanted,'--exact','--test-threads=1']); assert code == 0
    assert run.m['census'].controls(out,err,wanted,names) == r['rust']
    code,out,err = sdk.replay_stage(run,recipe,driver,r,'exact-python',[run.tools['python'],'-B',HERE/'exact_state_controls.py','-v']); assert code == 0
    run.owners.reuse_python_controls(out,err,PYTHON_CONTROLS); assert r['python_required'] == list(PYTHON_CONTROLS)
    return facts

def accept_geometry(run,recipe,driver,geometry,facts):
    value = driver.read_json(run,recipe,run.a.geometry,run.a.geometry_sha)
    geometry.acceptance(value,facts,reference(run.a,'preparation'),reference(run.a,'build'),
        reference(run.a,'sdk-build'),run.a.revision,PROFILE)
    for name,pin in value['supporting_pins'].items(): driver.raw_pin(run,recipe,Path(name),pin,128*MIB)
    return value

def pair_argv(binary,copies,output,key,table):
    checked_key(key); assert len(table) == 1
    row = table[0]; assert (row['function_id'],row['operation'],row['policy'],row['extent'],row['returns']) == (41,'exact_work_nonempty','whole',37,[36])
    assert type(row['elf_va']) is int and 0 < row['elf_va'] < 2**64-37 and row['elf_va']%4096+37 <= 4096
    argv = [str(binary),PROFILE,*[str(copies[k]) for k in ('dso_candidate','dso_trusted','app_candidate','app_trusted')],
        str(output),str(key['seed']),str(key['length']),str(row['elf_va']),'37']
    assert len(argv) == 11; return argv

def prepare_cohort(run,recipe,driver,builder,binary,facts):
    copies = {}
    for label,source in [('dso_candidate',facts['trusted']),('dso_trusted',facts['trusted']),
                         ('app_candidate',facts['application']),('app_trusted',facts['application'])]:
        destination = run.raw/(label+('.so' if label.startswith('dso') else '.elf'))
        builder.copy_product(run,recipe,Path(source),destination); copies[label] = str(destination)
    assert len({(Path(p).stat().st_dev,Path(p).stat().st_ino) for p in copies.values()}) == 4
    plans = []
    for index,row in enumerate(run.result['rows']):
        name = 'pair-'+str(index).zfill(2); directory = run.raw/(name+'-io'); output = directory/'output'
        argv = pair_argv(binary['products']['frontend-native-oracle']['path'],copies,output,row['key'],facts['table'])
        request = run.request(directory,argv,cpu=20,wall=30,cap=4*MIB); run.plan_bounded(name,directory,request)
        plans.append(dict(name=name,key=row['key'],request=request,output=str(output)))
    plan = dict(schema=SCHEMA,profile=PROFILE,cohort=run.a.cohort,all_keys=keys(),keys=keys(run.a.cohort),
        inputs=run.result['inputs'],plans=plans,copies=copies,attempts_per_key=1,cpu_seconds=20,wall_seconds=30,
        pair_seconds=15,steps_per_child=20000,callback_state='HELD',qualification=qualifications())
    run.freeze(run.raw/'plan.json',plan,4*MIB); return plan

def execute_cohort(run,recipe,driver,plan):
    assert [s['key'] for s in plan['plans']] == keys(run.a.cohort)
    population(run.result['rows'],run.a.cohort)
    for row,spec in zip(run.result['rows'],plan['plans']):
        try: recipe.bounded_ready(run,spec['request'],app_files=True)
        except BaseException as error:
            run.result['stop_reason'] = type(error).__name__+': '+str(error); break
        row.update(attempts=1,status='FAILED')
        try:
            directory = Path(spec['request']['stdout']).parent; output = Path(spec['output'])
            code,out,err = run.bounded(spec['name'],directory,spec['request'],generated=((output/OUTPUT,MIB),),app_files=True)
            row['child_exit'] = code
            assert output.is_dir() and not output.is_symlink() and sorted(p.name for p in output.iterdir()) == [OUTPUT]
            raw = driver.raw_pin(run,recipe,output/OUTPUT,cap=MIB)
            row['observed'] = pair_output(raw,out,err,row['key']); assert code == 0
            row.update(output_pin=run.retained[str(output/OUTPUT)],status='PASS')
        except BaseException as error: row['error'] = type(error).__name__+': '+str(error)
        finally:
            stage = next((r for r in run.result['stages'] if r['name'] == spec['name']),None)
            if stage is not None and 'closed' in stage: row['closed'] = stage['closed']
        if not run.safe: break
        run.budget.complete(); run.unchanged()
    if population(run.result['rows'],run.a.cohort): run.result['status'] = STATUS['exact-cohort']

def collect(run,recipe,driver,sdk,adapter,binary,facts):
    refs = driver.read_json(run,recipe,run.a.cohorts,run.a.cohorts_sha)
    assert type(refs) is list and len(refs) == 4 and [r['cohort'] for r in refs] == list(COHORTS)
    output = []
    for cohort,item in zip(COHORTS,refs):
        assert set(item) == {'cohort','result','owner'}
        r = record(run,recipe,driver,adapter,item['result'],item['owner'],'exact-cohort',True)
        assert r['arguments']['cohort'] == cohort and r['inputs'] == run.result['inputs']
        directory = Path(item['result']['path']).parent
        plan = driver.read_json(run,recipe,directory/'plan.json',cap=4*MIB)
        assert plan['schema'] == SCHEMA and plan['profile'] == PROFILE and plan['cohort'] == cohort
        assert plan['callback_state'] == 'HELD' and plan['qualification'] == qualifications()
        assert all(value is False for value in plan['qualification'].values())
        assert plan['all_keys'] == keys() and plan['keys'] == keys(cohort) and [s['key'] for s in plan['plans']] == keys(cohort)
        assert (plan['attempts_per_key'],plan['cpu_seconds'],plan['wall_seconds'],plan['pair_seconds'],plan['steps_per_child']) == (1,20,30,15,20000)
        assert plan['inputs'] == run.result['inputs']
        copies = plan['copies']; assert set(copies) == {'dso_candidate','dso_trusted','app_candidate','app_trusted'}
        for label,path in copies.items():
            expected = directory/(label+('.so' if label.startswith('dso') else '.elf')); assert path == str(expected)
            pin = facts['pins'][facts['trusted'] if label.startswith('dso') else facts['application']]
            driver.raw_pin(run,recipe,expected,pin,128*MIB)
        assert len({(Path(p).stat().st_dev,Path(p).stat().st_ino) for p in copies.values()}) == 4
        population(r['rows'],cohort)
        assert [s['name'] for s in r['stages']] == ['pair-'+str(i).zfill(2) for i in range(sum(x['attempts'] for x in r['rows']))]
        for index,(row,spec) in enumerate(zip(r['rows'],plan['plans'])):
            name = 'pair-'+str(index).zfill(2); d = directory/(name+'-io'); dest = d/'output'
            argv = pair_argv(binary['products']['frontend-native-oracle']['path'],copies,dest,row['key'],facts['table'])
            request = dict(argv=argv,cwd=str(ROOT),env=run.env,stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),cpu_seconds=20,wall_seconds=30,file_bytes=4*MIB)
            assert spec == dict(name=name,key=row['key'],request=request,output=str(dest))
            assert driver.read_json(run,recipe,d/'request.json') == request
            if row['attempts'] == 1:
                code,out,err = sdk.replay_stage(run,recipe,driver,r,name,argv,4*MIB)
                assert code == row['child_exit'] and row['closed'] == next(s for s in r['stages'] if s['name'] == name)['closed']
            if row['status'] == 'PASS':
                assert code == 0 and not dest.is_symlink() and sorted(p.name for p in dest.iterdir()) == [OUTPUT]
                raw = driver.raw_pin(run,recipe,dest/OUTPUT,row['output_pin'],MIB)
                assert pair_output(raw,out,err,row['key']) == row['observed']
            output.append(row); run.result['rows'][len(output)-1] = row
    assert [row['key'] for row in output] == keys(); run.result['rows'] = output
    if population(output):
        assert sum(uint(r['observed']['comparisons']) for r in output) == 26880
        assert sum(uint(r['observed']['visits']) for r in output) == 25600
        assert sum(uint(r['observed']['normal_reaps']) for r in output) == 256
        for seed in SEEDS:
            assert [r['key']['length'] for r in output if r['key']['seed'] == seed] == list(range(1,65))
        run.result['status'] = STATUS['exact-collect']

def main():
    started = time.monotonic(); parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=tuple(STATUS),required=True)
    for name in ('revision','reservation-tag','hardware'): parser.add_argument('--'+name,required=True)
    for name in ('raw','toolchain','user-home','cargo-home'): parser.add_argument('--'+name,type=Path,required=True)
    paths = ('build','build-owner','sdk-build','sdk-build-owner','sdk-controls','sdk-controls-owner','preparation','preparation-owner','geometry','cohorts')
    for name in paths:
        parser.add_argument('--'+name,type=Path); parser.add_argument('--'+name+'-sha')
    parser.add_argument('--cohort',choices=COHORTS)
    a = parser.parse_args()
    required = paths[:6]+(() if a.phase == 'exact-prepare' else paths[6:9])+((paths[9],) if a.phase == 'exact-collect' else ())
    for name in paths:
        values = (getattr(a,name.replace('-','_')),getattr(a,(name+'-sha').replace('-','_')))
        assert all(v is not None for v in values) if name in required else all(v is None for v in values)
    assert (a.cohort is not None) == (a.phase == 'exact-cohort')
    assert re.fullmatch('[0-9a-f]{40}',a.revision)
    for name in ('exact_state.py','exact_state_geometry.py','exact_state_owner.py','exact_state_controls.py',
                 'sdk_state.py','sdk_state_controls.py','build.py','reproduce.py','owner.py'):
        path = HERE/name; assert path.is_file() and not path.is_symlink() and path.stat().st_size <= MIB
        assert path.read_bytes() == subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',a.revision+':'+str(path.relative_to(ROOT))],timeout=15)
    adapter = load('_exact_state_adapter',HERE/'exact_state_owner.py')
    fields = tuple(k for k in adapter.COMMON+adapter.EXTRAS[a.phase] if k != 'owner')
    arguments = {k:str(getattr(a,k.replace('-','_'))) for k in fields}
    invocation,child = adapter.commands(dict(arguments,owner=str(a.raw.parent/'unused-owner.json')),str(Path(sys.executable).resolve(strict=True)),str(HERE/'exact_state_owner.py'))
    assert child == [str(Path(sys.executable).resolve(strict=True)),'-B',sys.argv[0],*sys.argv[1:]]
    builder = load('_exact_state_builder',HERE/'build.py'); driver = builder.load_driver(a.revision)
    run,recipe,_,leaf,owners,git = driver.bootstrap_context(a,started)
    run.deadline = started+1200; run.git = git; run.owners = owners; run.scalar_environment = dict(run.env)
    sdk = load('_exact_state_sdk',HERE/'sdk_state.py'); legacy_adapter = load('_exact_state_legacy_owner',HERE/'owner.py')
    geometry = load('_exact_state_geometry',HERE/'exact_state_geometry.py')
    fixture = load('_exact_state_fixture',ROOT/'tools/rapid-profiler/normal-work/exact_fixture.py')
    run.result = dict(schema=SCHEMA,profile=PROFILE,phase=a.phase,revision=a.revision,arguments=arguments,invocation=child,
        inputs={name:reference(a,name) for name in required if name != 'cohorts'},status='FAILED',scope=SCOPE,
        rows=initial_rows(a.cohort) if a.phase == 'exact-cohort' else initial_rows() if a.phase == 'exact-collect' else [],
        stages=[],environment=run.env,hardware=a.hardware,cpus=run.cpus,load_before=list(os.getloadavg()),
        source_unchanged=False,custody_closed=False,retention_verified=False)
    evidence(run.result)
    try:
        build = sdk.accept_inputs(run,recipe,driver)
        assert build['cpus'] == run.cpus and build['producer']['options']['reservation-tag'] == a.reservation_tag
        tools,versions = builder.tools_metadata(run,recipe)
        assert tools == build['tools'] and versions == build['versions']
        binary = sdk.accept_sdk_build(run,recipe,driver,legacy_adapter,build)
        sdk.accept_controls(run,recipe,driver,legacy_adapter,leaf,owners,build,binary)
        run.freeze(run.raw/'sources-before.json',run.sources,16*MIB)
        if a.phase == 'exact-prepare': prepare(run,recipe,driver,builder,sdk,fixture,geometry,build,binary)
        else:
            facts = read_preparation(run,recipe,driver,sdk,adapter,fixture,geometry,build,binary)
            accept_geometry(run,recipe,driver,geometry,facts)
            if a.phase == 'exact-cohort': execute_cohort(run,recipe,driver,prepare_cohort(run,recipe,driver,builder,binary,facts))
            else: collect(run,recipe,driver,sdk,adapter,binary,facts)
        run.unchanged(); run.freeze(run.raw/'sources-after.json',run.sources,16*MIB)
        assert run.retained[str(run.raw/'sources-before.json')] == run.retained[str(run.raw/'sources-after.json')]
        run.result['source_unchanged'] = True
    except BaseException as error: run.result.update(status='FAILED',error=type(error).__name__+': '+str(error))
    finally:
        run.budget.stopped()
        run.result.update(custody_closed=run.safe,retention_verified=False,retained=dict(run.retained),tool_pins=dict(run.tool_pins),
            load_after=list(os.getloadavg()),evidence_budget=run.budget.summary())
        try:
            assert run.safe and run.result['source_unchanged'] is True and not run.budget.exceeded
            assert run.budget.used <= recipe.EVIDENCE_LIMIT-recipe.FINAL_ALLOWANCE
            run.unchanged(); run.result['retention_verified'] = True
        except BaseException as error: run.result.update(status='FAILED',final_error=type(error).__name__+': '+str(error))
        evidence(run.result); recipe.save(run.raw/'result.json',run.result,32*MIB)
        print(json.dumps(projection(run.result),sort_keys=True))
    return 0 if run.result['status'] == STATUS[a.phase] and time.monotonic() < run.deadline else 1

if __name__ == '__main__':
    raise SystemExit(main())
