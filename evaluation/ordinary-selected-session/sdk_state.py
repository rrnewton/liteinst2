#!/usr/bin/env python3
"""Fixed public selected copied-caller SDK state preparation and 192-pair collection.

Uses the existing Run, bounded helper and public owner. No unsafe acceptance is
created here. Old scalar and 1280-pair native profiles remain separate.
"""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
PROFILE = 'selected-leaf-set-copied-state-v1'
SCHEMA = 'selected-sdk-public-v1'
COHORTS = ('unstripped-k10','unstripped-k1000','stripped-k10','stripped-k1000')
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
INPUTS = (b'',b'a',b'=',b'a=b',b'ABC=def',b'"A=B",C',b'""',b'"A""B",c',
          b'A'*64,b'='*64,b'a'*63+b'=',b' '*64)
HEADS = ((0,3,6,8,10,12,16,20,23,25,29,31,34,35,40),
         (0,3,5,8,11,16,19,22,24,28,32,35,37,40,41,48,51,54))
RETURNS = ((34,40),(40,54))
HEADER = 'profile,form,k,seed,function_id,input_index,functions,policies,status,children,comparisons,visits,original_steps,candidate_steps,result,outer_rax,input_reads,ret_offset,observed_heads,reachable_heads,observed_edges,reachable_edges,declared_returns,observed_head_set,observed_edge_set,reachable_head_set,reachable_edge_set,return_set,decoded_heads,caller_bytes,caller_heads,call_offset,continuation_offset,outer_ret_offset,subject_rsp_delta,target_calls,target_returns,outer_returns,normal_reaps\n'
OUTPUT = 'selected-leaf-set-pair.csv'
PREFIX = 'oracle::native_ordinary::normal_caller::selected_leaf_set::'
RUST_CONTROLS = tuple(PREFIX + n for n in (
    'tests::selected_keys_are_exact_192_and_cli_rejects_noncanonical_or_unknown_values',
    'tests::selected_wire_roundtrips_and_refuses_old_profiles_wrong_keys_and_policies',
    'tests::selected_complete_source_heads_returns_physical_owners_and_caller_are_joined',
    'trace::tests::selected_original_semantic_calibrations_reject_trace_value_input_read_and_state_mutants',
    'trace::tests::selected_pair_refuses_missing_call_return_reap_comparison_and_declared_return',
    'compiled::literal_answers_and_complete_reachable_population_are_frozen')) + (
    'selected_leaf_set_check::tests::selected_leaf_set_batch_joins_all_identity_rank_sequence_and_journal_words',
    'selected_leaf_set_check::tests::selected_leaf_set_history_report_and_reclaim_require_complete_state')
PYTHON_CONTROLS = (
    'test_population_is_four_exact_cohorts_and_sixteen_complete_groups',
    'test_literal_itineraries_values_and_boundary_sum_are_independent',
    'test_full_row_and_terminal_accept_every_frozen_key',
    'test_key_profile_policy_and_scalar_mutations_refuse',
    'test_visits_reads_returns_and_whole_coverage_sets_refuse',
    'test_counts_limits_framing_and_terminal_refuse',
    'test_actual_bounded_join_replays_nonzero_and_refuses_false_custody',
    'test_population_missing_duplicate_reordered_and_retry_refuse',
    'test_failed_and_unrun_rows_are_not_promoted',
    'test_control_inventory_requires_exact_new_names',
    'test_sdk_build_commands_select_distinct_release_binary_and_calibrations',
    'test_sdk_owner_commands_are_finite_and_old_profiles_stay_strict',
    'test_sdk_geometry_cannot_consume_scalar_or_mixed_policy_authority')
STATUS = {'sdk-build':'SDK_BUILD_PASS','sdk-controls':'SDK_CONTROLS_PASS',
          'sdk-cohort':'SDK_COHORT_PASS','sdk-collect':'SDK_192_STATE_PASS'}
SCOPE = ('Finite actual LeafSet SDK and copied complete machine caller state only; '
         'interval banks reclaimed, executable owners process-lived; no original-address '
         'Rust ABI, executable retirement, full SDK, performance or strict 2ms qualification.')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def uint(value):
    assert type(value) is str and re.fullmatch('0|[1-9][0-9]*',value)
    n=int(value);assert n<=2**64-1
    return n


def keys(cohort=None):
    assert cohort is None or cohort in COHORTS
    rows=[dict(form=form,k=k,seed=seed,function_id=function,input_index=index)
          for form in ('unstripped','stripped') for k in (10,1000)
          for seed in SEEDS for function in (101,202) for index in range(12)
          if cohort is None or cohort==form+'-k'+str(k)]
    assert len(rows)==(192 if cohort is None else 48)
    return rows


def checked_key(key):
    assert type(key) is dict and set(key)=={'form','k','seed','function_id','input_index'}
    assert type(key['form']) is str and all(type(key[n]) is int for n in ('k','seed','function_id','input_index'))
    assert key in keys()
    return key


def meaning(key):
    checked_key(key)
    data=INPUTS[key['input_index']];operation=(key['function_id']==202)
    visits=[0,3];reads=[]
    if not operation:
        answer=data.find(b'=');answer=len(data) if answer<0 else answer
        visits.append(6)
        if not data: ret=34
        else:
            visits += [8,10]
            for index,byte in enumerate(data):
                visits += [25,29];reads.append(index)
                if byte==61:
                    visits.append(31);ret=34;break
                visits += [16,20,23]
            else: ret=40
    else:
        answer=sum(65<=byte<=90 for byte in data)
        if not data: visits += [48,51];ret=54
        else:
            visits += [5,8,11]
            for index in range(len(data)):
                visits += [16,19,22,24,28,32,35];reads.append(index)
            visits.append(37);ret=40
    visits.append(ret)
    return dict(visits=visits,reads=reads,answer=answer,ret=ret)


def coverage(key):
    heads=set();edges=set()
    for index in range(12):
        v=meaning(dict(key,input_index=index))['visits']
        heads.update(v);edges.update(zip(v,v[1:]))
    return sorted(heads),sorted(edges)


def word_set(values):
    return ';'.join(map(str,values))


def edge_set(values):
    return ';'.join(str(a)+'-'+str(b) for a,b in values)


def expected_fields(key):
    m=meaning(key);op=int(key['function_id']==202)
    heads=sorted(set(m['visits']));edges=sorted(set(zip(m['visits'],m['visits'][1:])))
    reachable,reachable_edges=coverage(key)
    fields=dict(profile=PROFILE,functions='2',policies='whole+whole',status='PASS',children='2',
        **{k:str(v) for k,v in key.items()})
    fields.update({k:str(v) for k,v in dict(comparisons=len(m['visits'])+10,visits=len(m['visits']),
        result=m['answer'],outer_rax=m['answer'],input_reads=len(m['reads']),ret_offset=m['ret'],
        observed_heads=len(heads),reachable_heads=len(reachable),observed_edges=len(edges),
        reachable_edges=len(reachable_edges),declared_returns=2,decoded_heads=len(HEADS[op]),
        caller_bytes=20,caller_heads=9,call_offset=13,continuation_offset=15,outer_ret_offset=19,
        subject_rsp_delta=16,target_calls=2,target_returns=2,outer_returns=2,normal_reaps=2).items()})
    fields.update(observed_head_set=word_set(heads),observed_edge_set=edge_set(edges),
        reachable_head_set=word_set(reachable),reachable_edge_set=edge_set(reachable_edges),return_set=word_set(RETURNS[op]))
    return fields


def terminal(key,comparisons):
    return ('native-selected-leaf-set:profile='+PROFILE+':form='+key['form']+':k='+str(key['k'])+
        ':seed='+str(key['seed'])+':function='+str(key['function_id'])+':input='+str(key['input_index'])+
        ':required=1:pairs=1:children=2:comparisons='+str(comparisons)+
        ':target-calls=2:target-returns=2:real-outer-ret=2:normal-reaps=2:scope=copied-body-only:complete\n').encode('ascii')


def pair_output(raw,stdout,stderr,key):
    assert stderr==b'' and type(raw) is bytes and 0<len(raw)<=MIB
    assert raw.startswith(HEADER.encode()) and raw.endswith(b'\n') and b'\r' not in raw
    lines=raw.splitlines(keepends=True);assert len(lines)==2 and len(lines[1])<=768
    assert all(byte==10 or 32<=byte<127 for byte in raw)
    fields=lines[1][:-1].decode('ascii').split(',');columns=HEADER.strip().split(',')
    assert len(fields)==len(columns)==39
    row=dict(zip(columns,fields));expected=expected_fields(key)
    assert set(row)==set(expected)|{'original_steps','candidate_steps'}
    assert {name:row[name] for name in expected}==expected
    for name in ('original_steps','candidate_steps'):
        assert uint(row['comparisons'])<=uint(row[name])<=20000
    assert stdout==terminal(key,uint(row['comparisons']))
    return row


def initial_rows(cohort=None):
    return [dict(key=key,status='UNRUN',attempts=0) for key in keys(cohort)]


def population(rows,cohort=None):
    assert type(rows) is list and [r['key'] for r in rows]==keys(cohort)
    for row in rows:
        checked_key(row['key'])
        assert row['status'] in ('UNRUN','FAILED','PASS') and type(row['attempts']) is int
        assert row['attempts']==(0 if row['status']=='UNRUN' else 1)
    return all(row['status']=='PASS' for row in rows)


def inventory(names):
    assert len(names)==len(set(names))
    selected=[n for n in names if n.startswith((PREFIX,'selected_leaf_set_check::'))]
    assert set(selected)==set(RUST_CONTROLS) and len(selected)==8
    return RUST_CONTROLS


def sdk_commands(cargo):
    tail=['--locked','--offline','--jobs','4','--message-format=json-render-diagnostics']
    return ([str(cargo),'build','--release','-p','rapid-profiler','--bin','frontend-native-oracle',*tail],
        [str(cargo),'test','--release','-p','rapid-profiler','--test','frontend-native-calibrations','--no-run',*tail])


def load_context(args,started):
    # Authenticate all new imports before loading any project module.
    for name in ('sdk_state.py','sdk_state_controls.py','build.py','reproduce.py','owner.py'):
        path=HERE/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size<=MIB
        assert path.read_bytes()==subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',args.revision+':'+str(path.relative_to(ROOT))],timeout=15)
    import importlib.util
    spec=importlib.util.spec_from_file_location('_sdk_public_builder',HERE/'build.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    driver=builder.load_driver(args.revision)
    run,recipe,new,leaf,owners,git=driver.bootstrap_context(args,started)
    run.deadline=started+1200
    run.scalar_environment=dict(run.env)
    adapter=driver.load('sdk_owner',HERE/'owner.py')
    required=set(adapter.COMMON)-{'owner'} | set(adapter.SDK_EXTRAS[args.phase])
    arguments={key:str(getattr(args,key.replace('-','_'))) for key in required}
    run.result=dict(schema=SCHEMA,profile=PROFILE,phase=args.phase,revision=args.revision,
        status='FAILED',arguments=arguments,environment=run.env,hardware=args.hardware,cpus=run.cpus,
        invocation=[str(run.tools['python']),'-B',str(HERE/'sdk_state.py'),*sys.argv[1:]],
        stages=[],rows=initial_rows(args.cohort) if args.phase=='sdk-cohort' else initial_rows() if args.phase=='sdk-collect' else [],
        custody_closed=False,retention_verified=False,load_before=list(os.getloadavg()),scope=SCOPE)
    expected,_=adapter.commands(dict(arguments,owner=str(args.raw.parent/'unused-owner.json')),str(run.tools['python']),str(HERE/'owner.py'))
    # Child grammar does not depend on the outer owner destination.
    _,child=adapter.commands(dict(arguments,owner=str(args.raw.parent/'unused-owner.json')),str(run.tools['python']),expected[2])
    assert run.result['invocation']==child
    assert run.safe and time.monotonic()<run.deadline
    run.freeze(args.raw/'sources-before.json',run.sources,16*MIB)
    assert tuple(new['oracle'].LITERALS)==INPUTS
    return run,recipe,driver,builder,adapter,new,leaf,owners,git


def reference(args,name):
    return dict(path=str(getattr(args,name.replace('-','_'))),sha256=getattr(args,(name+'-sha').replace('-','_')))


def read_reference(run,recipe,driver,value,cap=32*MIB):
    assert set(value)=={'path','sha256'}
    return driver.read_json(run,recipe,Path(value['path']),value['sha256'],cap)


def projection(result):
    return dict(schema=SCHEMA,profile=PROFILE,phase=result['phase'],revision=result['revision'],
        status=result['status'],rows=len(result['rows']),passed=sum(r['status']=='PASS' for r in result['rows']),
        failed=sum(r['status']=='FAILED' for r in result['rows']),unrun=sum(r['status']=='UNRUN' for r in result['rows']),
        custody_closed=result['custody_closed'],retention_verified=result['retention_verified'])


def record(run,recipe,driver,adapter,result_ref,owner_ref,phase,allow_failed=False):
    result=read_reference(run,recipe,driver,result_ref);directory=Path(result_ref['path']).parent
    assert result['schema']==SCHEMA and result['profile']==PROFILE and result['phase']==phase
    assert result['revision']==run.a.revision and result['scope']==SCOPE
    assert result['status'] in ((STATUS[phase],'FAILED') if allow_failed else (STATUS[phase],))
    assert result['custody_closed'] is True and result['retention_verified'] is True
    assert result['environment']==run.env and result['hardware']==run.a.hardware
    assert result['cpus']==run.cpus
    owner=read_reference(run,recipe,driver,owner_ref)
    recipe.normal_closed(owner['closed'])
    assert owner['closed']['exit_code']==(0 if result['status']==STATUS[phase] else 1)
    assert owner['base']==run.a.revision and owner['working_source_sha256']=={} and owner['source_unchanged'] is True
    assert owner['reserved_cpus']==run.cpus and owner['attempts']==1 and owner['log_archived'] is True
    assert owner['wall_limit_seconds']==1200 and owner['output_limit_bytes']==8*MIB
    options=dict(result['arguments'],owner=owner_ref['path'])
    assert options['raw']==str(directory) and options['phase']==phase
    for name in ('revision','reservation-tag','toolchain','user-home','cargo-home','hardware'):
        assert options[name]==str(getattr(run.a,name.replace('-','_')))
    assert owner['hardware']==run.a.hardware
    public=owner['public_owner'];assert public['schema']=='selected-session-public-owner-v1'
    assert public['phase']==phase and public['revision']==run.a.revision
    assert public['recipe']=='evaluation/ordinary-selected-session/owner.py'
    assert public['recipe_sha256']==run.sources[str(HERE/'owner.py')]['sha256']
    invocation,child=adapter.commands(options,str(run.tools['python']),public['invocation'][2])
    assert public['invocation']==invocation and owner['command']==child==result['invocation']
    assert owner['env']==adapter.environment(options)
    raw=driver.raw_pin(run,recipe,Path(owner_ref['path']).with_suffix('.log'),cap=8*MIB)
    assert sha(raw)==owner['closed']['private_log_sha256'] and json.loads(raw)==projection(result)
    for name in ('sources-before.json','sources-after.json'):
        assert driver.read_json(run,recipe,directory/name,cap=16*MIB)==run.sources
    assert result['evidence_budget']['exceeded'] is False and result['evidence_budget']['reservation_active'] is False
    for name,pin in result['retained'].items(): driver.raw_pin(run,recipe,Path(name),pin,512*MIB)
    for name,pin in result['tool_pins'].items():
        driver.raw_pin(run,recipe,Path(name),pin,512*MIB)
        if name in run.tool_pins: assert run.tool_pins[name]==pin
        else: run.tool_pins[name]=pin
    return result


def accept_inputs(run,recipe,driver):
    a=run.a
    build=driver.accept_build(run,recipe,a.build,a.build_sha,a.build_owner,a.build_owner_sha,run.git)
    assert 'producer' in build and build['revision']==a.revision and build['hardware']==a.hardware
    # Adopt the exact authenticated build environment, as the existing tests reader does.
    comparable=dict(run.env,CLANG=build['tools']['clang']['path'],TMPDIR=build['environment']['TMPDIR'])
    assert comparable==build['environment']
    run.env.clear();run.env.update(build['environment']);run.result['environment']=dict(run.env)
    return build


def build_sdk(run,recipe,driver,builder,build):
    tools,versions=builder.tools_metadata(run,recipe)
    assert tools==build['tools'] and versions==build['versions']
    assert builder.source_inventory(run,run.git)==build['sources']
    run.result['build_reference']=reference(run.a,'build')
    run.result['build_owner_reference']=reference(run.a,'build-owner')
    products={};stages=[]
    for index,argv in enumerate(sdk_commands(run.tools['cargo'])):
        name=('sdk-oracle','sdk-calibrations')[index]
        row,out,_=builder.bounded(run,driver,recipe,name,run.raw/name,argv,(120,180,128*MIB))
        target,source,kind,test=(('frontend-native-oracle','native-interval/main.rs','bin',False),
            ('frontend-native-calibrations','native-interval/calibrations.rs','test',True))[index]
        original,artifact=run.m['native'].artifact(out,target,source,kind,test)
        pin=builder.copy_product(run,recipe,original,run.raw/target)
        run.freeze(run.raw/(name+'-artifact.json'),artifact)
        products[target]=dict(path=str(run.raw/target),**pin);stages.append(row)
    run.result.update(products=products,build_stages=stages,status=STATUS['sdk-build'])


def accept_sdk_build(run,recipe,driver,adapter,build):
    r=record(run,recipe,driver,adapter,reference(run.a,'sdk-build'),reference(run.a,'sdk-build-owner'),'sdk-build')
    assert r['build_reference']==reference(run.a,'build') and r['build_owner_reference']==reference(run.a,'build-owner')
    directory=Path(run.a.sdk_build).parent
    assert set(r['products'])=={'frontend-native-oracle','frontend-native-calibrations'}
    assert len(r['build_stages'])==len(r['stages'])==2
    for index,(row,argv) in enumerate(zip(r['build_stages'],sdk_commands(run.tools['cargo']))):
        name=('sdk-oracle','sdk-calibrations')[index];assert row['name']==name
        d=directory/name
        request=dict(argv=argv,cwd=str(ROOT),env=run.env,stdout=str(d/'stdout'),stderr=str(d/'stderr'),
            cpu_seconds=120,wall_seconds=180,file_bytes=128*MIB)
        code,out,err,receipt=driver.closed_stage(run,recipe,d,request,row['closed']);assert code==0
        assert row['request_sha256']==run.retained[str(d/'request.json')]['sha256']
        assert row['receipt_sha256']==run.retained[str(d/'receipt.json')]['sha256']
        assert (row['stdout_sha256'],row['stderr_sha256'])==(sha(out),sha(err))
        stage=r['stages'][index];assert stage['name']==name+'-owner' and stage['status']=='CLOSED_EXIT_0' and stage['closed']==row['closed']
        outer=directory/(name+'-owner')
        assert driver.read_json(run,recipe,outer/'command.json')==dict(argv=[str(run.tools['python']),'-B',str(ROOT/'tools/unwind-oracle/bounded_command.py'),
            '--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')],cwd=str(ROOT),env=run.env,wall_seconds=205,log_bytes=MIB)
        assert driver.read_json(run,recipe,outer/'closed.json')==row['closed']
        target,source,kind,test=(('frontend-native-oracle','native-interval/main.rs','bin',False),
            ('frontend-native-calibrations','native-interval/calibrations.rs','test',True))[index]
        original,artifact=run.m['native'].artifact(out,target,source,kind,test)
        assert driver.read_json(run,recipe,directory/(name+'-artifact.json'))==artifact
        product=r['products'][target];assert product['path']==str(directory/target)
        copied={k:product[k] for k in ('bytes','sha256')}
        driver.raw_pin(run,recipe,Path(product['path']),copied)
        driver.raw_pin(run,recipe,original,copied)
    return r


def old_controls(run,recipe,driver,leaf,owners,build,result_ref,owner_ref):
    # Explicit argument view for the unchanged old whole-profile reader; no global mutation.
    legacy=copy.copy(run);legacy.a=argparse.Namespace(**dict(vars(run.a),profile=driver.WHOLE_PROFILE))
    legacy.env=dict(run.scalar_environment);legacy.result=copy.deepcopy(run.result)
    return driver.replay_controls(legacy,recipe,leaf,owners,Path(result_ref['path']),result_ref['sha256'],
        Path(owner_ref['path']),owner_ref['sha256'],build,run.a.build,run.git)


def replay_stage(run,recipe,driver,result,name,argv,cap=MIB):
    directory=Path(result['arguments']['raw']);d=directory/(name+'-io');outer=directory/name
    rows=[r for r in result['stages'] if r['name']==name];assert len(rows)==1
    row=rows[0]
    request=dict(argv=list(map(str,argv)),cwd=str(ROOT),env=run.env,stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),
        cpu_seconds=20,wall_seconds=30,file_bytes=cap)
    actual=driver.read_json(run,recipe,d/'request.json');assert actual==request
    command=dict(argv=[str(run.tools['python']),'-B',str(ROOT/'tools/unwind-oracle/bounded_command.py'),
        '--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')],cwd=str(ROOT),env=run.env,wall_seconds=55,log_bytes=MIB)
    assert driver.read_json(run,recipe,outer/'command.json')==command
    closed=driver.read_json(run,recipe,outer/'closed.json');assert closed==row['closed']
    receipt=driver.read_json(run,recipe,d/'receipt.json')
    out=driver.raw_pin(run,recipe,d/'stdout.txt',cap=cap);err=driver.raw_pin(run,recipe,d/'stderr.txt',cap=cap)
    code=recipe.bounded_join(receipt,closed,run.retained[str(d/'request.json')],run.sources[str(ROOT/'tools/unwind-oracle/bounded_command.py')],recipe.pin(out),recipe.pin(err))
    assert row['status']=='CLOSED_EXIT_'+str(closed['exit_code'])
    parent=driver.raw_pin(run,recipe,outer/'parent.log',cap=MIB)
    assert sha(parent)==closed['private_log_sha256'] and json.loads(parent)==dict(exit=code,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=code==0)
    return code,out,err


def sdk_controls(run,recipe,driver,leaf,owners,build,sdk):
    before=reference(run.a,'controls');before_owner=reference(run.a,'controls-owner')
    old_controls(run,recipe,driver,leaf,owners,build,before,before_owner)
    binary=sdk['products']['frontend-native-calibrations']['path']
    out,err=run.stage('sdk-list',[binary,'--list']);names=run.m['census'].census(out,err);wanted=inventory(names)
    out,err=run.stage('sdk-rust',[binary,*wanted,'--exact','--test-threads=1'])
    rust=run.m['census'].controls(out,err,wanted,names)
    out,err=run.stage('sdk-python',[run.tools['python'],'-B',HERE/'sdk_state_controls.py','-v'])
    owners.reuse_python_controls(out,err,PYTHON_CONTROLS)
    run.result.update(status=STATUS['sdk-controls'],old_controls_reference=before,old_controls_owner_reference=before_owner,
        sdk_build_reference=reference(run.a,'sdk-build'),sdk_build_owner_reference=reference(run.a,'sdk-build-owner'),
        inventory=names,rust=rust,rust_required=list(wanted),python_required=list(PYTHON_CONTROLS))


def accept_controls(run,recipe,driver,adapter,leaf,owners,build,sdk):
    r=record(run,recipe,driver,adapter,reference(run.a,'sdk-controls'),reference(run.a,'sdk-controls-owner'),'sdk-controls')
    assert r['sdk_build_reference']==reference(run.a,'sdk-build') and r['sdk_build_owner_reference']==reference(run.a,'sdk-build-owner')
    old_controls(run,recipe,driver,leaf,owners,build,r['old_controls_reference'],r['old_controls_owner_reference'])
    assert [row['name'] for row in r['stages']]==['sdk-list','sdk-rust','sdk-python']
    binary=sdk['products']['frontend-native-calibrations']['path']
    code,out,err=replay_stage(run,recipe,driver,r,'sdk-list',[binary,'--list']);assert code==0
    names=run.m['census'].census(out,err);wanted=inventory(names);assert names==r['inventory']
    code,out,err=replay_stage(run,recipe,driver,r,'sdk-rust',[binary,*wanted,'--exact','--test-threads=1']);assert code==0
    assert run.m['census'].controls(out,err,wanted,names)==r['rust'] and r['rust_required']==list(wanted)
    code,out,err=replay_stage(run,recipe,driver,r,'sdk-python',[run.tools['python'],'-B',HERE/'sdk_state_controls.py','-v']);assert code==0
    owners.reuse_python_controls(out,err,PYTHON_CONTROLS);assert r['python_required']==list(PYTHON_CONTROLS)
    return r


def geometry_shape(value,build,sdk_ref):
    assert value['kind']=='selected-sdk-copied-geometry-acceptance-v1' and value['scope']==PROFILE
    assert value['status']=='INDEPENDENTLY_ACCEPTED_FOR_FIXED_COPIED_SDK_STATE'
    assert value['native_state']=='UNRUN_SEPARATE_REQUIRED' and value['sdk_build']==sdk_ref
    assert value['build_revision']==build['revision'] and value['products']==build['products']
    required=('complete_symbol_extents','complete_cfg_and_all_returns','complete_elf_and_source_pages',
        'strip_preserves_selected_bytes_and_pages','ordinary_rust_and_reference_callers','immutable_path_and_object_lifetime',
        'scalar_sysv_abi_and_readable_inputs','termination_no_hidden_calls_exits_or_concurrency','cet_and_signal_preconditions')
    assert set(value['premises'])==set(required) and all(value['premises'][k] is True for k in required)
    assert value['review'] and value['fact_pins']
    assert value['caller']=={'extent':20,'continuation':15}
    assert value['caller_state']==dict(heads=[0,1,4,7,10,13,15,18,19],call=13,outer_ret=19,subject_rsp_delta=16,stack_bytes=152,
        body_sha256='732eb5cbc05ef8024c072c75ca3df69d08214cec8dc92beec456b1a5a3ff3046')
    table=value['table'];assert len(table)==2
    assert [(r['function_id'],r['operation'],r['policy'],r['extent'],r['returns']) for r in table]==[
        (101,'first_equal','whole',41,[34,40]),(202,'uppercase_count','whole',55,[40,54])]
    assert type(table[0]['elf_va']) is int and table[0]['elf_va']>0 and table[0]['elf_va']%4096==0
    assert table[1]['elf_va']==table[0]['elf_va']+48
    return table


def accept_geometry(run,recipe,driver,new,build):
    value=driver.read_json(run,recipe,run.a.geometry,run.a.geometry_sha)
    assert value['build_result_sha256']==run.a.build_sha
    table=geometry_shape(value,build,reference(run.a,'sdk-build'))
    for name,pin in value['fact_pins'].items(): driver.raw_pin(run,recipe,Path(name),pin)
    ordered=tuple(dict(row,returns=tuple(row['returns'])) for row in table)
    new['output'].geometry(ordered,value['caller'],tuple(run.cpus[:2]),profile=driver.WHOLE_PROFILE)
    directory=Path(run.a.build).parent
    defs=new['geometry'].preserved(driver.symbol_suffix(recipe.read(directory/'leaves.so-elf/stdout',4*MIB)),
        driver.symbol_suffix(recipe.read(directory/'leaves-stripped.so-elf/stdout',4*MIB)))
    assert [(r['name'],r['elf_va'],r['extent']) for r in defs]==[(r['operation'],r['elf_va'],r['extent']) for r in table]
    assert value['source_pages']==[table[0]['elf_va']//4096]
    return value


def pair_argv(binary,copies,output,key,table):
    checked_key(key);assert len(table)==2
    return [str(binary),PROFILE,*[str(copies[k]) for k in ('dso_candidate','dso_trusted','app_candidate','app_trusted')],
        str(output),key['form'],str(key['k']),str(key['seed']),str(key['function_id']),str(key['input_index']),
        *[str(row[k]) for row in table for k in ('elf_va','extent')]]


def prepare_cohort(run,recipe,driver,builder,build,sdk,geometry):
    products=Path(run.a.build).parent/'products';copies={}
    dso='leaves.so' if run.a.cohort.startswith('unstripped-') else 'leaves-stripped.so'
    for label,source in [('dso_candidate',products/dso),('dso_trusted',products/dso),
                         ('app_candidate',products/'ordinary-interval'),('app_trusted',products/'ordinary-interval')]:
        destination=run.raw/(label+('.so' if label.startswith('dso') else '.elf'))
        builder.copy_product(run,recipe,source,destination);copies[label]=str(destination)
    assert len({(Path(p).stat().st_dev,Path(p).stat().st_ino) for p in copies.values()})==4
    binary=sdk['products']['frontend-native-oracle']['path'];plans=[]
    for index,row in enumerate(run.result['rows']):
        name='pair-'+str(index).zfill(2);directory=run.raw/(name+'-io');output=directory/'output'
        argv=pair_argv(binary,copies,output,row['key'],geometry['table']);assert len(argv)==16
        request=run.request(directory,argv,cpu=20,wall=30,cap=4*MIB);run.plan_bounded(name,directory,request)
        plans.append(dict(name=name,key=row['key'],request=request,output=str(output)))
    plan=dict(schema=SCHEMA,profile=PROFILE,cohort=run.a.cohort,all_keys=keys(),keys=keys(run.a.cohort),plans=plans,copies=copies,
        build=reference(run.a,'build'),build_owner=reference(run.a,'build-owner'),sdk_build=reference(run.a,'sdk-build'),
        sdk_build_owner=reference(run.a,'sdk-build-owner'),sdk_controls=reference(run.a,'sdk-controls'),
        sdk_controls_owner=reference(run.a,'sdk-controls-owner'),geometry=reference(run.a,'geometry'),
        attempts_per_key=1,cpu_seconds=20,wall_seconds=30,pair_seconds=15,steps_per_child=20000)
    run.freeze(run.raw/'plan.json',plan,4*MIB);return plan


def execute_cohort(run,recipe,driver,plan):
    for row,spec in zip(run.result['rows'],plan['plans']):
        try:
            recipe.bounded_ready(run,spec['request'],app_files=True)
        except BaseException as error:
            run.result['stop_reason']=type(error).__name__+': '+str(error);break
        row['attempts']=1;row['status']='FAILED'
        try:
            directory=Path(spec['request']['stdout']).parent;output=Path(spec['output'])
            code,out,err=run.bounded(spec['name'],directory,spec['request'],generated=((output/OUTPUT,MIB),),app_files=True)
            row['child_exit']=code
            assert output.is_dir() and not output.is_symlink() and sorted(p.name for p in output.iterdir())==[OUTPUT]
            raw=driver.raw_pin(run,recipe,output/OUTPUT,cap=MIB)
            row['observed']=pair_output(raw,out,err,row['key']);assert code==0
            row['output_pin']=run.retained[str(output/OUTPUT)]
            row['status']='PASS'
        except BaseException as error:
            row['error']=type(error).__name__+': '+str(error)
        finally:
            stage=next((r for r in run.result['stages'] if r['name']==spec['name']),None)
            if stage is not None and 'closed' in stage: row['closed']=stage['closed']
        if not run.safe: break
        run.budget.complete();run.unchanged()
    if population(run.result['rows'],run.a.cohort): run.result['status']=STATUS['sdk-cohort']


def collect(run,recipe,driver,adapter,build,sdk,geometry):
    refs=driver.read_json(run,recipe,run.a.cohorts,run.a.cohorts_sha)
    assert type(refs) is list and len(refs)==4
    assert [r['cohort'] for r in refs]==list(COHORTS)
    output=[]
    for cohort,item in zip(COHORTS,refs):
        assert set(item)=={'cohort','result','owner'}
        r=record(run,recipe,driver,adapter,item['result'],item['owner'],'sdk-cohort',allow_failed=True)
        assert r['arguments']['cohort']==cohort
        directory=Path(item['result']['path']).parent;plan=driver.read_json(run,recipe,directory/'plan.json',cap=4*MIB)
        assert plan['schema']==SCHEMA and plan['profile']==PROFILE and plan['cohort']==cohort
        assert plan['all_keys']==keys() and plan['keys']==keys(cohort) and [s['key'] for s in plan['plans']]==keys(cohort)
        assert (plan['attempts_per_key'],plan['cpu_seconds'],plan['wall_seconds'],plan['pair_seconds'],plan['steps_per_child'])==(1,20,30,15,20000)
        for name in ('build','build-owner','sdk-build','sdk-build-owner','sdk-controls','sdk-controls-owner','geometry'):
            assert plan[name.replace('-','_')]==reference(run.a,name)
        copies=plan['copies'];assert set(copies)=={'dso_candidate','dso_trusted','app_candidate','app_trusted'}
        dso='leaves.so' if cohort.startswith('unstripped-') else 'leaves-stripped.so'
        for label,path in copies.items():
            expected=directory/(label+('.so' if label.startswith('dso') else '.elf'));assert path==str(expected)
            driver.raw_pin(run,recipe,expected,build['products'][dso if label.startswith('dso') else 'ordinary-interval'])
        assert len({(Path(p).stat().st_dev,Path(p).stat().st_ino) for p in copies.values()})==4
        population(r['rows'],cohort)
        assert [s['name'] for s in r['stages']]==['pair-'+str(i).zfill(2) for i in range(sum(x['attempts'] for x in r['rows']))]
        for index,(row,spec) in enumerate(zip(r['rows'],plan['plans'])):
            name='pair-'+str(index).zfill(2);d=directory/(name+'-io');dest=d/'output'
            argv=pair_argv(sdk['products']['frontend-native-oracle']['path'],copies,dest,row['key'],geometry['table'])
            request=dict(argv=argv,cwd=str(ROOT),env=run.env,stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),cpu_seconds=20,wall_seconds=30,file_bytes=4*MIB)
            assert spec==dict(name=name,key=row['key'],request=request,output=str(dest))
            assert driver.read_json(run,recipe,d/'request.json')==request
            if row['attempts']==1:
                code,out,err=replay_stage(run,recipe,driver,r,name,argv,4*MIB)
                assert code==row['child_exit']
                assert row['closed']==next(s for s in r['stages'] if s['name']==name)['closed']
            if row['status']=='PASS':
                assert code==0
                assert sorted(p.name for p in dest.iterdir())==[OUTPUT] and not dest.is_symlink()
                raw=driver.raw_pin(run,recipe,dest/OUTPUT,row['output_pin'],MIB)
                assert pair_output(raw,out,err,row['key'])==row['observed']
            output.append(row)
            run.result['rows'][len(output)-1]=row
    assert [r['key'] for r in output]==keys();run.result['rows']=output
    if population(output):
        assert sum(uint(r['observed']['comparisons']) for r in output)==27560
        for form in ('unstripped','stripped'):
            for k in (10,1000):
                for seed in SEEDS:
                    for function in (101,202):
                        group=[r for r in output if tuple(r['key'][x] for x in ('form','k','seed','function_id'))==(form,k,seed,function)]
                        assert [r['key']['input_index'] for r in group]==list(range(12))
                        observed=set();edges=set();returns=set()
                        for r in group:
                            observed.update(uint(x) for x in r['observed']['observed_head_set'].split(';'))
                            edges.update(tuple(map(uint,x.split('-'))) for x in r['observed']['observed_edge_set'].split(';'))
                            returns.add(uint(r['observed']['ret_offset']))
                        expected,expected_edges=coverage(group[0]['key'])
                        assert observed==set(expected) and edges==set(expected_edges) and returns==set(RETURNS[int(function==202)])
        run.result['status']=STATUS['sdk-collect']


def main():
    started=time.monotonic();parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=tuple(STATUS),required=True)
    for name in ('revision','reservation-tag','hardware'): parser.add_argument('--'+name,required=True)
    for name in ('raw','toolchain','user-home','cargo-home'): parser.add_argument('--'+name,type=Path,required=True)
    paths=('build','build-owner','sdk-build','sdk-build-owner','controls','controls-owner','sdk-controls','sdk-controls-owner','geometry','cohorts')
    for name in paths:
        parser.add_argument('--'+name,type=Path);parser.add_argument('--'+name+'-sha')
    parser.add_argument('--cohort',choices=COHORTS)
    args=parser.parse_args()
    # Validate phase grammar before module loading or allocating any output.
    required={'sdk-build':('build','build-owner'),
        'sdk-controls':('build','build-owner','sdk-build','sdk-build-owner','controls','controls-owner'),
        'sdk-cohort':('build','build-owner','sdk-build','sdk-build-owner','sdk-controls','sdk-controls-owner','geometry'),
        'sdk-collect':('build','build-owner','sdk-build','sdk-build-owner','sdk-controls','sdk-controls-owner','geometry','cohorts')}[args.phase]
    for name in paths:
        values=(getattr(args,name.replace('-','_')),getattr(args,(name+'-sha').replace('-','_')))
        assert all(v is not None for v in values) if name in required else all(v is None for v in values)
    assert (args.cohort is not None)==(args.phase=='sdk-cohort')
    run,recipe,driver,builder,adapter,new,leaf,owners,git=load_context(args,started);run.git=git
    try:
        build=accept_inputs(run,recipe,driver)
        if args.phase=='sdk-build': build_sdk(run,recipe,driver,builder,build)
        else:
            sdk=accept_sdk_build(run,recipe,driver,adapter,build)
            if args.phase=='sdk-controls': sdk_controls(run,recipe,driver,leaf,owners,build,sdk)
            else:
                accept_controls(run,recipe,driver,adapter,leaf,owners,build,sdk)
                geometry=accept_geometry(run,recipe,driver,new,build)
                if args.phase=='sdk-cohort': execute_cohort(run,recipe,driver,prepare_cohort(run,recipe,driver,builder,build,sdk,geometry))
                else: collect(run,recipe,driver,adapter,build,sdk,geometry)
        run.unchanged();run.freeze(run.raw/'sources-after.json',run.sources,16*MIB)
    except BaseException as error:
        run.result.update(status='FAILED',error=type(error).__name__+': '+str(error))
    finally:
        run.budget.stopped()
        run.result.update(custody_closed=run.safe,retention_verified=False,retained=dict(run.retained),tool_pins=dict(run.tool_pins),
            load_after=list(os.getloadavg()),evidence_budget=run.budget.summary())
        try:
            assert run.safe and not run.budget.exceeded and run.budget.used<=recipe.EVIDENCE_LIMIT-recipe.FINAL_ALLOWANCE
            run.unchanged();run.result['retention_verified']=True
        except BaseException as error: run.result.update(status='FAILED',final_error=type(error).__name__+': '+str(error))
        recipe.save(run.raw/'result.json',run.result,32*MIB)
        print(json.dumps(projection(run.result),sort_keys=True))
    return 0 if run.result['status']==STATUS[args.phase] and time.monotonic()<run.deadline else 1


if __name__=='__main__':
    raise SystemExit(main())
