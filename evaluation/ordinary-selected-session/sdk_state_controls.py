#!/usr/bin/env python3
"""Fabricated SDK wire/plan/closure controls; no compiler or native dispatch."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode=True
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).parent/filename)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


sdk=load('_selected_sdk_controls','sdk_state.py')
owner=load('_selected_sdk_owner_controls','owner.py')
recipe=load('_selected_sdk_recipe_controls','../ordinary-module-session/reproduce.py')
VISITS=((4,11,9,14,24,19,16,46,326,9,324,326),(5,14,14,28,56,56,21,63,455,455,455,455))
ANSWERS=((0,1,0,1,3,2,2,8,64,0,63,64),(0,0,0,0,3,3,0,2,64,0,0,0))


def streams(key,changes=None):
    row=sdk.expected_fields(key)
    row.update(original_steps=row['comparisons'],candidate_steps=str(int(row['comparisons'])+8))
    if changes: row.update(changes)
    columns=sdk.HEADER.strip().split(',')
    raw=(sdk.HEADER+','.join(row[name] for name in columns)+'\n').encode()
    return raw,sdk.terminal(key,int(row['comparisons'])),b''


def options(phase):
    out=dict(phase=phase,revision='a'*40,**{'reservation-tag':'sdk-fixed',
        'owner':'/fabricated/owner.json','raw':'/fabricated/raw','toolchain':'/fabricated/toolchain',
        'user-home':'/fabricated/user','cargo-home':'/fabricated/cargo','hardware':'AMD EPYC Zen 5 dev host'})
    for key in (owner.SDK_EXTRAS[phase] if phase in owner.SDK_EXTRAS else owner.EXTRAS[phase]):
        out[key]='b'*64 if key.endswith('-sha') else 'unstripped-k10' if key=='cohort' else '/fabricated/'+key+'.json'
    return out


def geometry():
    build=dict(revision='a'*40,products={'fabricated':'identity'})
    ref=dict(path='/fabricated/sdk/result.json',sha256='b'*64)
    names=('complete_symbol_extents','complete_cfg_and_all_returns','complete_elf_and_source_pages',
        'strip_preserves_selected_bytes_and_pages','ordinary_rust_and_reference_callers','immutable_path_and_object_lifetime',
        'scalar_sysv_abi_and_readable_inputs','termination_no_hidden_calls_exits_or_concurrency','cet_and_signal_preconditions')
    value=dict(kind='selected-sdk-copied-geometry-acceptance-v1',scope=sdk.PROFILE,
        status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_COPIED_SDK_STATE',native_state='UNRUN_SEPARATE_REQUIRED',sdk_build=ref,
        build_revision=build['revision'],products=build['products'],premises=dict.fromkeys(names,True),
        review='fabricated explicit review only',fact_pins={'/fabricated/facts':{'sha256':'c'*64,'bytes':1}},
        caller=dict(extent=20,continuation=15),caller_state=dict(heads=[0,1,4,7,10,13,15,18,19],call=13,outer_ret=19,
            subject_rsp_delta=16,stack_bytes=152,body_sha256='732eb5cbc05ef8024c072c75ca3df69d08214cec8dc92beec456b1a5a3ff3046'),
        table=[dict(function_id=101,operation='first_equal',policy='whole',extent=41,returns=[34,40],elf_va=4096),
            dict(function_id=202,operation='uppercase_count',policy='whole',extent=55,returns=[40,54],elf_va=4144)])
    return value,build,ref


def closure_fixture(code):
    root=Path('/fabricated/sdk-cohort');name='pair-00';d=root/(name+'-io');outer=root/name
    argv=['/fabricated/oracle','fixed'];env={'LC_ALL':'C'}
    request=dict(argv=argv,cwd=str(sdk.ROOT),env=env,stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),
        cpu_seconds=20,wall_seconds=30,file_bytes=sdk.MIB)
    canonical=lambda v:(json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
    raw_request=canonical(request);out=b'raw stdout';err=b''
    parent=canonical(dict(exit=code,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=code==0))
    closed=dict(cleanup_complete=True,reaped_descendants=0,termination=None,exit_code=0 if code==0 else 1,
        private_log_sha256=sdk.sha(parent))
    helper=sdk.ROOT/'tools/unwind-oracle/bounded_command.py';helper_pin=recipe.pin(b'fixed helper')
    receipt=dict(exit=code,absence_proof='ECHILD',inputs_unchanged=True,wall_timeout=False,
        unexpected_descendants=[],cleanup_events=[],aborted=None,cleanup_error=None,
        request_sha256=sdk.sha(raw_request),helper_sha256=helper_pin['sha256'],stdout_sha256=sdk.sha(out),stderr_sha256=sdk.sha(err))
    command=dict(argv=['/tools/python','-B',str(helper),'--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')],
        cwd=str(sdk.ROOT),env=env,wall_seconds=55,log_bytes=sdk.MIB)
    files={str(d/'request.json'):raw_request,str(d/'receipt.json'):canonical(receipt),str(d/'stdout.txt'):out,
        str(d/'stderr.txt'):err,str(outer/'command.json'):canonical(command),str(outer/'closed.json'):canonical(closed),str(outer/'parent.log'):parent}
    run=SimpleNamespace(env=env,retained={},sources={str(helper):helper_pin},tools={'python':Path('/tools/python')})
    def raw_pin(run,unused,path,expected=None,cap=sdk.MIB):
        raw=files[str(path)];assert len(raw)<=cap
        actual=recipe.pin(raw)
        if expected is not None: assert actual==expected
        if str(path) in run.retained: assert run.retained[str(path)]==actual
        run.retained[str(path)]=actual
        return raw
    def read_json(run,unused,path,digest=None,cap=sdk.MIB):
        raw=raw_pin(run,unused,path,cap=cap)
        if digest is not None: assert sdk.sha(raw)==digest
        return json.loads(raw)
    driver=SimpleNamespace(read_json=read_json,raw_pin=raw_pin)
    result=dict(arguments={'raw':str(root)},stages=[dict(name=name,status='CLOSED_EXIT_'+str(closed['exit_code']),closed=closed)])
    return run,driver,result,name,argv,files,d,outer,canonical


class Controls(unittest.TestCase):
    def test_population_is_four_exact_cohorts_and_sixteen_complete_groups(self):
        all_keys=sdk.keys()
        self.assertEqual(len(all_keys),192)
        self.assertEqual([key for name in sdk.COHORTS for key in sdk.keys(name)],all_keys)
        groups={tuple(k[n] for n in ('form','k','seed','function_id')) for k in all_keys}
        self.assertEqual(len(groups),16)
        for group in groups:
            self.assertEqual([k['input_index'] for k in all_keys if tuple(k[n] for n in ('form','k','seed','function_id'))==group],list(range(12)))
        for value in (True,1.0,'1'):
            with self.assertRaises(AssertionError): sdk.checked_key(dict(all_keys[1],input_index=value))
        for name in ('unstripped-k11','unstripped-k10-retry','all',''):
            with self.assertRaises(AssertionError): sdk.keys(name)

    def test_literal_itineraries_values_and_boundary_sum_are_independent(self):
        total=0
        for key in sdk.keys():
            m=sdk.meaning(key);op=int(key['function_id']==202);index=key['input_index']
            self.assertEqual(len(m['visits']),VISITS[op][index]);self.assertEqual(m['answer'],ANSWERS[op][index])
            self.assertEqual(m['reads'],list(range(len(sdk.INPUTS[index]) if op else min(ANSWERS[0][index]+1,len(sdk.INPUTS[index])))))
            self.assertIn(m['ret'],((34,40),(40,54))[op]);self.assertEqual(m['visits'][-1],m['ret'])
            total+=len(m['visits'])+10
        self.assertEqual(total,27560)
        for key in (sdk.keys()[0],sdk.keys()[12]):
            heads,_=sdk.coverage(key);op=int(key['function_id']==202)
            self.assertEqual(set(sdk.HEADS[op])-set(heads),{41} if op else {12,35})
            self.assertTrue(set(sdk.RETURNS[op])<=set(heads))

    def test_full_row_and_terminal_accept_every_frozen_key(self):
        for key in sdk.keys():
            row=sdk.pair_output(*streams(key),key)
            self.assertEqual(len(row),39);self.assertEqual(row['normal_reaps'],'2')
            self.assertEqual(int(row['result']),ANSWERS[int(key['function_id']==202)][key['input_index']])

    def test_key_profile_policy_and_scalar_mutations_refuse(self):
        key=sdk.keys()[4]
        for name,value in dict(profile='normal-module-session',form='stripped',k='1000',seed='0',function_id='202',input_index='5',
                               functions='1',policies='whole+certified',status='FAIL',result='0',outer_rax='0').items():
            with self.subTest(field=name),self.assertRaises(AssertionError): sdk.pair_output(*streams(key,{name:value}),key)
        for value in ('01','+1',' 1','18446744073709551616','-1','1.0'):
            with self.assertRaises(AssertionError): sdk.uint(value)

    def test_visits_reads_returns_and_whole_coverage_sets_refuse(self):
        key=sdk.keys()[8]
        for name in ('visits','input_reads','ret_offset','observed_heads','reachable_heads','observed_edges','reachable_edges',
                     'declared_returns','decoded_heads','observed_head_set','observed_edge_set','reachable_head_set','reachable_edge_set','return_set'):
            with self.subTest(field=name),self.assertRaises(AssertionError): sdk.pair_output(*streams(key,{name:'0'}),key)
        raw,out,err=streams(key)
        with self.assertRaises(AssertionError): sdk.pair_output(raw.replace(b'34;40',b'40;34'),out,err,key)

    def test_counts_limits_framing_and_terminal_refuse(self):
        key=sdk.keys()[0]
        for name in ('children','comparisons','caller_bytes','caller_heads','call_offset','continuation_offset','outer_ret_offset',
                     'subject_rsp_delta','target_calls','target_returns','outer_returns','normal_reaps'):
            with self.subTest(field=name),self.assertRaises(AssertionError): sdk.pair_output(*streams(key,{name:'0'}),key)
        for name in ('original_steps','candidate_steps'):
            for value in ('13','20001','020'):
                with self.assertRaises(AssertionError): sdk.pair_output(*streams(key,{name:value}),key)
        raw,out,err=streams(key)
        for changed in (raw[:-1],raw+raw.splitlines(keepends=True)[1],raw.replace(b'\n',b'\r\n'),raw+b'\n',b'x'+raw):
            with self.assertRaises(AssertionError): sdk.pair_output(changed,out,err,key)
        for changed in (b'',out+b'\n',out.replace(b'normal-reaps=2',b'normal-reaps=1')):
            with self.assertRaises(AssertionError): sdk.pair_output(raw,changed,err,key)
        with self.assertRaises(AssertionError): sdk.pair_output(raw,out,b'diagnostic',key)

    def test_actual_bounded_join_replays_nonzero_and_refuses_false_custody(self):
        for code in (0,1,2):
            run,driver,result,name,argv,files,d,outer,canonical=closure_fixture(code)
            self.assertEqual(sdk.replay_stage(run,recipe,driver,result,name,argv),(code,b'raw stdout',b''))
        mutants=(('receipt.json','inputs_unchanged',False),('receipt.json','absence_proof','unknown'),
            ('receipt.json','wall_timeout',True),('receipt.json','unexpected_descendants',[19]),
            ('receipt.json','cleanup_events',[19]),('receipt.json','aborted','signal'),
            ('receipt.json','helper_sha256','0'*64),('receipt.json','stdout_sha256','0'*64),
            ('closed.json','cleanup_complete',False),('closed.json','reaped_descendants',1),
            ('closed.json','termination','timeout'),('closed.json','exit_code',1))
        for member,key,value in mutants:
            run,driver,result,name,argv,files,d,outer,canonical=closure_fixture(0)
            path=(outer if member=='closed.json' else d)/member
            changed=json.loads(files[str(path)]);changed[key]=value;files[str(path)]=canonical(changed)
            if member=='closed.json':
                result['stages'][0]['closed']=changed
                result['stages'][0]['status']='CLOSED_EXIT_'+str(changed['exit_code'])
            with self.subTest(member=member,field=key),self.assertRaises(AssertionError): sdk.replay_stage(run,recipe,driver,result,name,argv)

    def test_population_missing_duplicate_reordered_and_retry_refuse(self):
        rows=[dict(r,status='PASS',attempts=1) for r in sdk.initial_rows()]
        self.assertTrue(sdk.population(rows))
        for changed in (rows[:-1],rows+[rows[-1]],list(reversed(rows)),rows[:1]+rows[:-1]):
            with self.assertRaises(AssertionError): sdk.population(changed)
        for patch in ({'attempts':2},{'attempts':True},{'status':'UNRUN','attempts':1},{'status':'PASS','attempts':0}):
            changed=copy.deepcopy(rows);changed[1].update(patch)
            with self.assertRaises(AssertionError): sdk.population(changed)

    def test_failed_and_unrun_rows_are_not_promoted(self):
        for unknown in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                events=[];rows=sdk.initial_rows(sdk.COHORTS[0]);root=Path(directory)
                run=SimpleNamespace(result=dict(rows=rows,stages=[],status='FAILED'),safe=True,a=SimpleNamespace(cohort=sdk.COHORTS[0]))
                run.budget=SimpleNamespace(complete=lambda:events.append('complete'))
                run.unchanged=lambda:events.append('unchanged')
                def bounded(name,where,request,**kwargs):
                    self.assertTrue(kwargs['app_files']);events.append(name)
                    run.result['stages'].append(dict(name=name,closed={'actual':'closed'}))
                    if unknown:
                        run.safe=False;raise ValueError('unknown custody')
                    return 1,b'',b'normal failure'
                run.bounded=bounded
                def ready(value,request,app_files): self.assertIs(value,run);self.assertTrue(app_files)
                recipe=SimpleNamespace(bounded_ready=ready)
                plan=dict(plans=[dict(name='pair-'+str(i).zfill(2),key=r['key'],request={'stdout':str(root/str(i)/'stdout.txt')},
                    output=str(root/str(i)/'output')) for i,r in enumerate(rows)])
                sdk.execute_cohort(run,recipe,None,plan)
                self.assertFalse(sdk.population(rows,sdk.COHORTS[0]));self.assertEqual(run.result['status'],'FAILED')
                self.assertEqual(sum(r['attempts'] for r in rows),1 if unknown else 48)
                self.assertEqual(rows[0]['closed'],{'actual':'closed'})
                if unknown:
                    self.assertTrue(all(r['status']=='UNRUN' for r in rows[1:]));self.assertNotIn('complete',events)
                else:
                    self.assertTrue(all(r['status']=='FAILED' and r['child_exit']==1 for r in rows))
                    self.assertEqual(events.count('complete'),48)

    def test_control_inventory_requires_exact_new_names(self):
        names=['unchanged::old']+list(sdk.RUST_CONTROLS)
        self.assertEqual(sdk.inventory(names),sdk.RUST_CONTROLS)
        for mutated in (names[:-1],names+names[-1:],names+[sdk.PREFIX+'unknown'],
                        [n.replace('compiled::literal','compiled::tests::literal') for n in names]):
            with self.assertRaises(AssertionError): sdk.inventory(mutated)

    def test_sdk_build_commands_select_distinct_release_binary_and_calibrations(self):
        binary,test=sdk.sdk_commands('/tools/cargo')
        tail=['--locked','--offline','--jobs','4','--message-format=json-render-diagnostics']
        self.assertEqual(binary,['/tools/cargo','build','--release','-p','rapid-profiler','--bin','frontend-native-oracle',*tail])
        self.assertEqual(test,['/tools/cargo','test','--release','-p','rapid-profiler','--test','frontend-native-calibrations','--no-run',*tail])
        self.assertNotIn('--bin',test);self.assertEqual(owner.WALL_SECONDS,1200);self.assertEqual(owner.OUTPUT_BYTES,8*1048576)

    def test_sdk_owner_commands_are_finite_and_old_profiles_stay_strict(self):
        for phase in owner.SDK_EXTRAS:
            opts=options(phase);invocation,child=owner.commands(opts,'/tools/python','evaluation/ordinary-selected-session/owner.py')
            self.assertEqual(child[2],str(owner.HERE/'sdk_state.py'));self.assertEqual(child[3:5],['--phase',phase])
            self.assertEqual(invocation[3:5],['--phase',phase])
            for patch in ({'extra':'/fabricated/extra'},{'profile':'selected-session-whole-functional-v1'},{'phase':'sdk-retry'}):
                with self.assertRaises(AssertionError): owner.commands(dict(opts,**patch),'/tools/python',invocation[2])
        for phase in ('products','tests','controls','campaign'):
            opts=options(phase);_,child=owner.commands(opts,'/tools/python','evaluation/ordinary-selected-session/owner.py')
            self.assertEqual(Path(child[2]).name,'build.py' if phase in ('products','tests') else 'reproduce.py')
            with self.assertRaises(AssertionError): owner.commands(dict(opts,cohort='unstripped-k10'),'/tools/python','evaluation/ordinary-selected-session/owner.py')
        opts=options('sdk-cohort');opts['cohort']='all'
        with self.assertRaises(AssertionError): owner.commands(opts,'/tools/python','evaluation/ordinary-selected-session/owner.py')

    def test_sdk_geometry_cannot_consume_scalar_or_mixed_policy_authority(self):
        value,build,ref=geometry();self.assertEqual(sdk.geometry_shape(value,build,ref),value['table'])
        for patch in ({'kind':'selected-session-geometry-acceptance-v1'},{'scope':'selected-session-whole-functional-v1'},
            {'status':'INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION'},{'sdk_build':dict(ref,sha256='f'*64)},
            {'native_state':'PASS'},{'review':''},{'fact_pins':{}},{'caller':{'extent':20,'continuation':16}}):
            with self.assertRaises(AssertionError): sdk.geometry_shape(dict(value,**patch),build,ref)
        for section,field,replacement in (('caller_state','stack_bytes',151),('premises','cet_and_signal_preconditions',False)):
            mutated=copy.deepcopy(value);mutated[section][field]=replacement
            with self.assertRaises(AssertionError): sdk.geometry_shape(mutated,build,ref)
        for index,field,replacement in ((0,'policy','certified'),(1,'extent',54),(1,'returns',[40]),(1,'elf_va',4145)):
            mutated=copy.deepcopy(value);mutated['table'][index][field]=replacement
            with self.assertRaises(AssertionError): sdk.geometry_shape(mutated,build,ref)


if __name__=='__main__':
    assert {n for n in vars(Controls) if n.startswith('test_')}==set(sdk.PYTHON_CONTROLS)
    unittest.main()
