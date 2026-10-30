#!/usr/bin/env python3
"""Pure Exact37 wire/custody controls; no compiler, native child or owner runs."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

def load(name,filename):
    spec = importlib.util.spec_from_file_location(name,Path(__file__).parent/filename)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module

exact = load('_exact_controls_state','exact_state.py')
owner = load('_exact_controls_owner','exact_state_owner.py')
geometry = load('_exact_controls_geometry','exact_state_geometry.py')
legacy = load('_exact_controls_inherited','sdk_state_controls.py')
sdk,recipe = legacy.sdk,legacy.recipe

def streams(key,changes=None):
    # Independent cumulative input traversal, not the checker's scalar helper.
    index = (0,1)[key['seed'] == 0xfedcba9801234567]
    accumulator = 0; byte = 11+index
    for _ in range(key['length']):
        accumulator += byte ^ 90; byte = (byte+37)&255
    answer = accumulator ^ 11400714819323198485
    n = key['length']; visits = 6*n+5
    row = dict(profile='exact37-accuracy-copied-state-v1',k='10',seed=str(key['seed']),function_id='41',length=str(n),
        status='PASS',children='2',comparisons=str(visits+10),visits=str(visits),original_steps=str(visits+10),
        candidate_steps=str(visits+18),result=str(answer),outer_rax=str(answer),instructions=str(visits),
        conditional_branches=str(n),taken_branches=str(n-1),input_reads=str(n),return_reads='1',return_read_bytes='8',
        ret_offset='36',decoded_heads='11',observed_heads='11',caller_bytes='20',caller_heads='9',call_offset='13',
        continuation_offset='15',outer_ret_offset='19',subject_rsp_delta='16',target_calls='2',target_returns='2',outer_returns='2',normal_reaps='2')
    if changes: row.update(changes)
    raw = (exact.HEADER+','.join(row[k] for k in exact.HEADER.strip().split(','))+'\n').encode()
    terminal = (f'native-exact37-accuracy:profile=exact37-accuracy-copied-state-v1:k=10:seed={key["seed"]}:function=41:length={n}'
        f':required=1:pairs=1:children=2:comparisons={visits+10}:target-calls=2:target-returns=2:real-outer-ret=2:'
        'normal-reaps=2:scope=copied-body-only:complete\n').encode()
    return raw,terminal,b''

def options(phase):
    result = dict(phase=phase,revision='a'*40,**{'reservation-tag':'exact-fixed','owner':'/inert/owner.json',
        'raw':'/inert/raw','toolchain':'/inert/toolchain','user-home':'/inert/user','cargo-home':'/inert/cargo',
        'hardware':'AMD EPYC Zen 5 dev host'})
    for name in owner.EXTRAS[phase]:
        result[name] = 'b'*64 if name.endswith('-sha') else exact.COHORTS[0] if name == 'cohort' else '/inert/'+name+'.json'
    return result

def accepted():
    facts = dict(revision='a'*40,table=[dict(function_id=41,operation='exact_work_nonempty',policy='whole',elf_va=4096,extent=37,returns=[36])],
        source_page=dict(elf_va=4096,file_offset=4096,bytes=4096,sha256='c'*64),caller={'complete':'inert fixture'})
    ref = dict(path='/inert/result.json',sha256='b'*64)
    value = dict(kind='exact37-accuracy-copied-geometry-acceptance-v1',
        status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_EXACT37_COPIED_ACCURACY_STATE',scope=exact.PROFILE,revision='a'*40,
        preparation=ref,build=ref,sdk_build=ref,facts=facts,premises=dict.fromkeys(geometry.PREMISES,True),
        review='Inert explicit review fixture, not execution authority',supporting_pins={'/inert/basis':dict(bytes=1,sha256='c'*64)},
        native_state='UNRUN_SEPARATE_REQUIRED',qualification=dict(pmu_metric=False,cadence=False,performance=False))
    return value,facts,ref

def record_fixture():
    """Mock byte loading only; actual metadata and normal_closed predicates run."""
    opts = options('exact-prepare'); args = SimpleNamespace(**{k.replace('-','_'):v for k,v in opts.items()})
    args.revision = 'a'*40; source = {str(exact.HERE/'exact_state_owner.py'):recipe.pin(b'inert owner source')}
    run = SimpleNamespace(a=args,sources=source,env={'LC_ALL':'C'},cpus=[1,3,5],tools={'python':Path('/tools/python')},retained={},tool_pins={})
    invocation,child = owner.commands(opts,'/tools/python',str(owner.HERE/'exact_state_owner.py'))
    result = dict(schema=exact.SCHEMA,profile=exact.PROFILE,phase='exact-prepare',revision=args.revision,status=exact.STATUS['exact-prepare'],
        scope=exact.SCOPE,arguments={k:v for k,v in opts.items() if k != 'owner'},invocation=child,rows=[],environment=run.env,
        hardware=args.hardware,cpus=run.cpus,custody_closed=True,retention_verified=True,source_unchanged=True,
        retained={},tool_pins={},evidence_budget=dict(exceeded=False,reservation_active=False))
    exact.evidence(result); log = json.dumps(exact.projection(result)).encode()
    outer = dict(base=args.revision,working_source_sha256={},source_unchanged=True,reserved_cpus=run.cpus,attempts=1,
        log_archived=True,wall_limit_seconds=1200,output_limit_bytes=8*exact.MIB,hardware=args.hardware,command=child,
        env=owner.environment(opts),closed=dict(cleanup_complete=True,reaped_descendants=0,termination=None,exit_code=0,private_log_sha256=exact.sha(log)),
        public_owner=dict(schema=owner.SCHEMA,phase='exact-prepare',revision=args.revision,
            recipe='evaluation/ordinary-selected-session/exact_state_owner.py',recipe_sha256=source[str(exact.HERE/'exact_state_owner.py')]['sha256'],invocation=invocation))
    values={'/inert/raw/result.json':result,'/inert/owner.json':outer,
        '/inert/raw/sources-before.json':copy.deepcopy(source),'/inert/raw/sources-after.json':copy.deepcopy(source)}
    def raw_pin(run,unused,path,expected=None,cap=exact.MIB):
        raw=log if str(path)=='/inert/owner.log' else b'inert'
        pin=recipe.pin(raw)
        if expected is not None: assert pin==expected
        if str(path) in run.retained: assert run.retained[str(path)]==pin
        run.retained[str(path)]=pin;return raw
    driver=SimpleNamespace(read_json=lambda run,recipe,path,*args,**kwargs:values[str(path)],raw_pin=raw_pin)
    return run,driver,result,outer,values

def collection(root,failures=False):
    args=SimpleNamespace(cohorts=root/'refs.json',cohorts_sha='a'*64)
    run=SimpleNamespace(a=args,env={'LC_ALL':'C'},retained={},result=dict(rows=exact.initial_rows(),status='FAILED',phase='exact-collect',inputs={'fixed':'inert references'}))
    exact.evidence(run.result)
    contents={'dso':b'inert Exact37 ELF','app':b'inert complete caller ELF'}
    facts=dict(trusted='/inert/exact-final.so',application='/inert/ordinary-interval',
        pins={'/inert/exact-final.so':recipe.pin(contents['dso']),'/inert/ordinary-interval':recipe.pin(contents['app'])},table=accepted()[1]['table'])
    binary=dict(products={'frontend-native-oracle':{'path':'/inert/native-oracle'}})
    refs=[];records={};values={};wire={}
    def raw_pin(run,unused,path,expected=None,cap=exact.MIB):
        raw=path.read_bytes();assert len(raw)<=cap;pin=recipe.pin(raw)
        if expected is not None: assert pin==expected
        if str(path) in run.retained: assert run.retained[str(path)]==pin
        run.retained[str(path)]=pin;return raw
    driver=SimpleNamespace(read_json=lambda run,recipe,path,*args,**kwargs:values[str(path)],raw_pin=raw_pin)
    for number,cohort in enumerate(exact.COHORTS):
        directory=root/cohort;directory.mkdir();copies={}
        for label in ('dso_candidate','dso_trusted','app_candidate','app_trusted'):
            dest=directory/(label+('.so' if label.startswith('dso') else '.elf'))
            dest.write_bytes(contents['dso' if label.startswith('dso') else 'app']);copies[label]=str(dest)
        r=dict(arguments=dict(raw=str(directory),cohort=cohort),rows=[],stages=[],inputs=run.result['inputs'])
        plan=dict(schema=exact.SCHEMA,profile=exact.PROFILE,cohort=cohort,all_keys=exact.keys(),keys=exact.keys(cohort),copies=copies,
            plans=[],inputs=run.result['inputs'],attempts_per_key=1,cpu_seconds=20,wall_seconds=30,pair_seconds=15,steps_per_child=20000,
            callback_state='HELD',qualification=exact.qualifications())
        for i,key in enumerate(exact.keys(cohort)):
            name='pair-'+str(i).zfill(2);d=directory/(name+'-io');dest=d/'output';dest.mkdir(parents=True)
            raw,out,err=streams(key);(dest/exact.OUTPUT).write_bytes(raw)
            argv=exact.pair_argv('/inert/native-oracle',copies,dest,key,facts['table'])
            request=dict(argv=argv,cwd=str(exact.ROOT),env=run.env,stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),cpu_seconds=20,wall_seconds=30,file_bytes=4*exact.MIB)
            plan['plans'].append(dict(name=name,key=key,request=request,output=str(dest)));values[str(d/'request.json')]=request
            row=dict(key=key,status='PASS',attempts=1,child_exit=0,closed={'inert':True},
                observed=dict(zip(exact.HEADER.strip().split(','),raw.splitlines()[1].decode().split(','))),output_pin=recipe.pin(raw))
            if failures and i==31 and number==0:row.update(status='FAILED',child_exit=1,error='retained failure')
            if failures and i==31 and number==1:row=dict(key=key,status='UNRUN',attempts=0)
            r['rows'].append(row)
            if row['attempts']:
                r['stages'].append(dict(name=name,closed=row['closed']));wire[(str(directory),name)]=(row['child_exit'],out,err)
        ref=dict(path=str(directory/'result.json'),sha256='c'*64)
        refs.append(dict(cohort=cohort,result=ref,owner=dict(path=str(directory/'owner.json'),sha256='d'*64)))
        records[ref['path']]=r;values[str(directory/'plan.json')]=plan
    values[str(args.cohorts)]=refs
    def record(*args):
        assert args[-2:] == ('exact-cohort',True)
        result=records[args[4]['path']]
        assert args[5]['path']==str(Path(args[4]['path']).parent/'owner.json')
        return result
    def replay(run,recipe,driver,result,name,argv,cap):
        assert cap==4*exact.MIB;return wire[(result['arguments']['raw'],name)]
    return run,driver,binary,facts,values,records,record,replay

class Controls(unittest.TestCase):
    def test_full_population_four_cohorts_and_exact_independent_answers(self):
        all_keys=exact.keys();self.assertEqual(len(all_keys),128)
        self.assertEqual([k for cohort in exact.COHORTS for k in exact.keys(cohort)],all_keys)
        total=visits=0
        for key in all_keys:
            row=exact.pair_output(*streams(key),key);self.assertEqual(len(row),32)
            total+=int(row['comparisons']);visits+=int(row['visits'])
        self.assertEqual((total,visits),(26880,25600))
        for seed in exact.SEEDS:self.assertEqual([k['length'] for k in all_keys if k['seed']==seed],list(range(1,65)))

    def test_key_shape_missing_duplicate_unknown_reordered_and_retry_refuse(self):
        key=exact.keys()[0]
        for change in ({'k':1000},{'seed':0},{'function_id':101},{'length':0},{'length':65},{'length':True},{'extra':1}):
            with self.assertRaises(AssertionError):exact.checked_key(dict(key,**change))
        for mutant in ('missing','duplicate','unknown','reverse','retry','false-pass'):
            rows=exact.initial_rows()
            if mutant=='missing':rows.pop()
            elif mutant=='duplicate':rows[1]=rows[0]
            elif mutant=='unknown':rows[-1]['key']=dict(rows[-1]['key'],length=65)
            elif mutant=='reverse':rows.reverse()
            elif mutant=='retry':rows[0].update(status='FAILED',attempts=2)
            else:rows[0]['status']='PASS'
            with self.assertRaises(AssertionError):exact.population(rows)

    def test_all_32_columns_terminal_and_step_bounds_refuse_mutation(self):
        key=exact.keys()[63]
        for field in exact.HEADER.strip().split(','):
            with self.subTest(field=field),self.assertRaises(AssertionError):exact.pair_output(*streams(key,{field:'invalid'}),key)
        for field in ('original_steps','candidate_steps'):
            for value in ('398','20001','0399'):
                with self.assertRaises(AssertionError):exact.pair_output(*streams(key,{field:value}),key)
        raw,out,err=streams(key)
        for bad in (raw[:-1],raw+b'\n',raw+raw.splitlines(keepends=True)[1],raw.replace(b'\n',b'\r\n')):
            with self.assertRaises(AssertionError):exact.pair_output(bad,out,err,key)
        for bad in (b'',out+b'\n',out.replace(b'normal-reaps=2',b'normal-reaps=1')):
            with self.assertRaises(AssertionError):exact.pair_output(raw,bad,err,key)
        with self.assertRaises(AssertionError):exact.pair_output(raw,out,b'failure',key)
        with self.assertRaises(AssertionError):sdk.pair_output(raw,out,err,sdk.keys()[0])

    def test_all_eight_release_controls_are_mandatory_without_changing_legacy(self):
        names=list(sdk.RUST_CONTROLS+exact.RUST_CONTROLS)+['unrelated::test']
        self.assertEqual(sdk.inventory(names),sdk.RUST_CONTROLS)
        self.assertEqual(exact.inventory(names),exact.RUST_CONTROLS)
        for missing in exact.RUST_CONTROLS:
            with self.assertRaises(AssertionError):exact.inventory([n for n in names if n!=missing])
        for bad in (names+[exact.RUST_CONTROLS[0]],names+[exact.PREFIX+'tests::unknown']):
            with self.assertRaises(AssertionError):exact.inventory(bad)

    def test_owner_grammar_exact_cli_and_unchanged_limits(self):
        for phase in owner.EXTRAS:
            opts=options(phase);invocation,child=owner.commands(opts,'/tools/python',str(owner.HERE/'exact_state_owner.py'))
            self.assertEqual(child[2],str(exact.HERE/'exact_state.py'));self.assertNotIn('--owner',child)
            self.assertEqual(owner.environment(opts),legacy.owner.environment(opts))
            for change in ({'phase':'sdk-cohort'},{'revision':'a'*39},{'retry':'1'},{'raw':'relative'}):
                with self.assertRaises(AssertionError):owner.commands(dict(opts,**change),'/tools/python',invocation[2])
        copies={k:'/inert/'+k for k in ('dso_candidate','dso_trusted','app_candidate','app_trusted')}
        argv=exact.pair_argv('/inert/oracle',copies,'/inert/output',exact.keys()[0],accepted()[1]['table'])
        self.assertEqual(len(argv),11);self.assertEqual(argv[1],exact.PROFILE)
        self.assertEqual(argv[7:],[str(exact.SEEDS[0]),'1','4096','37'])

    def test_actual_page_and_complete_caller_instructions_require_identity(self):
        raw=b'prefix'+b'\0'*(4096-6)+geometry.BODY+b'\0'*(4096-37)
        selection=dict(elf_va=4096,length=37,head_offsets=geometry.HEADS,return_offsets=[36])
        elf=SimpleNamespace(elf=lambda data:dict(loads=[(1,5,4096,4096,0,37,37,4096)]),
            extent=lambda data,at,n:data[at:at+n],digest=recipe.pin)
        fixture=SimpleNamespace(CODE=geometry.BODY,describe=lambda data:selection,elf=elf)
        _,page,_=geometry.source_page(raw,fixture);self.assertEqual(page['sha256'],exact.sha(raw[4096:8192]))
        with self.assertRaises(AssertionError):geometry.source_page(raw[:4096]+b'x'+raw[4097:],fixture)
        def disassembly(body,heads):
            ends=heads[1:]+[len(body)]
            return ''.join(f' {4096+at:x}:\t{body[at:end].hex(" ")}\tfixture\n' for at,end in zip(heads,ends)).encode()
        for body,heads in ((geometry.BODY,geometry.HEADS),(geometry.CALLER,geometry.CALLER_HEADS)):
            good=disassembly(body,heads);geometry.instructions(good,4096,body,heads)
            for bad in (good.replace(b'1000:',b'1001:',1),good+b' 2000:\t90\tunexpected\n',good.splitlines(keepends=True)[0]):
                with self.assertRaises(AssertionError):geometry.instructions(bad,4096,body,heads)

    def test_geometry_requires_external_acceptance_and_all_source_joins(self):
        value,facts,ref=accepted();geometry.acceptance(value,facts,ref,ref,ref,'a'*40,exact.PROFILE)
        for field in ('kind','status','scope','revision','native_state'):
            bad=copy.deepcopy(value);bad[field]='wrong'
            with self.assertRaises(AssertionError):geometry.acceptance(bad,facts,ref,ref,ref,'a'*40,exact.PROFILE)
        for field in ('facts','preparation','build','sdk_build','supporting_pins'):
            bad=copy.deepcopy(value);bad[field]={}
            with self.assertRaises(AssertionError):geometry.acceptance(bad,facts,ref,ref,ref,'a'*40,exact.PROFILE)
        for field in geometry.PREMISES:
            bad=copy.deepcopy(value);bad['premises'][field]=False
            with self.assertRaises(AssertionError):geometry.acceptance(bad,facts,ref,ref,ref,'a'*40,exact.PROFILE)
        for flag in ('pmu_metric','cadence','performance'):
            bad=copy.deepcopy(value);bad['qualification'][flag]=True
            with self.assertRaises(AssertionError):geometry.acceptance(bad,facts,ref,ref,ref,'a'*40,exact.PROFILE)

    def test_record_rejects_owner_source_environment_and_closure_mutants(self):
        refs=({'path':'/inert/raw/result.json','sha256':'b'*64},{'path':'/inert/owner.json','sha256':'b'*64})
        run,driver,r,o,values=record_fixture();self.assertEqual(exact.record(run,recipe,driver,owner,*refs,'exact-prepare'),r)
        for mutant in ('base','overlay','source','cpu','attempts','cap','cleanup','rescue','recipe','argv','environment','before','after','metric'):
            run,driver,r,o,values=record_fixture()
            if mutant=='base':o['base']='f'*40
            elif mutant=='overlay':o['working_source_sha256']={'changed':'f'*64}
            elif mutant=='source':o['source_unchanged']=False
            elif mutant=='cpu':o['reserved_cpus']=[2,3,5]
            elif mutant=='attempts':o['attempts']=2
            elif mutant=='cap':o['wall_limit_seconds']=1201
            elif mutant=='cleanup':o['closed']['cleanup_complete']=False
            elif mutant=='rescue':o['closed']['reaped_descendants']=1
            elif mutant=='recipe':o['public_owner']['recipe_sha256']='f'*64
            elif mutant=='argv':o['command']=o['command']+['--retry']
            elif mutant=='environment':r['environment']={'LC_ALL':'different'}
            elif mutant in ('before','after'):values['/inert/raw/sources-'+mutant+'.json']={}
            else:r['qualification']['pmu_metric']=True
            with self.subTest(mutant=mutant),self.assertRaises(AssertionError):exact.record(run,recipe,driver,owner,*refs,'exact-prepare')
        # The inherited, actual bounded replay still rejects false ECHILD custody.
        run,driver,r,name,argv,files,d,outer,canonical=legacy.closure_fixture(0)
        receipt=json.loads(files[str(d/'receipt.json')]);receipt['absence_proof']='assumed';files[str(d/'receipt.json')]=canonical(receipt)
        with self.assertRaises(AssertionError):sdk.replay_stage(run,recipe,driver,r,name,argv)

    def test_dispatch_records_failures_and_stops_uncertain_custody(self):
        for uncertain in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                cohort=exact.COHORTS[0];rows=exact.initial_rows(cohort)
                run=SimpleNamespace(a=SimpleNamespace(cohort=cohort),safe=True,result=dict(rows=rows,status='FAILED',stages=[]),
                    budget=SimpleNamespace(complete=lambda:None),unchanged=lambda:None)
                def bounded(name,directory,request,**kwargs):
                    self.assertTrue(kwargs['app_files']);run.result['stages'].append(dict(name=name,closed={'inert':True}))
                    if uncertain:run.safe=False;raise ValueError('uncertain custody')
                    return 1,b'',b'retained failure'
                run.bounded=bounded
                plan=dict(plans=[dict(name='pair-'+str(i).zfill(2),key=r['key'],request={'stdout':str(Path(tmp)/str(i)/'stdout.txt')},output=str(Path(tmp)/str(i)/'output')) for i,r in enumerate(rows)])
                exact.execute_cohort(run,SimpleNamespace(bounded_ready=lambda *args,**kwargs:None),None,plan)
                self.assertEqual(len(rows),32);self.assertEqual(run.result['status'],'FAILED')
                self.assertEqual(sum(r['attempts'] for r in rows),1 if uncertain else 32)
                self.assertEqual(rows[0]['status'],'FAILED')
                if uncertain:self.assertTrue(all(r['status']=='UNRUN' for r in rows[1:]))
                else:self.assertTrue(all(r['status']=='FAILED' and r['child_exit']==1 for r in rows))

    def test_collector_replays_all_128_rows_and_retains_failures(self):
        for failures in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                run,driver,binary,facts,values,records,record,replay=collection(Path(tmp),failures)
                with patch.object(exact,'record',side_effect=record):exact.collect(run,recipe,driver,SimpleNamespace(replay_stage=replay),owner,binary,facts)
                exact.evidence(run.result)
                self.assertEqual([r['key'] for r in run.result['rows']],exact.keys())
                self.assertEqual([sum(r['status']==s for r in run.result['rows']) for s in ('PASS','FAILED','UNRUN')],[126,1,1] if failures else [128,0,0])
                self.assertEqual(run.result['status'],'FAILED' if failures else exact.STATUS['exact-collect'])
                self.assertEqual(run.result['callback_state'],'HELD' if failures else 'PASS')
                self.assertEqual(run.result['qualification'],dict(pmu_metric=False,cadence=False,performance=False))

    def test_collector_rejects_missing_duplicate_unknown_mutated_and_wrong_owner(self):
        for mutant in ('missing','duplicate','unknown','retry','result','request','source','owner'):
            with tempfile.TemporaryDirectory() as tmp:
                run,driver,binary,facts,values,records,record,replay=collection(Path(tmp))
                refs=values[str(run.a.cohorts)];first=refs[0];r=records[first['result']['path']]
                plan=values[str(Path(first['result']['path']).parent/'plan.json')]
                if mutant=='missing':refs.pop()
                elif mutant=='duplicate':refs[1]=refs[0]
                elif mutant=='unknown':r['rows'][0]['key']=dict(r['rows'][0]['key'],function_id=42)
                elif mutant=='retry':r['rows'][0]['attempts']=2
                elif mutant=='result':r['rows'][0]['observed']['result']='0'
                elif mutant=='request':plan['plans'][0]['request']['argv'][1]=sdk.PROFILE
                elif mutant=='source':facts['pins'][facts['trusted']]['sha256']='f'*64
                else:first['owner']['path']='/foreign/owner.json'
                with patch.object(exact,'record',side_effect=record),self.assertRaises(AssertionError):exact.collect(run,recipe,driver,SimpleNamespace(replay_stage=replay),owner,binary,facts)
                exact.evidence(run.result);self.assertEqual(run.result['status'],'FAILED');self.assertEqual(run.result['callback_state'],'HELD')

    def test_build_recipe_is_exact_and_no_profile_relaxes_legacy(self):
        functional=load('_exact_controls_functional','accuracy_functional.py')
        tools={k:Path('/tools')/k for k in ('python','gcc','readelf','objdump')};directory=Path('/inert/raw')
        self.assertEqual(exact.preparation_commands(directory,tools),functional.phase_commands(directory,tools,SimpleNamespace(MASTER='inert'))[1:])
        for wrong in (exact.PROFILE,{},None):
            with self.assertRaises(AssertionError):sdk._expected_fields(sdk.keys()[0],wrong)
        self.assertEqual(len(sdk.RUST_CONTROLS),8);self.assertEqual(len(sdk.PYTHON_CONTROLS),13)
        self.assertEqual(len(exact.RUST_CONTROLS),8);self.assertEqual(len(exact.PYTHON_CONTROLS),12)

if __name__ == '__main__':
    unittest.main()
