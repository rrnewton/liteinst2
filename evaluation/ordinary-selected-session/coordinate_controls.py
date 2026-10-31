#!/usr/bin/env python3
"""Pure coordinate/receipt controls; processes, native code and clocks are fake."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prior = load('_coordinate_prior', HERE/'prepared_phase_functional_controls.py')
producer, recipe, owner, reader = prior.producer, prior.recipe, prior.owner, prior.reader
c = load('_coordinate_controls', HERE/'accuracy_coordinates.py')
normal = load('_coordinate_closed_controls', HERE.parent/'ordinary-module-session/reproduce.py')


def coordinate(**changes):
    return c.checked(dict(dict(zip(c.FIELDS, (producer.MASTER,'calibration',1,'late_expensive',10,10,'locked'))),**changes))


def options(phase, cell):
    result = {k:'/tmp/'+k for k in owner.COMMON+owner.extras(phase)}
    result.update(phase=phase,revision='1'*40,**{'reservation-tag':'coordinate-fixture','hardware':'fixture'})
    result.update({k:str(v) for k,v in cell.items()})
    for key in result:
        if key.endswith('-sha'):
            result[key] = '2'*64
    return result


def facts(cell):
    pin = dict(bytes=1,sha256='1'*64)
    policy = c.authority(reader.truth,cell)[2]
    return dict(materials={k:dict(path='/m/'+k,**pin) for k in producer.MATERIALS},
        table=[dict(function_id=41,operation='exact_work_nonempty',policy='whole',elf_va=4096,extent=37,returns=[36])],
        caller=dict(extent=20,continuation=15),binary=dict(path='/bin/app',**pin),
        candidate=dict(path='/candidate',**pin),trusted=dict(path='/trusted',**pin),policy=policy,
        coordinate=cell,prepared_phase=producer.prepared_target(policy))


def closed_fixture(directory):
    """Real parser/receipt joins over synthetic data; never execution authority.

    The complete joined payload exceeds this control's 1 MiB file limit.
    Keep only those synthetic payload bytes in memory; all other receipt reads
    use the real file reader. Production joined-file I/O is unchanged.
    """
    rows,args = prior.fixture.fixture(kind='random')
    checked = prior.fixture.check(rows,args)
    joined = {k:v for k,v in checked.items() if k not in ('raw','stderr','wire_rows','numeric')}
    joined['numeric'] = {k:v for k,v in checked['numeric'].items() if k != 'rows'}
    joined['numeric_rows'] = checked['numeric']['rows']
    joined = recipe.json_records(joined)
    cell = coordinate(master='12'*32,workload='varied',**{'epoch-phase':'random'})
    files,_,policy = c.authority(reader.truth,cell)
    joined_paths = {directory/'raw'/'joined.json', directory/'other.json'}
    joined_bytes = {}
    def put(path,value):
        raw = c.canonical(value)
        if path in joined_paths:
            joined_bytes[path] = raw
        else:
            assert len(raw) <= 1048576
            path.write_bytes(raw)
        return dict(path=str(path),bytes=len(raw),sha256=producer.sha(raw))
    def read(path,cap):
        if path in joined_bytes:
            raw = joined_bytes[path]
            assert len(raw) <= cap
            return raw
        return producer.read(path,cap)
    raw = directory/'raw';raw.mkdir()
    opts = options('coordinate-functional',cell)
    opts.update(owner=str(directory/'owner.json'),raw=str(raw))
    invocation,command = owner.commands(opts,'/usr/bin/python3',str(HERE/'accuracy_functional_owner.py'))
    joined_ref = put(raw/'joined.json',joined)
    f = facts(cell)
    f.update(profile=c.PROFILE,revision=opts['revision'])
    f['materials'] = {}
    for name,data in files.items():
        path=directory/name;path.write_bytes(data)
        f['materials'][name] = dict(path=str(path),bytes=len(data),sha256=producer.sha(data))
    sources = {}
    for name in c.CATALOG_SOURCES:
        path = c.ROOT/name; data = path.read_bytes()
        sources[str(path)] = dict(bytes=len(data),sha256=producer.sha(data))
    retained = {}
    for name in ('sources-before.json','sources-after.json'):
        ref = put(raw/name,sources);retained[ref['path']] = {k:ref[k] for k in ('bytes','sha256')}
    size = len(files['input.csv']);writes=[];sent=0
    while sent < size:
        count=min(8192,size-sent);sent+=count;writes.append([2,2,sent,count])
    delivery = dict(status='PASS',profile=c.PROFILE,coordinate=cell,revision=opts['revision'],attempt=1,
        normal_reaps=1,rescue=False,cleanup_error=None,child_pid=123,child_exit=0,sent_bytes=size,
        overflow=None,ready_receipt_ns=1,eof_close_ns=3,writes=writes,totals=joined['totals'],
        **recipe.qualifications())
    row = dict(name=c.name(cell),status='PASS',attempts=1,records=2048,producer_exit=0,result=delivery,
        joined={k:joined_ref[k] for k in ('path','sha256')},totals=joined['totals'])
    result = dict(status='COORDINATE_FUNCTIONAL_STRUCTURAL_PASS',profile=c.PROFILE,
        phase='coordinate-functional',revision=opts['revision'],coordinate=cell,
        arguments={k:v for k,v in opts.items() if k != 'owner'},invocation=command,
        custody_closed=True,retention_verified=True,source_unchanged=True,retained=retained,
        cpus=[0,1,2],hardware='fixture',functional=row,facts=f,**recipe.qualifications())
    result_ref=put(raw/'result.json',result)
    log=c.canonical(recipe.summary(result));Path(opts['owner']).with_suffix('.log').write_bytes(log)
    outer = dict(base=opts['revision'],attempts=1,working_source_sha256={},wall_limit_seconds=1200,
        output_limit_bytes=8*1048576,source_unchanged=True,log_archived=True,command=command,
        reserved_cpus=[0,1,2],hardware='fixture',closed=dict(exit_code=0,termination=None,
            cleanup_complete=True,reaped_descendants=0,private_log_sha256=producer.sha(log)),
        public_owner=dict(schema=owner.SCHEMA,phase='coordinate-functional',revision=opts['revision'],
            recipe='evaluation/ordinary-selected-session/accuracy_functional_owner.py',
            recipe_sha256=sources[str(HERE/'accuracy_functional_owner.py')]['sha256'],invocation=invocation))
    event=dict(coordinate=cell,attempt=1,owner=put(Path(opts['owner']),outer),result=result_ref)
    return SimpleNamespace(event=event,result=result,joined=joined,put=put,
        producer=SimpleNamespace(read=read,sha=producer.sha,prepared_target=producer.prepared_target))


class Controls(unittest.TestCase):
    def test_exact_coordinate_domains_and_canonical_cli(self):
        cell = coordinate()
        self.assertEqual(c.options({k:str(v) for k,v in cell.items()}),cell)
        for key,value in (('master','A'*64),('population-phase','random'),('trial',0),('trial',101),
                ('trial',True),('k',9),('period-ms',2),('workload','subset'),('epoch-phase','calibration')):
            with self.assertRaises(AssertionError):c.checked(dict(cell,**{key:value}))
        for key in ('trial','k','period-ms'):
            for word in ('01','+1','1.0','',True):
                bad={k:str(v) for k,v in cell.items()};bad[key]=word
                with self.assertRaises(AssertionError):c.options(bad)
        with self.assertRaises(AssertionError):c.checked(dict(cell,epochs=521))

    def test_all_43200_keys_and_hash_bind_every_axis(self):
        keys=c.keys(producer.MASTER);plan=c.catalog(producer.MASTER)
        self.assertEqual((len(keys),len({c.canonical(k) for k in keys})),(43200,43200))
        self.assertEqual(plan['keyset_sha256'],hashlib.sha256(b''.join(map(c.canonical,keys))).hexdigest())
        self.assertEqual(keys[0],coordinate(workload='short',k=1,**{'period-ms':1,'epoch-phase':'random'}))
        self.assertEqual(keys[-1],coordinate(trial=100,workload='varied',k=1000,**{'population-phase':'comparison','period-ms':100}))
        self.assertEqual({k['trial'] for k in keys},set(range(1,101)))
        self.assertEqual({k['workload'] for k in keys},set(c.WORKLOADS))
        self.assertNotEqual(plan['keyset_sha256'],hashlib.sha256(b''.join(map(c.canonical,reversed(keys)))).hexdigest())

    def test_complete_materials_and_derived_policy_for_every_workload(self):
        for workload in c.WORKLOADS:
            cell=coordinate(workload=workload,trial=100,**{'population-phase':'comparison','period-ms':1,'epoch-phase':'random'})
            files,manifest,policy=c.authority(reader.truth,cell)
            expected,original=reader.truth.artifacts(cell['master'],'comparison',100,workload)
            self.assertEqual(files,dict(expected,**{'manifest.json':reader.truth.canonical(original)}))
            self.assertEqual(manifest,original)
            self.assertEqual(len(files['input.csv'].splitlines()),2048)
            self.assertIn({k:v for k,v in policy.items() if k!='epochs'},manifest['policies'])
            self.assertEqual(policy['epochs'],520)
            if workload=='short':self.assertEqual(len(files['input.csv']),4096)
            if workload=='long':self.assertEqual(len(files['input.csv']),133120)
        policy=c.authority(reader.truth,coordinate())[2]
        self.assertEqual(policy,producer.POLICY)

    def test_owner_options_keep_all_old_modes_closed(self):
        for phase in owner.COORDINATE_EXTRAS:
            opts=options(phase,coordinate(k=1000,**{'period-ms':100}))
            invocation,child=owner.commands(opts,'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))
            self.assertEqual(child[3:5],['--phase',phase])
            self.assertEqual(invocation[-14:],[v for key in c.FIELDS for v in ('--'+key,opts[key])])
            for key,value in (('epochs','521'),('delay-ns','0'),('target-epoch','1'),('k','9'),('trial','01')):
                with self.assertRaises(AssertionError):owner.commands(dict(opts,**{key:value}),'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))
        for phase in (*owner.EXTRAS,*owner.PHASE_EXTRAS,*owner.PREPARED_PHASE_EXTRAS):
            opts=options(phase,coordinate())
            with self.assertRaises(AssertionError):owner.commands(opts,'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))
        self.assertEqual(tuple(owner.EXTRAS),('accuracy-prepare','accuracy-functional'))
        self.assertEqual(tuple(owner.PREPARED_PHASE_EXTRAS),('prepared-phase-prepare','prepared-phase-functional'))

    def test_coordinate_plan_recomputes_materials_and_refuses_foreign_cell(self):
        cell=coordinate(trial=100,workload='long',k=1000,**{'population-phase':'holdout','period-ms':100,'epoch-phase':'random'})
        files,_,_=c.authority(reader.truth,cell)
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory).resolve();pins={}
            def put(name,raw):
                path=directory/name;path.write_bytes(raw)
                pins[str(path)]=dict(bytes=len(raw),sha256=producer.sha(raw))
                return dict(path=str(path),**pins[str(path)])
            f=facts(cell)
            f.update(revision='2'*40,profile=c.PROFILE,abi=producer.ABI)
            f['materials']={name:put(name,raw) for name,raw in files.items()}
            for key in ('binary','candidate','trusted'):f[key]=put(key,b'fixture-only')
            preparation=put('preparation',b'{}\n')
            accepted=dict(kind='selected-accuracy-coordinate-functional-geometry-acceptance-v1',
                status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION',scope=c.PROFILE,revision='2'*40,
                preparation_sha256=preparation['sha256'],facts=f,premises={k:True for k in recipe.PREMISES},
                review='Synthetic unsafe premises; no native call.',native_state='UNRUN_SEPARATE_REQUIRED')
            geometry=put('geometry',c.canonical(accepted))
            for path in (HERE/'accuracy_coordinates.py',HERE/'accuracy_functional.py'):
                raw=path.read_bytes();pins[str(path)]=dict(bytes=len(raw),sha256=producer.sha(raw))
            run=SimpleNamespace(a=SimpleNamespace(revision='2'*40,geometry=Path(geometry['path']),
                preparation=Path(preparation['path']),preparation_sha=preparation['sha256']),
                cpus=[0,1,2],sources=pins,tool_pins={},retained=pins)
            plan=recipe.input_plan(run,None,f,producer,epoch_phase='random',prepared=True,coordinate=cell)
            checked=producer.coordinate_arguments(plan,reader)
            self.assertEqual(checked['input_bytes'],files['input.csv'])
            self.assertEqual(len(checked['input_bytes']),133120)
            bad=copy.deepcopy(plan);bad['coordinate']['trial']=99
            with self.assertRaises(AssertionError):producer.coordinate_arguments(bad,reader)
            for name in producer.MATERIALS:
                path=Path(f['materials'][name]['path']);original=path.read_bytes();path.write_bytes(original[:-1])
                with self.assertRaises((AssertionError,ValueError)):producer.coordinate_arguments(plan,reader)
                path.write_bytes(original)

    def test_new_argv_ready_and_target_derive_from_coordinate(self):
        pin=dict(bytes=1,sha256='1'*64)
        run=SimpleNamespace(a=SimpleNamespace(revision='2'*40,geometry=Path('/g'),preparation=Path('/p'),preparation_sha='1'*64),
            cpus=[0,1,2],sources={},tool_pins={},retained={'/g':pin,'/p':pin})
        for k,period,kind in ((1,1,'locked'),(1000,100,'random')):
            cell=coordinate(k=k,**{'period-ms':period,'epoch-phase':kind});f=facts(cell)
            plan=recipe.input_plan(run,None,f,producer,epoch_phase=kind,prepared=True,coordinate=cell)
            self.assertEqual(plan['argv'][5:12],[str(k),str(period),'520',kind,str(f['policy']['delay_ns']),'1','1'])
            self.assertEqual(plan['profile'],c.PROFILE)
            self.assertEqual(plan['prepared_phase']['target_ns'],period*1000000+f['policy']['delay_ns'])
            raw=prior.prior.ready().replace(b'selected-accuracy-session-v1',reader.VERSION.encode()).decode().split(',')
            raw[2],raw[4]=str(k),str(period);wire=','.join(raw).encode()
            producer.ready_row(wire,123,[0,1,2],reader,policy=f['policy'])
            with self.assertRaises(AssertionError):producer.ready_row(wire,123,[0,1,2],reader)
            raw[3]='521'
            with self.assertRaises(AssertionError):producer.ready_row(','.join(raw).encode(),123,[0,1,2],reader,policy=f['policy'])
            with self.assertRaises(AssertionError):producer.prepared_phase_arguments(plan,reader)

    def test_geometry_rejects_other_cell_and_old_acceptance(self):
        cell=coordinate();f={'coordinate':cell}
        value=dict(kind='selected-accuracy-coordinate-functional-geometry-acceptance-v1',status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION',
            scope=c.PROFILE,revision='1'*40,preparation_sha256='2'*64,facts=f,premises={k:True for k in recipe.PREMISES},
            review='Synthetic premise; no execution authority.',native_state='UNRUN_SEPARATE_REQUIRED')
        recipe.accept_geometry(value,f,'2'*64,'1'*40,epoch_phase='locked',prepared=True,coordinate=cell)
        for changed in (coordinate(trial=2),coordinate(workload='short'),coordinate(k=1)):
            with self.assertRaises(AssertionError):recipe.accept_geometry(value,f,'2'*64,'1'*40,epoch_phase='locked',prepared=True,coordinate=changed)
        for premise in recipe.PREMISES:
            bad=copy.deepcopy(value);bad['premises'][premise]=False
            with self.assertRaises(AssertionError):recipe.accept_geometry(bad,f,'2'*64,'1'*40,epoch_phase='locked',prepared=True,coordinate=cell)
        with self.assertRaises(AssertionError):recipe.accept_geometry(value,f,'2'*64,'1'*40,epoch_phase='locked',prepared=True)

    def test_input_write_limit_is_derived_only_for_new_profile(self):
        outgoing=bytearray(b'x'*133120);writes=[];sent=0
        while outgoing:
            sent=producer.write_input(1,outgoing,sent,writes,lambda:7,lambda fd,data:min(4093,len(data)),limit=133120)
        self.assertEqual((sent,sum(r[3] for r in writes)),(133120,133120))
        self.assertEqual(writes[-1][2],133120)
        with self.assertRaises(AssertionError):producer.write_input(1,bytearray(b'x'),0,[None]*68608,lambda:7,lambda fd,data:1)
        with self.assertRaises(AssertionError):producer.write_input(1,bytearray(b'x'),0,[],lambda:7,lambda fd,data:1,limit=133120)
        with self.assertRaises(AssertionError):producer.write_input(1,bytearray(b'x'*4096),0,[],lambda:7,lambda fd,data:0,limit=4096)

    def test_absolute_deadline_and_old_caps_remain_exact(self):
        cell=coordinate();files,_,policy=c.authority(reader.truth,cell)
        plan=dict(profile=c.PROFILE,coordinate=cell,policy=policy,revision='1'*40,cpus=[0,1,2],argv=['/never-executed'])
        child=prior.prior.Child(0)
        with mock.patch.object(producer.time,'monotonic',side_effect=[0,15]), \
             mock.patch.object(producer.subprocess,'Popen',return_value=child), \
             mock.patch.object(producer.os,'sched_setaffinity'), \
             mock.patch.object(producer.os,'sched_getaffinity',return_value={2}):
            result,_,_,_,deadline=producer.coordinate_exchange(plan,dict(input_bytes=files['input.csv'],policy=policy),reader)
        self.assertEqual(deadline,15)
        self.assertEqual(result['status'],'FAILED')
        self.assertTrue(child.killed)
        self.assertIn('absolute 15-second',result['error'])
        self.assertEqual((producer.CAP,producer.LINE,reader.row_limit(520),reader.envelope_limit(520)),(8*1048576,350,13873,13874))
        self.assertEqual(producer.POLICY,dict(k=10,period_ms=10,epochs=520,phase='locked',delay_ns=0))
        self.assertEqual(c.authority(reader.truth,coordinate(**{'period-ms':1}))[2]['epochs']*1000000,520000000)

    def test_catalog_keeps_unrun_unknown_failed_and_rejects_duplicates(self):
        plan=c.catalog(producer.MASTER)
        events=[dict(coordinate=coordinate(trial=i),attempt=1,owner=None if i==1 else {},result=None) for i in (1,2,3)]
        result=c.collect(plan,events,lambda e:'FAILED' if e['coordinate']['trial']==2 else 'STRUCTURAL_PASS')
        self.assertEqual(result['counts'],dict(UNRUN=43197,UNKNOWN=1,FAILED=1,STRUCTURAL_PASS=1))
        self.assertFalse(result['all_reported_structural_pass'])
        self.assertFalse(result['structural_dispatch_coverage_complete'])
        self.assertFalse(result['accuracy_qualified'])
        with self.assertRaises(AssertionError):c.collect(plan,[events[0],events[0]],lambda e:'STRUCTURAL_PASS')
        with self.assertRaises(AssertionError):c.collect(dict(plan,cells=3),events,lambda e:'STRUCTURAL_PASS')
        with self.assertRaises(AssertionError):c.collect(plan,[dict(events[0],attempt=2)],lambda e:'STRUCTURAL_PASS')

    def test_catalog_requires_owner_first_and_complete_closed_population(self):
        reads=[]
        outer=dict(closed=None)
        raw=c.canonical(outer)
        ref=dict(path='/closed/owner.json',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        p=SimpleNamespace(read=lambda path,cap:(reads.append(str(path)) or raw),sha=producer.sha)
        event=dict(coordinate=coordinate(),attempt=1,owner=ref,result={'must':'not be read'})
        self.assertEqual(c.closed_report(event,p,None,None,None,truth=reader.truth,revision='1'*40),'UNKNOWN')
        self.assertEqual(reads,['/closed/owner.json'])
        outer.update(closed=dict(exit_code=1),source_unchanged=True,log_archived=True,attempts=1,
            working_source_sha256={},wall_limit_seconds=1200,output_limit_bytes=8*1048576)
        opts=options('coordinate-functional',coordinate());opts['owner']=ref['path']
        invocation,command=owner.commands(opts,'/usr/bin/python3',str(HERE/'accuracy_functional_owner.py'))
        outer.update(base=opts['revision'],command=command,public_owner=dict(schema=owner.SCHEMA,
            phase='coordinate-functional',revision=opts['revision'],recipe='evaluation/ordinary-selected-session/accuracy_functional_owner.py',
            recipe_sha256='1'*64,invocation=invocation))
        raw=c.canonical(outer);event['owner']=dict(ref,bytes=len(raw),sha256=producer.sha(raw));event['result']=None
        self.assertEqual(c.closed_report(event,p,None,owner,lambda closed:None,truth=reader.truth,revision='1'*40),'FAILED')
        with self.assertRaises(AssertionError):c.closed_report(dict(event,coordinate=coordinate(trial=2)),p,None,owner,lambda closed:None,truth=reader.truth,revision='1'*40)
        outer['closed']['exit_code']=0;raw=c.canonical(outer);event['owner'].update(bytes=len(raw),sha256=producer.sha(raw))
        self.assertEqual(c.closed_report(event,p,None,owner,lambda closed:None,truth=reader.truth,revision='1'*40),'UNKNOWN')
        rows,args=prior.fixture.fixture();joined=prior.fixture.check(rows,args)
        cell=coordinate(master='12'*32,workload='varied')
        c.reported_population(joined,cell,reader.truth)
        for changed in (dict(joined,calls=joined['calls'][:-1]),dict(joined,calls=[joined['calls'][0]]*2048)):
            with self.assertRaises(AssertionError):c.reported_population(changed,cell,reader.truth)
        with self.assertRaises(AssertionError):c.reported_population(joined,dict(cell,trial=2),reader.truth)

    def test_cancelled_or_partial_population_cannot_be_closed_success(self):
        rows,args=prior.fixture.fixture(period=1)
        valid=prior.fixture.check(rows,args)
        self.assertEqual((len(valid['calls']),valid['requested_phase_status']),(2048,'UNRESOLVED'))
        for tag in ('CALL','RESULT','CALLTIME','TARGET_ARM'):
            changed=copy.deepcopy(rows);del changed[next(i for i,r in enumerate(changed) if r[0]==tag)]
            with self.assertRaises(reader.Refused):reader.check(prior.fixture.old.encode(changed),b'',**args)
        cancelled=[*rows,['CANCELLED','1','41','never_invoked','1000000','1','0']]
        with self.assertRaises(reader.Refused):reader.check(prior.fixture.old.encode(cancelled),b'',**args)
        changed=copy.deepcopy(rows)
        first=next(row for row in changed if row[:2]==['CALLTIME','1']);first[4:]=['520000000','520000001']
        with self.assertRaises(reader.Refused):reader.check(prior.fixture.old.encode(changed),b'',**args)

    def test_new_controls_are_mandatory_in_preparation_replay(self):
        self.assertEqual(tuple(sorted(n for n in dir(Controls) if n.startswith('test_'))),tuple(sorted(c.CONTROLS)))
        tools={k:Path('/tools')/k for k in ('python','gcc','readelf','objdump')}
        old=recipe.phase_commands(Path('/raw'),tools,producer)
        new=recipe.phase_commands(Path('/raw'),tools,producer,coordinate())
        self.assertEqual(recipe.stage_names(),recipe.STAGES)
        self.assertEqual(recipe.stage_names(coordinate()),('coordinate-controls',)+recipe.STAGES)
        self.assertEqual(new[0],[str(tools['python']),'-B',str(HERE/'coordinate_controls.py'),'-v'])
        self.assertEqual(new[2:],old[1:])
        self.assertEqual(len(c.CONTROLS),16)
        self.assertEqual(recipe.qualifications()['matrix_complete'],False)


    def test_catalog_authenticates_all_code_before_any_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();expected={};verified=[]
            for name in c.CATALOG_SOURCES:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
                expected[name]=b'# source-only authentication fixture\n';path.write_bytes(expected[name])
            def git(argv,timeout):
                self.assertEqual(argv[:4],['/usr/bin/git','-C',root,'show'])
                self.assertEqual(timeout,15)
                revision,name=argv[-1].split(':',1);self.assertEqual(revision,'1'*40)
                verified.append(name);return expected[name]
            def imported(name,path):
                self.assertEqual(verified,list(c.CATALOG_SOURCES))
                return path
            with mock.patch.object(c,'ROOT',root), mock.patch.object(c.subprocess,'check_output',side_effect=git), \
                 mock.patch.object(c,'load',side_effect=imported) as imports:
                self.assertEqual(c.catalog_modules('1'*40),tuple(root/name for name in c.CATALOG_SOURCES[1:]))
                self.assertEqual(imports.call_count,5)
                for name in c.CATALOG_SOURCES:
                    verified.clear();imports.reset_mock();path=root/name;path.write_bytes(expected[name]+b'# drift')
                    with self.assertRaises(AssertionError):c.catalog_modules('1'*40)
                    imports.assert_not_called();path.write_bytes(expected[name])
                with self.assertRaises(AssertionError):c.catalog_modules(None)
                imports.assert_not_called()

    def test_catalog_real_closed_success_binds_coordinate_policy_and_joined(self):
        with tempfile.TemporaryDirectory() as directory:
            f=closed_fixture(Path(directory).resolve())
            joined_path=Path(f.result['functional']['joined']['path'])
            joined_bytes=f.producer.read(joined_path,24*1048576)
            self.assertEqual(json.loads(joined_bytes),f.joined)
            self.assertEqual((len(f.joined['calls']),f.joined['totals']['calls']),(2048,2048))
            with self.assertRaises(AssertionError):f.producer.read(joined_path,len(joined_bytes)-1)
            def project(event):
                return c.closed_report(event,f.producer,recipe,owner,normal.normal_closed,
                    truth=reader.truth,revision='1'*40)
            self.assertEqual(project(f.event),'STRUCTURAL_PASS')
            owner_path=Path(f.event['owner']['path']);owner_bytes=owner_path.read_bytes()
            log_path=owner_path.with_suffix('.log');log_bytes=log_path.read_bytes()
            mutants=[]
            for key,value in (('k',1),('period_ms',1),('epochs',519),('phase','locked'),('delay_ns',f.joined['policy']['delay_ns']+1),('epochs',520.0)):
                changed=copy.deepcopy(f.joined);changed['policy'][key]=value;mutants.append((changed,copy.deepcopy(f.result)))
                with self.assertRaises(AssertionError):c.reported_population(changed,f.event['coordinate'],reader.truth)
            changed=copy.deepcopy(f.joined);changed['unrelated_extra_field']='different used joined identity'
            mutants.append((changed,copy.deepcopy(f.result)))
            changed=copy.deepcopy(f.result);changed['facts']['policy']['k']=1;mutants.append((copy.deepcopy(f.joined),changed))
            changed=copy.deepcopy(f.result);changed['facts']['coordinate']['trial']=2;mutants.append((copy.deepcopy(f.joined),changed))
            changed=copy.deepcopy(f.result);changed['facts']['materials']['input.csv']['sha256']='0'*64
            mutants.append((copy.deepcopy(f.joined),changed))
            for joined,result in mutants:
                ref=f.put(Path(result['functional']['joined']['path']),joined)
                result['functional']['joined']={k:ref[k] for k in ('path','sha256')}
                event=dict(f.event,result=f.put(Path(f.event['result']['path']),result))
                with self.assertRaises(AssertionError):project(event)
                self.assertEqual(owner_path.read_bytes(),owner_bytes)
                self.assertEqual(log_path.read_bytes(),log_bytes)
            # A changed output location is also a different used identity.
            result=copy.deepcopy(f.result);ref=f.put(Path(directory).resolve()/'other.json',f.joined)
            result['functional']['joined']={k:ref[k] for k in ('path','sha256')}
            event=dict(f.event,result=f.put(Path(f.event['result']['path']),result))
            with self.assertRaises(AssertionError):project(event)
            self.assertEqual(owner_path.read_bytes(),owner_bytes)
            self.assertEqual(log_path.read_bytes(),log_bytes)

    def test_old_summaries_remain_byte_identical(self):
        for profile in (recipe.PROFILE,recipe.PHASE_PROFILE,recipe.PREPARED_PHASE_PROFILE):
            result=dict(status='FAILED',profile=profile,phase='fixture',revision='1'*40,
                functional=dict(name='fixture',status='FAILED',attempts=1,records=2048),
                custody_closed=True,retention_verified=True)
            expected=dict(status='FAILED',profile=profile,phase='fixture',revision='1'*40,
                functional=result['functional'],custody_closed=True,retention_verified=True,**recipe.qualifications())
            self.assertEqual(c.canonical(recipe.summary(result)),c.canonical(expected))


if __name__ == '__main__':
    unittest.main()
