#!/usr/bin/env python3
"""Fabricated receipt controls. No fixture is a native or root custody witness."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_receipt_under_test',HERE/'native_receipt.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
H=R._helpers()
FIXTURE_PATH=R.ROOT/'evaluation/ordinary-call-pair-native/controls.py'
fixture_source=R._read(FIXTURE_PATH,R.MIB)
assert R._pin(fixture_source)['sha256']=='33293f4a201d8b717cfa2d46dde16a31e67e257ef4bdab994c0e8a847f07c059'
F=R._module('wire_fixture',FIXTURE_PATH,fixture_source)
LAUNCHER_PATH=R.ROOT/'ignored/a5/normal-call-pair-launch-source-v1/launch.py'
launcher_source=R._read(LAUNCHER_PATH,R.MIB)
assert R._pin(launcher_source)['sha256']==R.LAUNCHER_SHA
L=R._module('launcher_fixture',LAUNCHER_PATH,launcher_source)
# Exact CLOSED source map, used only as fabricated protocol data.
ALLOCATOR_SOURCES={'py/dagrun/__init__.py': '6fa42195184b1ed623c4e245f9415e474faf17e8611539b4d04ffc3231ac2493', 'py/dagrun/__main__.py': 'efd0c8b9a289ab0ebc702b65d048e7fce178dd031301cf4430810a587c85adc7', 'py/dagrun/admission.py': 'c0805887a3f31205b8f38e02148c4b455fbb62ef256f58e70b51ee3e34eb1a52', 'py/dagrun/ambient.py': '288795b6a2e403fb50fe2a408019c34e60622d78e2d4a1678adda30a89fad7c1', 'py/dagrun/analyze.py': '04bd070ebe9eb693f56f878f1fb9a8d3754aba69d8b7f0fd58640374053c032a', 'py/dagrun/attribution.py': 'ccc64b3acdfcc6b0aef1ec8b05990d62e1199716cdac8596e8ee1397994cae90', 'py/dagrun/capabilities.py': '9680774e6e370a1eed85f691bfd8cf1431155e08f11a2bc94d1012df0edfaece', 'py/dagrun/cgroup.py': '916aa030a03abf4a1709afbc46196a4147577471ef1a97d39501603e63d69d76', 'py/dagrun/cli.py': 'e5a255167f4192fcb8c225ed7bb6602f7233eca09d160be196282da474b992d8', 'py/dagrun/cpuset_allocator.py': '61715797fca6a3c3ba17668eb5f3a820ac0b42b4bf092b6fb815b58c1ed800da', 'py/dagrun/envcheck.py': 'cdd97ad08d50cea716f6c89b0725fa90b3f0daf8ff4cf08693ff74a397c0c495', 'py/dagrun/estimates.py': 'ff9879ec94effe5dbda85c3b5f9eea16951f27b69e60c4a51919e5b973f14203', 'py/dagrun/gh_resolve.py': '03c6dc80d902c51ff163b629b0b44106d2ada6d772cd1c618ecc25923b04a438', 'py/dagrun/io.py': 'd1ef3241ffa133948e51446be58be046843e6d627f3c12f7d6acaa89327e82d2', 'py/dagrun/memory_feedback.py': '31d9126ffbb96e8ea7e7295ef17ff4e3098fda317e0d3a784952f0ca56693939', 'py/dagrun/model.py': 'a4aea0dc8391eedc176cfd1e5d60920984445828a0879ba0093cd1526701bf2c', 'py/dagrun/perflog.py': 'ab48263730e226e11f377671d4c2ebc91a88aac222f840c82632f7dae1de13ac', 'py/dagrun/proccpu.py': '23d03ba34acd9020eef23b399dcef04a3ccee93562583165d7e9a421b43d9a62', 'py/dagrun/procstat.py': 'f4a05f8d37d90a37eb3f4ec37206791742df7c61b2f20608c38461f9e6002a6f', 'py/dagrun/profile_capture.py': '095ced03d5d035e4729ac7eb262cbcb13d4d352d4b1fcf57b767f86ea57c08cc', 'py/dagrun/profile_enrich.py': '8f2a073a1a32de112aa0486debceb75c2ce038c0594810c3fafe963fd20a01b8', 'py/dagrun/profile_report.py': 'a8da24d411c42387ef784d26ba8ed5b48d00b991bf4dbb22299c32a1973a51dc', 'py/dagrun/protocols.py': '112cc489c3ce34db323aaf8c2cb5e7696bd45b71e9e1571a15d0ab76f1b7dfa5', 'py/dagrun/reservation.py': 'df55f994921fcca2250dc0b19646ede2ecc90875de8bfc6bca977310546dcd88', 'py/dagrun/scheduler.py': '8b3270b45a81f11961e3b3fec5bcfcc1e1adddb594ffa66fc1a90e42363d8855', 'py/dagrun/sizing.py': '8ff630b5eeaae9a2a0820b73eaaa4726d734caea4661c1798608e2dfeb7d6866', 'py/dagrun/summary.py': 'eb44f99d0690f8c2f4d9aa9a0a6a82f111f614e9648d18d874524097b9b00f46', 'py/dagrun/sweep.py': 'e8d2c38e3a1814e5b372813641916fcab1926bdf21d6812979dbdc2fb0ec9aee', 'py/dagrun/sync.py': 'f03feabf3ee2de3d5ed877f9e6481bd41d41cc049f9cbc8818defd48a1705c1b', 'py/dagrun/teardown.py': '7fd0bbcbc5758e0968441460c2c73be880043339e88d418a612772adad945909', 'py/dagrun/viz.py': '03dce1fb1bc44f9dcbe5dc86803512475b267eb2f236103ff5edf34cb84e498a'}
REVISION='1'*40
RAW=R.ROOT/'ignored/fabricated-receipt-native'
CPUS=[3,5,7]


def closed(data=b''):
    return dict(cleanup_complete=True,termination=None,exit_code=0,reaped_descendants=0,private_log_sha256=R._pin(data)['sha256'])


def protocol():
    paths=dict(root=str(R.ROOT),raw=str(RAW),capture=str(R.ROOT/'ignored/fabricated-receipt-capture'),
        log_dir=str(R.ROOT/'target/evaluation/fabricated-receipt-outer'),toolchain='/source-fixture/toolchain',
        user_home='/source-fixture/home',cargo_home='/source-fixture/cargo',allocator_root='/source-fixture/allocator')
    qualification=L.PROFILES['call-pair-original-native']
    return dict(CLOSED=True,execution='UNRUN',version=1,profile='call-pair-original-native',qualification=qualification,
        revision=REVISION,tag='fabricated-receipt',paths=paths,launcher=dict(path=str(LAUNCHER_PATH),**R._pin(launcher_source)),
        source_pins={name:dict(bytes=1,sha256=L.OWNER_SHA if name==L.OWNER else 'a'*64) for name in L.COMMON+L.EXTRA['call-pair-original-native']},
        tools={name:dict(path='/source-fixture/tools/'+name,bytes=1,sha256='b'*64) for name in L.TOOLS},
        allocator_revision='2'*40,allocator_sources=ALLOCATOR_SOURCES,session_env={},
        limits=dict(outer_seconds=1200,outer_log_bytes=8*R.MIB,evidence_bytes=2*1024**3,build_reserve_bytes=1024**3,
                    wrapper_bytes=24*R.MIB,slot_limit_bytes=20000000000))


def root_metadata():
    p=protocol();digest=R._pin(R._canonical(p))['sha256'];c=closed()
    result=dict(profile=p['profile'],qualification=p['qualification'],revision=REVISION,attempts=1,
        selected_outcome='CLOSED_EXIT_0',status='CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED',source_verified_after=True,
        protocol_sha256=digest,outer_seconds=1200,cleanup_seconds=3,owner_timeout_seconds=1199.5,closed=c)
    argv,env=L.command_environment(p)
    request=dict(command=argv,env=env,cwd=str(R.ROOT),tag=p['tag'],profile=p['profile'],limits=p['limits'],protocol_sha256=digest,attempts=1,retries=0)
    return p,result,c,request,digest


def result_metadata():
    r=H['native_recipe'];rows,_,_,_,_=F.fixture()
    return dict(kind='call-pair-original-native-release-v1',status='CALL_PAIR_ORIGINAL_NATIVE_LOCAL_COMPLETE',
        revision=REVISION,custody_closed=True,retention_verified=True,affinity=CPUS,
        cpu_roles=dict(supervisor_build_controls=CPUS,native_parent_and_tracees=5),reservation_tag='fabricated-receipt',scope=r.SCOPE,
        originals=[],installed=[],controls=[],prerequisites={},stages=[dict(name=n,status='CLOSED_EXIT_0',closed=closed()) for n in r.STAGES],
        planned_stages=[dict(name=n,status='CLOSED_EXIT_0',closed=closed()) for n in r.STAGES],
        evidence_budget=dict(limit=2048*R.MIB,final_allowance=64*R.MIB,held_bytes=0,reservation_active=False,exceeded=False,charged_rounded_bytes=4096),
        cohort=dict(name='call-pair',status='LOCAL_NATIVE_CHECKS_COMPLETE',attempts=1,required_pairs=192,catalog=r.catalog(),
            prefix_error=None,affinity_before=CPUS,affinity_after=CPUS,closed=closed(),observed=rows,comparisons=sum(r['comparisons'] for r in rows)))


def census():
    n,r=H['native'],H['native_recipe']
    prior=n.calibration_manifest(H['legacy'],H['normal'],H['whole'])
    inventory=list(prior)+list(H['leaf'].LEAF_CALIBRATIONS)+list(H['leaf'].EFFICIENCY_CALIBRATIONS)+list(r.ORACLE_CONTROLS)+[n.IGNORED]
    manifest=r.calibration_inventory(H['leaf'],prior,inventory,n.IGNORED)
    return dict(calibrations=manifest,ignored={n.IGNORED:n.IGNORE_REASON},ordinary=r.ORDINARY_CONTROLS,sdk=r.SDK_CONTROLS,core=r.CORE_CONTROLS,
        old_python=[n.PYTHON_CONTROLS,H['recipe'].PYTHON_CONTROLS,H['copied'].PYTHON_CONTROLS,H['copied'].RUNNER_CONTROLS,
                    H['leaf'].LEAF_CONTROLS,H['leaf'].EFFICIENCY_RUNNER_CONTROLS],checker=r.PYTHON_CONTROLS,runner=r.RUNNER_CONTROLS)


def geometry_streams():
    def dis(name,base,rows):
        return (f'{base:016x} <{name}>:\n'+''.join(f' {base+pc:x}:\t{code}\t{asm}\n' for pc,code,asm in rows)).encode()
    parent=[(0,'56','push rsi'),(1,'e8 fa 00 00 00','call 1100 <csv_fields>'),(6,'5a','pop rdx'),
            (7,'48 c1 e2 20','shl rdx,0x20'),(11,'48 09 d0','or rax,rdx'),(14,'c3','ret')]
    child=[(0,'48 85 f6','test rsi,rsi'),(3,'74 02','je 1107 <csv_fields+0x7>'),(5,'75 01','jne 1108 <csv_fields+0x8>'),(7,'c3','ret'),(8,'c3','ret')]
    caller=[(0,'53','push rbx'),(1,'48 89 cb','mov rbx,rcx'),(4,'ff d0','call rax'),(6,'48 89 03','mov QWORD PTR [rbx],rax'),(9,'5b','pop rbx'),(10,'c3','ret')]
    symbols=b'1: 0000000000001000 15 FUNC LOCAL DEFAULT 1 csv_summary\n2: 0000000000001100 9 FUNC LOCAL DEFAULT 1 csv_fields\n'
    callers=b'3: 0000000000002000 11 FUNC GLOBAL DEFAULT 1 liteinst_csv_call_and_store\n'
    return symbols,dis('csv_summary',4096,parent),dis('csv_fields',4352,child),dis('liteinst_csv_call_and_store',8192,caller),callers


def output_fixture():
    r,n=H['native_recipe'],H['native'];files={};value=census()
    def stream(name,out,err=b''):
        files[RAW/(name+'-io')/'stdout.txt']=out;files[RAW/(name+'-io')/'stderr.txt']=err
    def listed(names):return (''.join(n+': test\n' for n in names)+f'\n{len(names)} tests, 0 benchmarks\n').encode()
    def passed(names,inventory):
        count=len(names);noun='test' if count==1 else 'tests'
        return (f'\nrunning {count} {noun}\n'+''.join('test '+n+' ... ok\n' for n in names)+
            f'\ntest result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; {len(inventory)-count} filtered out; finished in 0.00s\n\n').encode()
    def python(names):return (''.join(n+f' (__main__.Controls.{n}) ... ok\n' for n in sorted(names))+f'\n------\nRan {len(names)} tests in 0.00s\n\nOK\n').encode()
    files[RAW/'controls.json']=R._canonical(value)
    manifest=value['calibrations'];stream('state-list',listed(list(manifest)+[n.IGNORED]))
    text=f'\nrunning {len(manifest)+1} tests\n'
    text+=''.join('test '+name+(' - should panic' if panic else '')+' ... ok\n' for name,panic in manifest.items())
    text+='test '+n.IGNORED+' ... ignored, '+n.IGNORE_REASON+'\n'
    text+=f'\ntest result: ok. {len(manifest)} passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s\n\n'
    stream('state-controls',text.encode())
    tools={name:Path('/source-fixture/tools')/name for name in L.TOOLS}
    bins={name:R.ROOT/'target/release/deps'/name for name in ('state','ordinary','sdk','core')}
    commands=R._commands(H,RAW,tools,bins)
    for target,wanted in [('ordinary',r.ORDINARY_CONTROLS),('sdk',r.SDK_CONTROLS),('core',r.CORE_CONTROLS)]:
        stream(target+'-list',listed(wanted))
        for name,(argv,_) in commands.items():
            if argv[0]==str(bins[target]) and argv[-1]=='--test-threads=1':
                selected=[n for n in wanted if n.startswith(argv[1])]
                stream(name,passed(selected,wanted));files[RAW/(name+'-io')/'request.json']=R._canonical(dict(argv=argv))
    for stage,names in [('legacy-python-controls',n.PYTHON_CONTROLS),('session-python-controls',H['recipe'].PYTHON_CONTROLS),
            ('copied-python-controls',H['copied'].PYTHON_CONTROLS),('copied-runner-controls',H['copied'].RUNNER_CONTROLS),
            ('leaf-python-controls',H['leaf'].LEAF_CONTROLS),('leaf-runner-controls',H['leaf'].EFFICIENCY_RUNNER_CONTROLS),
            ('python-controls',r.PYTHON_CONTROLS),('runner-controls',r.RUNNER_CONTROLS)]:stream(stage,b'',python(names))
    stream('module-build',b'')
    for name,data in zip(('module-symbols','parent-disassembly','child-disassembly','application-caller-disassembly','application-caller-symbols'),geometry_streams()):stream(name,data)
    f=F.fixture();geometry=dict(zip(('parent','child','caller'),f[2:]));files[RAW/'geometry.json']=R._canonical(geometry)
    for name,data in zip(('output/call-pair-state-pairs.csv','output/call-pair-state-coverage.csv','stdout.txt','stderr.txt'),F.encoded(f)):
        files[RAW/'native'/name]=data
    return files,result_metadata(),geometry


def reader(files):
    def get(path,cap):
        value=files[path];assert len(value)<=cap;return value
    return get


class Controls(unittest.TestCase):
    def test_fixed_five_qualifications_all_32_cases_and_request_freeze(self):
        r=H['native_recipe'];plan=R._plan(r,REVISION,'fabricated-receipt',CPUS)
        self.assertEqual(len(plan['catalog']),192);self.assertEqual(len(set(plan['catalog'])),192)
        self.assertEqual(plan['catalog'],[(k,s,c,v) for k in (10,1000) for s in r.SEEDS for c in range(1,17) for v in (1,2,3)])
        self.assertEqual(len(plan['stages']),37);self.assertEqual(plan['attempts'],1);self.assertEqual(plan['retries'],0)
        originals,installed=H['recipe'].catalog();self.assertEqual((len(originals),len(installed)),(32,320))
        self.assertEqual(sorted({r['attempt'] for r in installed}),[1,2,3,4,5])
        self.assertTrue(all(r['status']=='UNRUN' and r['attempts']==0 for r in originals+installed))
        for field in ('attempts','retries','pairs','children','target_calls','target_returns','normal_reaps'):
            bad=copy.deepcopy(plan);bad[field]+=1
            with self.assertRaises(AssertionError):R._equal(bad,R._plan(r,REVISION,'fabricated-receipt',CPUS))

    def test_exact_source_native_geometry_and_original_receipt_joins(self):
        files,result,geometry=output_fixture();got,parsed=R._outputs(H,reader(files),result,RAW)
        self.assertEqual(got,geometry);self.assertEqual((len(parsed['rows']),len(parsed['coverage'])),(192,12))
        self.assertEqual(R._derive(H,*geometry_streams()),geometry)
        for index,old,new in [(0,b'LOCAL',b'GLOBAL'),(1,b'e8 fa',b'e8 fb'),(2,b'je 1107',b'je 1106'),(3,b'ff d0',b'ff d1'),(4,b' 11 FUNC',b' 12 FUNC')]:
            streams=list(geometry_streams());streams[index]=streams[index].replace(old,new)
            with self.assertRaises(AssertionError):
                value=R._derive(H,*streams);R._equal(value,geometry)
        for name in ('output/call-pair-state-pairs.csv','output/call-pair-state-coverage.csv'):
            bad=dict(files);path=RAW/'native'/name;lines=bad[path].splitlines(keepends=True);bad[path]=b''.join(lines[:-1])
            with self.assertRaises(AssertionError):R._outputs(H,reader(bad),result,RAW)
        for key in ('parent','child','caller'):
            bad=copy.deepcopy(geometry);bad[key]['length']+=1
            with self.assertRaises(AssertionError):R._equal(got,bad)
        self.assertNotIn('original_result',parsed)
        # Every helper must be authenticated before any project source executes,
        # including a changed final member after all preceding members matched.
        source_read=R._read
        for name in R.SOURCE_PINS:
            bad_path=R.ROOT/name
            def read(path,cap):
                return b'changed source' if path==bad_path else source_read(path,cap)
            with patch.object(R,'_read',side_effect=read),patch.object(R,'_module') as execute:
                with self.assertRaises(AssertionError):R._helpers()
                execute.assert_not_called()

    def test_actual_pid_stream_hash_json_profile_before_custody_release(self):
        p,result,c,request,digest=root_metadata()
        R._root_guard(L,p,result,c,request,digest)
        seen=[];self.assertEqual(R._closed_read(c,lambda:seen.append('read') or b'output'),b'output');self.assertEqual(seen,['read'])
        for key,value in [('cleanup_complete',False),('cleanup_complete',1),('exit_code',1),('exit_code',False),('termination','timeout'),('reaped_descendants',1),('reaped_descendants',False)]:
            bad=dict(c);bad[key]=value;seen=[]
            with self.assertRaises(AssertionError):R._closed_read(bad,lambda:seen.append('read'))
            self.assertEqual(seen,[])
        for key,value in [('attempts',2),('source_verified_after',1),('selected_outcome','UNRUN'),('status','CALL_PAIR_ORIGINAL_NATIVE_LOCAL_COMPLETE'),('revision','2'*40),('owner_timeout_seconds',1201),('owner_timeout_seconds',float('nan'))]:
            bad=dict(result);bad[key]=value
            with self.assertRaises(AssertionError):R._root_guard(L,p,bad,c,request,digest)
        for key,value in [('command',[]),('protocol_sha256','f'*64),('cwd','/'),('attempts',True),('retries',1)]:
            bad=dict(request);bad[key]=value
            with self.assertRaises(AssertionError):R._root_guard(L,p,result,c,bad,digest)
        for data in (b'{"a":0,"a":1}',b'{"a":NaN}',b'{"a":Infinity}'):
            with self.assertRaises(AssertionError):R._json(data)
        self.assertNotIn('pid',c)
        assignment=R._canonical(dict(cores=CPUS,count=3))[:-1]
        summary=R._canonical(dict(status=L.PROFILES[p['profile']]['terminal'],custody_closed=True))
        log=b'cpuset-alloc: run: reserved '+assignment+b'; running whole tree pinned via AllowedCPUs=3,5,7\n'+summary
        log_closed=closed(log)
        actual=R._closed_read(log_closed,lambda:L.closed_log(log_closed,lambda:log))
        reservation=L.allocator_return(actual,log_closed,p['qualification'])
        self.assertEqual(reservation['recipe_exit'],0);self.assertIs(reservation['ledger_readback'],False)
        self.assertEqual(reservation['cores'],CPUS)
        for bad in (log+b'extra diagnostic\n',log.replace(b'AllowedCPUs=3,5,7',b'AllowedCPUs=3,5,8'),
                log.replace(b'"custody_closed":true',b'"custody_closed":1'),log.replace(b'LOCAL_COMPLETE',b'FAILED')):
            with self.assertRaises(AssertionError):L.allocator_return(bad,closed(bad),p['qualification'])
        with self.assertRaises(AssertionError):L.closed_log(log_closed,lambda:log+b'changed')
        for value in (dict(bytes=True,sha256='a'*64),dict(bytes=-1,sha256='a'*64),
                dict(bytes=513*R.MIB,sha256='a'*64),dict(bytes=1,sha256='A'*64),
                dict(bytes=1,sha256='a'*64,qualified=True)):
            with self.assertRaises(AssertionError):R._shape(value)

    def test_closed_failure_continues_unknown_custody_leaves_unrun(self):
        result=result_metadata();r=H['native_recipe'];R._result_header(result,r,REVISION,'fabricated-receipt',CPUS)
        for index in range(37):
            bad=copy.deepcopy(result);bad['stages'][index]['status']='FAILED';bad['planned_stages']=copy.deepcopy(bad['stages'])
            with self.assertRaises(AssertionError):R._result_header(bad,r,REVISION,'fabricated-receipt',CPUS)
        for key,value in [('custody_closed',False),('retention_verified',False),('status','FAILED'),('affinity',[3,5])]:
            bad=copy.deepcopy(result);bad[key]=value
            with self.assertRaises(AssertionError):R._result_header(bad,r,REVISION,'fabricated-receipt',CPUS)
        for field in ('error','final_error','projection_error'):
            bad=copy.deepcopy(result);bad[field]='retained failure'
            with self.assertRaises(AssertionError):R._result_header(bad,r,REVISION,'fabricated-receipt',CPUS)
        # The helper has no authority to start, retry or promote session slots.
        _,slots=H['recipe'].catalog();before=copy.deepcopy(slots)
        with self.assertRaises(AssertionError):R._zero(dict(closed(),exit_code=1))
        self.assertEqual(slots,before);self.assertTrue(all(s['status']=='UNRUN' for s in slots))

    def test_history_pressure_and_deadlines_remain_literal(self):
        r=H['native_recipe'];p=protocol();tools={k:Path(v['path']) for k,v in p['tools'].items()}
        bins={key:R.ROOT/'target/release/deps'/key for key in ('state','ordinary','sdk','core')}
        commands=R._commands(H,RAW,tools,bins);env=R._environment(p,tools)
        self.assertEqual(set(commands),set(r.STAGES[:-1]))
        self.assertEqual(sum(bounds==(120,180,128*R.MIB) for _,bounds in commands.values()),5)
        for name,wanted in commands.items():
            argv,(cpu,wall,cap)=wanted;io=RAW/(name+'-io');helper=R.ROOT/'tools/unwind-oracle/bounded_command.py'
            req=dict(argv=argv,cwd=str(R.ROOT),env=env,stdout=str(io/'stdout.txt'),stderr=str(io/'stderr.txt'),cpu_seconds=cpu,wall_seconds=wall,file_bytes=cap)
            parent=R._canonical(dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True));c=closed(parent)
            command=dict(argv=[str(tools['python']),'-B',str(helper),'--request',str(io/'request.json'),'--receipt',str(io/'receipt.json')],cwd=str(R.ROOT),env=env,wall_seconds=wall+25,log_bytes=R.MIB)
            pins={str(io/'request.json'):R._pin(R._canonical(req)),str(helper):dict(bytes=1,sha256='a'*64)}
            receipt=dict(exit=0,absence_proof='ECHILD',inputs_unchanged=True,wall_timeout=False,unexpected_descendants=[],cleanup_events=[],aborted=None,cleanup_error=None,
                request_sha256=pins[str(io/'request.json')]['sha256'],helper_sha256='a'*64,stdout_sha256=R._pin(b'')['sha256'],stderr_sha256=R._pin(b'')['sha256'])
            args=[H,RAW,tools,env,dict(name=name,status='CLOSED_EXIT_0',closed=c),command,req,receipt,c,parent,b'',b'',pins,wanted]
            R._bounded(*args)
            for field in ('cpu_seconds','wall_seconds','file_bytes'):
                bad=copy.deepcopy(req);bad[field]+=1;changed=list(args);changed[6]=bad
                with self.assertRaises(AssertionError):R._bounded(*changed)
            for field in ('request_sha256','helper_sha256','stdout_sha256','stderr_sha256'):
                bad=dict(receipt);bad[field]='0'*64;changed=list(args);changed[7]=bad
                with self.assertRaises(AssertionError):R._bounded(*changed)
        for field in p['limits']:
            bad=copy.deepcopy(p);bad['limits'][field]+=1
            with self.assertRaises(AssertionError):L.validate_protocol(bad)
        plan=R._plan(r,REVISION,'fabricated-receipt',CPUS)
        self.assertEqual((plan['pair_seconds'],plan['walk_steps'],plan['native_cpu_seconds'],plan['native_wall_seconds'],plan['outer_seconds']),(15,20000,480,510,1200))

    def test_exact_control_union_budget_first_pins_and_public_rows(self):
        value=census();sdk=list(H['native_recipe'].SDK_CONTROLS);R._census(H,value,sdk)
        self.assertEqual(len(sdk),30);self.assertTrue(sdk[-1].endswith('compact_journal_validation_keeps_all_words_at_every_phase'))
        for name in sdk:
            bad=copy.deepcopy(value);bad['sdk']=[n for n in sdk if n!=name]
            with self.assertRaises(AssertionError):R._census(H,bad,bad['sdk'])
        for observed in (sdk+[sdk[-1]],sdk+[sdk[-1].rsplit('::',1)[0]+'::unexpected']):
            with self.assertRaises(AssertionError):R._census(H,value,observed)
        files,result,_=output_fixture();key=RAW/'runtime-controls-io/stdout.txt';name=sdk[-1]
        data=files[key].decode();count=sum(n.startswith(name.rsplit('::',1)[0]+'::') for n in sdk)
        # Coherent reported counts and name removal still cannot pass the exact
        # current source-bound runtime inventory and output validator.
        files[key]=data.replace('test '+name+' ... ok\n','').replace(f'running {count} tests',f'running {count-1} tests').replace(f'{count} passed',f'{count-1} passed').encode()
        with self.assertRaises(AssertionError):R._outputs(H,reader(files),result,RAW)
        pins={};original=R._pin(b'original');R._first(pins,'evidence',original,original);before=copy.deepcopy(pins)
        for expected in (original,R._pin(b'changed')):
            with self.assertRaises(AssertionError):R._first(pins,'evidence',R._pin(b'changed'),expected)
            self.assertEqual(pins,before)
        for field,value in [('exceeded',True),('reservation_active',True),('held_bytes',1),('limit',2049*R.MIB),('final_allowance',63*R.MIB)]:
            bad=result_metadata();bad['evidence_budget'][field]=value
            with self.assertRaises(AssertionError):R._result_header(bad,H['native_recipe'],REVISION,'fabricated-receipt',CPUS)
        # Existing native public rows remain expressly unqualified; this helper
        # implements no compact session projection and assigns no native credit.
        projected=H['native_recipe'].public_projection(result_metadata())
        self.assertEqual(projected['status'],'UNQUALIFIED_PENDING_FINAL_RECEIPT')
        self.assertEqual(len(projected['outcomes']),192)
        self.assertTrue(all(v['status']=='OBSERVED_UNQUALIFIED' for v in projected['outcomes']))


if __name__=='__main__':
    unittest.main()
