#!/usr/bin/env python3
"""Pure wire/receipt/build controls plus temporary memfd ownership; no exec."""
import copy
from contextlib import ExitStack
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


def module(name):
    path=Path(__file__).with_name(name+'.py')
    spec=importlib.util.spec_from_file_location('native_control_'+name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


W=module('native_wire')
L=module('native_launch')
N=module('n01')


def request():
    def pin(path):return dict(path=path,bytes=4096,sha256='07'*32,stat=[1,2,0o100700,4096,3,4])
    def obj(path):return dict(file=pin(path),pages=[dict(relative=0,file_offset=0,
        permissions_at_exec='rw-p',permissions_at_entry='rw-p',file_backed=True,bytes=None)])
    return dict(main=obj('/main'),loader=obj('/loader'),bootstrap=obj('/bootstrap'),dependencies=[],dataset=pin('/dataset'),
        entry=0x401000,entry_bytes='c3',completion_relative=0x1000,completion_file_offset=None,xstate_bytes=576)


def receipt():
    return dict(schema='LI2-OBSERVER-RECEIPT-1',request_sha256='11'*32,transport_accepted=True,child_started=True,
        stops=[dict(kind=kind,status=status,siginfo='' if kind=='exec' else '00'*128)
               for kind,status in zip(('initial','exec','entry'),(0x137f,0x4057f,0x57f))],
        exec_auxv='00',entry_auxv='00',exec_maps='00',entry_maps='00',exec_status='00',entry_status='00',
        entry_registers='00'*216,entry_xstate='00'*576,debug_restored=True,primary_error=None,restore_error=None,
        cleanup_error=None,absence_echild=True,observation=dict(completion=1,main_entry=0x401000,
        bootstrap_bias=0x70000000,stopped_before_main_execution=True,observer_killed_child=True,absence_echild=True,
        route_coverage_complete=False),route_coverage_complete=False,native_correctness_complete=False)


class Wire(unittest.TestCase):
    def test_fixed_wire_prefix_and_every_frozen_input_are_present(self):
        raw=W.encode(request())
        self.assertTrue(raw.startswith(W.MAGIC));self.assertLess(len(raw),4096)
        for name in (b'/main',b'/loader',b'/bootstrap',b'/dataset'):self.assertIn(name,raw)
        self.assertEqual(raw[-4:],(576).to_bytes(4,'little'))

    def test_unknown_top_object_page_and_pin_keys_refuse(self):
        for level in ('request','object','page','pin'):
            value=request()
            target={'request':value,'object':value['main'],'page':value['main']['pages'][0],'pin':value['main']['file']}[level]
            target['unknown']=1
            with self.subTest(level=level),self.assertRaises(ValueError):W.encode(value)

    def test_bool_integer_and_noncanonical_digest_refuse(self):
        for changed in ('entry','time','sha','mode'):
            value=request()
            if changed=='entry':value['entry']=True
            elif changed=='time':value['main']['file']['stat'][4]=-1
            elif changed=='mode':value['main']['file']['stat'][2]=True
            else:value['main']['file']['sha256']='AA'*32
            with self.subTest(changed=changed),self.assertRaises(ValueError):W.encode(value)

    def test_path_alias_stat_size_and_nonregular_file_refuse(self):
        for path in ('/a/../main','/a//main','relative','/a/./main'):
            value=request();value['main']['file']['path']=path
            with self.subTest(path=path),self.assertRaises(ValueError):W.encode(value)
        for index,value in ((3,4095),(2,0o120700)):
            changed=request();changed['main']['file']['stat'][index]=value
            with self.subTest(index=index),self.assertRaises(ValueError):W.encode(changed)

    def test_page_alignment_order_permissions_and_full_image_refuse(self):
        for change in ('address','offset','wx','short','backing','duplicate'):
            value=request();page=value['main']['pages'][0]
            if change=='address':page['relative']=1
            elif change=='offset':page['file_offset']=1
            elif change=='wx':page['permissions_at_entry']='rwxp'
            elif change=='short':page['bytes']='00'*4095
            elif change=='backing':page['file_backed']=1
            else:value['main']['pages'].append(copy.deepcopy(page))
            with self.subTest(change=change),self.assertRaises(ValueError):W.encode(value)

    def test_dependency_dataset_entry_and_xstate_bounds_remain_strict(self):
        for change in ('dependencies','dataset','empty-entry','long-entry','completion','xstate'):
            value=request()
            if change=='dependencies':value['dependencies']=[copy.deepcopy(value['loader']) for _ in range(17)]
            elif change=='dataset':value['dataset']['bytes']=value['dataset']['stat'][3]=65537
            elif change=='empty-entry':value['entry_bytes']=''
            elif change=='long-entry':value['entry_bytes']='90'*16
            elif change=='completion':value['completion_relative']=1
            else:value['xstate_bytes']=575
            with self.subTest(change=change),self.assertRaises(ValueError):W.encode(value)

    def test_memfd_has_every_seal_exact_bytes_and_no_mutation(self):
        raw=W.encode(request());fd,digest=W.sealed(raw)
        try:
            self.assertEqual(digest,L.sha(raw));self.assertEqual(os.pread(fd,len(raw),0),raw)
            self.assertEqual(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&W.SEALS,W.SEALS)
            for mutate in (lambda:os.pwrite(fd,b'x',0),lambda:os.ftruncate(fd,len(raw)+1),lambda:os.ftruncate(fd,0)):
                with self.assertRaises(OSError):mutate()
        finally:os.close(fd)


class Receipts(unittest.TestCase):
    def check(self,value):return L.observer_receipt((json.dumps(value)+'\n').encode(),request(),'11'*32)
    def test_complete_preentry_receipt_preserves_raw_state_and_no_route_claim(self):
        value=receipt();self.assertEqual(self.check(value),value)
        self.assertEqual(len(bytes.fromhex(value['entry_registers'])),216)
        self.assertFalse(value['route_coverage_complete']);self.assertFalse(value['native_correctness_complete'])

    def test_any_missing_stop_or_changed_raw_status_refuses(self):
        for index in range(3):
            value=receipt();value['stops'][index]['status']+=0x100
            with self.subTest(index=index),self.assertRaises(ValueError):self.check(value)
        value=receipt();value['stops'].pop()
        with self.assertRaises(ValueError):self.check(value)

    def test_every_required_restoration_cleanup_and_error_gate_remains(self):
        for field in ('transport_accepted','child_started','debug_restored','absence_echild','primary_error','restore_error','cleanup_error'):
            value=receipt();value[field]=False if value[field] is True else 'failure'
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(value)

    def test_short_registers_xstate_siginfo_and_wrong_request_refuse(self):
        for field in ('entry_registers','entry_xstate','siginfo','request_sha256'):
            value=receipt()
            if field=='siginfo':value['stops'][2]['siginfo']=value['stops'][2]['siginfo'][:-2]
            elif field=='request_sha256':value[field]='22'*32
            else:value[field]=value[field][:-2]
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(value)

    def test_preentry_cannot_claim_route_or_native_or_wrong_completion(self):
        for field in ('route_coverage_complete','native_correctness_complete','completion','main_entry'):
            value=receipt()
            if field in ('completion','main_entry'):value['observation'][field]=0
            else:value[field]=True
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(value)

    def test_duplicate_keys_and_nonfinite_values_are_rejected(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(ValueError):L.decode(raw)


class Build(unittest.TestCase):
    def rows(self,root):
        return [dict(reason='compiler-artifact',manifest_path=str(root/L.NATIVE/'observer/Cargo.toml'),
            target=dict(name='li2-kernel-exec-observer',kind=['bin'],crate_types=['bin'],src_path=str(root/L.NATIVE/'observer/src/main.rs')),
            profile=dict(L.RELEASE),filenames=[str(root/'target/release/li2-kernel-exec-observer')],
            executable=str(root/'target/release/li2-kernel-exec-observer')),dict(reason='build-finished',success=True)]
    def check(self,rows):return L.compiler_artifact(('\n'.join(json.dumps(row) for row in rows)+'\n').encode(),Path('/repo'))
    def test_actual_release_executable_receipt_and_exact_rooted_command(self):
        self.assertEqual(self.check(self.rows(Path('/repo'))),Path('/repo/target/release/li2-kernel-exec-observer'))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();env={'CARGO_TARGET_DIR':str(root/'target')}
            argv=L.cargo_command('/tools/cargo',root,env)
            self.assertEqual(argv,['/tools/cargo','build','--release','--locked','--offline','--manifest-path',
                str(root/L.NATIVE/'observer/Cargo.toml'),'--bin','li2-kernel-exec-observer','--message-format=json'])
            with self.assertRaises(ValueError):L.cargo_command('/tools/cargo',root,{'CARGO_TARGET_DIR':str(root/'other')})

    def test_wrong_product_kind_profile_terminal_and_duplicate_refuse(self):
        for change in ('kind','debug','overflow','executable','terminal','duplicate'):
            rows=self.rows(Path('/repo'))
            if change=='kind':rows[0]['target']['kind']=['cdylib']
            elif change=='debug':rows[0]['profile']['debug_assertions']=False
            elif change=='overflow':rows[0]['profile']['overflow_checks']=False
            elif change=='executable':rows[0]['executable']=None
            elif change=='terminal':rows[1]['success']=1
            else:rows.insert(0,copy.deepcopy(rows[0]))
            with self.subTest(change=change),self.assertRaises(ValueError):self.check(rows)


class FinalReporting(unittest.TestCase):
    """Run real population/reporting code; native dispatch and admission are fakes.

    These are lifecycle controls, not bootstrap, build or native results. The
    original comparators and full populations use frozen corpus datasets/expected
    bytes; a simulated dispatcher writes those bytes without executing a subject.
    """
    def campaign(self,which,fail_close):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as patches:
            root=Path(temporary).resolve();(root/'ignored').mkdir()
            output=root/'ignored'/'population';events=[];calls=[]
            def stamp(info):
                return [info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
            def pin(path):
                raw=path.read_bytes()
                return dict(path=str(path),bytes=len(raw),sha256=L.sha(raw),stat=stamp(path.stat()))
            # Retain real frozen bytes for source guards. The collector/helper
            # are never executed; the corpus supplies only pure datasets/expected bytes.
            checkout=Path(L.__file__).resolve().parents[2]
            for relative in ('evaluation/offline-corpus/corpus.py',
                    'evaluation/offline-corpus/adjacent_whole.py','tools/unwind-oracle/bounded_command.py'):
                path=root/relative;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((checkout/relative).read_bytes())
            tools={}
            for name in ('python','timeout'):
                path=root/'tools'/name;path.write_bytes(b'not executable')
                tools[name]=pin(path)
            tools['helper']=pin(root/'tools/unwind-oracle/bounded_command.py')
            corpus=N.load_pinned(root/'evaluation/offline-corpus/corpus.py',N.CORPUS_SHA,'reporting_corpus')
            expected=corpus.expected

            class Custody:
                def __init__(self):self.files={}
                def retain(self,value,cap):
                    raw=Path(value['path']).read_bytes()
                    if len(raw)>cap or pin(Path(value['path']))!=value:raise ValueError('fixture custody')
                    self.files[value['path']]=(None,None,raw)
                    return raw
                def verify(self):pass
                def close(self):events.append('owner-close')
            class Store(Custody):
                def read(self,path,cap,value=None):
                    return self.retain(pin(Path(path)) if value is None else value,cap)
            class Reader:
                def __init__(self,directory):self.root=Path(directory)
                def bytes(self,relative,cap=1048576):
                    raw=(self.root/relative).read_bytes()
                    if len(raw)>cap:raise ValueError('fixture stream cap')
                    return raw
                def directory(self,relative):return os.open(self.root/relative,os.O_RDONLY|os.O_DIRECTORY)
                def names(self,relative):return sorted(p.name for p in (self.root/relative).iterdir())
                def verify(self):pass
                def close(self):events.append('reader-close')
            class Session:
                def __init__(self):
                    self.profile=dict(native_revision='1'*40)
                    self.programs={program:dict(main_bytes=b'candidate-'+program.encode(),
                        original_bytes=b'original-'+program.encode()) for program in N.PROGRAMS}
                    self.closed=False;self.close_calls=0;self.bound=[]
                def stable(self):
                    if self.closed:raise ValueError('closed fixture Session')
                def check_source(self,relative):
                    self.stable()
                    path=Path(N.__file__) if relative.endswith('/n01.py') else Path(L.__file__)
                    return L.sha(path.read_bytes())
                def execution_inputs(self):self.stable();return dict(tools=tools)
                def bind_main_copy(self,program,value):
                    self.stable()
                    if program in self.bound:raise ValueError('duplicate fixture copy')
                    self.bound.append(program)
                def request(self,program,dataset):self.stable();return request()
                def close(self):
                    if self.closed:return
                    self.close_calls+=1;self.closed=True;events.append('session-close')
                    if fail_close:raise ValueError('injected final Session close')
            session=Session()
            def invoke(ctx,directory,argv,env,_tools):
                self.assertEqual(env,{})
                calls.append((list(argv),dict(env)))
                if which=='observer':
                    value=receipt();value['request_sha256']=L.sha(W.encode(request()))
                    stdout=(json.dumps(value)+'\n').encode()
                else:
                    stdout=expected(ctx.ROOT.parent.name,Path(argv[1]).read_bytes())
                (directory/'stdout.txt').write_bytes(stdout);(directory/'stderr.txt').write_bytes(b'')
                return {},{}
            collector=SimpleNamespace(OutputReader=Reader,stamp=stamp,invoke=invoke)
            package=SimpleNamespace(Custody=Custody,stamp=stamp)
            def load(path,_digest,_name):
                name=Path(path).name
                return {'package.py':package,'adjacent_whole.py':collector,
                    'corpus.py':corpus,'native_launch.py':SimpleNamespace(child_signals=lambda:None)}[name]
            def completed(_collector,reader,_request,_command):
                return 0,reader.bytes('importer/stdout.txt',N.FILE_CAP),reader.bytes('importer/stderr.txt',N.FILE_CAP)
            patches.enter_context(mock.patch.object(N,'load_pinned',side_effect=load))
            patches.enter_context(mock.patch.object(N,'completed',side_effect=completed))
            def watched_write(original):
                def write(path,value,*args,**kwargs):
                    if Path(path).name=='closed.json':
                        self.assertTrue(session.closed,'Session must be consumed before the terminal marker')
                        events.append('terminal-marker')
                    return original(path,value,*args,**kwargs)
                return write
            if which=='observer':
                patches.enter_context(mock.patch.object(L,'source',side_effect=lambda _root,relative,_hash:
                    N if relative.endswith('/n01.py') else W))
                patches.enter_context(mock.patch.object(L,'observer_build',return_value=(None,Store(),None,lambda:None)))
                patches.enter_context(mock.patch.object(L,'child_signals',return_value=None))
                patches.enter_context(mock.patch.object(L,'write',side_effect=watched_write(L.write)))
                code=L.observe_population(root,output,root/'ignored'/'profile','11'*32,'22'*32,session)
                report=json.loads((output/'closed.json').read_bytes())
                rows=report['programs'];flag='pre_entry_observation_complete';error=report['error']
                self.assertEqual([row['program'] for row in rows],list(N.PROGRAMS))
                self.assertEqual(len(calls),2);self.assertEqual(report['ordinary_n01_invocations'],0)
                self.assertIs(report['native_correctness_complete'],False)
            else:
                patches.enter_context(mock.patch.object(N,'write',side_effect=watched_write(N.write)))
                code=N.run_final(root,output,session,dict(path=str(root/'ignored'/'profile'),sha256='11'*32))
                marker=json.loads((output/'closed.json').read_bytes())
                report=json.loads((output/'summary.json').read_bytes())
                rows=json.loads((output/'invocations.json').read_bytes());flag='native_correctness_complete';error=report['fatal']
                self.assertEqual([(r['program'],r['dataset'],r['lane']) for r in rows],
                    [(p,d,lane) for p in N.PROGRAMS for d in N.DATASETS for lane in N.LANES])
                self.assertEqual(len(calls),40);self.assertEqual(report['attempted'],40)
                self.assertEqual(report['counts'],dict(PASS=40,FAILED=0,UNRUN=0))
                pairs=json.loads((output/'pairs.json').read_bytes())
                self.assertEqual(len(pairs),20);self.assertTrue(all(row['status']=='PASS' for row in pairs))
                self.assertEqual(marker[flag],report[flag])
                self.assertEqual(marker['summary_sha256'],L.sha((output/'summary.json').read_bytes()))
                self.assertIs(marker['performance_eligible'],False)
                self.assertIs(report['performance_eligible'],False)
            self.assertTrue(all(row['status']=='PASS' and row['attempted'] for row in rows))
            self.assertEqual(session.bound,list(N.PROGRAMS))
            self.assertEqual(session.close_calls,1)
            self.assertLess(events.index('session-close'),events.index('terminal-marker'))
            self.assertEqual(code,1 if fail_close else 0)
            self.assertIs(report[flag],not fail_close)
            if fail_close:self.assertIn('injected final Session close',error)
            else:self.assertIsNone(error)
            self.assertIs(report['qualification_complete'],False)
            self.assertIs(report['route_coverage_complete'],False)
            session.close()  # Same idempotent fallback retained in main().
            self.assertEqual(session.close_calls,1)

    def test_observer_final_session_closes_before_success_marker(self):self.campaign('observer',False)
    def test_observer_close_failure_retains_both_rows_and_false_completion(self):self.campaign('observer',True)
    def test_n01_final_session_closes_before_success_marker(self):self.campaign('n01',False)
    def test_n01_close_failure_retains_all_forty_rows_and_false_completion(self):self.campaign('n01',True)


if __name__=='__main__':unittest.main()
