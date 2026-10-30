"""Additive inert kernel-profile controls. No native dispatch or live signal reset."""
import copy
from contextlib import ExitStack
import ctypes
import gzip
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest import mock


def module(name, path=None):
    path=path or Path(__file__).with_name(name+'.py')
    spec=importlib.util.spec_from_file_location('_kernel_controls_'+name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


K=module('kernel_basis');W=module('native_wire');L=module('native_launch')
A=module('final_admission');Q=module('prepare_profile')
OLD=module('native_launch_controls')
D=module('reproduce_preparation',Path(__file__).resolve().parents[1]/'offline-router-corpus/reproduce_preparation.py')
PLAIN=b'# CONFIG_X86_USER_SHADOW_STACK is not set\nCONFIG_X86_DISABLED_FEATURE_USER_SHSTK=y\n'


def compact(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def compressed(value=PLAIN):return gzip.compress(value,mtime=0)

def basis():
    raw=compressed()
    return dict(profile=K.PROFILE,basis_sha256='11'*32,release='fixture-kernel',
        config_gzip_bytes=len(raw),config_gzip_sha256=K.sha(raw),
        config_decoded_bytes=len(PLAIN),config_decoded_sha256=K.sha(PLAIN))


def record():
    blobs={name:compressed() if name=='config_gzip' else (name+' complete fixture').encode() for name in K.FILES}
    pins={name:dict(path='/ignored/'+name,bytes=len(raw),sha256=K.sha(raw),stat=[1,index+1,0o100400,len(raw),3,4])
          for index,(name,raw) in enumerate(blobs.items())}
    value=dict(schema=K.SCHEMA,profile=K.PROFILE,platform='linux-x86_64',release='fixture-kernel',files=pins,
        decoded=dict(bytes=len(PLAIN),sha256=K.sha(PLAIN)),obligation=K.OBLIGATION)
    calls=[]
    def retain(pin,cap):
        calls.append((copy.deepcopy(pin),cap));raw=blobs[Path(pin['path']).name]
        if len(raw)>cap or len(raw)!=pin['bytes'] or K.sha(raw)!=pin['sha256']:raise ValueError('fixture custody')
        return raw
    return value,blobs,calls,retain


class GzipAndBasis(unittest.TestCase):
    def test_whole_single_gzip_member_has_exact_required_configuration(self):
        self.assertEqual(K.config_bytes(compressed()),PLAIN)
        self.assertEqual((K.GZIP_CAP,K.DECODED_CAP,K.HEADER_CAP),(65536,524288,262144))

    def test_truncation_crc_concatenation_surplus_empty_and_expansion_refuse(self):
        raw=compressed();bad_crc=bytearray(raw);bad_crc[-8]^=1
        for data in (b'',raw[:-1],bytes(bad_crc),raw+raw,raw+b'x',b'x'*65537,compressed(b'x'*524289)):
            with self.subTest(length=len(data)),self.assertRaises(ValueError):K.config_bytes(data)

    def test_enabled_missing_duplicate_malformed_and_ambiguous_config_refuse(self):
        variants=(PLAIN.replace(b'is not set',b'is set'),PLAIN.replace(b'=y',b'=n'),
            PLAIN.splitlines(keepends=True)[0],PLAIN+PLAIN.splitlines(keepends=True)[0],
            PLAIN+b'CONFIG_X86_USER_SHADOW_STACK=y\n',b' '+PLAIN,
            PLAIN+b'# alias CONFIG_X86_USER_SHADOW_STACK\n',PLAIN[:-1],PLAIN+b'\0\n')
        for raw in variants:
            with self.subTest(raw=raw[:80]),self.assertRaises(ValueError):K.config_bytes(compressed(raw))

    def test_capsule_rejects_every_type_bound_unknown_mode_and_extra_key(self):
        for key,bad in (('profile','errno-fallback'),('basis_sha256','AA'*32),('release',''),('release','a'*129),
            ('release','x\ny'),('release','x y'),('release','é'),('config_gzip_bytes',True),('config_gzip_bytes',0),
            ('config_gzip_bytes',65537),('config_decoded_bytes',524289),('config_decoded_sha256','00'),('extra',0)):
            value=basis();value[key]=bad
            with self.subTest(key=key,bad=bad),self.assertRaises(ValueError):K.capsule(value)

    def test_all_four_file_pins_and_decoded_join_are_required(self):
        value,blobs,calls,retain=record();raw=compact(value)
        actual=K.inspect(raw,K.sha(raw),retain)
        self.assertEqual(actual,dict(basis(),basis_sha256=K.sha(raw)))
        self.assertEqual([Path(pin['path']).name for pin,cap in calls],list(K.FILES))
        self.assertEqual([cap for pin,cap in calls],[65536,262144,262144,262144])

    def test_separate_acceptance_cannot_be_derived_from_self_report(self):
        value,_,calls,retain=record()
        with self.assertRaises(ValueError):K.inspect(compact(value),'00'*32,retain)
        self.assertEqual(calls,[])
        for raw in (b'{"schema":1,"schema":2}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):K.decode(raw)

    def test_missing_extra_duplicate_inode_path_and_weakened_obligation_refuse(self):
        for fault in ('missing','extra','inode','path','obligation','schema','decoded-size','decoded-digest','empty-header'):
            value,blobs,calls,retain=record()
            if fault=='missing':del value['files']['prctl_header']
            elif fault=='extra':value['files']['extra']=value['files']['prctl_header']
            elif fault=='inode':value['files']['prctl_header']['stat'][:2]=value['files']['shstk_header']['stat'][:2]
            elif fault=='path':value['files']['prctl_header']['path']=value['files']['shstk_header']['path']
            elif fault=='obligation':value['obligation']='EINVAL implies disabled'
            elif fault=='schema':value['schema']='old'
            elif fault=='decoded-size':value['decoded']['bytes']+=1
            elif fault=='decoded-digest':value['decoded']['sha256']='00'*32
            else:blobs['prctl_header']=b'';value['files']['prctl_header'].update(bytes=0,sha256=K.sha(b''))
            raw=compact(value)
            with self.subTest(fault=fault),self.assertRaises(ValueError):K.inspect(raw,K.sha(raw),retain)

    def test_each_live_check_reads_again_and_refuses_same_size_change(self):
        expected=basis();uname=types.SimpleNamespace(sysname='Linux',machine='x86_64',release=expected['release'])
        with mock.patch.object(K.os,'uname',return_value=uname),mock.patch.object(K,'live_config',side_effect=[compressed(),compressed(),compressed()[:-1]+b'X']) as live:
            K.check_live(expected);K.check_live(expected)
            with self.assertRaises(ValueError):K.check_live(expected)
            self.assertEqual(live.call_count,3)

    def test_live_release_machine_length_and_decoded_digest_drift_refuse(self):
        for fault in ('release','machine','length','decoded','late-release'):
            expected=basis();good=types.SimpleNamespace(sysname='Linux',machine='x86_64',release=expected['release'])
            bad=types.SimpleNamespace(**vars(good));raw=compressed()
            if fault=='release':bad.release='other'
            elif fault=='machine':bad.machine='aarch64'
            elif fault=='length':expected['config_gzip_bytes']+=1
            elif fault=='decoded':expected['config_decoded_sha256']='00'*32
            else:bad.release='after'
            sequence=[good,bad] if fault=='late-release' else [bad,bad]
            with self.subTest(fault=fault),mock.patch.object(K.os,'uname',side_effect=sequence),mock.patch.object(K,'live_config',return_value=raw),self.assertRaises(ValueError):K.check_live(expected)


class WireAndReceipts(unittest.TestCase):
    def request(self):return dict(OLD.request(),kernel_basis=basis())
    def receipt(self):
        return dict(OLD.receipt(),schema='LI2-OBSERVER-RECEIPT-3',kernel_basis=basis(),kernel_checks=6,
            kernel_query=dict(result=-1,errno=22,output_hex='55aa55aa55aa55aa'))
    def check(self,value,request=None):return L.observer_receipt(compact(value)+b'\n',request or self.request(),'11'*32)

    def test_v2_preserves_the_whole_old_payload_and_exact_new_trailer(self):
        old=W.encode(OLD.request());new=W.encode(self.request());b=basis();release=b['release'].encode()
        trailer=b'\x01'+bytes.fromhex(b['basis_sha256'])+struct.pack('<I',len(release))+release
        for kind in ('gzip','decoded'):trailer+=struct.pack('<I',b['config_'+kind+'_bytes'])+bytes.fromhex(b['config_'+kind+'_sha256'])
        self.assertEqual(new,W.MAGIC_V2+old[len(W.MAGIC):]+trailer)
        self.assertEqual(W.MAGIC,b'LI2-OBSERVER-REQUEST\0\x01')
        self.assertEqual((W.CAP,W.PAGE_CAP),(260*1048576,65536))

    def test_v2_rejects_null_mode_missing_field_bool_length_and_surplus(self):
        for fault in ('null','mode','missing','bool','extra'):
            request=self.request()
            if fault=='null':request['kernel_basis']=None
            elif fault=='mode':request['kernel_basis']['profile']='inferred'
            elif fault=='missing':del request['kernel_basis']['basis_sha256']
            elif fault=='bool':request['kernel_basis']['config_gzip_bytes']=True
            else:request['kernel_basis']['extra']=0
            with self.subTest(fault=fault),self.assertRaises(ValueError):W.encode(request)

    def test_v2_keeps_every_existing_page_dataset_and_register_bound(self):
        for fault in ('dataset','pages','dependencies','xstate','entry'):
            request=self.request()
            if fault=='dataset':request['dataset']['bytes']=request['dataset']['stat'][3]=65537
            elif fault=='pages':request['main']['pages'][0]['permissions_at_entry']='rwxp'
            elif fault=='dependencies':request['dependencies']=[request['loader']]*17
            elif fault=='xstate':request['xstate_bytes']=16385
            else:request['entry_bytes']='90'*16
            with self.subTest(fault=fault),self.assertRaises(ValueError):W.encode(request)

    def test_v3_exact_six_checks_and_raw_query_are_required(self):
        value=self.receipt();self.assertEqual(self.check(value),value)
        for fault in ('basis','five','seven','bool','success','errno','sentinel','missing','extra','schema'):
            value=self.receipt()
            if fault=='basis':value['kernel_basis']['release']='other'
            elif fault in ('five','seven','bool'):value['kernel_checks']={'five':5,'seven':7,'bool':True}[fault]
            elif fault=='success':value['kernel_query']['result']=0
            elif fault=='errno':value['kernel_query']['errno']=1
            elif fault=='sentinel':value['kernel_query']['output_hex']='0'*16
            elif fault=='missing':value['kernel_query']=None
            elif fault=='extra':value['kernel_query']['extra']=0
            else:value['schema']='LI2-OBSERVER-RECEIPT-2'
            with self.subTest(fault=fault),self.assertRaises(ValueError):self.check(value)

    def test_v3_cannot_promote_old_failure_or_claim_route_or_native_correctness(self):
        for fault in ('primary_error','debug_restored','absence_echild','route_coverage_complete','native_correctness_complete','stops','exit','xstate'):
            value=self.receipt()
            if fault=='primary_error':value[fault]='Entry'
            elif fault in ('debug_restored','absence_echild'):value[fault]=False
            elif fault in ('route_coverage_complete','native_correctness_complete'):value[fault]=True
            elif fault=='stops':value['stops'].pop()
            elif fault=='exit':value['cleanup']['terminal_statuses'][0]['status']=0
            else:value['entry_xstate']='00'*575
            with self.subTest(fault=fault),self.assertRaises(ValueError):self.check(value)

    def test_old_receipt_cannot_accept_kernel_extension_or_infer_mode(self):
        self.assertEqual(self.check(OLD.receipt(),OLD.request()),OLD.receipt())
        with self.assertRaises(ValueError):self.check(self.receipt(),OLD.request())
        with self.assertRaises(ValueError):self.check(OLD.receipt(),self.request())


class DedicatedSignals(unittest.TestCase):
    def test_single_main_proof_precedes_any_reset_and_rejects_unknown_tid(self):
        for current,tids in ((7,[7,8]),(8,[7]),(7,[]),(7,[8])):
            with self.subTest(current=current,tids=tids),mock.patch.object(L.os,'uname',return_value=types.SimpleNamespace(sysname='Linux',machine='x86_64')),mock.patch.object(L.os,'getpid',return_value=7),mock.patch.object(L,'raw_syscall',return_value=current),mock.patch.object(L,'launch_task_ids',return_value=tids),mock.patch.object(L,'kernel_action') as actions,self.assertRaises(ValueError):L.normalize_launch_signals()
            actions.assert_not_called()

    def test_default_reset_readback_order_and_single_main_checks_are_exact(self):
        with mock.patch.object(L,'single_launch_main') as single,mock.patch.object(L,'kernel_mask',return_value=0) as mask,mock.patch.object(L,'kernel_action',return_value=(0,0,0,0)) as action:
            L.normalize_launch_signals()
        self.assertEqual(single.call_count,2);self.assertEqual(mask.call_count,2)
        self.assertEqual(action.call_args_list,[mock.call(32,reset=True),mock.call(32),mock.call(33,reset=True),mock.call(33)])

    def test_nonempty_full_mask_refuses_before_reset(self):
        for mask in (1,1<<31,1<<32,1<<63):
            with mock.patch.object(L,'single_launch_main'),mock.patch.object(L,'kernel_mask',return_value=mask),mock.patch.object(L,'kernel_action') as action,self.assertRaises(ValueError):L.normalize_launch_signals()
            action.assert_not_called()

    def test_each_reset_error_or_readback_difference_stops_before_next_action(self):
        for index in range(4):
            values=[(0,0,0,0)]*4;values[index]=OSError('injected') if index%2==0 else (0,1,0,0)
            with self.subTest(index=index),mock.patch.object(L,'single_launch_main'),mock.patch.object(L,'kernel_mask',return_value=0),mock.patch.object(L,'kernel_action',side_effect=values) as action,self.assertRaises((OSError,ValueError)):L.normalize_launch_signals()
            self.assertEqual(action.call_count,index+1)

    def test_raw_hidden_signal_abi_uses_four_words_and_eight_byte_mask(self):
        calls=[]
        def syscall(number,*args):
            calls.append((number,args))
            self.assertEqual(number,13);self.assertEqual(args[0].value,32);self.assertEqual(args[3].value,8)
            old=ctypes.cast(args[2],ctypes.POINTER(L.KernelSigaction)).contents
            self.assertEqual(tuple(getattr(old,n) for n,_ in L.KernelSigaction._fields_),(2**64-1,)*4)
            if args[1]:
                new=ctypes.cast(args[1],ctypes.POINTER(L.KernelSigaction)).contents
                self.assertEqual(tuple(getattr(new,n) for n,_ in L.KernelSigaction._fields_),(0,)*4)
            for name,_ in L.KernelSigaction._fields_:setattr(old,name,0)
            return 0
        with mock.patch.object(L,'raw_syscall',side_effect=syscall):
            self.assertEqual(L.kernel_action(32,reset=True),(0,)*4)
            self.assertEqual(L.kernel_action(32),(0,)*4)
        self.assertEqual(ctypes.sizeof(L.KernelSigaction),32);self.assertEqual(len(calls),2)

    def test_zero_syscall_return_without_output_cannot_forge_readback(self):
        with mock.patch.object(L,'raw_syscall',return_value=0):
            self.assertEqual(L.kernel_action(32),(2**64-1,)*4)
            self.assertEqual(L.kernel_mask(),2**64-1)
        with mock.patch.object(L,'raw_syscall',return_value=1),self.assertRaises(ValueError):L.kernel_action(32)

    def test_every_child_boundary_requires_raw_defaults_and_full_mask(self):
        for fault in ('mask','disposition'):
            with mock.patch.object(L,'single_launch_main'),mock.patch.object(L,'kernel_mask',return_value=(1<<32 if fault=='mask' else 0)),mock.patch.object(L,'kernel_action',return_value=(1,0,0,0)),mock.patch.object(L.signal,'pthread_sigmask') as old,self.assertRaises(ValueError):L.child_signals()
            old.assert_not_called()

    def test_old_known_ignored_signal_and_python_mask_guards_remain(self):
        with mock.patch.object(L,'single_launch_main'),mock.patch.object(L,'kernel_mask',return_value=0),mock.patch.object(L,'kernel_action',return_value=(0,)*4),mock.patch.object(L.signal,'pthread_sigmask',return_value={1}),self.assertRaises(ValueError):L.child_signals()
        with mock.patch.object(L,'single_launch_main'),mock.patch.object(L,'kernel_mask',return_value=0),mock.patch.object(L,'kernel_action',return_value=(0,)*4),mock.patch.object(L.signal,'pthread_sigmask',return_value=set()),mock.patch.object(L.signal,'valid_signals',return_value={1}),mock.patch.object(L.signal,'getsignal',return_value=L.signal.SIG_IGN),self.assertRaises(ValueError):L.child_signals()


class ProfileAuthority(unittest.TestCase):
    def draft(self,root,version=4):
        value={name:{} for name in ('native_sources','artifact_source_profile','arguments','bootstrap','contract','reviewed','observer')}
        value.update(schema='LI2STARTUP-FINAL-PROFILE-'+str(version),native_revision='invalid-stop-before-source')
        if version==4:value['kernel_basis']=dict(path=str(root/'ignored/basis'),sha256='11'*32)
        return value

    def test_missing_mismatched_acceptance_and_old_profile_override_fail_before_source_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'ignored').mkdir()
            for version,accepted,expected in ((4,None,'canonical final digest'),(4,'22'*32,'separately accepts'),(3,'11'*32,'old profile')):
                raw=compact(self.draft(root,version))
                with self.subTest(version=version,accepted=accepted),mock.patch.object(A,'read_file',return_value=(raw,{})),mock.patch.object(A,'load_source') as load,self.assertRaisesRegex(ValueError,expected):A.open_session(root,root/'ignored/profile',A.sha(raw),'33'*32,accepted)
                load.assert_not_called()

    def test_correct_new_acceptance_proceeds_to_unchanged_revision_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'ignored').mkdir();raw=compact(self.draft(root))
            with mock.patch.object(A,'read_file',return_value=(raw,{})),self.assertRaisesRegex(ValueError,'actual separately committed'):A.open_session(root,root/'ignored/profile',A.sha(raw),'33'*32,'11'*32)

    def test_prepare_new_mode_never_changes_old_dispatch_kwargs(self):
        for mode,kwargs in (('final-profile',dict(absolute_prerequisites=False)),('final-profile-absolute-prerequisites',dict(absolute_prerequisites=True)),('final-profile-kernel-config-off',dict(absolute_prerequisites=True,kernel_config_off=True))):
            argv=['prepare_profile.py',mode,'--inputs','/fixture','--inputs-sha256','1'*64,'--output','/draft']
            with mock.patch.object(sys,'argv',argv),mock.patch.object(Q,'final_profile') as dispatch:Q.main()
            self.assertEqual(dispatch.call_args.kwargs,kwargs)

    def test_session_request_carries_private_kernel_capsule_and_fresh_stability(self):
        stable=mock.Mock();held=types.SimpleNamespace(retain=mock.Mock(),verify=mock.Mock())
        item=dict(observer_objects={k:v for k,v in OLD.request().items() if k in ('main','loader','bootstrap','dependencies')},entry=0x401000,entry_bytes='c3',completion_relative=0x1000,completion_file_offset=None)
        for extended in (False,True):
            profile=dict(_root='/fixture',reviewed=dict(xstate_bytes=576))
            if extended:profile['_kernel_capsule']=basis()
            session=A.Session(A._CONSTRUCTION,profile,dict(checksum=item),{},None,held,None,stable)
            session._bound={'checksum'}
            with mock.patch.object(session,'stable',side_effect=stable):
                result=session.request('checksum',dict(path='/fixture/ignored/input'))
            self.assertEqual('kernel_basis' in result,extended)
            if extended:
                result['kernel_basis']['release']='changed'
                self.assertEqual(session._profile['_kernel_capsule'],basis())
        self.assertEqual(stable.call_count,4)

    def test_named_observe_and_n01_stages_require_both_exact_acceptances(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();profile=root/'profile.json'
            value=dict(schema='LI2STARTUP-FINAL-PROFILE-4',contract=dict(sha256='22'*32),kernel_basis=dict(sha256='11'*32))
            profile.write_bytes(compact(value))
            values=dict(root=str(root),**{'final-profile':str(profile),'final-profile-sha256':D.sha(profile.read_bytes()),'accept-contract-sha256':'22'*32,'accept-kernel-basis-sha256':'11'*32,'output':str(root/'output')})
            tail=[x for key,value in values.items() for x in ('--'+key,value)]
            for stage in ('observe-kernel-config-off','n01-kernel-config-off'):
                plan=dict(schema='LI2-PREPARATION-COMMAND-1',stage=stage,arguments=tail,history=[])
                argv=D.command(root,Path('/python'),plan)
                self.assertEqual(argv[3],stage.split('-')[0]);self.assertEqual(argv[-len(tail):],tail)
                for bad in ('wrong','missing','old-stage','history'):
                    changed=copy.deepcopy(plan)
                    if bad=='wrong':changed['arguments'][changed['arguments'].index('--accept-kernel-basis-sha256')+1]='33'*32
                    elif bad=='missing':at=changed['arguments'].index('--accept-kernel-basis-sha256');del changed['arguments'][at:at+2]
                    elif bad=='old-stage':changed['stage']=stage.split('-')[0]
                    else:changed['history']=[dict(path='/x',sha256='00'*32)]
                    with self.subTest(stage=stage,bad=bad),self.assertRaises(ValueError):D.command(root,Path('/python'),changed)


class Capture(unittest.TestCase):
    def fixture(self, root):
        entry=root/'evaluation/offline-router-native/kernel_basis.py'
        entry.parent.mkdir(parents=True);entry.write_bytes(b'# test location only\n')
        (root/'ignored').mkdir();headers=root/'fixture-kernel';headers.mkdir()
        for name,relative in K.HEADER_PATHS.items():
            path=headers/relative;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((name+' complete header\n').encode())
        return types.SimpleNamespace(root=root,headers=headers,release='fixture-kernel',output=root/'ignored/basis'),entry

    def context(self, root):
        args,entry=self.fixture(root);stack=ExitStack()
        stack.enter_context(mock.patch.object(K,'__file__',str(entry)))
        stack.enter_context(mock.patch.object(K.os,'uname',return_value=types.SimpleNamespace(sysname='Linux',machine='x86_64',release=args.release)))
        live=stack.enter_context(mock.patch.object(K,'live_config',return_value=compressed()))
        return args,stack,live

    def test_capture_retains_exact_four_whole_files_and_never_accepts_itself(self):
        with tempfile.TemporaryDirectory() as temporary:
            args,stack,live=self.context(Path(temporary).resolve())
            with stack:result=K.capture(args)
            self.assertEqual(result['status'],'DRAFT_KERNEL_BASIS_REQUIRES_EXPLICIT_REVIEW')
            self.assertEqual(result['evidence_files'],4);self.assertIs(result['execution_authorized'],False)
            self.assertEqual(result['native_dispatches'],0);self.assertIs(result['qualification_complete'],False)
            self.assertIs(result['performance_eligible'],False);self.assertEqual(live.call_count,3)
            raw=(args.output/'basis.json').read_bytes();value=json.loads(raw)
            self.assertEqual(K.sha(raw),result['basis']['sha256']);self.assertEqual(set(value['files']),set(K.FILES))
            self.assertEqual(set(p.name for p in args.output.iterdir()),{'basis.json','config.gz',*(name+'.h' for name in K.HEADER_PATHS)})
            for name,pin in value['files'].items():
                actual=K.file_bytes(pin['path'],K.GZIP_CAP if name=='config_gzip' else K.HEADER_CAP)
                self.assertEqual(actual[1],pin)
                expected=compressed() if name=='config_gzip' else (args.headers/K.HEADER_PATHS[name]).read_bytes()
                self.assertEqual(actual[0],expected)

    def test_changed_header_source_refuses_before_draft_basis_is_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            args,stack,_=self.context(Path(temporary).resolve());real=K.file_bytes;seen=[]
            path=args.headers/K.HEADER_PATHS['shstk_header']
            def changed(found,cap):
                if Path(found)==path:
                    seen.append(found)
                    if len(seen)==2:path.write_bytes(b'changed header\n')
                return real(found,cap)
            with stack,mock.patch.object(K,'file_bytes',side_effect=changed),self.assertRaisesRegex(ValueError,'header source identity'):K.capture(args)
            self.assertFalse((args.output/'basis.json').exists())

    def test_symlink_header_and_wrong_live_release_refuse_before_capture(self):
        for fault in ('symlink','release'):
            with tempfile.TemporaryDirectory() as temporary:
                args,stack,_=self.context(Path(temporary).resolve())
                if fault=='symlink':
                    path=args.headers/K.HEADER_PATHS['shstk_header'];path.unlink()
                    path.symlink_to(args.headers/K.HEADER_PATHS['processor_header'])
                else:
                    stack.enter_context(mock.patch.object(K.os,'uname',return_value=types.SimpleNamespace(
                        sysname='Linux',machine='x86_64',release='different')))
                with stack:
                    if fault=='symlink':
                        with self.assertRaises(OSError):K.capture(args)
                    else:
                        with self.assertRaisesRegex(ValueError,'explicit release equals actual live kernel'):K.capture(args)
                self.assertFalse(args.output.exists())

    def test_named_capture_stage_keeps_exact_flags_and_no_acceptance(self):
        flags=dict(root='/root',release='fixture-kernel',headers='/headers/fixture-kernel',output='/root/ignored/basis')
        tail=[item for key,value in flags.items() for item in ('--'+key,value)]
        plan=dict(schema='LI2-PREPARATION-COMMAND-1',stage='kernel-basis',arguments=tail,history=[])
        self.assertEqual(D.command(Path('/root'),Path('/python'),plan),
            ['/python','-B','evaluation/offline-router-native/kernel_basis.py','capture',*tail])
        plan['arguments']+=['--accept-kernel-basis-sha256','11'*32]
        with self.assertRaises(ValueError):D.command(Path('/root'),Path('/python'),plan)

    def test_new_final_input_assembler_preserves_all_refs_and_remains_unapproved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();private=root/'ignored';private.mkdir()
            def file(relative,raw=b'{}'):
                path=root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
                return dict(path=str(path),sha256=D.sha(raw))
            for name in ('producer/originals/closed.json','producer/producer/receipt.json','producer/startup-binding.json',
                         'verifier/build/closed.json','joins/closed.json','bootstrap/closed.json','observer/closed.json'):
                file('ignored/'+name)
            file(D.ARTIFACT+'Cargo.lock',b'lock')
            refs=dict(schema='LI2-PREPARATION-REFERENCES-2',producer=str(private/'producer'),verifier=str(private/'verifier'),
                joins=str(private/'joins'),bootstrap=str(private/'bootstrap'),observer_plan=file('ignored/observer-plan')['path'],
                observer_build=str(private/'observer'),contract=file('ignored/contract'),kernel_basis=file('ignored/basis'),
                xstate={name:file('ignored/probe-'+name) for name in ('owner_source','owner_receipt','log','raw')})
            reference=file('ignored/refs',compact(refs))
            args=types.SimpleNamespace(root=root,revision='a'*40,plan=Path(reference['path']),plan_sha256=reference['sha256'],output=private/'inputs')
            with mock.patch.object(D,'snapshot'),mock.patch.object(D,'git',return_value=Path(D.__file__).read_bytes()):
                with self.assertRaises(ValueError):D.final_inputs(args)
                self.assertEqual(D.final_inputs(args,kernel_config_off=True),0)
            value=json.loads(args.output.read_bytes())
            self.assertEqual(value['schema'],'LI2NATIVE-FINAL-PROFILE-INPUTS-2')
            for name in ('contract','kernel_basis','xstate'):self.assertEqual(value[name],refs[name])
            self.assertNotIn('execution_authorized',value);self.assertNotIn('reviewed',value)


if __name__=='__main__':unittest.main()
