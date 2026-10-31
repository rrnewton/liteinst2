#!/usr/bin/env python3
"""Pure prepared-entrypoint controls with explicit fake process/pipe custody."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    assert spec is not None and spec.loader is not None
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


prior=load('_prepared_prior_functional_controls',HERE/'accuracy_functional_controls.py')
producer,recipe,owner=prior.producer,prior.recipe,prior.owner
reader=load('_prepared_functional_reader',HERE.parent/'ordinary-accuracy/prepared_phase_output.py')
saved=sys.modules.get('prepared_phase_output')
sys.modules['prepared_phase_output']=reader
try:
    fixture=load('_prepared_full_wire_fixture',HERE.parent/'ordinary-accuracy/prepared_phase_controls.py')
finally:
    if saved is None:del sys.modules['prepared_phase_output']
    else:sys.modules['prepared_phase_output']=saved


class Controls(unittest.TestCase):
    def test_exact_new_owner_modes_preserve_old_options_and_reject_free_target(self):
        self.assertEqual(tuple(owner.EXTRAS),('accuracy-prepare','accuracy-functional'))
        self.assertEqual(tuple(owner.PHASE_EXTRAS),('phase-prepare','phase-functional'))
        self.assertEqual(tuple(owner.PREPARED_PHASE_EXTRAS),('prepared-phase-prepare','prepared-phase-functional'))
        for phase in owner.PREPARED_PHASE_EXTRAS:
            options={k:'/tmp/'+k for k in owner.COMMON+owner.extras(phase)}
            options.update(phase=phase,revision='1'*40,**{'reservation-tag':'prepared-1','hardware':'fixture','epoch-phase':'random'})
            for k in options:
                if k.endswith('-sha'):options[k]='2'*64
            argv,child=owner.commands(options,'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))
            self.assertEqual(child[3:5],['--phase',phase])
            self.assertEqual(child[-2:],['--epoch-phase','random'])
            self.assertNotIn('--owner',child)
            self.assertEqual(len(argv),3+2*len(options))
            for key,value in (('epoch-phase','calibration'),('epoch-phase',''),('phase','accuracy-prepare'),
                    ('command','/bin/true'),('delay-ns','0'),('target-epoch','1'),('target-ns','10000000')):
                with self.assertRaises(AssertionError):owner.commands(dict(options,**{key:value}),'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))
            with self.assertRaises(AssertionError):prior.legacy.commands(options,'/usr/bin/python3',str(prior.legacy.HERE/'owner.py'))

    def test_fixed_target_is_separate_from_original_five_key_manifest_policy(self):
        for kind in ('locked','random'):
            policy=producer.phase_policy(reader,kind);saved=copy.deepcopy(policy)
            target=producer.prepared_target(policy)
            self.assertEqual(set(policy),{'k','period_ms','epochs','phase','delay_ns'})
            self.assertEqual(policy,saved)
            self.assertEqual(target,dict(target_epoch=1,arm_number=2,target_ns=10000000+policy['delay_ns']))
            self.assertEqual(recipe.chosen_policy(reader,producer,kind,True),policy)
            self.assertEqual(recipe.initial_row(kind,True)['records'],2048)
            self.assertEqual(recipe.initial_row(kind,True)['attempts'],0)
            self.assertEqual(recipe.prepare_phase(kind,True),'prepared-phase-prepare')
            self.assertEqual(recipe.preparation_status(kind,True),'PREPARED_PHASE_PREPARATION_PASS')
        for key,value in (('epochs',1),('epochs',True),('epochs',521),('period_ms',2),('delay_ns',-1),('delay_ns',10000000),('phase','calibration'),('k',True)):
            with self.assertRaises(AssertionError):producer.prepared_target(dict(producer.POLICY,**{key:value}))
        with self.assertRaises(AssertionError):producer.prepared_target(dict(producer.POLICY,target_epoch=1))
        with self.assertRaises(AssertionError):recipe.profile(None,True)
        self.assertEqual(recipe.initial_row(),dict(name='calibration-trial1-late_expensive-k10-period10-e520',status='UNRUN',attempts=0,records=2048))

    def test_geometry_all_premises_and_new_scope_are_mutually_exact(self):
        facts={'external':'complete actual ELF/page/caller review, fixture only'}
        value=dict(kind='selected-accuracy-prepared-phase-functional-geometry-acceptance-v1',
            status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION',scope=recipe.PREPARED_PHASE_PROFILE,
            revision='1'*40,preparation_sha256='2'*64,facts=facts,premises={k:True for k in recipe.PREMISES},
            review='Fabricated external premise, not authority.',native_state='UNRUN_SEPARATE_REQUIRED')
        recipe.accept_geometry(value,facts,'2'*64,'1'*40,epoch_phase='random',prepared=True)
        for kind,scope,phase in (('selected-accuracy-functional-geometry-acceptance-v1',recipe.PROFILE,None),
                ('selected-accuracy-phase-functional-geometry-acceptance-v1',recipe.PHASE_PROFILE,'random')):
            legacy=dict(value,kind=kind,scope=scope)
            recipe.accept_geometry(legacy,facts,'2'*64,'1'*40,epoch_phase=phase)
            with self.assertRaises(AssertionError):recipe.accept_geometry(legacy,facts,'2'*64,'1'*40,epoch_phase='random',prepared=True)
            with self.assertRaises(AssertionError):recipe.accept_geometry(value,facts,'2'*64,'1'*40,epoch_phase=phase)
        for premise in recipe.PREMISES:
            bad=copy.deepcopy(value);bad['premises'][premise]=False
            with self.assertRaises(AssertionError):recipe.accept_geometry(bad,facts,'2'*64,'1'*40,epoch_phase='random',prepared=True)

    def test_argv_inserts_fixed_j_after_original_delay_and_keeps_entire_geometry(self):
        pin=dict(bytes=1,sha256='1'*64)
        run=SimpleNamespace(a=SimpleNamespace(revision='2'*40,geometry=Path('/g'),preparation=Path('/p'),preparation_sha='1'*64),
            cpus=[0,1,2],sources={},tool_pins={},retained={'/g':pin,'/p':pin})
        facts=dict(materials={k:dict(path='/m/'+k,**pin) for k in producer.MATERIALS},
            table=[dict(function_id=41,operation='exact_work_nonempty',policy='whole',elf_va=4096,extent=37,returns=[36])],
            caller=dict(extent=20,continuation=15),binary=dict(path='/bin/app',**pin),
            candidate=dict(path='/candidate',**pin),trusted=dict(path='/trusted',**pin),policy=producer.phase_policy(reader,'random'))
        facts['prepared_phase']=producer.prepared_target(facts['policy'])
        old=recipe.input_plan(run,None,facts,producer,epoch_phase='random')
        new=recipe.input_plan(run,None,facts,producer,epoch_phase='random',prepared=True)
        self.assertEqual((len(old['argv']),len(new['argv'])),(16,17))
        self.assertEqual(new['argv'][1],'normal-selected-accuracy-prepared-phase-session')
        self.assertEqual(new['argv'][2:10],old['argv'][2:10])
        self.assertEqual(new['argv'][10],'1')
        self.assertEqual(new['argv'][11:],old['argv'][10:])
        self.assertEqual(new['policy'],old['policy'])
        self.assertNotIn('prepared_phase',old)
        self.assertEqual(new['prepared_phase'],facts['prepared_phase'])
        self.assertEqual(new['profile'],producer.PREPARED_PHASE_PROFILE)
        with self.assertRaises(AssertionError):producer.arguments(new,prior.checker)
        with self.assertRaises(AssertionError):producer.phase_arguments(new,reader.phase)
        with self.assertRaises(AssertionError):producer.prepared_phase_arguments(old,reader)
        for key,value in (('target_epoch',2),('target_epoch',True),('arm_number',1),('target_ns',10000000)):
            bad=copy.deepcopy(facts);bad['prepared_phase'][key]=value
            with self.assertRaises(AssertionError):recipe.input_plan(run,None,bad,producer,epoch_phase='random',prepared=True)

    def test_ready_requires_new_version_pid_and_profile_before_same_sender(self):
        raw=prior.ready().replace(b'selected-accuracy-session-v1',reader.VERSION.encode())
        producer.ready_row(raw,123,[0,1,2],reader)
        for checker in (prior.checker,reader.phase):
            with self.assertRaises(AssertionError):producer.ready_row(raw,123,[0,1,2],checker)
        with self.assertRaises(AssertionError):producer.ready_row(prior.ready(),123,[0,1,2],reader)
        with self.assertRaises(AssertionError):producer.ready_row(raw,124,[0,1,2],reader)
        with self.assertRaises(AssertionError):producer.prepared_phase_exchange(dict(profile=producer.PHASE_PROFILE),{},reader)

    def test_cancelled_full_wire_with_done_and_exit_zero_is_failed_with_raw_retention(self):
        rows,args=fixture.fixture()
        rows.append(['CANCELLED','1','41','never_invoked','10000000','1','0'])
        wire=fixture.old.encode(rows)
        ready,rest=wire.split(b'\n',1)
        self.assertEqual(ready.split(b',')[:2],[b'READY',reader.VERSION.encode()])
        producer.ready_row(ready,123,[2,4,6],reader)
        class BothPipes(prior.Selector):
            def select(self,timeout):return [(key,1) for key in list(self.mapping.values())]
        for code in (0,1):
            child,selector=prior.Child(code),BothPipes()
            chunks=[ready+b'\n']+[rest[i:i+producer.CHUNK] for i in range(0,len(rest),producer.CHUNK)]
            errors=b'' if code==0 else b'cancelled without invocation\n'
            reads={11:chunks+[b''],12:[errors,b''] if errors else [b'']}
            write_input=producer.write_input
            writer=mock.Mock(side_effect=lambda fd,data:len(data))
            plan=dict(profile=producer.PREPARED_PHASE_PROFILE,revision='1'*40,cpus=[2,4,6],argv=['/not-executed'])
            with mock.patch.object(producer.subprocess,'Popen',return_value=child), \
                 mock.patch.object(producer.selectors,'DefaultSelector',return_value=selector), \
                 mock.patch.object(producer.os,'sched_setaffinity'), \
                 mock.patch.object(producer.os,'sched_getaffinity',return_value={6}), \
                 mock.patch.object(producer.os,'set_blocking'), \
                 mock.patch.object(producer.os,'read',side_effect=lambda fd,n:reads[fd].pop(0)), \
                 mock.patch.object(producer,'write_input',side_effect=lambda *a:write_input(*a,writer=writer)):
                result,out,err,overflow,_=producer.prepared_phase_exchange(plan,args,reader)
            self.assertEqual((out,err,overflow),(wire,errors,b''))
            self.assertEqual(result['status'],'FAILED')
            self.assertEqual((result['normal_reaps'],result['rescue'],result['child_exit']),(1,False,code))
            self.assertEqual(result['sent_bytes'],len(args['input_bytes']))
            self.assertEqual(sum(r[3] for r in result['writes']),len(args['input_bytes']))
            self.assertGreater(writer.call_count,0)
            self.assertFalse(child.killed)
            self.assertEqual(result['requested_phase_status'],'UNRESOLVED')
            self.assertFalse(result['metric_qualified'])
            if code==0:self.assertIn('cancellation is not a full returned population',result['error'])

    def test_new_failure_envelope_leaves_all_old_byte_line_row_caps_unchanged(self):
        self.assertEqual((producer.CAP,producer.LINE,reader.CAP,reader.LINE),(8*1048576,350,8*1048576,350))
        self.assertEqual((reader.row_limit(520),reader.envelope_limit(520),reader.phase.row_limit(520)),(13873,13874,13870))
        prefix=bytearray(b'x'*producer.CAP);overflow={}
        with self.assertRaises(ValueError):producer.append_observed(prefix,b'!','out',overflow)
        self.assertEqual(overflow,dict(stream='out',prefix_bytes=producer.CAP,chunk=b'!'))
        self.assertEqual(len(prefix),producer.CAP)
        self.assertEqual(producer.POLICY,dict(k=10,period_ms=10,epochs=520,phase='locked',delay_ns=0))

    def test_source_roster_and_qualification_flags_remain_explicit(self):
        builder=load('_prepared_builder_controls',HERE/'build.py')
        for name in ('output.py','phase_output.py','prepared_phase_output.py','reader_controls.py','phase_controls.py','prepared_phase_controls.py','truth.py'):
            self.assertIn('evaluation/ordinary-accuracy/'+name,builder.ACCURACY_SOURCES)
        self.assertEqual(len(builder.ACCURACY_SOURCES),len(set(builder.ACCURACY_SOURCES)))
        q=recipe.qualifications()
        self.assertEqual(q['requested_phase_status'],'UNRESOLVED')
        for name in ('matrix_complete','metric_qualified','native_state_qualified','performance_qualified','executable_retirement'):
            self.assertIs(q[name],False)


if __name__ == '__main__':
    unittest.main()
