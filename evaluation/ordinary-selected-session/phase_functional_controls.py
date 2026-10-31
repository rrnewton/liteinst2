#!/usr/bin/env python3
"""Pure finite phase-entrypoint controls, with injected pipes only."""
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


prior=load('_phase_prior_functional_controls',HERE/'accuracy_functional_controls.py')
producer,recipe,owner=prior.producer,prior.recipe,prior.owner
reader=load('_phase_functional_reader',HERE.parent/'ordinary-accuracy/phase_output.py')


class Controls(unittest.TestCase):
    def test_two_new_modes_have_exact_options_without_old_owner_escape(self):
        self.assertEqual(tuple(owner.EXTRAS),('accuracy-prepare','accuracy-functional'))
        self.assertEqual(tuple(owner.PHASE_EXTRAS),('phase-prepare','phase-functional'))
        for phase in owner.PHASE_EXTRAS:
            options={k:'/tmp/'+k for k in owner.COMMON+owner.extras(phase)}
            options.update(phase=phase,revision='1'*40,**{'reservation-tag':'phase-1','hardware':'fixture','epoch-phase':'random'})
            for k in options:
                if k.endswith('-sha'):options[k]='2'*64
            argv,child=owner.commands(options,'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))
            self.assertEqual(child[3:5],['--phase',phase])
            self.assertEqual(child[-2:],['--epoch-phase','random'])
            self.assertNotIn('--owner',child)
            self.assertEqual(len(argv),3+2*len(options))
            for key,value in (('epoch-phase','calibration'),('epoch-phase',''),('phase','accuracy-prepare'),
                              ('command','/bin/true'),('delay-ns','1')):
                with self.assertRaises(AssertionError):owner.commands(dict(options,**{key:value}),'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))
            with self.assertRaises(AssertionError):prior.legacy.commands(options,'/usr/bin/python3',str(prior.legacy.HERE/'owner.py'))
        for phase in owner.EXTRAS:
            with self.assertRaises(AssertionError):owner.commands(dict(prior.options(phase),**{'epoch-phase':'locked'}),'/usr/bin/python3',str(owner.HERE/'accuracy_functional_owner.py'))

    def test_delay_is_recomputed_from_fixed_full_manifest_not_free_argument(self):
        for kind in ('locked','random'):
            policy=producer.phase_policy(reader,kind)
            _,manifest=reader.truth.artifacts(producer.MASTER,'calibration',1,'late_expensive')
            self.assertIn({k:v for k,v in policy.items() if k!='epochs'},manifest['policies'])
            self.assertEqual((policy['k'],policy['period_ms'],policy['epochs']),(10,10,520))
            self.assertEqual(policy['phase'],kind)
            self.assertTrue(0<=policy['delay_ns']<10000000)
        self.assertEqual(producer.phase_policy(reader,'locked'),producer.POLICY)
        for bad in ('calibration','holdout','comparison',None,True):
            with self.assertRaises(AssertionError):producer.phase_policy(reader,bad)
        self.assertEqual(recipe.initial_row(),dict(name='calibration-trial1-late_expensive-k10-period10-e520',status='UNRUN',attempts=0,records=2048))
        self.assertEqual(recipe.initial_row('random')['records'],2048)

    def test_old_and_phase_geometry_acceptance_cannot_substitute(self):
        facts={'external':'complete actual ELF/page/caller acceptance, fixture only'}
        value=dict(kind='selected-accuracy-phase-functional-geometry-acceptance-v1',status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION',
            scope=recipe.PHASE_PROFILE,revision='1'*40,preparation_sha256='2'*64,facts=facts,
            premises={k:True for k in recipe.PREMISES},review='Fabricated external premise, not authority.',native_state='UNRUN_SEPARATE_REQUIRED')
        recipe.accept_geometry(value,facts,'2'*64,'1'*40,epoch_phase='random')
        with self.assertRaises(AssertionError):recipe.accept_geometry(value,facts,'2'*64,'1'*40)
        old=dict(value,kind='selected-accuracy-functional-geometry-acceptance-v1',scope=recipe.PROFILE)
        recipe.accept_geometry(old,facts,'2'*64,'1'*40)
        with self.assertRaises(AssertionError):recipe.accept_geometry(old,facts,'2'*64,'1'*40,epoch_phase='random')
        for premise in recipe.PREMISES:
            bad=copy.deepcopy(value);bad['premises'][premise]=False
            with self.assertRaises(AssertionError):recipe.accept_geometry(bad,facts,'2'*64,'1'*40,epoch_phase='random')

    def test_new_argv_inserts_only_phase_delay_and_keeps_full_actual_geometry(self):
        pin=dict(bytes=1,sha256='1'*64)
        run=SimpleNamespace(a=SimpleNamespace(revision='2'*40,geometry=Path('/g'),preparation=Path('/p'),preparation_sha='1'*64),
            cpus=[0,1,2],sources={},tool_pins={},retained={'/g':pin,'/p':pin})
        facts=dict(materials={k:dict(path='/m/'+k,**pin) for k in producer.MATERIALS},
            table=[dict(function_id=41,operation='exact_work_nonempty',policy='whole',elf_va=4096,extent=37,returns=[36])],
            caller=dict(extent=20,continuation=15),binary=dict(path='/bin/app',**pin),
            candidate=dict(path='/candidate',**pin),trusted=dict(path='/trusted',**pin),policy=producer.POLICY)
        old=recipe.input_plan(run,None,facts,producer)
        self.assertEqual(len(old['argv']),14)
        self.assertEqual(old['argv'][1],'normal-selected-accuracy-session')
        facts['policy']=producer.phase_policy(reader,'random')
        new=recipe.input_plan(run,None,facts,producer,epoch_phase='random')
        self.assertEqual(len(new['argv']),16)
        self.assertEqual(new['argv'][1],'normal-selected-accuracy-phase-session')
        self.assertEqual(new['argv'][8:10],['random',str(facts['policy']['delay_ns'])])
        self.assertEqual(new['argv'][2:8],old['argv'][2:8])
        self.assertEqual(new['argv'][10:],old['argv'][8:])
        self.assertEqual(new['profile'],producer.PHASE_PROFILE)
        with self.assertRaises(AssertionError):producer.arguments(new,prior.checker)
        with self.assertRaises(AssertionError):producer.phase_arguments(old,reader)
        with self.assertRaises(AssertionError):recipe.input_plan(run,None,facts,producer,epoch_phase='locked')

    def test_ready_requires_new_wire_and_actual_pid_before_input(self):
        raw=prior.ready().replace(b'selected-accuracy-session-v1',reader.VERSION.encode())
        producer.ready_row(raw,123,[0,1,2],reader)
        with self.assertRaises(AssertionError):producer.ready_row(prior.ready(),123,[0,1,2],reader)
        with self.assertRaises(AssertionError):producer.ready_row(raw,123,[0,1,2],prior.checker)
        for pid in (124,0):
            with self.assertRaises(AssertionError):producer.ready_row(raw,pid,[0,1,2],reader)

    def test_failed_phase_child_retains_bytes_and_actual_reap_with_no_metrics(self):
        class BothPipes(prior.Selector):
            def select(self,timeout):
                fd=(11,12,12,11)[min(self.turn,3)];self.turn+=1
                return [(self.mapping[fd],1)]
        child,selector=prior.Child(1),BothPipes()
        write_input=producer.write_input
        writer=mock.Mock(side_effect=lambda fd,data:len(data))
        ready=prior.ready().replace(b'selected-accuracy-session-v1',reader.VERSION.encode())
        reads={11:[ready+b'\n',b''],12:[b'failure bytes']}
        def read(fd,cap):
            if reads[fd]:return reads[fd].pop(0)
            return b''
        plan=dict(profile=producer.PHASE_PROFILE,revision='1'*40,cpus=[0,1,2],argv=['/not-executed'])
        with mock.patch.object(producer.subprocess,'Popen',return_value=child), \
             mock.patch.object(producer.selectors,'DefaultSelector',return_value=selector), \
             mock.patch.object(producer.os,'sched_setaffinity'), \
             mock.patch.object(producer.os,'sched_getaffinity',return_value={2}), \
             mock.patch.object(producer.os,'set_blocking'),mock.patch.object(producer.os,'read',side_effect=read), \
             mock.patch.object(producer,'write_input',side_effect=lambda *args:write_input(*args,writer=writer)):
            result,out,err,overflow,_=producer.phase_exchange(plan,dict(input_bytes=b'x\n'),reader)
        self.assertEqual(out,ready+b'\n')
        self.assertEqual(err,b'failure bytes')
        self.assertEqual(overflow,b'')
        self.assertEqual(result['status'],'FAILED')
        self.assertEqual((result['normal_reaps'],result['rescue'],result['child_exit']),(1,False,1))
        self.assertEqual(result['requested_phase_status'],'UNRESOLVED')
        self.assertFalse(result['metric_qualified'])
        writer.assert_called_once_with(10,bytearray(b'x\n'))
        self.assertEqual(result['sent_bytes'],2)
        self.assertEqual(len(result['writes']),1)

    def test_phase_stream_cap_retains_consumed_overflow_and_does_not_expand_old(self):
        self.assertEqual((producer.CAP,reader.CAP),(8*1048576,8*1048576))
        self.assertEqual(reader.row_limit(520),13870)
        prefix=bytearray(b'x'*producer.CAP);overflow={}
        with self.assertRaises(ValueError):producer.append_observed(prefix,b'!','out',overflow)
        self.assertEqual(overflow,dict(stream='out',prefix_bytes=producer.CAP,chunk=b'!'))
        self.assertEqual(len(prefix),producer.CAP)
        self.assertEqual(producer.POLICY,dict(k=10,period_ms=10,epochs=520,phase='locked',delay_ns=0))

    def test_complete_source_roster_contains_both_readers_and_no_authority_flags(self):
        builder=load('_phase_builder_controls',HERE/'build.py')
        for name in ('output.py','phase_output.py','reader_controls.py','phase_controls.py','truth.py'):
            self.assertIn('evaluation/ordinary-accuracy/'+name,builder.ACCURACY_SOURCES)
        self.assertEqual(len(builder.ACCURACY_SOURCES),len(set(builder.ACCURACY_SOURCES)))
        q=recipe.qualifications()
        self.assertEqual(q['requested_phase_status'],'UNRESOLVED')
        for name in ('matrix_complete','metric_qualified','native_state_qualified','performance_qualified','executable_retirement'):
            self.assertIs(q[name],False)


if __name__ == '__main__':
    unittest.main()
