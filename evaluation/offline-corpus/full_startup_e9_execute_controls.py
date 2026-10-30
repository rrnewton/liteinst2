#!/usr/bin/env python3
"""Inert execution-call-site controls: no process owner or ELF is invoked."""
import copy
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


def load(path, name):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


M = load(Path(__file__).with_name('full_startup_e9_execute.py'),'e9_execution_controls')
ROOT = Path(sys.argv.pop(1)).resolve() if len(sys.argv)>1 and not sys.argv[1].startswith('-') else Path.cwd()
N = load(ROOT/'evaluation/offline-router-native/n01.py','e9_execution_original_n01')
TOOLS = {name:dict(path='/tools/'+name) for name in ('python','timeout','helper')}
TOOLS['helper']['sha256'] = N.HELPER_SHA


class Invocation(unittest.TestCase):
    def args(self,phase='produce'):
        return [phase,'--source-revision','6'*40,'--root','/root','--plan','/root/ignored/prepared/plan.json',
                '--plan-sha256','1'*64,'--executor-sha256','2'*64]

    def test_phases_are_separate_and_outputs_require_actual_hashes(self):
        self.assertEqual(M.arguments(self.args()).phase,'produce')
        with self.assertRaises(ValueError):M.arguments(self.args('outputs'))
        extra=['--production-sha256','3'*64,'--n01-closed','/root/ignored/n01/closed.json','--n01-closed-sha256','4'*64]
        self.assertEqual(M.arguments(self.args('outputs')+extra).phase,'outputs')
        with self.assertRaises(ValueError):M.arguments(self.args()+extra)

    def test_unknown_and_duplicate_options_refuse(self):
        with self.assertRaises(SystemExit):M.arguments(self.args()+['--retry','2'])
        with self.assertRaises(SystemExit):M.arguments(self.args()+['--plan-sha','3'*64])
        with self.assertRaises(ValueError):M.arguments(self.args()+['--plan-sha256','3'*64])

    def test_exact_helper_bounds_and_empty_output_environment(self):
        req,cmd=M.request_command(Path('/root/ignored/case'),Path('/root/ignored/case/importer'),['/candidate','/data'],{},TOOLS)
        self.assertEqual((req['cpu_seconds'],req['wall_seconds'],req['file_bytes']),(20,30,16*M.MIB))
        self.assertEqual(req['env'],{})
        self.assertEqual(cmd['argv'],['/tools/timeout','--signal=TERM','--kill-after=10s','40s','/tools/python','-B',
            '/tools/helper','--request','/root/ignored/case/importer/request.json','--receipt','/root/ignored/case/importer/receipt.json'])
        self.assertEqual((cmd['parent_seconds'],cmd['cleanup_seconds']),(55,10))

    def test_prepared_request_is_compared_and_never_rewritten(self):
        folder=Path('/root/ignored/prepared/transport');root=Path('/root');argv=['/producer'];req,cmd=M.request_command(root,folder,argv,M.ENV,TOOLS)
        raw={str(folder/'request.json'):M.encode(req),str(folder/'command.json'):M.encode(cmd)}
        def collector(ctx,directory,actual,env,tools):
            ctx.B.write(directory/'request.json',req);ctx.B.write(directory/'command.json',cmd);return req,cmd
        inp=types.SimpleNamespace(tools=TOOLS,read=lambda path,cap:raw[str(path)],m={'collector':types.SimpleNamespace(invoke=collector)})
        with mock.patch.object(M,'write',side_effect=AssertionError('unexpected rewrite')):
            self.assertEqual(M.invoke(inp,folder,argv,M.ENV,cwd=root,prepared=True),(req,cmd))
            changed=dict(req,cpu_seconds=21);raw[str(folder/'request.json')]=M.encode(changed)
            with self.assertRaisesRegex(ValueError,'prepared request mutation'):M.invoke(inp,folder,argv,M.ENV,cwd=root,prepared=True)

    def test_production_attempts_all_eight_once_after_closed_tool_failure(self):
        commands=[dict(program=p,lane=l,phase=phase,directory='/fixed/'+p+'/'+l+'/'+phase,argv=['/producer'])
                  for p in ('checksum','rle-roundtrip') for l in ('stock','reference') for phase in ('transport','producer')]
        closed=mock.Mock(side_effect=[(1,{}),*((0,{}) for _ in range(7))])
        inp=types.SimpleNamespace(plan={'commands':commands},root=Path('/root'),tools=TOOLS,store=object(),stable=mock.Mock(),retain_command=mock.Mock(),
            m={'prepare':types.SimpleNamespace(PROGRAMS=('checksum','rle-roundtrip'),E9={'stock':None,'reference':None}),
               'custody':types.SimpleNamespace(closed=closed)})
        result={}
        with mock.patch.object(M,'invoke',return_value=({},{})) as invocation, mock.patch.object(M,'structural',return_value={'status':'PASS'}) as structural:
            M.produce(inp,result)
        self.assertEqual(invocation.call_count,8);self.assertEqual(closed.call_count,8);self.assertEqual(structural.call_count,3)
        self.assertEqual([r['status'] for r in result['commands']],['FAILED']+['PASS']*7)
        self.assertEqual([r['status'] for r in result['products']],['FAILED']+['PASS']*3)
        self.assertIs(result['structural_complete'],False)

    def test_production_signal_stops_and_preserves_unrun_remainder(self):
        commands=[dict(program='checksum',lane='stock',phase=str(i),directory='/fixed/'+str(i),argv=['/producer']) for i in range(8)]
        inp=types.SimpleNamespace(plan={'commands':commands},root=Path('/root'),tools=TOOLS,store=object(),stable=lambda:None,retain_command=lambda _:None,
            m={'prepare':types.SimpleNamespace(PROGRAMS=('checksum','rle-roundtrip'),E9={'stock':None,'reference':None}),
               'custody':types.SimpleNamespace(closed=lambda *args:(-9,{}))})
        result={}
        with mock.patch.object(M,'invoke',return_value=({},{})) as invocation:
            with self.assertRaisesRegex(ValueError,'signal termination'):M.produce(inp,result)
        self.assertEqual(invocation.call_count,1)
        self.assertEqual([r['status'] for r in result['commands']],['FAILED']+['UNRUN']*7)
        self.assertEqual(result['commands'][0]['exit'],-9)

    def test_production_preexisting_member_refuses_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);(directory/'sentinel').write_bytes(b'keep')
            inp=types.SimpleNamespace(plan={'commands':[{'directory':str(directory)}]},store=types.SimpleNamespace(members=lambda _:{'members':['command.json','receipt.json','request.json']}))
            before={p.name:p.read_bytes() for p in directory.iterdir()}
            with self.assertRaisesRegex(ValueError,'one attempt'):M.production_ready(inp)
            self.assertEqual({p.name:p.read_bytes() for p in directory.iterdir()},before)


def n01_fixture():
    programs=('checksum','rle-roundtrip');datasets=N.DATASETS;directory=Path('/root/ignored/n01');preparation=Path('/root/ignored/e9')
    native=N.planned_rows();rows=[];files={};values={};payload={}
    for p in programs:
        for d in datasets:
            data=d.encode();want=(p+':'+d).encode()
            for path in (preparation/'datasets'/d,directory/'datasets'/d):files[str(path)]=data
            for path in (preparation/p/'expected'/d,directory/p/'expected'/d):files[str(path)]=want
            for lane in ('native','liteinst','stock-algorithm','bootstrap-patched-reference'):
                rows.append(dict(program=p,dataset=d,lane=lane,status='UNRUN',attempts=0))
        for lane in N.LANES:files[str(directory/p/('run-'+lane))]=(p+lane).encode()
    for r in native:
        want=files[str(directory/r['program']/'expected'/r['dataset'])];data=files[str(directory/'datasets'/r['dataset'])]
        r.update(status='PASS',attempted=True,exit=0,actual_sha256=M.sha(want),stderr_sha256=M.sha(b''),
            expected_sha256=M.sha(want),input_sha256=M.sha(data),output_bytes=len(want),closure_complete=True,reason=None)
        payload[r['program'],r['dataset']+'-'+r['lane']]=(0,want,b'')
    ref={'path':'/root/ignored/final-profile.json','sha256':'profile'}
    summary=dict(profile='offline-router-N01-full-output-v1',invocation_count=40,pair_count=20,producer_dispatches=0,build_dispatches=0,ptrace_dispatches=0,
        final_profile=ref,qualification_complete=False,performance_eligible=False,route_coverage_complete=False,fatal=None,attempted=40,
        counts={'PASS':40,'FAILED':0,'UNRUN':0},native_correctness_complete=True)
    values.update({str(directory/'closed.json'):dict(summary_sha256='summary',invocations_sha256='invocations',pairs_sha256='pairs',performance_eligible=False,native_correctness_complete=True),
        str(directory/'summary.json'):summary,str(directory/'invocations.json'):native,str(directory/'pairs.json'):N.pairs(native),
        str(directory/'final-profile.json'):ref,ref['path']:dict(arguments={'main_joins':'/joins','main_joins_sha256':'joined'},native_sources={M.SOURCES['n01'][0]:M.SOURCES['n01'][1]})})
    plan=dict(main_joins={'directory':'/joins','sha256':'joined'},programs={p:dict(original_sha256=M.sha((p+'original').encode()),candidate_sha256=M.sha((p+'candidate').encode())) for p in programs})
    def completed(collector,view,request,command):return payload[view.reader.name,view.prefix]
    fake_n=types.SimpleNamespace(pairs=N.pairs,compare_output=N.compare_output,PrefixReader=N.PrefixReader,completed=completed)
    inp=types.SimpleNamespace(root=Path('/root'),directory=preparation,plan=plan,tools=TOOLS,readers=[],read=lambda path,*_:files[str(path)],value=lambda path,*_:values[str(path)],
        m={'n01':fake_n,'prepare':types.SimpleNamespace(PROGRAMS=programs),'collector':types.SimpleNamespace(OutputReader=lambda path:types.SimpleNamespace(name=path.name))},
        retain_command=mock.Mock(),stable=mock.Mock())
    return inp,rows,values,native,files,directory


class Join(unittest.TestCase):
    def test_all_forty_raw_cases_join_to_eighty_rows(self):
        inp,rows,_,_,_,directory=n01_fixture();baseline=M.joined_n01(inp,directory/'closed.json','closed',rows)
        self.assertEqual(len(baseline),20);self.assertEqual(len(rows),80)
        self.assertEqual(sum(r['status']=='PASS' for r in rows),40)
        self.assertEqual(sum(r['status']=='UNRUN' for r in rows),40)
        self.assertEqual(inp.retain_command.call_count,40)

    def test_wrong_original_or_candidate_copy_refuses(self):
        for lane in N.LANES:
            inp,rows,_,_,files,directory=n01_fixture();files[str(directory/'checksum'/('run-'+lane))]+=b'changed'
            with self.assertRaisesRegex(ValueError,'executable bytes'):M.joined_n01(inp,directory/'closed.json','closed',rows)

    def test_missing_case_is_not_a_smaller_population(self):
        inp,rows,_,native,_,directory=n01_fixture();native.pop()
        with self.assertRaisesRegex(ValueError,'twenty independently'):M.joined_n01(inp,directory/'closed.json','closed',rows)

    def test_changed_dataset_and_expected_bytes_refuse(self):
        for component in ('datasets','checksum/expected'):
            inp,rows,_,_,files,directory=n01_fixture();files[str(directory/component/'empty')]+=b'changed'
            with self.assertRaisesRegex(ValueError,'dataset/expected'):M.joined_n01(inp,directory/'closed.json','closed',rows)

    def test_recorded_failure_survives_incomplete_n01(self):
        inp,rows,values,native,_,directory=n01_fixture();native[0].update(status='FAILED',reason='retained signal failure')
        values[str(directory/'pairs.json')]=N.pairs(native);values[str(directory/'summary.json')]['fatal']='signal termination'
        with self.assertRaisesRegex(ValueError,'terminal population'):M.joined_n01(inp,directory/'closed.json','closed',rows)
        self.assertEqual(rows[0]['status'],'FAILED')
        self.assertEqual(rows[0]['recorded_n01_reason'],'retained signal failure')

    def test_claimed_pass_with_wrong_actual_hash_refuses(self):
        inp,rows,_,native,_,directory=n01_fixture();native[0]['actual_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'full output reconstruction'):M.joined_n01(inp,directory/'closed.json','closed',rows)


class TerminalPublication(unittest.TestCase):
    def fixture(self,directory):
        cases=[dict(program=p,dataset=d,lane=l,status='UNRUN',attempts=0) for p in N.PROGRAMS for d in N.DATASETS
               for l in ('native','liteinst','stock-algorithm','bootstrap-patched-reference')]
        return types.SimpleNamespace(directory=directory,reference={'path':'plan','sha256':'p'},
            plan={'cases':cases,'retained_history':[]},m={'prepare':types.SimpleNamespace(E9={'stock-algorithm':None,'bootstrap-patched-reference':None})},
            stable=mock.Mock(),close=mock.Mock())

    def argv(self):
        return ['produce','--source-revision','6'*40,'--root','/root','--plan','/root/ignored/p/plan.json','--plan-sha256','1'*64,'--executor-sha256','2'*64]

    def test_existing_result_directory_bytes_unchanged_on_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);M.write(directory/'production.json',b'existing');M.write(directory/'sentinel',b'keep')
            before={p.name:p.read_bytes() for p in directory.iterdir()};inp=self.fixture(directory)
            with mock.patch.object(M,'Inputs',return_value=inp),mock.patch.object(M,'produce',side_effect=AssertionError('dispatch')):
                self.assertEqual(M.main(self.argv()),1)
            self.assertEqual({p.name:p.read_bytes() for p in directory.iterdir()},before)

    def test_final_close_failure_withholds_success_and_keeps_all_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);inp=self.fixture(directory);inp.close.side_effect=ValueError('injected final close')
            def produce(inputs,result):result['structural_complete']=True
            with mock.patch.object(M,'Inputs',return_value=inp),mock.patch.object(M,'production_ready'),mock.patch.object(M,'produce',side_effect=produce):
                self.assertEqual(M.main(self.argv()),1)
            result=M.json.loads((directory/'production.json').read_bytes())
            self.assertIs(result['structural_complete'],False);self.assertEqual(len(result['cases']),80)
            self.assertIn('injected final close',result['error'])
            self.assertEqual(result['counts'],{'PASS':0,'FAILED':0,'UNRUN':80})

    def test_owned_success_closes_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);inp=self.fixture(directory)
            def close():self.assertFalse((directory/'production.json').exists())
            inp.close.side_effect=close
            def produce(inputs,result):result['structural_complete']=True
            with mock.patch.object(M,'Inputs',return_value=inp),mock.patch.object(M,'production_ready'),mock.patch.object(M,'produce',side_effect=produce):
                self.assertEqual(M.main(self.argv()),0)
            result=M.json.loads((directory/'production.json').read_bytes())
            self.assertIs(result['structural_complete'],True);self.assertIsNone(result['error'])
            self.assertEqual(result['new_e9_invocations'],0);self.assertEqual(result['joined_n01_invocations'],0)


class RetentionDiagnostics(unittest.TestCase):
    def instance(self, store):
        inputs=object.__new__(M.Inputs);inputs.store=store;inputs.members=[]
        return inputs

    def test_actual_retain_command_accepts_real_eight_file_directory_repeatedly(self):
        custody=load(ROOT/'evaluation/adjacent-b2/artifact-verifier/startup_custody.py','e9_real_retention_custody')
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp).resolve()
            for name in M.CONTROL:(directory/name).write_bytes(name.encode())
            store=custody.Store()
            try:
                inputs=self.instance(store)
                for _ in range(3):inputs.retain_command(directory)
                self.assertEqual(len(inputs.members),3)
                self.assertEqual(inputs.members[0][1]['members'],sorted(M.CONTROL))
                store.verify()
            finally:store.close()

    def test_real_retention_predicate_reports_actual_and_expected_without_accepting(self):
        actual=['command.json','request.json','unexpected']
        inputs=self.instance(types.SimpleNamespace(members=mock.Mock(return_value={'stat':[1,2,3,4,5,6],'members':actual})))
        with self.assertRaises(ValueError) as raised:inputs.retain_command(Path('/root/ignored/closed'))
        self.assertIn('actual='+repr(actual),str(raised.exception))
        self.assertIn('expected='+repr(sorted(M.CONTROL)),str(raised.exception))
        self.assertEqual(inputs.members,[])

    def test_closed_exit_is_retained_before_real_membership_refusal(self):
        commands=[dict(program=p,lane=l,phase=phase,directory='/fixed/'+p+'/'+l+'/'+phase,argv=['/producer'])
                  for p in N.PROGRAMS for l in ('stock','reference') for phase in ('transport','producer')]
        inputs=self.instance(types.SimpleNamespace(members=mock.Mock(return_value={'stat':[1,2,3,4,5,6],'members':[]})))
        inputs.plan={'commands':commands};inputs.root=Path('/root');inputs.tools=TOOLS;inputs.stable=mock.Mock()
        inputs.m={'prepare':types.SimpleNamespace(PROGRAMS=N.PROGRAMS,E9={'stock':None,'reference':None}),
                  'custody':types.SimpleNamespace(closed=mock.Mock(return_value=(0,{})))}
        result={}
        with mock.patch.object(M,'invoke',return_value=({},{})) as invoke:
            with self.assertRaisesRegex(ValueError,r'actual=\[\] expected='):M.produce(inputs,result)
        self.assertEqual(invoke.call_count,1)
        self.assertEqual(result['commands'][0]['exit'],0)
        self.assertIs(result['commands'][0]['closure_complete'],True)
        self.assertEqual(result['commands'][0]['status'],'FAILED')
        self.assertEqual([r['status'] for r in result['commands'][1:]],['UNRUN']*7)

    def test_source_revision_is_explicit_canonical_and_recorded(self):
        args=['produce','--root','/root','--plan','/root/ignored/p/plan.json','--plan-sha256','1'*64,'--executor-sha256','2'*64]
        with self.assertRaises(SystemExit):M.arguments(args)
        for value in ('a'*39,'a'*41,'A'*40,'g'*40):
            with self.subTest(value=value),self.assertRaises(SystemExit):M.arguments(args+['--source-revision',value])
        self.assertEqual(M.arguments(args+['--source-revision','a'*40]).source_revision,'a'*40)
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);fixture=TerminalPublication();inputs=fixture.fixture(directory)
            def produce(inputs,result):result['structural_complete']=True
            with mock.patch.object(M,'Inputs',return_value=inputs),mock.patch.object(M,'production_ready'),mock.patch.object(M,'produce',side_effect=produce):
                self.assertEqual(M.main(args+['--source-revision','a'*40]),0)
            result=M.json.loads((directory/'production.json').read_bytes())
            self.assertEqual(result['source_revision'],'a'*40)
            self.assertEqual(result['provenance']['source_revision'],'a'*40)

    def test_selected_revision_must_equal_the_actual_plan(self):
        inputs=object.__new__(M.Inputs);inputs.source_revision='a'*40
        inputs.plan={'profile':'actual-profile','source_revision':'b'*40}
        inputs.m={'prepare':types.SimpleNamespace(PROFILE='actual-profile'), 'adapter':None, 'corpus':None}
        with self.assertRaisesRegex(ValueError,'current full-startup source'):inputs.validate_plan()


if __name__ == '__main__':
    unittest.main()
