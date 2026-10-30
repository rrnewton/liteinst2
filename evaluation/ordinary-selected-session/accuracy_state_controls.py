#!/usr/bin/env python3
"""Pure routing/collector controls; all native, build and owner products are inert copies."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode=True
import copy
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).parent/filename)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


legacy=load('_accuracy_inherited_controls','sdk_state_controls.py')
sdk=legacy.sdk
owner=load('_accuracy_owner_controls','accuracy_owner.py')
P=sdk._ACCURACY
NEW='selected-leaf-set-accuracy-state-v1'


def streams(key,changes=None):
    # Prescribed change to independently fixed legacy expected bytes, never a
    # copy of the actual new checker/collector output.
    raw,out,err=legacy.streams(key)
    if changes:
        header,row=raw.decode('ascii').splitlines()
        fields=dict(zip(header.split(','),row.split(',')))
        fields.update(changes)
        raw=(header+'\n'+','.join(fields[name] for name in header.split(','))+'\n').encode('ascii')
    return raw.replace((sdk.PROFILE+',').encode(),(NEW+',').encode(),1),out.replace(sdk.PROFILE.encode(),NEW.encode(),1),err


def geometry():
    value,build,ref=legacy.geometry()
    value.update(kind='selected-sdk-accuracy-geometry-acceptance-v1',scope=NEW,
        status='INDEPENDENTLY_ACCEPTED_FOR_FIXED_COPIED_ACCURACY_STATE',
        qualification=dict(pmu_metric=False,cadence=False,performance=False),
        accuracy_policy=dict(k=[10,1000],epoch_ms=10,epochs=1,calls=4096,arm='manual-one-bank'))
    return value,build,ref


def collection(root,failures=False):
    """Inert preverified cohort copies isolate the shared full-collection path.

    Receipt/owner verification is deliberately mocked here; inherited controls
    exercise the real replay_stage/bounded_join path and its custody mutants.
    """
    args=SimpleNamespace(cohorts=root/'refs.json',cohorts_sha='a'*64)
    references=('build','build-owner','sdk-build','sdk-build-owner','sdk-controls','sdk-controls-owner','geometry')
    for name in references:
        setattr(args,name.replace('-','_'),root/(name+'.json'))
        setattr(args,(name+'-sha').replace('-','_'),'b'*64)
    run=SimpleNamespace(a=args,env={'LC_ALL':'C'},retained={},result=dict(rows=sdk.initial_rows(),status='FAILED',phase='accuracy-collect'))
    sdk._evidence(run.result,P)
    contents={'leaves.so':b'inert-unstripped','leaves-stripped.so':b'inert-stripped','ordinary-interval':b'inert-caller'}
    build=dict(products={n:legacy.recipe.pin(b) for n,b in contents.items()})
    binary=dict(products={'frontend-native-oracle':{'path':'/inert/native-oracle'}})
    geo=geometry()[0];refs=[];records={};values={};wire={}
    def raw_pin(run,unused,path,expected=None,cap=sdk.MIB):
        raw=path.read_bytes();assert len(raw)<=cap;pin=legacy.recipe.pin(raw)
        if expected is not None: assert pin==expected
        if str(path) in run.retained: assert run.retained[str(path)]==pin
        run.retained[str(path)]=pin;return raw
    def read_json(run,unused,path,digest=None,cap=sdk.MIB): return values[str(path)]
    for number,cohort in enumerate(sdk.COHORTS):
        directory=root/cohort;directory.mkdir();copies={}
        for label in ('dso_candidate','dso_trusted','app_candidate','app_trusted'):
            name=('leaves.so' if cohort.startswith('unstripped-') else 'leaves-stripped.so') if label.startswith('dso') else 'ordinary-interval'
            dest=directory/(label+('.so' if label.startswith('dso') else '.elf'));dest.write_bytes(contents[name]);copies[label]=str(dest)
        r=dict(arguments=dict(raw=str(directory),cohort=cohort),rows=[],stages=[])
        plan=dict(schema=P['schema'],profile=NEW,cohort=cohort,all_keys=sdk.keys(),keys=sdk.keys(cohort),copies=copies,plans=[],
            attempts_per_key=1,cpu_seconds=20,wall_seconds=30,pair_seconds=15,steps_per_child=20000,
            callback_state='HELD',qualification=dict(pmu_metric=False,cadence=False,performance=False))
        plan.update({n.replace('-','_'):sdk.reference(args,n) for n in references})
        for i,key in enumerate(sdk.keys(cohort)):
            name='pair-'+str(i).zfill(2);d=directory/(name+'-io');dest=d/'output';dest.mkdir(parents=True)
            raw,out,err=streams(key);(dest/sdk.OUTPUT).write_bytes(raw)
            argv=sdk._pair_argv(binary['products']['frontend-native-oracle']['path'],copies,dest,key,geo['table'],P)
            request=dict(argv=argv,cwd=str(sdk.ROOT),env=run.env,stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),cpu_seconds=20,wall_seconds=30,file_bytes=4*sdk.MIB)
            plan['plans'].append(dict(name=name,key=key,request=request,output=str(dest)));values[str(d/'request.json')]=request
            row=dict(key=key,status='PASS',attempts=1,child_exit=0,closed={'inert':True},
                observed=dict(zip(sdk.HEADER.strip().split(','),raw.splitlines()[1].decode().split(','))),output_pin=legacy.recipe.pin(raw))
            if failures and i==47 and number==0: row.update(status='FAILED',child_exit=1,error='retained child failure')
            if failures and i==47 and number==1: row=dict(key=key,status='UNRUN',attempts=0)
            r['rows'].append(row)
            if row['attempts']:
                r['stages'].append(dict(name=name,closed=row['closed']))
                wire[(str(directory),name)]=(row['child_exit'],out,err)
        ref=dict(path=str(directory/'result.json'),sha256='c'*64)
        refs.append(dict(cohort=cohort,result=ref,owner=dict(path=str(directory/'owner.json'),sha256='d'*64)))
        records[ref['path']]=r;values[str(directory/'plan.json')]=plan
    values[str(args.cohorts)]=refs
    def record(*args):
        assert args[-1] is P and args[-3]=='accuracy-cohort' and args[-2] is True
        return records[args[4]['path']]
    def replay(run,recipe,driver,result,name,argv,cap):
        assert cap==4*sdk.MIB
        return wire[(result['arguments']['raw'],name)]
    driver=SimpleNamespace(read_json=read_json,raw_pin=raw_pin)
    return run,driver,build,binary,geo,values,records,record,replay


class LegacyControls(legacy.Controls):
    """All 13 original methods and assertions are inherited unchanged."""


class AccuracyControls(unittest.TestCase):
    def test_all_192_new_rows_and_old_public_refusals(self):
        total=0
        for key in sdk.keys():
            raw,out,err=streams(key);row=sdk._pair_output(raw,out,err,key,P)
            self.assertEqual(len(row),39);self.assertEqual(row['profile'],NEW)
            total+=int(row['comparisons'])
            with self.assertRaises(AssertionError): sdk.pair_output(raw,out,err,key)
            with self.assertRaises(AssertionError): sdk._pair_output(*legacy.streams(key),key,P)
        self.assertEqual(total,27560)
        with self.assertRaises(TypeError): P['profile']='anything'
        for wrong in (dict(P),sdk.PROFILE,NEW,None,True):
            with self.assertRaises(AssertionError): sdk._expected_fields(sdk.keys()[0],wrong)

    def test_every_column_terminal_and_native_bound_remain_exact(self):
        key=sdk.keys()[8]
        for field in sdk.HEADER.strip().split(','):
            with self.subTest(field=field),self.assertRaises(AssertionError):
                sdk._pair_output(*streams(key,{field:'invalid'}),key,P)
        for field in ('original_steps','candidate_steps'):
            for value in ('0','20001','020'):
                with self.assertRaises(AssertionError): sdk._pair_output(*streams(key,{field:value}),key,P)
        raw,out,err=streams(key)
        for changed in (b'',out+b'\n',out.replace(b'normal-reaps=2',b'normal-reaps=1')):
            with self.assertRaises(AssertionError): sdk._pair_output(raw,changed,err,key,P)
        with self.assertRaises(AssertionError): sdk._pair_output(raw,out,b'diagnostic',key,P)

    def test_owner_and_cli_are_disjoint_and_legacy_stays_fixed(self):
        self.assertEqual(owner.COMMON,legacy.owner.COMMON)
        for phase in owner.SDK_EXTRAS:
            old='sdk-cohort' if phase=='accuracy-cohort' else 'sdk-collect'
            opts=legacy.options(old);opts['phase']=phase
            invocation,child=owner.commands(opts,'/tools/python',str(owner.HERE/'accuracy_owner.py'))
            self.assertEqual(child[2],str(owner.HERE/'accuracy_state.py'))
            self.assertEqual(child[3:5],['--phase',phase]);self.assertEqual(owner.environment(opts),legacy.owner.environment(opts))
            with self.assertRaises(AssertionError): legacy.owner.commands(opts,'/tools/python',str(owner.HERE/'owner.py'))
            for change in ({'phase':old},{'profile':NEW},{'cohort':'retry'},{'revision':'0'*39}):
                with self.assertRaises(AssertionError): owner.commands(dict(opts,**change),'/tools/python',invocation[2])
            with patch.object(sdk,'_load_context') as context,patch.object(sys,'argv',child[2:]),patch('sys.stderr',new=io.StringIO()):
                with self.assertRaises(SystemExit): sdk.main()
                context.assert_not_called()
        with patch.object(sdk,'_main',return_value=7) as shared:
            self.assertEqual(sdk.main(),7);shared.assert_called_once_with(sdk._LEGACY)

    def test_geometry_requires_new_review_same_whole_bodies_and_fresh_build(self):
        value,build,ref=geometry();self.assertEqual(sdk._geometry_shape(value,build,ref,P),value['table'])
        with self.assertRaises(AssertionError): sdk.geometry_shape(value,build,ref)
        with self.assertRaises(AssertionError): sdk._geometry_shape(*legacy.geometry(),P)
        for field,replacement in (('kind','selected-sdk-copied-geometry-acceptance-v1'),('scope',sdk.PROFILE),
            ('native_state','PASS'),('build_revision','f'*40),('products',{}),('sdk_build',dict(ref,sha256='f'*64))):
            with self.subTest(field=field),self.assertRaises(AssertionError): sdk._geometry_shape(dict(value,**{field:replacement}),build,ref,P)
        for section,field,replacement in (('accuracy_policy','k',[1,10,100,1000]),('accuracy_policy','arm','scheduled'),
            ('accuracy_policy','epoch_ms',1),('accuracy_policy','epochs',True),('qualification','pmu_metric',0),('qualification','pmu_metric',True),('qualification','cadence',True),
            ('qualification','performance',True),('caller_state','stack_bytes',151)):
            bad=copy.deepcopy(value);bad[section][field]=replacement
            with self.assertRaises(AssertionError): sdk._geometry_shape(bad,build,ref,P)
        for i,field,replacement in ((0,'policy','certified'),(1,'extent',54),(1,'returns',[40]),(1,'elf_va',4145)):
            bad=copy.deepcopy(value);bad['table'][i][field]=replacement
            with self.assertRaises(AssertionError): sdk._geometry_shape(bad,build,ref,P)

    def test_shared_dispatch_accepts_each_new_row_once_and_remains_held(self):
        with tempfile.TemporaryDirectory() as tmp:
            run,driver,build,binary,geo,values,records,record,replay=collection(Path(tmp))
            cohort=sdk.COHORTS[0];directory=Path(tmp)/cohort
            run.a.cohort=cohort;run.safe=True;events=[]
            run.result=dict(rows=sdk.initial_rows(cohort),stages=[],status='FAILED',phase='accuracy-cohort')
            run.budget=SimpleNamespace(complete=lambda:None);run.unchanged=lambda:None
            def bounded(name,directory,request,**kwargs):
                self.assertTrue(kwargs['app_files']);events.append(name)
                run.result['stages'].append(dict(name=name,closed={'inert':True}))
                key=run.result['rows'][int(name[5:])]['key']
                _,out,err=streams(key);return 0,out,err
            run.bounded=bounded
            sdk._execute_cohort(run,SimpleNamespace(bounded_ready=lambda *a,**k:None),driver,values[str(directory/'plan.json')],P)
            sdk._evidence(run.result,P)
            self.assertEqual(events,['pair-'+str(i).zfill(2) for i in range(48)])
            self.assertTrue(sdk.population(run.result['rows'],cohort))
            self.assertEqual(run.result['status'],'SDK_ACCURACY_COHORT_STATE_PASS')
            self.assertEqual(run.result['callback_state'],'HELD')

    def test_new_dispatch_keeps_closed_failures_and_stops_uncertain_custody(self):
        for uncertain in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                rows=sdk.initial_rows(sdk.COHORTS[0]);events=[]
                run=SimpleNamespace(a=SimpleNamespace(cohort=sdk.COHORTS[0]),safe=True,result=dict(rows=rows,status='FAILED',stages=[]))
                run.budget=SimpleNamespace(complete=lambda:events.append('complete'));run.unchanged=lambda:None
                def bounded(name,directory,request,**kwargs):
                    events.append(name);run.result['stages'].append(dict(name=name,closed={'inert':True}))
                    if uncertain: run.safe=False;raise ValueError('uncertain custody')
                    return 1,b'',b'closed failure'
                run.bounded=bounded
                plan=dict(plans=[dict(name='pair-'+str(i).zfill(2),key=r['key'],request={'stdout':str(Path(tmp)/str(i)/'stdout.txt')},output=str(Path(tmp)/str(i)/'output')) for i,r in enumerate(rows)])
                sdk._execute_cohort(run,SimpleNamespace(bounded_ready=lambda *a,**k:None),None,plan,P)
                self.assertEqual(run.result['status'],'FAILED');self.assertEqual(len(rows),48)
                self.assertEqual(sum(r['attempts'] for r in rows),1 if uncertain else 48)
                self.assertEqual(rows[0]['status'],'FAILED');self.assertEqual(rows[0]['closed'],{'inert':True})
                if uncertain: self.assertTrue(all(r['status']=='UNRUN' for r in rows[1:]))
                else: self.assertTrue(all(r['status']=='FAILED' and r['child_exit']==1 for r in rows))

    def test_full_collection_keeps_192_slots_and_held_state_for_any_failure(self):
        for failures in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                run,driver,build,binary,geo,values,records,record,replay=collection(Path(tmp),failures)
                with patch.object(sdk,'_record',side_effect=record),patch.object(sdk,'replay_stage',side_effect=replay):
                    sdk._collect(run,None,driver,None,build,binary,geo,P)
                sdk._evidence(run.result,P);rows=run.result['rows']
                self.assertEqual([r['key'] for r in rows],sdk.keys());self.assertEqual(len(rows),192)
                self.assertEqual(run.result['qualification'],dict(pmu_metric=False,cadence=False,performance=False))
                self.assertEqual(run.result['callback_state'],'HELD' if failures else 'PASS')
                self.assertEqual(run.result['status'],'FAILED' if failures else 'SDK_ACCURACY_192_STATE_PASS')
                self.assertEqual([sum(r['status']==s for r in rows) for s in ('PASS','FAILED','UNRUN')],[190,1,1] if failures else [192,0,0])

    def test_collect_rejects_missing_duplicate_retry_old_request_and_source_pin(self):
        for mutant in ('missing','duplicate','retry','old-request','source-pin'):
            with tempfile.TemporaryDirectory() as tmp:
                run,driver,build,binary,geo,values,records,record,replay=collection(Path(tmp))
                refs=values[str(run.a.cohorts)];first=refs[0];r=records[first['result']['path']]
                plan=values[str(Path(first['result']['path']).parent/'plan.json')]
                if mutant=='missing': refs.pop()
                elif mutant=='duplicate': refs[1]=refs[0]
                elif mutant=='retry': r['rows'][0]['attempts']=2
                elif mutant=='old-request': plan['plans'][0]['request']['argv'][1]=sdk.PROFILE
                else: build['products']['leaves.so']['sha256']='f'*64
                with patch.object(sdk,'_record',side_effect=record),patch.object(sdk,'replay_stage',side_effect=replay),self.assertRaises(AssertionError):
                    sdk._collect(run,None,driver,None,build,binary,geo,P)
                sdk._evidence(run.result,P)
                self.assertEqual(len(run.result['rows']),192);self.assertEqual(run.result['callback_state'],'HELD')
                self.assertEqual(run.result['status'],'FAILED')


if __name__=='__main__':
    unittest.main()
