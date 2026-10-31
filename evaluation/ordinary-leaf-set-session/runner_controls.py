#!/usr/bin/env python3
"""Fabricated runner controls; no process ownership, native or timing credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]

def load(name,path):
    spec=importlib.util.spec_from_file_location('_leaf_runner_control_'+name,path)
    assert spec and spec.loader
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module

runner=load('runner',HERE/'reproduce.py')
catalog=load('catalog',HERE/'catalog.py')
producer=load('producer',HERE/'produce.py')
checker=load('checker',HERE/'output.py')
recipe=load('recipe',ROOT/'evaluation/ordinary-module-session/reproduce.py')
native=load('native',ROOT/'evaluation/ordinary-module-native/reproduce.py')
single=load('single',ROOT/'tools/rapid-profiler/verify_normal_session.py')
module=load('module',ROOT/'evaluation/ordinary-module/reproduce.py')


def leaves():
    return [dict(function_id=catalog.FUNCTION_IDS[i],operation=op,policy=catalog.POLICIES[i],
                 elf_va=4096+64*i,extent=48,returns=(17,47)) for i,op in enumerate(catalog.OPERATIONS)]


def observation():
    table=tuple(leaves()[:2]);records=(b'12, 3',)
    row=dict(record_id=1,length=5,checksum=checker.fnv(records[0]),value_0=2,value_1=5)
    checked=dict(rows={'READY':[dict(pid=123)],'DONE':[dict(input_status='COMPLETE')],
                       'RESULT':[row],'IO':[dict(write_blocked=0)]},expected_exit=0,
                 totals=dict(records=1,functions=2,calls=2,sampled=2,unsampled=0,epochs=1,batches=1))
    original=dict(status='ORIGINAL_SCALAR_PASS',ready=dict(cpu=4,n=2,records=1),
        results=[[1,5,checker.fnv(records[0]),2,5]],totals=dict(records=1,calls=2,returns=2),
        table=[dict(leaf,index=i,return_count=2) for i,leaf in enumerate(table)])
    return table,records,checked,original


class Controls(unittest.TestCase):
    def refuses(self,fn):
        with self.assertRaises((AssertionError,ValueError,KeyError,UnicodeError)):fn()

    def test_fixed_catalog_and_literal_accepted_bytes(self):
        refs=catalog.references();rows=catalog.catalog()
        self.assertEqual(len(refs),24);self.assertEqual(len(rows),120)
        self.assertEqual([(r['attempt'],r['index']) for r in rows],[(a,i) for a in range(1,6) for i in range(24)])
        records=calls=0
        for row in refs:
            case=catalog.case(row['n'],row['k'],row['kind'])
            self.assertEqual(case['epochs'],520)
            wanted=() if row['kind']=='empty' else tuple(catalog.LITERALS[i%8] for i in range(row['k']+1)) if row['kind']=='budget' else (b'12, 3',b'"4 5",6')
            self.assertEqual(case['records'],wanted)
            self.assertEqual(case['data'],b''.join(p+b'\n' for p in wanted)+(b'a"b\n' if row['kind']=='syntax' else b''))
            self.assertTrue(all(len(p)<=64 for p in wanted))
            records+=len(wanted);calls+=row['n']*len(wanted)
        self.assertEqual((records,calls),(4064,10160))
        self.assertEqual(catalog.LITERALS,(b'',b'a,b',b'"1 2", 3',b'"",42,  ',b'""""',b' '*64,b','*64,b'9'*64))
        for args in ((0,10,'empty'),(5,10,'empty'),(True,10,'empty'),(1,11,'empty'),(1,10,'retry')):
            self.refuses(lambda args=args:catalog.case(*args))

    def test_reference_gate_requires_exact_source_table_and_all_results(self):
        table,records,checked,original=observation()
        runner.reference_join(original,checked,table,records,4)
        for key,value in (('status','UNRUN_SEPARATE_REQUIRED'),('results',[]),('totals',dict(records=1,calls=1,returns=2))):
            bad=copy.deepcopy(original);bad[key]=value
            self.refuses(lambda bad=bad:runner.reference_join(bad,checked,table,records,4))
        for field in ('function_id','operation','policy','elf_va','extent','returns','return_count','index'):
            bad=copy.deepcopy(original);old=bad['table'][1][field];bad['table'][1][field]=old+1 if type(old)is int else 'wrong'
            self.refuses(lambda bad=bad:runner.reference_join(bad,checked,table,records,4))
        bad=copy.deepcopy(original);bad['results'][0][-1]+=1
        self.refuses(lambda:runner.reference_join(bad,checked,table,records,4))
        self.refuses(lambda:runner.reference_join(original,checked,table,records,5))

    def test_immutable_commands_source_and_first_pins(self):
        parent=ROOT/'target/evaluation';parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='leaf-runner-control-',dir=parent) as temporary:
            run=object.__new__(recipe.Run);run.raw=Path(temporary);run.build_scratch=(run.raw/'tmp',)
            run.retained={};run.budget=recipe.EvidenceBudget();run.m={'native':native};run.env={'LC_ALL':'C'}
            directory,command=run.command('one',['/fabricated/not-executed'],30)
            first=copy.deepcopy(run.retained)
            self.assertEqual(run.command('one',['/fabricated/not-executed'],30),(directory,command))
            self.refuses(lambda:run.command('one',['/different/not-executed'],30))
            (directory/'command.json').write_bytes(b'changed\n')
            self.refuses(lambda:run.remember(directory/'command.json'))
            self.assertEqual(run.retained,first)
            self.refuses(lambda:native.pins_ok(first))
            self.refuses(lambda:run.freeze(run.raw/'tmp'/'evidence.json',{}))

    def test_complete_closure_pid_stderr_exit_and_scalar_joins(self):
        table,records,checked,_=observation();case=dict(name='fixture',n=2,k=10,data=b'12, 3\n')
        out,err=b'actual stdout',b'actual stderr'
        result=dict(normal_reaps=1,rescue=False,cleanup_error=None,child_pid=123,child_exit=0,status='PASS',
            stdout_sha256=recipe.pin(out)['sha256'],stderr_sha256=recipe.pin(err)['sha256'],sent_bytes=6,
            name='fixture',n=2,k=10,totals=checked['totals'],done=checked['rows']['DONE'][0],
            original_values=runner.result_values(checked,2),write_blocked=0)
        runner.producer_join(result,0,out,err,checked,case,recipe.pin)
        for field,value in (('normal_reaps',0),('rescue',True),('cleanup_error','error'),('child_pid',124),('child_exit',1),
                            ('status','FAILED'),('stdout_sha256','0'*64),('stderr_sha256','0'*64),('sent_bytes',5),
                            ('name','other'),('n',3),('k',1000),('totals',{}),('done',{}),('original_values',[]),('write_blocked',1)):
            bad=copy.deepcopy(result);bad[field]=value
            self.refuses(lambda bad=bad:runner.producer_join(bad,0,out,err,checked,case,recipe.pin))
        self.refuses(lambda:runner.producer_join(result,1,out,err,checked,case,recipe.pin))
        receipt=dict(exit=0,absence_proof='ECHILD',inputs_unchanged=True,wall_timeout=False,unexpected_descendants=[],
            cleanup_events=[],aborted=None,cleanup_error=None,request_sha256='a',helper_sha256='b',stdout_sha256='c',stderr_sha256='d')
        closed=dict(cleanup_complete=True,reaped_descendants=0,termination=None,exit_code=0)
        pins=[{'sha256':s} for s in 'abcd']
        self.assertEqual(recipe.bounded_join(receipt,closed,*pins),0)
        for field,value in (('cleanup_complete',False),('reaped_descendants',1),('termination','timeout'),('exit_code',1)):
            bad=dict(closed,**{field:value});self.refuses(lambda bad=bad:recipe.bounded_join(receipt,bad,*pins))
        for field,value in (('absence_proof','none'),('inputs_unchanged',False),('wall_timeout',True),('cleanup_events',[1])):
            bad=dict(receipt,**{field:value});self.refuses(lambda bad=bad:recipe.bounded_join(bad,closed,*pins))


        # The actual transition helper must retain uncertainty/reservation until
        # every independently parsed APP/producer stream identity joins.
        identified=dict(result,index=0)
        def state():
            run=object.__new__(recipe.Run);run.safe=False;run.budget=recipe.EvidenceBudget();run.budget.reserve(8192)
            return run
        def envelope(value):return json.dumps(value,sort_keys=True).encode()+b'\n'
        def confirm(run,value=identified,code=0,outer=None,outer_err=b'',app_out=out,app_err=err):
            runner.confirm_producer_custody(run,value,code,envelope(value) if outer is None else outer,
                outer_err,app_out,app_err,checked,case,0,recipe.pin)
        for field,value in (('normal_reaps',0),('normal_reaps',True),('rescue',True),('cleanup_error','error'),
                            ('child_pid',124),('child_exit',-9),('stdout_sha256','0'*64),('stderr_sha256','0'*64),
                            ('index',1),('name','other'),('n',3),('k',1000)):
            bad=dict(identified,**{field:value});run=state()
            self.refuses(lambda run=run,bad=bad:confirm(run,bad))
            self.assertFalse(run.safe);self.assertTrue(run.budget.active);self.assertEqual(run.budget.held,8192)
        for options in (dict(code=2),dict(app_out=out+b'x'),dict(app_err=err+b'x'),dict(outer_err=b'diagnostic\n'),
                        dict(outer=b'not JSON\n'),dict(outer=envelope(dict(identified,child_pid=124))),
                        dict(outer=envelope(dict(identified,extra='unjoined')))):
            run=state();self.refuses(lambda run=run,options=options:confirm(run,**options))
            self.assertFalse(run.safe);self.assertTrue(run.budget.active);self.assertEqual(run.budget.held,8192)
        run=state();confirm(run)
        self.assertTrue(run.safe);self.assertFalse(run.budget.active);self.assertEqual(run.budget.held,0)
        # A normally closed, identified functional failure may advance, but
        # it still fails the original complete PASS predicate.
        failed=dict(identified,status='FAILED',child_exit=1,error='functional failure')
        run=state();confirm(run,failed,code=1)
        self.assertTrue(run.safe);self.assertFalse(run.budget.active);self.assertEqual(run.budget.held,0)
        self.refuses(lambda:runner.producer_join(failed,1,out,err,checked,case,recipe.pin))
        run=state();run.budget.exceeded=True;self.refuses(lambda:confirm(run))
        self.assertFalse(run.safe);self.assertTrue(run.budget.active);self.assertEqual(run.budget.held,8192)

    def test_exact_control_censuses_reject_missing_extra_and_keep_t2(self):
        old=tuple(single.SESSION)+tuple(single.TRACE)+recipe.CONSUMER+tuple(module.MODULE_TESTS)+tuple(module.CSV_TESTS)+recipe.OWNER_CONTROLS+recipe.REUSE_CONTROLS
        self.assertEqual(len(old),52)
        inventory=list(old+runner.APP_CONTROLS)+['normal::session::two::tests::unrelated']
        self.assertEqual(set(runner.ordinary_inventory(inventory,recipe,single,module)),set(old+runner.APP_CONTROLS))
        for name in old+runner.APP_CONTROLS:
            self.refuses(lambda name=name:runner.ordinary_inventory([n for n in inventory if n!=name],recipe,single,module))
        for prefix in ('normal::session::tests::','normal::module::','normal::csv::','normal::leaf_set::','normal::module::session::input::leaf_set_tests::','normal::session::worker::leaf_set_tests::'):
            self.refuses(lambda prefix=prefix:runner.ordinary_inventory(inventory+[prefix+'unexpected'],recipe,single,module))
        self.assertEqual(runner.sdk_inventory(list(runner.SDK_CONTROLS)),runner.SDK_CONTROLS)
        for name in runner.SDK_CONTROLS:
            self.refuses(lambda name=name:runner.sdk_inventory([n for n in runner.SDK_CONTROLS if n!=name]))
        for prefix in {n.split('::tests::')[0] for n in runner.SDK_CONTROLS}:
            self.refuses(lambda prefix=prefix:runner.sdk_inventory(list(runner.SDK_CONTROLS)+[prefix+'::tests::extra']))

        self.assertEqual(len(runner.APP_CONTROLS[:27]), 27)
        self.assertEqual(len(runner.ordinary_inventory(inventory,recipe,single,module)),88)
        self.assertEqual(len(runner.SDK_CONTROLS),45)
        self.assertEqual(len(runner.ACCURACY_CONTROLS),11)
        self.assertEqual(len(runner.SDK_ACCURACY_CONTROLS),27)
        self.assertEqual(runner.APP_CONTROLS[16:27],runner.ACCURACY_CONTROLS)
        self.assertEqual(len(runner.PHASE_CONTROLS),9)
        self.assertEqual(runner.APP_CONTROLS[27:],runner.PHASE_CONTROLS)
        self.refuses(lambda:runner.ordinary_inventory(list(old+runner.APP_CONTROLS[:27]),recipe,single,module))
        for prefix in runner.PHASE_PREFIXES:
            self.refuses(lambda prefix=prefix:runner.ordinary_inventory(inventory+[prefix+'unregistered'],recipe,single,module))
        self.assertEqual(runner.SDK_CONTROLS[18:],runner.SDK_ACCURACY_CONTROLS)
        self.assertEqual(runner.SDK_LEGACY_PREFIXES,tuple(sorted({n.split('::tests::')[0]+'::' for n in runner.SDK_CONTROLS[:18]})))
        for name in old+runner.APP_CONTROLS:
            self.refuses(lambda name=name:runner.ordinary_inventory(inventory+[name],recipe,single,module))
        self.refuses(lambda:runner.ordinary_inventory(list(old+runner.APP_CONTROLS[:16]),recipe,single,module))
        for prefix in ('normal::leaf_set::accuracy_tests::','normal::leaf_set::selected::accuracy_tests::',
                       'normal::leaf_set::counter::tests::','normal::session::io::accuracy_tests::'):
            self.refuses(lambda prefix=prefix:runner.ordinary_inventory(inventory+[prefix+'unregistered'],recipe,single,module))
        for name in runner.SDK_CONTROLS:
            self.refuses(lambda name=name:runner.sdk_inventory(list(runner.SDK_CONTROLS)+[name]))
        self.refuses(lambda:runner.sdk_inventory(list(runner.SDK_CONTROLS[:18])))
        for prefix in ('frontend_native::always_on::normal::accuracy::tests::',
                       'frontend_native::always_on::normal::leaf_set::accuracy_tests::',
                       'frontend_native::backoff::accuracy_tests::',
                       'frontend_native::backoff::driver::schedule::accuracy_tests::'):
            self.refuses(lambda prefix=prefix:runner.sdk_inventory(list(runner.SDK_CONTROLS)+[prefix+'unregistered']))
        for name in runner.SDK_ACCURACY_CONTROLS:
            changed=[n if n!=name else name.rsplit('::',1)[0]+'::unregistered' for n in runner.SDK_CONTROLS]
            self.refuses(lambda changed=changed:runner.sdk_inventory(changed))

    def test_failures_keep_all_attempts_and_stop_uncertain_custody(self):
        _,rows=runner.initial_rows(catalog)
        def closed(row):row.update(status='FAILED' if row['index']==1 else 'PASS',attempts=1)
        runner.execute_once(rows,closed)
        self.assertTrue(all(r['attempts']==1 for r in rows));self.assertEqual(sum(r['status']=='FAILED' for r in rows),5)
        self.refuses(lambda:runner.execute_once(rows,closed))
        _,rows=runner.initial_rows(catalog)
        def uncertain(row):
            row.update(status='FAILED',attempts=1)
            raise RuntimeError('unknown APP custody')
        with self.assertRaises(RuntimeError):runner.execute_once(rows,uncertain)
        self.assertEqual(rows[0]['status'],'FAILED');self.assertTrue(all(r['status']=='UNRUN' and r['attempts']==0 for r in rows[1:]))

    def test_geometry_keeps_symbols_operation_identity_and_continuation(self):
        raw=leaves();raw[0]['elf_va'],raw[1]['elf_va']=raw[1]['elf_va'],raw[0]['elf_va']
        table=runner.selected_table(raw,2,catalog,checker)
        self.assertEqual([r['operation'] for r in table],['length','csv_fields'])
        for key,value in (('operation','unknown'),('function_id',22),('policy','whole'),('returns',(48,)),('elf_va',raw[1]['elf_va'])):
            bad=copy.deepcopy(raw);bad[0][key]=value;self.refuses(lambda bad=bad:runner.selected_table(bad,4,catalog,checker))
        symbols=b' 1: 0000000000001000 5 FUNC LOCAL DEFAULT 1 csv_fields\n'
        self.assertEqual(native.selection(symbols,'csv_fields',256),(4096,5))
        self.refuses(lambda:native.selection(symbols+symbols,'csv_fields',256))
        self.refuses(lambda:native.selection(symbols.replace(b'FUNC',b'OBJECT'),'csv_fields',256))
        dis=b'0000000000001000 <csv_fields>:\n 1000:\t90\tnop\n 1001:\t90\tnop\n 1002:\t90\tnop\n 1003:\t90\tnop\n 1004:\tc3\tret\n'
        body=native.body_geometry(native.geometry(dis,'csv_fields',4096,5),4096,5)
        self.assertEqual(body['returns'],[4]);self.assertEqual(body['heads'],list(range(5)))
        self.refuses(lambda:native.geometry(dis.replace(b' 1003:',b' 1002:'),'csv_fields',4096,5))
        shape=dict(elf_va=4096,length=5,continuation_offset=3)
        module.caller_symbols(symbols.replace(b'csv_fields',b'liteinst_csv_call_and_store').replace(b'LOCAL',b'GLOBAL').decode(),shape)
        self.refuses(lambda:module.caller_symbols(symbols.replace(b'csv_fields',b'liteinst_csv_call_and_store').replace(b'LOCAL',b'GLOBAL').decode(),dict(shape,length=6)))
        product=dict(reason='compiler-artifact',manifest_path=str(ROOT/'tools/rapid-profiler/Cargo.toml'),
            target=dict(name='rapid_profiler',src_path=str(ROOT/'tools/rapid-profiler/src/lib.rs'),kind=['lib'],crate_types=['lib']),
            profile=dict(opt_level='3',debuginfo=0,test=True,debug_assertions=True,overflow_checks=True),
            fresh=False,executable=str(ROOT/'target/release/deps/rapid_profiler-abcd'))
        def build(value):return (json.dumps(value)+'\n'+json.dumps(dict(reason='build-finished',success=True))+'\n').encode()
        self.assertEqual(runner.library_product(build(product)),(Path(product['executable']),product))
        for field,value in (('opt_level','0'),('debuginfo',1),('debug_assertions',False),('overflow_checks',False)):
            bad=copy.deepcopy(product);bad['profile'][field]=value
            self.refuses(lambda bad=bad:runner.library_product(build(bad)))
        bad=copy.deepcopy(product);bad['target']['kind']=['bin']
        self.refuses(lambda:runner.library_product(build(bad)))
        bad=copy.deepcopy(product);bad['executable']=str(ROOT/'target/debug/deps/rapid_profiler-abcd')
        self.refuses(lambda:runner.library_product(build(bad)))

    def test_aggregate_budget_and_public_projection_preserve_all_rows(self):
        budget=recipe.EvidenceBudget();budget.reserve(8192);budget.charge('a',1);budget.charge('a',1)
        self.assertEqual(budget.used,4096);budget.complete();budget.reserve(4096);budget.stopped()
        self.assertEqual(budget.used,8192);self.refuses(lambda:budget.room(recipe.EVIDENCE_LIMIT))
        budget=recipe.EvidenceBudget();budget.reserve(4096);self.refuses(lambda:budget.charge('a',8192));self.assertTrue(budget.exceeded)
        originals,installed=runner.initial_rows(catalog)
        result=dict(status='FAILED',revision='0'*40,originals=originals,installed=installed,
            planned_stages=[dict(name=n,status='UNRUN') for n in runner.PLANNED_STAGES],custody_closed=False,retention_verified=False)
        public=runner.projection(result);self.assertEqual((len(public['originals']),len(public['installed'])),(24,120))
        self.assertLess(len(recipe.canonical(public)),runner.PUBLIC_CAP)
        installed[7].update(status='FAILED',attempts=1,error='private host/path must not export',directory='/private/path')
        public=runner.projection(result);self.assertEqual(public['installed'][7]['status'],'FAILED')
        self.assertNotIn(b'/private/path',recipe.canonical(public));self.assertEqual(public['qualifications'][0]['failed'],1)
        self.assertEqual(public['native_state'],'UNRUN_SEPARATE_REQUIRED')
        for row in originals+installed:
            row.update(status='PASS',attempts=1,records=2048,calls=4096,sampled=4096,unsampled=4096,
                       epochs=520,batches=4096,child_exit=1,normal_reaps=1,function_closed=4096,exhausted_generations=520)
        self.assertLess(len(recipe.canonical(runner.projection(result))),runner.PUBLIC_CAP)
        self.assertEqual(len(runner.PLANNED_STAGES),len(set(runner.PLANNED_STAGES)))
        self.assertEqual(len([n for n in runner.PLANNED_STAGES if n.startswith('attempt-')]),120)

    def test_producer_plan_and_ready_domains(self):
        case=catalog.case(3,10,'budget');table=leaves()[:3]
        index=next(r['index'] for r in catalog.references() if (r['n'],r['k'],r['kind'])==(3,10,'budget'))
        plan=dict(index=index,n=3,k=10,kind='budget',name=case['name'],epochs=520,
            data_sha256=hashlib.sha256(case['data']).hexdigest(),cpus=[2,4,6],table=table,caller=dict(extent=32,continuation=17),
            binary='/not-executed/bin',candidate='/not-executed/candidate',trusted='/not-executed/trusted')
        plan['argv']=[plan['binary'],'normal-leaf-set-session',plan['candidate'],plan['trusted'],'10','520','3']
        for leaf in table:plan['argv'] += [str(leaf['function_id']),leaf['operation'],str(leaf['elf_va']),str(leaf['extent']),leaf['policy']]
        got,args=producer.plan_arguments(plan,catalog,checker);self.assertEqual(got,case);self.assertEqual(args['cpus'],(2,4))
        for key,value in (('epochs',3),('index',0),('name','other'),('cpus',[2,2,6]),('data_sha256','0'*64),('argv',plan['argv']+['retry'])):
            bad=dict(plan,**{key:value});self.refuses(lambda bad=bad:producer.plan_arguments(bad,catalog,checker))
        raw=b'READY,leaf-set-session-v1,10,520,10,2,64,1365,3,1,1836016641,123,123,124,2,4,8192,3,1'
        producer.ready_row(raw,123,checker)
        for bad in (raw.replace(b',123,123,',b',124,124,'),raw+b',0',raw.replace(b'leaf-set-session-v1',b'old'),b'x'*350):
            self.refuses(lambda bad=bad:producer.ready_row(bad,123,checker))


if __name__=='__main__':
    unittest.main()
