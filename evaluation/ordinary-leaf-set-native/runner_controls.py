#!/usr/bin/env python3
"""Fabricated source-level runner controls; no native process or closure evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
R=load('_whole_runner_controls',HERE/'reproduce.py')
N=load('_whole_native_helpers',ROOT/'evaluation/ordinary-module-native/reproduce.py')
O=load('_whole_old_recipe',ROOT/'evaluation/ordinary-rust-invoke-native/reproduce.py')
OLD=load('_whole_old_wire',ROOT/'evaluation/ordinary-rust-invoke-native/rust_invoke.py')
LEAF=load('_whole_leaf_wire',HERE/'leaf_set_native.py')

def request():
    raw=ROOT/'ignored/fabricated-whole-run'; cohort=raw/'leaf-native'
    argv=list(map(str,[ROOT/'target/release/frontend-native-oracle','normal-leaf-set-rust-state',
        raw/'leaf-module-candidate.so',raw/'leaf-module-trusted.so',raw/'application-candidate',raw/'application-trusted',
        cohort/'output',4096,126,4352,41,4608,40,4864,30]))
    return dict(argv=argv,cwd=str(ROOT),env={'LITEINST_EVALUATION':'1'},stdout=str(cohort/'stdout.txt'),
        stderr=str(cohort/'stderr.txt'),cpu=5,pins={str(HERE/'reproduce.py'):{},argv[0]:{},**{x:{} for x in argv[2:6]}})


def prefix(kind,count):
    checker=OLD if kind == 'legacy' else LEAF; names=checker.HEADER.split(',')
    keys=('seed','function','case') if kind == 'legacy' else ('subset','k','seed','function','case')
    result=checker.HEADER+'\n'
    for key in R.catalog(kind)[:count]:
        row={name:'0' for name in names}; row.update(profile=checker.PROFILE,status='PASS')
        row.update({name:str(value) for name,value in zip(keys,key)})
        if row['function'] == ('csv' if kind == 'legacy' else '1'): row.update(input_reads='',input_bytes='')
        result+=','.join(row[name] for name in names)+'\n'
    return result.encode('ascii')


class Controls(unittest.TestCase):
    def test_profile_catalog_preserves_old48_and_fixed_new1280(self):
        old=R.catalog('legacy'); new=R.catalog('leaf')
        self.assertEqual(old,[(seed,name,i) for seed in R.SEEDS for name,n in (('csv',16),('length',8)) for i in range(1,n+1)])
        expected=[(mask,k,seed,op,i) for mask in range(1,16) for k in (10,1000) for seed in R.SEEDS
                  for op,n in ((1,16),(2,8),(3,8),(4,8)) if mask & (1 << (op-1)) for i in range(1,n+1)]
        self.assertEqual(new,expected); self.assertEqual((len(old),len(new),len(set(new))),(48,1280,1280))
        self.assertEqual([sum(x[3] == op for x in new) for op in (1,2,3,4)],[512,256,256,256])
        self.assertEqual(len({key[:4] for key in new}),128)
        for kind,n in (('legacy',48),('leaf',1280)):
            row=R.initial_cohort(kind); self.assertEqual((row['status'],row['attempts']),('UNRUN',0))
            self.assertEqual(row['catalog'],R.catalog(kind)); self.assertEqual(row['required_pairs'],n)
            self.assertTrue(all(row[k] == n*2 for k in ('required_children','required_target_calls','required_target_returns','required_outer_returns','required_normal_reaps')))
        self.assertEqual(R.STAGES[-2:],('legacy-native-outer','leaf-native-outer'))
        self.assertEqual(len(R.STAGES),len(set(R.STAGES))); self.assertEqual(len(R.STAGES),32)
        with self.assertRaises(AssertionError): R.catalog('retry')

    def test_exact_native_calibration_union_refuses_missing_extra(self):
        peers={key:load('_whole_census_'+key,ROOT/N.MODULES[key]) for key in ('legacy','normal','whole')}
        prior=N.calibration_manifest(peers['legacy'],peers['normal'],peers['whole'])
        inventory=list(prior)+list(R.LEAF_CALIBRATIONS)+[N.IGNORED]
        got=R.calibration_inventory(prior,inventory,N.IGNORED)
        self.assertEqual(len(got),193); self.assertEqual({k:got[k] for k in prior},prior)
        self.assertTrue(all(got[k] is False for k in R.LEAF_CALIBRATIONS))
        for name in inventory:
            with self.assertRaises(AssertionError): R.calibration_inventory(prior,[n for n in inventory if n != name],N.IGNORED)
        for bad in (inventory+['unexpected::test'],inventory+[inventory[0]]):
            with self.assertRaises(AssertionError): R.calibration_inventory(prior,bad,N.IGNORED)
        bad=dict(prior);bad.pop(next(iter(bad)))
        with self.assertRaises(AssertionError): R.calibration_inventory(bad,inventory,N.IGNORED)
        self.assertEqual((len(N.PYTHON_CONTROLS),len(O.PYTHON_CONTROLS),len(O.RUNNER_CONTROLS),len(R.LEAF_CONTROLS),len(R.RUNNER_CONTROLS)),(18,10,4,10,7))
        self.assertEqual(R.SDK_CONTROL,'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_roles_and_policies_cover_all_members')

    def test_whole_request_policies_extents_coordinates_and_cpu(self):
        req=request(); cpus=[3,5,7]
        with patch.object(Path,'resolve',lambda p,strict=False:p):
            self.assertEqual(R.request_shape(req,cpus),Path(req['stdout']).parent)
            for op in range(4):
                for size in (5,256 if op == 0 else 80):
                    good=copy.deepcopy(req);good['argv'][8+op*2]=str(size);R.request_shape(good,cpus)
                for size in (4,257 if op == 0 else 81):
                    bad=copy.deepcopy(req);bad['argv'][8+op*2]=str(size)
                    with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for index,value in ((1,'normal-rust-invoke-state'),(2,'wrong'),(5,'wrong'),(6,'wrong'),(7,'+4096'),(9,'4097'),(13,'12287'),(14,'80'),(7,'18446744073709551615')):
                bad=copy.deepcopy(req);bad['argv'][index]=value
                if index == 14: bad['argv'][13]='12286' # third page after a straddling last body
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            bad=copy.deepcopy(req);bad['argv'][0]+='\0'
            with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for key,value in (('cpu',3),('cpu',True),('cwd','/'),('stdout',req['stderr'])):
                bad=copy.deepcopy(req);bad[key]=value
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for key in req['pins']:
                bad=copy.deepcopy(req);del bad['pins'][key]
                with self.assertRaises(AssertionError):R.request_shape(bad,cpus)
            for cpus_bad in ([3,5],[7,5,3],[3,3,7],[3,5,1024]):
                with self.assertRaises(AssertionError):R.request_shape(req,cpus_bad)
        self.assertEqual(R.POLICIES,('certified','whole','whole','whole'))

    def test_complete_independent_body_geometry_and_operation_order(self):
        va=4096
        rows=[(va,b'\x48\x85\xf6','test rsi,rsi'),(va+3,b'\x74\x02','je 1007 <f+7>'),
              (va+5,b'\x31\xc0','xor eax,eax'),(va+7,b'\xc3','ret')]
        bodies=[]
        for op,base in enumerate((0x4200,0x4100,0x4300,0x4000),1):
            shifted=[(pc-va+base,code,asm if not asm.startswith('je') else f'je {base+7:x} <f+7>') for pc,code,asm in rows]
            body=R.full_body_geometry(N,shifted,base,8,op); bodies.append(body)
            self.assertEqual(body['heads'],[0,3,5,7]); self.assertEqual(body['edges'],[[0,3],[3,5],[3,7],[5,7]])
            self.assertEqual((body['operation'],body['function_id'],body['returns']),(op,300+op,[7]))
        caller=dict(length=20,heads=[0,1,4,7,10,13,15,18,19],call_offset=13,continuation_offset=15,outer_ret_offset=19,subject_rsp_delta=16)
        LEAF.geometry(bodies,caller)
        self.assertEqual([x['operation'] for x in sorted(bodies,key=lambda x:x['elf_va'])],[4,2,1,3])
        for op,size in ((0,8),(5,8),(True,8),(2,81),(3,256),(4,81),(1,257)):
            with self.assertRaises(AssertionError):R.full_body_geometry(N,rows,va,size,op)
        for i in (1,2,3):
            bad=copy.deepcopy(bodies);bad[i]['length']=81
            with self.assertRaises(AssertionError):LEAF.geometry(bad,caller)
        for badrow in ((va+3,b'\xe8\x00\x00\x00\x00','call 1007 <f+7>'),(va+3,b'\x74\x02','je 1006 <f+6>')):
            bad=list(rows);bad[1]=badrow
            with self.assertRaises(AssertionError):R.full_body_geometry(N,bad,va,8,1)

    def test_prefix_retention_keeps_missing_keys_unrun_without_qualification(self):
        for kind,checker,total in (('legacy',OLD,48),('leaf',LEAF,1280)):
            data=prefix(kind,3); observed,error=R.prefix_rows(data,checker.HEADER,kind)
            self.assertEqual((len(observed),error),(3,None))
            row=R.initial_cohort(kind);row.update(status='FAILED',attempts=1,observed=observed)
            out=R.public_projection(dict(status='FAILED',revision='a'*40,cohorts=[row]))['cohorts'][0]
            self.assertEqual(len(out['outcomes']),total)
            self.assertEqual([x['status'] for x in out['outcomes'][:4]],['OBSERVED_UNQUALIFIED']*3+['UNRUN'])
            self.assertEqual(out['outcomes'][0]['values'],observed[0])
            cut=R.prefix_rows(data+b'incomplete',checker.HEADER,kind); self.assertEqual((len(cut[0]),cut[1]),(3,'TRUNCATED_TAIL'))
            lines=data.splitlines(keepends=True); changed=lines[:2]+[lines[1]]+lines[2:]
            cut=R.prefix_rows(b''.join(changed),checker.HEADER,kind);self.assertEqual((len(cut[0]),cut[1]),(1,'FIRST_INVALID_ROW'))
            self.assertEqual(R.prefix_rows(b'wrong\n',checker.HEADER,kind),([],'HEADER_OR_TRUNCATION'))
            with self.assertRaises(AssertionError):R.prefix_rows(b'x'*(65537 if kind == 'legacy' else R.MIB+1),checker.HEADER,kind)
            full=R.prefix_rows(prefix(kind,total),checker.HEADER,kind); self.assertEqual((len(full[0]),full[1]),(total,None))
        for key in ('profile','status'):
            data=prefix('leaf',1).replace((LEAF.PROFILE if key == 'profile' else 'PASS').encode(),b'other',1)
            self.assertEqual(R.prefix_rows(data,LEAF.HEADER,'leaf')[1],'FIRST_INVALID_ROW')

    def test_once_only_failure_and_closed_output_custody(self):
        row=R.initial_cohort('leaf');R.begin(row);self.assertEqual((row['status'],row['attempts']),('FAILED',1))
        with self.assertRaises(AssertionError):R.begin(row)
        log=b'wrapper failed'; closed=dict(exit_code=127,termination=None,cleanup_complete=True,reaped_descendants=0,
                                         private_log_sha256=hashlib.sha256(log).hexdigest())
        R.closed_output(closed,log) # retention only, never native acceptance
        with self.assertRaises(AssertionError):O.accept_closure(row,closed,log)
        for key,value in (('cleanup_complete',False),('reaped_descendants',-1),('reaped_descendants',True),('private_log_sha256','0'*64)):
            bad=dict(closed);bad[key]=value
            with self.assertRaises(AssertionError):R.closed_output(bad,log)
        run=SimpleNamespace(safe=False)
        recipe=SimpleNamespace(read=lambda *a: self.fail('read output before custody'))
        with self.assertRaises(AssertionError):R.capture_prefix(run,recipe,row,Path('/unused'),Path('/unused'),closed,LEAF)
        def fail_owned(*a,**kw): raise AssertionError('uncertain owner')
        run=SimpleNamespace(safe=False,raw=ROOT/'ignored/fabricated-whole-run',tools={'python':'python'},result={'stages':[]},
            command=lambda *a:None,freeze=lambda *a:None,owned=fail_owned)
        first=R.initial_cohort('legacy'); later=R.initial_cohort('leaf')
        with patch.object(R.os,'getloadavg',return_value=(0,0,0)),patch.object(R.os,'sched_getaffinity',return_value={3,5,7}):
            with self.assertRaises(AssertionError):
                R.execute_cohort(run,recipe,O,first,{'stdout':str(run.raw/'native/stdout.txt')},{'sha256':'a'*64},OLD,[],{})
        self.assertEqual((first['status'],first['attempts']),('FAILED',1));self.assertEqual((later['status'],later['attempts']),('UNRUN',0))

    def test_public_projection_keeps_final_and_external_authority_separate(self):
        rows=[R.initial_cohort(k) for k in ('legacy','leaf')]
        result=dict(status='FAILED',revision='a'*40,cohorts=rows,private_path='/private/host/user',error='Error')
        out=R.public_projection(result)
        self.assertEqual([len(x['outcomes']) for x in out['cohorts']],[48,1280])
        self.assertTrue(all(r['status'] == 'UNRUN' for c in out['cohorts'] for r in c['outcomes']))
        self.assertNotIn('/private',json.dumps(out)); self.assertEqual(out['status'],'UNQUALIFIED_PENDING_FINAL_RECEIPT')
        result.update(status='LEAF_SET_WHOLE_NATIVE_LOCAL_COMPLETE',custody_closed=True,retention_verified=True)
        out=R.public_projection(result)
        self.assertTrue(out['external_owner_required']);self.assertEqual(out['status'],'UNQUALIFIED_PENDING_FINAL_RECEIPT')
        self.assertNotIn('NATIVE_PASS',json.dumps(out)); self.assertIn('Schedule',out['scope'])
        bad=copy.deepcopy(result);bad['cohorts'][1]['catalog'].pop()
        with self.assertRaises(AssertionError):R.public_projection(bad)


    def test_efficiency_inventory_requires_all199_and_rejects_new_ignores(self):
        peers={key:load('_efficiency_census_'+key,ROOT/N.MODULES[key]) for key in ('legacy','normal','whole')}
        prior=N.calibration_manifest(peers['legacy'],peers['normal'],peers['whole'])
        inventory=list(prior)+list(R.LEAF_CALIBRATIONS)+list(R.EFFICIENCY_CALIBRATIONS)+[N.IGNORED]
        got=R.efficiency_calibration_inventory(prior,inventory,N.IGNORED)
        original=R.calibration_inventory(prior,list(prior)+list(R.LEAF_CALIBRATIONS)+[N.IGNORED],N.IGNORED)
        self.assertEqual(len(got),199)
        self.assertEqual({name:got[name] for name in original},original)
        self.assertEqual(set(got)-set(original),set(R.EFFICIENCY_CALIBRATIONS))
        self.assertTrue(all(got[name] is False for name in R.EFFICIENCY_CALIBRATIONS))
        self.assertEqual((len(R.RUNNER_CONTROLS),len(R.EFFICIENCY_RUNNER_CONTROLS)),(7,8))
        self.assertEqual(R.EFFICIENCY_RUNNER_CONTROLS[:-1],R.RUNNER_CONTROLS)
        self.assertEqual(R.EFFICIENCY_RUNNER_CONTROLS[-1],self._testMethodName)
        self.assertEqual(set(R.EFFICIENCY_SOURCES),{'tests/support/native_copied_capture.rs','tests/support/native_copied_capture/tests.rs'})
        for name in inventory:
            with self.assertRaises(AssertionError):
                R.efficiency_calibration_inventory(prior,[n for n in inventory if n != name],N.IGNORED)
            with self.assertRaises(AssertionError):
                R.efficiency_calibration_inventory(prior,inventory+[name],N.IGNORED)
        with self.assertRaises(AssertionError):
            R.efficiency_calibration_inventory(prior,inventory+['unexpected::test'],N.IGNORED)
        body=''.join('test '+name+(' - should panic' if panic else '')+' ... ok\n' for name,panic in got.items())
        output=('\nrunning 200 tests\n'+body+f'test {N.IGNORED} ... ignored, {N.IGNORE_REASON}\n\n'
                'test result: ok. 199 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\n').encode()
        N.calibration_output(output,b'',got)
        for name in R.EFFICIENCY_CALIBRATIONS:
            with self.assertRaises(AssertionError):
                R.efficiency_calibration_inventory(prior,inventory,name)
            for suffix in ('ignored','ignored, new exemption','FAILED'):
                bad=output.replace(('test '+name+' ... ok').encode(),('test '+name+' ... '+suffix).encode())
                with self.assertRaises(AssertionError): N.calibration_output(bad,b'',got)

if __name__ == '__main__':
    unittest.main()
