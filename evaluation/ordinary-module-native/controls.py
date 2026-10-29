#!/usr/bin/env python3
"""Fabricated parser/authority controls; no native subject or compiled artifact is used."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def sibling(name):
    spec = importlib.util.spec_from_file_location('module_control_'+name, HERE/(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


C = sibling('module_native')
R = sibling('reproduce')
GEOMETRY = [dict(length=126, heads=[0,10,20,89,125], edges=4, returns=[89,125]),
            dict(length=41, heads=[0,5,10,34,40], edges=4, returns=[34,40])]


def fixture(k=16, csv_index=0):
    rows = []
    for seed in C.SEEDS:
        for i,(length,value) in enumerate(zip(C.CSV_LENGTHS,C.CSV_VALUES)):
            n=i%8; other=C.LENGTH_VALUES[n]; reads=int(C.LENGTH_BOUNDS[n]!=0)
            rows.append(dict(zip(C.HEADER.split(','),(
                k,seed,i+1,n+1,length,C.LENGTH_BOUNDS[n],csv_index,1-csv_index,'PASS',2,56,
                4,4,4,4,56,57,value,other,value,other,2*(value+other),
                (89,125)[i%2],(34,40)[i%2],(89,125)[i%2],(34,40)[i%2],
                3,2,3,2,reads,reads,reads,reads,4,8,8,2,2))))
    coverage=[dict(zip(C.COVERAGE.split(','),(k,seed,16,8,4,5,3,4,2,5,4,2))) for seed in C.SEEDS]
    return rows,coverage


def encode(rows,coverage,k=16,csv_index=0):
    def table(header,rows):
        return (header+'\n'+''.join(','.join(str(r[n]) for n in header.split(','))+'\n' for r in rows)).encode('ascii')
    return [table(C.HEADER,rows),table(C.COVERAGE,coverage),
            (C.terminal(k,sum(r['comparisons'] for r in rows))+'\n').encode('ascii'),b'',k,copy.deepcopy(GEOMETRY),csv_index]


class Controls(unittest.TestCase):
    def refuses(self,rows,coverage,k=16,csv_index=0):
        with self.assertRaises(AssertionError):C.check(*encode(rows,coverage,k,csv_index))

    def test_complete_both_cohorts_and_canonical_indices(self):
        for k in (16,1):
            for index in (0,1):
                rows,coverage=fixture(k,index);args=encode(rows,coverage,k,index);got=C.check(*args)
                self.assertEqual((got['rows'],got['coverage']),(rows,coverage))
                self.assertEqual((got['pairs_table'],got['coverage_table'],got['terminal']),tuple(args[:3]))
                self.assertEqual((got['pairs'],got['children'],got['normal_reaps'],got['target_calls'],got['outer_returns']),(32,64,64,256,64))
                self.assertEqual(got['comparisons'],32*56)
                self.assertLess(coverage[0]['csv_observed_heads'],coverage[0]['csv_declared_heads'])

    def test_framing_domains_order_and_all_columns(self):
        rows,coverage=fixture();args=encode(rows,coverage)
        for index,data in ((0,args[0][:-1]),(0,args[0]+b'\n'),(0,args[0].replace(b'\n',b'\r\n')),
                           (0,args[0].replace(b'PASS',b'pass',1)),(0,b'x'*32769),(1,b'x'*1025),
                           (2,args[2]+b'\n'),(3,b'warning\n'),(0,args[0].replace(b',PASS,',b',"PASS",',1))):
            bad=args.copy();bad[index]=data
            with self.assertRaises(AssertionError):C.check(*bad)
        for key in C.HEADER.split(','):
            if key=='status':continue
            for value in ('00','+1','-1',' 1','1.0',str(1<<64),'1'*100):
                bad=encode(rows,coverage)
                text=bad[0].decode('ascii').splitlines()
                fields=text[1].split(',');fields[C.HEADER.split(',').index(key)]=value
                text[1]=','.join(fields);bad[0]=('\n'.join(text)+'\n').encode('ascii')
                with self.assertRaises(AssertionError):C.check(*bad)
        for key in C.COVERAGE.split(','):
            bad=copy.deepcopy(coverage);bad[0][key]='01';self.refuses(rows,bad)
        self.refuses(rows[:-1],coverage);self.refuses(rows+[rows[-1]],coverage)
        bad=copy.deepcopy(rows);bad[1]=copy.deepcopy(bad[0]);self.refuses(bad,coverage)
        bad=copy.deepcopy(rows);bad[0],bad[1]=bad[1],bad[0];self.refuses(bad,coverage)
        self.refuses(rows,list(reversed(coverage)));self.refuses(rows,coverage[:1])
        for index,value in ((4,True),(4,10),(6,True),(6,2)):
            bad=args.copy();bad[index]=value
            with self.assertRaises(AssertionError):C.check(*bad)

    def test_fixed_inputs_values_and_full_four_call_population(self):
        rows,coverage=fixture()
        for key in ('k','seed','case','length_case','csv_length','length_bound','csv_index','length_index',
                    'value0','value1','value2','value3','outer_value','children','target_calls',
                    'target_returns','outer_returns','normal_reaps','declared_returns'):
            bad=copy.deepcopy(rows);bad[0][key]+=1;self.refuses(bad,coverage)
        bad=copy.deepcopy(rows)
        for key in ('value0','value2','outer_value'):bad[0][key],bad[2][key]=bad[2][key],bad[0][key]
        self.assertEqual(sum(r['value0'] for r in rows),sum(r['value0'] for r in bad))
        self.refuses(bad,coverage)
        self.refuses(*fixture(1),k=16)

    def test_comparisons_steps_and_terminal_conservation(self):
        rows,coverage=fixture()
        for key,value in (('comparisons',57),('visits0',0),('visits2',5),('visits3',5),
                          ('original_steps',55),('candidate_steps',20001)):
            bad=copy.deepcopy(rows);bad[0][key]=value;self.refuses(bad,coverage)
        for r in rows:r['original_steps']=r['candidate_steps']=20000
        self.assertEqual(C.check(*encode(rows,coverage))['comparisons'],1792)
        args=encode(rows,coverage)
        for source,target in ((b'k=16',b'k=1'),(b'comparisons=1792',b'comparisons=1791'),
                              (b'target-calls=256',b'target-calls=128'),(b'normal-reaps=64',b'normal-reaps=63'),
                              (b'real-outer-ret=64',b'real-outer-ret=32'),(b'complete',b'incomplete')):
            bad=args.copy();bad[2]=bad[2].replace(source,target)
            with self.assertRaises(AssertionError):C.check(*bad)

    def test_length_reads_bytes_and_repeated_calls(self):
        rows,coverage=fixture()
        for key,value in (('length_reads1',1),('length_bytes1',1)):
            bad=copy.deepcopy(rows);bad[0][key]=value;self.refuses(bad,coverage)
        for at,reads,size in ((0,1,1),(1,0,0),(1,5,5),(1,1,0),(1,1,9)):
            bad=copy.deepcopy(rows)
            for n in (0,1):bad[at]['length_reads'+str(n)]=reads;bad[at]['length_bytes'+str(n)]=size
            self.refuses(bad,coverage)
        for n in (0,1):rows[1]['length_bytes'+str(n)]=8
        self.assertEqual(C.check(*encode(rows,coverage))['rows'][1]['length_bytes0'],8)

    def test_complete_ret_unions_and_coverage_geometry(self):
        rows,coverage=fixture()
        for key,value in (('ret_offset0',0),('ret_offset1',41),('ret_offset2',125),('ret_offset3',40),
                          ('csv_heads',5),('csv_edges',4),('length_heads',5),('length_edges',4)):
            bad=copy.deepcopy(rows);bad[0][key]=value;self.refuses(bad,coverage)
        for name in ('csv_cases','length_cases','csv_declared_heads','csv_declared_edges','csv_returns',
                     'length_heads','length_edges','length_returns'):
            bad=copy.deepcopy(coverage);bad[0][name]+=1;self.refuses(rows,bad)
        for name,value in (('csv_observed_heads',2),('csv_observed_heads',6),('csv_observed_edges',1),('csv_observed_edges',5)):
            bad=copy.deepcopy(coverage);bad[0][name]=value;self.refuses(rows,bad)
        for f,ret in ((0,89),(1,34)):
            bad=copy.deepcopy(rows)
            for r in bad[16:]:r['ret_offset'+str(f)]=r['ret_offset'+str(f+2)]=ret
            self.refuses(bad,coverage)
        args=encode(rows,coverage);args[5][0]['returns']=[89]
        with self.assertRaises(AssertionError):C.check(*args)

    def test_source_local_import_and_optimization_refusal(self):
        self.assertEqual(Path(C.__file__).resolve(),HERE/'module_native.py')
        with tempfile.TemporaryDirectory(dir=R.ROOT/'ignored',prefix='module-import-control-') as temporary:
            cwd=Path(temporary);(cwd/'module_native.py').write_text('raise RuntimeError("ambient import")\n')
            env=dict(os.environ,PYTHONPATH=str(cwd),PYTHONDONTWRITEBYTECODE='1')
            code=('import importlib.util,pathlib; p=pathlib.Path('+repr(str(HERE/'controls.py'))+'); '
                  's=importlib.util.spec_from_file_location("owned_controls",p); m=importlib.util.module_from_spec(s); '
                  's.loader.exec_module(m); assert pathlib.Path(m.C.__file__).resolve()==p.parent/"module_native.py"')
            done=subprocess.run([sys.executable,'-B','-c',code],cwd=cwd,env=env,capture_output=True,timeout=10)
            self.assertEqual((done.returncode,done.stdout,done.stderr),(0,b'',b''))
            for name in ('module_native.py','reproduce.py','controls.py'):
                done=subprocess.run([sys.executable,'-B','-O',str(HERE/name)],cwd=cwd,env=env,capture_output=True,timeout=10)
                self.assertNotEqual(done.returncode,0);self.assertEqual((done.stdout,done.stderr),(b'',b'assertions required\n'))
            self.assertFalse((cwd/'__pycache__').exists())

    def test_cargo_symbols_and_complete_helper_geometry(self):
        product=dict(reason='compiler-artifact',manifest_path=str(R.ROOT/'tools/rapid-profiler/Cargo.toml'),
            target=dict(name='frontend-native-oracle',src_path=str(R.ROOT/'tools/rapid-profiler/native-interval/main.rs'),kind=['bin'],crate_types=['bin']),
            profile=dict(opt_level='3',debuginfo=0,test=False,debug_assertions=True,overflow_checks=True),fresh=True,
            executable=str(R.ROOT/'target/release/frontend-native-oracle'))
        def messages(p):return b'\n'.join(json.dumps(x).encode() for x in (p,dict(reason='build-finished',success=True)))
        with patch.object(Path,'resolve',lambda p,**kw:p):
            self.assertEqual(R.artifact(messages(product),'frontend-native-oracle','native-interval/main.rs','bin',False)[1],product)
            for key,value in (('opt_level','0'),('debuginfo',False),('debug_assertions',False),('overflow_checks',False)):
                bad=copy.deepcopy(product);bad['profile'][key]=value
                with self.assertRaises(AssertionError):R.artifact(messages(bad),'frontend-native-oracle','native-interval/main.rs','bin',False)
        sym=b' 1: 0000000000001000 126 FUNC LOCAL DEFAULT 5 csv_fields\n'
        self.assertEqual(R.selection(sym,'csv_fields',256),(4096,126))
        for bad in (sym+sym,sym.replace(b'LOCAL',b'GLOBAL'),sym.replace(b'126',b'257'),sym.replace(b'DEFAULT 5',b'DEFAULT UND')):
            with self.assertRaises(AssertionError):R.selection(bad,'csv_fields',256)
        symbol=b' 1: 0000000000002000 123 FUNC GLOBAL DEFAULT 5 normal_module_caller\n'*2
        parts=['0000000000002000 <normal_module_caller>:']
        for begin,end in zip(R.CALLER_HEADS,R.CALLER_HEADS[1:]+(123,)):
            parts.append(f'    {8192+begin:x}:\t'+R.CALLER_BYTES[begin:end].hex(' ')+'\tnop')
        text=('\n'.join(parts)+'\n').encode()
        self.assertEqual(R.caller_geometry(text,symbol)['heads'],list(R.CALLER_HEADS))
        for data,symbols in ((text.replace(b'41 57',b'41 56',1),symbol),(text,symbol.replace(b'123',b'122')),
                             (text.replace(b'2002:',b'2003:'),symbol),(text,symbol.replace(b'GLOBAL',b'LOCAL'))):
            with self.assertRaises(AssertionError):R.caller_geometry(data,symbols)
        body=b'0000000000001000 <csv_fields>:\n    1000:\tb8 01 00 00 00\tmov eax,0x1\n    1005:\tc3\tret\n'
        self.assertEqual(R.body_geometry(R.geometry(body,'csv_fields',4096,6),4096,6),dict(length=6,heads=[0,5],edges=1,returns=[5]))
        with self.assertRaises(AssertionError):R.geometry(body,'csv_fields',4096,7)
        padded=[(4096,b'\xeb\x03','jmp 1005 <strnlen+0x5>'),(4098,b'\x0f\x1f\x00','nop DWORD PTR [rax]'),(4101,b'\xc3','ret')]
        self.assertEqual(R.body_geometry(padded,4096,6,True),dict(length=6,heads=[0,5],edges=1,returns=[5]))
        self.assertEqual(R.body_geometry(padded,4096,6)['heads'],[0,2,5])
        bad=padded.copy();bad[1]=(4098,b'\x48\x31\xc0','xor rax,rax')
        with self.assertRaises(AssertionError):R.body_geometry(bad,4096,6,True)
        with self.assertRaises(AssertionError):R.body_geometry([(4096,b'\xeb\x01','jmp 1003 <csv_fields+0x3>'),(4098,b'\xc3','ret')],4096,3)

    def test_exact_cohort_requests_and_bounds(self):
        with tempfile.TemporaryDirectory(dir=R.ROOT/'ignored',prefix='module-request-control-') as temporary:
            raw=Path(temporary)
            for k in (16,1):
                d=raw/f'k{k}';d.mkdir()
                argv=[str(R.ROOT/'target/release/frontend-native-oracle'),'normal-module-state',str(k),
                      str(raw/'module-candidate.so'),str(raw/'module-trusted.so'),'4096','126','4224','41',
                      str(raw/'caller-candidate.so'),str(raw/'caller-trusted.so'),str(d/'native-output')]
                req=dict(argv=argv,cwd=str(R.ROOT),env={},stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),
                         pins={p:{} for p in (str(HERE/'reproduce.py'),argv[0],*argv[3:5],*argv[9:11])})
                self.assertEqual(R.request_shape(req),d)
                for index,value in ((1,'normal-csv-state'),(2,'016'),(6,'257'),(8,'81'),(5,str(1<<64)),(7,'4100'),(11,str(d/'other'))):
                    bad=copy.deepcopy(req);bad['argv'][index]=value
                    with self.assertRaises(AssertionError):R.request_shape(bad)
                reverse=copy.deepcopy(req);reverse['argv'][5:9]=['4224','126','4096','41']
                self.assertEqual(R.request_shape(reverse),d)
                bad=copy.deepcopy(req);bad['pins'].pop(argv[0])
                with self.assertRaises(AssertionError):R.request_shape(bad)

    def test_original_evidence_pins_and_closure_failure(self):
        closed=dict(exit_code=0,termination=None,cleanup_complete=True,reaped_descendants=0);R.closed_ok(closed)
        for key,value in (('exit_code',1),('termination','timeout'),('cleanup_complete',False),('reaped_descendants',1)):
            with self.assertRaises(AssertionError):R.closed_ok(dict(closed,**{key:value}))
        with tempfile.TemporaryDirectory(dir=R.ROOT/'ignored',prefix='module-pins-control-') as temporary:
            root=Path(temporary);pins={}
            for name in ('plan.json','stage/request.json','stage/receipt.json','stage/stdout.txt','stage/command.json','stage/closed.json',
                         'owner/stage.log','stage/parent.log','k16/request.json','k16/native-attempt.json','k16/native-closed.json',
                         'k16/native-output/normal-module-pairs.csv','k1/native-output/normal-module-coverage.csv'):
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'original\n');R.retain(pins,p)
            original=copy.deepcopy(pins)
            def result():return dict(status='NATIVE_STATE_PASS',native=[dict(k=k,status='NATIVE_STATE_PASS',attempts=1) for k in (16,1)])
            good=result();R.final_retention(good,pins,True);self.assertTrue(good['retention_verified'])
            for name in pins:
                p=Path(name);p.write_bytes(b'changed!\n')
                with self.assertRaises(AssertionError):R.retain(pins,p)
                bad=result();R.final_retention(bad,pins,True)
                self.assertEqual(bad['status'],'FAILED');self.assertTrue(all(r['status']=='FAILED' for r in bad['native']))
                self.assertEqual((pins,bad['retained']),(original,original));p.write_bytes(b'original\n')
            bad=result()
            with patch.object(R,'digest',side_effect=RuntimeError('no possibly live reads')):R.final_retention(bad,pins,False)
            self.assertFalse(bad['retention_verified']);self.assertFalse(bad['custody_closed'])
            self.assertEqual(bad['retained'],original)

    def test_once_only_cohorts_preserve_failed_and_unrun(self):
        rows=[dict(k=k,status='UNRUN',attempts=0) for k in (16,1)];calls=[]
        def fail():calls.append(1);return dict(exit_code=1,termination=None,cleanup_complete=True,reaped_descendants=0)
        R.once(rows[0],fail)
        self.assertEqual((rows[0]['status'],rows[0]['attempts'],rows[1]['status'],rows[1]['attempts']),('FAILED',1,'UNRUN',0))
        with self.assertRaises(AssertionError):R.once(rows[0],fail)
        self.assertEqual(calls,[1])
        def interrupted():raise RuntimeError('no closure')
        with self.assertRaises(RuntimeError):R.once(rows[1],interrupted)
        self.assertEqual((rows[1]['status'],rows[1]['attempts']),('FAILED',1))

    def test_full_control_censuses_refuse_names_and_counts(self):
        modules={name:R.load(name,R.ROOT/R.MODULES[name]) for name in ('legacy','normal','whole')}
        manifest=R.calibration_manifest(modules['legacy'],modules['normal'],modules['whole'])
        self.assertEqual(len(manifest),159);self.assertTrue(set(R.MODULE_TESTS)<=set(manifest))
        self.assertEqual(len(R.MODULE_TESTS),10)
        body=''.join('test '+name+(' - should panic' if panic else '')+' ... ok\n' for name,panic in sorted(manifest.items()))
        text=(f'\nrunning 160 tests\n'+body+f'test {R.IGNORED} ... ignored, {R.IGNORE_REASON}\n\n'
              'test result: ok. 159 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\n').encode()
        R.calibration_output(text,b'',manifest)
        for old,new in ((next(iter(manifest)).encode(),b'unknown::renamed'),(b'159 passed',b'158 passed'),(b'1 ignored',b'0 ignored')):
            with self.assertRaises(AssertionError):R.calibration_output(text.replace(old,new,1),b'',manifest)
        output=''.join(f'{n} (__main__.Controls.{n}) ... ok\n' for n in sorted(R.PYTHON_CONTROLS))
        output+='\n----------------------------------------------------------------------\nRan 12 tests in 0.01s\n\nOK\n'
        R.python_output(b'',output.encode())
        for old,new in (('Ran 12','Ran 11'),(R.PYTHON_CONTROLS[0],'renamed_control')):
            with self.assertRaises(AssertionError):R.python_output(b'',output.replace(old,new).encode())


if __name__ == '__main__':
    unittest.main()
