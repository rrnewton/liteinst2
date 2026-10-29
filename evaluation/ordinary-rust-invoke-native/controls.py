#!/usr/bin/env python3
"""Fabricated hostile-data controls for the separate copied-body checker; no native evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('owned_rust_invoke_checker', HERE/'rust_invoke.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
BODIES = [dict(length=126, heads=[0,10,20,89,125], edges=4, returns=[89,125]),
          dict(length=41, heads=[0,5,10,34,40], edges=4, returns=[34,40])]
CALLER = dict(length=20, heads=[0,1,4,7,10,13,15,18,19], call_offset=13,
              continuation_offset=15, outer_ret_offset=19, subject_rsp_delta=16)
BODY_HEX = '534889cb4889f84889f74889d6ffd04889035bc3'


def fixture(caller=None):
    caller = CALLER if caller is None else caller
    rows = []; coverage = []
    for seed in C.SEEDS:
        for f, name in enumerate(('csv', 'length')):
            bounds = C.CSV_LENGTHS if f == 0 else C.LENGTH_BOUNDS
            values = C.CSV_VALUES if f == 0 else C.LENGTH_VALUES
            comparisons = len(caller['heads'])+5
            for i, (bound, value) in enumerate(zip(bounds, values)):
                reads = None if f == 0 else int(bound != 0)
                rows.append(dict(zip(C.HEADER.split(','), (
                    C.PROFILE,seed,name,i+1,bound,'PASS',2,comparisons,4,comparisons,comparisons+1,
                    value,0 if i % 2 == 0 else C.U64,reads,reads,BODIES[f]['returns'][i%2],3,5,2,4,2,
                    caller['length'],len(caller['heads']),caller['call_offset'],caller['continuation_offset'],
                    caller['outer_ret_offset'],caller['subject_rsp_delta'],2,2,2,2))))
            coverage.append(dict(zip(C.COVERAGE.split(','), (
                C.PROFILE,seed,name,len(bounds),4 if f == 0 else 5,5,3 if f == 0 else 4,4,2,2,len(bounds)*comparisons))))
    return rows, coverage


def encode(rows, coverage, *, bodies=None, caller=None):
    def table(header, rows):
        return (header+'\n'+''.join(','.join('' if r[k] is None else str(r[k])
                for k in header.split(','))+'\n' for r in rows)).encode('ascii')
    return dict(pairs=table(C.HEADER,rows), coverage=table(C.COVERAGE,coverage),
                stdout=(C.terminal(sum(r['comparisons'] for r in rows))+'\n').encode('ascii'), stderr=b'',
                bodies=copy.deepcopy(BODIES if bodies is None else bodies),
                caller=copy.deepcopy(CALLER if caller is None else caller))


def recount(rows, coverage):
    for c, (start, stop) in zip(coverage, ((0,16),(16,24),(24,40),(40,48))):
        c['comparisons'] = sum(r['comparisons'] for r in rows[start:stop])


class Controls(unittest.TestCase):
    def refuses(self, rows, coverage, **geometry):
        with self.assertRaises(AssertionError): C.check(**encode(rows,coverage,**geometry))

    def test_complete_fixed_population_preserves_raw_tables_and_scope(self):
        rows, coverage = fixture(); args = encode(rows,coverage); got = C.check(**args)
        self.assertEqual((got['rows'],got['coverage']),(rows,coverage))
        self.assertEqual((got['pairs_table'],got['coverage_table'],got['terminal']),tuple(args[k] for k in ('pairs','coverage','stdout')))
        self.assertEqual(tuple(got[k] for k in ('pairs','children','target_calls','target_returns','outer_returns','normal_reaps')),(48,96,96,96,96,96))
        self.assertEqual(got['comparisons'],672)
        self.assertEqual(got['status'],'COPIED_RUST_INVOKE_TRANSCRIPT_VALIDATED')
        self.assertIn('application call-site ABI',got['scope']); self.assertIn('do not replay',got['source_attested'])
        self.assertEqual((got['bodies'],got['caller']),(BODIES,CALLER))
        optional=dict(CALLER,elf_va=C.U64-20,body_hex=BODY_HEX)
        self.assertEqual(C.check(**encode(rows,coverage,caller=optional))['caller'],optional)

    def test_all_framing_columns_and_unsigned_domains(self):
        rows, coverage = fixture(); args = encode(rows,coverage)
        for key in ('pairs','coverage','stdout'):
            for data in (args[key][:-1],args[key]+b'\n',args[key].replace(b'\n',b'\r\n'),b'',b'\xff\n',args[key]+b'\x00'):
                bad=args.copy();bad[key]=data
                with self.assertRaises(AssertionError): C.check(**bad)
        for key,cap in (('pairs',65536),('coverage',65536),('stdout',1024)):
            bad=args.copy();bad[key]=b'x'*cap+b'\n'
            with self.assertRaises(AssertionError): C.check(**bad)
        for key,value in (('stderr',b'warning\n'),('stderr',''),('pairs',bytearray(args['pairs']))):
            bad=args.copy();bad[key]=value
            with self.assertRaises(AssertionError): C.check(**bad)
        for header,key,row_index in ((C.HEADER,'pairs',17),(C.COVERAGE,'coverage',1)):
            for column,name in enumerate(header.split(',')):
                if name in ('profile','function','status'): continue
                for value in ('','00','+1','-1',' 1','1.0',str(1<<64),'9'*21):
                    bad=args.copy();lines=bad[key].decode().splitlines();words=lines[row_index].split(',')
                    words[column]=value;lines[row_index]=','.join(words);bad[key]=('\n'.join(lines)+'\n').encode()
                    with self.assertRaises(AssertionError): C.check(**bad)
        for key in ('pairs','coverage'):
            for source,target in ((b'copied-rust-invoke-v1',b'copied-rust-invoke-v2'),(b',csv,',b',CSV,')):
                bad=args.copy();bad[key]=bad[key].replace(source,target,1)
                with self.assertRaises(AssertionError): C.check(**bad)
        for suffix in (b',extra',b','):
            bad=args.copy();lines=bad['pairs'].splitlines();lines[1]+=suffix;bad['pairs']=b'\n'.join(lines)+b'\n'
            with self.assertRaises(AssertionError): C.check(**bad)

    def test_population_order_missing_duplicate_extra_rows(self):
        rows,coverage=fixture()
        self.refuses(rows[:-1],coverage);self.refuses(rows+[rows[-1]],coverage)
        self.refuses(rows,coverage[:-1]);self.refuses(rows,coverage+[coverage[-1]])
        for a,b in ((0,1),(15,16),(0,24),(16,40)):
            bad=copy.deepcopy(rows);bad[a],bad[b]=bad[b],bad[a];self.refuses(bad,coverage)
        bad=copy.deepcopy(rows);bad[1]=copy.deepcopy(bad[0]);self.refuses(bad,coverage)
        for at in range(4):
            bad=copy.deepcopy(coverage);bad[at]['cases']-=1;self.refuses(rows,bad)
        self.refuses(rows,list(reversed(coverage)))

    def test_selected_inputs_results_and_raw_outer_rax(self):
        rows,coverage=fixture()
        for at in (0,15,16,23,24,47):
            for key in ('seed','case','bound','result','children','target_calls','target_returns','outer_returns','normal_reaps'):
                bad=copy.deepcopy(rows);bad[at][key]+=1;self.refuses(bad,coverage)
        bad=copy.deepcopy(rows)
        bad[0]['result'],bad[2]['result']=bad[2]['result'],bad[0]['result']
        self.assertEqual(sum(r['result'] for r in bad),sum(r['result'] for r in rows));self.refuses(bad,coverage)
        for value in (0,C.U64):
            for r in rows:r['outer_rax']=value
            self.assertTrue(all(r['outer_rax']==value for r in C.check(**encode(rows,coverage))['rows']))
        bad=copy.deepcopy(rows);bad[0]['status']='FAILED';self.refuses(bad,coverage)

    def test_comparisons_steps_and_terminal_conservation(self):
        rows,coverage=fixture()
        for key,value in (('visits',0),('comparisons',13),('original_steps',13),('candidate_steps',20001)):
            bad=copy.deepcopy(rows);bad[0][key]=value;recount(bad,coverage);self.refuses(bad,coverage)
        rows,coverage=fixture()
        for r in rows:r['visits']=19990;r['comparisons']=r['original_steps']=r['candidate_steps']=20000
        recount(rows,coverage);self.assertEqual(C.check(**encode(rows,coverage))['comparisons'],960000)
        rows[0]['visits']+=1;rows[0]['comparisons']+=1;rows[0]['original_steps']+=1;rows[0]['candidate_steps']+=1
        recount(rows,coverage);self.refuses(rows,coverage)
        rows,coverage=fixture();args=encode(rows,coverage)
        for source,target in ((b'pairs=48',b'pairs=47'),(b'children=96',b'children=95'),(b'comparisons=672',b'comparisons=671'),
                              (b'coverage-seeds=2',b'coverage-seeds=1'),(b'csv-cases-per-seed=16',b'csv-cases-per-seed=15'),
                              (b'length-cases-per-seed=8',b'length-cases-per-seed=7'),(b'target-calls=96',b'target-calls=95'),
                              (b'target-returns=96',b'target-returns=95'),(b'real-outer-ret=96',b'real-outer-ret=95'),
                              (b'normal-reaps=96',b'normal-reaps=95'),(b'copied-body-only',b'application'),(b':complete',b':incomplete')):
            bad=args.copy();bad['stdout']=bad['stdout'].replace(source,target)
            with self.assertRaises(AssertionError): C.check(**bad)
        bad=copy.deepcopy(coverage);bad[0]['comparisons']+=1;self.refuses(rows,bad)

    def test_caller_parent_geometry_is_required(self):
        rows,coverage=fixture()
        for key in ('caller_bytes','caller_heads','call_offset','continuation_offset','outer_ret_offset','subject_rsp_delta'):
            bad=copy.deepcopy(rows);bad[0][key]+=1;self.refuses(bad,coverage)
        for key,value in (('length',0),('length',257),('heads',[]),('heads',[0,True,19]),('heads',[0,[],19]),
                          ('call_offset',12),('continuation_offset',18),('outer_ret_offset',18),('subject_rsp_delta',17),
                          ('subject_rsp_delta',272),('elf_va',C.U64-19),('body_hex',BODY_HEX.upper()),('extra',1)):
            caller=copy.deepcopy(CALLER);caller[key]=value;self.refuses(rows,coverage,caller=caller)
        caller=copy.deepcopy(CALLER);del caller['call_offset'];self.refuses(rows,coverage,caller=caller)
        caller=dict(length=256,heads=list(range(0,234,3))+[234,235]+[236+n for n in CALLER['heads']],
                    call_offset=249,continuation_offset=251,outer_ret_offset=255,subject_rsp_delta=16,
                    body_hex='4d89d2'*78+'5058'+BODY_HEX)
        rows,coverage=fixture(caller);self.assertEqual(C.check(**encode(rows,coverage,caller=caller))['caller'],caller)

    def test_selected_body_geometry_and_ret_union_are_required(self):
        rows,coverage=fixture()
        for at in (0,16):
            for key in ('declared_heads','declared_edges','declared_returns'):
                bad=copy.deepcopy(rows);bad[at][key]+=1;self.refuses(bad,coverage)
            bad=copy.deepcopy(rows);bad[at]['ret_offset']=0;self.refuses(bad,coverage)
        for start,stop,f in ((0,16,0),(16,24,1),(24,40,0),(40,48,1)):
            bad=copy.deepcopy(rows)
            for r in bad[start:stop]:r['ret_offset']=BODIES[f]['returns'][0]
            self.refuses(bad,coverage)
        for f in (0,1):
            for key,value in (('length',4),('heads',[0,0]),('heads',[0,'5']),('returns',[]),('returns',[True]),('edges',True)):
                bodies=copy.deepcopy(BODIES);bodies[f][key]=value;self.refuses(rows,coverage,bodies=bodies)
            bodies=copy.deepcopy(BODIES);bodies[f]['returns']=[BODIES[f]['returns'][0]];self.refuses(rows,coverage,bodies=bodies)
        for key in ('observed_returns','declared_returns'):
            bad=copy.deepcopy(coverage);bad[0][key]=1;self.refuses(rows,bad)

    def test_csv_subset_and_length_full_coverage_are_distinct(self):
        rows,coverage=fixture();self.assertLess(coverage[0]['observed_heads'],coverage[0]['declared_heads'])
        self.assertEqual(C.check(**encode(rows,coverage))['coverage'],coverage)
        for at in (0,16):
            for key,value in (('observed_heads',1),('observed_heads',5),('observed_edges',1),('observed_edges',4)):
                bad=copy.deepcopy(rows);bad[at][key]=value;self.refuses(bad,coverage)
        for at in range(4):
            for key,value in (('observed_heads',2),('observed_heads',6),('observed_edges',1),('observed_edges',5),
                              ('declared_heads',6),('declared_edges',5)):
                bad=copy.deepcopy(coverage);bad[at][key]=value;self.refuses(rows,bad)
        for at in (1,3):
            bad=copy.deepcopy(coverage);bad[at]['observed_heads']=4;self.refuses(rows,bad)
            bad=copy.deepcopy(coverage);bad[at]['observed_edges']=3;self.refuses(rows,bad)

    def test_length_read_domains_and_csv_absence_are_required(self):
        rows,coverage=fixture()
        for key in ('input_reads','input_bytes'):
            bad=copy.deepcopy(rows);bad[0][key]=0;self.refuses(bad,coverage)
            bad=copy.deepcopy(rows);bad[16][key]=None;self.refuses(bad,coverage)
        for at,reads,size in ((16,1,1),(17,0,0),(17,5,5),(17,1,0),(17,1,9)):
            bad=copy.deepcopy(rows);bad[at]['input_reads']=reads;bad[at]['input_bytes']=size;self.refuses(bad,coverage)
        rows[17]['input_bytes']=8;self.assertEqual(C.check(**encode(rows,coverage))['rows'][17]['input_bytes'],8)
        self.assertIsNone(C.check(**encode(rows,coverage))['rows'][0]['input_reads'])

    def test_source_local_import_and_optimization_refusal(self):
        self.assertEqual(Path(C.__file__).resolve(),HERE/'rust_invoke.py')
        with tempfile.TemporaryDirectory(dir=ROOT/'ignored',prefix='rust-invoke-checker-control-') as temporary:
            cwd=Path(temporary);(cwd/'rust_invoke.py').write_text('raise RuntimeError("ambient import")\n')
            env=dict(os.environ,PYTHONPATH=str(cwd),PYTHONDONTWRITEBYTECODE='1')
            code=('import importlib.util,pathlib; p=pathlib.Path('+repr(str(HERE/'controls.py'))+'); '
                  's=importlib.util.spec_from_file_location("owned_controls",p); m=importlib.util.module_from_spec(s); '
                  's.loader.exec_module(m); assert pathlib.Path(m.C.__file__).resolve()==p.parent/"rust_invoke.py"')
            done=subprocess.run([sys.executable,'-B','-c',code],cwd=cwd,env=env,capture_output=True,timeout=10)
            self.assertEqual((done.returncode,done.stdout,done.stderr),(0,b'',b''))
            for name in ('rust_invoke.py','controls.py'):
                done=subprocess.run([sys.executable,'-B','-O',str(HERE/name)],cwd=cwd,env=env,capture_output=True,timeout=10)
                self.assertEqual((done.stdout,done.stderr),(b'',b'assertions required\n'));self.assertNotEqual(done.returncode,0)
            self.assertFalse((cwd/'__pycache__').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
