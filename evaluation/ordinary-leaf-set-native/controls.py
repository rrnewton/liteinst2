#!/usr/bin/env python3
"""Fabricated native LeafSet transcript controls; no native or process evidence."""
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
spec = importlib.util.spec_from_file_location('owned_leaf_set_native_checker', HERE/'leaf_set_native.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
CASES = {
    1: ((0,1,5,1,2,2,2,2,5,7,9,8,4,5,24,29), (1,1,3,2,3,2,2,1,1,2,3,2,1,2,4,3)),
    2: ((0,1,1,2,17,64,64,64), (0,0,1,1,8,0,63,64)),
    3: ((0,5,1,1,10,64,64,64), (0,2,0,0,2,64,0,32)),
    4: ((0,5,1,1,10,64,64,64), (0,1,1,0,1,0,64,32)),
}
CALLER = dict(length=20, heads=[0,1,4,7,10,13,15,18,19], call_offset=13,
              continuation_offset=15, outer_ret_offset=19, subject_rsp_delta=16)
BODY_HEX = '534889cb4889f84889f74889d6ffd04889035bc3'
BODIES = [dict(operation=op, function_id=300+op, elf_va=va, length=40,
               heads=[0,5,10,20,30,39], returns=[20,39],
               edges=[[0,5],[5,10],[5,39],[10,5],[10,20],[30,39]])
          for op, va in enumerate((0x1200,0x6100,0x1100,0x6200), 1)]


def fixture(caller=None):
    caller = CALLER if caller is None else caller
    rows = []; coverage = []
    for mask in range(1, 16):
        ordered = sorted((op for op in range(1,5) if mask & (1 << (op-1))), key=lambda op: BODIES[op-1]['elf_va'])
        for k in (10, 1000):
            for seed in SEEDS:
                for op in range(1, 5):
                    if op not in ordered:
                        continue
                    start = len(rows); bounds, values = CASES[op]
                    for i, (bound, value) in enumerate(zip(bounds, values)):
                        reads = (0 if bound == 0 else min(bound, value+1)) if op == 2 else bound
                        visits = max(6, reads+4); comparisons = len(caller['heads'])+visits+1
                        reads = None if op == 1 else reads
                        values_row = (C.PROFILE,mask,len(ordered),k,ordered.index(op),300+op,seed,op,i+1,bound,
                                      'PASS',2,comparisons,visits,comparisons,comparisons+1,value,
                                      0 if i % 2 == 0 else C.U64,reads,reads,39 if i % 2 == 0 else 20,
                                      3 if i == 0 else 4,6 if op == 1 else 5,
                                      2 if i == 0 else 4,6 if op == 1 else 5,2,
                                      caller['length'],len(caller['heads']),caller['call_offset'],
                                      caller['continuation_offset'],caller['outer_ret_offset'],caller['subject_rsp_delta'],2,2,2,2)
                        assert len(values_row) == 36
                        rows.append(dict(zip(C.HEADER.split(','), values_row)))
                    coverage.append(dict(zip(C.COVERAGE.split(','), (
                        C.PROFILE,mask,len(ordered),k,ordered.index(op),300+op,seed,op,len(bounds),
                        5,6 if op == 1 else 5,5,6 if op == 1 else 5,2,2,
                        sum(r['comparisons'] for r in rows[start:])))))
    return rows, coverage


def terminal(comparisons):
    return (f'native-leaf-set-rust:profile=leaf-set-whole-rust-v1:required=1280:pairs=1280:children=2560:'
            f'comparisons={comparisons}:coverage-groups=128:subsets=15:k-values=2:seeds=2:'
            'target-calls=2560:target-returns=2560:real-outer-ret=2560:normal-reaps=2560:'
            'scope=copied-body-only:complete\n').encode('ascii')


def encode(rows, coverage, *, bodies=None, caller=None):
    def table(header, data):
        return (header+'\n'+''.join(','.join('' if r[k] is None else str(r[k])
                for k in header.split(','))+'\n' for r in data)).encode('ascii')
    return dict(pairs=table(C.HEADER,rows), coverage=table(C.COVERAGE,coverage),
                stdout=terminal(sum(r['comparisons'] for r in rows)), stderr=b'',
                bodies=copy.deepcopy(BODIES if bodies is None else bodies),
                caller=copy.deepcopy(CALLER if caller is None else caller))


def recount(rows, coverage):
    cursor = 0
    for group in coverage:
        count = len(CASES[group['function']][0])
        group['comparisons'] = sum(r['comparisons'] for r in rows[cursor:cursor+count])
        cursor += count
    assert cursor == 1280


class Controls(unittest.TestCase):
    def refuses(self, rows, coverage, **geometry):
        with self.assertRaises(AssertionError):
            C.check(**encode(rows, coverage, **geometry))

    def test_all1280_pairs_and128_coverage_groups_bind_independent_geometry(self):
        rows, coverage = fixture(); args = encode(rows, coverage); got = C.check(**args)
        self.assertEqual((len(got['rows']),len(got['coverage'])), (1280,128))
        self.assertEqual((got['rows'],got['coverage']), (rows,coverage))
        self.assertEqual(tuple(got[k] for k in ('pairs_table','coverage_table','terminal')), tuple(args[k] for k in ('pairs','coverage','stdout')))
        self.assertEqual(tuple(got[k] for k in ('children','target_calls','target_returns','outer_returns','normal_reaps')), (2560,)*5)
        self.assertEqual([sum(r['function']==op for r in rows) for op in range(1,5)], [512,256,256,256])
        self.assertEqual([sum(r['n']==n for r in rows) for n in range(1,5)], [160,480,480,160])
        self.assertEqual((got['bodies'],got['caller']), (BODIES,CALLER))
        self.assertEqual({r['k'] for r in rows}, {10,1000})
        self.assertEqual({r['seed'] for r in rows}, set(SEEDS))
        for r in rows:
            if r['subset'] == 15:
                self.assertEqual(r['selected_index'], {1:1,2:2,3:0,4:3}[r['function']])
        self.assertEqual(got['comparisons'], sum(r['comparisons'] for r in rows))
        caller = dict(CALLER, elf_va=C.U64-20, body_hex=BODY_HEX)
        self.assertEqual(C.check(**encode(rows,coverage,caller=caller))['caller'], caller)

    def test_full_catalog_order_missing_duplicate_and_coherent_subset_changes(self):
        rows, coverage = fixture()
        self.refuses(rows[:-1],coverage); self.refuses(rows+[rows[-1]],coverage)
        self.refuses(rows,coverage[:-1]); self.refuses(rows,coverage+[coverage[-1]])
        for a,b in ((0,1),(15,16),(0,32),(0,64),(640,641),(1278,1279)):
            changed=copy.deepcopy(rows); changed[a],changed[b]=changed[b],changed[a]; self.refuses(changed,coverage)
        changed=copy.deepcopy(rows); changed[1]=copy.deepcopy(changed[0]); self.refuses(changed,coverage)
        for key, value in (('subset',0),('subset',16),('n',5),('k',16),('selected_index',4),('function_id',0),('function',0),('case',0),('seed',0)):
            changed=copy.deepcopy(rows); changed[-1][key]=value; self.refuses(changed,coverage)
        changed=copy.deepcopy(rows); groups=copy.deepcopy(coverage)
        for r in changed:
            r['subset']=16-r['subset']
        for r in groups:
            r['subset']=16-r['subset']
        self.refuses(changed,groups)
        groups=copy.deepcopy(coverage); groups[0],groups[1]=groups[1],groups[0]; self.refuses(rows,groups)
        for key in ('subset','n','k','selected_index','function_id','seed','function','cases'):
            groups=copy.deepcopy(coverage); groups[-1][key]+=1; self.refuses(rows,groups)

    def test_literal_inputs_values_and_raw_outer_rax_domains(self):
        rows, coverage = fixture()
        for op in range(1,5):
            expected_bounds, expected_values = CASES[op]
            self.assertEqual(tuple(len(b) for b,v in C.cases(op)), expected_bounds)
            self.assertEqual(tuple(v for b,v in C.cases(op)), expected_values)
            at=next(i for i,r in enumerate(rows) if r['function']==op)
            for key in ('bound','result'):
                changed=copy.deepcopy(rows); changed[at][key]+=1; self.refuses(changed,coverage)
            changed=copy.deepcopy(rows)
            for r in changed:
                if r['function']==op:
                    r['result']=(r['result']+1) & C.U64
            self.refuses(changed,coverage)
        self.assertEqual(C.cases(1)[0], (b'',1))
        self.assertEqual(C.cases(3)[4][0], b'\x00\x1f !\t/09:\xff')
        for raw in (0,C.U64):
            for r in rows:
                r['outer_rax']=raw
            got=C.check(**encode(rows,coverage))
            self.assertTrue(all(r['outer_rax']==raw for r in got['rows']))
        changed=copy.deepcopy(rows); changed[0]['outer_rax']=C.U64+1; self.refuses(changed,coverage)
        changed=copy.deepcopy(rows); changed[0]['result']=C.U64; self.refuses(changed,coverage)

    def test_full_table_caller_geometry_and_complete_ret_coverage(self):
        rows, coverage = fixture()
        for key in ('caller_bytes','caller_heads','call_offset','continuation_offset','outer_ret_offset','subject_rsp_delta',
                    'declared_heads','declared_edges','declared_returns'):
            changed=copy.deepcopy(rows); changed[0][key]+=1; self.refuses(changed,coverage)
        for key,value in (('length',0),('length',257),('heads',[]),('heads',[0,True,19]),('heads',[0,[],19]),
                          ('call_offset',12),('continuation_offset',18),('outer_ret_offset',18),('subject_rsp_delta',17),
                          ('subject_rsp_delta',272),('elf_va',C.U64-19),('body_hex',BODY_HEX.upper()),('extra',1)):
            caller=copy.deepcopy(CALLER); caller[key]=value; self.refuses(rows,coverage,caller=caller)
        for index in range(4):
            for key,value in (('operation',0),('function_id',400),('length',4),('elf_va',C.U64-38),('heads',[0,0]),
                              ('returns',[]),('returns',[True]),('edges',0),('edges',[[0,0]]),('extra',1)):
                bodies=copy.deepcopy(BODIES); bodies[index][key]=value; self.refuses(rows,coverage,bodies=bodies)
        bodies=copy.deepcopy(BODIES); bodies[1]['elf_va']=bodies[0]['elf_va']; self.refuses(rows,coverage,bodies=bodies)
        bodies=copy.deepcopy(BODIES); bodies[0]['elf_va']=0x9000; self.refuses(rows,coverage,bodies=bodies)
        bodies=copy.deepcopy(BODIES); bodies[0]['elf_va'],bodies[2]['elf_va']=bodies[2]['elf_va'],bodies[0]['elf_va']
        self.refuses(rows,coverage,bodies=bodies)
        for group in (0,4,8,12,127):
            start=sum(c['cases'] for c in coverage[:group]); count=coverage[group]['cases']
            changed=copy.deepcopy(rows)
            for r in changed[start:start+count]:
                r['ret_offset']=20
            self.refuses(changed,coverage)
        changed=copy.deepcopy(rows); changed[-1]['ret_offset']=30; self.refuses(changed,coverage)
        bodies=copy.deepcopy(BODIES); bodies[2]['edges'].remove([10,20]); self.refuses(rows,coverage,bodies=bodies)
        caller=dict(length=256,heads=list(range(0,234,3))+[234,235]+[236+n for n in CALLER['heads']],
                    call_offset=249,continuation_offset=251,outer_ret_offset=255,subject_rsp_delta=16,
                    body_hex='4d89d2'*78+'5058'+BODY_HEX)
        rows,coverage=fixture(caller); self.assertEqual(C.check(**encode(rows,coverage,caller=caller))['caller'],caller)

    def test_csv_observed_union_remains_distinct_from_full_other_cfg(self):
        rows,coverage=fixture(); got=C.check(**encode(rows,coverage))
        for c in got['coverage']:
            self.assertEqual(c['observed_heads'],5)
            self.assertEqual(c['declared_heads'],6 if c['function']==1 else 5)
            self.assertEqual(c['observed_edges'],5)
            self.assertEqual(c['declared_edges'],6 if c['function']==1 else 5)
        for op in range(1,5):
            group=next(i for i,c in enumerate(coverage) if c['function']==op)
            for key,value in (('observed_heads',2),('observed_heads',7),('observed_edges',1),('observed_edges',7),
                              ('declared_heads',7),('declared_edges',7),('observed_returns',1),('declared_returns',1)):
                changed=copy.deepcopy(coverage); changed[group][key]=value; self.refuses(rows,changed)
            if op!=1:
                for key in ('observed_heads','observed_edges'):
                    changed=copy.deepcopy(coverage); changed[group][key]=4; self.refuses(rows,changed)
        for key,value in (('observed_heads',1),('observed_heads',7),('observed_edges',0),('observed_edges',7)):
            changed=copy.deepcopy(rows); changed[0][key]=value; self.refuses(changed,coverage)
        changed=copy.deepcopy(rows); groups=copy.deepcopy(coverage)
        for r in changed:
            if r['function']==1:
                r['declared_heads']=5; r['declared_edges']=5
        for c in groups:
            if c['function']==1:
                c['declared_heads']=5; c['declared_edges']=5
        self.refuses(changed,groups)

    def test_raw_absence_canonical_numbers_caps_and_all_counters(self):
        rows,coverage=fixture(); args=encode(rows,coverage)
        for key,cap in (('pairs',1048576),('coverage',65536),('stdout',1024)):
            for data in (b'',args[key][:-1],args[key]+b'\n',args[key].replace(b'\n',b'\r\n'),
                         b'\xff\n',args[key]+b'\x00',b'x'*cap+b'\n'):
                changed=args.copy(); changed[key]=data
                with self.assertRaises(AssertionError): C.check(**changed)
        for key in ('pairs','coverage'):
            for row_index in (0,1):
                changed=args.copy(); data=changed[key].splitlines(); data[row_index]+=b',extra'
                changed[key]=b'\n'.join(data)+b'\n'
                with self.assertRaises(AssertionError): C.check(**changed)
            changed=args.copy(); changed[key]=changed[key].replace(b'leaf-set-whole-rust-v1',b'leaf-set-whole-rust-v2',1)
            with self.assertRaises(AssertionError): C.check(**changed)
        changed=args.copy(); changed['pairs']=bytearray(changed['pairs'])
        with self.assertRaises(AssertionError): C.check(**changed)
        for header,key,at in ((C.HEADER,'pairs',65),(C.COVERAGE,'coverage',5)):
            for column,name in enumerate(header.split(',')):
                if name in ('profile','status'):
                    continue
                for value in ('','00','+1','-1',' 1','1.0',str(1<<64),'9'*21):
                    changed=args.copy(); data=changed[key].decode().splitlines(); fields=data[at].split(',')
                    fields[column]=value; data[at]=','.join(fields); changed[key]=('\n'.join(data)+'\n').encode()
                    with self.assertRaises(AssertionError): C.check(**changed)
        for key in ('input_reads','input_bytes'):
            changed=copy.deepcopy(rows); changed[0][key]=0; self.refuses(changed,coverage)
            at=next(i for i,r in enumerate(rows) if r['function']==2)
            changed=copy.deepcopy(rows); changed[at][key]=None; self.refuses(changed,coverage)
        for op in (2,3,4):
            at=next(i for i,r in enumerate(rows) if r['function']==op)
            for offset,reads,size in ((0,1,1),(1,0,0),(1,1,9),(1,1,0),(1,100,100)):
                changed=copy.deepcopy(rows); changed[at+offset]['input_reads']=reads; changed[at+offset]['input_bytes']=size
                self.refuses(changed,coverage)
            if op in (3,4):
                changed=copy.deepcopy(rows); changed[at+1]['input_reads']=1; changed[at+1]['input_bytes']=4
                self.refuses(changed,coverage)
        for key,value in (('visits',0),('comparisons',0),('original_steps',20001),('candidate_steps',0),
                          ('children',1),('target_calls',1),('target_returns',1),('outer_returns',1),('normal_reaps',1)):
            changed=copy.deepcopy(rows); changed[0][key]=value; groups=copy.deepcopy(coverage); recount(changed,groups)
            self.refuses(changed,groups)
        for r in rows:
            r['visits']=19990; r['comparisons']=r['original_steps']=r['candidate_steps']=20000
        recount(rows,coverage); self.assertEqual(C.check(**encode(rows,coverage))['comparisons'],25600000)
        rows[0]['candidate_steps']=20001; self.refuses(rows,coverage)

        # Exhaustive byte alphabet at the actual production lines() boundary.
        # These are parser controls, not native or process evidence.
        for value in range(256):
            data=bytes([value])+b'\n'
            if value == 10 or 32 <= value < 127:
                self.assertEqual(C.lines(data,2), ['', ''] if value == 10 else [chr(value)])
            else:
                with self.assertRaises(AssertionError): C.lines(data,2)
        self.assertEqual(C.lines(b'\n',1), [''])
        self.assertEqual(C.lines(b' ~\n',3), [' ~'])
        self.assertEqual(C.lines(b'\n \n~\n',5), ['', ' ', '~'])
        class BytesSubclass(bytes):
            pass
        for data in (None,'x\n',bytearray(b'x\n'),memoryview(b'x\n'),BytesSubclass(b'x\n'),
                     b'',b'x',b'\r\n',b'\x7f\n'):
            with self.assertRaises(AssertionError): C.lines(data,8)
        with self.assertRaises(AssertionError): C.lines(b'\n',0)
        for cap in (1024,65536,1048576):
            data=b'~'*(cap-1)+b'\n'
            self.assertEqual(C.lines(data,cap), ['~'*(cap-1)])
            with self.assertRaises(AssertionError): C.lines(data,cap-1)
            with self.assertRaises(AssertionError): C.lines(data+b'\n',cap)

    def test_partial_failed_unrun_or_unclosed_population_cannot_qualify(self):
        rows,coverage=fixture(); args=encode(rows,coverage)
        for status in ('FAILED','UNRUN','PASS '):
            changed=copy.deepcopy(rows); changed[0]['status']=status; self.refuses(changed,coverage)
        for source,target in ((b'required=1280',b'required=1279'),(b'pairs=1280',b'pairs=1279'),(b'children=2560',b'children=2559'),
                              (b'coverage-groups=128',b'coverage-groups=127'),(b'subsets=15',b'subsets=14'),(b'k-values=2',b'k-values=1'),
                              (b'seeds=2',b'seeds=1'),(b'target-calls=2560',b'target-calls=2559'),(b'target-returns=2560',b'target-returns=2559'),
                              (b'real-outer-ret=2560',b'real-outer-ret=2559'),(b'normal-reaps=2560',b'normal-reaps=2559'),
                              (b'copied-body-only',b'application'),(b':complete',b':incomplete')):
            changed=args.copy(); changed['stdout']=changed['stdout'].replace(source,target)
            self.assertNotEqual(changed['stdout'],args['stdout'])
            with self.assertRaises(AssertionError): C.check(**changed)
        changed=args.copy(); changed['stdout']=terminal(sum(r['comparisons'] for r in rows)+1)
        with self.assertRaises(AssertionError): C.check(**changed)
        for error in (b'FAILED: child\n',b'warning\n',b'\x00',''):
            changed=args.copy(); changed['stderr']=error
            with self.assertRaises(AssertionError): C.check(**changed)
        changed=copy.deepcopy(coverage); changed[-1]['comparisons']+=1; self.refuses(rows,changed)
        got=C.check(**args)
        self.assertEqual(got['status'],'LEAF_SET_WHOLE_TRANSCRIPT_VALIDATED')
        self.assertIn('process closure',got['source_attested'])
        self.assertIn('separately required',got['scope'])
        self.assertNotIn('NATIVE_PASS',got['status'])

    def test_source_local_import_and_optimization_guard(self):
        self.assertEqual(Path(C.__file__).resolve(), HERE/'leaf_set_native.py')
        with tempfile.TemporaryDirectory(dir=ROOT/'ignored',prefix='leaf-set-native-checker-control-') as temporary:
            cwd=Path(temporary); (cwd/'leaf_set_native.py').write_text('raise RuntimeError("ambient import")\n')
            env=dict(os.environ,PYTHONPATH=str(cwd),PYTHONDONTWRITEBYTECODE='1')
            code=('import importlib.util,pathlib; p=pathlib.Path('+repr(str(HERE/'controls.py'))+'); '
                  's=importlib.util.spec_from_file_location("owned_controls",p); m=importlib.util.module_from_spec(s); '
                  's.loader.exec_module(m); assert pathlib.Path(m.C.__file__).resolve()==p.parent/"leaf_set_native.py"')
            done=subprocess.run([sys.executable,'-B','-c',code],cwd=cwd,env=env,capture_output=True,timeout=10)
            self.assertEqual((done.returncode,done.stdout,done.stderr),(0,b'',b''))
            for name in ('leaf_set_native.py','controls.py'):
                done=subprocess.run([sys.executable,'-B','-O',str(HERE/name)],cwd=cwd,env=env,capture_output=True,timeout=10)
                self.assertEqual((done.stdout,done.stderr),(b'',b'assertions required\n')); self.assertNotEqual(done.returncode,0)
            self.assertFalse((cwd/'__pycache__').exists())


    def test_whole_policy_and_full_table_extent_boundaries(self):
        self.assertEqual(tuple(C.policy(op) for op in range(1,5)),
                         ('certified','whole','whole','whole'))
        for operation in range(1,5):
            maximum = 256 if operation == 1 else 80
            self.assertEqual(C.maximum_extent(operation), maximum)
            for extent in (5,maximum):
                body = dict(operation=operation,function_id=300+operation,elf_va=0x4000,
                            length=extent,heads=[0,extent-1],edges=[[0,extent-1]],returns=[extent-1])
                self.assertEqual(C.body_geometry(body,operation)['returns'], {extent-1})
            for extent in (4,maximum+1,257):
                body = dict(operation=operation,function_id=300+operation,elf_va=0x4000,
                            length=extent,heads=[0,extent-1],edges=[[0,extent-1]],returns=[extent-1])
                with self.assertRaises(AssertionError): C.body_geometry(body,operation)
        for operation in (0,5,True,'1'):
            with self.assertRaises(AssertionError): C.policy(operation)
            with self.assertRaises(AssertionError): C.maximum_extent(operation)
        rows,coverage=fixture()
        for index in (1,2,3):
            for extent in (4,81,256):
                bodies=copy.deepcopy(BODIES); bodies[index]['length']=extent
                self.refuses(rows,coverage,bodies=bodies)
        # The initial full geometry preflight checks spaces even though the
        # first subset contains CSV only; no later successful case is selected.
        bodies=copy.deepcopy(BODIES); bodies[3]['length']=81
        with self.assertRaises(AssertionError): C.geometry(bodies,CALLER)
        got=C.check(**encode(rows,coverage))
        self.assertEqual(got['policies'], ['certified','whole','whole','whole'])
        self.assertEqual([r['function'] for r in sorted(
            (r for r in rows if r['subset']==15 and r['k']==10 and r['seed']==SEEDS[0] and r['case']==1),
            key=lambda r:r['selected_index'])], [3,1,2,4])
        self.assertEqual([C.policy(op) for op in (3,1,2,4)], ['whole','certified','whole','whole'])

    def test_old_profile_and_status_cannot_be_relabelled(self):
        rows,coverage=fixture(); args=encode(rows,coverage)
        got=C.check(**args)
        self.assertEqual(got['profile'],'leaf-set-whole-rust-v1')
        self.assertEqual(got['status'],'LEAF_SET_WHOLE_TRANSCRIPT_VALIDATED')
        for old in (b'leaf-set-copied-rust-v1',b'leaf-set-whole-rust-v2'):
            changed=args.copy()
            for key in ('pairs','coverage','stdout'):
                changed[key]=changed[key].replace(b'leaf-set-whole-rust-v1',old)
                self.assertNotEqual(changed[key],args[key])
            with self.assertRaises(AssertionError): C.check(**changed)
        self.assertNotEqual(got['status'],'LEAF_SET_COPIED_TRANSCRIPT_VALIDATED')
        self.assertNotIn('NATIVE_PASS',got['status'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
