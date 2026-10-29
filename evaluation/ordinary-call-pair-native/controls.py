#!/usr/bin/env python3
"""Fabricated complete wire controls. These never execute an application subject."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode=True
import copy
import importlib.util
from pathlib import Path
import subprocess
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_call_pair_wire_controls',HERE/'call_pair_native.py')
W=importlib.util.module_from_spec(spec); spec.loader.exec_module(W)


def geometry():
    pv,cv=4096,4352
    pcode=b'\x56\xe8'+(cv-(pv+6)).to_bytes(4,'little',signed=True)+b'\x5a\x48\xc1\xe2\x20\x48\x09\xd0\xc3'
    parent=dict(elf_va=pv,length=15,heads=[0,1,6,7,11,14],edges=5,returns=[14],call_offset=1,continuation_offset=6,child_delta=16,callee_entry=cv,body_hex=pcode.hex())
    child=dict(elf_va=cv,length=9,heads=[0,3,5,7,8],edges=5,returns=[7,8])
    caller=dict(elf_va=8192,length=11,heads=[0,1,4,6,9,10],call_offset=4,continuation_offset=6,outer_ret_offset=10,subject_rsp_delta=16,lowest_stack=8,body_hex='534889cbffd04889035bc3')
    return parent,child,caller


def fixture():
    p,c,h=geometry(); rows=[]; groups=[]
    for k,seed,case,scenario in W.catalog():
        data,value=W.RECORDS[case-1]; sampled=int(scenario!=3)
        r=dict(zip(W.HEADER.split(','),[0]*45))
        r.update(k=k,seed=seed,case=case,scenario=scenario,input_len=len(data),fields=value,packed=(len(data)<<32)|value,
            caller_extent=11,caller_heads=6,caller_call=4,caller_continuation=6,caller_ret=10,caller_delta=16,stack_bytes=168,
            parent_extent=15,parent_heads=6,parent_edges=5,parent_returns=1,parent_visits=6,parent_ret_offset=14,child_delta=16,
            child_extent=9,child_heads=4,child_edges=3,child_declared_heads=5,child_declared_edges=5,child_declared_returns=2,
            child_visits=5,child_ret_offset=7+(case%2),comparisons=18,original_steps=24,candidate_steps=80,
            parent_generation=10,child_generation=(10 if scenario==1 else 11 if scenario==2 else 0),child_sampled=sampled,
            parent_actual_children=1,parent_sampled_children=sampled,child_end_sequence=sampled,parent_end_sequence=1+sampled,
            history_actions=3 if scenario==2 else 2,journal_events=4,target_calls=4,target_returns=4,outer_returns=2,normal_reaps=2)
        rows.append(r)
    for k in (10,1000):
        for scenario in (1,2,3):
            for seed in W.SEEDS:
                groups.append(dict(k=k,scenario=scenario,seed=seed,cases=16,parent_heads=6,parent_edges=5,parent_returns=1,
                    child_heads=5,child_edges=5,child_returns=2,child_declared_heads=5,child_declared_edges=5,child_declared_returns=2))
    return rows,groups,p,c,h


def table(header,rows):
    return (header+'\n'+''.join(','.join(str(r[n]) for n in header.split(','))+'\n' for r in rows)).encode('ascii')


def encoded(f):
    rows,groups,p,c,h=f
    return table(W.HEADER,rows),table(W.COVERAGE,groups),(W.terminal(sum(r['comparisons'] for r in rows))+'\n').encode(),b''


def check(f):
    p,c,h=f[2:]; return W.check(*encoded(f),parent=p,child=c,caller=h)


class Controls(unittest.TestCase):
    def refuse(self,f):
        with self.assertRaises((AssertionError,ValueError,KeyError,IndexError,TypeError)): check(f)

    def test_complete192_pairs_and12_groups_keep_exact_original_address_scope(self):
        f=fixture(); result=check(f)
        self.assertEqual((result['status'],result['pairs'],result['children'],result['groups']),(W.STATUS,192,384,12))
        self.assertEqual(result['rows'],f[0]); self.assertEqual(result['coverage'],f[1]); self.assertEqual(result['pairs_table'],encoded(f)[0])
        self.assertIn('Numeric joins only',result['authority']); self.assertEqual(result['profile'],'normal-call-pair-original-rust-v1')
        self.assertEqual(sum(r['target_calls'] for r in f[0]),768); self.assertEqual(sum(r['normal_reaps'] for r in f[0]),384)

    def test_matrix_order_missing_duplicate_and_coherent_subset_refuse(self):
        for index in (0,1,95,191):
            f=fixture(); f[0].pop(index); self.refuse(f)
        for mutate in (lambda rows:rows.append(dict(rows[-1])),lambda rows:rows.__setitem__(1,dict(rows[0])),lambda rows:rows.reverse()):
            f=fixture(); mutate(f[0]); self.refuse(f)
        f=fixture()
        for r in f[0]: r['k']=10
        for r in f[1]: r['k']=10
        self.refuse(f)
        f=fixture(); f[1][0],f[1][1]=f[1][1],f[1][0]; self.refuse(f)

    def test_literal_csv_inputs_fields_and_packed_results(self):
        self.assertEqual([len(x) for x,_ in W.RECORDS],[0,1,5,1,2,2,2,2,5,7,9,8,4,5,24,29])
        self.assertEqual([n for _,n in W.RECORDS],[1,1,3,2,3,2,2,1,1,2,3,2,1,2,4,3])
        for case in range(16):
            for key in ('input_len','fields','packed'):
                f=fixture(); f[0][case*3][key]+=1; self.refuse(f)
        f=fixture();f[0][0].update(input_len=1,packed=(1<<32)|1);self.refuse(f)

    def test_independent_complete_caller_parent_child_geometry(self):
        for part,key,value in [(2,'length',81),(2,'edges',4),(2,'returns',[7,14]),(2,'callee_entry',4353),(2,'call_offset',0),(3,'length',257),(3,'heads',[0,3,3,7,8]),(3,'returns',[9]),(4,'outer_ret_offset',9),(4,'heads',[0,4,6,9,10]),(4,'subject_rsp_delta',17)]:
            f=fixture();f[part][key]=value;self.refuse(f)
        f=fixture();f[2]['body_hex']=f[2]['body_hex'].replace('e8','e9',1);self.refuse(f)
        f=fixture();f[4]['body_hex']=f[4]['body_hex'][:-2]+'c2';self.refuse(f)
        f=fixture();f[3]['elf_va']=4097;self.refuse(f)
        f=fixture();f[3]['elf_va']=12287;f[2]['callee_entry']=12287;self.refuse(f)

    def test_nested_stack_historical_excursion_and_child_delta(self):
        for d in (16,32,48,64):
            f=fixture();f[2]['child_delta']=d
            for r in f[0]:r.update(child_delta=d,stack_bytes=16+d+136)
            check(f)
        f=fixture();f[4]['lowest_stack']=256
        for r in f[0]:r['stack_bytes']=264
        check(f);f[0][0]['stack_bytes']=168;self.refuse(f)
        for d in (0,8,65,80):
            f=fixture();f[2]['child_delta']=d;self.refuse(f)
        for low in (7,257,True):
            f=fixture();f[4]['lowest_stack']=low;self.refuse(f)
        f=fixture();f[4]['subject_rsp_delta']=256;f[4]['lowest_stack']=248;f[2]['child_delta']=64
        for r in f[0]:r.update(caller_delta=256,child_delta=64,stack_bytes=456)
        check(f);f[0][0]['stack_bytes']=457;self.refuse(f)

    def test_scenarios_generations_lifo_sequences_and_history(self):
        for i in (0,1,2):
            for key in ('child_sampled','parent_actual_children','parent_sampled_children','child_end_sequence','parent_end_sequence','history_actions','journal_events'):
                f=fixture();f[0][i][key]+=1;self.refuse(f)
        for i,value in ((0,11),(1,10),(1,0),(2,10)):
            f=fixture();f[0][i]['child_generation']=value;self.refuse(f)
        f=fixture();f[0][0]['parent_generation']=0;self.refuse(f)
        f=fixture();f[0][1].update(child_sampled=0,parent_sampled_children=0,child_generation=0,child_end_sequence=0,parent_end_sequence=1);self.refuse(f)

    def test_every_raw_counter_and_step_bound(self):
        exempt={'parent_generation','child_generation','original_steps','candidate_steps','child_visits','child_heads','child_edges','child_ret_offset'}
        for name in W.HEADER.split(','):
            if name in exempt: continue
            f=fixture();f[0][0][name]+=1;self.refuse(f)
        for field in ('original_steps','candidate_steps'):
            for value in (0,17,20001):
                f=fixture();f[0][0][field]=value;self.refuse(f)
            f=fixture();f[0][0][field]=20000;check(f)
        for field,value in [('child_visits',0),('child_heads',1),('child_heads',6),('child_edges',1),('child_edges',6),('child_ret_offset',6)]:
            f=fixture();f[0][0][field]=value;self.refuse(f)
        f=fixture();f[0][0]['parent_generation']=(1<<64)-1;f[0][0]['child_generation']=(1<<64)-1;check(f)

    def test_csv_observed_union_and_all_declared_returns(self):
        f=fixture()
        for g in f[1]:g.update(child_heads=4,child_edges=3)
        check(f) # A bounded union can be a strict subset of declared CSV CFG.
        for key,value in [('child_heads',3),('child_edges',2),('child_returns',1),('child_declared_heads',6),('child_declared_edges',6),('child_declared_returns',1),('parent_heads',5),('parent_edges',4),('parent_returns',0),('cases',15)]:
            f=fixture();f[1][0][key]=value;self.refuse(f)
        f=fixture()
        for r in f[0]:r['child_ret_offset']=7
        self.refuse(f)

    def test_canonical_bytes_numbers_framing_caps_and_stderr(self):
        f=fixture();streams=encoded(f);kwargs=dict(parent=f[2],child=f[3],caller=f[4])
        for slot in range(3):
            for bad in (b'',streams[slot][:-1],streams[slot]+b'\n',streams[slot].replace(b'\n',b'\r\n'),streams[slot]+b'\x00'):
                args=list(streams);args[slot]=bad
                with self.assertRaises(AssertionError):W.check(*args,**kwargs)
        for word in ('','00','+1','-1',' 1','1.0',str(1<<64)):
            args=list(streams);lines=args[0].splitlines();row=lines[1].split(b',');row[0]=word.encode();lines[1]=b','.join(row);args[0]=b'\n'.join(lines)+b'\n'
            with self.assertRaises(AssertionError):W.check(*args,**kwargs)
        with self.assertRaises(AssertionError):W.check(*streams[:3],b'warning\n',**kwargs)
        for slot,cap in ((0,524288),(1,16384),(2,1024)):
            args=list(streams);args[slot]=b'x'*cap+b'\n'
            with self.assertRaises(AssertionError):W.check(*args,**kwargs)
        for b in range(256):
            raw=bytes([b])+b'\n'
            if 32<=b<=126:self.assertEqual(W.lines(raw,2),[chr(b)])
            else:
                with self.assertRaises(AssertionError):W.lines(raw,2)

    def test_terminal_population_comparisons_and_old_profiles(self):
        f=fixture();args=list(encoded(f));kwargs=dict(parent=f[2],child=f[3],caller=f[4])
        for old,new in [(b'required=192',b'required=191'),(b'pairs=192',b'pairs=193'),(b'children=384',b'children=383'),(b'comparisons=3456',b'comparisons=3457'),(b'normal-reaps=384',b'normal-reaps=383'),(b'original-caller-nested-body',b'copied-body-only'),(W.PROFILE.encode(),b'leaf-set-whole-rust-v1')]:
            bad=args.copy();bad[2]=args[2].replace(old,new);self.assertNotEqual(bad[2],args[2])
            with self.assertRaises(AssertionError):W.check(*bad,**kwargs)
        f=fixture();f[0][0]['comparisons']+=1;self.refuse(f)

    def test_coherent_geometry_corruptions_require_external_authority(self):
        f=fixture()
        for r in f[0]:r.update(parent_heads=7,parent_edges=6,parent_visits=7,comparisons=19)
        for g in f[1]:g.update(parent_heads=7,parent_edges=6)
        self.refuse(f)
        f=fixture()
        for r in f[0]:r.update(caller_extent=12,caller_ret=11)
        self.refuse(f)
        f=fixture();f[2]['elf_va']+=4096;f[2]['callee_entry']+=4096;f[3]['elf_va']+=4096
        # A coherent independently supplied ELF rebase is a numeric relationship,
        # never proof that those bytes were executed or the children reaped.
        result=check(f);self.assertIn('require the authenticated native adapter',result['authority'])

    def test_source_local_import_and_optimization_guard(self):
        self.assertEqual(Path(W.__file__).resolve(),HERE/'call_pair_native.py')
        result=subprocess.run([sys.executable,'-O','-B',str(HERE/'call_pair_native.py')],capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'');self.assertIn(b'assertions required',result.stderr)


if __name__=='__main__':unittest.main()
