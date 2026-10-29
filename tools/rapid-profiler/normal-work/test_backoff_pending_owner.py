#!/usr/bin/env python3
"""Independent fabricated complete fixtures; native controls remain separate."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import copy
import importlib.util
from pathlib import Path
import subprocess
import unittest

_path = Path(__file__).resolve().with_name('backoff_pending_owner.py')
_spec = importlib.util.spec_from_file_location('_pending_owner_controls', _path)
if _spec is None or _spec.loader is None:
    raise RuntimeError('missing local pending-owner checker')
parser = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(parser)
COMMENT = '# normal backoff pending owner; deterministic native functional control; schedule not run; no timing or performance claim'
HEADER = 'id,repetition,case,seed_index,length,input_fnv1a64,value,instructions,conditional,taken,input_bytes,ret_bytes,batch,owner,generation,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,ack,ack_ordinal,completed_sequence'
FIELDS = tuple(HEADER.split(','))
CASES = ((0,1,7552869386198218469,11400714819323198532,11,1,0,1,8),
    (0,64,7552869386198218469,11400714819323190453,389,64,63,64,8),
    (1,1,8995313910352961381,11400714819323198531,11,1,0,1,8),
    (1,64,8995313910352961381,11400714819323190389,389,64,63,64,8))
U64 = 18446744073709551615


def fixture(k=10):
    t = 22 if k == 10 else 1006
    rows = []
    for g in range(3072):
        generation,prefix,local = (17,1,g) if g < t else (29,2,g-t)
        sampled = local < k
        rows.append(list(map(str,[g+1,g//24+1,g%24+1,*CASES[(g%8)//2],g//24+1,
            'sampled' if sampled else 'closed',generation,local if sampled else '',prefix,
            8388616+g//2*16,2097152+(30 if g%2 == 0 else 48),g*100,g*100+50,7,7,50,
            'C' if g%24 == 23 else 'N','' if g%24 == 23 else g+2,
            (prefix-1)*k+local if sampled else ''])))
    phases=[]
    for i in (1,2,3):
        totals=(t,t,t-1,k,t-1-k) if i < 3 else (t+2,t+2,t+1,k+1,t-k)
        phases.append(list(map(str,['PHASE',i,'shared-owner' if i < 3 else 'reclaimed',t,17,29,
            *totals,'true' if i < 3 else 'false',0,1,k,1 if i < 3 else 2,29,2,i,(t-22)//24])))
    terminal=(f'normal-observer-backoff-pending-owner FUNCTIONAL_PASS k={k} hold_ordinal={t}'
        ' generation_a=17 generation_b=29 arms=2 repetitions=128 calls=3072 helper_calls=1536'
        ' instructions=614400 conditional=99840 taken=96768 input_bytes=99840 ret_bytes=24576'
        ' pid=4242 tid=4242 controller_tid=4243 app_cpu=2 controller_cpu=3 entry=1048576'
        f' caller=2097152 install=1851943729 function=1 batches=128 events=6144 rows=3072 sampled={2*k}'
        f' unsampled={3072-2*k} reports=2 records={2*k} actions=3 journal_words=65536'
        ' next_entry_acknowledgements=2944 checkpoint_acknowledgements=128 banks=3'
        ' observed_generations=2 rearmed=true sampled_after_closed=true input_unchanged=true'
        ' detached=true joined=1 old_report_copies=1 shared_owner_refusals=2 reclaim_before_checkpoint=true'
        ' phase_rows=3 deadline_scope=original-15s-functional schedule=not-run timing=none')
    return dict(comment=COMMENT,header=HEADER,rows=rows,
        history=['HISTORY,1,published,17','HISTORY,2,published,29','HISTORY,3,removed,29'],
        reports=[f'REPORT,1,17,{k}',f'REPORT,2,29,{k}'],phases=phases,terminal=terminal)


def encode(w):
    return ('\n'.join([w['comment'],w['header'],*(','.join(r) for r in w['rows']),
        *w['history'],*w['reports'],*(','.join(r) for r in w['phases']),w['terminal']])+'\n').encode('ascii')


def change(w,key,value):
    w=copy.deepcopy(w)
    w['terminal']=' '.join(key+'='+value if v.startswith(key+'=') else v for v in w['terminal'].split(' '))
    return w


class Controls(unittest.TestCase):
    def check(self,w,k=10):
        return parser.check(encode(w),b'',k,2,3)

    def refuse(self,w,k=10):
        with self.assertRaises(AssertionError):
            self.check(w,k)

    def test_complete_k10_and_k1000_and_lossless_phases(self):
        for k,t in ((10,22),(1000,1006)):
            w=fixture(k);got=self.check(w,k)
            self.assertEqual((got['status'],got['row_count'],len(got['rows']),len(got['phases'])),('FUNCTIONAL_PASS',3072,3072,3))
            self.assertEqual((got['sampled'],got['unsampled'],got['hold_ordinal']),(2*k,3072-2*k,t))
            self.assertEqual(got['table'],(HEADER+'\n'+''.join(','.join(r)+'\n' for r in w['rows'])).encode())
            for name,key in (('history','history_table'),('reports','report_table')):
                self.assertEqual(got[key],('\n'.join(w[name])+'\n').encode())
            self.assertEqual(got['phase_table'],(''.join(','.join(p)+'\n' for p in w['phases'])).encode())
            self.assertEqual(got['phases'][2]['completed_batches'],(t-22)//24)
            self.assertEqual(got['coverage']['published_but_unobserved'],[])
            self.assertEqual(got['schedule'],'not-run');self.assertIn('do not export',got['source_attested'])

    def test_phase_order_identity_totals_and_refusal_counts(self):
        for k in (10,1000):
            w=fixture(k)
            for i in range(3):
                for col in range(1,20):
                    bad=copy.deepcopy(w)
                    v=bad['phases'][i][col]
                    bad['phases'][i][col]=str(int(v)+1) if v.isdigit() else ('false' if v=='true' else 'invalid')
                    self.refuse(bad,k)
            for key,value in (('old_report_copies','2'),('shared_owner_refusals','1'),('shared_owner_refusals','3'),
                ('reclaim_before_checkpoint','false'),('generation_a','29'),('generation_b','30'),('hold_ordinal','24')):
                self.refuse(change(w,key,value),k)
            for i in range(3):
                bad=copy.deepcopy(w);del bad['phases'][i];self.refuse(bad,k)
                bad=copy.deepcopy(w);bad['phases'].insert(i,bad['phases'][i]);self.refuse(bad,k)
            bad=copy.deepcopy(w);bad['phases'][0],bad['phases'][1]=bad['phases'][1],bad['phases'][0];self.refuse(bad,k)

    def test_reclaim_must_precede_same_block_checkpoint(self):
        for k,t in ((10,22),(1000,1006)):
            w=fixture(k)
            for i in range(3):
                bad=copy.deepcopy(w);bad['phases'][i][-1]=str((t-22)//24+1);self.refuse(bad,k)
            for row,field,value in ((t-1,'ack','C'),(t-1,'ack_ordinal',''),(t+1,'ack','N'),(t+1,'ack_ordinal',str(t+3))):
                bad=copy.deepcopy(w);bad['rows'][row][FIELDS.index(field)]=value;self.refuse(bad,k)
            bad=copy.deepcopy(w);bad['phases'][2][8]=str(t+2);self.refuse(bad,k)

    def test_exact_owner_boundary_and_full_sampled_closed_population(self):
        for k,t in ((10,22),(1000,1006)):
            w=fixture(k)
            for row,field,value in ((0,'invocation','1'),(k,'owner','sampled'),(t-1,'generation','29'),
                (t,'generation','17'),(t,'history_prefix','1'),(t,'invocation','1'),(t,'completed_sequence','0'),
                (3071,'owner','sampled'),(t+k,'invocation','0')):
                bad=copy.deepcopy(w);bad['rows'][row][FIELDS.index(field)]=value;self.refuse(bad,k)
            # Complete, internally coherent mixed populations at a different boundary
            # remain outside this deterministic control (common grammar still accepts).
            bad=copy.deepcopy(w)
            for g in range(t-2,t):
                r=bad['rows'][g];r[13:17]=['sampled','29',str(g-(t-2)),'2'];r[26]=str(k+g-(t-2))
            for g in range(t,t+k):
                r=bad['rows'][g];local=g-(t-2)
                r[13]='sampled' if local<k else 'closed';r[15]=str(local) if local<k else '';r[26]=str(k+local) if local<k else ''
            self.refuse(bad,k)

    def test_work_history_reports_and_full_framing_refuse(self):
        w=fixture();data=encode(w)
        for row in (0,23,24,3071):
            for field in FIELDS[:12]:
                bad=copy.deepcopy(w);at=FIELDS.index(field);bad['rows'][row][at]=str(int(bad['rows'][row][at])+1);self.refuse(bad)
            bad=copy.deepcopy(w);del bad['rows'][row];self.refuse(bad)
        for name in ('history','reports'):
            for i in range(len(w[name])):
                bad=copy.deepcopy(w);del bad[name][i];self.refuse(bad)
                bad=copy.deepcopy(w);bad[name][i]+=',0';self.refuse(bad)
        for bad in (b'',data[:-1],data+b'\n',b'x\n'+data,data.replace(b'\n',b'\r\n',1),data+b'\xff',b'x'*906305):
            with self.assertRaises(AssertionError):parser.check(bad,b'',10,2,3)
        for stderr in (b'warning\n','',None):
            with self.assertRaises(AssertionError):parser.check(data,stderr,10,2,3)
        for value in ('01','-1','+1',str(U64+1),'1.0'):
            bad=copy.deepcopy(w);bad['phases'][0][1]=value;self.refuse(bad)
        for i in range(len(w['terminal'].split(' '))):
            bad=copy.deepcopy(w);words=bad['terminal'].split(' ');del words[i];bad['terminal']=' '.join(words);self.refuse(bad)

    def test_strict_timed_checker_stays_separate(self):
        w=fixture()
        with self.assertRaises(AssertionError):parser.common.check(encode(w),b'',10,2,3)
        for key,value in (('schedule','10ms-2ms'),('deadline_scope','issued-arms-and-requested-shutdown'),('timing','ns')):
            self.refuse(change(w,key,value))
        bad=copy.deepcopy(w);bad['comment']=parser.common.COMMENT;self.refuse(bad)
        bad=copy.deepcopy(w);bad['terminal']=bad['terminal'].replace('normal-observer-backoff-pending-owner','normal-observer-backoff',1);self.refuse(bad)
        self.assertEqual(parser.common.LITERALS['policy'],'10ms-2ms')
        self.assertEqual(parser.common.LITERALS['stop_reason'],'Requested')

    def test_raw_clocks_zero_max_and_expected_roles(self):
        w=fixture()
        for g,r in enumerate(w['rows']):
            r[19:24]=list(map(str,(0,U64,4294967295,4294967295,U64) if g%2 else (U64,U64,0,0,0)))
        got=self.check(w);self.assertEqual(got['zero_raw_spans'],1536);self.assertEqual(got['rows'][1]['raw_ticks'],U64)
        for row,col,value in ((0,20,'0'),(0,22,'1'),(1,23,'0'),(1,21,'4294967296'),(0,17,'0'),(1,18,'2097182')):
            bad=copy.deepcopy(w);bad['rows'][row][col]=value;self.refuse(bad)
        for k,a,c in ((True,2,3),(10,2,2),(10,True,3),(10,3,2),(1000,2,3),(10,2,1024)):
            with self.assertRaises(AssertionError):parser.check(encode(w),b'',k,a,c)
        for key,value in (('pid','0'),('tid','4243'),('controller_tid','4242'),('entry','0'),('caller',str(U64)),('app_cpu','3')):
            self.refuse(change(w,key,value))

    def test_local_import_and_optimized_entrypoints_refuse(self):
        self.assertEqual(Path(parser.__file__).resolve(),Path(__file__).resolve().with_name('backoff_pending_owner.py'))
        self.assertEqual(Path(parser.common.__file__).resolve(),Path(__file__).resolve().with_name('backoff_work.py'))
        for name in ('backoff_pending_owner.py',Path(__file__).name):
            path=str(Path(__file__).resolve().with_name(name))
            for tail in ([path],['-c','import runpy,sys; runpy.run_path(sys.argv[1])',path]):
                child=subprocess.run([sys.executable,'-B','-O',*tail],capture_output=True,timeout=5,check=False)
                self.assertEqual((child.returncode,child.stdout,child.stderr),(1,b'',b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
