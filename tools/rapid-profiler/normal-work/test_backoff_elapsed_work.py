#!/usr/bin/env python3
"""Fabricated elapsed-wire controls; no native, scheduling or timing evidence."""
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
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE/filename)
    if spec is None or spec.loader is None:
        raise RuntimeError('missing local checker source')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load('_elapsed_under_test', 'backoff_elapsed_work.py')
U64 = 18446744073709551615
COMMENT = '# normal observer backoff elapsed; complete fixed work and raw callback ticks with a separate RAW timing appendix; no accuracy, cheap-off or 520-arm qualification'
HEADER = 'id,repetition,case,seed_index,length,input_fnv1a64,value,instructions,conditional,taken,input_bytes,ret_bytes,batch,owner,generation,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,ack,ack_ordinal,completed_sequence'
FIELDS = tuple(HEADER.split(','))
TIMING_COMMENT = '# normal backoff elapsed v1; segmented guarded call-path and validated service wall nanoseconds; no subtraction, accuracy, speedup or continuous-throughput claim'
TIMING_HEADER = 'kind,index,start_ns,end_ns'
# Independent literal scalar/input/work expectations; no parser algebra is used.
CASES = ((0, 1, 7552869386198218469, 11400714819323198532, 11, 1, 0, 1, 8),
    (0, 64, 7552869386198218469, 11400714819323190453, 389, 64, 63, 64, 8),
    (1, 1, 8995313910352961381, 11400714819323198531, 11, 1, 0, 1, 8),
    (1, 64, 8995313910352961381, 11400714819323190389, 389, 64, 63, 64, 8))


def fixture(k=10, prefixes=None, generations=(17, 29, 41, 53), spans=None):
    if prefixes is None:
        a, b = (17, 47) if k == 10 else (1007, 2050)
        prefixes = [1]*a+[2]*(b-a)+[4]*(3072-b)
    rows, counts, observed = [], [0]*len(generations), set()
    sequence, first_closed, after = 0, None, False
    for g, prefix in enumerate(prefixes):
        row = [g+1, g//24+1, g % 24+1, *CASES[(g % 8)//2]]
        at = prefix-1
        sampled = counts[at] < k
        if sampled:
            invocation, completed = counts[at], sequence
            counts[at] += 1
            sequence += 1
            after |= first_closed is not None and prefix > first_closed
        else:
            invocation, completed = '', ''
            if first_closed is None:
                first_closed = prefix
        observed.add(prefix)
        row += [g//24+1, 'sampled' if sampled else 'closed', generations[at],
            invocation, prefix, 0x800008+(g//2)*16,
            0x200000+(30 if g % 2 == 0 else 48), 1000+g*100, 1050+g*100,
            7, 7, 50, 'C' if g % 24 == 23 else 'N', '' if g % 24 == 23 else g+2,
            completed]
        rows.append(list(map(str, row)))
    arms = len(generations)
    history = [f'HISTORY,{i},published,{generation}' for i, generation in enumerate(generations, 1)]
    history.append(f'HISTORY,{arms+1},removed,{generations[-1]}')
    reports = [f'REPORT,{i},{generation},{count}'
        for i, (generation, count) in enumerate(zip(generations, counts), 1)]
    end = (f'normal-observer-backoff-elapsed FUNCTIONAL_PASS k={k} policy=10ms-2ms epoch_limit=520'
        f' stop_reason=Requested arms={arms} committed_arms={arms} completed_arms={arms} pending_arm=none'
        ' repetitions=128 calls=3072 helper_calls=1536 instructions=614400 conditional=99840'
        ' taken=96768 input_bytes=99840 ret_bytes=24576 pid=4242 tid=4242 controller_tid=4243'
        ' app_cpu=2 controller_cpu=3 entry=1048576 caller=2097152 install=1851943729 function=1'
        f' batches=128 events=6144 rows=3072 sampled={sequence} unsampled={3072-sequence}'
        f' reports={arms} records={sequence} actions={arms+1} journal_words=65536'
        ' next_entry_acknowledgements=2944 checkpoint_acknowledgements=128 banks=3'
        f' observed_generations={len(observed)} rearmed={str(arms > 1).lower()}'
        f' sampled_after_closed={str(after).lower()} input_unchanged=true detached=true joined=1'
        ' deadline_scope=issued-arms-and-requested-shutdown all_elapsed_due_arms=unqualified'
        ' cheap_off=false timing=raw-appendix')
    spans = ([('setup', 0, 0, 10), *(('body', i+1, 20+10*i, 25+10*i) for i in range(128)),
        ('service', 0, 20, 1300)] if spans is None else spans)
    timing_end = (f'normal-observer-backoff-elapsed TIMING_COMPLETE k={k} app_cpu=2 controller_cpu=3'
        ' clock=CLOCK_MONOTONIC_RAW units=ns timing_rows=130'
        f' setup_ns={spans[0][3]-spans[0][2]}'
        f' body_ns={sum(row[3]-row[2] for row in spans[1:-1])}'
        f' service_ns={spans[-1][3]-spans[-1][2]}')
    return dict(comment=COMMENT, header=HEADER, rows=rows, history=history, reports=reports, end=end,
        timing_comment=TIMING_COMMENT, timing_header=TIMING_HEADER,
        spans=[list(map(str, row)) for row in spans], timing_end=timing_end)


def functional(wire):
    return ('\n'.join([wire['comment'], wire['header'],
        *(','.join(row) for row in wire['rows']), *wire['history'], *wire['reports'],
        wire['end']])+'\n').encode('ascii')


def encode(wire):
    return functional(wire)+('\n'.join([wire['timing_comment'], wire['timing_header'],
        *(','.join(row) for row in wire['spans']), wire['timing_end']])+'\n').encode('ascii')


def terminal_change(wire, key, value, timing=False):
    wire = copy.deepcopy(wire)
    field = 'timing_end' if timing else 'end'
    words = wire[field].split(' ')
    assert sum(word.startswith(key+'=') for word in words) == 1
    wire[field] = ' '.join(key+'='+value if word.startswith(key+'=') else word for word in words)
    return wire


class Controls(unittest.TestCase):
    def check(self, wire, k=10):
        return P.check(encode(wire), b'', k, 2, 3)

    def refuse(self, wire, k=10):
        with self.assertRaises(AssertionError):
            self.check(wire, k)

    def test_complete_k10_k1000_population_and_lossless_timing(self):
        for k, sampled in ((10, 30), (1000, 3000)):
            wire = fixture(k)
            with patch.object(P.common, 'check', side_effect=AssertionError('old framing called')):
                with patch.object(P.common, '_population', wraps=P.common._population) as call:
                    got = self.check(wire, k)
                    call.assert_called_once()
                    args = call.call_args.args
                    self.assertEqual(args[:3], ([','.join(row) for row in wire['rows']], wire['history'], wire['reports']))
                    self.assertEqual((args[3]['timing'], args[4]), ('raw-appendix', k))
            f = got['functional']
            self.assertEqual((got['status'], got['k'], got['app_cpu'], got['controller_cpu']), ('TIMING_COMPLETE', k, 2, 3))
            self.assertEqual((f['status'], f['row_count'], len(f['rows']), f['sampled'], f['unsampled']),
                ('FUNCTIONAL_PASS', 3072, 3072, sampled, 3072-sampled))
            self.assertEqual(f['totals'], dict(instructions=614400, conditional=99840, taken=96768, input_bytes=99840, ret_bytes=24576))
            self.assertEqual(got['functional_prefix'], functional(wire))
            self.assertEqual(f['table'], (HEADER+'\n'+''.join(','.join(row)+'\n' for row in wire['rows'])).encode())
            self.assertEqual(f['history_table'], ('\n'.join(wire['history'])+'\n').encode())
            self.assertEqual(f['report_table'], ('\n'.join(wire['reports'])+'\n').encode())
            for raw, row in zip(wire['rows'], f['rows']):
                self.assertEqual(tuple('' if row[key] is None else str(row[key]) for key in FIELDS), tuple(raw))
            self.assertEqual((got['clock'], got['units'], got['timing_rows'], got['setup_ns'], got['body_ns'], got['service_ns']),
                ('CLOCK_MONOTONIC_RAW', 'ns', 130, 10, 640, 1280))
            returned = [got['setup'], *got['body'], got['service']]
            rebuilt = TIMING_HEADER+'\n'+''.join(','.join(str(row[key]) for key in ('kind','index','start_ns','end_ns'))+'\n' for row in returned)
            self.assertEqual(got['timing_table'], rebuilt.encode())
            self.assertEqual(len(got['body']), 128)
            self.assertEqual(got['zero_body_spans'], 0)
            self.assertEqual(set(got['division_status'].values()), {'NOT_COMPUTED'})
            self.assertIn('separate clock origin', got['scope'])
            self.assertIn('post-output Schedule', got['source_attested'])
            self.assertNotIn('No timer, performance', f['scope'])

    def test_empty_epochs_all_sampled_and_maximum_history(self):
        got = self.check(fixture())['functional']
        self.assertEqual(got['coverage']['published_but_unobserved'], [41])
        self.assertEqual(got['coverage']['closed_generations'], [17, 29, 53])
        self.assertEqual(got['coverage']['sampled_after_closed'], 'OBSERVED')
        one = self.check(fixture(prefixes=[1]*3072, generations=(U64,)))['functional']
        self.assertFalse(one['rearmed'])
        self.assertEqual(one['coverage']['later_generation_calls'], 'UNEXERCISED')
        sampled = self.check(fixture(1000, prefixes=[1]*768+[2]*768+[3]*768+[4]*768), 1000)['functional']
        self.assertEqual(sampled['unsampled'], 0)
        self.assertEqual(sampled['coverage']['function_closed'], 'UNEXERCISED')
        wire = fixture(prefixes=[520]*3072, generations=tuple(range(1,521)))
        f = self.check(wire)['functional']
        self.assertEqual((len(encode(wire).splitlines()), len(f['history']), len(f['reports_table'])), (4249,521,520))
        self.assertEqual(f['coverage']['published_but_unobserved'], list(range(1,520)))

    def test_zero_full_width_and_separate_clock_origins(self):
        for point in (0, U64):
            spans = [('setup',0,point,point), *(('body',i,point,point) for i in range(1,129)), ('service',0,point,point)]
            wire = fixture(spans=spans)
            for g, row in enumerate(wire['rows']):
                # Deliberately unrelated raw-callback clocks; no cross-clock comparison.
                row[19:24] = [str(U64 if g % 2 else 0)]*2+['4294967295']*2+['0']
            got = self.check(wire)
            self.assertEqual((got['setup_ns'], got['body_ns'], got['service_ns'], got['zero_body_spans']), (0,0,0,128))
            self.assertEqual(set(got['division_status'].values()), {'UNRESOLVED_ZERO'})
            self.assertEqual(got['functional']['zero_raw_spans'], 3072)
            self.assertEqual(got['service']['end_ns'], point)
        spans = [('setup',0,0,0), ('body',1,0,U64), *(('body',i,U64,U64) for i in range(2,129)), ('service',0,0,U64)]
        got = self.check(fixture(spans=spans))
        self.assertEqual((got['body_ns'],got['service_ns'],got['zero_body_spans']), (U64,U64,127))
        self.assertEqual(got['division_status']['setup_ns'], 'UNRESOLVED_ZERO')
        spans = [('setup',0,0,U64), *(('body',i,U64,U64) for i in range(1,129)), ('service',0,U64,U64)]
        self.assertEqual(self.check(fixture(spans=spans))['setup_ns'], U64)

    def test_actual_grammar_framing_caps_and_request_domains(self):
        data = encode(fixture())
        for bad in (b'',data[:-1],data+b'\n',b'extra\n'+data,data+b'extra\n',data+b'\xff',
            b'x'*922689,data.decode(),bytearray(data),None):
            with self.assertRaises(AssertionError): P.check(bad,b'',10,2,3)
        for sep in (b'\r\n',b'\r',b'\t',b'\v',b'\f',b'\0',b'\x7f'):
            with self.assertRaises(AssertionError): P.check(data.replace(b'\n',sep,1),b'',10,2,3)
        for stderr in (b'warning\n',b' ',None,'',bytearray()):
            with self.assertRaises(AssertionError): P.check(data,stderr,10,2,3)
        for k in (0,9,11,999,1001,True,'10',None):
            with self.assertRaises(AssertionError): P.check(data,b'',k,2,3)
        for a,c in ((2,2),(-1,3),(2,1024),(True,3),(2,'3'),(3,2),(0,3)):
            with self.assertRaises(AssertionError): P.check(data,b'',10,a,c)
        for field in ('comment','header','timing_comment','timing_header'):
            bad=fixture();bad[field]+='!';self.refuse(bad)
        for field,tail in (('end',' '*4096),('timing_end',' '*16384)):
            bad=fixture();bad[field]+=tail;self.refuse(bad)
        limits=terminal_change(fixture(),'app_cpu','0');limits=terminal_change(limits,'controller_cpu','1023')
        limits=terminal_change(limits,'app_cpu','0',True);limits=terminal_change(limits,'controller_cpu','1023',True)
        got=P.check(encode(limits),b'',10,0,1023)
        self.assertEqual((got['app_cpu'],got['controller_cpu']), (0,1023))

    def test_functional_terminal_policy_identity_counts_and_order(self):
        wire=fixture()
        changes=(('k','1000'),('policy','10ms-3ms'),('stop_reason','EpochLimit'),('arms','0'),('arms','521'),
            ('committed_arms','3'),('completed_arms','3'),('pending_arm','0'),('pid','0'),('pid','2147483648'),
            ('tid','4243'),('controller_tid','4242'),('controller_tid','2147483648'),('entry','0'),('entry',str(U64-36)),
            ('caller',str(U64-66)),('sampled','29'),('unsampled','3043'),('records','29'),('reports','3'),
            ('actions','6'),('observed_generations','4'),('rearmed','false'),('sampled_after_closed','false'),
            ('input_unchanged','false'),('detached','false'),('joined','0'),('all_elapsed_due_arms','qualified'),
            ('deadline_scope','all-elapsed-arms'),('cheap_off','true'),('timing','none'))
        for key,value in changes:self.refuse(terminal_change(wire,key,value))
        words=wire['end'].split(' ')
        for i in (0,1,2,6,18,len(words)-1):
            for replacement in ([],[words[i],words[i]],[words[i]+'!']):
                bad=copy.deepcopy(wire);bad['end']=' '.join(words[:i]+replacement+words[i+1:]);self.refuse(bad)
        for key in ('epoch_limit','repetitions','calls','helper_calls','instructions','conditional','taken','input_bytes',
            'ret_bytes','install','function','batches','events','rows','journal_words','next_entry_acknowledgements',
            'checkpoint_acknowledgements','banks'):
            value=next(word.split('=')[1] for word in words if word.startswith(key+'='))
            self.refuse(terminal_change(wire,key,str(int(value)+1)))
        bad=copy.deepcopy(wire);words[2],words[3]=words[3],words[2];bad['end']=' '.join(words);self.refuse(bad)

    def test_complete_work_owner_stack_ack_and_history_report_joins(self):
        wire=fixture()
        for g,field,value in ((0,'value','0'),(0,'input_fnv1a64','0'),(0,'instructions','12'),
            (0,'owner','closed'),(10,'invocation','0'),(10,'completed_sequence','10'),(17,'completed_sequence','0'),
            (17,'history_prefix','1'),(47,'generation','41'),(0,'entry_rsp','120'),(1,'entry_rsp',str(0x800018)),
            (0,'return_word',str(0x200000+48)),(23,'ack','N'),(23,'ack_ordinal','25'),(24,'batch','1'),
            (0,'end_ticks','999'),(0,'raw_ticks','49'),(0,'end_aux','8'),(0,'start_aux','4294967296'),
            (0,'id','01'),(0,'start_ticks',str(U64+1))):
            bad=copy.deepcopy(wire);bad['rows'][g][FIELDS.index(field)]=value;self.refuse(bad)
        for group,index in (('rows',0),('rows',3071),('history',0),('history',4),('reports',0),('reports',3)):
            for count in (0,2):
                bad=copy.deepcopy(wire);bad[group][index:index+1]=[bad[group][index]]*count;self.refuse(bad)
        for group,i,line in (('history',1,'HISTORY,2,published,17'),('history',4,'HISTORY,5,removed,41'),
            ('reports',0,'REPORT,1,17,9'),('reports',2,'REPORT,3,41,1')):
            bad=copy.deepcopy(wire);bad[group][i]=line;self.refuse(bad)
        bad=copy.deepcopy(wire);bad['reports'][0]='REPORT,1,17,9';bad['reports'][1]='REPORT,2,29,11';self.refuse(bad)
        bad=copy.deepcopy(wire);bad['rows'][23],bad['rows'][24]=bad['rows'][24],bad['rows'][23];self.refuse(bad)
        bad=copy.deepcopy(wire);bad['rows'][0][6]=str(int(bad['rows'][0][6])+1);bad['rows'][1][6]=str(int(bad['rows'][1][6])-1);self.refuse(bad)

    def test_timing_population_order_and_columns(self):
        wire=fixture()
        for i in range(130):
            for count in (0,2):
                bad=copy.deepcopy(wire);bad['spans'][i:i+1]=[bad['spans'][i]]*count;self.refuse(bad)
        for i in (0,1,64,128):
            bad=copy.deepcopy(wire);bad['spans'][i],bad['spans'][i+1]=bad['spans'][i+1],bad['spans'][i];self.refuse(bad)
        for i in (0,1,64,128,129):
            for count in (3,5):
                bad=copy.deepcopy(wire);bad['spans'][i]=(bad['spans'][i]+['0'])[:count];self.refuse(bad)
        for i,field,value in ((0,0,'body'),(1,1,'2'),(128,1,'127'),(129,0,'body'),(129,1,'1')):
            bad=copy.deepcopy(wire);bad['spans'][i][field]=value;self.refuse(bad)

    def test_timing_numbers_arithmetic_and_enclosure_boundaries(self):
        wire=fixture()
        for text in ('','00','01','+1','-1','1.0','1e0',' 1','1 ',str(U64+1),'9'*21):
            bad=copy.deepcopy(wire);bad['spans'][1][2]=text;self.refuse(bad)
        for i,field,value in ((0,1,'00'),(0,2,'11'),(0,3,'21'),(1,3,'19'),(2,2,'24'),
            (129,2,'19'),(129,3,'1294')):
            bad=copy.deepcopy(wire);bad['spans'][i][field]=value;self.refuse(bad)
        # Coherent advertised sums cannot repair overlap, overflow or a missing tail.
        for spans in (
            [('setup',0,0,0),*(('body',i,0,U64) for i in range(1,129)),('service',0,0,U64)],
            [('setup',0,0,0),('body',1,20,25),('body',2,24,29),
             *(('body',i,20+10*(i-1),25+10*(i-1)) for i in range(3,129)),('service',0,20,1300)]):
            bad=fixture(spans=spans)
            if int(bad['timing_end'].split('body_ns=')[1].split(' ')[0])>U64:
                bad=terminal_change(bad,'body_ns',str(U64),True)
            self.refuse(bad)
        bad=copy.deepcopy(wire);bad['spans'][-1][2]='19'
        self.refuse(terminal_change(bad,'service_ns','1281',True))
        bad=copy.deepcopy(wire);bad['spans'][-1][3]='1294'
        self.refuse(terminal_change(bad,'service_ns','1274',True))
        for key,value in (('setup_ns','11'),('body_ns','639'),('service_ns','1279')):
            self.refuse(terminal_change(wire,key,value,True))

    def test_timing_terminal_and_request_identity(self):
        wire=fixture()
        for key,value in (('k','1000'),('app_cpu','3'),('controller_cpu','2'),('clock','CLOCK_MONOTONIC'),
            ('units','ticks'),('timing_rows','129')):
            self.refuse(terminal_change(wire,key,value,True))
        for key in ('k','app_cpu','controller_cpu','timing_rows','setup_ns','body_ns','service_ns'):
            for value in ('00',str(U64+1)):
                self.refuse(terminal_change(wire,key,value,True))
        words=wire['timing_end'].split(' ')
        for i in range(len(words)):
            for replacement in ([],[words[i],words[i]]):
                bad=copy.deepcopy(wire);bad['timing_end']=' '.join(words[:i]+replacement+words[i+1:]);self.refuse(bad)
        bad=copy.deepcopy(wire);words[2],words[3]=words[3],words[2];bad['timing_end']=' '.join(words);self.refuse(bad)
        for text in ('normal-observer-throughput','normal-observer-backoff','FUNCTIONAL_PASS'):
            bad=copy.deepcopy(wire)
            word='TIMING_COMPLETE' if text=='FUNCTIONAL_PASS' else 'normal-observer-backoff-elapsed'
            bad['timing_end']=bad['timing_end'].replace(word,text,1);self.refuse(bad)

    def test_old_grammars_remain_distinct(self):
        old=load('_elapsed_old_fixture', 'test_backoff_work.py')
        pending=load('_elapsed_pending_checker', 'backoff_pending_owner.py')
        throughput=load('_elapsed_throughput_checker', 'throughput_work.py')
        for k in (10,1000):
            original=old.encode(old.fixture(k))
            self.assertEqual(P.common.check(original,b'',k,2,3)['status'], 'FUNCTIONAL_PASS')
            with self.assertRaises(AssertionError):P.check(original,b'',k,2,3)
            wire=fixture(k)
            for data in (functional(wire),encode(wire)):
                with self.assertRaises(AssertionError):P.common.check(data,b'',k,2,3)
                with self.assertRaises(AssertionError):pending.check(data,b'',k,2,3)
                with self.assertRaises(AssertionError):throughput.check(data,b'','always-on')
            # Reusing the old name and timing literal is not the actual new grammar.
            bad=terminal_change(wire,'timing','none');bad['end']=bad['end'].replace('backoff-elapsed','backoff',1)
            self.refuse(bad,k)

    def test_source_local_import_and_optimized_entrypoints(self):
        self.assertEqual(Path(P.common.__file__).resolve(), HERE/'backoff_work.py')
        with tempfile.TemporaryDirectory(prefix='backoff-elapsed-check-',dir=os.environ.get('TMPDIR')) as directory:
            root=Path(directory)
            for name in ('backoff_work.py','backoff_elapsed_work.py'):
                (root/name).write_text("raise RuntimeError('ambient import')\n")
            for name in ('backoff_elapsed_work.py','test_backoff_elapsed_work.py'):
                path=str(HERE/name)
                for tail in ([path],['-c','import runpy,sys;runpy.run_path(sys.argv[1])',path]):
                    child=subprocess.run([sys.executable,'-B','-O',*tail],cwd=root,capture_output=True,timeout=5,check=False)
                    self.assertEqual((child.returncode,child.stdout,child.stderr),(1,b'',b'assertions required\n'))
            code=("import importlib.util,sys;s=importlib.util.spec_from_file_location('x',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.common.__file__)")
            child=subprocess.run([sys.executable,'-B','-c',code,str(HERE/'backoff_elapsed_work.py')],
                cwd=root,capture_output=True,timeout=5,check=False)
            self.assertEqual((child.returncode,child.stdout,child.stderr),(0,(str(HERE/'backoff_work.py')+'\n').encode(),b''))
            self.assertFalse((root/'__pycache__').exists())


if __name__ == '__main__':
    unittest.main()
