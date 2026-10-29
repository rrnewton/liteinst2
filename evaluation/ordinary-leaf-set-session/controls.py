#!/usr/bin/env python3
"""Fabricated transcript controls only; no native owner, receipt or timing proof."""
if not __debug__:
    raise SystemExit('assertions required')

import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

_path = Path(__file__).resolve().with_name('output.py')
_spec = importlib.util.spec_from_file_location('_leaf_set_wire_controls_output', _path)
assert _spec is not None and _spec.loader is not None
output = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(output)

# Independent literal truth vectors, not calls to the production recognizer.
LITERALS = ((b'', (1, 0, 0, 0)), (b'a,b', (2, 3, 0, 0)),
            (b'"1 2", 3', (2, 8, 3, 2)), (b'"",42,  ', (3, 8, 2, 2)))
OPERATIONS = ('csv_fields', 'length', 'ascii_digits', 'ascii_spaces')


def checksum(payload):
    h = 0xcbf29ce484222325
    for byte in payload:
        h = ((h ^ byte) * 0x100000001b3) % (1 << 64)
    return h


def fixture(n=3, count=3, k=10, arms=1, prefixes=None, operations=None,
            report_order=None, width=1, outcome='eof', error='none', records=None):
    operations = OPERATIONS[:n] if operations is None else operations
    assert len(operations) == n
    values = tuple(LITERALS[i % len(LITERALS)] for i in range(count)) if records is None else records
    assert len(values) == count
    table = tuple(dict(function_id=101*i, operation=operations[i], policy='certified' if i % 2 == 0 else 'whole',
                       elf_va=4096+64*i, extent=48, returns=(17, 47)) for i in range(n))
    args = dict(records=tuple(payload for payload, _ in values), table=table,
                caller=dict(extent=32, continuation=17), k=k, epochs=arms,
                outcome=outcome, input_error=error, cpus=(2, 4))
    rows = [['READY', 'leaf-set-session-v1', k, arms, 10, 2, 64, min(2048, 4096//n), n, 1,
             0x6d6f6401, 123, 123, 124, 2, 4, 0x800000, n, 1]]
    for i, leaf in enumerate(table):
        entry = 0x20000 + leaf['elf_va']
        rows.append(['LEAF', i, leaf['function_id'], leaf['operation'], leaf['policy'], leaf['elf_va'], 48, entry, entry+48, 2])
        rows.extend(['RET', i, offset] for offset in (17, 47))
    histories = [['HISTORY', (i-1)//width+1, i, 'published', 100+i] for i in range(1, arms+1)]
    removal = ['HISTORY', arms//width+1, arms+1, 'removed', 100+arms]
    prefixes = [arms] * (n*count) if prefixes is None else prefixes
    assert len(prefixes) == n*count
    remove_first = width != 1 or (prefixes and max(prefixes) == arms+1)
    rows.extend(histories)
    if remove_first:
        rows.append(removal)
    slots, ranks, samples = {}, {}, {}
    counts = [dict(sampled=0, closed=0, initial=0, removed=0) for _ in range(n)]
    masks, completed = [0]*n, 0
    for ordinal, prefix in enumerate(prefixes, 1):
        index, record = (ordinal-1)%n, (ordinal-1)//n+1
        generation = 0 if prefix == 0 else 100+min(prefix, arms)
        rank = ranks.get((generation, index), 0)
        owner = 'initial' if prefix == 0 else 'removed' if prefix == arms+1 else 'sampled' if rank < k else 'closed'
        sampled = owner == 'sampled'
        slot = slots.get(generation, 0)
        offset = table[index]['returns'][(record-1)%2]
        row = ['CALL', record, index, ordinal, owner, generation, slot+1 if sampled else 0, prefix,
               offset, 0x9008, 0x800011, ordinal, ordinal+1, 0, 0,
               'checkpoint' if index+1 == n else 'next', 0 if index+1 == n else ordinal+1, record, completed]
        rows.append(row)
        counts[index][owner] += 1
        masks[index] |= 1 << ((record-1)%2)
        if sampled:
            samples[generation, slot] = ['SAMPLE', record, index, generation, slot, rank, completed, ordinal, 'value', ordinal+1]
            slots[generation] = slot+1; ranks[generation, index] = rank+1; completed += 1
        if index+1 == n:
            payload, truths = values[record-1]
            scalar = [truths[OPERATIONS.index(op)] for op in operations]
            rows.append(['RESULT', record, len(payload), checksum(payload), *scalar, ordinal-n+1, ordinal])
    if not remove_first:
        rows.append(removal)
    report_order = tuple(range(101, 101+arms)) if report_order is None else report_order
    for generation in report_order:
        rows.append(['REPORT', generation, slots.get(generation, 0)])
    for generation in report_order:
        rows.extend(samples[generation, slot] for slot in range(slots.get(generation, 0)))
    for i, c in enumerate(counts):
        rows.append(['COVERAGE', i, count, c['sampled'], c['closed'], c['initial'], c['removed'], 2, masks[i]])
    rows.append(['IO', 0])
    status = {'eof': 'COMPLETE', 'input_error': 'INPUT_REFUSED', 'input_incomplete': 'INPUT_INCOMPLETE'}[outcome]
    rows.append(['DONE', status, 'EpochLimit' if outcome == 'input_incomplete' else 'Requested', arms, arms+1,
                 count, n*count, n*count, n*count, completed, n*count-completed, count,
                 sum(t[0] for _, t in values), sum(len(p) for p, _ in values),
                 int(outcome == 'eof' or error == 'unterminated'), error, int(outcome == 'eof'), 1, 1])
    return rows, args


def encode(rows):
    return ('\n'.join(','.join(map(str, row)) for row in rows) + '\n').encode('ascii')


def stderr_for(args):
    # Fabricated controls only. Production must pass the real stderr bytes.
    if args['outcome'] == 'input_error':
        return ('normal-leaf-set-session INPUT_REFUSED: ' + args['input_error'] + '\n').encode('ascii')
    if args['outcome'] == 'input_incomplete':
        return b'normal-leaf-set-session INPUT_INCOMPLETE\n'
    return b''


def check(rows, args):
    return output.check(encode(rows), stderr_for(args), **args)


def first(rows, tag):
    return next(i for i, row in enumerate(rows) if row[0] == tag)


class Controls(unittest.TestCase):
    def refuses(self, rows, args):
        with self.assertRaises((AssertionError, ValueError, UnicodeError)):
            check(rows, args)

    def test_all_cardinalities_empty_and_complete_populations(self):
        for n in range(1, 5):
            for count in (0, 1, 13):
                for k in (10, 1000):
                    rows, args = fixture(n=n, count=count, k=k)
                    result = check(rows, args)
                    self.assertEqual(result['totals']['calls'], n*count)
                    self.assertEqual(result['totals']['batches'], count)
                    self.assertEqual(result['raw'], encode(rows))
                    self.assertEqual(result['stderr'], b'')
                    self.assertEqual(len(result['ordered']), len(rows))
        for operation in OPERATIONS:
            rows, args = fixture(n=1, operations=(operation,))
            check(rows, args)

    def test_input_grammar_and_four_operation_results_are_independent(self):
        literals = LITERALS + ((b' '*64, (1,64,0,64)), (b','*64, (65,64,0,0)), (b'9'*64,(1,64,64,0)))
        rows, args = fixture(n=4, count=len(literals), records=literals)
        check(rows, args)
        for i, row in enumerate(rows):
            if row[0] == 'RESULT':
                for position in range(1, len(row)):
                    bad = copy.deepcopy(rows); bad[i][position] += 1; self.refuses(bad, args)
        coherent = dict(args, records=(b'', b'z,b', *args['records'][2:]))
        self.refuses(rows, coherent)
        for payload in (b'a"b', b'"open', b'"a"z', b'"a" ,b', b'\x00', b'\n', b'\x7f', b'\xff', b'a'*65):
            changed = dict(args, records=(payload, *args['records'][1:]))
            self.refuses(rows, changed)
        for payload, values in ((b'""', (1,2,0,0)), (b'""""', (1,4,0,0)), (b'a,', (2,2,0,0)), (b',a', (2,2,0,0))):
            check(*fixture(n=4, count=1, records=((payload, values),)))

    def test_selected_table_and_runtime_geometry_require_complete_exact_identity(self):
        rows, args = fixture(n=4)
        for key, value in (('function_id', args['table'][0]['function_id']), ('operation', 'csv_fields'),
                           ('policy', 'fallback'), ('elf_va', 4096), ('extent', 257), ('returns', (47,17)), ('extra', 1)):
            bad = copy.deepcopy(args); bad['table'][-1][key] = value; self.refuses(rows, bad)
        for key, value in (('extent', 0), ('extent', 257), ('continuation', 0), ('continuation', 32), ('extra', 1)):
            bad = copy.deepcopy(args); bad['caller'][key] = value; self.refuses(rows, bad)
        for tag, positions in (('LEAF', range(1,10)), ('RET', (1,2))):
            at = first(rows, tag)
            for position in positions:
                bad = copy.deepcopy(rows); bad[at][position] = bad[at][position]+1 if type(bad[at][position]) is int else 'wrong'; self.refuses(bad, args)
        for position in (2,3,4,5,6,7,8,9,10,11,12,14,15,16,17,18):
            bad = copy.deepcopy(rows); bad[0][position] += 1; self.refuses(bad, args)
        for value in (0,123):
            bad=copy.deepcopy(rows);bad[0][13]=value;self.refuses(bad,args)
        bad=copy.deepcopy(rows);bad[0][16]=(1<<64)-16;self.refuses(bad,args)
        # Coherent external ID changes, including zero/MAX, remain numeric identities.
        good=copy.deepcopy(rows);trusted=copy.deepcopy(args)
        trusted['table'][-1]['function_id']=(1<<64)-1
        [row for row in good if row[0]=='LEAF'][-1][2]=(1<<64)-1
        check(good,trusted)
        # A coherent last-entry change still cannot create a second DSO bias.
        bad=copy.deepcopy(rows);leaf=[row for row in bad if row[0]=='LEAF'][-1];leaf[7]+=4096;leaf[8]+=4096;self.refuses(bad,args)
        bad=copy.deepcopy(args);bad['table']=(bad['table'][1],bad['table'][0],*bad['table'][2:]);self.refuses(rows,bad)

    def test_each_wire_family_missing_duplicate_reordered_or_extra_refuses(self):
        rows,args=fixture(n=4)
        for tag in tuple(output.FIELDS)+('RESULT',):
            at=first(rows,tag)
            self.refuses(rows[:at]+rows[at+1:],args)
            self.refuses(rows[:at]+[rows[at]]+rows[at:],args)
        for tag in ('LEAF','RET','CALL','RESULT','SAMPLE','COVERAGE','HISTORY'):
            indices=[i for i,r in enumerate(rows) if r[0]==tag]
            if len(indices)>1:
                bad=copy.deepcopy(rows);a,b=indices[:2];bad[a],bad[b]=bad[b],bad[a];self.refuses(bad,args)
        self.refuses(rows+[['UNKNOWN',0]],args)
        self.refuses([['UNKNOWN',0]]+rows,args)

    def test_history_starts_at_one_and_keeps_multi_action_chunks_and_empty_reports(self):
        for width in (1,8):
            rows,args=fixture(n=3,count=2,arms=520,prefixes=[513]*6,width=width)
            result=check(rows,args);self.assertEqual(len(result['rows']['REPORT']),520)
            for field in (1,2):
                bad=copy.deepcopy(rows)
                for row in bad:
                    if row[0]=='HISTORY':row[field]-=1
                self.refuses(bad,args)
            bad=copy.deepcopy(rows)
            for row in bad:
                if row[0]=='HISTORY':row[1]=(row[2]-1)//9+1
            self.refuses(bad,args)
        rows,args=fixture(n=1,arms=2)
        report=rows.pop(first(rows,'REPORT'));rows.insert(first(rows,'CALL'),report)
        # Generation101 is closed by102, so its empty Report may appear early.
        check(rows,args)
        bad=copy.deepcopy(rows);bad[first(bad,'REPORT')][1]=102;self.refuses(bad,args)
        bad=copy.deepcopy(rows);bad[first(bad,'HISTORY')][3]='removed';self.refuses(bad,args)

    def test_global_slots_local_ranks_and_mixed_generation_record(self):
        prefixes=[1,1,2]+[2]*30
        rows,args=fixture(n=3,count=11,arms=2,prefixes=prefixes,report_order=(102,101))
        result=check(rows,args)
        self.assertEqual(result['totals']['sampled'],32)
        self.assertEqual(result['totals']['unsampled'],1)
        self.assertEqual([s['function_rank'] for s in result['rows']['SAMPLE'][-2:]],[0,0])
        for position in (1,2,3,5,6,7,18):
            bad=copy.deepcopy(rows);at=first(bad,'CALL');bad[at][position]+=1;self.refuses(bad,args)
        bad=copy.deepcopy(rows);row=bad[first(bad,'CALL')];row[4]='closed';row[6]=0;self.refuses(bad,args)
        initial,args=fixture(n=3,count=2,arms=1,prefixes=[0,0,1,1,2,2])
        self.assertEqual(check(initial,args)['totals']['unsampled'],4)

    def test_full_budget_call_sample_boundary_and_function_closed(self):
        for n in range(1,5):
            for k in (10,1000):
                rows,args=fixture(n=n,count=k+1,k=k)
                result=check(rows,args)
                sampled=[r for r in result['rows']['CALL'] if r['owner']=='sampled']
                self.assertEqual(sampled[-1]['invocation'],n*k)
                self.assertEqual(result['rows']['SAMPLE'][-1]['invocation'],n*k-1)
                self.assertEqual(result['totals']['unsampled'],n)
                bad=copy.deepcopy(rows)
                for row in bad:
                    if row[0]=='CALL' and row[4]=='sampled':row[6]+=1
                    if row[0]=='SAMPLE':row[4]+=1
                self.refuses(bad,args)
                bad=copy.deepcopy(rows);last=[r for r in bad if r[0]=='CALL' and r[4]=='sampled'][-1];last[6]=n*k-1;self.refuses(bad,args)

    def test_three_call_records_checkpoint_without_six_call_batches(self):
        rows,args=fixture(n=3,count=2)
        result=check(rows,args)
        self.assertEqual([(r['batch_number'],r['acknowledgement']) for r in result['rows']['CALL']],[(1,'next'),(1,'next'),(1,'checkpoint'),(2,'next'),(2,'next'),(2,'checkpoint')])
        bad=copy.deepcopy(rows);calls=[r for r in bad if r[0]=='CALL']
        calls[2][15:17]=['next',4]
        for row in calls[3:]:row[17]=1
        bad[-1][11]=1;self.refuses(bad,args)
        # No HISTORY/REPORT interleaving or delayed RESULT within a returned group.
        bad, mixed=fixture(n=3,count=2,arms=2,prefixes=[1]*6)
        h=bad.pop(first(bad,'HISTORY')+1);bad.insert(first(bad,'CALL')+1,h);self.refuses(bad,mixed)
        bad=copy.deepcopy(rows);at=first(bad,'RESULT');r=bad.pop(at);bad.insert(at+3,r);self.refuses(bad,args)

    def test_stack_continuation_return_and_acknowledgement_domains(self):
        rows,args=fixture(n=4)
        at=first(rows,'CALL')
        for position,value in ((8,18),(9,8),(9,120),(9,(1<<64)-1),(9,4096),(10,0x800012),(15,'checkpoint'),(16,0),(17,0),(13,1<<32),(14,1<<32)):
            bad=copy.deepcopy(rows);bad[at][position]=value;self.refuses(bad,args)
        for rsp in (136,(1<<64)-24):
            good=copy.deepcopy(rows)
            for row in good:
                if row[0]=='CALL':row[9]=rsp
            self.assertEqual(check(good,args)['rows']['CALL'][0]['entry_rsp'],rsp)
        # Raw thread IDs and RSP are numeric observations, not external witnesses.
        good=copy.deepcopy(rows);good[0][13]=(1<<64)-1;check(good,args)

    def test_report_sample_bijection_copy_order_and_payload_observation(self):
        rows,args=fixture(n=2,count=2,arms=2,prefixes=[1,1,2,2],report_order=(102,101))
        self.assertEqual([r['generation'] for r in check(rows,args)['rows']['REPORT']],[102,101])
        for tag,positions in (('REPORT',(1,2)),('SAMPLE',range(1,10))):
            at=first(rows,tag)
            for position in positions:
                bad=copy.deepcopy(rows);bad[at][position]=bad[at][position]+1 if type(bad[at][position]) is int else 'unavailable';self.refuses(bad,args)
        bad=copy.deepcopy(rows);ss=[i for i,r in enumerate(bad) if r[0]=='SAMPLE'];a,b=ss[0],ss[-1];bad[a],bad[b]=bad[b],bad[a];self.refuses(bad,args)
        bad=copy.deepcopy(rows);bad.insert(first(bad,'COVERAGE')+1,bad.pop(first(bad,'SAMPLE')));self.refuses(bad,args)

    def test_zero_maximum_and_unavailable_precedence_are_lossless(self):
        rows,args=fixture(n=3)
        for start,end,a,b,kind,value in ((0,0,0,0,'value',0),((1<<64)-1,(1<<64)-1,(1<<32)-1,(1<<32)-1,'value',(1<<64)-1),((1<<64)-1,0,7,7,'unavailable',2),((1<<64)-1,0,7,8,'unavailable',1)):
            good=copy.deepcopy(rows)
            for row in good:
                if row[0]=='CALL':row[11:15]=[start,end,a,b]
                if row[0]=='SAMPLE':row[7:10]=[start,kind,value]
            result=check(good,args);self.assertEqual(result['raw'],encode(good));self.assertEqual(result['rows']['CALL'][0]['end_ticks'],end)
            for wrong in (0,3):
                bad=copy.deepcopy(good);sample=bad[first(bad,'SAMPLE')];sample[8:10]=['unavailable',wrong];self.refuses(bad,args)
        good=copy.deepcopy(rows);good[first(good,'IO')][1]=(1<<64)-1
        self.assertEqual(check(good,args)['rows']['IO'][0]['write_blocked'],(1<<64)-1)

    def test_coverage_and_terminal_conserve_all_rows(self):
        rows,args=fixture(n=4,count=13)
        for tag,positions in (('COVERAGE',range(1,9)),('DONE',range(3,19))):
            at=first(rows,tag)
            for position in positions:
                bad=copy.deepcopy(rows)
                bad[at][position]=bad[at][position]+1 if type(bad[at][position]) is int else 'syntax'
                self.refuses(bad,args)
        for n in range(1,5):
            count=min(2048,4096//n)
            rows,args=fixture(n=n,count=count,k=1000)
            result=check(rows,args);self.assertEqual(result['totals']['calls'],n*count)
            bad=copy.deepcopy(args);bad['records']+=(b'',);self.refuses(rows,bad)
        # Exact maximum rows: 4096 sampled calls, 2048 records, 520 generations
        # and four declared RETs per leaf. Numeric fixture, no admission claim.
        rows,args=fixture(n=2,count=2048,k=1000,arms=520,
                          prefixes=[1]*2000+[2]*2000+[3]*96)
        expanded=[]
        for row in rows:
            if row[0]=='LEAF':
                row[9]=4;args['table'][row[1]]['returns']=(0,17,23,47)
            if row[0]=='RET':
                expanded.append(['RET',row[1],0 if row[2]==17 else 23])
            if row[0]=='COVERAGE':row[7:9]=[4,10]
            expanded.append(row)
        result=check(expanded,args)
        self.assertEqual(len(result['ordered']),11296)
        self.assertEqual(result['totals']['sampled'],4096)

    def test_exact_stderr_expected_outcomes_and_hard_failures_remain_distinct(self):
        cases=[('eof','none'),('input_incomplete','none')]+[('input_error',e) for e in ('syntax','overlong','unterminated','record_limit')]
        for outcome,error in cases:
            count=1024 if error=='record_limit' else 2
            rows,args=fixture(n=4,count=count,outcome=outcome,error=error)
            actual=stderr_for(args);data=encode(rows);result=output.check(data,actual,**args)
            self.assertEqual(result['expected_exit'],0 if outcome=='eof' else 1)
            self.assertEqual(result['outcome'],outcome);self.assertEqual(result['input_error'],error)
            hard=b'normal-leaf-set-session FAILED: late; retirement pending\n'
            variants=[hard,actual+hard,hard+actual,actual+b'\n',b' '+actual,actual+b'\xff',bytearray(actual),actual.decode('ascii')]
            if actual:variants += [b'',actual[:-1],actual.replace(b'\n',b'\r\n')]
            for wrong in variants:
                with self.assertRaises((AssertionError,ValueError,UnicodeError)):output.check(data,wrong,**args)
            for other,why in cases:
                if (other,why)!=(outcome,error):self.refuses(rows,dict(args,outcome=other,input_error=why))
            bad=copy.deepcopy(rows);bad[-1][1]='FAILED';self.refuses(bad,args)
        rows,args=fixture(n=1,count=1,outcome='input_error',error='record_limit');self.refuses(rows,args)

    def test_framing_numeric_caps_and_optimization_refusal(self):
        rows,args=fixture(n=3)
        at=first(rows,'CALL')
        for value in ('','+1','-1','01',' 1','1 ',str(1<<64),'١'):
            bad=copy.deepcopy(rows);bad[at][1]=value
            data=('\n'.join(','.join(map(str,r)) for r in bad)+'\n').encode('utf-8')
            with self.assertRaises((AssertionError,ValueError,UnicodeError)):output.check(data,b'',**args)
        data=encode(rows)
        for bad in (b'',data[:-1],data+b'\n',data.replace(b'\n',b'\r\n'),data.replace(b'READY',b'\xffREADY',1),b'x'*(output.CAP+1),bytearray(data)):
            with self.assertRaises((AssertionError,ValueError,UnicodeError)):output.check(bad,b'',**args)
        self.assertEqual(output.framing(b'x'*349+b'\n',b'',b''),[['x'*349]])
        for bad in (b'x'*350+b'\n',b'x\n'*(output.MAX_LINES+1)):
            with self.assertRaises(AssertionError):output.framing(bad,b'',b'')
        for key,value in (('k',True),('epochs',0),('cpus',(2,2)),('records',list(args['records'])),('table',list(args['table']))):
            self.refuses(rows,dict(args,**{key:value}))
        for a,b in (((1<<64)-1,1),(-1,1),(True,1)):
            with self.assertRaises(AssertionError):output.add(a,b)
        self.assertEqual(output.add((1<<64)-2,1),(1<<64)-1)
        for name in ('output.py','controls.py'):
            child=subprocess.run([sys.executable,'-B','-O',str(Path(__file__).resolve().with_name(name))],capture_output=True,timeout=5)
            self.assertEqual(child.returncode,1);self.assertEqual(child.stdout,b'');self.assertEqual(child.stderr,b'assertions required\n')


if __name__ == '__main__':
    unittest.main()
