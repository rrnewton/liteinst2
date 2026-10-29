"""Fabricated numeric controls; none supplies native or owned-process authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('call_pair_output_controls_subject', HERE / 'output.py')
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)
U64 = (1 << 64) - 1
U32 = (1 << 32) - 1

# Independent fixture columns and literals, not imported from the checker.
COLUMNS = {
    'READY': 'profile K epoch_limit active_ms poll_lateness_ms payload_cap record_cap queue_cap registration install pid main_tid worker_tid main_cpu worker_cpu caller_entry'.split(),
    'FUNCTION': 'node function_id elf_va extent runtime_entry runtime_end declared_returns'.split(),
    'RET': 'node offset'.split(),
    'EDGE': 'call_pc child_entry continuation child_stack_delta'.split(),
    'HISTORY': 'batch_number absolute_prefix_1 kind generation'.split(),
    'REPORT': 'generation rows'.split(),
    'CALL': 'id node function_id ordinal parent_ordinal owner generation invocation_1 history_prefix sequence_before actual_children has_sampled_children sampled_children_or_zero acknowledgement rank_1_or_zero'.split(),
    'RAW': 'id node entry_pc return_pc entry_rsp return_word resume_pc resume_rsp value start_ticks end_ticks start_aux end_aux'.split(),
    'RESULT': 'id length fnv1a64 packed_result expected_fields parent_ordinal child_ordinal'.split(),
    'SAMPLE': 'id node function_id generation invocation_0 rank_0 start_sequence entry_ticks thread completed_children observation_kind observation_value'.split(),
    'COVERAGE': 'node sampled function_closed removed initial observed_ret_mask declared_ret_mask'.split(),
    'IO': ['write_blocked_count'],
    'DONE': 'input_status stop_reason arms history_end accepted entered ret_observed confirmed completed unsampled roots child_acks batches field_sum byte_sum observed_eof input_error input_complete'.split(),
}


def checksum(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value ^= byte
        value *= 0x100000001b3
        value %= 1 << 64
    return value


def fixture(records=((b'a,b', 2),), *, k=10, epochs=3, arms=None, prefixes=None,
            generation_ids=None, outcome='eof', error='none', eof=None, report_order=None,
            ticks=None, four_rets=False, reverse_va=False):
    """Owned synthetic values only; caller/body coordinates do not admit machine bytes."""
    if arms is None:
        arms = epochs
    if generation_ids is None:
        generation_ids = [11 + 7*i for i in range(arms)]
    assert len(generation_ids) == arms
    parent_va, child_va = (0x2040, 0x2000) if reverse_va else (0x2000, 0x2040)
    parent = dict(length=16, elf_va=parent_va, heads=[0, 4, 9, 12, 15], returns=[15], edges=4,
                  call_offset=4, continuation_offset=9, child_delta=32, callee_entry=child_va, body_hex='00'*16)
    child = dict(length=24, elf_va=child_va, heads=[0, 3, 6, 9, 12, 15, 18, 21, 23],
                 returns=[15, 18, 21, 23] if four_rets else [21, 23], edges=9)
    caller = dict(length=20, elf_va=0x1000, heads=[0, 4, 7, 10, 13, 16, 19], call_offset=7,
                  continuation_offset=10, outer_ret_offset=19, subject_rsp_delta=32, lowest_stack=24, body_hex='00'*20)
    args = dict(records=tuple(x for x, _ in records), k=k, epochs=epochs, outcome=outcome,
                input_error=error, geometry=dict(parent=parent, child=child), caller=caller, cpus=(2, 3))
    rows = []

    def emit(name, *values):
        assert len(values) == len(COLUMNS[name])
        rows.append([name, *values])

    emit('READY', 'normal-call-pair-session-v1', k, epochs, 10, 2, 64, 2048, 4, 1, 0x63700001,
         100, 100, 101, 2, 3, 0x401000)
    entries = [0x500000+parent_va, 0x500000+child_va]
    for node, body in enumerate((parent, child)):
        emit('FUNCTION', node, 501+node, body['elf_va'], body['length'], entries[node], entries[node]+body['length'], len(body['returns']))
        for ret in body['returns']:
            emit('RET', node, ret)
    emit('EDGE', entries[0]+4, entries[1], entries[0]+9, 32)
    emitted_history = 0

    def history_to(end):
        nonlocal emitted_history
        while emitted_history < end:
            emitted_history += 1
            published = emitted_history <= arms
            generation = generation_ids[emitted_history-1] if published else generation_ids[-1]
            emit('HISTORY', emitted_history, emitted_history, 'published' if published else 'removed', generation)

    slots = {g: 0 for g in generation_ids}
    ranks = {g: [0, 0] for g in generation_ids}
    samples = {g: [] for g in generation_ids}
    coverage = [[0, 0, 0, 0] for _ in range(2)]
    masks = [0, 0]
    completed = 0
    for root, (data, fields) in enumerate(records, 1):
        pref = prefixes[root-1] if prefixes is not None else (min((root-1)//k + 1, arms),)*2
        history_to(max(pref))
        owners = []
        for node, prefix in enumerate(pref):
            if prefix == 0:
                owner, g = 'initial', 0
            elif prefix == arms+1:
                owner, g = 'removed', generation_ids[-1]
            else:
                g = generation_ids[prefix-1]
                owner = 'sampled' if ranks[g][node] < k else 'closed'
            owners.append((owner, g))
        for node, ((owner, g), prefix) in enumerate(zip(owners, pref)):
            sampled = owner == 'sampled'
            slot = slots[g] if sampled else None
            rank = ranks[g][node] if sampled else None
            if sampled:
                slots[g] += 1
                ranks[g][node] += 1
            sampled_children = int(node == 0 and owners[1][0] == 'sampled') if sampled else 0
            ordinal = 2*root-1+node
            emit('CALL', root, node, 501+node, ordinal, 2*root-1, owner, g,
                 slot+1 if sampled else 0, prefix, completed, 1-node, int(sampled), sampled_children,
                 'checkpoint' if node == 0 else 'continuation', rank+1 if sampled else 0)
            body = (parent, child)[node]
            ret_index = (root-1) % len(body['returns'])
            ret = body['returns'][ret_index]
            rsp = 0x800008 - node*32
            word = 0x40100a if node == 0 else entries[0]+9
            start, end, start_aux, end_aux = ticks[root-1][node] if ticks is not None else (100*root+node, 100*root+node+9, 3, 3)
            emit('RAW', root, node, entries[node], entries[node]+ret, rsp, word, word, rsp+8,
                 (len(data) << 32)|fields if node == 0 else fields, start, end, start_aux, end_aux)
            coverage[node][('sampled', 'closed', 'removed', 'initial').index(owner)] += 1
            masks[node] |= 1 << ret_index
            if sampled:
                observation = ('unavailable', 1) if start_aux != end_aux else ('unavailable', 2) if end < start else ('value', end)
                samples[g].append([root, node, 501+node, g, slot, rank, completed, start, 1, sampled_children, *observation])
        completed += sum(owner == 'sampled' for owner, _ in owners)
        emit('RESULT', root, len(data), checksum(data), (len(data) << 32)|fields, fields, 2*root-1, 2*root)
    history_to(arms+1)
    early_reports = report_order is None and arms > 3
    if report_order is None:
        report_order = list(generation_ids) if early_reports else list(reversed(generation_ids))
    for g in report_order:
        emit('REPORT', g, slots[g])
    for g in report_order:
        for sample in samples[g]:
            emit('SAMPLE', *sample)
    for node, body in enumerate((parent, child)):
        emit('COVERAGE', node, *coverage[node], masks[node], (1 << len(body['returns']))-1)
    emit('IO', 0)
    if eof is None:
        eof = int(outcome == 'eof' or error == 'unterminated')
    emit('DONE', {'eof': 'COMPLETE', 'input_error': 'INPUT_REFUSED', 'input_incomplete': 'INPUT_INCOMPLETE'}[outcome],
         'EpochLimit' if outcome == 'input_incomplete' else 'Requested', arms, arms+1, len(records),
         2*len(records), 2*len(records), 2*len(records), completed, 2*len(records)-completed,
         len(records), len(records), len(records), sum(f for _, f in records), sum(len(d) for d, _ in records),
         eof, error, int(outcome == 'eof'))
    stderr = b'' if outcome == 'eof' else b'normal-call-pair-session INPUT_INCOMPLETE\n' if outcome == 'input_incomplete' else f'normal-call-pair-session INPUT_REFUSED: {error}\n'.encode()
    if early_reports:
        # Final immutable counts are known to this fabricated fixture. Copy each
        # old Report after replacement, so the E3 wire never needs 4 live banks.
        retained = {r[1]:r for r in rows if r[0]=='REPORT'}
        ordered = []
        current = None
        for row in rows:
            if row[0]=='REPORT':
                continue
            ordered.append(row)
            if row[0]=='HISTORY':
                if current is not None:
                    ordered.append(retained.pop(current))
                current = row[4] if row[3]=='published' else None
        assert not retained
        rows = ordered
    return rows, stderr, args


def encode(rows):
    return b''.join((','.join(map(str, row))+'\n').encode('ascii') for row in rows)


def change(rows, family, key, value, occurrence=0):
    rows = copy.deepcopy(rows)
    candidates = [r for r in rows if r[0] == family]
    candidates[occurrence][COLUMNS[family].index(key)+1] = value
    return rows


class Controls(unittest.TestCase):
    def accept(self, data):
        rows, stderr, args = data
        return subject.check(encode(rows), stderr, **args)

    def reject(self, rows, stderr, args):
        with self.assertRaises((AssertionError, KeyError, IndexError, TypeError, ValueError)):
            subject.check(encode(rows), stderr, **args)

    def test_complete_empty_one_and_nested_populations(self):
        for records in ((), ((b'', 1),), ((b'a,b', 2), (b'"a""b",c', 2), (b',,', 3))):
            data = fixture(records)
            result = self.accept(data)
            self.assertEqual(result['status'], 'CALL_PAIR_SESSION_FUNCTIONAL_PASS')
            self.assertEqual(result['expected_exit'], 0)
            self.assertEqual(len(result['rows']['CALL']), 2*len(records))
            self.assertEqual(result['totals']['roots'], len(records))
            self.assertEqual(result['results'], [dict(id=i+1, length=len(d), fnv=checksum(d), fields=f, packed=(len(d)<<32)|f) for i, (d, f) in enumerate(records)])
            for name in COLUMNS:
                self.assertEqual(result['tables'][name], encode([r for r in data[0] if r[0] == name]))
        corpus = ((b'',1),(b'a',1),(b'a,b,c',3),(b',',2),(b',,',3),(b'a,',2),(b',a',2),
            (b'""',1),(b'"a,b"',1),(b'"a","b"',2),(b'a,"b,c",d',3),(b'"a""b",c',2),
            (b'""""',1),(b'"",""',2),(b'plain,"say ""hi""",,tail',4),(b'"comma,, and ""quote""",last,',3))
        self.assertEqual([r['fields'] for r in self.accept(fixture(corpus))['results']], [f for _,f in corpus])
        maximum = fixture(((b','*64, 65),)*2048, k=1000, epochs=520, four_rets=True)
        result = self.accept(maximum)
        self.assertEqual(len(maximum[0]), 15390)
        self.assertLessEqual(len(encode(maximum[0])), 4194304)
        self.assertEqual((len(result['rows']['SAMPLE']), len(result['rows']['REPORT']), result['totals']['history_end']), (4096, 520, 521))
        self.assertEqual(result['totals']['field_sum'], 2048*65)
        self.assertEqual(result['totals']['byte_sum'], 2048*64)
        self.assertEqual(result['rows']['CALL'][-1]['invocation_1'], 96)
        self.assertEqual(result['rows']['SAMPLE'][-1]['invocation_0'], 95)

    def test_exact_profile_function_edge_ret_and_caller_identity(self):
        self.accept(fixture(reverse_va=True))  # Roles are not VA-sort positions.
        rows, err, args = fixture()
        mutations = [('READY','profile','normal-leaf-set-session-v1',0), ('READY','K',1000,0),
            ('READY','install',0,0), ('READY','registration',2,0), ('READY','worker_tid',100,0),
            ('READY','main_tid',102,0), ('READY','main_cpu',3,0), ('READY','caller_entry',0x401001,0),
            ('FUNCTION','function_id',502,0), ('FUNCTION','runtime_end',0x502011,0),
            ('FUNCTION','runtime_entry',0x503040,1), ('RET','offset',22,1),
            ('EDGE','continuation',0x50200a,0), ('EDGE','child_stack_delta',16,0)]
        for family, key, value, occurrence in mutations:
            self.reject(change(rows, family, key, value, occurrence), err, args)
        for location, key, value in [('parent','callee_entry',0), ('parent','call_offset',3),
                ('parent','length',81), ('child','length',257), ('child','elf_va',0x9000),
                ('child','returns',[21,21]), ('child','heads',[0,23])]:
            changed = copy.deepcopy(args); changed['geometry'][location][key] = value
            self.reject(rows, err, changed)
        for key, value in [('continuation_offset',11), ('outer_ret_offset',18), ('lowest_stack',257), ('elf_va',0x1001)]:
            changed = copy.deepcopy(args); changed['caller'][key] = value
            self.reject(rows, err, changed)
        # Coherent translated wire still has to match independently admitted source coordinates.
        changed = copy.deepcopy(rows)
        for r in changed:
            if r[0] == 'FUNCTION':
                for key in ('elf_va', 'runtime_entry', 'runtime_end'):
                    r[COLUMNS['FUNCTION'].index(key)+1] += 4096
        self.reject(changed, err, args)

    def test_all_wire_families_order_cardinality_and_canonical_domains(self):
        rows, err, args = fixture(((b'a',1),(b'b',1)))
        for family in COLUMNS:
            at = next(i for i, r in enumerate(rows) if r[0] == family)
            self.reject(rows[:at]+rows[at+1:], err, args)
            self.reject(rows[:at]+[rows[at]]+rows[at:], err, args)
        for family in ('CALL', 'RAW', 'RESULT', 'SAMPLE', 'COVERAGE'):
            positions = [i for i,r in enumerate(rows) if r[0] == family]
            changed = copy.deepcopy(rows)
            changed[positions[0]], changed[positions[-1]] = changed[positions[-1]], changed[positions[0]]
            self.reject(changed, err, args)
        for word in ('', '00', '+1', '-1', ' 1', '1 ', '1.0', '1e0', str(1<<64)):
            self.reject(change(rows,'CALL','id',word), err, args)
        self.reject(change(rows,'RAW','start_aux',1<<32),err,args)
        self.reject(change(rows,'READY','pid',1<<32),err,args)
        wrapped=change(change(rows,'RAW','entry_rsp',U64-7),'RAW','resume_rsp',0)
        self.reject(wrapped,err,args)
        self.reject(change(rows,'READY','caller_entry',U64-15),err,args)
        self.reject(change(rows,'RAW','entry_rsp',408),err,args)
        for key in ('k','epochs'):
            bad = dict(args); bad[key] = True
            self.reject(rows,err,bad)
        bad = dict(args, cpus=(2, True)); self.reject(rows,err,bad)

    def test_each_frame_generation_global_slot_and_local_rank(self):
        rows, err, args = fixture(((b'a',1),(b'b',1)), prefixes=[(1,2),(2,2)])
        result = self.accept((rows,err,args))
        self.assertEqual(result['coverage']['cross_generation_roots'],1)
        self.assertEqual([r['invocation_1'] for r in result['rows']['CALL']], [1,1,2,3])
        self.assertEqual([r['rank_1_or_zero'] for r in result['rows']['CALL']], [1,1,1,2])
        for key in ('generation','invocation_1','rank_1_or_zero','history_prefix','ordinal','function_id'):
            original = [r for r in rows if r[0]=='CALL'][1][COLUMNS['CALL'].index(key)+1]
            self.reject(change(rows,'CALL',key,original+1,1),err,args)
        # Coherently shifting both representations cannot evade exact slot/rank bases.
        for call_key, sample_key in [('invocation_1','invocation_0'),('rank_1_or_zero','rank_0')]:
            bad = copy.deepcopy(rows)
            for r in bad:
                if r[0] == 'CALL' and r[6] == 'sampled':
                    r[COLUMNS['CALL'].index(call_key)+1] += 1
                if r[0] == 'SAMPLE':
                    r[COLUMNS['SAMPLE'].index(sample_key)+1] += 1
            self.reject(bad,err,args)
        bad = copy.deepcopy(rows)
        for r in bad:
            if r[0] in ('CALL','SAMPLE'):
                r[COLUMNS[r[0]].index('function_id')+1] = 501
        self.reject(bad,err,args)

    def test_child_ack_lifo_sequences_and_actual_sampled_children(self):
        rows, err, args = fixture(((b'a,b',2),(b'',1)))
        result = self.accept((rows,err,args))
        self.assertEqual([r['sequence_before'] for r in result['rows']['CALL']], [0,0,2,2])
        self.assertEqual([r['sampled_children_or_zero'] for r in result['rows']['CALL']], [1,0,1,0])
        for family,key,value,occ in [('CALL','acknowledgement','checkpoint',1),('CALL','actual_children',0,0),
                ('CALL','actual_children',1,1),('CALL','sampled_children_or_zero',0,0),
                ('CALL','has_sampled_children',0,1),('CALL','sequence_before',1,1),
                ('RAW','entry_rsp',0x800008,1),('RAW','resume_rsp',0x800000,1),
                ('RAW','return_word',0x40100a,1),('RAW','resume_pc',0x50200a,1),
                ('RAW','value',1,1),('RAW','value',2,0),('RESULT','child_ordinal',1,0)]:
            self.reject(change(rows,family,key,value,occ),err,args)
        bad=copy.deepcopy(rows)
        for r in bad:
            if r[0] in ('CALL','SAMPLE') and r[2] == 1:
                key = 'sequence_before' if r[0]=='CALL' else 'start_sequence'
                r[COLUMNS[r[0]].index(key)+1] += 1
        self.reject(bad,err,args)
        for key in ('roots','child_acks','batches','confirmed','completed','unsampled'):
            self.reject(change(rows,'DONE',key,999),err,args)

    def test_report_invocation_slots_and_payload_children_are_independent(self):
        rows, err, args = fixture(((b'a,b',2),(b'c,d',2)), arms=1)
        result = self.accept((rows,err,args))
        self.assertEqual([r['invocation_0'] for r in result['rows']['SAMPLE']],[0,1,2,3])
        self.assertEqual([r['completed_children'] for r in result['rows']['SAMPLE']],[1,0,1,0])
        self.assertEqual([r['value'] for r in result['rows']['RAW']],[3*(1<<32)+2,2]*2)
        for key, value in [('invocation_0',1),('completed_children',0),('thread',101),('observation_value',0),('entry_ticks',0)]:
            self.reject(change(rows,'SAMPLE',key,value),err,args)
        for occurrence in (0,2,3):
            self.reject(change(rows,'SAMPLE','completed_children',occurrence,occurrence),err,args)
        bad = copy.deepcopy(rows)
        for r in bad:
            if r[0] == 'SAMPLE':
                r[COLUMNS['SAMPLE'].index('completed_children')+1] = r[COLUMNS['SAMPLE'].index('invocation_0')+1]
        self.reject(bad,err,args)
        self.reject(change(rows,'REPORT','rows',3),err,args)
        # A Report may precede the retained application batch: no readiness-at-checkpoint inference.
        report = next(r for r in rows if r[0]=='REPORT')
        moved = [r for r in rows if r is not report]
        first = next(i for i,r in enumerate(moved) if r[0]=='CALL')
        removal = next(r for r in moved if r[0]=='HISTORY' and r[3]=='removed')
        moved.remove(removal); moved.insert(first,removal); moved.insert(first+1,report)
        self.accept((moved,err,args))

    def test_closed_removed_initial_and_history_report_bijections(self):
        closed = fixture(((b'x',1),)*11,k=10,epochs=1)
        result = self.accept(closed)
        self.assertEqual(result['rows']['CALL'][-1]['owner'],'closed')
        self.assertEqual(result['coverage']['nodes'][0]['exhausted_generations'],[11])
        rows, err, args = closed
        self.reject(change(rows,'CALL','owner','closed',0),err,args)
        self.reject(change(rows,'CALL','rank_1_or_zero',1,20),err,args)
        split = fixture(((b'a',1),)*11, epochs=2, prefixes=[(1,1)]*10+[(1,2)])
        split_checked = self.accept(split)
        self.assertEqual([r['owner'] for r in split_checked['rows']['CALL'][-2:]], ['closed','sampled'])
        self.assertEqual([r['sampled_children_or_zero'] for r in split_checked['rows']['CALL'][-2:]], [0,0])
        self.assertEqual(split_checked['rows']['CALL'][-1]['invocation_1'], 1)
        self.reject(change(split[0],'CALL','sampled_children_or_zero',1,20),split[1],split[2])
        mixed = fixture(((b'a',1),)*3, epochs=1, prefixes=[(0,0),(1,1),(1,2)])
        checked = self.accept(mixed)
        self.assertEqual(checked['coverage']['removed_child_roots'],1)
        self.assertEqual([r['owner'] for r in checked['rows']['CALL']],['initial','initial','sampled','sampled','sampled','removed'])
        rows,err,args=mixed
        for family,key,value,occ in [('CALL','generation',11,0),('CALL','history_prefix',1,0),
                ('CALL','generation',0,5),('CALL','owner','closed',5),
                ('HISTORY','generation',12,1),('HISTORY','absolute_prefix_1',3,1),
                ('HISTORY','batch_number',3,1),('REPORT','generation',12,0)]:
            self.reject(change(rows,family,key,value,occ),err,args)
        rows,err,args=fixture((),epochs=520)
        self.assertEqual(len(self.accept((rows,err,args))['rows']['REPORT']),520)
        self.reject(change(rows,'REPORT','rows',1,100),err,args)
        self.reject(change(rows,'HISTORY','generation',11,1),err,args)
        late = fixture(((b'a',1),),epochs=520,prefixes=[(513,513)])
        self.assertEqual([r['history_prefix'] for r in self.accept(late)['rows']['CALL']], [513,513])
        reports=[r for r in rows if r[0]=='REPORT']
        no_reports=[r for r in rows if r[0]!='REPORT']
        before_tail=next(i for i,r in enumerate(no_reports) if r[0]=='COVERAGE')
        self.reject(no_reports[:before_tail]+reports+no_reports[before_tail:],err,args)
        # Reopening after the terminal Removed is forbidden even with all publications retained.
        bad=copy.deepcopy(rows); hist=[i for i,r in enumerate(bad) if r[0]=='HISTORY']
        bad[hist[-1]],bad[hist[-2]]=bad[hist[-2]],bad[hist[-1]]
        self.reject(bad,err,args)

    def test_zero_maximum_unavailable_and_unexercised_coverage(self):
        ticks=[((0,0,0,0),(U64,0,U32,0)),((U64,0,U32,U32),(0,U64,U32,U32))]
        rows,err,args=fixture(((b'',1),(b'a',1)),ticks=ticks,generation_ids=[U64-2,U64-1,U64])
        result=self.accept((rows,err,args))
        self.assertEqual(result['coverage']['sampled_aux_mismatch'],1)
        self.assertEqual(result['coverage']['sampled_clock_regression'],1)
        self.assertEqual(result['coverage']['sampled_zero_tick_endpoints'],5)
        self.assertIn('closed',result['coverage']['nodes'][0]['unexercised_owners'])
        self.assertEqual(result['rows']['RAW'][1]['start_ticks'],U64)
        self.assertEqual(result['rows']['RAW'][1]['start_aux'],U32)
        samples=[r for r in rows if r[0]=='SAMPLE']
        aux = next(i for i,r in enumerate(samples) if (r[1],r[2])==(1,1))
        self.reject(change(rows,'SAMPLE','observation_value',2,aux),err,args)
        self.reject(change(rows,'SAMPLE','observation_kind','value',aux),err,args)
        self.reject(change(rows,'COVERAGE','observed_ret_mask',0),err,args)
        self.reject(change(rows,'COVERAGE','declared_ret_mask',3),err,args)
        for value in (0,U64):
            retained=self.accept((change(rows,'IO','write_blocked_count',value),err,args))
            self.assertEqual(retained['rows']['IO'][0]['write_blocked_count'],value)
        for key in ('start_aux','end_aux'):
            self.reject(change(rows,'RAW',key,U32+1),err,args)

    def test_typed_refusal_incomplete_and_accepted_prefix_are_distinct(self):
        records=((b'a,b',2),(b'',1),(b'"x,y"',1))
        for error in ('syntax','overlong','unterminated','record_limit'):
            accepted=(((b'a',1),)*2048 if error=='record_limit' else records)
            for eof in ((1,) if error=='unterminated' else (0,)):
                rows,err,args=fixture(accepted,k=1000,outcome='input_error',error=error,eof=eof)
                checked=self.accept((rows,err,args))
                self.assertEqual(checked['expected_exit'],1)
                self.assertEqual(checked['totals']['accepted'],len(accepted))
                self.reject(change(rows,'DONE','input_complete',1),err,args)
                self.reject(change(rows,'DONE','observed_eof',1-eof),err,args)
                if error!='record_limit':
                    self.reject(rows,err,dict(args,records=args['records'][:-1]))
        rows,err,args=fixture(records,outcome='input_incomplete')
        self.assertEqual(self.accept((rows,err,args))['expected_exit'],1)
        for key,value in [('observed_eof',1),('stop_reason','Requested'),('arms',2),('input_status','COMPLETE')]:
            self.reject(change(rows,'DONE',key,value),err,args)
        self.reject(rows,err,dict(args,outcome='eof'))
        rows,err,args=fixture(((b'a,b',2),))
        self.reject(rows,err,dict(args,records=(b'z,b',)))
        for invalid in (b'"unterminated',b'a"b',b'"a"z',b'\x00',b'\x7f',b'\n',b'a'*65):
            self.reject(rows,err,dict(args,records=(invalid,)))
        # Independently accepted bytes, not same-length/same-field-count data or a supplied field count.
        self.reject(rows,err,dict(args,records=((b'a,b',2),)))
        self.reject(change(rows,'RESULT','fnv1a64',checksum(b'z,b')),err,args)

    def test_caps_stderr_completion_and_optimized_import_refuse(self):
        rows,err,args=fixture()
        wire=encode(rows)
        for data in (b'',wire[:-1],wire+b'\n',wire.replace(b'\n',b'\r\n'),wire+b'EXTRA,1\n',
                b'X'*350+b'\n',b'X'*4194304+b'\n'):
            with self.assertRaises((AssertionError,KeyError,ValueError)):
                subject.check(data,err,**args)
        for byte in range(256):
            if byte==10 or 32<=byte<127:
                continue
            with self.assertRaises(AssertionError):
                subject.check(wire.replace(b'READY',bytes([byte])+b'READY',1),err,**args)
        for extra in (b'x',b'\n',b'normal-call-pair-session INPUT_INCOMPLETE\n'):
            self.reject(rows,extra,args)
        self.reject(change(rows,'DONE','entered',0),err,args)
        # Both lines have the actual DONE field count, enums and canonical u64s;
        # only the 350/351-byte frame differs. This is not a complete transcript.
        values={key:U64 for key in COLUMNS['DONE']}
        values.update(input_status='INPUT_INCOMPLETE',stop_reason='EpochLimit',input_error='record_limit',arms=111111111)
        line=encode([['DONE',*(values[key] for key in COLUMNS['DONE'])]])
        self.assertEqual(len(line),350)
        self.assertEqual(subject.framing(line,0,1)[1]['DONE'][0],values)
        values['arms']=1111111111
        line=encode([['DONE',*(values[key] for key in COLUMNS['DONE'])]])
        self.assertEqual(len(line),351)
        with self.assertRaises(AssertionError):
            subject.framing(line,0,1)
        for file in ('output.py','controls.py'):
            result=subprocess.run([sys.executable,'-O',str(HERE/file)],capture_output=True,timeout=5,check=False)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'assertions required',result.stderr)
        scratch = HERE.parents[1] / 'target' / 'evaluation'
        self.assertTrue(scratch.is_dir())
        self.assertEqual(scratch.resolve(strict=True), scratch)
        with tempfile.TemporaryDirectory(prefix='call-pair-output-controls-', dir=scratch) as tmp:
            Path(tmp,'output.py').write_text('raise RuntimeError("foreign import")\n')
            code='import runpy; d=runpy.run_path('+repr(str(HERE/'controls.py'))+'); print(d["subject"].__file__)'
            result=subprocess.run([sys.executable,'-c',code],cwd=tmp,capture_output=True,timeout=5,check=False)
            self.assertEqual(result.returncode,0)
            self.assertEqual(Path(result.stdout.decode().strip()),HERE/'output.py')


if __name__ == '__main__':
    unittest.main()
