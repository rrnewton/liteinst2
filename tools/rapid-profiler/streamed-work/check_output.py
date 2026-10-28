"""Independent finite streamed joins; unexported journal/Report fields stay source-attested."""
import csv
import re
import sys

if sys.flags.optimize:
    raise RuntimeError('assertions required')

TRANSITIONS = 'action,index,generation,requested_ns,before_ns,after_ns'
CALLS = 'external_id,ordinal,length,owner,generation,invocation,before_ns,after_ns,value,pre_rsp,entry_rsp,resumed_rsp,start_ticks,end_ticks,start_aux,end_aux,entry_pc,return_pc'
BATCHES = 'number,raw_start,raw_end,event_start,event_end,sequence_start,sequence_end,next_ordinal,gate_sequence,entries,returns,sampled,removed'
RETIREMENT = 'epoch,generation,checkpoint_ordinal,retire_before_ns,retire_after_ns,stage_complete_ns,record_start,record_end'
REPORTS = 'generation,invocation,thread,start_sequence,entry_ticks,end_ticks,rank,children'


def number(value):
    assert re.fullmatch(r'0|[1-9][0-9]*', value)
    result = int(value)
    assert result < 2**64
    return result


def table(lines, header, count, strings=()):
    assert len(lines) == count + 1 and lines[0] == header
    keys = header.split(',')
    rows = list(csv.DictReader(lines, strict=True))
    assert len(rows) == count
    for line, row in zip(lines[1:], rows):
        assert set(row) == set(keys) and all(isinstance(v, str) for v in row.values())
        assert ','.join(row[k] for k in keys) == line
        for key in set(keys) - set(strings):
            row[key] = number(row[key])
    return rows


def parse(data):
    assert 0 < len(data) <= 1048576 and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').splitlines()
    terminal = re.fullmatch(
        r'streamed-work PASS originals=160 calls=160 entries=160 returns=160 sampled=([0-9]+) unsampled=([0-9]+) '
        r'epochs=20 slots=3 retired=20 replacements=17 batches=40 raw_rows=160 events=320 actions=40 reports=([0-9]+) '
        r'active_coverage=20 off_coverage=20 windowend_ns=([0-9]+) worker_cpu=([0-9]+) controller_cpu=([0-9]+) '
        r'input_unchanged=true detached=true joined=true', lines[-1])
    assert terminal is not None
    sampled, removed, reports, end, worker, controller = map(number, terminal.groups())
    assert 20 <= sampled <= 140 and removed == 160 - sampled and reports == sampled and worker != controller
    assert len(lines) == 272 + sampled
    assert [lines[i] for i in (0, 42, 204, 246, 268)] == ['# transitions', '# calls', '# batches', '# retirement', '# reports']
    transitions = table(lines[1:42], TRANSITIONS, 40, ('action',))
    calls = table(lines[43:204], CALLS, 160, ('owner', 'invocation'))
    batches = table(lines[205:246], BATCHES, 40)
    retired = table(lines[247:268], RETIREMENT, 20, ('stage_complete_ns',))
    observations = table(lines[269:-2], REPORTS, sampled)
    generations = [t['generation'] for t in transitions[::2]]
    assert 0 < generations[0] and all(a < b for a, b in zip(generations, generations[1:]))
    base = transitions[0]['after_ns']
    deadline = base + 2000000000
    assert deadline < 2**64 and base + 800000000 <= end < deadline
    for i, action in enumerate(transitions):
        requested = 0 if i == 0 else base + (40*(i//2) + (30 if i % 2 else 0))*1000000
        assert (action['action'], action['index'], action['generation'], action['requested_ns']) == (
            'arm' if i % 2 == 0 else 'disarm', i, generations[i//2], requested)
        assert requested <= action['before_ns'] <= action['after_ns'] <= end
        if i:
            assert transitions[i-1]['after_ns'] <= action['before_ns']
    counts, coverage, completed_at = [0]*20, [0]*40, [0]
    expected_reports, pcs = [], set()
    previous_binding = previous_end = 0
    for i, call in enumerate(calls):
        n = 1 if i % 2 == 0 else 64
        assert (call['external_id'], call['ordinal'], call['length']) == (1000+i, i+1, n)
        assert call['before_ns'] >= base + (40*(i//8) + (2, 7, 12, 17, 22, 27, 32, 37)[i%8])*1000000
        assert previous_end <= call['before_ns'] <= call['after_ns'] <= end
        previous_end = call['after_ns']
        assert call['value'] == sum((((j*37+11) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15
        assert 0 < call['entry_rsp'] and call['entry_rsp'] + 8 == call['pre_rsp'] == call['resumed_rsp']
        assert call['pre_rsp'] % 16 == 0 and 0 < call['entry_pc'] and call['return_pc'] == call['entry_pc'] + 36
        pcs.add((call['entry_pc'], call['return_pc']))
        assert call['start_ticks'] <= call['end_ticks'] and call['start_aux'] == call['end_aux'] < 2**32
        generation = call['generation']
        assert generation in generations and call['owner'] in ('sampled', 'removed')
        epoch = generations.index(generation)
        binding = 2*epoch + (call['owner'] == 'removed')
        assert previous_binding <= binding
        previous_binding = binding
        # Intersection of actual call/operation brackets, not a fabricated
        # admission timestamp. An old owner's return may cross removal.
        assert call['after_ns'] >= transitions[binding]['before_ns']
        if binding < 39:
            assert call['before_ns'] <= transitions[binding+1]['after_ns']
        for j, action in enumerate(transitions):
            window_end = transitions[j+1]['before_ns'] if j < 39 else end
            if action['after_ns'] < call['before_ns'] and call['after_ns'] < window_end:
                assert binding == j
                coverage[j] += 1
        if call['owner'] == 'sampled':
            invocation = number(call['invocation'])
            assert invocation == counts[epoch]
            expected_reports.append(dict(generation=generation, invocation=invocation, thread=1,
                start_sequence=len(expected_reports), entry_ticks=call['start_ticks'], end_ticks=call['end_ticks'], rank=invocation, children=0))
            counts[epoch] += 1
        else:
            assert call['invocation'] == ''
        completed_at.append(len(expected_reports))
    assert len(pcs) == 1 and completed_at[-1] == sampled and all(coverage)
    assert observations == expected_reports
    assert lines[-2] == (f'# actual whole-call coverage {coverage}; full journal pages checked in process, not exported; uncalibrated finite trial')
    gate_base = batches[0]['gate_sequence'] - 4
    assert gate_base >= 0
    for i, batch in enumerate(batches):
        start, stop = 4*i, 4*(i+1)
        assert batch == dict(number=i+1, raw_start=start, raw_end=stop, event_start=2*start, event_end=2*stop,
            sequence_start=completed_at[start], sequence_end=completed_at[stop], next_ordinal=stop+1, gate_sequence=gate_base+stop,
            entries=stop, returns=stop, sampled=completed_at[stop], removed=stop-completed_at[stop])
    record_end = previous_retire_end = 0
    for epoch, row in enumerate(retired):
        assert (row['epoch'], row['generation'], row['record_start'], row['record_end']) == (
            epoch, generations[epoch], record_end, record_end + counts[epoch])
        record_end = row['record_end']
        checkpoint = next((c for c in calls if c['before_ns'] > transitions[2*epoch+1]['after_ns']), None)
        assert checkpoint is not None and row['checkpoint_ordinal'] == checkpoint['ordinal']
        # Retirement sees only complete four-call packets. This checks the
        # exported clock ordering; the owned send/drain proof stays in Rust.
        packet_last = calls[4*((checkpoint['ordinal']-1)//4)+3]
        assert max(previous_retire_end, packet_last['after_ns']) <= row['retire_before_ns'] <= row['retire_after_ns'] <= end
        if epoch < 17:
            staged = number(row['stage_complete_ns'])
            assert row['retire_after_ns'] <= staged < base + (40*(epoch+3)-10)*1000000
            previous_retire_end = staged
        else:
            assert row['stage_complete_ns'] == ''
            previous_retire_end = row['retire_after_ns']
    assert record_end == sampled
    return dict(transitions=transitions, calls=calls, batches=batches, retirement=retired, reports=observations,
        sampled=sampled, unsampled=removed, coverage=coverage, generations=generations, gate_sequence_base=gate_base,
        windowend_ns=end, worker_cpu=worker, controller_cpu=controller,
        original_instructions=sum(6*c['length']+5 for c in calls), original_branches=sum(c['length'] for c in calls),
        original_taken=sum(c['length']-1 for c in calls), input_byte_reads=sum(c['length'] for c in calls), return_word_reads=160)
