"""Independent finite-population checks; Instant brackets are not admission times."""
import csv
import re

TRANSITIONS = 'action,index,generation,requested_ns,before_ns,after_ns'
CALLS = 'external_id,ordinal,length,owner,generation,invocation,before_ns,after_ns,value,pre_rsp,entry_rsp,resumed_rsp,start_ticks,end_ticks,start_aux,end_aux,entry_pc,return_pc'
REPORTS = 'generation,invocation,thread,start_sequence,entry_ticks,end_ticks,rank,children'


def number(value):
    assert re.fullmatch(r'0|[1-9][0-9]*', value)
    result = int(value)
    assert result < 2**64
    return result


def table(lines, header, count, strings=()):
    assert len(lines) == count + 1 and lines[0] == header
    rows = list(csv.DictReader(lines, strict=True))
    assert len(rows) == count
    for row in rows:
        assert set(row) == set(header.split(','))
        for key, value in row.items():
            assert isinstance(value, str)
            if key not in strings:
                row[key] = number(value)
    return rows


def parse(data):
    assert 0 < len(data) <= 1048576 and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').splitlines()
    terminal = re.fullmatch(
        r'timed-work PASS originals=24 calls=24 entries=24 returns=24 sampled=([0-9]+) unsampled=([0-9]+) '
        r'epochs=3 actions=6 raw_rows=24 reports=([0-9]+) active_coverage=3 off_coverage=3 windowend_ns=([0-9]+) '
        r'worker_cpu=([0-9]+) controller_cpu=([0-9]+) input_unchanged=true joined=true', lines[-1])
    assert terminal is not None
    sampled, unsampled, reports, end, worker, controller = map(number, terminal.groups())
    assert 3 <= sampled <= 21 and unsampled == 24 - sampled and reports == sampled
    assert worker != controller
    assert len(lines) == 37 + sampled
    assert [lines[i] for i in (0, 8, 34)] == ['# transitions', '# calls', '# reports']
    transitions = table(lines[1:8], TRANSITIONS, 6, ('action',))
    calls = table(lines[9:34], CALLS, 24, ('owner', 'invocation'))
    observations = table(lines[35:-1], REPORTS, sampled)
    base = transitions[0]['after_ns']
    deadline = base + 2000000000
    deadlines = [0] + [base + n * 1000000 for n in (30, 40, 70, 80, 110)]
    assert base + 120000000 <= end < deadline and end >= transitions[-1]['after_ns']
    for i, action in enumerate(transitions):
        assert (action['action'], action['index'], action['generation'], action['requested_ns']) == (
            'arm' if i % 2 == 0 else 'disarm', i, i // 2 + 1, deadlines[i])
        assert action['requested_ns'] <= action['before_ns'] <= action['after_ns'] < deadline
        if i:
            assert transitions[i-1]['after_ns'] <= action['before_ns']
    counts = [0, 0, 0]
    coverage = [0] * 6
    expected_reports = []
    previous_binding = 0
    previous_end = 0
    completed = 0
    pcs = set()
    for i, call in enumerate(calls):
        n = 1 if i % 2 == 0 else 64
        assert (call['external_id'], call['ordinal'], call['length']) == (1000+i, i+1, n)
        assert call['before_ns'] >= base + (40*(i//8) + (2, 7, 12, 17, 22, 27, 32, 37)[i%8])*1000000
        assert previous_end <= call['before_ns'] <= call['after_ns'] < deadline
        previous_end = call['after_ns']
        assert call['value'] == sum((((j*37+11) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15
        assert call['entry_rsp'] + 8 == call['pre_rsp'] == call['resumed_rsp'] and call['entry_rsp'] > 0
        assert call['pre_rsp'] % 16 == 0
        assert 0 < call['entry_pc'] and call['return_pc'] == call['entry_pc'] + 36
        pcs.add((call['entry_pc'], call['return_pc']))
        assert call['start_ticks'] <= call['end_ticks'] and call['start_aux'] == call['end_aux'] < 2**32
        generation = call['generation']
        assert generation in (1, 2, 3)
        assert call['owner'] in ('sampled', 'removed')
        binding = 2*(generation-1) + (call['owner'] == 'removed')
        assert binding >= previous_binding
        previous_binding = binding
        # A reservation occurred somewhere within the call and operation
        # brackets. This intersection does not identify its actual timestamp.
        assert call['after_ns'] >= transitions[binding]['before_ns']
        if binding < 5:
            assert call['before_ns'] <= transitions[binding+1]['after_ns']
        for j, action in enumerate(transitions):
            stable_end = transitions[j+1]['before_ns'] if j < 5 else end
            if action['after_ns'] < call['before_ns'] and call['after_ns'] < stable_end:
                assert binding == j
                coverage[j] += 1
        if call['owner'] == 'sampled':
            invocation = number(call['invocation'])
            assert invocation == counts[generation-1]
            expected_reports.append(dict(generation=generation, invocation=invocation, thread=1,
                start_sequence=completed, entry_ticks=call['start_ticks'], end_ticks=call['end_ticks'],
                rank=invocation, children=0))
            counts[generation-1] += 1
            completed += 1
        else:
            assert call['invocation'] == ''
    assert len(pcs) == 1 and completed == sampled and all(count > 0 for count in coverage)
    assert observations == expected_reports
    return dict(transitions=transitions, calls=calls, reports=observations, coverage=coverage,
        sampled=sampled, unsampled=unsampled, windowend_ns=end, worker_cpu=worker, controller_cpu=controller,
        original_instructions=4800, original_branches=780, original_taken=756, input_byte_reads=780)
