#!/usr/bin/env python3
"""Strict fixed-work back-off transcript, without native or timing authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import re

U64 = (1 << 64)-1
U32 = (1 << 32)-1
I32 = (1 << 31)-1
ROWS = 3072
MAX_OUTPUT = 906304
MAX_LINES = 4116
MAX_ROW = 272
MAX_SUMMARY = 64
COMMENT = '# normal observer backoff; complete fixed work and raw callback ticks; no timing, accuracy, cheap-off or 520-arm qualification'
HEADER = 'id,repetition,case,seed_index,length,input_fnv1a64,value,instructions,conditional,taken,input_bytes,ret_bytes,batch,owner,generation,invocation,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,ack,ack_ordinal,completed_sequence'
FIELDS = tuple(HEADER.split(','))
WORK = ('instructions', 'conditional', 'taken', 'input_bytes', 'ret_bytes')
KEYS = ('k', 'policy', 'epoch_limit', 'stop_reason', 'arms', 'committed_arms',
    'completed_arms', 'pending_arm', 'repetitions', 'calls', 'helper_calls',
    'instructions', 'conditional', 'taken', 'input_bytes', 'ret_bytes', 'pid',
    'tid', 'controller_tid', 'app_cpu', 'controller_cpu', 'entry', 'caller',
    'install', 'function', 'batches', 'events', 'rows', 'sampled', 'unsampled',
    'reports', 'records', 'actions', 'journal_words', 'next_entry_acknowledgements',
    'checkpoint_acknowledgements', 'banks', 'observed_generations', 'rearmed',
    'sampled_after_closed', 'input_unchanged', 'detached', 'joined', 'deadline_scope',
    'all_elapsed_due_arms', 'cheap_off', 'timing')
LITERALS = dict(policy='10ms-2ms', stop_reason='Requested', pending_arm='none',
    deadline_scope='issued-arms-and-requested-shutdown',
    all_elapsed_due_arms='unqualified', timing='none')
BOOLEANS = ('rearmed', 'sampled_after_closed', 'input_unchanged', 'detached', 'cheap_off')
FIXED = dict(epoch_limit=520, repetitions=128, calls=ROWS, helper_calls=1536,
    instructions=614400, conditional=99840, taken=96768, input_bytes=99840,
    ret_bytes=24576, install=1851943729, function=1, batches=128, events=6144,
    rows=ROWS, journal_words=65536, next_entry_acknowledgements=2944,
    checkpoint_acknowledgements=128, banks=3, joined=1)
UINT = re.compile(r'0|[1-9][0-9]{0,19}')
ASCII = re.compile(rb'[\x20-\x7e\n]+')
SCOPE = ('Complete fixed-work wire checks only; all raw callback endpoints and zero '
    'spans retained. No timer, performance, accuracy, cheap-off or full-A5 qualification. '
    'Requested stop does not prove every elapsed due arm was evaluated; absent '
    'closed/later-generation activity remains UNEXERCISED, not a missing row.')
SOURCE_ATTESTED = ('The wire does not contain the complete 512-word journals, Report '
    'payloads or history-chunk stream/range fields. Their full equality, actual '
    'ordinary CALL/RET, input/source/generated-byte/stack custody before checkpoints, '
    'actual singleton CPU/TID placement, detach, controller join and original deadline '
    'checks require authenticated producer execution. This checker only joins the '
    'exported rows and summaries; source/binary, process closure, reservation and '
    'external timer authority remain separate.')


def _uint(text):
    assert type(text) is str and UINT.fullmatch(text)
    value = int(text)
    assert value <= U64
    return value


def _cases():
    # Independent fixed-input/scalar/work algebra, never candidate observations.
    cases = []
    for seed in (0, 1):
        data = [(37*j+11+seed) % 256 for j in range(64)]
        digest = 14695981039346656037
        for byte in data:
            digest = ((digest ^ byte)*1099511628211) & U64
        for n in (1, 64):
            cases.append((seed, n, digest,
                sum(byte ^ 0x5a for byte in data[:n]) ^ 0x9e3779b97f4a7c15,
                6*n+5, n, n-1, n, 8))
    return tuple(cases)


def _terminal(line, k, app_cpu, controller_cpu):
    words = line.split(' ')
    assert words[:2] == ['normal-observer-backoff', 'FUNCTIONAL_PASS']
    assert len(words) == len(KEYS)+2
    result = {}
    for key, word in zip(KEYS, words[2:]):
        assert word.startswith(key+'=')
        value = word[len(key)+1:]
        if key in LITERALS:
            assert value == LITERALS[key]
            result[key] = value
        elif key in BOOLEANS:
            assert value in ('true', 'false')
            result[key] = value == 'true'
        else:
            result[key] = _uint(value)
    assert all(result[key] == value for key, value in FIXED.items())
    assert (result['k'], result['app_cpu'], result['controller_cpu']) == (k, app_cpu, controller_cpu)
    assert 0 < result['pid'] <= I32 and result['tid'] == result['pid']
    assert 0 < result['controller_tid'] <= I32 and result['controller_tid'] != result['tid']
    assert 0 < result['entry'] <= U64-37 and 0 < result['caller'] <= U64-67
    arms = result['arms']
    assert 1 <= arms <= 520
    assert result['committed_arms'] == result['completed_arms'] == result['reports'] == arms
    assert result['actions'] == arms+1 and result['rearmed'] == (arms > 1)
    assert result['sampled'] == result['records'] <= ROWS
    assert result['sampled']+result['unsampled'] == ROWS
    assert 1 <= result['observed_generations'] <= arms
    assert result['input_unchanged'] and result['detached'] and not result['cheap_off']
    return result


def check(stdout, stderr, k, app_cpu, controller_cpu):
    assert type(k) is int and k in (10, 1000)
    assert all(type(cpu) is int and 0 <= cpu <= 1023 for cpu in (app_cpu, controller_cpu))
    assert app_cpu != controller_cpu
    assert type(stdout) is bytes and 0 < len(stdout) <= MAX_OUTPUT
    assert type(stderr) is bytes and stderr == b''
    assert stdout.endswith(b'\n') and ASCII.fullmatch(stdout)
    lines = stdout[:-1].decode('ascii').split('\n')
    assert len(lines) <= MAX_LINES and lines[:2] == [COMMENT, HEADER]
    terminal = _terminal(lines[-1], k, app_cpu, controller_cpu)
    arms = terminal['arms']
    assert len(lines) == ROWS+4+2*arms
    assert sum(len(line)+1 for line in (lines[0], lines[1], lines[-1])) <= 4096
    row_lines = lines[2:2+ROWS]
    history_lines = lines[2+ROWS:3+ROWS+arms]
    report_lines = lines[3+ROWS+arms:-1]
    return _population(row_lines, history_lines, report_lines, terminal, k)


def _population(row_lines, history_lines, report_lines, terminal, k):
    arms = terminal['arms']
    history, generations = [], []
    for i, line in enumerate(history_lines, 1):
        assert len(line)+1 <= MAX_SUMMARY
        cells = line.split(',')
        assert len(cells) == 4 and cells[0] == 'HISTORY' and _uint(cells[1]) == i
        generation = _uint(cells[3])
        assert generation > 0
        if i <= arms:
            assert cells[2] == 'published'
            assert not generations or generation > generations[-1]
            generations.append(generation)
        else:
            assert cells[2] == 'removed' and generation == generations[-1]
        history.append(dict(index=i, kind=cells[2], generation=generation))
    cases = _cases()
    rows, counts, closed_counts = [], [0]*arms, [0]*arms
    sampled, previous_prefix, first_closed, sampled_after_closed = 0, 0, None, False
    for g, line in enumerate(row_lines):
        assert len(line)+1 <= MAX_ROW
        cells = line.split(',')
        assert len(cells) == len(FIELDS)
        owner = cells[13]
        assert owner in ('sampled', 'closed')
        row = {}
        for field, value in zip(FIELDS, cells):
            absent = (owner == 'closed' and field in ('invocation', 'completed_sequence')) or (
                field == 'ack_ordinal' and g % 24 == 23)
            if absent:
                assert value == ''
                row[field] = None
            elif field in ('owner', 'ack'):
                row[field] = value
            else:
                row[field] = _uint(value)
        assert tuple(row[field] for field in FIELDS[:12]) == (
            g+1, g//24+1, g % 24+1, *cases[(g % 8)//2])
        assert row['batch'] == g//24+1
        prefix = row['history_prefix']
        assert previous_prefix <= prefix <= arms and prefix >= 1
        previous_prefix = prefix
        at = prefix-1
        assert row['generation'] == generations[at]
        if owner == 'sampled':
            assert not closed_counts[at] and counts[at] < k
            assert row['invocation'] == counts[at] and row['completed_sequence'] == sampled
            counts[at] += 1
            sampled += 1
            sampled_after_closed |= first_closed is not None and prefix > first_closed
        else:
            assert counts[at] == k
            closed_counts[at] += 1
            if first_closed is None:
                first_closed = prefix
        rsp = row['entry_rsp']
        assert rsp % 16 == 8 and 128 <= rsp <= U64-8
        assert row['return_word'] == terminal['caller']+(30 if g % 2 == 0 else 48)
        if g % 2:
            assert rsp == rows[-1]['entry_rsp']
        assert row['start_ticks'] <= row['end_ticks']
        assert row['raw_ticks'] == row['end_ticks']-row['start_ticks']
        assert row['start_aux'] == row['end_aux'] <= U32
        assert row['ack'] == ('C' if g % 24 == 23 else 'N')
        assert row['ack_ordinal'] == (None if g % 24 == 23 else g+2)
        rows.append(row)
    reports = []
    for i, line in enumerate(report_lines, 1):
        assert len(line)+1 <= MAX_SUMMARY
        cells = line.split(',')
        assert len(cells) == 4 and cells[0] == 'REPORT'
        index, generation, count = map(_uint, cells[1:])
        assert (index, generation, count) == (i, generations[i-1], counts[i-1])
        assert count <= k
        reports.append(dict(index=index, generation=generation, records=count))
    observed = {row['generation'] for row in rows}
    assert terminal['sampled'] == sampled and terminal['unsampled'] == sum(closed_counts)
    assert terminal['observed_generations'] == len(observed)
    assert terminal['sampled_after_closed'] == sampled_after_closed
    totals = {field: sum(row[field] for row in rows) for field in WORK}
    assert totals == {field: terminal[field] for field in WORK}
    assert len({row['batch'] for row in rows}) == terminal['batches']
    assert sum(row['ack'] == 'N' for row in rows) == terminal['next_entry_acknowledgements']
    assert sum(row['ack'] == 'C' for row in rows) == terminal['checkpoint_acknowledgements']
    coverage = dict(
        published_but_unobserved=[generation for generation in generations if generation not in observed],
        sampled_generations=[generation for generation, n in zip(generations, counts) if n],
        closed_generations=[generation for generation, n in zip(generations, closed_counts) if n],
        function_closed='OBSERVED' if sum(closed_counts) else 'UNEXERCISED',
        later_generation_calls='OBSERVED' if any(row['history_prefix'] > 1 for row in rows) else 'UNEXERCISED',
        later_generation_samples='OBSERVED' if any(counts[1:]) else 'UNEXERCISED',
        sampled_after_closed='OBSERVED' if sampled_after_closed else 'UNEXERCISED')
    return dict(status='FUNCTIONAL_PASS', **{key: value for key, value in terminal.items() if key != 'rows'},
        terminal=terminal, row_count=terminal['rows'], totals=totals, rows=rows,
        history=history, reports_table=reports, coverage=coverage,
        table=(HEADER+'\n'+'\n'.join(row_lines)+'\n').encode('ascii'),
        history_table=('\n'.join(history_lines)+'\n').encode('ascii'),
        report_table=('\n'.join(report_lines)+'\n').encode('ascii'),
        zero_raw_spans=sum(row['raw_ticks'] == 0 for row in rows),
        scope=SCOPE, source_attested=SOURCE_ATTESTED)
