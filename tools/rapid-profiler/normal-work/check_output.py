#!/usr/bin/env python3
"""Strict finite normal-caller functional population; no native-state credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import csv
import re

HEADER = 'ordinal,case,bound,value,owner,generation,invocation,history_prefix,ret_offset,caller_continuation,ack,start_ticks,end_ticks,start_aux,end_aux'
TERMINAL = 'normal-work complete original_calls=8 installed_calls=8 caller_sites=2 next_entry_acknowledgements=7 checkpoint_acknowledgements=1 sampled=4 closed=2 removed=2 generations=2 events=16 journal_words=512 reports=2 worker_joins=1'
# The established immutable production-strnlen input cohort, kept in source order.
CASES = (
    ('zero-bound', 0, 0), ('single-empty', 1, 0), ('single-nonzero', 1, 1),
    ('last-of-two', 2, 1), ('interior', 17, 8), ('long-empty', 64, 0),
    ('long-last', 64, 63), ('full-bound', 64, 64),
)
SEEDS = (0x1234567887654320, 0xFEDCBA9801234567)
STATE_HEADER = 'mode,seed,case,bound,status,children,comparisons,visits0,visits1,original_steps,candidate_steps,value0,value1,outer_value,input_reads0,input_reads1,input_bytes0,input_bytes1,ret_offset0,ret_offset1,target_calls,target_returns,outer_returns,normal_reaps,helper_joins'
DROP = 'normal-drop complete owner={} original_calls=8 installed_calls=2 entered=2 ret_observed=2 confirmed=1 completed=1 unsampled=0 checkpoints=0 reattach_refusals=1 pending_after_tls_exit=1 worker_joins=1\n'


def number(word):
    assert isinstance(word, str) and re.fullmatch(r'0|[1-9][0-9]*', word)
    n = int(word)
    assert n < 2**64
    return n


def functional(data):
    assert isinstance(data, bytes) and 0 < len(data) < 65536
    assert data.endswith(b'\n') and b'\r' not in data
    assert all(byte == 10 or 32 <= byte <= 126 for byte in data)
    lines = data[:-1].decode('ascii').split('\n')
    assert len(lines) == 10 and lines[0] == HEADER and lines[-1] == TERMINAL
    rows = list(csv.DictReader(lines[:-1], strict=True))
    assert len(rows) == 8
    text = {'case', 'owner', 'invocation', 'ack'}
    for row in rows:
        assert set(row) == set(HEADER.split(','))
        for key in set(row) - text:
            row[key] = number(row[key])
    generations = (rows[0]['generation'], rows[2]['generation'])
    assert 0 < generations[0] < generations[1]
    for i, (row, (name, bound, value)) in enumerate(zip(rows, CASES)):
        assert (row['ordinal'], row['case'], row['bound'], row['value']) == (i+1, name, bound, value)
        expected = ('sampled', generations[i//2], str(i % 2)) if i < 4 else (
            'closed' if i < 6 else 'removed', generations[1], '')
        assert (row['owner'], row['generation'], row['invocation']) == expected
        assert row['history_prefix'] == (1 if i < 2 else 3 if i < 6 else 4)
        assert 0 < row['ret_offset'] < 80
        assert row['caller_continuation'] == (30, 48)[i % 2]
        assert row['ack'] == ('checkpoint' if i == 7 else 'next-entry')
        assert row['start_aux'] == row['end_aux'] < 2**32
        assert row['end_ticks'] >= row['start_ticks']
    # The empty/found path and the nonempty bound-exhausted path use different
    # RETs in this fixed optimized body. Exact offsets and actual instruction
    # paths remain native-validator work; neither path can disappear here.
    assert len({r['ret_offset'] for r in rows}) == 2
    early, exhausted = rows[0]['ret_offset'], rows[7]['ret_offset']
    assert early != exhausted
    assert all(r['ret_offset'] == (exhausted if i in (2, 7) else early)
               for i, r in enumerate(rows))
    return rows, ('\n'.join(lines[:-1])+'\n').encode('ascii')


def lifecycle(data, owner):
    assert owner in ('sampled', 'function-closed')
    assert data == DROP.format(owner).encode('ascii')


def state(data, stdout, stderr, length):
    assert type(length) is int and 5 <= length <= 80
    assert isinstance(data, bytes) and 0 < len(data) < 65536 and stderr == b''
    assert data.endswith(b'\n') and all(b == 10 or 32 <= b <= 126 for b in data)
    lines = data[:-1].decode('ascii').split('\n')
    assert len(lines) == 18 and lines[0] == STATE_HEADER
    rows = list(csv.DictReader(lines, strict=True))
    assert len(rows) == 17
    expected = [('stable', seed, case) for seed in SEEDS for case in CASES]
    expected.append(('crossed-owner', SEEDS[0], CASES[-1]))
    for row, (mode, seed, (name, bound, value)) in zip(rows, expected):
        assert set(row) == set(STATE_HEADER.split(','))
        for key in set(row) - {'mode', 'case', 'status'}:
            row[key] = number(row[key])
        assert (row['mode'], row['seed'], row['case'], row['bound'], row['status']) == (
            mode, seed, name, bound, 'PASS')
        assert (row['children'], row['target_calls'], row['target_returns'],
                row['outer_returns'], row['normal_reaps'], row['helper_joins']) == (
                    2, 4, 4, 2, 2, int(mode == 'crossed-owner'))
        assert row['visits0'] > 0 and row['visits1'] > 0
        assert row['comparisons'] == 24 + row['visits0'] + row['visits1']
        assert row['comparisons'] <= row['original_steps'] <= 20000
        assert row['comparisons'] <= row['candidate_steps'] <= 20000
        assert (row['value0'], row['value1'], row['outer_value']) == (value, value, value*2)
        # This frozen body reads one byte per tested input position. Zero bound
        # reads none; a found zero is included, an exhausted bound is not exceeded.
        reads = value + int(value < bound)
        assert all(row[k] == reads for k in ('input_reads0', 'input_reads1', 'input_bytes0', 'input_bytes1'))
        assert 0 < row['ret_offset0'] == row['ret_offset1'] < length
    for i in range(8):
        assert rows[i]['ret_offset0'] == rows[i+8]['ret_offset0']
    assert rows[7]['ret_offset0'] == rows[16]['ret_offset0']
    assert len({r['ret_offset0'] for r in rows[:8]}) == 2
    totals = dict(comparisons=sum(r['comparisons'] for r in rows),
                  input_reads=sum(r['input_reads0']+r['input_reads1'] for r in rows),
                  input_bytes=sum(r['input_bytes0']+r['input_bytes1'] for r in rows))
    terminal = ('native-normal:selection=freebsd-strnlen-14.1-v1:stable-required=16:stable-pairs=16:'
                'crossed-owner-pairs=1:pairs=17:children=34:comparisons={comparisons}:'
                'input-reads={input_reads}:input-bytes={input_bytes}:coverage-seeds=2:'
                'target-calls=68:target-returns=68:real-outer-ret=34:helper-joins=1:complete\n')
    assert stdout == terminal.format(**totals).encode('ascii')
    return rows, totals


def join(native, work):
    assert len(native) == 17 and len(work) == 8
    for i, row in enumerate(work):
        assert (row['case'], row['bound'], row['value'], row['ret_offset']) == (
            native[i]['case'], native[i]['bound'], native[i]['value0'], native[i]['ret_offset0'])
