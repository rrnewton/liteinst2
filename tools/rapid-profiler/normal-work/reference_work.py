#!/usr/bin/env python3
"""Strict finite uncalibrated normal-reference collector projection."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

MIB = 1048576
U64 = (1 << 64)-1
U32 = (1 << 32)-1
SEEDS = (1311768467139281696, 18364758542526924135)
COMMENT = '# normal reference collector; raw same-call endpoints are uncalibrated; no accuracy or performance claim'
HEADER = 'leg,id,repeat,seed_index,seed,length,input_fnv1a64,value,instructions,conditional_branches,taken_branches,input_bytes,ret_bytes,reference_sequence,reference_start_ticks,reference_end_ticks,reference_start_aux,reference_end_aux,reference_rsp,reference_ticks,pid,tid,registration,install,function,generation,ordinal,owner,invocation,history_prefix,entry_pc,return_pc,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,raw_ticks,entry_gap_ticks,return_gap_ticks,ack,ack_ordinal'
FIELDS = tuple(HEADER.split(','))
TERMINAL = 'normal-reference-work FUNCTIONAL_PASS selection=normal-reference-exact-37-v1 originals=24 installed=24 helper_calls=24 reference_cells=48 batches=1 events=48 reports=1 records=24 actions=2 entered=24 ret_observed=24 confirmed=24 completed=24 unsampled=0 whole_journal_words=512 per_leg_instructions=4800 per_leg_conditional=780 per_leg_taken=756 per_leg_input_bytes=780 per_leg_ret_bytes=192 input_unchanged=true joined=true'
SDK_FIELDS = FIELDS[22:]
TEXT_FIELDS = ('leg', 'owner', 'ack')
WORK_FIELDS = ('instructions', 'conditional_branches', 'taken_branches', 'input_bytes', 'ret_bytes')
SCOPE = ('Functional uncalibrated collector only. R is a fenced CALL enclosure and H a '
    'callback interval; neither is original body-only duration. Original-before-installed '
    'order is not a drift-controlled perturbation comparison. No accuracy, performance, '
    'session-temporal, PMU or full-A5 claim. Zero spans are retained without relative error.')
SOURCE_ATTESTED = ('Actual helper returns, cell-store provenance, full source/generated/input '
    'and stack custody, complete512-word journal and Report/history joins require the '
    'producer source and separately owned execution receipts. This compact table is not '
    'an independent replay of those checks; originals have no SDK stack observation.')


def _uint(text):
    assert type(text) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}', text)
    value = int(text)
    assert value <= U64
    return value


def _expected(index):
    # Independent closed input/scalar/work algebra, never observed output or time.
    case = (index % 8)//2
    seed_index, length = case//2, (1, 64)[case % 2]
    data = [(37*j+11+seed_index) % 256 for j in range(64)]
    integrity = 14695981039346656037
    for byte in data:
        integrity = ((integrity ^ byte)*1099511628211) & U64
    return dict(id=index+1, repeat=index//8+1, seed_index=seed_index,
        seed=SEEDS[seed_index], length=length, input_fnv1a64=integrity,
        value=sum(byte ^ 0x5a for byte in data[:length]) ^ 0x9e3779b97f4a7c15,
        instructions=6*length+5, conditional_branches=length, taken_branches=length-1,
        input_bytes=length, ret_bytes=8)


def check(stdout, stderr):
    assert type(stdout) is bytes and 0 < len(stdout) <= MIB
    assert type(stderr) is bytes and stderr == b''
    assert stdout.endswith(b'\n') and all(c == 10 or 32 <= c <= 126 for c in stdout)
    lines = stdout[:-1].decode('ascii').split('\n')
    assert len(lines) == 51 and lines[:2] == [COMMENT, HEADER] and lines[-1] == TERMINAL
    assert len(FIELDS) == len(set(FIELDS)) == 43
    rows = []
    for position, line in enumerate(lines[2:-1]):
        index, installed = position % 24, position >= 24
        cells = line.split(','); assert len(cells) == 43
        absent = set(SDK_FIELDS) if not installed else ({'ack_ordinal'} if index == 23 else set())
        row = {}
        for name, cell in zip(FIELDS, cells):
            if name in absent:
                assert cell == ''; row[name] = None
            elif name in TEXT_FIELDS:
                assert cell != ''; row[name] = cell
            else:
                row[name] = _uint(cell)
        assert row['leg'] == ('installed' if installed else 'original')
        assert all(row[name] == value for name, value in _expected(index).items())
        assert row['reference_sequence'] == position+1
        assert 0 < row['pid'] <= U32 and row['tid'] == row['pid']
        a, b = row['reference_start_ticks'], row['reference_end_ticks']
        assert a <= b and row['reference_ticks'] == b-a
        assert row['reference_start_aux'] == row['reference_end_aux'] <= U32
        p = row['reference_rsp']
        assert 136 <= p <= U64-48 and p % 16 == 0
        if installed:
            assert (row['registration'], row['install'], row['function']) == (1, 1852990822, 1)
            assert row['generation'] > 0 and row['ordinal'] == index+1
            assert row['owner'] == 'sampled' and row['invocation'] == index and row['history_prefix'] == 1
            assert 0 < row['entry_pc'] <= U64-36 and row['return_pc'] == row['entry_pc']+36
            assert row['entry_rsp']+8 == p and row['entry_rsp'] % 16 == 8
            continuation = 80 if index % 2 == 0 else 216
            assert row['return_word'] > continuation
            helper = row['return_word']-continuation
            assert helper % 4096 == 0
            s, e = row['start_ticks'], row['end_ticks']
            assert a <= s <= e <= b
            assert row['start_aux'] == row['end_aux'] == row['reference_start_aux']
            assert (row['raw_ticks'], row['entry_gap_ticks'], row['return_gap_ticks']) == (e-s, s-a, b-e)
            assert row['entry_gap_ticks']+row['raw_ticks']+row['return_gap_ticks'] == row['reference_ticks']
            assert row['ack'] == ('next-entry' if index < 23 else 'caller-checkpoint')
            assert row['ack_ordinal'] == (index+2 if index < 23 else None)
        rows.append(row)
    assert all(rows[i-1]['reference_end_ticks'] <= rows[i]['reference_start_ticks']
        for i in range(1, 48))
    assert len({row['pid'] for row in rows}) == 1
    assert len({row['reference_start_aux'] for row in rows}) == 1
    # Same P within each actual two-CALL helper; no across-pair/leg stack equality.
    assert all(rows[i]['reference_rsp'] == rows[i+1]['reference_rsp'] for i in range(0, 48, 2))
    installed_rows = rows[24:]
    assert len({row['generation'] for row in installed_rows}) == 1
    assert len({row['entry_pc'] for row in installed_rows}) == 1
    assert len({row['return_word']-(80 if i % 2 == 0 else 216)
        for i, row in enumerate(installed_rows)}) == 1
    totals = {leg: {name: sum(row[name] for row in rows[start:start+24]) for name in WORK_FIELDS}
        for leg, start in (('original', 0), ('installed', 24))}
    assert all(tuple(value[name] for name in WORK_FIELDS) == (4800, 780, 756, 780, 192)
        for value in totals.values())
    table = ('\n'.join(lines[1:-1])+'\n').encode('ascii')
    return dict(status='FUNCTIONAL_PASS', selection='normal-reference-exact-37-v1',
        originals=24, installed=24, helper_calls=24, reference_cells=48, batches=1,
        events=48, reports=1, records=24, actions=2, entered=24, ret_observed=24,
        confirmed=24, completed=24, unsampled=0, whole_journal_words=512,
        pid=rows[0]['pid'], generation=installed_rows[0]['generation'],
        zero_reference_spans=sum(row['reference_ticks'] == 0 for row in rows),
        work=totals, rows=rows, table=table, scope=SCOPE, source_attested=SOURCE_ATTESTED)
