#!/usr/bin/env python3
"""Strict finite native protocol projection; no independent machine-state evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

CSV_CAP = 65536
STDOUT_CAP = 4096
U64 = (1 << 64) - 1
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
HEADER = ('seed,length,status,children,comparisons,visits0,visits1,original_steps,'
    'candidate_steps,value0,value1,outer_value,instructions,conditional_branches,'
    'taken_branches,input_reads,return_reads,return_read_bytes,ret_offset0,'
    'ret_offset1,target_calls,target_returns,outer_returns,normal_reaps')
FIELDS = tuple(HEADER.split(','))
TERMINAL = (
    b'native-normal-exact:selection=normal-exact-37-v1:required=4:pairs=4:children=8:'
    b'comparisons=1696:instructions=1600:conditional=260:taken=252:input-reads=260:'
    b'return-reads=8:return-read-bytes=64:target-calls=16:target-returns=16:'
    b'real-outer-ret=8:normal-reaps=8:complete\n')
TOTAL_FIELDS = ('children', 'comparisons', 'instructions', 'conditional_branches',
    'taken_branches', 'input_reads', 'return_reads', 'return_read_bytes',
    'target_calls', 'target_returns', 'outer_returns', 'normal_reaps')
SCOPE = ('Counts describe two original subject bodies per pair; transfer/reap counts '
    'include both children. Full-state comparison, physical transfers and normal '
    'reaps are producer-attested and require separate source/artifact/owned-receipt '
    'qualification. No timing, PMU, performance or concurrent-interleaving claim.')


def _u64(text):
    assert isinstance(text, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', text)
    value = int(text)
    assert value <= U64
    return value


def _expected(seed_index, length):
    # Independent algebra for the fixed request and original body. No Rust,
    # decoder, observed visits, timestamps or emitted work labels are inputs.
    value = sum(((37*i+11+seed_index) % 256) ^ 0x5a for i in range(length))
    value ^= 0x9e3779b97f4a7c15
    visits = 6*length+5
    return dict(seed=SEEDS[seed_index], length=length, status='PASS', children=2,
        comparisons=24+2*visits, visits0=visits, visits1=visits,
        value0=value, value1=value, outer_value=(2*value) & U64,
        instructions=2*visits, conditional_branches=2*length,
        taken_branches=2*(length-1), input_reads=2*length, return_reads=2,
        return_read_bytes=16, ret_offset0=36, ret_offset1=36,
        target_calls=4, target_returns=4, outer_returns=2, normal_reaps=2)


def check(csv_bytes, stdout_bytes, stderr_bytes):
    assert type(csv_bytes) is bytes and 0 < len(csv_bytes) <= CSV_CAP
    assert type(stdout_bytes) is bytes and 0 < len(stdout_bytes) <= STDOUT_CAP
    assert type(stderr_bytes) is bytes and stderr_bytes == b''
    assert csv_bytes.endswith(b'\n') and all(b == 10 or 32 <= b <= 126 for b in csv_bytes)
    lines = csv_bytes[:-1].decode('ascii').split('\n')
    assert len(lines) == 5 and lines[0] == HEADER
    rows = []
    for index, line in enumerate(lines[1:]):
        cells = line.split(',')
        assert len(cells) == len(FIELDS)
        row = {key: value if key == 'status' else _u64(value)
               for key, value in zip(FIELDS, cells)}
        expected = _expected(index//2, (1, 64)[index % 2])
        assert set(row) == set(expected) | {'original_steps', 'candidate_steps'}
        assert all(row[key] == value for key, value in expected.items())
        assert row['comparisons'] <= row['original_steps'] <= 20000
        assert row['comparisons'] <= row['candidate_steps'] <= 20000
        rows.append(row)
    totals = {key: sum(row[key] for row in rows) for key in TOTAL_FIELDS}
    assert tuple(totals[key] for key in TOTAL_FIELDS) == (
        8, 1696, 1600, 260, 252, 260, 8, 64, 16, 16, 8, 8)
    assert stdout_bytes == TERMINAL
    return dict(status='FUNCTIONAL_PASS', selection='normal-exact-37-v1', pairs=4,
        **totals, original_steps=sum(row['original_steps'] for row in rows),
        candidate_steps=sum(row['candidate_steps'] for row in rows), rows=rows, scope=SCOPE)
