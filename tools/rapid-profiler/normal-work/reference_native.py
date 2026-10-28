#!/usr/bin/env python3
"""Strict four-pair reference-state projection; no duration-accuracy inference."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

CSV_CAP = 65536
STDOUT_CAP = 4096
U64 = (1 << 64)-1
U32 = (1 << 32)-1
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
HEADER = ('seed,length,status,children,comparisons,visits0,visits1,original_steps,'
    'candidate_steps,value0,value1,outer_value,instructions,conditional_branches,'
    'taken_branches,input_reads,return_reads,return_read_bytes,ret_offset0,'
    'ret_offset1,target_calls,target_returns,outer_returns,normal_reaps,reader_checks,'
    'output_stores,helper_heads,interior_heads,returned_cells,'
    'original0_start_ticks,original0_start_aux,original0_end_ticks,original0_end_aux,'
    'original1_start_ticks,original1_start_aux,original1_end_ticks,original1_end_aux,'
    'candidate0_start_ticks,candidate0_start_aux,candidate0_end_ticks,candidate0_end_aux,'
    'candidate1_start_ticks,candidate1_start_aux,candidate1_end_ticks,candidate1_end_aux')
FIELDS = tuple(HEADER.split(','))
ENDPOINT_FIELDS = tuple(child+str(call)+'_'+side+'_'+part
    for child in ('original', 'candidate') for call in (0, 1)
    for side in ('start', 'end') for part in ('ticks', 'aux'))
TERMINAL = (
    b'native-normal-reference:selection=normal-reference-exact-37-v1:required=4:pairs=4:children=8:'
    b'comparisons=1736:instructions=1600:conditional=260:taken=252:input-reads=260:'
    b'return-reads=8:return-read-bytes=64:target-calls=16:target-returns=16:'
    b'real-outer-ret=8:normal-reaps=8:reader-checks=32:output-stores=96:'
    b'helper-heads=640:interior-heads=368:returned-cells=16:complete\n')
TOTAL_FIELDS = ('children', 'comparisons', 'instructions', 'conditional_branches',
    'taken_branches', 'input_reads', 'return_reads', 'return_read_bytes',
    'target_calls', 'target_returns', 'outer_returns', 'normal_reaps', 'reader_checks',
    'output_stores', 'helper_heads', 'interior_heads', 'returned_cells')
SCOPE = ('Functional reference-state projection only. Work counts describe two original '
    'subject bodies per pair; helper/reader/store/cell/transfer/reap counts include both '
    'children. Actual state preservation, RDTSCP output-to-store provenance, returns, '
    'postflight and reaps are producer-attested and require separate source/artifact/'
    'owned-receipt qualification. Enclosures are not independent body-duration truth. '
    'No calibration, timing accuracy, performance, PMU or concurrent-interleaving claim.')


def _u64(text):
    assert isinstance(text, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', text)
    value = int(text)
    assert value <= U64
    return value


def _expected(seed_index, length):
    # Fixed original-body algebra; no observed count/timestamp is an input.
    value = (sum(((37*j+11+seed_index) % 256) ^ 0x5a for j in range(length)) & U64)
    value ^= 0x9e3779b97f4a7c15
    visits = 6*length+5
    return dict(seed=SEEDS[seed_index], length=length, status='PASS', children=2,
        comparisons=34+2*visits, visits0=visits, visits1=visits,
        value0=value, value1=value, outer_value=(2*value) & U64,
        instructions=2*visits, conditional_branches=2*length,
        taken_branches=2*(length-1), input_reads=2*length, return_reads=2,
        return_read_bytes=16, ret_offset0=36, ret_offset1=36,
        target_calls=4, target_returns=4, outer_returns=2, normal_reaps=2,
        reader_checks=8, output_stores=24, helper_heads=160, interior_heads=92, returned_cells=4)


def check(csv_bytes, stdout_bytes, stderr_bytes):
    assert type(csv_bytes) is bytes and 0 < len(csv_bytes) <= CSV_CAP
    assert type(stdout_bytes) is bytes and 0 < len(stdout_bytes) <= STDOUT_CAP
    assert type(stderr_bytes) is bytes and stderr_bytes == b''
    assert csv_bytes.endswith(b'\n') and all(b == 10 or 32 <= b <= 126 for b in csv_bytes)
    lines = csv_bytes[:-1].decode('ascii').split('\n')
    assert len(lines) == 5 and lines[0] == HEADER
    assert len(FIELDS) == len(set(FIELDS)) == 45 and FIELDS[29:] == ENDPOINT_FIELDS
    rows = []
    for index, line in enumerate(lines[1:]):
        cells = line.split(','); assert len(cells) == 45
        row = {key: value if key == 'status' else _u64(value) for key, value in zip(FIELDS, cells)}
        expected = _expected(index//2, (1, 64)[index % 2])
        assert set(row) == set(expected) | {'original_steps', 'candidate_steps'} | set(ENDPOINT_FIELDS)
        assert all(row[key] == value for key, value in expected.items())
        # The46 reader-interior heads are still stepped/witnessed in EACH child.
        for key in ('original_steps', 'candidate_steps'):
            assert row['comparisons']+46 <= row[key] <= 20000
        for child in ('original', 'candidate'):
            ticks = [row[child+str(call)+'_'+side+'_ticks'] for call in (0, 1) for side in ('start', 'end')]
            aux = [row[child+str(call)+'_'+side+'_aux'] for call in (0, 1) for side in ('start', 'end')]
            assert ticks[0] <= ticks[1] <= ticks[2] <= ticks[3]
            assert all(value <= U32 for value in aux) and len(set(aux)) == 1
        rows.append(row)
    totals = {key: sum(row[key] for row in rows) for key in TOTAL_FIELDS}
    assert tuple(totals[key] for key in TOTAL_FIELDS) == (
        8, 1736, 1600, 260, 252, 260, 8, 64, 16, 16, 8, 8, 32, 96, 640, 368, 16)
    assert stdout_bytes == TERMINAL
    return dict(status='FUNCTIONAL_PASS', selection='normal-reference-exact-37-v1', pairs=4,
        **totals, original_steps=sum(row['original_steps'] for row in rows),
        candidate_steps=sum(row['candidate_steps'] for row in rows), rows=rows, scope=SCOPE)
