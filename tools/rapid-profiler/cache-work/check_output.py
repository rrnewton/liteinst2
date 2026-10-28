"""Exact finite cache-work projection, not a hardware-cache measurement."""
import csv
import re

HEADER = ('seed,case,status,children,comparisons,original_visits,original_steps,candidate_steps,'
    'instructions,conditional_branches,taken_branches,input_reads,return_reads,'
    'model_events,model_hits,model_misses,model_hit_bits,value')
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
CASES = (
    ('reuse4', (0, 1, 2, 3), 64, 5),
    ('cold16', tuple(range(16)), 16, 17),
    ('chase8', (0, 3, 6, 1, 4, 7, 2, 5), 64, 9),
    ('fit2', (0, 4), 64, 3),
    ('conflict3', (0, 4, 8), 64, 65),
    ('capacity12', tuple(range(12)), 64, 65),
)
TERMINAL = ('native-cache:required=12:pairs=12:children=24:comparisons=3564:'
    'instructions=3432:conditional=672:taken=660:input-reads=1356:return-reads=12:'
    'model-events=1368:model-misses=328:real-outer-ret=24:complete\n')


def number(word):
    assert isinstance(word, str) and re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word)
    assert value < 2**64
    return value


def pairs(data, terminal, stderr):
    assert stderr == b'' and terminal == TERMINAL.encode('ascii')
    assert 0 < len(data) <= 1048576 and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').split('\n')[:-1]
    assert len(lines) == 13 and lines[0] == HEADER
    rows = list(csv.DictReader(lines, strict=True))
    assert len(rows) == 12
    population = [(seed, case) for seed in SEEDS for case in CASES]
    for row, (seed, (name, cycle, n, misses)) in zip(rows, population):
        assert set(row) == set(HEADER.split(',')) and all(isinstance(v, str) for v in row.values())
        assert (row['case'], row['status']) == (name, 'PASS')
        for key in set(row) - {'case', 'status', 'model_hit_bits'}:
            row[key] = number(row[key])
        instructions, reads = 5*n+6, 2*n+2
        assert (row['seed'], row['children']) == (seed, 2)
        assert row['instructions'] == row['original_visits'] == instructions
        assert row['comparisons'] == instructions+11
        assert row['comparisons'] <= min(row['original_steps'], row['candidate_steps'])
        assert max(row['original_steps'], row['candidate_steps']) <= 20000
        assert (row['conditional_branches'], row['taken_branches'], row['input_reads'], row['return_reads']) == (n, n-1, 2*n+1, 1)
        assert (row['model_events'], row['model_hits'], row['model_misses']) == (reads, reads-misses, misses)
        fitting = name in ('reuse4', 'chase8', 'fit2')
        bits = '0' + ''.join(('1' if i == 0 or fitting and i >= len(cycle) else '0')+'1' for i in range(n)) + '0'
        assert row['model_hit_bits'] == bits
        assert bits.count('1') == row['model_hits'] and bits.count('0') == row['model_misses']
        key, mask = 0x9e3779b97f4a7c15, 2**64-1
        value = sum(seed ^ (key*(cycle[i % len(cycle)]+1) & mask) for i in range(n)) & mask
        assert row['value'] == value ^ key
    totals = {key: sum(row[key] for row in rows) for key in (
        'children', 'comparisons', 'instructions', 'conditional_branches', 'taken_branches',
        'input_reads', 'return_reads', 'model_events', 'model_hits', 'model_misses')}
    assert totals == dict(children=24, comparisons=3564, instructions=3432,
        conditional_branches=672, taken_branches=660, input_reads=1356,
        return_reads=12, model_events=1368, model_hits=1040, model_misses=328)
    return rows
