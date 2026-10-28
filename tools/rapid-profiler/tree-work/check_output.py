"""Fixed tree state/work protocol; cache-model results are not hardware misses."""
import csv
import re

HEADER = ('seed,case,status,children,comparisons,original_visits,original_steps,candidate_steps,'
    'instructions,root_instructions,child_instructions,conditional_branches,taken_branches,'
    'input_reads,return_reads,call_stores,model_events,model_hits,model_misses,root_misses,'
    'child_misses,model_writebacks,model_hit_bits,value,transfers,real_outer_returns')
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
CASES = (('fit2', (0, 4), 3), ('conflict3', (0, 4, 8), 65))
TERMINAL = ('native-tree:required=4:pairs=4:children=8:comparisons=1372:instructions=1328:'
    'conditional=256:taken=252:input-reads=516:return-reads=8:call-stores=4:'
    'model-events=528:model-hits=392:model-misses=136:transfers=24:real-outer-ret=8:complete\n')


def number(word):
    assert isinstance(word, str) and re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word)
    assert value < 2**64
    return value


def pairs(data, terminal, stderr):
    assert stderr == b'' and terminal == TERMINAL.encode('ascii')
    assert 0 < len(data) <= 1048576 and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').split('\n')[:-1]
    assert len(lines) == 5 and lines[0] == HEADER
    rows = list(csv.DictReader(lines, strict=True))
    assert len(rows) == 4
    population = [(seed, case) for seed in SEEDS for case in CASES]
    for row, (seed, (name, cycle, misses)) in zip(rows, population):
        assert set(row) == set(HEADER.split(',')) and all(isinstance(v, str) for v in row.values())
        assert (row['case'], row['status']) == (name, 'PASS')
        for key in set(row) - {'case', 'status', 'model_hit_bits'}:
            row[key] = number(row[key])
        assert (row['seed'], row['children'], row['transfers'], row['real_outer_returns']) == (seed, 2, 6, 2)
        assert (row['instructions'], row['root_instructions'], row['child_instructions']) == (332, 6, 326)
        assert row['original_visits'] == 332 and row['comparisons'] == 343
        assert row['comparisons'] <= min(row['original_steps'], row['candidate_steps'])
        assert max(row['original_steps'], row['candidate_steps']) <= 20000
        assert (row['conditional_branches'], row['taken_branches'], row['input_reads'],
            row['return_reads'], row['call_stores']) == (64, 63, 129, 2, 1)
        assert (row['model_events'], row['model_hits'], row['model_misses'], row['root_misses'],
            row['child_misses'], row['model_writebacks']) == (132, 132-misses, misses, 1, misses-1, 0)
        # Literal positions, independent of the Rust model's mutable cache ways.
        miss_indices = {0, 1, 4} if name == 'fit2' else {0, 1, *range(4, 130, 2)}
        bits = ''.join('0' if i in miss_indices else '1' for i in range(132))
        assert row['model_hit_bits'] == bits
        assert bits.count('1') == row['model_hits'] and bits.count('0') == row['model_misses']
        key, mask = 0x9e3779b97f4a7c15, 2**64-1
        value = sum(seed ^ (key*(cycle[i % len(cycle)]+1) & mask) for i in range(64)) & mask
        assert row['value'] == ((value ^ key)+1) & mask
    totals = {key: sum(row[key] for row in rows) for key in (
        'children', 'comparisons', 'instructions', 'root_instructions', 'child_instructions',
        'conditional_branches', 'taken_branches', 'input_reads', 'return_reads', 'call_stores',
        'model_events', 'model_hits', 'model_misses', 'root_misses', 'child_misses',
        'model_writebacks', 'transfers', 'real_outer_returns')}
    assert totals == dict(children=8, comparisons=1372, instructions=1328,
        root_instructions=24, child_instructions=1304, conditional_branches=256,
        taken_branches=252, input_reads=516, return_reads=8, call_stores=4,
        model_events=528, model_hits=392, model_misses=136, root_misses=4,
        child_misses=132, model_writebacks=0, transfers=24, real_outer_returns=8)
    return rows
