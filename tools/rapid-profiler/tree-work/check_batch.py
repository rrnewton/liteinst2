"""Strict four-pair source-batch protocol; selected state, not middle-state credit."""
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import re

HEADER = ('seed,case,status,children,calls_per_child,full_indices,comparisons,original_visits,'
    'original_steps,candidate_steps,selected0_original_steps,selected0_candidate_steps,'
    'selected7_original_steps,selected7_candidate_steps,hardware_stops_original,'
    'hardware_stops_candidate,tree_transfers,outer_calls,outer_returns,normal_reaps,'
    'source_attested_finishes,candidate_rows,candidate_events,candidate_report_records,value')
FIELDS = tuple(HEADER.split(','))
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
CASES = ('fit2', 'conflict3')
TERMINAL = ('native-tree-batch:required=4:pairs=4:children=8:roots=64:selected-call-pairs=8:'
    'comparisons=2744:tree-transfers=192:outer-calls=64:outer-returns=64:hardware-stops=304:'
    'source-attested-finishes=8:candidate-rows=64:candidate-events=128:'
    'candidate-report-records=64:selected=0+7:middle=functional-only:complete\n')
FIXED = dict(children=2, calls_per_child=8, comparisons=686, original_visits=664,
    hardware_stops_original=38, hardware_stops_candidate=38, tree_transfers=48,
    outer_calls=16, outer_returns=16, normal_reaps=2, source_attested_finishes=2,
    candidate_rows=16, candidate_events=32, candidate_report_records=16)
STEPS = ('original_steps', 'candidate_steps', 'selected0_original_steps',
    'selected0_candidate_steps', 'selected7_original_steps', 'selected7_candidate_steps')
CONTROLS = (
    'oracle::native_ordinary::tree_batch::tests::batch_armed_all_fields_and_retained_lifetime_refuse_corruption',
    'oracle::native_ordinary::tree_batch::tests::batch_checkpoint_exact_idle_refuses_missing_or_early_return',
    'oracle::native_ordinary::tree_batch::tests::batch_checkpoint_requires_exact_self_thread_signal',
    'oracle::native_ordinary::tree_batch::tests::batch_outer_call_checks_actual_instruction_successor_word_and_rf',
)
SOURCE_ATTESTED = ('Successful eight-call API finishes and complete candidate row, full512-word '
    'journal, Report/history/input/retirement/detach joins are child-source assertions before '
    'normal exit0. The compact CSV does not independently export or replay those objects.')
SCOPE = ('Four finite pairs; only indices0/7 receive full-state and original operand inspection. '
    'The six middle calls have functional and actual transfer checks. Continued instructions '
    'are not counted SINGLESTEP operations. No timing, hardware-cache, accuracy or performance claim.')


def uint(word):
    assert type(word) is str and len(word) <= 20 and re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word)
    assert value < 1 << 64
    return value


def value(seed, case):
    # Independent multiplicities for the fixed64-iteration walk, not the Rust
    # interpreter/cache model or the exported value. Child XOR then caller+1.
    counts = {'fit2': ((0, 32), (4, 32)), 'conflict3': ((0, 22), (4, 21), (8, 21))}[case]
    key, mask = 0x9e3779b97f4a7c15, (1 << 64) - 1
    total = sum(count * (seed ^ ((key * (node + 1)) & mask)) for node, count in counts)
    return (((total & mask) ^ key) + 1) & mask


def parse(data, terminal, stderr):
    """Consume exact CSV/stdout/stderr bytes; runner owns source and process closure."""
    assert type(data) is bytes and type(terminal) is bytes and type(stderr) is bytes
    assert terminal == TERMINAL.encode('ascii') and stderr == b''
    assert 0 < len(data) <= 1048576 and data.endswith(b'\n')
    assert all(byte == 10 or 32 <= byte <= 126 for byte in data)
    lines = data.decode('ascii').split('\n')[:-1]
    assert len(lines) == 5 and lines[0] == HEADER
    rows = []
    for index, line in enumerate(lines[1:]):
        words = line.split(',')
        assert len(words) == len(FIELDS)
        row = dict(zip(FIELDS, words))  # Equal lengths were checked explicitly.
        seed, case = SEEDS[index // 2], CASES[index % 2]
        assert (row['case'], row['status'], row['full_indices']) == (case, 'PASS', '0+7')
        for field in FIELDS:
            if field not in ('case', 'status', 'full_indices'):
                row[field] = uint(row[field])
        assert row['seed'] == seed
        for field, expected in FIXED.items():
            assert row[field] == expected
        for field in STEPS:
            assert 1 <= row[field] <= 20000
        # Frozen oracle:343 compared original points entail342 loop steps;
        # returned() adds the actual outer RET. Each middle round adds5 steps.
        assert row['selected0_original_steps'] == row['selected7_original_steps'] == 343
        assert row['selected0_candidate_steps'] >= 343 and row['selected7_candidate_steps'] >= 343
        for side in ('original', 'candidate'):
            assert row['selected0_' + side + '_steps'] + row['selected7_' + side + '_steps'] + 30 == row[side + '_steps']
        assert row['original_steps'] == 716
        assert row['value'] == value(seed, case)
        rows.append(row)
    totals = {field: sum(row[field] for row in rows) for field in FIXED if field != 'calls_per_child'}
    assert totals == dict(children=8, comparisons=2744, original_visits=2656,
        hardware_stops_original=152, hardware_stops_candidate=152, tree_transfers=192,
        outer_calls=64, outer_returns=64, normal_reaps=8, source_attested_finishes=8,
        candidate_rows=64, candidate_events=128, candidate_report_records=64)
    summary = dict(status='PASS', pairs=len(rows), children=totals['children'],
        roots=sum(row['children'] * row['calls_per_child'] for row in rows),
        selected_call_pairs=2 * len(rows), comparisons=totals['comparisons'],
        selected_original_visits=totals['original_visits'], tree_transfers=totals['tree_transfers'],
        outer_calls=totals['outer_calls'], outer_returns=totals['outer_returns'],
        hardware_stops=totals['hardware_stops_original'] + totals['hardware_stops_candidate'],
        normal_reaps=totals['normal_reaps'], source_attested_finishes=totals['source_attested_finishes'],
        candidate_rows=totals['candidate_rows'], candidate_events=totals['candidate_events'],
        candidate_report_records=totals['candidate_report_records'], full_indices=[0, 7],
        middle='functional-only')
    assert (summary['roots'], summary['selected_call_pairs'], summary['hardware_stops']) == (64, 8, 304)
    return dict(summary=summary, rows=rows, source_attested=SOURCE_ATTESTED, scope=SCOPE)


def parse_controls(stdout, stderr):
    """Exactly four named libtest controls; no native or full-target run credit."""
    assert type(stdout) is bytes and type(stderr) is bytes and stderr == b''
    assert 0 < len(stdout) <= 1048576
    assert all(byte == 10 or 32 <= byte <= 126 for byte in stdout)
    lines = stdout.decode('ascii').split('\n')
    assert len(lines) == 10 and lines[:2] == ['', 'running 4 tests']
    assert lines[6] == '' and lines[8:] == ['', '']
    names = []
    for line in lines[2:6]:
        match = re.fullmatch(r'test ([a-zA-Z0-9_:]+) \.\.\. ok', line)
        assert match is not None
        names.append(match.group(1))
    # Parallel libtest completion order is not a case-selection rule.
    assert len(set(names)) == 4 and set(names) == set(CONTROLS)
    assert re.fullmatch(r'test result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; '
        r'91 filtered out; finished in (?:0|[1-9][0-9]*)\.[0-9]{2}s', lines[7])
    return dict(status='PASS', passed=4, failed=0, ignored=0, measured=0,
        filtered=91, tests=sorted(names), scope='Four named pure oracle predicates only; native execution is separate.')
