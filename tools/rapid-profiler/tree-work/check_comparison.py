"""Strict matched-consumer transcript, including a separate native metadata case."""
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import re
import csv

MODES = ('native', 'original-sdk', 'k1', 'k10', 'k24')
HEADER = ('mode,block,call_first,call_last,roots,node_rows,sampled,closed,batches,'
    'events,reports,generation,history_prefix,gate_first,gate_last,completed_before,'
    'completed_after,conflict_population,conflict_retained,selection_error_numerator,'
    'selection_error_denominator,root_inclusive_instructions,root_exclusive_instructions,'
    'child_instructions,checksum')
FIELDS = tuple(HEADER.split(','))
ABSENT = ('generation', 'history_prefix', 'gate_first', 'gate_last', 'completed_before',
    'completed_after', 'conflict_retained', 'selection_error_numerator',
    'selection_error_denominator')
CLOCK_FIELDS = tuple(f's{i}_{part}' for i in range(4)
    for part in ('wall_before', 'cpu', 'wall_after')) + (
    'wall_resolution_ns', 'cpu_resolution_ns', 'whole_wall_lower_ns', 'whole_wall_ns',
    'whole_cpu_ns', 'loop_wall_lower_ns', 'loop_wall_ns', 'loop_cpu_ns')
TERMINAL_FIELDS = ('mode', 'blocks', 'roots', 'calls', 'originals', 'installed_roots',
    'node_rows', 'sampled', 'closed', 'batches', 'events', 'reports', 'epochs', 'actions',
    'root_inclusive_instructions', 'root_exclusive_instructions', 'child_instructions',
    'input_unchanged', 'records_joined', 'clock_scope', 'collected_results') + CLOCK_FIELDS
SOURCE_ATTESTED = ('Actual source/input/gate/return checks, all sealed node/journal/Report '
    'joins for installed modes, generation/action correspondence, and OS-clock acquisition and S0..S3 '
    'placement are enforced in Rust. Compact rows do not independently replay those objects.')


def uint(word):
    assert re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word)
    assert value < 2**64
    return value


def sint(word):
    assert re.fullmatch(r'0|-?[1-9][0-9]*', word)
    value = int(word)
    assert -(2**63) <= value < 2**63
    return value


def block_checksum():
    # Independent scalar multiplicities: five roots per seed for fit2, seven
    # per seed for conflict3. This neither runs the interpreter nor a cache model.
    mask, key = 2**64 - 1, 0x9e3779b97f4a7c15
    result = 0
    for seed in (0x1234567887654320, 0xfedcba9801234567):
        for roots, counts in ((5, ((0, 32), (4, 32))),
                             (7, ((0, 22), (4, 21), (8, 21)))):
            total = sum(count * (seed ^ ((key * (node + 1)) & mask))
                for node, count in counts)
            root = (((total & mask) ^ key) + 1) & mask
            result = (result + roots * root) & mask
    return result


def clocks(summary):
    triples = [tuple(summary[f's{i}_{part}'] for part in ('wall_before', 'cpu', 'wall_after'))
        for i in range(4)]
    assert summary['wall_resolution_ns'] > 0 and summary['cpu_resolution_ns'] > 0
    assert all(before <= after for before, cpu, after in triples)
    for previous, current in zip(triples, triples[1:]):
        assert previous[2] <= current[0] and previous[1] <= current[1]
    for prefix, first, last in (('whole', 0, 3), ('loop', 1, 2)):
        start, end = triples[first], triples[last]
        lower, upper, cpu = end[0] - start[2], end[2] - start[0], end[1] - start[1]
        assert lower >= 0 and upper > 0 and cpu > 0
        assert summary[prefix + '_wall_lower_ns'] == lower
        assert summary[prefix + '_wall_ns'] == upper
        assert summary[prefix + '_cpu_ns'] == cpu
    # Sequential wall/CPU reads, not simultaneous clocks. No CPU<=wall,
    # duration/resolution threshold, trimming or substitute lower-span metric.


def parse(stdout, stderr, requested_mode):
    """Complete transcript only. Source/artifact/process closure belongs to runner."""
    assert type(requested_mode) is str and requested_mode in MODES
    assert type(stdout) is bytes and type(stderr) is bytes and stderr == b''
    assert 0 < len(stdout) <= 1048576 and stdout.endswith(b'\n')
    assert all(byte == 10 or 32 <= byte <= 126 for byte in stdout)
    lines = stdout.decode('ascii').split('\n')[:-1]
    assert len(lines) == 66 and lines[0] == HEADER
    installed = requested_mode not in ('native', 'original-sdk')
    k = {'native': 0, 'original-sdk': 0, 'k1': 1, 'k10': 10, 'k24': 24}[requested_mode]
    checksum = block_checksum()
    rows, previous_generation = [], 0
    for block, line in enumerate(lines[1:65]):
        words = line.split(',')
        assert len(words) == len(FIELDS)
        row = dict(zip(FIELDS, words))
        assert row['mode'] == requested_mode
        for name in FIELDS[1:]:
            if not installed and name in ABSENT:
                assert row[name] == ''
                row[name] = None
            else:
                row[name] = sint(row[name]) if name == 'selection_error_numerator' else uint(row[name])
        expected = dict(block=block, call_first=24*block+1, call_last=24*block+24,
            roots=24, node_rows=48 if installed else 0, sampled=2*k,
            closed=48-2*k if installed else 0, batches=3 if installed else 0,
            events=96 if installed else 0, reports=2*k, conflict_population=14,
            root_inclusive_instructions=7968, root_exclusive_instructions=144,
            child_instructions=7824, checksum=checksum)
        if installed:
            assert row['generation'] > previous_generation
            previous_generation = row['generation']
            retained = max(k-10, 0)
            expected.update(history_prefix=2*block+1, gate_first=24*block+1,
                gate_last=24*block+24, completed_before=2*k*block,
                completed_after=2*k*(block+1), conflict_retained=retained,
                selection_error_numerator=24*retained-14*k, selection_error_denominator=24*k)
        assert all(row[name] == value for name, value in expected.items())
        rows.append(row)

    words = lines[-1].split(' ')
    assert words[:2] == ['tree-comparison', 'FUNCTIONAL_PASS']
    assert len(words) == len(TERMINAL_FIELDS) + 2
    summary = dict(status='FUNCTIONAL_PASS')
    for name, word in zip(TERMINAL_FIELDS, words[2:]):
        prefix = name + '='
        assert word.startswith(prefix)
        value = word[len(prefix):]
        if name in ('mode', 'clock_scope'):
            summary[name] = value
        elif name in ('input_unchanged', 'records_joined'):
            assert value in ('true', 'false')
            summary[name] = value == 'true'
        else:
            summary[name] = uint(value)
    summed = ('roots', 'node_rows', 'sampled', 'closed', 'batches', 'events', 'reports',
        'root_inclusive_instructions', 'root_exclusive_instructions', 'child_instructions')
    expected = {name: sum(row[name] for row in rows) for name in summed}
    expected.update(mode=requested_mode, blocks=64, calls=1536,
        originals=0 if installed else 1536, installed_roots=1536 if installed else 0,
        epochs=64 if installed else 0, actions=128 if installed else 0,
        input_unchanged=True, records_joined=installed, clock_scope='matched-consumer', collected_results=1536)
    assert all(summary[name] == value for name, value in expected.items())
    clocks(summary)
    return dict(summary=summary, rows=rows, source_attested=SOURCE_ATTESTED,
        scope='Finite complete workload and matched-consumer clock arithmetic; primary internal wall spans '
        'are upper enclosures. Native source/call qualification and process timing are separate. No hook-latency, '
        'hardware-cache, calibrated timing or perf-accuracy claim.')


def native_pairs(table, stdout, stderr):
    assert type(table) is bytes and 0 < len(table) <= 1048576 and table.endswith(b'\n')
    assert all(byte == 10 or 32 <= byte <= 126 for byte in table)
    assert stderr == b'' and stdout == (b'native-call-tree:required=4:pairs=4:children=8:comparisons=1356:'
        b'outer-calls=8:subject-transfers=24:real-outer-ret=8:callback-visits=20:complete\n')
    header = 'seed,case,status,children,comparisons,visits,original_steps,candidate_steps,value,outer_calls,subject_transfers,outer_returns,callback_visits'
    lines = table.decode('ascii').split('\n')[:-1]
    assert len(lines) == 5 and lines[0] == header
    rows = list(csv.DictReader(lines, strict=True)); assert len(rows) == 4
    values = (13455538007910626262, 14448916110156114966, 18114441086748040058, 6122101979721109698)
    for index, row in enumerate(rows):
        assert set(row) == set(header.split(',')) and row['status'] == 'PASS'
        assert all(type(value) is str for value in row.values())
        assert ','.join(row[key] for key in header.split(',')) == lines[index+1]
        assert row['case'] == ('fit2' if index < 2 else 'conflict3')
        for key in set(row)-{'status', 'case'}: row[key] = uint(row[key])
        assert row['seed'] == (0x1234567887654320, 0xfedcba9801234567)[index % 2]
        assert row['value'] == values[index]
        expected = dict(children=2, comparisons=339, visits=332, outer_calls=2,
            subject_transfers=6, outer_returns=2, callback_visits=5)
        assert all(row[key] == value for key, value in expected.items())
        assert 339 <= row['original_steps'] <= 20000 and 339 <= row['candidate_steps'] <= 20000
    return rows
