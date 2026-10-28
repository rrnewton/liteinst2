"""Strict finite tree population projection; no native-state or timing accuracy."""
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import re

HEADER = ('k,external_id,seed,case,node,parent,function,ordinal,owner,generation,'
    'invocation,inclusive_instructions,exclusive_instructions,value,gate_sequence,'
    'start_ticks,end_ticks,start_aux,end_aux')
FIELDS = tuple(HEADER.split(','))
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
POLICIES = (1, 10, 24)
SOURCE_ATTESTED = ('Complete guarded input and returned-call checks, sealed rows, '
    'three full 512-word journal pages, stream/history and full Report payload '
    'joins are enforced by Rust; those objects are not all exported in this CSV.')


def uint(word, bits=64):
    assert re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word)
    assert value < 1 << bits
    return value


def child_value(seed, case):
    # Independent multiplicities for the fixed 64-link cycles, not a simulator
    # or a call into the Rust interpreter. The caller adds one to this result.
    counts = ((0, 32), (4, 32)) if case == 'fit2' else ((0, 22), (4, 21), (8, 21))
    key, mask = 0x9e3779b97f4a7c15, (1 << 64) - 1
    total = sum(count * (seed ^ ((key * (node + 1)) & mask)) for node, count in counts)
    return (total & mask) ^ key


def parse(stdout, stderr, k):
    """Accept one complete producer transcript; caller supplies the requested K.

    Runtime/source/artifact/process closure remains the runner's responsibility.
    A consistent nonzero generation is exported identity, not a new epoch permit.
    """
    assert type(k) is int and k in POLICIES
    assert type(stdout) is bytes and type(stderr) is bytes and stderr == b''
    assert 0 < len(stdout) <= 1048576 and stdout.endswith(b'\n')
    assert all(byte == 10 or 32 <= byte <= 126 for byte in stdout)
    lines = stdout.decode('ascii').split('\n')[:-1]
    assert len(lines) == 50 and lines[0] == HEADER
    rows = []
    for position, line in enumerate(lines[1:49]):
        words = line.split(',')
        assert len(words) == len(FIELDS)
        row = dict(zip(FIELDS, words))  # Exact field lengths checked above.
        for name in FIELDS:
            if name in ('case', 'owner'):
                continue
            if name in ('parent', 'invocation') and row[name] == '':
                row[name] = None
            else:
                row[name] = uint(row[name], 32 if name.endswith('_aux') else 64)
        index, node = divmod(position, 2)
        external_id = index + 1
        seed = SEEDS[index % 2]
        case = 'fit2' if index < 10 else 'conflict3'
        sampled = external_id <= k
        assert (row['k'], row['external_id'], row['seed'], row['case']) == (k, external_id, seed, case)
        assert (row['node'], row['parent'], row['function'], row['ordinal']) == (
            node, external_id if node else None, node + 1, position + 1)
        assert (row['owner'], row['invocation']) == (
            'sampled' if sampled else 'closed', position if sampled else None)
        assert row['generation'] > 0
        assert (row['inclusive_instructions'], row['exclusive_instructions']) == (
            (332, 6) if node == 0 else (326, 326))
        child = child_value(seed, case)
        assert row['value'] == ((child + 1) % (1 << 64) if node == 0 else child)
        assert row['gate_sequence'] == 24 + external_id
        assert row['start_ticks'] <= row['end_ticks']
        assert row['start_aux'] == row['end_aux']
        rows.append(row)

    generation, aux = rows[0]['generation'], rows[0]['start_aux']
    previous_end = 0
    assert len(rows[::2]) == len(rows[1::2]) == 24
    for root, child in zip(rows[::2], rows[1::2]):
        assert root['generation'] == child['generation'] == generation
        assert root['start_aux'] == child['start_aux'] == aux
        assert previous_end <= root['start_ticks'] <= child['start_ticks']
        assert child['end_ticks'] <= root['end_ticks']
        previous_end = root['end_ticks']

    roots = rows[::2]
    children = rows[1::2]
    sampled = sum(row['owner'] == 'sampled' for row in rows)
    conflict = sum(row['case'] == 'conflict3' for row in roots)
    selected = sum(row['case'] == 'conflict3' and row['owner'] == 'sampled' for row in roots)
    inclusive = sum(row['inclusive_instructions'] for row in roots)
    exclusive = sum(row['exclusive_instructions'] for row in roots)
    child_instructions = sum(row['exclusive_instructions'] for row in children)
    assert (sampled, conflict, selected) == (2 * k, 14, max(k - 10, 0))
    assert (inclusive, exclusive, child_instructions) == (7968, 144, 7824)
    error, denominator = 24 * selected - conflict * k, 24 * k
    terminal = (f'tree-population FUNCTIONAL_PASS k={k} originals=24 roots=24 nodes=48 '
        f'sampled={sampled} closed={48-sampled} batches=3 events=96 reports={sampled} actions=2 '
        f'conflict_population={conflict} conflict_retained={selected} '
        f'selection_error_numerator={error} selection_error_denominator={denominator} '
        f'root_inclusive_instructions={inclusive} root_exclusive_instructions={exclusive} '
        f'child_instructions={child_instructions} input_unchanged=true records_joined=true uncalibrated=true')
    assert lines[-1] == terminal
    summary = dict(status='FUNCTIONAL_PASS', k=k, originals=24, roots=24, nodes=48,
        sampled=sampled, closed=48-sampled, batches=3, events=96, reports=sampled, actions=2,
        conflict_population=conflict, conflict_retained=selected,
        selection_error_numerator=error, selection_error_denominator=denominator,
        root_inclusive_instructions=inclusive, root_exclusive_instructions=exclusive,
        child_instructions=child_instructions, generation=generation, aux=aux,
        input_unchanged=True, records_joined=True, uncalibrated=True)
    return dict(summary=summary, rows=rows,
        source_attested=SOURCE_ATTESTED,
        scope='Finite functional population and fixed-byte work/selection; no new full-state, hardware-cache, calibrated timing or performance claim.')
