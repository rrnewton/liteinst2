"""Strict finite selected-loader transcripts; closure and file provenance are separate joins."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import re

MIB = 1048576
U64 = (1 << 64) - 1
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
LENGTHS = (1, 2, 17, 64, 3, 63, 7, 32)
OWNERS = ('sampled', 'sampled', 'closed', 'closed', 'removed', 'sampled', 'sampled', 'closed')
INVOCATIONS = (0, 1, None, None, None, 0, 1, None)
PREFIXES = (1, 1, 1, 1, 2, 3, 3, 3)
STATE_HEADER = 'seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value'
WORK_COMMENT = '# selected final-ELF scalar calls; raw callback ticks are uncalibrated; no accuracy or performance claim'
WORK_HEADER = 'ordinal,length,owner,generation,invocation,history_prefix,ret_offset,native_value,value,start_ticks,end_ticks,start_aux,end_aux,elapsed_ticks'
WORK_TERMINAL = 'selected-work PASS originals=8 calls=8 sampled=4 closed=3 removed=1 reports=2+2 batches=1 events=16 actions=4 entries=8 returns=8 completed=4 unsampled=4 raw_rows=8 input_unchanged=true joined=true'
REFUSALS = ('named-final,expected-refusal,SymbolOwner',
    'wrong-whole-file,expected-refusal,SourceBytes',
    'changed-selected-byte,expected-refusal,SourceBytes')
REFUSAL_TERMINAL = 'selected-refusals complete cases=3 expected_refusals=3 subject_calls=0'


def lines(data):
    assert type(data) is bytes and 0 < len(data) <= MIB and data.endswith(b'\n')
    assert all(c == 10 or 32 <= c < 127 for c in data)
    return data.decode('ascii')[:-1].split('\n')


def uint(text, maximum=U64):
    assert re.fullmatch(r'0|[1-9][0-9]*', text)
    value = int(text)
    assert value <= maximum
    return value


def scalar(length, seed=0, offset=0):
    return sum(((((offset + j) * 37 + 11 + seed) & 255) ^ 0x5a) for j in range(length)) ^ 0x9e3779b97f4a7c15


def state(table, stdout, stderr):
    assert stderr == b''
    text = lines(table)
    assert len(text) == 5 and text[0] == STATE_HEADER
    rows = []
    for line, (seed, length) in zip(text[1:], ((s, n) for s in SEEDS for n in (1, 64))):
        fields = line.split(',')
        assert len(fields) == 9 and fields[2] == 'PASS'
        row = dict(zip(STATE_HEADER.split(','), fields))
        for key in row:
            if key != 'status': row[key] = uint(row[key])
        assert row['seed'] == seed and row['length'] == length and row['children'] == 2
        assert 0 < row['original_visits'] < row['comparisons'] <= row['original_steps'] <= 20000
        assert row['comparisons'] <= row['candidate_steps'] <= 20000
        assert row['value'] == scalar(length, seed, 128)
        rows.append(row)
    comparisons = sum(r['comparisons'] for r in rows)
    assert lines(stdout) == [f'native-selected:selection=selected-checksum-v1:required=4:pairs=4:children=8:comparisons={comparisons}:real-outer-ret=8:complete']
    return dict(summary=dict(status='PASS', pairs=4, children=8, comparisons=comparisons, real_outer_returns=8), rows=rows,
        source_attested='Full state, complete RET union, source/image bytes, four raw rows/Reports and normal reaps; caller separately authenticates normal process closure.')


def work(stdout, stderr, function_length):
    assert stderr == b'' and type(function_length) is int and 1 <= function_length <= 256
    text = lines(stdout)
    assert len(text) == 11 and text[:2] == [WORK_COMMENT, WORK_HEADER] and text[-1] == WORK_TERMINAL
    rows = []
    for i, line in enumerate(text[2:-1]):
        fields = line.split(',')
        assert len(fields) == 14
        row = dict(zip(WORK_HEADER.split(','), fields))
        assert row['owner'] == OWNERS[i]
        for key in row:
            if key == 'owner': continue
            row[key] = None if key == 'invocation' and row[key] == '' else uint(row[key])
        assert row['ordinal'] == i + 1 and row['length'] == LENGTHS[i]
        assert row['generation'] > 0 and row['invocation'] == INVOCATIONS[i]
        assert row['history_prefix'] == PREFIXES[i] and 0 < row['ret_offset'] < function_length
        assert row['native_value'] == row['value'] == scalar(LENGTHS[i])
        assert row['start_aux'] == row['end_aux'] < (1 << 32)
        assert row['start_ticks'] <= row['end_ticks'] and row['elapsed_ticks'] == row['end_ticks'] - row['start_ticks']
        rows.append(row)
    a, b = rows[0]['generation'], rows[5]['generation']
    assert a < b and [r['generation'] for r in rows] == [a] * 5 + [b] * 3
    # These are actual callback enclosures, not original-call timestamps. The
    # source checks the real RET set; no fabricated compiler-specific RET offsets.
    return dict(summary=dict(status='PASS', originals=8, calls=8, sampled=4, closed=3, removed=1,
        reports=[2, 2], batches=1, events=16, actions=4, entries=8, returns=8, completed=4,
        unsampled=4, raw_rows=8, generations=[a, b]), rows=rows,
        source_attested='Full guarded input, actual original values, complete RET union, worker join, all 512 journal words and complete Reports. CSV is not a full journal/Report replay.',
        scope='Uncalibrated raw callback ticks; no performance or accuracy claim.')


def refusals(stdout, stderr):
    assert stderr == b''
    assert lines(stdout) == ['case,status,refusal', *REFUSALS, REFUSAL_TERMINAL]
    return dict(status='PASS', cases=3, expected_refusals=3, subject_calls=0,
        rows=[dict(zip(('case', 'status', 'refusal'), row.split(','))) for row in REFUSALS],
        scope='Pre-loading public-loader errors; source ordering and runner-owned exact file mutations are separate authority. No native wrong-object-base injection.')


def census(stdout, stderr):
    assert stderr == b''
    text = [line for line in lines(stdout) if line]
    match = re.fullmatch(r'([0-9]+) tests, 0 benchmarks', text[-1])
    assert match and int(match[1]) > 0
    names = []
    for line in text[:-1]:
        assert line.endswith(': test')
        name = line[:-6]
        assert re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)+', name)
        names.append(name)
    assert len(names) == len(set(names)) == int(match[1])
    return names


def controls(stdout, stderr, expected, inventory):
    assert stderr == b'' and len(expected) == len(set(expected)) > 0
    assert set(expected).issubset(inventory) and len(inventory) == len(set(inventory))
    count, filtered = len(expected), len(inventory) - len(expected)
    noun = 'test' if count == 1 else 'tests'
    prefix = f'\nrunning {count} {noun}\n'
    text = stdout.decode('ascii')
    assert 0 < len(stdout) <= MIB and text.startswith(prefix)
    body = text[len(prefix):].split('\n')
    assert len(body) == count + 4 and body[count] == '' and body[-2:] == ['', '']
    names = []
    for line in body[:count]:
        match = re.fullmatch(r'test ([A-Za-z_0-9:]+) \.\.\. ok', line)
        assert match
        names.append(match[1])
    assert len(names) == len(set(names)) and set(names) == set(expected)
    assert re.fullmatch(rf'test result: ok\. {count} passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in [0-9]+\.[0-9]+s', body[count + 1])
    return dict(status='PASS', passed=count, failed=0, ignored=0, filtered=filtered, names=names)
