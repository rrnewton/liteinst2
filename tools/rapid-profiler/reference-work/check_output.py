"""Finite reference-clock projections; no calibration or timing accuracy verdict."""
import csv
import re

PAIR_HEADER = 'seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,reader_checks,timestamp_joins,returned_records,value'
PAIR_PASS = ('native-exact-reference:required=4:pairs=4:children=8:comparisons=872:'
    'reader-checks=16:timestamp-joins=16:returned-records=8:truth-instructions=800:'
    'conditional=130:taken=126:input-reads=130:return-reads=4:subject-ret=8:real-outer-ret=8:complete\n')
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
SCOPE = '# uncalibrated real-CALL enclosures and hook endpoints; fixed-assembly work model, no timing-accuracy, frequency-conversion or performance claim'
HEADER = 'leg,external_id,gate_sequence,ordinal,length,owner,generation,invocation,instructions,branches,taken_branches,input_byte_reads,return_read_bytes,value,reference_start_ticks,reference_end_ticks,reference_start_aux,reference_end_aux,raw_start_ticks,raw_end_ticks,raw_start_aux,raw_end_aux,enclosure_ticks,raw_ticks,entry_gap_ticks,return_gap_ticks'
PASS = ('exact-reference FUNCTIONAL_PASS originals=24 installed=24 raw_rows=24 sampled=24 unsampled=0 report_records=24 '
    'original_instructions=4800 installed_instructions=4800 same_thread=true detached=true input_unchanged=true uncalibrated=true')
ORIGINAL_EMPTY = frozenset(('ordinal', 'generation', 'invocation', 'raw_start_ticks', 'raw_end_ticks', 'raw_start_aux', 'raw_end_aux', 'raw_ticks', 'entry_gap_ticks', 'return_gap_ticks'))


def number(word):
    assert isinstance(word, str) and re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word)
    assert value < 2**64
    return value


def table(data, header, count):
    assert 0 < len(data) <= 1048576 and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').splitlines()
    assert len(lines) == count + 1 and lines[0] == header
    rows = list(csv.DictReader(lines, strict=True))
    assert len(rows) == count
    assert all(set(row) == set(header.split(',')) and all(isinstance(v, str) for v in row.values()) for row in rows)
    return rows


def pairs(data, terminal, stderr):
    assert stderr == b'' and terminal == PAIR_PASS.encode('ascii')
    rows = table(data, PAIR_HEADER, 4)
    for row, (seed, n) in zip(rows, [(seed, n) for seed in SEEDS for n in (1, 64)]):
        assert row['status'] == 'PASS'
        for key in set(row) - {'status'}:
            row[key] = number(row[key])
        assert (row['seed'], row['length'], row['children']) == (seed, n, 2)
        assert row['original_visits'] == 6*n + 5
        # Eighteen restored wrapper instruction heads are fixed by the separate
        # literal stencil. Reader transparency is counted independently below.
        assert row['comparisons'] == row['original_visits'] + 18
        assert row['comparisons'] <= min(row['original_steps'], row['candidate_steps'])
        assert max(row['original_steps'], row['candidate_steps']) <= 20000
        assert (row['reader_checks'], row['timestamp_joins'], row['returned_records']) == (4, 4, 2)
        expected = sum(((((128+j)*37+11+seed) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15
        assert row['value'] == expected
    assert sum(row['comparisons'] for row in rows) == 872
    return rows


def calibrations(stdout, stderr):
    assert stderr == b'' and 0 < len(stdout) <= 1048576
    text = stdout.decode('ascii')
    pattern = (r'\nrunning 43 tests\n((?:test [A-Za-z0-9_:]+ \.\.\. ok\n){43})\n'
        r'test result: ok\. 43 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9]+\.[0-9]+s\n\n')
    match = re.fullmatch(pattern, text)
    assert match is not None
    names = [line.split()[1] for line in match.group(1).splitlines()]
    assert len(set(names)) == 43


def functional(data, stderr):
    assert stderr == b'' and 0 < len(data) <= 1048576 and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').splitlines()
    assert len(lines) == 51 and lines[0] == SCOPE and lines[-1] == PASS
    csv_bytes = ('\n'.join(lines[1:-1])+'\n').encode('ascii')
    rows = table(csv_bytes, HEADER, 48)
    first_sequence = generation = aux = last_end = None
    for position, row in enumerate(rows):
        original = position < 24
        index = position % 24
        n = 1 if index % 2 == 0 else 64
        assert row['leg'] == ('original' if original else 'installed')
        assert row['owner'] == ('original' if original else 'sampled')
        empty = ORIGINAL_EMPTY if original else frozenset()
        assert all(row[key] == '' for key in empty)
        for key in set(row) - empty - {'leg', 'owner'}:
            row[key] = number(row[key])
        assert (row['external_id'], row['length']) == (0x72656600+index, n)
        assert (row['instructions'], row['branches'], row['taken_branches'], row['input_byte_reads'], row['return_read_bytes']) == (6*n+5, n, n-1, n, 8)
        expected = sum((((j*37+11) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15
        assert row['value'] == expected
        if position == 0:
            first_sequence, aux = row['gate_sequence'], row['reference_start_aux']
            assert 0 < first_sequence <= 2**64-48 and aux < 2**32
        assert row['gate_sequence'] == first_sequence+position
        assert row['reference_start_aux'] == row['reference_end_aux'] == aux
        start, end = row['reference_start_ticks'], row['reference_end_ticks']
        assert start <= end and row['enclosure_ticks'] == end-start
        assert last_end is None or start >= last_end
        last_end = end
        if not original:
            if index == 0:
                generation = row['generation']
                assert generation > 0
            assert (row['ordinal'], row['generation'], row['invocation']) == (index+1, generation, index)
            assert row['raw_start_aux'] == row['raw_end_aux'] == aux
            raw_start, raw_end = row['raw_start_ticks'], row['raw_end_ticks']
            assert start <= raw_start <= raw_end <= end
            assert row['raw_ticks'] == raw_end-raw_start
            assert row['entry_gap_ticks'] == raw_start-start
            assert row['return_gap_ticks'] == end-raw_end
            assert row['enclosure_ticks'] == row['entry_gap_ticks']+row['raw_ticks']+row['return_gap_ticks']
    assert sum(row['instructions'] for row in rows[:24]) == sum(row['instructions'] for row in rows[24:]) == 4800
    return rows, csv_bytes
