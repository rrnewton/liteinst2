"""Closed strnlen protocols and build-input checks; no runtime or cache/timing model."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import hashlib
import re

MIB = 1048576
U64 = (1 << 64) - 1
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
CASES = ('zero-bound', 'single-empty', 'single-nonzero', 'last-of-two',
         'interior', 'long-empty', 'long-last', 'full-bound')
BOUNDS = (0, 1, 1, 2, 17, 64, 64, 64)
NULS = (None, 0, None, 1, 8, 0, 63, None)
VALUES = (0, 0, 1, 1, 8, 0, 63, 64)
OWNERS = ('sampled', 'sampled', 'closed', 'closed', 'removed', 'sampled', 'sampled', 'closed')
INVOCATIONS = (0, 1, None, None, None, 0, 1, None)
PREFIXES = (1, 1, 1, 1, 2, 3, 3, 3)
STATE_HEADER = 'seed,case,bound,status,children,comparisons,original_visits,original_steps,candidate_steps,value,input_reads,input_bytes,observed_heads,observed_edges,declared_heads,declared_edges,declared_returns,ret_offset'
WORK_COMMENT = '# unchanged FreeBSD strnlen calls; raw callback ticks are uncalibrated; no accuracy or performance claim'
WORK_HEADER = 'ordinal,case,bound,owner,generation,invocation,history_prefix,ret_offset,native_value,value,start_ticks,end_ticks,start_aux,end_aux,elapsed_ticks'
WORK_TERMINAL = 'strnlen-work PASS originals=8 calls=8 sampled=4 closed=3 removed=1 reports=2+2 batches=1 events=16 actions=4 entries=8 returns=8 completed=4 unsampled=4 raw_rows=8 input_unchanged=true joined=true'
REFUSALS = ('named-final,expected-refusal,SymbolOwner', 'wrong-whole-file,expected-refusal,SourceBytes',
            'changed-selected-byte,expected-refusal,SourceBytes')
REFUSAL_TERMINAL = 'strnlen-refusals complete cases=3 expected_refusals=3 subject_calls=0'
SOURCE_SHA256 = '969eb826cd618ff799cdc4fcc9d61edd044a314bd39208479787eda622c4f336'
SOURCE_BLOB = 'b44f8ab2194710a91dfde4be07384f1fbdeec79a'
BODY = 'size_t strnlen(const char *s, size_t maxlen) { size_t len; for (len = 0; len < maxlen; len++, s++) { if (!*s) break; } return (len); }'


def lines(data):
    assert type(data) is bytes and 0 < len(data) <= MIB and data.endswith(b'\n')
    assert all(c == 10 or 32 <= c < 127 for c in data)
    return data.decode('ascii')[:-1].split('\n')


def uint(value, maximum=U64):
    assert re.fullmatch(r'0|[1-9][0-9]*', value)
    number = int(value)
    assert number <= maximum
    return number


def expected(index):
    data = [1 + ((37 * i + 128) % 255) for i in range(64)]
    if NULS[index] is not None:
        data[NULS[index]] = 0
    result = next((i for i, value in enumerate(data[:BOUNDS[index]]) if value == 0), BOUNDS[index])
    assert result == VALUES[index]
    return result


def state(table, stdout, stderr, function_length):
    assert stderr == b'' and type(function_length) is int and 5 <= function_length <= 80
    text = lines(table)
    assert len(text) == 17 and text[0] == STATE_HEADER
    rows = []
    for number, line in enumerate(text[1:]):
        index, seed = number % 8, SEEDS[number // 8]
        fields = line.split(',')
        assert len(fields) == 18
        row = dict(zip(STATE_HEADER.split(','), fields))
        assert row['case'] == CASES[index] and row['status'] == 'PASS'
        for key in row:
            if key not in ('case', 'status'):
                row[key] = uint(row[key])
        assert (row['seed'], row['bound'], row['children'], row['value']) == (seed, BOUNDS[index], 2, expected(index))
        assert 0 < row['original_visits'] and row['comparisons'] == row['original_visits'] + 11
        assert row['comparisons'] <= row['original_steps'] <= 20000
        assert row['comparisons'] <= row['candidate_steps'] <= 20000
        assert 1 <= row['observed_heads'] <= row['declared_heads'] <= function_length
        assert row['observed_edges'] <= row['declared_edges'] <= 2 * row['declared_heads']
        assert 1 <= row['declared_returns'] <= 4 and 0 < row['ret_offset'] < function_length
        assert row['input_reads'] <= row['original_visits']
        assert row['input_reads'] <= row['input_bytes'] <= 8 * row['input_reads']
        assert (row['input_reads'] == row['input_bytes'] == 0) if index == 0 else row['input_reads'] > 0
        rows.append(row)
    declared = {(r['declared_heads'], r['declared_edges'], r['declared_returns']) for r in rows}
    assert len(declared) == 1
    returns = [{r['ret_offset'] for r in rows[start:start + 8]} for start in (0, 8)]
    assert returns[0] == returns[1] and len(returns[0]) == rows[0]['declared_returns']
    comparisons = sum(r['comparisons'] for r in rows)
    reads, byte_count = (sum(r[k] for r in rows) for k in ('input_reads', 'input_bytes'))
    assert lines(stdout) == [f'native-strnlen:selection=freebsd-strnlen-14.1-v1:required=16:pairs=16:children=32:comparisons={comparisons}:input-reads={reads}:input-bytes={byte_count}:coverage-seeds=2:real-outer-ret=32:complete']
    return dict(summary=dict(status='PASS', pairs=16, children=32, comparisons=comparisons,
        input_reads=reads, input_bytes=byte_count, coverage_seeds=2, real_outer_returns=32,
        ret_offsets=sorted(returns[0])), rows=rows,
        source_attested='Full original/candidate state and input, actual input operand containment, complete head/edge/RET union, source/image/Report joins and normal reaps. Scalar CSV cannot independently replay those complete checks.')


def work(stdout, stderr, function_length):
    assert stderr == b'' and type(function_length) is int and 5 <= function_length <= 80
    text = lines(stdout)
    assert len(text) == 11 and text[:2] == [WORK_COMMENT, WORK_HEADER] and text[-1] == WORK_TERMINAL
    rows = []
    for index, line in enumerate(text[2:-1]):
        fields = line.split(',')
        assert len(fields) == 15
        row = dict(zip(WORK_HEADER.split(','), fields))
        assert row['case'] == CASES[index] and row['owner'] == OWNERS[index]
        for key in row:
            if key not in ('case', 'owner'):
                row[key] = None if key == 'invocation' and row[key] == '' else uint(row[key])
        assert (row['ordinal'], row['bound']) == (index + 1, BOUNDS[index])
        assert row['generation'] > 0 and row['invocation'] == INVOCATIONS[index]
        assert row['history_prefix'] == PREFIXES[index] and 0 < row['ret_offset'] < function_length
        assert row['native_value'] == row['value'] == expected(index)
        assert row['start_aux'] == row['end_aux'] < (1 << 32)
        assert row['start_ticks'] <= row['end_ticks'] and row['elapsed_ticks'] == row['end_ticks'] - row['start_ticks']
        rows.append(row)
    a, b = rows[0]['generation'], rows[5]['generation']
    assert a < b and [r['generation'] for r in rows] == [a] * 5 + [b] * 3
    return dict(summary=dict(status='PASS', originals=8, calls=8, sampled=4, closed=3, removed=1,
        reports=[2, 2], batches=1, events=16, actions=4, entries=8, returns=8, completed=4,
        unsampled=4, raw_rows=8, generations=[a, b]), rows=rows,
        source_attested='Actual original/installed calls, complete guarded input, return/sequence joins, two handshakes, all512 journal words, complete Reports, detach and real worker join; not a CSV replay of full state.',
        scope='Uncalibrated raw callback ticks; no accuracy, performance or full-A5 claim.')


def refusals(stdout, stderr):
    assert stderr == b''
    assert lines(stdout) == ['case,status,refusal', *REFUSALS, REFUSAL_TERMINAL]
    return dict(status='PASS', cases=3, expected_refusals=3, subject_calls=0,
        rows=[dict(zip(('case', 'status', 'refusal'), line.split(','))) for line in REFUSALS],
        scope='Preload public-loader refusals; no native malformed pointer or wrong-runtime-base credit.')


def join(state_result, work_result):
    states, calls = state_result['rows'], work_result['rows']
    assert len(states) == 16 and len(calls) == 8
    assert {r['ret_offset'] for r in calls} == set(state_result['summary']['ret_offsets'])
    for index, call in enumerate(calls):
        pair = [states[index], states[index + 8]]
        assert all((r['case'], r['bound'], r['value']) == (call['case'], call['bound'], call['value']) for r in pair)
        assert call['ret_offset'] in {r['ret_offset'] for r in pair}


def dependencies(data):
    assert type(data) is bytes and 0 < len(data) <= MIB and data.endswith(b'\n')
    assert all(c in (9, 10) or 32 <= c < 127 for c in data)
    text = data.decode('ascii').replace('\\\n', ' ')
    assert text.startswith('strnlen-inputs:') and text.count(':') == 1
    names = text[len('strnlen-inputs:'):].split()
    assert 1 <= len(names) <= 128 and len(names) == len(set(names))
    assert all(re.fullmatch(r'/[A-Za-z0-9_.+/-]+', name) and '..' not in name.split('/') for name in names)
    return names


def preprocessing(source, expanded, defines):
    assert hashlib.sha256(source).hexdigest() == SOURCE_SHA256
    assert hashlib.sha1(b'blob ' + str(len(source)).encode() + b'\0' + source).hexdigest() == SOURCE_BLOB
    assert type(expanded) is bytes and 0 < len(expanded) <= MIB
    text = expanded.decode('ascii')
    compact = re.sub(r'\s+', '', text)
    assert compact.endswith(re.sub(r'\s+', '', BODY))
    # A second inline/fortify/substituted definition is not the pinned subject.
    assert len(re.findall(r'\bstrnlen\s*\([^;{}]*\)\s*\{', text)) == 1
    assert 'typedeflongunsignedintsize_t;' in compact or 'typedefunsignedlongintsize_t;' in compact
    assert type(defines) is bytes and 0 < len(defines) <= MIB and defines.endswith(b'\n')
    macros = {}
    for line in defines.decode('ascii')[:-1].split('\n'):
        match = re.fullmatch(r'#define ([A-Za-z_][A-Za-z_0-9]*)(\([^\n]*?\))?(?: (.*))?', line)
        assert match and match[1] not in macros
        macros[match[1]] = (match[2], match[3] or '')
    required = {'__SIZEOF_POINTER__': '8', '__SIZEOF_SIZE_T__': '8', '__SIZEOF_LONG__': '8',
        '__SIZEOF_INT__': '4', '__CHAR_BIT__': '8', '__LP64__': '1', '_LP64': '1',
        '__x86_64__': '1', '__linux__': '1', '__STDC_HOSTED__': '1',
        '__BYTE_ORDER__': '__ORDER_LITTLE_ENDIAN__', '__ORDER_LITTLE_ENDIAN__': '1234'}
    assert all(macros.get(k) == (None, value) for k, value in required.items())
    assert macros.get('__SIZE_TYPE__') in ((None, 'long unsigned int'), (None, 'unsigned long int'))
    assert 'strnlen' not in macros and 'size_t' not in macros
    return dict(architecture='x86_64', operating_system='linux', data_model='LP64', pointer_bits=64,
        size_t_bits=64, char_bits=8, function_body='exact pinned strnlen definition after preprocessing')
