"""Strict module-session wire checks; process/source/native authority is external."""
if not __debug__:
    raise SystemExit('assertions required')

U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
CAP = 4 * 1024 * 1024
INSTALL = 0x6d6f6401
FUNCTIONS = (101, 202)
FIELDS = {
    'READY': 'schema k epoch_limit period_ms lateness_ms payload_limit record_limit queue_capacity reply_capacity install pid main_tid worker_tid controller_cpu worker_cpu csv_entry length_entry csv_end length_end caller_entry',
    'RET': 'function offset',
    'HISTORY': 'chunk absolute_index kind generation',
    'REPORT': 'generation records',
    'CALL': 'id function ordinal owner generation invocation_plus_one history_prefix return_offset entry_rsp return_word start_ticks end_ticks start_aux end_aux ack ack_ordinal batch sequence_before',
    'RESULT': 'id length checksum csv_value length_value csv_ordinal length_ordinal',
    'SAMPLE': 'id function generation invocation rank sequence_before entry_value end_kind end_value',
    'COVERAGE': 'function physical_calls sampled_calls closed_calls initial_calls removed_calls declared_returns observed_return_mask',
    'IO': 'write_blocked',
    'DONE': 'status stop_reason armed history_end accepted entered ret_observed confirmed completed unsampled batches fields_total bytes_total eof input_error input_complete detach joins',
}
WORDS = {
    ('READY', 'schema'): ('module-session-v1',),
    ('HISTORY', 'kind'): ('published', 'removed'),
    ('CALL', 'owner'): ('sampled', 'closed', 'initial', 'removed'),
    ('CALL', 'ack'): ('next', 'checkpoint'),
    ('SAMPLE', 'end_kind'): ('value', 'unavailable'),
    ('DONE', 'status'): ('COMPLETE', 'INPUT_REFUSED', 'INPUT_INCOMPLETE'),
    ('DONE', 'stop_reason'): ('Requested', 'EpochLimit'),
    ('DONE', 'input_error'): ('none', 'syntax', 'overlong', 'unterminated', 'record_limit'),
}
MAX = dict(READY=1, RET=8, HISTORY=521, REPORT=520, CALL=4096,
           RESULT=2048, SAMPLE=4096, COVERAGE=2, IO=1, DONE=1)


def uint(text):
    assert isinstance(text, str) and 1 <= len(text) <= 20
    assert text == '0' or (text[0] in '123456789' and all(c in '0123456789' for c in text))
    value = int(text)
    assert value <= U64
    return value


def fnv(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & U64
    return value


def lines(data, stderr, expected_stderr=b''):
    assert type(data) is bytes and type(stderr) is bytes and stderr == expected_stderr
    assert 0 < len(data) <= CAP and data.endswith(b'\n')
    text = data.decode('ascii')
    rows = text[:-1].split('\n')
    assert len(rows) <= 11294
    assert all(0 < len(row) + 1 <= 350 and '\r' not in row for row in rows)
    return [row.split(',') for row in rows]


def expected_records(records):
    assert type(records) is tuple and len(records) <= 2048
    for record in records:
        assert type(record) is tuple and len(record) == 2
        payload, fields = record
        assert type(payload) is bytes and len(payload) <= 64
        assert all(0x20 <= byte <= 0x7e for byte in payload)
        assert type(fields) is int and 1 <= fields <= 65


def check(stdout, stderr, *, records, k, epochs, outcome, input_error,
          lengths, returns, continuation, cpus):
    expected_records(records)
    assert type(k) is int and k in (10, 1000)
    assert type(epochs) is int and 1 <= epochs <= 520
    assert outcome in ('eof', 'input_error', 'input_incomplete')
    assert input_error in WORDS['DONE', 'input_error']
    assert (outcome == 'input_error') == (input_error != 'none')
    expected_stderr = b''
    if outcome == 'input_error':
        expected_stderr = ('normal-module-session INPUT_REFUSED: ' + input_error + '\n').encode('ascii')
    elif outcome == 'input_incomplete':
        expected_stderr = b'normal-module-session INPUT_INCOMPLETE\n'
    assert type(lengths) is tuple and len(lengths) == 2
    assert all(type(n) is int for n in lengths)
    assert 5 <= lengths[0] <= 256 and 5 <= lengths[1] <= 80
    assert type(returns) is tuple and len(returns) == 2
    for length, offsets in zip(lengths, returns):
        assert type(offsets) is tuple and 1 <= len(offsets) <= 4
        assert all(type(n) is int and 0 < n < length for n in offsets)
        assert offsets == tuple(sorted(set(offsets)))
    assert type(continuation) is int and 0 < continuation <= U64
    assert type(cpus) is tuple and len(cpus) == 2 and cpus[0] != cpus[1]
    assert all(type(cpu) is int and 0 <= cpu < 1024 for cpu in cpus)
    parsed = {tag: [] for tag in FIELDS}
    ordered = []
    for row in lines(stdout, stderr, expected_stderr):
        tag, *cells = row
        assert tag in FIELDS
        names = FIELDS[tag].split()
        assert len(cells) == len(names)
        value = {}
        for name, cell in zip(names, cells):
            choices = WORDS.get((tag, name))
            if choices is not None:
                assert cell in choices
                value[name] = cell
            else:
                value[name] = uint(cell)
        parsed[tag].append(value)
        assert len(parsed[tag]) <= MAX[tag]
        ordered.append((tag, value))
    assert ordered[0][0] == 'READY' and [tag for tag, _ in ordered[-2:]] == ['IO', 'DONE']
    assert all(len(parsed[tag]) == 1 for tag in ('READY', 'IO', 'DONE'))
    ready = parsed['READY'][0]
    assert (ready['k'], ready['epoch_limit']) == (k, epochs)
    assert tuple(ready[key] for key in ('period_ms', 'lateness_ms', 'payload_limit', 'record_limit', 'queue_capacity', 'reply_capacity', 'install')) == (10, 2, 64, 2048, 4, 1, INSTALL)
    assert 0 < ready['pid'] <= U32 and ready['main_tid'] == ready['pid']
    assert 0 < ready['worker_tid'] <= U32 and ready['worker_tid'] != ready['main_tid']
    assert (ready['controller_cpu'], ready['worker_cpu']) == cpus
    entries = (ready['csv_entry'], ready['length_entry'])
    ends = (ready['csv_end'], ready['length_end'])
    assert all(0 < entry <= U64 - length and end == entry + length
               for entry, length, end in zip(entries, lengths, ends))
    assert ends[0] <= entries[1] and entries[0] // 4096 == (ends[1] - 1) // 4096
    assert 0 < ready['caller_entry'] <= U64 - continuation
    word = ready['caller_entry'] + continuation
    declared = [dict(function=function, offset=offset)
                for function, offsets in zip(FUNCTIONS, returns) for offset in offsets]
    assert parsed['RET'] == declared
    assert ordered[1:1 + len(declared)] == [('RET', value) for value in declared]
    assert all(tag not in ('READY', 'RET') for tag, _ in ordered[1 + len(declared):])
    n = len(records)
    histories = [('initial', 0)]
    publications = []
    reports = []
    report_counts = {}
    counts = {function: dict(sampled=0, closed=0, initial=0, removed=0) for function in FUNCTIONS}
    per_function = {}
    per_generation = {}
    samples = {}
    observed = {function: 0 for function in FUNCTIONS}
    calls = []
    result_count = 0
    completed = 0
    previous_prefix = 0
    batch = 0
    batch_size = 0
    chunk = 0
    chunk_size = 0
    phase = 'observations'
    for tag, row in ordered[1 + len(declared):-2]:
        if tag in ('HISTORY', 'REPORT', 'CALL', 'RESULT'):
            assert phase == 'observations'
        elif tag == 'SAMPLE':
            assert phase in ('observations', 'samples')
            phase = 'samples'
        elif tag == 'COVERAGE':
            phase = 'coverage'
        else:
            assert False
        if tag == 'HISTORY':
            assert row['absolute_index'] == len(histories)
            assert row['chunk'] >= 1
            if row['chunk'] != chunk:
                assert row['chunk'] == chunk + 1
                chunk, chunk_size = row['chunk'], 0
            chunk_size += 1
            assert chunk_size <= 8
            kind, generation = row['kind'], row['generation']
            assert generation > 0 and histories[-1][0] != 'removed'
            if kind == 'published':
                assert len(publications) < epochs
                assert not publications or generation > publications[-1]
                publications.append(generation)
            else:
                assert publications and generation == publications[-1]
            histories.append((kind, generation))
        elif tag == 'REPORT':
            generation = row['generation']
            assert generation in publications and generation not in report_counts
            assert row['records'] <= 2 * k
            reports.append(generation)
            report_counts[generation] = row['records']
        elif tag == 'CALL':
            ordinal = len(calls) + 1
            function = FUNCTIONS[(ordinal - 1) % 2]
            assert ordinal <= 2 * n
            assert (row['ordinal'], row['id'], row['function']) == (ordinal, (ordinal + 1) // 2, function)
            prefix = row['history_prefix']
            assert previous_prefix <= prefix < len(histories)
            previous_prefix = prefix
            state, generation = histories[prefix]
            assert row['generation'] == generation
            owner = row['owner']
            assert owner in ('sampled', 'closed') if state == 'published' else owner == state
            assert row['sequence_before'] == completed
            if owner == 'sampled':
                invocation = per_generation.get(generation, 0)
                rank = per_function.get((generation, function), 0)
                assert rank < k and invocation < 2 * k
                assert row['invocation_plus_one'] == invocation + 1
                samples[generation, invocation] = (row, rank)
                per_generation[generation] = invocation + 1
                per_function[generation, function] = rank + 1
                completed += 1
            else:
                assert row['invocation_plus_one'] == 0
                if owner == 'closed':
                    assert per_function.get((generation, function), 0) == k
            counts[function][owner] += 1
            offsets = returns[FUNCTIONS.index(function)]
            assert row['return_offset'] in offsets
            observed[function] |= 1 << offsets.index(row['return_offset'])
            assert 128 <= row['entry_rsp'] <= U64 - 8 and row['entry_rsp'] % 16 == 8
            assert row['return_word'] == word
            assert row['start_aux'] <= U32 and row['end_aux'] <= U32
            if row['batch'] != batch:
                assert row['batch'] == batch + 1
                assert not calls or (calls[-1]['ack'] == 'checkpoint' and batch_size in (2, 4))
                batch, batch_size = row['batch'], 0
            else:
                assert calls and calls[-1]['ack'] == 'next'
            batch_size += 1
            assert batch_size <= 4
            assert row['ack_ordinal'] == (ordinal + 1 if row['ack'] == 'next' else 0)
            calls.append(row)
        elif tag == 'RESULT':
            result_count += 1
            assert result_count <= n and len(calls) >= 2 * result_count
            payload, fields = records[result_count - 1]
            assert row == dict(id=result_count, length=len(payload), checksum=fnv(payload),
                               csv_value=fields, length_value=len(payload),
                               csv_ordinal=2 * result_count - 1, length_ordinal=2 * result_count)
    assert len(calls) == 2 * n and result_count == n
    assert not calls or (calls[-1]['ack'] == 'checkpoint' and batch_size in (2, 4))
    assert publications and histories[-1] == ('removed', publications[-1])
    assert len(histories) == len(publications) + 2
    assert set(reports) == set(publications)
    assert all(report_counts[generation] == per_generation.get(generation, 0) for generation in reports)
    expected_samples = []
    for generation in reports:
        for invocation in range(report_counts[generation]):
            row, rank = samples[generation, invocation]
            if row['start_aux'] != row['end_aux']:
                end_kind, end_value = 'unavailable', 1
            elif row['end_ticks'] < row['start_ticks']:
                end_kind, end_value = 'unavailable', 2
            else:
                end_kind, end_value = 'value', row['end_ticks']
            expected_samples.append(dict(id=row['id'], function=row['function'], generation=generation,
                                         invocation=invocation, rank=rank, sequence_before=row['sequence_before'],
                                         entry_value=row['start_ticks'], end_kind=end_kind, end_value=end_value))
    assert parsed['SAMPLE'] == expected_samples
    expected_coverage = []
    for function, offsets in zip(FUNCTIONS, returns):
        value = counts[function]
        expected_coverage.append(dict(function=function, physical_calls=n,
                                     **{name + '_calls': value[name] for name in value},
                                     declared_returns=len(offsets), observed_return_mask=observed[function]))
    assert parsed['COVERAGE'] == expected_coverage
    assert [tag for tag, _ in ordered[-4:]] == ['COVERAGE', 'COVERAGE', 'IO', 'DONE']
    done = parsed['DONE'][0]
    assert done['armed'] == len(publications) and done['history_end'] == len(histories) - 1
    assert done['accepted'] == n
    assert (done['entered'], done['ret_observed'], done['confirmed']) == (2 * n,) * 3
    assert done['completed'] == completed and done['unsampled'] == 2 * n - completed
    assert done['batches'] == batch
    assert done['fields_total'] == sum(fields for _, fields in records)
    assert done['bytes_total'] == sum(len(payload) for payload, _ in records)
    assert done['detach'] == done['joins'] == 1
    assert done['eof'] in (0, 1) and done['input_complete'] in (0, 1)
    assert done['input_error'] == input_error
    if outcome == 'eof':
        assert (done['status'], done['stop_reason'], done['eof'], done['input_complete']) == ('COMPLETE', 'Requested', 1, 1)
    elif outcome == 'input_incomplete':
        assert (done['status'], done['stop_reason'], done['eof'], done['input_complete']) == ('INPUT_INCOMPLETE', 'EpochLimit', 0, 0)
        assert done['armed'] == epochs
    else:
        assert done['status'] == 'INPUT_REFUSED' and done['stop_reason'] == 'Requested'
        assert done['input_complete'] == 0
        if input_error == 'unterminated':
            assert done['eof'] == 1
    return dict(status='FUNCTIONAL_WIRE_PASS', rows=parsed, raw=stdout,
                totals=dict(records=n, calls=2 * n, sampled=completed, unsampled=2 * n - completed,
                            epochs=len(publications), batches=batch),
                scope='Wire identities and complete declared input population only; process closure, source custody, journal words, Schedule and native state are external authority.')


def original_check(stdout, stderr, *, records, lengths, cpu):
    expected_records(records)
    assert type(lengths) is tuple and len(lengths) == 2
    assert type(cpu) is int and 0 <= cpu < 1024
    rows = lines(stdout, stderr)
    assert len(rows) == len(records) + 2
    ready = rows[0]
    assert len(ready) == 11 and ready[:2] == ['ORIGINAL_READY', 'module-original-v1']
    values = list(map(uint, ready[2:]))
    pid, tid, actual_cpu, entry0, end0, entry1, end1, caller, count = values
    assert 0 < pid <= U32 and tid == pid and actual_cpu == cpu and caller > 0
    assert count == len(records)
    assert all(type(length) is int for length in lengths)
    assert 5 <= lengths[0] <= 256 and 5 <= lengths[1] <= 80
    assert 0 < entry0 <= U64 - lengths[0] and end0 == entry0 + lengths[0]
    assert 0 < entry1 <= U64 - lengths[1] and end1 == entry1 + lengths[1]
    assert end0 <= entry1 and entry0 // 4096 == (end1 - 1) // 4096
    results = []
    for index, (row, (payload, fields)) in enumerate(zip(rows[1:-1], records), 1):
        assert len(row) == 6 and row[0] == 'ORIGINAL'
        numbers = list(map(uint, row[1:]))
        assert numbers == [index, len(payload), fnv(payload), fields, len(payload)]
        results.append(numbers)
    assert rows[-1][0] == 'ORIGINAL_DONE' and len(rows[-1]) == 4
    assert list(map(uint, rows[-1][1:])) == [len(records), 2 * len(records), 2 * len(records)]
    return dict(status='ORIGINAL_SCALAR_PASS', ready=values, results=results, raw=stdout,
                scope='Actual original scalar rows joined to independent expected inputs; external source, caller and process custody remain required.')


ORIGINAL_REFUSALS = (
    'bad_magic', 'count_over_2048', 'truncated_length', 'truncated_payload',
    'length_over_64', 'non_ascii_payload', 'malformed_csv', 'trailing_input_byte')


def original_refusal(stdout, stderr, exit_code, reason):
    """Typed input refusal only; source, owner closure and deadline are external."""
    assert type(reason) is str and reason in ORIGINAL_REFUSALS
    assert type(exit_code) is int and exit_code == 2
    assert type(stdout) is bytes and stdout == b''
    assert type(stderr) is bytes
    assert stderr == b'module-session-original INPUT_REFUSED: ' + reason.encode('ascii') + b'\n'
    return dict(status='EXPECTED_INPUT_REFUSAL', reason=reason, exit_code=exit_code)
