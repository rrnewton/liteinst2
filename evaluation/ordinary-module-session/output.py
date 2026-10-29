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


OWNER_PHASE_FIELDS = 'name entered ret_observed confirmed completed unsampled batches banks current_generation history_end reports held_report_copies shared_owner_refusals a_slot b_slot a_report_index_plus1 a_output_emitted checkpoint_calls a_reclaimed b_report_observation detach joins'.split()


def owner_check(stdout, stderr, *, k, direction, geometry, cpus):
    """Fixed owner-control wire only, never an external PID or Arc-ownership proof."""
    assert type(k) is int and k in (10, 1000) and direction in ('csv-length', 'length-csv')
    assert type(stdout) is bytes and len(stdout) <= 629852
    rows = lines(stdout, stderr)
    assert len(rows) <= 3033
    at = 0
    def take(tag, count):
        nonlocal at
        assert at < len(rows)
        row = rows[at]; at += 1
        assert row[:len(tag)] == tag and len(row) == len(tag) + count
        return row[len(tag):]
    run = take(['META', 'run'], 12)
    assert run[:5] == ['module-session-owner-v1', 'session-absolute-v1', 'not-run', str(k), direction]
    install, pid, controller, worker, controller_cpu, worker_cpu, registration = map(uint, run[5:])
    assert install == INSTALL and registration == 1
    assert 0 < pid == controller <= (1 << 31) - 1 and 0 < worker <= (1 << 31) - 1 and worker != pid
    assert type(cpus) is tuple and len(cpus) == 2 and all(type(c) is int and 0 <= c < 1024 for c in cpus)
    assert cpus[0] != cpus[1] and (controller_cpu, worker_cpu) == cpus
    code = take(['META', 'code'], 10)
    assert code[0] == '6f' * 32
    mapping, code_generation, function0, function1, csv_entry, csv_end, length_entry, length_end, caller = map(uint, code[1:])
    assert mapping == csv_entry and code_generation == 1 and (function0, function1) == FUNCTIONS
    csv_length, length_length = geometry['csv_length'], geometry['length_length']
    assert all(type(v) is int for v in (csv_length, length_length, geometry['csv_va'], geometry['length_va'], geometry['continuation']))
    assert 5 <= csv_length <= 256 and 5 <= length_length <= 80
    assert 0 < geometry['csv_va'] <= csv_entry and 0 < csv_entry <= U64 - csv_length and csv_end == csv_entry + csv_length
    base = csv_entry - geometry['csv_va']
    assert 0 < geometry['length_va'] <= U64 - base and length_entry == base + geometry['length_va']
    assert 0 < length_entry <= U64 - length_length and length_end == length_entry + length_length
    assert csv_end <= length_entry and csv_entry // 4096 == (length_end - 1) // 4096
    stack_low, stack_high, caller_low, caller_high = map(uint, take(['META', 'memory'], 4))
    assert 0 < stack_low < stack_high <= U64 and 0 < caller_low <= caller < caller_high
    assert 0 < geometry['continuation'] <= U64 - caller
    continuation = caller + geometry['continuation']; assert continuation < caller_high
    assert take(['META', 'input'], 4) == ['612c622c63', '5', '3', '5']
    returns = geometry['returns']
    assert len(returns) == 2
    for function, offsets in enumerate(returns):
        assert 1 <= len(offsets) <= 4 and list(offsets) == sorted(set(offsets))
        extent = (csv_length, length_length)[function]
        for offset in offsets:
            assert type(offset) is int and 0 < offset < extent
            assert list(map(uint, take(['META', 'ret'], 2))) == [function, offset]
    arow = take(['HISTORY'], 4)
    assert arow[:3] == ['1', '1', 'published']; a = uint(arow[3]); assert a > 0
    h = (k + 3) // 4
    hot = 0 if direction == 'csv-length' else 1
    cold = 1 - hot
    calls, raw, phases, samples = [], [], [], []
    def pair(ordinal, function, generation, owner, invocation, prefix, batch, ack):
        values = take(['CALL'], 9)
        expected = 3 if function == 0 else 5
        assert values[5] == owner
        numbers = [uint(v) for i, v in enumerate(values) if i != 5]
        assert numbers == [ordinal, function, expected, expected, generation, invocation, prefix, batch]
        words = take(['RAW'], 10)
        assert words[8] == ack
        nums = [uint(v) for i, v in enumerate(words) if i != 8]
        o, rsp, return_word, offset, start, end, aux0, aux1, ack_ordinal = nums
        assert o == ordinal and 128 <= rsp <= U64 - 8 and rsp % 16 == 8
        assert stack_low <= rsp - 128 and rsp + 8 <= stack_high
        assert return_word == continuation and caller_low <= return_word < caller_high
        assert offset in returns[function] and aux0 <= U32 and aux1 <= U32
        assert ack_ordinal == (ordinal + 1 if ack == 'next' else 0)
        calls.append(dict(ordinal=ordinal, function=function, generation=generation, owner=owner,
                          invocation_plus1=invocation, prefix=prefix, batch=batch, expected=expected, value=expected))
        raw.append(dict(ordinal=o, entry_rsp=rsp, return_word=return_word, return_offset=offset,
                        start_ticks=start, end_ticks=end, start_aux=aux0, end_aux=aux1, ack=ack, ack_ordinal=ack_ordinal))
    def phase(expected):
        actual = take(['PHASE'], len(OWNER_PHASE_FIELDS))
        parsed = [v if i in (0, 19) else uint(v) for i, v in enumerate(actual)]
        assert parsed == expected
        phases.append(dict(zip(OWNER_PHASE_FIELDS, parsed)))
    for i in range(1, k + 1):
        pair(i, hot, a, 'sampled', i, 1, (i + 3) // 4, 'checkpoint' if i % 4 == 0 or i == k else 'next')
    phase(['hot-exhaust', k, k, k, k, 0, h, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, h, 0, 'not-checked', 0, 0])
    pair(k + 1, cold, a, 'sampled', k + 1, 1, h + 1, 'checkpoint')
    phase(['cold-available', k + 1, k + 1, k + 1, k + 1, 0, h + 1, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, h + 1, 0, 'not-checked', 0, 0])
    phase(['held', k + 2, k + 2, k + 1, k + 1, 0, h + 1, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, h + 1, 0, 'not-checked', 0, 0])
    brow = take(['HISTORY'], 4); assert brow[:3] == ['2', '2', 'published']
    b = uint(brow[3]); assert b > a
    assert list(map(uint, take(['META', 'epochs'], 2))) == [a, b]
    assert list(map(uint, take(['REPORT'], 2))) == [a, k + 1]
    phase(['refused-twice', k + 2, k + 2, k + 1, k + 1, 0, h + 1, 1, b, 2, 1, 1, 2, 1, 1, 1, 1, h + 1, 0, 'not-checked', 0, 0])
    assert take(['HISTORY'], 4) == ['3', '3', 'removed', str(b)]
    phase(['released-before-checkpoint', k + 3, k + 3, k + 2, k + 1, 1, h + 1, 2, 0, 3, 1, 1, 2, 0, 1, 0, 0, h + 1, 1, 'pending', 0, 0])
    pair(k + 2, hot, a, 'closed', 0, 1, h + 2, 'next')
    pair(k + 3, cold, b, 'sampled', 1, 2, h + 2, 'checkpoint')
    assert list(map(uint, take(['REPORT'], 2))) == [b, 1]
    for i, (call, clock) in enumerate(zip(calls, raw)):
        if call['owner'] == 'closed': continue
        generation = call['generation']; invocation = call['invocation_plus1'] - 1
        rank = i if i < k else 0
        sequence = i if i <= k else k + 1
        if clock['start_aux'] != clock['end_aux']: kind, value = 'unavailable', 1
        elif clock['end_ticks'] < clock['start_ticks']: kind, value = 'unavailable', 2
        else: kind, value = 'value', clock['end_ticks']
        row = take(['SAMPLE'], 8); assert row[6] == kind
        numbers = [uint(v) for j, v in enumerate(row) if j != 6]
        assert numbers == [generation, call['function'], invocation, rank, sequence, clock['start_ticks'], value]
        samples.append(dict(generation=generation, function=call['function'], invocation=invocation, rank=rank,
                            start_sequence=sequence, entry_value=clock['start_ticks'], end_kind=kind, end_value=value))
    phase(['finish', k + 3, k + 3, k + 3, k + 2, 1, h + 2, 3, 0, 3, 2, 1, 2, 0, 0, 0, 0, h + 3, 1, 'copied', 1, 1])
    terminal = f'module-session-owner:profile=session-absolute-v1:schedule=not-run:k={k}:direction={direction}:calls={k+3}:confirmed={k+3}:sampled={k+2}:unsampled=1:batches={h+2}:reports=2:actions=3:banks=3:shared-owner-refusals=2:held-report-copies=1:reclaimed-before-checkpoint=1:worker-joins=1:complete'
    assert at + 1 == len(rows) and rows[at] == [terminal]
    return dict(status='OWNER_WIRE_PASS', k=k, direction=direction, calls=calls, raw=raw, phases=phases, samples=samples,
                stdout=stdout, generations=[a, b], pid=pid, worker_tid=worker,
                totals=dict(calls=k+3, sampled=k+2, unsampled=1, batches=h+2, reports=2, actions=3),
                scope='Fixed owner wire only; actual receipt/Arc, source/journal, deadline and closure are external authority.')
