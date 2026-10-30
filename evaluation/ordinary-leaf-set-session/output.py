"""Strict LeafSet numeric wire; native, custody, closure and clocks stay external."""
if not __debug__:
    raise SystemExit('assertions required')

U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
CAP = 4 * 1024 * 1024
LINE = 350
MAX_LINES = 11296
INSTALL = 0x6d6f6401
OPS = ('csv_fields', 'length', 'ascii_digits', 'ascii_spaces')
ERRORS = ('none', 'syntax', 'overlong', 'unterminated', 'record_limit')
FIELDS = {
    'READY': 'version k epochs period_ms lateness_ms payload_cap record_cap batch_call_cap registration install pid controller_tid worker_tid controller_cpu worker_cpu caller_entry n code_generation',
    'LEAF': 'index function_id operation policy elf_va extent entry end declared_returns',
    'RET': 'index offset',
    'HISTORY': 'batch_number absolute_prefix kind generation',
    'REPORT': 'generation records',
    'CALL': 'record_id index ordinal owner generation invocation history_prefix ret_offset entry_rsp return_word start_ticks end_ticks start_aux end_aux acknowledgement ack_ordinal batch_number sequence_before',
    'SAMPLE': 'record_id index generation invocation function_rank sequence_before entry_value end_kind end_value',
    'COVERAGE': 'index accepted sampled function_closed initial_disarmed removed declared_returns observed_return_mask',
    'IO': 'write_blocked',
    'DONE': 'input_status stop_reason armed history_end accepted entered ret_observed confirmed completed unsampled batches csv_input_fields input_bytes raw_eof input_refusal eof_without_error detached source_verified',
}
WORDS = {
    ('READY', 'version'): ('leaf-set-session-v1',),
    ('LEAF', 'operation'): OPS,
    ('LEAF', 'policy'): ('certified', 'whole'),
    ('HISTORY', 'kind'): ('published', 'removed'),
    ('CALL', 'owner'): ('sampled', 'closed', 'initial', 'removed'),
    ('CALL', 'acknowledgement'): ('next', 'checkpoint'),
    ('SAMPLE', 'end_kind'): ('value', 'unavailable'),
    ('DONE', 'input_status'): ('COMPLETE', 'INPUT_REFUSED', 'INPUT_INCOMPLETE'),
    ('DONE', 'stop_reason'): ('Requested', 'EpochLimit'),
    ('DONE', 'input_refusal'): ERRORS,
}


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


def integer(value, low=0, high=U64):
    assert type(value) is int and low <= value <= high
    return value


def add(a, b):
    integer(a); integer(b)
    assert a <= U64 - b
    return a + b


def truths(data):
    """Independent input recognizer and scalar expectations, no selected-code call."""
    assert type(data) is bytes and len(data) <= 64
    assert all(0x20 <= byte <= 0x7e for byte in data)
    # Parse one field at a time, including the final empty field after a comma.
    at, fields = 0, 0
    while True:
        fields += 1
        if at < len(data) and data[at] == 34:
            at += 1
            while True:
                assert at < len(data)
                byte = data[at]; at += 1
                if byte != 34:
                    continue
                if at < len(data) and data[at] == 34:
                    at += 1
                else:
                    break
            assert at == len(data) or data[at] == 44
        else:
            while at < len(data) and data[at] != 44:
                assert data[at] != 34
                at += 1
        if at == len(data):
            break
        assert data[at] == 44
        at += 1
    assert 1 <= fields <= 65
    return dict(csv_fields=fields, length=len(data),
                ascii_digits=sum(48 <= byte <= 57 for byte in data),
                ascii_spaces=data.count(b' '))


def geometry(table, caller, cpus):
    return _geometry(table, caller, cpus, OPS)


def _geometry(table, caller, cpus, allowed_operations):
    assert type(table) is tuple and 1 <= len(table) <= 4
    keys = {'function_id', 'operation', 'policy', 'elf_va', 'extent', 'returns'}
    ids, operations, prior_end = set(), set(), 0
    for leaf in table:
        assert type(leaf) is dict and set(leaf) == keys
        function = integer(leaf['function_id'])
        assert function not in ids; ids.add(function)
        operation = leaf['operation']
        assert type(operation) is str and operation in allowed_operations and operation not in operations
        operations.add(operation)
        assert type(leaf['policy']) is str and leaf['policy'] in ('certified', 'whole')
        extent = integer(leaf['extent'], 1 if leaf['policy'] == 'certified' else 5,
                         256 if leaf['policy'] == 'certified' else 80)
        va = integer(leaf['elf_va'], 1)
        assert va >= prior_end
        prior_end = add(va, extent)
        returns = leaf['returns']
        assert type(returns) is tuple and 1 <= len(returns) <= 4
        assert all(type(offset) is int and 0 <= offset < extent for offset in returns)
        assert returns == tuple(sorted(set(returns)))
    assert type(caller) is dict and set(caller) == {'extent', 'continuation'}
    integer(caller['extent'], 1, 256)
    integer(caller['continuation'], 1, caller['extent'] - 1)
    assert type(cpus) is tuple and len(cpus) == 2 and cpus[0] != cpus[1]
    for cpu in cpus:
        integer(cpu, 0, 1023)


def framing(data, stderr, expected_stderr):
    assert type(data) is bytes and type(stderr) is bytes and stderr == expected_stderr
    assert 0 < len(data) <= CAP and data.endswith(b'\n')
    rows = data.decode('ascii')[:-1].split('\n')
    assert len(rows) <= MAX_LINES
    assert all(0 < len(row) + 1 <= LINE and '\r' not in row for row in rows)
    return [row.split(',') for row in rows]


def check(stdout, stderr, *, records, table, caller, k, epochs, outcome, input_error, cpus):
    return _check(stdout, stderr, records=records, table=table, caller=caller, k=k,
                  epochs=epochs, outcome=outcome, input_error=input_error, cpus=cpus,
                  operations=OPS, version='leaf-set-session-v1', semantic_rows=None,
                  command='normal-leaf-set-session', status='LEAF_SET_WIRE_PASS')


def _check(stdout, stderr, *, records, table, caller, k, epochs, outcome, input_error, cpus,
           operations, version, semantic_rows, command, status):
    # Private semantic seam. The old public wrapper passes its original exact
    # vocabulary and derives every value as before; wire/ownership logic is shared.
    _geometry(table, caller, cpus, operations)
    n = len(table)
    limit = min(2048, 4096 // n)
    integer(k); assert k in (10, 1000)
    integer(epochs, 1, 520)
    assert type(records) is tuple and len(records) <= limit
    expected = tuple(truths(payload) for payload in records)
    count = len(records)
    if semantic_rows is not None:
        assert type(semantic_rows) is tuple and len(semantic_rows) == count
        keys = {'csv_fields', *operations}
        for row, grammar in zip(semantic_rows, expected):
            assert type(row) is dict and set(row) == keys
            for value in row.values():
                integer(value)
            assert row['csv_fields'] == grammar['csv_fields']
        expected = semantic_rows
    assert type(outcome) is str and outcome in ('eof', 'input_error', 'input_incomplete')
    assert type(input_error) is str and input_error in ERRORS
    assert (outcome == 'input_error') == (input_error != 'none')
    expected_stderr = b''
    if outcome == 'input_error':
        assert (count == limit) if input_error == 'record_limit' else (count < limit)
        expected_stderr = (command + ' INPUT_REFUSED: ' + input_error + '\n').encode('ascii')
    elif outcome == 'input_incomplete':
        expected_stderr = (command + ' INPUT_INCOMPLETE\n').encode('ascii')
    fields = dict(FIELDS, RESULT='record_id length checksum ' +
                  ' '.join('value_' + str(i) for i in range(n)) + ' first_ordinal last_ordinal')
    caps = dict(READY=1, LEAF=n, RET=4*n, HISTORY=epochs+1, REPORT=epochs,
                CALL=n*count, RESULT=count, SAMPLE=n*count, COVERAGE=n, IO=1, DONE=1)
    words = dict(WORDS)
    words['READY', 'version'] = (version,)
    words['LEAF', 'operation'] = operations
    parsed, ordered = {tag: [] for tag in fields}, []
    for cells in framing(stdout, stderr, expected_stderr):
        tag, *cells = cells
        assert tag in fields
        names = fields[tag].split()
        assert len(names) == len(cells)
        row = {}
        for name, cell in zip(names, cells):
            choices = words.get((tag, name))
            if choices is None:
                row[name] = uint(cell)
            else:
                assert cell in choices
                row[name] = cell
        parsed[tag].append(row)
        assert len(parsed[tag]) <= caps[tag]
        ordered.append((tag, row))
    assert ordered[0][0] == 'READY'
    assert all(len(parsed[tag]) == 1 for tag in ('READY', 'IO', 'DONE'))
    ready = parsed['READY'][0]
    fixed = dict(k=k, epochs=epochs, period_ms=10, lateness_ms=2, payload_cap=64,
                 record_cap=limit, batch_call_cap=n, registration=1, install=INSTALL,
                 controller_cpu=cpus[0], worker_cpu=cpus[1], n=n, code_generation=1)
    assert all(ready[key] == value for key, value in fixed.items())
    assert 0 < ready['pid'] <= U32 and ready['controller_tid'] == ready['pid']
    assert ready['worker_tid'] > 0 and ready['worker_tid'] != ready['controller_tid']
    caller_entry = integer(ready['caller_entry'], 1)
    add(caller_entry, caller['extent'])
    word = add(caller_entry, caller['continuation'])
    at, bias, pages = 1, None, set()
    for index, leaf in enumerate(table):
        assert at < len(ordered) and ordered[at][0] == 'LEAF'
        row = ordered[at][1]; at += 1
        entry = row['entry']
        assert entry >= leaf['elf_va'] and entry > 0
        if bias is None:
            bias = entry - leaf['elf_va']
        assert entry == add(bias, leaf['elf_va'])
        end = add(entry, leaf['extent'])
        assert row == dict(index=index, function_id=leaf['function_id'], operation=leaf['operation'],
                           policy=leaf['policy'], elf_va=leaf['elf_va'], extent=leaf['extent'],
                           entry=entry, end=end, declared_returns=len(leaf['returns']))
        pages.update(range(entry // 4096, (end - 1) // 4096 + 1))
        for offset in leaf['returns']:
            assert at < len(ordered) and ordered[at] == ('RET', dict(index=index, offset=offset))
            at += 1
    assert 1 <= len(pages) <= 2
    assert len(parsed['LEAF']) == n
    assert all(tag not in ('READY', 'LEAF', 'RET') for tag, _ in ordered[at:])
    assert [tag for tag, _ in ordered[-n-2:]] == ['COVERAGE'] * n + ['IO', 'DONE']
    histories, publications, reports, report_counts = [('initial', 0)], [], [], {}
    counts = [dict(sampled=0, closed=0, initial=0, removed=0) for _ in table]
    observed = [0] * n
    slots, ranks, samples = {}, {}, {}
    calls, completed, result_count, prior_prefix = [], 0, 0, 0
    chunk, chunk_size, group, phase = 0, 0, 0, 'observations'
    previous_tag = 'RET'
    for tag, row in ordered[at:-2]:
        if group:
            assert tag == ('CALL' if group < n else 'RESULT')
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
            assert row['absolute_prefix'] == len(histories)
            assert row['batch_number'] >= 1
            if row['batch_number'] == chunk:
                assert previous_tag == 'HISTORY'
            if row['batch_number'] != chunk:
                assert row['batch_number'] == chunk + 1
                chunk, chunk_size = row['batch_number'], 0
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
            assert histories[-1] != ('published', generation)
            assert row['records'] <= n * k
            reports.append(generation); report_counts[generation] = row['records']
        elif tag == 'CALL':
            ordinal = len(calls) + 1
            index = (ordinal - 1) % n
            record = (ordinal - 1) // n + 1
            assert ordinal <= n * count
            assert result_count == record - 1 and group == index
            assert (row['ordinal'], row['record_id'], row['index'], row['batch_number']) == (ordinal, record, index, record)
            prefix = row['history_prefix']
            assert prior_prefix <= prefix < len(histories)
            prior_prefix = prefix
            state, generation = histories[prefix]
            assert row['generation'] == generation
            owner = row['owner']
            assert owner in ('sampled', 'closed') if state == 'published' else owner == state
            assert row['sequence_before'] == completed
            if owner == 'sampled':
                slot, rank = slots.get(generation, 0), ranks.get((generation, index), 0)
                assert slot < n*k and rank < k
                assert row['invocation'] == add(slot, 1)
                samples[generation, slot] = (row, rank)
                slots[generation] = slot + 1; ranks[generation, index] = rank + 1
                completed += 1
            else:
                assert row['invocation'] == 0
                if owner == 'closed':
                    assert ranks.get((generation, index), 0) == k
            counts[index][owner] += 1
            offsets = table[index]['returns']
            assert row['ret_offset'] in offsets
            observed[index] |= 1 << offsets.index(row['ret_offset'])
            assert 128 <= row['entry_rsp'] <= U64 - 8 and row['entry_rsp'] % 16 == 8
            assert row['return_word'] == word
            assert row['start_aux'] <= U32 and row['end_aux'] <= U32
            ack = 'checkpoint' if index + 1 == n else 'next'
            assert row['acknowledgement'] == ack
            assert row['ack_ordinal'] == (0 if ack == 'checkpoint' else add(ordinal, 1))
            calls.append(row); group += 1
        elif tag == 'RESULT':
            assert group == n
            result_count += 1
            assert result_count <= count and len(calls) == n * result_count
            payload, values = records[result_count-1], expected[result_count-1]
            wanted = dict(record_id=result_count, length=len(payload), checksum=fnv(payload),
                          first_ordinal=n*(result_count-1)+1, last_ordinal=n*result_count)
            wanted.update(('value_' + str(i), values[leaf['operation']]) for i, leaf in enumerate(table))
            assert row == wanted
            group = 0
        previous_tag = tag
    assert group == 0 and len(calls) == n*count and result_count == count
    assert publications and histories[-1] == ('removed', publications[-1])
    assert len(histories) == len(publications) + 2
    assert set(reports) == set(publications)
    assert all(report_counts[generation] == slots.get(generation, 0) for generation in reports)
    expected_samples = []
    for generation in reports:
        for slot in range(report_counts[generation]):
            row, rank = samples[generation, slot]
            assert row['invocation'] == add(slot, 1)
            if row['start_aux'] != row['end_aux']:
                kind, value = 'unavailable', 1
            elif row['end_ticks'] < row['start_ticks']:
                kind, value = 'unavailable', 2
            else:
                kind, value = 'value', row['end_ticks']
            expected_samples.append(dict(record_id=row['record_id'], index=row['index'], generation=generation,
                invocation=slot, function_rank=rank, sequence_before=row['sequence_before'],
                entry_value=row['start_ticks'], end_kind=kind, end_value=value))
    assert parsed['SAMPLE'] == expected_samples
    assert parsed['COVERAGE'] == [dict(index=i, accepted=count, sampled=c['sampled'],
        function_closed=c['closed'], initial_disarmed=c['initial'], removed=c['removed'],
        declared_returns=len(table[i]['returns']), observed_return_mask=observed[i]) for i, c in enumerate(counts)]
    done = parsed['DONE'][0]
    assert done['armed'] == len(publications) and done['history_end'] == len(histories) - 1
    assert done['accepted'] == count
    assert (done['entered'], done['ret_observed'], done['confirmed']) == (n*count,) * 3
    assert done['completed'] == completed and done['unsampled'] == n*count-completed
    assert done['batches'] == count
    assert done['csv_input_fields'] == sum(v['csv_fields'] for v in expected)
    assert done['input_bytes'] == sum(map(len, records))
    assert done['detached'] == done['source_verified'] == 1
    assert done['raw_eof'] in (0, 1) and done['eof_without_error'] in (0, 1)
    assert done['input_refusal'] == input_error
    if outcome == 'eof':
        assert (done['input_status'], done['stop_reason'], done['raw_eof'], done['eof_without_error']) == ('COMPLETE', 'Requested', 1, 1)
    elif outcome == 'input_incomplete':
        assert (done['input_status'], done['stop_reason'], done['raw_eof'], done['eof_without_error']) == ('INPUT_INCOMPLETE', 'EpochLimit', 0, 0)
        assert done['armed'] == epochs
    else:
        assert done['input_status'] == 'INPUT_REFUSED' and done['stop_reason'] == 'Requested'
        assert done['eof_without_error'] == 0
        if input_error == 'unterminated':
            assert done['raw_eof'] == 1
    return dict(status=status, outcome=outcome, input_error=input_error,
                expected_exit=0 if outcome == 'eof' else 1, rows=parsed, ordered=ordered,
                raw=stdout, stderr=stderr,
                totals=dict(records=count, functions=n, calls=n*count, sampled=completed,
                            unsampled=n*count-completed, epochs=len(publications), batches=count),
                scope='Numeric wire and independent accepted population only. Physical mapping/source/caller custody, full512-word journals, opaque SDK owners/payloads, actual process exit/closure, Schedule deadlines and native/full-state authority remain external.')
