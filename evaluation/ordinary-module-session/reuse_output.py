"""Strict separate reuse wire; native/source/owner qualification stays external."""
if not __debug__:
    raise SystemExit('assertions required')

U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
MAX_BYTES = 631092
MAX_LINES = 3043
INSTALL = 0x6d6f6401
PHASE_FIELDS = (
    'name entered ret_observed confirmed completed unsampled batches banks '
    'current_generation history_end reports held_report_copies shared_owner_refusals '
    'a_slot b_slot c_slot a_report_index_plus1 a_output_emitted checkpoint_calls '
    'a_reclaimed c_restaged b_report_observation c_report_observation '
    'a_copy_unchanged detach joins').split()
ROW_LIMITS = {
    ('META', 'run'): 350, ('META', 'code'): 350, ('META', 'memory'): 100,
    ('META', 'input'): 64, ('META', 'ret'): 64, ('META', 'epochs'): 96,
    ('CALL',): 200, ('RAW',): 220, ('HISTORY',): 96, ('REPORT',): 64,
    ('SAMPLE',): 200, ('PHASE',): 350,
}


def _uint(text):
    assert type(text) is str and 1 <= len(text) <= 20
    assert text == '0' or (text[0] in '123456789' and all(c in '0123456789' for c in text))
    value = int(text)
    assert value <= U64
    return value


def check(stdout, stderr, *, k, direction, geometry, cpus):
    """Wire acceptance only; caller must separately require actual exit 0/closure."""
    assert type(k) is int and k in (10, 1000)
    assert type(direction) is str and direction in ('csv-length', 'length-csv')
    assert type(cpus) is tuple and len(cpus) == 2
    assert all(type(n) is int and 0 <= n < 1024 for n in cpus) and cpus[0] != cpus[1]
    assert type(geometry) is dict
    assert {'csv_length', 'length_length', 'csv_va', 'length_va', 'continuation', 'returns'} <= geometry.keys()
    lengths = (geometry['csv_length'], geometry['length_length'])
    vas = (geometry['csv_va'], geometry['length_va'])
    offset = geometry['continuation']
    assert all(type(n) is int for n in (*lengths, *vas, offset))
    assert 5 <= lengths[0] <= 256 and 5 <= lengths[1] <= 80
    assert all(0 < n <= U64 for n in (*vas, offset))
    returns = geometry['returns']
    assert type(returns) in (tuple, list) and len(returns) == 2
    for extent, offsets in zip(lengths, returns):
        assert type(offsets) in (tuple, list) and 1 <= len(offsets) <= 4
        assert all(type(n) is int and 0 < n < extent for n in offsets)
        assert list(offsets) == sorted(set(offsets))
    assert type(stdout) is bytes and type(stderr) is bytes and stderr == b''
    assert 0 < len(stdout) <= min(MAX_BYTES, (k + 5) * 420 + (k + 4) * 200 + 8192)
    assert stdout.endswith(b'\n')
    text = stdout.decode('ascii')
    lines = text[:-1].split('\n')
    assert len(lines) <= MAX_LINES
    assert all(0 < len(line) + 1 <= 350 and '\r' not in line for line in lines)
    rows = [line.split(',') for line in lines]
    at = 0

    def take(tag, count):
        nonlocal at
        assert at < len(rows)
        row = rows[at]
        assert row[:len(tag)] == list(tag) and len(row) == len(tag) + count
        assert len(lines[at]) + 1 <= ROW_LIMITS[tag]
        at += 1
        return row[len(tag):]

    run = take(('META', 'run'), 12)
    assert run[:5] == ['module-session-reuse-v1', 'session-absolute-v1', 'not-run', str(k), direction]
    install, pid, controller, worker, controller_cpu, worker_cpu, registration = map(_uint, run[5:])
    assert install == INSTALL and registration == 1
    assert 0 < pid == controller <= (1 << 31) - 1
    assert 0 < worker <= (1 << 31) - 1 and worker != pid
    assert (controller_cpu, worker_cpu) == cpus
    code = take(('META', 'code'), 10)
    assert code[0] == '6f' * 32  # Caller namespace, not a file digest.
    mapping, code_generation, f0, f1, entry0, end0, entry1, end1, caller = map(_uint, code[1:])
    assert mapping == entry0 and code_generation == 1 and (f0, f1) == (101, 202)
    assert 0 < vas[0] <= entry0 <= U64 - lengths[0] and end0 == entry0 + lengths[0]
    base = entry0 - vas[0]
    assert vas[1] <= U64 - base and entry1 == base + vas[1]
    assert 0 < entry1 <= U64 - lengths[1] and end1 == entry1 + lengths[1]
    assert end0 <= entry1 and entry0 // 4096 == (end1 - 1) // 4096
    memory = list(map(_uint, take(('META', 'memory'), 4)))
    stack_low, stack_high, caller_low, caller_high = memory
    assert 0 < stack_low < stack_high and 0 < caller_low <= caller < caller_high
    assert offset <= U64 - caller
    continuation = caller + offset
    assert caller_low <= continuation < caller_high
    assert take(('META', 'input'), 4) == ['612c622c63', '5', '3', '5']
    declared = []
    for function, offsets in enumerate(returns):
        for ret in offsets:
            assert list(map(_uint, take(('META', 'ret'), 2))) == [function, ret]
            declared.append(dict(function_index=function, offset=ret))

    calls, raw, phases, samples, histories, reports = [], [], [], [], [], []

    def history(number, kind, expected=None):
        row = take(('HISTORY',), 4)
        assert row[:3] == [str(number), str(number), kind]
        generation = _uint(row[3])
        assert generation > 0 and (expected is None or generation == expected)
        histories.append(dict(chunk=number, prefix=number, kind=kind, generation=generation))
        return generation

    def report(generation, records):
        assert list(map(_uint, take(('REPORT',), 2))) == [generation, records]
        reports.append(dict(generation=generation, records=records))

    def pair(ordinal, function, generation, owner, invocation, prefix, batch, ack):
        row = take(('CALL',), 9)
        expected = (3, 5)[function]
        assert row[5] == owner
        assert [_uint(v) for i, v in enumerate(row) if i != 5] == [
            ordinal, function, expected, expected, generation, invocation, prefix, batch]
        words = take(('RAW',), 10)
        assert words[8] == ack
        o, rsp, word, ret, start, end, aux0, aux1, next_ordinal = (
            _uint(v) for i, v in enumerate(words) if i != 8)
        assert o == ordinal and 128 <= rsp <= U64 - 8 and rsp % 16 == 8
        assert stack_low <= rsp - 128 and rsp + 8 <= stack_high
        assert word == continuation and caller_low <= word < caller_high
        assert ret in returns[function] and aux0 <= U32 and aux1 <= U32
        assert next_ordinal == (ordinal + 1 if ack == 'next' else 0)
        calls.append(dict(ordinal=ordinal, function=function, expected=expected, value=expected,
                          generation=generation, owner=owner, invocation_plus1=invocation,
                          prefix=prefix, batch=batch))
        raw.append(dict(ordinal=o, entry_rsp=rsp, return_word=word, return_offset=ret,
                        start_ticks=start, end_ticks=end, start_aux=aux0, end_aux=aux1,
                        ack=ack, ack_ordinal=next_ordinal))

    def phase(expected):
        row = take(('PHASE',), len(PHASE_FIELDS))
        parsed = [cell if type(want) is str else _uint(cell) for cell, want in zip(row, expected)]
        assert parsed == expected
        phases.append(dict(zip(PHASE_FIELDS, parsed)))

    h = (k + 3) // 4
    hot = 0 if direction == 'csv-length' else 1
    cold = 1 - hot
    a = history(1, 'published')
    for n in range(1, k + 1):
        pair(n, hot, a, 'sampled', n, 1, (n + 3) // 4,
             'checkpoint' if n % 4 == 0 or n == k else 'next')
    phase(['hot-exhaust', k, k, k, k, 0, h, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, 0, h, 0, 0, 'not-checked', 'not-checked', 0, 0, 0])
    pair(k + 1, cold, a, 'sampled', k + 1, 1, h + 1, 'checkpoint')
    phase(['cold-available', k+1, k+1, k+1, k+1, 0, h+1, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, 0, h+1, 0, 0, 'not-checked', 'not-checked', 0, 0, 0])
    phase(['held', k+2, k+2, k+1, k+1, 0, h+1, 2, a, 1, 0, 0, 0, 1, 0, 0, 0, 0, h+1, 0, 0, 'not-checked', 'not-checked', 0, 0, 0])
    b = history(2, 'published')
    assert b > a
    report(a, k + 1)
    phase(['refused-twice', k+2, k+2, k+1, k+1, 0, h+1, 1, b, 2, 1, 1, 2, 1, 1, 0, 1, 1, h+1, 0, 0, 'not-checked', 'not-checked', 1, 0, 0])
    phase(['released-before-checkpoint', k+3, k+3, k+2, k+1, 1, h+1, 2, b, 2, 1, 1, 2, 0, 1, 0, 1, 1, h+1, 1, 0, 'not-checked', 'not-checked', 1, 0, 0])
    c = history(3, 'published')
    assert c > b
    assert list(map(_uint, take(('META', 'epochs'), 3))) == [a, b, c]
    phase(['recycled-armed', k+3, k+3, k+2, k+1, 1, h+1, 1, c, 3, 1, 1, 2, 0, 1, 1, 1, 1, h+1, 1, 1, 'pending', 'not-checked', 1, 0, 0])
    report(b, 1)
    history(4, 'removed', c)
    phase(['recycled-returned', k+5, k+5, k+4, k+3, 1, h+1, 2, 0, 4, 2, 1, 2, 0, 0, 1, 1, 1, h+1, 1, 1, 'copied', 'pending', 1, 0, 0])
    pair(k + 2, hot, a, 'closed', 0, 1, h + 2, 'next')
    pair(k + 3, cold, b, 'sampled', 1, 2, h + 2, 'next')
    pair(k + 4, hot, c, 'sampled', 1, 3, h + 2, 'next')
    pair(k + 5, cold, c, 'sampled', 2, 3, h + 2, 'checkpoint')
    report(c, 2)
    sequence = 0
    for i, (call, clock) in enumerate(zip(calls, raw)):
        if call['owner'] == 'closed':
            continue
        rank = i if i < k else 0
        invocation = call['invocation_plus1'] - 1
        if clock['start_aux'] != clock['end_aux']:
            kind, value = 'unavailable', 1
        elif clock['end_ticks'] < clock['start_ticks']:
            kind, value = 'unavailable', 2
        else:
            kind, value = 'value', clock['end_ticks']
        row = take(('SAMPLE',), 8)
        assert row[6] == kind
        assert [_uint(v) for j, v in enumerate(row) if j != 6] == [
            call['generation'], call['function'], invocation, rank, sequence, clock['start_ticks'], value]
        samples.append(dict(generation=call['generation'], function=call['function'], invocation=invocation,
                            rank=rank, start_sequence=sequence, entry_value=clock['start_ticks'],
                            end_kind=kind, end_value=value))
        sequence += 1
    phase(['finish', k+5, k+5, k+5, k+4, 1, h+2, 3, 0, 4, 3, 1, 2, 0, 0, 0, 1, 1, h+3, 1, 1, 'copied', 'copied', 1, 1, 1])
    terminal = f'module-session-reuse:profile=session-absolute-v1:schedule=not-run:k={k}:direction={direction}:calls={k+5}:confirmed={k+5}:sampled={k+4}:unsampled=1:batches={h+2}:reports=3:actions=4:banks=3:shared-owner-refusals=2:held-report-copies=1:reclaimed-before-checkpoint=1:restaged=1:worker-joins=1:complete'
    assert at + 1 == len(rows) and rows[at] == [terminal]
    assert len(rows) == 3 * k + 35 + len(declared)
    totals = dict(calls=k+5, confirmed=k+5, sampled=k+4, unsampled=1, batches=h+2,
                  checkpoint_calls=h+3, reports=3, actions=4, banks=3, restaged=1)
    meta = dict(
        run=dict(schema=run[0], profile=run[1], schedule=run[2], k=k, direction=direction,
                 install=install, pid=pid, controller_tid=controller, worker_tid=worker,
                 controller_cpu=controller_cpu, worker_cpu=worker_cpu, registration=registration),
        code=dict(source_hex=code[0], mapping=mapping, code_generation=code_generation,
                  function0=f0, function1=f1, csv_entry=entry0, csv_end=end0,
                  length_entry=entry1, length_end=end1, caller_entry=caller),
        memory=dict(zip(('stack_low', 'stack_high', 'caller_low', 'caller_high'), memory)),
        input=dict(payload_hex='612c622c63', length=5, csv_expected=3, length_expected=5),
        returns=declared, epochs=dict(generation_a=a, generation_b=b, generation_c=c))
    completion = dict(profile='session-absolute-v1', schedule='not-run', k=k, direction=direction,
                      calls=k+5, confirmed=k+5, sampled=k+4, unsampled=1, batches=h+2,
                      reports=3, actions=4, banks=3, shared_owner_refusals=2,
                      held_report_copies=1, reclaimed_before_checkpoint=1, restaged=1,
                      worker_joins=1, complete=True)
    return dict(status='REUSE_WIRE_PASS', k=k, direction=direction, stdout=stdout, rows=rows,
                metadata=meta, calls=calls, raw=raw, phases=phases, samples=samples,
                history=histories, reports=reports, terminal=completion, generations=[a, b, c],
                pid=pid, worker_tid=worker, totals=totals,
                counts=dict(META=5+len(declared), CALL=k+5, RAW=k+5, SAMPLE=k+4,
                            HISTORY=4, REPORT=3, PHASE=8, terminal=1),
                scope='Wire-only reuse observations; actual source/ELF/caller, journal/payload, opaque bank/Report ownership, physical return, deadline, exit 0 and normal process closure require separate authority. No Schedule, architectural-state, timing, allocation or A5 qualification.')
