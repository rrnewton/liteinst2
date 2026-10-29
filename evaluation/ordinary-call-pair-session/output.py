"""Direct nested CallPair wire checks; physical execution and owned closure are external."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

U64 = (1 << 64) - 1
U32 = (1 << 32) - 1
CAP = 4194304
ROW_CAP = 350
PROFILE = 'normal-call-pair-session-v1'
STATUS = 'CALL_PAIR_SESSION_FUNCTIONAL_PASS'
FUNCTIONS = (501, 502)
FIELDS = {
    'READY': 'profile K epoch_limit active_ms poll_lateness_ms payload_cap record_cap queue_cap registration install pid main_tid worker_tid main_cpu worker_cpu caller_entry'.split(),
    'FUNCTION': 'node function_id elf_va extent runtime_entry runtime_end declared_returns'.split(),
    'RET': 'node offset'.split(),
    'EDGE': 'call_pc child_entry continuation child_stack_delta'.split(),
    'HISTORY': 'batch_number absolute_prefix_1 kind generation'.split(),
    'REPORT': 'generation rows'.split(),
    'CALL': 'id node function_id ordinal parent_ordinal owner generation invocation_1 history_prefix sequence_before actual_children has_sampled_children sampled_children_or_zero acknowledgement rank_1_or_zero'.split(),
    'RAW': 'id node entry_pc return_pc entry_rsp return_word resume_pc resume_rsp value start_ticks end_ticks start_aux end_aux'.split(),
    'RESULT': 'id length fnv1a64 packed_result expected_fields parent_ordinal child_ordinal'.split(),
    'SAMPLE': 'id node function_id generation invocation_0 rank_0 start_sequence entry_ticks thread completed_children observation_kind observation_value'.split(),
    'COVERAGE': 'node sampled function_closed removed initial observed_ret_mask declared_ret_mask'.split(),
    'IO': ['write_blocked_count'],
    'DONE': 'input_status stop_reason arms history_end accepted entered ret_observed confirmed completed unsampled roots child_acks batches field_sum byte_sum observed_eof input_error input_complete'.split(),
}
WORDS = {
    ('READY', 'profile'): (PROFILE,),
    ('HISTORY', 'kind'): ('published', 'removed'),
    ('CALL', 'owner'): ('sampled', 'closed', 'removed', 'initial'),
    ('CALL', 'acknowledgement'): ('checkpoint', 'continuation'),
    ('SAMPLE', 'observation_kind'): ('value', 'unavailable'),
    ('DONE', 'input_status'): ('COMPLETE', 'INPUT_REFUSED', 'INPUT_INCOMPLETE'),
    ('DONE', 'stop_reason'): ('Requested', 'EpochLimit'),
    ('DONE', 'input_error'): ('none', 'syntax', 'overlong', 'unterminated', 'record_limit'),
}
SOURCE_ATTESTED = (
    'Opaque receipt identity, Completion/Terminal global invocation slots, complete Payloads and LIFO receipt consumption.',
    'Every physical 512-word journal including its zero tail, captured thread/stack identity and actual call/return acknowledgements.',
    'Held file/image/input/unsafe writable-stack ownership and complete emitted ELF/caller/parent/child admission.',
)
SCOPE = ('Numeric functional transcript only, tentative until exact actual exit and final owned source/artifact/retirement closure. '
         'No independent Schedule/deadline, native-state, K-exhaustion beyond observed rows, owner-reuse, timing, accuracy or full-A5 authority.')


# These two primitives are byte-literal copies from ordinary-module-session/output.py.
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


def number(value, low=0, high=U64):
    assert type(value) is int and low <= value <= high
    return value


def add(a, b):
    return number(number(a) + number(b))


def fields(data):
    """One printable valid CSV record; empty bytes mean one empty field."""
    assert type(data) is bytes and len(data) <= 64
    assert all(32 <= byte < 127 for byte in data)
    offset = 0
    count = 0
    while True:
        field = re.match(rb'"(?:[^"]|"")*"|[^",]*', data[offset:])
        assert field is not None
        offset += field.end()
        count += 1
        if offset == len(data):
            return count
        assert data[offset] == 44
        offset += 1


def descriptor(d, low, high):
    """Numeric consistency of an independently admitted complete descriptor."""
    assert type(d) is dict
    length = number(d['length'], low, high)
    va = number(d['elf_va'], 1)
    add(va, length)
    heads, returns = d['heads'], d['returns']
    assert type(heads) is list and 1 <= len(heads) <= length
    for x in heads:
        number(x, 0, length - 1)
    assert heads == sorted(set(heads)) and heads[0] == 0
    assert all(1 <= b - a <= 15 for a, b in zip(heads, heads[1:] + [length]))
    assert type(returns) is list and 1 <= len(returns) <= 4
    for x in returns:
        number(x, 0, length - 1)
        assert x in heads
    assert returns == sorted(set(returns))
    number(d['edges'], len(heads) - len(returns), 2 * (len(heads) - len(returns)))
    return d


def geometry_inputs(geometry, caller):
    assert type(geometry) is dict and set(geometry) == {'parent', 'child'}
    parent = descriptor(geometry['parent'], 5, 80)
    child = descriptor(geometry['child'], 1, 256)
    assert parent['elf_va'] + parent['length'] <= child['elf_va'] or child['elf_va'] + child['length'] <= parent['elf_va']
    pages = {p for d in (parent, child) for p in range(d['elf_va'] // 4096, (d['elf_va'] + d['length'] - 1) // 4096 + 1)}
    assert 1 <= len(pages) <= 2
    assert parent['returns'] == [parent['length'] - 1]
    assert parent['edges'] == len(parent['heads']) - 1
    call = number(parent['call_offset'], 1, parent['length'] - 1)
    cont = number(parent['continuation_offset'], 1, parent['length'] - 1)
    assert call in parent['heads'] and cont == add(call, 5)
    assert parent['heads'][parent['heads'].index(call) + 1] == cont
    assert cont <= parent['returns'][0]
    assert number(parent['child_delta']) in (16, 32, 48, 64)
    assert number(parent['callee_entry']) == child['elf_va']
    assert type(caller) is dict
    length = number(caller['length'], 1, 256)
    add(number(caller['elf_va'], 1), length)
    heads = caller['heads']
    assert type(heads) is list and 1 <= len(heads) <= length
    for h in heads:
        number(h, 0, length - 1)
    assert heads == sorted(set(heads)) and heads[0] == 0
    assert all(1 <= b - a <= 15 for a, b in zip(heads, heads[1:] + [length]))
    call = number(caller['call_offset'], 0, length - 1)
    cont = number(caller['continuation_offset'], 1, length - 1)
    assert call in heads and heads[heads.index(call) + 1] == cont and cont - call in (2, 3)
    assert number(caller['outer_ret_offset']) == heads[-1] == length - 1 and call < cont < length - 1
    delta = number(caller['subject_rsp_delta'], 16, 256)
    lowest = number(caller['lowest_stack'], delta - 8, 256)
    assert delta % 16 == 0 and lowest % 8 == 0
    assert max(lowest, delta + parent['child_delta'] + 128) + 8 <= 456
    return (parent, child)


def framing(data, n, epochs):
    assert type(data) is bytes and 0 < len(data) <= CAP and data.endswith(b'\n')
    assert re.fullmatch(rb'[\x20-\x7e\n]+', data)
    raw = data.splitlines(keepends=True)
    assert len(raw) <= 13 + (epochs + 1) + epochs + 7 * n
    rows = {name: [] for name in FIELDS}
    tables = {name: [] for name in FIELDS}
    ordered = []
    limits = dict(READY=1, FUNCTION=2, RET=5, EDGE=1, HISTORY=epochs + 1,
                  REPORT=epochs, CALL=2*n, RAW=2*n, RESULT=n, SAMPLE=2*n,
                  COVERAGE=2, IO=1, DONE=1)
    for line in raw:
        assert 1 < len(line) <= ROW_CAP
        words = line[:-1].decode('ascii').split(',')
        name = words[0]
        assert name in FIELDS and len(words) == len(FIELDS[name]) + 1
        row = {}
        for key, word in zip(FIELDS[name], words[1:]):
            domain = WORDS.get((name, key))
            if domain is None:
                row[key] = uint(word)
            else:
                assert word in domain
                row[key] = word
        rows[name].append(row)
        assert len(rows[name]) <= limits[name]
        tables[name].append(line)
        ordered.append((name, row))
    return ordered, rows, {name: b''.join(lines) for name, lines in tables.items()}


def check(stdout: bytes, stderr: bytes, *, records, k, epochs, outcome, input_error, geometry, caller, cpus):
    number(k); assert k in (10, 1000)
    number(epochs, 1, 520)
    assert type(records) in (list, tuple) and len(records) <= 2048
    truths = [fields(data) for data in records]
    n = len(records)
    assert type(cpus) in (list, tuple) and len(cpus) == 2
    for cpu in cpus:
        number(cpu, 0, 1023)
    assert cpus[0] != cpus[1]
    assert outcome in ('eof', 'input_error', 'input_incomplete')
    assert input_error in ('none', 'syntax', 'overlong', 'unterminated', 'record_limit')
    assert type(stderr) is bytes
    if outcome == 'input_error':
        assert input_error != 'none'
        assert (n == 2048) if input_error == 'record_limit' else (n < 2048)
        assert stderr == f'normal-call-pair-session INPUT_REFUSED: {input_error}\n'.encode('ascii')
        expected_exit = 1
    else:
        assert input_error == 'none'
        assert stderr == (b'' if outcome == 'eof' else b'normal-call-pair-session INPUT_INCOMPLETE\n')
        expected_exit = int(outcome != 'eof')
    bodies = geometry_inputs(geometry, caller)
    ordered, rows, tables = framing(stdout, n, epochs)
    at = 0

    def take(name):
        nonlocal at
        assert at < len(ordered) and ordered[at][0] == name
        row = ordered[at][1]
        at += 1
        return row

    ready = take('READY')
    fixed = (PROFILE, k, epochs, 10, 2, 64, 2048, 4, 1, 0x63700001)
    assert tuple(ready[key] for key in FIELDS['READY'][:10]) == fixed
    number(ready['pid'], 1, U32)
    assert ready['main_tid'] == ready['pid']
    assert ready['worker_tid'] > 0 and ready['worker_tid'] != ready['main_tid']
    assert (ready['main_cpu'], ready['worker_cpu']) == tuple(cpus)
    caller_entry = number(ready['caller_entry'], 1)
    add(caller_entry, caller['length'])
    assert caller_entry >= caller['elf_va'] and (caller_entry - caller['elf_va']) % 4096 == 0
    parent_word = add(caller_entry, caller['continuation_offset'])
    functions = []
    load_bias = None
    returns = []
    for node, d in enumerate(bodies):
        f = take('FUNCTION')
        assert tuple(f[x] for x in ('node', 'function_id', 'elf_va', 'extent', 'declared_returns')) == (node, FUNCTIONS[node], d['elf_va'], d['length'], len(d['returns']))
        entry = number(f['runtime_entry'], 1)
        assert f['runtime_end'] == add(entry, d['length']) and entry >= d['elf_va']
        bias = entry - d['elf_va']
        assert bias % 4096 == 0
        if load_bias is None:
            load_bias = bias
        assert bias == load_bias
        for offset in d['returns']:
            assert take('RET') == {'node': node, 'offset': offset}
        functions.append(f)
        returns.append([add(entry, r) for r in d['returns']])
    edge = take('EDGE')
    assert edge == dict(call_pc=add(functions[0]['runtime_entry'], bodies[0]['call_offset']),
                        child_entry=functions[1]['runtime_entry'],
                        continuation=add(functions[0]['runtime_entry'], bodies[0]['continuation_offset']),
                        child_stack_delta=bodies[0]['child_delta'])

    history = [('initial', 0)]
    publications = []
    reports = {}
    report_order = []
    slots = {}
    ranks = {}
    samples = {}
    counts = [[0] * 4 for _ in range(2)]
    masks = [0, 0]
    completed = 0
    prefix = 0
    root = 0
    batch = 0
    batch_size = 0
    previous_kind = None
    removed = False
    cross_generation = 0
    removed_child = 0
    results = []
    while at < len(ordered) and ordered[at][0] in ('HISTORY', 'REPORT', 'CALL'):
        kind = ordered[at][0]
        if kind == 'HISTORY':
            h = take(kind)
            assert not removed
            assert h['absolute_prefix_1'] == len(history)
            if h['batch_number'] == batch:
                assert previous_kind == 'HISTORY'
                batch_size += 1
            else:
                assert h['batch_number'] == batch + 1
                batch = h['batch_number']
                batch_size = 1
            assert 1 <= batch <= epochs + 1 and batch_size <= 8
            g = h['generation']
            assert g > 0
            if h['kind'] == 'published':
                assert len(publications) < epochs and (not publications or g > publications[-1])
                publications.append(g)
                # A copied Report is a necessary (not sufficient) bank-release step.
                assert len(publications) - len(reports) <= 3
                slots[g] = 0
                ranks[g] = [0, 0]
            else:
                assert publications and g == publications[-1]
                removed = True
            history.append((h['kind'], g))
        elif kind == 'REPORT':
            report = take(kind)
            g = report['generation']
            assert g in publications and g not in reports and report['rows'] <= 2*k
            assert history[-1] != ('published', g)
            reports[g] = report['rows']
            report_order.append(g)
        else:
            assert root < n
            calls = []
            raws = []
            for node in range(2):
                c, raw = take('CALL'), take('RAW')
                calls.append(c); raws.append(raw)
                ordinal = 2*root + 1 + node
                assert tuple(c[x] for x in ('id', 'node', 'function_id', 'ordinal', 'parent_ordinal')) == (root+1, node, FUNCTIONS[node], ordinal, 2*root+1)
                assert c['actual_children'] == 1-node
                assert c['acknowledgement'] == ('checkpoint' if node == 0 else 'continuation')
                assert c['sequence_before'] == completed
                assert prefix <= c['history_prefix'] < len(history)
                prefix = c['history_prefix']
                owner, g = c['owner'], c['generation']
                state, binding = history[prefix]
                if owner == 'initial':
                    assert prefix == g == 0 and state == 'initial'
                elif owner == 'removed':
                    assert state == 'removed' and g == binding
                else:
                    assert state == 'published' and g == binding
                if owner == 'sampled':
                    assert slots[g] < 2*k and ranks[g][node] < k
                    assert c['invocation_1'] == slots[g] + 1 and c['rank_1_or_zero'] == ranks[g][node] + 1
                    assert c['has_sampled_children'] == 1
                    slots[g] += 1
                    ranks[g][node] += 1
                    samples[g, c['invocation_1'] - 1] = (c, raw)
                else:
                    if owner == 'closed':
                        assert ranks[g][node] == k
                    assert c['invocation_1'] == c['rank_1_or_zero'] == c['has_sampled_children'] == c['sampled_children_or_zero'] == 0
                assert (raw['id'], raw['node'], raw['entry_pc']) == (root+1, node, functions[node]['runtime_entry'])
                assert raw['return_pc'] in returns[node]
                masks[node] |= 1 << returns[node].index(raw['return_pc'])
                assert raw['entry_rsp'] >= 416 and raw['entry_rsp'] % 16 == 8
                assert raw['resume_rsp'] == add(raw['entry_rsp'], 8)
                expected_word = parent_word if node == 0 else edge['continuation']
                assert raw['return_word'] == raw['resume_pc'] == expected_word
                assert raw['value'] == ((len(records[root]) << 32) | truths[root] if node == 0 else truths[root])
                number(raw['start_aux'], 0, U32); number(raw['end_aux'], 0, U32)
                counts[node][('sampled', 'closed', 'removed', 'initial').index(owner)] += 1
            assert raws[0]['entry_rsp'] >= edge['child_stack_delta']
            assert raws[1]['entry_rsp'] == raws[0]['entry_rsp'] - edge['child_stack_delta']
            for node, c in enumerate(calls):
                children = int(node == 0 and calls[1]['owner'] == 'sampled')
                assert c['sampled_children_or_zero'] == (children if c['owner'] == 'sampled' else 0)
            completed += sum(c['owner'] == 'sampled' for c in calls)
            cross_generation += int(calls[0]['generation'] != calls[1]['generation'])
            removed_child += int(calls[1]['owner'] == 'removed')
            r = take('RESULT')
            result = dict(id=root+1, length=len(records[root]), fnv=fnv(records[root]), fields=truths[root], packed=(len(records[root]) << 32) | truths[root])
            assert r == dict(id=result['id'], length=result['length'], fnv1a64=result['fnv'], packed_result=result['packed'], expected_fields=result['fields'], parent_ordinal=2*root+1, child_ordinal=2*root+2)
            results.append(result)
            root += 1
        previous_kind = kind
    assert root == n and removed and len(history) == len(publications) + 2
    assert set(reports) == set(publications)
    assert all(reports[g] == slots[g] for g in publications)
    unavailable = [0, 0]
    zero_endpoints = 0
    for g in report_order:
        for slot in range(reports[g]):
            c, raw = samples[g, slot]
            if raw['start_aux'] != raw['end_aux']:
                observation, value = 'unavailable', 1
                unavailable[0] += 1
            elif raw['end_ticks'] < raw['start_ticks']:
                observation, value = 'unavailable', 2
                unavailable[1] += 1
            else:
                observation, value = 'value', raw['end_ticks']
            zero_endpoints += int(raw['start_ticks'] == 0) + int(raw['end_ticks'] == 0)
            assert take('SAMPLE') == dict(id=c['id'], node=c['node'], function_id=c['function_id'], generation=g,
                invocation_0=slot, rank_0=c['rank_1_or_zero']-1, start_sequence=c['sequence_before'],
                entry_ticks=raw['start_ticks'], thread=1, completed_children=c['sampled_children_or_zero'],
                observation_kind=observation, observation_value=value)
    node_coverage = []
    for node in range(2):
        coverage = take('COVERAGE')
        assert coverage == dict(zip(FIELDS['COVERAGE'], (node, *counts[node], masks[node], (1 << len(returns[node])) - 1)))
        node_coverage.append(dict(coverage, unobserved_returns=[r for i, r in enumerate(bodies[node]['returns']) if not masks[node] & (1 << i)],
            unexercised_owners=[name for name, count in zip(('sampled', 'closed', 'removed', 'initial'), counts[node]) if not count],
            exhausted_generations=[g for g in publications if ranks[g][node] == k]))
    take('IO')
    done = take('DONE')
    assert at == len(ordered)
    exact = dict(arms=len(publications), history_end=len(history)-1, accepted=n, entered=2*n,
        ret_observed=2*n, confirmed=2*n, completed=completed, unsampled=2*n-completed,
        roots=n, child_acks=n, batches=n, field_sum=sum(truths), byte_sum=sum(map(len, records)), input_error=input_error)
    assert all(done[key] == value for key, value in exact.items())
    assert done['observed_eof'] in (0, 1)
    if outcome == 'eof':
        assert (done['input_status'], done['stop_reason'], done['observed_eof'], done['input_complete']) == ('COMPLETE', 'Requested', 1, 1)
    elif outcome == 'input_error':
        assert (done['input_status'], done['stop_reason'], done['input_complete']) == ('INPUT_REFUSED', 'Requested', 0)
        # Input::frame observes EOF only in Eof/Unterminated; a sticky refusal
        # returns Stop before any later frame can change that flag.
        assert done['observed_eof'] == int(input_error == 'unterminated')
    else:
        assert (done['input_status'], done['stop_reason'], done['observed_eof'], done['input_complete'], done['arms']) == ('INPUT_INCOMPLETE', 'EpochLimit', 0, 0, epochs)
    return dict(status=STATUS, rows=rows, tables=tables, totals=done, expected_exit=expected_exit,
        results=results, coverage=dict(nodes=node_coverage, cross_generation_roots=cross_generation,
            removed_child_roots=removed_child, sampled_aux_mismatch=unavailable[0],
            sampled_clock_regression=unavailable[1], sampled_zero_tick_endpoints=zero_endpoints),
        source_attested=SOURCE_ATTESTED, scope=SCOPE)
