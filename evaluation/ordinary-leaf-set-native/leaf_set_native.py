"""Numeric copied-LeafSet transcript joins; native/source/process authority is external."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

U64 = (1 << 64) - 1
PROFILE = 'leaf-set-whole-rust-v1'
POLICIES = ('certified', 'whole', 'whole', 'whole')
SEEDS = (1311768467139281696, 18364758542526924135)
HEADER = 'profile,subset,n,k,selected_index,function_id,seed,function,case,bound,status,children,comparisons,visits,original_steps,candidate_steps,result,outer_rax,input_reads,input_bytes,ret_offset,observed_heads,declared_heads,observed_edges,declared_edges,declared_returns,caller_bytes,caller_heads,call_offset,continuation_offset,outer_ret_offset,subject_rsp_delta,target_calls,target_returns,outer_returns,normal_reaps'
COVERAGE = 'profile,subset,n,k,selected_index,function_id,seed,function,cases,observed_heads,declared_heads,observed_edges,declared_edges,observed_returns,declared_returns,comparisons'
CSV_INPUTS = (b'', b'a', b'a,b,c', b',', b',,', b'a,', b',a', b'""', b'"a,b"',
              b'"a","b"', b'a,"b,c",d', b'"a""b",c', b'""""', b'"",""',
              b'plain,"say ""hi""",,tail', b'"comma,, and ""quote""",last,')
CSV_VALUES = (1, 1, 3, 2, 3, 2, 2, 1, 1, 2, 3, 2, 1, 2, 4, 3)
LENGTH_BOUNDS = (0, 1, 1, 2, 17, 64, 64, 64)
LENGTH_NULS = (None, 0, None, 1, 8, 0, 63, None)
LENGTH_VALUES = (0, 0, 1, 1, 8, 0, 63, 64)
SCANNER_INPUTS = (b'', b'/09: ', b' ', b'/', bytes.fromhex('001f2021092f30393aff'),
                  b'9' * 64, b' ' * 64, b'0 ' * 32)
DIGIT_VALUES = (0, 2, 0, 0, 2, 64, 0, 32)
SPACE_VALUES = (0, 1, 1, 0, 1, 0, 64, 32)
SCOPE = ('Copied Rust body, one selected call in one fresh LeafSet epoch per child only. '
         'No original-address caller, threaded application, cross-function confirmation, '
         'K exhaustion, recycled-bank reuse, Schedule, timing or full-A5 qualification. '
         'The unchanged old 48-pair prerequisite remains separately required.')
SOURCE_ATTESTED = ('Full state/XSAVE/input/stack/source/journal/Reports, exact caller and scanner '
                   'instruction effects, actual calls/returns, read-offset and head/edge unions, '
                   'opaque ownership and normal reaps remain native-source authority. Numeric '
                   'tables do not replay these facts or authenticate ELF bytes or process closure.')


def uint(word):
    assert type(word) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}', word)
    value = int(word)
    assert value <= U64
    return value


def number(value, lo=0, hi=U64):
    assert type(value) is int and lo <= value <= hi
    return value


def policy(operation):
    number(operation, 1, 4)
    return POLICIES[operation-1]


def maximum_extent(operation):
    return 256 if policy(operation) == 'certified' else 80


def lines(data, cap):
    assert type(data) is bytes and 0 < len(data) <= cap and data.endswith(b'\n')
    assert re.fullmatch(rb'[\x20-\x7e\n]+', data)
    return data[:-1].decode('ascii').split('\n')


def heads(values, length):
    assert type(values) is list and 1 <= len(values) <= length
    assert all(type(x) is int and 0 <= x < length for x in values)
    assert values[0] == 0 and values == sorted(set(values))


def cases(operation):
    number(operation, 1, 4)
    if operation == 1:
        return tuple(zip(CSV_INPUTS, CSV_VALUES))
    if operation == 2:
        result = []
        for bound, nul, expected in zip(LENGTH_BOUNDS, LENGTH_NULS, LENGTH_VALUES):
            data = bytearray(1 + ((37 * i + 128) % 255) for i in range(64))
            if nul is not None:
                data[nul] = 0
            actual = bytes(data[:bound])
            assert next((i for i, b in enumerate(actual) if b == 0), bound) == expected
            result.append((actual, expected))
        return tuple(result)
    values = DIGIT_VALUES if operation == 3 else SPACE_VALUES
    for data, expected in zip(SCANNER_INPUTS, values):
        assert (sum(48 <= b <= 57 for b in data) if operation == 3 else data.count(32)) == expected
    return tuple(zip(SCANNER_INPUTS, values))


def table(data, header, count, cap, row_cap):
    text = lines(data, cap)
    assert len(text) == count + 1 and text[0] == header and len(text[0]) + 1 <= 1024
    keys = header.split(','); rows = []
    for line in text[1:]:
        assert len(line) + 1 <= row_cap
        values = line.split(','); assert len(values) == len(keys)
        row = dict(zip(keys, values))
        assert row['profile'] == PROFILE and row['function'] in ('1', '2', '3', '4')
        if 'status' in row:
            assert row['status'] == 'PASS'
        for key, value in row.items():
            if key in ('profile', 'status'):
                continue
            if key in ('input_reads', 'input_bytes') and row['function'] in ('1', 1):
                assert value == ''; row[key] = None
            else:
                row[key] = uint(value)
        rows.append(row)
    return rows


def body_geometry(g, operation):
    required = {'operation', 'function_id', 'elf_va', 'length', 'heads', 'edges', 'returns'}
    assert type(g) is dict and set(g) == required
    assert number(g['operation'], 1, 4) == operation
    assert number(g['function_id']) == 300 + operation
    number(g['elf_va'], 1); number(g['length'], 5, maximum_extent(operation))
    assert g['elf_va'] + g['length'] <= U64
    heads(g['heads'], g['length'])
    ret = g['returns']; edges = g['edges']; full = set(g['heads'])
    assert type(ret) is list and 1 <= len(ret) <= 4
    assert all(type(x) is int and 0 < x < g['length'] for x in ret)
    assert ret == sorted(set(ret)) and set(ret) <= full
    assert type(edges) is list and len(edges) <= 2 * (len(full) - len(ret))
    for pair in edges:
        assert type(pair) is list and len(pair) == 2
        assert all(type(x) is int and x in full for x in pair)
        assert pair[0] != pair[1] and pair[0] not in ret
    assert edges == sorted([list(x) for x in set(map(tuple, edges))])
    successors = {h: [b for a, b in edges if a == h] for h in full}
    assert all((len(successors[h]) == 0 if h in ret else 1 <= len(successors[h]) <= 2) for h in full)
    reachable = set(); pending = [0]
    while pending:
        at = pending.pop()
        if at not in reachable:
            reachable.add(at); pending.extend(successors[at])
    assert set(ret) <= reachable
    can_return = set(ret)
    for _ in full:
        can_return.update(a for a, b in edges if b in can_return)
    assert reachable <= can_return
    declared_heads = full if operation == 1 else reachable
    declared_edges = {tuple(e) for e in edges if e[0] in declared_heads}
    return dict(heads=declared_heads, edges=declared_edges, returns=set(ret))


def caller_geometry(caller):
    required = {'length', 'heads', 'call_offset', 'continuation_offset', 'outer_ret_offset', 'subject_rsp_delta'}
    assert type(caller) is dict and required <= set(caller) <= required | {'elf_va', 'body_hex'}
    number(caller['length'], 1, 256); heads(caller['heads'], caller['length'])
    assert len(caller['heads']) >= 3
    for key in ('call_offset', 'continuation_offset', 'outer_ret_offset'):
        number(caller[key], 0, caller['length']-1)
        assert caller[key] in caller['heads']
    call, continuation, ret = (caller[k] for k in ('call_offset', 'continuation_offset', 'outer_ret_offset'))
    assert call < continuation < ret == caller['length']-1 == caller['heads'][-1]
    assert caller['heads'][caller['heads'].index(call)+1] == continuation
    assert continuation-call in (2, 3)
    assert all(1 <= b-a <= 15 for a, b in zip(caller['heads'], caller['heads'][1:]))
    number(caller['subject_rsp_delta'], 16, 256)
    assert caller['subject_rsp_delta'] % 16 == 0
    if 'elf_va' in caller:
        number(caller['elf_va'], 1); assert caller['elf_va'] + caller['length'] <= U64
    if 'body_hex' in caller:
        text = caller['body_hex']
        assert type(text) is str and re.fullmatch('[0-9a-f]{'+str(2*caller['length'])+'}', text)
        assert text.endswith('c3')


def geometry(bodies, caller):
    assert type(bodies) in (list, tuple) and len(bodies) == 4
    graphs = [body_geometry(g, op) for op, g in enumerate(bodies, 1)]
    ordered = sorted(bodies, key=lambda g: g['elf_va'])
    assert all(a['elf_va'] + a['length'] <= b['elf_va'] for a, b in zip(ordered, ordered[1:]))
    pages = {page for g in bodies for page in range(g['elf_va']//4096, (g['elf_va']+g['length']-1)//4096+1)}
    assert 1 <= len(pages) <= 2
    caller_geometry(caller)
    return graphs


def terminal(comparisons):
    number(comparisons, 1)
    return (f'native-leaf-set-rust:profile={PROFILE}:required=1280:pairs=1280:children=2560:'
            f'comparisons={comparisons}:coverage-groups=128:subsets=15:k-values=2:seeds=2:'
            'target-calls=2560:target-returns=2560:real-outer-ret=2560:normal-reaps=2560:'
            'scope=copied-body-only:complete')


def check(pairs, coverage, stdout, stderr, *, bodies, caller):
    """Require independent parent geometry; a valid transcript is not a native receipt."""
    assert type(stderr) is bytes and stderr == b''
    graphs = geometry(bodies, caller)
    rows = table(pairs, HEADER, 1280, 1048576, 768)
    covered = table(coverage, COVERAGE, 128, 65536, 384)
    cursor = 0; group_index = 0
    for subset in range(1, 16):
        selected = sorted((g for g in bodies if subset & (1 << (g['operation']-1))), key=lambda g: g['elf_va'])
        for k in (10, 1000):
            for seed in SEEDS:
                for operation, g in enumerate(bodies, 1):
                    if not subset & (1 << (operation-1)):
                        continue
                    graph = graphs[operation-1]; corpus = cases(operation)
                    group = rows[cursor:cursor+len(corpus)]; cursor += len(corpus)
                    identity = (subset, len(selected), k, selected.index(g), g['function_id'], seed, operation)
                    names = ('subset','n','k','selected_index','function_id','seed','function')
                    for case, (r, (data, value)) in enumerate(zip(group, corpus), 1):
                        assert tuple(r[x] for x in names) == identity
                        assert (r['case'], r['bound'], r['result']) == (case, len(data), value)
                        assert tuple(r[x] for x in ('children','target_calls','target_returns','outer_returns','normal_reaps')) == (2,2,2,2,2)
                        assert (r['caller_bytes'], r['caller_heads']) == (caller['length'], len(caller['heads']))
                        assert all(r[x] == caller[x] for x in ('call_offset','continuation_offset','outer_ret_offset','subject_rsp_delta'))
                        assert r['visits'] > 0 and r['comparisons'] == len(caller['heads']) + r['visits'] + 1
                        assert r['comparisons'] <= r['original_steps'] <= 20000
                        assert r['comparisons'] <= r['candidate_steps'] <= 20000
                        assert (r['declared_heads'], r['declared_edges'], r['declared_returns']) == tuple(len(graph[x]) for x in ('heads','edges','returns'))
                        assert r['ret_offset'] in graph['returns']
                        assert 2 <= r['observed_heads'] <= min(r['visits'], len(graph['heads']))
                        assert r['observed_heads']-1 <= r['observed_edges'] <= min(r['visits']-1, len(graph['edges']))
                        if operation != 1:
                            reads, size = r['input_reads'], r['input_bytes']
                            assert reads <= r['visits'] and reads <= size <= 8*reads <= U64
                            if len(data) == 0:
                                assert reads == size == 0
                            else:
                                assert reads > 0
                                if operation in (3, 4):
                                    assert size >= len(data)
                    c = covered[group_index]; group_index += 1
                    assert tuple(c[x] for x in names) == identity and c['cases'] == len(corpus)
                    assert {r['ret_offset'] for r in group} == graph['returns']
                    assert c['observed_returns'] == c['declared_returns'] == len(graph['returns'])
                    assert c['comparisons'] == sum(r['comparisons'] for r in group) <= U64
                    for field in ('heads', 'edges'):
                        declared = len(graph[field]); counts = [r['observed_'+field] for r in group]
                        assert c['declared_'+field] == declared
                        assert max(counts) <= c['observed_'+field] <= min(sum(counts), declared)
                        if operation != 1:
                            assert c['observed_'+field] == declared
    assert cursor == 1280 and group_index == 128
    comparisons = sum(r['comparisons'] for r in rows)
    assert 0 < comparisons <= U64 and lines(stdout, 1024) == [terminal(comparisons)]
    return dict(status='LEAF_SET_WHOLE_TRANSCRIPT_VALIDATED', profile=PROFILE,
                pairs=1280, children=2560, target_calls=2560, target_returns=2560,
                outer_returns=2560, normal_reaps=2560, comparisons=comparisons,
                coverage_groups=128, rows=rows, coverage=covered, pairs_table=pairs,
                coverage_table=coverage, terminal=stdout, bodies=bodies, caller=caller,
                scope=SCOPE, source_attested=SOURCE_ATTESTED,
                policies=[policy(op) for op in range(1, 5)])
