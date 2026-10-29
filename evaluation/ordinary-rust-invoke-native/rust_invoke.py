"""Complete copied-Rust-invoke transcript joins; native and process authority is separate."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

U64 = (1 << 64) - 1
PROFILE = 'copied-rust-invoke-v1'
SEEDS = (1311768467139281696, 18364758542526924135)
CSV_LENGTHS = (0, 1, 5, 1, 2, 2, 2, 2, 5, 7, 9, 8, 4, 5, 24, 29)
CSV_VALUES = (1, 1, 3, 2, 3, 2, 2, 1, 1, 2, 3, 2, 1, 2, 4, 3)
LENGTH_BOUNDS = (0, 1, 1, 2, 17, 64, 64, 64)
LENGTH_VALUES = (0, 0, 1, 1, 8, 0, 63, 64)
HEADER = 'profile,seed,function,case,bound,status,children,comparisons,visits,original_steps,candidate_steps,result,outer_rax,input_reads,input_bytes,ret_offset,observed_heads,declared_heads,observed_edges,declared_edges,declared_returns,caller_bytes,caller_heads,call_offset,continuation_offset,outer_ret_offset,subject_rsp_delta,target_calls,target_returns,outer_returns,normal_reaps'
COVERAGE = 'profile,seed,function,cases,observed_heads,declared_heads,observed_edges,declared_edges,observed_returns,declared_returns,comparisons'
SCOPE = ('Exact copied Rust invoke body under the admitted four-origin entry contract only; '
         'no original-address execution, application call-site ABI, whole worker, timing, '
         'accuracy, performance or full-A5 qualification.')


def uint(word):
    assert type(word) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}', word)
    value = int(word)
    assert value <= U64
    return value


def number(value, lo=0, hi=U64):
    assert type(value) is int and lo <= value <= hi
    return value


def lines(data, cap):
    assert type(data) is bytes and 0 < len(data) <= cap and data.endswith(b'\n')
    assert all(c == 10 or 32 <= c < 127 for c in data)
    return data[:-1].decode('ascii').split('\n')


def table(data, header, count):
    text = lines(data, 65536)
    assert len(text) == count + 1 and text[0] == header
    keys = header.split(','); rows = []
    for line in text[1:]:
        values = line.split(','); assert len(values) == len(keys)
        row = dict(zip(keys, values))
        assert row['profile'] == PROFILE and row['function'] in ('csv', 'length')
        if 'status' in row: assert row['status'] == 'PASS'
        for key, value in row.items():
            if key in ('profile', 'function', 'status'): continue
            if key in ('input_reads', 'input_bytes') and row['function'] == 'csv':
                assert value == ''; row[key] = None
            else:
                row[key] = uint(value)
        rows.append(row)
    return rows


def heads(values, length):
    assert type(values) is list and 1 <= len(values) <= length
    assert all(type(x) is int and 0 <= x < length for x in values)
    assert values[0] == 0 and values == sorted(set(values))


def geometry(bodies, caller):
    assert type(bodies) in (list, tuple) and len(bodies) == 2
    for g, limit in zip(bodies, (256, 80)):
        assert type(g) is dict and set(g) == {'length', 'heads', 'edges', 'returns'}
        number(g['length'], 5, limit); heads(g['heads'], g['length'])
        ret = g['returns']
        assert type(ret) is list and 1 <= len(ret) <= 4
        assert all(type(x) is int and 0 < x < g['length'] for x in ret) and ret == sorted(set(ret))
        assert set(ret) <= set(g['heads'])
        number(g['edges'], len(g['heads'])-len(ret), 2*(len(g['heads'])-len(ret)))
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


def terminal(comparisons):
    return (f'native-rust-invoke:profile={PROFILE}:required=48:pairs=48:children=96:'
            f'comparisons={comparisons}:coverage-seeds=2:csv-cases-per-seed=16:length-cases-per-seed=8:'
            'target-calls=96:target-returns=96:real-outer-ret=96:normal-reaps=96:scope=copied-body-only:complete')


def check(pairs, coverage, stdout, stderr, *, bodies, caller):
    """Parent geometry is independent authority; tables cannot authenticate native custody."""
    assert type(stderr) is bytes and stderr == b''
    geometry(bodies, caller)
    rows = table(pairs, HEADER, 48); covered = table(coverage, COVERAGE, 4)
    groups = []; cursor = 0
    for seed in SEEDS:
        for f, name in enumerate(('csv', 'length')):
            bounds = CSV_LENGTHS if f == 0 else LENGTH_BOUNDS
            values = CSV_VALUES if f == 0 else LENGTH_VALUES
            g = bodies[f]; group = rows[cursor:cursor+len(bounds)]; cursor += len(bounds)
            for case, (r, bound, value) in enumerate(zip(group, bounds, values), 1):
                assert (r['seed'], r['function'], r['case'], r['bound'], r['result']) == (seed, name, case, bound, value)
                assert tuple(r[k] for k in ('children','target_calls','target_returns','outer_returns','normal_reaps')) == (2,2,2,2,2)
                assert (r['caller_bytes'], r['caller_heads']) == (caller['length'], len(caller['heads']))
                assert all(r[k] == caller[k] for k in ('call_offset','continuation_offset','outer_ret_offset','subject_rsp_delta'))
                assert r['visits'] > 0 and r['comparisons'] == len(caller['heads']) + r['visits'] + 1
                assert r['comparisons'] <= r['original_steps'] <= 20000
                assert r['comparisons'] <= r['candidate_steps'] <= 20000
                assert (r['declared_heads'], r['declared_edges'], r['declared_returns']) == (len(g['heads']), g['edges'], len(g['returns']))
                assert r['ret_offset'] in g['returns']
                assert 2 <= r['observed_heads'] <= min(r['visits'], len(g['heads']))
                assert r['observed_heads']-1 <= r['observed_edges'] <= min(r['visits']-1, g['edges'])
                if f == 1:
                    reads, size = r['input_reads'], r['input_bytes']
                    assert reads <= r['visits'] and reads <= size <= 8*reads <= U64
                    if bound == 0: assert reads == size == 0
                    else: assert reads > 0
            groups.append((seed, name, g, group))
    assert cursor == 48
    for c, (seed, name, g, group) in zip(covered, groups):
        assert (c['seed'], c['function'], c['cases']) == (seed, name, len(group))
        assert {r['ret_offset'] for r in group} == set(g['returns'])
        assert c['observed_returns'] == c['declared_returns'] == len(g['returns'])
        assert c['comparisons'] == sum(r['comparisons'] for r in group) <= U64
        for field in ('heads', 'edges'):
            declared = len(g['heads']) if field == 'heads' else g['edges']
            counts = [r['observed_'+field] for r in group]
            assert c['declared_'+field] == declared
            assert max(counts) <= c['observed_'+field] <= min(sum(counts), declared)
            if name == 'length': assert c['observed_'+field] == declared
    comparisons = sum(r['comparisons'] for r in rows)
    assert 0 < comparisons <= U64 and lines(stdout, 1024) == [terminal(comparisons)]
    return dict(status='COPIED_RUST_INVOKE_TRANSCRIPT_VALIDATED', profile=PROFILE,
                pairs=48, children=96, target_calls=96, target_returns=96, outer_returns=96,
                normal_reaps=96, comparisons=comparisons, rows=rows, coverage=covered,
                pairs_table=pairs, coverage_table=coverage, terminal=stdout, bodies=bodies,
                caller=caller, scope=SCOPE,
                source_attested='Full state/XSAVE/input/stack/source/journal/Reports, caller instruction effects, actual calls/RET and normal reaps remain native-source authority; numeric tables do not replay them.')
