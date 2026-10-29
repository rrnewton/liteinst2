"""Complete module-native tables; process, source and architectural custody are separate."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

U64 = (1 << 64) - 1
SEEDS = (1311768467139281696, 18364758542526924135)
CSV_LENGTHS = (0, 1, 5, 1, 2, 2, 2, 2, 5, 7, 9, 8, 4, 5, 24, 29)
CSV_VALUES = (1, 1, 3, 2, 3, 2, 2, 1, 1, 2, 3, 2, 1, 2, 4, 3)
LENGTH_BOUNDS = (0, 1, 1, 2, 17, 64, 64, 64)
LENGTH_VALUES = (0, 0, 1, 1, 8, 0, 63, 64)
HEADER = 'k,seed,case,length_case,csv_length,length_bound,csv_index,length_index,status,children,comparisons,visits0,visits1,visits2,visits3,original_steps,candidate_steps,value0,value1,value2,value3,outer_value,ret_offset0,ret_offset1,ret_offset2,ret_offset3,csv_heads,csv_edges,length_heads,length_edges,length_reads0,length_reads1,length_bytes0,length_bytes1,declared_returns,target_calls,target_returns,outer_returns,normal_reaps'
COVERAGE = 'k,seed,csv_cases,length_cases,csv_observed_heads,csv_declared_heads,csv_observed_edges,csv_declared_edges,csv_returns,length_heads,length_edges,length_returns'
SCOPE = ('CSV and length bodies under the distinct 123-byte four-call C helper; '
         'no Rust application-caller, timing, accuracy, performance or full-A5 qualification.')


def uint(word):
    assert isinstance(word, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', word)
    value = int(word)
    assert value <= U64
    return value


def lines(data, cap):
    assert type(data) is bytes and 0 < len(data) <= cap and data.endswith(b'\n')
    assert all(c == 10 or 32 <= c < 127 for c in data)
    return data[:-1].decode('ascii').split('\n')


def table(data, header, count, cap):
    text = lines(data, cap)
    assert len(text) == count + 1 and text[0] == header
    names = header.split(','); rows = []
    for line in text[1:]:
        words = line.split(','); assert len(words) == len(names)
        row = dict(zip(names, words))
        if 'status' in row: assert row['status'] == 'PASS'
        rows.append({k: v if k == 'status' else uint(v) for k, v in row.items()})
    return rows


def terminal(k, comparisons):
    return (f'native-normal-module:k={k}:required=32:pairs=32:children=64:comparisons={comparisons}:'
            'coverage-seeds=2:csv-cases-per-seed=16:length-cases-per-seed=8:target-calls=256:'
            'target-returns=256:real-outer-ret=64:normal-reaps=64:complete')


def _geometry(stderr, geometry):
    assert type(stderr) is bytes and stderr == b'' and len(geometry) == 2
    for g, ceiling in zip(geometry, (256, 80)):
        assert type(g['length']) is int and 5 <= g['length'] <= ceiling
        assert g['heads'] == sorted(set(g['heads'])) and g['heads'][0] == 0
        assert all(type(x) is int and 0 <= x < g['length'] for x in g['heads'])
        assert g['returns'] == sorted(set(g['returns'])) and 1 <= len(g['returns']) <= 4
        assert set(g['returns']) <= set(g['heads']) and all(x > 0 for x in g['returns'])
        assert type(g['edges']) is int and len(g['heads'])-len(g['returns']) <= g['edges'] <= 2*(len(g['heads'])-len(g['returns']))


def _population(rows, covered, k, geometry, csv_index):
    total_returns = sum(len(g['returns']) for g in geometry)
    for i, r in enumerate(rows):
        case = i % 16; length_case = case % 8
        assert (r['k'], r['seed'], r['case'], r['length_case']) == (k, SEEDS[i//16], case+1, length_case+1)
        assert (r['csv_length'], r['length_bound']) == (CSV_LENGTHS[case], LENGTH_BOUNDS[length_case])
        assert (r['csv_index'], r['length_index']) == (csv_index, 1-csv_index)
        assert (r['children'], r['target_calls'], r['target_returns'], r['outer_returns'], r['normal_reaps']) == (2, 8, 8, 2, 2)
        values = (CSV_VALUES[case], LENGTH_VALUES[length_case]) * 2
        assert tuple(r['value'+str(n)] for n in range(4)) == values
        assert r['outer_value'] == sum(values)
        visits = [r['visits'+str(n)] for n in range(4)]
        assert all(v > 0 for v in visits) and visits[:2] == visits[2:]
        assert r['comparisons'] == 40 + sum(visits)
        assert r['comparisons'] <= r['original_steps'] <= 20000
        assert r['comparisons'] <= r['candidate_steps'] <= 20000
        assert r['declared_returns'] == total_returns
        for f, name in enumerate(('csv', 'length')):
            assert r['ret_offset'+str(f)] == r['ret_offset'+str(f+2)] in geometry[f]['returns']
            heads, edges = r[name+'_heads'], r[name+'_edges']
            assert 2 <= heads <= min(visits[f], len(geometry[f]['heads']))
            assert heads-1 <= edges <= min(visits[f]-1, geometry[f]['edges'])
        reads, size = r['length_reads0'], r['length_bytes0']
        assert (reads, size) == (r['length_reads1'], r['length_bytes1'])
        assert reads <= visits[1] and reads <= size <= 8*reads
        if r['length_bound'] == 0: assert reads == size == 0
        else: assert reads > 0
    for index, c in enumerate(covered):
        group = rows[index*16:(index+1)*16]
        assert (c['k'], c['seed'], c['csv_cases'], c['length_cases']) == (k, SEEDS[index], 16, 8)
        for f, name in enumerate(('csv', 'length')):
            g = geometry[f]
            assert {r['ret_offset'+str(f)] for r in group} == set(g['returns'])
            assert c[name+'_returns'] == len(g['returns'])
            for field in ('heads', 'edges'):
                declared = len(g['heads']) if field == 'heads' else g['edges']
                counts = [r[name+'_'+field] for r in group]
                if name == 'csv':
                    assert c['csv_declared_'+field] == declared
                    assert max(counts) <= c['csv_observed_'+field] <= min(sum(counts), declared)
                else:
                    assert max(counts) <= c['length_'+field] == declared <= sum(counts)
    comparisons = sum(r['comparisons'] for r in rows)
    return comparisons


def check(pairs, coverage, stdout, stderr, k, geometry, csv_index):
    """geometry is CSV then length, authenticated from complete trusted ELF disassembly."""
    assert type(k) is int and k in (16, 1) and type(csv_index) is int and csv_index in (0, 1)
    _geometry(stderr, geometry)
    rows = table(pairs, HEADER, 32, 32768)
    covered = table(coverage, COVERAGE, 2, 1024)
    comparisons = _population(rows, covered, k, geometry, csv_index)
    assert comparisons <= U64 and lines(stdout, 1024) == [terminal(k, comparisons)]
    return dict(status='NATIVE_STATE_TRANSCRIPT_VALIDATED', k=k, pairs=32, children=64,
                target_calls=256, target_returns=256, outer_returns=64, normal_reaps=64,
                comparisons=comparisons, rows=rows, coverage=covered, pairs_table=pairs,
                coverage_table=coverage, terminal=stdout, scope=SCOPE,
                source_attested='Full state/XSAVE/stack/data/source/journal/Reports, actual four calls/returns and normal reaps; tables do not replay those checks.')


SESSION_PROFILE = 'session-absolute-v1'
SESSION_HEADER = 'profile,' + HEADER
SESSION_COVERAGE = 'profile,' + COVERAGE
SESSION_SCOPE = ('Native streaming module body-state under the unchanged four-call helper only; '
                 'no pending-owner, Rust-caller, timing, accuracy, performance or full-A5 qualification.')


def session_table(data, header, count):
    text = lines(data, 65536)
    assert len(text) == count + 1 and text[0] == header
    names = header.split(','); rows = []
    for line in text[1:]:
        words = line.split(','); assert len(words) == len(names)
        row = dict(zip(names, words))
        assert row['profile'] == SESSION_PROFILE
        if 'status' in row: assert row['status'] == 'PASS'
        rows.append({k: v if k in ('profile', 'status') else uint(v) for k, v in row.items()})
    return rows


def session_terminal(k, comparisons):
    return (f'native-normal-module-session:profile=session-absolute-v1:k={k}:'
            f'e=3:t=1:d=1:m=1:a={2*k}:resident-actions=8:'
            f'required=32:pairs=32:children=64:comparisons={comparisons}:'
            'coverage-seeds=2:csv-cases-per-seed=16:length-cases-per-seed=8:target-calls=256:'
            'target-returns=256:real-outer-ret=64:normal-reaps=64:complete')


def check_session(pairs, coverage, stdout, stderr, k, geometry, csv_index):
    """Parse the actual Session wire directly; geometry remains separately authenticated."""
    assert type(k) is int and k in (10, 1000) and type(csv_index) is int and csv_index in (0, 1)
    _geometry(stderr, geometry)
    rows = session_table(pairs, SESSION_HEADER, 32)
    covered = session_table(coverage, SESSION_COVERAGE, 2)
    comparisons = _population(rows, covered, k, geometry, csv_index)
    assert comparisons <= U64 and lines(stdout, 1024) == [session_terminal(k, comparisons)]
    return dict(status='NATIVE_SESSION_STATE_TRANSCRIPT_VALIDATED', profile=SESSION_PROFILE,
                k=k, pairs=32, children=64, target_calls=256, target_returns=256,
                outer_returns=64, normal_reaps=64, comparisons=comparisons, rows=rows,
                coverage=covered, pairs_table=pairs, coverage_table=coverage, terminal=stdout,
                scope=SESSION_SCOPE,
                source_attested='Full state/XSAVE/stack/data/source/journal/Report/history/reclaim and normal reaps remain native-source authority; tables do not replay those checks.')
