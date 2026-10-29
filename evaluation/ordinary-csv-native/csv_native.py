"""Strict CSV native-state transcript; process/source custody is a separate join."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import re

U64 = (1 << 64) - 1
SEEDS = (1311768467139281696, 18364758542526924135)
LENGTHS = (0, 1, 5, 1, 2, 2, 2, 2, 5, 7, 9, 8, 4, 5, 24, 29)
VALUES = (1, 1, 3, 2, 3, 2, 2, 1, 1, 2, 3, 2, 1, 2, 4, 3)
HEADER = 'seed,case,length,status,children,comparisons,visits0,visits1,original_steps,candidate_steps,value0,value1,outer_value,ret_offset0,ret_offset1,heads0,heads1,edges0,edges1,declared_returns,target_calls,target_returns,outer_returns,normal_reaps'
COVERAGE = 'seed,cases,observed_heads,declared_heads,observed_edges,declared_edges,observed_returns,declared_returns'
SCOPE = ('CSV body under the existing 67-byte caller; no functional Rust-caller, '
         'timing, performance, arbitrary-module or full-A5 qualification.')


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
    names = header.split(',')
    rows = []
    for line in text[1:]:
        words = line.split(',')
        assert len(words) == len(names)
        row = dict(zip(names, words))
        if 'status' in row:
            assert row['status'] == 'PASS'
        rows.append({k: v if k == 'status' else uint(v) for k, v in row.items()})
    return rows


def terminal(comparisons):
    return (f'native-normal-csv:selection=normal-csv-fields-v1:required=32:pairs=32:'
            f'children=64:comparisons={comparisons}:coverage-seeds=2:cases-per-seed=16:'
            'target-calls=128:target-returns=128:real-outer-ret=64:normal-reaps=64:complete')


def check(pairs, coverage, stdout, stderr, extent):
    assert type(extent) is int and 5 <= extent <= 256 and type(stderr) is bytes and stderr == b''
    rows = table(pairs, HEADER, 32, 32768)
    covered = table(coverage, COVERAGE, 2, 1024)
    for i, r in enumerate(rows):
        case = i % 16
        assert (r['seed'], r['case'], r['length']) == (SEEDS[i // 16], case + 1, LENGTHS[case])
        assert (r['children'], r['target_calls'], r['target_returns'], r['outer_returns'], r['normal_reaps']) == (2, 4, 4, 2, 2)
        assert r['value0'] == r['value1'] == VALUES[case] and r['outer_value'] == 2 * VALUES[case]
        assert r['visits0'] > 0 and r['visits1'] > 0
        assert r['comparisons'] == 24 + r['visits0'] + r['visits1']
        assert r['comparisons'] <= r['original_steps'] <= 20000
        assert r['comparisons'] <= r['candidate_steps'] <= 20000
        assert 0 < r['ret_offset0'] == r['ret_offset1'] < extent
        assert r['heads0'] == r['heads1'] and r['edges0'] == r['edges1']
        assert 1 <= r['declared_returns'] <= 4
        for n in (0, 1):
            heads, edges, visits = (r[k + str(n)] for k in ('heads', 'edges', 'visits'))
            assert 2 <= heads <= min(visits, extent)
            assert heads - 1 <= edges <= visits - 1
    declared = {r['declared_returns'] for r in rows}
    assert len(declared) == 1
    ret_sets = []
    geometry = set()
    for seed, c in enumerate(covered):
        group = rows[16 * seed:16 * (seed + 1)]
        ret_set = {r['ret_offset0'] for r in group}
        ret_sets.append(ret_set)
        assert c['seed'] == SEEDS[seed] and c['cases'] == 16
        assert c['observed_returns'] == c['declared_returns'] == len(ret_set)
        assert {c['declared_returns']} == declared
        h, e, r = (c['declared_' + k] for k in ('heads', 'edges', 'returns'))
        assert 2 <= h <= extent and r <= h and h - r <= e <= 2 * (h - r)
        geometry.add((h, e, r))
        for field in ('heads', 'edges'):
            values = [row[field + str(n)] for row in group for n in (0, 1)]
            assert max(values) <= c['observed_' + field] <= min(sum(values), c['declared_' + field])
    assert ret_sets[0] == ret_sets[1] and len(geometry) == 1
    comparisons = sum(r['comparisons'] for r in rows)
    assert comparisons <= U64 and lines(stdout, 1024) == [terminal(comparisons)]
    return dict(status='NATIVE_STATE_TRANSCRIPT_VALIDATED', pairs=32, children=64,
                target_calls=128, target_returns=128, outer_returns=64, normal_reaps=64,
                comparisons=comparisons, rows=rows, coverage=covered,
                pairs_table=pairs, coverage_table=coverage, terminal=stdout, scope=SCOPE,
                source_attested='Complete state/XSAVE/stack/data/source/journal/Reports, actual calls/returns, declared geometry and normal reaps; tables alone do not replay those checks.')
