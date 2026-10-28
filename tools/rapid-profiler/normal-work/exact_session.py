#!/usr/bin/env python3
"""Fixed original-work populations; no timestamp-derived work or duration claim."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import csv
import io
from check_session_two import check_exact

SCHEDULES = ('short', 'long', 'alternating', 'late-long')
PARTITIONS = ('population', 'admitted', 'retained', 'dropped', 'unsampled')
METRICS = ('instructions', 'conditional_branches', 'taken_branches',
    'input_byte_reads', 'return_reads', 'return_read_bytes')
FIELDS = ('schedule', 'k', 'worker', *(p+'_calls' for p in PARTITIONS),
    *(p+'_'+m for p in PARTITIONS for m in METRICS),
    'error_numerator', 'error_denominator', 'error_status')
SUMMARY_CAP = 8192


def commands(schedule, k):
    """The complete, immutable request population exists before child creation."""
    assert schedule in SCHEDULES and type(k) is int and k in (10, 1000)
    lengths = {'short': (1,)*24, 'long': (64,)*24,
        'alternating': (1, 64)*12, 'late-long': (1,)*10+(64,)*14}[schedule]
    base = 0x4e57524b0000 + SCHEDULES.index(schedule)*1000 + (k == 1000)*100
    calls = tuple(('CALL', base+2*i+w, n, bytes((37*j+11+w) % 256 for j in range(n)))
        for i, n in enumerate(lengths) for w in (0, 1))
    return calls + (('FLUSH', base+99),)


def work(n):
    assert type(n) is int and n in (1, 64)
    # Independently specified original body, including its RET, excluding caller
    # and instrumentation. The native oracle separately qualifies these counts.
    return (6*n+5, n, n-1, n, 1, 8)


def measure(text, schedule, k, epochs):
    summary, joined = check_exact(text, commands(schedule, k), k, epochs, 'EpochLimit')
    return summary, _reduce(summary, joined, schedule, k)


def selection_error(n, population_work, retained, retained_work):
    assert all(type(v) is int and v >= 0 for v in (n, population_work, retained, retained_work))
    assert 0 <= retained <= n and n > 0 and retained_work <= population_work
    if not retained:
        assert retained_work == 0
        return dict(error_numerator=None, error_denominator=None, error_status='unresolved')
    return dict(error_numerator=retained_work*n-population_work*retained,
        error_denominator=retained*n, error_status='exact')


def _reduce(summary, joined, schedule, k):
    expected = commands(schedule, k)[:-1]
    assert len(joined) == len(expected) == 48
    by_id = {r.id: r for r in joined}
    assert len(by_id) == 48 and set(by_id) == {c[1] for c in expected}
    for index, (_, id_, bound, data) in enumerate(expected):
        row = by_id[id_]
        assert (row.worker, row.ordinal, row.bound, row.data) == (1+index % 2, 1+index//2, bound, data)
        assert row.owner in ('sampled', 'closed', 'removed', 'initial')
        assert row.disposition in ('retained', 'dropped', 'unsampled')
        assert (row.owner == 'sampled') == (row.disposition != 'unsampled')
    rows = []
    for worker in (1, 2, 0):
        selected = [r for r in joined if worker == 0 or r.worker == worker]
        groups = {'population': selected,
            'admitted': [r for r in selected if r.owner == 'sampled'],
            **{p: [r for r in selected if r.disposition == p] for p in PARTITIONS[2:]}}
        row = dict(schedule=schedule, k=k, worker=str(worker) if worker else 'combined')
        for partition, records in groups.items():
            row[partition+'_calls'] = len(records)
            totals = tuple(sum(work(r.bound)[i] for r in records) for i in range(len(METRICS)))
            row.update((partition+'_'+metric, total) for metric, total in zip(METRICS, totals))
        for suffix in ('calls', *METRICS):
            assert row['population_'+suffix] == row['admitted_'+suffix]+row['unsampled_'+suffix]
            assert row['admitted_'+suffix] == row['retained_'+suffix]+row['dropped_'+suffix]
        n, p = row['population_calls'], row['population_instructions']
        retained, sampled_work = row['retained_calls'], row['retained_instructions']
        assert n == (48 if worker == 0 else 24)
        row.update(selection_error(n, p, retained, sampled_work))
        if retained:
            if schedule in ('short', 'long'): assert row['error_numerator'] == 0
        if k == 1000:
            assert retained == n and row['dropped_calls'] == row['unsampled_calls'] == 0
            assert row['error_numerator'] == 0
        rows.append(row)
    combined = rows[-1]
    for partition in PARTITIONS:
        for suffix in ('calls', *METRICS):
            key = partition+'_'+suffix
            assert combined[key] == rows[0][key]+rows[1][key]
    for key, partition in (('calls', 'population'), ('admitted', 'admitted'),
            ('retained', 'retained'), ('dropped', 'dropped'), ('unsampled', 'unsampled')):
        assert summary[key] == combined[partition+'_calls']
    assert [w['worker'] for w in summary['workers']] == [1, 2]
    for row, worker in zip(rows, summary['workers']):
        assert (worker['calls'], worker['completed'], worker['unsampled']) == (
            row['population_calls'], row['admitted_calls'], row['unsampled_calls'])
    return rows


def encode(rows):
    assert len(rows) == 3 and [r['worker'] for r in rows] == ['1', '2', 'combined']
    assert len(FIELDS) == 41 and all(len(name) <= 32 for name in FIELDS)
    for row in rows:
        assert set(row) == set(FIELDS)
        for value in row.values():
            text = '' if value is None else str(value)
            assert len(text) <= 32 and all(32 <= ord(c) < 127 and c not in ',"' for c in text)
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=FIELDS, lineterminator='\n')
    writer.writeheader(); writer.writerows(rows)
    data = output.getvalue().encode('ascii')
    assert 0 < len(data) <= SUMMARY_CAP
    return data
