#!/usr/bin/env python3
"""Strict one-process reference leg; no calibration, estimate or counterpart synthesis."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import importlib.util
from pathlib import Path

# Reuse only the authenticated sibling's pure constants and fixed input algebra.
# Resolve by file, not sys.path; the recipe pins both files before this import.
_spec = importlib.util.spec_from_file_location('normal_reference_leg_work',
    Path(__file__).with_name('reference_work.py'))
work = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(work)
MIB, U64, U32 = work.MIB, work.U64, work.U32
PHASES = ('qualification', 'calibration', 'holdout', 'comparison')
LEGS = ('original', 'installed')
COMMENT = '# normal reference leg; raw same-call endpoints are uncalibrated; no accuracy or performance claim'
HEADER = 'phase,trial,'+work.HEADER
FIELDS = ('phase', 'trial', *work.FIELDS)
COUNTS = {
    'original': dict(batches=0, events=0, reports=0, records=0, actions=0, entered=0,
        ret_observed=0, confirmed=0, completed=0, whole_journal_words=0),
    'installed': dict(batches=1, events=48, reports=1, records=24, actions=2, entered=24,
        ret_observed=24, confirmed=24, completed=24, whole_journal_words=512),
}
SCOPE = ('Functional uncalibrated single-leg collector only. R is a fenced CALL enclosure '
    'and H a callback interval, not original body-only duration. Fresh-process contrast '
    'includes setup, configuration, cache and ASLR effects; no accuracy, performance, '
    'perturbation estimate, PMU, session-temporal or full-A5 claim. Zero spans retained.')
SOURCE_ATTESTED = work.SOURCE_ATTESTED


def _key(phase, trial, leg):
    assert type(phase) is str and phase in PHASES
    assert type(trial) is int and 1 <= trial <= U64
    assert type(leg) is str and leg in LEGS


def _terminal(phase, trial, leg):
    _key(phase, trial, leg)
    c = COUNTS[leg]
    return (f'normal-reference-leg FUNCTIONAL_PASS phase={phase} trial={trial} leg={leg} '
        'selection=normal-reference-exact-37-v1 calls=24 helper_calls=12 reference_cells=24 '
        f'batches={c["batches"]} events={c["events"]} reports={c["reports"]} '
        f'records={c["records"]} actions={c["actions"]} entered={c["entered"]} '
        f'ret_observed={c["ret_observed"]} confirmed={c["confirmed"]} completed={c["completed"]} '
        f'unsampled=0 whole_journal_words={c["whole_journal_words"]} '
        'instructions=4800 conditional=780 taken=756 input_bytes=780 ret_bytes=192 '
        'input_unchanged=true joined=true')


def check(stdout, stderr, phase, trial, leg):
    _key(phase, trial, leg)  # The expected manifest key never comes from the output.
    assert type(stdout) is bytes and 0 < len(stdout) <= MIB
    assert type(stderr) is bytes and stderr == b''
    assert stdout.endswith(b'\n') and all(c == 10 or 32 <= c <= 126 for c in stdout)
    lines = stdout[:-1].decode('ascii').split('\n')
    assert len(lines) == 27 and lines[:2] == [COMMENT, HEADER]
    assert lines[-1] == _terminal(phase, trial, leg)
    assert len(FIELDS) == len(set(FIELDS)) == 45
    installed = leg == 'installed'
    rows = []
    for index, line in enumerate(lines[2:-1]):
        cells = line.split(','); assert len(cells) == 45
        absent = set(work.SDK_FIELDS) if not installed else ({'ack_ordinal'} if index == 23 else set())
        row = {}
        for name, cell in zip(FIELDS, cells):
            if name in absent:
                assert cell == ''; row[name] = None
            elif name in ('phase', *work.TEXT_FIELDS):
                assert cell != ''; row[name] = cell
            else:
                row[name] = work._uint(cell)
        assert (row['phase'], row['trial'], row['leg']) == (phase, trial, leg)
        assert all(row[name] == value for name, value in work._expected(index).items())
        assert row['reference_sequence'] == index+1  # Local in either fresh process.
        assert 0 < row['pid'] <= U32 and row['tid'] == row['pid']
        a, b = row['reference_start_ticks'], row['reference_end_ticks']
        assert a <= b and row['reference_ticks'] == b-a
        assert row['reference_start_aux'] == row['reference_end_aux'] <= U32
        p = row['reference_rsp']
        assert 136 <= p <= U64-48 and p % 16 == 0
        if installed:
            assert (row['registration'], row['install'], row['function']) == (1, 1852990822, 1)
            assert row['generation'] > 0 and row['ordinal'] == index+1
            assert row['owner'] == 'sampled' and row['invocation'] == index and row['history_prefix'] == 1
            assert 0 < row['entry_pc'] <= U64-36 and row['return_pc'] == row['entry_pc']+36
            assert row['entry_rsp']+8 == p and row['entry_rsp'] % 16 == 8
            continuation = 80 if index % 2 == 0 else 216
            assert row['return_word'] > continuation
            helper = row['return_word']-continuation
            assert helper % 4096 == 0
            s, e = row['start_ticks'], row['end_ticks']
            assert a <= s <= e <= b
            assert row['start_aux'] == row['end_aux'] == row['reference_start_aux']
            assert (row['raw_ticks'], row['entry_gap_ticks'], row['return_gap_ticks']) == (e-s, s-a, b-e)
            assert row['entry_gap_ticks']+row['raw_ticks']+row['return_gap_ticks'] == row['reference_ticks']
            assert row['ack'] == ('next-entry' if index < 23 else 'caller-checkpoint')
            assert row['ack_ordinal'] == (index+2 if index < 23 else None)
        rows.append(row)
    assert all(rows[i-1]['reference_end_ticks'] <= rows[i]['reference_start_ticks'] for i in range(1, 24))
    assert len({row['pid'] for row in rows}) == 1
    assert len({row['reference_start_aux'] for row in rows}) == 1
    assert all(rows[i]['reference_rsp'] == rows[i+1]['reference_rsp'] for i in range(0, 24, 2))
    if installed:
        assert len({row['generation'] for row in rows}) == 1
        assert len({row['entry_pc'] for row in rows}) == 1
        assert len({row['return_word']-(80 if i % 2 == 0 else 216) for i, row in enumerate(rows)}) == 1
    totals = {name: sum(row[name] for row in rows) for name in work.WORK_FIELDS}
    assert tuple(totals[name] for name in work.WORK_FIELDS) == (4800, 780, 756, 780, 192)
    table = ('\n'.join(lines[1:-1])+'\n').encode('ascii')
    return dict(status='FUNCTIONAL_PASS', phase=phase, trial=trial, leg=leg,
        selection='normal-reference-exact-37-v1', calls=24, helper_calls=12, reference_cells=24,
        **COUNTS[leg], unsampled=0, pid=rows[0]['pid'],
        generation=rows[0]['generation'] if installed else None,
        zero_reference_spans=sum(row['reference_ticks'] == 0 for row in rows),
        work=totals, rows=rows, table=table, scope=SCOPE, source_attested=SOURCE_ATTESTED)
