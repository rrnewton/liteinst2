#!/usr/bin/env python3
"""Fixed observer transcript plus elapsed-wall endpoints; no rate estimator."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import importlib.util
from pathlib import Path

_path = Path(__file__).resolve().with_name('observer_work.py')
_spec = importlib.util.spec_from_file_location('_throughput_observer_work', _path)
if _spec is None or _spec.loader is None:
    raise RuntimeError('missing local observer checker')
OBSERVER = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(OBSERVER)

PREFIX_LINES = 3075
LINES = 3208
MAX_OUTPUT = 806912
COMMENT = '# normal throughput v1; segmented call-path and validated service elapsed wall nanoseconds; no subtraction, accuracy, or continuous-throughput claim'
HEADER = 'kind,index,start_ns,end_ns'
KEYS = ('mode', 'cpu', 'clock', 'units', 'timing_rows', 'setup_ns', 'body_ns', 'service_ns')
SCOPE = ('Raw CLOCK_MONOTONIC_RAW wall endpoints and fixed functional population only. '
    'No rates, subtraction, correction, on-CPU/body-only truth, continuous throughput, '
    'accuracy, performance qualification or full-A5 claim. Process-timer MONOTONIC '
    'absolute endpoints have a separate clock origin.')
SOURCE_ATTESTED = ('Actual clock reads/conversion, singleton CPU custody and reservation, '
    'physical calls/returns, source/input postflight before checkpoints, and full '
    'journal/Report/history/service-boundary custody remain producer/native/external '
    'authority. This parser verifies the transcript, not those physical observations.')


def _division(value):
    return 'UNRESOLVED_ZERO' if value == 0 else 'NOT_COMPUTED'


def _terminal(line, mode):
    words = line.split(' ')
    assert words[:2] == ['normal-observer-throughput', 'TIMING_COMPLETE']
    assert len(words) == len(KEYS)+2
    out = {}
    for key, word in zip(KEYS, words[2:]):
        assert word.startswith(key+'=')
        value = word[len(key)+1:]
        out[key] = value if key in ('mode', 'clock', 'units') else OBSERVER._uint(value)
    assert (out['mode'], out['clock'], out['units'], out['timing_rows']) == (
        mode, 'CLOCK_MONOTONIC_RAW', 'ns', 130)
    assert out['cpu'] <= 1023
    return out


def check(stdout, stderr, mode):
    assert type(mode) is str and mode in ('native', 'always-on')
    assert type(stdout) is bytes and 0 < len(stdout) <= MAX_OUTPUT
    assert stdout.endswith(b'\n') and OBSERVER.ASCII.fullmatch(stdout)
    raw = stdout.split(b'\n')
    assert len(raw) == LINES+1 and raw[-1] == b''
    prefix = b'\n'.join(raw[:PREFIX_LINES])+b'\n'
    functional = OBSERVER.check(prefix, stderr, mode)
    lines = [line.decode('ascii') for line in raw[PREFIX_LINES:-1]]
    assert len(lines) == 133 and lines[:2] == [COMMENT, HEADER]
    terminal = _terminal(lines[-1], mode)
    expected = [('setup', 0), *(('body', i) for i in range(1, 129)), ('service', 0)]
    rows = []
    for line, (kind, index) in zip(lines[2:-1], expected):
        cells = line.split(',')
        assert len(cells) == 4 and cells[0] == kind
        assert OBSERVER._uint(cells[1]) == index
        start, end = OBSERVER._uint(cells[2]), OBSERVER._uint(cells[3])
        assert start <= end
        elapsed = end-start
        rows.append(dict(kind=kind, index=index, start_ns=start, end_ns=end,
            elapsed_ns=elapsed, division_status=_division(elapsed)))
    assert len(rows) == 130
    setup, body, service = rows[0], rows[1:-1], rows[-1]
    total = 0
    for row in body:
        total += row['elapsed_ns']
        assert total <= OBSERVER.U64
    assert setup['end_ns'] <= body[0]['start_ns']
    for left, right in zip(body, body[1:]):
        assert left['end_ns'] <= right['start_ns']
    assert service['start_ns'] == body[0]['start_ns']
    assert service['end_ns'] >= body[-1]['end_ns']
    assert total <= service['elapsed_ns']
    assert (terminal['setup_ns'], terminal['body_ns'], terminal['service_ns']) == (
        setup['elapsed_ns'], total, service['elapsed_ns'])
    return dict(status='TIMING_COMPLETE', **terminal, functional=functional,
        functional_prefix=prefix, setup=setup, body=body, service=service,
        timing_table=('\n'.join(lines[1:-1])+'\n').encode('ascii'),
        zero_body_spans=sum(row['elapsed_ns'] == 0 for row in body),
        division_status={key: _division(terminal[key]) for key in ('setup_ns', 'body_ns', 'service_ns')},
        scope=SCOPE, source_attested=SOURCE_ATTESTED)
