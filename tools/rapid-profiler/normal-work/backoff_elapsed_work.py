#!/usr/bin/env python3
"""Actual back-off elapsed wire; no native, deadline or performance authority."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import importlib.util
from pathlib import Path

_path = Path(__file__).resolve().with_name('backoff_work.py')
_spec = importlib.util.spec_from_file_location('_elapsed_backoff_population', _path)
if _spec is None or _spec.loader is None:
    raise RuntimeError('missing local back-off population checker')
common = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(common)

MAX_OUTPUT = 922688
MAX_LINES = 4249
TIMING_LINES = 133
TIMING_CAP = 16384
TIMING_ROW_CAP = 64
COMMENT = '# normal observer backoff elapsed; complete fixed work and raw callback ticks with a separate RAW timing appendix; no accuracy, cheap-off or 520-arm qualification'
TIMING_COMMENT = '# normal backoff elapsed v1; segmented guarded call-path and validated service wall nanoseconds; no subtraction, accuracy, speedup or continuous-throughput claim'
TIMING_HEADER = 'kind,index,start_ns,end_ns'
TIMING_KEYS = ('k', 'app_cpu', 'controller_cpu', 'clock', 'units', 'timing_rows',
    'setup_ns', 'body_ns', 'service_ns')
FUNCTIONAL_SCOPE = ('Complete fixed-work population and raw callback endpoints only; '
    'the separate elapsed appendix describes a guarded call path and validated service. '
    'Absent closed/later-generation activity remains UNEXERCISED. No timing accuracy, '
    'cheap-off, 520-arm or full-A5 qualification; Requested stop does not prove every '
    'elapsed due arm was assessed.')
SCOPE = ('Raw CLOCK_MONOTONIC_RAW spans and complete fixed work only. No rate, ratio, '
    'subtraction, body-only truth, pure observer cost, speedup, continuous throughput, '
    'accuracy or full-A5 qualification. First-block preflight precedes service; setup '
    'plus service is not an exhaustive process partition. External process_timer '
    'CLOCK_MONOTONIC endpoints have a separate clock origin.')
SOURCE_ATTESTED = (common.SOURCE_ATTESTED+' Actual RAW reads/conversion and operation '
    'boundaries remain producer/native authority. Printed terminals are tentative '
    'until the unchanged post-output Schedule completion and successful native/timer '
    'status plus normal owned closure. The wire grants none of those facts.')


def _division(value):
    return 'UNRESOLVED_ZERO' if value == 0 else 'NOT_COMPUTED'


def _terminal(line, k, app_cpu, controller_cpu):
    words = line.split(' ')
    assert words[:2] == ['normal-observer-backoff-elapsed', 'FUNCTIONAL_PASS']
    assert len(words) == len(common.KEYS)+2
    result = {}
    for key, word in zip(common.KEYS, words[2:]):
        assert word.startswith(key+'=')
        value = word[len(key)+1:]
        if key == 'timing':
            assert value == 'raw-appendix'
            result[key] = value
        elif key in common.LITERALS:
            assert value == common.LITERALS[key]
            result[key] = value
        elif key in common.BOOLEANS:
            assert value in ('true', 'false')
            result[key] = value == 'true'
        else:
            result[key] = common._uint(value)
    assert all(result[key] == value for key, value in common.FIXED.items())
    assert (result['k'], result['app_cpu'], result['controller_cpu']) == (k, app_cpu, controller_cpu)
    assert 0 < result['pid'] <= common.I32 and result['tid'] == result['pid']
    assert 0 < result['controller_tid'] <= common.I32 and result['controller_tid'] != result['tid']
    assert 0 < result['entry'] <= common.U64-37 and 0 < result['caller'] <= common.U64-67
    arms = result['arms']
    assert 1 <= arms <= 520
    assert result['committed_arms'] == result['completed_arms'] == result['reports'] == arms
    assert result['actions'] == arms+1 and result['rearmed'] == (arms > 1)
    assert result['sampled'] == result['records'] <= common.ROWS
    assert result['sampled']+result['unsampled'] == common.ROWS
    assert 1 <= result['observed_generations'] <= arms
    assert result['input_unchanged'] and result['detached'] and not result['cheap_off']
    return result


def _timing_terminal(line, k, app_cpu, controller_cpu):
    words = line.split(' ')
    assert words[:2] == ['normal-observer-backoff-elapsed', 'TIMING_COMPLETE']
    assert len(words) == len(TIMING_KEYS)+2
    result = {}
    for key, word in zip(TIMING_KEYS, words[2:]):
        assert word.startswith(key+'=')
        value = word[len(key)+1:]
        result[key] = value if key in ('clock', 'units') else common._uint(value)
    assert (result['k'], result['app_cpu'], result['controller_cpu']) == (k, app_cpu, controller_cpu)
    assert (result['clock'], result['units'], result['timing_rows']) == ('CLOCK_MONOTONIC_RAW', 'ns', 130)
    return result


def check(stdout, stderr, k, app_cpu, controller_cpu):
    assert type(k) is int and k in (10, 1000)
    assert all(type(cpu) is int and 0 <= cpu <= 1023 for cpu in (app_cpu, controller_cpu))
    assert app_cpu != controller_cpu
    assert type(stdout) is bytes and 0 < len(stdout) <= MAX_OUTPUT
    assert type(stderr) is bytes and stderr == b''
    assert stdout.endswith(b'\n') and common.ASCII.fullmatch(stdout)
    lines = stdout[:-1].decode('ascii').split('\n')
    assert 3211 <= len(lines) <= MAX_LINES
    functional_lines, timing_lines = lines[:-TIMING_LINES], lines[-TIMING_LINES:]
    assert functional_lines[:2] == [COMMENT, common.HEADER]
    terminal = _terminal(functional_lines[-1], k, app_cpu, controller_cpu)
    arms = terminal['arms']
    assert len(functional_lines) == common.ROWS+4+2*arms
    prefix = ('\n'.join(functional_lines)+'\n').encode('ascii')
    assert len(prefix) <= common.MAX_OUTPUT
    assert sum(len(line)+1 for line in (functional_lines[0], functional_lines[1], functional_lines[-1])) <= 4096
    row_lines = functional_lines[2:2+common.ROWS]
    history_lines = functional_lines[2+common.ROWS:3+common.ROWS+arms]
    report_lines = functional_lines[3+common.ROWS+arms:-1]
    assert (len(row_lines), len(history_lines), len(report_lines)) == (3072, arms+1, arms)
    # Validate the actual elapsed framing before sharing only population semantics.
    functional = common._population(row_lines, history_lines, report_lines, terminal, k)
    functional.update(scope=FUNCTIONAL_SCOPE, source_attested=SOURCE_ATTESTED)
    assert len(timing_lines) == TIMING_LINES and timing_lines[:2] == [TIMING_COMMENT, TIMING_HEADER]
    assert sum(len(line)+1 for line in timing_lines) <= TIMING_CAP
    timing = _timing_terminal(timing_lines[-1], k, app_cpu, controller_cpu)
    expected = [('setup', 0), *(('body', i) for i in range(1, 129)), ('service', 0)]
    rows = []
    for line, (kind, index) in zip(timing_lines[2:-1], expected):
        assert len(line)+1 <= TIMING_ROW_CAP
        cells = line.split(',')
        assert len(cells) == 4 and cells[0] == kind
        assert common._uint(cells[1]) == index
        start, end = common._uint(cells[2]), common._uint(cells[3])
        assert start <= end
        elapsed = end-start
        rows.append(dict(kind=kind, index=index, start_ns=start, end_ns=end,
            elapsed_ns=elapsed, division_status=_division(elapsed)))
    assert len(rows) == 130
    setup, body, service = rows[0], rows[1:-1], rows[-1]
    total = 0
    for row in body:
        total += row['elapsed_ns']
        assert total <= common.U64
    assert setup['end_ns'] <= body[0]['start_ns']
    for left, right in zip(body, body[1:]):
        assert left['end_ns'] <= right['start_ns']
    assert service['start_ns'] == body[0]['start_ns']
    assert service['end_ns'] >= body[-1]['end_ns']
    assert total <= service['elapsed_ns']
    assert (timing['setup_ns'], timing['body_ns'], timing['service_ns']) == (
        setup['elapsed_ns'], total, service['elapsed_ns'])
    return dict(status='TIMING_COMPLETE', **timing, functional=functional,
        functional_prefix=prefix, setup=setup, body=body, service=service,
        timing_table=('\n'.join(timing_lines[1:-1])+'\n').encode('ascii'),
        zero_body_spans=sum(row['elapsed_ns'] == 0 for row in body),
        division_status={key: _division(timing[key]) for key in ('setup_ns', 'body_ns', 'service_ns')},
        scope=SCOPE, source_attested=SOURCE_ATTESTED)
