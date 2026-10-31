"""Explicit shared-Instant observations; no phase tolerance or PMU clock transform."""
from pathlib import Path
import importlib.util
import sys

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location('_phase_accuracy_base', Path(__file__).with_name('output.py'))
assert _spec is not None and _spec.loader is not None
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)
VERSION = 'selected-accuracy-phase-session-v1'
CAP, LINE, RECORDS = base.CAP, base.LINE, base.RECORDS
Refused, need, uint = base.Refused, base.need, base.uint
shared, truth, authority = base.shared, base.truth, base.authority


def row_limit(epochs):
    base.integer(epochs, 1, 520)
    # One leaf: old 5R+3E+20, plus R CALLTIME, one PHASE, one RELEASE.
    return 6 * RECORDS + 3 * epochs + 22


def framing(stdout, stderr, epochs):
    need(type(stdout) is bytes and type(stderr) is bytes, 'raw stream types')
    need(0 < len(stdout) <= CAP and stdout.endswith(b'\n'), 'finite complete stream')
    need(stderr == b'', 'nonempty terminal stderr remains a refusal')
    need(stdout.count(b'\n') <= row_limit(epochs), 'finite phase row count')
    lines = stdout.decode('ascii')[:-1].split('\n')
    need(all(0 < len(line) + 1 <= LINE and '\r' not in line for line in lines), 'line framing')
    return [line.split(',') for line in lines]


def observations(rows, policy):
    return _observations(rows, policy, VERSION, ['PHASE', policy['phase'], str(policy['delay_ns'])])


def _observations(rows, policy, version, header):
    need(len(rows) >= 4 and rows[0][:2] == ['READY', version], 'explicit phase header')
    need(rows[3] == header, 'requested manifest phase/delay')
    kept, times, release = rows[:3], [], None
    at = 4
    while at < len(rows):
        row = rows[at]
        need(row[0] not in ('PHASE', 'RELEASE', 'CALLTIME'), 'phase row position/uniqueness')
        kept.append(row)
        if row[0] == 'RESULT':
            ordinal = len(times) + 1
            need(ordinal <= RECORDS and at + 3 < len(rows), 'complete phase population')
            # PMU cells are unmodified; the common validator owns their full joins.
            need(rows[at + 1][0] == rows[at + 2][0] == 'PMU', 'phase after both endpoints')
            kept.extend(rows[at + 1:at + 3])
            at += 3
            if ordinal == 1:
                r = rows[at]
                need(len(r) == 5 and r[:3] == ['RELEASE', '1', '41'], 'once-only first release')
                release = dict(gate_enter_ns=uint(r[3]), released_ns=uint(r[4]))
                at += 1
                need(at < len(rows), 'release without returned first call')
            t = rows[at]
            need(len(t) == 6 and t[:4] == ['CALLTIME', str(ordinal), str(ordinal), '41'], 'timing identity/order')
            before, after = uint(t[4]), uint(t[5])
            need(before <= after and (not times or times[-1]['after_return_ns'] <= before), 'call clock order')
            times.append(dict(ordinal=ordinal, record_id=ordinal, function_id=41,
                              before_invoke_ns=before, after_return_ns=after))
        at += 1
    need(release is not None and len(times) == RECORDS, 'all 2048 returned timings')
    return kept, release, times


def check(stdout, stderr, *, manifest_bytes, input_bytes, selected_bytes, truth_bytes,
          table, caller, body_bytes, abi, policy, cpus):
    try:
        # Authenticate every source-bound input before inspecting requested phase.
        authority(manifest_bytes, input_bytes, selected_bytes, truth_bytes,
                  table, caller, body_bytes, abi, policy, cpus)
        rows = framing(stdout, stderr, policy['epochs'])
        kept, release, times = observations(rows, policy)
        result = base._check_rows(stdout, stderr, manifest_bytes, input_bytes, selected_bytes,
            truth_bytes, table, caller, body_bytes, abi, policy, cpus, kept, VERSION)
        annotate(result, release, times, policy)
        result['wire_rows'] = rows
        return result
    except (AssertionError, ValueError, KeyError, TypeError, IndexError, UnicodeError) as error:
        raise Refused(str(error) or 'strict phase guard', stdout, stderr) from error


def annotate(result, release, times, policy):
    arms = result['arms']
    need(arms and arms[0]['completed_ns'] <= release['gate_enter_ns'] <= release['released_ns']
         <= times[0]['before_invoke_ns'], 'first arm/gate/release/call order')
    period = policy['period_ms'] * 1000000
    fence = policy['epochs'] * period + 2000000000
    need(policy['delay_ns'] <= release['released_ns'] < fence, 'original release delay/fence')
    need(release['gate_enter_ns'] < policy['delay_ns'] or
         release['released_ns'] == release['gate_enter_ns'], 'already-due gate is released without another observation')
    need(all(t['after_return_ns'] < fence for t in times), 'original call safety fence')
    release.update(requested_delay_ns=policy['delay_ns'],
        absolute_lateness_ns=release['released_ns'] - policy['delay_ns'],
        epoch_index=release['released_ns'] // period, remainder_ns=release['released_ns'] % period)
    for timing, call in zip(times, result['calls']):
        normal = call['call']
        need(normal['ordinal'] == timing['ordinal'] and normal['record_id'] == timing['record_id']
             and normal['index'] == 0, 'timing/NORMAL identity')
        # This is interval overlap only. NORMAL/history owns generation, and
        # the enclosure includes the ordinary call wrapper/store/RET.
        before, after = timing['before_invoke_ns'], timing['after_return_ns']
        overlap = [a['number'] for a in arms if a['started_ns'] <= after and before <= a['completed_ns']]
        due = [a['number'] for a in arms if before <= a['due_ns'] <= after]
        timing.update(before_requested_error_ns=before-policy['delay_ns'],
            after_requested_error_ns=after-policy['delay_ns'],
            before_epoch_index=before // period, before_remainder_ns=before % period,
            after_epoch_index=after // period, after_remainder_ns=after % period,
            overlapping_arm_count=len(overlap), first_overlapping_arm=overlap[0] if overlap else None,
            last_overlapping_arm=overlap[-1] if overlap else None,
            enclosed_due_count=len(due), first_enclosed_due=due[0] if due else None,
            last_enclosed_due=due[-1] if due else None)
        call['call_timing'] = timing
    result.update(phase_observations=dict(requested=dict(phase=policy['phase'],
        delay_ns=policy['delay_ns']), release=release, clock='shared in-process Instant origin',
        timing_scope='Enclosure of csv::invoke, including CALL/store/RET; not exact leaf entry/RET instants.',
        calibration_status='UNRESOLVED', phase_realization_status='UNRESOLVED',
        clock_transform='NONE: no join to producer monotonic_ns, TSC or PMU clocks'))
