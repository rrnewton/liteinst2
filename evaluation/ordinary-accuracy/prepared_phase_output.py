"""Prepared first-call observations; strict full population, no phase tolerance."""
from pathlib import Path
import importlib.util
import sys

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location('_prepared_phase_accuracy', Path(__file__).with_name('phase_output.py'))
assert _spec is not None and _spec.loader is not None
phase = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(phase)
base = phase.base
VERSION = 'selected-accuracy-prepared-phase-session-v1'
CAP, LINE, RECORDS = base.CAP, base.LINE, base.RECORDS
Refused, need, uint = base.Refused, base.need, base.uint
shared, truth, authority = base.shared, base.truth, base.authority


def row_limit(epochs):
    base.integer(epochs, 2, 520)
    # Old 5R+3E+20 + R CALLTIME + header + RELEASE + PREPARED + TARGET_ARM + GATE.
    return 6 * RECORDS + 3 * epochs + 25


def envelope_limit(epochs):
    # Retain one possible cancellation row, never admit it as complete success.
    return row_limit(epochs) + 1


def framing(stdout, stderr, epochs):
    need(type(stdout) is bytes and type(stderr) is bytes, 'raw stream types')
    need(0 < len(stdout) <= CAP and stdout.endswith(b'\n'), 'finite complete stream')
    need(stderr == b'', 'nonempty terminal stderr remains a refusal')
    need(stdout.count(b'\n') <= row_limit(epochs), 'finite prepared phase success row count')
    lines = stdout.decode('ascii')[:-1].split('\n')
    need(all(0 < len(line) + 1 <= LINE and '\r' not in line for line in lines), 'line framing')
    return [line.split(',') for line in lines]


def observations(rows, policy):
    target = policy['period_ms'] * 1000000 + policy['delay_ns']
    header = ['PREPARED_PHASE', policy['phase'], str(policy['delay_ns']), '1', str(target)]
    need(len(rows) >= 4 and rows[0][:2] == ['READY', VERSION], 'explicit prepared phase header')
    need(rows[3] == header, 'fixed target epoch and original manifest phase/delay')
    kept, prepared, arm, gate = [], None, None, None
    target_history_prefix = None
    for at, row in enumerate(rows):
        tag = row[0]
        need(tag != 'CANCELLED', 'cancellation is not a full returned population')
        if tag in ('PREPARED', 'TARGET_ARM'):
            need(0 < at < len(rows)-1 and len(rows[at-1]) >= 4
                 and rows[at-1][0] == 'HISTORY' and rows[at-1][3] == 'published',
                 'prepared observation follows actual publication')
            following = rows[at+1]
            if tag == 'PREPARED':
                need(prepared is None and len(row) == 4 and row[:3] == ['PREPARED', '1', '41'],
                     'one exact prepared record identity')
                need(len(following) == 7 and following[:2] == ['ARM', '1'], 'prepared before actual ARM1')
                prepared = dict(record_id=1, function_id=41, ready_before_origin_ns=uint(row[3]))
            else:
                need(arm is None and len(row) == 6 and row[:2] == ['TARGET_ARM', '2'], 'one actual target ARM2')
                need(len(following) == 7 and following[0] == 'ARM' and following[1:6] == row[1:]
                     and following[6] == '1', 'exact accepted target/ARM join')
                arm = dict(zip(('number','generation','due_ns','started_ns','completed_ns'), map(uint,row[1:])))
                target_history_prefix = uint(rows[at-1][2])
        elif tag == 'GATE':
            need(gate is None and len(row) == 5 and row[:3] == ['GATE', '1', '41'], 'one exact gate identity')
            need(at >= 3 and at+1 < len(rows) and rows[at-3][0] == 'RESULT'
                 and rows[at-2][0] == rows[at-1][0] == 'PMU' and rows[at+1][:3] == ['RELEASE','1','41'],
                 'first gate after both endpoints immediately before release')
            gate = dict(first_poll_ns=uint(row[3]), opened_ns=uint(row[4]))
        else:
            need(tag != 'PREPARED_PHASE' or at == 3, 'one initial prepared phase metadata row')
            kept.append(row)
    need(prepared is not None and arm is not None and gate is not None, 'all prepared observations required')
    # The unchanged common phase parser joins every original RELEASE/CALLTIME.
    numeric, release, times = phase._observations(kept, policy, VERSION, header)
    return numeric, prepared, arm, target_history_prefix, gate, release, times


def check(stdout, stderr, *, manifest_bytes, input_bytes, selected_bytes, truth_bytes,
          table, caller, body_bytes, abi, policy, cpus):
    try:
        authority(manifest_bytes, input_bytes, selected_bytes, truth_bytes,
                  table, caller, body_bytes, abi, policy, cpus)
        rows = framing(stdout, stderr, policy['epochs'])
        kept, prepared, target_arm, target_history_prefix, gate, release, times = observations(rows, policy)
        result = base._check_rows(stdout, stderr, manifest_bytes, input_bytes, selected_bytes,
            truth_bytes, table, caller, body_bytes, abi, policy, cpus, kept, VERSION)
        arms = result['arms']
        need(len(arms) >= 2 and all(arms[1][k] == v for k,v in target_arm.items()), 'actual accepted ARM2 identity')
        need(result['calls'][0]['call']['history_prefix'] >= target_history_prefix,
             'prepared first call precedes actual target publication')
        period = policy['period_ms'] * 1000000
        target, end = period + policy['delay_ns'], policy['epochs'] * period
        need(target_arm['due_ns'] == period and target < end, 'immutable epoch-one target inside original end')
        need(gate['first_poll_ns'] <= gate['opened_ns'] and
             max(target, target_arm['completed_ns']) <= gate['opened_ns'], 'prepared gate readiness and clock order')
        need(gate['opened_ns'] == release['gate_enter_ns'] == release['released_ns']
             <= times[0]['before_invoke_ns'] < end, 'actual admission samples before original end')
        # All old gates/joins and original timestamp-minus-delay fields are retained.
        phase.annotate(result, release, times, policy)
        for timing in times:
            timing.update(before_target_error_ns=timing['before_invoke_ns']-target,
                after_target_error_ns=timing['after_return_ns']-target,
                before_target_whole_periods_late=(timing['before_invoke_ns']-target)//period,
                after_target_whole_periods_late=(timing['after_return_ns']-target)//period)
        result.update(wire_rows=rows, prepared_phase_observations=dict(
            target_epoch=1, target_ns=target, original_end_ns=end, prepared=prepared,
            target_arm=target_arm, target_publication_history_prefix=target_history_prefix, gate=gate,
            release_target_lateness_ns=release['released_ns']-target,
            release_target_whole_periods_late=(release['released_ns']-target)//period,
            phase_realization_status='UNRESOLVED', calibration_status='UNRESOLVED',
            timing_scope='Actual worker admission samples; preemption can delay physical native entry.',
            input_scope='First accepted row prepared before origin; later CSV polling paused through first return.'))
        return result
    except (AssertionError, ValueError, KeyError, TypeError, IndexError, UnicodeError) as error:
        raise Refused(str(error) or 'strict prepared phase guard', stdout, stderr) from error
