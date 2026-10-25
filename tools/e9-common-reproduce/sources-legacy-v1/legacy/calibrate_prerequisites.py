#!/usr/bin/env python3
"""Prospective pure completion-summary negatives; no external commands."""
import copy
import json
from pathlib import Path
import sys
import tempfile

if sys.flags.optimize:
    raise SystemExit('optimized Python disables prerequisite calibration')
from prerequisites import (COHORT_SHA, SELECTED_SHA, EMITTED_SHA, TOTALS,
                           require_gate_summary, validate)

ACCEPTED = ['exact fresh six/core native/state inventory']
REFUSED = ['missing fresh state terminal', 'wrong completion status',
    'historical original cohort', 'historical selection', 'historical emitted cohort',
    'missing B1 output', 'refusal substituted for positive', 'missing baseline',
    'missing native execution', 'missing state trace', 'missing state point',
    'missing hook witness', 'missing file page', 'missing original state phase',
    'missing capture file', 'missing capture directory', 'full qualification claimed',
    'backend ABI relabelled resolved', 'E9 native enabled']


def calibrate():
    original = dict(status='FRESH_CORRECTED_CORE_EMISSION_NATIVE_STATE_COMPLETE',
        original_cohort_sha256=COHORT_SHA, selected_manifest_sha256=SELECTED_SHA,
        emitted_cohort_sha256=EMITTED_SHA, emitted_B1=6, refused=0,
        original_baselines=4, rewritten_native=36, state_totals=copy.deepcopy(TOTALS),
        state_phases=[48, 48, 48], captured_files=2642, captured_directories=702,
        qualification_complete=False, backend_ABI_defect_resolved=False,
        E9_native_enabled=False)
    require_gate_summary(original)
    rejected = []
    def refuse(name, call):
        try:
            call()
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError('invalid prerequisite accepted: ' + name)
    with tempfile.TemporaryDirectory(prefix='e9-prerequisite-negative-') as empty:
        refuse(REFUSED[0], lambda: validate(Path(empty), {}))
    def changed(name, key, value):
        value_map = copy.deepcopy(original); value_map[key] = value
        refuse(name, lambda: require_gate_summary(value_map))
    changed(REFUSED[1], 'status', 'NATIVE_FINISHED_CAPTURE_AUDIT_PENDING')
    for index, key in [(2, 'original_cohort_sha256'), (3, 'selected_manifest_sha256'), (4, 'emitted_cohort_sha256')]:
        changed(REFUSED[index], key, '0' * 64)
    for index, key, value in [(5, 'emitted_B1', 5), (6, 'refused', 1),
            (7, 'original_baselines', 3), (8, 'rewritten_native', 35)]:
        changed(REFUSED[index], key, value)
    for index, key in [(9, 'traces'), (10, 'points'), (11, 'hook_witnesses'), (12, 'file_pages')]:
        totals = copy.deepcopy(TOTALS); totals[key] -= 1
        changed(REFUSED[index], 'state_totals', totals)
    for index, key, value in [(13, 'state_phases', [47, 48, 48]),
            (14, 'captured_files', 2641), (15, 'captured_directories', 701),
            (16, 'qualification_complete', True), (17, 'backend_ABI_defect_resolved', True),
            (18, 'E9_native_enabled', True)]:
        changed(REFUSED[index], key, value)
    assert rejected == REFUSED and len(ACCEPTED) == 1 and len(rejected) == 19
    return dict(accepted=ACCEPTED, refused=rejected, acceptances=1, refusals=19,
                actual_process_launches=0, actual_state_traces=0)


if __name__ == '__main__':
    print(json.dumps(calibrate(), indent=2))
