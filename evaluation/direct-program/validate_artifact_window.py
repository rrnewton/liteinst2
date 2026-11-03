#!/usr/bin/env python3
"""Shared artifact-window emission controls with the prior stack campaign."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_stack.py')
spec = importlib.util.spec_from_file_location('artifact_window_stack_controls', SOURCE)
stack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stack)
CONTROLS = {
    'artifact-window': ('trampoline::artifact_window::tests::', (
        'single_observation_keeps_ordinary_symbolic_bytes_maps_and_requirements',
        'stack_window_preserves_every_head_and_exact_callback_pc_fields',
        'internal_branch_targets_selected_entry_not_restored_body',
        'population_validation_preserves_existing_window_error_precedence',
        'complete_action_accounting_rejects_missing_duplicated_and_wrong_fields',
        'artifact_linking_keeps_original_field_error_before_missing_hook_and_fixed_obligation',
        'final_link_and_size_refusals_leave_old_live_actions_unsupported',
    )),
    'observer-sequence': ('trampoline::observer_sequence::tests::', (
        'instrumentation_refusal_precedes_restore_coordinate',
        'successful_instrumentation_preserves_later_coordinate_refusal',
    )),
}
COMMANDS = list(stack.COMMANDS)
for name, (prefix, _) in CONTROLS.items():
    COMMANDS.insert(-2, (name, ['cargo', 'test', '-p', 'liteinst2', '--lib', prefix], 180))


def validate_result(name, raw):
    stack.validate_result(name, raw)
    if name in CONTROLS:
        cases = CONTROLS[name][1]
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(str(len(cases)).encode(), b'0', b'0')], 'exact new control population must run'
    for control, (prefix, cases) in CONTROLS.items():
        if name in (control, 'workspace'):
            for case in cases:
                assert raw.splitlines().count(('test ' + prefix + case + ' ... ok').encode()) == 1, 'new control missing: ' + case


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv.count('--focused') <= 1
    focused = '--focused' in sys.argv
    if focused:
        sys.argv.remove('--focused')
    selected = [row for row in COMMANDS if row[0] in ('fmt', *CONTROLS)] if focused else COMMANDS
    raise SystemExit(stack.cuts.clock.shared.main(
        commands=selected,
        profile='artifact-window-focused-180-v1' if focused else 'artifact-window-correctness-1800-360-v1',
        scope='Focused emission controls only; not full workspace validation.' if focused else
              'Required correctness and prior stack controls plus typed artifact-window emission. '
              'No grouped planning, native corpus, runtime exemption, performance or strict A4 qualification.',
        log_namespace='artifact-window', validate_result=validate_result))
