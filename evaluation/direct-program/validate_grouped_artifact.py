#!/usr/bin/env python3
"""Grouped artifact controls through the existing artifact-window validator."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_artifact_window.py')
spec = importlib.util.spec_from_file_location('grouped_artifact_window_controls', SOURCE)
window = importlib.util.module_from_spec(spec)
spec.loader.exec_module(window)
CONTROLS = {
    'grouped-core': ('quiescent::artifact_window::tests::', (
        'exact_six_pop_has_one_plan_and_all_selected_and_unselected_entry_routes',
        'outside_branch_entries_keep_both_head_kinds_and_an_internal_transfer_still_refuses',
        'explicit_population_and_profile_guards_refuse_before_any_physical_attempt',
        'identity_current_bytes_and_cet_refuse_at_their_original_stages',
        'pending_outsider_is_checked_after_candidate_append_without_mutating_predecessor',
        'exact_end_and_displacement_bounds_precede_unchanged_call_qualification',
        'one_page_one_candidate_and_symbol_limits_remain_hard_refusals',
    )),
    'grouped-frontend': ('grouped_artifact_frontend::tests::', (
        'grouped_six_pop_carrier_retains_all_members_routes_and_one_image',
        'grouped_policy_and_both_metadata_forms_bind_total_partition',
        'grouped_membership_mutations_refuse_without_singleton_fallback',
        'grouped_jump_member_is_never_filtered_and_refusal_is_atomic',
        'grouped_pending_and_resource_failures_leave_complete_draft_unmodified',
        'grouped_carrier_refusal_withholds_all_six_and_preserves_original_identity',
        'grouped_nongroup_route_retains_legacy_images_edits_and_outcomes',
    )),
    'artifact-window-native': ('', (
        'artifact_window_native_every_entry',
        'artifact_window_native_branch_paths',
        'artifact_window_native_rsp_effects',
        'artifact_window_native_later_operand_fault',
    )),
}
COMMANDS = list(window.COMMANDS)
for row in (
    ('grouped-core', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                      'quiescent::artifact_window::tests::'], 180),
    ('grouped-frontend', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib',
                          'grouped_artifact_frontend::tests::'], 180),
    ('artifact-window-native', ['cargo', 'test', '-p', 'liteinst2',
                                '--test', 'quiescent_oracle', 'artifact_window_native_'], 180),
):
    COMMANDS.insert(-2, row)


def validate_result(name, raw):
    window.validate_result(name, raw)
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
    raise SystemExit(window.stack.cuts.clock.shared.main(
        commands=selected,
        profile='grouped-artifact-focused-180-v1' if focused else 'grouped-artifact-correctness-1800-360-v1',
        scope='Focused core/frontend/native artifact controls only; not full workspace validation.' if focused else
              'Required correctness and all prior controls plus grouped artifact planning/frontend '
              'and finite native emission controls. No actual-program corpus, runtime exemption, '
              'performance or strict A4 qualification.',
        log_namespace='grouped-artifact', validate_result=validate_result))
