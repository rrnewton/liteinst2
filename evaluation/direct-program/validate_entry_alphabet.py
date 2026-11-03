#!/usr/bin/env python3
"""Explicit entry-alphabet controls through the unchanged min5 validator."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_minimum_window.py')
spec = importlib.util.spec_from_file_location('entry_alphabet_minimum_controls', SOURCE)
minimum = importlib.util.module_from_spec(spec)
spec.loader.exec_module(minimum)
CONTROLS = {
    'alphabet-digits': ('emission::placement::digits::tests::', (
        'all_entry_bytes_and_fixed_conflicts_are_exact_in_each_digit',
        'digit_minimum_matches_finite_enumeration_across_carries',
        'all_masks_match_small_signed_partial_and_full_page_oracle',
        'fixed06_wrapper_matches_independent_argmin_for_every_mask',
        'alphabet_geometry_does_not_change_fixed_profile_or_indexed_attempt_zero',
        'clipped_signed_edges_empty_sets_and_interval_order_are_exact',
    )),
    'alphabet-checked-target': ('emission::placement::entry_alphabet::tests::', (
        'checked_target_preserves_seed_or_selects_one_alphabet_target',
        'checked_target_rejoins_every_field_and_rejects_coherent_non_alphabet_bytes',
        'consumption_rechecks_permits_occupancy_and_unchanged_one_page_policy',
    )),
    'alphabet-core': ('quiescent::artifact_window::placement_tests::', (
        'actual_prepared_window_uses_non06_target_with_all_entries_and_observations',
        'explicit_fixed06_is_identical_to_legacy_success_and_refusal',
        'one_failed_encode_has_no_indexed_proof_and_append_failure_keeps_image_acceptance',
        'source_entry_current_overlay_and_size_refusals_keep_original_precedence',
        'alphabet_authority_refuses_live_unprepared_and_mixed_control_paths',
    )),
    'alphabet-frontend': ('grouped_artifact_frontend::alphabet_tests::', (
        'alphabet_group_keeps_every_observation_and_retained_entry_in_one_plan',
        'alphabet_policy_and_binding_are_distinct_while_min5_geometry_and_caps_stay_exact',
        'alphabet_does_not_repair_short_min5_seals_or_split_atomically_withheld_groups',
        'alphabet_storage_is_independent_and_singletons_keep_the_legacy_engine',
    )),
    'alphabet-cli': ('grouped_alphabet_tests::', (
        'alphabet_cli_selector_is_distinct_and_preserves_old_routes_and_storage',
        'alphabet_cli_keeps_complete_union_and_whole_unit_refusals_in_both_storage_modes',
        'alphabet_cli_rejects_old_profile_and_repinned_placement_or_embedded_metadata',
    )),
    'alphabet-router-native': ('entry_router::imp::entry_alphabet_native_tests::', (
        'alphabet_min5_every_entry_routes_through_production',
        'alphabet_min5_ret_fault_preserves_prior_pop_and_callbacks',
        'alphabet_min5_non06_pop_fault_preserves_uncommitted_state',
    )),
}
PYTHON_CONTROLS = (
    'test_alphabet_full_population_and_atomic_outcomes_keep_both_storage_modes',
    'test_alphabet_profile_mode_and_whole_policy_identity_cannot_be_relabelled',
    'test_alphabet_keeps_exact_min5_source_membership_routes_and_numeric_limits',
    'test_alphabet_refused_seals_and_withheld_members_never_become_emissions',
)

COMMANDS = list(minimum.COMMANDS)
for row in (
    ('alphabet-digits', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                         'emission::placement::digits::tests::'], 180),
    ('alphabet-checked-target', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                                 'emission::placement::entry_alphabet::tests::'], 180),
    ('alphabet-core', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                       'quiescent::artifact_window::placement_tests::'], 180),
    ('alphabet-frontend', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib',
                           'grouped_artifact_frontend::alphabet_tests::'], 180),
    ('alphabet-cli', ['cargo', 'test', '-p', 'liteinst-rewrite', '--example',
                      'disassembly_sites', 'grouped_alphabet_tests::'], 180),
    ('alphabet-router-native', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                                'entry_router::imp::entry_alphabet_native_tests::'], 180),
    ('alphabet-linkage-python', ['/usr/bin/python3.9', '-I', '-B',
                                 'evaluation/direct-program/test_grouped_alphabet_linkage.py', '-v'], 180),
):
    COMMANDS.insert(-2, row)


def validate_result(name, raw):
    minimum.validate_result(name, raw)
    if name in CONTROLS:
        cases = CONTROLS[name][1]
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(str(len(cases)).encode(), b'0', b'0')], 'exact alphabet control population must run'
    for control, (prefix, cases) in CONTROLS.items():
        if name in (control, 'workspace'):
            for case in cases:
                assert raw.splitlines().count(('test ' + prefix + case + ' ... ok').encode()) == 1, 'alphabet control missing: ' + case
    if name == 'alphabet-linkage-python':
        assert re.findall(rb'^Ran (\d+) tests in ', raw, re.M) == [b'4'] and raw.rstrip().endswith(b'OK')
        for case in PYTHON_CONTROLS:
            assert raw.splitlines().count((case + ' (__main__.GroupedAlphabetLinkage) ... ok').encode()) == 1, 'alphabet Python control missing: ' + case


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv.count('--focused') <= 1
    focused = '--focused' in sys.argv
    if focused:
        sys.argv.remove('--focused')
    ledger = minimum.ledger
    grouped = ledger.upstream.program.grouped
    # All prior 163 controls, plus 14 core/4 frontend/3 CLI/3 native/4 Python.
    focused_names = ('fmt', *grouped.window.CONTROLS, 'native-stack', *grouped.CONTROLS,
                     'grouped-cli', 'grouped-linkage-python', *ledger.upstream.CONTROLS,
                     'upstream-linkage-python', *ledger.CONTROLS, 'ledger-storage-python',
                     *minimum.CONTROLS, 'min5-linkage-python', *CONTROLS, 'alphabet-linkage-python')
    selected = [row for row in COMMANDS if row[0] in focused_names] if focused else COMMANDS
    raise SystemExit(grouped.window.stack.cuts.clock.shared.main(
        commands=selected,
        profile='entry-alphabet-focused-180-v1' if focused else 'entry-alphabet-correctness-1800-360-v1',
        scope='Focused 191 inherited/min5/alphabet controls only; not full workspace validation.' if focused else
              'Required correctness and every prior minimum-window control plus explicit entry-alphabet '
              'placement arithmetic, authority, frontend, CLI/linkage and finite production-router native '
              'controls. No actual-program corpus, runtime exemption, performance or strict A4 qualification.',
        log_namespace='entry-alphabet', validate_result=validate_result))
