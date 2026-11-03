#!/usr/bin/env python3
"""Explicit min5 controls through the unchanged compact-ledger validator."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_ledger_chunks.py')
spec = importlib.util.spec_from_file_location('minimum_window_ledger_controls', SOURCE)
ledger = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger)
CONTROLS = {'min5-core': ('quiescent::artifact_window::min5_tests::',
               ('seal_stops_at_first_whole_end_without_conflating_selected_and_retained_spans',
                'final_unselected_ret_uses_existing_encoder_routes_mask_and_continuation',
                'owned_seal_joins_exact_geometry_identity_bytes_and_supplied_population',
                'source_and_population_failures_precede_collection_without_search_credit',
                'block_and_displacement_bounds_keep_original_qualifier_precedence',
                'seal_does_not_bypass_current_overlay_pending_or_terminal_entry_checks',
                'seal_is_not_a_physical_budget_fitting_or_hook_binding_success')),
 'min5-frontend': ('grouped_artifact_frontend::min5_tests::',
                   ('min5_retained_ret_reaches_actual_carrier_without_changing_selected_population',
                    'min5_preflight_failure_keeps_all_units_and_exact_member_refusals_atomic',
                    'min5_full_manifest_and_frozen_source_join_reject_consumed_straddling_or_changed_input',
                    'min5_named_bounds_and_final_carrier_refusal_never_relax_atomicity',
                    'min5_reuses_compact_codec_and_unchanged_singleton_engine')),
 'min5-cli': ('grouped_min5_tests::',
              ('min5_cli_selector_is_explicit_and_keeps_legacy_and_storage_routes',
               'min5_cli_keeps_complete_population_for_retained_ret_and_preflight_refusal',
               'min5_cli_binding_rejects_old_profile_replay_and_mutated_policy_or_carrier')),
 'min5-router-native': ('entry_router::imp::routed_jmp_native_tests::',
                        ('row_00',
                         'row_01',
                         'row_02',
                         'row_03',
                         'row_04',
                         'row_05',
                         'row_06',
                         'row_07',
                         'row_08',
                         'row_09',
                         'row_10',
                         'row_11',
                         'row_12',
                         'row_13',
                         'row_14',
                         'row_15',
                         'row_16',
                         'row_17',
                         'row_18',
                         'row_19',
                         'row_20',
                         'row_21',
                         'row_22',
                         'row_23',
                         'row_24',
                         'row_25',
                         'row_26',
                         'row_27',
                         'row_28',
                         'row_29',
                         'row_30',
                         'actual_f_after_deactivation_uses_default_sigill',
                         'actual_f_without_owner_uses_default_sigill',
                         'readiness_disposition_and_duplicate_owner_refuse_before_source_publication',
                         'min5_every_entry_routes_through_production_and_preserves_ret_state',
                         'min5_unselected_ret_fault_preserves_prior_pop_and_callback_state'))}
PYTHON_CONTROLS = ('test_min5_exact_tail_keeps_complete_outcomes_and_both_storage_modes',
 'test_min5_sealed_end_source_tiling_and_all_tail_routes_are_exact',
 'test_min5_full_manifest_retained_tail_upstream_and_straddlers_cannot_disappear',
 'test_min5_refused_seals_keep_every_member_and_never_grant_local_acceptance')

COMMANDS = list(ledger.COMMANDS)
for row in (
    ('min5-core', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                   'quiescent::artifact_window::min5_tests::'], 180),
    ('min5-frontend', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib',
                       'grouped_artifact_frontend::min5_tests::'], 180),
    ('min5-cli', ['cargo', 'test', '-p', 'liteinst-rewrite', '--example',
                  'disassembly_sites', 'grouped_min5_tests::'], 180),
    ('min5-router-native', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                            'entry_router::imp::routed_jmp_native_tests::'], 180),
    ('min5-linkage-python', ['/usr/bin/python3.9', '-I', '-B',
                             'evaluation/direct-program/test_grouped_min5_linkage.py', '-v'], 180),
):
    COMMANDS.insert(-2, row)


def validate_result(name, raw):
    ledger.validate_result(name, raw)
    if name in CONTROLS:
        cases = CONTROLS[name][1]
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(str(len(cases)).encode(), b'0', b'0')], 'exact min5 control population must run'
    for control, (prefix, cases) in CONTROLS.items():
        if name in (control, 'workspace'):
            for case in cases:
                assert raw.splitlines().count(('test ' + prefix + case + ' ... ok').encode()) == 1, 'min5 control missing: ' + case
    if name == 'min5-linkage-python':
        assert re.findall(rb'^Ran (\d+) tests in ', raw, re.M) == [b'4'] and raw.rstrip().endswith(b'OK')
        for case in PYTHON_CONTROLS:
            assert raw.splitlines().count((case + ' (__main__.GroupedMin5Linkage) ... ok').encode()) == 1, 'min5 Python control missing: ' + case


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv.count('--focused') <= 1
    focused = '--focused' in sys.argv
    if focused:
        sys.argv.remove('--focused')
    grouped = ledger.upstream.program.grouped
    # Previous 60 plus emission/observer 9, native-stack 4, old router 34,
    # and min5 core 7/frontend 5/CLI 3/router 2/Python 4: 128 controls.
    focused_names = ('fmt', *grouped.window.CONTROLS, 'native-stack', *grouped.CONTROLS,
                     'grouped-cli', 'grouped-linkage-python', *ledger.upstream.CONTROLS,
                     'upstream-linkage-python', *ledger.CONTROLS, 'ledger-storage-python',
                     *CONTROLS, 'min5-linkage-python')
    selected = [row for row in COMMANDS if row[0] in focused_names] if focused else COMMANDS
    raise SystemExit(grouped.window.stack.cuts.clock.shared.main(
        commands=selected,
        profile='minimum-window-focused-180-v1' if focused else 'minimum-window-correctness-1800-360-v1',
        scope='Focused 128 inherited/min5 controls only; not full workspace validation.' if focused else
              'Required correctness and every prior compact-ledger control plus exact minimum-window '
              'core/frontend/CLI/linkage and finite production-router native controls. No actual-program '
              'corpus, runtime exemption, performance or strict A4 qualification.',
        log_namespace='minimum-window', validate_result=validate_result))
