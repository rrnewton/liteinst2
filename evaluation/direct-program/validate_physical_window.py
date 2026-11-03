#!/usr/bin/env python3
"""Per-physical minimum-window controls through the shared alphabet validator."""
import importlib.util
from pathlib import Path
import re
import sys

SOURCE = Path(__file__).with_name('validate_entry_alphabet.py')
spec = importlib.util.spec_from_file_location('physical_window_alphabet_controls', SOURCE)
alphabet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(alphabet)
CONTROLS = {'physical-core': ('quiescent::artifact_window::physical::tests::',
                   ('earlier_physical_head_recovers_short_span_with_actual_alphabet_image_and_all_routes',
                    'refused_call_suffix_is_custodied_and_qualified_once_without_retained_authority',
                    'cap_start_fifteen_byte_dependency_keeps_one_sixty_four_of_sixty_five_run',
                    'owned_schedule_binds_source_policy_population_and_domain_without_borrowed_authority',
                    'reached_row_mismatch_aborts_instead_of_skipping_or_double_counting',
                    'fixed06_same_extent_preserves_complete_existing_plan_and_failure_results',
                    'fresh_overlay_entry_pending_and_image_errors_keep_shared_order_and_atomicity',
                    'immutable_global_guards_and_collector_early_breaks_keep_exact_dependencies')),
 'physical-frontend': ('grouped_artifact_frontend::physical::tests::',
                       ('physical_min5_refused_same_site_keeps_earlier_minimum_and_actual_ordinal',
                        'physical_min5_refused_suffix_immediate_is_still_a_source_dependency',
                        'physical_min5_complete_manifest_rejects_consumed_and_straddling_foreign_members',
                        'physical_min5_serializes_first_sixty_four_rows_without_losing_omitted_prefix_membership',
                        'physical_min5_policy_refusal_has_no_invented_domain_and_atomic_failure_keeps_all_sites',
                        'physical_min5_storage_is_independent_and_carrier_refusal_cannot_promote_a_plan')),
 'physical-cli': ('grouped_physical_tests::',
                  ('physical_cli_keeps_old_selectors_and_exact_storage_arity',
                   'physical_cli_full_population_and_repinned_policy_keep_portable_binding')),
 'physical-router-native': ('entry_router::imp::physical_window_native_tests::',
                            ('physical_min5_every_entry_routes_through_production',
                             'physical_min5_ret_fault_preserves_prior_pop_and_callbacks',
                             'physical_min5_non06_pop_fault_preserves_uncommitted_state'))}
PYTHON_CONTROLS = ('test_physical_full_denominator_atomic_outcomes_and_both_storage_modes',
 'test_physical_repinned_omission_order_end_source_and_actual_step_rejected',
 'test_physical_every_ready_window_membership_routes_and_policy_identity',
 'test_physical_global_refusal_is_exact_and_local_refusal_is_not_final_refusal',
 'test_physical_cap_start_fifteen_bytes_and_omitted_sixty_fifth_head')

COMMANDS = list(alphabet.COMMANDS)
for row in (
    ('physical-core', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                       'quiescent::artifact_window::physical::tests::'], 180),
    ('physical-frontend', ['cargo', 'test', '-p', 'liteinst-rewrite', '--lib',
                           'grouped_artifact_frontend::physical::tests::'], 180),
    ('physical-cli', ['cargo', 'test', '-p', 'liteinst-rewrite', '--example',
                      'disassembly_sites', 'grouped_physical_tests::'], 180),
    ('physical-router-native', ['cargo', 'test', '-p', 'liteinst2', '--lib',
                                'entry_router::imp::physical_window_native_tests::'], 180),
    ('physical-linkage-python', ['/usr/bin/python3.9', '-I', '-B',
                                 'evaluation/direct-program/test_grouped_physical_linkage.py', '-v'], 180),
):
    COMMANDS.insert(-2, row)


def validate_result(name, raw):
    alphabet.validate_result(name, raw)
    if name in CONTROLS:
        cases = CONTROLS[name][1]
        rows = re.findall(rb'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', raw, re.M)
        assert rows == [(str(len(cases)).encode(), b'0', b'0')], 'exact physical-window control population must run'
    for control, (prefix, cases) in CONTROLS.items():
        if name in (control, 'workspace'):
            for case in cases:
                assert raw.splitlines().count(('test ' + prefix + case + ' ... ok').encode()) == 1, 'physical-window control missing: ' + case
    if name == 'physical-linkage-python':
        assert re.findall(rb'^Ran (\d+) tests in ', raw, re.M) == [b'5'] and raw.rstrip().endswith(b'OK')
        for case in PYTHON_CONTROLS:
            assert raw.splitlines().count((case + ' (__main__.GroupedPhysicalLinkage) ... ok').encode()) == 1, 'physical-window Python control missing: ' + case


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.argv.count('--focused') <= 1
    focused = '--focused' in sys.argv
    if focused:
        sys.argv.remove('--focused')
    minimum = alphabet.minimum
    ledger = minimum.ledger
    grouped = ledger.upstream.program.grouped
    # Preserve all 191 prior controls; add 8 core/6 frontend/2 CLI/3 native/5 Python.
    focused_names = ('fmt', *grouped.window.CONTROLS, 'native-stack', *grouped.CONTROLS,
                     'grouped-cli', 'grouped-linkage-python', *ledger.upstream.CONTROLS,
                     'upstream-linkage-python', *ledger.CONTROLS, 'ledger-storage-python',
                     *minimum.CONTROLS, 'min5-linkage-python', *alphabet.CONTROLS,
                     'alphabet-linkage-python', *CONTROLS, 'physical-linkage-python')
    selected = [row for row in COMMANDS if row[0] in focused_names] if focused else COMMANDS
    raise SystemExit(grouped.window.stack.cuts.clock.shared.main(
        commands=selected,
        profile='physical-window-focused-180-v1' if focused else 'physical-window-correctness-1800-360-v1',
        scope='Focused 215 inherited and physical-window controls only; not full workspace validation.' if focused else
              'Required correctness and every prior alphabet control plus per-physical minimum-window '
              'source dependencies, exact frontend/CLI/linkage and finite production-router native controls. '
              'No actual-program corpus, runtime exemption, performance or strict A4 qualification.',
        log_namespace='physical-window', validate_result=validate_result))
