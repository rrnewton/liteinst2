#!/usr/bin/env python3
"""Five fixed release LeafSet functional qualifications; no retry or native-state claim.

Use a hard three-CPU reservation and external7200-second/8MiB owner. Raw evidence
is private; a reservation tag or affinity alone does not establish the reservation.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
PUBLIC_CAP = 80000
PASS = 'LEAF_SET_FUNCTIONAL_PASS'
SCOPE = ('Release scalar functional qualification with required original references only. '
         'Numeric wire does not grant opaque owner/source/native-state authority. '
         'A complete LeafSet native-state prerequisite and prior copied-Rust admission '
         'remain separate; no timing, pure overhead, arbitrary/nested-module or full-A5 claim.')
RECIPE_SHA = '4389493950775ca1c494bf7e28ff8326cbd61d2fbbda0ef53af953a4ff24f659'
APP_CONTROLS = ('normal::leaf_set::tests::canonical_table_cli_keeps_all_functions_and_refuses_invalid_last', 'normal::leaf_set::tests::operations_match_accepted_encoded_bytes_without_calling_targets', 'normal::leaf_set::tests::typed_completion_and_wire_bounds_keep_all_outcomes', 'normal::leaf_set::tests::accepted_pending_leaf_record_survives_full_queue_and_disconnect', 'normal::leaf_set::worker::tests::command_flush_boundary_is_exact_for_each_cardinality_and_old_default', 'normal::leaf_set::worker::tests::guarded_return_checks_all_operations_and_owner_retention', 'normal::leaf_set::check::tests::ordered_population_n1_through_n4_keeps_global_and_local_coordinates', 'normal::leaf_set::check::tests::population_refuses_full_table_identity_and_each_journal_word', 'normal::leaf_set::check::tests::mixed_history_and_full_budget_keep_one_based_call_and_zero_based_sample', 'normal::leaf_set::check::tests::report_payload_and_wire_refuse_shift_missing_duplicate_and_unavailable_corruption', 'normal::module::session::input::leaf_set_tests::bounded_frame_limit_preserves_extra_byte_eof_and_accepted_snapshot', 'normal::session::worker::leaf_set_tests::actual_drive_flushes_each_three_call_command_before_next')
APP_CONTROLS += (
    'normal::leaf_set::preparation_diagnostic::tests::fixed_site_classes_keep_failure_framing',
    'normal::leaf_set::preparation_diagnostic::tests::fixed_reasons_never_format_dynamic_error_strings',
    'normal::leaf_set::preparation_diagnostic::tests::planning_metadata_uses_only_retained_lengths_and_flags',
    'normal::leaf_set::preparation_diagnostic::tests::maximum_counters_and_overflow_keep_one_bounded_failure_line',
)
# Complete new accuracy modules are required, never ignored by a prefix exception.
ACCURACY_PREFIXES = (
    'normal::leaf_set::accuracy_tests::',
    'normal::leaf_set::selected::accuracy_tests::',
    'normal::leaf_set::counter::tests::',
    'normal::session::io::accuracy_tests::',
)
ACCURACY_CONTROLS = (
    'normal::leaf_set::accuracy_tests::accuracy_ready_binds_actual_period_and_old_headers_remain_literal',
    'normal::leaf_set::accuracy_tests::consumer_refuses_legacy_substitution_wrong_k_epochs_calls_or_transport_options',
    'normal::leaf_set::accuracy_tests::arm_wire_keeps_actual_observations_and_late_completed_arms',
    'normal::leaf_set::selected::accuracy_tests::full_matrix_preserves_every_selected_function_and_full_input_denominator',
    'normal::leaf_set::selected::accuracy_tests::invalid_accuracy_profile_and_selection_refuse_before_table_loading',
    'normal::leaf_set::selected::accuracy_tests::table_refusal_remains_terminal_and_old_parser_does_not_accept_new_k_or_grammar',
    'normal::leaf_set::counter::tests::failed_acquisition_and_close_keep_all_raw_attribute_bytes_and_absences',
    'normal::leaf_set::counter::tests::short_and_failed_reads_preserve_return_errno_length_buffer_and_both_clocks',
    'normal::leaf_set::counter::tests::numeric_extremes_fit_350_without_scaling_id_loss_or_debug_fields',
    'normal::session::io::accuracy_tests::complete_rosters_fit_only_the_explicit_accuracy_output_capacity',
    'normal::session::io::accuracy_tests::both_caps_refuse_one_byte_over_without_discarding_pending_output',
)
APP_CONTROLS += ACCURACY_CONTROLS
PHASE_PREFIXES = ('normal::leaf_set::selected::phase_tests::', 'normal::session::phase::tests::')
PHASE_CONTROLS = (
    'normal::leaf_set::selected::phase_tests::phase_cli_is_explicit_and_mutually_refuses_legacy_grammars',
    'normal::leaf_set::selected::phase_tests::phase_parser_requires_every_nonempty_frozen_input_without_changing_old_table',
    'normal::session::phase::tests::request_is_separate_and_never_changes_the_accuracy_policy',
    'normal::session::phase::tests::origin_first_arm_and_clock_failures_are_terminal',
    'normal::session::phase::tests::zero_and_random_gate_are_once_only_and_keep_whole_period_lateness',
    'normal::session::phase::tests::return_clock_refusal_keeps_release_and_never_invents_timing',
    'normal::session::phase::tests::all_2048_rows_join_exact_identity_without_duplicate_or_missing_credit',
    'normal::session::phase::tests::observations_preserve_actual_thread_errno',
    'normal::session::phase::tests::phase_wire_fits_old_8mib_and_exact_geometry_rejects_every_changed_byte',
)
APP_CONTROLS += PHASE_CONTROLS
# Complete prepared modules and the exact additions within old namespaces.
# PHASE_CONTROLS remains the original nine; none is exempted or replaced.
PREPARED_PREFIXES = (
    'normal::leaf_set::prepared::tests::',
    'normal::module::session::worker::prepared_owner_tests::',
    'normal::session::io::prepared_input_tests::',
    'normal::session::phase::prepared::tests::',
    'normal::session::worker::prepared_tests::',
)
PREPARED_CONTROLS = (
    'normal::leaf_set::check::tests::cancelled_first_keeps_accepted_owner_and_refuses_any_native_or_extra_population',
    'normal::leaf_set::prepared::tests::prepared_setup_uses_one_absolute_deadline_without_input_or_owner_extension',
    'normal::leaf_set::selected::phase_tests::prepared_cli_is_disjoint_and_requires_fixed_j_inside_original_epochs',
    'normal::leaf_set::selected::phase_tests::prepared_cli_retains_complete_2048_nonempty_population_and_original_delay',
    'normal::module::session::worker::prepared_owner_tests::prepared_guard_is_owned_before_call_and_unused_drop_retains_controller_record',
    'normal::module::session::worker::prepared_owner_tests::prepared_guard_refuses_corruption_and_wrong_initial_record',
    'normal::session::io::prepared_input_tests::prepared_pause_does_not_accept_prefetched_rows_or_promise_early_eof',
    'normal::session::phase::prepared::tests::prepared_request_is_fixed_j_no_extra_epoch_and_original_profiles_unchanged',
    'normal::session::phase::prepared::tests::prepared_barrier_precedes_one_origin_and_records_actual_ready_lead',
    'normal::session::phase::prepared::tests::prepared_requires_actual_accepted_arm2_and_keeps_generation_not_epoch_arithmetic',
    'normal::session::phase::prepared::tests::prepared_gate_checks_target_edges_whole_period_misses_end_and_clock_regression',
    'normal::session::phase::prepared::tests::prepared_cancel_never_fabricates_release_return_or_full_population',
    'normal::session::phase::prepared::tests::prepared_real_phase_clock_requires_all2048_and_keeps_shared_monotonicity',
    'normal::session::phase::prepared::tests::prepared_final_admission_refuses_end_after_custody_without_fabricated_timing',
    'normal::session::phase::prepared::tests::prepared_poll_acquires_origin_before_sampling_and_keeps_real_regressions',
    'normal::session::worker::prepared_tests::prepared_queued_stop_wins_before_poll_and_only_idle_checkpoint_detaches',
    'normal::session::worker::prepared_tests::prepared_wait_does_not_block_internal_stop_or_invent_return',
    'normal::session::worker::prepared_tests::prepared_stop_after_release_waits_for_actual_return_and_flush_before_detach',
)
APP_CONTROLS += PREPARED_CONTROLS

SDK_CONTROLS = ('frontend_native::module::ordinary::normal_leaf_set::tests::leaf_set_selection_count_order_and_source_are_exact', 'frontend_native::module::ordinary::normal_leaf_set::tests::leaf_set_page_union_refuses_conflicts_gaps_and_third_page', 'frontend_native::module::ordinary::normal_leaf_set::tests::leaf_set_overlay_retains_every_unselected_byte', 'frontend_native::module::ordinary::normal_leaf_set::tests::leaf_set_last_selection_refuses_before_loader', 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_roles_and_policies_cover_all_members', 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_budget_refuses_aggregate_overflow', 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_identity_and_complete_union_are_required', 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_control_lookup_keeps_exact_function', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_profile_requires_exact_count_k_history_and_mode', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_banks_prepare_once_and_preserve_refused_identity', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_runtime_keeps_saved_function_and_closed_receipt', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_transfer_validates_every_row_and_journal_word', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_transfer_refusals_leave_receipt_and_cursors_unchanged', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_output_captures_complete_identity_before_consumption', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_reclaim_preserves_shared_owners_and_fresh_generation', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_handles_refuse_all_old_profiles', 'frontend_native::always_on::normal::leaf_set::history::tests::leaf_set_history_full_identity_and_replay_are_exact', 'frontend_native::always_on::normal::leaf_set::history::tests::leaf_set_history_streams_do_not_retain_epochs')
# Derive the old broad ownership prefixes from the unchanged eighteen names
# before appending modules whose registration is accuracy_tests, not tests.
SDK_LEGACY_PREFIXES = tuple(sorted({name.split('::tests::')[0] + '::' for name in SDK_CONTROLS}))
SDK_ACCURACY_PREFIXES = (
    'frontend_native::always_on::normal::accuracy::tests::',
    'frontend_native::always_on::normal::leaf_set::accuracy_tests::',
    'frontend_native::backoff::accuracy_tests::',
    'frontend_native::backoff::driver::schedule::accuracy_tests::',
)
SDK_ACCURACY_CONTROLS = (
    'frontend_native::always_on::normal::accuracy::tests::accuracy_attributes_are_exact_current_thread_pinned_non_inherited_instructions',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_open_failure_retains_both_attr_images_and_errno_without_ioctl_or_read',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_each_partial_read_and_error_retains_exact_raw_buffer_and_result',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_id_enable_and_read_identity_failures_never_discard_words',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_pid_or_tid_mismatch_cannot_read_disable_or_close_foreign_owner',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_disable_and_close_failures_are_retained_and_close_is_never_retried',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_drop_has_one_owned_close_even_during_unwind',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_32_real_normal_calls_keep_sampled_unsampled_and_exact_acknowledgments',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_all_pmu_open_failures_preserve_all_normal_work_and_missing_endpoints',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_short_or_error_endpoints_survive_real_normal_checkpoint',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_pre_ret_endpoint_does_not_acknowledge_receipt_and_missing_ret_refuses',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_legacy_export_and_allocation_refusals_cannot_drop_or_ack_sidecars',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_33rd_call_refuses_capacity_without_an_extra_endpoint_or_reset',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_sidecar_key_end_presence_and_owner_drift_refuse_without_consumption',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_facade_checkpoint_and_empty_detach_return_all_counter_custody',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_dropped_or_forgotten_handle_keeps_normal_receipt_and_counter_owner',
    'frontend_native::always_on::normal::accuracy::tests::accuracy_state_owner_drift_refuses_export_without_consumption',
    'frontend_native::always_on::normal::leaf_set::accuracy_tests::accuracy_bindings_require_explicit_policy_exact_config_and_original_limits',
    'frontend_native::always_on::normal::leaf_set::accuracy_tests::old_and_accuracy_banks_cannot_substitute_even_at_identical_k_and_period',
    'frontend_native::always_on::normal::leaf_set::accuracy_tests::matrix_uses_real_k_closure_receipt_acknowledgement_recycled_banks_and_history',
    'frontend_native::backoff::accuracy_tests::accuracy_matrix_is_explicit_and_keeps_finite_and_deadline_bounds',
    'frontend_native::backoff::accuracy_tests::legacy_constructor_is_not_an_accuracy_policy_even_at_identical_numbers',
    'frontend_native::backoff::accuracy_tests::old_driver_boundary_refuses_accuracy_before_any_activation',
    'frontend_native::backoff::driver::schedule::accuracy_tests::matrix_has_exact_original_dues_520_acknowledged_arms_and_exclusive_shutdown',
    'frontend_native::backoff::driver::schedule::accuracy_tests::overlapping_one_ms_windows_keep_original_dues_without_renewing_lateness',
    'frontend_native::backoff::driver::schedule::accuracy_tests::every_period_keeps_two_ms_edges_sticky_failure_and_actual_completed_count',
    'frontend_native::backoff::driver::schedule::accuracy_tests::one_ms_end_and_requested_stop_do_not_get_a_fresh_arm_or_shutdown_budget',
)
SDK_CONTROLS += SDK_ACCURACY_CONTROLS

CHECKER_CONTROLS = ('test_all_cardinalities_empty_and_complete_populations', 'test_input_grammar_and_four_operation_results_are_independent', 'test_selected_table_and_runtime_geometry_require_complete_exact_identity', 'test_each_wire_family_missing_duplicate_reordered_or_extra_refuses', 'test_history_starts_at_one_and_keeps_multi_action_chunks_and_empty_reports', 'test_global_slots_local_ranks_and_mixed_generation_record', 'test_full_budget_call_sample_boundary_and_function_closed', 'test_three_call_records_checkpoint_without_six_call_batches', 'test_stack_continuation_return_and_acknowledgement_domains', 'test_report_sample_bijection_copy_order_and_payload_observation', 'test_zero_maximum_and_unavailable_precedence_are_lossless', 'test_coverage_and_terminal_conserve_all_rows', 'test_exact_stderr_expected_outcomes_and_hard_failures_remain_distinct', 'test_framing_numeric_caps_and_optimization_refusal')
RUNNER_CONTROLS = ('test_fixed_catalog_and_literal_accepted_bytes', 'test_reference_gate_requires_exact_source_table_and_all_results', 'test_immutable_commands_source_and_first_pins', 'test_complete_closure_pid_stderr_exit_and_scalar_joins', 'test_exact_control_censuses_reject_missing_extra_and_keep_t2', 'test_failures_keep_all_attempts_and_stop_uncertain_custody', 'test_geometry_keeps_symbols_operation_identity_and_continuation', 'test_aggregate_budget_and_public_projection_preserve_all_rows', 'test_producer_plan_and_ready_domains')

REFERENCE_CONTROLS = ('test_original_all_cardinalities_operations_and_byte_truth', 'test_original_geometry_last_selection_ret_and_identity', 'test_original_framing_numeric_order_and_totals', 'test_original_values_and_same_aggregate_corruption', 'test_original_frames_and_inherited_refusals', 'test_original_local_dependency_and_optimized_refusal')
PLANNED_STAGES = tuple('tool-'+name for name in ('cc1','collect2','as','ld')) + (
    'module-build','module-symbols','csv_fields-disassembly','leaf_length-disassembly',
    'leaf_ascii_digits-disassembly','leaf_ascii_spaces-disassembly',
    'application-build','application-caller-disassembly','application-caller-symbols',
    'ordinary-build','ordinary-list','ordinary-controls','sdk-build','sdk-list','sdk-controls',
    'old-python-controls','checker-controls','runner-controls','mount-controls-build','mount-controls',
    'original-controls-build','original-controls','original-python-controls',
    'original-build','original-caller-disassembly','original-caller-symbols') + tuple(
    f'original-{i:02}-owner' for i in range(24)) + tuple(
    f'attempt-{attempt}-n{n}-k{k}-{kind}-owner' for attempt in range(1,6)
    for n in range(1,5) for k in (10,1000) for kind in ('empty','budget','syntax'))


def initial_rows(catalog):
    originals = [dict(row, status='UNRUN', attempts=0) for row in catalog.references()]
    installed = [dict(row, status='UNRUN', attempts=0) for row in catalog.catalog()]
    assert len(originals) == 24 and len(installed) == 120
    return originals, installed


def ordinary_inventory(inventory, recipe, single, module):
    assert len(inventory) == len(set(inventory))
    assert len(ACCURACY_CONTROLS) == len(set(ACCURACY_CONTROLS)) == 11
    assert set(n for n in inventory if n.startswith(ACCURACY_PREFIXES)) == set(ACCURACY_CONTROLS)
    assert len(PHASE_CONTROLS) == len(set(PHASE_CONTROLS)) == 9
    assert len(PREPARED_CONTROLS) == len(set(PREPARED_CONTROLS)) == 18
    prepared_phase = tuple(n for n in PREPARED_CONTROLS if n.startswith(PHASE_PREFIXES))
    assert len(prepared_phase) == 2
    assert set(n for n in inventory if n.startswith(PHASE_PREFIXES)) == set(PHASE_CONTROLS + prepared_phase)
    prepared_modules = tuple(n for n in PREPARED_CONTROLS if n.startswith(PREPARED_PREFIXES))
    assert len(prepared_modules) == 15
    assert set(n for n in inventory if n.startswith(PREPARED_PREFIXES)) == set(prepared_modules)
    prefixes = ('normal::leaf_set::', 'normal::module::session::input::leaf_set_tests::',
                'normal::session::worker::leaf_set_tests::') + ACCURACY_PREFIXES + PHASE_PREFIXES + PREPARED_PREFIXES
    assert set(n for n in inventory if n.startswith(prefixes)) == set(APP_CONTROLS)
    prior = recipe.ordinary_inventory([n for n in inventory if n not in APP_CONTROLS],
                                     single, module, recipe.OWNER_CONTROLS)
    assert len(prior) == 52 and len(APP_CONTROLS[:27]) == 27 and len(APP_CONTROLS) == 54
    assert APP_CONTROLS[27:36] == PHASE_CONTROLS and APP_CONTROLS[36:] == PREPARED_CONTROLS
    wanted = tuple(prior) + APP_CONTROLS
    assert len(wanted) == len(set(wanted)) == 106
    return wanted


def sdk_inventory(inventory):
    assert len(inventory) == len(set(inventory))
    assert len(SDK_ACCURACY_CONTROLS) == len(set(SDK_ACCURACY_CONTROLS)) == 27
    assert set(n for n in inventory if n.startswith(SDK_ACCURACY_PREFIXES)) == set(SDK_ACCURACY_CONTROLS)
    prefixes = SDK_LEGACY_PREFIXES + SDK_ACCURACY_PREFIXES
    assert set(name for name in inventory if name.startswith(prefixes)) == set(SDK_CONTROLS)
    assert len(SDK_CONTROLS) == len(set(SDK_CONTROLS)) == 45
    return SDK_CONTROLS


def library_product(data):
    messages = [json.loads(line) for line in data.splitlines()]
    assert messages and messages[-1] == dict(reason='build-finished', success=True)
    products = [m for m in messages if m.get('reason') == 'compiler-artifact'
                and m['target']['name'] == 'rapid_profiler' and m['profile']['test'] is True]
    assert len(products) == 1
    product = products[0]
    assert product['manifest_path'] == str(ROOT/'tools/rapid-profiler/Cargo.toml')
    assert product['target']['src_path'] == str(ROOT/'tools/rapid-profiler/src/lib.rs')
    assert product['target']['kind'] == product['target']['crate_types'] == ['lib']
    assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True,
                                     debug_assertions=True, overflow_checks=True)
    assert type(product['profile']['debuginfo']) is int and type(product['fresh']) is bool
    binary = Path(product['executable'])
    assert binary.is_absolute() and binary.parent == ROOT/'target/release/deps'
    assert re.fullmatch('rapid_profiler-[0-9a-f]+', binary.name)
    return binary, product


def library_artifact(data):
    binary, product = library_product(data)
    assert binary.resolve(strict=True) == binary
    return binary, product


def selected_table(all_leaves, n, catalog, checker):
    assert type(n) is int and 1 <= n <= 4 and len(all_leaves) == 4
    by_operation = {leaf['operation']: leaf for leaf in all_leaves}
    assert len(by_operation) == 4 and set(by_operation) == set(catalog.OPERATIONS)
    chosen = tuple(sorted((dict(by_operation[op], returns=tuple(by_operation[op]['returns']))
                           for op in catalog.OPERATIONS[:n]), key=lambda leaf: leaf['elf_va']))
    checker.geometry(chosen, dict(extent=2, continuation=1), (0, 1))
    expected = dict(zip(catalog.OPERATIONS, zip(catalog.FUNCTION_IDS, catalog.POLICIES)))
    assert all((leaf['function_id'], leaf['policy']) == expected[leaf['operation']] for leaf in chosen)
    pages = {address // 4096 for leaf in chosen
             for address in (leaf['elf_va'], leaf['elf_va'] + leaf['extent'] - 1)}
    assert 1 <= len(pages) <= 2
    return chosen


def result_values(checked, n):
    return [[row['record_id'], row['length'], row['checksum'],
             *[row['value_' + str(i)] for i in range(n)]] for row in checked['rows']['RESULT']]


def reference_join(original, checked, table, records, cpu):
    assert original['status'] == 'ORIGINAL_SCALAR_PASS'
    assert original['results'] == result_values(checked, len(table))
    assert len(original['results']) == len(records)
    # Full original wire/table/domain validation belongs to independently loaded
    # original_output.check; this join cannot substitute a result status alone.
    assert original['ready']['cpu'] == cpu
    assert original['ready']['n'] == len(table) and original['ready']['records'] == len(records)
    assert original['totals'] == dict(records=len(records),calls=len(table)*len(records),returns=len(table)*len(records))
    assert len(original['table']) == len(table)
    for index,(observed,leaf) in enumerate(zip(original['table'],table)):
        assert observed['index'] == index
        assert all(observed[key] == leaf[key] for key in ('function_id','operation','policy','elf_va','extent','returns'))
        assert observed['return_count'] == len(leaf['returns'])


def confirm_producer_custody(run, result, code, out, err, app_out, app_err, checked, case, index, pin):
    """Only the complete actual stream envelope authorizes later child work."""
    assert run.safe is False and run.budget.active is True
    assert type(code) is int and code in (0, 1)
    assert type(result['normal_reaps']) is int and result['normal_reaps'] == 1
    assert result['rescue'] is False and result['cleanup_error'] is None
    assert type(result['child_pid']) is int and result['child_pid'] == checked['rows']['READY'][0]['pid']
    assert type(result['child_exit']) is int and result['child_exit'] in (0, 1)
    assert result['stdout_sha256'] == pin(app_out)['sha256'] and result['stderr_sha256'] == pin(app_err)['sha256']
    assert err == b'' and json.loads(out) == result
    assert type(result['index']) is int and result['index'] == index
    assert result['name'] == case['name']
    assert type(result['n']) is int and result['n'] == case['n']
    assert type(result['k']) is int and result['k'] == case['k']
    # Complete may refuse an exceeded reservation; that must keep safe false.
    run.budget.complete()
    run.safe = True


def confirm_profile_custody(binding, plan, run, result, code, out, err, app_out, app_err, checked, case, index, pin):
    # Profile identity is part of the continuation envelope, before either mutation.
    assert run.safe is False and run.budget.active is True
    binding.check_result(plan, result)
    confirm_producer_custody(run, result, code, out, err, app_out, app_err, checked, case, index, pin)


def producer_join(producer, code, stdout, stderr, checked, case, pin):
    assert producer['normal_reaps'] == 1 and producer['rescue'] is False and producer['cleanup_error'] is None
    assert type(producer['child_pid']) is int and producer['child_pid'] == checked['rows']['READY'][0]['pid']
    assert type(producer['child_exit']) is int and producer['child_exit'] == checked['expected_exit']
    assert producer['stdout_sha256'] == pin(stdout)['sha256'] and producer['stderr_sha256'] == pin(stderr)['sha256']
    assert code == 0 and producer['status'] == 'PASS'
    assert producer['sent_bytes'] == len(case['data'])
    assert producer['name'] == case['name'] and producer['k'] == case['k'] and producer['n'] == case['n']
    assert producer['totals'] == checked['totals'] and producer['done'] == checked['rows']['DONE'][0]
    assert producer['original_values'] == result_values(checked, case['n'])
    assert producer['write_blocked'] == checked['rows']['IO'][0]['write_blocked']


def projection(result):
    keys = ('index', 'attempt', 'n', 'k', 'kind', 'status', 'attempts', 'records', 'calls',
            'sampled', 'unsampled', 'epochs', 'batches', 'child_exit', 'normal_reaps', 'function_closed', 'exhausted_generations')
    originals = [{key: row.get(key) for key in keys} for row in result['originals']]
    installed = [{key: row.get(key) for key in keys} for row in result['installed']]
    assert len(originals) == 24 and len(installed) == 120
    attempts = [dict(attempt=a, **{status.lower(): sum(row['status'] == status for row in installed if row['attempt'] == a)
                                for status in ('PASS', 'FAILED', 'UNRUN')}) for a in range(1, 6)]
    return dict(status=result['status'], revision=result['revision'], originals=originals, installed=installed,
                qualifications=attempts, stages=[dict(name=row['name'],status=row['status']) for row in result['planned_stages']],
                reference_required=True, native_state='UNRUN_SEPARATE_REQUIRED',
                custody_closed=result['custody_closed'], retention_verified=result['retention_verified'],
                evidence_budget=result.get('evidence_budget'), scope=SCOPE)


def write_blob(run, path, data):
    assert type(data) is bytes and len(data) <= MIB
    run.budget.charge(str(path), len(data))
    with path.open('xb') as stream: stream.write(data)
    return run.remember(path)


def copy_dso(run, source, destination):
    data = run.m['native'].read(source, MIB)
    write_blob(run, destination, data)
    assert (source.stat().st_dev, source.stat().st_ino) != (destination.stat().st_dev, destination.stat().st_ino)
    assert run.retained[str(destination)] == run.retained[str(source)]


def execute_once(rows, invoke):
    for row in rows:
        assert row['status'] == 'UNRUN' and row['attempts'] == 0
        invoke(row)

def freeze_campaign(run, recipe, catalog, producer, checker, binary, original, leaves, shape, original_shape, candidate, trusted, original_dso, *, binding=None):
    profile_fields = {} if binding is None else binding.fields()
    producer_entry = HERE/'produce.py' if binding is None else ROOT/binding.producer_path
    plans = run.raw/'plans'; plans.mkdir()
    static = {path: value['sha256'] for path, value in (run.sources | run.tool_pins | run.retained).items()}
    tables = {n: selected_table(leaves, n, catalog, checker) for n in range(1, 5)}
    for row in run.result['originals']:
        case = catalog.case(row['n'], row['k'], row['kind'])
        path = plans/f"original-{row['index']:02}.bin"
        write_blob(run, path, recipe.frame(tuple((payload, checker.truths(payload)['csv_fields']) for payload in case['records'])))
        table = tables[row['n']]
        argv = [original, original_dso, path, run.cpus[1], row['n']]
        for leaf in table:
            argv += [leaf['function_id'], leaf['operation'], leaf['elf_va'], leaf['extent'], leaf['policy'],
                     ','.join(map(str, leaf['returns']))]
        directory = run.raw/f"original-{row['index']:02}"
        row.update(directory=str(directory), request=run.request(directory, argv), table=list(table))
        run.plan_bounded(directory.name+'-owner', directory, row['request'])
    for row in run.result['installed']:
        case = catalog.case(row['n'], row['k'], row['kind'])
        label = f"attempt-{row['attempt']}-{case['name']}"
        table = tables[row['n']]
        argv = [str(binary), 'normal-leaf-set-session', str(candidate), str(trusted), str(row['k']), '520', str(row['n'])]
        for leaf in table:
            argv += [str(leaf['function_id']), leaf['operation'], str(leaf['elf_va']), str(leaf['extent']), leaf['policy']]
        plan = dict(index=row['index'], n=row['n'], k=row['k'], kind=row['kind'], name=case['name'], epochs=520,
                    data_sha256=hashlib.sha256(case['data']).hexdigest(), cpus=run.cpus, table=list(table),
                    caller=shape, binary=str(binary), candidate=str(candidate), trusted=str(trusted), pins=static, argv=argv)
        if binding is not None:
            plan.update(profile_fields)
            binding.check_plan(plan)
        producer.plan_arguments(plan, catalog, checker)
        path = plans/(label+'.json'); digest = run.freeze(path, plan)
        directory, child_raw = run.raw/label, run.raw/(label+'-child')
        request = run.request(directory, [run.tools['python'], '-B', producer_entry, '--plan', path,
                                          '--plan-sha', digest['sha256'], '--raw', child_raw])
        row.update(directory=str(directory), child_raw=str(child_raw), plan=str(path), request=request)
        run.plan_bounded(label+'-owner', directory, request)
    run.freeze(run.raw/'campaign-plan.json', dict(originals=run.result['originals'], installed=run.result['installed'],
        tables=tables, caller=shape, original_caller=original_shape, whole_qualifications=5, reference_children=24,
        installed_children=120, epochs=520, attempts_per_slot=1, retries=0,
        accepted=[dict(**row, records_hex=[p.hex() for p in catalog.case(row['n'],row['k'],row['kind'])['records']])
                  for row in catalog.references()], **profile_fields), cap=16*MIB)
    run.unchanged()
    return tables


def campaign(run, recipe, catalog, checker, producer, original_output, tables, shape, original_shape, *, binding=None):
    references = {}
    def reference(row):
        run.unchanged(); recipe.bounded_ready(run, row['request'])
        row.update(status='FAILED', attempts=1)
        directory = Path(row['directory'])
        code, out, err = run.bounded(directory.name+'-owner', directory, row['request'])
        try:
            assert code == 0
            case = catalog.case(row['n'], row['k'], row['kind'])
            checked = original_output.check(out, err, records=case['records'], table=tables[row['n']],
                                            caller=original_shape, cpu=run.cpus[1])
            assert checked['status'] == 'ORIGINAL_SCALAR_PASS'
            references[row['index']] = checked
            row.update(status='PASS', records=len(case['records']), calls=row['n']*len(case['records']),
                       child_exit=code, normal_reaps=1)
        except (AssertionError, ValueError, KeyError, IndexError, UnicodeError) as error:
            row['error'] = type(error).__name__
        run.unchanged(); run.freeze(run.raw/(directory.name+'-outcome.json'), row)
    execute_once(run.result['originals'], reference)
    assert len(references) == 24 and all(row['status'] == 'PASS' for row in run.result['originals'])
    run.result['reference_complete'] = True
    def installed(row):
        run.unchanged(); recipe.bounded_ready(run, row['request'], app_files=True)
        row.update(status='FAILED', attempts=1)
        directory = Path(row['directory'])
        code, out, err = run.bounded(directory.name+'-owner', directory, row['request'], app_files=True)
        try:
            # Outer closure alone does not identify or normally reap the APP.
            run.safe = False
            child = Path(row['child_raw'])
            for name in ('stdout.txt', 'stderr.txt', 'result.json'): run.remember(child/name, cap=recipe.CAP)
            result = json.loads(recipe.read(child/'result.json', recipe.CAP))
            app_out, app_err = recipe.read(child/'stdout.txt', recipe.CAP), recipe.read(child/'stderr.txt', recipe.CAP)
            plan = json.loads(recipe.read(Path(row['plan']), MIB))
            case, args = producer.plan_arguments(plan, catalog, checker)
            checked = checker.check(app_out, app_err, **args)
            if binding is None:
                confirm_producer_custody(run, result, code, out, err, app_out, app_err, checked, case, row['index'], recipe.pin)
            else:
                confirm_profile_custody(binding, plan, run, result, code, out, err, app_out, app_err, checked, case, row['index'], recipe.pin)
            producer_join(result, code, app_out, app_err, checked, case, recipe.pin)
            assert err == b'' and json.loads(out) == result
            assert result['index'] == row['index']
            reference_join(references[row['index']], checked, tables[row['n']], case['records'], run.cpus[1])
            row.update(**checked['totals'], child_exit=result['child_exit'], normal_reaps=1,
                       function_closed=sum(r['function_closed'] for r in checked['rows']['COVERAGE']),
                       exhausted_generations=sum(r['records'] == row['n']*row['k'] for r in checked['rows']['REPORT']))
            run.unchanged(); row['status'] = 'PASS'
        except BaseException as error:
            row['error'] = type(error).__name__
            if not run.safe: raise
            run.unchanged()
        run.freeze(run.raw/(directory.name+'-outcome.json'), row)
    execute_once(run.result['installed'], installed)


def original_setup(run, recipe, owners):
    tools=run.tools
    flags=['-O2','-std=c11','-Wall','-Wextra','-Werror']
    mount=run.raw/'mount-control-bin'
    out,err=run.stage('mount-controls-build',[tools['gcc'],*flags,ROOT/'evaluation/ordinary-module-session/original_mount_controls.c','-ldl','-o',mount],generated=((mount,MIB),))
    assert out==err==b''
    out,err=run.stage('mount-controls',[mount]);assert out==b'ORIGINAL_MOUNT_CONTROLS_PASS controls=6\n' and err==b''
    controls=run.raw/'original-control-bin'
    out,err=run.stage('original-controls-build',[tools['gcc'],*flags,HERE/'original_controls.c','-ldl','-o',controls],generated=((controls,MIB),))
    assert out==err==b''
    out,err=run.stage('original-controls',[controls]);assert out==b'LEAF_ORIGINAL_CONTROLS_PASS controls=4\n' and err==b''
    out,err=run.stage('original-python-controls',[tools['python'],'-B',HERE/'original_controls.py','-v'])
    owners.reuse_python_controls(out,err,REFERENCE_CONTROLS)
    original=run.raw/'original'
    out,err=run.stage('original-build',[tools['gcc'],*flags,'-fno-stack-protector','-fomit-frame-pointer',
        '-fcf-protection=none','-fno-builtin','-Wl,--build-id=none,-z,now,-z,noexecstack',HERE/'original.c','-ldl','-o',original],generated=((original,MIB),))
    assert out==err==b''
    shape=recipe.caller(run,'original-caller',original)
    return original,dict(extent=shape['length'],continuation=shape['continuation_offset'])


def _main(started, *, binding=None):
    profile_fields = {} if binding is None else binding.fields()
    pass_status = PASS if binding is None else binding.status
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True); ap.add_argument('--reservation-tag', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'): ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', a.reservation_tag)
    assert HERE == ROOT/'evaluation/ordinary-leaf-set-session'
    for path in (ROOT, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.raw.is_relative_to(ROOT/'ignored') and not os.path.lexists(a.raw)
    assert not os.path.lexists(ROOT/'target/evaluation'/a.raw.name)
    os.chdir(ROOT)
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo','rustc','rustdoc')}
    tools.update({n: Path('/usr/bin',n).resolve(strict=True) for n in ('git','gcc','readelf','objdump','bash','rg')})
    tools['python'] = Path(sys.executable).resolve(strict=True)
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(ROOT/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
        LITEINST_EVALUATION='1', TMPDIR=str(a.raw/'tmp'))
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', ROOT, *args], env=env, timeout=15)
        assert len(data) <= 32*MIB
        return data
    assert git('rev-parse','--show-toplevel').decode().strip() == str(ROOT)
    assert git('rev-parse','HEAD').decode().strip() == a.revision
    assert git('status','--porcelain','--untracked-files=no') == b''
    recipe_path = ROOT/'evaluation/ordinary-module-session/reproduce.py'
    for path in (Path(__file__).resolve(), recipe_path):
        assert not path.is_symlink() and path.is_file() and path.stat().st_size <= MIB
        assert path.read_bytes() == git('show', a.revision+':'+str(path.relative_to(ROOT)))
    assert hashlib.sha256(recipe_path.read_bytes()).hexdigest() == RECIPE_SHA
    spec = importlib.util.spec_from_file_location('_leaf_set_existing_recipe', recipe_path)
    assert spec and spec.loader
    recipe = importlib.util.module_from_spec(spec); spec.loader.exec_module(recipe)
    extra = dict(catalog=HERE/'catalog.py', producer=HERE/'produce.py', output=HERE/'output.py',
                 original_output=HERE/'original_output.py', owners=ROOT/'evaluation/ordinary-module-session/owners.py')
    if binding is not None:
        extra['catalog'] = ROOT/binding.catalog_path
    required = set(recipe.MODULES.values()) | {str(path.relative_to(ROOT)) for path in extra.values()} | {
        'evaluation/ordinary-leaf-set-session/reproduce.py', 'evaluation/ordinary-leaf-set-session/runner_controls.py',
        'evaluation/ordinary-leaf-set-session/controls.py', 'evaluation/ordinary-leaf-set-session/original.c',
        'evaluation/ordinary-leaf-set-session/original_controls.c', 'evaluation/ordinary-leaf-set-session/original_controls.py',
        'evaluation/ordinary-module-session/original.c', 'evaluation/ordinary-module-session/original_mount_controls.c',
        'evaluation/ordinary-module-session/controls.py', 'evaluation/ordinary-module-session/reproduce.py',
        'tools/unwind-oracle/bounded_command.py',
        'tests/call_tree_truth.rs', 'tools/rapid-profiler/normal-work/leaf_set.c',
        'tools/rapid-profiler/normal-work/csv_fields.c', 'tools/rapid-profiler/strnlen-work/localize.map'}
    if binding is not None:
        required.update(binding.required_sources())
    names = git('ls-files','-z','--','src','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock',
                'README.md','build.rs',':(glob)**/Cargo.toml',*sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required <= set(names)
    sources = {}
    for name in names:
        data = recipe.read(ROOT/name); assert data == git('show',a.revision+':'+name)
        sources[str(ROOT/name)] = recipe.pin(data)
    for name, expected in (('evaluation/admission/processes.py',recipe.OWNER_SHA),
        ('tools/unwind-oracle/bounded_command.py',recipe.BOUNDED_SHA),('evaluation/ordinary-module-session/corpus.py',recipe.CORPUS_SHA)):
        assert sources[str(ROOT/name)]['sha256'] == expected
    if binding is not None:
        binding.check_sources(ROOT, sources)
    tool_pins = {str(path): recipe.pin(recipe.read(path,512*MIB)) for path in tools.values()}
    assert git('rev-parse','HEAD').decode().strip() == a.revision
    assert git('status','--porcelain','--untracked-files=no') == b''
    modules = {key: recipe.load(key, ROOT/path) for key,path in recipe.MODULES.items()}
    new = {key: recipe.load('leaf_'+key,path) for key,path in extra.items()}
    assert sources[str(HERE/'catalog.py')]['sha256'] == new['producer'].CATALOG
    if binding is not None:
        assert new['catalog'].PROFILE == binding.identity and new['catalog'].POLICIES == binding.policies
    a.raw.mkdir(mode=0o700); (a.raw/'tmp').mkdir()
    run = recipe.Run(a,a.raw,tools,env,sources,modules,started,tool_pins)
    originals, installed = initial_rows(new['catalog'])
    run.result.update(status='FAILED', originals=originals, installed=installed, controls=[], prerequisites={},
        reference_complete=False, native_state='UNRUN_SEPARATE_REQUIRED', scope=SCOPE)
    if binding is not None:
        run.result.update(profile_fields)
    stages = PLANNED_STAGES
    if binding is not None:
        index = stages.index('mount-controls-build')
        stages = stages[:index] + ('whole-profile-controls',) + stages[index:]
    run.result['planned_stages'] = [dict(name=name,status='UNRUN') for name in stages]
    try:
        run.freeze(a.raw/'sources-before.json',sources,cap=16*MIB)
        run.freeze(a.raw/'initial-plan.json',dict(revision=a.revision,originals=originals,installed=installed,stages=stages,
            attempts=5,retries=0,epochs=520,resident_banks=3,outer_seconds=7200,producer_seconds=15,
            cpu_seconds=20,inner_wall_seconds=30,owner_wall_seconds=55,stream_bytes=recipe.CAP,
            cpus=run.cpus,reservation_tag=a.reservation_tag,reservation_authority='external hard owner only',
            scope=SCOPE,evidence_limit=recipe.EVIDENCE_LIMIT,final_allowance=recipe.FINAL_ALLOWANCE,**profile_fields))
        for name in ('cc1','collect2','as','ld'):
            out,err = run.stage('tool-'+name,[tools['gcc'],'-print-prog-name='+name])
            assert err == b'' and out.endswith(b'\n') and out.count(b'\n') == 1
            reported = out[:-1].decode('utf-8')
            path = Path(reported) if '/' in reported else Path(shutil.which(reported,path=env['PATH']) or '')
            assert path.is_absolute(); path=path.resolve(strict=True)
            value = recipe.pin(recipe.read(path,512*MIB))
            if str(path) in run.tool_pins: assert run.tool_pins[str(path)] == value
            else: run.tool_pins[str(path)] = value
        run.freeze(a.raw/'tools.json',run.tool_pins)
        native=modules['native'];trusted=a.raw/'leaf-set-trusted.so';candidate=a.raw/'leaf-set-candidate.so';original_dso=a.raw/'leaf-set-original.so'
        out,err=run.stage('module-build',[tools['gcc'],*native.MODULE_FLAGS,ROOT/'tools/rapid-profiler/normal-work/leaf_set.c','-o',trusted],generated=((trusted,MIB),))
        assert out == err == b''
        copy_dso(run,trusted,candidate);copy_dso(run,trusted,original_dso)
        assert (candidate.stat().st_dev,candidate.stat().st_ino)!=(original_dso.stat().st_dev,original_dso.stat().st_ino)
        symbols,err=run.stage('module-symbols',[tools['readelf'],'--wide','--syms',trusted]);assert err==b''
        leaves=[];body_geometry=[]
        for i,symbol in enumerate(new['catalog'].SYMBOLS):
            policy=new['catalog'].POLICIES[i]
            va,size=native.selection(symbols,symbol,80 if policy=='whole' else 256)
            out,err=run.stage(symbol+'-disassembly',[tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble='+symbol,trusted]);assert err==b''
            body=native.body_geometry(native.geometry(out,symbol,va,size),va,size)
            body_geometry.append(body)
            leaves.append(dict(function_id=new['catalog'].FUNCTION_IDS[i],operation=new['catalog'].OPERATIONS[i],
                               policy=policy,elf_va=va,extent=size,returns=body['returns']))
        selected_table(leaves,4,new['catalog'],new['output'])
        cargo=['--locked','--offline','--release','--jobs','4','-p','rapid-profiler','--message-format=json-render-diagnostics']
        out,_=run.stage('application-build',[tools['cargo'],'build','--bin','ordinary-interval',*cargo],120,180,128*MIB)
        binary,product=native.artifact(out,'ordinary-interval','ordinary-interval/main.rs','bin',False)
        run.remember(binary);run.freeze(a.raw/'application-artifact.json',dict(product=product,binary=run.retained[str(binary)]))
        caller=recipe.caller(run,'application-caller',binary)
        shape=dict(extent=caller['length'],continuation=caller['continuation_offset'])
        out,_=run.stage('ordinary-build',[tools['cargo'],'test','--bin','ordinary-interval','--no-run',*cargo],120,180,128*MIB)
        test_binary,product=native.artifact(out,'ordinary-interval','ordinary-interval/main.rs','bin',True)
        run.remember(test_binary);run.freeze(a.raw/'ordinary-artifact.json',dict(product=product,binary=run.retained[str(test_binary)]))
        out,err=run.stage('ordinary-list',[test_binary,'--list']);inventory=modules['census'].census(out,err)
        expected=ordinary_inventory(inventory,recipe,modules['single'],modules['module'])
        out,err=run.stage('ordinary-controls',[test_binary,*expected,'--exact','--test-threads=1'])
        modules['census'].controls(out,err,expected,inventory)
        out,_=run.stage('sdk-build',[tools['cargo'],'test','--lib','--no-run',*cargo],120,180,128*MIB)
        sdk,product=library_artifact(out);run.remember(sdk)
        run.freeze(a.raw/'sdk-artifact.json',dict(product=product,binary=run.retained[str(sdk)]))
        out,err=run.stage('sdk-list',[sdk,'--list']);inventory=modules['census'].census(out,err);expected_sdk=sdk_inventory(inventory)
        out,err=run.stage('sdk-controls',[sdk,*expected_sdk,'--exact','--test-threads=1'])
        modules['census'].controls(out,err,expected_sdk,inventory)
        run.freeze(a.raw/'controls.json',dict(ordinary=list(expected),sdk=list(expected_sdk),old_python=list(recipe.PYTHON_CONTROLS),
            checker=list(CHECKER_CONTROLS),runner=list(RUNNER_CONTROLS),reference=list(REFERENCE_CONTROLS),c_reference_controls=4,c_mount_controls=6))
        out,err=run.stage('old-python-controls',[tools['python'],'-B',ROOT/'evaluation/ordinary-module-session/controls.py','-v']);recipe.python_controls(out,err)
        for label,name,names in (('checker-controls','controls.py',CHECKER_CONTROLS),('runner-controls','runner_controls.py',RUNNER_CONTROLS)):
            out,err=run.stage(label,[tools['python'],'-B',HERE/name,'-v']);new['owners'].reuse_python_controls(out,err,names)
        if binding is not None:
            control_path=(ROOT/binding.catalog_path).with_name('profile_controls.py')
            out,err=run.stage('whole-profile-controls',[tools['python'],'-B',control_path,'-v'])
            new['owners'].reuse_python_controls(out,err,binding.control_names())
            run.freeze(a.raw/'whole-controls.json',dict(profile_fields,controls=list(binding.control_names())))
        original,original_shape = original_setup(run,recipe,new['owners'])
        run.freeze(a.raw/'geometry.json',dict(leaves=leaves,bodies=body_geometry,caller=caller,original_caller=original_shape,
            trusted=run.retained[str(trusted)],candidate=run.retained[str(candidate)],original_dso=run.retained[str(original_dso)]))
        tables=freeze_campaign(run,recipe,new['catalog'],new['producer'],new['output'],binary,original,leaves,shape,original_shape,candidate,trusted,original_dso,binding=binding)
        campaign(run,recipe,new['catalog'],new['output'],new['producer'],new['original_output'],tables,shape,original_shape,binding=binding)
        run.unchanged();run.freeze(a.raw/'sources-after.json',sources,cap=16*MIB)
        assert tuple(row['name'] for row in run.result['stages']) == tuple(stages)
        if all(row['status']=='PASS' for row in originals+installed):run.result['status']=pass_status
    except BaseException as error:
        run.result['error']=type(error).__name__
    finally:
        run.budget.stopped()
        run.result.update(custody_closed=run.safe,retained=dict(run.retained),tool_pins=dict(run.tool_pins),
            end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),load_after=list(os.getloadavg()),
            evidence_budget=run.budget.summary(),build_space_exclusions=[str(path) for path in run.build_scratch])
        seen={row['name']:row for row in run.result['stages']}
        run.result['planned_stages']=[seen.get(name,dict(name=name,status='UNRUN')) for name in stages]
        try:
            assert run.safe and not run.budget.exceeded and run.budget.used<=recipe.EVIDENCE_LIMIT-recipe.FINAL_ALLOWANCE
            run.unchanged();run.result['retention_verified']=True
        except BaseException as error:
            run.result.update(status='FAILED',final_error=type(error).__name__)
        public=projection(run.result)
        if binding is not None:
            public.update(profile_fields)
        recipe.save(a.raw/'result.json',run.result,32*MIB)
        recipe.save(a.raw/'summary.json',public,PUBLIC_CAP)
        print(json.dumps({key:value for key,value in public.items() if key not in ('originals','installed','stages')},sort_keys=True))
    return 0 if run.result['status']==pass_status and time.monotonic()<run.deadline else 1


def main():
    started = time.monotonic()
    return _main(started)


if __name__ == '__main__':
    raise SystemExit(main())
