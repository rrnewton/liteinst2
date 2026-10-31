#!/usr/bin/env python3
"""Fixed CallPair input-session campaign; source/native prerequisite remains separate."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import types

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
PROFILE = 'call-pair-session-qualification-v1'
PASS = 'CALL_PAIR_SESSION_FUNCTIONAL_PASS'
SCOPE = 'Functional input-session outcomes only. Native prerequisite is separate; no performance, accuracy, whole-worker state or broader A5 claim.'
RECEIPT_API_SHA = '533cd498dbe43fed871f72e889d064cc27bdd403ee7138e55cd8a139f98ac345'
RECIPE_SHA = '4389493950775ca1c494bf7e28ff8326cbd61d2fbbda0ef53af953a4ff24f659'
NATIVE_LAUNCHER = 'evaluation/ordinary-call-pair-native/launch.py'
NATIVE_LAUNCHER_SHA = '5665c1dd0b98ff0884fd3132ed807b33e814463d226158f532ea4605ea90b7e5'
COUNTS = (0, 1, 182, 2048, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2048, 2048, 2048, 0, 3, 48, 2048)
SETUP = ('tool-cc1', 'tool-collect2', 'tool-as', 'tool-ld', 'module-build', 'module-symbols', 'parent-disassembly', 'child-disassembly', 'application-build', 'application-caller-disassembly', 'application-caller-symbols', 'ordinary-build', 'ordinary-list', 'ordinary-controls', 'sdk-build', 'sdk-list', 'sdk-controls', 'core-build', 'core-list', 'core-controls', 'old-module-python-controls', 'old-leaf-checker-controls', 'old-leaf-runner-controls', 'old-leaf-original-controls', 'old-whole-profile-controls', 'checker-controls', 'runner-controls', 'original-python-controls', 'mount-controls-build', 'mount-controls', 'original-controls-build', 'original-controls', 'original-build', 'original-caller-disassembly', 'original-caller-symbols')
APP_CONTROLS = ('normal::call_pair::tests::exact_cli_preserves_logical_roles_both_address_orders_and_all_bounds', 'normal::call_pair::tests::typed_input_outcomes_remain_nonzero_after_finalization_and_preserve_empty_record', 'normal::call_pair::check::tests::nested_rows_join_real_shape_lifo_payloads_and_independent_generations', 'normal::call_pair::check::tests::full_512_word_journal_event_order_and_both_identity_rows_refuse_corruption', 'normal::call_pair::check::tests::independent_function_budgets_closed_removed_initial_and_stop_between_entries', 'normal::call_pair::check::tests::returned_completion_payload_and_report_bijection_predicates_refuse_coherent_changes', 'normal::call_pair::check::tests::raw_endpoints_keep_zero_maximum_migration_and_regression_without_timing_claim', 'normal::call_pair::check::tests::every_report_generation_and_sample_has_one_complete_join_including_empty_epochs', 'normal::call_pair::check::tests::numeric_rows_have_exact_fields_complete_raw_values_and_bounded_ascii_framing', 'normal::call_pair::check::tests::complete_role_census_preserves_original_call_continuation_and_every_child_ret', 'normal::call_pair::worker::tests::complete_roots_require_both_rows_child_acks_and_all_pair_totals', 'normal::call_pair::worker::tests::packed_guarded_parent_value_keeps_one_real_call_owner_shape')
SDK_CONTROLS = ('frontend_native::module::ordinary::normal_leaf_set::tests::leaf_set_selection_count_order_and_source_are_exact', 'frontend_native::module::ordinary::normal_leaf_set::tests::leaf_set_page_union_refuses_conflicts_gaps_and_third_page', 'frontend_native::module::ordinary::normal_leaf_set::tests::leaf_set_overlay_retains_every_unselected_byte', 'frontend_native::module::ordinary::normal_leaf_set::tests::leaf_set_last_selection_refuses_before_loader', 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_roles_and_policies_cover_all_members', 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_budget_refuses_aggregate_overflow', 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_identity_and_complete_union_are_required', 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_control_lookup_keeps_exact_function', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_profile_requires_exact_count_k_history_and_mode', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_banks_prepare_once_and_preserve_refused_identity', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_runtime_keeps_saved_function_and_closed_receipt', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_transfer_validates_every_row_and_journal_word', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_transfer_refusals_leave_receipt_and_cursors_unchanged', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_output_captures_complete_identity_before_consumption', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_reclaim_preserves_shared_owners_and_fresh_generation', 'frontend_native::always_on::normal::leaf_set::tests::leaf_set_handles_refuse_all_old_profiles', 'frontend_native::always_on::normal::leaf_set::history::tests::leaf_set_history_full_identity_and_replay_are_exact', 'frontend_native::always_on::normal::leaf_set::history::tests::leaf_set_history_streams_do_not_retain_epochs', 'frontend_native::module::ordinary::call_pair::tests::parent_dataflow_accepts_distinct_frames_and_preserves_roles', 'frontend_native::module::ordinary::call_pair::tests::parent_rejects_edges_and_incomplete_geometry', 'frontend_native::module::ordinary::call_pair::tests::parent_rejects_wrong_arguments_clobber_and_uninitialized_stack', 'frontend_native::module::ordinary::call_pair::tests::parent_rejects_bad_frame_restoration_prefixes_and_unsupported_ops', 'frontend_native::module::ordinary::call_pair::tests::pair_selection_and_contract_require_independent_disjoint_source', 'frontend_native::module::ordinary::call_pair::tests::pair_overlay_and_page_union_preserve_call_and_untouched_bytes', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_plans_all_roles_with_original_call_and_full_reads', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_sparse_pages_and_reversed_roles_keep_canonical_union', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_refuses_source_identity_roles_and_short_regions', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_exclusion_refuses_displacement_write_and_lock_overlap', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair_budget_refuses_excess_members_without_widening_old_paths', 'frontend_native::always_on::site::ordinary::call_pair::tests::call_pair240_carries_exact_profile_for_every_planned_role', 'frontend_native::always_on::normal::call_pair::tests::profile_and_banks_reject_other_limits', 'frontend_native::always_on::normal::call_pair::tests::actual_receipts_child_ack_then_root_checkpoint', 'frontend_native::always_on::normal::call_pair::tests::ret_observation_is_not_ack_and_rejects_identity', 'frontend_native::always_on::normal::call_pair::tests::stack_envelope_requires_exact_layout_and_ranges', 'frontend_native::always_on::normal::call_pair::tests::wrong_role_pc_and_control_refuse', 'frontend_native::always_on::normal::call_pair::tests::transfer_checks_all_words_and_capacity_before_consume', 'frontend_native::always_on::normal::call_pair::tests::mixed_generations_keep_own_receipts', 'frontend_native::always_on::normal::call_pair::tests::removed_child_keeps_actual_tree', 'frontend_native::always_on::normal::call_pair::tests::function_closed_report_ready_but_reclaim_shared', 'frontend_native::always_on::normal::call_pair::tests::sampled_parent_blocks_report_until_root', 'frontend_native::always_on::normal::call_pair::tests::full_budget_keeps_global_slots_function_ranks', 'frontend_native::always_on::normal::call_pair::tests::completed_payload_wrong_function_or_children_refuse', 'frontend_native::always_on::normal::call_pair::tests::history_stream_and_batch_identity_are_exact', 'frontend_native::always_on::normal::call_pair::tests::lost_handle_retains_owner_and_sticky_failure', 'frontend_native::always_on::normal::call_pair::tests::order_failures_before_consumption', 'frontend_native::always_on::normal::call_pair::tests::old_profile_exclusions_remain', 'frontend_native::always_on::normal::call_pair::tests::report_global_slots_and_payload_child_counts_are_independent', 'frontend_native::always_on::normal::call_pair::tests::compact_journal_validation_keeps_all_words_at_every_phase')
CORE_CONTROLS = ('trampoline::stack_profile_tests::explicit_legacy_matches_old_constructor_bytes_layout_maps_and_owners', 'trampoline::stack_profile_tests::nonlegacy_profile_refuses_mixed_modes_before_emission', 'trampoline::stack_profile_tests::profile_is_part_of_image_identity_not_a_byte_length_guess', 'trampoline::stack_profile_tests::call_pair240_has_distinct_geometry_and_image_identity', 'trampoline::stack_profile_tests::call_pair240_keeps_the_same_nonlegacy_mixed_mode_refusals', 'frame_trace::tests::call_pair_stack::call_pair240_all_bounded_roles_preserve_enclosing_window', 'frame_trace::tests::call_pair_stack::call_pair240_old144_overlaps_child_and_earlier_caller_excursions', 'frame_trace::tests::call_pair_stack::call_pair240_actual_reserve_recovery_restore_and_profile_mutations_refuse')
OLD_PYTHON = {'evaluation/ordinary-module-session/controls.py': ['test_caller_symbol_filter_keeps_all_matches_failures_and_literal_paths', 'test_actual_stderr_requires_exact_finalized_outcome_and_no_hard_diagnostic', 'test_campaign_actual_producer_identity_and_all_failure_rows', 'test_campaign_closed_functional_failure_continues_but_unknown_custody_stops', 'test_campaign_commands_freeze_exact_argv_before_owner_and_never_refresh', 'test_campaign_exact_ordinary_namespaces_keep_unrelated_two_caller_inventory', 'test_campaign_exact_python_names_and_local_import_refusal', 'test_campaign_fixed_catalog_frames_and_owner_status_join', 'test_campaign_missing_app_identity_stops_and_budget_stop_keeps_unrun', 'test_campaign_native_profiles_census_and_complete_retained_counts', 'test_campaign_storage_reserves_complete_stage_and_never_refreshes_charge', 'test_complete_empty_closed_and_absolute_history_populations', 'test_eof_typed_refusal_and_incomplete_are_distinct', 'test_every_family_missing_duplicate_reorder_and_extra_refuses', 'test_fixed_catalog_has_exact_special_inputs_and_error_classes', 'test_global_slots_function_ranks_closed_budget_and_report_order', 'test_history_starts_at_one_and_preserves_multi_action_chunks', 'test_numeric_framing_actual_stderr_and_caps', 'test_optimization_refuses_before_production_checks', 'test_original_input_refusal_never_accepts_hard_failure', 'test_original_reference_uses_all_values_and_exact_population', 'test_owner_four_cases_keep_full_raw_zero_max_and_unavailable', 'test_owner_identity_phases_reports_raw_and_complete_order_refuse', 'test_scalar_input_fingerprint_and_complete_results_are_independent', 'test_stack_continuation_ack_and_batch_boundaries', 'test_zero_maximum_and_raw_unavailable_are_retained'], 'evaluation/ordinary-leaf-set-session/controls.py': ['test_all_cardinalities_empty_and_complete_populations', 'test_input_grammar_and_four_operation_results_are_independent', 'test_selected_table_and_runtime_geometry_require_complete_exact_identity', 'test_each_wire_family_missing_duplicate_reordered_or_extra_refuses', 'test_history_starts_at_one_and_keeps_multi_action_chunks_and_empty_reports', 'test_global_slots_local_ranks_and_mixed_generation_record', 'test_full_budget_call_sample_boundary_and_function_closed', 'test_three_call_records_checkpoint_without_six_call_batches', 'test_stack_continuation_return_and_acknowledgement_domains', 'test_report_sample_bijection_copy_order_and_payload_observation', 'test_zero_maximum_and_unavailable_precedence_are_lossless', 'test_coverage_and_terminal_conserve_all_rows', 'test_exact_stderr_expected_outcomes_and_hard_failures_remain_distinct', 'test_framing_numeric_caps_and_optimization_refusal'], 'evaluation/ordinary-leaf-set-session/runner_controls.py': ['test_fixed_catalog_and_literal_accepted_bytes', 'test_reference_gate_requires_exact_source_table_and_all_results', 'test_immutable_commands_source_and_first_pins', 'test_complete_closure_pid_stderr_exit_and_scalar_joins', 'test_exact_control_censuses_reject_missing_extra_and_keep_t2', 'test_failures_keep_all_attempts_and_stop_uncertain_custody', 'test_geometry_keeps_symbols_operation_identity_and_continuation', 'test_aggregate_budget_and_public_projection_preserve_all_rows', 'test_producer_plan_and_ready_domains'], 'evaluation/ordinary-leaf-set-session/original_controls.py': ['test_original_all_cardinalities_operations_and_byte_truth', 'test_original_geometry_last_selection_ret_and_identity', 'test_original_framing_numeric_order_and_totals', 'test_original_values_and_same_aggregate_corruption', 'test_original_frames_and_inherited_refusals', 'test_original_local_dependency_and_optimized_refusal'], 'evaluation/ordinary-leaf-set-whole-session/profile_controls.py': ['test_fixed_bindings_and_default_catalog_are_literal', 'test_whole_catalog_keeps_all_24_and_120_bytes_and_counts', 'test_plan_profile_hash_paths_and_policies_before_import', 'test_table_policy_guard_covers_va_order_and_unselected_last', 'test_receipt_identity_precedes_custody_release_and_closed_failure', 'test_bootstrap_deadline_source_locality_and_inventory']}
CHECKER_CONTROLS = ('test_complete_empty_one_and_nested_populations', 'test_exact_profile_function_edge_ret_and_caller_identity', 'test_all_wire_families_order_cardinality_and_canonical_domains', 'test_each_frame_generation_global_slot_and_local_rank', 'test_child_ack_lifo_sequences_and_actual_sampled_children', 'test_report_invocation_slots_and_payload_children_are_independent', 'test_closed_removed_initial_and_history_report_bijections', 'test_zero_maximum_unavailable_and_unexercised_coverage', 'test_typed_refusal_incomplete_and_accepted_prefix_are_distinct', 'test_caps_stderr_completion_and_optimized_import_refuse')
RUNNER_CONTROLS = ('test_fixed_five_qualifications_all_32_cases_and_request_freeze', 'test_exact_source_native_geometry_and_original_receipt_joins', 'test_actual_pid_stream_hash_json_profile_before_custody_release', 'test_closed_failure_continues_unknown_custody_leaves_unrun', 'test_history_pressure_and_deadlines_remain_literal', 'test_exact_control_union_budget_first_pins_and_public_rows')
ORIGINAL_CONTROLS = ('test_parent_original_rows_values_and_same_sum_mutation', 'test_original_complete_elf_edge_caller_and_independent_copies', 'test_original_exact_frames_refusals_and_empty_population', 'test_original_caps_identity_domains_and_local_optimized_refusal')
REQUIRED_NATIVE = ('evaluation/admission/processes.py', 'evaluation/ordinary-call-pair-native/README.md', 'evaluation/ordinary-call-pair-native/call_pair_native.py', 'evaluation/ordinary-call-pair-native/controls.py', 'evaluation/ordinary-call-pair-native/reproduce.py', 'evaluation/ordinary-call-pair-native/runner_controls.py', 'evaluation/ordinary-csv/reproduce.py', 'evaluation/ordinary-leaf-set-native/controls.py', 'evaluation/ordinary-leaf-set-native/leaf_set_native.py', 'evaluation/ordinary-leaf-set-native/reproduce.py', 'evaluation/ordinary-leaf-set-native/runner_controls.py', 'evaluation/ordinary-leaf-set-session/reproduce.py', 'evaluation/ordinary-module-native/controls.py', 'evaluation/ordinary-module-native/module_native.py', 'evaluation/ordinary-module-native/reproduce.py', 'evaluation/ordinary-module-session/controls.py', 'evaluation/ordinary-module-session/corpus.py', 'evaluation/ordinary-module-session/output.py', 'evaluation/ordinary-module-session/produce.py', 'evaluation/ordinary-module-session/reproduce.py', 'evaluation/ordinary-module/reproduce.py', 'evaluation/ordinary-rust-invoke-native/caller.py', 'evaluation/ordinary-rust-invoke-native/controls.py', 'evaluation/ordinary-rust-invoke-native/reproduce.py', 'evaluation/ordinary-rust-invoke-native/runner_controls.py', 'evaluation/ordinary-rust-invoke-native/rust_invoke.py', 'tests/call_tree_truth.rs', 'tests/support/native_call_pair.rs', 'tests/support/native_call_pair/parent.rs', 'tests/support/native_call_pair/phase.rs', 'tests/support/native_call_pair/tests.rs', 'tests/support/native_call_pair/trace.rs', 'tests/support/native_copied_capture.rs', 'tests/support/native_copied_rust.rs', 'tests/support/native_copied_rust/effects.rs', 'tests/support/native_normal_caller.rs', 'tests/support/native_normal_module.rs', 'tools/rapid-profiler/native-interval/normal/rust_invoke_artifact.rs', 'tools/rapid-profiler/normal-work/call_pair.c', 'tools/rapid-profiler/normal-work/csv_fields.c', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/caller.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/check.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/check/tests.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/held.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/lifecycle.rs', 'tools/rapid-profiler/selected-work/check_output.py', 'tools/rapid-profiler/strnlen-work/localize.map', 'tools/rapid-profiler/verify_normal_session.py', 'tools/unwind-oracle/bounded_command.py', 'tests/support/native_call_pair/witness.rs', 'tests/support/native_call_pair/trace_join.rs', 'tests/support/native_call_pair/trace_join/tests.rs', 'tools/rapid-profiler/ordinary-interval/normal/call_pair_state/witness.rs')
HELPER_PINS = {'evaluation/ordinary-module-session/reproduce.py': {'bytes': 57511, 'sha256': '4389493950775ca1c494bf7e28ff8326cbd61d2fbbda0ef53af953a4ff24f659'}, 'evaluation/ordinary-module-native/reproduce.py': {'bytes': 44878, 'sha256': '5cce60e76d7ec2011c8facb0a5c1101e0100e13aac8ed9b6317846de35fd3146'}, 'evaluation/ordinary-call-pair-native/reproduce.py': {'bytes': 45011, 'sha256': '540f43ef7c29fc2f260ed9cc25ca0c6c749d4ee0714e5705cf25938af4401ea6'}, 'evaluation/ordinary-csv/reproduce.py': {'bytes': 13439, 'sha256': 'ae70dac850876452d1f09a8480d4381a5814846e1a7e394a33f620bb00699cf3'}, 'evaluation/ordinary-module/reproduce.py': {'bytes': 17353, 'sha256': '60a73415980261fa1f1176f58423da8c77bf6775c2033def4f7469c74677c84c'}, 'evaluation/ordinary-rust-invoke-native/caller.py': {'bytes': 3565, 'sha256': 'aa2d28441c9b477e5e85fea0a61b160cb5026c55bbc129c2b40502c3a5d12d4c'}, 'evaluation/ordinary-call-pair-native/call_pair_native.py': {'bytes': 13366, 'sha256': '928933236372eb8ea8333e05b980708644d6196a2df50757262a2e4e7c41ce1c'}, 'tools/rapid-profiler/selected-work/check_output.py': {'bytes': 7232, 'sha256': '5855c42be2b9a42e85b121f9d8b763e51747f842c8cf85e05dc1736a4f10e4a9'}, 'evaluation/ordinary-rust-invoke-native/reproduce.py': {'bytes': 23732, 'sha256': '434ffdc1be5107a408767d81e85a77ee1a21878b482b8bcb0951e0ee4c4f38de'}, 'evaluation/ordinary-leaf-set-native/reproduce.py': {'bytes': 38376, 'sha256': 'b0aee80e836f0e78fba601d12cdbdbc86cff21a95bf8c1add71b490a5a7f6349'}, 'evaluation/ordinary-leaf-set-session/reproduce.py': {'bytes': 47290, 'sha256': 'be48a4c172579a93278a08b806f2820912033ac3795a2411706f6350c550a844'}, 'tools/rapid-profiler/reference-work/check_output.py': {'bytes': 17495, 'sha256': 'a5e0683ade47a94913afb53a15123a53b316172d8d9936f3a925b8a2b64b7189'}, 'tools/rapid-profiler/verify_normal_interval.py': {'bytes': 58210, 'sha256': '7a1e480c8fb815bb62165773650a0f8590c5bdc6ba39fc1189c63bceb1e085a7'}, 'tools/rapid-profiler/verify_strnlen_interval.py': {'bytes': 34037, 'sha256': '9a37fa20311984d5ba755458e7858578165e0d7a2df583599a1b2057e50e6126'}}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def pin(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def load(name, path, data):
    # Execute only the complete source buffer already authenticated to exact Git.
    module = types.ModuleType(name); module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def source_inventory(git, recipe, launcher, extra):
    # The actual campaign must retain every source later required by accept_native.
    required = set(REQUIRED_NATIVE) | set(HELPER_PINS) | set(recipe.MODULES.values()) | set(extra.values()) | {
        'evaluation/ordinary-call-pair-session/'+n for n in ('reproduce.py', 'runner_controls.py', 'README.md', 'produce.py',
            'producer_controls.py', 'receipt_controls.py', 'controls.py', 'original.c', 'original_controls.c', 'original_controls.py')}
    required.update(launcher.COMMON + launcher.EXTRA['call-pair-original-native'])
    required.add(NATIVE_LAUNCHER)
    source_dirs = ('evaluation/ordinary-module-session', 'evaluation/ordinary-leaf-set-session', 'evaluation/ordinary-leaf-set-whole-session')
    for directory in source_dirs:
        names = git('ls-files', '-z', '--', directory).decode().rstrip('\0').split('\0')
        required.update(n for n in names if n.endswith(('.py', '.c', '.S', '.md')))
    names = git('ls-files', '-z', '--', 'src', 'crates', 'tests/support', 'tools/rapid-profiler', 'Cargo.toml', 'Cargo.lock',
                'README.md', 'build.rs', '.cargo', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required <= set(names)
    return required, names


def catalog(shared, corpus):
    cases = tuple(shared.case_spec(corpus, i) for i in range(32))
    assert tuple(len(c['records']) for c in cases) == COUNTS and sum(COUNTS) == 10537
    rows = []
    for i, case in enumerate(cases):
        data = corpus.framed(case['records']) if i >= 30 else case['data']
        rows.append(dict(case=i, name=case['name'], outcome=case['outcome'], input_error=case['input_error'],
            accepted=[dict(hex=r.payload.hex(), fields=r.fields) for r in case['records']], data_sha256=pin(data)['sha256']))
    originals = [dict(case=i, status='UNRUN', reason='UN', attempts=0) for i in range(32)]
    installed = [dict(attempt=a, k=k, case=i, status='UNRUN', reason='UN', attempts=0)
                 for a in range(1, 6) for k in (10, 1000) for i in range(32)]
    assert len(installed) == 320
    return cases, rows, originals, installed


def stage_names(malformed):
    assert len(malformed) == 8 and len({n for n, _ in malformed}) == 8
    result = SETUP + tuple('malformed-'+n for n, _ in malformed) + tuple(f'original-{i:02}' for i in range(32)) + tuple(
        f'attempt-{a}-k{k}-case-{i:02}' for a in range(1, 6) for k in (10, 1000) for i in range(32))
    assert len(result) == len(set(result)) == 395
    return result


def selected(inventory, names):
    assert len(inventory) == len(set(inventory)) and len(names) == len(set(names))
    prefixes = tuple(sorted({n.rsplit('::', 1)[0]+'::' for n in names}))
    assert {n for n in inventory if n.startswith(prefixes)} == set(names)
    return tuple(names)


def ordinary_inventory(inventory, leaf, recipe, modules):
    assert len(inventory) == len(set(inventory))
    assert {n for n in inventory if n.startswith('normal::call_pair::')} == set(APP_CONTROLS)
    old = leaf.ordinary_inventory([n for n in inventory if n not in APP_CONTROLS], recipe,
                                 modules['single'], modules['module'])
    assert len(old) == 88 and len(APP_CONTROLS) == 12
    wanted = tuple(old)+APP_CONTROLS
    assert len(wanted) == len(set(wanted)) == 100
    return wanted


def runner_census(stdout, stderr, producer_names):
    assert stdout == b''
    wanted = [(n, 'Controls') for n in sorted(RUNNER_CONTROLS)] + [(n, 'ReceiptControls') for n in sorted(RUNNER_CONTROLS)] + [(n, 'ProducerControls') for n in sorted(producer_names)]
    assert len(wanted) == len(set(wanted)) == 17
    lines = stderr.decode('ascii').splitlines(); assert len(lines) == len(wanted)+5
    for line, (name, cls) in zip(lines, wanted):
        assert re.fullmatch(re.escape(name)+r' \(__main__\.'+cls+r'(?:\.'+re.escape(name)+r')?\) \.\.\. ok', line)
    tail = lines[len(wanted):]
    assert tail[0] == tail[3] == '' and tail[4] == 'OK' and re.fullmatch('-+', tail[1])
    assert re.fullmatch(r'Ran 17 tests in [0-9]+\.[0-9]+s', tail[2])


def mark_started(run, row):
    assert run.safe is True and row['status'] == 'UNRUN' and row['attempts'] == 0
    run.unchanged()
    row.update(status='FAILED', reason='OT', attempts=1)
    run.freeze(run.raw/(row['name']+'-started.json'), row)


def bounded(run, stage, directory, request, *, generated=(), app_files=False):
    mark_started(run, stage)
    try:
        result = run.bounded(stage['name'], directory, request, generated=(*generated, (run.raw/(stage['name']+'-outcome.json'), MIB)), app_files=app_files)
    except BaseException:
        # Run.safe can describe owner cleanup before the complete normal-wait
        # envelope is joined. A partial bounded() return never permits advance.
        run.safe = False
        stage['reason'] = 'CL'
        raise
    return result


def setup_stage(run, rows, name, argv, validate, *, cpu=20, wall=30, cap=MIB, generated=()):
    row = rows[name]; directory = run.raw/(name+'-io')
    request = run.request(directory, argv, cpu, wall, cap)
    run.plan_bounded(name, directory, request)
    code, out, err = bounded(run, row, directory, request, generated=generated)
    assert code == 0
    value = validate(out, err)
    row.update(status='PASS', reason='OK')
    run.freeze(run.raw/(name+'-outcome.json'), row)
    return value


def empty(out, err):
    assert out == err == b''


def no_stderr(out, err):
    assert err == b''
    return out


def write_bytes(run, path, data, cap=MIB, mode=None):
    assert len(data) <= cap
    run.budget.charge(str(path), len(data))
    with path.open('xb') as stream: stream.write(data)
    if mode is not None: path.chmod(mode)
    return run.remember(path, pin(data), cap)


def copy_file(run, recipe, source, target, cap, mode=None):
    original = run.remember(source, cap=cap)
    data = recipe.read(source, cap); assert pin(data) == original
    value = write_bytes(run, target, data, cap, mode)
    assert value == original
    a, b = source.stat(), target.stat()
    assert (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) and b.st_nlink == 1
    if mode is not None: assert stat.S_IMODE(b.st_mode) == mode
    return value


def reference_argv(original, dso, trusted, frame, cpu, geometry):
    parent, child = geometry['parent'], geometry['child']
    return [original, dso, trusted, frame, cpu, parent['elf_va'], parent['length'], child['elf_va'], child['length'],
            parent['call_offset'], parent['continuation_offset'], parent['child_delta'], parent['returns'][0],
            ','.join(map(str, child['returns']))]


def freeze_subjects(run, recipe, modules, cases, cases_public, originals, installed, malformed,
                    binary, candidate, trusted, original, original_dso, geometry):
    profile = modules['profile']; binding = profile.call_pair_binding()
    requests = {}; names = stage_names(malformed)
    # Keep one immutable source/tool/artifact map; no per-case executable copies.
    pins = {path: value['sha256'] for path, value in (run.sources | run.tool_pins | run.retained).items()}
    for i, (reason, data) in enumerate(malformed):
        name = 'malformed-'+reason; frame = run.raw/(name+'.frame')
        write_bytes(run, frame, data)
        argv = reference_argv(original, original_dso, trusted, frame, run.cpus[1], geometry)
        directory = run.raw/(name+'-io'); req = run.request(directory, argv)
        run.plan_bounded(name, directory, req); requests[name] = (directory, req, None)
    for row in originals:
        i = row['case']; name = f'original-{i:02}'; frame = run.raw/(name+'.frame')
        records = tuple((r.payload, r.fields) for r in cases[i]['records'])
        write_bytes(run, frame, modules['original_output'].frame(records))
        reqdir = run.raw/(name+'-io'); req = run.request(reqdir, reference_argv(original, original_dso, trusted, frame, run.cpus[1], geometry))
        run.plan_bounded(name, reqdir, req); requests[name] = (reqdir, req, None)
    parent, child = geometry['parent'], geometry['child']
    for row in installed:
        i, k, attempt = row['case'], row['k'], row['attempt']; name = f'attempt-{attempt}-k{k}-case-{i:02}'
        plan = dict(profile=PROFILE, application_profile=binding.application_profile, producer=binding.producer_path,
            corpus_sha256=binding.corpus_sha256, attempt=attempt, case=i, name=cases[i]['name'], k=k, epochs=520,
            data_sha256=cases_public[i]['data_sha256'], cpus=run.cpus, pins=pins, binary=str(binary),
            candidate=str(candidate), trusted=str(trusted), geometry=dict(parent=parent, child=child), caller=geometry['caller'])
        plan['argv'] = list(map(str, [binary, 'normal-call-pair-session', candidate, trusted, k, 520,
            501, parent['elf_va'], parent['length'], 502, child['elf_va'], child['length']]))
        binding.check_plan(plan)
        path = run.raw/(name+'-plan.json'); plan_pin = run.freeze(path, plan)
        argv = [run.tools['python'], '-B', HERE/'produce.py', '--plan', path, '--plan-sha', plan_pin['sha256'], '--raw', run.raw/(name+'-app')]
        reqdir = run.raw/(name+'-io'); req = run.request(reqdir, argv)
        run.plan_bounded(name, reqdir, req); requests[name] = (reqdir, req, plan)
    assert set(requests) == set(names[35:]) and len(requests) == 360
    run.freeze(run.raw/'subject-requests.json', {n: dict(directory=str(d), request_pin=run.retained[str(d/'request.json')], plan_pin=None if p is None else run.retained[str(run.raw/(n+'-plan.json'))]) for n, (d, q, p) in requests.items()}, cap=32*MIB)
    return requests


def ready_identity(profile, plan, result, stdout):
    # Only the actual READY row is parsed here. No functional checker result or
    # successful transcript is synthesized to authorize a closed failure.
    first, separator, _ = stdout.partition(b'\n')
    assert separator == b'\n'
    profile.call_pair_binding().ready(first, result['child_pid'], plan)
    row = first.decode('ascii').split(',')
    return dict(rows=dict(READY=[dict(pid=profile.uint(row[11]))]))


def compare_reference(checked, original):
    assert original['status'] == 'CALL_PAIR_ORIGINAL_SCALAR_PASS'
    actual = [[r[k] for k in ('id', 'length', 'fnv', 'fields', 'packed')] for r in checked['results']]
    assert actual == original['results']


def subject(run, recipe, stages, row, name, requests, action, *, app_files=False):
    directory, request, plan = requests[name]
    recipe.bounded_ready(run, request, app_files=app_files)
    run.budget.room(recipe.bounded_growth(request, ((run.raw/(name+'-outcome.json'), MIB),), app_files))
    assert row['status'] == 'UNRUN' and row['attempts'] == 0
    try:
        code, out, err = bounded(run, stages[name], directory, request, app_files=app_files)
        row.update(status='FAILED', reason='OT', attempts=1)
        if app_files: run.safe = False
        value = action(code, out, err, plan)
        assert run.safe is True and not run.budget.active
        row.update(status='PASS', reason='OK', checked=value)
        stages[name].update(status='PASS', reason='OK')
    except (AssertionError, ValueError, KeyError, IndexError, UnicodeError, OSError) as error:
        if stages[name]['attempts']:
            row.update(status='FAILED', attempts=1)
        row.update(error=type(error).__name__, reason='ST' if run.safe and not run.budget.active else 'CL')
        stages[name]['reason'] = row['reason']
        if not run.safe or run.budget.active: raise
    run.unchanged()
    run.freeze(run.raw/(name+'-outcome.json'), row)


def campaign(run, recipe, modules, stages, cases, originals, installed, malformed, requests, geometry, original_caller):
    checker, profile, ref = modules['pair_output'], modules['profile'], modules['original_output']
    geometry_pair = dict(parent=geometry['parent'], child=geometry['child'])
    for row, (reason, _) in zip(run.result['controls'], malformed):
        def refused(code, out, err, plan):
            ref.refusal(out, err, code, reason)
            return dict(status='EXPECTED_INPUT_REFUSAL', exit=code)
        subject(run, recipe, stages, row, 'malformed-'+reason, requests, refused)
    for row in originals:
        i = row['case']
        def reference(code, out, err, plan):
            assert code == 0
            checked = ref.check(out, err, records=tuple((r.payload, r.fields) for r in cases[i]['records']),
                geometry=geometry_pair, caller=original_caller, cpu=run.cpus[1])
            return {key: value for key, value in checked.items() if key != 'raw'}
        subject(run, recipe, stages, row, f'original-{i:02}', requests, reference)
    assert all(r['status'] == 'PASS' for r in originals+run.result['controls'])
    for row in installed:
        i, k, attempt = row['case'], row['k'], row['attempt']; name = f'attempt-{attempt}-k{k}-case-{i:02}'
        def application(code, out, err, plan):
            appdir = run.raw/(name+'-app')
            # All APP files are read only after bounded normal closure; retain
            # each first pin before interpreting either result or transcript.
            assert appdir.resolve(strict=True) == appdir and appdir.is_dir()
            assert {p.name for p in appdir.iterdir()} == {'stdout.txt', 'stderr.txt', 'result.json'}
            for part, cap in (('stdout.txt', recipe.CAP), ('stderr.txt', recipe.CAP), ('result.json', MIB)):
                run.remember(appdir/part, cap=cap)
            data = recipe.read(appdir/'result.json', MIB)
            actual = recipe.read(appdir/'stdout.txt', recipe.CAP)
            errors = recipe.read(appdir/'stderr.txt', recipe.CAP)
            result = json.loads(data)
            envelope = ready_identity(profile, plan, result, actual)
            profile.confirm_custody(run, plan, result, code, out, err, actual, errors, envelope)
            checked = profile.call_pair_binding().check(checker, actual, errors, plan, cases[i])
            expected = modules['corpus'].framed(cases[i]['records']) if i >= 30 else cases[i]['data']
            profile.join_pass(plan, result, code, checked, len(expected))
            compare_reference(checked, originals[i]['checked'])
            return dict(status=checked['status'], totals=checked['totals'], coverage=checked['coverage'],
                results_sha256=pin(canonical(checked['results']))['sha256'],
                evidence={part: dict(path=str(appdir/part), **run.retained[str(appdir/part)])
                          for part in ('stdout.txt', 'stderr.txt', 'result.json')})
        subject(run, recipe, stages, row, name, requests, application, app_files=True)


def qualifications(installed):
    assert len(installed) == 320
    result = []
    for attempt in range(1, 6):
        rows = installed[(attempt-1)*64:attempt*64]
        assert [(r['attempt'], r['k'], r['case']) for r in rows] == [(attempt, k, i) for k in (10, 1000) for i in range(32)]
        counts = {s: sum(r['status'] == s for r in rows) for s in ('PASS', 'FAILED', 'UNRUN')}
        assert sum(counts.values()) == 64
        status = 'PASS' if counts['PASS'] == 64 else 'UNRUN' if counts['UNRUN'] == 64 else 'FAILED'
        result.append(dict(attempt=attempt, status=status, **{'pass': counts['PASS'], 'failed': counts['FAILED'], 'unrun': counts['UNRUN']}, required_roots=21074, required_target_rows=42148))
    return result


def projection(result, catalog_sha, names_sha, raw_sha):
    assert result['custody_closed'] is True and result['retention_verified'] is True
    qs = qualifications(result['installed'])
    assert result['qualifications'] == qs and result['overall']['status'] == result['status']
    families = [('S', result['planned_stages']), ('R', result['originals']), ('M', result['controls']),
                ('I', result['installed']), ('Q', qs), ('N', [result['native']]), ('O', [result['overall']])]
    expected = dict(S=395, R=32, M=8, I=320, Q=5, N=1, O=1)
    lines = ['kind,index,status,reason,record_sha256\n']
    for kind, rows in families:
        assert len(rows) == expected[kind]
        for i, row in enumerate(rows, 1 if kind == 'Q' else 0):
            status = row['status']; assert status in ('PASS', 'FAILED', 'UNRUN')
            reason = row.get('reason', 'OK' if status == 'PASS' else 'UN' if status == 'UNRUN' else 'OT')
            assert reason in ('OK','UN','SO','TO','AR','GE','IN','CL','ID','ST','PR','BU','IO','NA','OT')
            line = f'{kind},{i},{status},{reason},{pin(canonical(row))["sha256"]}\n'
            assert len(line) <= 81
            lines.append(line)
    output = ''.join(lines).encode('ascii'); assert len(output) <= 61761 and len(lines) == 763
    refs = result['references']
    summary = dict(version=1, profile=PROFILE, revision=result['revision'], status=result['status'],
        catalog_sha256=catalog_sha, stage_names_sha256=names_sha, outcomes_sha256=pin(output)['sha256'], raw_result_sha256=raw_sha,
        native_receipt_sha256=pin(canonical(refs['native']))['sha256'], sources_sha256=pin(canonical(refs['sources']))['sha256'],
        tools_sha256=pin(canonical(refs['tools']))['sha256'], receipt_api_sha256=RECEIPT_API_SHA,
        counts=expected, accepted_counts=list(COUNTS), qualifications=qs, scope=SCOPE)
    encoded = canonical(summary)
    assert len(encoded) <= 1813 and len(encoded)+len(output) < 80000
    return output, encoded


def main():
    started = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('revision', 'reservation-tag', 'native-receipt-sha256', 'native-protocol-sha256'):
        ap.add_argument('--'+name, required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home', 'native-receipt', 'native-protocol'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', a.revision) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', a.reservation_tag)
    assert all(re.fullmatch('[0-9a-f]{64}', x) for x in (a.native_receipt_sha256, a.native_protocol_sha256))
    assert HERE == ROOT/'evaluation/ordinary-call-pair-session'
    for path in (ROOT, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    for path in (a.native_receipt, a.native_protocol):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.raw.is_relative_to(ROOT/'ignored') and re.fullmatch('[A-Za-z0-9_.-]+', a.raw.name)
    assert not os.path.lexists(a.raw) and not os.path.lexists(ROOT/'target/evaluation'/a.raw.name)
    os.chdir(ROOT)
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc', 'rustdoc')}
    tools.update({n: Path('/usr/bin', n).resolve(strict=True) for n in ('git', 'gcc', 'readelf', 'objdump', 'bash', 'rg', 'du', 'systemd-run', 'true')})
    tools['python'] = Path(sys.executable).resolve(strict=True)
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(ROOT/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
        LITEINST_EVALUATION='1', TMPDIR=str(a.raw/'tmp'))
    def git(*args):
        value = subprocess.check_output([tools['git'], '-C', ROOT, *args], env=env, timeout=15)
        assert len(value) <= 32*MIB
        return value
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(ROOT)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    # Bootstrap source is held and joined to Git before any project import.
    recipe_path = ROOT/'evaluation/ordinary-module-session/reproduce.py'
    held = {}
    for path in (Path(__file__).resolve(), recipe_path, ROOT/NATIVE_LAUNCHER):
        assert not path.is_symlink() and path.is_file() and path.stat().st_size <= MIB
        data = path.read_bytes(); assert data == git('show', a.revision+':'+str(path.relative_to(ROOT)))
        held[str(path.relative_to(ROOT))] = data
    assert pin(held[str(recipe_path.relative_to(ROOT))])['sha256'] == RECIPE_SHA
    assert pin(held[NATIVE_LAUNCHER])['sha256'] == NATIVE_LAUNCHER_SHA
    recipe = load('_call_pair_campaign_owner', recipe_path, held[str(recipe_path.relative_to(ROOT))])
    native_launcher = load('_call_pair_campaign_native_launcher', ROOT/NATIVE_LAUNCHER, held[NATIVE_LAUNCHER])
    extra = dict(leaf='evaluation/ordinary-leaf-set-session/reproduce.py', native_recipe='evaluation/ordinary-call-pair-native/reproduce.py',
        owners='evaluation/ordinary-module-session/owners.py', native_receipt='evaluation/ordinary-call-pair-session/native_receipt.py',
        profile='evaluation/ordinary-call-pair-session/profile.py', pair_output='evaluation/ordinary-call-pair-session/output.py',
        original_output='evaluation/ordinary-call-pair-session/original_output.py')
    required, names = source_inventory(git, recipe, native_launcher, extra)
    sources = {}
    for name in names:
        data = recipe.read(ROOT/name); assert data == git('show', a.revision+':'+name)
        sources[str(ROOT/name)] = pin(data)
        if name in required: held[name] = data
    for name, value in HELPER_PINS.items(): assert sources[str(ROOT/name)] == value
    for name, digest in (('evaluation/admission/processes.py', recipe.OWNER_SHA),
        ('tools/unwind-oracle/bounded_command.py', recipe.BOUNDED_SHA), ('evaluation/ordinary-module-session/corpus.py', recipe.CORPUS_SHA)):
        assert sources[str(ROOT/name)]['sha256'] == digest
    tool_pins = {str(path): pin(recipe.read(path, 512*MIB)) for path in tools.values()}
    modules = {key: load('_campaign_'+key, ROOT/path, held[path]) for key, path in recipe.MODULES.items()}
    modules.update({key: load('_campaign_'+key, ROOT/path, held[path]) for key, path in extra.items()})
    modules['profile'].call_pair_binding().check_sources(ROOT, {p: v['sha256'] for p, v in sources.items()})
    modules['native_recipe'].tool_alias(tools, env)
    a.raw.mkdir(mode=0o700); (a.raw/'tmp').mkdir()
    run = recipe.Run(a, a.raw, tools, env, sources, modules, started, tool_pins)
    run.build_scratch = (a.raw/'tmp',)
    cases, catalog_rows, originals, installed = catalog(modules['producer'], modules['corpus'])
    malformed = recipe.malformed_frames(); names = stage_names(malformed)
    stages = {n: dict(name=n, status='UNRUN', reason='UN', attempts=0) for n in names}
    run.result.update(profile=PROFILE, status='FAILED', originals=originals, installed=installed,
        controls=[dict(name=n, status='UNRUN', reason='UN', attempts=0) for n, _ in malformed],
        prerequisites={}, native=dict(status='UNRUN', reason='UN', attempts=0), planned_stages=list(stages.values()),
        references={n: dict(status='UNRUN', pin=None) for n in ('sources', 'tools', 'native')}, scope=SCOPE)
    catalog_sha = pin(canonical(catalog_rows))['sha256']; names_sha = pin(canonical(names))['sha256']
    def stage(name, argv, validator=no_stderr, **kwargs):
        return setup_stage(run, stages, name, argv, validator, **kwargs)
    try:
        run.unchanged()
        launcher = ROOT/NATIVE_LAUNCHER
        launcher_bytes = recipe.read(launcher, MIB)
        assert pin(launcher_bytes)['sha256'] == NATIVE_LAUNCHER_SHA
        run.remember(launcher, pin(launcher_bytes), MIB)
        source_pin = run.freeze(a.raw/'sources-before.json', sources, cap=16*MIB)
        run.result['references']['sources'] = dict(status='PASS', pin=dict(path=str(a.raw/'sources-before.json'), **source_pin))
        run.freeze(a.raw/'catalog.json', catalog_rows, cap=4*MIB)
        run.freeze(a.raw/'stage-names.json', names)
        run.freeze(a.raw/'initial-plan.json', dict(profile=PROFILE, revision=a.revision, attempts=5, retries=0,
            references=32, malformed=8, installed=320, owned_stages=395, k_order=[10,1000], case_order=list(range(32)),
            original_rows=originals, installed_rows=installed, malformed_rows=run.result['controls'], stage_rows=list(stages.values()),
            accepted_counts=COUNTS, catalog_sha256=catalog_sha, stage_names_sha256=names_sha, cpus=run.cpus,
            reservation_tag=a.reservation_tag, reservation_authority='external hard owner only',
            epochs=520, resident_banks=3, arm_ns=2000000, period_ns=10000000, shutdown_ns=2000000000,
            outer_seconds=7200, outer_log_bytes=8*MIB, producer_seconds=15, cpu_seconds=20, wall_seconds=30,
            owner_seconds=55, stream_bytes=recipe.CAP, evidence_bytes=recipe.EVIDENCE_LIMIT, final_allowance=recipe.FINAL_ALLOWANCE,
            build_space_exclusions=[str(a.raw/'tmp')], shared_target=str(ROOT/'target'),
            native_receipt=dict(path=str(a.native_receipt), sha256=a.native_receipt_sha256),
            native_protocol=dict(path=str(a.native_protocol), sha256=a.native_protocol_sha256)))
        for label in ('cc1', 'collect2', 'as', 'ld'):
            def subtool(out, err):
                assert err == b'' and out.endswith(b'\n') and out.count(b'\n') == 1
                name = out[:-1].decode('utf-8')
                path = Path(name) if '/' in name else Path(shutil.which(name, path=env['PATH']) or '')
                assert path.is_absolute(); path = path.resolve(strict=True)
                value = pin(recipe.read(path, 512*MIB))
                if str(path) in run.tool_pins: assert run.tool_pins[str(path)] == value
                else: run.tool_pins[str(path)] = value
            stage('tool-'+label, [tools['gcc'], '-print-prog-name='+label], subtool)
        tools_pin = run.freeze(a.raw/'tools.json', run.tool_pins)
        run.result['references']['tools'] = dict(status='PASS', pin=dict(path=str(a.raw/'tools.json'), **tools_pin))
        native = modules['native']; native_recipe = modules['native_recipe']; leaf = modules['leaf']; census = modules['census']
        trusted, candidate, original_dso = (a.raw/n for n in ('module-trusted.so', 'module-candidate.so', 'module-original.so'))
        stage('module-build', [tools['gcc'], *native.MODULE_FLAGS, ROOT/'tools/rapid-profiler/normal-work/call_pair.c', '-o', trusted], empty, generated=((trusted,MIB),(candidate,MIB),(original_dso,MIB)))
        copy_file(run, recipe, trusted, candidate, MIB); copy_file(run, recipe, trusted, original_dso, MIB)
        assert candidate.stat().st_ino != original_dso.stat().st_ino
        symbols = stage('module-symbols', [tools['readelf'], '--wide', '--syms', trusted])
        parent_bytes = stage('parent-disassembly', [tools['objdump'], '-d', '-M', 'intel', '--insn-width=16', '--disassemble=csv_summary', trusted])
        child_bytes = stage('child-disassembly', [tools['objdump'], '-d', '-M', 'intel', '--insn-width=16', '--disassemble=csv_fields', trusted])
        cargo = ['--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', '--message-format=json-render-diagnostics']
        def artifact(out, err, kind):
            binary, product = native.artifact(out, 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', kind == 'ordinary')
            run.remember(binary); run.freeze(a.raw/(kind+'-artifact.json'), dict(product=product, binary=run.retained[str(binary)]))
            return binary
        application = a.raw/'application'
        binary = stage('application-build', [tools['cargo'], 'build', '--bin', 'ordinary-interval', *cargo],
                       lambda o,e: artifact(o,e,'application'), cpu=120, wall=180, cap=128*MIB, generated=((application,512*MIB),))
        copy_file(run, recipe, binary, application, 512*MIB, 0o700)
        caller_bytes = stage('application-caller-disassembly', [tools['objdump'], '-d', '-M', 'intel', '--insn-width=16', '--disassemble=liteinst_csv_call_and_store', application])
        caller_symbols = stage('application-caller-symbols', recipe.caller_symbol_command(tools, application))
        geometry = modules['native_receipt'].derive_native_geometry(symbols, parent_bytes, child_bytes, caller_bytes, caller_symbols)
        run.freeze(a.raw/'geometry.json', geometry)
        ordinary = stage('ordinary-build', [tools['cargo'], 'test', '--bin', 'ordinary-interval', '--no-run', *cargo],
                         lambda o,e: artifact(o,e,'ordinary'), cpu=120, wall=180, cap=128*MIB)
        inventory = stage('ordinary-list', [ordinary,'--list'], census.census)
        ordinary_names = ordinary_inventory(inventory, leaf, recipe, modules)
        stage('ordinary-controls', [ordinary,*ordinary_names,'--exact','--test-threads=1'], lambda o,e: census.controls(o,e,ordinary_names,inventory))
        def library(out, err, label):
            product_fn = leaf.library_artifact if label == 'sdk' else native_recipe.core_product
            path, product = product_fn(out); assert path.resolve(strict=True) == path
            run.remember(path); run.freeze(a.raw/(label+'-artifact.json'), dict(product=product,binary=run.retained[str(path)]))
            return path
        sdk = stage('sdk-build', [tools['cargo'],'test','--lib','--no-run',*cargo], lambda o,e: library(o,e,'sdk'), cpu=120,wall=180,cap=128*MIB)
        sdk_inventory = stage('sdk-list', [sdk,'--list'], census.census)
        assert len(SDK_CONTROLS) == 48 and tuple(native_recipe.SDK_CONTROLS) == SDK_CONTROLS[18:]
        sdk_names = selected(sdk_inventory, SDK_CONTROLS)
        stage('sdk-controls', [sdk,*sdk_names,'--exact','--test-threads=1'], lambda o,e: census.controls(o,e,sdk_names,sdk_inventory))
        core = stage('core-build', [tools['cargo'],'test','--lib','--no-run','--locked','--offline','--release','--jobs','4','-p','liteinst2','--message-format=json-render-diagnostics'], lambda o,e: library(o,e,'core'),cpu=120,wall=180,cap=128*MIB)
        core_inventory = stage('core-list', [core,'--list'], census.census); core_names = selected(core_inventory, CORE_CONTROLS)
        stage('core-controls', [core,*core_names,'--exact','--test-threads=1'], lambda o,e: census.controls(o,e,core_names,core_inventory))
        old_labels = ('old-module-python-controls','old-leaf-checker-controls','old-leaf-runner-controls','old-leaf-original-controls','old-whole-profile-controls')
        for label, (path, wanted) in zip(old_labels, OLD_PYTHON.items()):
            stage(label, [tools['python'],'-B',ROOT/path,'-v'], lambda o,e,w=tuple(wanted): modules['owners'].reuse_python_controls(o,e,w))
        stage('checker-controls', [tools['python'],'-B',HERE/'controls.py','-v'], lambda o,e: modules['owners'].reuse_python_controls(o,e,CHECKER_CONTROLS))
        stage('runner-controls', [tools['python'],'-B',HERE/'runner_controls.py','-v'], lambda o,e: runner_census(o,e,modules['profile'].CONTROLS))
        stage('original-python-controls', [tools['python'],'-B',HERE/'original_controls.py','-v'], lambda o,e: modules['owners'].reuse_python_controls(o,e,ORIGINAL_CONTROLS))
        run.freeze(a.raw/'controls.json', dict(ordinary=ordinary_names, sdk=sdk_names, core=core_names, old_python=OLD_PYTHON,
            checker=CHECKER_CONTROLS, runner=RUNNER_CONTROLS, receipt_parent=RUNNER_CONTROLS, producer=modules['profile'].CONTROLS,
            original=ORIGINAL_CONTROLS, mount_c=6, original_c=4))
        flags = ['-O2','-std=c11','-Wall','-Wextra','-Werror']
        for label, source, expected in (
            ('mount', ROOT/'evaluation/ordinary-module-session/original_mount_controls.c', b'ORIGINAL_MOUNT_CONTROLS_PASS controls=6\n'),
            ('original', HERE/'original_controls.c', b'CALL_PAIR_ORIGINAL_CONTROLS_PASS controls=4\n')):
            control = a.raw/(label+'-control-bin')
            stage(label+'-controls-build', [tools['gcc'],*flags,source,'-ldl','-o',control], empty, generated=((control,MIB),))
            def c_control(out, err, expected=expected): assert out == expected and err == b''
            stage(label+'-controls', [control], c_control)
        original = a.raw/'original'
        stage('original-build', [tools['gcc'],*flags,'-fno-stack-protector','-fomit-frame-pointer','-fcf-protection=none','-fno-builtin',
            '-Wl,--build-id=none,-z,now,-z,noexecstack',HERE/'original.c','-ldl','-o',original], empty, generated=((original,MIB),))
        cbytes = stage('original-caller-disassembly', [tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble=liteinst_csv_call_and_store',original])
        csymbols = stage('original-caller-symbols', recipe.caller_symbol_command(tools,original))
        cshape = modules['csv'].caller_geometry(cbytes.decode('ascii')); modules['module'].caller_symbols(csymbols.decode('ascii'),cshape)
        original_caller = dict(extent=cshape['length'],continuation=cshape['continuation_offset'])
        run.freeze(a.raw/'original-geometry.json', original_caller)
        # The explicit protocol digest is independent caller authority. No
        # protocol pin is inferred from the receipt being evaluated.
        protocol_data = recipe.read(a.native_protocol,2*MIB); assert pin(protocol_data)['sha256'] == a.native_protocol_sha256
        protocol_pin = dict(path=str(a.native_protocol), **run.remember(a.native_protocol,pin(protocol_data),2*MIB))
        gate = run.result['native']; gate.update(status='FAILED',reason='NA',attempts=1)
        run.freeze(a.raw/'native-started.json', gate)
        accepted = modules['native_receipt'].accept_native(run,a.native_receipt,a.native_receipt_sha256,expected=dict(
            revision=a.revision,protocol_pin=protocol_pin,source_pins=run.sources,tool_pins=run.tool_pins,
            module_pin=run.retained[str(trusted)],application_pin=run.retained[str(application)],geometry=geometry))
        gate.update(status='PASS',reason='OK',checked=accepted)
        run.result['references']['native'] = dict(status='PASS',pin=accepted['receipt'])
        run.freeze(a.raw/'native-accepted.json', accepted, cap=4*MIB)
        requests = freeze_subjects(run,recipe,modules,cases,catalog_rows,originals,installed,malformed,
            application,candidate,trusted,original,original_dso,geometry)
        campaign(run,recipe,modules,stages,cases,originals,installed,malformed,requests,geometry,original_caller)
        run.unchanged(); run.freeze(a.raw/'sources-after.json',sources,cap=16*MIB)
        assert all(r['status'] == 'PASS' for r in list(stages.values())+originals+installed+run.result['controls']+[gate])
        run.result['status'] = 'PASS'
    except BaseException as error:
        run.result.update(status='FAILED',error=type(error).__name__)
        if run.result['native']['attempts'] and run.result['native']['status'] != 'PASS':
            value = run.retained.get(str(a.native_receipt))
            run.result['references']['native'] = dict(status='FAILED',pin=None if value is None else dict(path=str(a.native_receipt),**value))
    finally:
        run.budget.stopped()
        run.result.update(custody_closed=run.safe,retained=dict(run.retained),tool_pins=dict(run.tool_pins),
            end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),load_after=list(os.getloadavg()),
            evidence_budget=run.budget.summary(),build_space_exclusions=[str(p) for p in run.build_scratch])
        try:
            assert run.safe is True and not run.budget.exceeded
            run.unchanged(); run.result['retention_verified'] = True
        except BaseException as error:
            run.result.update(status='FAILED',final_error=type(error).__name__,retention_verified=False)
        run.result['qualifications'] = qualifications(run.result['installed'])
        run.result['overall'] = dict(profile=PROFILE, revision=a.revision, status=run.result['status'])
        raw = canonical(run.result); assert len(raw) <= 32*MIB
        final_cost = max(4096, ((len(raw)+4095)//4096)*4096)
        assert final_cost <= recipe.FINAL_ALLOWANCE and run.budget.used+final_cost <= recipe.EVIDENCE_LIMIT
        with (a.raw/'result.json').open('xb') as stream: stream.write(raw)
        if run.result['custody_closed'] and run.result['retention_verified']:
            outputs, summary = projection(run.result,catalog_sha,names_sha,pin(raw)['sha256'])
            for name,data in (('outcomes.csv',outputs),('summary.json',summary)):
                final_cost += max(4096, ((len(data)+4095)//4096)*4096)
                assert final_cost <= recipe.FINAL_ALLOWANCE and run.budget.used+final_cost <= recipe.EVIDENCE_LIMIT
                with (a.raw/name).open('xb') as stream: stream.write(data)
            print(json.dumps(dict(profile=PROFILE,status=PASS if run.result['status']=='PASS' else 'FAILED',
                summary_sha256=pin(summary)['sha256'],outcomes_sha256=pin(outputs)['sha256']),sort_keys=True))
    return 0 if run.result['status'] == 'PASS' and run.result['retention_verified'] and time.monotonic() < run.deadline else 1


if __name__ == '__main__':
    raise SystemExit(main())
