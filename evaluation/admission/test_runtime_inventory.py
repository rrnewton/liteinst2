"""Source inventory and strict historical projection; no native execution."""

import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

import native_fixtures as fixtures
from parsing import InvalidEvidence, require

UNIT_INCREMENT = 133
PURE_INCREMENT = 117
NATIVE_INCREMENT = 16
RECORDER_INCREMENT = 11
OLD_CORPUS_SHA256 = "82bae1b8166db1ab4ec6de9ed117c1d8478d294cffa7d6d61793a20d53f40d39"
OLD_NATIVE56_SHA256 = "faa3331583cc37593b7562ae294e30ea15c72a4de95337fed9aa9a5d851b71b9"
RUNTIME_ROWS = ({'cohort': 'b3_runtime_startup',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_startup_preserves_real_boundary_state_sources_and_nx'},
 {'cohort': 'b3_runtime_startup',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_owner_refuses_raw_bypass_and_repeated_start'},
 {'cohort': 'b3_runtime_startup',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_expired_original_deadline_keeps_pristine_exec'},
 {'cohort': 'b3_runtime_startup',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_one_short_bootstrap_reservation_keeps_pristine_exec'},
 {'cohort': 'b3_runtime_startup',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_source_window_refusal_retains_completed_bootstrap'},
 {'cohort': 'b3_runtime_startup',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::native_tests::initial_runtime_unwind_retains_native_bootstrap_until_physical_cleanup'},
 {'cohort': 'b3_runtime_ordinary',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_literal_moves_and_add_preserve_exact_checkpoints'},
 {'cohort': 'b3_runtime_ordinary',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_single_step_stops_before_same_page_marker'},
 {'cohort': 'b3_runtime_ordinary',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_conditional_branch_preserves_complete_state'},
 {'cohort': 'b3_runtime_ordinary',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_same_pc_loop_consumes_distinct_origin'},
 {'cohort': 'b3_runtime_ordinary',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::runtime_ordinary_nop_matches_independent_raw_single_step'},
 {'cohort': 'b3_runtime_selected',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_cpu_and_ordinary_keep_exact_control_lineage'},
 {'cohort': 'b3_runtime_selected',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_native_refuses_without_ordinary_fallback'},
 {'cohort': 'b3_runtime_selected',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_selected_syscall_refuses_without_ordinary_fallback'},
 {'cohort': 'b3_runtime_selected',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_ordinary_memory_and_stack_refuse_before_effects'},
 {'cohort': 'b3_runtime_selected',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::runtime_actual_dr7_refuses_before_original_release'})
RUST_METHODS = {'crates/liteinst-launch/src/lifecycle/initial_source_tests.rs': ('initial_source_singleton_keeps_exact_registry_and_candidate',
                                                                  'initial_source_singleton_refuses_foreign_and_numeric_bindings_without_mutation',
                                                                  'initial_source_singleton_rejects_live_model_changes_and_retains_diagnostics'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/ordinary/tests.rs': ('ordinary_fixed_schedule_prepays_six_refreshes_and_full_sixteen_states',
                                                                                              'ordinary_current_borrow_requires_exact_active_register_origin_and_generation',
                                                                                              'ordinary_completed_same_pc_is_distinct_from_unchanged_generic_progress',
                                                                                              'ordinary_history_keeps_every_full_before_step_and_closed_observation',
                                                                                              'ordinary_rejects_foreign_source_execution_origin_encoding_and_deadline_atomically',
                                                                                              'ordinary_final_row_corruptions_cannot_partially_consume_old_origin',
                                                                                              'ordinary_each_actual_chain_row_requires_its_genuine_phase_and_newer_token',
                                                                                              'ordinary_trace_identity_and_all_classification_fields_are_exact',
                                                                                              'ordinary_logical_and_opening_whole_state_must_stay_exact',
                                                                                              'ordinary_reservation_keeps_all_six_existing_limit_gates',
                                                                                              'ordinary_one_byte_short_preparation_and_late_reservation_refuse_atomically',
                                                                                              'ordinary_preallocated_capacity_and_serial_checks_precede_every_mutation',
                                                                                              'ordinary_payload_transfers_preserve_exact_allocations_and_charge_once',
                                                                                              'ordinary_failures_and_finished_reservations_never_refund_prepaid_storage',
                                                                                              'ordinary_duplicate_claim_model_foreign_reservation_and_expiry_never_replay',
                                                                                              'ordinary_candidate_binding_keeps_full_snapshot_identity_and_selected_first',
                                                                                              'ordinary_preparation_prebinds_checked_origin_serial_before_effects'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/runtime.rs': ('initial_runtime_reservation_keeps_all_six_ceilings_and_atomic_refusal',
                                                                                       'initial_runtime_binding_transfers_unused_charge_once_without_refund',
                                                                                       'initial_runtime_binding_rejects_changed_descriptive_identity_without_spending',
                                                                                       'initial_runtime_origin_charge_has_no_fake_exec_epoch_or_witness'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/selected_runtime/tests.rs': ('prepared_selected_commits_exact_full_history_without_post_effect_allocation',
                                                                                                      'selected_successor_corruptions_leave_complete_model_unchanged',
                                                                                                      'selected_before_and_model_corruption_refuse_before_prepaid_storage',
                                                                                                      'selected_one_byte_short_and_origin_or_witness_short_reservations_are_exact',
                                                                                                      'selected_preparation_is_not_replay_or_foreign_census_authority',
                                                                                                      'selected_serial_overflow_refuses_without_retiring_any_original'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/instruction/tests.rs': ('register_and_immediate_encodings_need_no_data_footprint',
                                                                                                  'lea_and_memory_encoded_nop_access_no_data',
                                                                                                  'actual_load_store_and_compare_memory_need_separate_footprints',
                                                                                                  'stack_and_calls_remain_ineligible_even_at_exact_source_page_end',
                                                                                                  'both_register_and_memory_indirect_jumps_require_their_own_proof',
                                                                                                  'relative_self_branch_and_unseen_next_page_are_eligible_descriptions',
                                                                                                  'branch_target_fallthrough_and_current_pc_exclude_private_code',
                                                                                                  'selected_candidate_never_enters_ordinary_transport',
                                                                                                  'unsupported_inc_is_refused_by_the_closed_classifier'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/maps/tests.rs': ('two_fetch_pages_preserve_full_vma_and_exact_split_identity',
                                                                                           'exact_page_ending_does_not_open_the_never_executed_next_page',
                                                                                           'full_one_page_source_does_not_create_a_fictitious_split',
                                                                                           'foreign_or_incomplete_source_geometry_cannot_describe_fetch_permission',
                                                                                           'each_temporary_source_piece_keeps_exact_backing_offsets_paths_and_permissions',
                                                                                           'unrelated_rows_and_extra_or_missing_rows_are_not_permissions_to_mutate',
                                                                                           'closed_permission_requires_the_complete_original_raw_inventory',
                                                                                           'prospective_split_row_ceiling_is_checked_before_any_native_effect'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/native_tests.rs': ('initial_runtime_startup_preserves_real_boundary_state_sources_and_nx',
                                                                                             'initial_runtime_owner_refuses_raw_bypass_and_repeated_start',
                                                                                             'initial_runtime_expired_original_deadline_keeps_pristine_exec',
                                                                                             'initial_runtime_one_short_bootstrap_reservation_keeps_pristine_exec',
                                                                                             'initial_runtime_source_window_refusal_retains_completed_bootstrap',
                                                                                             'initial_runtime_unwind_retains_native_bootstrap_until_physical_cleanup'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/selected/tests.rs': ('six_cpu_results_preserve_full_unrelated_state_and_exact_width',
                                                                                               'selected_semantic_failures_are_not_relabelled',
                                                                                               'valid_getpid_semantics_cannot_enter_cpu_only_transport',
                                                                                               'selected_control_flags_are_checked_without_masking',
                                                                                               'selected_reservation_retains_all_six_dimensions_and_bounded_shape'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/tests.rs': ('initial_runtime_prefix_uses_observed_extent_and_preserves_initialized_storage',
                                                                                      'initial_runtime_prefix_rejects_incomplete_failed_foreign_or_unbounded_progress',
                                                                                      'initial_runtime_prefix_does_not_hide_malformed_observed_suffixes'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_capture/tests.rs': ('initial_capture_bounds_are_fixed_and_partial_has_no_complete_variant',
                                                                                              'initial_capture_large_vma_windows_keep_one_real_mapping_identity',
                                                                                              'initial_capture_scan_closure_includes_last_trailing_head_decode',
                                                                                              'initial_capture_interior_edges_never_become_nonexecutable',
                                                                                              'initial_capture_adjacent_executable_dependencies_refuse_both_directions',
                                                                                              'initial_capture_window_and_overlap_limits_refuse_before_source_reads',
                                                                                              'initial_capture_partial_entries_cannot_admit_selected_sites',
                                                                                              'initial_capture_snapshot_moves_keep_exact_capacity_and_payload_once',
                                                                                              'initial_capture_entry_path_moves_preallocated_storage_without_losing_bytes',
                                                                                              'initial_capture_retained_identity_index_and_full_snapshot_are_exact',
                                                                                              'initial_capture_current_stop_and_complete_state_cannot_rebind',
                                                                                              'initial_capture_every_snapshot_byte_including_dependency_suffix_is_retained',
                                                                                              'initial_capture_failed_prefix_and_unwind_keep_initialized_storage',
                                                                                              'initial_capture_complete_map_status_needs_exact_nonempty_proc_prefix',
                                                                                              'initial_capture_source_charge_is_bytes_only_and_never_refunded'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_instruction/tests.rs': ('runtime_instruction_selected_classes_keep_existing_exact_dispatch',
                                                                                                  'runtime_instruction_alias_errors_never_fall_through_to_ordinary',
                                                                                                  'runtime_instruction_selected_classification_is_not_state_release_permission',
                                                                                                  'runtime_instruction_mov_width_and_high8_rex_boundary_remain_exact',
                                                                                                  'runtime_instruction_memory_and_lea_keep_original_address_operands',
                                                                                                  'runtime_instruction_integer_and_compare_families_retain_flags_input',
                                                                                                  'runtime_instruction_stack_nop_and_near_control_families_are_closed',
                                                                                                  'runtime_instruction_every_near_condition_keeps_literal_relative_target',
                                                                                                  'runtime_instruction_indirect_transfers_do_not_invent_destinations',
                                                                                                  'runtime_instruction_embedded_selected_and_alternate_pc_use_original_bytes',
                                                                                                  'runtime_instruction_candidate_keeps_full_snapshot_and_all_register_fields',
                                                                                                  'runtime_instruction_complete_snapshot_closure_is_required_at_window_edges',
                                                                                                  'runtime_instruction_source_and_relative_address_overflow_refuse',
                                                                                                  'runtime_instruction_ordinary_state_and_writer_profile_is_exact',
                                                                                                  'runtime_instruction_hidden_prefix_and_notrack_hazards_refuse',
                                                                                                  'runtime_instruction_flags_inhibition_and_exception_codes_never_become_ordinary',
                                                                                                  'runtime_instruction_strings_transactions_and_architectural_system_state_refuse',
                                                                                                  'runtime_instruction_unlisted_alternate_ordinary_forms_stay_unsupported'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_native/profile/tests.rs': ('owned_native_lineage_never_accepts_an_unrelated_or_refreshed_checkpoint',
                                                                                                     'owned_native_profile_requires_all_rseq_bytes_exact_count_and_cet_completion'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_native/tests.rs': ('owned_native_capability_accepts_only_nonaccessing_literal_families',
                                                                                             'owned_native_capability_refuses_memory_stack_indirect_and_selected',
                                                                                             'owned_native_state_refuses_tf_rf_mode_and_partial_extent',
                                                                                             'owned_native_trace_requires_actual_identity_code_errno_address_and_dr6',
                                                                                             'owned_native_debug_requires_all_observed_words_and_exact_status',
                                                                                             'owned_native_whole_control_comparison_retains_xstate_mask_and_flags',
                                                                                             'owned_native_checkpoint_requires_real_sequence_and_same_identity',
                                                                                             'owned_native_storage_reserves_all_raw_waits_and_never_grants_empty_completion'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/source_identity/geometry/tests.rs': ('source_inventory_keeps_whole_vma_and_original_executable_neighbors',
                                                                                                       'source_inventory_requires_preallocated_pristine_bounded_row_storage'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/source_identity/initial/tests.rs': ('initial_task_census_requires_one_exact_numeric_member_and_full_records',
                                                                                                      'initial_task_status_preserves_exact_single_tgid_gate',
                                                                                                      'initial_proc_pid_component_uses_fixed_exact_decimal_storage'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/source_identity/read/tests.rs': ('source_prefix_unaligned_words_preserve_exact_requested_bytes',
                                                                                                   'source_prefix_failed_word_retains_prior_bytes_and_exact_errno',
                                                                                                   'source_prefix_late_deadline_keeps_complete_bytes_unqualified',
                                                                                                   'source_maps_full_prefix_requires_actual_zero_bound_read',
                                                                                                   'source_prefix_reuse_refuses_without_replacing_prior_observation',
                                                                                                   'source_prefix_range_rejects_empty_overflow_and_original_limit_excess'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/bootstrap/initial/tests.rs': ('initial_bootstrap_shape_retains_full_paths_and_exact_executable_profile',
                                                                                      'initial_bootstrap_capacity_counts_six_max_states_three_maps_and_descriptors',
                                                                                      'initial_bootstrap_effect_capacity_keeps_every_attempt_and_first_failure',
                                                                                      'initial_bootstrap_progress_never_completes_an_unattempted_or_failed_effect',
                                                                                      'initial_bootstrap_transfer_is_one_shot_and_preserves_failed_data',
                                                                                      'initial_bootstrap_final_inventory_requires_exact_identity_and_only_x_removal',
                                                                                      'initial_bootstrap_range_checks_whole_interval_private_coverage_and_permissions',
                                                                                      'initial_bootstrap_state_copy_preserves_full_payload_without_native_credit'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/ordinary/native_tests.rs': ('runtime_ordinary_literal_moves_and_add_preserve_exact_checkpoints',
                                                                                                      'runtime_ordinary_single_step_stops_before_same_page_marker',
                                                                                                      'runtime_ordinary_conditional_branch_preserves_complete_state',
                                                                                                      'runtime_ordinary_same_pc_loop_consumes_distinct_origin',
                                                                                                      'runtime_ordinary_nop_matches_independent_raw_single_step'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/selected/native/native_tests.rs': ('runtime_selected_cpu_and_ordinary_keep_exact_control_lineage',
                                                                                                             'runtime_selected_native_refuses_without_ordinary_fallback',
                                                                                                             'runtime_selected_syscall_refuses_without_ordinary_fallback',
                                                                                                             'runtime_ordinary_memory_and_stack_refuse_before_effects',
                                                                                                             'runtime_actual_dr7_refuses_before_original_release')}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def before_runtime(declared):
    """Validate the entire exact addition before exposing the old catalog.

    Used only by historical controls. No parser fallback or runtime gate uses
    this projection, and an unknown/missing/relabeled new row is never erased.
    """
    require(type(declared) is dict, "runtime_inventory_differs")
    require(type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 254 + RECORDER_INCREMENT, "runtime_inventory_differs")
    rows = declared.get("native_validation_fixtures")
    require(type(rows) is list and len(rows) == 56 + NATIVE_INCREMENT
            and rows[56:] == list(RUNTIME_ROWS), "runtime_inventory_differs")
    fixtures.catalog(rows)
    require(digest(rows[:56]) == OLD_NATIVE56_SHA256, "runtime_inventory_differs")
    cohorts = declared.get("harness_test_counts")
    require(type(cohorts) is dict and set(cohorts) == {"workspace_tests", "serial_launch"},
            "runtime_inventory_differs")
    for name in ("workspace_tests", "serial_launch"):
        require(type(cohorts[name]) is dict
                and cohorts[name].get(fixtures.UNIT) == {"tests": 355 + UNIT_INCREMENT, "ignored": 0},
                "runtime_inventory_differs")
        require(type(cohorts[name][fixtures.UNIT]["tests"]) is int
                and type(cohorts[name][fixtures.UNIT]["ignored"]) is int, "runtime_inventory_differs")
    result = copy.deepcopy(declared)
    result["recorder_tests"] = 254
    result["native_validation_fixtures"] = result["native_validation_fixtures"][:56]
    for cohort in result["harness_test_counts"].values():
        cohort[fixtures.UNIT] = {"tests": 355, "ignored": 0}
    require(digest(result) == OLD_CORPUS_SHA256, "runtime_inventory_differs")
    return result


class RuntimeInventoryTests(unittest.TestCase):
    def test_exact_source_methods_bind_all_pure_and_three_native_cohorts(self):
        root = Path(__file__).resolve().parents[2]
        native = []
        total = 0
        prefixes = {
            "runtime/native_tests.rs": "linux::remote::dynamic::owner::admission::runtime::native_tests::",
            "runtime/ordinary/native_tests.rs": "linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::",
            "runtime/selected/native/native_tests.rs": "linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::",
        }
        for path, expected in RUST_METHODS.items():
            text = (root / path).read_text()
            names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", text)
            self.assertEqual(names, list(expected), path)
            self.assertEqual(len(names), len(set(names)), path)
            self.assertNotRegex(text, r"#\[ignore(?:\]|\()")
            total += len(names)
            for suffix, prefix in prefixes.items():
                if path.endswith(suffix):
                    native.extend(prefix + name for name in names)
        self.assertEqual(total, UNIT_INCREMENT)
        self.assertEqual(len(native), NATIVE_INCREMENT)
        self.assertEqual(total - len(native), PURE_INCREMENT)
        self.assertEqual(set(native), {row["test"] for row in RUNTIME_ROWS})
        self.assertEqual(fixtures.RUNTIME_ROWS, RUNTIME_ROWS)

    def test_current_catalog_preserves_every_old_row_helper_and_collection_exactly(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        original = copy.deepcopy(declared)
        previous = before_runtime(declared)
        self.assertEqual(declared, original)
        self.assertEqual(digest(previous), OLD_CORPUS_SHA256)
        self.assertEqual(previous["native_validation_fixtures"], declared["native_validation_fixtures"][:56])
        self.assertEqual(declared["backing_cleanup_harnesses"], previous["backing_cleanup_harnesses"])
        for field, count in (("native_cases", 50), ("dynamic_admission_fixtures", 15), ("dynamic_matrix_cases", 388)):
            self.assertEqual(declared[field], previous[field])
            self.assertEqual(len(declared[field]), count)
        for command, harnesses, tests, ignored in (("workspace_tests", 89, 1864, 4), ("serial_launch", 27, 780, 0)):
            actual = declared["harness_test_counts"][command]
            self.assertEqual(len(actual), harnesses)
            self.assertEqual(sum(row["tests"] for row in actual.values()), tests)
            self.assertEqual(sum(row["ignored"] for row in actual.values()), ignored)
            for name, row in previous["harness_test_counts"][command].items():
                if name != fixtures.UNIT:
                    self.assertEqual(actual[name], row)
        self.assertEqual(declared["recorder_tests"], 265)
        self.assertEqual(len(fixtures.catalog(declared["native_validation_fixtures"])), 72)

    def test_projection_refuses_missing_relabelled_unknown_and_changed_history(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        for index in range(16):
            for change in ("missing", "duplicate", "cohort", "harness", "name", "extra"):
                changed = copy.deepcopy(declared)
                rows = changed["native_validation_fixtures"]
                if change == "missing":
                    rows.pop(56 + index)
                elif change == "duplicate":
                    rows.append(copy.deepcopy(rows[56 + index]))
                elif change == "extra":
                    rows[56 + index]["extra"] = "PRIVATE_SENTINEL"
                else:
                    key = {"cohort": "cohort", "harness": "harness", "name": "test"}[change]
                    rows[56 + index][key] = "PRIVATE_SENTINEL"
                with self.subTest(index=index, change=change), self.assertRaises(InvalidEvidence) as caught:
                    before_runtime(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for field in ("recorder", "unit", "old_unit", "ignored", "old_native", "static", "dynamic", "matrix", "helper", "baseline"):
            changed = copy.deepcopy(declared)
            if field == "recorder": changed["recorder_tests"] -= 1
            elif field == "unit": changed["harness_test_counts"]["workspace_tests"][fixtures.UNIT]["tests"] -= 1
            elif field == "old_unit": changed["harness_test_counts"]["serial_launch"]["test/dynamic_fork"]["tests"] -= 1
            elif field == "ignored": changed["harness_test_counts"]["workspace_tests"][fixtures.UNIT]["ignored"] = 1
            elif field == "old_native": changed["native_validation_fixtures"][0]["test"] += "_changed"
            elif field == "static": changed["native_cases"].pop()
            elif field == "dynamic": changed["dynamic_admission_fixtures"].pop()
            elif field == "matrix": changed["dynamic_matrix_cases"].pop()
            elif field == "helper": changed["backing_cleanup_harnesses"]["serial_launch"][0]["trajectories"].pop()
            else: changed["baseline_revision"] = "0" * 40
            with self.subTest(field=field), self.assertRaises(InvalidEvidence):
                before_runtime(changed)
