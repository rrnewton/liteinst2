"""Strict historical projection for the finite opt-in owned-stack addition.

Recorder regressions only: no native execution, permission or cleanup proof.
Every new and historical corpus field is authenticated before peeling.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

import native_fixtures as fixtures
from parsing import require

PRE_OWNED_STACK_CORPUS_SHA256 = '9339fdbaf687b1b77ebf549c887e61e1b6e78df7e224c764f64f3fecf0a0f791'
OLD_NATIVE86_SHA256 = '0da8ac8f1fca083116742d908213ba7f7770f3eec2043d53e65c34f35811ee0b'
OLD_PYTHON302_SHA256 = 'ef88eda4e26b581167c865bf32550ffa93bdcb15d755145795fa4650a005ac4b'
NATIVE_ROOT = 'linux::remote::dynamic::owner::admission::runtime::stack::native_tests'
NATIVE_NAMES = ('runtime_stack_call_ret_matches_raw_full_state_and_stack',
 'runtime_stack_boundary_call_ret_keeps_unexecuted_next_page_nx',
 'runtime_stack_crossing_call_opens_exact_two_pages',
 'runtime_stack_unaligned_two_page_word_preserves_neighbors',
 'runtime_stack_kernel_selected_ordinary_chain_preserves_call_history',
 'runtime_stack_default_encodings_targets_and_slot_refuse_before_release',
 'runtime_stack_metadata_changes_refuse_with_actual_records',
 'runtime_stack_nonresident_word_refuses_before_peek',
 'runtime_stack_nonexclusive_word_refuses_with_two_owned_pins',
 'runtime_stack_after_a_ac_refuses_before_private_effects',
 'runtime_stack_after_a_pkru_refuses_before_private_effects',
 'runtime_stack_after_b_ac_retains_actual_alignment_fault',
 'runtime_stack_after_b_pkru_retains_actual_access_fault',
 'runtime_stack_late_failure_and_unwind_retain_call_custody',
 'runtime_stack_budget_deadline_and_stale_source_refuse_before_effects',
 'runtime_stack_raw_io_failures_keep_request_prefix_and_cleanup',
 'runtime_stack_installed_allocation_failures_settle_before_cleanup')
ROWS = tuple({"cohort": "b3_owned_stack", "harness": fixtures.UNIT,
              "test": NATIVE_ROOT + "::" + name} for name in NATIVE_NAMES)
RUST_METHODS = {'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_stack/tests/access.rs': ('stack_cpuid_requires_each_actual_record_and_closed_component_layout',
                                                                                                   'stack_xstate_requires_independent_success_and_exact_iovec_extent',
                                                                                                   'stack_pkru_requires_export_presence_uncompacted_header_and_key_zero_rights',
                                                                                                   'stack_native64_access_refuses_ac_tf_rf_vm_and_changed_segments',
                                                                                                   'stack_pagemap_requires_both_resident_exclusive_pages_and_exact_request'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_stack/tests/allocation.rs': ('stack_exact_owners_preserve_capacity_alignment_drop_and_overflow',
                                                                                                       'stack_empty_headers_allocate_exact_three_independent_payloads_without_observations',
                                                                                                       'stack_each_allocation_failure_keeps_installed_prefix_and_first_error',
                                                                                                       'stack_each_installed_allocation_survives_caught_model_unwind',
                                                                                                       'stack_measured_capacity_tally_corruption_is_not_a_reservation_or_refund'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_stack/tests/metadata.rs': ('stack_smaps_matches_complete_inventory_and_retains_raw_path_bytes',
                                                                                                     'stack_smaps_key_and_vmflags_are_positive_closed_unique_facts',
                                                                                                     'stack_identity_uses_complete_original_row_not_stack_name_or_endpoints',
                                                                                                     'stack_file_capture_requires_complete_actual_request_prefix_and_closes'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_stack/tests/validation.rs': ('stack_bootstrap_data_uses_actual_first_user_pkru_and_exact_restore_chain',
                                                                                                       'stack_profile_description_requires_complete_original_stack_and_post_read_state',
                                                                                                       'stack_unstarted_failed_and_aborted_storage_never_yields_descriptions',
                                                                                                       'stack_encoding_and_address_profile_are_closed_with_untouched_return_page_geometry',
                                                                                                       'stack_frozen_word_geometry_preserves_cross_page_envelope_and_rejects_growth',
                                                                                                       'stack_word_requires_exact_real_request_shape_without_rejecting_all_ones_data',
                                                                                                       'stack_operand_description_binds_current_full_state_metadata_word_and_layout',
                                                                                                       'stack_call_effect_preserves_every_register_flag_xstate_mask_and_neighbor',
                                                                                                       'stack_ret_effect_requires_captured_target_and_unchanged_entire_envelope'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_stack_native/acquire/tests.rs': ('stack_native_empty_and_allocated_owners_never_issue_certificates',
                                                                                                           'stack_native_each_wrapper_allocation_error_retains_exact_installed_prefix',
                                                                                                           'stack_native_each_wrapper_unwind_keeps_successful_capacity_without_refund',
                                                                                                           'stack_native_first_failure_survives_later_diagnostics_and_abort',
                                                                                                           'stack_native_buffer_identity_survives_header_move_but_not_copy_or_resize',
                                                                                                           'stack_native_capture_progress_rejects_unallocated_failed_and_repeated_entry'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_stack_native/io/tests.rs': ('stack_native_proc_path_is_exact_bounded_positive_tid',
                                                                                                      'stack_native_pagemap_extent_rebuilds_exact_frozen_one_or_two_pages',
                                                                                                      'stack_native_pagemap_access_requires_both_owned_fds_procfs_and_closes',
                                                                                                      'stack_native_peek_keeps_all_ones_and_failed_second_request_prefix'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_stack_native/tests.rs': ('owned_stack_native_empty_and_fixed_allocation_have_exact_owners',
                                                                                                   'owned_stack_native_allocation_errors_retain_every_installed_prefix',
                                                                                                   'owned_stack_native_allocation_unwinds_retain_exact_prefix_and_payload',
                                                                                                   'owned_stack_native_page_boundary_keeps_fixed_charge_and_original_geometry',
                                                                                                   'owned_stack_native_closed_encoding_gate_rejects_selected_prefixes_and_indirect',
                                                                                                   'owned_stack_native_trace_model_requires_full_raw_identity_and_debug',
                                                                                                   'owned_stack_native_expected_word_changes_only_exact_call_slot',
                                                                                                   'owned_stack_native_first_error_and_unattempted_diagnostics_never_become_success'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/runtime_stack/tests.rs': ('stack_census_prepays_exact_six_refreshes_and_sixteen_state_owners',
                                                                                                   'stack_census_retains_every_partial_allocation_before_error_or_unwind',
                                                                                                   'stack_census_requires_settlement_and_keeps_failed_settlement_atomic',
                                                                                                   'stack_census_ret_commits_exact_chain_and_preserves_prepaid_owners',
                                                                                                   'stack_census_call_boundary_retains_return_without_opening_its_page',
                                                                                                   'stack_census_missing_call_or_return_with_call_refuses_atomically',
                                                                                                   'stack_census_rejects_every_checkpoint_identity_phase_and_order_corruption',
                                                                                                   'stack_census_rejects_full_state_and_raw_trace_corruption',
                                                                                                   'stack_census_requires_each_word_capture_and_its_exact_phase_association',
                                                                                                   'stack_census_rejects_pagemap_descriptor_and_independent_query_corruption',
                                                                                                   'stack_census_rejects_changed_stack_word_neighbor_or_opened_extra_page',
                                                                                                   'stack_census_unproven_orig_rax_deadline_and_capacity_refusals_keep_prefix'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/stack_calls/tests.rs': ('stack_calls_fixed_slots_and_full_record_are_prepaid_once',
                                                                                                 'stack_calls_record_error_and_unwind_keep_allocated_prefix_and_charge',
                                                                                                 'stack_calls_append_moves_exact_owner_before_any_completion',
                                                                                                 'stack_calls_reject_stale_or_foreign_append_without_taking_record',
                                                                                                 'stack_calls_source_identity_keeps_full_window_and_boundary_return',
                                                                                                 'stack_calls_ret_and_expired_history_never_remove_or_refund'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/stack/tests.rs': ('runtime_stack_default_profile_preserves_explicit_refusal',
                                                                                            'runtime_stack_dispatch_requires_exact_unprefixed_call_or_return',
                                                                                            'runtime_stack_reservation_has_exact_axes_and_call_increment',
                                                                                            'runtime_stack_startup_owns_fixed_indices_and_profile_once',
                                                                                            'runtime_stack_root_allocation_errors_settle_every_installed_prefix',
                                                                                            'runtime_stack_root_allocation_unwinds_settle_before_original_rethrow',
                                                                                            'runtime_stack_complete_allocation_preserves_input_and_keeps_temporary_headroom',
                                                                                            'runtime_stack_startup_partial_errors_keep_exact_payload_prefixes',
                                                                                            'runtime_stack_startup_partial_unwinds_keep_exact_payload_prefixes',
                                                                                            'runtime_stack_installed_header_settles_without_claiming_payload_or_permit',
                                                                                            'runtime_stack_header_settlement_failure_retains_original_failure_and_owner',
                                                                                            'runtime_stack_startup_nested_profile_failures_keep_each_real_payload',
                                                                                            'runtime_stack_nested_native_and_word_failures_settle_each_real_prefix',
                                                                                            'runtime_stack_nested_census_and_call_failures_settle_each_real_prefix',
                                                                                            'runtime_stack_closed_fault_configuration_rejects_reuse_and_out_of_bounds'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/stack/native_tests.rs': ('runtime_stack_call_ret_matches_raw_full_state_and_stack',
    'runtime_stack_boundary_call_ret_keeps_unexecuted_next_page_nx',
    'runtime_stack_crossing_call_opens_exact_two_pages',
    'runtime_stack_unaligned_two_page_word_preserves_neighbors',
    'runtime_stack_metadata_changes_refuse_with_actual_records',
    'runtime_stack_nonresident_word_refuses_before_peek',
    'runtime_stack_nonexclusive_word_refuses_with_two_owned_pins',
    'runtime_stack_raw_io_failures_keep_request_prefix_and_cleanup',
    'runtime_stack_after_a_ac_refuses_before_private_effects',
    'runtime_stack_after_a_pkru_refuses_before_private_effects',
    'runtime_stack_after_b_ac_retains_actual_alignment_fault',
    'runtime_stack_after_b_pkru_retains_actual_access_fault',
    'runtime_stack_kernel_selected_ordinary_chain_preserves_call_history',
    'runtime_stack_default_encodings_targets_and_slot_refuse_before_release',
    'runtime_stack_late_failure_and_unwind_retain_call_custody',
    'runtime_stack_budget_deadline_and_stale_source_refuse_before_effects',
    'runtime_stack_installed_allocation_failures_settle_before_cleanup')}
PYTHON_MODULE = "test_owned_stack"
PYTHON_METHODS = (
    PYTHON_MODULE + ".OwnedStackTests.test_owned_stack_addition_preserves_exact_sources_corpus_and_history",
    PYTHON_MODULE + ".OwnedStackTests.test_owned_stack_projection_rejects_every_identity_count_and_source_mutation",
    PYTHON_MODULE + ".OwnedStackTests.test_owned_stack_closed_outcomes_preserve_failure_prefix_and_privacy",
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def before_owned_stack(declared):
    """Validate the complete current corpus and sources before historical use."""
    require(type(declared) is dict and type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 305, "owned_stack_inventory_differs")
    rows = declared.get("native_validation_fixtures")
    require(type(rows) is list and len(rows) == 103 and rows[86:] == list(ROWS),
            "owned_stack_inventory_differs")
    fixtures.catalog(rows)
    require(digest(rows[:86]) == OLD_NATIVE86_SHA256, "owned_stack_inventory_differs")
    cohorts = declared.get("harness_test_counts")
    require(type(cohorts) is dict and set(cohorts) == {"workspace_tests", "serial_launch"},
            "owned_stack_inventory_differs")
    for name in ("workspace_tests", "serial_launch"):
        require(type(cohorts[name]) is dict
                and cohorts[name].get(fixtures.UNIT) == {"tests": 703, "ignored": 0},
                "owned_stack_inventory_differs")
        require(type(cohorts[name][fixtures.UNIT]["tests"]) is int
                and type(cohorts[name][fixtures.UNIT]["ignored"]) is int,
                "owned_stack_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["recorder_tests"] = 302
    previous["native_validation_fixtures"] = previous["native_validation_fixtures"][:86]
    for cohort in previous["harness_test_counts"].values():
        cohort[fixtures.UNIT] = {"tests": 612, "ignored": 0}
    require(digest(previous) == PRE_OWNED_STACK_CORPUS_SHA256, "owned_stack_inventory_differs")
    require_current_owned_stack_sources()
    return previous


def before_owned_stack_python(identities):
    """Preserve all 302 prior identities and the exact order of the new three."""
    require(type(identities) is list and len(identities) == 305
            and all(type(value) is str for value in identities)
            and len(set(identities)) == len(identities), "owned_stack_source_inventory_differs")
    old = [value for value in identities if not value.startswith(PYTHON_MODULE + ".")]
    new = [value for value in identities if value.startswith(PYTHON_MODULE + ".")]
    require(new == list(PYTHON_METHODS) and len(old) == 302
            and digest(old) == OLD_PYTHON302_SHA256, "owned_stack_source_inventory_differs")
    return old


def validate_owned_stack_source(path, names):
    require(type(path) is str and path in RUST_METHODS and type(names) is list
            and names == list(RUST_METHODS[path]), "owned_stack_source_inventory_differs")


def require_current_owned_stack_sources():
    """All 91 source identities remain required, including all 17 native names."""
    root = Path(__file__).resolve().parents[2]
    for path in RUST_METHODS:
        try:
            source = (root / path).read_text()
        except (OSError, UnicodeError):
            require(False, "owned_stack_source_inventory_differs")
        names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
        validate_owned_stack_source(path, names)
        require(not re.search(r"#\[ignore(?:\]|\()", source),
                "owned_stack_source_inventory_differs")
