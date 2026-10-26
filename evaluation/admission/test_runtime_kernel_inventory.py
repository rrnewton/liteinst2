"""Strict additive kernel inventory; source reads and synthetic controls only."""

import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

import native_fixtures as fixtures
from parsing import InvalidEvidence, require
from consumer_inventory import (CONSUMER_METHODS, OLD_PYTHON284_SHA256,
                                before_consumer, before_consumer_python)

PURE_INCREMENT = 64
NATIVE_INCREMENT = 6
UNIT_INCREMENT = 70
RECORDER_INCREMENT = 11
PRE_KERNEL_CORPUS_SHA256 = "7ddcdd88762432db824bf74cd35657025c26b3d9123cfbfb339788161ba70c4c"
OLD_NATIVE75_SHA256 = "09ebfa76c15ccdf7d383ec7dd29873d70ed2f0c6782f2bf6f8d72335ce304d79"
OLD_RUNTIME138_SHA256 = "01e631010eb89714e044c5646e53041bbab048e1f9432defc5da2ca95ec50a25"
OLD_PYTHON273_SHA256 = "2d7345310ebe7b8bc30e139a3407a228a9c1106ded9991925f65d37baeaf0e7a"
KERNEL_NATIVE_SOURCE = "crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/kernel/native_tests.rs"
KERNEL_NATIVE_ROOT = "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests"
KERNEL_ROWS = ({'cohort': 'b3_runtime_kernel',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_public_getpid_selected_ordinary_exit_preserves_lineage'},
 {'cohort': 'b3_runtime_kernel',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_gettid_exit_group_retains_real_terminal'},
 {'cohort': 'b3_runtime_kernel',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_cross_page_syscall_preserves_exact_fetch'},
 {'cohort': 'b3_runtime_kernel',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_default_native_and_cpu_refusals_keep_current_state'},
 {'cohort': 'b3_runtime_kernel',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_fault_and_unsupported_syscalls_never_release'},
 {'cohort': 'b3_runtime_kernel',
  'harness': 'unit/liteinst_launch/lib',
  'test': 'linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_stale_reply_keeps_physical_custody'})
KERNEL_METHODS = {'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/ordinary/tests.rs': ('ordinary_after_sealed_kernel_return_resets_only_at_actual_trace_model',
                                                                                              'ordinary_kernel_provenance_never_waives_trace_or_close_max_requirement'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/runtime_kernel/tests.rs': ('runtime_kernel_return_preserves_actual_entry_exit_and_all_refreshes',
                                                                                                    'runtime_kernel_terminal_keeps_real_terminal_without_a_user_successor',
                                                                                                    'runtime_kernel_reservation_enforces_all_six_limits_before_preparation',
                                                                                                    'runtime_kernel_six_axis_overflow_refuses_without_mutation',
                                                                                                    'runtime_kernel_preparation_requires_exact_source_invocation_and_current_state',
                                                                                                    'runtime_kernel_return_rejects_full_observation_changes_atomically',
                                                                                                    'runtime_kernel_raw_reads_preserve_exact_success_substrates_and_lengths',
                                                                                                    'runtime_kernel_syscall_info_and_actual_event_are_both_required',
                                                                                                    'runtime_kernel_return_trace_and_each_stop_identity_remain_binding',
                                                                                                    'runtime_kernel_terminal_requires_real_status_eventmsg_and_original_pin_completion',
                                                                                                    'runtime_kernel_late_capacity_serial_and_reservation_refusals_keep_all_prepared_data',
                                                                                                    'runtime_kernel_original_deadline_and_one_use_remain_exact',
                                                                                                    'runtime_kernel_inherited_register_tag_requires_full_retained_lineage',
                                                                                                    'runtime_kernel_cpu_successor_preserves_provenance_and_rejects_changed_bookkeeping',
                                                                                                    'runtime_kernel_unsealed_nonmax_or_changed_selected_model_never_prepares'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_kernel_native/io/tests.rs': ('runtime_kernel_raw_state_keeps_full_initialized_substrate_and_exact_extent',
                                                                                                       'runtime_kernel_raw_owned_trap_requires_exact_si_kernel_and_request_success',
                                                                                                       'runtime_kernel_raw_syscall_header_checks_meaningful_length_arch_and_phase'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_kernel_native/runner/validate/tests.rs': ('runtime_kernel_projection_keeps_real_orig_rax_rcx_r11_and_flags',
                                                                                                                    'runtime_kernel_full_architecture_comparison_rejects_every_field_change',
                                                                                                                    'runtime_kernel_native_syscall_wait_refuses_signal_event_and_terminal_lookalikes',
                                                                                                                    'runtime_kernel_state_profile_refuses_debug_flags_mode_and_partial_xstate'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_kernel_native/tests.rs': ('runtime_kernel_native_fixed_layout_charges_all_unused_terminal_capacity',
                                                                                                    'runtime_kernel_native_partial_allocation_refusal_keeps_prior_storage',
                                                                                                    'runtime_kernel_native_effect_capacity_is_thirty_seven_and_never_skips_pending',
                                                                                                    'runtime_kernel_native_terminal_raw_header_has_no_fabricated_request_credit',
                                                                                                    'runtime_kernel_native_error_and_unwind_keep_first_failure_and_never_seal',
                                                                                                    'runtime_kernel_native_checked_storage_arithmetic_refuses_overflow'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/selected/native/control_tests.rs': ('selected_control_preapply_storage_is_distinct_and_fully_charged',
                                                                                                              'selected_control_full_state_comparison_keeps_orig_xstate_and_mask_exact'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_native/profile/tests.rs': ('kernel_control_requires_exact_current_checkpoint_and_original_return_identity',
                                                                                                     'kernel_control_does_not_allow_a_bare_number_or_normalized_max',
                                                                                                     'kernel_control_keeps_every_original_native_state_gate',
                                                                                                     'kernel_control_ordinary_trace_requires_max_and_preserves_other_controls',
                                                                                                     'kernel_control_selected_checks_both_actual_orig_values',
                                                                                                     'kernel_control_selected_six_cpu_models_preserve_full_inherited_state',
                                                                                                     'kernel_control_selected_rejects_flags_aliases_and_semantic_mismatch',
                                                                                                     'kernel_control_temporary_reservation_keeps_retained_profile_separate'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/kernel_journal/runtime/tests.rs': ('runtime_journal_detached_preparation_charges_full_replacement_without_refund',
                                                                                           'runtime_journal_detached_drop_and_stale_foreign_attach_leave_archive_exact',
                                                                                           'runtime_journal_shape_checks_actual_capacity_overflow_and_mixed_stream_order',
                                                                                           'runtime_journal_failed_getregs_preserves_independent_max_substrate_and_errno',
                                                                                           'runtime_journal_complete_claim_refuses_pointer_length_and_state_corruption',
                                                                                           'runtime_journal_partial_wait_and_first_error_survive_cleanup_and_owner_drop',
                                                                                           'runtime_journal_exact_fact_capacity_keeps_prefix_and_separate_first_failure',
                                                                                           'runtime_journal_unwind_marks_only_incomplete_runtime_attempt',
                                                                                           'runtime_journal_exact_layout_preserves_initialized_ownership_and_checked_bounds',
                                                                                           'runtime_journal_terminal_and_unheld_headers_never_imply_query_permission',
                                                                                           'runtime_journal_return_commit_comparison_binds_every_identity_and_exact_stop',
                                                                                           'runtime_journal_terminal_commit_comparison_requires_real_tag_and_no_successor'),
 'crates/liteinst-launch/src/lifecycle/initial_kernel/tests.rs': ('kernel_singleton_requires_exact_entry_exit_and_pre_exit_model_phases',
                                                                  'kernel_singleton_cannot_borrow_the_settled_source_predicate',
                                                                  'kernel_singleton_refuses_changed_membership_generation_origin_and_obligations'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/kernel/namespace/tests.rs': ('namespace_evidence_requires_all_three_actual_object_identities',
                                                                                                       'namespace_evidence_rejects_each_missing_or_failed_native_outcome',
                                                                                                       'namespace_evidence_rejects_partial_and_wrong_filesystem_or_namespace_type'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/kernel/tests.rs': ('runtime_kernel_default_profile_keeps_native_effects_refused',
                                                                                             'runtime_kernel_policy_accepts_only_four_exact_native64_operations',
                                                                                             'runtime_kernel_policy_rejects_aliases_and_cpu_instructions',
                                                                                             'runtime_kernel_complete_reservation_separates_return_and_terminal_storage',
                                                                                             'runtime_kernel_reservation_refuses_one_short_and_overflow_before_allocation',
                                                                                             'runtime_kernel_exact_allocation_owns_only_initialized_elements'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/kernel/native_tests.rs': ('runtime_kernel_public_getpid_selected_ordinary_exit_preserves_lineage',
                                                                                                    'runtime_kernel_gettid_exit_group_retains_real_terminal',
                                                                                                    'runtime_kernel_cross_page_syscall_preserves_exact_fetch',
                                                                                                    'runtime_kernel_default_native_and_cpu_refusals_keep_current_state',
                                                                                                    'runtime_kernel_fault_and_unsupported_syscalls_never_release',
                                                                                                    'runtime_kernel_stale_reply_keeps_physical_custody')}
PREEXISTING_METHODS = {'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/ordinary/tests.rs': ('ordinary_fixed_schedule_prepays_six_refreshes_and_full_sixteen_states',
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
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_native/profile/tests.rs': ('owned_native_lineage_never_accepts_an_unrelated_or_refreshed_checkpoint',
                                                                                                     'owned_native_profile_requires_all_rseq_bytes_exact_count_and_cet_completion')}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def before_kernel(declared):
    """Authenticate the complete addition before exposing the exact old corpus.

    This is only a historical-test projection, never recorder acceptance or a
    fallback for missing runtime evidence. Every unknown or altered row fails.
    """
    declared = before_consumer(declared)
    require(type(declared) is dict, "kernel_inventory_differs")
    require(type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 273 + RECORDER_INCREMENT,
            "kernel_inventory_differs")
    rows = declared.get("native_validation_fixtures")
    require(type(rows) is list and len(rows) == 75 + NATIVE_INCREMENT
            and rows[75:] == list(KERNEL_ROWS), "kernel_inventory_differs")
    fixtures.catalog(rows)
    require(digest(rows[:75]) == OLD_NATIVE75_SHA256, "kernel_inventory_differs")
    cohorts = declared.get("harness_test_counts")
    require(type(cohorts) is dict and set(cohorts) == {"workspace_tests", "serial_launch"},
            "kernel_inventory_differs")
    for name in ("workspace_tests", "serial_launch"):
        require(type(cohorts[name]) is dict
                and cohorts[name].get(fixtures.UNIT) == {"tests": 494 + UNIT_INCREMENT, "ignored": 0},
                "kernel_inventory_differs")
        require(type(cohorts[name][fixtures.UNIT]["tests"]) is int
                and type(cohorts[name][fixtures.UNIT]["ignored"]) is int,
                "kernel_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["recorder_tests"] = 273
    previous["native_validation_fixtures"] = previous["native_validation_fixtures"][:75]
    for cohort in previous["harness_test_counts"].values():
        cohort[fixtures.UNIT] = {"tests": 494, "ignored": 0}
    require(digest(previous) == PRE_KERNEL_CORPUS_SHA256, "kernel_inventory_differs")
    return previous


def before_kernel_source(path, names):
    """Remove only the exact declared appended methods for a historical view."""
    if path not in KERNEL_METHODS:
        return names
    previous = PREEXISTING_METHODS.get(path, ())
    require(type(names) is list and names == list(previous + KERNEL_METHODS[path]),
            "kernel_source_inventory_differs")
    return list(previous)


class RuntimeKernelInventoryTests(unittest.TestCase):
    def test_kernel_source_methods_preserve_runtime138_and_all273_python_identities(self):
        # Lazy import avoids a projection-helper import cycle. These are source
        # identities only; no Rust test or native request is executed here.
        from test_runtime_inventory import RUST_METHODS, RUNTIME_ROWS

        root = Path(__file__).resolve().parents[2]
        self.assertEqual(digest(RUST_METHODS), OLD_RUNTIME138_SHA256)
        self.assertEqual(sum(map(len, RUST_METHODS.values())), 138)
        self.assertEqual(len(RUNTIME_ROWS), 18)
        self.assertEqual(sum(map(len, KERNEL_METHODS.values())), UNIT_INCREMENT)
        self.assertEqual(len(KERNEL_METHODS[KERNEL_NATIVE_SOURCE]), NATIVE_INCREMENT)
        self.assertEqual(UNIT_INCREMENT - NATIVE_INCREMENT, PURE_INCREMENT)
        self.assertEqual(fixtures.RUNTIME_KERNEL_ROOT, KERNEL_NATIVE_ROOT)
        self.assertEqual(fixtures.RUNTIME_KERNEL_ROWS, KERNEL_ROWS)
        for path, expected in KERNEL_METHODS.items():
            text = (root / path).read_text()
            names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", text)
            self.assertEqual(names, list(PREEXISTING_METHODS.get(path, ()) + expected), path)
            self.assertEqual(len(names), len(set(names)), path)
            self.assertNotRegex(text, r"#\[ignore(?:\]|\()")
            self.assertEqual(before_kernel_source(path, names), list(PREEXISTING_METHODS.get(path, ())))
        self.assertEqual([KERNEL_NATIVE_ROOT + "::" + name for name in KERNEL_METHODS[KERNEL_NATIVE_SOURCE]],
                         [row["test"] for row in KERNEL_ROWS])
        old_python, new_python = [], []
        current_python = []
        new_modules = {"test_runtime_kernel_inventory", "test_runtime_kernel_fixtures"}
        for path in sorted(Path(__file__).parent.glob("test_*.py")):
            tree = ast.parse(path.read_text())
            for cls in tree.body:
                if not isinstance(cls, ast.ClassDef):
                    continue
                for method in cls.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_"):
                        identity = path.stem + "." + cls.name + "." + method.name
                        (new_python if path.stem in new_modules else old_python).append(identity)
                        current_python.append(identity)
        previous_python = before_consumer_python(current_python)
        self.assertEqual(len(previous_python), 284)
        self.assertEqual(digest(previous_python), OLD_PYTHON284_SHA256)
        old_python = [value for value in old_python if value in previous_python]
        self.assertEqual(len(old_python), 273)
        self.assertEqual(digest(old_python), OLD_PYTHON273_SHA256)
        self.assertEqual(len(new_python), RECORDER_INCREMENT)
        self.assertEqual(len(old_python + new_python), len(set(old_python + new_python)))
        for changed in (current_python[:-1], current_python + [current_python[-1]],
                        ["PRIVATE_SENTINEL"] + current_python[1:], list(reversed(current_python))):
            with self.assertRaisesRegex(InvalidEvidence, "^consumer_source_inventory_differs$") as caught:
                before_consumer_python(changed)
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for identity in CONSUMER_METHODS:
            changed = list(current_python)
            changed[changed.index(identity)] = identity + "_unlisted"
            with self.assertRaisesRegex(InvalidEvidence, "^consumer_source_inventory_differs$"):
                before_consumer_python(changed)

    def test_kernel_current_counts_preserve_exact_old_corpus_and_separate_collections(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        original = copy.deepcopy(declared)
        pre_consumer = before_consumer(declared)
        self.assertEqual(pre_consumer | {"recorder_tests": 296}, declared)
        previous = before_kernel(declared)
        self.assertEqual(declared, original)
        self.assertEqual(digest(previous), PRE_KERNEL_CORPUS_SHA256)
        self.assertEqual(declared["native_validation_fixtures"][:75], previous["native_validation_fixtures"])
        self.assertEqual(digest(declared["native_validation_fixtures"][:75]), OLD_NATIVE75_SHA256)
        self.assertEqual(declared["native_validation_fixtures"][75:], list(KERNEL_ROWS))
        for name, harnesses, total, ignores in (("workspace_tests", 89, 1940, 4),
                                               ("serial_launch", 27, 856, 0)):
            current = declared["harness_test_counts"][name]
            self.assertEqual(len(current), harnesses)
            self.assertEqual(sum(row["tests"] for row in current.values()), total)
            self.assertEqual(sum(row["ignored"] for row in current.values()), ignores)
            self.assertEqual(current[fixtures.UNIT], {"tests": 564, "ignored": 0})
            self.assertEqual({key: value for key, value in current.items() if key != fixtures.UNIT},
                             {key: value for key, value in previous["harness_test_counts"][name].items()
                              if key != fixtures.UNIT})
        self.assertEqual(before_consumer(declared)["recorder_tests"], 284)
        self.assertEqual(declared["recorder_tests"], 296)
        self.assertEqual(len(fixtures.catalog(declared["native_validation_fixtures"])), 81)
        for field, count in (("native_cases", 50), ("dynamic_admission_fixtures", 15),
                             ("dynamic_matrix_cases", 388)):
            self.assertEqual(declared[field], previous[field])
            self.assertEqual(len(declared[field]), count)
        self.assertEqual(declared["backing_cleanup_harnesses"], previous["backing_cleanup_harnesses"])

    def test_kernel_projection_refuses_new_or_old_identity_source_and_count_tampering(self):
        declared = json.loads(Path(__file__).with_name("corpus.json").read_text())
        for changed in (declared | {"recorder_tests": 284},
                        declared | {"recorder_tests": 296.0},
                        declared | {"recorder_tests": True},
                        declared | {"unlisted": "PRIVATE_SENTINEL"}):
            with self.assertRaisesRegex(InvalidEvidence, "^consumer_inventory_differs$") as caught:
                before_consumer(changed)
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for index in range(6):
            for change in ("missing", "duplicate", "position", "cohort", "harness", "test", "extra"):
                changed = copy.deepcopy(declared)
                rows = changed["native_validation_fixtures"]
                if change == "missing": rows.pop(75 + index)
                elif change == "duplicate": rows.append(copy.deepcopy(rows[75 + index]))
                elif change == "position": rows[75 + index], rows[74] = rows[74], rows[75 + index]
                elif change == "extra": rows[75 + index]["extra"] = "PRIVATE_SENTINEL"
                else: rows[75 + index][change] = "PRIVATE_SENTINEL"
                with self.subTest(index=index, change=change), self.assertRaises(InvalidEvidence) as caught:
                    before_kernel(changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        for change in ("recorder", "unit", "unit_type", "ignored_type", "old_unit", "old_native",
                       "runtime", "static", "dynamic", "matrix", "helper", "baseline"):
            changed = copy.deepcopy(declared)
            if change == "recorder": changed["recorder_tests"] -= 1
            elif change == "unit": changed["harness_test_counts"]["workspace_tests"][fixtures.UNIT]["tests"] -= 1
            elif change == "unit_type": changed["harness_test_counts"]["serial_launch"][fixtures.UNIT]["tests"] = 564.0
            elif change == "ignored_type": changed["harness_test_counts"]["workspace_tests"][fixtures.UNIT]["ignored"] = False
            elif change == "old_unit": changed["harness_test_counts"]["serial_launch"]["test/dynamic_fork"]["tests"] -= 1
            elif change == "old_native": changed["native_validation_fixtures"][0]["test"] += "_extra"
            elif change == "runtime": changed["native_validation_fixtures"][56]["test"] += "_extra"
            elif change == "static": changed["native_cases"].pop()
            elif change == "dynamic": changed["dynamic_admission_fixtures"].pop()
            elif change == "matrix": changed["dynamic_matrix_cases"].pop()
            elif change == "helper": changed["backing_cleanup_harnesses"]["serial_launch"][0]["trajectories"].pop()
            else: changed["baseline_revision"] = "0" * 40
            with self.subTest(change=change), self.assertRaises(InvalidEvidence):
                before_kernel(changed)
        for path, added in KERNEL_METHODS.items():
            original = list(PREEXISTING_METHODS.get(path, ()) + added)
            for changed in (original[:-1], original + [original[-1]],
                            ["PRIVATE_SENTINEL"] + original[1:], list(reversed(original))):
                with self.subTest(path=path), self.assertRaisesRegex(
                        InvalidEvidence, "^kernel_source_inventory_differs$") as caught:
                    before_kernel_source(path, changed)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
