"""Exact historical projection for the finite initial coalescence addition.

Used only by recorder regressions. This cannot qualify a run, remove required
native outcomes, or substitute a model receipt for physical cleanup.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

import native_fixtures as fixtures
from parsing import require
from core_a3_inventory import before_core_a3
from core_719519_inventory import before_core_719519
from ordinary_shared_inventory import before_ordinary_shared
from ordinary_thirtytwo_inventory import before_ordinary_thirtytwo
from core_c73f159_inventory import before_core_c73f159
from core_ae149a9_inventory import before_core_ae149a9
from core_041bd4a_inventory import before_core_041bd4a
from inprocess_inventory import before_inprocess
from runtime_stack_consumer_inventory import (before_runtime_stack_consumer,
                                               before_runtime_stack_consumer_python)
from core_main_inventory import before_core_main
from owned_stack_inventory import before_owned_stack, before_owned_stack_python

PRE_COALESCENCE_CORPUS_SHA256 = '58a05eb23df1a5d9c9cda0a32f7838363b0406ac5aee1b9fce5cf75a596b7b2b'
OLD_NATIVE83_SHA256 = '65c43f0b2312c0f42644bbbb609f6e0cae9b4e37a3c8722fd6af6c1efbd94685'
OLD_PYTHON299_SHA256 = 'cb15858cf83048bb2233ff1326ddea6d324b9f21c5512fb7dbaa3f0992302b9c'
NATIVE_ROOT = 'linux::remote::dynamic::owner::admission::runtime::coalescence_native_tests'
NATIVE_NAMES = ('initial_runtime_coalescence_merges_pair_and_recloses_original_rx_fetch',
 'initial_runtime_coalescence_one_short_capacity_keeps_pristine_exec',
 'initial_runtime_coalescence_unwind_retains_native_evidence_through_cleanup')
ROWS = tuple({"cohort": "b3_initial_coalescence", "harness": fixtures.UNIT,
              "test": NATIVE_ROOT + "::" + name} for name in NATIVE_NAMES)
RUST_METHODS = {'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/initial_coalescence/rows/tests.rs': ('pair_rows_accept_exact_separate_union_and_original_opening',
                                                                                                       'pair_rows_refuse_each_member_profile_and_identity_change',
                                                                                                       'pair_rows_refuse_union_corruption_in_each_retained_column',
                                                                                                       'pair_rows_refuse_separate_changes_except_the_one_x_bit',
                                                                                                       'pair_rows_opening_refuses_header_x_and_every_changed_source_row',
                                                                                                       'pair_rows_detect_both_third_row_extensions_without_absorbing_them',
                                                                                                       'pair_rows_reject_file_end_overflow_and_unaligned_offsets',
                                                                                                       'pair_rows_refuse_new_pair_field_width_and_separator_spelling'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/initial_coalescence/tests.rs': ('initial_pair_plan_preserves_original_extent_spans_and_executable_order',
                                                                                                  'initial_pair_inventory_requires_exact_quarantine_prefix_and_target_stage',
                                                                                                  'initial_pair_inventory_consumes_every_row_without_count_only_acceptance',
                                                                                                  'initial_pair_inventory_keeps_unrelated_rows_and_all_raw_spelling_exact',
                                                                                                  'initial_pair_inventory_requires_exact_disjoint_island_identity',
                                                                                                  'initial_pair_transition_checks_both_tables_and_unchanged_island_row',
                                                                                                  'initial_pair_selection_keeps_unsupported_profiles_on_the_strict_path',
                                                                                                  'initial_pair_selection_refuses_multiple_pairs_third_rows_and_visible_aliases',
                                                                                                  'initial_pair_projection_preserves_source_scope_and_descriptor_pool_ownership',
                                                                                                  'initial_pair_projection_revalidation_refuses_forged_derived_metadata',
                                                                                                  'initial_pair_inventory_handles_island_before_pair_without_index_aliasing',
                                                                                                  'initial_pair_plan_rejects_malformed_excessive_and_overflowing_descriptions'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_capture/coalesced/tests.rs': ('coalesced_source_keeps_original_rx_and_excludes_header_authority',
                                                                                                        'coalesced_fetch_opens_only_original_rx_and_requires_exact_closed_table',
                                                                                                        'coalesced_separate_nx_uses_same_original_source_without_fictitious_union',
                                                                                                        'coalesced_preflight_charges_pair_and_exact_overlapping_windows',
                                                                                                        'coalesced_preflight_failure_retains_geometry_capacity_and_no_ids',
                                                                                                        'coalesced_window_recheck_rejects_each_original_dependency_change',
                                                                                                        'coalesced_sidecar_exact_capacity_is_separately_retained_once',
                                                                                                        'coalesced_preflight_preserves_alias_and_original_executable_neighbor_refusals'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/source_identity/initial/checkpoint.rs': ('initial_pair_read_description_refuses_every_non_restored_or_signal_phase',),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/bootstrap/initial/coalescence/tests.rs': ('coalescence_exact_layout_helpers_refuse_overflow_and_preserve_empty_ownership',
                                                                                                  'coalescence_prepared_storage_has_exact_payloads_and_no_native_completion',
                                                                                                  'coalescence_each_partial_allocation_refusal_or_unwind_retains_prefix_and_cannot_restart',
                                                                                                  'coalescence_allocation_identity_and_accounting_corruption_are_refused',
                                                                                                  'coalescence_supplied_call_facts_require_wait_queries_result_mask_and_completion',
                                                                                                  'coalescence_every_supplied_state_query_must_succeed_independently',
                                                                                                  'coalescence_incomplete_or_wrong_operation_read_progress_never_finishes_original_capture'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/coalescence_native_tests.rs': ('initial_runtime_coalescence_merges_pair_and_recloses_original_rx_fetch',
                                                                                                         'initial_runtime_coalescence_one_short_capacity_keeps_pristine_exec',
                                                                                                         'initial_runtime_coalescence_unwind_retains_native_evidence_through_cleanup')}
PYTHON_MODULE = "test_initial_coalescence"
PYTHON_METHODS = (
    PYTHON_MODULE + ".InitialCoalescenceTests.test_coalescence_addition_preserves_exact_sources_corpus_and_python_inventory",
    PYTHON_MODULE + ".InitialCoalescenceTests.test_coalescence_projection_rejects_source_row_count_and_historical_tampering",
    PYTHON_MODULE + ".InitialCoalescenceTests.test_coalescence_closed_catalog_and_results_preserve_failure_prefix_and_privacy",
)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def before_coalescence_baseline(declared):
    """Authenticate every new and old field before returning the prior corpus."""
    require(type(declared) is dict and type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 302, "coalescence_inventory_differs")
    rows = declared.get("native_validation_fixtures")
    require(type(rows) is list and len(rows) == 86 and rows[83:] == list(ROWS),
            "coalescence_inventory_differs")
    fixtures.catalog(rows)
    require(digest(rows[:83]) == OLD_NATIVE83_SHA256, "coalescence_inventory_differs")
    cohorts = declared.get("harness_test_counts")
    require(type(cohorts) is dict and set(cohorts) == {"workspace_tests", "serial_launch"},
            "coalescence_inventory_differs")
    for name in ("workspace_tests", "serial_launch"):
        require(type(cohorts[name]) is dict
                and cohorts[name].get(fixtures.UNIT) == {"tests": 612, "ignored": 0},
                "coalescence_inventory_differs")
        require(type(cohorts[name][fixtures.UNIT]["tests"]) is int
                and type(cohorts[name][fixtures.UNIT]["ignored"]) is int,
                "coalescence_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["recorder_tests"] = 299
    previous["native_validation_fixtures"] = previous["native_validation_fixtures"][:83]
    for cohort in previous["harness_test_counts"].values():
        cohort[fixtures.UNIT] = {"tests": 573, "ignored": 0}
    require(digest(previous) == PRE_COALESCENCE_CORPUS_SHA256, "coalescence_inventory_differs")
    require_current_coalescence_sources()
    return previous


def before_coalescence_python_baseline(identities):
    """Remove only the exact three added source identities, in original order."""
    require(type(identities) is list and len(identities) == 302
            and all(type(value) is str for value in identities)
            and len(set(identities)) == len(identities), "coalescence_source_inventory_differs")
    old = [value for value in identities if not value.startswith(PYTHON_MODULE + ".")]
    new = [value for value in identities if value.startswith(PYTHON_MODULE + ".")]
    require(new == list(PYTHON_METHODS) and len(old) == 299
            and digest(old) == OLD_PYTHON299_SHA256, "coalescence_source_inventory_differs")
    return old


def validate_coalescence_source(path, names):
    require(type(path) is str and path in RUST_METHODS and type(names) is list
            and names == list(RUST_METHODS[path]), "coalescence_source_inventory_differs")


def require_current_coalescence_sources():
    """All 39 exact source methods are required before historical peeling."""
    root = Path(__file__).resolve().parents[2]
    for path in RUST_METHODS:
        try:
            source = (root / path).read_text()
        except (OSError, UnicodeError):
            require(False, "coalescence_source_inventory_differs")
        names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
        validate_coalescence_source(path, names)
        require(not re.search(r"#\[ignore(?:\]|\()", source),
                "coalescence_source_inventory_differs")


def before_coalescence(declared):
    return before_coalescence_baseline(before_core_main(before_owned_stack(before_core_a3(before_runtime_stack_consumer(before_core_719519(before_ordinary_shared(before_ordinary_thirtytwo(before_core_c73f159(before_core_ae149a9(before_core_041bd4a(before_inprocess(declared))))))))))))


def before_coalescence_python(identities):
    return before_coalescence_python_baseline(before_owned_stack_python(before_runtime_stack_consumer_python(identities)))
