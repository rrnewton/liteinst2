"""Strict historical fixture projection for ordinary history/custody additions.

Only recorder tests call this helper. Drivers consume the unprojected current
corpus and require all 107 native fixture and all 736 launcher tests. This is
source/corpus authentication, never compiled-baseline or execution evidence.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

import native_fixtures as fixtures
from parsing import require

PRE_ORDINARY_SHARED_CORPUS_SHA256 = '4413abf57a6d87e4574bde653dfeb4321670488497c7eead35dbe76148b043f6'
CURRENT_ORDINARY_SHARED_CORPUS_SHA256 = '5088c4e4cc75288a7a7b13498bbcb25846fce920b3379f77b1ce0dbbd79891fb'
RUST_METHODS = {'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/ordinary/shared/tests.rs': ('ordinary_shared_allocation_error_and_unwind_retain_every_installed_prefix',
                                                                                                     'ordinary_shared_prior_is_the_single_pre_effect_payload_owner',
                                                                                                     'ordinary_shared_semantic_rows_preserve_all_headers_and_role_aliases',
                                                                                                     'ordinary_shared_equal_bytes_do_not_substitute_for_canonical_provenance',
                                                                                                     'ordinary_shared_resolver_rejects_foreign_identity_role_and_endpoint',
                                                                                                     'ordinary_shared_row_grammar_is_exact_and_resolution_failure_is_not_skipped',
                                                                                                     'ordinary_shared_incomplete_and_corrupted_payload_extents_cannot_resolve',
                                                                                                     'ordinary_shared_stage_errors_and_unwinds_retain_every_initialized_prefix',
                                                                                                     'ordinary_shared_snapshot_compares_every_byte_and_header_separately_from_identity',
                                                                                                     'ordinary_shared_box_move_preserves_bytes_and_historical_owner_resolution',
                                                                                                     'ordinary_shared_invalid_prior_extent_and_binding_keep_first_error',
                                                                                                     'ordinary_shared_complete_storage_refuses_reuse_without_overwriting_records'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/ordinary/shared_commit/tests.rs': ('ordinary_shared_shape_has_five_exact_distinct_payloads',
                                                                                                            'ordinary_shared_model_publishes_exact_seven_rows_and_full_states',
                                                                                                            'ordinary_shared_allocation_prefixes_settle_once_on_error_and_unwind',
                                                                                                            'ordinary_shared_canonical_capture_and_copy_prefixes_are_required',
                                                                                                            'ordinary_shared_full_validator_rejects_changed_binding_state_trace_and_sequence',
                                                                                                            'ordinary_shared_final_checks_precede_every_publication',
                                                                                                            'ordinary_shared_resolver_rejects_wrong_owner_evidence_and_endpoints',
                                                                                                            'ordinary_shared_history_snapshots_keep_bytes_ids_and_checked_prefixes'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/ordinary/native_tests/allocation.rs': ('runtime_ordinary_allocation_errors_retain_actual_pending_custody',
                                                                                                                 'runtime_ordinary_allocation_unwinds_retain_actual_pending_custody',
                                                                                                                 'runtime_ordinary_transfer_copy_conversion_failures_retain_actual_custody',
                                                                                                                 'runtime_ordinary_growth_failures_preserve_prior_completed_custody'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/ordinary/storage/tests.rs': ('ordinary_root_every_allocation_error_keeps_exact_installed_prefix',
                                                                                                       'ordinary_root_every_post_install_unwind_keeps_exact_payload_and_debit',
                                                                                                       'ordinary_root_no_growth_and_two_generations_preserve_all_box_owners',
                                                                                                       'ordinary_root_transfer_copy_and_native_conversion_boundaries_retain_progress',
                                                                                                       'ordinary_root_secondary_settlement_and_finish_keep_original_error_and_unwind',
                                                                                                       'ordinary_root_reuse_and_slot_shape_refusal_do_not_discard_owner'),
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_native/storage/tests.rs': ('ordinary_pending_native_missing_owner_conversion_retains_every_present_byte',
                                                                                                     'ordinary_pending_native_conversion_is_move_only_and_does_not_complete_instruction',
                                                                                                     'ordinary_pending_native_failure_reuse_and_capacity_guards_retain_owners')}
SOURCE_SHA256 = {'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/ordinary/shared/tests.rs': 'fe92af341a15bc241c95b1da228a801eb6bbe89c2ebb393e85f50e5d655ff074',
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/census/ordinary/shared_commit/tests.rs': 'c36d2d1536d279ba9b664785b7dbab97a38ac0e518dd5e8f25cf4113d9e52c60',
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/ordinary/native_tests/allocation.rs': '7ca5622c20fa49662d519f5f998e91832bee479d831cb57f3f17f9d6c128d977',
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime/ordinary/storage/tests.rs': 'e112962b376b27ad0148f35050b63213ace760e747512da6a7a93fec7a4def37',
 'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/runtime_native/storage/tests.rs': '9d6f3335df4a162652e35aa27039bf07a5a4bf43a99e62daeca6946f7faf7b43'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_current_ordinary_shared_sources():
    root = Path(__file__).resolve().parents[2]
    for path, expected in RUST_METHODS.items():
        try:
            data = (root / path).read_bytes()
            source = data.decode("utf-8")
        except (OSError, UnicodeError):
            require(False, "ordinary_shared_source_inventory_differs")
        require(hashlib.sha256(data).hexdigest() == SOURCE_SHA256[path]
                and re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source) == list(expected)
                and not re.search(r"#\[ignore(?:\]|\()", source),
                "ordinary_shared_source_inventory_differs")


def before_ordinary_shared(declared):
    """Authenticate the complete 107/736 corpus, then return the exact 103/703 fixture.

    A historical input, second peel or future catalogue never falls back.
    Current driver/receipt paths do not call this projection.
    """
    require(type(declared) is dict and digest(declared) == CURRENT_ORDINARY_SHARED_CORPUS_SHA256,
            "ordinary_shared_inventory_differs")
    rows = declared["native_validation_fixtures"]
    require(type(rows) is list and len(rows) == 107
            and rows[103:] == list(fixtures.ORDINARY_ALLOCATION_ROWS),
            "ordinary_shared_inventory_differs")
    fixtures.catalog(rows)
    for cohort in ("workspace_tests", "serial_launch"):
        observed = declared["harness_test_counts"][cohort][fixtures.UNIT]
        require(observed == {"tests": 736, "ignored": 0}
                and all(type(value) is int for value in observed.values()),
                "ordinary_shared_inventory_differs")
    previous = copy.deepcopy(declared)
    previous["native_validation_fixtures"] = previous["native_validation_fixtures"][:103]
    for cohort in ("workspace_tests", "serial_launch"):
        previous["harness_test_counts"][cohort][fixtures.UNIT]["tests"] = 703
    require(digest(previous) == PRE_ORDINARY_SHARED_CORPUS_SHA256,
            "ordinary_shared_inventory_differs")
    require_current_ordinary_shared_sources()
    return previous
