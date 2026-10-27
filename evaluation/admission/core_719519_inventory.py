"""Closed historical corpus projection for the eighteen merged719519 tests.

Recorder fixtures only. Current drivers retain the complete95-harness corpus;
this source authentication is not a native or merged-revision execution result.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require

PRE_CORE_719519_CORPUS_SHA256 = '5ace8d0218e9872689c6573f5ccd1e8ed137dcd6651a34925c7454e2d244f7da'
CURRENT_CORE_719519_CORPUS_SHA256 = '4413abf57a6d87e4574bde653dfeb4321670488497c7eead35dbe76148b043f6'
ADDED_HARNESSES = {'test/cross_function_neighbor': {'ignored': 0, 'tests': 9},
 'test/foreign_neighbor_engine': {'ignored': 0, 'tests': 9}}
RUST_METHODS = {'tests/cross_function_neighbor.rs': ('exact_id15_id57_two_owner_gateways_images_and_original_relative_bytes',
                                      'missing_partial_stale_or_changed_original_victim_authority_refuses',
                                      'both_entry_owners_and_saved_resumes_remain_complete',
                                      'wrong_forced_head_block_function_or_semantics_cannot_borrow_authority',
                                      'changed_selected_and_victim_operations_refuse_without_mutating_predecessor',
                                      'current_full_reads_keep_other_edits_and_inherited_locks_are_not_reset',
                                      'unchanged_budget_and_both_source_placement_exclusions_are_enforced',
                                      'cross_function_direct_branch_into_victim_interior_and_cet_are_refused',
                                      'exact_upper_rel8_limit_is_accepted_and_next_byte_refuses'),
 'tests/foreign_neighbor_engine.rs': ('empty_foreign_failure_and_local_success_are_unchanged',
                                      'id15_continuation_retains_all_five_local_refusals_and_exact_foreign_geometry',
                                      'forced_tactic_and_exact_forced_victim_are_never_substituted',
                                      'failed_foreign_qualification_is_retained_and_consumes_the_shared_victim_budget',
                                      'preflight_refusal_cannot_evade_victim_budget_or_widen_allocations',
                                      'exhausted_original_victim_or_pair_budget_never_restarts_at_foreign_owner',
                                      'failed_foreign_pair_is_not_reset_and_survives_later_success',
                                      'duplicate_eligible_heads_refuse_before_foreign_emission',
                                      'foreign_success_cannot_lose_inherited_site_or_allocation_ownership')}
SOURCE_SHA256 = {'Cargo.toml': 'cc8da284807082bbe47c265a4830ffced4bd173f95a9e2571ecdec6f568130c6',
 'src/lib.rs': '2e4cb57fb7be6c78d58a5582c5ab4e6408f373c1840243a30d71e49438db363a',
 'src/emission.rs': 'ae43e2b42c0e575cf8ec227f61a6866cacd7fcedb00c94627dd5ce5ebd2d6d51',
 'src/engine.rs': '1c43f22fae312f76968c9f64e9cfc9e7de96ba08fa625fc54eefb2f4d39e628b',
 'src/neighbor.rs': '7ffea697019b497757032b92dd8db2dadad0e43ed0bae047810dd02168af49ea',
 'src/engine_foreign.rs': 'ec13c316ae69a4907271be2da3ae514452eb877ca347024a836d7eae1c365499',
 'src/neighbor_cross_function.rs': '79c57511ff80b6113fef4e90e2175cc6730cce73e804889b3cb7637fa2f86f86',
 'tests/cross_function_neighbor.rs': '3f9f57217b6d00943613f3cebbbbe4a412310f082f23e5a00a4127822a3b7b41',
 'tests/foreign_neighbor_engine.rs': '6c5714eb9ea8e5b7dac81d65d1409c857642381bc7782d7062e83639b2592e33'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_current_core_719519_sources():
    root = Path(__file__).resolve().parents[2]
    for path, expected_hash in SOURCE_SHA256.items():
        try:
            data = (root / path).read_bytes()
            source = data.decode("utf-8")
        except (OSError, UnicodeError):
            require(False, "core_719519_source_inventory_differs")
        require(hashlib.sha256(data).hexdigest() == expected_hash,
                "core_719519_source_inventory_differs")
        if path in RUST_METHODS:
            require(re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
                    == list(RUST_METHODS[path])
                    and not re.search(r"#\[ignore(?:\]|\()", source),
                    "core_719519_source_inventory_differs")


def before_core_719519(declared):
    """Authenticate the entire current corpus before peeling only two new rows."""
    require(type(declared) is dict and digest(declared) == CURRENT_CORE_719519_CORPUS_SHA256,
            "core_719519_inventory_differs")
    workspace = declared["harness_test_counts"]["workspace_tests"]
    require(len(workspace) == 95, "core_719519_inventory_differs")
    for identity, expected in ADDED_HARNESSES.items():
        observed = workspace[identity]
        require(type(observed) is dict and observed == expected
                and all(type(value) is int for value in observed.values()),
                "core_719519_inventory_differs")
    previous = copy.deepcopy(declared)
    for identity in ADDED_HARNESSES:
        del previous["harness_test_counts"]["workspace_tests"][identity]
    require(digest(previous) == PRE_CORE_719519_CORPUS_SHA256,
            "core_719519_inventory_differs")
    require_current_core_719519_sources()
    return previous
