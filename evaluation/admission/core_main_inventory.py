"""Exact history adapter for the separately merged 49-method core addition.

Test-only source/corpus authentication; no native or qualification evidence.
"""

import ast
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
from owned_stack_inventory import before_owned_stack_python

PRE_CORE_MAIN_CORPUS_SHA256 = 'efc707cf3f8de3b4b1cc13fcb15d480ad18d0352c25e3e6d1b95c34fc9250410'
OLD_PYTHON302_SHA256 = 'ef88eda4e26b581167c865bf32550ffa93bdcb15d755145795fa4650a005ac4b'
ADDED_HARNESSES = {'test/e9_common_seed_contract': {'ignored': 0, 'tests': 3},
 'unit/common_sites/common_sites': {'ignored': 0, 'tests': 24}}
CHANGED_HARNESSES = {'unit/liteinst_rewrite/lib': (62, 76), 'unit/rapid_profiler/lib': (98, 106)}
RUST_METHODS = {'tests/e9_common_seed_contract.rs': ('exact_complete_inventory_and_range_owners_only',
                                      'finite_case_domain_preserves_every_head_and_exact_call_return_words',
                                      'invalid_anchor_domains_are_refused_before_seed_construction'),
 'tools/elf-rewrite/examples/common_sites.rs': ('explicit_v2_grammar_keeps_exact_caps_and_v1_separate',
                                                'signed_digit_successor_retains_negative_edges_and_entry_bytes',
                                                'digit_minimum_matches_bounded_independent_byte_enumeration',
                                                'heap_store_uses_complete_ret_entry_and_unaligned_preferred_pc',
                                                'upstream_windows_use_original_head_budget_before_qualification',
                                                'complete_jump_cell_keeps_unplaceable_id15_as_neutral_permit',
                                                'full_page_slot_ownership_and_exhaustion_are_not_byte_only',
                                                'derived_domain_must_own_loads_carrier_and_all_permits',
                                                'unchanged_core_accepts_heap_b1_but_retains_old_arena_and_id15_refusals',
                                                'carrier_low_canonical_endpoint_is_admitted_but_crossing_refuses',
                                                'original_load_low_canonical_endpoint_is_admitted_but_crossing_refuses',
                                                'strict_policy_keeps_three_ranges_and_all_bounds',
                                                'selection_roundtrip_retains_every_head_and_exact_static_sites',
                                                'rsp_red_zone_and_frame_bounds_are_checked_without_pointer_masks',
                                                'jump_policy_retains_jumps_but_not_call_ret_or_loop',
                                                'complete_heads_and_single_store_are_not_visit_filtered',
                                                'complete_jump_table_includes_unconditional_and_conditional',
                                                'explicit_and_implicit_rsp_writes_are_owned',
                                                'unknown_writers_stay_visible_and_refuse_full_selection',
                                                'return_slot_and_unproven_stack_adjustments_refuse',
                                                'inconsistent_join_depth_refuses',
                                                'foreign_middle_indirect_and_recursive_transfers_refuse_without_site_filtering',
                                                'changed_store_displacement_or_width_never_gets_heap_credit',
                                                'scanner_rejects_invalid_and_truncated_tail'),
 'tools/elf-rewrite/src/carrier/dynamic_copy_fixtures.rs': ('copy_size_comes_from_complete_symbol_and_unique_file_or_zero_owner',
                                                            'copy_global_and_absent_version_are_explicit_and_unknown_versions_refuse',
                                                            'copy_symbol_profile_size_name_and_target_are_not_guessed',
                                                            'copy_does_not_accept_rel_or_jump_table_profiles',
                                                            'copy_destination_rejects_permissions_crossings_ambiguity_and_overflow',
                                                            'copy_requires_complete_hash_symbol_string_and_version_metadata',
                                                            'copy_shares_all_write_overlap_source_and_budget_checks',
                                                            'copy_carrier_preserves_original_metadata_loads_and_destination_reservations'),
 'tools/elf-rewrite/src/carrier/property_fixtures.rs': ('isa_requirements_and_empty_feature_records_keep_exact_bytes_and_owners',
                                                        'cet_unknown_and_duplicate_properties_stay_refused',
                                                        'malformed_note_lengths_name_types_and_padding_are_not_ignored',
                                                        'property_header_and_unique_read_only_mapping_must_agree',
                                                        'property_bytes_cannot_be_declared_as_executable_dependencies',
                                                        'freestanding_profile_still_refuses_a_valid_property_note'),
 'tools/rapid-profiler/src/counter_reading.rs': ('full_running_is_an_interval_property_and_keeps_both_endpoints',
                                                 'multiplexed_estimates_preserve_integer_and_fractional_results',
                                                 'zero_count_with_running_time_is_distinct_from_zero_running',
                                                 'missing_endpoints_keep_presence_and_known_facts_without_a_missing_cause',
                                                 'regressions_remain_ambiguous_and_all_regressing_fields_are_visible',
                                                 'endpoint_and_interval_time_inconsistencies_refuse_estimates',
                                                 'changed_count_without_running_time_is_retained_without_an_estimate',
                                                 'extreme_products_and_quotients_are_exact_beyond_u64')}
SOURCE_WIRING = {'tools/elf-rewrite/Cargo.toml': '[[example]]\n'
                                 'name = "common_sites"\n'
                                 'path = "examples/common_sites.rs"\n'
                                 'test = true',
 'tools/elf-rewrite/src/carrier/dynamic.rs': '#[cfg(test)]\n'
                                             '#[path = "dynamic_copy_fixtures.rs"]\n'
                                             'mod copy_fixtures;',
 'tools/elf-rewrite/src/carrier/mod.rs': '#[cfg(test)]\n#[path = "image_fixtures.rs"]\nmod image_fixtures;',
 'tools/elf-rewrite/src/carrier/image_fixtures.rs': '#[path = "property_fixtures.rs"]\n'
                                                    'mod property_fixtures;',
 'tools/rapid-profiler/src/lib.rs': 'pub mod counter_reading;'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_core_main_source(path, names):
    require(type(path) is str and path in RUST_METHODS and type(names) is list
            and names == list(RUST_METHODS[path]), "core_main_source_inventory_differs")


def require_current_core_main_sources():
    root = Path(__file__).resolve().parents[2]
    for path in RUST_METHODS:
        try:
            source = (root / path).read_text()
        except (OSError, UnicodeError):
            require(False, "core_main_source_inventory_differs")
        names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
        validate_core_main_source(path, names)
        require(not re.search(r"#\[ignore(?:\]|\()", source), "core_main_source_inventory_differs")
    for path, fragment in SOURCE_WIRING.items():
        try:
            source = (root / path).read_text()
        except (OSError, UnicodeError):
            require(False, "core_main_source_inventory_differs")
        require(source.count(fragment) == 1, "core_main_source_inventory_differs")
    identities = []
    try:
        for path in sorted(Path(__file__).parent.glob("test_*.py")):
            for cls in ast.parse(path.read_text()).body:
                if isinstance(cls, ast.ClassDef):
                    identities.extend(path.stem + "." + cls.name + "." + method.name
                                      for method in cls.body
                                      if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                                      and method.name.startswith("test_"))
    except (OSError, UnicodeError, SyntaxError):
        require(False, "core_main_source_inventory_differs")
    identities = before_owned_stack_python(identities)
    require(len(identities) == 302 and len(set(identities)) == 302
            and digest(identities) == OLD_PYTHON302_SHA256, "core_main_source_inventory_differs")


def before_core_main(declared):
    """Authenticate every current field before returning the complete old corpus."""
    require(type(declared) is dict and type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 302, "core_main_inventory_differs")
    cohorts = declared.get("harness_test_counts")
    require(type(cohorts) is dict and set(cohorts) == {"workspace_tests", "serial_launch"}
            and type(cohorts["workspace_tests"]) is dict, "core_main_inventory_differs")
    workspace = cohorts["workspace_tests"]
    require(len(workspace) == 91, "core_main_inventory_differs")
    for identity, value in ADDED_HARNESSES.items():
        require(type(workspace.get(identity)) is dict and workspace[identity] == value
                and all(type(word) is int for word in workspace[identity].values()),
                "core_main_inventory_differs")
    for identity, (_, current) in CHANGED_HARNESSES.items():
        require(type(workspace.get(identity)) is dict
                and workspace[identity] == {"tests": current, "ignored": 0}
                and all(type(word) is int for word in workspace[identity].values()),
                "core_main_inventory_differs")
    previous = copy.deepcopy(declared)
    prior = previous["harness_test_counts"]["workspace_tests"]
    for identity in ADDED_HARNESSES:
        del prior[identity]
    for identity, (count, _) in CHANGED_HARNESSES.items():
        prior[identity] = {"tests": count, "ignored": 0}
    require(digest(previous) == PRE_CORE_MAIN_CORPUS_SHA256, "core_main_inventory_differs")
    require_current_core_main_sources()
    return previous
