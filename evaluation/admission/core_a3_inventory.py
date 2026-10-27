"""Strict complete-corpus projection for the separately merged twenty A3 tests.

Historical recorder controls only; no native or qualification evidence.
"""

import ast
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
from runtime_stack_consumer_inventory import before_runtime_stack_consumer_python

PRE_CORE_A3_CORPUS_SHA256 = '9fa263ff4f52fadfbb3f9a2d010d58846a52bb25ce28d9c1b22fee6bdb331a0c'
OLD_PYTHON305_SHA256 = 'b48c3f3f5c2e33915767d3f31e0032fbd79ccafa23138cfa624e7520adcd8089'
ADDED_HARNESSES = {'test/e9_common_core_pages_contract': {'ignored': 0, 'tests': 9},
 'unit/verify_common_core/verify_common_core': {'ignored': 0, 'tests': 3}}
CHANGED_HARNESSES = {'test/integration': ({'ignored': 0, 'tests': 11}, {'ignored': 0, 'tests': 14}),
 'unit/liteinst2/lib': ({'ignored': 1, 'tests': 208}, {'ignored': 1, 'tests': 213})}
RUST_METHODS = {'src/artifact_overlay_tests.rs': ('five_tactics_decode_originals_and_keep_inherited_full_reads',
                                   'generalized_and_prefixed_puns_preserve_inherited_suffix_and_store_padding',
                                   'all_five_tactics_refuse_changed_selected_bytes_even_when_replacing',
                                   'successor_and_neighbor_refuse_changed_original_victims',
                                   'changed_same_site_window_keeps_the_bounded_upstream_candidate'),
 'tests/e9_common_core_pages_contract.rs': ('mixed_load_order_retains_full_original_pages_and_generated_zero_tail',
                                            'half_open_original_window_preserves_high_only_and_both_adjacent_pages',
                                            'missing_changed_reordered_or_extra_original_owners_refuse',
                                            'original_overlap_and_lower_straddle_refuse',
                                            'generated_exact_and_rounded_overlap_refuse',
                                            'generated_permissions_remain_read_or_read_execute',
                                            'generated_page_and_load_count_limits_remain_exact',
                                            'whole_union_span_includes_lower_pages_and_keeps_exact_limit',
                                            'file_geometry_and_address_endpoint_refusals_remain'),
 'tools/elf-rewrite/examples/verify_common_core.rs': ('complete_policy_versions_preserve_caps_and_authenticate_original_owners',
                                                      'four_pivot_ceiling_matches_bounded_bruteforce_and_signed_edges',
                                                      'original_blocks_all_sites_and_heap_permit_have_independent_expected_coordinates'),
 'tools/elf-rewrite/tests/support/composition_overlay.rs': ('independent_original_mov_probes_compose_current_full_reads_and_original_sparse_edits',
                                                            'overlapping_later_original_window_refuses_complete_selection_and_keeps_first_step',
                                                            'predecessor_authentication_requires_exact_identity_originals_and_complete_coverage')}
SOURCE_WIRING = {'src/lib.rs': '#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]\n'
               'mod artifact_overlay_tests;',
 'tools/elf-rewrite/Cargo.toml': '[[example]]\n'
                                 'name = "verify_common_core"\n'
                                 'path = "examples/verify_common_core.rs"\n'
                                 'test = true',
 'tools/elf-rewrite/tests/integration.rs': '#[path = "support/composition_overlay.rs"]\n'
                                           'mod composition_overlay;'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_core_a3_source(path, names):
    require(type(path) is str and path in RUST_METHODS and type(names) is list
            and names == list(RUST_METHODS[path]), "core_a3_source_inventory_differs")


def require_current_core_a3_sources():
    root = Path(__file__).resolve().parents[2]
    for path in RUST_METHODS:
        try:
            source = (root / path).read_text()
        except (OSError, UnicodeError):
            require(False, "core_a3_source_inventory_differs")
        names = re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
        validate_core_a3_source(path, names)
        require(not re.search(r"#\[ignore(?:\]|\()", source), "core_a3_source_inventory_differs")
    for path, fragment in SOURCE_WIRING.items():
        try:
            source = (root / path).read_text()
        except (OSError, UnicodeError):
            require(False, "core_a3_source_inventory_differs")
        require(source.count(fragment) == 1, "core_a3_source_inventory_differs")
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
        require(False, "core_a3_source_inventory_differs")
    identities = before_runtime_stack_consumer_python(identities)
    require(len(identities) == 305 and len(set(identities)) == 305
            and digest(identities) == OLD_PYTHON305_SHA256, "core_a3_source_inventory_differs")


def before_core_a3(declared):
    """Require the complete new catalog, then recover the exact complete old one."""
    require(type(declared) is dict and type(declared.get("recorder_tests")) is int
            and declared["recorder_tests"] == 305, "core_a3_inventory_differs")
    cohorts = declared.get("harness_test_counts")
    require(type(cohorts) is dict and set(cohorts) == {"workspace_tests", "serial_launch"}
            and type(cohorts["workspace_tests"]) is dict, "core_a3_inventory_differs")
    workspace = cohorts["workspace_tests"]
    require(len(workspace) == 93, "core_a3_inventory_differs")
    for identity, value in ADDED_HARNESSES.items():
        require(type(workspace.get(identity)) is dict and workspace[identity] == value
                and all(type(word) is int for word in workspace[identity].values()),
                "core_a3_inventory_differs")
    for identity, (_, value) in CHANGED_HARNESSES.items():
        require(type(workspace.get(identity)) is dict and workspace[identity] == value
                and all(type(word) is int for word in workspace[identity].values()),
                "core_a3_inventory_differs")
    previous = copy.deepcopy(declared)
    prior = previous["harness_test_counts"]["workspace_tests"]
    for identity in ADDED_HARNESSES:
        del prior[identity]
    for identity, (value, _) in CHANGED_HARNESSES.items():
        prior[identity] = copy.deepcopy(value)
    require(digest(previous) == PRE_CORE_A3_CORPUS_SHA256, "core_a3_inventory_differs")
    require_current_core_a3_sources()
    return previous
