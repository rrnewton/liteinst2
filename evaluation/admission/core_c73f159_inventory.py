"""Closed historical projection for the incoming c73 core source.

Test fixtures only: current drivers require the full current corpus. Seventeen
literal declarations compile into thirty-two workspace instances through the
explicit shared planning-profile ancestry. No native result is manufactured.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
from core_ae149a9_inventory import source_before_core_ae149a9

PRE_CORE_C73F159_CORPUS_SHA256 = 'bf3808f67ced232b2f72d1b4bbb4fcd68224358d373f79b3cf8d58bf235a08fa'
CURRENT_CORE_C73F159_CORPUS_SHA256 = '2dc2a498feb6349785a15691410db411932f9bd902d3585a86248f0c9b122970'
CHANGED_HARNESSES = {'test/a2_oracle': ({'ignored': 0, 'tests': 40}, {'ignored': 0, 'tests': 41}),
 'test/boundary_signal_oracle': ({'ignored': 0, 'tests': 27}, {'ignored': 0, 'tests': 28}),
 'test/call_return_oracle': ({'ignored': 0, 'tests': 27}, {'ignored': 0, 'tests': 28}),
 'test/controlled_oracle': ({'ignored': 0, 'tests': 27}, {'ignored': 0, 'tests': 28}),
 'test/entry_paths_oracle': ({'ignored': 0, 'tests': 27}, {'ignored': 0, 'tests': 28}),
 'test/eviction_chain_extensions': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 29}),
 'test/eviction_chain_oracle': ({'ignored': 0, 'tests': 29}, {'ignored': 0, 'tests': 30}),
 'test/exception_landing': ({'ignored': 0, 'tests': 27}, {'ignored': 0, 'tests': 28}),
 'test/integration': ({'ignored': 0, 'tests': 14}, {'ignored': 0, 'tests': 19}),
 'test/mandatory_prefix_oracle': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 29}),
 'test/neighbor_eviction_oracle': ({'ignored': 0, 'tests': 70}, {'ignored': 0, 'tests': 72}),
 'test/parked_context_oracle': ({'ignored': 0, 'tests': 27}, {'ignored': 0, 'tests': 28}),
 'test/prefixed_pun_oracle': ({'ignored': 0, 'tests': 27}, {'ignored': 0, 'tests': 28}),
 'test/quiescent_oracle': ({'ignored': 0, 'tests': 30}, {'ignored': 0, 'tests': 31}),
 'test/rel32_endpoint_oracle': ({'ignored': 0, 'tests': 27}, {'ignored': 0, 'tests': 28}),
 'test/successor_eviction_oracle': ({'ignored': 0, 'tests': 31}, {'ignored': 0, 'tests': 32}),
 'unit/liteinst_rewrite/lib': ({'ignored': 0, 'tests': 76}, {'ignored': 0, 'tests': 79}),
 'unit/verify_common_core/verify_common_core': ({'ignored': 0, 'tests': 3}, {'ignored': 0, 'tests': 11})}
RUST_METHODS = {'tests/support/cross_function_neighbor_oracle.rs': ('native_foreign_neighbor_two_owners_all_heads_both_seeds',),
 'tests/support/e9_common_planning_profile.rs': ('exact_caller_profile_and_whole_marker_must_agree',),
 'tools/elf-rewrite/examples/support/common_core_foreign.rs': ('two_declared_owners_keep_current_reads_and_callback_free_id57',
                                                               'missing_conflicting_or_incomplete_owner_cannot_supply_a_victim',
                                                               'full_current_reads_cannot_shrink_or_revert_inherited_edits',
                                                               'changed_original_in_either_displaced_interval_refuses_before_pair_writes',
                                                               'entry_dependency_role_and_original_boundary_mutations_refuse',
                                                               'selected_relay_and_both_e9_targets_are_exact',
                                                               'auxiliary_hook_operation_bytes_and_continuation_are_not_exempted'),
 'tools/elf-rewrite/src/neighbor_catalogue.rs': ('conditional_targets_and_fallthrough_bound_the_actual_blocks',
                                                 'foreign_interior_and_unowned_successors_are_refused',
                                                 'direct_calls_split_blocks_without_granting_callee_ownership'),
 'tools/elf-rewrite/tests/support/owned_neighbors.rs': ('opt_in_keeps_both_selected_hooks_and_foreign_victim_is_auxiliary',
                                                        'missing_foreign_head_or_unresolved_resume_keeps_full_failed_report',
                                                        'declared_block_must_match_the_decoded_control_flow',
                                                        'forced_unknown_victim_and_zero_original_budget_do_not_substitute',
                                                        'duplicate_function_declarations_must_agree_on_entry_provenance')}
COMPILED_METHODS = ({'harness': 'test/neighbor_eviction_oracle',
  'path': 'tests/support/cross_function_neighbor_oracle.rs',
  'test': 'cross_function_native::native_foreign_neighbor_two_owners_all_heads_both_seeds'},
 {'harness': 'test/a2_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/boundary_signal_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/call_return_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/controlled_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/entry_paths_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/eviction_chain_extensions',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/eviction_chain_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/mandatory_prefix_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/neighbor_eviction_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/parked_context_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/prefixed_pun_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/quiescent_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/rel32_endpoint_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/successor_eviction_oracle',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'test/exception_landing',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tests/support/e9_common_planning_profile.rs',
  'test': 'planning_profile::tests::exact_caller_profile_and_whole_marker_must_agree'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_foreign.rs',
  'test': 'common_core_foreign::tests::two_declared_owners_keep_current_reads_and_callback_free_id57'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_foreign.rs',
  'test': 'common_core_foreign::tests::missing_conflicting_or_incomplete_owner_cannot_supply_a_victim'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_foreign.rs',
  'test': 'common_core_foreign::tests::full_current_reads_cannot_shrink_or_revert_inherited_edits'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_foreign.rs',
  'test': 'common_core_foreign::tests::changed_original_in_either_displaced_interval_refuses_before_pair_writes'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_foreign.rs',
  'test': 'common_core_foreign::tests::entry_dependency_role_and_original_boundary_mutations_refuse'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_foreign.rs',
  'test': 'common_core_foreign::tests::selected_relay_and_both_e9_targets_are_exact'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_foreign.rs',
  'test': 'common_core_foreign::tests::auxiliary_hook_operation_bytes_and_continuation_are_not_exempted'},
 {'harness': 'unit/liteinst_rewrite/lib',
  'path': 'tools/elf-rewrite/src/neighbor_catalogue.rs',
  'test': 'neighbor_catalogue::tests::conditional_targets_and_fallthrough_bound_the_actual_blocks'},
 {'harness': 'unit/liteinst_rewrite/lib',
  'path': 'tools/elf-rewrite/src/neighbor_catalogue.rs',
  'test': 'neighbor_catalogue::tests::foreign_interior_and_unowned_successors_are_refused'},
 {'harness': 'unit/liteinst_rewrite/lib',
  'path': 'tools/elf-rewrite/src/neighbor_catalogue.rs',
  'test': 'neighbor_catalogue::tests::direct_calls_split_blocks_without_granting_callee_ownership'},
 {'harness': 'test/integration',
  'path': 'tools/elf-rewrite/tests/support/owned_neighbors.rs',
  'test': 'owned_neighbors::opt_in_keeps_both_selected_hooks_and_foreign_victim_is_auxiliary'},
 {'harness': 'test/integration',
  'path': 'tools/elf-rewrite/tests/support/owned_neighbors.rs',
  'test': 'owned_neighbors::missing_foreign_head_or_unresolved_resume_keeps_full_failed_report'},
 {'harness': 'test/integration',
  'path': 'tools/elf-rewrite/tests/support/owned_neighbors.rs',
  'test': 'owned_neighbors::declared_block_must_match_the_decoded_control_flow'},
 {'harness': 'test/integration',
  'path': 'tools/elf-rewrite/tests/support/owned_neighbors.rs',
  'test': 'owned_neighbors::forced_unknown_victim_and_zero_original_budget_do_not_substitute'},
 {'harness': 'test/integration',
  'path': 'tools/elf-rewrite/tests/support/owned_neighbors.rs',
  'test': 'owned_neighbors::duplicate_function_declarations_must_agree_on_entry_provenance'})
SOURCE_SHA256 = {'Cargo.toml': 'cc8da284807082bbe47c265a4830ffced4bd173f95a9e2571ecdec6f568130c6',
 'tests/a2_oracle.rs': '3dc3b782e8530f93129f22591c91db04c5ce76a2a15caa443022a7db9da97c50',
 'tests/boundary_signal_oracle.rs': '44898d3621b5982f1d396f337299816934510c9796d3eec98c7a0b2567ed1a00',
 'tests/call_return_oracle.rs': '54dd4a1c895ed7a71255b8c03b0edf525ada18dbf5a19dae8a05e2ab06077a93',
 'tests/controlled_oracle.rs': 'bb00ae7c089d3fa433506a0cf87cc33a7c0a64baefad8961b4d9287613380a7f',
 'tests/entry_paths_oracle.rs': '05a95a08e9e2de68db391f6b3b50aa461748aef993854cb328e33a1176312b50',
 'tests/eviction_chain_extensions.rs': '65bc955f0ab2a5653885a7844f3e97475aa80f42b8afa69c7ed7f3e85e80b33d',
 'tests/eviction_chain_oracle.rs': '841e2d0c1ed09c2373f0c616426392a81c3aa7a2001b43110c3e2d16a07b4d23',
 'tests/mandatory_prefix_oracle.rs': 'e093dd101451d136f73faee279365fa48fe48c89b560cb9b0ce65b03cff77b2b',
 'tests/neighbor_eviction_oracle.rs': '5b1f6d6a001d92d0ebf96b7d3f0f679ddd0506a73971901c7898af68865255eb',
 'tests/parked_context_oracle.rs': 'ef571fae32d7095f97b58dbec97ba10f77160fcb3098b7bae76703763d7f6341',
 'tests/prefixed_pun_oracle.rs': 'c1538a91a3c34f8e743c459867883402a7f235e1457490ada8c805f36a921296',
 'tests/quiescent_oracle.rs': 'cd7ff42dd50da089f13ca538d09d8057f68dab93ff882ef24ed9b05825d1f8e2',
 'tests/rel32_endpoint_oracle.rs': 'cf00e1bf1f17a1fd3d7c8a65e790d8c7db0f11162d95409bed5e466f9be35642',
 'tests/successor_eviction_oracle.rs': 'caa94cbd108de7b984057cb589c09dcb365977e7446e6f2632c8bbf1ac1b5ad5',
 'tests/support/cross_function_neighbor_oracle.rs': '0c29abab39b6948e89840350c715b04085fdfb679c7f06b2e2b45f07b1847182',
 'tests/support/e9_common_core.rs': '16d6bde706f4ebad1147916ed8e1f968ad394f0ad9ddca910a87306e31827635',
 'tests/support/e9_common_image.rs': '99a4c285c1335a399800f692d63b03053c0b43d844b608e03236308d47f3d525',
 'tests/support/e9_common_planning_profile.rs': '873bfbd50f2878e37bbef91193db4726faed18af5dacf395b1726882e637dcf5',
 'tests/support/elf_exec_oracle.rs': '1302da90836b31f9346cff5c20a458f4e5b3134b0f529e21f5027f78e4764c6b',
 'tests/support/quiescent_oracle.rs': 'e8c17e5daaf6e9720d6c515fd5e6f986307eca9c12ce115cdd51b465406dc756',
 'tools/elf-rewrite/Cargo.toml': 'efa2528a5905f3a0d4d4424dfedff8d5fcba7365a03d63f969b4a613629e544f',
 'tools/elf-rewrite/examples/support/common_core_foreign.rs': '8942cae7f6948e05ae838c294eda690e2859e9a92289a6bcafb34ac1a8067e2c',
 'tools/elf-rewrite/examples/verify_common_core.rs': 'c49b710e7f07511f4a3dfc67aa1f016912120af97d4ae623ea14bb3ab2da4626',
 'tools/elf-rewrite/src/lib.rs': '8d918e27afb71ec808cb0cf794ccdab175643fe433ebd86e8d52d7aaa4b552c5',
 'tools/elf-rewrite/src/main.rs': 'e8afc63d3205f8c8d68bc0851d19efed8061a219ce7193f64c6fde0866e7a6d2',
 'tools/elf-rewrite/src/neighbor_catalogue.rs': '4ece0f34bb910e7f627a41c514a1ec7b90c7a321e9952484cfda1393b7f76b7d',
 'tools/elf-rewrite/tests/integration.rs': '714d6efdc0e52d63bae2a94a89f3070c5b784358e94ef41d1fd2773e51a35166',
 'tools/elf-rewrite/tests/support/owned_neighbors.rs': '1374b4efeb3e285f6df0713b6ed2de94874d99a8ad1b834abd3d9c3472bc4e31',
 'tools/exception-oracle/Cargo.toml': '09a149ab9dd290ae2fc3e8938b9af4d898783319ed32932e9528fc8e7b6e05db',
 'tools/exception-oracle/tests/exception_landing.rs': '0218bd7bc9a45606e8d1a2531b3e457c394ef1fd86fa17efbe1812614be2548b'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_current_core_c73f159_sources():
    root = Path(__file__).resolve().parents[2]
    for path, expected_hash in SOURCE_SHA256.items():
        try:
            data = (root / path).read_bytes()
            data = source_before_core_ae149a9(path, data)
            source = data.decode("utf-8")
        except (OSError, UnicodeError):
            require(False, "core_c73f159_source_inventory_differs")
        require(hashlib.sha256(data).hexdigest() == expected_hash,
                "core_c73f159_source_inventory_differs")
        if path in RUST_METHODS:
            require(re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
                    == list(RUST_METHODS[path])
                    and not re.search(r"#\[ignore(?:\]|\()", source),
                    "core_c73f159_source_inventory_differs")


def before_core_c73f159(declared):
    """Authenticate the whole2232 corpus before recovering the exact2200 one."""
    require(type(declared) is dict and digest(declared) == CURRENT_CORE_C73F159_CORPUS_SHA256,
            "core_c73f159_inventory_differs")
    workspace = declared["harness_test_counts"]["workspace_tests"]
    require(len(workspace) == 95, "core_c73f159_inventory_differs")
    for identity, (_, current) in CHANGED_HARNESSES.items():
        observed = workspace[identity]
        require(type(observed) is dict and observed == current
                and all(type(value) is int for value in observed.values()),
                "core_c73f159_inventory_differs")
    previous = copy.deepcopy(declared)
    for identity, (prior, _) in CHANGED_HARNESSES.items():
        previous["harness_test_counts"]["workspace_tests"][identity] = copy.deepcopy(prior)
    require(digest(previous) == PRE_CORE_C73F159_CORPUS_SHA256,
            "core_c73f159_inventory_differs")
    require_current_core_c73f159_sources()
    return previous
