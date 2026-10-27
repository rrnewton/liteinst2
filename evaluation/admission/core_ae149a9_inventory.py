"""Closed historical corpus/source projection for the incoming ae149a9 core.

Test fixtures only. Five literal declarations compile into35 distinct workspace
instances. Current drivers still require the entire current corpus. No native
result or successful qualification is manufactured here.
"""

import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
from inprocess_inventory import source_before_inprocess

PRE_CORE_AE149A9_CORPUS_SHA256 = '2dc2a498feb6349785a15691410db411932f9bd902d3585a86248f0c9b122970'
CURRENT_CORE_AE149A9_CORPUS_SHA256 = 'b330c13e03db56ff7c6a34c121cd41e91d58c92928f71441b4427a771ecfbe3d'
CHANGED_HARNESSES = {'test/a2_oracle': ({'ignored': 0, 'tests': 41}, {'ignored': 0, 'tests': 43}),
 'test/boundary_signal_oracle': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 30}),
 'test/call_return_oracle': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 30}),
 'test/controlled_oracle': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 30}),
 'test/entry_paths_oracle': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 30}),
 'test/eviction_chain_extensions': ({'ignored': 0, 'tests': 29}, {'ignored': 0, 'tests': 31}),
 'test/eviction_chain_oracle': ({'ignored': 0, 'tests': 30}, {'ignored': 0, 'tests': 32}),
 'test/exception_landing': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 30}),
 'test/mandatory_prefix_oracle': ({'ignored': 0, 'tests': 29}, {'ignored': 0, 'tests': 31}),
 'test/neighbor_eviction_oracle': ({'ignored': 0, 'tests': 72}, {'ignored': 0, 'tests': 74}),
 'test/parked_context_oracle': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 30}),
 'test/prefixed_pun_oracle': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 30}),
 'test/quiescent_oracle': ({'ignored': 0, 'tests': 31}, {'ignored': 0, 'tests': 33}),
 'test/rel32_endpoint_oracle': ({'ignored': 0, 'tests': 28}, {'ignored': 0, 'tests': 30}),
 'test/successor_eviction_oracle': ({'ignored': 0, 'tests': 32}, {'ignored': 0, 'tests': 34}),
 'unit/verify_common_core/verify_common_core': ({'ignored': 0, 'tests': 11}, {'ignored': 0, 'tests': 16})}
RUST_METHODS = {'tests/support/e9_common_router_contract.rs': ('exact_legacy_and_invalid_evex_markers',
                                                'route_identity_and_explicit_opt_in'),
 'tools/elf-rewrite/examples/support/common_core_router.rs': ('plan_wide_two_image_requirements_and_mutations',
                                                              'whole_original_b1_route_and_current_read_are_authenticated',
                                                              'legacy_and_duplicate_router_records_refuse')}
COMPILED_METHODS = ({'harness': 'test/a2_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/a2_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/boundary_signal_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/boundary_signal_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/call_return_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/call_return_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/controlled_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/controlled_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/entry_paths_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/entry_paths_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/eviction_chain_extensions',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/eviction_chain_extensions',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/eviction_chain_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/eviction_chain_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/mandatory_prefix_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/mandatory_prefix_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/neighbor_eviction_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/neighbor_eviction_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/parked_context_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/parked_context_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/prefixed_pun_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/prefixed_pun_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/quiescent_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/quiescent_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/rel32_endpoint_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/rel32_endpoint_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/successor_eviction_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/successor_eviction_oracle',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'test/exception_landing',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'test/exception_landing',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'oracle::elf_exec_oracle::common_image::core_pair::router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'router_contract::tests::exact_legacy_and_invalid_evex_markers'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tests/support/e9_common_router_contract.rs',
  'test': 'router_contract::tests::route_identity_and_explicit_opt_in'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_router.rs',
  'test': 'common_core_router::tests::plan_wide_two_image_requirements_and_mutations'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_router.rs',
  'test': 'common_core_router::tests::whole_original_b1_route_and_current_read_are_authenticated'},
 {'harness': 'unit/verify_common_core/verify_common_core',
  'path': 'tools/elf-rewrite/examples/support/common_core_router.rs',
  'test': 'common_core_router::tests::legacy_and_duplicate_router_records_refuse'})
SOURCE_SHA256 = {'Cargo.lock': 'd8f447b6869ecbb2638a96a82034e1c6485a00d4e0406ff547715e5d67db51b8',
 'Cargo.toml': 'cc8da284807082bbe47c265a4830ffced4bd173f95a9e2571ecdec6f568130c6',
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
 'tests/support/e9_common_core.rs': 'e40a441970517aa0c0a32a9f5222480bea64ee554e3eb5b2a147d5b5dde5b88b',
 'tests/support/e9_common_image.rs': '99a4c285c1335a399800f692d63b03053c0b43d844b608e03236308d47f3d525',
 'tests/support/e9_common_planning_profile.rs': '873bfbd50f2878e37bbef91193db4726faed18af5dacf395b1726882e637dcf5',
 'tests/support/e9_common_router_contract.rs': '117e56b69a8f6020e8a9eadcf0802dbf5ab0fd2a84893be4dbbf3a7d8a582cfb',
 'tests/support/e9_common_router_controls.rs': '4104cce63784b34d4a572799da60f80d824a75aaf50394138596a59185ce1d1d',
 'tests/support/e9_common_router_native.rs': '4e793a2f48588060fb827807a882461e7f23a3dcd81d86d568facec08c5108d8',
 'tests/support/elf_exec_driver.rs': '25f5ba3d2b47b7ffd525f3a5398b93d83f5e06ea14ceaecddd45b16dceae6130',
 'tests/support/elf_exec_oracle.rs': '1302da90836b31f9346cff5c20a458f4e5b3134b0f529e21f5027f78e4764c6b',
 'tests/support/quiescent_oracle.rs': 'e8c17e5daaf6e9720d6c515fd5e6f986307eca9c12ce115cdd51b465406dc756',
 'tools/elf-rewrite/Cargo.toml': 'efa2528a5905f3a0d4d4424dfedff8d5fcba7365a03d63f969b4a613629e544f',
 'tools/elf-rewrite/examples/support/common_core_foreign.rs': '8942cae7f6948e05ae838c294eda690e2859e9a92289a6bcafb34ac1a8067e2c',
 'tools/elf-rewrite/examples/support/common_core_router.rs': '1ee59854e36795fc1df5e0eb4443724075c9ac5d0b884661ff91f67582472cda',
 'tools/elf-rewrite/examples/verify_common_core.rs': 'f7f1021a80c0aa4992364ca356db9af1fb2f77edf56e1638efde7e591fc73cb1',
 'tools/elf-rewrite/src/lib.rs': '8d918e27afb71ec808cb0cf794ccdab175643fe433ebd86e8d52d7aaa4b552c5',
 'tools/elf-rewrite/src/main.rs': 'e8afc63d3205f8c8d68bc0851d19efed8061a219ce7193f64c6fde0866e7a6d2',
 'tools/elf-rewrite/src/neighbor_catalogue.rs': '4ece0f34bb910e7f627a41c514a1ec7b90c7a321e9952484cfda1393b7f76b7d',
 'tools/elf-rewrite/tests/integration.rs': '714d6efdc0e52d63bae2a94a89f3070c5b784358e94ef41d1fd2773e51a35166',
 'tools/elf-rewrite/tests/support/owned_neighbors.rs': '1374b4efeb3e285f6df0713b6ed2de94874d99a8ad1b834abd3d9c3472bc4e31',
 'tools/exception-oracle/Cargo.toml': '13fde0b76cea61d1caecf580626d185ee30286278f5da92b6c4bea4995f207ee',
 'tools/exception-oracle/tests/exception_landing.rs': '0218bd7bc9a45606e8d1a2531b3e457c394ef1fd86fa17efbe1812614be2548b'}
SOURCE_PROJECTIONS = {'tests/support/e9_common_core.rs': {'current_sha256': 'e40a441970517aa0c0a32a9f5222480bea64ee554e3eb5b2a147d5b5dde5b88b',
                                     'inverse': ((8,
                                                  18,
                                                  '',
                                                  '#[path = "e9_common_router_contract.rs"]\n'
                                                  'mod router_contract;\n'
                                                  '#[path = "e9_common_router_native.rs"]\n'
                                                  'mod router_native;\n'
                                                  'use router_contract::{Route, RouterMode};\n'
                                                  '#[path = "e9_common_router_controls.rs"]\n'
                                                  'mod router_controls;\n'
                                                  'pub fn router_controls_main() {\n'
                                                  '    router_controls::main();\n'
                                                  '}\n'),
                                                 (70, 71, '', '    trap: bool,\n'),
                                                 (87, 88, '', '    routes: Vec<Route>,\n'),
                                                 (96, 97, '', '        router: RouterMode,\n'),
                                                 (225,
                                                  287,
                                                  '',
                                                  '        let mut routes = Vec::new();\n'
                                                  '        if router.enabled() {\n'
                                                  '            assert_eq!(\n'
                                                  '                rows[cursor],\n'
                                                  '                vec!["router-profile", '
                                                  'router_contract::PROFILE]\n'
                                                  '            );\n'
                                                  '            cursor += 1;\n'
                                                  '            while rows[cursor][0] == "router" {\n'
                                                  '                let r = &rows[cursor];\n'
                                                  '                assert_eq!(r.len(), 6);\n'
                                                  '                routes.push(Route {\n'
                                                  '                    pc: number(r[1]),\n'
                                                  '                    target: number(r[2]),\n'
                                                  '                    source_start: number(r[3]),\n'
                                                  '                    source_end: number(r[4]),\n'
                                                  '                    fetch: bytes(r[5]),\n'
                                                  '                });\n'
                                                  '                cursor += 1;\n'
                                                  '            }\n'
                                                  '        }\n'
                                                  '        router_contract::check_routes(&routes);\n'
                                                  '        let ledger: Vec<Vec<_>> = '
                                                  'text(get("plan-ledger.tsv"))\n'
                                                  '            .lines()\n'
                                                  "            .map(|r| r.split('\\t').collect())\n"
                                                  '            .collect();\n'
                                                  '        let declared: Vec<_> = ledger\n'
                                                  '            .iter()\n'
                                                  '            .filter(|r| r[0] == "entry-router-required")\n'
                                                  '            .map(|r| {\n'
                                                  '                assert_eq!(r.len(), 5);\n'
                                                  '                (number(r[3]), number(r[4]))\n'
                                                  '            })\n'
                                                  '            .collect();\n'
                                                  '        assert_eq!(declared.len(), routes.len());\n'
                                                  '        assert_eq!(\n'
                                                  '            '
                                                  'declared.into_iter().collect::<BTreeSet<_>>(),\n'
                                                  '            routes.iter().map(|r| (r.pc, '
                                                  'r.target)).collect()\n'
                                                  '        );\n'
                                                  '        for route in &routes {\n'
                                                  '            let source = seed::ORIGINAL_RANGES\n'
                                                  '                .iter()\n'
                                                  '                .find(|r| {\n'
                                                  '                    r.pc == route.source_start && r.pc + '
                                                  'r.bytes.len() as u64 == route.source_end\n'
                                                  '                })\n'
                                                  '                .unwrap();\n'
                                                  '            assert!(source.pc <= route.pc && route.pc < '
                                                  'source.pc + source.bytes.len() as u64);\n'
                                                  '            assert!(\n'
                                                  '                seed::HEADS\n'
                                                  '                    .iter()\n'
                                                  '                    .any(|h| h.pc == route.pc && '
                                                  '!matches!(h.flow, seed::Flow::Call(_)))\n'
                                                  '            );\n'
                                                  '            assert_eq!(\n'
                                                  '                ledger\n'
                                                  '                    .iter()\n'
                                                  '                    .filter(|r| r[0] == "route"\n'
                                                  '                        && number(r[2]) == route.pc\n'
                                                  '                        && number(r[3]) == route.target)\n'
                                                  '                    .count(),\n'
                                                  '                1\n'
                                                  '            );\n'
                                                  '        }\n'
                                                  '        let mut used_routes = BTreeSet::new();\n'),
                                                 (300,
                                                  301,
                                                  '            while rows[cursor][0] == "walk" {\n',
                                                  '            while rows[cursor][0] == "walk" || '
                                                  '(router.enabled() && rows[cursor][0] == "trap") {\n'),
                                                 (308,
                                                  322,
                                                  '                walk.push(Walk { pc, next, bytes: b });\n',
                                                  '                let trap = r[0] == "trap";\n'
                                                  '                if trap {\n'
                                                  '                    assert_eq!(pc, src.pc);\n'
                                                  '                    assert!(walk.is_empty());\n'
                                                  '                    let route = routes.iter().find(|r| '
                                                  'r.pc == pc).unwrap();\n'
                                                  '                    assert_eq!((next, b.as_slice()), '
                                                  '(route.target, route.fetch.as_slice()));\n'
                                                  '                    assert!(used_routes.insert(pc));\n'
                                                  '                }\n'
                                                  '                walk.push(Walk {\n'
                                                  '                    trap,\n'
                                                  '                    pc,\n'
                                                  '                    next,\n'
                                                  '                    bytes: b,\n'
                                                  '                });\n'),
                                                 (344,
                                                  345,
                                                  '',
                                                  '        assert_eq!(used_routes, routes.iter().map(|r| '
                                                  'r.pc).collect());\n'),
                                                 (350, 351, '', '            routes,\n'),
                                                 (352,
                                                  357,
                                                  '',
                                                  '        for route in &out.routes {\n'
                                                  '            assert!(out.pages.iter().any(|p| p.flags == '
                                                  '5\n'
                                                  '                && p.address <= route.target\n'
                                                  '                && route.target < p.address + 4096));\n'
                                                  '        }\n'),
                                                 (576,
                                                  578,
                                                  '',
                                                  '    let router = (!versions.candidate.routes.is_empty())\n'
                                                  '        .then(|| '
                                                  'router_native::Router::new(&versions.candidate.routes));\n'),
                                                 (599,
                                                  605,
                                                  '',
                                                  '    if let Some(router) = &router {\n'
                                                  '        '
                                                  'trace.write_all(router.descriptor().as_bytes()).unwrap();\n'
                                                  '    }\n'
                                                  '    if let Some(router) = &router {\n'
                                                  '        router.observed(&child, "before", &mut trace);\n'
                                                  '    }\n'),
                                                 (617,
                                                  631,
                                                  '        step(&child, &mut steps);\n',
                                                  '        if w.trap {\n'
                                                  '            let route = versions\n'
                                                  '                .candidate\n'
                                                  '                .routes\n'
                                                  '                .iter()\n'
                                                  '                .find(|r| r.pc == w.pc)\n'
                                                  '                .unwrap();\n'
                                                  '            router\n'
                                                  '                .as_ref()\n'
                                                  '                .unwrap()\n'
                                                  '                .deliver(&child, route, &mut steps, &mut '
                                                  'trace);\n'
                                                  '        } else {\n'
                                                  '            step(&child, &mut steps);\n'
                                                  '        }\n'),
                                                 (632,
                                                  644,
                                                  '        writeln!(&mut trace, "prefix\\t{}\\t{}\\t{}", '
                                                  'w.pc, next, hex(&w.bytes)).unwrap();\n',
                                                  '        if w.trap {\n'
                                                  '            writeln!(\n'
                                                  '                &mut trace,\n'
                                                  '                "trap-prefix\\t{}\\t{}\\t{}",\n'
                                                  '                w.pc,\n'
                                                  '                next,\n'
                                                  '                hex(&w.bytes)\n'
                                                  '            )\n'
                                                  '            .unwrap();\n'
                                                  '        } else {\n'
                                                  '            writeln!(&mut trace, "prefix\\t{}\\t{}\\t{}", '
                                                  'w.pc, next, hex(&w.bytes)).unwrap();\n'
                                                  '        }\n'),
                                                 (682,
                                                  685,
                                                  '',
                                                  '    if let Some(router) = &router {\n'
                                                  '        router.observed(&child, "after", &mut trace);\n'
                                                  '    }\n'),
                                                 (725,
                                                  726,
                                                  '',
                                                  '    let router = RouterMode::arguments(&mut args);\n'),
                                                 (739,
                                                  740,
                                                  '',
                                                  '    let bootstrap = '
                                                  'router.enabled().then(router_native::Bootstrap::new);\n'),
                                                 (751, 752, '', '        router,\n'),
                                                 (925, 926, '', '    drop(bootstrap);\n')),
                                     'previous_sha256': '16d6bde706f4ebad1147916ed8e1f968ad394f0ad9ddca910a87306e31827635'},
 'tools/elf-rewrite/examples/verify_common_core.rs': {'current_sha256': 'f7f1021a80c0aa4992364ca356db9af1fb2f77edf56e1638efde7e591fc73cb1',
                                                      'inverse': ((23,
                                                                   28,
                                                                   '',
                                                                   '#[path = '
                                                                   '"support/common_core_router.rs"]\n'
                                                                   'mod common_core_router;\n'
                                                                   '#[path = '
                                                                   '"../../../tests/support/e9_common_router_contract.rs"]\n'
                                                                   'mod router_contract;\n'
                                                                   'use router_contract::RouterMode;\n'),
                                                                  (389,
                                                                   390,
                                                                   'fn ledger_shape(rows: &[Vec<&str>]) {\n',
                                                                   'fn ledger_shape(rows: &[Vec<&str>], '
                                                                   'router: RouterMode) {\n'),
                                                                  (407,
                                                                   408,
                                                                   '',
                                                                   '            "entry-router-required" if '
                                                                   'router.enabled() => 5,\n'),
                                                                  (921,
                                                                   922,
                                                                   '',
                                                                   '    let router = '
                                                                   'RouterMode::arguments(&mut args);\n'),
                                                                  (1338,
                                                                   1339,
                                                                   '    ledger_shape(&r);\n',
                                                                   '    ledger_shape(&r, router);\n'),
                                                                  (1356,
                                                                   1360,
                                                                   '    assert!(!r.iter().any(|x| x[0] == '
                                                                   '"entry-router-required"));\n',
                                                                   '    if !router.enabled() {\n'
                                                                   '        assert!(!r.iter().any(|x| x[0] '
                                                                   '== "entry-router-required"));\n'
                                                                   '    }\n'
                                                                   '    let router_declarations = '
                                                                   'common_core_router::declarations(router, '
                                                                   '&r);\n'),
                                                                  (1394,
                                                                   1411,
                                                                   '        assert_eq!(&live[0][3..], '
                                                                   '["true", "true", "false"]);\n',
                                                                   '        let routed_step = '
                                                                   'router_declarations\n'
                                                                   '            .iter()\n'
                                                                   '            .any(|x| (x.0, x.1) == '
                                                                   '(n(step[1]), n(step[2])));\n'
                                                                   '        if routed_step {\n'
                                                                   '            assert!(router.enabled());\n'
                                                                   '            assert_eq!(&live[0][3..], '
                                                                   '["true", "true", "true"]);\n'
                                                                   '            common_core_router::step(\n'
                                                                   '                &r,\n'
                                                                   '                step,\n'
                                                                   '                &router_declarations,\n'
                                                                   '                &old,\n'
                                                                   '                &original.bytes,\n'
                                                                   '                &overlay,\n'
                                                                   '            );\n'
                                                                   '        } else {\n'
                                                                   '            assert_eq!(&live[0][3..], '
                                                                   '["true", "true", "false"]);\n'
                                                                   '        }\n'),
                                                                  (1488,
                                                                   1489,
                                                                   '',
                                                                   '                | '
                                                                   '"entry-router-required"\n'),
                                                                  (1857,
                                                                   1858,
                                                                   '        let mut requirements: Vec<_> = '
                                                                   'r\n'
                                                                   '            .iter()\n'
                                                                   '            .filter(|x| x[0] == '
                                                                   '"unmet-requirement" && n(x[1]) == id)\n'
                                                                   '            .map(|x| (n(x[2]), '
                                                                   'n(x[3])))\n'
                                                                   '            .collect();\n'
                                                                   '        requirements.sort();\n'
                                                                   '        let mut expected: Vec<_> = [1, '
                                                                   '2, 3, 4, 7, 8].map(|v| (v, '
                                                                   '0)).to_vec();\n'
                                                                   '        if hooks > 0 {\n'
                                                                   '            expected.push((5, 2));\n'
                                                                   '        }\n'
                                                                   '        expected.sort();\n'
                                                                   '        assert_eq!(requirements, '
                                                                   'expected);\n',
                                                                   '        '
                                                                   'common_core_router::requirements(&r, id, '
                                                                   'hooks, router, &router_declarations);\n'),
                                                                  (1947,
                                                                   1949,
                                                                   '',
                                                                   '    let router_routes =\n'
                                                                   '        '
                                                                   'common_core_router::authenticate(&r, '
                                                                   '&router_declarations, &all_heads, '
                                                                   '&elf);\n'),
                                                                  (2051,
                                                                   2067,
                                                                   '',
                                                                   '    if router.enabled() {\n'
                                                                   '        writeln!(&mut witness, '
                                                                   '"router-profile\\t{}", '
                                                                   'router_contract::PROFILE).unwrap();\n'
                                                                   '        for route in &router_routes {\n'
                                                                   '            writeln!(\n'
                                                                   '                &mut witness,\n'
                                                                   '                '
                                                                   '"router\\t{}\\t{}\\t{}\\t{}\\t{}",\n'
                                                                   '                route.pc,\n'
                                                                   '                route.target,\n'
                                                                   '                route.source_start,\n'
                                                                   '                route.source_end,\n'
                                                                   '                hex(&route.fetch)\n'
                                                                   '            )\n'
                                                                   '            .unwrap();\n'
                                                                   '        }\n'
                                                                   '    }\n'
                                                                   '    let mut used_router_routes = '
                                                                   'BTreeSet::new();\n'),
                                                                  (2103,
                                                                   2115,
                                                                   '',
                                                                   '            if let Some(route) = '
                                                                   'router_routes.iter().find(|route| '
                                                                   'route.pc == at) {\n'
                                                                   '                '
                                                                   'assert!(router.enabled());\n'
                                                                   '                assert_eq!(\n'
                                                                   '                    at, src.pc,\n'
                                                                   '                    "router only at its '
                                                                   'authenticated original entry"\n'
                                                                   '                );\n'
                                                                   '                assert_eq!(route.target, '
                                                                   'head.route);\n'
                                                                   '                '
                                                                   'assert!(used_router_routes.insert(at));\n'
                                                                   '                gateway.push((at, '
                                                                   'route.target, route.fetch.clone()));\n'
                                                                   '                at = route.target;\n'
                                                                   '                continue;\n'
                                                                   '            }\n'),
                                                                  (2135,
                                                                   2140,
                                                                   '            writeln!(&mut witness, '
                                                                   '"walk\\t{}\\t{pc}\\t{next}\\t{}", '
                                                                   'src.pc, hex(&b)).unwrap();\n',
                                                                   '            if '
                                                                   'router_routes.iter().any(|route| '
                                                                   'route.pc == pc) {\n'
                                                                   '                writeln!(&mut witness, '
                                                                   '"trap\\t{}\\t{pc}\\t{next}\\t{}", '
                                                                   'src.pc, hex(&b)).unwrap();\n'
                                                                   '            } else {\n'
                                                                   '                writeln!(&mut witness, '
                                                                   '"walk\\t{}\\t{pc}\\t{next}\\t{}", '
                                                                   'src.pc, hex(&b)).unwrap();\n'
                                                                   '            }\n'),
                                                                  (2142,
                                                                   2146,
                                                                   '',
                                                                   '    assert_eq!(\n'
                                                                   '        used_router_routes,\n'
                                                                   '        router_routes.iter().map(|r| '
                                                                   'r.pc).collect()\n'
                                                                   '    );\n')),
                                                      'previous_sha256': 'c49b710e7f07511f4a3dfc67aa1f016912120af97d4ae623ea14bb3ab2da4626'},
 'tools/exception-oracle/Cargo.toml': {'current_sha256': '13fde0b76cea61d1caecf580626d185ee30286278f5da92b6c4bea4995f207ee',
                                       'inverse': ((8,
                                                    9,
                                                    '',
                                                    'iced-x86 = { version = "1.21.0", default-features = '
                                                    'false, features = ["std", "decoder"] }\n'),),
                                       'previous_sha256': '09a149ab9dd290ae2fc3e8938b9af4d898783319ed32932e9528fc8e7b6e05db'}}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_current_core_ae149a9_sources():
    root = Path(__file__).resolve().parents[2]
    for path, expected_hash in SOURCE_SHA256.items():
        try:
            data = (root / path).read_bytes()
            data = source_before_inprocess(path, data, "core_ae149a9_source_inventory_differs")
            source = data.decode("utf-8")
        except (OSError, UnicodeError):
            require(False, "core_ae149a9_source_inventory_differs")
        require(hashlib.sha256(data).hexdigest() == expected_hash,
                "core_ae149a9_source_inventory_differs")
        if path in RUST_METHODS:
            require(re.findall(r"#\[test\]\s*fn\s+([A-Za-z0-9_]+)\s*\(", source)
                    == list(RUST_METHODS[path])
                    and not re.search(r"#\[ignore(?:\]|\()", source),
                    "core_ae149a9_source_inventory_differs")


def source_before_core_ae149a9(path, data):
    """Recover exact prior bytes for only the three changed c73-bound paths.

    This ingest seam retains the old checker's fixed error category. It accepts
    only the new complete source hash, never arbitrary edits or old live bytes.
    The caller still applies every original old hash/declaration predicate.
    """
    if path not in SOURCE_PROJECTIONS:
        return data
    row = SOURCE_PROJECTIONS[path]
    error = "core_c73f159_source_inventory_differs"
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row["current_sha256"], error)
    lines = data.decode("utf-8").splitlines(keepends=True)
    for start, end, previous, current in reversed(row["inverse"]):
        require("".join(lines[start:end]) == current, error)
        lines[start:end] = previous.splitlines(keepends=True)
    previous = "".join(lines).encode("utf-8")
    require(hashlib.sha256(previous).hexdigest() == row["previous_sha256"], error)
    return previous


def before_core_ae149a9(declared):
    """Authenticate the full2267 corpus, then recover the exact2232 corpus."""
    require(type(declared) is dict and digest(declared) == CURRENT_CORE_AE149A9_CORPUS_SHA256,
            "core_ae149a9_inventory_differs")
    workspace = declared["harness_test_counts"]["workspace_tests"]
    require(len(workspace) == 95, "core_ae149a9_inventory_differs")
    for identity, (_, current) in CHANGED_HARNESSES.items():
        observed = workspace[identity]
        require(type(observed) is dict and observed == current
                and all(type(value) is int for value in observed.values()),
                "core_ae149a9_inventory_differs")
    previous = copy.deepcopy(declared)
    for identity, (prior, _) in CHANGED_HARNESSES.items():
        previous["harness_test_counts"]["workspace_tests"][identity] = copy.deepcopy(prior)
    require(digest(previous) == PRE_CORE_AE149A9_CORPUS_SHA256,
            "core_ae149a9_inventory_differs")
    require_current_core_ae149a9_sources()
    return previous
