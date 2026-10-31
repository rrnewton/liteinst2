"""Exact opt-in source transition; no extra default Rust execution is claimed."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_0fb574_inventory as current
import core_c712_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
import core_981419_inventory as latest


class Main0fb574InventoryTests(unittest.TestCase):
    def test_exact_native_startup_sources_catalog_and_refusals(self):
        actual = current.mainaf81.before_current(current.mainaf81.maindd75.before_current(latest.before_current(json.loads(Path(__file__).with_name('corpus.json').read_bytes()))))
        rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (106, 3861, 37))
        self.assertEqual(actual['recorder_tests'], 357)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual(old['recorder_tests'], 356)
        self.assertEqual(actual['harness_test_counts'], old['harness_test_counts'])
        self.assertEqual((len(actual['harness_test_counts']['serial_launch']),
                          sum(x['tests'] for x in actual['harness_test_counts']['serial_launch'].values())), (27, 1039))
        # Complete older proofs remain in their original recorder cases. This
        # new case authenticates the strict newest entry and source boundary.
        with patch.object(inventory, 'require_historical356') as earlier:
            self.assertIsNone(inventory.require_historical357(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_historical357(wrong)
        for value in (356, 358, True, 357.0):
            wrong = copy.deepcopy(actual); wrong['recorder_tests'] = value
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_inventory_differs$'):
                current.before_current(wrong)
        for field, values in (('tests', (398, 400, True, 399.0)), ('ignored', (0, 2, True, 1.0))):
            for value in values:
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/liteinst2/lib'][field] = value
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_inventory_differs$'):
                    current.before_current(wrong)
        for key in actual:
            wrong = dict(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_inventory_differs$'):
                current.before_current(wrong)
        identities = current.mainaf81.before_python(current.mainaf81.maindd75.before_python(latest.before_python(historical.python_identities(Path(__file__).parent))))
        self.assertEqual((len(identities), current.digest(identities)), (357, current.PYTHON_CURRENT))
        old_ids = current.before_python(identities)
        self.assertEqual((len(old_ids), current.digest(old_ids)), (356, previous.PYTHON_CURRENT))
        self.assertEqual(set(identities) - set(old_ids), {current.ADDED})
        for wrong in (old_ids, identities + [identities[0]], list(reversed(identities)),
                      [name + '_changed' if name == current.ADDED else name for name in identities]):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_python_inventory_differs$'):
                current.before_python(wrong)
        self.assertEqual(current.DATA['added_default_methods'], {})
        self.assertEqual(current.DATA['workspace_changes'], {})
        self.assertEqual(current.DATA['default_harness_changes'], 0)
        self.assertEqual(current.DATA['default_ignore_changes'], 0)
        self.assertEqual({path: len(names) for path, names in current.DATA['added_excluded_methods'].items()}, {
            'evaluation/offline-router-native/observer/src/tests.rs': 22,
            'evaluation/offline-router-native/observer/src/wire.rs': 4,
            'src/offline_router/host_identity_tests.rs': 15})
        self.assertEqual(current.DATA['excluded_default'], dict(observer_previous=30,
            observer_current=56, observer_manifest='evaluation/offline-router-native/observer/Cargo.toml',
            observer_independent_workspace=True, offline_router_previous=7,
            offline_router_current=22, required_feature='offline-router'))
        self.assertEqual(current.DATA['moved_helper'], dict(path='tests/support/isolated_native_test.rs',
            child='tests/support/bounded_proc_stat.rs', tests=0, ignored=0,
            old_parent='src/entry_router/imp/routed_jmp_native_tests.rs', new_parent='src/lib.rs'))
        read = Path.read_bytes
        for kind, function in (('projections', current.source_before),
                               ('evaluation_projections', current.source_before_evaluation)):
            for path, row in current.DATA[kind].items():
                raw = read(current.ROOT / path)
                restored = function(path, raw, 'startup_inverse_control')
                self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
                for wrong in (raw + b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^startup_inverse_control$'):
                        function(path, wrong, 'startup_inverse_control')
        for path in current.DATA['methods']:
            target = current.ROOT / path; raw = read(target)
            def changed(candidate):
                return raw + b'\n' if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_source_inventory_differs$'):
                    current.require_sources()
        # Coherent hashes cannot substitute a new method or module edge for
        # the actual opt-in declarations underlying the unchanged default count.
        for path, added in current.DATA['added_excluded_methods'].items():
            target = current.ROOT / path; raw = read(target)
            changed_raw = raw.replace(added[0].encode(), (added[0] + '_renamed').encode())
            self.assertNotEqual(changed_raw, raw)
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('method gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_source_inventory_differs$'):
                    current.require_sources()
        for path, literal in (('src/lib.rs', 'feature = "offline-router"'),
                              ('src/offline_router/host.rs', '#[path = "host_identity_tests.rs"]\nmod identity_tests;'),
                              ('evaluation/offline-router-native/observer/Cargo.toml', '[workspace]')):
            target = current.ROOT / path; raw = read(target)
            changed_raw = raw.replace(literal.encode(), b'')
            self.assertNotEqual(changed_raw, raw)
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('module gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_source_inventory_differs$'):
                    current.require_sources()
