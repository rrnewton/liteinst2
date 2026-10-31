"""Exact accuracy-SDK successor with causal declaration and historical refusals."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_20cbe_inventory as current
import core_981419_inventory as previous
import core_dd75_inventory as selected
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
import core_97ab_inventory as native_indexed
import core_f353_inventory as indexed
import core_d8d85_inventory as artifact
import core_34c47_inventory as prepared
import core_acc247_inventory as incoming


class Main20cbeInventoryTests(unittest.TestCase):
    def test_exact37_sources_instances_catalog_and_causal_refusals(self):
        actual = incoming.before_current(prepared.before_current(artifact.before_current(indexed.before_current(native_indexed.before_current(json.loads(Path(__file__).with_name('corpus.json').read_bytes()))))))
        rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (109, 4099, 37))
        self.assertEqual(current.DATA['default_test_additions'], 14)
        self.assertEqual(current.DATA['default_harness_changes'], 0)
        self.assertEqual(current.DATA['default_ignore_changes'], 0)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual((actual['recorder_tests'], old['recorder_tests']), (361, 360))
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        self.assertEqual((len(actual['harness_test_counts']['serial_launch']),
                          sum(x['tests'] for x in actual['harness_test_counts']['serial_launch'].values())), (27, 1039))
        with patch.object(inventory, 'require_historical360') as earlier:
            self.assertIsNone(inventory.require_historical361(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_historical361(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main981419_inventory_differs$'):
            previous.before_current(actual)
        self.assertEqual(previous.peel_current(actual, 'catalog_control', 'source_control'), previous.before_current(old))
        for key in actual:
            wrong = copy.deepcopy(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main20cbe_inventory_differs$'):
                current.before_current(wrong)
        for name, change in current.DATA['workspace_changes'].items():
            for field in ('tests', 'ignored'):
                for value in (change['current'][field] + 1, True, float(change['current'][field])):
                    wrong = copy.deepcopy(actual); wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main20cbe_inventory_differs$'):
                        current.before_current(wrong)
        identities = incoming.before_python(prepared.before_python(artifact.before_python(indexed.before_python(native_indexed.before_python(historical.python_identities(Path(__file__).parent))))))
        old_ids = current.before_python(identities)
        self.assertEqual((len(identities), len(old_ids)), (361, 360))
        self.assertEqual(current.digest(old_ids), previous.PYTHON_CURRENT)
        self.assertEqual(set(identities) - set(old_ids), {current.ADDED})
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main981419_python_inventory_differs$'):
            previous.before_python(identities)
        for wrong in (old_ids, identities + [identities[0]], list(reversed(identities))):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main20cbe_python_inventory_differs$'):
                current.before_python(wrong)
        read = Path.read_bytes
        for kind, function in (('projections', current.source_before),
                               ('evaluation_projections', current.source_before_evaluation)):
            for path, row in current.DATA[kind].items():
                raw = read(current.ROOT / path)
                restored = function(path, raw, 'accuracy_inverse_control')
                self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
                for wrong in (raw + b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^accuracy_inverse_control$'):
                        function(path, wrong, 'accuracy_inverse_control')
                corrupted = copy.deepcopy(row)
                corrupted['edits'][0][2] += '\n'
                with patch.dict(current.DATA[kind], {path: corrupted}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^accuracy_bad_inverse_control$'):
                        function(path, raw, 'accuracy_bad_inverse_control')
        for path in current.DATA['added_default_methods']:
            target = current.ROOT / path; raw = read(target)
            def changed(candidate):
                return raw + b'\n' if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main20cbe_source_inventory_differs$'):
                    current.require_sources()
        # Repair the supplied whole-blob hash, then reach the actual declaration
        # and module-edge gates before any inverse. A bypass reaches the sentinel.
        stimuli = [(p, names[0], names[0] + '_wrong')
                   for p, names in current.DATA['added_default_methods'].items()]
        stimuli += [(p, literals[0], '') for p, literals in current.DATA['module_chains'].items()]
        for path, before, after in stimuli:
            target = current.ROOT / path; raw = read(target)
            changed_raw = raw.replace(before.encode(), after.encode())
            self.assertNotEqual(changed_raw, raw)
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main20cbe_source_inventory_differs$'):
                    current.require_sources()
        self.assertEqual({path: len(names) for path, names in current.DATA['added_default_methods'].items()}, {
            'tests/support/native_exact_accuracy/tests.rs': 6,
            'tools/rapid-profiler/native-interval/normal/selected_leaf_set/exact_check.rs': 2})
        self.assertEqual(current.DATA['default_method_instances'], {
            'tests/support/native_exact_accuracy/tests.rs': ['test/frontend_native_calibrations', 'unit/ordinary_interval/main'],
            'tools/rapid-profiler/native-interval/normal/selected_leaf_set/exact_check.rs': ['test/frontend_native_calibrations']})
        self.assertEqual(sum(len(current.DATA['added_default_methods'][path])*len(rows)
                             for path, rows in current.DATA['default_method_instances'].items()), 14)
        # Incoming source changes must not mask the older dd75 declaration gates.
        probes = (
            ('tests/support/native_normal_caller.rs', 'normal_ready_refuses_wrong_caller_maps_and_extents'),
            ('tests/support/native_normal_caller.rs', '#[path = "native_selected_leaf_set.rs"]\npub mod selected_leaf_set;'),
            ('tools/rapid-profiler/native-interval/calibrations.rs', '#[path = "../../../tests/support/native_interval_oracle.rs"]\nmod oracle;'),
        )
        self.assertEqual(len(probes), 3)
        for path, literal in probes:
            target = current.ROOT / path; raw = read(target)
            prior = current.source_before(path, raw, 'exact37_old_declaration_inverse')
            self.assertEqual(hashlib.sha256(prior).hexdigest(), selected.DATA['sources'][path])
            self.assertEqual((raw.count(literal.encode()), prior.count(literal.encode())), (1, 1))
            altered = literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            changed_raw = raw.replace(literal.encode(), altered.encode())
            changed_prior = prior.replace(literal.encode(), altered.encode())
            self.assertNotEqual(changed_raw, raw)
            row = copy.deepcopy(current.DATA['projections'][path])
            row['current_sha256'] = hashlib.sha256(changed_raw).hexdigest()
            row['previous_sha256'] = hashlib.sha256(changed_prior).hexdigest()
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.dict(current.DATA['projections'], {path: row}):
                self.assertEqual(current.source_before(path, changed_raw,
                    'exact37_old_declaration_inverse'), changed_prior)
                with patch.object(Path, 'read_bytes', changed), \
                     patch.dict(selected.DATA['sources'], {path: hashlib.sha256(changed_prior).hexdigest()}), \
                     patch.object(selected, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('historical declaration gate omitted'))):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^maindd75_source_inventory_differs$'):
                        selected.require_sources()
