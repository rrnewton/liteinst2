"""Exact accuracy-SDK successor with causal declaration and historical refusals."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_981419_inventory as current
import core_dd75_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
import core_34c47_inventory as prepared
import core_acc247_inventory as incoming
import core_20cbe_inventory as newest


class Main981419InventoryTests(unittest.TestCase):
    def test_exact_accuracy_sources_catalog_and_causal_refusals(self):
        actual = newest.before_current(incoming.before_current(prepared.before_current(json.loads(Path(__file__).with_name('corpus.json').read_bytes()))))
        rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (109, 4085, 37))
        self.assertEqual(current.DATA['default_test_additions'], 38)
        self.assertEqual(current.DATA['default_harness_changes'], 0)
        self.assertEqual(current.DATA['default_ignore_changes'], 0)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual((actual['recorder_tests'], old['recorder_tests']), (360, 359))
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        self.assertEqual((len(actual['harness_test_counts']['serial_launch']),
                          sum(x['tests'] for x in actual['harness_test_counts']['serial_launch'].values())), (27, 1039))
        with patch.object(inventory, 'require_historical359') as earlier:
            self.assertIsNone(inventory.require_historical360(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_historical360(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^maindd75_inventory_differs$'):
            previous.before_current(actual)
        self.assertEqual(previous.peel_current(actual, 'catalog_control', 'source_control'), previous.before_current(old))
        for key in actual:
            wrong = copy.deepcopy(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main981419_inventory_differs$'):
                current.before_current(wrong)
        for name, change in current.DATA['workspace_changes'].items():
            for field in ('tests', 'ignored'):
                for value in (change['current'][field] + 1, True, float(change['current'][field])):
                    wrong = copy.deepcopy(actual); wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main981419_inventory_differs$'):
                        current.before_current(wrong)
        identities = newest.before_python(incoming.before_python(prepared.before_python(historical.python_identities(Path(__file__).parent))))
        old_ids = current.before_python(identities)
        self.assertEqual((len(identities), len(old_ids)), (360, 359))
        self.assertEqual(current.digest(old_ids), previous.PYTHON_CURRENT)
        self.assertEqual(set(identities) - set(old_ids), {current.ADDED})
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^maindd75_python_inventory_differs$'):
            previous.before_python(identities)
        for wrong in (old_ids, identities + [identities[0]], list(reversed(identities))):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main981419_python_inventory_differs$'):
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
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main981419_source_inventory_differs$'):
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
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main981419_source_inventory_differs$'):
                    current.require_sources()
        # These inherited gates used to see current source directly. Carry an
        # equal-length mutation through the new upstream inverse without changing
        # its edit list, then require the original historical declaration guard.
        historical_stimuli = (
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/ordinary-interval/normal/leaf_set.rs', 'canonical_table_cli_keeps_all_functions_and_refuses_invalid_last'),
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/ordinary-interval/normal/leaf_set/check.rs', 'ordered_population_n1_through_n4_keeps_global_and_local_coordinates'),
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/ordinary-interval/normal/leaf_set/worker.rs', 'command_flush_boundary_is_exact_for_each_cardinality_and_old_default'),
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/ordinary-interval/normal/session.rs', 'guarded_wait_preserves_original_due_end_and_shutdown_boundaries'),
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/ordinary-interval/main.rs', 'mod normal;'),
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/ordinary-interval/normal/leaf_set.rs', 'mod check;'),
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/ordinary-interval/normal/leaf_set/selected.rs', '#[cfg(test)]\n#[path = "selected_tests.rs"]\npub(in crate::normal) mod controls;'),
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/src/frontend_native/always_on.rs', 'pub(super) mod site;'),
            (inventory.main367.mainc712.main0fb574.mainaf81, 'tools/rapid-profiler/src/frontend_native/mod.rs', 'mod module;'),
            (previous, 'tools/rapid-profiler/native-interval/main.rs', '#[path = "../../../tests/support/native_interval_oracle.rs"]\nmod oracle;'),
            (previous, 'tools/rapid-profiler/native-interval/normal/selected_leaf_set.rs', 'mod check;'),
            (previous, 'tools/rapid-profiler/ordinary-interval/main.rs', '#[path = "../../../tests/support/native_interval_oracle.rs"]\nmod oracle;'),
        )
        self.assertEqual(len(historical_stimuli), 12)
        for layer, path, literal in historical_stimuli:
            target = current.ROOT / path; raw = read(target)
            prior = current.source_before(path, raw, 'accuracy_historical_inverse')
            self.assertEqual(hashlib.sha256(prior).hexdigest(), layer.DATA['sources'][path])
            self.assertEqual((raw.count(literal.encode()), prior.count(literal.encode())), (1, 1))
            altered = literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            changed_raw = raw.replace(literal.encode(), altered.encode())
            changed_prior = prior.replace(literal.encode(), altered.encode())
            self.assertNotEqual(changed_raw, raw)
            prepared_input = prepared.source_before(path, raw, 'upstream_control')
            changed_prepared = prepared_input.replace(literal.encode(), altered.encode())
            newest_outer = {}
            if path in prepared.DATA['projections']:
                row = copy.deepcopy(prepared.DATA['projections'][path])
                row['current_sha256'] = hashlib.sha256(changed_raw).hexdigest()
                row['previous_sha256'] = hashlib.sha256(changed_prepared).hexdigest()
                newest_outer[path] = row
            incoming_input = incoming.source_before(path, raw, 'upstream_control')
            changed_incoming = incoming_input.replace(literal.encode(), altered.encode())
            outer = {}
            if path in incoming.DATA['projections']:
                row = copy.deepcopy(incoming.DATA['projections'][path])
                row['current_sha256'] = hashlib.sha256(changed_prepared).hexdigest()
                row['previous_sha256'] = hashlib.sha256(changed_incoming).hexdigest()
                outer[path] = row
            current_input = newest.source_before(path, raw, 'upstream_control')
            changed_input = current_input.replace(literal.encode(), altered.encode())
            upstream = {}
            if path in newest.DATA['projections']:
                row = copy.deepcopy(newest.DATA['projections'][path])
                row['current_sha256'] = hashlib.sha256(changed_incoming).hexdigest()
                row['previous_sha256'] = hashlib.sha256(changed_input).hexdigest()
                upstream[path] = row
            projection = copy.deepcopy(current.DATA['projections'][path])
            projection['current_sha256'] = hashlib.sha256(changed_input).hexdigest()
            projection['previous_sha256'] = hashlib.sha256(changed_prior).hexdigest()
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.dict(prepared.DATA['projections'], newest_outer), \
                 patch.dict(incoming.DATA['projections'], outer), \
                 patch.dict(newest.DATA['projections'], upstream), \
                 patch.dict(current.DATA['projections'], {path: projection}):
                # This positive join fails if an upstream gate still masks the
                # intended declaration stimulus or if its edits erase it.
                self.assertEqual(current.source_before(path, changed_raw,
                    'accuracy_historical_inverse'), changed_prior)
                with patch.object(Path, 'read_bytes', changed), \
                     patch.dict(layer.DATA['sources'], {path: hashlib.sha256(changed_prior).hexdigest()}), \
                     patch.object(layer, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('historical declaration gate omitted'))):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main' + ('dd75' if layer is previous else 'af81') + '_source_inventory_differs$'):
                        layer.require_sources()
