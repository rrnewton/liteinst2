"""Live selected-SDK source/inverse refusal, with strict historical catalog entry."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_dd75_inventory as current
import core_af81_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
import core_20cbe_inventory as newest
import core_981419_inventory as latest


class MainDd75InventoryTests(unittest.TestCase):
    def test_exact_selected_sdk_sources_and_strict_historical_refusals(self):
        actual = latest.before_current(newest.before_current(json.loads(Path(__file__).with_name('corpus.json').read_bytes())))
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual((actual['recorder_tests'], old['recorder_tests']), (359, 358))
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        with patch.object(inventory, 'require_historical358') as earlier:
            self.assertIsNone(inventory.require_historical359(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_historical359(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_inventory_differs$'):
            previous.before_current(actual)
        self.assertEqual(previous.peel_current(actual, 'catalog_control', 'source_control'), previous.before_current(old))
        for key in actual:
            wrong = copy.deepcopy(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^maindd75_inventory_differs$'):
                current.before_current(wrong)
        for name, change in current.DATA['workspace_changes'].items():
            for field in ('tests', 'ignored'):
                for value in (change['current'][field] + 1, True, float(change['current'][field])):
                    wrong = copy.deepcopy(actual); wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^maindd75_inventory_differs$'):
                        current.before_current(wrong)
        identities = latest.before_python(newest.before_python(historical.python_identities(Path(__file__).parent)))
        old_ids = current.before_python(identities)
        self.assertEqual((len(identities), len(old_ids)), (359, 358))
        self.assertEqual(current.digest(old_ids), previous.PYTHON_CURRENT)
        self.assertEqual(set(identities) - set(old_ids), {current.ADDED})
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_python_inventory_differs$'):
            previous.before_python(identities)
        for wrong in (old_ids, identities + [identities[0]], list(reversed(identities))):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^maindd75_python_inventory_differs$'):
                current.before_python(wrong)
        read = Path.read_bytes
        for kind, function in (('projections', current.source_before),
                               ('evaluation_projections', current.source_before_evaluation)):
            for path, row in current.DATA[kind].items():
                raw = read(current.ROOT / path)
                restored = function(path, raw, 'selected_sdk_inverse_control')
                self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
                for wrong in (raw + b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^selected_sdk_inverse_control$'):
                        function(path, wrong, 'selected_sdk_inverse_control')
        # Causally prove declaration and module membership checks before inverses:
        # repair the supplied outer hash, but not the required name/edge inventory.
        stimuli = [(p, row['all'][0], row['all'][0] + '_wrong')
                   for p, row in current.DATA['methods'].items() if row['all']]
        stimuli += [(p, literals[0], '') for p, literals in current.DATA['module_chains'].items()]
        for path, before, after in stimuli:
            target = current.ROOT / path; raw = read(target); changed_raw = raw.replace(before.encode(), after.encode())
            self.assertNotEqual(changed_raw, raw)
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^maindd75_source_inventory_differs$'):
                    current.require_sources()
