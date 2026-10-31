"""Additive source/catalog controls for the real SPSC test population."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_c712_inventory as current
import core_367_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
import core_f353_inventory as indexed
import core_d8d85_inventory as artifact
import core_34c47_inventory as prepared
import core_acc247_inventory as incoming
import core_20cbe_inventory as newest
import core_981419_inventory as latest


class MainC712InventoryTests(unittest.TestCase):
    def test_exact_software_preemption_sources_catalog_and_refusals(self):
        actual = current.main0fb574.before_current(current.main0fb574.mainaf81.before_current(current.main0fb574.mainaf81.maindd75.before_current(latest.before_current(newest.before_current(incoming.before_current(prepared.before_current(artifact.before_current(indexed.before_current(json.loads(Path(__file__).with_name('corpus.json').read_bytes()))))))))))
        rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (106, 3861, 37))
        self.assertEqual(rows['unit/liteinst_preempt/main'], {'tests': 32, 'ignored': 0})
        self.assertEqual(actual['recorder_tests'], 356)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual(old['recorder_tests'], 355)
        self.assertEqual(old['harness_test_counts']['workspace_tests']['unit/liteinst_preempt/main'],
                         {'tests': 2, 'ignored': 0})
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        self.assertEqual((len(actual['harness_test_counts']['serial_launch']),
                          sum(x['tests'] for x in actual['harness_test_counts']['serial_launch'].values())), (27, 1039))
        # The unchanged historical tests and required-check preflight execute the
        # complete older proof. This case isolates the new strict entry boundary.
        with patch.object(inventory, 'require_historical355') as earlier:
            self.assertIsNone(inventory.require_historical356(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_historical356(wrong)
        for field, values in (('recorder_tests', (355, 357, True, 356.0)),):
            for value in values:
                wrong = copy.deepcopy(actual); wrong[field] = value
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainc712_inventory_differs$'):
                    current.before_current(wrong)
        for value in (2, 31, 33, True, 32.0):
            wrong = copy.deepcopy(actual)
            wrong['harness_test_counts']['workspace_tests']['unit/liteinst_preempt/main']['tests'] = value
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainc712_inventory_differs$'):
                current.before_current(wrong)
        for key in actual:
            wrong = dict(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainc712_inventory_differs$'):
                current.before_current(wrong)
        identities = current.main0fb574.before_python(current.main0fb574.mainaf81.before_python(current.main0fb574.mainaf81.maindd75.before_python(latest.before_python(newest.before_python(incoming.before_python(prepared.before_python(artifact.before_python(indexed.before_python(historical.python_identities(Path(__file__).parent))))))))))
        self.assertEqual((len(identities), current.digest(identities)), (356, current.PYTHON_CURRENT))
        old_ids = current.before_python(identities)
        self.assertEqual((len(old_ids), current.digest(old_ids)), (355, previous.PYTHON_CURRENT))
        self.assertEqual(set(identities) - set(old_ids), {current.ADDED})
        for wrong in (old_ids, identities + [identities[0]], list(reversed(identities)),
                      [name + '_changed' if name == current.ADDED else name for name in identities]):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainc712_python_inventory_differs$'):
                current.before_python(wrong)
        self.assertEqual({path: len(names) for path, names in current.DATA['added_default_methods'].items()}, {
            'tools/software-preemption/main.rs': 7,
            'tools/software-preemption/inline_clock.rs': 2,
            'tools/software-preemption/inline_clock/rendezvous/tests.rs': 21})
        self.assertEqual(sum(len(names) for names in current.DATA['added_default_methods'].values()), 30)
        self.assertEqual(current.DATA['default_harness_changes'], 0)
        self.assertEqual(current.DATA['default_ignore_changes'], 0)
        read = Path.read_bytes
        # Authenticate every changed old source before reversing it, including
        # non-Rust consumers already pinned by earlier source layers.
        for kind, function in (('projections', current.source_before),
                               ('evaluation_projections', current.source_before_evaluation)):
            for path, row in current.DATA[kind].items():
                raw = read(current.ROOT / path)
                restored = function(path, raw, 'spsc_inverse_control')
                self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
                for wrong in (raw + b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^spsc_inverse_control$'):
                        function(path, wrong, 'spsc_inverse_control')
        for path in current.DATA['methods']:
            target = current.ROOT / path; raw = read(target)
            def changed(candidate):
                return raw + b'\n' if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainc712_source_inventory_differs$'):
                    current.require_sources()
        # A coherent source/hash rename must fail actual method membership,
        # not an unrelated stale source pin or the historical inverse.
        for path, added in current.DATA['added_default_methods'].items():
            target = current.ROOT / path; raw = read(target)
            changed_raw = raw.replace(added[0].encode(), (added[0] + '_renamed').encode())
            self.assertNotEqual(changed_raw, raw)
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('method gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainc712_source_inventory_differs$'):
                    current.require_sources()
        path = 'tools/software-preemption/inline_clock/rendezvous.rs'
        target = current.ROOT / path; raw = read(target)
        changed_raw = raw.replace(b'#[cfg(test)]\nmod tests;', b'#[cfg(test)]\nmod tests;\n#[cfg(test)]\nmod tests;')
        self.assertNotEqual(changed_raw, raw)
        def changed(candidate):
            return changed_raw if candidate == target else read(candidate)
        with patch.object(Path, 'read_bytes', changed), \
             patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
             patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('module gate omitted'))):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainc712_source_inventory_differs$'):
                current.require_sources()
