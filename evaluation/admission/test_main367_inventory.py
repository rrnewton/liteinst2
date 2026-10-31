"""Additive supplied-source/catalog controls; never native execution evidence."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_367_inventory as current
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
import core_20cbe_inventory as newest
import core_981419_inventory as latest
import recorder_shards_inventory as shards


class Main367InventoryTests(unittest.TestCase):
    def test_exact_absolute_startup_sources_catalog_and_refusals(self):
        actual = current.mainc712.before_current(current.mainc712.main0fb574.before_current(current.mainc712.main0fb574.mainaf81.before_current(current.mainc712.main0fb574.mainaf81.maindd75.before_current(latest.before_current(newest.before_current(json.loads(Path(__file__).with_name('corpus.json').read_bytes())))))))
        rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (106, 3831, 37))
        self.assertEqual(rows['unit/liteinst_artifact/lib'], {'tests': 50, 'ignored': 0})
        self.assertEqual(rows['unit/liteinst_rewrite/lib'], {'tests': 155, 'ignored': 0})
        self.assertEqual(actual['recorder_tests'], 355)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), shards.CURRENT)
        self.assertEqual(old['recorder_tests'], 354)
        self.assertEqual(sum(x['tests'] for x in old['harness_test_counts']['workspace_tests'].values()), 3822)
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        self.assertIsNone(inventory.require_historical355(actual))
        self.assertIsNone(inventory.require_historical354(old))
        for wrong in (old, shards.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_historical355(wrong)
        for name, number in (('unit/liteinst_artifact/lib', 50), ('unit/liteinst_rewrite/lib', 155)):
            for value in (number - 1, number + 1, True, float(number)):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests'][name]['tests'] = value
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                    inventory.require_historical355(wrong)
        for value in (354, 356, True, 355.0):
            wrong = copy.deepcopy(actual); wrong['recorder_tests'] = value
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main367_inventory_differs$'):
                current.before_current(wrong)
        for key in actual:
            wrong = dict(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main367_inventory_differs$'):
                current.before_current(wrong)
        identities = current.mainc712.before_python(current.mainc712.main0fb574.before_python(current.mainc712.main0fb574.mainaf81.before_python(current.mainc712.main0fb574.mainaf81.maindd75.before_python(latest.before_python(newest.before_python(historical.python_identities(Path(__file__).parent)))))))
        self.assertEqual(len(identities), 355)
        previous = current.before_python(identities)
        self.assertEqual((len(previous), current.digest(previous)), (354, shards.PYTHON_CURRENT))
        self.assertEqual([name for name in previous if name in shards.ADDED], list(shards.ADDED))
        for wrong in (identities[:-1], identities + [identities[0]], list(reversed(identities)),
                      [name + '_changed' if name == current.ADDED else name for name in identities]):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main367_python_inventory_differs$'):
                current.before_python(wrong)
        expected = {
            'crates/liteinst-artifact/src/startup/tests.rs': [
                'absolute_class_retains_both_complete_populations_and_wire_roles',
                'absolute_roles_are_distinct_actual_sorted_roster_indices',
                'absolute_metadata_every_byte_and_owner_are_exact',
                'absolute_wire_cannot_relabel_roles_version_or_surplus_with_a_fresh_digest'],
            'tools/elf-rewrite/src/carrier/startup_fixtures.rs': [
                'absolute_startup_has_exact_nine_rows_and_original_preservation',
                'absolute_startup_path_roles_are_literal_and_distinct',
                'absolute_startup_charges_all_names_and_exact_new_table_to_old_aggregate_caps',
                'absolute_startup_output_recheck_rejects_all_metadata_bytes_and_writable_owner',
                'absolute_startup_still_checks_original_sections_and_carrier_aliases']}
        self.assertEqual(current.DATA['added_default_methods'], expected)
        self.assertEqual(current.DATA['excluded_default'], dict(core_feature_tests=7,
            rewrite_feature_tests=12, example_feature_tests=5, bootstrap_standalone_tests=5,
            required_feature='offline-router', standalone_manifest='crates/liteinst-bootstrap/Cargo.toml'))
        self.assertEqual(len(current.DATA['projections']), 14)
        read = Path.read_bytes
        for path, row in current.DATA['projections'].items():
            target = current.ROOT / path; raw = read(target)
            restored = current.source_before(path, raw, 'absolute_inverse_control')
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            for wrong in (raw + b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^absolute_inverse_control$'):
                    current.source_before(path, wrong, 'absolute_inverse_control')
            def changed(candidate):
                return raw + b'\n' if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main367_source_inventory_differs$'):
                    current.require_sources()
        # Change a real method while coherently changing its whole-source hash.
        # The exact method-membership gate must reject before any sparse inverse.
        for path, added in expected.items():
            target = current.ROOT / path; raw = read(target)
            changed_raw = raw.replace(added[0].encode(), (added[0] + '_renamed').encode())
            self.assertNotEqual(changed_raw, raw)
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('method gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main367_source_inventory_differs$'):
                    current.require_sources()
