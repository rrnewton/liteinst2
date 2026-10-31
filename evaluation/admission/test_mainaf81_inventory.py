"""Exact default ADC/compiled test census with explicit historical boundaries."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_af81_inventory as current
import core_0fb574_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
import core_97ab_inventory as native_indexed
import core_f353_inventory as indexed
import core_d8d85_inventory as artifact
import core_34c47_inventory as prepared
import core_acc247_inventory as incoming
import core_20cbe_inventory as newest
import core_981419_inventory as latest


class MainAf81InventoryTests(unittest.TestCase):
    def test_exact_adc_compiled_sources_catalog_and_refusals(self):
        actual = current.maindd75.before_current(latest.before_current(newest.before_current(incoming.before_current(prepared.before_current(artifact.before_current(indexed.before_current(native_indexed.before_current(json.loads(Path(__file__).with_name('corpus.json').read_bytes())))))))))
        rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (109, 4033, 37))
        self.assertEqual(actual['recorder_tests'], 358)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual(old['recorder_tests'], 357)
        self.assertEqual((len(old['harness_test_counts']['workspace_tests']),
                          sum(x['tests'] for x in old['harness_test_counts']['workspace_tests'].values())), (106, 3861))
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        self.assertEqual((len(actual['harness_test_counts']['serial_launch']),
                          sum(x['tests'] for x in actual['harness_test_counts']['serial_launch'].values())), (27, 1039))
        with patch.object(inventory, 'require_historical357') as earlier:
            self.assertIsNone(inventory.require_historical358(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_historical358(wrong)
        # Strict historical entry must reject the valid successor. Compatibility
        # is explicit in peel_current and in the old tests' input setup only.
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_inventory_differs$'):
            previous.before_current(actual)
        self.assertEqual(previous.peel_current(actual, 'catalog_control', 'source_control'), previous.before_current(old))
        for value in (357, 359, True, 358.0):
            wrong = copy.deepcopy(actual); wrong['recorder_tests'] = value
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_inventory_differs$'):
                current.before_current(wrong)
        for name, change in current.DATA['workspace_changes'].items():
            self.assertEqual(rows[name], change['current'])
            for field in ('tests', 'ignored'):
                for value in (change['current'][field] + 1, True, float(change['current'][field])):
                    wrong = copy.deepcopy(actual); wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_inventory_differs$'):
                        current.before_current(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_inventory_differs$'):
                current.before_current(wrong)
        for key in actual:
            wrong = dict(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_inventory_differs$'):
                current.before_current(wrong)
        identities = current.maindd75.before_python(latest.before_python(newest.before_python(incoming.before_python(prepared.before_python(artifact.before_python(indexed.before_python(native_indexed.before_python(historical.python_identities(Path(__file__).parent)))))))))
        self.assertEqual((len(identities), current.digest(identities)), (358, current.PYTHON_CURRENT))
        old_ids = current.before_python(identities)
        self.assertEqual((len(old_ids), current.digest(old_ids)), (357, previous.PYTHON_CURRENT))
        self.assertEqual(set(identities) - set(old_ids), {current.ADDED})
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main0fb574_python_inventory_differs$'):
            previous.before_python(identities)
        self.assertEqual(previous.peel_python(identities), previous.before_python(old_ids))
        for wrong in (old_ids, identities + [identities[0]], list(reversed(identities)),
                      [name + '_changed' if name == current.ADDED else name for name in identities]):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_python_inventory_differs$'):
                current.before_python(wrong)
        self.assertEqual(current.DATA['default_harness_changes'], 3)
        self.assertEqual(current.DATA['default_ignore_changes'], 0)
        self.assertEqual(current.DATA['default_test_additions'], 172)
        self.assertEqual(current.DATA['expanded_macro_counts'], {'compiled_selected_native': 16, 'selected_session_controls': 24})
        self.assertEqual(current.DATA['shared_oracle_tests'], 35)
        self.assertEqual(current.DATA['new_harness_counts'], {'test/adc_state_oracle': 40,
            'test/whole_adc_state_oracle': 39, 'test/compiled_selected_state_oracle': 54})
        self.assertEqual(current.DATA['excluded_custom_harness'], dict(name='precontext_native', harness=False, previous=True))
        read = Path.read_bytes
        for kind, function in (('projections', current.source_before),
                               ('evaluation_projections', current.source_before_evaluation)):
            for path, row in current.DATA[kind].items():
                raw = read(current.ROOT / path)
                restored = function(path, raw, 'adc_inverse_control')
                self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
                for wrong in (raw + b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^adc_inverse_control$'):
                        function(path, wrong, 'adc_inverse_control')
        for path in current.DATA['methods']:
            target = current.ROOT / path; raw = read(target)
            def changed(candidate):
                return raw + b'\n' if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_source_inventory_differs$'):
                    current.require_sources()
        # Even coherent source hash changes cannot rename a required declaration,
        # macro expansion or module edge before the exact source inverses run.
        stimuli = []
        for path, row in current.DATA['methods'].items():
            if row['all']:
                stimuli.append((path, row['all'][0], row['all'][0] + '_renamed'))
            for template in row['templates']:
                stimuli.append((path, template, template.replace('#[test]', '#[cfg(test)]')))
        stimuli.extend([('tests/compiled_selected_state_oracle.rs', 'native_case!(first_equal_mask_0, 0, 0);',
                         'native_case!(first_equal_mask_wrong, 0, 0);'),
                        ('tools/rapid-profiler/ordinary-interval/normal/selected_session_controls.rs',
                         'labels_are_fixed_copyable_csv_safe_identifiers,',
                         'labels_are_fixed_copyable_csv_safe_identifiers_wrong,')])
        for path, literals in current.DATA['module_chains'].items():
            stimuli.append((path, literals[0], ''))
        for path, old_text, new_text in stimuli:
            target = current.ROOT / path; raw = read(target)
            changed_raw = raw.replace(old_text.encode(), new_text.encode())
            self.assertNotEqual(changed_raw, raw)
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainaf81_source_inventory_differs$'):
                    current.require_sources()
