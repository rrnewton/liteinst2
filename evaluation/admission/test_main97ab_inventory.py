"""Exact native indexed-DSO successor; historical assertions remain in their original domains."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_97ab_inventory as current
import core_f353_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing


class Main97abInventoryTests(unittest.TestCase):
    def test_exact_native_indexed_sources_and_historical_refusals(self):
        actual = json.loads(Path(__file__).with_name('corpus.json').read_bytes())
        rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (112, 4255, 37))
        self.assertEqual(current.DATA['default_test_additions'], 58)
        self.assertEqual(current.DATA['default_harness_changes'], 0)
        self.assertEqual(current.DATA['default_ignore_changes'], 0)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual((actual['recorder_tests'], old['recorder_tests']), (366, 365))
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        self.assertEqual((len(actual['harness_test_counts']['serial_launch']),
                          sum(x['tests'] for x in actual['harness_test_counts']['serial_launch'].values())), (27, 1039))
        with patch.object(inventory, 'require_historical365') as earlier:
            self.assertIsNone(inventory.require_current(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainf353_inventory_differs$'):
            previous.before_current(actual)
        self.assertEqual(previous.peel_current(actual, 'catalog_control', 'source_control'), previous.before_current(old))
        for key in actual:
            wrong = copy.deepcopy(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_current(wrong)
        for name in current.DATA['workspace_changes']:
            for field in ('tests', 'ignored'):
                for value in (rows[name][field]+1, True, float(rows[name][field])):
                    wrong = copy.deepcopy(actual); wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_current(wrong)
        identities = historical.python_identities(Path(__file__).parent)
        old_ids = current.before_python(identities)
        self.assertEqual((len(identities), len(old_ids)), (366, 365))
        self.assertEqual(current.digest(old_ids), previous.PYTHON_CURRENT)
        self.assertEqual(set(identities)-set(old_ids), {current.ADDED})
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainf353_python_inventory_differs$'):
            previous.before_python(identities)
        for wrong in (old_ids, identities+[identities[0]], list(reversed(identities))):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_python_inventory_differs$'):
                current.before_python(wrong)
        read = Path.read_bytes
        for kind, function in (('projections', current.source_before),
                               ('evaluation_projections', current.source_before_evaluation)):
            for path, row in current.DATA[kind].items():
                raw = read(current.ROOT/path)
                restored = function(path, raw, 'indexed_inverse_control')
                self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
                for wrong in (raw+b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^indexed_inverse_control$'):
                        function(path, wrong, 'indexed_inverse_control')
                bad = copy.deepcopy(row); bad['edits'][0][2] += '\n'
                with patch.dict(current.DATA[kind], {path:bad}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^indexed_bad_inverse_control$'):
                        function(path, raw, 'indexed_bad_inverse_control')
        self.assertEqual(sum(len(current.DATA['added_default_methods'][p])*len(v)
            for p,v in current.DATA['default_method_instances'].items()), 58)
        stimuli = [(p, names[0], names[0]+'_wrong') for p,names in current.DATA['added_default_methods'].items()]
        stimuli += [(p, values[0], '') for p,values in current.DATA['module_chains'].items()]
        for path, before, after in stimuli:
            target = current.ROOT/path; raw = read(target)
            self.assertEqual(raw.count(before.encode()), 1)
            wrong = raw.replace(before.encode(), after.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path:hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('indexed declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in current.DATA['added_default_methods']:
            target = current.ROOT/path; raw = read(target)
            def changed(candidate): return raw+b'\n' if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Repair the outer hashes coherently so old declaration gates must fire.
        probes = (
            ('tools/elf-rewrite/examples/indexed_dso_support/elf.rs',
             'complete_symbol_snapshot_retains_hidden_and_localized_forms_and_exact_owners'),
            ('tools/elf-rewrite/tests/indexed_dso_source.rs',
             '#[path = "../examples/indexed_dso_support/caller.rs"]\nmod caller;'),
        )
        self.assertEqual(len(probes), 2)
        for path, literal in probes:
            target = current.ROOT / path; raw = read(target)
            prior = current.source_before(path, raw, 'native_indexed_old_inverse')
            self.assertEqual(hashlib.sha256(prior).hexdigest(), previous.DATA['sources'][path])
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
                    'native_indexed_old_inverse'), changed_prior)
                with patch.object(Path, 'read_bytes', changed), \
                     patch.dict(previous.DATA['sources'], {path: hashlib.sha256(changed_prior).hexdigest()}), \
                     patch.object(previous, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('historical declaration gate omitted'))):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainf353_source_inventory_differs$'):
                        previous.require_sources()
        self.assertEqual(current.DATA['native_example'], dict(
            name='indexed_dso_native', test=False, bench=False, default_test_harness=False))
        self.assertNotIn('unit/indexed_dso_native/indexed_dso_native', rows)
