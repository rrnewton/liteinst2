"""Exact prepared-phase successor; inherited362 identities and historical declarations stay strict."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import core_34c47_inventory as current
import core_acc247_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
import core_f353_inventory as indexed
import core_d8d85_inventory as artifact


class Main34c47InventoryTests(unittest.TestCase):
    def test_exact_prepared_sources_instances_and_causal_history_refusals(self):
        actual = artifact.before_current(indexed.before_current(json.loads(Path(__file__).with_name('corpus.json').read_bytes())))
        rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (109, 4126, 37))
        self.assertEqual(current.DATA['default_test_additions'], 18)
        self.assertEqual(current.DATA['default_harness_changes'], 0)
        self.assertEqual(current.DATA['default_ignore_changes'], 0)
        old = current.before_current(actual)
        self.assertEqual(current.digest(old), previous.CURRENT)
        self.assertEqual((actual['recorder_tests'], old['recorder_tests']), (363, 362))
        self.assertEqual(actual['harness_test_counts']['serial_launch'], old['harness_test_counts']['serial_launch'])
        self.assertEqual((len(actual['harness_test_counts']['serial_launch']),
                          sum(x['tests'] for x in actual['harness_test_counts']['serial_launch'].values())), (27, 1039))
        with patch.object(inventory, 'require_historical362') as earlier:
            self.assertIsNone(inventory.require_historical363(actual))
            earlier.assert_called_once_with(old)
        for wrong in (old, previous.before_current(old)):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_historical363(wrong)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainacc247_inventory_differs$'):
            previous.before_current(actual)
        self.assertEqual(previous.peel_current(actual, 'catalog_control', 'source_control'), previous.before_current(old))
        for key in actual:
            wrong = copy.deepcopy(actual); wrong[key] = None
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main34c47_inventory_differs$'):
                current.before_current(wrong)
        for name, change in current.DATA['workspace_changes'].items():
            for field in ('tests', 'ignored'):
                for value in (change['current'][field] + 1, True, float(change['current'][field])):
                    wrong = copy.deepcopy(actual); wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main34c47_inventory_differs$'):
                        current.before_current(wrong)
        identities = artifact.before_python(indexed.before_python(historical.python_identities(Path(__file__).parent)))
        old_ids = current.before_python(identities)
        self.assertEqual((len(identities), len(old_ids)), (363, 362))
        self.assertEqual(current.digest(old_ids), previous.PYTHON_CURRENT)
        self.assertEqual(set(identities) - set(old_ids), {current.ADDED})
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainacc247_python_inventory_differs$'):
            previous.before_python(identities)
        for wrong in (old_ids, identities + [identities[0]], list(reversed(identities))):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main34c47_python_inventory_differs$'):
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
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main34c47_source_inventory_differs$'):
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
            # Preserve the same declaration stimulus through the new exact
            # current-to34c source inverse, then repair only its upstream facts.
            upstream = copy.deepcopy(current.DATA['source_projections_23d6'])
            prior_raw = current.source_before23d6(path, raw, 'snapshot_declaration_inverse')
            changed_prior = prior_raw.replace(before.encode(), after.encode())
            if path in upstream:
                upstream[path]['current_sha256'] = hashlib.sha256(changed_raw).hexdigest()
                upstream[path]['previous_sha256'] = hashlib.sha256(changed_prior).hexdigest()
            with patch.dict(current.DATA['source_projections_23d6'], upstream):
                self.assertEqual(current.source_before23d6(path, changed_raw,
                    'snapshot_declaration_inverse'), changed_prior)
            def changed(candidate):
                return changed_raw if candidate == target else read(candidate)
            with patch.dict(current.DATA['source_projections_23d6'], upstream), \
                 patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(changed_raw).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main34c47_source_inventory_differs$'):
                    current.require_sources()
        self.assertEqual({path: len(names) for path, names in current.DATA['added_default_methods'].items()}, {'tools/rapid-profiler/ordinary-interval/normal/leaf_set/check.rs': 1, 'tools/rapid-profiler/ordinary-interval/normal/leaf_set/prepared.rs': 1, 'tools/rapid-profiler/ordinary-interval/normal/leaf_set/selected.rs': 2, 'tools/rapid-profiler/ordinary-interval/normal/module/session/worker.rs': 2, 'tools/rapid-profiler/ordinary-interval/normal/session/io.rs': 1, 'tools/rapid-profiler/ordinary-interval/normal/session/phase/prepared/tests.rs': 8, 'tools/rapid-profiler/ordinary-interval/normal/session/worker/prepared_tests.rs': 3})
        self.assertEqual(current.DATA['default_method_instances'], {'tools/rapid-profiler/ordinary-interval/normal/leaf_set/check.rs': ['unit/ordinary_interval/main'], 'tools/rapid-profiler/ordinary-interval/normal/leaf_set/prepared.rs': ['unit/ordinary_interval/main'], 'tools/rapid-profiler/ordinary-interval/normal/leaf_set/selected.rs': ['unit/ordinary_interval/main'], 'tools/rapid-profiler/ordinary-interval/normal/module/session/worker.rs': ['unit/ordinary_interval/main'], 'tools/rapid-profiler/ordinary-interval/normal/session/io.rs': ['unit/ordinary_interval/main'], 'tools/rapid-profiler/ordinary-interval/normal/session/phase/prepared/tests.rs': ['unit/ordinary_interval/main'], 'tools/rapid-profiler/ordinary-interval/normal/session/worker/prepared_tests.rs': ['unit/ordinary_interval/main']})
        self.assertEqual(sum(len(current.DATA['added_default_methods'][path])*len(rows)
                             for path, rows in current.DATA['default_method_instances'].items()), 18)
        probes = (
            ('tools/rapid-profiler/ordinary-interval/normal/leaf_set/selected.rs', 'phase_cli_is_explicit_and_mutually_refuses_legacy_grammars'),
            ('tools/rapid-profiler/ordinary-interval/normal/leaf_set/selected.rs', '#[cfg(test)]\nmod phase_tests {'),
            ('tools/rapid-profiler/ordinary-interval/normal/session/phase.rs', 'request_is_separate_and_never_changes_the_accuracy_policy'),
        )
        self.assertEqual(len(probes), 3)
        for path, literal in probes:
            target = current.ROOT / path; raw = read(target)
            prior = current.source_before(path, raw, 'prepared_old_declaration_inverse')
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
                    'prepared_old_declaration_inverse'), changed_prior)
                with patch.object(Path, 'read_bytes', changed), \
                     patch.dict(previous.DATA['sources'], {path: hashlib.sha256(changed_prior).hexdigest()}), \
                     patch.object(previous, 'source_before', side_effect=lambda p, b, e: b if p != path else (_ for _ in ()).throw(AssertionError('historical declaration gate omitted'))):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^mainacc247_source_inventory_differs$'):
                        previous.require_sources()

        # No new test identity or corpus. All three actual incoming blobs are
        # required; historical bytes and repaired current-only hashes refuse.
        self.assertEqual(set(current.DATA['source_projections_23d6']), {
            'tools/rapid-profiler/ordinary-interval/normal/csv.rs',
            'tools/rapid-profiler/ordinary-interval/normal/csv/tests.rs',
            'tools/rapid-profiler/ordinary-interval/normal/module/session/worker.rs',
        })
        for path, row in current.DATA['source_projections_23d6'].items():
            target = current.ROOT / path; raw = read(target)
            restored = current.source_before23d6(path, raw, 'snapshot_inverse_control')
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row['current_sha256'])
            self.assertEqual(hashlib.sha256(restored).hexdigest(), row['previous_sha256'])
            self.assertEqual(row['current_sha256'], current.DATA['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], restored, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^snapshot_inverse_control$'):
                    current.source_before23d6(path, wrong, 'snapshot_inverse_control')
            with patch.dict(current.DATA['sources'], {path: row['previous_sha256']}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main34c47_source_inventory_differs$'):
                    current.require_sources()
            broken = copy.deepcopy(row); broken['edits'][0][2] += '\n'
            with patch.dict(current.DATA['source_projections_23d6'], {path: broken}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^snapshot_bad_inverse_control$'):
                    current.source_before23d6(path, raw, 'snapshot_bad_inverse_control')
            altered = raw + b'\n'; repaired = copy.deepcopy(row)
            repaired['current_sha256'] = hashlib.sha256(altered).hexdigest()
            with patch.dict(current.DATA['source_projections_23d6'], {path: repaired}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^snapshot_prior_hash_control$'):
                    current.source_before23d6(path, altered, 'snapshot_prior_hash_control')
            for altered in (restored, raw + b'\n'):
                def changed(candidate):
                    return altered if candidate == target else read(candidate)
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main34c47_source_inventory_differs$'):
                        current.require_sources()

        # Coordinate sources add no recorder identity or Rust instance. The
        # actual current blobs must peel exactly to the retained23d6 snapshot.
        coordinate_changed = {
            'evaluation/ordinary-selected-session/accuracy_functional.py',
            'evaluation/ordinary-selected-session/accuracy_functional_owner.py',
            'evaluation/ordinary-selected-session/accuracy_produce.py',
        }
        coordinate_added = {
            'evaluation/ordinary-selected-session/accuracy_coordinates.py',
            'evaluation/ordinary-selected-session/coordinate_controls.py',
            'evaluation/ordinary-selected-session/COORDINATES.md',
        }
        self.assertEqual(set(current.DATA['source_projections_bf8b']), coordinate_changed)
        self.assertTrue(coordinate_added <= set(current.DATA['sources']))
        for path, row in current.DATA['source_projections_bf8b'].items():
            raw = read(current.ROOT / path)
            prior = current.source_before_bf8b(path, raw, 'coordinate_inverse_control')
            self.assertEqual(hashlib.sha256(raw).hexdigest(), current.DATA['sources'][path])
            self.assertEqual(hashlib.sha256(prior).hexdigest(), row['previous_sha256'])
            self.assertEqual(row['previous_sha256'], current.DATA['projections'][path]['current_sha256'])
            self.assertEqual(current.source_before(path, raw, 'coordinate_whole_history'),
                current.inverse(path, prior, current.DATA['projections'], 'coordinate_whole_history'))
            for wrong in (raw+b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^coordinate_inverse_control$'):
                    current.source_before_bf8b(path, wrong, 'coordinate_inverse_control')
            broken = copy.deepcopy(row); broken['edits'][0][2] += '\n'
            with patch.dict(current.DATA['source_projections_bf8b'], {path: broken}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^coordinate_bad_inverse_control$'):
                    current.source_before_bf8b(path, raw, 'coordinate_bad_inverse_control')
            altered = raw+b'\n'; repaired = copy.deepcopy(row)
            repaired['current_sha256'] = hashlib.sha256(altered).hexdigest()
            with patch.dict(current.DATA['source_projections_bf8b'], {path: repaired}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^coordinate_prior_hash_control$'):
                    current.source_before_bf8b(path, altered, 'coordinate_prior_hash_control')
        for path in coordinate_changed | coordinate_added:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate == target:
                        if missing:
                            raise FileNotFoundError(path)
                        return raw+b'\n'
                    return read(candidate)
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main34c47_source_inventory_differs$'):
                        current.require_sources()
