"""Exact native indexed-DSO successor; historical assertions remain in their original domains."""
import copy
import hashlib
import json
import re
from pathlib import Path
import unittest
from unittest.mock import patch

import core_97ab_inventory as current
import core_f353_inventory as previous
import core_5cda_inventory as historical
import core_cc846_inventory as inventory
import parsing
from test_parsing import counts, summary


class Main97abInventoryTests(unittest.TestCase):
    def test_exact_native_indexed_sources_and_historical_refusals(self):
        actual = json.loads(Path(__file__).with_name('corpus.json').read_bytes())
        # Five incoming default tests preserve every older catalog and test gate.
        flat = current.DATA['source_successor_03ed2c31']
        flat_prior = current.before_03ed2c31(actual)
        flat_rows = actual['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(flat_prior), current.FLAT_PREVIOUS)
        self.assertEqual((len(flat_rows), sum(x['tests'] for x in flat_rows.values()),
                          sum(x['ignored'] for x in flat_rows.values())), (120, 4615, 43))
        self.assertEqual(flat_rows['unit/rapid_profiler/lib'], counts(634, 37))
        self.assertEqual(flat_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(629, 37))
        self.assertEqual((flat['default_method_additions'], flat['new_method_declarations'],
                          flat['default_method_removals'], flat['default_harness_changes'],
                          flat['default_ignore_changes'], flat['default_doctest_additions'],
                          flat['recorder_identity_changes'], flat['feature_method_additions'],
                          flat['feature_method_removals']), (5, 5, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(flat['added_default_methods'], {'tools/rapid-profiler/src/frontend/interval_entry/tests.rs': ['checked_exit_preserves_actual_receipt_refusals_and_owner_followthrough', 'checked_exit_drop_and_actual_completion_hooks_preserve_partial_state'], 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/qualification/tests.rs': ['flat_witness_matches_typed_encoder_across_receipts_rearm_and_sparse_reset', 'flat_witness_copies_all_journal_words_and_keeps_actual_receipt_independent', 'flat_witness_preserves_refusals_sequence_panic_and_borrow_boundary']})
        self.assertEqual(flat['default_method_instances'],
                         {p: ['unit/rapid_profiler/lib'] for p in flat['added_default_methods']})
        self.assertEqual((flat['added_feature_methods'], flat['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(flat['source_paths']), len(flat['source_projections'])), (7, 7))
        self.assertEqual(flat['new_sources'], ['tools/rapid-profiler/src/frontend/completion.rs'])
        self.assertEqual(flat['newly_bound_sources'], [
            'tools/rapid-profiler/src/frontend/completion.rs',
            'tools/rapid-profiler/src/frontend/interval_entry/tests.rs'])
        self.assertEqual(flat_prior['harness_test_counts']['serial_launch'], actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], flat_prior['recorder_tests']), (366, 366))
        for path, row in flat['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_03ed2c31(path, raw, 'flat_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (flat['source_preimages'][path]['bytes'], row['previous_sha256']))
            if path in flat['new_sources']:
                self.assertEqual(prior, b'')
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^flat_source_inverse$'):
                    current.source_before_03ed2c31(path, wrong, 'flat_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(flat['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^flat_source_inverse$'):
                        current.source_before_03ed2c31(path, raw, 'flat_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_03ed2c31(flat_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(flat_rows['unit/rapid_profiler/lib'][field]),
                          flat_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_03ed2c31(wrong)
        wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_03ed2c31(wrong)
        read = Path.read_bytes
        flat_stimuli = [(p, 'fn ' + n + '(') for p, names in flat['added_default_methods'].items() for n in names]
        flat_stimuli += [(p, literal) for p, literals in flat['module_chains'].items() for literal in literals]
        for path, literal in flat_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('flat declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # The two row-prefix methods are ordinary default library tests.
        # Preserve the complete fe97 catalog and every historical source target.
        row_prefix = current.DATA['source_successor_4261826']
        row_prefix_prior = current.before_4261826(actual)
        row_prefix_rows = flat_prior['harness_test_counts']['workspace_tests']
        row_prefix_path = 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs'
        self.assertEqual(current.digest(row_prefix_prior), current.ROW_PREFIX_PREVIOUS)
        self.assertEqual((len(row_prefix_rows), sum(x['tests'] for x in row_prefix_rows.values()),
                          sum(x['ignored'] for x in row_prefix_rows.values())), (120, 4610, 43))
        self.assertEqual(row_prefix_rows['unit/rapid_profiler/lib'], counts(629, 37))
        self.assertEqual(row_prefix_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(627, 37))
        self.assertEqual((row_prefix['default_method_additions'], row_prefix['new_method_declarations'],
                          row_prefix['default_method_removals'], row_prefix['default_harness_changes'],
                          row_prefix['default_ignore_changes'], row_prefix['default_doctest_additions'],
                          row_prefix['recorder_identity_changes'], row_prefix['feature_method_additions'],
                          row_prefix['feature_method_removals']), (2, 2, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(row_prefix['added_default_methods'], {row_prefix_path: [
            'row_prefix_matches_full_shape_at_each_position_and_receipt_kind',
            'row_prefix_preserves_current_overflow_and_earlier_row_error_order']})
        self.assertEqual(row_prefix['default_method_instances'], {row_prefix_path: ['unit/rapid_profiler/lib']})
        self.assertEqual((row_prefix['added_feature_methods'], row_prefix['added_ignored_methods']), ({}, {}))
        self.assertEqual((len(row_prefix['source_paths']), len(row_prefix['source_projections'])), (2, 2))
        self.assertEqual(row_prefix_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], row_prefix_prior['recorder_tests']), (366, 366))
        for path, row in row_prefix['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_4261826(path, raw, 'row_prefix_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (row_prefix['source_preimages'][path]['bytes'], row['previous_sha256']))
            self.assertEqual(row['previous_sha256'],
                             current.DATA['source_successor_f9f89ac']['sources'][path]
                             if path in current.DATA['source_successor_f9f89ac']['sources'] else
                             current.DATA['source_successor_bad32a8']['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^row_prefix_source_inverse$'):
                    current.source_before_4261826(path, wrong, 'row_prefix_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(row_prefix['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^row_prefix_source_inverse$'):
                        current.source_before_4261826(path, raw, 'row_prefix_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_4261826(row_prefix_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(row_prefix_rows['unit/rapid_profiler/lib'][field]),
                          row_prefix_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_4261826(wrong)
        wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_4261826(wrong)
        read = Path.read_bytes
        row_prefix_stimuli = [(row_prefix_path, 'fn ' + name + '(')
                             for name in row_prefix['added_default_methods'][row_prefix_path]]
        row_prefix_stimuli += [(path, literal) for path, literals in row_prefix['module_chains'].items()
                              for literal in literals]
        for path, literal in row_prefix_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            replacement = literal.replace('(', '_wrong(', 1) if literal.startswith('fn ') else literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('row-prefix declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # The current publisher adds two feature-only declarations; the entire
        # default catalog and every historical source target remain exact.
        publisher = current.DATA['source_successor_fe97f683']
        publisher_path = 'tools/rapid-profiler/native-interval/normal/module/early_entry/publisher.rs'
        self.assertEqual((publisher['default_method_additions'], publisher['default_method_removals'],
                          publisher['default_harness_changes'], publisher['default_ignore_changes'],
                          publisher['default_doctest_additions'], publisher['recorder_identity_changes'],
                          publisher['feature_method_additions'], publisher['feature_method_removals']),
                         (0, 0, 0, 0, 0, 0, 2, 0))
        self.assertEqual(publisher['added_feature_methods'], {publisher_path: [
            'avx2_selection_requires_every_actual_image_and_complete_ymm_state',
            'selected_publisher_preserves_all640_cells_resets_partition_and_alignment']})
        self.assertEqual(publisher['feature_method_instances'], {publisher_path: [
            'test/frontend_native_calibrations [frontend-native-qualification]']})
        self.assertEqual((publisher['added_default_methods'], publisher['added_ignored_methods'],
                          publisher['workspace_changes']), ({}, {}, {}))
        self.assertEqual((publisher['current_corpus_sha256'], publisher['previous_corpus_sha256']),
                         (current.ROW_PREFIX_PREVIOUS, current.ROW_PREFIX_PREVIOUS))
        self.assertEqual(current.digest(actual), current.CURRENT)
        self.assertEqual((len(publisher['source_paths']), len(publisher['source_projections'])), (2, 2))
        self.assertEqual(current.DATA['methods'][publisher_path]['all'],
                         current.DATA['source_successor_65ee8ea']['feature_only_methods'][publisher_path]
                         + publisher['added_feature_methods'][publisher_path])
        for path, literals in publisher['module_chains'].items():
            self.assertEqual(literals, current.DATA['module_chains'][path])
            text = (current.ROOT / path).read_text()
            self.assertTrue(all(text.count(literal) == 1 for literal in literals))
        for path, row in publisher['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_fe97f683(path, raw, 'publisher_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (publisher['source_preimages'][path]['bytes'], row['previous_sha256']))
            self.assertEqual(row['previous_sha256'], current.DATA['source_successor_e691b0d']['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^publisher_source_inverse$'):
                    current.source_before_fe97f683(path, wrong, 'publisher_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(publisher['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^publisher_source_inverse$'):
                        current.source_before_fe97f683(path, raw, 'publisher_source_inverse')
        read = Path.read_bytes
        target = current.ROOT / publisher_path
        raw = read(target)
        for name in publisher['added_feature_methods'][publisher_path]:
            literal = ('fn ' + name + '(').encode()
            self.assertEqual(raw.count(literal), 1)
            wrong = raw.replace(literal, ('fn ' + name + '_wrong(').encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {publisher_path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != publisher_path else (_ for _ in ()).throw(AssertionError('publisher declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Immutable binding and completed-PC diagnostics add six default instances.
        binding = current.DATA['source_successor_f9f89ac']
        binding_prior = current.before_f9f89ac(actual)
        binding_rows = row_prefix_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(binding_prior), current.BINDING_PREVIOUS)
        self.assertEqual((len(binding_rows), sum(x['tests'] for x in binding_rows.values()),
                          sum(x['ignored'] for x in binding_rows.values())), (120, 4608, 43))
        self.assertEqual({name: binding_rows[name] for name in binding['workspace_changes']}, {
            'unit/rapid_profiler/lib': counts(627, 37),
            'test/frontend_native_calibrations': counts(238, 1),
            'unit/ordinary_interval/main': counts(523, 1)})
        self.assertEqual((binding['default_method_additions'], binding['new_method_declarations'],
                          binding['default_method_removals'], binding['default_harness_changes'],
                          binding['default_ignore_changes'], binding['default_doctest_additions'],
                          binding['recorder_identity_changes'], binding['feature_method_additions'],
                          binding['feature_method_removals']), (6, 4, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(binding['added_default_methods'], {'tests/support/native_normal_module/early_entry/pc_counts.rs': ['counts_only_completed_transitions_and_preserves_each_pc', 'capacity_exhaustion_counts_drops_without_growing_or_losing_records'], 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/binding_envelope.rs': ['binding_envelope_preserves_malformed_profiles_and_fresh_error_order', 'binding_envelope_replacement_revalidates_and_retains_exact_arc']})
        self.assertEqual(binding['default_method_instances'], {'tests/support/native_normal_module/early_entry/pc_counts.rs': ['test/frontend_native_calibrations', 'unit/ordinary_interval/main'], 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/binding_envelope.rs': ['unit/rapid_profiler/lib']})
        self.assertEqual(sum(len(names) * len(binding['default_method_instances'][path])
                             for path, names in binding['added_default_methods'].items()), 6)
        self.assertEqual(binding['added_ignored_methods'], {})
        self.assertEqual((len(binding['source_paths']), len(binding['source_projections'])), (5, 3))
        self.assertEqual([path for path, value in binding['source_preimages'].items() if value is None],
                         ['tests/support/native_normal_module/early_entry/pc_counts.rs', 'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/binding_envelope.rs'])
        self.assertEqual(binding_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], binding_prior['recorder_tests']), (366, 366))
        for path, row in binding['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_f9f89ac(path, raw, 'binding_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (binding['source_preimages'][path]['bytes'], row['previous_sha256']))
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^binding_source_inverse$'):
                    current.source_before_f9f89ac(path, wrong, 'binding_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(binding['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^binding_source_inverse$'):
                        current.source_before_f9f89ac(path, raw, 'binding_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_f9f89ac(binding_prior)
        for name in binding['workspace_changes']:
            for field in ('tests', 'ignored'):
                for value in (None, True, float(binding_rows[name][field]), binding_rows[name][field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_f9f89ac(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_f9f89ac(wrong)
        read = Path.read_bytes
        binding_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in binding['added_default_methods'].items() for name in names]
        binding_stimuli += [(path, literal, '')
            for path, literals in binding['module_chains'].items() for literal in literals]
        for path, literal, replacement in binding_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('binding declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in binding['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # Current-RET geometry adds two default tests; the complete physical
        # predecessor and every earlier historical target stay exact.
        current_ret = current.DATA['source_successor_bad32a8']
        current_ret_prior = current.before_bad32a8(actual)
        current_ret_rows = binding_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(current_ret_prior), current.CURRENT_RET_PREVIOUS)
        self.assertEqual((len(current_ret_rows), sum(x['tests'] for x in current_ret_rows.values()),
                          sum(x['ignored'] for x in current_ret_rows.values())), (120, 4602, 43))
        self.assertEqual(current_ret_rows['unit/rapid_profiler/lib'], counts(625, 37))
        self.assertEqual(current_ret_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(623, 37))
        self.assertEqual(current_ret_rows['test/frontend_native_calibrations'], counts(236, 1))
        self.assertEqual((current_ret['default_method_additions'], current_ret['default_method_removals'],
                          current_ret['default_harness_changes'], current_ret['default_ignore_changes'],
                          current_ret['default_doctest_additions'], current_ret['recorder_identity_changes'],
                          current_ret['feature_method_additions'], current_ret['feature_method_removals']),
                         (2, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(current_ret['added_default_methods'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs': [
                'current_ret_geometry_preserves_paired_late_refusals_and_receipts',
                'current_ret_geometry_uses_actual_validation_with_foreign_rows_and_rearm']})
        self.assertEqual(current_ret['default_method_instances'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs':
                ['unit/rapid_profiler/lib']})
        self.assertEqual(sum(len(names) * len(current_ret['default_method_instances'][path])
                             for path, names in current_ret['added_default_methods'].items()), 2)
        self.assertEqual(current_ret['added_ignored_methods'], {})
        self.assertEqual((len(current_ret['source_paths']), len(current_ret['source_projections'])), (3, 3))
        self.assertTrue(all(value is not None for value in current_ret['source_preimages'].values()))
        self.assertEqual(current_ret_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], current_ret_prior['recorder_tests']), (366, 366))
        for path, row in current_ret['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_bad32a8(path, raw, 'current_ret_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (current_ret['source_preimages'][path]['bytes'], row['previous_sha256']))
            self.assertEqual(row['previous_sha256'], current.DATA['source_successor_e5462b7']['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^current_ret_source_inverse$'):
                    current.source_before_bad32a8(path, wrong, 'current_ret_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(current_ret['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^current_ret_source_inverse$'):
                        current.source_before_bad32a8(path, raw, 'current_ret_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_bad32a8(current_ret_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(current_ret_rows['unit/rapid_profiler/lib'][field]),
                          current_ret_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_bad32a8(wrong)
        wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_bad32a8(wrong)
        read = Path.read_bytes
        current_ret_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in current_ret['added_default_methods'].items() for name in names]
        current_ret_stimuli += [(path, literal, '')
            for path, literals in current_ret['module_chains'].items() for literal in literals]
        for path, literal, replacement in current_ret_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('current-RET declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        # Physical slots and retained geometry add seven default library tests.
        # The complete e691 catalog and every earlier source target remain exact.
        physical = current.DATA['source_successor_e5462b7']
        physical_prior = current.before_e5462b7(actual)
        physical_rows = current_ret_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(physical_prior), current.PHYSICAL_PREVIOUS)
        self.assertEqual((len(physical_rows), sum(x['tests'] for x in physical_rows.values()),
                          sum(x['ignored'] for x in physical_rows.values())), (120, 4600, 43))
        self.assertEqual(physical_rows['unit/rapid_profiler/lib'], counts(623, 37))
        self.assertEqual(physical_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(616, 37))
        self.assertEqual(physical_rows['test/frontend_native_calibrations'], counts(236, 1))
        self.assertEqual((physical['default_method_additions'], physical['default_method_removals'],
                          physical['default_harness_changes'], physical['default_ignore_changes'],
                          physical['default_doctest_additions'], physical['recorder_identity_changes'],
                          physical['feature_method_additions'], physical['feature_method_removals']),
                         (7, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(physical['added_default_methods'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs': [
                'physical_occupancy_matches_original_for_all_6480_metadata_patterns',
                'physical_occupancy_matches_original_live_prefixes_and_rearm',
                'geometry_facts_match_original_across_masks_rearm_and_reset',
                'geometry_facts_require_exact_owner_and_key_and_invalidate_on_replacement',
                'geometry_facts_preserve_original_geometry_error_precedence'],
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/physical_slots.rs': [
                'all_occupancies_and_replacements_match_original_array_queries',
                'out_of_range_replacements_preserve_all_values_masks_and_counts']})
        self.assertEqual(physical['default_method_instances'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs':
                ['unit/rapid_profiler/lib'],
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/physical_slots.rs':
                ['unit/rapid_profiler/lib']})
        self.assertEqual(sum(len(names) * len(physical['default_method_instances'][path])
                             for path, names in physical['added_default_methods'].items()), 7)
        self.assertEqual(physical['added_ignored_methods'], {})
        self.assertEqual((len(physical['source_paths']), len(physical['source_projections'])), (7, 6))
        self.assertEqual([path for path, value in physical['source_preimages'].items() if value is None],
                         ['tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/physical_slots.rs'])
        self.assertEqual(physical_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], physical_prior['recorder_tests']), (366, 366))
        for path, row in physical['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_e5462b7(path, raw, 'physical_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (physical['source_preimages'][path]['bytes'], row['previous_sha256']))
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^physical_source_inverse$'):
                    current.source_before_e5462b7(path, wrong, 'physical_source_inverse')
            for field in ('edits', 'current_sha256', 'previous_sha256'):
                malformed = copy.deepcopy(row)
                if field == 'edits': malformed['edits'][0][2] += '\n'
                else: malformed[field] = '0' * 64
                with patch.dict(physical['source_projections'], {path: malformed}):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^physical_source_inverse$'):
                        current.source_before_e5462b7(path, raw, 'physical_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e5462b7(physical_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(physical_rows['unit/rapid_profiler/lib'][field]),
                          physical_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_e5462b7(wrong)
        wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e5462b7(wrong)
        read = Path.read_bytes
        physical_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in physical['added_default_methods'].items() for name in names]
        physical_stimuli += [(path, literal, '')
            for path, literals in physical['module_chains'].items() for literal in literals]
        for path, literal, replacement in physical_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in physical['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # The entry post-shape proof adds exactly two default library tests.
        # Changed feature-only publisher code contributes no new test methods.
        entry_normal = current.DATA['source_successor_e691b0d']
        entry_normal_prior = current.before_e691b0d(actual)
        entry_normal_rows = physical_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(entry_normal_prior), current.ENTRY_PROOF_PREVIOUS)
        self.assertEqual((len(entry_normal_rows), sum(x['tests'] for x in entry_normal_rows.values()),
                          sum(x['ignored'] for x in entry_normal_rows.values())), (120, 4593, 43))
        self.assertEqual(entry_normal_rows['unit/rapid_profiler/lib'], counts(616, 37))
        self.assertEqual(entry_normal_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(614, 37))
        self.assertEqual(entry_normal_rows['test/frontend_native_calibrations'], counts(236, 1))
        self.assertEqual((entry_normal['default_method_additions'], entry_normal['default_method_removals'],
                          entry_normal['default_harness_changes'], entry_normal['default_ignore_changes'],
                          entry_normal['default_doctest_additions'], entry_normal['recorder_identity_changes'],
                          entry_normal['feature_method_additions'], entry_normal['feature_method_removals']),
                         (2, 0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(entry_normal['added_default_methods'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs': [
                'entry_normal_proof_matches_full_postshape_across_receipts_and_rearm',
                'entry_normal_proof_keeps_changed_fields_depth_and_late_error_order']})
        self.assertEqual(sum(len(names) * len(entry_normal['default_method_instances'][path])
                             for path, names in entry_normal['added_default_methods'].items()), 2)
        self.assertEqual(entry_normal['default_method_instances'], {
            'tools/rapid-profiler/src/frontend_native/always_on/normal/module/owned/early_entry/checked_visit/tests.rs':
                ['unit/rapid_profiler/lib']})
        self.assertEqual(entry_normal['unchanged_feature_only_methods'],
                         current.DATA['source_successor_65ee8ea']['feature_only_methods'])
        self.assertEqual(sum(map(len, entry_normal['unchanged_feature_only_methods'].values())), 3)
        self.assertEqual(entry_normal['added_ignored_methods'], {})
        self.assertEqual((len(entry_normal['source_paths']), len(entry_normal['source_projections'])), (4, 4))
        self.assertEqual(entry_normal_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], entry_normal_prior['recorder_tests']), (366, 366))
        for path, row in entry_normal['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_e691b0d(path, raw, 'entry_normal_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (entry_normal['source_preimages'][path]['bytes'], row['previous_sha256']))
            self.assertEqual(row['previous_sha256'], current.DATA['source_successor_65ee8ea']['sources'][path])
            for wrong in (raw + b'\n', raw[:-1], prior, bytearray(raw), raw.decode()):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^entry_normal_source_inverse$'):
                    current.source_before_e691b0d(path, wrong, 'entry_normal_source_inverse')
            malformed = copy.deepcopy(row)
            malformed['edits'][0][2] += '\n'
            with patch.dict(entry_normal['source_projections'], {path: malformed}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^entry_normal_source_inverse$'):
                    current.source_before_e691b0d(path, raw, 'entry_normal_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e691b0d(entry_normal_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(entry_normal_rows['unit/rapid_profiler/lib'][field]),
                          entry_normal_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_e691b0d(wrong)
        wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e691b0d(wrong)
        wrong = copy.deepcopy(actual)
        wrong['harness_test_counts']['workspace_tests']['test/frontend_native_calibrations'] = counts(239, 1)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e691b0d(wrong)
        read = Path.read_bytes
        entry_normal_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for group in ('added_default_methods', 'unchanged_feature_only_methods')
            for path, names in entry_normal[group].items() for name in names]
        entry_normal_stimuli += [(path, literal, '')
            for path, literals in entry_normal['module_chains'].items() for literal in literals]
        for path, literal, replacement in entry_normal_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in entry_normal['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # Current RET proofs add ten default tests; the publisher's three tests
        # remain feature-only and cannot increase the default calibration row.
        ret = current.DATA['source_successor_65ee8ea']
        ret_prior = current.before_65ee8ea(actual)
        ret_rows = entry_normal_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(ret_prior), current.RET_PROOF_PREVIOUS)
        self.assertEqual((len(ret_rows), sum(x['tests'] for x in ret_rows.values()),
                          sum(x['ignored'] for x in ret_rows.values())), (120, 4591, 43))
        self.assertEqual(ret_rows['unit/rapid_profiler/lib'], counts(614, 37))
        self.assertEqual(ret_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(604, 37))
        self.assertEqual(ret_rows['test/frontend_native_calibrations'], counts(236, 1))
        self.assertEqual((ret['default_method_additions'], ret['default_method_removals'],
                          ret['default_harness_changes'], ret['default_ignore_changes'],
                          ret['default_doctest_additions'], ret['recorder_identity_changes']),
                         (10, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(ret['default_method_instances'][path])
                             for path, names in ret['added_default_methods'].items()), 10)
        self.assertEqual(sum(map(len, ret['feature_only_methods'].values())), 3)
        self.assertEqual(ret['added_ignored_methods'], {})
        self.assertEqual((len(ret['source_paths']), len(ret['source_projections'])), (5, 4))
        self.assertEqual([path for path, value in ret['source_preimages'].items() if value is None],
                         ['tools/rapid-profiler/native-interval/normal/module/early_entry/publisher.rs'])
        self.assertEqual(ret_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        for path, row in ret['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_65ee8ea(path, raw, 'ret_proof_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (ret['source_preimages'][path]['bytes'], row['previous_sha256']))
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ret_proof_source_inverse$'):
                current.source_before_65ee8ea(path, raw + b'\n', 'ret_proof_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_65ee8ea(ret_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(ret_rows['unit/rapid_profiler/lib'][field]),
                          ret_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_65ee8ea(wrong)
        wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_65ee8ea(wrong)
        wrong = copy.deepcopy(actual)
        wrong['harness_test_counts']['workspace_tests']['test/frontend_native_calibrations'] = counts(239, 1)
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_65ee8ea(wrong)
        read = Path.read_bytes
        ret_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for group in ('added_default_methods', 'feature_only_methods')
            for path, names in ret[group].items() for name in names]
        ret_stimuli += [(path, literal, '')
            for path, literals in ret['module_chains'].items() for literal in literals]
        for path, literal, replacement in ret_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in ret['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # The later snapshot implementation adds three tests in the same
        # Rapid library. Its prior source and complete catalog stay explicit.
        snapshot = current.DATA['source_successor_79b34bc']
        snapshot_prior = current.before_79b34bc(actual)
        snapshot_rows = ret_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(snapshot_prior), current.ENTRY_ADMISSION_CURRENT)
        self.assertEqual((len(snapshot_rows), sum(x['tests'] for x in snapshot_rows.values()),
                          sum(x['ignored'] for x in snapshot_rows.values())), (120, 4581, 43))
        self.assertEqual((snapshot['default_method_additions'], snapshot['default_method_removals'],
                          snapshot['default_harness_changes'], snapshot['default_ignore_changes'],
                          snapshot['default_doctest_additions'], snapshot['recorder_identity_changes']),
                         (3, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(snapshot['default_method_instances'][path])
                             for path, names in snapshot['added_default_methods'].items()), 3)
        self.assertEqual(snapshot_rows['unit/rapid_profiler/lib'], counts(604, 37))
        self.assertEqual(snapshot_prior['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'],
                         counts(601, 37))
        self.assertEqual(snapshot['added_ignored_methods'], {})
        for path, row in snapshot['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_79b34bc(path, raw, 'snapshot_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (snapshot['source_preimages'][path]['bytes'], row['previous_sha256']))
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^snapshot_source_inverse$'):
                current.source_before_79b34bc(path, raw + b'\n', 'snapshot_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_79b34bc(snapshot_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(snapshot_rows['unit/rapid_profiler/lib'][field]),
                          snapshot_rows['unit/rapid_profiler/lib'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_79b34bc(wrong)
        wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests']['unit/rapid_profiler/lib']
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_79b34bc(wrong)
        read = Path.read_bytes
        snapshot_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in snapshot['added_default_methods'].items() for name in names]
        snapshot_stimuli += [(path, literal, '')
            for path, literals in snapshot['module_chains'].items() for literal in literals]
        for path, literal, replacement in snapshot_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in snapshot['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # Keep the merged typed entry-admission catalog distinct from every
        # earlier boundary, including its four explicitly ignored native tests.
        entry = current.DATA['source_successor_a8acec5']
        entry_prior = current.before_a8acec5(actual)
        entry_rows = snapshot_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(entry_prior), current.ENTRY_ADMISSION_PREVIOUS)
        self.assertEqual((len(entry_rows), sum(x['tests'] for x in entry_rows.values()),
                          sum(x['ignored'] for x in entry_rows.values())), (120, 4578, 43))
        self.assertEqual((entry['default_method_additions'], entry['default_doctest_additions'],
                          entry['default_method_removals'], entry['default_harness_changes'],
                          entry['default_ignore_changes'], entry['recorder_identity_changes']),
                         (33, 1, 0, 1, 4, 0))
        self.assertEqual(sum(len(names) * len(entry['default_method_instances'][path])
                             for path, names in entry['added_default_methods'].items()), 33)
        self.assertEqual(sum(map(len, entry['added_default_methods'].values())), 30)
        self.assertEqual(entry['default_method_instances']['tests/support/native_normal_module/early_entry.rs'],
                         ['test/frontend_native_calibrations', 'unit/ordinary_interval/main'])
        self.assertEqual(entry_rows['unit/ordinary_interval/main'], counts(521, 1))
        self.assertEqual(entry_prior['harness_test_counts']['workspace_tests']['unit/ordinary_interval/main'],
                         counts(518, 1))
        self.assertEqual(sum(len(names) for names in entry['added_ignored_methods'].values()), 4)
        self.assertEqual(sum(len(blocks) for blocks in entry['doctests'].values()), 1)
        self.assertEqual(entry_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        self.assertEqual((actual['recorder_tests'], entry_prior['recorder_tests']), (366, 366))
        for path, row in entry['source_projections'].items():
            raw = (current.ROOT / path).read_bytes()
            prior = current.source_before_a8acec5(path, raw, 'entry_admission_source_inverse')
            self.assertEqual((len(prior), hashlib.sha256(prior).hexdigest()),
                             (entry['source_preimages'][path]['bytes'], row['previous_sha256']))
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^entry_admission_source_inverse$'):
                current.source_before_a8acec5(path, raw + b'\n', 'entry_admission_source_inverse')
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_a8acec5(entry_prior)
        for name, change in entry['workspace_changes'].items():
            self.assertEqual(entry_rows[name], change['current'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(entry_rows[name][field]), entry_rows[name][field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_a8acec5(wrong)
            wrong = copy.deepcopy(actual)
            del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_a8acec5(wrong)
        read = Path.read_bytes
        entry_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in entry['added_default_methods'].items() for name in names]
        entry_stimuli += [(path, literal, '')
            for path, literals in entry['module_chains'].items() for literal in literals]
        entry_stimuli += [(path, block, replacement)
            for path, blocks in entry['doctests'].items() for block in blocks
            for replacement in ('', block + '\n' + block, block.replace('compile_fail,E0277', 'ignore'))]
        entry_stimuli += [tuple(row) for row in entry['ignore_stimuli']]
        for path, literal, replacement in entry_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            self.assertNotEqual(wrong, raw)
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('entry-admission declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in entry['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        # The merged benchmark contributes three real tests in one new harness.
        # Preserve the whole earlier catalog as a distinct, refused predecessor.
        point_prior = current.before_e5ab521(actual)
        point_rows = entry_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(point_prior), current.POINT_PREVIOUS)
        self.assertEqual((len(point_rows), sum(x['tests'] for x in point_rows.values()),
                          sum(x['ignored'] for x in point_rows.values())), (119, 4544, 39))
        self.assertEqual(point_rows['unit/point_throughput/main'], dict(tests=3, ignored=0))
        self.assertEqual(point_prior['harness_test_counts']['serial_launch'],
                         actual['harness_test_counts']['serial_launch'])
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
            current.before_e5ab521(point_prior)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(point_rows['unit/point_throughput/main'][field]),
                          point_rows['unit/point_throughput/main'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/point_throughput/main'][field] = value
                self.assertNotEqual(current.digest(wrong), current.digest(actual))
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_e5ab521(wrong)
        native_indexed = current.before_29859(actual)
        rows = native_indexed['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (112, 4255, 37))
        self.assertEqual(current.digest(native_indexed), current.NATIVE_INDEXED_CURRENT)
        phase_catalog = current.before_96378(actual)
        rows = phase_catalog['harness_test_counts']['workspace_tests']
        self.assertEqual((len(rows), sum(x['tests'] for x in rows.values()),
                          sum(x['ignored'] for x in rows.values())), (112, 4266, 37))
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

        # Exact current phase diagnostics add eleven real tests in the existing
        # harness. The old native-indexed whole catalog remains a predecessor,
        # never an alternative accepted by the current qualification entrypoint.
        phase = current.DATA['source_successor_29859']
        self.assertEqual((phase['default_method_additions'], phase['default_method_removals'],
                          phase['default_harness_changes'], phase['default_ignore_changes'],
                          phase['recorder_identity_changes']), (11, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) for names in phase['added_default_methods'].values()), 11)
        self.assertEqual(phase['default_method_instances'], {
            path: ['unit/ordinary_interval/main'] for path in phase['added_default_methods']})
        self.assertEqual(entry_prior['harness_test_counts']['workspace_tests']['unit/ordinary_interval/main'],
                         dict(tests=518, ignored=1))
        self.assertEqual(native_indexed['harness_test_counts']['workspace_tests']['unit/ordinary_interval/main'],
                         dict(tests=507, ignored=1))
        for wrong in (native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_29859(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for field in ('tests', 'ignored'):
            for value in (None, True, float(rows['unit/ordinary_interval/main'][field]),
                          rows['unit/ordinary_interval/main'][field] + 1):
                wrong = copy.deepcopy(actual)
                wrong['harness_test_counts']['workspace_tests']['unit/ordinary_interval/main'][field] = value
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                    current.before_29859(wrong)
        new_stimuli = [(path, name, name + '_wrong')
                       for path, names in phase['added_default_methods'].items() for name in names]
        new_stimuli += [(path, literal, '')
                        for path, literals in phase['module_chains'].items() for literal in literals]
        self.assertEqual(len(new_stimuli), 22)
        for path, literal, replacement in new_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            # Repair the outer hash so the declaration/module gate, rather
            # than the inverse or stale whole-file pin, must reject the change.
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('phase declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in phase['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # This exact catalog is a new boundary. Neither historical complete
        # catalog, missing harness, changed count/type nor old ignore census
        # may substitute for the actual current workspace.
        incoming = current.DATA['source_successor_96378']
        live_rows = current.before_fd4c6(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual((len(live_rows), sum(x['tests'] for x in live_rows.values()),
                          sum(x['ignored'] for x in live_rows.values())), (113, 4312, 39))
        self.assertEqual(current.digest(phase_catalog), current.PHASE_CURRENT)
        self.assertEqual((incoming['default_method_additions'], incoming['default_doctest_additions'],
                          incoming['default_method_removals'], incoming['default_harness_changes'],
                          incoming['default_ignore_changes'], incoming['recorder_identity_changes']),
                         (44, 2, 0, 1, 2, 0))
        self.assertEqual(sum(len(names) * len(incoming['default_method_instances'][path])
                             for path, names in incoming['added_default_methods'].items()), 44)
        self.assertEqual(sum(len(names) for names in incoming['added_ignored_methods'].values()), 2)
        self.assertEqual(sum(len(rows) for rows in incoming['doctests'].values()), 2)
        self.assertEqual(incoming['excluded_standalone'], dict(
            path='evaluation/custody-file-read-probe/probe.rs', default_test_harness=False,
            reason='No Cargo target or module includes this standalone diagnostic.'))
        for wrong in (phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_96378(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in incoming['workspace_changes'].items():
            self.assertEqual(live_rows[name], change['current'])
            # Mutate the current input; live_rows remains the exact historical boundary.
            current_row = actual['harness_test_counts']['workspace_tests'][name]
            for field in ('tests', 'ignored'):
                for value in (None, True, float(current_row[field]), current_row[field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    self.assertNotEqual(current.digest(wrong), current.digest(actual))
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_96378(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            self.assertNotEqual(current.digest(wrong), current.digest(actual))
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_96378(wrong)
        incoming_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in incoming['added_default_methods'].items() for name in names]
        incoming_stimuli += [(path, literal, '')
            for path, literals in incoming['module_chains'].items() for literal in literals]
        incoming_stimuli += [(path, block, replacement)
            for path, blocks in incoming['doctests'].items() for block in blocks
            for replacement in ('', block + '\n' + block, block.replace('compile_fail,E0277', 'ignore'))]
        incoming_stimuli += [(path, literal, literal.replace('#[ignore', '#[cfg'))
            for path in incoming['added_ignored_methods']
            for literal in re.findall(r'#\[ignore[^\n]*', (current.ROOT / path).read_text())]
        for path, literal, replacement in incoming_stimuli:
            target = current.ROOT / path; raw = read(target)
            # The current export blocks grew; authenticate the old declarations
            # in their exact predecessor before mutating the complete new blocks.
            declaration = current.DATA['source_successor_a8acec5']['module_chain_changes'].get(path)
            if declaration is not None and literal == declaration['previous']:
                prior = current.source_before_a8acec5(path, raw, 'incoming_export_inverse')
                self.assertEqual(prior.count(literal.encode()), 1)
                literal = declaration['current']
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('incoming declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in incoming['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # Current placement adds thirteen tests to three existing harnesses.
        # Preserve the entire prior catalog and every earlier control above.
        placement = current.DATA['source_successor_fd4c6']
        placement_rows = current.before_b0a30(actual)['harness_test_counts']['workspace_tests']
        placement_before = current.before_fd4c6(actual)
        self.assertEqual(current.digest(placement_before), current.PLACEMENT_PREVIOUS)
        self.assertEqual((len(placement_rows), sum(x['tests'] for x in placement_rows.values()),
                          sum(x['ignored'] for x in placement_rows.values())), (113, 4325, 39))
        self.assertEqual((placement['default_method_additions'], placement['default_doctest_additions'],
                          placement['default_method_removals'], placement['default_harness_changes'],
                          placement['default_ignore_changes'], placement['recorder_identity_changes']),
                         (13, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(placement['default_method_instances'][path])
                             for path, names in placement['added_default_methods'].items()), 13)
        self.assertEqual((placement['added_ignored_methods'], placement['doctests']), ({}, {}))
        for wrong in (placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_fd4c6(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in placement['workspace_changes'].items():
            self.assertEqual(placement_rows[name], change['current'])
            self.assertEqual(placement_before['harness_test_counts']['workspace_tests'][name],
                             change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(placement_rows[name][field]), placement_rows[name][field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_fd4c6(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_fd4c6(wrong)
        placement_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in placement['added_default_methods'].items() for name in names]
        placement_stimuli += [(path, literal, '')
            for path, literals in placement['module_chains'].items() for literal in literals]
        for path, literal, replacement in placement_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('placement declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in placement['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # Entry veneers add 55 methods to four existing harnesses. The
        # complete prior placement catalog remains an independent boundary.
        entry = current.DATA['source_successor_b0a30']
        entry_rows = current.before_b6fea(actual)['harness_test_counts']['workspace_tests']
        entry_before = current.before_b0a30(actual)
        self.assertEqual(current.digest(entry_before), current.ENTRY_PREVIOUS)
        self.assertEqual((len(entry_rows), sum(x['tests'] for x in entry_rows.values()),
                          sum(x['ignored'] for x in entry_rows.values())), (113, 4380, 39))
        self.assertEqual((entry['default_method_additions'], entry['default_doctest_additions'],
                          entry['default_method_removals'], entry['default_harness_changes'],
                          entry['default_ignore_changes'], entry['recorder_identity_changes']),
                         (55, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(entry['default_method_instances'][path])
                             for path, names in entry['added_default_methods'].items()), 55)
        self.assertEqual((entry['added_ignored_methods'], entry['doctests']), ({}, {}))
        for wrong in (entry_before, placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_b0a30(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in entry['workspace_changes'].items():
            self.assertEqual(entry_rows[name], change['current'])
            self.assertEqual(entry_before['harness_test_counts']['workspace_tests'][name],
                             change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(entry_rows[name][field]), entry_rows[name][field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_b0a30(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_b0a30(wrong)
        entry_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in entry['added_default_methods'].items() for name in names]
        entry_stimuli += [(path, literal, '')
            for path, literals in entry['module_chains'].items() for literal in literals]
        for path, literal, replacement in entry_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('entry declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in entry['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # The new Linux loader is a real default integration harness. All
        # earlier complete catalogs and their assertions remain unchanged.
        rx = current.DATA['source_successor_b6fea']
        rx_rows = current.before_124521(actual)['harness_test_counts']['workspace_tests']
        rx_before = current.before_b6fea(actual)
        self.assertEqual(current.digest(rx_before), current.RX_PREVIOUS)
        self.assertEqual((len(rx_rows), sum(x['tests'] for x in rx_rows.values()),
                          sum(x['ignored'] for x in rx_rows.values())), (114, 4395, 39))
        self.assertEqual((rx['default_method_additions'], rx['default_doctest_additions'],
                          rx['default_method_removals'], rx['default_harness_changes'],
                          rx['default_ignore_changes'], rx['recorder_identity_changes']),
                         (15, 0, 0, 1, 0, 0))
        self.assertEqual(sum(len(names) * len(rx['default_method_instances'][path])
                             for path, names in rx['added_default_methods'].items()), 15)
        self.assertEqual((rx['added_ignored_methods'], rx['doctests']), ({}, {}))
        self.assertEqual(rx['default_method_instances']['tools/elf-rewrite/tests/rx_run_loader.rs'],
                         ['test/rx_run_loader'])
        for wrong in (rx_before, entry_before, placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_b6fea(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in rx['workspace_changes'].items():
            self.assertEqual(rx_rows[name], change['current'])
            self.assertEqual(rx_before['harness_test_counts']['workspace_tests'].get(name),
                             change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(rx_rows[name][field]), rx_rows[name][field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_b6fea(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_b6fea(wrong)
        rx_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in rx['added_default_methods'].items() for name in names]
        rx_stimuli += [(path, literal, '')
            for path, literals in rx['module_chains'].items() for literal in literals]
        for path, literal, replacement in rx_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('RX-run declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in rx['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()
        loader = 'test/rx_run_loader'
        loader_header = ('     Running tests/rx_run_loader.rs '
                         '(target/debug/deps/rx_run_loader-0123456789abcdef)')
        loader_log = '\n'.join((loader_header, 'running 2 tests', summary(2)))
        loader_expected = {loader: counts(2)}
        self.assertEqual(parsing.harness_id(loader_header), loader)
        self.assertEqual(rx_rows[loader], loader_expected[loader])
        loader_row = parsing.parse_harnesses(loader_log, loader_expected, 0)[0]
        self.assertEqual(loader_row['outer'], dict(passed=2, failed=0, ignored=0,
                                                  measured=0, filtered=0, result='ok'))
        for bad in (loader_log.replace('running 2 tests', 'running 1 test'),
                    loader_log.replace('running 2 tests', 'running 3 tests'),
                    loader_log.replace(summary(2), summary(1, ignored=1)),
                    loader_log.replace(summary(2), summary(1, filtered=1)),
                    loader_log.replace(summary(2), ''), loader_log + '\n' + loader_log,
                    loader_log.replace('rx_run_loader-', 'other-')):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, loader_expected, 0)
        failed = loader_log.replace(summary(2), summary(1, failed=1))
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^successful_exit_with_failed_summary$'):
            parsing.parse_harnesses(failed, loader_expected, 0)
        loader_row = parsing.parse_harnesses(failed, loader_expected, 1)[0]
        self.assertEqual((loader_row['outer']['result'], loader_row['outer']['passed'],
                          loader_row['outer']['failed']), ('FAILED', 1, 1))


        # All twenty overlapping-relay methods remain mandatory on the same
        # four default harnesses, above the complete packed-RX predecessor.
        overlap = current.DATA['source_successor_124521']
        overlap_rows = current.before_abe7(actual)['harness_test_counts']['workspace_tests']
        overlap_before = current.before_124521(actual)
        self.assertEqual(current.digest(overlap_before), current.OVERLAP_PREVIOUS)
        self.assertEqual((len(overlap_rows), sum(x['tests'] for x in overlap_rows.values()),
                          sum(x['ignored'] for x in overlap_rows.values())), (114, 4415, 39))
        self.assertEqual((overlap['default_method_additions'], overlap['default_doctest_additions'],
                          overlap['default_method_removals'], overlap['default_harness_changes'],
                          overlap['default_ignore_changes'], overlap['recorder_identity_changes']),
                         (20, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(overlap['default_method_instances'][path])
                             for path, names in overlap['added_default_methods'].items()), 20)
        self.assertEqual((overlap['added_ignored_methods'], overlap['doctests']), ({}, {}))
        self.assertEqual(overlap_before['harness_test_counts']['workspace_tests'], rx_rows)
        for wrong in (overlap_before, rx_before, entry_before, placement_before,
                      phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_124521(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in overlap['workspace_changes'].items():
            self.assertEqual(overlap_rows[name], change['current'])
            self.assertEqual(overlap_before['harness_test_counts']['workspace_tests'][name],
                             change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(overlap_rows[name][field]), overlap_rows[name][field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_124521(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_124521(wrong)
        overlap_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in overlap['added_default_methods'].items() for name in names]
        overlap_stimuli += [(path, literal, '')
            for path, literals in overlap['module_chains'].items() for literal in literals]
        for path, literal, replacement in overlap_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('overlap declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in overlap['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()


        # Incoming finite-region/batch source adds 30 methods and eight docs.
        # Every old catalog remains exact behind the new whole inverse.
        clock = current.DATA['source_successor_abe7']
        clock_rows = current.before_c110(actual)['harness_test_counts']['workspace_tests']
        clock_before = current.before_abe7(actual)
        self.assertEqual(current.digest(clock_before), current.CLOCK_PREVIOUS)
        self.assertEqual((len(clock_rows), sum(x['tests'] for x in clock_rows.values()),
                          sum(x['ignored'] for x in clock_rows.values())), (115, 4453, 39))
        self.assertEqual(clock_before['harness_test_counts']['workspace_tests'], overlap_rows)
        self.assertEqual((clock['default_method_additions'], clock['default_doctest_additions'],
                          clock['default_method_removals'], clock['default_harness_changes'],
                          clock['default_ignore_changes'], clock['recorder_identity_changes']),
                         (30, 8, 0, 1, 0, 0))
        self.assertEqual(sum(len(names) * len(clock['default_method_instances'][path])
                             for path, names in clock['added_default_methods'].items()), 30)
        self.assertEqual(clock['added_ignored_methods'], {})
        self.assertEqual({path: len(blocks) for path, blocks in clock['doctest_sources'].items()},
                         {'src/backedge_clock.rs': 3, 'src/backedge_clock/batch.rs': 8})
        self.assertEqual(sum(block.startswith('    ///') for block in
                             clock['doctest_sources']['src/backedge_clock/batch.rs']), 1)
        self.assertEqual((actual['recorder_tests'], actual['harness_test_counts']['serial_launch']),
                         (clock_before['recorder_tests'], clock_before['harness_test_counts']['serial_launch']))
        for wrong in (clock_before, overlap_before, rx_before, entry_before, placement_before,
                      phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_abe7(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in clock['workspace_changes'].items():
            self.assertEqual(clock_rows[name], change['current'])
            self.assertEqual(clock_before['harness_test_counts']['workspace_tests'].get(name), change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(clock_rows[name][field]), clock_rows[name][field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_abe7(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_abe7(wrong)
        clock_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in clock['added_default_methods'].items() for name in names]
        clock_stimuli += [(path, literal, '')
            for path, literals in clock['module_chains'].items() for literal in literals]
        clock_stimuli += [(path, block, block.replace('```compile_fail', '```'))
            for path, blocks in clock['doctest_sources'].items() for block in blocks]
        for path, literal, replacement in clock_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('clock declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in clock['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        clock_id = 'unit/owned_region_clock/owned_region_clock'
        clock_header = ('     Running unittests examples/owned_region_clock.rs '
                        '(target/debug/examples/owned_region_clock-0123456789abcdef)')
        clock_log = '\n'.join((clock_header, 'running 3 tests', summary(3)))
        clock_expected = {clock_id: counts(3)}
        self.assertEqual(clock_rows[clock_id], clock_expected[clock_id])
        self.assertEqual(parsing.harness_id(clock_header), clock_id)
        clock_row = parsing.parse_harnesses(clock_log, clock_expected, 0)[0]
        self.assertEqual(clock_row['outer'], dict(passed=3, failed=0, ignored=0,
                                                 measured=0, filtered=0, result='ok'))
        self.assertEqual((clock_row['declared_outer_tests'], clock_row['nested_starts'],
                          clock_row['unmatched_nested_starts']), (3, 0, 0))
        for malformed in (
                clock_header.replace('target/debug/examples/', 'target/debug/deps/'),
                clock_header.replace('unittests examples/owned_region_clock.rs',
                                     'unittests src/lib.rs').replace('target/debug/examples/', 'target/debug/deps/'),
                clock_header.replace('target/debug/examples/owned_region_clock-', 'target/debug/deps/other-'),
                clock_header.replace('target/debug/examples/owned_region_clock-', 'target/debug/examples/other-'),
                clock_header.replace('examples/owned_region_clock.rs', 'examples/other.rs'),
                clock_header.replace('owned_region_clock', 'owned_region_clock_extra'),
                clock_header.replace('target/debug/examples/', '/PRIVATE_SENTINEL/'),
                clock_header.replace('target/debug/examples/', 'target/debug/examples/../examples/'),
                clock_header.replace('-0123456789abcdef)', '-nothex)')):
            with self.subTest(clock_header=malformed), self.assertRaises(parsing.InvalidEvidence):
                parsing.harness_id(malformed)
        for bad in (clock_log.replace('running 3 tests', 'running 2 tests'),
                    clock_log.replace('running 3 tests', 'running 4 tests'),
                    clock_log.replace(summary(3), summary(2, filtered=1)),
                    clock_log.replace(summary(3), summary(2, ignored=1)),
                    clock_log.replace(summary(3), summary(2, measured=1)),
                    clock_log.replace('running 3 tests', 'running 3 tests\nrunning 1 test'),
                    clock_log.replace(summary(3), ''), clock_log + '\n' + summary(3),
                    clock_log + '\n' + clock_log):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, clock_expected, 0)
        failed = clock_log.replace(summary(3), summary(2, failed=1))
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^successful_exit_with_failed_summary$'):
            parsing.parse_harnesses(failed, clock_expected, 0)
        failed_row = parsing.parse_harnesses(failed, clock_expected, 1)[0]
        self.assertEqual((failed_row['outer']['result'], failed_row['outer']['passed'],
                          failed_row['outer']['failed']), ('FAILED', 2, 1))


        # Incoming admission comparison adds three exact tests, no new harness.
        # The complete former current catalog remains the sole predecessor.
        comparison = current.DATA['source_successor_c110']
        comparison_before = current.before_c110(actual)
        comparison_rows = current.before_667921(actual)['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(comparison_before), current.ADMISSION_PREVIOUS)
        self.assertEqual(comparison_before['harness_test_counts']['workspace_tests'], clock_rows)
        self.assertEqual((len(comparison_rows), sum(x['tests'] for x in comparison_rows.values()),
                          sum(x['ignored'] for x in comparison_rows.values())), (115, 4456, 39))
        self.assertEqual((comparison['default_method_additions'], comparison['default_doctest_additions'],
                          comparison['default_method_removals'], comparison['default_harness_changes'],
                          comparison['default_ignore_changes'], comparison['recorder_identity_changes']),
                         (3, 0, 0, 0, 0, 0))
        self.assertEqual(sum(len(names) * len(comparison['default_method_instances'][path])
                             for path, names in comparison['added_default_methods'].items()), 3)
        self.assertEqual(comparison['added_ignored_methods'], {})
        self.assertEqual((actual['recorder_tests'], actual['harness_test_counts']['serial_launch']),
                         (comparison_before['recorder_tests'], comparison_before['harness_test_counts']['serial_launch']))
        for wrong in (comparison_before, clock_before, overlap_before, rx_before, entry_before,
                      placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_c110(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in comparison['workspace_changes'].items():
            self.assertEqual(comparison_rows[name], change['current'])
            self.assertEqual(clock_rows[name], change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(comparison_rows[name][field]), comparison_rows[name][field] + 1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_c110(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_c110(wrong)
        comparison_stimuli = [(path, 'fn ' + name + '(', 'fn ' + name + '_wrong(')
            for path, names in comparison['added_default_methods'].items() for name in names]
        comparison_stimuli += [(path, '#[test]\n    fn ' + name + '(',
                                '#[test]\n    #[ignore]\n    fn ' + name + '(')
            for path, names in comparison['added_default_methods'].items() for name in names]
        comparison_stimuli += [(path, literal, '')
            for path, literals in comparison['module_chains'].items() for literal in literals]
        self.assertEqual(len(comparison_stimuli), 10)
        for path, literal, replacement in comparison_stimuli:
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong = raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e: b if p != path else (_ for _ in ()).throw(AssertionError('comparison declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in comparison['source_paths']:
            target = current.ROOT / path; raw = read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate != target: return read(candidate)
                    if missing: raise FileNotFoundError(path)
                    return raw + b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()


        # Early-control contributes 15 new declarations and two complete
        # inherited 35-test populations; all earlier catalogues remain exact.
        early = current.DATA['source_successor_667921']
        early_before = current.before_667921(actual)
        early_rows = point_prior['harness_test_counts']['workspace_tests']
        self.assertEqual(current.digest(early_before), current.EARLY_PREVIOUS)
        self.assertEqual(early_before['harness_test_counts']['workspace_tests'], comparison_rows)
        self.assertEqual((len(early_rows), sum(x['tests'] for x in early_rows.values()),
                          sum(x['ignored'] for x in early_rows.values())), (118, 4541, 39))
        self.assertEqual((early['default_method_additions'], early['new_method_declarations'],
                          early['inherited_test_instances'], early['default_harness_changes'],
                          early['default_method_removals'], early['default_doctest_additions'],
                          early['default_ignore_changes'], early['recorder_identity_changes']),
                         (85, 15, 70, 3, 0, 0, 0, 0))
        self.assertEqual(sum(len(v) * len(early['default_method_instances'][p])
                             for p,v in early['added_default_methods'].items()), 15)
        self.assertEqual(sum(len(v) * len(early['inherited_method_instances'][p])
                             for p,v in early['inherited_default_methods'].items()), 70)
        self.assertEqual(early['inherited_support']['tests'], 35)
        self.assertEqual((len(early['inherited_support']['files']), len(early['inherited_support']['edges'])), (37, 36))
        self.assertEqual(early['added_ignored_methods'], {})
        self.assertEqual((actual['recorder_tests'], actual['harness_test_counts']['serial_launch']),
                         (early_before['recorder_tests'], early_before['harness_test_counts']['serial_launch']))
        for wrong in (early_before, comparison_before, clock_before, overlap_before, rx_before,
                      entry_before, placement_before, phase_catalog, native_indexed, old):
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_667921(wrong)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^ac0963_inventory_differs$'):
                inventory.require_current(wrong)
        for name, change in early['workspace_changes'].items():
            self.assertEqual(early_rows[name], change['current'])
            self.assertEqual(comparison_rows.get(name), change['previous'])
            for field in ('tests', 'ignored'):
                for value in (None, True, float(early_rows[name][field]), early_rows[name][field]+1):
                    wrong = copy.deepcopy(actual)
                    wrong['harness_test_counts']['workspace_tests'][name][field] = value
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                        current.before_667921(wrong)
            wrong = copy.deepcopy(actual); del wrong['harness_test_counts']['workspace_tests'][name]
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_inventory_differs$'):
                current.before_667921(wrong)
        early_stimuli = [(p, 'fn '+n+'(', 'fn '+n+'_wrong(')
            for p,names in early['added_default_methods'].items() for n in names]
        early_stimuli += [(p, literal, replacement) for p,literal,replacement in early['ignore_stimuli']]
        early_stimuli += [(p, literal, '') for p,literals in early['module_chains'].items() for literal in literals]
        self.assertEqual(len(early_stimuli), 44)
        for path, literal, replacement in early_stimuli:
            target=current.ROOT/path; raw=read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            wrong=raw.replace(literal.encode(), replacement.encode())
            def changed(candidate): return wrong if candidate==target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path:hashlib.sha256(wrong).hexdigest()}), \
                 patch.object(current, 'source_before', side_effect=lambda p,b,e:b if p!=path else (_ for _ in ()).throw(AssertionError('early declaration gate omitted'))):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()
        for path in early['source_paths']:
            target=current.ROOT/path; raw=read(target)
            for missing in (False, True):
                def changed(candidate):
                    if candidate!=target:return read(candidate)
                    if missing:raise FileNotFoundError(path)
                    return raw+b'\n'
                with patch.object(Path, 'read_bytes', changed):
                    with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                        current.require_sources()

        # The new Cargo example has one exact source/binary/output-directory
        # identity. Its ten tests cannot be admitted under the generic matcher.
        example = 'unit/full_program_bridge/full_program_bridge'
        example_header = ('     Running unittests examples/full_program_bridge.rs '
                          '(target/debug/examples/full_program_bridge-0123456789abcdef)')
        example_log = '\n'.join((example_header, 'running 10 tests', summary(10)))
        expected = {example: counts(10)}
        self.assertEqual(live_rows[example], expected[example])
        self.assertEqual(parsing.harness_id(example_header), example)
        row = parsing.parse_harnesses(example_log, expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=10, failed=0, ignored=0,
                                           measured=0, filtered=0, result='ok'))
        self.assertEqual((row['declared_outer_tests'], row['nested_starts'],
                          row['unmatched_nested_starts']), (10, 0, 0))
        for malformed in (
                example_header.replace('target/debug/examples/', 'target/debug/deps/'),
                example_header.replace('unittests examples/full_program_bridge.rs',
                                       'unittests src/lib.rs').replace('target/debug/examples/', 'target/debug/deps/'),
                example_header.replace('target/debug/examples/full_program_bridge-', 'target/debug/deps/other-'),
                example_header.replace('target/debug/examples/full_program_bridge-', 'target/debug/examples/other-'),
                example_header.replace('examples/full_program_bridge.rs', 'examples/other.rs'),
                example_header.replace('full_program_bridge', 'full_program_bridge_extra'),
                example_header.replace('target/debug/examples/', '/PRIVATE_SENTINEL/'),
                example_header.replace('target/debug/examples/', 'target/debug/examples/../examples/'),
                example_header.replace('-0123456789abcdef)', '-nothex)')):
            with self.subTest(full_program_header=malformed), self.assertRaises(parsing.InvalidEvidence):
                parsing.harness_id(malformed)
        for bad in (example_log.replace('running 10 tests', 'running 9 tests'),
                    example_log.replace('running 10 tests', 'running 11 tests'),
                    example_log.replace(summary(10), summary(9, filtered=1)),
                    example_log.replace(summary(10), summary(9, ignored=1)),
                    example_log.replace(summary(10), summary(9, measured=1)),
                    example_log.replace('running 10 tests', 'running 10 tests\nrunning 1 test'),
                    example_log.replace(summary(10), ''),
                    example_log + '\n' + summary(10), example_log + '\n' + example_log):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)
        failed = example_log.replace(summary(10), summary(9, failed=1))
        with self.assertRaisesRegex(parsing.InvalidEvidence, '^successful_exit_with_failed_summary$'):
            parsing.parse_harnesses(failed, expected, 0)
        row = parsing.parse_harnesses(failed, expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']),
                         ('FAILED', 9, 1))

        # Two source-bound compile-fail doctests extend the old 2+45 partition
        # to exactly 2+47. Both declarations, summaries and terminal are required.
        doc = '\n'.join(('   Doc-tests rapid_profiler', 'running 2 tests', summary(2),
                         'running 47 tests', summary(47),
                         'all doctests ran in 0.51s; merged doctests compilation took 0.21s'))
        expected = {'doc/rapid_profiler': counts(49)}
        self.assertEqual(live_rows['doc/rapid_profiler'], expected['doc/rapid_profiler'])
        row = parsing.parse_harnesses(doc, expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=49, failed=0, ignored=0,
                                           measured=0, filtered=0, result='ok'))
        self.assertEqual(row['declared_outer_tests'], 2)
        self.assertEqual([part['declared_tests'] for part in row['partitions']], [2, 47])
        self.assertEqual([part['summary']['passed'] for part in row['partitions']], [2, 47])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (0, 0))
        reordered = '\n'.join(('   Doc-tests rapid_profiler', 'running 47 tests', summary(47),
                               'running 2 tests', summary(2), doc.splitlines()[-1]))
        for bad in (doc.replace('rapid_profiler', 'example'), reordered,
                    doc.replace('running 2 tests', 'running 3 tests'),
                    doc.replace('running 47 tests', 'running 46 tests'),
                    doc.replace('running 47 tests', 'running 48 tests'),
                    doc.replace(summary(2), summary(1)),
                    doc.replace(summary(47), summary(46)),
                    doc.replace(summary(2), summary(2, filtered=1)),
                    doc.replace(summary(47), summary(47, filtered=1)),
                    doc.replace(summary(47), summary(46, ignored=1)),
                    doc.replace(summary(47), summary(46, measured=1)),
                    doc.replace(summary(47), summary(46, failed=1)),
                    doc.replace(summary(47), summary(47, result='FAILED')),
                    doc.replace('running 47 tests', 'running 47 tests\nrunning 47 tests'),
                    doc.replace(summary(2), summary(2) + '\n' + summary(2)),
                    doc.replace(summary(2), ''), doc.replace(summary(47), ''),
                    '\n'.join(doc.splitlines()[:-1]), doc + '\n' + doc.splitlines()[-1],
                    doc + '\nrunning 1 test\n' + summary(1),
                    doc.replace('all doctests ran in 0.51s;', 'all doctests ran in NaNs;')):
            with self.subTest(incoming_doc_partition=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, expected, 0)
        for total, ignored in ((48, 0), (50, 0), (49, 1)):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(doc, {'doc/rapid_profiler': counts(total, ignored)}, 0)
        failed = doc.replace(summary(47), summary(46, failed=1))
        row = parsing.parse_harnesses(failed, expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']),
                         ('FAILED', 48, 1))
        self.assertEqual(row['partitions'][1]['summary']['failed'], 1)

        # The incoming source adds one compile-fail declaration. Require its
        # exact 2+48 rustdoc partition without changing the historical 2+47.
        entry_doc = '\n'.join(('   Doc-tests rapid_profiler', 'running 2 tests', summary(2),
                               'running 48 tests', summary(48),
                               'all doctests ran in 0.67s; merged doctests compilation took 0.26s'))
        entry_expected = {'doc/rapid_profiler': counts(50)}
        self.assertEqual(snapshot_prior['harness_test_counts']['workspace_tests']['doc/rapid_profiler'],
                         entry_expected['doc/rapid_profiler'])
        row = parsing.parse_harnesses(entry_doc, entry_expected, 0)[0]
        self.assertEqual(row['outer'], dict(passed=50, failed=0, ignored=0,
                                           measured=0, filtered=0, result='ok'))
        self.assertEqual(row['declared_outer_tests'], 2)
        self.assertEqual([part['declared_tests'] for part in row['partitions']], [2, 48])
        self.assertEqual([part['summary']['passed'] for part in row['partitions']], [2, 48])
        self.assertEqual((row['nested_starts'], row['unmatched_nested_starts']), (0, 0))
        reordered = '\n'.join(('   Doc-tests rapid_profiler', 'running 48 tests', summary(48),
                               'running 2 tests', summary(2), entry_doc.splitlines()[-1]))
        for bad in (entry_doc.replace('rapid_profiler', 'example'), reordered,
                    entry_doc.replace('running 2 tests', 'running 3 tests'),
                    entry_doc.replace('running 48 tests', 'running 47 tests'),
                    entry_doc.replace('running 48 tests', 'running 49 tests'),
                    entry_doc.replace(summary(2), summary(1)),
                    entry_doc.replace(summary(48), summary(47)),
                    entry_doc.replace(summary(2), summary(2, filtered=1)),
                    entry_doc.replace(summary(48), summary(48, filtered=1)),
                    entry_doc.replace(summary(48), summary(47, ignored=1)),
                    entry_doc.replace(summary(48), summary(47, measured=1)),
                    entry_doc.replace(summary(48), summary(47, failed=1)),
                    entry_doc.replace(summary(48), summary(48, result='FAILED')),
                    entry_doc.replace('running 48 tests', 'running 48 tests\nrunning 48 tests'),
                    entry_doc.replace(summary(2), summary(2) + '\n' + summary(2)),
                    entry_doc.replace(summary(2), ''), entry_doc.replace(summary(48), ''),
                    '\n'.join(entry_doc.splitlines()[:-1]), entry_doc + '\n' + entry_doc.splitlines()[-1],
                    entry_doc + '\nrunning 1 test\n' + summary(1),
                    entry_doc.replace('all doctests ran in 0.67s;', 'all doctests ran in NaNs;')):
            with self.subTest(entry_doc_partition=bad), self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(bad, entry_expected, 0)
        for total, ignored in ((49, 0), (51, 0), (50, 1)):
            with self.assertRaises(parsing.InvalidEvidence):
                parsing.parse_harnesses(entry_doc, {'doc/rapid_profiler': counts(total, ignored)}, 0)
        failed = entry_doc.replace(summary(48), summary(47, failed=1))
        row = parsing.parse_harnesses(failed, entry_expected, 1)[0]
        self.assertEqual((row['outer']['result'], row['outer']['passed'], row['outer']['failed']),
                         ('FAILED', 49, 1))
        self.assertEqual(row['partitions'][1]['summary']['failed'], 1)


        # Exact projections return private graphs even when custom deepcopy
        # publishes a plain container. DATA patching must retain this behavior.
        def mutable_ids(value):
            pending = [value]; seen = set(); mutable = set()
            while pending:
                item = pending.pop()
                if not isinstance(item, (dict, list, tuple)) or id(item) in seen:
                    continue
                seen.add(id(item))
                if isinstance(item, (dict, list)):
                    mutable.add(id(item))
                pending.extend(item.keys() if isinstance(item, dict) else ())
                pending.extend(item.values() if isinstance(item, dict) else item)
            return mutable

        published = []
        class PublishedCopy(dict):
            def __deepcopy__(self, memo):
                result = {}; memo[id(self)] = result
                result.update((copy.deepcopy(k, memo), copy.deepcopy(v, memo))
                              for k, v in self.items())
                published.append(result)
                return result

        projections = ((current.before_96378, phase_catalog),
                       (current.before_29859, native_indexed),
                       (current.before_current, old))
        for function, expected_projection in ((current.before_03ed2c31, flat_prior), (current.before_4261826, row_prefix_prior), (current.before_f9f89ac, binding_prior), (current.before_bad32a8, current_ret_prior), (current.before_e5462b7, physical_prior), *projections):
            supplied = copy.deepcopy(actual)
            supplied['harness_test_counts']['serial_launch'] = PublishedCopy(
                supplied['harness_test_counts']['serial_launch'])
            published.clear()
            result = function(supplied)
            self.assertEqual(result, expected_projection)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))
        change = current.DATA['source_successor_96378']['workspace_changes']['doc/rapid_profiler']
        for function, expected_projection in projections[1:]:
            published.clear()
            with patch.dict(change, previous=PublishedCopy(change['previous'])):
                result = function(actual)
                self.assertEqual(result, expected_projection)
                self.assertEqual(len(published), 1)
                self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
                self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))
            self.assertEqual(actual['recorder_tests'], 366)

        # The new outer projection also returns a private graph under publishing deepcopy.
        for source in ('declared', 'metadata'):
            supplied = copy.deepcopy(actual)
            change = current.DATA['source_successor_c110']['workspace_changes']['unit/liteinst_preempt/main']
            published.clear()
            if source == 'declared':
                supplied['harness_test_counts']['serial_launch'] = PublishedCopy(
                    supplied['harness_test_counts']['serial_launch'])
                result = current.before_c110(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result = current.before_c110(supplied)
            self.assertEqual(result, comparison_before)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # Preserve private ownership through the newly added outer transition.
        for source in ('declared', 'metadata'):
            supplied=copy.deepcopy(actual)
            change=current.DATA['source_successor_667921']['workspace_changes']['unit/liteinst2/lib']
            published.clear()
            if source=='declared':
                supplied['harness_test_counts']['serial_launch']=PublishedCopy(supplied['harness_test_counts']['serial_launch'])
                result=current.before_667921(supplied)
            else:
                with patch.dict(change, previous=PublishedCopy(change['previous'])):
                    result=current.before_667921(supplied)
            self.assertEqual(result, early_before)
            self.assertEqual(supplied, actual)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(supplied))
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        for path, literal in (("tools/rapid-profiler/point-throughput/main.rs", "#[cfg(test)]\nmod tests;"),
                              *(("tools/rapid-profiler/point-throughput/tests.rs", name)
                                for name in current.DATA['source_successor_e5ab521']['methods'])):
            target = current.ROOT / path; raw = read(target)
            self.assertEqual(raw.count(literal.encode()), 1)
            altered = literal[:-1] + ('x' if literal[-1] != 'x' else 'y')
            wrong = raw.replace(literal.encode(), altered.encode())
            def changed(candidate): return wrong if candidate == target else read(candidate)
            with patch.object(Path, 'read_bytes', changed), \
                 patch.dict(current.DATA['sources'], {path: hashlib.sha256(wrong).hexdigest()}):
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^main97ab_source_inventory_differs$'):
                    current.require_sources()

        # The latest metadata row may publish a copy too; the result stays private.
        published.clear()
        change = physical['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_e5462b7(actual)
            self.assertEqual(result, physical_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The new current-RET metadata transition also cannot publish its output.
        published.clear()
        change = current_ret['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_bad32a8(actual)
            self.assertEqual(result, current_ret_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # The current metadata transition also cannot publish its private output.
        published.clear()
        change = binding['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_f9f89ac(actual)
            self.assertEqual(result, binding_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # New row-prefix metadata also cannot publish the private result.
        published.clear()
        change = row_prefix['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_4261826(actual)
            self.assertEqual(result, row_prefix_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # Incoming metadata must not publish a caller-owned catalog through deepcopy.
        published.clear()
        change = flat['workspace_changes']['unit/rapid_profiler/lib']
        with patch.dict(change, previous=PublishedCopy(change['previous'])):
            result = current.before_03ed2c31(actual)
            self.assertEqual(result, flat_prior)
            self.assertEqual(len(published), 1)
            self.assertFalse(mutable_ids(result) & mutable_ids(published[0]))
            self.assertFalse(mutable_ids(result) & mutable_ids(current.DATA))

        # Sparse inverses retain exact edit ordering, including equal-position
        # insertions, and both whole-byte identity gates.
        raw = b'abcdef'
        for edits, expected_raw in (([], b'abcdef'),
                ([[1, 3, 'X'], [3, 5, 'Y']], b'aXYf'),
                ([[2, 2, 'X'], [2, 2, 'Y']], b'abXYcdef'),
                ([[0, 1, ''], [5, 6, '']], b'bcde')):
            inverse_row = dict(current_sha256=hashlib.sha256(raw).hexdigest(),
                previous_sha256=hashlib.sha256(expected_raw).hexdigest(), edits=edits)
            result = current.inverse('probe', raw, {'probe': inverse_row}, 'sparse_control')
            self.assertIs(type(result), bytes)
            self.assertEqual(result, expected_raw)
            for field in ('current_sha256', 'previous_sha256'):
                malformed = copy.deepcopy(inverse_row); malformed[field] = '0' * 64
                with self.assertRaisesRegex(parsing.InvalidEvidence, '^sparse_control$'):
                    current.inverse('probe', raw, {'probe': malformed}, 'sparse_control')
        for edits in ([[3, 5, 'Y'], [1, 3, 'X']], [[1, 4, 'X'], [3, 5, 'Y']],
                      [[False, 1, 'X']], [[0, 7, 'X']], [[0, 1, b'X']]):
            malformed = dict(current_sha256=hashlib.sha256(raw).hexdigest(),
                previous_sha256=hashlib.sha256(raw).hexdigest(), edits=edits)
            with self.assertRaisesRegex(parsing.InvalidEvidence, '^sparse_control$'):
                current.inverse('probe', raw, {'probe': malformed}, 'sparse_control')
