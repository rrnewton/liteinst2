#!/usr/bin/env python3
"""Pure v6 material controls. Synthetic source-join fixtures are not corpus outcomes."""
import hashlib
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

assert not sys.flags.optimize, 'assertions required'


def load(name, expected):
    path = Path(__file__).resolve().with_name(name)
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == expected
    module = types.ModuleType('authenticated_' + name.replace('.', '_')); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


C = load('disassembly_controls.py', 'f0d7f5572017fcc8a8f14c59e2980e97e50359e7d165c2b748de99439d93346d')
M = load('adjacent_routed_jmp_material.py', '05e86b0652d7989a0f8abd825d5001d2e6fc5bcf4440504651633034b32834db')
D = M.D
fixture, mutate_section, rebind = C.fixture, C.mutate_section, C.rebind


class RoutedJmpMaterialControls(unittest.TestCase):
    """Pure material contracts; none of these rows qualifies an importer or candidate."""

    PROFILE = 'offline-whole-authored-adjacent-routed-jmp-short-t3-pending-2g-v1'
    OLD_PROFILE = 'offline-whole-authored-short-t3-pending-2g-v1'
    COUNTS = (('checksum', (80, 16)), ('rle-roundtrip', (107, 26)))
    INPUTS = ('source', 'linker', 'object', 'original', 'heads', 'target')

    @staticmethod
    def pins(inputs):
        return {key: hashlib.sha256(value).hexdigest() for key, value in inputs.items()}

    @classmethod
    def labels(cls, upper, lower, joint):
        # Expected labels are prospective literals, never copied from new output.
        return dict(profile=cls.PROFILE, adjacent_pairs='original-geometry-jcc-or-routed-jmp-v1',
                    adjacent_upper=upper, adjacent_lower=lower, adjacent_joint=joint,
                    neighbor_victims='short-only', neighbor_ownership='inherited-t3',
                    pending_selected='full-instruction-ownership',
                    qualification_complete=False)

    def once(self, program, inputs, expected, budgets=(2, 1, 2)):
        upper, lower, joint = budgets
        with mock.patch.object(D, 'attempt', wraps=D.attempt) as delegated:
            result = M.attempt_adjacent_routed_jmp(program, inputs, expected,
                                           upper=upper, lower=lower, joint=joint)
        delegated.assert_called_once_with(program, inputs, expected, profile=self.OLD_PROFILE)
        return result

    def preserved_refusal(self, program, counts, inputs, expected, stage):
        original_inputs, original_pins = dict(inputs), dict(expected)
        old = D.attempt(program, inputs, expected, profile=self.OLD_PROFILE)
        self.assertEqual(old['status'], 'MATERIALS_REFUSED')
        self.assertEqual(old['failure']['stage'], stage)
        result = self.once(program, inputs, expected)
        # Full equality retains every diagnostic member, input identity and file.
        self.assertEqual(result, dict(old, **self.labels(2, 1, 2)))
        self.assertEqual((result['source_expected_heads'], result['source_expected_jumps']), counts)
        self.assertIs(result['qualification_complete'], False)
        self.assertIs(result['importer_verified'], False)
        self.assertEqual(inputs, original_inputs)
        self.assertEqual(expected, original_pins)
        return old, result

    def test_rj17_complete_two_programs_near_short_and_independent_v6_policy(self):
        self.assertEqual(M.PROFILE, self.PROFILE)
        budgets = ((0, 0, 0), (0, 256, 0), (1, 0, 0), (1, 1, 0),
                   (1, 1, 1), (2, 1, 2), (256, 0, 256), (256, 256, 256))
        modes = [b'neighbor-victims short-only\n',
                 b'neighbor-ownership inherited-t3\n',
                 b'pending-selected full-instruction-ownership\n']
        for short_jumps in (False, True):
            totals = [0, 0]
            for program, counts in self.COUNTS:
                inputs = fixture(program, short_jumps=short_jumps)
                expected = self.pins(inputs)
                saved_inputs, saved_expected = dict(inputs), dict(expected)
                old = D.attempt(program, inputs, expected, profile=self.OLD_PROFILE)
                self.assertEqual(old['status'], 'MATERIALS_READY')
                self.assertEqual((old['source_expected_heads'], old['source_expected_jumps']), counts)
                self.assertEqual((old['roster_checked_heads'], old['roster_checked_jumps']), counts)
                self.assertIs(old['importer_verified'], False)
                self.assertIs(old['qualification_complete'], False)
                before = old['files']['policy.txt'].splitlines(keepends=True)
                self.assertEqual(before[0], b'LI2DISASM-POLICY 4\n')
                self.assertEqual(before[3:6], modes)
                self.assertEqual(set(old['files']), {'ledger.txt', 'source-inventory.tsv', 'policy.txt'})
                for upper, lower, joint in budgets:
                    with self.subTest(program=program, short=short_jumps, upper=upper, lower=lower, joint=joint):
                        marker = b'adjacent-pairs original-geometry-jcc-or-routed-jmp-v1\n'
                        budget = f'adjacent-pair-budgets {upper} {lower} {joint}\n'.encode('ascii')
                        # Independently prescribed transformation of the OLD pending
                        # profile; never strip or read mode rows from the new result.
                        policy = b''.join([b'LI2DISASM-POLICY 6\n', *before[1:6],
                                           marker, budget, *before[6:]])
                        files = dict(old['files'], **{'policy.txt': policy})
                        wanted = dict(old, **self.labels(upper, lower, joint))
                        wanted['files'] = files
                        result = self.once(program, inputs, expected, (upper, lower, joint))
                        self.assertEqual(result, wanted)
                        self.assertIs(result['importer_verified'], False)
                        self.assertIs(result['qualification_complete'], False)
                        self.assertEqual(result['files']['ledger.txt'], old['files']['ledger.txt'])
                        self.assertEqual(result['files']['source-inventory.tsv'], old['files']['source-inventory.tsv'])
                        rows = result['files']['policy.txt'].splitlines(keepends=True)
                        self.assertEqual(rows[:8], [b'LI2DISASM-POLICY 6\n', before[1], before[2],
                                                   *modes, marker, budget])
                        for row in [rows[0], *modes, marker, budget]:
                            self.assertEqual(rows.count(row), 1)
                        self.assertEqual(sum(row.startswith(b'adjacent-pair-budgets ') for row in rows), 1)
                        self.assertEqual(rows[8:], before[6:])
                        self.assertEqual(rows[11], b'limits 1048576 32 32 131072 128 2097152 1048576 128 2147483648\n')
                        searches = [row.split() for row in rows if row.startswith(b'search ')]
                        allocations = [row.split() for row in rows if row.startswith(b'allocation ')]
                        self.assertEqual([int(row[1]) for row in searches], list(range(1, counts[1] + 1)))
                        self.assertTrue(all(row[2:] == [b'preferred', b'64', b'256', b'64', b'none', b'256', b'4096']
                                            for row in searches))
                        self.assertEqual([(int(row[1]), row[2]) for row in allocations],
                                         [(sid, role) for sid in range(1, counts[1] + 1)
                                          for role in (b'selected', b'victim')])
                        self.assertTrue(all(row[4:6] == [b'1', b'4096'] for row in allocations))
                        ledger = result['files']['ledger.txt'].splitlines()
                        inventory = result['files']['source-inventory.tsv'].splitlines()[1:]
                        self.assertEqual(sum(row.startswith(b'head ') for row in ledger), counts[0])
                        self.assertEqual(len(inventory), counts[0])
                        self.assertEqual(sum(int(row.split(b'\t')[-1]) for row in inventory), counts[1])
                        self.assertEqual((result['source_expected_heads'], result['source_expected_jumps']), counts)
                        self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), counts)
                        self.assertNotEqual(hashlib.sha256(policy).digest(), hashlib.sha256(old['files']['policy.txt']).digest())
                        self.assertEqual(inputs, saved_inputs)
                        self.assertEqual(expected, saved_expected)
                totals = [a + b for a, b in zip(totals, counts)]
            self.assertEqual(totals, [187, 42])

    def test_rj17_invalid_budgets_refuse_before_any_delegation(self):
        invalid = []
        for index in range(3):
            for value in (False, True, '0', '256', -1, 257, 1.0, None):
                values = [2, 1, 2]
                values[index] = value
                invalid.append(tuple(values))
        invalid += [(0, 0, 1), (1, 256, 2), (255, 256, 256)]
        for program, counts in self.COUNTS:
            for upper, lower, joint in invalid:
                with self.subTest(program=program, upper=upper, lower=lower, joint=joint):
                    # Deliberately non-dictionaries: invalid budgets must refuse
                    # before consulting inputs or entering the old adapter.
                    inputs, expected = object(), object()
                    with mock.patch.object(D, 'attempt', side_effect=AssertionError('unexpected delegation')) as delegated:
                        result = M.attempt_adjacent_routed_jmp(program, inputs, expected,
                                                       upper=upper, lower=lower, joint=joint)
                    delegated.assert_not_called()
                    wanted = dict(self.labels(upper, lower, joint), program=program,
                                  status='MATERIALS_REFUSED', files={},
                                  source_expected_heads=counts[0], source_expected_jumps=counts[1],
                                  roster_checked_heads=None, roster_checked_jumps=None,
                                  importer_verified=False,
                                  failure=dict(stage='adjacent-budgets', error='ValueError'))
                    self.assertEqual(result, wanted)
                    self.assertIs(result['qualification_complete'], False)
                    self.assertIs(result['importer_verified'], False)

    def test_rj17_preserves_every_input_pin_bound_and_authored_source_refusal(self):
        for short_jumps in (False, True):
            for program, counts in self.COUNTS:
                for key in self.INPUTS:
                    with self.subTest(program=program, short=short_jumps, input=key, refusal='digest'):
                        inputs = fixture(program, short_jumps=short_jumps)
                        expected = self.pins(inputs)
                        inputs[key] += b'x'
                        _, result = self.preserved_refusal(program, counts, inputs, expected, 'inputs')
                        self.assertEqual(result['failure'], dict(stage='inputs', error='AssertionError'))
                        self.assertEqual(result['files'], {})
                        self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), (None, None))
                        self.assertEqual(result['expected_input_sha256'], expected)
                        self.assertEqual(result['observed_input_sha256'], self.pins(inputs))
                    with self.subTest(program=program, short=short_jumps, input=key, refusal='bound'):
                        inputs = fixture(program, short_jumps=short_jumps)
                        inputs[key] = b'x' * 1048577
                        _, result = self.preserved_refusal(program, counts, inputs, self.pins(inputs), 'inputs')
                        self.assertEqual(result['failure'], dict(stage='inputs', error='AssertionError'))
                        self.assertEqual(result['files'], {})
                        self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), (None, None))
                        self.assertEqual(result['observed_input_bytes'][key], 1048577)
                        self.assertIsNone(result['observed_input_sha256'][key])
                for key in ('source', 'linker'):
                    inputs = fixture(program, short_jumps=short_jumps)
                    inputs[key] += b'\n'
                    _, result = self.preserved_refusal(program, counts, inputs, self.pins(inputs), 'inputs')
                    self.assertEqual(result['files'], {})
                    self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), (None, None))

    def test_rj17_preserves_later_refusals_and_exact_diagnostic_members(self):
        mutations = ('object-owner', 'image-owner', 'head-missing', 'head-duplicate',
                     'head-reordered', 'relocation', 'linked-code')
        for short_jumps in (False, True):
            for program, counts in self.COUNTS:
                for mutation in mutations:
                    with self.subTest(program=program, short=short_jumps, mutation=mutation):
                        inputs = fixture(program, short_jumps=short_jumps)
                        if mutation == 'object-owner':
                            inputs = mutate_section(inputs, 'object', '.note.fixture', 2, 6)
                            stage = 'object-elf-ownership'
                        elif mutation == 'image-owner':
                            inputs = mutate_section(inputs, 'original', '.text', 3, 0x401001)
                            stage = 'object-elf-ownership'
                        elif mutation.startswith('head-'):
                            rows = inputs['heads'].splitlines(keepends=True)
                            if mutation == 'head-missing':
                                del rows[4]
                            elif mutation == 'head-duplicate':
                                rows.insert(4, rows[4])
                            else:
                                rows[4], rows[5] = rows[5], rows[4]
                            inputs['heads'] = b''.join(rows)
                            stage = 'head-transport'
                        elif mutation == 'relocation':
                            obj = D.Elf(inputs['object'], 1)
                            raw = bytearray(inputs['object'])
                            raw[obj.section('.rela.text.start')[4]] ^= 1
                            inputs['object'] = bytes(raw)
                            inputs = rebind(inputs)
                            stage = 'relocations-and-code'
                        else:
                            raw = bytearray(inputs['original'])
                            raw[8192] ^= 1
                            inputs['original'] = bytes(raw)
                            inputs = rebind(inputs)
                            stage = 'relocations-and-code'
                        _, result = self.preserved_refusal(program, counts, inputs, self.pins(inputs), stage)
                        self.assertEqual(result['files'], {})
                        self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), (None, None))
                baseline_inputs = fixture(program, short_jumps=short_jumps)
                baseline = D.attempt(program, baseline_inputs, self.pins(baseline_inputs), profile=self.OLD_PROFILE)
                self.assertEqual(baseline['status'], 'MATERIALS_READY')
                for target in (b'target fxsave64\n', b'target xsave64 4\n',
                               b'target xsave64 7\n', b'target xsave64 3\n\n'):
                    inputs = fixture(program, short_jumps=short_jumps)
                    inputs['target'] = target
                    _, result = self.preserved_refusal(program, counts, inputs, self.pins(inputs), 'policy')
                    self.assertEqual(set(result['files']), {'ledger.txt', 'source-inventory.tsv'})
                    self.assertEqual(result['files'], {name: baseline['files'][name]
                                                       for name in ('ledger.txt', 'source-inventory.tsv')})
                    self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), counts)

    def test_rj17_remains_a_separate_selector_with_unchanged_legacy_limits(self):
        profiles = ('offline-whole-authored-null-jumps-v1',
                    'offline-whole-authored-window-permits-v1',
                    'offline-whole-authored-broad-span-2g-v1',
                    'offline-whole-authored-short-only-2g-v1',
                    'offline-whole-authored-short-t3-ownership-2g-v1',
                    'offline-whole-authored-short-t3-pending-2g-v1')
        self.assertEqual((D.PROFILE, D.WINDOW_PROFILE, D.BROAD_PROFILE, D.SHORT_PROFILE,
                          D.SHORT_T3_OWNERSHIP_PROFILE, D.SHORT_T3_PENDING_PROFILE), profiles)
        self.assertEqual(D.LIMITS, '1048576 32 32 131072 128 2097152 1048576 128 16777216')
        self.assertEqual(D.BROAD_LIMITS, '1048576 32 32 131072 128 2097152 1048576 128 2147483648')
        for program, counts in self.COUNTS:
            inputs = fixture(program)
            expected = self.pins(inputs)
            for profile in profiles:
                result = D.attempt(program, inputs, expected, profile=profile)
                self.assertEqual(result['status'], 'MATERIALS_READY')
                self.assertEqual((result['roster_checked_heads'], result['roster_checked_jumps']), counts)
                self.assertNotIn('adjacent_pairs', result)
                self.assertNotIn(b'adjacent-pairs', result['files']['policy.txt'])
                self.assertIs(result['qualification_complete'], False)
                self.assertIs(result['importer_verified'], False)
            with self.assertRaises(AssertionError):
                D.attempt(program, inputs, expected, profile=self.PROFILE)
            with self.assertRaises(AssertionError):
                D._window_policy(D.Elf(inputs['original'], 2), [(0x401000, 2, 4096)], self.PROFILE)

    def test_rj17_does_not_retry_or_relabel_an_unexpected_delegated_exception(self):
        for program, _ in self.COUNTS:
            inputs, expected = object(), object()
            failure = RuntimeError('synthetic delegated exception')
            with mock.patch.object(D, 'attempt', side_effect=failure) as delegated:
                with self.assertRaises(RuntimeError) as raised:
                    M.attempt_adjacent_routed_jmp(program, inputs, expected, upper=2, lower=1, joint=2)
            self.assertIs(raised.exception, failure)
            delegated.assert_called_once_with(program, inputs, expected, profile=self.OLD_PROFILE)




if __name__ == '__main__':
    unittest.main()
