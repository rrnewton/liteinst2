#!/usr/bin/env python3
"""Pure rejection-witness controls; no build, process launch or candidate call."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location('preemption_run', Path(__file__).with_name('run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def witness(cause, present, site, count):
    return b'LI2SPSC1' + struct.pack('<12Q', cause, 27, 1, 1, 0, 1,
        present, site, count, 2, 1, 1)


RECORDS = {
    'wrong-site': witness(1, 1, 28, 1),
    'wrong-count': witness(1, 1, 27, 2),
    'no-reply': witness(2, 0, 0, 0),
}


class RefusalWitnessControls(unittest.TestCase):
    def test_each_actual_expected_outcome_is_accepted(self):
        for case, data in RECORDS.items():
            with self.subTest(case=case):
                self.assertEqual(len(data), 104)
                runner.require_refusal_witness(case, data)

    def test_timeout_cannot_supply_wrong_tuple_credit(self):
        # This is the review counterexample: the controller wrote its intended
        # parked marker, but the worker actually returned Timeout before a reply.
        for requested in ('wrong-site', 'wrong-count'):
            with self.subTest(requested=requested):
                with self.assertRaises(AssertionError):
                    runner.require_refusal_witness(requested, RECORDS['no-reply'])

    def test_all_other_case_substitutions_refuse(self):
        for requested in RECORDS:
            for observed, data in RECORDS.items():
                if requested == observed:
                    continue
                with self.subTest(requested=requested, observed=observed):
                    with self.assertRaises(AssertionError):
                        runner.require_refusal_witness(requested, data)

    def test_disconnect_protocol_and_unconsumed_or_correct_tuple_refuse(self):
        invalid = [witness(3, 0, 0, 0), witness(4, 0, 0, 0),
                   witness(1, 0, 28, 1), witness(1, 1, 27, 1),
                   witness(1, 1, 28, 2), witness(2, 1, 28, 1)]
        for requested in RECORDS:
            for i, data in enumerate(invalid):
                with self.subTest(requested=requested, mutant=i):
                    with self.assertRaises(AssertionError):
                        runner.require_refusal_witness(requested, data)

    def test_every_changed_clock_application_and_tuple_field_refuses(self):
        for case, data in RECORDS.items():
            fields = struct.unpack('<12Q', data[8:])
            for index in range(12):
                changed = list(fields)
                changed[index] ^= 1
                mutant = data[:8] + struct.pack('<12Q', *changed)
                with self.subTest(case=case, field=index):
                    with self.assertRaises(AssertionError):
                        runner.require_refusal_witness(case, mutant)

    def test_missing_partial_trailing_and_wrong_magic_refuse(self):
        for case, data in RECORDS.items():
            mutants = [data[:n] for n in range(104)] + [data + b'\0', b'?' + data[1:]]
            for i, mutant in enumerate(mutants):
                with self.subTest(case=case, mutant=i):
                    with self.assertRaises(AssertionError):
                        runner.require_refusal_witness(case, mutant)

    def test_unknown_control_cannot_select_a_known_outcome(self):
        with self.assertRaises(AssertionError):
            runner.require_refusal_witness('unknown', RECORDS['no-reply'])


if __name__ == '__main__':
    unittest.main()
