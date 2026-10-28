#!/usr/bin/env python3
"""Corrupted qualification records must fail the same validators used by verify.py."""
import copy
import hashlib
import json
import unittest
import verify


def fixture():
    pairs = []
    for seed in (0x1234567887654320, 0xfedcba9801234567):
        for mode in (0, 1):
            for selected in (False, True):
                pairs.append(dict(mode=mode, seed=seed, initial_selector=selected,
                    ret_offset=27 if mode == 0 else 20, comparisons=18 if mode == 0 else 19,
                    original_steps=100, candidate_steps=1000,
                    callback_events=2 if selected else 0, observer_entries=2 if selected else 0,
                    subject_returns=2, outer_returns=2, flip_acknowledgements=2, helper_joins=2))
    return dict(schema=1, profile='precontext-v1', status='PASS', pairs=pairs,
        malformed=[dict(tag=tag, sigill=True, local_ud2=True, original_heads=0,
            callback_events=0, observer_entries=0, subject_returns=0, outer_returns=0,
            cleanup='SIGKILL_REAP_ECHILD', steps=12) for tag in ('phase', 'choice')],
        totals=dict(pairs=8, positive_children=16, malformed_children=2, comparisons=148,
            callback_events=8, subject_returns=16, outer_returns=16, helper_joins=16),
        scope='fixed-core-no-frontend-or-performance', pure_controls=[
            'gate_displacement', 'scratch_layout', 'ack_fields', 'duplicate_ack_tail', 'slow_ret_log'])


class CorruptionControls(unittest.TestCase):
    def setUp(self):
        self.good = fixture()
        verify.validate_terminal(self.good)

    def refuses(self, mutate):
        changed = copy.deepcopy(self.good)
        mutate(changed)
        with self.assertRaises((AssertionError, ValueError, KeyError, TypeError)):
            verify.validate_terminal(changed)

    def test_complete_unique_case_population(self):
        self.refuses(lambda v: v['pairs'].pop())
        self.refuses(lambda v: v['pairs'].append(copy.deepcopy(v['pairs'][0])))
        self.refuses(lambda v: v['pairs'].__setitem__(1, copy.deepcopy(v['pairs'][0])))
        for key, value in [('seed', 0), ('mode', 2), ('initial_selector', 0)]:
            self.refuses(lambda v, k=key, n=value: v['pairs'][0].__setitem__(k, n))

    def test_accounting_return_and_bound_corruption(self):
        for key in ('comparisons', 'callback_events', 'observer_entries', 'subject_returns',
                    'outer_returns', 'flip_acknowledgements', 'helper_joins'):
            for selected_index in (0, 1):
                self.refuses(lambda v, k=key, i=selected_index: v['pairs'][i].__setitem__(k, v['pairs'][i][k] + 1))
        for key, value in [('ret_offset', 20), ('original_steps', 20001), ('candidate_steps', 0),
                           ('comparisons', True)]:
            self.refuses(lambda v, k=key, n=value: v['pairs'][0].__setitem__(k, n))
        for key in self.good['totals']:
            self.refuses(lambda v, k=key: v['totals'].__setitem__(k, v['totals'][k] - 1))

    def test_malformed_cases_require_fault_and_no_execution(self):
        self.refuses(lambda v: v['malformed'].pop())
        self.refuses(lambda v: v['malformed'].__setitem__(1, copy.deepcopy(v['malformed'][0])))
        for key, value in [('sigill', False), ('local_ud2', False), ('cleanup', 'UNKNOWN'),
                           ('original_heads', 1), ('callback_events', 1), ('observer_entries', 1),
                           ('subject_returns', 1), ('outer_returns', 1), ('steps', 20001)]:
            self.refuses(lambda v, k=key, n=value: v['malformed'][0].__setitem__(k, n))

    def test_required_protocol_controls_and_scope(self):
        for i in range(5):
            self.refuses(lambda v, n=i: v['pure_controls'].pop(n))
        for key, value in [('schema', True), ('status', 'FAILED'), ('profile', 'another'),
                           ('scope', 'performance'), ('extra', 1)]:
            self.refuses(lambda v, k=key, n=value: v.__setitem__(k, n))

    def test_exact_json_document(self):
        raw = json.dumps(self.good, separators=(',', ':')).encode() + b'\n'
        self.assertEqual(verify.read_terminal(raw), self.good)
        for corrupt in (raw + b'\n', raw + raw, raw[:-1],
                        raw.replace(b'"schema":1', b'"schema":1,"schema":1'),
                        raw.replace(b'"schema":1', b'"schema":NaN'),
                        raw.replace(b'"schema":1', b'"schema":Infinity')):
            with self.assertRaises((AssertionError, ValueError)):
                verify.read_terminal(corrupt)

    def test_closed_process_and_diagnostics(self):
        stdout, stderr = b'candidate result\n', b''
        good = dict(exit=0, wall_timeout=False, absence_proof='ECHILD',
            unexpected_descendants=[], cleanup_events=[], cleanup_error=None, aborted=None,
            inputs_unchanged=True, stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest())
        verify.validate_native_closed(good, stdout, stderr)
        for key, value in [('exit', 1), ('exit', False), ('wall_timeout', True),
                           ('absence_proof', None), ('unexpected_descendants', [7]),
                           ('cleanup_events', [dict(event='reaped')]), ('cleanup_error', 'error'),
                           ('aborted', 'signal'), ('inputs_unchanged', False),
                           ('stdout_sha256', '0' * 64), ('stderr_sha256', '0' * 64)]:
            changed = {**good, key: value}
            with self.assertRaises(AssertionError):
                verify.validate_native_closed(changed, stdout, stderr)
        warning = b'warning\n'
        changed = {**good, 'stderr_sha256': hashlib.sha256(warning).hexdigest()}
        with self.assertRaises(AssertionError):
            verify.validate_native_closed(changed, stdout, warning)


if __name__ == '__main__':
    unittest.main()
