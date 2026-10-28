"""Synthetic terminal controls only; no compiler, native call or export replay."""
import importlib.util
from pathlib import Path
import re
import sys
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('backoff_recipe', Path(__file__).with_name('verify.py'))
recipe = importlib.util.module_from_spec(spec); spec.loader.exec_module(recipe)

# Independent literal fixture: no producer FIELDS/FIXED/template generation.
VALID = (
    'backoff-work COMPLETE originals=8 k=10 calls=4000 arms=520 reports=520 actions=521 sampled=3000 unsampled=1000 '
    'initial=50 closed=900 removed=50 max_entry_prefix=520 sampled_after_closed=true epoch_limit=520 call_limit=100000 '
    'stop_reason=epoch-limit max_arm_late_ns=1000000 stop_ack_ns=5200100000 removed_ns=5200200000 controller_done_ns=5201000000 '
    'call_batches=1000 history_batches=521 accepted_exports=2041 written_exports=2041 written_bytes=4000000 '
    'worker_detached=true actual_threads_joined=3 export_synced=true result_input_rsp_checked=true '
    'scope=finite-functional-raw-uncalibrated mandatory_hooks=on\n').encode('ascii')


def change(data, key, value):
    changed, count = re.subn(rb'(?<= )'+key.encode()+rb'=[^ \n]+', (key+'='+str(value)).encode(), data)
    assert count == 1
    return changed


class BackoffRecipe(unittest.TestCase):
    def refuse(self, data, k=10, size=4000000):
        with self.assertRaises((AssertionError, UnicodeDecodeError)):
            recipe.parse_terminal(data, k, size)

    def test_positive_full_trials_and_k1000_without_closure_or_1000_calls(self):
        got = recipe.parse_terminal(VALID, 10, 4000000)
        self.assertEqual((got['calls'], got['arms'], got['history_batches']), (4000, 520, 521))
        self.assertTrue(got['sampled_after_closed'])
        other = VALID
        for key, value in dict(k=1000, calls=100, sampled=100, unsampled=0, initial=0, closed=0, removed=0,
                sampled_after_closed='false', call_batches=25, accepted_exports=1066, written_exports=1066).items():
            other = change(other, key, value)
        got = recipe.parse_terminal(other, 1000, 4000000)
        self.assertEqual(got['calls'], 100)
        self.assertFalse(got['sampled_after_closed'])

    def test_exact_policy_population_and_source_attested_flags(self):
        for key, value in dict(originals=7, k=1000, arms=519, reports=519, actions=520, history_batches=520,
                epoch_limit=519, call_limit=99999, stop_reason='requested', calls=0, actual_threads_joined=2,
                worker_detached='false', export_synced='false', result_input_rsp_checked='false',
                mandatory_hooks='off', scope='full-state').items():
            with self.subTest(key=key): self.refuse(change(VALID, key, value))
        for calls in (32, 100000): self.refuse(change(VALID, 'calls', calls))
        self.refuse(VALID, k=True)

    def test_owners_real_prefix_and_k10_rearm(self):
        for key, value in dict(sampled=2999, unsampled=999, initial=49, closed=899, removed=49,
                max_entry_prefix=512, sampled_after_closed='false').items():
            with self.subTest(key=key): self.refuse(change(VALID, key, value))
        self.refuse(change(VALID, 'max_entry_prefix', 522))
        no_closed = change(change(VALID, 'closed', 0), 'initial', 950)
        self.refuse(no_closed)

    def test_absolute_deadline_boundaries_and_nonrenewed_shutdown(self):
        boundary = change(change(VALID, 'max_arm_late_ns', 2000000), 'controller_done_ns', 7199999999)
        self.assertEqual(recipe.parse_terminal(boundary, 10, 4000000)['controller_done_ns'], 7199999999)
        for key, value in dict(max_arm_late_ns=2000001, stop_ack_ns=5199999999,
                removed_ns=5200099999, controller_done_ns=5200199999).items():
            with self.subTest(key=key): self.refuse(change(VALID, key, value))
        # Still below ack+2s, but beyond the immutable original end+2s.
        self.refuse(change(VALID, 'controller_done_ns', 7200000000))
        self.refuse(change(VALID, 'stop_ack_ns', 'none'))

    def test_batch_export_and_exact_file_size_joins(self):
        for key, value in dict(call_batches=999, accepted_exports=2040, written_exports=2040, written_bytes=3999999).items():
            with self.subTest(key=key): self.refuse(change(VALID, key, value))
        too_many = change(VALID, 'call_batches', 4001)
        too_many = change(change(too_many, 'accepted_exports', 5042), 'written_exports', 5042)
        self.refuse(too_many)
        self.refuse(VALID, size=4000001)
        for size in (0, 64*1048576+1):
            self.refuse(change(VALID, 'written_bytes', size), size=size)
        exact_cap = change(VALID, 'written_bytes', 64*1048576)
        self.assertEqual(recipe.parse_terminal(exact_cap, 10, 64*1048576)['written_bytes'], 64*1048576)

    def test_complete_strict_single_line_no_implicit_coercion(self):
        for bad in (b'', VALID[:-1], VALID+VALID, VALID+b'FAILED\n', b'notice\n'+VALID,
                VALID.replace(b'\n', b'\r\n'), VALID.replace(b'COMPLETE', b'FAILED'),
                VALID.replace(b' calls=4000', b''), VALID.replace(b' calls=4000', b' calls=4000 calls=4000'),
                VALID.replace(b' arms=520 reports=520', b' reports=520 arms=520'),
                VALID.replace(b' calls=4000', b' calls=04000'), change(VALID, 'calls', 2**64),
                change(VALID, 'sampled_after_closed', '1'), VALID+b'\xff', b'x'*4097):
            with self.subTest(size=len(bad)): self.refuse(bad)


if __name__ == '__main__': unittest.main()
