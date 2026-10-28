"""Fabricated parser controls only; no native calls or private export replay."""
import ast
import importlib.util
import itertools
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('optional_backoff_check', Path(__file__).with_name('check_output.py'))
checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(checker)

# Independent fixed fixtures, not assembled from the parser's expected fields.
NATIVE = (
    '\nrunning 1 test\ntest frontend_native::backoff::optional::tests::native::optional_backoff_native_disable_rearm_and_old_owner ... '
    'optional-backoff-native PASS originals=13 calls=13 fast=1 slow=12 sampled=12 unsampled=0 batches=13 events=24 '
    'history_batches=5 actions=5 epochs=3 retired=3 report_records=12 registrations=1 post_disable_fast=1 '
    'post_rearm_sampled=2 inflight_old_owner=1 worker_joins=1 short_ret_refusals=1 detached=true input_unchanged=true\n'
    'ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 900 filtered out; finished in 0.04s\n\n').encode('ascii')
VALID = (
    'optional-backoff-work COMPLETE originals=8 k=10 calls=1000 fast=100 slow=900 sampled=800 unsampled=100 '
    'arms=520 reports=520 disabled=80 actions=601 history_batches=601 call_batches=250 max_entry_prefix=600 '
    'epoch_limit=520 call_limit=100000 stop_reason=epoch-limit max_arm_late_ns=1000000 stop_ack_ns=5200100000 '
    'removed_ns=5200200000 controller_done_ns=5201000000 accepted_exports=1371 written_exports=1371 written_bytes=4000000 '
    'worker_detached=true actual_threads_joined=3 export_synced=true result_input_rsp_checked=true '
    'worker_backpressure=immediate scope=finite-functional-raw-uncalibrated post_disable_rearm_coverage=not-qualified\n').encode('ascii')


def change(data, key, value):
    data, count = re.subn(rb'(?<= )'+key.encode()+rb'=[^ \n]+', (key+'='+str(value)).encode(), data)
    assert count == 1
    return data


class OptionalBackoffRecipe(unittest.TestCase):
    def refuse(self, data, k=10, size=4000000, wait=False):
        with self.assertRaises((AssertionError, UnicodeDecodeError)):
            checker.parse_terminal(data, k, size, wait)

    def test_exact_native_case_and_every_reported_field(self):
        got = checker.native_output(NATIVE, b'')
        self.assertEqual((got['originals'], got['calls'], got['fast'], got['slow']), (13, 13, 1, 12))
        self.assertEqual((got['history_batches'], got['actions'], got['report_records']), (5, 5, 12))
        self.assertEqual((got['post_disable_fast'], got['post_rearm_sampled'], got['inflight_old_owner']), (1, 2, 1))
        self.assertIs(got['detached'], True)
        self.assertNotIn('clock_loop_proven', got)
        terminal = NATIVE.split(b' ... ', 1)[1].split(b'\n', 1)[0]
        for word in terminal.split()[2:]:
            key, value = word.decode().split('=')
            with self.subTest(key=key):
                bad = change(NATIVE, key, int(value)+1 if value.isdecimal() else 'false')
                with self.assertRaises(AssertionError): checker.native_output(bad, b'')

    def test_native_requires_one_exact_test_clean_stderr_and_complete_protocol(self):
        for bad in (b'', NATIVE[:-1], NATIVE+NATIVE, b'notice\n'+NATIVE, NATIVE+b'FAILED\n',
                NATIVE.replace(b'\n', b'\r\n'), NATIVE.replace(b'1 passed', b'0 passed'),
                NATIVE.replace(b'1 passed', b'2 passed'), NATIVE.replace(b'0 failed', b'1 failed'),
                NATIVE.replace(b'0 ignored', b'1 ignored'), NATIVE.replace(b'PASS', b'FAILED'),
                NATIVE.replace(b'optional_backoff_native_disable_rearm_and_old_owner', b'another_test'),
                NATIVE.replace(b'0.04s', b'nans'), NATIVE+b'\xff', b'x'*4097):
            with self.subTest(size=len(bad)):
                with self.assertRaises((AssertionError, UnicodeDecodeError)): checker.native_output(bad, b'')
        for bad in (b'\n', b'warning\n', b'\x00'):
            with self.assertRaises(AssertionError): checker.native_output(NATIVE, bad)

    def test_actual_eight_flag_prerequisites_require_all_thirty_prior_stages(self):
        names = ('exact_work', 'concurrent_epochs', 'retire_epochs', 'drain_completed', 'streamed_epochs',
            'stream_history', 'optional_frontend', 'optional_backoff_control')
        tree = ast.parse((ROOT/'verify_ordinary_interval.py').read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        guards = []
        for statement in main.body:
            if not isinstance(statement, ast.Assert): continue
            attrs = [n.attr for n in ast.walk(statement.test) if isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name) and n.value.id == 'a']
            if len(attrs) == 2 and set(attrs) <= set(names): guards.append(statement)
        self.assertEqual(len(guards), 7)
        code = compile(ast.fix_missing_locations(ast.Module(body=guards, type_ignores=[])), '<actual flag guards>', 'exec')
        legal = 0
        for bits in itertools.product((False, True), repeat=8):
            expected = bits == tuple(i < sum(bits) for i in range(8))
            scope = {'a': SimpleNamespace(**dict(zip(names, bits)))}
            if expected: exec(code, scope); legal += 1
            else:
                with self.assertRaises(AssertionError): exec(code, scope)
        self.assertEqual(legal, 9)

    def test_distinct_optional_modes_and_small_k1000_population(self):
        got = checker.parse_terminal(VALID, 10, 4000000)
        self.assertEqual((got['calls'], got['fast'], got['slow'], got['actions']), (1000, 100, 900, 601))
        self.assertEqual(got['post_disable_rearm_coverage'], 'not-qualified')
        wait = change(VALID, 'worker_backpressure', 'bounded-wait')
        self.assertEqual(checker.parse_terminal(wait, 10, 4000000, True)['worker_backpressure'], 'bounded-wait')
        self.refuse(wait); self.refuse(VALID, wait=True)
        other = VALID
        for key, value in dict(k=1000, calls=100, fast=0, slow=100, sampled=100, unsampled=0, disabled=0,
                actions=521, history_batches=521, call_batches=25, max_entry_prefix=520,
                accepted_exports=1066, written_exports=1066).items(): other = change(other, key, value)
        self.assertEqual(checker.parse_terminal(other, 1000, 4000000)['calls'], 100)
        self.refuse(change(VALID, 'post_disable_rearm_coverage', 'qualified'))

    def test_sparse_counts_disable_bounds_and_real_high_prefix(self):
        for key, value in dict(calls=999, fast=99, slow=899, sampled=799, unsampled=99, disabled=521,
                actions=600, history_batches=600, max_entry_prefix=512).items():
            with self.subTest(key=key): self.refuse(change(VALID, key, value))
        self.refuse(change(VALID, 'max_entry_prefix', 602))
        # Keep both cumulative sum equations valid while violating K closure.
        bad = change(change(VALID, 'sampled', 799), 'unsampled', 101)
        self.refuse(bad)
        # Zero D/Fast is allowed for K1000, but cannot satisfy K10 acceptance.
        bad = VALID
        for key, value in dict(disabled=0, actions=521, history_batches=521, max_entry_prefix=520,
                accepted_exports=1291, written_exports=1291).items(): bad = change(bad, key, value)
        self.refuse(bad)
        self.refuse(change(change(VALID, 'fast', 0), 'calls', 900))

    def test_full_window_exact_deadlines_and_no_stopped_prefix_credit(self):
        for key, value in dict(originals=7, arms=519, reports=519, epoch_limit=519, call_limit=99999,
                stop_reason='requested', max_arm_late_ns=2000001, stop_ack_ns=5199999999,
                removed_ns=5200099999, controller_done_ns=5200199999, actual_threads_joined=2,
                worker_detached='false', export_synced='false', result_input_rsp_checked='false').items():
            with self.subTest(key=key): self.refuse(change(VALID, key, value))
        edge = change(change(VALID, 'max_arm_late_ns', 2000000), 'controller_done_ns', 7199999999)
        self.assertEqual(checker.parse_terminal(edge, 10, 4000000)['max_arm_late_ns'], 2000000)
        self.refuse(change(edge, 'controller_done_ns', 7200000000))
        for n in (32, 100000): self.refuse(change(VALID, 'calls', n))

    def test_complete_export_and_actual_size_joins(self):
        for key, value in dict(call_batches=249, accepted_exports=1370, written_exports=1370, written_bytes=3999999).items():
            with self.subTest(key=key): self.refuse(change(VALID, key, value))
        bad = VALID
        for key, value in dict(call_batches=1001, accepted_exports=2122, written_exports=2122).items(): bad = change(bad, key, value)
        self.refuse(bad)
        for size in (0, 64*1048576+1): self.refuse(change(VALID, 'written_bytes', size), size=size)
        self.refuse(VALID, size=4000001)
        cap = change(VALID, 'written_bytes', 64*1048576)
        self.assertEqual(checker.parse_terminal(cap, 10, 64*1048576)['written_bytes'], 64*1048576)

    def test_strict_grammar_no_mode_confusion_or_boolean_integer_coercion(self):
        for bad in (b'', VALID[:-1], VALID+VALID, b'notice\n'+VALID, VALID+b'FAILED\n',
                VALID.replace(b'\n', b'\r\n'), VALID.replace(b'COMPLETE', b'FAILED'),
                VALID.replace(b'optional-backoff-work ', b'backoff-work '),
                VALID.replace(b'optional-backoff-work ', b'optional-backoff-work-wait '),
                VALID.replace(b' calls=1000', b''), VALID.replace(b' calls=1000', b' calls=1000 calls=1000'),
                VALID.replace(b' fast=100 slow=900', b' slow=900 fast=100'), change(VALID, 'calls', '01000'),
                change(VALID, 'calls', 2**64), change(VALID, 'worker_backpressure', 'unbounded'),
                change(VALID, 'scope', 'full-state'), VALID+b'\xff', b'x'*4097):
            with self.subTest(size=len(bad)): self.refuse(bad)
        self.refuse(VALID, k=True); self.refuse(VALID, size=True)
        for mode in (None, 1, 'immediate'): self.refuse(VALID, wait=mode)


if __name__ == '__main__': unittest.main()
