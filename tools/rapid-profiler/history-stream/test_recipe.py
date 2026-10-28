"""Fabricated history protocol and prerequisite controls; no native execution."""
import ast
import importlib.util
import itertools
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
PATH = Path(__file__).resolve().parents[1] / 'verify_ordinary_interval.py'
spec = importlib.util.spec_from_file_location('history_recipe', PATH)
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


def transcript(filtered=217, elapsed='0.04'):
    return ('\nrunning 1 test\ntest '+recipe.HISTORY_TEST+' ... '+recipe.HISTORY_PASS+
        '\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '+
        str(filtered)+' filtered out; finished in '+elapsed+'s\n\n').encode('ascii')


class HistoryRecipe(unittest.TestCase):
    def refuse(self, stdout, stderr=b''):
        with self.assertRaises((AssertionError, UnicodeDecodeError)):
            recipe.history_output(stdout, stderr)

    def test_exact_native_protocol_and_variable_libtest_metadata(self):
        for filtered, elapsed in ((0, '0.00'), (217, '0.04'), (900, '14.99')):
            got = recipe.history_output(transcript(filtered, elapsed), b'')
            self.assertEqual((got['originals'], got['calls'], got['sampled'], got['rows'], got['events']), (2, 2, 2, 2, 4))
            self.assertEqual((got['actions'], got['history_batches'], got['max_resident'], got['epochs'], got['retired']), (600, 77, 8, 300, 300))
            self.assertEqual((got['old_prefix'], got['new_prefix'], got['interval_batches'], got['registrations']), (1, 599, 2, 1))
            self.assertIs(got['joined'], True)
            self.assertNotIn('epoch_limit', got)  # Not printed: separately source-attested.
            self.assertNotIn('retained_owner_release', got)

    def test_all_flag_combinations_use_actual_prerequisite_predicates(self):
        names = ('exact_work', 'concurrent_epochs', 'retire_epochs', 'drain_completed', 'streamed_epochs', 'stream_history')
        main = next(n for n in ast.parse(PATH.read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        guards = []
        for statement in main.body:
            if not isinstance(statement, ast.Assert):
                continue
            attrs = [n.attr for n in ast.walk(statement.test) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == 'a']
            if len(attrs) == 2 and set(attrs) <= set(names):
                guards.append(statement)
        self.assertEqual(len(guards), 5)
        predicate = compile(ast.fix_missing_locations(ast.Module(body=guards, type_ignores=[])), '<actual prerequisite guards>', 'exec')
        valid = 0
        for bits in itertools.product((False, True), repeat=6):
            # Legal flag sets are exactly the seven prefixes of this chain.
            expected = bits == tuple(i < sum(bits) for i in range(6))
            with self.subTest(flags=bits):
                if expected:
                    exec(predicate, {'a': SimpleNamespace(**dict(zip(names, bits)))})
                    valid += 1
                else:
                    with self.assertRaises(AssertionError):
                        exec(predicate, {'a': SimpleNamespace(**dict(zip(names, bits)))})
        self.assertEqual(valid, 7)

    def test_each_reported_count_prefix_and_joined_state_is_exact(self):
        original = transcript()
        for word in recipe.HISTORY_PASS.split()[2:]:
            key, value = word.split('=', 1)
            changed = str(int(value)+1) if value.isdecimal() else 'false'
            with self.subTest(field=key):
                self.refuse(original.replace(word.encode(), (key+'='+changed).encode(), 1))
        self.refuse(original.replace(b'old_prefix=1 new_prefix=599', b'old_prefix=599 new_prefix=1'))
        self.refuse(original.replace(b' history_batches=77', b''))
        self.refuse(original.replace(b' history_batches=77', b' history_batches=77 history_batches=77'))

    def test_failed_partial_extra_wrong_case_and_libtest_summary_refuse(self):
        good = transcript()
        for bad in (b'', good[:-1], good+b'FAILED after output\n', b'FAILED before output\n'+good,
                good+good, good.replace(b'\n', b'\r\n'), good.replace(b'history-native PASS', b'history-native FAILED'),
                good.replace(recipe.HISTORY_TEST.encode(), b'another_test'), good.replace(b'1 passed', b'0 passed'),
                good.replace(b'1 passed', b'2 passed'), good.replace(b'0 failed', b'1 failed'),
                good.replace(b'0 ignored', b'1 ignored'), good.replace(b'0 measured', b'1 measured'),
                good.replace(b' ... ', b' ... ignored\n'), good.replace(b'217 filtered out', b'-1 filtered out'),
                good.replace(b'0.04s', b'nans'), good+b'\xff', b'x'*(recipe.MIB+1)):
            with self.subTest(size=len(bad)):
                self.refuse(bad)

    def test_nonempty_stderr_never_gets_native_success_credit(self):
        for stderr in (b'warning\n', b'\n', b'FAILED\n', b'\x00'):
            with self.subTest(stderr=stderr):
                self.refuse(transcript(), stderr)


if __name__ == '__main__':
    unittest.main()
