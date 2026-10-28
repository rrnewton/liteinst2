"""Pure protocol controls; no child, native instruction or timing is executed."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import importlib.util
from pathlib import Path
import unittest
import copy

spec = importlib.util.spec_from_file_location('process_timing', Path(__file__).with_name('process_timing.py'))
timing = importlib.util.module_from_spec(spec); spec.loader.exec_module(timing)
ARGV = ['/example/client', 'argument']


def fixture():
    return dict(token=timing.token(ARGV), timer_pid=123, child_pid=124, wait_pid=124, argc=2,
        wait_status=0, exit=0, signal=0, core=0, exec_errno=0,
        start_sec=1, start_nsec=500, end_sec=2, end_nsec=700,
        user_sec=0, user_usec=123, system_sec=0, system_usec=7,
        resolution_ns=1, process_wall_ns=1000000200, child_user_us=123,
        child_system_us=7, child_cpu_us=130)


def encode(row):
    return ('process-timer-v1 '+' '.join(f'{k}={row[k]}' for k in timing.FIELDS)+'\n').encode('ascii')


class ProcessTiming(unittest.TestCase):
    def test_actual_request_tail_record_budget_and_inner_clock_join(self):
        spec = importlib.util.spec_from_file_location('comparison_runner', Path(__file__).with_name('comparison_runner.py'))
        runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
        timer, record = Path('/example/timer'), Path('/example/trial/timing.txt')
        launch = dict(argv=[str(timer), str(record), timing.token(ARGV), '--', *ARGV],
            stdout='/example/trial/stdout.txt', stderr='/example/trial/stderr.txt',
            cpu_seconds=20, wall_seconds=30, file_bytes=1048576)
        summary = dict(s0_wall_before=1000000500, s3_wall_after=2000000700)
        row = fixture()
        self.assertEqual(runner.join_timing(launch, timer, record, ARGV, encode(row), summary), row)
        for i in range(len(launch['argv'])):
            bad = copy.deepcopy(launch); bad['argv'][i] += 'wrong'
            with self.assertRaises(AssertionError): runner.join_timing(bad, timer, record, ARGV, encode(row), summary)
        for field, value in (('stdout', '/different/stdout.txt'), ('stderr', '/different/stderr.txt'),
                ('cpu_seconds', 21), ('wall_seconds', 31), ('file_bytes', 1048577)):
            bad = dict(launch, **{field: value})
            with self.assertRaises(AssertionError): runner.join_timing(bad, timer, record, ARGV, encode(row), summary)
        for changed in (dict(s0_wall_before=1000000499), dict(s3_wall_after=2000000701),
                        dict(s0_wall_before=2000000701)):
            bad = dict(summary, **changed)
            with self.assertRaises(AssertionError): runner.join_timing(launch, timer, record, ARGV, encode(row), bad)

    def refuse(self, row):
        with self.assertRaises(AssertionError): timing.parse(encode(row), ARGV)

    def test_exact_actual_arithmetic_zero_cpu_and_no_cpu_wall_filter(self):
        row = fixture(); self.assertEqual(timing.successful(timing.parse(encode(row), ARGV)), row)
        row.update(user_usec=0, system_usec=0, child_user_us=0, child_system_us=0, child_cpu_us=0)
        self.assertEqual(timing.parse(encode(row), ARGV), row)
        row.update(user_sec=999, child_user_us=999000000, child_cpu_us=999000000)
        self.assertEqual(timing.parse(encode(row), ARGV), row)
        for seconds, fraction, base in ((-1, 0, 10**9), (0, -1, 10**9), (0, 10**9, 10**9),
                (2**64, 0, 10**9), (0, 10**6, 10**6), (True, 0, 10**9)):
            with self.assertRaises(AssertionError): timing.scaled(seconds, fraction, base)
        self.assertEqual(timing.scaled(18446744073, 709551615, 10**9), 2**64-1)
        with self.assertRaises(AssertionError): timing.scaled(18446744073, 709551616, 10**9)

    def test_pid_command_status_and_raw_derived_contradictions(self):
        cases = dict(token='0'*64, timer_pid=124, child_pid=125, wait_pid=125, argc=3,
            wait_status=1, exit=1, signal=1, core=1, exec_errno=2,
            start_sec=2, start_nsec=10**9, end_sec=0, end_nsec=10**9,
            user_sec=1, user_usec=10**6, system_sec=1, system_usec=10**6,
            resolution_ns=0, process_wall_ns=1, child_user_us=1, child_system_us=1, child_cpu_us=1)
        for field, value in cases.items():
            with self.subTest(field=field): self.refuse(dict(fixture(), **{field: value}))
        for field in ('timer_pid', 'child_pid', 'wait_pid'):
            for value in (0, 2**31): self.refuse(dict(fixture(), **{field: value}))
        with self.assertRaises(AssertionError): timing.parse(encode(fixture()), ['/example/other', 'argument'])

    def test_complete_canonical_grammar_and_integer_domains(self):
        row = fixture(); good = encode(row); words = good[:-1].split(b' ')
        for i in range(len(words)):
            for bad in (words[:i]+words[i+1:], words[:i]+[words[i]]+words[i:]):
                with self.assertRaises(AssertionError): timing.parse(b' '.join(bad)+b'\n', ARGV)
        for key in timing.FIELDS[1:]:
            for value in ('-2', '+1', '01', '-0', '1.0', 'true', str(2**64), ''):
                self.refuse(dict(row, **{key: value}))
        for bad in (good[:-1], good+b'\n', good.replace(b'\n', b'\r\n'), b'\n'+good,
                    good+b'extra', good.replace(b' ', b'\t', 1), bytearray(good), good.decode('ascii')):
            with self.assertRaises(AssertionError): timing.parse(bad, ARGV)

    def test_actual_nonzero_signal_exec_failure_and_excess_wall_never_pass(self):
        for changes in (dict(exit=7, wait_status=7<<8), dict(exit=-1, signal=15, wait_status=15),
                        dict(exit=-1, signal=6, core=1, wait_status=134),
                        dict(exit=127, wait_status=127<<8, exec_errno=2),
                        dict(end_sec=32, process_wall_ns=31000000200)):
            row = dict(fixture(), **changes)
            self.assertEqual(timing.parse(encode(row), ARGV), row)
            with self.assertRaises(AssertionError): timing.successful(row)


if __name__ == '__main__': unittest.main()
