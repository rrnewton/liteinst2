#!/usr/bin/env python3
"""Protocol controls for the hardware prerequisite, using fabricated text only."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')

spec = importlib.util.spec_from_file_location('hardware_stop', Path(__file__).with_name('verify_hardware_stop.py'))
hardware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hardware)


def output(rf=2, tf=0):
    return ('\nrunning 1 test\ntest '+hardware.NATIVE+' ... '
        f'tree-hardware-stop PASS children=1 stops=2 steps=2 rf_observed={rf} step_tf_bits={tf} '
        'rf_clear_after_steps=true debug_restored=true state_unchanged=true exit=0 reaped=1 echild=1\n'
        'ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 90 filtered out; finished in 0.02s\n\n').encode('ascii')


class HardwareProtocol(unittest.TestCase):
    def test_optimized_entry_and_import_are_refused(self):
        for name in ('verify_hardware_stop.py', 'test_hardware_stop.py'):
            path = str(Path(__file__).with_name(name))
            for argv in ([path, '--help'],
                    ['-c', 'import runpy,sys; runpy.run_path(sys.argv[1])', path]):
                result = subprocess.run([sys.executable, '-O', '-B', *argv],
                    capture_output=True, timeout=5, check=False)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                    (1, b'', b'assertions required\n'))

    def test_pure_requires_every_named_control_once(self):
        good = ('\nrunning 8 tests\n'+''.join('test '+n+' ... ok\n' for n in hardware.PURE)+
            '\ntest result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 83 filtered out; finished in 0.01s\n\n').encode('ascii')
        self.assertEqual(hardware.parse_pure(good, b'')['passed'], 8)
        for index, name in enumerate(hardware.PURE):
            for changed in (b'foreign', hardware.PURE[(index+1) % 8].encode('ascii')):
                with self.assertRaises(AssertionError):
                    hardware.parse_pure(good.replace(name.encode('ascii'), changed, 1), b'')
        for bad in (good[:-1], good+b'\n', good.replace(b'0 ignored', b'1 ignored'),
                good.replace(b' ... ok', b' ... ignored', 1), good.replace(b'8 passed', b'7 passed'),
                good.replace(b'83 filtered out', b'82 filtered out'),
                good.replace(b'83 filtered out', b'84 filtered out')):
            with self.assertRaises(AssertionError):
                hardware.parse_pure(bad, b'')
        with self.assertRaises(AssertionError):
            hardware.parse_pure(good, b'warning')

    def test_observed_flags_are_reported_without_inventing_rf(self):
        for rf in range(3):
            for tf in range(4):
                got = hardware.parse_native(output(rf, tf), b'')
                self.assertEqual((got['stops_exposing_rf'], got['steps_exposing_tf_bits']), (rf, tf))

    def test_each_fixed_claim_and_libtest_envelope_is_required(self):
        good = output()
        for field in (b'children=1', b'stops=2', b'steps=2', b'PASS', b'rf_observed=2',
                b'step_tf_bits=0', b'rf_clear_after_steps=true', b'debug_restored=true',
                b'state_unchanged=true', b'exit=0', b'reaped=1', b'echild=1',
                b'1 passed', b'0 failed', b'0 ignored', b'90 filtered out', hardware.NATIVE.encode('ascii')):
            with self.assertRaises(AssertionError):
                hardware.parse_native(good.replace(field, field+b'X', 1), b'')
        for bad in (b'', good[:-1], good+b'\n', good.replace(b'\n', b'\r\n'), output(3), output(2, 4),
                good.replace(b'90 filtered out', b'89 filtered out'),
                good.replace(b'90 filtered out', b'91 filtered out')):
            with self.assertRaises(AssertionError):
                hardware.parse_native(bad, b'')
        with self.assertRaises(AssertionError):
            hardware.parse_native(good, b'warning\n')


if __name__ == '__main__':
    unittest.main()
