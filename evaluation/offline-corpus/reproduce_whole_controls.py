#!/usr/bin/env python3
"""Fabricated CLI/dispatch controls only; never run a capture, planner or child."""
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

if sys.flags.optimize:
    raise SystemExit('assertions required')
path = Path(__file__).resolve().with_name('reproduce_whole.py')
with path.open('rb') as stream:
    raw = stream.read(1048577)
assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == '3d0b854b8c6b9cd1e07ffe2b65ed0f17998e4c8871f1b7949b1455de387ab2f0'
R = types.ModuleType('authenticated_whole_reproducer')
R.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), R.__dict__)


class WholeReproducerControls(unittest.TestCase):
    def test_fixed_cli_choices_and_unchanged_default(self):
        argv = ['--capture', '/synthetic-closed', '--capture-sha256', 'a' * 64,
                '--output', '/synthetic-new']
        default = R.arguments(argv)
        self.assertEqual(default.placement_profile, R.D.PROFILE)
        self.assertEqual(default.capture, Path('/synthetic-closed'))
        self.assertEqual(default.capture_sha256, 'a' * 64)
        self.assertEqual(default.output, Path('/synthetic-new'))
        for profile in (R.D.PROFILE, R.D.WINDOW_PROFILE):
            explicit = R.arguments(argv + ['--placement-profile', profile])
            self.assertEqual(vars(explicit), dict(vars(default), placement_profile=profile))
        for suffix in (['--placement-profile', 'unknown'], ['--placement-profile']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                R.arguments(argv + suffix)
            self.assertEqual(error.exception.code, 2)

    def test_dispatch_is_once_and_preserves_refusal_or_exception(self):
        for profile in (R.D.PROFILE, R.D.WINDOW_PROFILE):
            keywords = {} if profile == R.D.PROFILE else {'profile': R.D.WINDOW_PROFILE}
            for program in R.B.PROGRAMS:
                inputs, expected = object(), object()
                for status in ('MATERIALS_READY', 'MATERIALS_REFUSED'):
                    result = dict(status=status, qualification_complete=False, files={})
                    with mock.patch.object(R.D, 'attempt', return_value=result) as call:
                        self.assertIs(R.material_attempt(program, inputs, expected, profile), result)
                        call.assert_called_once_with(program, inputs, expected, **keywords)
                failure = RuntimeError('synthetic adapter refusal')
                with mock.patch.object(R.D, 'attempt', side_effect=failure) as call:
                    with self.assertRaises(RuntimeError) as error:
                        R.material_attempt(program, inputs, expected, profile)
                    self.assertIs(error.exception, failure)
                    call.assert_called_once_with(program, inputs, expected, **keywords)
        with mock.patch.object(R.D, 'attempt') as call:
            with self.assertRaises(AssertionError):
                R.material_attempt('checksum', object(), object(), 'unknown')
            call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
