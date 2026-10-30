#!/usr/bin/env python3
"""Mocked child-free preflight controls: no fork, wait or signal touches a child."""
import errno
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location('probe_xstate_controls_target',
    Path(__file__).with_name('probe_xstate.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


class ChildPreflight(unittest.TestCase):
    def call(self, result=None, failure=None):
        with mock.patch.object(P.os, 'waitid', return_value=result, side_effect=failure) as wait:
            try:
                return P.require_child_free()
            finally:
                wait.assert_called_once_with(P.os.P_ALL, 0,
                    P.os.WEXITED | P.os.WSTOPPED | P.os.WCONTINUED
                    | P.os.WNOHANG | P.os.WNOWAIT | P.WALL)

    def test_only_exact_echild_exception_accepts(self):
        self.assertIsNone(self.call(failure=ChildProcessError(errno.ECHILD, 'no children')))

    def test_no_event_none_still_refuses_live_child(self):
        with self.assertRaises(ValueError):
            self.call(result=None)

    def test_every_wait_event_refuses_without_consuming_it(self):
        for code in (P.os.CLD_EXITED, P.os.CLD_KILLED, P.os.CLD_DUMPED,
                     P.os.CLD_TRAPPED, P.os.CLD_STOPPED, P.os.CLD_CONTINUED):
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.call(result=SimpleNamespace(si_pid=17, si_code=code, si_status=0))

    def test_wrong_childprocesserror_errno_never_proves_absence(self):
        for number in (None, 0, errno.EINVAL, errno.EINTR, errno.ESRCH):
            with self.subTest(errno=number), self.assertRaises(ValueError):
                self.call(failure=ChildProcessError(number, 'wrong errno'))

    def test_other_oserror_propagates_without_retry_or_success(self):
        failure = OSError(errno.EINVAL, 'waitid unavailable')
        with self.assertRaises(OSError) as raised:
            self.call(failure=failure)
        self.assertIs(raised.exception, failure)


if __name__ == '__main__':
    unittest.main()
