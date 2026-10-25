"""Bounded ownership regressions; all artifacts remain in ignored workspace storage."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import processes


class ProcessOwnershipTests(unittest.TestCase):
    def setUp(self):
        root = processes.ROOT / "target/evaluation/admission/process-tests"
        root.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.directory.cleanup)
        self.log = Path(self.directory.name) / "private.log"
        self.prior_subreaper = processes._subreaper()
        self.prior_sigint = signal.getsignal(signal.SIGINT)

    def run_python(self, source, timeout=1, limit=8192):
        return processes.run_command([sys.executable, "-c", source], os.environ,
                                     self.log, timeout, limit)

    def assert_clean(self, result):
        self.assertTrue(result["cleanup_complete"], result)
        self.assertEqual(processes._direct_children(), set())
        self.assertEqual(processes._subreaper(), self.prior_subreaper)
        self.assertEqual(signal.getsignal(signal.SIGINT), self.prior_sigint)
        self.assertEqual(result["private_log_sha256"],
                         hashlib.sha256(self.log.read_bytes()).hexdigest())

    def test_success_nonzero_and_signal_preserve_actual_exit_status(self):
        for source, expected in [
            ("print('complete')", 0),
            ("raise SystemExit(7)", 7),
            ("import os,signal; os.kill(os.getpid(),signal.SIGTERM)", -signal.SIGTERM),
        ]:
            with self.subTest(expected=expected):
                result = self.run_python(source)
                self.assertEqual(result["exit_code"], expected)
                self.assertIsNone(result["termination"])
                self.assertEqual(result["reaped_descendants"], 0)
                self.assert_clean(result)

    def test_stdout_eof_does_not_disable_the_wall_deadline(self):
        result = self.run_python("import os,time; os.close(1); os.close(2); time.sleep(60)",
                                 timeout=0.1)
        self.assertEqual(result["termination"], "timeout")
        self.assertEqual(result["exit_code"], -signal.SIGKILL)
        self.assertLess(result["seconds"], 0.1 + processes.CLEANUP_SECONDS + 0.5)
        self.assert_clean(result)

    def test_successful_leader_cannot_leave_an_inherited_pipe_child(self):
        result = self.run_python("import os,time\n"
                                 "if os.fork() == 0:\n time.sleep(60)\n"
                                 "else:\n os._exit(0)\n")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["termination"], "descendants_after_exit")
        self.assertEqual(result["reaped_descendants"], 1)
        self.assertLess(result["seconds"], processes.CLEANUP_SECONDS + 0.5)
        self.assert_clean(result)

    def test_detached_session_grandchild_is_adopted_killed_and_reaped(self):
        # Each parent waits for a pipe byte before exiting, so both descendants
        # and both new sessions definitely exist before cleanup starts.
        source = """import os,time
ready_read, ready_write = os.pipe()
if os.fork() == 0:
    os.close(ready_read)
    os.setsid()
    inner_read, inner_write = os.pipe()
    if os.fork() == 0:
        os.close(inner_read)
        os.setsid()
        os.close(1)
        os.close(2)
        os.write(inner_write, b'x')
        time.sleep(60)
    os.close(inner_write)
    assert os.read(inner_read, 1) == b'x'
    os.write(ready_write, b'x')
    os._exit(0)
os.close(ready_write)
assert os.read(ready_read, 1) == b'x'
os._exit(0)
"""
        result = self.run_python(source)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["termination"], "descendants_after_exit")
        self.assertEqual(result["reaped_descendants"], 2)
        self.assert_clean(result)

    def test_detached_child_holding_stdout_cannot_outlive_a_successful_leader(self):
        source = """import os,time
ready_read, ready_write = os.pipe()
if os.fork() == 0:
    os.close(ready_read)
    os.setsid()
    os.write(1, b'detached child ready\\n')
    os.write(ready_write, b'x')
    time.sleep(60)
os.close(ready_write)
assert os.read(ready_read, 1) == b'x'
os._exit(0)
"""
        result = self.run_python(source)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["termination"], "descendants_after_exit")
        self.assertEqual(result["reaped_descendants"], 1)
        self.assertEqual(self.log.read_bytes(), b"detached child ready\n")
        self.assert_clean(result)

    def test_output_limit_kills_and_reaps_without_expanding_the_log(self):
        result = self.run_python("import os\nwhile True: os.write(1,b'x'*65536)", limit=64)
        self.assertEqual(result["termination"], "output_limit")
        self.assertEqual(result["exit_code"], -signal.SIGKILL)
        self.assertEqual(self.log.read_bytes(), b"x" * 64)
        self.assert_clean(result)

    def test_nested_supervisors_keep_descendant_ownership_separate(self):
        nested_log = Path(self.directory.name) / "nested-private.log"
        child = ("import os,time\n"
                 "if os.fork() == 0:\n os.setsid(); time.sleep(60)\n"
                 "else:\n os._exit(0)\n")
        source = ("import json,os,sys\n"
                  "sys.path.insert(0,'evaluation/admission')\n"
                  "import processes\n"
                  f"result=processes.run_command([sys.executable,'-c',{child!r}],"
                  f"os.environ,{str(nested_log)!r},1)\n"
                  "print(json.dumps(result))\n")
        result = self.run_python(source, timeout=2)
        self.assertEqual(result["exit_code"], 0)
        self.assertIsNone(result["termination"])
        self.assertEqual(result["reaped_descendants"], 0)
        nested = json.loads(self.log.read_text())
        self.assertEqual(nested["exit_code"], 0)
        self.assertEqual(nested["termination"], "descendants_after_exit")
        self.assertTrue(nested["cleanup_complete"])
        self.assertEqual(nested["reaped_descendants"], 1)
        self.assertEqual(nested["private_log_sha256"],
                         hashlib.sha256(nested_log.read_bytes()).hexdigest())
        self.assert_clean(result)

    def test_sigint_between_spawn_and_owner_assignment_is_deferred_until_cleanup(self):
        real_popen = subprocess.Popen

        def spawn_then_interrupt(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            signal.raise_signal(signal.SIGINT)
            return child

        with mock.patch.object(processes.subprocess, "Popen", spawn_then_interrupt):
            result = self.run_python("import time; time.sleep(60)")
        self.assertEqual(result["termination"], "interrupted")
        self.assertEqual(result["exit_code"], -signal.SIGKILL)
        self.assertEqual(result["reaped_descendants"], 0)
        self.assert_clean(result)

    def test_spawn_failure_has_an_empty_hashed_log_and_no_children(self):
        missing = str(Path(self.directory.name) / "absent-program")
        result = processes.run_command([missing], os.environ, self.log, 1)
        self.assertEqual(result["termination"], "spawn_error")
        self.assertIsNone(result["exit_code"])
        self.assertEqual(result["reaped_descendants"], 0)
        self.assert_clean(result)

    def test_existing_child_is_never_adopted_killed_or_reaped_by_the_helper(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            result = self.run_python("raise SystemExit(0)")
            self.assertEqual(result["termination"], "ownership_refused")
            self.assertIsNone(result["exit_code"])
            self.assertEqual(result["reaped_descendants"], 0)
            self.assertTrue(result["cleanup_complete"])
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.kill()
            unrelated.wait(timeout=3)
        self.assertEqual(processes._direct_children(), set())


if __name__ == "__main__":
    unittest.main()
