#!/usr/bin/env python3
"""Prospective pure mocked repeated-signal test; launches no process or signal."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

if sys.flags.optimize:
    raise SystemExit('optimized Python disables supervisor calibration')
sys.dont_write_bytecode = True
import runner


def calibrate():
    class StuckHelper:
        pid = 123456
        returncode = None
        def __init__(self):
            self.waits = []; self.terminated = False; self.killed = False
        def wait(self, *, timeout):
            self.waits.append(timeout)
            raise subprocess.TimeoutExpired('mock-only-helper', timeout)
        def poll(self):
            return None
        def terminate(self):
            self.terminated = True
        def kill(self):
            self.killed = True
    helper = StuckHelper()
    watched = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    initial = {sig: signal.SIG_DFL for sig in watched}
    current = dict(initial)
    deliveries = []
    def disposition(sig, handler):
        previous = current[sig]; current[sig] = handler
        return previous
    actual_write = runner.write_new
    def write_with_repeated_signals(path, value):
        if path.name.endswith('.supervisor.json') or path.name == 'failed-incomplete.json':
            for sig in watched:
                deliveries.append((path.name, int(sig)))
                assert current[sig] == signal.SIG_IGN, 'receipt write exposed to repeated signal'
                # Deliver through the simulated disposition, without os.kill or
                # changing a real process signal state.
                if callable(current[sig]):
                    current[sig](sig, None)
        return actual_write(path, value)
    source = {'python': {'path': '/mock-only/python'}}
    manifest = {'cases': [{'id': 'mock-case'}]}
    binding = {'path': '/mock-only/helper.py', 'sha256': 'a'*64}
    def plan(_manifest, target):
        directory = target/'mock-case'
        return [dict(name=name, request=dict(argv=['/mock-only/e9'], cwd=str(directory),
            env={}, stdout=str(directory/(name+'.stdout')), stderr=str(directory/(name+'.stderr')),
            cpu_seconds=20, wall_seconds=45, file_bytes=runner.MAX_FILE)) for name in ('frontend', 'backend')]
    with tempfile.TemporaryDirectory(prefix='mock-signals-', dir=Path(__file__).resolve().parent) as scratch:
        root = Path(scratch)
        args = SimpleNamespace(mode='stage1', source_manifest_sha256='b'*64, output=root/'new-run',
                               helper_binding=root/'mock-binding', helper_binding_sha256='c'*64)
        with mock.patch.object(runner, 'RUNS', root), \
             mock.patch.object(runner, 'frozen', return_value=(source, manifest)), \
             mock.patch.object(runner, 'bind_helper', return_value=binding), \
             mock.patch.object(runner, 'command_plan', side_effect=plan), \
             mock.patch.object(runner, 'authenticate_case', return_value=(b'original', {})), \
             mock.patch.object(runner.subprocess, 'Popen', return_value=helper), \
             mock.patch.object(runner.signal, 'getsignal', side_effect=lambda sig: current[sig]), \
             mock.patch.object(runner.signal, 'signal', side_effect=disposition), \
             mock.patch.object(runner, 'write_new', side_effect=write_with_repeated_signals):
            try:
                runner.run(args)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise AssertionError('stuck helper became successful')
        assert current == initial
        assert helper.waits == [55, 10, 5]
        assert helper.terminated and helper.killed
        assert len(deliveries) == 6
        assert {name for name, _ in deliveries} == {'frontend.supervisor.json', 'failed-incomplete.json'}
        supervisor = json.loads((args.output/'mock-case/frontend.supervisor.json').read_text())
        failed = json.loads((args.output/'failed-incomplete.json').read_text())
        assert supervisor['helper_watchdog_timeout'] and supervisor['termination_grace_timeout'] and supervisor['post_kill_wait_timeout']
        assert supervisor['unresolved_ownership'] and supervisor['external_cleanup_required']
        assert not supervisor['helper_receipt_validated']
        assert failed['status'] == 'FAILED_INCOMPLETE_NO_RETRY'
        assert failed['unresolved_ownership'] and failed['external_cleanup_required']
        assert not failed['rewritten_app_executed'] and failed['completed_cases'] == []
        assert len(failed['supervisor_receipts']) == 1
        assert not (args.output/'stage1-complete.json').exists()
    return dict(mocked_scenarios=1, simulated_signal_deliveries=6, helper_wait_seconds=helper.waits,
                actual_process_launches=0, actual_signals_sent=0)


if __name__ == '__main__':
    print(json.dumps(calibrate(), indent=2))
