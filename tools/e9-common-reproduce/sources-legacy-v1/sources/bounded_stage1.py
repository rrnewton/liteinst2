"""Exact historical bounded stage-1 helper bodies; no new supervisor."""
import sys
if sys.flags.optimize: raise SystemExit("optimized Python forbidden")
sys.dont_write_bytecode = True
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from old_audit import digest, loads, read_file, validate_helper_receipt
MAX_FILE = 16 * 1024 * 1024
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}

def write_new(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as stream: stream.write(raw)
    return raw


def capture(path):
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_size <= MAX_FILE
    raw = path.read_bytes(); assert len(raw) <= MAX_FILE
    return raw


def inventory(directory):
    result = {}
    pending = [directory]
    seen = 0
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                seen += 1
                assert seen <= 512, 'bounded artifact inventory exceeded'
                path = Path(entry.path)
                assert not path.is_symlink()
                if path.is_dir():
                    pending.append(path)
                    continue
                assert path.is_file()
                result[str(path.relative_to(directory))] = dict(bytes=path.stat().st_size, sha256=digest(capture(path)))
    return result


class FailureSignals:
    def __init__(self):
        self.previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}

    def ignore(self):
        for sig in self.previous:
            signal.signal(sig, signal.SIG_IGN)

    def restore(self):
        for sig, handler in self.previous.items():
            signal.signal(sig, handler)


def helper_command(item, source, binding, verify, failure_signals):
    case = Path(item['request']['cwd']); name = item['name']
    request_path = case/f'{name}.request.json'; receipt_path = case/f'{name}.receipt.json'
    request_raw = write_new(request_path, item['request'])
    command = [source['python']['path'], binding['path'], '--request', str(request_path), '--receipt', str(receipt_path)]
    verify()  # Full source/tool/input/helper check immediately before every launch.
    started = time.monotonic(); child = None; interrupted = None
    helper_watchdog_timeout = False; terminate_sent = False; kill_sent = False
    termination_grace_timeout = False; post_kill_wait_timeout = False
    cleanup_error = None; helper_receipt_validated = False
    old_handlers = {}
    def stop(signum, frame):
        raise KeyboardInterrupt(f'calibration interrupted by signal {signum}')
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT): old_handlers[sig] = signal.signal(sig, stop)
    try:
        with (case/f'{name}.supervisor.stdout').open('xb') as out, (case/f'{name}.supervisor.stderr').open('xb') as err:
            child = subprocess.Popen(command, cwd=case, env=ENV, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            # E9 retains wall45 and the helper cleanup retains five seconds.
            # A separate fixed55-second watchdog also bounds helper receipt/I/O
            # overhead. It never extends E9's requested wall or CPU allowance.
            try:
                status = child.wait(timeout=55)
            except subprocess.TimeoutExpired:
                helper_watchdog_timeout = True
                raise
        assert status == 0, 'bounded helper failed; retained output is not a success'
        stdout = capture(Path(item['request']['stdout'])); stderr = capture(Path(item['request']['stderr']))
        receipt = loads(read_file(receipt_path))
        validate_helper_receipt(receipt, request_raw, binding['sha256'], stdout, stderr)
        helper_receipt_validated = True
        verify()
        return stdout, stderr
    except BaseException as error:
        interrupted = type(error).__name__ + ': ' + str(error)
        # Repeated catchable signals cannot interrupt the finite failure path.
        failure_signals.ignore()
        try:
            if child is not None and child.poll() is None:
                try:
                    child.terminate(); terminate_sent = True
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    termination_grace_timeout = True
                    # SIGKILL is not descendant-collection evidence. Even if
                    # the direct helper reaps, external ownership stays pending
                    # unless its exact successful cleanup receipt was verified.
                    try:
                        child.kill(); kill_sent = True
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        post_kill_wait_timeout = True
        except BaseException as cleanup_failure:
            cleanup_error = type(cleanup_failure).__name__ + ': ' + str(cleanup_failure)
        # Keep these signals ignored through both the supervisor receipt below
        # and run()'s failed-incomplete receipt. run() restores the original
        # dispositions only after that terminal failure evidence is written.
        raise
    finally:
        try:
            write_new(case/f'{name}.supervisor.json', dict(argv=command, elapsed_seconds=time.monotonic()-started,
                exit=None if child is None else child.returncode, interrupted=interrupted,
                request_sha256=digest(request_raw), helper_sha256=binding['sha256'],
                helper_watchdog_seconds=55, termination_grace_seconds=10, post_kill_wait_seconds=5,
                helper_watchdog_timeout=helper_watchdog_timeout, terminate_sent=terminate_sent,
                termination_grace_timeout=termination_grace_timeout, kill_sent=kill_sent,
                post_kill_wait_timeout=post_kill_wait_timeout, cleanup_error=cleanup_error,
                helper_receipt_validated=helper_receipt_validated,
                unresolved_ownership=child is not None and not helper_receipt_validated,
                external_cleanup_required=child is not None and not helper_receipt_validated,
                child_pid=None if child is None else child.pid))
        finally:
            if interrupted is None:
                for sig, handler in old_handlers.items(): signal.signal(sig, handler)

