"""Bounded Linux command ownership for the serial evaluation supervisor.

run_command requires one supervisor thread, no pre-existing children, default
SIGCHLD handling and no competing reaper. These checks are part of its contract:
subreaper adoption alone cannot distinguish concurrent, unrelated child owners.
The command may fork, change process groups or create sessions. The optional
proc children file supplies direct children. Without it, one-level proc entries
are candidates only: a stable pidfd must pass a nonreaping owned-child wait.
Global waits only prove absence of children; they never consume a wait status.
An incomplete cleanup poisons this module and retains its unreaped owners.
"""

import ctypes
import datetime as dt
import hashlib
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
CLEANUP_SECONDS = 3.0
_WALL = 0x40000000
_GET_SUBREAPER = 37
_SET_SUBREAPER = 36
_RETAINED = []


class _OwnershipError(Exception):
    pass


def _children_file():
    path = Path(f"/proc/self/task/{os.getpid()}/children")
    words = path.read_text().split()
    if any(not word.isascii() or not word.isdecimal() for word in words):
        raise _OwnershipError()
    return {int(word) for word in words}


def _no_children():
    # None means at least one live child; a status means a terminal child.
    # Only ECHILD proves absence. WNOWAIT never consumes an existing child.
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | _WALL)
    except ChildProcessError:
        return True
    return False


def _check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise _OwnershipError()


def _proc_candidates(deadline):
    # No recursion, PPid inference, numeric signals or proc-derived ownership.
    _check_deadline(deadline)
    with os.scandir("/proc") as entries:
        for entry in entries:
            _check_deadline(deadline)
            if entry.name.isascii() and entry.name.isdecimal():
                yield int(entry.name)


def _direct_children(deadline=None, strategy=None):
    if deadline is None:
        deadline = time.monotonic() + CLEANUP_SECONDS
    _check_deadline(deadline)
    if strategy != "pidfd_authenticated_proc_candidates":
        try:
            children = _children_file()
            _check_deadline(deadline)
            return children
        except FileNotFoundError:
            if strategy == "proc_children":
                raise
    children = set()
    for pid in _proc_candidates(deadline):
        _check_deadline(deadline)
        try:
            candidate = _Child(pid)
        except (ChildProcessError, ProcessLookupError):
            continue
        # There is no competing reaper: an authenticated child cannot lose its
        # identity while this supervisor closes and later reopens its pidfd.
        try:
            children.add(pid)
        finally:
            os.close(candidate.pidfd)
    _check_deadline(deadline)
    return children


def _subreaper(value=None):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if value is None:
        output = ctypes.c_int()
        result = libc.prctl(_GET_SUBREAPER, ctypes.addressof(output), 0, 0, 0)
        value = output.value
    else:
        result = libc.prctl(_SET_SUBREAPER, value, 0, 0, 0)
    if result != 0:
        raise OSError(ctypes.get_errno(), "subreaper operation failed")
    return value


def _preflight():
    if sys.platform != "linux" or _RETAINED:
        raise _OwnershipError()
    if {entry.name for entry in Path("/proc/self/task").iterdir()} != {str(os.getpid())}:
        raise _OwnershipError()
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL or not _no_children():
        raise _OwnershipError()
    # A custom handler could fork or reap while the supervisor is inspecting
    # ownership. Python's ordinary SIGINT handler only raises KeyboardInterrupt.
    for number in signal.valid_signals():
        if number in (signal.SIGKILL, signal.SIGSTOP):
            continue
        handler = signal.getsignal(number)
        if handler not in (signal.SIG_DFL, signal.SIG_IGN, None):
            if number != signal.SIGINT or handler != signal.default_int_handler:
                raise _OwnershipError()
    if not all((hasattr(os, "pidfd_open"), hasattr(os, "P_PIDFD"),
                hasattr(signal, "pidfd_send_signal"))):
        raise _OwnershipError()
    descriptor = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(descriptor, 0)
    finally:
        os.close(descriptor)
    try:
        if _children_file():
            raise _OwnershipError()
        return "proc_children"
    except FileNotFoundError:
        return "pidfd_authenticated_proc_candidates"


class _Child:
    def __init__(self, pid):
        self.pid = pid
        self.pidfd = os.pidfd_open(pid)
        self.reaped = False
        try:
            self.exit_status()
        except BaseException:
            os.close(self.pidfd)
            self.pidfd = None
            raise

    def exit_status(self):
        # WNOWAIT pins both PID and process-group identity until cleanup has
        # finished sending group signals. Never use Popen.poll(), which reaps.
        status = os.waitid(os.P_PIDFD, self.pidfd,
                           os.WEXITED | os.WNOHANG | os.WNOWAIT | _WALL)
        if status is not None and status.si_pid != self.pid:
            raise _OwnershipError()
        return status

    def kill(self):
        try:
            signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def reap(self):
        if self.exit_status() is None:
            return False
        pid, status = os.waitpid(self.pid, os.WNOHANG | _WALL)
        if pid == self.pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
            self.reaped = True
            os.close(self.pidfd)
            self.pidfd = None
            return True
        return False


def _returncode(status):
    if status is None:
        return None
    if status.si_code == os.CLD_EXITED:
        return status.si_status
    if status.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -status.si_status
    raise _OwnershipError()


def _kill_group(leader_pid):
    # The caller retains an unreaped leader. Its numeric PID cannot be reused
    # for an unrelated process group while this operation is possible.
    try:
        os.killpg(leader_pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_command(argv, env, log, timeout_seconds, max_log_bytes=8 * 1024 * 1024):
    """Run one command, capture bounded private output and reap its whole tree.

    The wall deadline remains active after stdout EOF. Cleanup always runs,
    including after exit zero, and has a separate three-second upper budget.
    Descendants in other sessions are adopted and killed through stable pidfds.
    Exit zero with adopted descendants is a lifecycle failure even if all are
    subsequently reaped. SIGINT is deferred across ownership transitions.
    Failure details use a closed vocabulary; neither argv nor output is returned.
    """
    begin = time.monotonic()
    result = {"start_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "exit_code": None, "termination": None, "seconds": None,
              "private_log_sha256": None, "cleanup_complete": True,
              "reaped_descendants": 0, "child_discovery_strategy": "not_needed"}
    log = Path(log)
    if not log.resolve().is_relative_to((ROOT / "target/evaluation").resolve()):
        raise ValueError("private log must remain under target/evaluation")
    if (not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds) or timeout_seconds <= 0
            or type(max_log_bytes) is not int or max_log_bytes < 1):
        raise ValueError("invalid command bounds")
    process = None
    leader = None
    children = {}
    prior_subreaper = None
    prior_sigint = None
    interrupted = False
    written = 0
    capture_failed = False
    cleanup_failed = False

    def fail(reason):
        if result["termination"] is None:
            result["termination"] = reason

    def defer_sigint(_number, _frame):
        nonlocal interrupted
        interrupted = True

    with log.open("wb") as output, selectors.DefaultSelector() as selector:
        def drain(wait=0.0):
            nonlocal written, capture_failed
            if not selector.get_map():
                if wait:
                    time.sleep(wait)
                return
            try:
                for key, _ in selector.select(wait):
                    try:
                        data = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    available = max_log_bytes - written
                    output.write(data[:available])
                    written += min(len(data), available)
                    if len(data) > available:
                        fail("output_limit")
            except OSError:
                capture_failed = True
                fail("capture_error")

        try:
            result["child_discovery_strategy"] = _preflight()
            # Raising KeyboardInterrupt inside Popen.__init__ can leave a child
            # without an assigned owner. Deferral also makes reap+state updates
            # indivisible with respect to SIGINT. A caught signal disposition is
            # reset by exec, so this handler does not leak into the command.
            original_sigint = signal.getsignal(signal.SIGINT)
            if original_sigint != signal.SIG_IGN:
                signal.signal(signal.SIGINT, defer_sigint)
                prior_sigint = original_sigint
            prior_subreaper = _subreaper()
            _subreaper(1)
            try:
                process = subprocess.Popen(argv, cwd=ROOT, env=env,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           start_new_session=True)
            except OSError:
                fail("spawn_error")
            if process is not None:
                leader = _Child(process.pid)
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = begin + timeout_seconds
                while True:
                    if interrupted:
                        fail("interrupted")
                    status = leader.exit_status()
                    if status is not None:
                        result["exit_code"] = _returncode(status)
                        break
                    if time.monotonic() >= deadline:
                        fail("timeout")
                    if result["termination"] is not None:
                        break
                    drain(min(0.02, max(0, deadline - time.monotonic())))
        except _OwnershipError:
            fail("ownership_refused")
        except KeyboardInterrupt:
            fail("interrupted")
        except (OSError, ValueError):
            fail("setup_error" if process is None else "capture_error")
        finally:
            if process is not None:
                cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
                try:
                    # Recover a partial pidfd setup while the unreaped Popen
                    # child still pins the group's numeric identity.
                    _kill_group(process.pid)
                    if leader is None:
                        leader = _Child(process.pid)
                    while time.monotonic() < cleanup_deadline:
                        if not leader.reaped:
                            _kill_group(process.pid)
                            leader.kill()
                            status = leader.exit_status()
                            if status is not None:
                                if result["exit_code"] is None:
                                    result["exit_code"] = _returncode(status)
                                # This is the last numeric group signal. Reap
                                # the pinned leader so ECHILD can subsequently
                                # prove complete cleanup without trusting a
                                # proc enumeration's racing snapshot.
                                _kill_group(process.pid)
                                if leader.reap():
                                    process.returncode = result["exit_code"]
                        if leader.reaped and _no_children():
                            break
                        excluded = {process.pid} if not leader.reaped else set()
                        for pid in _direct_children(
                                cleanup_deadline, result["child_discovery_strategy"]) - excluded:
                            if pid not in children:
                                children[pid] = _Child(pid)
                        for child in children.values():
                            child.kill()
                        for pid, child in list(children.items()):
                            if child.reap():
                                result["reaped_descendants"] += 1
                                del children[pid]
                        if leader.reaped and not children and _no_children():
                            break
                        drain(0.01)
                    else:
                        cleanup_failed = True

                    if not leader.reaped or children or not _no_children():
                        cleanup_failed = True
                    # All owned writers are now dead; drain their finite tail.
                    while selector.get_map() and time.monotonic() < cleanup_deadline:
                        drain(0.01)
                    if selector.get_map():
                        capture_failed = True
                        fail("capture_error")
                except (OSError, _OwnershipError, KeyboardInterrupt):
                    cleanup_failed = True
                finally:
                    if process.stdout is not None:
                        process.stdout.close()
                    if cleanup_failed:
                        result["cleanup_complete"] = False
                        fail("cleanup_incomplete")
                        # No Popen destructor or future helper call may reap a
                        # retained owner behind this cleanup failure's back.
                        _RETAINED.append((process, leader, children))
            if prior_subreaper is not None and not cleanup_failed:
                try:
                    _subreaper(prior_subreaper)
                except OSError:
                    fail("setup_error")
            if capture_failed:
                fail("capture_error")
            if prior_sigint is not None:
                signal.signal(signal.SIGINT, prior_sigint)
            if interrupted:
                fail("interrupted")
            if result["exit_code"] == 0 and result["reaped_descendants"]:
                fail("descendants_after_exit")
    result["seconds"] = time.monotonic() - begin
    result["private_log_sha256"] = hashlib.sha256(log.read_bytes()).hexdigest()
    return result
