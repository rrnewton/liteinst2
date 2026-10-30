#!/usr/bin/env python3
"""Measure kernel xstate length on one own stopped child; never exec a program."""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time


CAP = 16384
MINIMUM = 576
SECONDS = 15
CLEANUP_SECONDS = 5
WALL = 0x40000000


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def deadline(end):
    if time.monotonic() >= end:
        raise TimeoutError('probe deadline')


def require_child_free():
    # WNOWAIT leaves every existing status owned by its caller. A zero/no-event
    # return still means a live child exists; only exact ECHILD proves absence.
    # __WALL includes children whose clone exit signal is not SIGCHLD.
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WSTOPPED | os.WCONTINUED
                  | os.WNOHANG | os.WNOWAIT | WALL)
    except ChildProcessError as error:
        need(error.errno == errno.ECHILD, 'exact child-free preflight errno')
    else:
        raise ValueError('dedicated child-free process')


def wait_event(pid, end):
    while True:
        deadline(end)
        got, status = os.waitpid(pid, os.WNOHANG | WALL)
        if got:
            need(got == pid, 'exact owned child')
            return status
        time.sleep(min(0.001, max(0, end-time.monotonic())))


def cleanup(pid, report):
    """Only this unreaped child is signalled; terminal wait plus global ECHILD."""
    end = time.monotonic() + CLEANUP_SECONDS
    if not report['child_reaped']:
        try:
            os.kill(pid, signal.SIGKILL)
            report['kill_sent'] = True
        except ProcessLookupError:
            pass
        while not report['child_reaped']:
            status = wait_event(pid, end)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                report['terminal_status'] = status
                report['child_reaped'] = True
            else:
                os.kill(pid, signal.SIGKILL)
    deadline(end)
    try:
        os.waitpid(-1, os.WNOHANG | WALL)
    except ChildProcessError as error:
        need(error.errno == errno.ECHILD, 'exact absence errno')
        report['absence_proof'] = 'ECHILD'
    else:
        raise ValueError('unexpected remaining child')
    deadline(end)


def save_raw(path, raw, end):
    deadline(end)
    root = Path(__file__).resolve().parents[2]
    need(path.is_absolute() and path.is_relative_to(root/'ignored')
         and path.parent.resolve(strict=True) == path.parent, 'new private raw output')
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=parent)
        os.fchmod(fd, 0o400)
        at = 0
        while at < len(raw):
            deadline(end)
            written = os.write(fd, raw[at:])
            need(written > 0, 'complete raw write')
            at += written
        os.fsync(fd)
        need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o400, 'private raw mode')
        deadline(end)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw-output', type=Path)
    args = parser.parse_args()
    report = dict(schema='LI2HOST-XSTATE-1', hardware='AMD EPYC Zen 5 dev host',
        probe_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        platform='linux-x86_64', request_bytes=CAP, xstate_bytes=None, xstate_sha256=None,
        initial_status=None, terminal_status=None, child_started=False, child_reaped=False,
        kill_sent=False, absence_proof=None, raw_saved=False, observation_complete=False,
        command_seconds=SECONDS, cleanup_seconds=CLEANUP_SECONDS, errors=[],
        exec_dispatches=0, candidate_dispatches=0, native_dispatches=0,
        qualification_complete=False, performance_eligible=False)
    pid = None; raw = None; stage = 'preflight'; handlers = {}
    began = time.monotonic(); end = began + SECONDS
    def error(failure):
        report['errors'].append(dict(stage=stage,type=type(failure).__name__,errno=getattr(failure,'errno',None)))
    def interruption(signum, frame):
        failure = InterruptedError(signum, 'probe interrupted')
        if stage == 'cleanup':
            error(failure)  # Finish kill/reap, while retaining the interruption.
        else:
            raise failure
    try:
        need(sys.platform == 'linux' and os.uname().machine == 'x86_64'
             and ctypes.sizeof(ctypes.c_void_p) == 8, 'Linux x86-64 only')
        own = os.getpid()
        need(os.listdir('/proc/self/task') == [str(own)], 'dedicated single thread')
        require_child_free()
        need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'normal child wait ownership')
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interruption)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        libc.ptrace.restype = ctypes.c_long
        libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
        libc.prctl.restype = ctypes.c_int
        class Iovec(ctypes.Structure):
            _fields_ = [('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
        stage = 'fork'; deadline(end)
        pid = os.fork()
        if pid == 0:
            # No child creates descendants or execs. Parent death also kills a
            # stopped child, even if the parent's outer owner must SIGKILL it.
            try:
                if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != own:
                    os._exit(120)
                if libc.ptrace(0, 0, None, None) != 0:  # PTRACE_TRACEME
                    os._exit(121)
                os.kill(os.getpid(), signal.SIGSTOP)
            finally:
                os._exit(122)  # Any unexpected continuation fails closed.
        report['child_started'] = True
        stage = 'initial-stop'
        status = wait_event(pid, end); report['initial_status'] = status
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            report['child_reaped'] = True; report['terminal_status'] = status
        need(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP
             and status >> 16 == 0, 'exact initial SIGSTOP')
        stage = 'getregset'; deadline(end)
        data = (ctypes.c_ubyte * CAP)()
        iovec = Iovec(ctypes.addressof(data), CAP)
        ctypes.set_errno(0)
        if libc.ptrace(0x4204, pid, ctypes.c_void_p(0x202), ctypes.byref(iovec)) != 0:
            raise OSError(ctypes.get_errno(), 'GETREGSET')
        deadline(end)
        need(MINIMUM <= iovec.length <= CAP and iovec.base == ctypes.addressof(data), 'actual full-buffer xstate result')
        raw = bytes(data[:iovec.length])
        report['xstate_bytes'] = len(raw)
        report['xstate_sha256'] = hashlib.sha256(raw).hexdigest()
        deadline(end)
    except BaseException as failure:
        error(failure)
    finally:
        if pid is not None and pid > 0:
            stage = 'cleanup'
            try:
                cleanup(pid, report)
                if raw is not None:
                    need(os.WIFSIGNALED(report['terminal_status'])
                         and os.WTERMSIG(report['terminal_status']) == signal.SIGKILL,
                         'exact killed measurement child')
            except BaseException as failure:
                error(failure)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    if not report['errors'] and raw is not None and args.raw_output is not None:
        stage = 'raw-output'
        try:
            save_raw(args.raw_output, raw, end); report['raw_saved'] = True
        except BaseException as failure:
            error(failure)
    report['observation_complete'] = bool(not report['errors'] and raw is not None
        and report['child_reaped'] and report['absence_proof'] == 'ECHILD')
    report['elapsed_seconds'] = time.monotonic()-began
    print(json.dumps(report, sort_keys=True, separators=(',',':')))
    return 0 if report['observation_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
