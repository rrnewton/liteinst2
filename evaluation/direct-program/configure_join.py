#!/usr/bin/env python3
"""Join configure and all adopted children; the external owner enforces deadlines."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

_WALL = 0x40000000


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER); args = parser.parse_args()
    assert args.command[:1] == ['--'] and len(args.command) > 1 and not args.receipt.exists()
    assert sys.platform == 'linux' and threading.active_count() == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
    try: os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | _WALL)
    except ChildProcessError: pass
    else: raise AssertionError('initial ECHILD required')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(36, 1, 0, 0, 0): raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    leader = subprocess.Popen(args.command[1:]); adopted = []; leader_status = None
    while True:
        try: pid, status = os.waitpid(-1, _WALL)
        except InterruptedError: continue
        except ChildProcessError: break
        row = dict(pid=pid, wait_status=status, exit_code=os.waitstatus_to_exitcode(status))
        if pid == leader.pid and leader_status is None:
            leader_status = row; leader.returncode = row['exit_code']
        else: adopted.append(row)
    assert leader_status is not None
    passed = leader_status['exit_code'] == 0 and all(row['exit_code'] == 0 for row in adopted)
    record = dict(status='PASS' if passed else 'FAILED', initial_echild=True, joined_echild=True,
                  command=args.command[1:], leader=leader_status, adopted=adopted)
    with args.receipt.open('x') as stream:
        json.dump(record, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(args.receipt.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return int(not passed)


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    raise SystemExit(main())
