#!/usr/bin/env python3
"""Repeat one pinned carrier command; preserve its actual nonzero CLI status."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
PINS = dict(core='2ebb35cf4489856bd77a894480e5d8b219e035d3eff95c9c32e03a9a6e944f8b',
    original='987b20efe393a0a2ca0293cd5601ba323b3f8292c9f1b5fab8a22b3124d3cff8',
    selection='9c200659f67725b0ddce8f2ca974d8f329de1270d8e37f3018259877547fd4b9',
    helper='c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44')


def read(p):
    assert p.is_absolute() and '..' not in p.parts and p.resolve(strict=True) == p
    fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        s = os.fstat(f.fileno())
        assert stat.S_ISREG(s.st_mode) and 0 <= s.st_size <= 128 * 1048576
        b = f.read(128 * 1048576 + 1)
        assert len(b) == s.st_size and fields(s) == fields(os.fstat(f.fileno())) == fields(p.lstat())
    return b, fields(s)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write(p, value):
    with p.open('xb') as f:
        f.write((json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


def main():
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported; assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'core', 'original', 'selection', 'raw'):
        parser.add_argument('--' + name, type=Path, required=True)
    a = parser.parse_args()
    assert a.repo.is_absolute() and a.repo.resolve(strict=True) == a.repo
    assert a.raw.is_absolute() and '..' not in a.raw.parts and a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.raw.is_relative_to(a.repo / 'ignored') and not a.raw.exists() and not a.raw.is_symlink()
    inputs = dict(core=a.core, original=a.original, selection=a.selection,
                  helper=a.repo / 'tools/unwind-oracle/bounded_command.py')
    before = {k: read(p) for k, p in inputs.items()}
    assert all(sha(before[k][0]) == digest for k, digest in PINS.items())
    assert before['core'][1][2] & 0o111
    a.raw.mkdir(); d = a.raw / 'command'; d.mkdir()
    request = dict(argv=[str(a.core), 'prepare', str(a.original), str(a.selection), str(a.raw / 'artifact')],
        cwd=str(a.repo), env=ENV, cpu_seconds=20, wall_seconds=30, file_bytes=16777216,
        stdout=str(d / 'stdout.txt'), stderr=str(d / 'stderr.txt'))
    write(d / 'request.json', request)
    outer = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', '40s', '/usr/bin/python3.9', '-B',
             str(inputs['helper']), '--request', str(d / 'request.json'), '--receipt', str(d / 'receipt.json')]
    write(d / 'command.json', dict(argv=outer, cwd=str(a.repo), env=ENV, parent_timeout_seconds=55,
                                  request_sha256=sha(read(d / 'request.json')[0])))
    write(a.raw / 'inputs.json', {k: dict(sha256=sha(v[0]), bytes=len(v[0]), stat=v[1]) for k, v in before.items()})
    started = time.monotonic(); code = None; timed_out = False
    try:
        with (d / 'helper.stdout').open('xb') as out, (d / 'helper.stderr').open('xb') as err:
            child = subprocess.Popen(outer, cwd=a.repo, env=ENV, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=err, start_new_session=True)
            try:
                code = child.wait(timeout=55)
            except BaseException as error:
                timed_out = isinstance(error, subprocess.TimeoutExpired)
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                code = child.wait()
                raise
    finally:
        write(d / 'parent-closed.json', dict(exit=code, parent_timeout=timed_out,
            parent_wait_returned=code is not None, operational_seconds=time.monotonic() - started))
        after = {k: read(p) for k, p in inputs.items()}
        write(a.raw / 'inputs-after.json', {k: dict(sha256=sha(v[0]), bytes=len(v[0]), stat=v[1]) for k, v in after.items()})
    assert not timed_out and all(read(inputs[k]) == value for k, value in before.items())
    receipt = json.loads(read(d / 'receipt.json')[0])
    assert receipt.keys() == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout', 'unexpected_descendants',
        'absence_proof', 'stdout_sha256', 'stderr_sha256', 'elapsed_seconds', 'cleanup_events', 'cleanup_error', 'aborted', 'inputs_unchanged'}
    assert type(receipt['exit']) is int and receipt['request_sha256'] == sha(read(d / 'request.json')[0])
    assert receipt['helper_sha256'] == PINS['helper'] and receipt['wall_timeout'] is False
    assert receipt['absence_proof'] == 'ECHILD' and receipt['inputs_unchanged'] is True
    assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
    assert receipt['cleanup_error'] is receipt['aborted'] is None and 0 <= receipt['elapsed_seconds'] <= 30
    for name in ('stdout', 'stderr'):
        assert receipt[name + '_sha256'] == sha(read(d / (name + '.txt'))[0])
    assert code == (0 if receipt['exit'] == 0 else 1)
    terminal = dict(exit=receipt['exit'], wall_timeout=False, absence_proof='ECHILD', descendants=0, success=receipt['exit'] == 0)
    assert read(d / 'helper.stdout')[0] == (json.dumps(terminal) + '\n').encode() and not read(d / 'helper.stderr')[0]
    print(json.dumps(dict(child_exit=receipt['exit'], outer_exit=code, absence_proof='ECHILD',
                         qualification_complete=False)))
    return receipt['exit'] if receipt['exit'] >= 0 else 128 - receipt['exit']


if __name__ == '__main__':
    raise SystemExit(main())
