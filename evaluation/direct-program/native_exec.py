#!/usr/bin/env python3
"""Authenticate two FDs, then become cat; no subprocess, watchdog or shell fallback."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import sys


CATALOG_SHA = '2b89602488e2b1854e0df68ecdf49243d4c952a2f393fad4a56785db4a539bde'


def high(fd):
    try: return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
    finally: os.close(fd)


def hold(path, size, digest):
    fd = high(os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK))
    before = os.fstat(fd); assert stat.S_ISREG(before.st_mode) and before.st_size == int(size)
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    h = hashlib.sha256()
    for block in iter(lambda: os.read(fd, 1024**2), b''): h.update(block)
    assert h.hexdigest() == digest and stamp(before) == stamp(os.fstat(fd)) == stamp(os.lstat(path))
    os.lseek(fd, 0, 0)
    return fd


def main():
    catalog_bytes = Path(__file__).with_name('program_catalog.json').read_bytes()
    assert hashlib.sha256(catalog_bytes).hexdigest() == CATALOG_SHA
    catalog = json.loads(catalog_bytes)
    assert sys.argv[9:] in [[program, *case['argv']] for program, cases in catalog['programs'].items() for case in cases]
    executable = hold(*sys.argv[1:4]); source = hold(*sys.argv[4:7])
    assert os.fstat(executable).st_mode & 0o777 == 0o500 and len(os.sched_getaffinity(0)) == 1
    for key, value in ((resource.RLIMIT_CPU, 20), (resource.RLIMIT_AS, 2*1024**3), (resource.RLIMIT_FSIZE, 1024**2), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (value, value))
    stderr = high(os.open(sys.argv[7], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600))
    os.dup2(source, 0); os.dup2(stderr, 2); os.close(source); os.close(stderr); os.umask(0o077)
    try:
        os.execve(executable, sys.argv[9:], dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC'))
    except OSError as error:
        with Path(sys.argv[8]).open('x') as stream:
            json.dump(dict(errno=error.errno, strerror=error.strerror, no_fallback=True), stream)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        directory = os.open(Path(sys.argv[8]).parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        return 111
    raise AssertionError('execve returned')


if __name__ == '__main__':
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    raise SystemExit(main())
