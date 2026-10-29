#!/usr/bin/env python3
"""One exact-revision throughput comparison; normal exit is not performance proof."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import traceback

REV = '6332c8f229833e7f6b9a7c99c9101c410e6cb0cb'
TAG = 'li2core-throughput-6332c8f'
WALL, CAP = 1200, 8 * 1048576
DRIVER = 'tools/rapid-profiler/normal-work/throughput_probe.py'
OWNER = 'evaluation/admission/processes.py'
SOURCES = {
    DRIVER: 'bcc8065afabe0e7aec45f0a71721d7ae1db3ccdf75345375fb89fcf950c4105e',
    OWNER: '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f',
}


def digest(path):
    h = hashlib.sha256(); size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            size += len(block); h.update(block)
    return dict(bytes=size, sha256=h.hexdigest())


def write(path, data):
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'raw', 'allocator', 'toolchain', 'user-home', 'cargo-home'):
        parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args(); repo = a.repo
    for p in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.allocator.is_absolute() and a.allocator.is_file() and os.access(a.allocator, os.X_OK)
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    python = Path(sys.executable).resolve(strict=True)
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', LC_ALL='C', LANG='C',
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    # Preserve only explicitly supplied session/ledger coordinates; invent none.
    for name in ('XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'DAGRUN_CORE_LEDGER'):
        if name in os.environ:
            value = os.environ[name]
            assert value and len(value) <= 4096 and not any(c in value for c in '\0\r\n')
            env[name] = value
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], env=env, timeout=15)
        assert len(data) <= CAP
        return data
    def source_check():
        assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
        assert git('rev-parse', 'HEAD').decode().strip() == REV
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        for name, sha in SOURCES.items():
            data = (repo/name).read_bytes()
            assert hashlib.sha256(data).hexdigest() == sha and data == git('show', REV+':'+name)
    source_check()  # Authenticate the sole project import before loading it.
    tools = (python, Path('/usr/bin/git'), a.allocator, a.toolchain/'bin/cargo', a.toolchain/'bin/rustc')
    def tool_pins():
        return {str(p):dict(resolved=str(p.resolve(strict=True)), **digest(p)) for p in tools}
    before_tools = tool_pins()
    os.umask(0o077); a.raw.mkdir(mode=0o700)
    log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
    assert log_root.resolve(strict=True) == log_root
    log = Path(tempfile.mkdtemp(prefix='ordinary-throughput-6332c8f-', dir=log_root))/'outer.log'
    driver = [str(python), '-B', str(repo/DRIVER), '--revision', REV,
        '--raw', str(a.raw/'comparison'), '--toolchain', str(a.toolchain),
        '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home), '--reservation-tag', TAG]
    argv = [str(a.allocator), 'run', '--cores', '4', '--sample-s', '1', '--tag', TAG, '--', *driver]
    request = dict(revision=REV, argv=argv, driver_argv=driver, env=env, cwd=str(repo),
        reservation=dict(cores=4, tag=TAG, invocation=argv[:argv.index('--')+1],
            authority='Caller-supplied allocator; root must authenticate reservation and hard AllowedCPUs. Tag alone is not proof.'),
        wall_seconds=WALL, log_bytes=CAP, invocations=1, retries=0, pairs=5, trials=10,
        source_sha256=SOURCES, tools=before_tools, reproducer=digest(Path(__file__).resolve()),
        private_log=str(log), driver_raw=str(a.raw/'comparison'))
    request_pin = write(a.raw/'request.json', encoded(request))
    result = dict(status='NOT_LAUNCHED', revision=REV, request=request_pin, closed=None,
        scope='One invocation only. Outer closure/exit never substitutes for the driver results, reservation proof or performance evidence.')
    code = 2
    try:
        spec = importlib.util.spec_from_file_location('throughput_reproducer_owner', repo/OWNER)
        assert spec is not None and spec.loader is not None
        owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
        result['status'] = 'LAUNCH_ATTEMPTED'
        closed = owner.run_command(argv, env, log, WALL, CAP)
        result['closed'] = write(a.raw/'outer-closed.json', encoded(closed))
        data = log.read_bytes()
        result['log'] = write(a.raw/'outer.log', data)
        assert len(data) <= CAP and result['log']['sha256'] == closed['private_log_sha256']
        assert type(closed['exit_code']) is int and closed['exit_code'] in (0, 1)
        assert closed['termination'] is None and closed['cleanup_complete'] is True
        assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0
        source_check(); assert tool_pins() == before_tools
        assert digest(a.raw/'request.json') == request_pin
        assert digest(Path(__file__).resolve()) == request['reproducer']
        result.update(status='NORMAL_OUTER_EXIT', outer_exit=closed['exit_code'], source_unchanged=True)
        code = closed['exit_code']  # Preserve normal failure, never relabel it PASS.
    except BaseException as error:
        result.update(status='WRAPPER_REFUSED', error_type=type(error).__name__)
        result['failure'] = write(a.raw/'wrapper-failure.txt', traceback.format_exc().encode('utf-8'))
    finally:
        write(a.raw/'reproducer-result.json', encoded(result))
    print('throughput-reproducer '+result['status']+' exit='+str(code))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
