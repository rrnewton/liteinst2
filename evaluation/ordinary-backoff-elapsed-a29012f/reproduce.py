#!/usr/bin/env python3
"""One exact-revision segmented elapsed catalog; normal exit is not qualification proof."""
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

REV = 'a29012f08baf7a5a334103ea9e8c95b3ffe45888'
TAG = 'li2core-backoff-elapsed-order-a29012f'
WALL, CAP = 1200, 8 * 1048576
DRIVER = 'tools/rapid-profiler/normal-work/backoff_elapsed_probe.py'
OWNER = 'evaluation/admission/processes.py'
MODES = ('native', 'always-on', 'backoff-k10', 'backoff-k1000')
CATALOG = [dict(trial=4*b+i+1, block=b+1, mode=MODES[(b+i)%4])
           for b in range(5) for i in range(4)]
SOURCES = {
    DRIVER: '5678b33ad513ad6f19d0cacec9fdce5d2f63bf95f168b2df336b4a429ee6d039',
    OWNER: '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f',
    'tools/rapid-profiler/normal-work/backoff_elapsed_work.py': '3c74562f4e57872752af53ef5ec5d5f36964d6a19d64c1723b0c5ff1d755f024',
    'tools/rapid-profiler/normal-work/test_backoff_elapsed_work.py': '3727104985c3875fb2c3f4e780b9a1d98014ba14a33edbd326af0cf0d5eb8e37',
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
    log = Path(tempfile.mkdtemp(prefix='ordinary-backoff-elapsed-order-a29012f-', dir=log_root))/'outer.log'
    driver = [str(python), '-B', str(repo/DRIVER), '--revision', REV,
        '--raw', str(a.raw/'qualification'), '--toolchain', str(a.toolchain),
        '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home), '--reservation-tag', TAG]
    argv = [str(a.allocator), 'run', '--cores', '4', '--sample-s', '1', '--tag', TAG, '--', *driver]
    request = dict(revision=REV, argv=argv, driver_argv=driver, env=env, cwd=str(repo),
        reservation=dict(cores=4, tag=TAG, invocation=argv[:argv.index('--')+1],
            authority='Caller-supplied allocator; root must authenticate reservation and hard AllowedCPUs. Tag alone is not proof.'),
        wall_seconds=WALL, log_bytes=CAP, invocations=1, retries=0,
        pending_owner_controls=2, pending_owner_k=[10, 1000],
        blocks=5, trials=20, trial_catalog=CATALOG,
        protocol_sha256='13cec7f96bd6aae664ba5ffd5f74130a17d2b02c929703004b5e5d3d776890b3',
        order_protocol_sha256='63821363182bdc8abc28eb77e2c633525dbde8e91891c74c85f110220c7b4bc6',
        qualification_variant='validation-order-v1',
        source_sha256=SOURCES, tools=before_tools, reproducer=digest(Path(__file__).resolve()),
        private_log=str(log), driver_raw=str(a.raw/'qualification'))
    request_pin = write(a.raw/'request.json', encoded(request))
    result = dict(status='NOT_LAUNCHED', revision=REV, request=request_pin, closed=None,
        scope='One invocation only. Segmented whole validated configuration elapsed observations; no pure observer overhead, application speedup or accuracy claim. Outer closure/exit never substitutes for driver results or reservation proof. Prior strict 2 ms/520-arm outcomes remain unchanged.')
    code = 2
    try:
        spec = importlib.util.spec_from_file_location('backoff_reproducer_owner', repo/OWNER)
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
    print('backoff-elapsed-reproducer '+result['status']+' exit='+str(code))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
