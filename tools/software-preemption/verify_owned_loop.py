#!/usr/bin/env python3
"""Build once and verify the fixed owned-loop client; no performance claim."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import traceback

EXPECTED = b'owned-loop PASS bytes=64 stops=16,32,48 taken=63 encounters=64 parked=3 joined=true data_reclaimed=true checksum=8352\n'
MIB = 1048576


def digest(path):
    owner = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode)
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(MIB), b''): result.update(block)
        assert owner(before) == owner(os.fstat(stream.fileno())) == owner(Path(path).lstat())
    return dict(sha256=result.hexdigest(), bytes=before.st_size)


def save(path, value):
    with path.open('x') as stream: json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False); stream.write('\n')


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    sys.dont_write_bytecode = True
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'): ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args(); repo = Path(__file__).resolve().parents[2]; raw = a.raw
    assert Path(__file__).resolve() == repo/'tools/software-preemption/verify_owned_loop.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home): assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert raw.is_absolute() and raw.is_relative_to(repo/'ignored') and not raw.exists()
    assert raw.parent.resolve(strict=True) == raw.parent
    raw.mkdir(mode=0o700); result = dict(schema=1, status='FAILED', revision=a.revision, functional_only=True, stage='preflight')
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]; assert len(cpus) == 4
        os.sched_setaffinity(0, cpus); assert set(os.sched_getaffinity(0)) == set(cpus)
        tools = {name: (a.toolchain/'bin'/name).resolve(strict=True) for name in ('cargo', 'rustc')}
        tools.update(python=Path(sys.executable).resolve(strict=True), git=Path('/usr/bin/git').resolve(strict=True))
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
            RUSTC=str(tools['rustc']), CARGO_TARGET_DIR=str(repo/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
            CARGO_NET_OFFLINE='true', CARGO_PROFILE_DEV_OPT_LEVEL='0', CARGO_PROFILE_DEV_DEBUG='0',
            CARGO_PROFILE_DEV_DEBUG_ASSERTIONS='true', CARGO_PROFILE_DEV_OVERFLOW_CHECKS='true',
            CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        def git(*argv): return subprocess.check_output([str(tools['git']), '-C', str(repo), *argv], env=env, timeout=15)
        def sources():
            assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
            assert git('rev-parse', 'HEAD').decode().strip() == a.revision
            assert git('status', '--porcelain', '--untracked-files=no') == b''
            names = git('ls-files', '-z', '--', 'src', 'Cargo.toml', 'Cargo.lock', 'examples/owned_loop_clock.rs',
                'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py',
                'tools/software-preemption/verify_owned_loop.py').decode().rstrip('\0').split('\0')
            assert 'examples/owned_loop_clock.rs' in names and 'tools/software-preemption/verify_owned_loop.py' in names
            return {name: digest(repo/name) for name in names}
        before = sources(); tool_hashes = {name: digest(p) for name, p in tools.items()}
        save(raw/'sources-before.json', before); save(raw/'tools.json', {n: dict(path=str(p), **tool_hashes[n]) for n, p in tools.items()})
        version = subprocess.check_output([str(tools['rustc']), '--version', '--verbose'], env=env, timeout=15).decode()
        (raw/'rustc-version.txt').write_text(version)
        rust = dict(line.split(': ', 1) for line in version.splitlines() if ': ' in line)
        assert re.fullmatch('[0-9A-Za-z.+_-]+', rust['release']) and re.fullmatch('[0-9a-f]{40}', rust['commit-hash'])
        assert rust['host'] == 'x86_64-unknown-linux-gnu'
        rows = [dict(line.split(':', 1) for line in block.splitlines() if ':' in line) for block in Path('/proc/cpuinfo').read_text().split('\n\n') if block.strip()]
        rows = [{k.strip(): v.strip() for k, v in row.items()} for row in rows]
        selected = [r for r in rows if int(r['processor']) in cpus]; assert {int(r['processor']) for r in selected} == set(cpus)
        hardware = {(r['vendor_id'], *(int(r[k]) for k in ('cpu family', 'model', 'stepping'))) for r in selected}
        assert len(hardware) == 1; vendor, family, model, stepping = hardware.pop()
        assert vendor in ('GenuineIntel', 'AuthenticAMD')
        result.update(source_files=before, tools=tool_hashes, rust={k: rust[k] for k in ('release', 'commit-hash', 'host')},
            hardware=dict(architecture='x86_64', vendor=vendor, family=family, model=model, stepping=stepping, affinity_cpus=4,
                owner_label='AMD EPYC Zen 5 dev host', owner_label_origin='owner-specified; not inferred from observed CPU fields'))
        spec = importlib.util.spec_from_file_location('owned_loop_processes', repo/'evaluation/admission/processes.py')
        processes = importlib.util.module_from_spec(spec); spec.loader.exec_module(processes)
        log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='owned-loop-', dir=log_root))
        helper = repo/'tools/unwind-oracle/bounded_command.py'
        def stage(name, argv, cpu, wall, cap):
            result['stage'] = name; directory = raw/name; directory.mkdir(); (directory/'tmp').mkdir()
            request = dict(argv=argv, cwd=str(repo), env=dict(env, TMPDIR=str(directory/'tmp')),
                stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            save(directory/'request.json', request)
            command = [str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
            save(directory/'parent-command.json', dict(argv=command, env=env, affinity=cpus, wall_seconds=wall+25))
            closed = processes.run_command(command, env, logs/(name+'.log'), wall+25, MIB)
            save(directory/'parent-closed.json', closed)
            assert closed['exit_code'] == 0 and closed['termination'] is None and closed['cleanup_complete'] and closed['reaped_descendants'] == 0
            receipt = json.loads((directory/'receipt.json').read_text())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['request_sha256'] == digest(directory/'request.json')['sha256'] and receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            for stream in ('stdout', 'stderr'): assert receipt[stream+'_sha256'] == digest(directory/(stream+'.txt'))['sha256']
            assert json.loads((logs/(name+'.log')).read_text()) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            assert sources() == before and {n: digest(p) for n, p in tools.items()} == tool_hashes
            result[name] = dict(process_exit=0, cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap, strict_cleanup=True)
            return directory
        build_args = ['build', '--locked', '--offline', '--jobs', '4', '--example', 'owned_loop_clock', '--message-format=json-render-diagnostics']
        build = stage('build', [str(tools['cargo']), *build_args], 120, 180, 128*MIB)
        messages = [json.loads(line) for line in (build/'stdout.txt').read_text().splitlines()]
        assert messages[-1] == dict(reason='build-finished', success=True)
        products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'owned_loop_clock']
        assert len(products) == 1; product = products[0]; binary = repo/'target/debug/examples/owned_loop_clock'
        assert product['executable'] == str(binary) and product['target']['kind'] == ['example'] and type(product['fresh']) is bool
        assert product['manifest_path'] == str(repo/'Cargo.toml') and product['target']['src_path'] == str(repo/'examples/owned_loop_clock.rs')
        profile = product['profile']; assert profile['opt_level'] == '0' and profile['debuginfo'] == 0 and not profile['test']
        assert profile['debug_assertions'] and profile['overflow_checks']
        result['build']['cargo_fresh'] = product['fresh']
        result['binary'] = digest(binary); native = stage('native', [str(binary)], 20, 30, MIB)
        assert (native/'stdout.txt').read_bytes() == EXPECTED and (native/'stderr.txt').read_bytes() == b''
        assert digest(binary) == result['binary']; save(raw/'sources-after.json', sources())
        result.update(status='PASS', stage='complete', bytes_transformed=64, stop_counts=[16, 32, 48], taken=63, encounters=64,
            parked_checks=3, worker_joined=True, data_reclaimed=True, checksum=8352,
            commands=[['$CARGO', *build_args], ['$REPO/target/debug/examples/owned_loop_clock']])
    except BaseException:
        (raw/'failure.txt').write_text(traceback.format_exc())
    save(raw/'result.json', result); print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
