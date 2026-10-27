#!/usr/bin/env python3
"""Release-build and verify the fixed ordinary interval client; raw ticks only."""
import argparse
import csv
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

MIB = 1048576
LENGTHS = [1, 2, 17, 64, 3, 63, 7, 32]
SCOPE = '# raw callback-positioned RDTSCP ticks; uncalibrated, includes instrumentation/descheduling; no accuracy or nanosecond claim'
HEADER = 'ordinal,length,owner,generation,invocation,ret_offset,native_value,value,start_ticks,end_ticks,start_aux,end_aux,elapsed_ticks'
PASS = 'ordinary-interval PASS originals=8 calls=8 entries=8 returns=8 completed=6 unsampled=2 raw_rows=8 reports=4+2 short_ret_refused=true input_unchanged=true joined=true'
CFLAGS = ['-O2', '-fPIC', '-shared', '-nostdlib', '-fno-builtin', '-fno-stack-protector', '-fomit-frame-pointer',
    '-fno-tree-vectorize', '-fno-tree-slp-vectorize', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
    '-fcf-protection=none', '-Wl,-z,now', '-Wl,-z,noexecstack']


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


def output(data):
    assert data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').splitlines()
    assert len(lines) == 11 and lines[0] == SCOPE and lines[1] == HEADER and lines[-1] == PASS
    rows = list(csv.DictReader(lines[1:-1], strict=True)); assert len(rows) == 8
    for i, row in enumerate(rows):
        assert set(row) == set(HEADER.split(','))
        for key in row:
            if key not in ('owner', 'invocation'):
                assert re.fullmatch(r'0|[1-9][0-9]*', row[key]); row[key] = int(row[key]); assert row[key] < 2**64
        assert (row['ordinal'], row['length'], row['generation']) == (i+1, LENGTHS[i], 1 if i < 6 else 2)
        if i in (4, 5): assert row['owner'] == 'closed' and row['invocation'] == ''; row['invocation'] = None
        else:
            assert row['owner'] == 'sampled' and row['invocation'] == str(i if i < 4 else i-6)
            row['invocation'] = int(row['invocation'])
        expected = sum((((j*37+11) & 255) ^ 0x5a) for j in range(LENGTHS[i])) ^ 0x9e3779b97f4a7c15
        assert row['value'] == row['native_value'] == expected and 0 < row['ret_offset'] < 256
        assert row['start_aux'] == row['end_aux'] < 2**32 and row['end_ticks'] >= row['start_ticks']
        assert row['elapsed_ticks'] == row['end_ticks'] - row['start_ticks']
    return rows, '\n'.join(lines[1:-1])+'\n'


def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    sys.dont_write_bytecode = True
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'): ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args(); repo = Path(__file__).resolve().parents[2]; raw = a.raw
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/verify_ordinary_interval.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home): assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert raw.is_absolute() and raw.is_relative_to(repo/'ignored') and not raw.exists()
    assert raw.parent.resolve(strict=True) == raw.parent
    raw.mkdir(mode=0o700); result = dict(schema=1, status='FAILED', revision=a.revision, stage='preflight',
        scope='uncalibrated functional raw-TSC observations; no timing accuracy or throughput claim', native_state_qualification='separate prerequisite; not performed by this script')
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]; assert len(cpus) == 4
        os.sched_setaffinity(0, cpus); assert set(os.sched_getaffinity(0)) == set(cpus)
        tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
        tools.update(python=Path(sys.executable).resolve(strict=True), git=Path('/usr/bin/git').resolve(strict=True), gcc=Path('/usr/bin/gcc').resolve(strict=True))
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
            RUSTC=str(tools['rustc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(repo/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
            CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
            CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
            CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        def command(argv): return subprocess.check_output(argv, cwd=repo, env=env, timeout=15).decode('ascii')
        def git(*argv): return command([str(tools['git']), '-C', str(repo), *argv])
        names = ['Cargo.toml', 'Cargo.lock', 'tools/rapid-profiler/Cargo.toml', 'tools/rapid-profiler/ordinary-interval/main.rs',
            'tools/rapid-profiler/native-interval/ordinary_checksum.c', 'tools/rapid-profiler/src/generation.rs',
            'tools/rapid-profiler/src/frontend.rs', 'tools/rapid-profiler/src/frontend_native/ordinary/mod.rs',
            'tools/rapid-profiler/src/frontend_native/ordinary/cfg.rs',
            'tools/rapid-profiler/src/frontend_native/always_on.rs', 'tools/rapid-profiler/src/frontend_native/always_on/gate.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/timing.rs', 'tools/rapid-profiler/src/frontend_native/always_on/site/ordinary.rs',
            'tools/rapid-profiler/verify_ordinary_interval.py', 'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py']
        def sources():
            assert git('rev-parse', '--show-toplevel').strip() == str(repo) and git('rev-parse', 'HEAD').strip() == a.revision
            assert git('status', '--porcelain', '--untracked-files=no') == ''
            assert set(git('ls-files', '-z', '--', *names).rstrip('\0').split('\0')) == set(names)
            return {n: digest(repo/n) for n in names}
        before = sources(); tool_hashes = {n: digest(p) for n, p in tools.items()}
        save(raw/'sources-before.json', before); save(raw/'tools.json', {n: dict(path=str(p), **tool_hashes[n]) for n, p in tools.items()})
        rust_text = command([str(tools['rustc']), '--version', '--verbose']); (raw/'rustc-version.txt').write_text(rust_text)
        rust = dict(line.split(': ', 1) for line in rust_text.splitlines() if ': ' in line)
        assert re.fullmatch('[0-9A-Za-z.+_-]+', rust['release']) and re.fullmatch('[0-9a-f]{40}', rust['commit-hash'])
        assert rust['host'] == 'x86_64-unknown-linux-gnu'
        gcc = command([str(tools['gcc']), '-dumpfullversion', '-dumpversion']).strip(); assert re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', gcc)
        cargo = command([str(tools['cargo']), '--version']).strip(); assert re.fullmatch(r'cargo [0-9A-Za-z.+_-]+ \([0-9a-f]{7,40} [0-9-]+\)', cargo)
        git_version = git('--version').strip(); assert re.fullmatch(r'git version [0-9]+(?:\.[0-9]+)+', git_version)
        rows = [{k.strip(): v.strip() for k, v in (line.split(':', 1) for line in block.splitlines() if ':' in line)} for block in Path('/proc/cpuinfo').read_text().split('\n\n') if block.strip()]
        selected = [r for r in rows if int(r['processor']) in cpus]; assert {int(r['processor']) for r in selected} == set(cpus)
        hardware = {(r['vendor_id'], *(int(r[k]) for k in ('cpu family', 'model', 'stepping'))) for r in selected}
        assert len(hardware) == 1; vendor, family, model, stepping = hardware.pop(); assert vendor in ('GenuineIntel', 'AuthenticAMD')
        result.update(sources=before, tools=tool_hashes, versions=dict(rust={k: rust[k] for k in ('release', 'commit-hash', 'host')}, cargo=cargo, gcc=gcc, git=git_version, python=list(sys.version_info[:3])),
            hardware=dict(architecture='x86_64', vendor=vendor, family=family, model=model, stepping=stepping, build_affinity_cpus=4, native_affinity_cpus=1,
                owner_label='AMD EPYC Zen 5 dev host', owner_label_origin='owner-specified; not inferred from observed CPU fields'))
        spec = importlib.util.spec_from_file_location('ordinary_processes', repo/'evaluation/admission/processes.py')
        processes = importlib.util.module_from_spec(spec); spec.loader.exec_module(processes)
        log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='ordinary-interval-', dir=log_root)); helper = repo/'tools/unwind-oracle/bounded_command.py'
        def stage(name, argv, cpu, wall, cap):
            result['stage'] = name; directory = raw/name; directory.mkdir(); (directory/'tmp').mkdir()
            request = dict(argv=argv, cwd=str(repo), env=dict(env, TMPDIR=str(directory/'tmp')), stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            save(directory/'request.json', request)
            invocation = [str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
            save(directory/'parent-command.json', dict(argv=invocation, env=env, affinity=cpus, wall_seconds=wall+25))
            closed = processes.run_command(invocation, env, logs/(name+'.log'), wall+25, MIB); save(directory/'parent-closed.json', closed)
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
        source = repo/'tools/rapid-profiler/native-interval/ordinary_checksum.c'; trusted = raw/'trusted.so'; candidate = raw/'candidate.so'
        cargv = [str(tools['gcc']), *CFLAGS, str(source), '-o', str(trusted)]
        stage('c-build', cargv, 20, 30, MIB); trusted_hash = digest(trusted); assert 0 < trusted_hash['bytes'] <= MIB
        with trusted.open('rb') as inp, candidate.open('xb') as out: out.write(inp.read(MIB+1))
        assert trusted.read_bytes() == candidate.read_bytes() and digest(trusted) == digest(candidate) == trusted_hash
        assert (trusted.stat().st_dev, trusted.stat().st_ino) != (candidate.stat().st_dev, candidate.stat().st_ino)
        build_args = ['build', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', '--bin', 'ordinary-interval', '--message-format=json-render-diagnostics']
        build = stage('build', [str(tools['cargo']), *build_args], 120, 180, 128*MIB)
        messages = [json.loads(line) for line in (build/'stdout.txt').read_text().splitlines()]; assert messages[-1] == dict(reason='build-finished', success=True)
        products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'ordinary-interval']
        assert len(products) == 1; product = products[0]; binary = repo/'target/release/ordinary-interval'
        assert product['executable'] == str(binary) and product['target']['kind'] == ['bin'] and product['target']['crate_types'] == ['bin'] and type(product['fresh']) is bool
        assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml') and product['target']['src_path'] == str(repo/'tools/rapid-profiler/ordinary-interval/main.rs')
        profile = product['profile']; assert set(profile) == {'opt_level', 'debuginfo', 'test', 'debug_assertions', 'overflow_checks'}
        assert type(profile['opt_level']) is str and profile['opt_level'] == '3'
        assert type(profile['debuginfo']) is int and profile['debuginfo'] == 0 and profile['test'] is False
        assert profile['debug_assertions'] is True and profile['overflow_checks'] is True
        result['build'].update(cargo_fresh=product['fresh'], profile=profile); result['binary'] = digest(binary); result['dso'] = trusted_hash
        assert digest(trusted) == digest(candidate) == trusted_hash and trusted.read_bytes() == candidate.read_bytes()
        native = stage('native', [str(binary), str(candidate), str(trusted)], 20, 30, MIB)
        assert (native/'stderr.txt').read_bytes() == b''
        checked, table = output((native/'stdout.txt').read_bytes())
        assert digest(binary) == result['binary'] and digest(trusted) == digest(candidate) == trusted_hash
        assert trusted.read_bytes() == candidate.read_bytes(); save(raw/'sources-after.json', sources())
        (raw/'rows.csv').write_text(table)
        result.update(status='PASS', stage='complete', rows=checked, originals=8, calls=8, entries=8, returns=8, completed=6, unsampled=2, reports=[4, 2],
            required_short_ret_refusal=True, whole_guarded_input_bytes=96, worker_joined=True,
            commands=[['$GCC', *CFLAGS, '$REPO/tools/rapid-profiler/native-interval/ordinary_checksum.c', '-o', '$RAW/trusted.so'], ['$CARGO', *build_args],
                ['$REPO/target/release/ordinary-interval', '$RAW/candidate.so', '$RAW/trusted.so']])
    except BaseException:
        (raw/'failure.txt').write_text(traceback.format_exc())
    save(raw/'result.json', result); print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
