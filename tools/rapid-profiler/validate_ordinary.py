#!/usr/bin/env python3
"""Seven fixed final gates; bounded private logs and a small sanitized receipt."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys
import traceback

MIB = 1048576
HELPER = 'evaluation/admission/processes.py'
HELPER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
COMMANDS = [
    ('fmt', ['fmt', '--check'], 180),
    ('clippy', ['clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
    ('check', ['check', '--workspace', '--all-features', '--all-targets'], 180),
    ('workspace', ['test', '--workspace'], 360),
    ('serial-launch', ['test', '-p', 'liteinst-launch', '--', '--test-threads=1', '--nocapture'], 180),
    ('staged-allocation', ['test', '-p', 'liteinst2', '--lib', 'staged'], 180),
    ('prefixed-pun', ['test', '-p', 'liteinst2', '--test', 'prefixed_pun_oracle'], 180),
]
REGRESSIONS = {
    'staged-allocation': ['trampoline::tests::dropping_staged_image_releases_its_exact_mapping',
        'trampoline::observing_control_tests::observing_control_staged_drop_unmaps_before_releasing_last_owners'],
    'prefixed-pun': ['native_state_covers_every_prefixed_pun_and_original_successor'],
}
SUMMARY = re.compile(rb'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                     rb'(\d+) measured; (\d+) filtered out; finished in (\d+(?:\.\d+)?)s')


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def pin(path):
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        before = os.fstat(f.fileno()); assert stat.S_ISREG(before.st_mode)
        digest = hashlib.sha256(); blob = hashlib.sha1(b'blob '+str(before.st_size).encode()+b'\0')
        for block in iter(lambda: f.read(MIB), b''): digest.update(block); blob.update(block)
        assert fields(before) == fields(os.fstat(f.fileno())) == fields(Path(path).lstat())
    return dict(sha256=digest.hexdigest(), bytes=before.st_size, git_blob=blob.hexdigest(), owner=fields(before))


def public_pin(value):
    return {k: value[k] for k in ('sha256', 'bytes')}


def terminals(data):
    # Literal observations only. Nested terminals are never summed as outer tests.
    return [dict(byte_offset=m.start(), result=m[1].decode(),
                 **dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'),
                            (int(m[i]) for i in range(2, 7)))), seconds=m[7].decode())
            for m in SUMMARY.finditer(data)]


def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    sys.dont_write_bytecode = True
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'output', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    ap.add_argument('--revision', required=True); ap.add_argument('--cpus', required=True)
    a = ap.parse_args(); repo, out = a.repo, a.output
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert out.is_absolute() and out.is_relative_to(repo/'ignored') and out != repo/'ignored'
    assert out.parent.resolve(strict=True) == out.parent and not out.exists() and not out.is_symlink()
    cpus = [int(x) for x in a.cpus.split(',')]
    assert len(cpus) == len(set(cpus)) == 4 and min(cpus) >= 0 and set(cpus) <= os.sched_getaffinity(0)
    os.sched_setaffinity(0, cpus); assert os.sched_getaffinity(0) == set(cpus)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    out.mkdir(mode=0o700); (out/'tmp').mkdir()
    records = [dict(name=n, argv=['$TOOLCHAIN/bin/cargo', *args], wall_seconds=w,
                    max_log_bytes=8*MIB, status='UNRUN') for n, args, w in COMMANDS]
    result = dict(schema=1, status='FAILED', revision=a.revision, stages=records,
        scope='Exact-revision final validation commands; operational durations, not performance.',
        counting='Literal terminal observations, not additive outer or unique-test totals; nested rows are not extra credit.',
        aggregate_test_count=None, native_qualification=False, cpus=sorted(cpus), jobs=4,
        source_before_after_equal=None, tools_before_after_equal=None,
        cleanup_seconds_per_command=3, total_gate_wall_seconds=sum(w for _, _, w in COMMANDS))
    current = None
    def save(): (out/'receipt.json').write_bytes(encoded(result))
    save()
    try:
        bin_dir = a.toolchain/'bin'
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(bin_dir)+':/usr/bin:/bin',
            RUSTC=str(bin_dir/'rustc'), RUSTDOC=str(bin_dir/'rustdoc'), CARGO_TARGET_DIR=str(repo/'target'),
            CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', RUST_TEST_THREADS='4',
            CARGO_TERM_COLOR='never', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
            CARGO_PROFILE_DEV_OPT_LEVEL='0', CARGO_PROFILE_TEST_OPT_LEVEL='0',
            CARGO_PROFILE_DEV_DEBUG_ASSERTIONS='true', CARGO_PROFILE_TEST_DEBUG_ASSERTIONS='true',
            CARGO_PROFILE_DEV_OVERFLOW_CHECKS='true', CARGO_PROFILE_TEST_OVERFLOW_CHECKS='true',
            RUSTFLAGS='', RUSTDOCFLAGS='', RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='',
            LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1',
            TMPDIR=str(out/'tmp'), LITEINST_EVALUATION='1')
        result['environment'] = dict(env, HOME='$USER_HOME', CARGO_HOME='$CARGO_HOME',
            PATH='$TOOLCHAIN/bin:/usr/bin:/bin', RUSTC='$TOOLCHAIN/bin/rustc', RUSTDOC='$TOOLCHAIN/bin/rustdoc',
            CARGO_TARGET_DIR='$REPO/target', TMPDIR='$RAW/tmp')
        selected = {n: bin_dir/n for n in ('cargo', 'rustc', 'rustdoc', 'cargo-fmt', 'rustfmt', 'cargo-clippy', 'clippy-driver')}
        selected.update(git=Path('/usr/bin/git'), python=Path(sys.executable))
        def tools():
            return {n: dict(lookup=tuple(p.lstat()[k] for k in (0, 1, 2, 6, 8, 9)),
                            resolved=str(p.resolve(strict=True)), pin=pin(p.resolve(strict=True))) for n, p in selected.items()}
        helper = repo/HELPER; assert pin(helper)['sha256'] == HELPER_SHA
        spec = importlib.util.spec_from_file_location('_ordinary_gate_processes', helper)
        processes = importlib.util.module_from_spec(spec); spec.loader.exec_module(processes)
        assert processes.ROOT == repo and processes.CLEANUP_SECONDS == 3.0
        log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
        assert log_root.resolve(strict=True) == log_root
        logs = log_root/('ordinary-gates-'+out.name); logs.mkdir()
        serial = 0
        def run(argv, wall, cap):
            nonlocal serial
            serial += 1; log = logs/('%03d.log' % serial)
            closed = processes.run_command(argv, env, log, wall, cap)
            data = log.read_bytes(); assert len(data) <= cap
            assert hashlib.sha256(data).hexdigest() == closed['private_log_sha256']
            (out/('%03d-command.json' % serial)).write_bytes(encoded(dict(argv=argv, env=env, cwd=str(repo),
                cpus=sorted(cpus), wall_seconds=wall, max_log_bytes=cap, closed=closed)))
            return data, closed
        def clean(closed):
            return closed['exit_code'] == 0 and closed['termination'] is None and closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0
        def query(argv, cap=MIB):
            data, closed = run(argv, 30, cap); assert clean(closed); return data
        def git(*args):
            return query(['/usr/bin/git', '--no-optional-locks', '--no-replace-objects', '-c', 'core.fsmonitor=false',
                          '-C', str(repo), *args], 4*MIB)
        def head():
            assert git('rev-parse', 'HEAD').decode().strip() == a.revision
            assert git('status', '--porcelain', '--untracked-files=no') == b''
        def source():
            head(); assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
            rows = {}
            for line in git('ls-tree', '-rz', '--full-tree', a.revision).split(b'\0'):
                if not line: continue
                meta, name = line.split(b'\t'); mode, kind, oid = meta.decode().split(); name = name.decode()
                path = repo/name; assert not Path(name).is_absolute() and '..' not in Path(name).parts
                assert kind == 'blob' and mode in ('100644', '100755') and path.parent.resolve(strict=True) == path.parent
                value = pin(path); assert value['git_blob'] == oid and bool(value['owner'][2] & 0o111) == (mode == '100755')
                rows[name] = value
            assert HELPER in rows and 'Cargo.lock' in rows and rows[HELPER]['sha256'] == HELPER_SHA
            return rows
        own = pin(Path(__file__).resolve(strict=True)); before_tools = tools(); before = source()
        result['source_files'] = len(before)
        result['source_inventory_sha256'] = hashlib.sha256(encoded({n: public_pin(v) for n, v in before.items()})).hexdigest()
        result['runner'] = public_pin(own); result['tools'] = {n: public_pin(v['pin']) for n, v in before_tools.items()}
        rust_text = query([str(selected['rustc']), '--version', '--verbose'], 65536).decode('ascii')
        rust = dict(s.split(': ', 1) for s in rust_text.splitlines() if ': ' in s)
        assert rust['release'] == '1.97.1' and rust['host'] == 'x86_64-unknown-linux-gnu' and re.fullmatch('[0-9a-f]{40}', rust['commit-hash'])
        cargo = query([str(selected['cargo']), '--version'], 65536).decode('ascii').strip()
        assert re.fullmatch(r'cargo 1\.97\.1 \([0-9a-f]{7,40} [0-9-]+\)', cargo)
        result['versions'] = dict(rust={k: rust[k] for k in ('release', 'commit-hash', 'host')}, cargo=cargo, python=list(sys.version_info[:3]))
        with Path('/proc/cpuinfo').open('rb') as stream: cpuinfo = stream.read(4*MIB+1)
        assert len(cpuinfo) <= 4*MIB
        cpu_rows = [{k.strip(): v.strip() for k, v in (line.split(':', 1) for line in block.splitlines() if ':' in line)}
                    for block in cpuinfo.decode('ascii').split('\n\n') if block.strip()]
        selected_cpus = [row for row in cpu_rows if int(row['processor']) in cpus]
        assert len(selected_cpus) == 4 and {int(row['processor']) for row in selected_cpus} == set(cpus)
        hardware = {(row['vendor_id'], *(int(row[k]) for k in ('cpu family', 'model', 'stepping'))) for row in selected_cpus}
        assert len(hardware) == 1; vendor, family, model, stepping = hardware.pop(); assert vendor in ('GenuineIntel', 'AuthenticAMD')
        result['hardware'] = dict(architecture=rust['host'].split('-')[0], vendor=vendor, family=family, model=model, stepping=stepping,
            build_affinity_cpus=4, owner_label='AMD EPYC Zen 5 dev host', owner_label_origin='owner-specified; not inferred from observed CPU fields')
        for current, (_, args, wall) in zip(records, COMMANDS):
            head(); assert tools() == before_tools and pin(Path(__file__).resolve(strict=True)) == own
            assert os.sched_getaffinity(0) == set(cpus)
            current['status'] = 'RUNNING'; save()
            data, closed = run([str(selected['cargo']), *args], wall, 8*MIB)
            current.update(closed=closed, terminal_observations=terminals(data))
            assert clean(closed)
            if args[0] == 'test': assert current['terminal_observations'], 'missing test summaries'
            for name in REGRESSIONS.get(current['name'], []):
                assert data.decode().splitlines().count('test '+name+' ... ok') == 1, 'missing exact allocation-regression terminal'
            current['allocation_regressions_passed'] = REGRESSIONS.get(current['name'], [])
            head(); assert tools() == before_tools and pin(Path(__file__).resolve(strict=True)) == own
            current['status'] = 'PASS'; save()
        result['status'] = 'PASS'
    except BaseException as error:
        if current is not None and current['status'] == 'RUNNING': current['status'] = 'FAILED'
        result['failure_kind'] = type(error).__name__
        (out/'failure.txt').write_text(traceback.format_exc())
    if 'before' in locals():
        try:
            result['source_before_after_equal'] = source() == before
            result['tools_before_after_equal'] = tools() == before_tools
            assert result['source_before_after_equal'] and result['tools_before_after_equal'] and pin(Path(__file__).resolve(strict=True)) == own
        except BaseException as error: result.update(status='FAILED', postcheck_failure_kind=type(error).__name__)
    save(); print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
