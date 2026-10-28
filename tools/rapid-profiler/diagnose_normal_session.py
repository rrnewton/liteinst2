#!/usr/bin/env python3
"""Fresh-build deadline diagnostic: at most ten late-long K10 cases; stop at first failure."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

MIB = 1048576
PROFILE = dict(opt_level='3', debuginfo=0, test=False, debug_assertions=True, overflow_checks=True)


def digest(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False)+'\n')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/diagnose_normal_session.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for path in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 4, 'inherit exactly four CPUs'
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
    tools.update(python=Path(sys.executable).resolve(strict=True),
        **{n: Path('/usr/bin', n).resolve(strict=True) for n in ('git', 'gcc')})
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(a.toolchain/'bin/rustc'), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def command(argv):
        data = subprocess.check_output(argv, cwd=repo, env=env, timeout=15)
        assert len(data) <= 16*MIB
        return data
    def git(*args): return command([str(tools['git']), '-C', str(repo), *args])
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    required = {'tools/rapid-profiler/diagnose_normal_session.py', 'tools/rapid-profiler/verify_normal_session.py',
        'tools/rapid-profiler/verify_ordinary_interval.py', 'tools/rapid-profiler/normal-work/exact_fixture.py',
        'tools/rapid-profiler/normal-work/exact_session.py', 'tools/rapid-profiler/normal-work/check_session_two.py',
        'tools/rapid-profiler/normal-work/session_two_driver.py', 'tools/rapid-profiler/normal-work/session_driver.py',
        'tools/rapid-profiler/selected-work/provenance.py', 'tools/rapid-profiler/exact-work/exact_work.S',
        'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py'}
    names = git('ls-files', '-z', '--', 'src', 'tests', 'tools/rapid-profiler', 'Cargo.toml', 'Cargo.lock',
        'README.md', 'build.rs', '.cargo', 'rust-toolchain', 'rust-toolchain.toml', ':(glob)**/Cargo.toml',
        *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    sources = {n: digest(repo/n) for n in names}
    for n in names: assert (repo/n).read_bytes() == git('show', a.revision+':'+n)
    for name in ('cc1', 'collect2', 'as', 'ld'):
        reported = command([str(tools['gcc']), '-print-prog-name='+name]).decode('ascii').strip()
        assert reported and '\n' not in reported
        path = Path(reported) if '/' in reported else Path(shutil.which(reported, path=env['PATH']) or '')
        assert path.is_absolute(); tools[name] = path.resolve(strict=True)
    tool_hashes = {n: digest(p) for n, p in tools.items()}
    # All project imports and their source dependencies have been Git-authenticated.
    prior = load('diagnostic_json', repo/'tools/rapid-profiler/verify_normal_session.py')
    owner = load('diagnostic_owner', repo/'evaluation/admission/processes.py')
    shared = load('diagnostic_flags', repo/'tools/rapid-profiler/verify_ordinary_interval.py')
    fixture = load('diagnostic_fixture', repo/'tools/rapid-profiler/normal-work/exact_fixture.py')
    assert 'check_session_two' not in sys.modules
    sys.modules['check_session_two'] = load('check_session_two', repo/'tools/rapid-profiler/normal-work/check_session_two.py')
    work = load('diagnostic_work', repo/'tools/rapid-profiler/normal-work/exact_session.py')
    read, decode = prior.read, prior.decode
    a.raw.mkdir(mode=0o700)
    save(a.raw/'sources-before.json', sources)
    save(a.raw/'private-environment.json', dict(env=env, tools={n: str(p) for n, p in tools.items()}))
    result = dict(schema=1, revision=a.revision, status='FAILED', stage='setup', cpus=cpus,
        kind='diagnostic only; no whole-qualification, native-oracle, accuracy or performance credit',
        policy='At most10 fixed complete late-long K10 cases; stop first failure, never first pass; no retries.',
        lineage='Portable successor of diagnose-loop-v3: fresh fixture/build commands replace previous campaign artifacts.',
        sources=dict(count=len(sources), manifest=digest(a.raw/'sources-before.json')), tools=tool_hashes,
        stages=[], cases=[dict(name=f'case-{i:02}', status='UNRUN') for i in range(10)])
    artifacts = {}
    def pin(path):
        got = digest(path)
        if path in artifacts: assert artifacts[path] == got
        artifacts[path] = got
        return got
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        assert {n: digest(repo/n) for n in names} == sources
        assert {n: digest(p) for n, p in tools.items()} == tool_hashes
        assert all(digest(p) == h for p, h in artifacts.items())
        assert sorted(os.sched_getaffinity(0)) == cpus
    def public(value):
        value = str(value)
        for name, path in tools.items():
            if value == str(path): return '$'+name.upper()
        for path, token in ((a.raw, '$RAW'), (repo, '$REPO'), (a.toolchain, '$TOOLCHAIN'),
                (a.cargo_home, '$CARGO_HOME'), (a.user_home, '$USER_HOME')):
            if value == str(path) or value.startswith(str(path)+'/'): return token+value[len(str(path)):]
        assert not value.startswith('/') and '/home/' not in value and '@' not in value
        return value
    result['command'] = ['$PYTHON', '-B', '$REPO/tools/rapid-profiler/diagnose_normal_session.py',
        '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN',
        '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME']
    save(a.raw/'plan.json', dict(result, maximum_cases=10, producer_seconds=15,
        case_cpu_seconds=20, case_wall_seconds=30, case_file_bytes=4*MIB, owner_seconds=55, owner_log_bytes=MIB))
    def stage(name, argv, cpu=20, wall=30, cap=4*MIB, failure_allowed=False):
        unchanged(); result['stage'] = name
        row = dict(name=name, status='FAILED', command=[public(v) for v in argv],
            cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap, owner_wall_seconds=wall+25)
        result['stages'].append(row); save(a.raw/'result.json', result)
        d = a.raw/name; d.mkdir(); (d/'tmp').mkdir()
        request = dict(argv=list(map(str, argv)), cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')),
            stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
        save(d/'request.json', request); pin(d/'request.json')
        parent = [str(tools['python']), '-B', str(repo/'tools/unwind-oracle/bounded_command.py'),
            '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
        parent_request = dict(argv=parent, env=env, affinity=cpus, wall_seconds=wall+25, output_bytes=MIB)
        save(d/'parent-command.json', parent_request); pin(d/'parent-command.json')
        closed = owner.run_command(parent, env, logs/(name+'.log'), wall+25, MIB)
        (d/'parent.log').write_bytes((logs/(name+'.log')).read_bytes()); save(d/'parent-closed.json', closed)
        assert closed['termination'] is None and closed['cleanup_complete'] is True
        assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0
        assert type(closed['exit_code']) is int and closed['exit_code'] in ((0, 1) if failure_allowed else (0,))
        receipt = read(d/'receipt.json')
        assert type(receipt['exit']) is int and receipt['exit'] == closed['exit_code']
        assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
        assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['cleanup_error'] is receipt['aborted'] is None
        assert read(d/'request.json') == request and read(d/'parent-command.json') == parent_request
        assert receipt['request_sha256'] == digest(d/'request.json')['sha256']
        assert receipt['helper_sha256'] == sources['tools/unwind-oracle/bounded_command.py']['sha256']
        assert closed['private_log_sha256'] == digest(d/'parent.log')['sha256']
        assert read(d/'parent.log') == dict(exit=receipt['exit'], wall_timeout=False, absence_proof='ECHILD',
            descendants=0, success=receipt['exit'] == 0)
        for stream in ('stdout', 'stderr'): assert receipt[stream+'_sha256'] == digest(d/(stream+'.txt'))['sha256']
        row.update({key: pin(d/file) for key, file in (('request', 'request.json'), ('receipt', 'receipt.json'),
            ('parent_command', 'parent-command.json'), ('closed', 'parent-closed.json'), ('parent', 'parent.log'),
            ('stdout', 'stdout.txt'), ('stderr', 'stderr.txt'))}, process_exit=receipt['exit'])
        unchanged(); return d, row
    try:
        log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
        assert log_root.resolve(strict=True) == log_root
        logs = Path(tempfile.mkdtemp(prefix='normal-loop-diagnostic-', dir=log_root))
        trusted, candidate, selection = (a.raw/n for n in ('exact-final.so', 'exact-candidate.so', 'exact-selection.json'))
        d, row = stage('fixture-build', [tools['gcc'], *shared.CFLAGS,
            repo/'tools/rapid-profiler/exact-work/exact_work.S', '-o', trusted], cap=MIB)
        assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
        final_hash = pin(trusted); assert 0 < final_hash['bytes'] <= MIB
        details = fixture.describe(trusted.read_bytes()); assert details['final'] == final_hash and details['length'] == 37
        save(selection, dict(details, revision=a.revision)); manifest = pin(selection)
        unchanged()  # Complete independent authority exists BEFORE separate candidate creation.
        with candidate.open('xb') as stream: stream.write(trusted.read_bytes())
        assert pin(candidate) == final_hash
        assert fixture.authenticate(candidate, trusted, details['elf_va'], 37, selection, manifest['sha256']) == details
        result['selection'] = dict(**details, candidate=digest(candidate), manifest=manifest)
        row['status'] = 'PASS'
        d, row = stage('release-build', [tools['cargo'], 'build', '--locked', '--offline', '--release', '--jobs', '4',
            '-p', 'rapid-profiler', '--bin', 'ordinary-interval', '--message-format=json-render-diagnostics'], 120, 180, 128*MIB)
        messages = [decode(line) for line in (d/'stdout.txt').read_bytes().splitlines()]
        assert messages[-1] == dict(reason='build-finished', success=True)
        products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'ordinary-interval']
        assert len(products) == 1; product = products[0]; binary = repo/'target/release/ordinary-interval'
        assert product['executable'] == str(binary) and binary.resolve(strict=True) == binary
        assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
        assert product['target']['src_path'] == str(repo/'tools/rapid-profiler/ordinary-interval/main.rs')
        assert product['target']['kind'] == product['target']['crate_types'] == ['bin']
        assert product['profile'] == PROFILE and type(product['fresh']) is bool
        assert type(product['profile']['debuginfo']) is int and product['profile']['test'] is False
        assert product['profile']['debug_assertions'] is product['profile']['overflow_checks'] is True
        result['binary'] = dict(content=pin(binary), profile=PROFILE, cargo_fresh=product['fresh']); row['status'] = 'PASS'
        planned = work.commands('late-long', 10); assert len(planned) == 49
        intended = (json.dumps([list(c[:3])+[c[3].hex()] if c[0] == 'CALL' else list(c)
            for c in planned], separators=(',', ':'))+'\n').encode('ascii')
        assert 0 < len(intended) <= 16384
        (a.raw/'intended.json').write_bytes(intended); pin(a.raw/'intended.json')
        for case in result['cases']:
            case['status'] = 'FAILED'; name = case['name']; output = a.raw/name/'producer'
            d, row = stage(name, [tools['python'], '-B', repo/'tools/rapid-profiler/normal-work/session_two_driver.py',
                '--binary', binary, '--candidate', candidate, '--trusted', trusted, '--elf-va', str(details['elf_va']),
                '--length', '37', '--output', output, '--k', '10', '--mode', 'exact', '--schedule', 'late-long',
                '--selection', selection, '--selection-sha256', manifest['sha256']], failure_allowed=True)
            summary = read(output/'result.json'); assert read(d/'stdout.txt') == summary
            assert summary['status'] in ('PASS', 'FAILED') and summary['mode'] == 'exact' and summary['k'] == 10
            assert summary['rescue'] is False and type(summary['child_exit']) is int
            assert (output/'intended.json').read_bytes() == intended
            case.update(status=summary['status'], child_exit=summary['child_exit'], rescue=False,
                result=pin(output/'result.json'), transcript=pin(output/'stdout.txt'), diagnostic=pin(output/'stderr.txt'),
                intended=pin(output/'intended.json'))
            if summary['status'] == 'FAILED':
                assert row['process_exit'] == 1
                result['status'] = 'FAILURE_REPRODUCED'; unchanged(); break
            assert row['process_exit'] == summary['child_exit'] == 0
            assert (d/'stderr.txt').read_bytes() == (output/'stderr.txt').read_bytes() == b''
            assert summary['schedule'] == 'late-long' and summary['normal_reaps'] == 1 and summary['rescues'] == 0 and summary['absence'] == 'ECHILD'
            assert tuple(summary[k] for k in ('calls', 'accepted', 'flushes', 'arms', 'actions', 'detaches', 'joins')) == (48, 49, 1, 520, 521, 2, 2)
            assert summary['cancelled'] == summary['unfinished'] == 0 and summary['stop_reason'] == 'EpochLimit'
            assert [w['calls'] for w in summary['workers']] == [24, 24]
            assert case['transcript'] == dict(bytes=summary['transcript_bytes'], sha256=summary['transcript_sha256'])
            assert case['intended'] == dict(bytes=summary['intended_bytes'], sha256=summary['intended_sha256'])
            case['work'] = pin(output/'work.csv')
            assert case['work'] == dict(bytes=summary['work_bytes'], sha256=summary['work_sha256'])
            case['counts'] = {k: summary[k] for k in ('calls', 'arms', 'actions', 'detaches', 'joins')}
            row['status'] = 'PASS'; unchanged(); save(a.raw/'result.json', result)
        else:
            result['status'] = 'NO_FAILURE_REPRODUCED'
        unchanged(); result['stage'] = 'complete'
        save(a.raw/'sources-after.json', {n: digest(repo/n) for n in names})
        result['sources']['after'] = pin(a.raw/'sources-after.json')
        save(a.raw/'result.json', result); print(json.dumps(result, indent=2)); return 0
    except BaseException as error:
        result.update(status='FAILED', error_type=type(error).__name__)
        try:
            unchanged()
            save(a.raw/'sources-after.json', {n: digest(repo/n) for n in names})
            result['sources']['after'] = pin(a.raw/'sources-after.json')
        except BaseException as postflight:
            result['postflight_error_type'] = type(postflight).__name__
        save(a.raw/'result.json', result)
        raise


if __name__ == '__main__':
    raise SystemExit(main())
