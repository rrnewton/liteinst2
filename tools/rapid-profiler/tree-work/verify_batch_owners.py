#!/usr/bin/env python3
"""Release qualification of nineteen real source-batch owners; no timing claim."""
import argparse
import csv
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import traceback

MIB = 1048576
PREFIX = 'frontend_native::always_on::tests::concurrent_native::tree_native::batch_owner_native::'
CASES = [
    ('finish_reuse_capacity', 16, 32, 6, 'AdmissionCapacityPermit', 0, False),
    ('sampled_abc', 0, 8, 1, 'None', 1, False),
    ('closed_abc', 0, 8, 1, 'None', 1, False),
]
for kind in ('original', 'installed'):
    for suffix, n, reason in [('drop_0', 0, 'Abandoned'), ('drop_1', 1, 'Abandoned'),
            ('forget_0', 0, 'Unfinished'), ('forget_1', 1, 'Unfinished'),
            ('first_error', 1, 'ControllerReentry'), ('caller_unwind', 1, 'Abandoned'),
            ('early_finish', 1, 'CallCount'), ('extra_call', 8, 'CallCount')]:
        CASES.append((kind+'_'+suffix, n if kind == 'original' else 0,
            n if kind == 'installed' else 0, 0, reason, 0, kind == 'installed'))
CASES = tuple(CASES)


def expected(case):
    name, original, installed, finishes, refusal, joins, poison = case
    return (f'tree-batch-owner PASS case={name} originals={original} installed={installed} '
        f'finishes={finishes} refusal={refusal} joins={joins} retained_poison={str(poison).lower()}')


def parse(case, stdout, stderr):
    assert case in CASES and stderr == b'' and 0 < len(stdout) <= MIB
    text = stdout.decode('ascii')
    start = '\nrunning 1 test\ntest '+PREFIX+case[0]+' ... '+expected(case)+'\nok\n\n'
    end = r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n'
    assert re.fullmatch(re.escape(start)+end, text)
    return dict(status='PASS', case=case[0], original_roots=case[1], installed_roots=case[2],
        successful_batch_finishes=case[3], expected_refusal=case[4], helper_joins=case[5], retained_poison=case[6])


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    sys.dont_write_bytecode = True
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[3]
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/tree-work/verify_batch_owners.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for path in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    a.raw.mkdir(parents=True)
    assert a.raw.resolve(strict=True) == a.raw
    result = dict(schema_version=1, revision=a.revision, status='FAILED', stage='setup',
        scope='Nineteen fresh-process public-owner controls, plus the unchanged one-call owner prerequisite. No full-register-state, performance, Busy-unwind or abandoned-original seal-runtime claim.',
        command=['python3', '-B', 'tools/rapid-profiler/tree-work/verify_batch_owners.py',
            '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN',
            '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'],
        limits=dict(native_cpu_seconds=10, native_wall_seconds=15, native_file_bytes=MIB,
            existing_controller_wait_seconds=2, build_jobs=4),
        stages=[], cases=[dict(case=c[0], status='UNRUN') for c in CASES])
    def save_private(path, value):
        with path.open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n')
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]
        assert len(cpus) == 4
        os.sched_setaffinity(0, cpus)
        assert set(os.sched_getaffinity(0)) == set(cpus)
        tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
        tools.update(python=Path(sys.executable).resolve(strict=True),
            git=Path('/usr/bin/git').resolve(strict=True), gcc=Path('/usr/bin/gcc').resolve(strict=True))
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
            PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(tools['rustc']),
            CC=str(tools['gcc']), CARGO_TARGET_DIR=str(repo/'target'), CARGO_INCREMENTAL='0',
            CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
            CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
            CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true', CARGO_TERM_COLOR='never',
            LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        def command(argv):
            return subprocess.check_output(argv, cwd=repo, env=env, timeout=15).decode('ascii')
        def git(*argv):
            return command([str(tools['git']), '-C', str(repo), *argv])
        assert git('rev-parse', 'HEAD').strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == ''
        # Authenticate the pure shared receipt helpers before importing them.
        receipt_source = 'tools/rapid-profiler/verify_ordinary_interval.py'
        assert (repo/receipt_source).read_bytes() == subprocess.check_output(
            [str(tools['git']), 'show', a.revision+':'+receipt_source], cwd=repo, timeout=15)
        shared = load('batch_owner_shared', repo/receipt_source)
        digest = shared.digest
        required = {'Cargo.toml', 'Cargo.lock', 'README.md', 'src/lib.rs', receipt_source,
            'tools/rapid-profiler/Cargo.toml', 'tools/rapid-profiler/src/lib.rs',
            'tools/rapid-profiler/build.rs', 'tools/rapid-profiler/fixtures/simple.c',
            'tools/rapid-profiler/native-interval/subject.S',
            'tools/rapid-profiler/native-interval/branch-subject.S',
            'tools/rapid-profiler/src/frontend_native/always_on/tree/native_checks.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native/tree_native/batch_owner_native.rs',
            'tools/rapid-profiler/tree-work/tree_work.S',
            'tools/rapid-profiler/tree-work/verify_batch_owners.py',
            'tools/rapid-profiler/tree-work/test_batch_owners.py',
            'tools/unwind-oracle/bounded_command.py', 'evaluation/admission/processes.py'}
        names = git('ls-files', '-z', '--', 'src', 'tools/rapid-profiler/src',
            ':(glob)**/Cargo.toml', *sorted(required)).rstrip('\0').split('\0')
        assert len(names) == len(set(names)) and all(names) and required.issubset(names)
        def sources():
            assert git('rev-parse', 'HEAD').strip() == a.revision
            assert git('status', '--porcelain', '--untracked-files=no') == ''
            return {n: digest(repo/n) for n in names}
        before = sources()
        tool_hashes = {n: digest(p) for n, p in tools.items()}
        result.update(sources=before, tools=tool_hashes)
        save_private(a.raw/'private-environment.json', dict(env=env, tools={n: str(p) for n, p in tools.items()}, affinity=cpus))
        rust = command([str(tools['rustc']), '--version', '--verbose'])
        rust = dict(line.split(': ', 1) for line in rust.splitlines() if ': ' in line)
        assert rust['host'] == 'x86_64-unknown-linux-gnu'
        assert re.fullmatch('[0-9A-Za-z.+_-]+', rust['release'])
        assert re.fullmatch('[0-9a-f]{40}', rust['commit-hash'])
        gcc = command([str(tools['gcc']), '-dumpfullversion', '-dumpversion']).strip()
        assert re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', gcc)
        result['versions'] = dict(rust={k: rust[k] for k in ('release', 'commit-hash', 'host')}, gcc=gcc, python=list(sys.version_info[:3]))
        rows = [dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
            for block in Path('/proc/cpuinfo').read_text().split('\n\n') if block.strip()]
        rows = [{k.strip(): v.strip() for k, v in row.items()} for row in rows]
        selected = [r for r in rows if int(r['processor']) in cpus]
        assert {int(r['processor']) for r in selected} == set(cpus)
        hardware = {(r['vendor_id'], *(int(r[k]) for k in ('cpu family', 'model', 'stepping'))) for r in selected}
        assert len(hardware) == 1
        vendor, family, model, stepping = hardware.pop()
        assert vendor in ('AuthenticAMD', 'GenuineIntel')
        result['hardware'] = dict(owner_label='AMD EPYC Zen 5 dev host', owner_label_origin='owner specified',
            architecture='x86_64', vendor=vendor, family=family, model=model, stepping=stepping,
            build_affinity_cpus=4, native_actual_caller_and_helper_shared_cpus=1)
        processes = load('batch_owner_processes', repo/'evaluation/admission/processes.py')
        log_root = repo/'target/evaluation'
        log_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='tree-batch-owner-', dir=log_root))
        helper = repo/'tools/unwind-oracle/bounded_command.py'
        artifacts = {}
        def unchanged():
            assert sources() == before
            assert {n: digest(p) for n, p in tools.items()} == tool_hashes
            assert {str(p): digest(p) for p in artifacts} == {str(p): h for p, h in artifacts.items()}
        def public_arg(s):
            for path, token in ((a.raw, '$RAW'), (a.toolchain, '$TOOLCHAIN'), (repo, '$REPO')):
                if s == str(path) or s.startswith(str(path)+'/'):
                    return token+s[len(str(path)):]
            if s in (str(tools['python']), str(tools['gcc']), str(tools['cargo'])):
                return next('$'+name.upper() for name, path in tools.items() if s == str(path))
            assert not s.startswith('/')
            return s
        def stage(name, argv, cpu, wall, cap, extra_env=None):
            result['stage'] = name
            row = dict(name=name, status='FAILED', command=[public_arg(s) for s in argv],
                cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            result['stages'].append(row)
            unchanged()
            directory = a.raw/name
            directory.mkdir()
            (directory/'tmp').mkdir()
            request = dict(argv=argv, cwd=str(repo), env=dict(env, **(extra_env or {}), TMPDIR=str(directory/'tmp')),
                stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'),
                cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            save_private(directory/'request.json', request)
            invocation = [str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
            closed = processes.run_command(invocation, env, logs/(name+'.log'), wall+25, MIB)
            save_private(directory/'parent-closed.json', closed)
            row['parent'] = closed
            assert closed['exit_code'] == 0 and closed['termination'] is None and closed['cleanup_complete'] and closed['reaped_descendants'] == 0
            receipt = json.loads((directory/'receipt.json').read_text())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['request_sha256'] == digest(directory/'request.json')['sha256']
            assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            for stream in ('stdout', 'stderr'):
                assert receipt[stream+'_sha256'] == digest(directory/(stream+'.txt'))['sha256']
            log = (logs/(name+'.log')).read_bytes()
            (directory/'parent.log').write_bytes(log)
            assert json.loads(log) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            unchanged()
            row.update(status='PASS', exit=0, absence_proof='ECHILD', rescues=0,
                elapsed_seconds=receipt['elapsed_seconds'], receipt_sha256=digest(directory/'receipt.json')['sha256'],
                stdout_sha256=receipt['stdout_sha256'], stderr_sha256=receipt['stderr_sha256'])
            return directory
        stage('parser-controls', [str(tools['python']), '-B', str(repo/'tools/rapid-profiler/tree-work/test_batch_owners.py')], 10, 15, MIB)
        trusted, candidate = a.raw/'trusted.so', a.raw/'candidate.so'
        stage('tree-build', [str(tools['gcc']), *shared.CFLAGS, str(repo/'tools/rapid-profiler/tree-work/tree_work.S'), '-o', str(trusted)], 20, 30, MIB)
        dso = digest(trusted)
        assert 0 < dso['bytes'] <= MIB
        candidate.write_bytes(trusted.read_bytes())
        assert candidate.read_bytes() == trusted.read_bytes()
        assert (trusted.stat().st_dev, trusted.stat().st_ino) != (candidate.stat().st_dev, candidate.stat().st_ino)
        assert digest(candidate) == dso
        artifacts.update({trusted: dso, candidate: dso})
        args = ['test', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', '--lib', '--no-run', '--message-format=json-render-diagnostics']
        built = stage('test-build', [str(tools['cargo']), *args], 120, 180, 128*MIB)
        messages = [json.loads(line) for line in (built/'stdout.txt').read_text().splitlines()]
        assert messages[-1] == dict(reason='build-finished', success=True)
        products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'rapid_profiler' and m['profile']['test']]
        assert len(products) == 1
        product = products[0]
        binary = Path(product['executable'])
        assert binary.resolve(strict=True) == binary and binary.parent == repo/'target/release/deps'
        assert re.fullmatch('rapid_profiler-[0-9a-f]+', binary.name)
        assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
        assert product['target']['src_path'] == str(repo/'tools/rapid-profiler/src/lib.rs')
        assert product['target']['kind'] == product['target']['crate_types'] == ['lib']
        assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
        assert type(product['profile']['debuginfo']) is int and type(product['fresh']) is bool
        assert all(product['profile'][key] is True for key in ('test', 'debug_assertions', 'overflow_checks'))
        artifacts[binary] = digest(binary)
        result['artifacts'] = dict(test_binary=artifacts[binary], profile=product['profile'], cargo_fresh=product['fresh'], dso=dso)
        native_env = dict(RAPID_TREE_CANDIDATE=str(candidate), RAPID_TREE_EXPECTED=str(trusted))
        def run_native(name, test):
            return stage(name, [str(binary), test, '--exact', '--ignored', '--nocapture', '--test-threads=1'], 10, 15, MIB, native_env)
        old = run_native('old-owner-prerequisite', shared.TREE_OWNER_TEST)
        result['old_owner_prerequisite'] = shared.tree_owner_output((old/'stdout.txt').read_bytes(), (old/'stderr.txt').read_bytes())
        for index, case in enumerate(CASES):
            result['cases'][index]['status'] = 'FAILED'
            directory = run_native(case[0], PREFIX+case[0])
            result['cases'][index] = parse(case, (directory/'stdout.txt').read_bytes(), (directory/'stderr.txt').read_bytes())
            unchanged()
            print(case[0]+' PASS', flush=True)
        assert len(result['cases']) == 19 and all(c['status'] == 'PASS' for c in result['cases'])
        counts = {key: sum(c[key] for c in result['cases']) for key in ('original_roots', 'installed_roots', 'successful_batch_finishes', 'helper_joins')}
        assert counts == dict(original_roots=29, installed_roots=61, successful_batch_finishes=8, helper_joins=2)
        result.update(status='PASS', stage='complete', totals=counts)
    except BaseException as error:
        result['error_type'] = type(error).__name__
        (a.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        save_private(a.raw/'result.json', result)
        with (a.raw/'cases.csv').open('x', newline='') as stream:
            fields = ['case', 'status', 'original_roots', 'installed_roots', 'successful_batch_finishes', 'expected_refusal', 'helper_joins', 'retained_poison']
            writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
            writer.writeheader()
            writer.writerows(result['cases'])
    print('tree-batch-owners '+result['status']+' stage='+result['stage'], flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
