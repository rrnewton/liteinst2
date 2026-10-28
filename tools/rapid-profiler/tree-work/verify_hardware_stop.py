#!/usr/bin/env python3
"""Release hardware prerequisite and optional eight-call batch state qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import traceback

if sys.flags.optimize:
    raise SystemExit('assertions required')

MIB = 1048576
PREFIX = 'oracle::native_ordinary::hardware::'
NATIVE = PREFIX+'control::owned_execution_breakpoint_restores_then_steps_then_stops'
PURE = tuple(PREFIX+'tests::'+name for name in (
    'hardware_event_requires_exact_owned_trap', 'hardware_initial_owner_and_offsets_are_closed',
    'hardware_peek_preserves_valid_minus_one', 'hardware_harness_only_removes_authenticated_rf',
    'hardware_partial_install_and_restore_keep_custody', 'hardware_readback_and_exact_restoration',
    'hardware_cleanup_does_not_touch_running_or_terminal_child',
    'hardware_targets_authenticate_closed_tree_and_literal_bytes'))


def digest(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def parse_native(stdout, stderr):
    assert stderr == b'' and 0 < len(stdout) <= MIB
    start = '\nrunning 1 test\ntest '+NATIVE+' ... '
    terminal = (r'tree-hardware-stop PASS children=1 stops=2 steps=2 rf_observed=([0-2]) '
        r'step_tf_bits=([0-3]) rf_clear_after_steps=true debug_restored=true '
        r'state_unchanged=true exit=0 reaped=1 echild=1\nok\n\n')
    end = r'test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 94 filtered out; finished in [0-9]+\.[0-9]+s\n\n'
    match = re.fullmatch(re.escape(start)+terminal+end, stdout.decode('ascii'))
    assert match is not None
    return dict(status='PASS', children=1, hardware_stops=2, single_steps=2,
        stops_exposing_rf=int(match[1]), steps_exposing_tf_bits=int(match[2]),
        rf_clear_after_each_step=True, debug_restored=True, state_unchanged=True,
        exit=0, reaped=1, echild=1)


def parse_pure(stdout, stderr):
    assert stderr == b'' and 0 < len(stdout) <= MIB
    match = re.fullmatch(r'\nrunning 8 tests\n((?:test [A-Za-z0-9_:]+ \.\.\. ok\n){8})\n'
        r'test result: ok\. 8 passed; 0 failed; 0 ignored; 0 measured; 87 filtered out; finished in [0-9]+\.[0-9]+s\n\n',
        stdout.decode('ascii'))
    assert match is not None
    names = [line.split()[1] for line in match[1].splitlines()]
    assert len(names) == len(set(names)) == 8 and set(names) == set(PURE)
    return dict(status='PASS', passed=8, failed=0, ignored=0)


def load(path):
    spec = importlib.util.spec_from_file_location('hardware_stop_processes', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch-state', action='store_true',
        help='also qualify four eight-call SDK pairs; first/last full state, middle transfers/functional only')
    parser.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args()
    repo = Path(__file__).resolve().parents[3]
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for path in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    a.raw.mkdir(parents=True)
    assert a.raw.resolve(strict=True) == a.raw
    result = dict(schema_version=1, revision=a.revision, status='FAILED', stage='setup',
        scope='Fixture hardware-stop prerequisite only. No SDK batch, application-state population or performance result.',
        command=['python3', '-B', 'tools/rapid-profiler/tree-work/verify_hardware_stop.py',
            '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN',
            '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'], stages=[])
    if a.batch_state:
        result['command'].append('--batch-state')
        result['scope'] = ('Hardware prerequisite plus four eight-call original/installed pairs. '
            'Only calls 1 and 8 receive full state/operand comparison; middle calls receive '
            'physical-transfer and functional checks. No performance or clock-accuracy result.')
        result['batch_state'] = dict(status='UNRUN')

    def save(path, value):
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
            return subprocess.check_output(argv, cwd=repo, env=env, timeout=15)

        def git(*args):
            return command([str(tools['git']), '-C', str(repo), *args])

        required = {'Cargo.toml', 'Cargo.lock', 'README.md',
            'tests/support/native_tree_hardware.rs', 'tests/support/native_tree_hardware_control.rs',
            'tests/support/native_tree_batch.rs', 'tools/rapid-profiler/native-interval/tree/batch.rs',
            'tools/rapid-profiler/tree-work/verify_hardware_stop.py',
            'tools/rapid-profiler/tree-work/test_hardware_stop.py',
            'tools/rapid-profiler/build.rs', 'tools/rapid-profiler/native-interval/calibrations.rs',
            'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py'}
        if a.batch_state:
            required.update({'tools/rapid-profiler/tree-work/check_batch.py',
                'tools/rapid-profiler/tree-work/test_batch_recipe.py',
                'tools/rapid-profiler/tree-work/tree_work.S',
                'tools/rapid-profiler/verify_ordinary_interval.py',
                'tools/rapid-profiler/native-interval/main.rs'})
        names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler',
            ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
        assert len(names) == len(set(names)) and all(names) and required.issubset(names)

        def sources():
            assert git('rev-parse', 'HEAD').decode().strip() == a.revision
            assert git('status', '--porcelain', '--untracked-files=no') == b''
            return {n: digest(repo/n) for n in names}

        source = sources()
        # Bind imported executable code to Git before evaluating it.
        process_path = 'evaluation/admission/processes.py'
        assert (repo/process_path).read_bytes() == git('show', a.revision+':'+process_path)
        processes = load(repo/process_path)
        save(a.raw/'source-inputs.json', source)
        result['source_inputs'] = dict(count=len(source), manifest=digest(a.raw/'source-inputs.json'))
        tool_hashes = {n: digest(p) for n, p in tools.items()}
        result['tools'] = tool_hashes
        save(a.raw/'private-environment.json', dict(env=env, tools={n: str(p) for n, p in tools.items()}, affinity=cpus))
        rust = command([str(tools['rustc']), '--version', '--verbose']).decode('ascii')
        rust = dict(line.split(': ', 1) for line in rust.splitlines() if ': ' in line)
        assert rust['host'] == 'x86_64-unknown-linux-gnu' and re.fullmatch('[0-9a-f]{40}', rust['commit-hash'])
        gcc = command([str(tools['gcc']), '-dumpfullversion', '-dumpversion']).decode('ascii').strip()
        assert re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', gcc)
        assert re.fullmatch('[0-9A-Za-z.+_-]+', rust['release'])
        result['versions'] = dict(rust={k: rust[k] for k in ('release', 'commit-hash', 'host')},
            gcc=gcc, python=list(sys.version_info[:3]))
        rows = [dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
            for block in Path('/proc/cpuinfo').read_text().split('\n\n') if block.strip()]
        rows = [{k.strip(): v.strip() for k, v in row.items()} for row in rows]
        selected = [r for r in rows if int(r['processor']) in cpus]
        assert {int(r['processor']) for r in selected} == set(cpus)
        hardware = {(r['vendor_id'], *(int(r[k]) for k in ('cpu family', 'model', 'stepping'))) for r in selected}
        assert len(hardware) == 1
        vendor, family, model, stepping = hardware.pop()
        assert vendor in ('AuthenticAMD', 'GenuineIntel')
        result['hardware'] = dict(owner_label='AMD EPYC Zen 5 dev host', architecture='x86_64',
            vendor=vendor, family=family, model=model, stepping=stepping, affinity_cpus=4)
        log_root = repo/'target/evaluation'
        log_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='hardware-stop-', dir=log_root))
        artifacts = {}

        def unchanged():
            assert sources() == source
            assert {n: digest(p) for n, p in tools.items()} == tool_hashes
            assert {p: digest(p) for p in artifacts} == artifacts

        def public_arg(arg):
            for path, token in ((a.raw, '$RAW'), (repo, '$REPO'), (a.toolchain, '$TOOLCHAIN')):
                if arg == str(path) or arg.startswith(str(path)+'/'):
                    return token+arg[len(str(path)):]
            for name, path in tools.items():
                if arg == str(path):
                    return '$'+name.upper()
            assert not arg.startswith('/')
            return arg

        def stage(name, argv, cpu, wall, cap):
            result['stage'] = name
            row = dict(name=name, status='FAILED', command=[public_arg(s) for s in argv],
                cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            result['stages'].append(row)
            unchanged()
            directory = a.raw/name
            directory.mkdir()
            (directory/'tmp').mkdir()
            request = dict(argv=argv, cwd=str(repo), env=dict(env, TMPDIR=str(directory/'tmp')),
                stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'),
                cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            save(directory/'request.json', request)
            helper = repo/'tools/unwind-oracle/bounded_command.py'
            argv = [str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'),
                '--receipt', str(directory/'receipt.json')]
            closed = processes.run_command(argv, env, logs/(name+'.log'), wall+25, MIB)
            save(directory/'parent-closed.json', closed)
            assert closed['exit_code'] == 0 and closed['termination'] is None
            assert closed['cleanup_complete'] and closed['reaped_descendants'] == 0
            receipt = json.loads((directory/'receipt.json').read_text())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['request_sha256'] == digest(directory/'request.json')['sha256']
            assert receipt['helper_sha256'] == source['tools/unwind-oracle/bounded_command.py']['sha256']
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

        stage('parser-controls', [str(tools['python']), '-B', str(repo/'tools/rapid-profiler/tree-work/test_hardware_stop.py')], 10, 15, MIB)
        args = ['test', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler',
            '--test', 'frontend-native-calibrations', '--no-run', '--message-format=json-render-diagnostics']
        built = stage('build', [str(tools['cargo']), *args], 120, 180, 128*MIB)
        messages = [json.loads(line) for line in (built/'stdout.txt').read_text().splitlines()]
        assert messages[-1] == dict(reason='build-finished', success=True)
        products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'frontend-native-calibrations']
        assert len(products) == 1
        product = products[0]
        binary = Path(product['executable'])
        assert binary.resolve(strict=True) == binary and binary.parent == repo/'target/release/deps'
        assert re.fullmatch('frontend_native_calibrations-[0-9a-f]+', binary.name)
        assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
        assert product['target']['src_path'] == str(repo/'tools/rapid-profiler/native-interval/calibrations.rs')
        assert product['target']['kind'] == ['test'] and product['target']['crate_types'] == ['bin']
        assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
        assert type(product['profile']['debuginfo']) is int and type(product['fresh']) is bool
        assert all(product['profile'][key] is True for key in ('test', 'debug_assertions', 'overflow_checks'))
        artifacts[binary] = digest(binary)
        result['artifact'] = dict(binary=artifacts[binary], profile=product['profile'], cargo_fresh=product['fresh'])
        pure = stage('pure-controls', [str(binary), PREFIX+'tests::', '--test-threads=1'], 10, 15, MIB)
        result['pure'] = parse_pure((pure/'stdout.txt').read_bytes(), (pure/'stderr.txt').read_bytes())
        observed = stage('hardware-native', [str(binary), NATIVE, '--exact', '--ignored', '--nocapture', '--test-threads=1'], 10, 15, MIB)
        result['native'] = parse_native((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
        unchanged()
        if a.batch_state:
            # This branch starts only after the actual same-build hardware
            # control passed. It neither retries nor substitutes a stop method.
            checker_path = 'tools/rapid-profiler/tree-work/check_batch.py'
            shared_path = 'tools/rapid-profiler/verify_ordinary_interval.py'
            for name in (checker_path, shared_path):
                assert (repo/name).read_bytes() == git('show', a.revision+':'+name)
            checker, shared = load(repo/checker_path), load(repo/shared_path)
            stage('batch-parser-controls', [str(tools['python']), '-B',
                str(repo/'tools/rapid-profiler/tree-work/test_batch_recipe.py')], 10, 15, MIB)
            pure = stage('batch-pure-controls', [str(binary), 'oracle::native_ordinary::tree_batch::tests::',
                '--test-threads=1'], 10, 15, MIB)
            result['batch_controls'] = checker.parse_controls(
                (pure/'stdout.txt').read_bytes(), (pure/'stderr.txt').read_bytes())
            trusted, candidate = a.raw/'trusted.so', a.raw/'candidate.so'
            stage('tree-build', [str(tools['gcc']), *shared.CFLAGS,
                str(repo/'tools/rapid-profiler/tree-work/tree_work.S'), '-o', str(trusted)], 20, 30, MIB)
            dso = digest(trusted)
            assert 0 < dso['bytes'] <= MIB
            candidate.write_bytes(trusted.read_bytes())
            assert candidate.read_bytes() == trusted.read_bytes() and digest(candidate) == dso
            assert (trusted.stat().st_dev, trusted.stat().st_ino) != (candidate.stat().st_dev, candidate.stat().st_ino)
            artifacts.update({trusted: dso, candidate: dso})
            args = ['build', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler',
                '--bin', 'frontend-native-oracle', '--message-format=json-render-diagnostics']
            built = stage('batch-build', [str(tools['cargo']), *args], 120, 180, 128*MIB)
            messages = [json.loads(line) for line in (built/'stdout.txt').read_text().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'frontend-native-oracle']
            assert len(products) == 1
            product = products[0]
            batch_binary = Path(product['executable'])
            assert batch_binary.resolve(strict=True) == batch_binary == repo/'target/release/frontend-native-oracle'
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler/native-interval/main.rs')
            assert product['target']['kind'] == product['target']['crate_types'] == ['bin']
            assert product['profile'] == dict(opt_level='3', debuginfo=0, test=False, debug_assertions=True, overflow_checks=True)
            assert type(product['profile']['debuginfo']) is int and type(product['fresh']) is bool
            assert product['profile']['test'] is False
            assert all(product['profile'][key] is True for key in ('debug_assertions', 'overflow_checks'))
            artifacts[batch_binary] = digest(batch_binary)
            result['batch_artifacts'] = dict(binary=artifacts[batch_binary], dso=dso,
                profile=product['profile'], cargo_fresh=product['fresh'])
            directory = a.raw/'batch-output'
            assert not directory.exists()
            result['batch_state']['status'] = 'FAILED'
            observed = stage('batch-native', [str(batch_binary), 'tree-batch-state',
                str(candidate), str(trusted), str(directory)], 90, 90, MIB)
            assert directory.resolve(strict=True) == directory and directory.is_dir()
            assert {p.name for p in directory.iterdir()} == {'tree-batch-pairs.csv'}
            table = (directory/'tree-batch-pairs.csv').read_bytes()
            result['batch_state'] = checker.parse(table,
                (observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            assert result['batch_state']['summary']['status'] == 'PASS'
            (a.raw/'tree-batch-pairs.csv').write_bytes(table)
            result['batch_state']['csv'] = 'tree-batch-pairs.csv'
            result['batch_state']['csv_digest'] = digest(a.raw/'tree-batch-pairs.csv')
            unchanged()
        result.update(status='PASS', stage='complete')
    except BaseException as error:
        result['error_type'] = type(error).__name__
        (a.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        save(a.raw/'result.json', result)
    print(('tree-batch-state' if a.batch_state else 'tree-hardware-stop')+
        ' '+result['status']+' stage='+result['stage'], flush=True)
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
