#!/usr/bin/env python3
"""Build and run the fixed optional-gate state qualification, with bounded logs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

MIB = 1048576
PROCESS_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
BOUNDED_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def closed_ok(closed):
    assert closed['exit_code'] == 0 and closed['termination'] is None
    assert closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0


def validate_pairs(rows):
    assert type(rows) is list and len(rows) == 8
    fields = set(('mode seed initial_selector ret_offset comparisons original_steps candidate_steps '
                  'callback_events observer_entries subject_returns outer_returns '
                  'flip_acknowledgements helper_joins').split())
    expected = {(mode, seed, selected) for mode in (0, 1)
                for seed in (0x1234567887654320, 0xfedcba9801234567)
                for selected in (False, True)}
    seen = set()
    for row in rows:
        assert type(row) is dict and set(row) == fields
        assert type(row['initial_selector']) is bool
        for key in fields - {'initial_selector'}:
            assert type(row[key]) is int and 0 <= row[key] < 2**64
        identity = (row['mode'], row['seed'], row['initial_selector'])
        assert identity in expected and identity not in seen
        seen.add(identity)
        mode, _, selected = identity
        assert row['ret_offset'] == (27 if mode == 0 else 20)
        assert row['comparisons'] == (18 if mode == 0 else 19)
        assert row['comparisons'] <= row['original_steps'] <= 20000
        assert row['comparisons'] <= row['candidate_steps'] <= 20000
        assert row['callback_events'] == row['observer_entries'] == (2 if selected else 0)
        for key in ('subject_returns', 'outer_returns', 'flip_acknowledgements', 'helper_joins'):
            assert row[key] == 2
    assert seen == expected and sum(r['comparisons'] for r in rows) == 148


def validate_terminal(value):
    assert type(value) is dict and set(value) == {
        'schema', 'profile', 'status', 'pairs', 'malformed', 'totals', 'scope', 'pure_controls'}
    assert type(value['schema']) is int and value['schema'] == 1
    assert value['profile'] == 'precontext-v1' and value['status'] == 'PASS'
    assert value['scope'] == 'fixed-core-no-frontend-or-performance'
    assert value['pure_controls'] == [
        'gate_displacement', 'scratch_layout', 'ack_fields', 'duplicate_ack_tail', 'slow_ret_log']
    validate_pairs(value['pairs'])
    assert value['totals'] == dict(pairs=8, positive_children=16, malformed_children=2,
        comparisons=148, callback_events=8, subject_returns=16, outer_returns=16, helper_joins=16)
    assert all(type(n) is int for n in value['totals'].values())
    assert type(value['malformed']) is list and len(value['malformed']) == 2
    for tag, row in zip(('phase', 'choice'), value['malformed']):
        assert type(row) is dict and set(row) == {
            'tag', 'sigill', 'local_ud2', 'original_heads', 'callback_events', 'observer_entries',
            'subject_returns', 'outer_returns', 'cleanup', 'steps'}
        assert row['tag'] == tag and row['sigill'] is row['local_ud2'] is True
        for field in ('original_heads', 'callback_events', 'observer_entries', 'subject_returns', 'outer_returns'):
            assert type(row[field]) is int and row[field] == 0
        assert row['cleanup'] == 'SIGKILL_REAP_ECHILD'
        assert type(row['steps']) is int and 0 < row['steps'] <= 20000


def read_terminal(raw):
    assert 0 < len(raw) <= 65536 and raw.endswith(b'\n') and raw.count(b'\n') == 1
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, 'duplicate JSON key'
            result[key] = value
        return result
    def invalid_constant(_):
        raise AssertionError('non-finite JSON value')
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)
    validate_terminal(value)
    return value


def validate_native_closed(result, stdout, stderr):
    assert result['exit'] == 0 and type(result['exit']) is int
    assert result['wall_timeout'] is False and result['absence_proof'] == 'ECHILD'
    assert result['unexpected_descendants'] == result['cleanup_events'] == []
    assert result['cleanup_error'] is result['aborted'] is None and result['inputs_unchanged'] is True
    assert hashlib.sha256(stdout).hexdigest() == result['stdout_sha256']
    assert hashlib.sha256(stderr).hexdigest() == result['stderr_sha256']
    assert stderr == b'', 'native success must have no diagnostics'


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'cargo-home'):
        ap.add_argument('--' + name, required=True, type=Path)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo / 'ignored')
    assert not a.raw.exists() and a.raw.parent.resolve(strict=True) == a.raw.parent
    toolchain = a.toolchain.resolve(strict=True)
    cargo_home = a.cargo_home.resolve(strict=True)
    a.raw.mkdir(mode=0o700)
    public = a.raw / 'public'
    public.mkdir()
    os.chdir(repo)
    cpus = sorted(os.sched_getaffinity(0))[:4]
    assert len(cpus) == 4
    os.sched_setaffinity(0, cpus)
    env = dict(HOME=os.environ['HOME'], PATH=str(toolchain / 'bin') + ':/usr/bin:/bin',
        RUSTC=str(toolchain / 'bin/rustc'), CARGO_HOME=str(cargo_home),
        CARGO_TARGET_DIR=str(repo / 'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
        CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        return subprocess.check_output(['/usr/bin/git', *args], env=env, timeout=10)
    def stable():
        assert git('rev-parse', 'HEAD').decode().strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        assert set(os.sched_getaffinity(0)) == set(cpus)
    stable()
    assert Path(__file__).resolve() == repo / 'evaluation/precontext/verify.py'
    assert Path(__file__).read_bytes() == git('show', a.revision + ':evaluation/precontext/verify.py')
    runner = repo / 'evaluation/admission/processes.py'
    bounded = repo / 'tools/unwind-oracle/bounded_command.py'
    assert digest(runner) == PROCESS_SHA and digest(bounded) == BOUNDED_SHA
    spec = importlib.util.spec_from_file_location('precontext_processes', runner)
    processes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(processes)
    fields = {}
    for line in Path('/proc/cpuinfo').read_text().split('\n\n')[0].splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            if key.strip() in ('vendor_id', 'cpu family', 'model', 'stepping'):
                fields[key.strip()] = value.strip()
    receipt = dict(schema=1, status='FAILED', revision=a.revision,
        source_tree=git('rev-parse', 'HEAD^{tree}').decode().strip(),
        scope='Fixed functional state qualification. Command durations are not performance measurements.',
        hardware=dict(label='AMD EPYC Zen 5 dev host', observed_cpu=fields, affinity=cpus),
        rustc=subprocess.check_output([env['RUSTC'], '--version'], env=env, timeout=10).decode().strip(),
        kernel=os.uname().release.split('-', 1)[0],
        recipe=['python3', '-B', 'evaluation/precontext/verify.py', '--revision', a.revision,
                '--raw', '$REPO/ignored/NEW_RUN', '--toolchain', '$TOOLCHAIN', '--cargo-home', '$CARGO_HOME'],
        helpers=dict(process=PROCESS_SHA, bounded=BOUNDED_SHA), commands=[],
        runner_sha256=digest(Path(__file__)), compiler_jobs=4,
        # Cargo emits unit_mode.is_any_test(); harness=false controls --test separately.
        profile=dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True),
        limits=dict(cpu_seconds=20, wall_seconds=30, file_bytes=MIB), native='UNRUN')
    save(public / 'receipt.json', receipt)
    logs = repo / 'target/evaluation' / a.raw.name
    logs.mkdir(parents=True)
    def command(name, argv, public_argv, seconds, output_bytes):
        stable()
        closed = processes.run_command(argv, env, logs / (name + '.log'), seconds, output_bytes)
        data = (logs / (name + '.log')).read_bytes()
        assert hashlib.sha256(data).hexdigest() == closed['private_log_sha256']
        (a.raw / (name + '.log')).write_bytes(data)
        receipt['commands'].append(dict(name=name, argv=public_argv, wall_seconds=seconds, closed=closed))
        save(public / 'receipt.json', receipt)
        closed_ok(closed)
        stable()
        return data
    try:
        command('recipe-controls', [sys.executable, '-B', 'evaluation/precontext/test_verify.py'],
                ['$PYTHON', '-B', 'evaluation/precontext/test_verify.py'], 30, MIB)
        prerequisites = [
            ('core-controls', ['test', '--release', '-p', 'liteinst2', '--lib', 'precontext::'], 6),
            ('compile-fail-contracts', ['test', '--release', '-p', 'liteinst2', '--doc', 'precontext'], 2),
            ('planner-controls', ['test', '--release', '-p', 'liteinst2', '--test', 'precontext_planning'], 8),
            ('oracle-calibrations', ['test', '--release', '-p', 'rapid-profiler', '--test', 'frontend-native-calibrations'], 31),
        ]
        for name, args, count in prerequisites:
            data = command(name, [str(toolchain / 'bin/cargo'), *args], ['cargo', *args], 180, 8 * MIB)
            terminals = re.findall(rb'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', data, re.M)
            assert terminals == [(b'ok', str(count).encode(), b'0', b'0')]
            receipt['commands'][-1]['libtest'] = dict(passed=count, failed=0, ignored=0)
            save(public / 'receipt.json', receipt)
        argv = ['test', '--release', '-p', 'liteinst2', '--test', 'precontext_native',
                '--no-run', '--message-format=json']
        data = command('build', [str(toolchain / 'bin/cargo'), *argv], ['cargo', *argv], 180, 8 * MIB)
        messages = [json.loads(line) for line in data.decode().splitlines() if line.startswith('{')]
        artifacts = [m for m in messages if m.get('reason') == 'compiler-artifact'
                     and m['target']['name'] == 'precontext_native' and m['executable'] is not None]
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact['profile'] == receipt['profile']
        assert artifact['profile']['test'] is True
        assert artifact['target']['kind'] == ['test']
        assert Path(artifact['manifest_path']).resolve() == repo / 'Cargo.toml'
        assert Path(artifact['target']['src_path']).resolve() == repo / 'tests/precontext_native.rs'
        assert artifact['target']['crate_types'] == ['bin']
        assert type(artifact['fresh']) is bool
        binary = Path(artifact['executable']).resolve(strict=True)
        assert binary.is_relative_to(repo / 'target/release/deps')
        receipt['artifact'] = dict(path=str(binary.relative_to(repo)), sha256=digest(binary),
                                   fresh=artifact['fresh'])
        request = dict(argv=[str(binary)], cwd=str(repo), env=env,
            stdout=str(a.raw / 'native.stdout'), stderr=str(a.raw / 'native.stderr'), **receipt['limits'])
        save(a.raw / 'native-request.json', request)
        receipt['native'] = 'FAILED'
        save(public / 'receipt.json', receipt)
        command('native', [sys.executable, '-B', str(bounded), '--request', str(a.raw / 'native-request.json'),
                          '--receipt', str(a.raw / 'native-closed.json')],
                ['$PYTHON', '-B', 'tools/unwind-oracle/bounded_command.py', '--request', '$RAW/native-request.json',
                 '--receipt', '$RAW/native-closed.json'], 55, MIB)
        result = json.loads((a.raw / 'native-closed.json').read_text())
        receipt['native_closed'] = {
            key: result[key] for key in ('exit', 'wall_timeout', 'absence_proof', 'stdout_sha256',
                'stderr_sha256', 'elapsed_seconds', 'inputs_unchanged')}
        receipt['native_closed'].update(metadata_sha256=digest(a.raw / 'native-closed.json'),
            unexpected_descendants=len(result['unexpected_descendants']),
            cleanup_events=len(result['cleanup_events']),
            cleanup_error=result['cleanup_error'] is not None, aborted=result['aborted'] is not None)
        raw = (a.raw / 'native.stdout').read_bytes()
        validate_native_closed(result, raw, (a.raw / 'native.stderr').read_bytes())
        assert result['request_sha256'] == digest(a.raw / 'native-request.json')
        assert result['helper_sha256'] == BOUNDED_SHA
        read_terminal(raw)
        stable()
        assert digest(binary) == receipt['artifact']['sha256']
        assert digest(runner) == PROCESS_SHA and digest(bounded) == BOUNDED_SHA
        (public / 'cases.json').write_bytes(raw)
        receipt['native'] = receipt['status'] = 'PASS'
    finally:
        save(public / 'receipt.json', receipt)


if __name__ == '__main__':
    main()
