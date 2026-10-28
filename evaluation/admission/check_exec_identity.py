#!/usr/bin/env python3
"""Validate executable identity with libtest's default host parallelism.

Private bounded logs stay under ignored/. The receipt contains exact commands,
revision and operational durations; these are not performance measurements.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys

HELPER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
MIB = 1024 * 1024


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cargo-home', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--checks-only', action='store_true',
                      help='Run only the seven workspace and historical allocation checks after a merge.')
    mode.add_argument('--include-reachable-allocation', action='store_true',
                        help='Also qualify trampoline allocation under forced and default-parallel contention.')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.output.absolute()
    assert out.is_relative_to(repo / 'ignored') and out.parent.resolve() == out.parent
    assert not out.exists()
    out.mkdir(mode=0o700)
    os.chdir(repo)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    toolchain = args.toolchain.resolve(strict=True)
    cargo = toolchain / 'bin/cargo'
    env = dict(HOME=os.environ['HOME'])
    env.update(PATH=str(toolchain / 'bin') + ':/usr/bin:/bin', RUSTC=str(toolchain / 'bin/rustc'),
        RUSTDOC=str(toolchain / 'bin/rustdoc'), CARGO_HOME=str(args.cargo_home.resolve(strict=True)),
        CARGO_TARGET_DIR=str(repo / 'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
        CARGO_NET_OFFLINE='true', CARGO_TERM_COLOR='never', CARGO_PROFILE_DEV_DEBUG='0',
        CARGO_PROFILE_TEST_DEBUG='0', CARGO_PROFILE_DEV_OPT_LEVEL='0', CARGO_PROFILE_TEST_OPT_LEVEL='0',
        CARGO_PROFILE_DEV_DEBUG_ASSERTIONS='true', CARGO_PROFILE_TEST_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_DEV_OVERFLOW_CHECKS='true', CARGO_PROFILE_TEST_OVERFLOW_CHECKS='true',
        LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', LITEINST_EVALUATION='1')
    def git(*argv):
        return subprocess.check_output(['/usr/bin/git', '--no-optional-locks', *argv], timeout=10)
    revision = git('rev-parse', 'HEAD').decode().strip()
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
    unchanged()
    helper = repo / 'evaluation/admission/processes.py'
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == HELPER_SHA
    spec = importlib.util.spec_from_file_location('exec_identity_processes', helper)
    processes = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(processes)
    logs = repo / 'target/evaluation' / out.name
    logs.mkdir(parents=True)
    affinity = sorted(os.sched_getaffinity(0))
    fields = {}
    for line in Path('/proc/cpuinfo').read_text().split('\n\n')[0].splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            if key.strip() in ('vendor_id', 'cpu family', 'model', 'stepping'):
                fields[key.strip()] = value.strip()
    result = dict(schema=1, revision=revision, status='FAILED', commands=[],
        hardware=dict(owner_label='AMD EPYC Zen 5 dev host', observed_cpu=fields,
                      available_affinity_cpus=len(affinity)),
        parallelism='No affinity change or RUST_TEST_THREADS override; libtest uses its default except explicitly serial-launch.',
        compiler_jobs=4, helper_sha256=HELPER_SHA,
        runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        kernel_version=os.uname().release.split('-', 1)[0],
        rustc=subprocess.check_output([env['RUSTC'], '--version'], env=env, timeout=10).decode().strip(),
        scope='Functional validation. Seconds are command wall durations, not throughput or profiler accuracy.',
        recipe='python3 -B evaluation/admission/check_exec_identity.py --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" --output "$REPO/ignored/NEW_RUN"'
               + (' --include-reachable-allocation' if args.include_reachable_allocation else
                  ' --checks-only' if args.checks_only else ''))
    steps = [
        ('fmt', ['fmt', '--check'], 180),
        ('clippy', ['clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
        ('check', ['check', '--workspace', '--all-features', '--all-targets'], 180),
        ('library-default', ['test', '-p', 'liteinst-launch', '--lib'], 240),
        ('projection-pressure', ['test', '-p', 'liteinst-launch', '--lib', 'native_query', '--', '--nocapture'], 120),
        ('cleanup', ['test', '-p', 'liteinst-launch', '--test', 'exec_backing_cleanup'], 120),
        *[(f'b3-default-{i:02}', ['test', '-p', 'liteinst-launch', '--test', 'b3_exec_admission'], 120) for i in range(1, 26)],
        ('workspace-default', ['test', '--workspace'], 360),
        ('serial-launch', ['test', '-p', 'liteinst-launch', '--', '--test-threads=1', '--nocapture'], 180),
        ('staged-allocation', ['test', '-p', 'liteinst2', '--lib', 'staged'], 180),
        ('prefixed-pun', ['test', '-p', 'liteinst2', '--test', 'prefixed_pun_oracle'], 180),
    ]
    if args.include_reachable_allocation:
        steps[3:3] = [
            ('build-tests', ['test', '--workspace', '--no-run'], 180),
            ('reachable-contention', ['test', '-p', 'liteinst2', '--lib', 'trampoline::near_mapping::tests::', '--', '--nocapture'], 120),
            *[(f'core-default-{i:02}', ['test', '-p', 'liteinst2', '--lib'], 180) for i in range(1, 26)],
        ]
    if args.checks_only:
        required = {'fmt', 'clippy', 'check', 'workspace-default', 'serial-launch',
                    'staged-allocation', 'prefixed-pun'}
        steps = [step for step in steps if step[0] in required]
        assert len(steps) == len(required)
    result['scope'] += ' ' + ('Seven merge checks only; no repeated issue-specific campaign.'
                              if args.checks_only else 'Complete executable-identity campaign.')
    def save():
        (out / 'receipt.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    save()
    try:
        for name, argv, wall in steps:
            unchanged()
            assert sorted(os.sched_getaffinity(0)) == affinity
            path = logs / (name + '.log')
            closed = processes.run_command([str(cargo), *argv], env, path, wall, 8 * MIB)
            data = path.read_bytes()
            (out / path.name).write_bytes(data)
            terminals = [dict(result=m[1], passed=int(m[2]), failed=int(m[3]), ignored=int(m[4]))
                for m in re.finditer(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', data.decode())]
            result['commands'].append(dict(name=name, argv=['cargo', *argv], wall_limit_seconds=wall,
                closed=closed, terminal_observations=terminals))
            save()
            print(name, closed['exit_code'], flush=True)
            assert closed['exit_code'] == 0 and closed['termination'] is None
            assert closed['cleanup_complete'] and closed['reaped_descendants'] == 0
            if name == 'reachable-contention':
                expected = [
                    'reachable_mapping_gap_walk_is_complete_aligned_and_below_first',
                    'reachable_mapping_full_extent_and_address_boundaries_are_exact',
                    'reachable_mapping_occupied_exhaustion_and_errno_early_stop',
                    'reachable_mapping_native_stale_gap_retains_competitor',
                ]
                assert terminals == [dict(result='ok', passed=len(expected), failed=0, ignored=0)]
                for case in expected:
                    assert data.count(('test trampoline::near_mapping::tests::' + case + ' ... ok').encode()) == 1
            if name.startswith('core-default-'):
                for case in [
                    'observing_control_executable_drop_keeps_code_dependencies_alive',
                    'observing_control_arena_refusal_preserves_slots_bytes_and_static_support',
                    'observing_control_staged_drop_unmaps_before_releasing_last_owners',
                ]:
                    assert data.count(('test trampoline::observing_control_tests::' + case + ' ... ok').encode()) == 1
            if name == 'projection-pressure':
                measurements = re.findall(r'native_query profile=ATOMIC queries=128 baseline_queries=1 maps_rows=(\d+) owned_rows=(\d+) churn_cycles=(\d+) strict_text_refusal=true', data.decode())
                assert len(measurements) == 1
                rows, owned, cycles = map(int, measurements[0])
                assert rows > 512 and owned > 512 and cycles >= 129
                assert terminals == [dict(result='ok', passed=1, failed=0, ignored=0)]
                result['pressure'] = dict(queries=128, baseline_queries=1, maps_rows=rows, owned_rows=owned, churn_cycles=cycles)
                save()
            if name.startswith('b3-default-'):
                assert terminals == [dict(result='ok', passed=7, failed=0, ignored=0)]
            unchanged()
        result['status'] = 'PASS'
    finally:
        save()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
