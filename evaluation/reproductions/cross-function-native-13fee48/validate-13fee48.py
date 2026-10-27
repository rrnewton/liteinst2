#!/usr/bin/env python3
"""Run one exact-revision core validation phase, retaining private raw logs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys

REVISION = '13fee48dad74409e401dce4943de7dc6dc416625'
COMMANDS = {
    'targeted': (['cargo', 'test', '-p', 'liteinst2', '--test', 'neighbor_eviction_oracle',
                 'cross_function_native::native_foreign_neighbor_two_owners_all_heads_both_seeds',
                 '--', '--exact'], 180, 4),
    'serial': (['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--',
                '--test-threads=1', '--nocapture'], 180, 4),
    'parallel-library': (['cargo', 'test', '-p', 'liteinst2', '--lib'], 360, 8),
    'parallel-prefixed': (['cargo', 'test', '-p', 'liteinst2', '--test', 'prefixed_pun_oracle'], 360, 8),
}


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'output', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--' + name, type=Path, required=True)
    ap.add_argument('--phase', choices=[*COMMANDS, 'required'], required=True)
    args = ap.parse_args()
    repo, out = args.repo, args.output
    for p in (repo, args.toolchain, args.user_home, args.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert out.is_absolute() and out.is_relative_to(repo / 'ignored')
    assert out.parent.resolve(strict=True) == out.parent and not out.exists()
    env = dict(HOME=str(args.user_home), CARGO_HOME=str(args.cargo_home),
               PATH=str(args.toolchain / 'bin') + ':/usr/bin:/bin',
               CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
               CARGO_TERM_COLOR='never', CARGO_TARGET_DIR=str(repo / 'target'),
               CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
               RUSTFLAGS='', RUSTDOCFLAGS='', RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='',
               LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1',
               TMPDIR=str(out / 'tmp'), LITEINST_EVALUATION='1')
    def git(*parts):
        return subprocess.check_output(['/usr/bin/git', '-C', str(repo), *parts], env=env, timeout=30)
    assert git('rev-parse', 'HEAD').decode().strip() == REVISION
    assert not git('diff', '--binary', 'HEAD', '--')
    modules = {}
    for name, relative in [('observe', 'evaluation/trampoline-parallel.py'),
                           ('processes', 'evaluation/admission/processes.py')]:
        p = repo / relative
        assert p.read_bytes() == git('show', REVISION + ':' + relative)
        spec = importlib.util.spec_from_file_location('_core_validation_' + name, p)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules[name] = module
    observe, processes = modules['observe'], modules['processes']
    if args.phase == 'required':
        argv = ['/usr/bin/python3.9', '-B', str(repo / 'evaluation/required-gates.py'),
                '--repo', str(repo), '--output', str(out / 'gates')]
        wall, cpu_count = 1000, 4  # Inner gates retain 180/360/180-second limits.
    else:
        argv, wall, cpu_count = COMMANDS[args.phase]
    cpus = set(range(cpu_count))
    assert cpus <= os.sched_getaffinity(0)
    os.sched_setaffinity(0, cpus)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    out.mkdir()
    (out / 'tmp').mkdir()
    def snapshot():
        return dict(source=observe.source(repo, '/usr/bin/git', env),
                    tools={n: observe.tool(args.toolchain / 'bin' / n) for n in ('cargo', 'rustc', 'rustdoc')},
                    configurations=observe.configuration(repo, args.cargo_home))
    before = snapshot()
    observe.write(out / 'inputs-before.json', before)
    hardware = dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(),
                    cpu_model=next(x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines()
                                   if x.startswith('model name')),
                    kernel_release=platform.release(), libc=platform.libc_ver())
    observe.write(out / 'hardware.json', hardware)
    log = repo / 'target/evaluation' / (out.name + '-13fee48.log')
    log.parent.mkdir(parents=True, exist_ok=True)
    assert not log.exists()
    own_source = Path(__file__).resolve().read_bytes()
    observe.write(out / 'command.json', dict(argv=argv, cwd=str(repo), env=env,
                  affinity=sorted(cpus), timeout_seconds=wall, max_log_bytes=8 * 1024 * 1024,
                  source_revision=REVISION, caller_sha256=hashlib.sha256(own_source).hexdigest(),
                  debug_info='disabled to keep the bounded slot below 20 GB; debug assertions unchanged',
                  rustc=subprocess.check_output(['rustc', '--version', '--verbose'], env=env).decode()))
    result = processes.run_command(argv, env, log, wall, 8 * 1024 * 1024)
    observe.write(out / 'process-result.json', result)
    data, _ = observe.read(log)
    assert hashlib.sha256(data).hexdigest() == result['private_log_sha256']
    with (out / 'command.log').open('xb') as f:
        f.write(data)
    after = snapshot()
    observe.write(out / 'inputs-after.json', after)
    passed = (result['exit_code'] == 0 and result['termination'] is None
              and result['cleanup_complete'] is True and result['reaped_descendants'] == 0
              and before == after and Path(__file__).resolve().read_bytes() == own_source)
    summary = dict(status='PASS' if passed else 'FAILED', revision=REVISION, phase=args.phase,
                   command=result, source_tools_configs_equal=before == after,
                   qualification_complete=False, durations='operational, not performance measurements')
    observe.write(out / 'summary.json', summary)
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
