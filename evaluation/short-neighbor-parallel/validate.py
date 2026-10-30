#!/usr/bin/env python3
"""Reproduce the parallel workspace check; private logs stay under ignored/."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    assert Path.cwd() == root
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], timeout=10).decode().strip() == args.revision
    assert not subprocess.check_output(['git', 'diff', '--binary', 'HEAD', '--'], timeout=10)
    out = args.output.resolve()
    assert out.is_relative_to(root / 'ignored') and not out.exists()
    out.mkdir(parents=True)
    helper = root / 'evaluation/admission/processes.py'
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
    spec = importlib.util.spec_from_file_location('parallel_validation_owner', helper)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    commands = [
        ('fmt', ['cargo', 'fmt', '--check'], 180),
        ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
        ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180),
        ('workspace', ['cargo', 'test', '-j', '16', '--workspace', '--no-fail-fast'], 900),
        ('serial-launch', ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--', '--test-threads=1', '--nocapture'], 180),
    ]
    load = lambda: Path('/proc/loadavg').read_text().split()[:3]
    env = dict(os.environ)
    # Preserve the host's 316-thread test concurrency even with reserved CPUs.
    env['RUST_TEST_THREADS'] = '316'
    planned = dict(revision=args.revision, commands=commands,
                   affinity=sorted(os.sched_getaffinity(0)),
                   test_threads=316, load_average=load(), output_cap=8 * 1024 * 1024,
                   qualification='NONE',
                   scope='Parallel correctness command with prospectively declared wall bounds; not a performance qualification.')
    (out / 'planned.json').write_text(json.dumps(planned, indent=2) + '\n')
    log_dir = root / 'target/evaluation/short-neighbor-parallel'
    log_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for name, command, limit in commands:
        log = log_dir / (out.name + '-' + name + '.log')
        assert not log.exists()
        before = load()
        result = owner.run_command(command, env, log, limit, 8 * 1024 * 1024)
        assert result['cleanup_complete'] is True
        raw = log.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == result['private_log_sha256']
        (out / (name + '.log')).write_bytes(raw)
        results.append(dict(name=name, command=command, result=result,
                            load_before=before, load_after=load()))
        print(json.dumps(results[-1]), flush=True)
    assert not subprocess.check_output(['git', 'diff', '--binary', 'HEAD', '--'], timeout=10)
    (out / 'closed.json').write_text(json.dumps(dict(planned=planned, results=results), indent=2) + '\n')
    raise SystemExit(int(any(row['result']['exit_code'] != 0
                             or row['result']['termination'] is not None
                             or row['result']['reaped_descendants'] != 0
                             for row in results)))


if __name__ == '__main__':
    if __debug__ is not True:
        raise SystemExit('assertions required')
    main()
