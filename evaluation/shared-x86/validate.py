#!/usr/bin/env python3
"""Fixed shared-x86 correctness campaign; all captures remain under ignored/."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CAP = 8 * 1024 * 1024
# These are the existing cumulative slot ceilings, not a fresh reserve.
CEILINGS = (19_994_091_520, 19_061_190_371)
COMMANDS = [
    ('fmt', ['cargo', 'fmt', '--check'], 180),
    ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
    ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180),
    ('decoder-default', ['sh', 'tools/page-entry/selected/build.sh'], 150),
    ('decoder-extended', ['sh', 'tools/page-entry/selected/build.sh'], 150),
    ('workspace', ['cargo', 'test', '-j', '12', '--workspace', '--no-fail-fast'], 1800),
    ('serial-launch', ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--', '--test-threads=1', '--nocapture'], 180),
]


def durable(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(*, commands=COMMANDS, profile='shared-x86-correctness-1800-v1',
         scope='Correctness only; no throughput or page-exemption claim.',
         log_namespace='shared-x86', validate_result=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--toolchain', required=True, type=Path)
    args = parser.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    assert Path.cwd().resolve() == ROOT
    out = args.output.resolve()
    assert out.is_relative_to(ROOT / 'ignored') and not out.exists()
    toolchain = args.toolchain.resolve(strict=True)
    cpus = sorted(os.sched_getaffinity(0))
    assert len(cpus) == 12, 'reserve twelve CPUs externally before dispatch'
    env = dict(HOME=os.environ['HOME'], PATH=str(toolchain / 'bin') + ':/usr/bin:/bin',
               LANG='C', LC_ALL='C', CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='12',
               RUST_TEST_THREADS='12', CARGO_NET_OFFLINE='true',
               CARGO_TARGET_DIR=str(ROOT / 'target'), CARGO_PROFILE_DEV_DEBUG='0',
               CARGO_PROFILE_TEST_DEBUG='0', RUSTC=str(toolchain / 'bin/rustc'),
               RUSTDOC=str(toolchain / 'bin/rustdoc'))

    def git(*argv):
        return subprocess.check_output(['/usr/bin/git', '-c', 'index.threads=1',
                                        '-c', 'core.preloadIndex=false', *argv], env=env, timeout=15)

    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == args.revision
        assert not git('diff', '--binary', 'HEAD', '--')
        assert sorted(os.sched_getaffinity(0)) == cpus

    unchanged()
    helper = ROOT / 'evaluation/admission/processes.py'
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
    spec = importlib.util.spec_from_file_location('shared_x86_owner', helper)
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    out.mkdir(parents=True)
    assert re.fullmatch('[a-z0-9-]+', log_namespace)
    logs = ROOT / 'target/evaluation' / log_namespace / out.name
    logs.mkdir(parents=True, exist_ok=False)
    receipt = dict(profile=profile, revision=args.revision,
                   tree=git('rev-parse', 'HEAD^{tree}').decode().strip(), cpus=cpus,
                   hardware='AMD EPYC Zen 5 dev host', qualification='NONE',
                   scope=scope,
                   environment=env, capacity_ceilings=CEILINGS, commands=commands,
                   load_before=os.getloadavg(), results=[], status='FAILED',
                   outcomes={name: 'UNOBSERVED' for name, _, _ in commands})
    durable(out / 'planned.json', receipt)
    safe = True
    before_done = False

    def run(name, command, wall, environment, expected=0):
        nonlocal safe
        unchanged()
        row = dict(name=name, command=command, wall_seconds=wall, expected_exit=expected, load_before=os.getloadavg())
        receipt['results'].append(row)
        safe = False
        result = owner.run_command(command, environment, logs / (name + '.log'), wall, CAP)
        # Close the owner durably before reading any of its captured output.
        durable(out / (name + '-owner.json'), result)
        row['owner'] = result
        safe = result['cleanup_complete'] is True
        assert safe, 'incomplete cleanup; do not inspect the capture'
        raw = (logs / (name + '.log')).read_bytes()
        assert len(raw) <= CAP and hashlib.sha256(raw).hexdigest() == result['private_log_sha256']
        with (out / (name + '.log')).open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        row['load_after'] = os.getloadavg()
        unchanged()
        assert result['exit_code'] == expected and result['termination'] is None and result['reaped_descendants'] == 0, name + ' failed'
        return raw

    def capacity(tag):
        measured = []
        for apparent in (False, True):
            name = tag + ('-apparent' if apparent else '-allocated')
            command = ['/usr/bin/prlimit', '--cpu=30', '--as=268435456', '--fsize=65536', '--core=0', '--',
                       '/usr/bin/du', '--block-size=1', '--count-links', '--max-depth=1']
            if apparent:
                command.append('--apparent-size')
            raw = run(name, command + [str(ROOT)], 180, env)
            rows = [line.split('\t') for line in raw.decode().splitlines()]
            assert all(len(row) == 2 and row[0].isdigit() for row in rows)
            assert len({row[1] for row in rows}) == len(rows)
            values = {path: int(size) for size, path in rows}
            receipt[name] = {part: values[str(ROOT / part)] for part in ('ignored', 'target')}
            receipt[name]['total'] = values[str(ROOT)]
            measured.append(values[str(ROOT)])
        assert all(value < ceiling for value, ceiling in zip(measured, CEILINGS)), 'cumulative slot ceiling exceeded'
        return measured

    decoder_spec = importlib.util.spec_from_file_location('shared_x86_decoder_controls', Path(__file__).with_name('decoder.py'))
    decoder = importlib.util.module_from_spec(decoder_spec)
    decoder_spec.loader.exec_module(decoder)

    try:
        capacity('before')
        before_done = True
        for name, command, wall in commands:
            environment = dict(env)
            if name == 'serial-launch':
                environment['RUST_TEST_THREADS'] = '1'
            if name.startswith('decoder-'):
                command = ['/usr/bin/taskset', '-c', str(cpus[0]), '/usr/bin/prlimit',
                           '--cpu=120', '--as=2147483648', '--fsize=134217728', '--core=0', '--', *command]
            if name == 'decoder-extended':
                environment['LI2_DECODER_FEATURES'] = 'linked-epoch,mov-guard,add-guard'
            receipt['outcomes'][name] = 'DISPATCHED_UNKNOWN'
            try:
                raw = run(name, command, wall, environment)
                if validate_result is not None:
                    validate_result(name, raw)
                if name.startswith('decoder-'):
                    measured = capacity(name + '-built')
                    assert all(value + 320 * 1024 * 1024 < ceiling for value, ceiling in zip(measured, CEILINGS)), 'decoder copy/link reserve unavailable'
                    decoder.controls(ROOT, out, name, cpus[0], environment, run, durable, receipt)
                receipt['outcomes'][name] = 'PASS'
            except BaseException:
                if safe:
                    receipt['outcomes'][name] = 'FAILED'
                raise
        receipt['commands_passed'] = True
    except BaseException as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if before_done and safe:
            try:
                capacity('after')
                unchanged()
                receipt['postflight_passed'] = True
            except BaseException as error:
                receipt['postflight_error'] = type(error).__name__ + ': ' + str(error)
        if receipt.get('commands_passed') and receipt.get('postflight_passed') and 'error' not in receipt:
            receipt['status'] = 'PASS'
        receipt['cleanup_complete'] = safe
        receipt['load_after'] = os.getloadavg()
        durable(out / 'closed.json', receipt)
    return int(receipt['status'] != 'PASS')


if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode):
        raise SystemExit('use Python -I -B with assertions enabled')
    raise SystemExit(main())
