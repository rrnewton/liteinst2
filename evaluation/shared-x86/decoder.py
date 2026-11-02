"""Existing supplied-byte decoder controls for one retained build profile."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

ARTIFACTS = ('decoder.a', 'decoder.d', 'decoder-rustc.txt', 'decoder-cargo.txt',
             'cc-version.txt', 'bridge-selected.so', 'observe')


def controls(root, out, label, cpu, env, run, durable, receipt):
    product = root / 'target/page-entry/selected'
    dest = out / label
    dest.mkdir()
    size = sum((product / name).stat().st_size for name in ARTIFACTS)
    assert size <= 128 * 1024 * 1024, 'retained build set exceeds fixed 128 MiB'
    artifacts = {}
    for name in ARTIFACTS:
        source = product / name
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        shutil.copyfile(source, dest / name)
        assert hashlib.sha256((dest / name).read_bytes()).hexdigest() == before
        artifacts[name] = dict(bytes=source.stat().st_size, sha256=before)
    receipt.setdefault('decoder_builds', {})[label] = dict(artifacts=artifacts, cases=[])
    row = receipt['decoder_builds'][label]
    fixture = root / 'tools/page-entry/selected/tests/decoder'
    archive = dest / 'decoder.a'
    common = ['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-builtin',
              '-fno-tree-loop-distribute-patterns', '-mgeneral-regs-only']
    link = [
        ('controls', [*common, str(fixture / 'control_driver.c'), str(fixture / 'support.c'),
                      str(archive), '-Wl,--gc-sections', '-o', str(dest / 'decoder-controls')]),
        ('free', [*common, '-ffreestanding', '-fno-stack-protector', '-fno-pie', '-no-pie',
                  '-ffunction-sections', '-fdata-sections', '-nostdlib',
                  str(fixture / 'freestanding/entry.S'), str(fixture / 'freestanding/harness.c'),
                  str(fixture / 'support.c'), str(archive), '-Wl,--no-undefined,--gc-sections,-e,_start',
                  '-o', str(dest / 'decoder-freestanding')]),
    ]
    for name, command in link:
        run(label + '-link-' + name,
            ['/usr/bin/taskset', '-c', str(cpu), '/usr/bin/prlimit', '--cpu=30',
             '--as=536870912', '--fsize=67108864', '--core=0', '--', *command], 60, env)
    helper = root / 'tools/unwind-oracle/bounded_command.py'
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
    reader_path = root / 'tools/page-entry/selected/tests/region_decoder/check.py'
    spec = importlib.util.spec_from_file_location('original_decoder_reader', reader_path)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    cases = [
        ('forms', [str(dest / 'decoder-controls')], 0),
        ('tiny-arena', [str(dest / 'decoder-controls'), 'tiny_arena'], 125),
        ('personality', [str(dest / 'decoder-controls'), 'personality'], 125),
        ('freestanding', [str(dest / 'decoder-freestanding')], 0),
    ]
    for index, (name, command, expected) in enumerate(cases):
        case = dest / name
        case.mkdir()
        request = dict(argv=['/usr/bin/taskset', '-c', str(cpu), '/usr/bin/prlimit',
                            '--as=268435456', '--', *command], cwd=str(root), env=env,
                       stdout=str(case / 'stdout'), stderr=str(case / 'stderr'),
                       cpu_seconds=3, wall_seconds=10, file_bytes=1048576)
        durable(case / 'request.json', request)
        # The existing helper returns1 for an intentional child125; retain both.
        run(label + '-' + name,
            [sys.executable, '-I', '-B', str(helper), '--request', str(case / 'request.json'),
             '--receipt', str(case / 'child.json')], 20, env, expected=0 if expected == 0 else 1)
        child = json.loads((case / 'child.json').read_text())
        durable(case / 'closed-child.json', child)
        assert child['request_sha256'] == hashlib.sha256((case / 'request.json').read_bytes()).hexdigest()
        assert child['helper_sha256'] == hashlib.sha256(helper.read_bytes()).hexdigest()
        assert child['exit'] == expected and child['absence_proof'] == 'ECHILD'
        assert not child['wall_timeout'] and not child['unexpected_descendants']
        assert not child['cleanup_events'] and child['cleanup_error'] is None
        assert child['aborted'] is None and child['inputs_unchanged']
        stdout, stderr = (case / 'stdout').read_bytes(), (case / 'stderr').read_bytes()
        assert len(stdout) <= 2048 and len(stderr) <= 2048
        assert hashlib.sha256(stdout).hexdigest() == child['stdout_sha256']
        assert hashlib.sha256(stderr).hexdigest() == child['stderr_sha256']
        result = reader.check(stdout, stderr, expected, index)
        negative = reader.controls(stdout, stderr, expected, index)
        assert len(negative) == (12, 4, 4, 14)[index]
        row['cases'].append(dict(name=name, expected_exit=expected, actual_exit=child['exit'],
                                 result=result, reader_controls=len(negative)))
    for name, wanted in artifacts.items():
        path = dest / name
        assert path.stat().st_size == wanted['bytes']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == wanted['sha256']
