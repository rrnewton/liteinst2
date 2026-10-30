#!/usr/bin/env python3
"""Fixed D01 adjacent capture only; no candidate or native execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import types

assert not sys.flags.optimize, 'assertions required'
path = Path(__file__).resolve().with_name('build_whole.py')
with path.open('rb') as stream:
    raw = stream.read(1048577)
assert len(raw) <= 1048576 and hashlib.sha256(raw).hexdigest() == '2731a71ee7848098be194111baf240b498dbbaf18c82252877d1a95345d1d3d2'
B = types.ModuleType('authenticated_legacy_whole_builder'); B.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), B.__dict__)
identity, configuration, write = B.identity, B.configuration, B.write
PROGRAMS, PROFILE, HELPER_SHA = B.PROGRAMS, B.PROFILE, B.HELPER_SHA
CAPTURE_PROFILE = 'offline-whole-capture-adjacent-b2-u2-l1-j2-v1'
MATERIAL_PROFILE = 'offline-whole-authored-adjacent-b2-short-t3-pending-2g-v1'
IMPORTER_PROFILE = 'elf-disassembly-null-jumps-adjacent-b2-short-t3-pending-v1'


# Private immutable descriptors; CLI inputs cannot supply another profile.
LEGACY = (CAPTURE_PROFILE, MATERIAL_PROFILE, IMPORTER_PROFILE,
          'adjacent_b2_disassembly_sites', 'build_adjacent_whole.py')
ROUTED = ('offline-whole-capture-adjacent-routed-jmp-u2-l1-j2-v1',
          'offline-whole-authored-adjacent-routed-jmp-short-t3-pending-2g-v1',
          'elf-disassembly-null-jumps-adjacent-routed-jmp-short-t3-pending-v1',
          'adjacent_routed_jmp_disassembly_sites', 'build_adjacent_routed_jmp_whole.py')


def descriptor(profile):
    assert profile is LEGACY or profile is ROUTED, 'fixed capture descriptor'
    return profile


def labels(profile=LEGACY):
    capture, material, importer, _, _ = descriptor(profile)
    return dict(capture_profile=capture, material_profile=material,
                importer_profile=importer, adjacent_upper=2, adjacent_lower=1,
                adjacent_joint=2, expected_programs=2, expected_heads=187, expected_selected=42,
                milestone='D01_FULL_ROSTER_PRODUCER_DIAGNOSTIC',
                artifact_complete=False, independent_artifact_verified=False,
                native_correctness_complete=False, classification_complete=False,
                corpus_success_claimed=False, performance_eligible=False)


def bounded(path, cap):
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    assert len(raw) <= cap, 'capture read bound'
    return raw


def check_artifact(raw, phase):
    messages = [json.loads(line) for line in raw.splitlines()]
    artifacts = [m for m in messages if m.get('reason') == 'compiler-artifact'
                 and m['target']['name'] == phase['product_name'] and m.get('executable')]
    assert len(artifacts) == 1 and artifacts[0]['profile'] == PROFILE
    assert all(type(artifacts[0]['profile'][key]) is type(value) for key, value in PROFILE.items())
    assert artifacts[0]['target']['kind'] == [phase['product_kind']]
    assert artifacts[0]['executable'] == phase['product']
    finished = [m for m in messages if m.get('reason') == 'build-finished']
    assert finished == [dict(reason='build-finished', success=True)] and finished[0]['success'] is True


def phase_plan(repo, raw, tools, source, profile=LEGACY):
    _, _, _, producer, _ = descriptor(profile)
    phases = []
    for package, kind, name in (('liteinst-rewrite', 'example', producer),
                                 ('liteinst2', 'bin', 'elf-exec-oracle')):
        phases.append(dict(name='build-' + name, dependencies=[], limits=[120, 180, 128],
            argv=[tools['cargo']['path'], 'build', '--release', '--locked', '--offline',
                  '--package', package, '--' + kind, name, '--message-format=json'],
            product=str(repo / 'target/release' / ('examples' if kind == 'example' else '') / name),
            product_kind=kind, product_name=name))
    phases.append(dict(name='target', dependencies=['build-elf-exec-oracle'],
        limits=[20, 30, 16], argv=[str(repo / 'target/release/elf-exec-oracle'), 'target']))
    for program in PROGRAMS:
        directory = raw / program
        obj, original = directory / 'subject.o', directory / 'original'
        phases.append(dict(name=program + '-as', dependencies=[], limits=[60, 90, 128],
            argv=[tools['as']['path'], '--64', str(source / (program + '.S')), '-o', str(obj)],
            outputs=[str(obj)]))
        phases.append(dict(name=program + '-ld', dependencies=[program + '-as'], limits=[60, 90, 128],
            argv=[tools['ld']['path'], '-static', '-nostdlib', '--build-id=none', '-z', 'noexecstack',
                  '-T', str(source / 'layout.ld'), str(obj), '-o', str(original)], outputs=[str(original)]))
        for symbol in ('_start', 'kernel', 'null_hook'):
            phases.append(dict(name=program + '-disassemble-' + symbol,
                dependencies=[program + '-ld'], limits=[20, 30, 16],
                argv=[tools['objdump']['path'], '-d', '-w', '--insn-width=16',
                      '--disassemble=' + symbol, str(original)]))
    return phases


def main(profile=LEGACY):
    _, _, _, _, entry_name = descriptor(profile)
    assert not sys.flags.optimize, 'assertions required'
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('raw', 'toolchain', 'cargo-home', 'user-home'):
        parser.add_argument('--' + key, type=Path, required=True)
    args = parser.parse_args()
    for directory in (args.toolchain, args.cargo_home, args.user_home):
        assert directory.is_absolute() and directory.resolve(strict=True) == directory
        assert directory.is_dir(), 'canonical existing input directory'
    repo = Path(__file__).resolve().parents[2]
    raw = args.raw.absolute()
    assert raw.is_relative_to(repo / 'ignored') and not raw.exists()
    assert raw.parent.resolve(strict=True) == raw.parent
    raw.mkdir(mode=0o700)
    env = dict(HOME=str(args.user_home), CARGO_HOME=str(args.cargo_home),
               PATH=str(args.toolchain / 'bin') + ':/usr/bin:/bin',
               RUSTC=str(args.toolchain / 'bin/rustc'),
               RUSTDOC=str(args.toolchain / 'bin/rustdoc'),
               CARGO_TARGET_DIR=str(repo / 'target'), CARGO_INCREMENTAL='0',
               CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
               CARGO_TERM_COLOR='never', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
               CARGO_PROFILE_RELEASE_DEBUG='0',
               CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
               LC_ALL='C', LANG='C', PYTHONDONTWRITEBYTECODE='1')
    git = lambda *a: subprocess.check_output(['/usr/bin/git', '-C', str(repo), *a],
                                             env=env, timeout=15)
    revision = git('rev-parse', 'HEAD').decode().strip()
    assert not git('diff', '--binary', 'HEAD', '--'), 'clean tracked source'
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    tools = {name: identity(path) for name, path in {
        'python': Path(sys.executable), 'helper': helper,
        'as': Path('/usr/bin/as'), 'ld': Path('/usr/bin/ld'),
        'objdump': Path('/usr/bin/objdump'),
        'timeout': Path('/usr/bin/timeout'),
        'cargo': args.toolchain / 'bin/cargo',
        'rustc': args.toolchain / 'bin/rustc'}.items()}
    assert tools['helper']['sha256'] == HELPER_SHA
    source = repo / 'evaluation/offline-corpus'
    inputs = {str(path): identity(path) for path in
              [source / entry_name, Path(__file__), Path(B.__file__), source / 'layout.ld',
               repo / 'Cargo.toml', repo / 'Cargo.lock',
               *(source / (p + '.S') for p in PROGRAMS)]}
    configs = configuration(repo, args.cargo_home)
    configuration_complete = all(c['state'] != 'READ_DENIED' for c in configs.values())
    # Freeze every command before executing the first one. Dependencies can
    # leave a phase UNRUN, but no phase is retried or replaced after its result.
    for program in PROGRAMS:
        (raw / program).mkdir()
    phases = phase_plan(repo, raw, tools, source, profile)
    before = dict(**labels(profile), revision=revision, hardware='AMD EPYC Zen 5 dev host', env=env,
                  tools=tools, inputs=inputs, configurations=configs, phases=phases,
                  configuration_complete=configuration_complete,
                  affinity=sorted(os.sched_getaffinity(0)),
                  load_average=Path('/proc/loadavg').read_text().split()[:3],
                  qualification_complete=False)
    write(raw / 'planned.json', before)
    results = {p['name']: dict(status='UNRUN') for p in phases}
    watched = dict(inputs)

    def stable():
        assert git('rev-parse', 'HEAD').decode().strip() == revision
        assert not git('diff', '--binary', 'HEAD', '--')
        assert all(identity(row['path']) == row for row in tools.values())
        assert all(identity(path) == row for path, row in watched.items())
        assert configuration(repo, args.cargo_home) == configs

    try:
        for phase in phases:
            name = phase['name']
            row = results[name]
            if any(results[d]['status'] != 'PASS' for d in phase['dependencies']):
                continue
            stable()
            directory = raw / name
            directory.mkdir()
            cpu, wall, mib = phase['limits']
            request = dict(argv=phase['argv'], cwd=str(repo), env=env,
                stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'),
                cpu_seconds=cpu, wall_seconds=wall, file_bytes=mib * 1048576)
            write(directory / 'request.json', request)
            row['status'] = 'FAILED'
            command = [tools['timeout']['path'], '--signal=TERM', '--kill-after=10s',
                       str(wall + 10) + 's', tools['python']['path'], '-B', str(helper), '--request',
                       str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
            write(directory / 'command.json', dict(argv=command, env=env,
                cwd=str(repo), parent_seconds=wall + 25, cleanup_seconds=10))
            child = None
            parent = dict(wait_returned=False, exit=None, error=None)
            begin = time.monotonic()
            try:
                with (directory / 'helper.stdout').open('xb') as out, (directory / 'helper.stderr').open('xb') as err:
                    child = subprocess.Popen(command, env=env, cwd=repo, stdin=subprocess.DEVNULL,
                        stdout=out, stderr=err, start_new_session=True)
                    try:
                        child.wait(timeout=wall + 25)
                        parent['wait_returned'] = True
                    except BaseException as error:
                        parent['error'] = type(error).__name__
                        if child.poll() is None:
                            try:
                                os.killpg(child.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        child.wait(timeout=10)
                        parent['wait_returned'] = True
                        raise
            finally:
                parent.update(exit=child.returncode if child else None,
                              seconds=time.monotonic() - begin)
                write(directory / 'parent-closed.json', parent)
            assert parent['wait_returned'] and parent['error'] is None
            rc = parent['exit']
            # Only inspect the files after the helper has closed and proved
            # ECHILD. An uncertain closure stops the whole material capture.
            receipt = json.loads(bounded(directory / 'receipt.json', 1048576))
            assert receipt['absence_proof'] == 'ECHILD' and receipt['cleanup_error'] is None
            assert receipt['request_sha256'] == identity(directory / 'request.json')['sha256']
            assert receipt['helper_sha256'] == HELPER_SHA and receipt['inputs_unchanged']
            for stream in ('stdout', 'stderr'):
                assert receipt[stream + '_sha256'] == identity(directory / (stream + '.txt'))['sha256']
            row.update(helper_exit=rc, receipt=receipt)
            if rc or receipt['exit'] != 0 or receipt['wall_timeout'] or receipt['aborted'] is not None or receipt['cleanup_events'] or receipt['unexpected_descendants']:
                continue
            assert bounded(directory / 'helper.stderr', 1048576) == b''
            for path in phase.get('outputs', []):
                watched[path] = identity(path)
            if 'product' in phase:
                check_artifact(bounded(directory / 'stdout.txt', mib * 1048576), phase)
                watched[phase['product']] = identity(phase['product'])
            stable()
            row['status'] = 'PASS'
    finally:
        write(raw / 'closed.json', dict(**labels(profile), revision=revision, results=results,
            files=watched, load_average=Path('/proc/loadavg').read_text().split()[:3],
            configuration_complete=configuration_complete,
            configuration_scope='READ_DENIED records an observation, never inaccessible contents or proof Cargo ignored them',
            qualification_complete=False))
    commands_complete = len(results) == len(phases) and all(r['status'] == 'PASS' for r in results.values())
    # Retain incomplete configuration as a nonzero outcome even when the raw
    # commands close successfully. This is useful capture, not a cleared gate.
    return 1 if not commands_complete else 0 if configuration_complete else 2


if __name__ == '__main__':
    raise SystemExit(main())
