#!/usr/bin/env python3
"""Build and independently disassemble both unchanged authored programs once.

Run under cpuset-alloc and an outer owned-process supervisor. This produces raw
materials only. It neither admits a ledger nor executes rewritten programs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
PROGRAMS = ('checksum', 'rle-roundtrip')
PROFILE = dict(opt_level='3', debuginfo=0, debug_assertions=True,
               overflow_checks=True, test=False)


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def identity(path):
    path = Path(path).resolve(strict=True)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_size <= 256 * 1048576
        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size,
                        s.st_mtime_ns, s.st_ctime_ns]
    assert fields(before) == fields(after) == fields(path.stat())
    assert len(data) == before.st_size
    return dict(path=str(path), sha256=hashlib.sha256(data).hexdigest(),
                bytes=len(data), stat=fields(before))


def configuration(repo, cargo_home):
    paths = {p / '.cargo' / name for p in (repo, *repo.parents)
             for name in ('config', 'config.toml')}
    paths.update(cargo_home / name for name in ('config', 'config.toml'))
    result = {}
    for path in sorted(paths):
        try:
            s = path.lstat()
            lookup = [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        except FileNotFoundError as error:
            result[str(path)] = dict(state='ABSENT', errno=error.errno)
            continue
        except PermissionError as error:
            result[str(path)] = dict(state='READ_DENIED', errno=error.errno, lookup_stat=None)
            continue
        try:
            result[str(path)] = dict(state='READ', lookup_stat=lookup, identity=identity(path))
            s = path.lstat()
            assert lookup == [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        except FileNotFoundError as error:
            result[str(path)] = dict(state='TARGET_ABSENT', errno=error.errno, lookup_stat=lookup)
        except PermissionError as error:
            result[str(path)] = dict(state='READ_DENIED', errno=error.errno, lookup_stat=lookup)
    return result


def main():
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
              [Path(__file__), source / 'layout.ld',
               repo / 'Cargo.toml', repo / 'Cargo.lock',
               *(source / (p + '.S') for p in PROGRAMS)]}
    configs = configuration(repo, args.cargo_home)
    configuration_complete = all(c['state'] != 'READ_DENIED' for c in configs.values())
    # Freeze every command before executing the first one. Dependencies can
    # leave a phase UNRUN, but no phase is retried or replaced after its result.
    phases = []
    for package, kind, name in (('liteinst-rewrite', 'example', 'disassembly_sites'),
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
        directory.mkdir()
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
    before = dict(revision=revision, hardware='AMD EPYC Zen 5 dev host', env=env,
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
            receipt = json.loads((directory / 'receipt.json').read_bytes())
            assert receipt['absence_proof'] == 'ECHILD' and receipt['cleanup_error'] is None
            assert receipt['request_sha256'] == identity(directory / 'request.json')['sha256']
            assert receipt['helper_sha256'] == HELPER_SHA and receipt['inputs_unchanged']
            for stream in ('stdout', 'stderr'):
                assert receipt[stream + '_sha256'] == identity(directory / (stream + '.txt'))['sha256']
            row.update(helper_exit=rc, receipt=receipt)
            if rc or receipt['exit'] != 0 or receipt['wall_timeout'] or receipt['aborted'] is not None or receipt['cleanup_events'] or receipt['unexpected_descendants']:
                continue
            assert not (directory / 'helper.stderr').read_bytes()
            for path in phase.get('outputs', []):
                watched[path] = identity(path)
            if 'product' in phase:
                messages = [json.loads(s) for s in (directory / 'stdout.txt').read_bytes().splitlines()]
                artifact = [m for m in messages if m.get('reason') == 'compiler-artifact'
                            and m['target']['name'] == phase['product_name'] and m.get('executable')]
                assert len(artifact) == 1 and artifact[0]['profile'] == PROFILE
                assert artifact[0]['target']['kind'] == [phase['product_kind']]
                assert artifact[0]['executable'] == phase['product']
                assert [m for m in messages if m.get('reason') == 'build-finished'] == [dict(reason='build-finished', success=True)]
                watched[phase['product']] = identity(phase['product'])
            stable()
            row['status'] = 'PASS'
    finally:
        write(raw / 'closed.json', dict(revision=revision, results=results,
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
