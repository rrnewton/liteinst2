#!/usr/bin/env python3
"""Seven fixed default-parallel test invocations; all records remain under ignored/."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time

SCRIPT = 'evaluation/trampoline-parallel.py'
CHILD = 'LITEINST2_STAGED_DROP_CHILD'
WALL_SECONDS = 360
NAMES = ['library-1', 'library-2', 'library-3',
         'prefixed-pun-1', 'prefixed-pun-2', 'prefixed-pun-3', 'workspace']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def fields(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode)
        data = stream.read()
        after = os.fstat(stream.fileno())
    assert fields(before) == fields(after) == fields(path.stat())
    assert len(data) == before.st_size
    return data, fields(before)


def tool(path):
    path = Path(path).absolute()
    before = fields(path.lstat())
    resolved = path.resolve(strict=True)
    data, owner = read(resolved)
    assert before == fields(path.lstat()) and path.resolve(strict=True) == resolved
    return dict(path=str(path), resolved=str(resolved), lookup_stat=before,
                stat=owner, bytes=len(data), sha256=digest(data))


def source(repo, git, env):
    def query(*args):
        return subprocess.check_output([git, '-C', str(repo), *args], env=env, timeout=30)
    revision = query('rev-parse', 'HEAD').decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', revision)
    assert not query('diff', '--binary', 'HEAD', '--'), 'tracked worktree must be clean'
    files = {}
    for row in query('ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        name = name.decode()
        assert kind == 'blob' and mode in ('100644', '100755')
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        path = repo / relative
        assert path.parent.resolve(strict=True) == path.parent
        data, owner = read(path)
        actual_oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        assert actual_oid == oid and bool(owner[2] & 0o111) == (mode == '100755'), name
        files[name] = dict(sha256=digest(data), bytes=len(data), mode=mode, stat=owner)
    assert SCRIPT in files and 'Cargo.lock' in files
    assert Path(__file__).resolve(strict=True) == repo / SCRIPT
    return dict(revision=revision, files=files)


def configuration(repo, cargo_home):
    paths = {directory / '.cargo' / name for directory in [repo, *repo.parents]
             for name in ('config', 'config.toml')}
    paths.update(cargo_home / name for name in ('config', 'config.toml'))
    observed = {}
    for path in sorted(paths):
        try:
            lookup = fields(path.lstat())
        except FileNotFoundError:
            observed[str(path)] = dict(state='ABSENT', errno=2)
            continue
        except PermissionError as error:
            observed[str(path)] = dict(state='READ_DENIED', errno=error.errno, lookup_stat=None)
            continue
        try:
            observed[str(path)] = dict(state='READ', identity=tool(path))
        except FileNotFoundError:
            observed[str(path)] = dict(state='TARGET_ABSENT', errno=2, lookup_stat=lookup)
        except PermissionError as error:
            observed[str(path)] = dict(state='READ_DENIED', errno=error.errno, lookup_stat=lookup)
    return observed


def summaries(data):
    # Nested terminals can interleave. Keep literal observations, not invented
    # outer-group totals or counts inferred from "running N tests" child starts.
    pattern = re.compile(rb'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; '
                         rb'(\d+) ignored; (\d+) measured; (\d+) filtered out;')
    return [dict(byte_offset=m.start(), text=m.group().decode('ascii'),
                 status=m[1].decode('ascii'), passed=int(m[2]), failed=int(m[3]),
                 ignored=int(m[4]), measured=int(m[5]), filtered_out=int(m[6]),
                 attribution='unclassified terminal observation; not additive')
            for m in pattern.finditer(data)]


def execute(repo, output, env, row):
    row['status'] = 'RUNNING'
    row['start_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    start = time.monotonic()
    process = None
    timed_out = False
    errors = []
    log = output / (row['name'] + '.log')
    try:
        with log.open('xb') as stream:
            process = subprocess.Popen(row['argv'], cwd=repo, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            row['pid'] = process.pid
            row['session_and_process_group'] = process.pid
            try:
                process.wait(timeout=WALL_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    errors.append('timeout process group already absent')
                process.wait()
    except BaseException as error:
        errors.append(type(error).__name__ + ': ' + str(error))
    finally:
        # Also close a spawned session on interruption or wait/write failure.
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                errors.append('cleanup process group already absent')
            except OSError as error:
                errors.append('killpg: ' + repr(error))
            try:
                process.wait()
            except OSError as error:
                errors.append('wait: ' + repr(error))
    row.update(exit_code=None if process is None else process.returncode,
               leader_reaped=process is not None and process.returncode is not None,
               timed_out=timed_out, operational_seconds=time.monotonic() - start,
               errors=errors)
    if log.exists():
        data, owner = read(log)
        row.update(log=log.name, log_sha256=digest(data), log_bytes=len(data),
                   log_stat=owner, terminal_observations=summaries(data))
    row['status'] = ('PASS' if row['exit_code'] == 0 and row['leader_reaped']
                     and not timed_out and not errors else 'FAIL')
    return row['status'] == 'PASS'


def main():
    if sys.flags.optimize:
        raise RuntimeError('optimized Python disables required assertions')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--toolchain', type=Path, required=True)
    parser.add_argument('--user-home', type=Path, required=True)
    parser.add_argument('--cargo-home', type=Path, required=True)
    args = parser.parse_args()
    repo, output, toolchain = args.repo, args.output, args.toolchain
    for path in (repo, toolchain, args.user_home, args.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert output.is_absolute() and output.parent.resolve(strict=True) == output.parent
    assert output.is_relative_to(repo / 'ignored') and output != repo / 'ignored'
    assert '..' not in output.parts and not output.exists() and not output.is_symlink()
    output.mkdir()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = dict(HOME=str(args.user_home), CARGO_HOME=str(args.cargo_home),
               LC_ALL='C', PYTHONDONTWRITEBYTECODE='1',
               CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
               CARGO_TARGET_DIR=str(repo / 'target'), CARGO_NET_OFFLINE='true',
               RUSTC=str(toolchain / 'bin/rustc'), RUSTDOC=str(toolchain / 'bin/rustdoc'),
               PATH=str(toolchain / 'bin') + ':/usr/bin:/bin')
    assert 'RUST_TEST_THREADS' not in env and CHILD not in env
    cargo = str(toolchain / 'bin/cargo')
    commands = [dict(name=name, argv=[cargo, 'test', '--offline', '--locked'] +
                    (['--workspace'] if name == 'workspace' else
                     ['-p', 'liteinst2', '--test', 'prefixed_pun_oracle']
                     if name.startswith('prefixed-pun-') else ['-p', 'liteinst2', '--lib']),
                    cwd=str(repo), env=dict(env, TMPDIR=str(output / (name + '-tmp'))),
                    wall_seconds=WALL_SECONDS, status='UNRUN') for name in NAMES]
    write(output / 'plan.json', dict(schema=1, commands=commands,
                                   environment_policy='explicit fields only; no inherited variables',
                                   absent_environment=['RUST_TEST_THREADS', CHILD], retries=0))
    rows = json.loads(json.dumps(commands))
    before = None
    after = None
    errors = []
    try:
        names = dict(cargo=cargo, rustc=env['RUSTC'], rustdoc=env['RUSTDOC'],
                     python=sys.executable, git=shutil.which('git', path=env['PATH']),
                     cc=shutil.which('cc', path=env['PATH']))
        assert all(names.values()), 'selected tool lookup failed'
        git = names['git']
        def snapshot():
            return dict(source=source(repo, git, env),
                        tools={n: tool(p) for n, p in names.items()},
                        cargo_configurations=configuration(repo, args.cargo_home))
        before = snapshot()
        write(output / 'inputs-before.json', before)
        hardware = dict(
            host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(),
            host_label_authority='operator-provided host description; model recorded separately',
            cpu_model=next(line.split(':', 1)[1].strip() for line in
                           Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),
            logical_cpus=os.cpu_count(), kernel_release=platform.release(), libc=platform.libc_ver())
        write(output / 'hardware.json', hardware)
        assert hardware['architecture'] == 'x86_64' and 'AMD EPYC' in hardware['cpu_model']
        for row in rows:
            observed = snapshot()
            write(output / (row['name'] + '-inputs-before.json'), observed)
            assert observed == before, 'source/tool drift before ' + row['name']
            Path(row['env']['TMPDIR']).mkdir()
            passed = execute(repo, output, row['env'], row)
            write(output / (row['name'] + '-command-result.json'), row)
            observed = snapshot()
            write(output / (row['name'] + '-inputs-after.json'), observed)
            row['inputs_before_after_equal'] = observed == before
            write(output / (row['name'] + '-result.json'), row)
            assert observed == before, 'source/tool drift after ' + row['name']
            if not passed:
                break
        after = snapshot()
        write(output / 'inputs-after.json', after)
        assert after == before, 'final source/tool drift'
    except BaseException as error:
        errors.append(type(error).__name__ + ': ' + str(error))
    complete = before is not None and after == before and not errors and all(r['status'] == 'PASS' for r in rows)
    summary = dict(schema=1, completed=complete, status='PASS' if complete else 'FAIL',
                   revision=None if before is None else before['source']['revision'],
                   source_before_after_equal=before is not None and after == before,
                   config_content_attestation_complete=before is not None and all(
                       row['state'] != 'READ_DENIED' for row in before['cargo_configurations'].values()),
                   commands=rows, errors=errors, enclosing_parent_closed=None,
                   scope='Seven unfiltered default-parallel invocations; selected source/tool observations only.',
                   limits=['Raw terminal observations are not aggregated: nested test processes may interleave.',
                           'Durations are operational diagnostics, not performance measurements.',
                           'No full Cargo configuration, dependency-artifact, or runtime-loader closure is claimed.',
                           'Ancestor/CARGO_HOME config lookup observations are retained; READ_DENIED is not absence or proof of Cargo consumption.',
                           'Leader waits are recorded; enclosing caller closure is a separate root observation.',
                           'No A4 completion, architectural-state or broader qualification claim.'],
                   qualification_complete=False)
    write(output / 'summary.json', summary)
    print(json.dumps(dict(status=summary['status'], revision=summary['revision'],
                          phases=[dict(name=r['name'], status=r['status']) for r in rows])), flush=True)
    return 0 if complete else 1


if __name__ == '__main__':
    raise SystemExit(main())
