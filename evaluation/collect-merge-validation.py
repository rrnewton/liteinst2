#!/usr/bin/env python3
"""Project twelve closed merged-validation commands; never execute validation."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

REVISION = '41a236dff00295a70b5c4cf2982eb91359e5b2c1'
PINS = {
    'required': ('evaluation/required-gates.py', '6d71d2a6518b8d93e136fb5fcb8170dded37e7bcfa0eae2c1fdefb1582a1fb8b'),
    'serial': ('evaluation/serial-launch.py', 'dc3885bec8e3717ecd4122895f0f3646e98b2e08b0a1cc1bebfb0449a08620a4'),
    'parallel': ('evaluation/trampoline-parallel.py', '0d3697eaaf433fc76d22f4ec7b6bc8047d0260f90bf9227072ad8dee2f4662ba'),
}
GATES = [('fmt', ['cargo', 'fmt', '--check'], 180),
         ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
         ('test', ['cargo', 'test', '--workspace'], 360),
         ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180)]
PARALLEL = ['library-1', 'library-2', 'library-3', 'prefixed-pun-1', 'prefixed-pun-2', 'prefixed-pun-3', 'workspace']
SERIAL = ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--', '--test-threads=1', '--nocapture']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def owner(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def main():
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported')
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'raw', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    args = ap.parse_args()
    repo, raw, out = args.repo, args.raw, args.output
    for path in (repo, raw):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert raw.is_relative_to(repo / 'ignored')
    assert out.is_absolute() and out.parent.resolve(strict=True) == out.parent
    assert out.is_relative_to(repo / 'ignored') and not out.exists() and not out.is_symlink()
    inputs = {}

    def read(path):
        assert path.is_absolute() and path.parent.resolve(strict=True) == path.parent
        assert not path.is_relative_to(repo / 'target')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
            before = os.fstat(stream.fileno())
            assert stat.S_ISREG(before.st_mode)
            data = stream.read()
            assert owner(before) == owner(os.fstat(stream.fileno())) == owner(path.lstat())
        fact = dict(sha256=sha(data), bytes=len(data), owner=owner(before))
        assert str(path) not in inputs or inputs[str(path)] == fact
        inputs[str(path)] = fact
        return data

    def load(path):
        return json.loads(read(path))

    def git(*parts):
        result = subprocess.run(['/usr/bin/git', '--no-optional-locks', '--no-replace-objects',
            '-c', 'core.fsmonitor=false', '-C', str(repo), *parts],
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
        assert not result.stderr
        return result.stdout

    reporter = Path(__file__).resolve(strict=True)
    reporter_bytes = read(reporter)
    reporter_revision = git('rev-parse', 'HEAD').decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', reporter_revision)
    assert reporter.is_relative_to(repo) and git('show', reporter_revision + ':' + str(reporter.relative_to(repo))) == reporter_bytes
    assert not git('diff', '--no-ext-diff', '--no-textconv', '--binary', 'HEAD', '--')
    launches = {}
    for phase, (_, expected_sha) in PINS.items():
        directory = raw / (phase + '-launch')
        command, started, closed = [load(directory / (name + '.json')) for name in ('command', 'started', 'closed')]
        assert command['source_revision'] == REVISION and command['cwd'] == str(repo)
        assert command['recipe_sha256'] == expected_sha == sha(read(Path(command['argv'][2])))
        assert command['argv'][1] == '-B'
        assert started['command_sha256'] == inputs[str(directory / 'command.json')]['sha256']
        assert closed['parent_wait_returned'] is True and closed['pid'] == started['pid']
        assert type(closed['exit']) is int and closed['operational_seconds'] >= 0
        for stream in ('stdout', 'stderr'):
            assert sha(read(directory / (stream + '.txt'))) == closed[stream + '_sha256']
        assert command['cpu_affinity'] == list(range(8 if phase == 'parallel' else 4))
        launches[phase] = dict(command=command, started=started, closed=closed,
            parent_source_sha256=sha(read(directory / 'launch.py')))
    for phase in ('required', 'parallel'):
        path, digest = PINS[phase]
        assert sha(git('show', REVISION + ':' + path)) == digest

    snapshots = {}
    for phase in ('serial', 'parallel'):
        before = load(raw / phase / 'inputs-before.json')
        after = load(raw / phase / 'inputs-after.json')
        assert before == after and before['source']['revision'] == REVISION
        snapshots[phase] = before
    source = snapshots['serial']['source']['files']
    assert {p: {k: v[k] for k in ('sha256', 'bytes', 'mode')} for p, v in source.items()} == {
        p: {k: v[k] for k in ('sha256', 'bytes', 'mode')} for p, v in snapshots['parallel']['source']['files'].items()}
    gates = load(raw / 'required/commands.json')
    assert gates['head'] == REVISION and gates['tracked_diff_sha256'] == sha(b'')
    assert gates['source_sha256'] == {p: v['sha256'] for p, v in source.items()}
    # Source() in the pinned recipes authenticates whole Git blob bytes/modes.
    # Do not reread compiler products, caches, or the private supervisor log.
    hardware = load(raw / 'serial/hardware.json')
    other_hardware = load(raw / 'parallel/hardware.json')
    keys = ('architecture', 'cpu_model', 'kernel_release', 'libc', 'logical_cpus')
    assert all(hardware[k] == other_hardware[k] for k in keys)
    assert hardware['architecture'] == 'x86_64' and 'AMD EPYC' in hardware['cpu_model']
    hardware = dict(host_label='AMD EPYC Zen 5 dev host', **{k: hardware[k] for k in keys})
    contexts = []

    def row(name, phase, argv, env, affinity, wall, status, result, exit_code, seconds, log=None, log_sha=None):
        assert status in ('PASS', 'FAIL', 'UNRUN')
        if log is not None:
            assert sha(read(log)) == log_sha
        contexts.append(dict(name=name, phase=phase, status=status, exit=exit_code,
            operational_seconds=seconds, cpu_seconds=None, cpu_seconds_basis='not measured by these recipes',
            command=dict(argv=argv, cwd=str(repo), env=env, cpu_affinity=affinity, wall_seconds=wall),
            result=result, log_sha256=log_sha,
            log_bytes=None if log is None else inputs[str(log)]['bytes'],
            recipe_sha256=PINS[phase][1], tested_revision=REVISION))

    required_env = dict(launches['required']['command']['env'], CARGO_INCREMENTAL='0',
        CARGO_BUILD_JOBS='4', CARGO_TARGET_DIR=str(repo / 'target'), RUST_TEST_THREADS='4',
        CARGO_NET_OFFLINE='true', TMPDIR=str(raw / 'required'))
    records = gates['records']
    assert 1 <= len(records) <= 4
    assert all(r['exit'] == 0 for r in records[:-1])
    for i, (name, argv, wall) in enumerate(GATES):
        result = records[i] if i < len(records) else None
        if result is not None:
            assert (result['name'], result['argv'], result['timeout_seconds']) == (name, argv, wall)
            assert result['log'] == str((raw / 'required' / (name + '.log')).relative_to(repo))
        row('required-' + name, 'required', argv, required_env, list(range(4)), wall,
            'UNRUN' if result is None else 'PASS' if result['exit'] == 0 else 'FAIL', result,
            None if result is None else result['exit'], None if result is None else result['seconds'],
            None if result is None else raw / 'required' / (name + '.log'), None if result is None else result['sha256'])
    assert (launches['required']['closed']['exit'] == 0) == (len(records) == 4 and all(r['exit'] == 0 for r in records))

    serial = load(raw / 'serial/command.json')
    serial_result = load(raw / 'serial/process-result.json')
    serial_summary = load(raw / 'serial/summary.json')
    copied = load(raw / 'serial/log-copy.json')
    assert serial['argv'] == SERIAL and serial['cwd'] == str(repo) and serial['source_revision'] == REVISION
    assert (serial['timeout_seconds'], serial['max_log_bytes'], serial['cleanup_seconds']) == (180, 8388608, 3)
    assert serial['affinity'] == list(range(4)) and serial['caller_sha256'] == PINS['serial'][1]
    assert serial_summary['command'] == serial_result and serial_summary['revision'] == REVISION
    assert serial_summary['inputs_before_after_equal'] and serial_summary['caller_unchanged']
    assert copied['sha256'] == serial_result['private_log_sha256'] and copied['destination'] == 'serial.log'
    serial_pass = serial_result['exit_code'] == 0 and serial_result['termination'] is None and serial_result['cleanup_complete'] is True and serial_result['reaped_descendants'] == 0
    assert serial_summary['status'] == ('PASS_COMMAND_AND_STABLE_INPUTS' if serial_pass else 'FAILED')
    assert (launches['serial']['closed']['exit'] == 0) == serial_pass
    row('serial-launch', 'serial', SERIAL, serial['env'], serial['affinity'], 180,
        'PASS' if serial_pass else 'FAIL', serial_result, serial_result['exit_code'], serial_result['seconds'],
        raw / 'serial/serial.log', serial_result['private_log_sha256'])
    contexts[-1]['command'].update(max_log_bytes=8388608, cleanup_seconds=3)
    assert copied['bytes'] == contexts[-1]['log_bytes']

    plan = load(raw / 'parallel/plan.json')
    parallel = load(raw / 'parallel/summary.json')
    assert parallel['revision'] == REVISION and parallel['source_before_after_equal']
    assert plan['retries'] == 0 and plan['absent_environment'] == ['RUST_TEST_THREADS', 'LITEINST2_STAGED_DROP_CHILD']
    assert len(plan['commands']) == len(parallel['commands']) == 7
    stopped = False
    for name, planned, result in zip(PARALLEL, plan['commands'], parallel['commands']):
        assert planned['name'] == result['name'] == name and planned['status'] == 'UNRUN'
        for key in ('argv', 'cwd', 'env', 'wall_seconds'):
            assert planned[key] == result[key]
        argv = [planned['argv'][0], 'test', '--offline', '--locked'] + (
            ['--workspace'] if name == 'workspace' else ['-p', 'liteinst2', '--test', 'prefixed_pun_oracle']
            if name.startswith('prefixed') else ['-p', 'liteinst2', '--lib'])
        assert planned['argv'] == argv and planned['cwd'] == str(repo) and planned['wall_seconds'] == 360
        assert not {'RUST_TEST_THREADS', 'LITEINST2_STAGED_DROP_CHILD', 'LITEINST2_PREFIXED_PUN_CHILD'} & set(planned['env'])
        status = result['status']
        assert status in ('PASS', 'FAIL', 'UNRUN') and (not stopped or status == 'UNRUN')
        if status != 'UNRUN':
            assert load(raw / 'parallel' / (name + '-result.json')) == result
            for when in ('before', 'after'):
                assert load(raw / 'parallel' / (name + '-inputs-' + when + '.json')) == snapshots['parallel']
            assert result['inputs_before_after_equal']
            passed = result['exit_code'] == 0 and result['leader_reaped'] and not result['timed_out'] and not result['errors']
            assert status == ('PASS' if passed else 'FAIL')
            assert result['log'] == name + '.log'
        stopped = stopped or status != 'PASS'
        # Literal terminal observations and owners stay private; no inferred totals.
        public_result = {k: v for k, v in result.items() if k not in ('argv', 'cwd', 'env', 'terminal_observations', 'log_stat')}
        row('parallel-' + name, 'parallel', argv, planned['env'], list(range(8)), 360, status,
            public_result, result.get('exit_code'), result.get('operational_seconds'),
            None if status == 'UNRUN' else raw / 'parallel' / result['log'], result.get('log_sha256'))
    parallel_pass = not parallel['errors'] and all(r['status'] == 'PASS' for r in parallel['commands'])
    assert parallel['completed'] == parallel_pass and parallel['status'] == ('PASS' if parallel_pass else 'FAIL')
    assert (launches['parallel']['closed']['exit'] == 0) == parallel_pass
    assert len(contexts) == 12

    roles = {'$REPO': str(repo), '$RAW': str(raw), '$HOME': serial['env']['HOME'],
             '$CARGO_HOME': serial['env']['CARGO_HOME'], '$TOOLCHAIN': serial['env']['PATH'].split(':')[0].removesuffix('/bin')}
    assert len(set(roles.values())) == len(roles) and all(v.startswith('/') for v in roles.values())
    roles['$RAW_REL'] = str(raw.relative_to(repo))
    pattern = re.compile('|'.join(re.escape(v) for v in sorted(roles.values(), key=len, reverse=True)))
    reverse = {v: k for k, v in roles.items()}
    token = re.compile('|'.join(re.escape(k) for k in sorted(roles, key=len, reverse=True)))
    def transform(value, restore=False):
        if isinstance(value, str):
            if not restore:
                assert not any(k in value for k in roles)
            return token.sub(lambda m: roles[m[0]], value) if restore else pattern.sub(lambda m: reverse[m[0]], value)
        if isinstance(value, list):
            return [transform(v, restore) for v in value]
        if isinstance(value, dict):
            return {k: transform(v, restore) for k, v in value.items()}
        return value
    public_contexts = transform(contexts)
    public_launches = transform(launches)
    assert transform(public_contexts, True) == contexts and transform(public_launches, True) == launches
    tool_rows = {phase: {name: {k: v[k] for k in ('path', 'resolved', 'sha256', 'bytes')}
                        for name, v in snapshot['tools'].items()} for phase, snapshot in snapshots.items()}
    source_digest = sha(encode({p: {k: v[k] for k in ('sha256', 'bytes', 'mode')} for p, v in source.items()}))
    summary = dict(schema=1, tested_revision=REVISION,
        reporter=dict(revision=reporter_revision, sha256=sha(reporter_bytes)), hardware=hardware,
        source=dict(files=len(source), sha256=source_digest, before_after_equal=True,
                    authority='Whole Git blob/mode checks in pinned serial/default recipes; required hash map equal.'),
        status='PASS' if all(c['status'] == 'PASS' for c in contexts) and
            all(launch['closed']['exit'] == 0 for launch in launches.values()) else 'FAIL',
        parallel_errors=transform(parallel['errors']),
        command_rows=12, command_statuses={status: sum(c['status'] == status for c in contexts) for status in ('PASS', 'FAIL', 'UNRUN')},
        launches=public_launches, tools=transform(tool_rows),
        configuration_attestation=dict(parallel_complete=parallel['config_content_attestation_complete'],
            scope='Saved observations only; READ_DENIED is not absence or a Cargo-consumption proof.'),
        reproducers={phase: dict(path=path, sha256=digest) for phase, (path, digest) in PINS.items()},
        test_counts=None, test_counts_scope='Independent complete log review is separate; no counts inferred here.',
        qualification_complete=False,
        limits=['Operational durations are not benchmarks; CPU time was not measured.',
                'Serial is one command, not the complete admission protocol.',
                'Required/default recipes record leader waits; serial separately records its owned-descendant cleanup.',
                'Parent wait records are saved caller authority, not a new descendant-closure proof.',
                'No full dependency, Cargo-config, runtime-loader, architectural-state or milestone qualification.'])
    table = io.StringIO(newline='')
    columns = ['name', 'phase', 'status', 'exit', 'operational_seconds', 'cpu_seconds', 'log_sha256', 'log_bytes', 'tested_revision', 'recipe_sha256']
    writer = csv.DictWriter(table, fieldnames=columns); writer.writeheader()
    for c in contexts:
        writer.writerow({k: c[k] for k in columns})
    public = {'summary.json': encode(summary), 'commands.json': encode(public_contexts), 'commands.csv': table.getvalue().encode()}
    for data in public.values():
        text = data.decode()
        assert '/home/' not in text and '/Users/' not in text and str(repo) not in text
        assert not re.search(r'\b' + re.escape(Path(roles['$HOME']).name) + r'\b', text)
    assert reporter_bytes == read(reporter) and git('rev-parse', 'HEAD').decode().strip() == reporter_revision
    assert not git('diff', '--no-ext-diff', '--no-textconv', '--binary', 'HEAD', '--')
    for path, fact in list(inputs.items()):
        assert inputs[path] == fact and sha(read(Path(path))) == fact['sha256']
    out.mkdir(); (out / 'public').mkdir()
    for name, data in public.items():
        with (out / 'public' / name).open('xb') as stream:
            stream.write(data)
    index = {name: dict(sha256=sha(data), bytes=len(data)) for name, data in public.items()}
    with (out / 'public/files.json').open('xb') as stream:
        stream.write(encode(index))
    with (out / 'private-binding.json').open('xb') as stream:
        stream.write(encode(dict(schema=1, inputs=inputs, roles=roles,
            exact_contexts=contexts, exact_launches=launches, public=index,
            reporter_revision=reporter_revision, tested_revision=REVISION,
            scope='Saved-record projection; actual review and collector enclosing wait remain separate.')))
    print(json.dumps(dict(status=summary['status'], command_rows=12, tested_revision=REVISION)))


if __name__ == '__main__':
    main()
