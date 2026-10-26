#!/usr/bin/env python3
"""Publish a finite saved-record summary; never invoke tests, compilers or raw scripts."""
import argparse
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

REVISION = '8ff87a0a14c9348610c843063516c79190f6dede'
SCRIPT = 'evaluation/collect-trampoline-parallel.py'
PINS = {
    'evaluation/trampoline-parallel.py': '0d3697eaaf433fc76d22f4ec7b6bc8047d0260f90bf9227072ad8dee2f4662ba',
    'evaluation/required-gates.py': '6d71d2a6518b8d93e136fb5fcb8170dded37e7bcfa0eae2c1fdefb1582a1fb8b',
    'evaluation/e9-common-app/build_inventory.py': '01a500aa807b131c94d158efb95a625eb777b11846013cd14fbddf33f63ee1b9',
}
PARALLEL = ['library-1', 'library-2', 'library-3',
            'prefixed-pun-1', 'prefixed-pun-2', 'prefixed-pun-3', 'workspace']
GATES = [('fmt', ['cargo', 'fmt', '--check']),
         ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings']),
         ('test', ['cargo', 'test', '--workspace']),
         ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'])]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def fields(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path):
    assert path.is_absolute() and path.parent.resolve(strict=True) == path.parent
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode)
        data = stream.read()
        after = os.fstat(stream.fileno())
    assert fields(before) == fields(after) == fields(path.stat()) and len(data) == before.st_size
    return data


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, 'duplicate JSON key'
            result[key] = value
        return result
    return json.loads(read(path), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def index(root):
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            owner = fields(path.lstat())
            key = str(path.relative_to(root))
            if path.is_symlink():
                target = os.readlink(path)
                assert fields(path.lstat()) == owner
                result[key] = dict(kind='symlink', target=target, stat=owner)
                if name in dirs:
                    dirs.remove(name)
            elif path.is_file():
                data = read(path)
                result[key] = dict(kind='file', sha256=sha(data), bytes=len(data), stat=owner)
            else:
                assert path.is_dir(), 'unsupported raw owner'
                result[key] = dict(kind='directory', stat=owner)
    return result


def terminals(data):
    pattern = re.compile(rb'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; '
                         rb'(\d+) ignored; (\d+) measured; (\d+) filtered out;')
    return [dict(byte_offset=m.start(), text=m.group().decode(), status=m[1].decode(),
                 passed=int(m[2]), failed=int(m[3]), ignored=int(m[4]), measured=int(m[5]),
                 filtered_out=int(m[6]), attribution='unclassified terminal observation; not additive')
            for m in pattern.finditer(data)]


def git(repo, *args):
    return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-C', str(repo), *args],
                                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=30)


def source_map(repo, files):
    rows = []
    for row in git(repo, 'ls-tree', '-rz', '--full-tree', REVISION).split(b'\0'):
        if row:
            meta, name = row.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            assert kind == 'blob' and mode in ('100644', '100755')
            rows.append((name.decode(), mode, oid))
    assert set(files) == {row[0] for row in rows}
    data = subprocess.check_output(
        ['/usr/bin/git', '--no-replace-objects', '-C', str(repo), 'cat-file', '--batch'],
        input=''.join(oid + '\n' for _, _, oid in rows).encode(),
        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, timeout=30)
    at = 0
    clean = {}
    for name, mode, oid in rows:
        end = data.index(b'\n', at)
        observed_oid, kind, size = data[at:end].decode().split()
        size = int(size)
        assert observed_oid == oid and kind == 'blob'
        body = data[end + 1:end + 1 + size]
        assert len(body) == size and data[end + 1 + size:end + 2 + size] == b'\n'
        clean[name] = dict(mode=mode, bytes=size, sha256=sha(body))
        assert {k: files[name][k] for k in clean[name]} == clean[name], name
        at = end + 2 + size
    assert at == len(data)
    for name, digest in PINS.items():
        assert clean[name]['sha256'] == digest
    return clean


def transforms(roles):
    assert set(roles) == {'$REPO', '$PARALLEL', '$BUILD', '$HOME', '$CARGO_HOME', '$TOOLCHAIN',
                          '$PARALLEL_LAUNCH', '$BUILD_LAUNCH'}
    assert len(set(roles.values())) == len(roles)
    assert all(Path(p).is_absolute() and '..' not in Path(p).parts for p in roles.values())
    forward = re.compile('|'.join(re.escape(p) for p in sorted(roles.values(), key=len, reverse=True)))
    reverse = re.compile('|'.join(re.escape(p) for p in sorted(roles, key=len, reverse=True)))
    back = {v: k for k, v in roles.items()}
    def walk(value, pattern, replacements):
        if isinstance(value, str):
            return pattern.sub(lambda match: replacements[match[0]], value)
        if isinstance(value, list):
            return [walk(x, pattern, replacements) for x in value]
        if isinstance(value, dict):
            result = {walk(k, pattern, replacements): walk(v, pattern, replacements) for k, v in value.items()}
            assert len(result) == len(value), 'normalization key collision'
            return result
        return value
    def public(value):
        assert all(token.encode() not in encode(value) for token in roles), 'literal role collision'
        normalized = walk(value, forward, back)
        assert walk(normalized, reverse, roles) == value, 'whole decoded inverse failed'
        return normalized
    return public


def csv_bytes(rows, columns):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=columns, lineterminator='\n')
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(row[k], sort_keys=True, separators=(',', ':'))
                         if isinstance(row.get(k), (list, dict)) else row.get(k) for k in columns})
    return stream.getvalue().encode()


def main():
    if sys.flags.optimize:
        raise RuntimeError('optimized Python is unsupported')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'regression', 'build', 'admission', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    repo, raw, build, output = args.repo, args.regression, args.build, args.output
    for p in (repo, raw, build):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert raw.is_relative_to(repo / 'ignored') and build.is_relative_to(repo / 'ignored')
    assert output.is_absolute() and output.parent.resolve(strict=True) == output.parent
    assert output.is_relative_to(repo / 'ignored') and '..' not in output.parts
    assert not output.exists() and not output.is_symlink()
    assert not output.is_relative_to(raw) and not output.is_relative_to(build)
    collector_revision = git(repo, 'rev-parse', 'HEAD').decode().strip()
    assert not git(repo, 'diff', '--binary', 'HEAD', '--')
    assert Path(__file__).resolve(strict=True) == repo / SCRIPT
    collector_source = read(repo / SCRIPT)
    assert git(repo, 'show', 'HEAD:' + SCRIPT) == collector_source
    admission_bytes = read(args.admission)
    admission = load(args.admission)
    assert admission['schema'] == 1 and admission['tested_revision'] == REVISION
    roles = admission['roles']
    assert roles['$REPO'] == str(repo) and roles['$PARALLEL'] == str(raw) and roles['$BUILD'] == str(build)
    public = transforms(roles)
    authorities, authority_refs = {}, []
    for kind in ('parent_closures', 'reviews'):
        assert set(admission[kind]) == {'regression', 'required_build'}
        authorities[kind] = {}
        for scope, item in admission[kind].items():
            record = item['record']
            assert sha(read(Path(record['path']))) == record['sha256']
            authority_refs.append(record)
            if kind == 'parent_closures':
                assert item['closed'] is True and item['reaped'] is True
                assert type(item['exit_code']) is int
            authorities[kind][scope] = dict(sha256=record['sha256'],
                                           authority='explicit caller-supplied saved-record reference')
            if kind == 'parent_closures':
                authorities[kind][scope].update(closed=item['closed'], reaped=item['reaped'], exit_code=item['exit_code'])
    original_indices = dict(regression=index(raw), required=index(build / 'required'))
    named = ['source.json', 'source-after.json', 'tools.json', 'tools-after.json',
             'configs.json', 'configs-after.json', 'config-scope.json', 'hardware.json']
    named_hashes = {n: sha(read(build / n)) for n in named}
    before = load(raw / 'inputs-before.json')
    summary = load(raw / 'summary.json')
    plan = load(raw / 'plan.json')
    assert before['source']['revision'] == summary['revision'] == REVISION
    sources = source_map(repo, before['source']['files'])
    bs, ba = load(build / 'source.json'), load(build / 'source-after.json')
    assert bs['revision'] == ba['revision'] == REVISION and bs['files'] == sources
    build_source_equal = bs == ba
    command_rows, counts = [], []
    assert [r['name'] for r in plan['commands']] == PARALLEL
    assert len(summary['commands']) == 7
    stopped = False
    for planned, row in zip(plan['commands'], summary['commands']):
        name = planned['name']
        assert row['name'] == name and row['status'] in ('PASS', 'FAIL', 'UNRUN')
        for key in ('argv', 'env', 'cwd', 'wall_seconds'):
            assert row[key] == planned[key]
        expected = [roles['$TOOLCHAIN'] + '/bin/cargo', 'test', '--offline', '--locked']
        expected += (['--workspace'] if name == 'workspace' else
                     ['-p', 'liteinst2', '--test', 'prefixed_pun_oracle']
                     if name.startswith('prefixed-pun-') else ['-p', 'liteinst2', '--lib'])
        assert row['argv'] == expected and row['wall_seconds'] == 360 and row['cwd'] == str(repo)
        expected_env = dict(HOME=roles['$HOME'], CARGO_HOME=roles['$CARGO_HOME'], LC_ALL='C',
                            PYTHONDONTWRITEBYTECODE='1', CARGO_BUILD_JOBS='4', CARGO_INCREMENTAL='0',
                            CARGO_NET_OFFLINE='true', CARGO_TARGET_DIR=str(repo / 'target'),
                            RUSTC=roles['$TOOLCHAIN'] + '/bin/rustc', RUSTDOC=roles['$TOOLCHAIN'] + '/bin/rustdoc',
                            PATH=roles['$TOOLCHAIN'] + '/bin:/usr/bin:/bin', TMPDIR=str(raw / (name + '-tmp')))
        assert row['env'] == expected_env
        if stopped:
            assert row['status'] == 'UNRUN', 'no continuation or retry after failure'
        stopped |= row['status'] != 'PASS'
        if row['status'] != 'UNRUN':
            assert type(row['exit_code']) is int or row['exit_code'] is None
            assert type(row['leader_reaped']) is bool and type(row['timed_out']) is bool
            assert isinstance(row['errors'], list) and all(isinstance(x, str) for x in row['errors'])
            data = read(raw / row['log'])
            assert row['log'] == name + '.log' and sha(data) == row['log_sha256']
            assert terminals(data) == row['terminal_observations']
            expected_pass = row['exit_code'] == 0 and row['leader_reaped'] and not row['timed_out'] and not row['errors']
            assert (row['status'] == 'PASS') == expected_pass
            assert type(row['operational_seconds']) in (int, float) and math.isfinite(row['operational_seconds']) and row['operational_seconds'] >= 0
            saved = load(raw / (name + '-command-result.json'))
            assert saved == {k: v for k, v in row.items() if k != 'inputs_before_after_equal'}
            assert load(raw / (name + '-inputs-before.json')) == before
            if (raw / (name + '-result.json')).exists():
                assert load(raw / (name + '-result.json')) == row
                observed = load(raw / (name + '-inputs-after.json'))
                assert row['inputs_before_after_equal'] == (observed == before)
            counts.extend(dict(group='default-parallel', command=name, ordinal=i, **r)
                          for i, r in enumerate(terminals(data)))
        else:
            assert row == planned and not (raw / (name + '.log')).exists()
        command_rows.append(dict(group='default-parallel', name=name, status=row['status'],
                                 argv=row['argv'], env=row['env'], cwd=row['cwd'],
                                 exit_code=row.get('exit_code'), wall_seconds=360,
                                 operational_seconds=row.get('operational_seconds'), log_sha256=row.get('log_sha256')))
    required = load(build / 'required/command.json')
    required_result = load(build / 'required/result.json')
    assert all(required_result[k] == v for k, v in required.items())
    gate_dir = build / 'required/gates'
    assert required['name'] == 'required' and required['cwd'] == str(repo)
    assert required['argv'][1:] == ['-B', str(repo / 'evaluation/required-gates.py'), '--repo', str(repo), '--output', str(gate_dir)]
    assert required['outer_argv'] == required['argv'] and required['outer_env'] == required['env']
    assert required['parent_timeout_seconds'] == 1000
    assert type(required_result['exit']) is int and type(required_result['parent_timeout']) is bool
    required_env = dict(expected_env, RUST_TEST_THREADS='4', RUSTC_WRAPPER='',
                        RUSTC_WORKSPACE_WRAPPER='', TMPDIR=str(build / 'required/tmp'))
    assert required['env'] == required_env
    assert required['argv'][0] in load(build / 'tools.json')
    assert Path(required['argv'][0]).name.startswith('python3')
    gate_receipt = load(gate_dir / 'commands.json') if (gate_dir / 'commands.json').exists() else None
    if gate_receipt is not None:
        assert gate_receipt['head'] == REVISION and gate_receipt['tracked_diff_sha256'] == sha(b'')
        assert gate_receipt['source_sha256'] == {n: r['sha256'] for n, r in sources.items()}
    gate_env = dict(required['env'], CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
                    CARGO_TARGET_DIR=str(repo / 'target'), RUST_TEST_THREADS='4',
                    CARGO_NET_OFFLINE='true', TMPDIR=str(gate_dir))
    records = [] if gate_receipt is None else gate_receipt['records']
    assert 0 <= len(records) <= 4
    for i, (name, argv) in enumerate(GATES):
        row = records[i] if i < len(records) else None
        wall = 360 if name == 'test' else 180
        if row is not None:
            assert row['name'] == name and row['argv'] == argv and row['timeout_seconds'] == wall
            log = gate_dir / (name + '.log')
            assert row['log'] == str(log.relative_to(repo))
            data = read(log)
            assert sha(data) == row['sha256']
            assert type(row['exit']) is int or row['exit'] == 'timeout'
            assert type(row['seconds']) in (int, float) and math.isfinite(row['seconds']) and row['seconds'] >= 0
            if i + 1 < len(records):
                assert row['exit'] == 0, 'required gates cannot continue after failure'
            counts.extend(dict(group='required', command=name, ordinal=j, **r)
                          for j, r in enumerate(terminals(data)))
        else:
            assert not (gate_dir / (name + '.log')).exists()
        command_rows.append(dict(group='required', name=name,
                                 status='UNRUN' if row is None else ('PASS' if row['exit'] == 0 else 'FAIL'),
                                 argv=argv, env=gate_env, cwd=str(repo), wall_seconds=wall,
                                 exit_code=None if row is None else row['exit'],
                                 operational_seconds=None if row is None else row['seconds'],
                                 log_sha256=None if row is None else row['sha256']))
    parallel_after = load(raw / 'inputs-after.json') if (raw / 'inputs-after.json').exists() else None
    parallel_inputs_equal = before == parallel_after
    assert summary['source_before_after_equal'] == parallel_inputs_equal
    assert type(summary['completed']) is bool and summary['status'] == ('PASS' if summary['completed'] else 'FAIL')
    assert summary['completed'] == (parallel_inputs_equal and not summary['errors'] and
                                    all(r['status'] == 'PASS' for r in summary['commands']))
    hardware = dict(regression=load(raw / 'hardware.json'), required_build=load(build / 'hardware.json'))
    for row in hardware.values():
        assert row['host_label'] == 'AMD EPYC Zen 5 dev host' and row['architecture'] == 'x86_64'
    normalized_commands = public(command_rows)
    tools = dict(regression=before['tools'], required_build=load(build / 'tools.json'))
    report = dict(schema=1, tested_revision=REVISION, collector_revision=collector_revision,
                  collector_source_sha256=sha(collector_source), hardware=hardware, tools=public(tools),
                  source_files=len(sources), source_map_sha256=sha(encode(sources)),
                  default_parallel_completed=summary['completed'],
                  default_parallel_status=summary['status'],
                  required_gate_command_scope_complete=len(records) == 4 and all(r['exit'] == 0 for r in records),
                  required_runner_exit=required_result['exit'],
                  required_runner_timeout=required_result['parent_timeout'],
                  parallel_inputs_equal=parallel_inputs_equal, build_source_before_after_equal=build_source_equal,
                  build_tools_before_after_equal=load(build / 'tools.json') == load(build / 'tools-after.json'),
                  build_config_observations_equal=load(build / 'configs.json') == load(build / 'configs-after.json'),
                  config_content_attestation_complete=summary['config_content_attestation_complete'],
                  authority_references=authorities, command_rows=11, aggregate_test_counts=None,
                  raw_index_sha256={k: sha(encode(v)) for k, v in original_indices.items()},
                  qualification_complete=False,
                  limitations=['The seven default-parallel invocations and four required gates are separate scopes.',
                               'Terminal rows have unknown outer/nested attribution; do not add them or infer cases from child starts.',
                               'Durations are operational diagnostics, not benchmarks.',
                               'Parent closure and independent reviews are caller-supplied references, not inferred from saved command results.',
                               'Denied configuration contents, full dependency/loader closure, native state and A4 completion are unqualified.',
                               'Older failed and completed common-build histories are separate and receive no new credit.'])
    original_context = dict(required_runner=required, required_runner_result=required_result,
                            parallel_plan=plan, parallel_summary=summary)
    context = public(original_context)
    files = {'summary.json': encode(report) + b'\n',
             'commands.json': encode(dict(rows=normalized_commands, context=context)) + b'\n',
             'commands.csv': csv_bytes(normalized_commands, ['group', 'name', 'status', 'exit_code', 'wall_seconds',
                 'operational_seconds', 'argv', 'env', 'cwd', 'log_sha256']),
             'terminal-observations.json': encode(counts) + b'\n',
             'terminal-observations.csv': csv_bytes(counts, ['group', 'command', 'ordinal', 'byte_offset', 'status',
                 'passed', 'failed', 'ignored', 'measured', 'filtered_out', 'attribution', 'text'])}
    forbidden = [str(Path(roles['$HOME']).name), platform.node(), *admission['forbidden_text']]
    for data in files.values():
        text = data.decode()
        assert '/home/' not in text and '/Users/' not in text
        assert not re.search(r'\b[\w-]+(?:\.[\w-]+)*\.(?:com|net|org|internal)\b', text)
        assert all(not word or not re.search(r'(?<![\w])' + re.escape(word) + r'(?![\w])', text) for word in forbidden)
    assert original_indices == dict(regression=index(raw), required=index(build / 'required'))
    assert named_hashes == {n: sha(read(build / n)) for n in named}
    assert read(args.admission) == admission_bytes
    for record in authority_refs:
        assert sha(read(Path(record['path']))) == record['sha256']
    assert git(repo, 'rev-parse', 'HEAD').decode().strip() == collector_revision
    assert not git(repo, 'diff', '--binary', 'HEAD', '--') and read(repo / SCRIPT) == collector_source
    output.mkdir()
    payload = output / 'public'
    payload.mkdir()
    for name, data in files.items():
        with (payload / name).open('xb') as stream:
            stream.write(data)
    with (payload / 'files.json').open('xb') as stream:
        stream.write(encode({n: dict(sha256=sha(b), bytes=len(b)) for n, b in files.items()}) + b'\n')
    binding = dict(schema=1, admission_sha256=sha(admission_bytes), roles=roles,
                   collector_revision=collector_revision, collector_source_sha256=sha(collector_source),
                   tested_revision=REVISION, indices=original_indices, named_build_inputs=named_hashes,
                   complete_decoded_command_inverse=True, original_command_rows=command_rows,
                   original_context_sha256=sha(encode(original_context)),
                   authority_inputs=admission, public_files={p.name: sha(read(p)) for p in payload.iterdir()})
    with (output / 'private-binding.json').open('xb') as stream:
        stream.write(encode(binding) + b'\n')
    print('COLLECTED 11 command rows; terminal observations remain unaggregated', flush=True)


if __name__ == '__main__':
    main()
