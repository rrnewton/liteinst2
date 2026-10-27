#!/usr/bin/env python3
"""Report one reviewed original-derived static build; never run validation."""
import argparse
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SELF = 'evaluation/e9-common-app/collect_placement_build.py'
BUILD = 'evaluation/e9-common-app/build_inventory.py'
PROFILE_NAME = 'original-derived-v1'
BASELINE_REVISION = 'cbb189d1d17f947c97194842129b66eb68b0531f'
BASELINE_BINDING_SHA = 'f0acc3a82290802f2dedfab2f31f51830f063eecc3cc54e282b138ed0ea4e0da'
BASELINE_GROUPS_SHA = 'cec143ad09954a8178d1ad165d21274006c05ad3665bc50fc0a69c63788a32a2'
GATES_SHA = '6d71d2a6518b8d93e136fb5fcb8170dded37e7bcfa0eae2c1fdefb1582a1fb8b'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
CELLS = [f'{h}-{s}-{v}' for h in ('null', 'journal') for s in ('jump-site', 'heap-write') for v in ('unstripped', 'stripped')]
STAGES = ['required', 'native-compile', 'common-sites-compile', 'target'] + ['inventory-' + c for c in CELLS]
GATES = [('fmt', ['cargo', 'fmt', '--check'], 180),
         ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
         ('test', ['cargo', 'test', '--workspace'], 360),
         ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180)]
INVENTORY = {'COMPLETE', 'blocks.tsv', 'instructions.tsv', 'memory-writes.tsv', 'padding.tsv', 'policy.txt', 'selection.txt', 'sites.tsv', 'status.tsv', 'target.txt'}
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
CAP = 64 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def loads(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            assert k not in result, 'duplicate JSON key'
            result[k] = v
        return result
    def invalid(value):
        raise AssertionError('non-JSON constant: ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read(path):
    path = Path(path)
    assert path.is_absolute() and '..' not in path.parts
    assert path.parent.resolve(strict=True) == path.parent
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        assert stat.S_ISREG(before.st_mode) and before.st_size <= CAP
        raw = stream.read(CAP + 1)
        assert len(raw) == before.st_size and fields(before) == fields(os.fstat(stream.fileno()))
        return raw, fields(before)


def seconds(value):
    assert type(value) in (int, float) and math.isfinite(value) and value >= 0
    return value


def git(repo, *args, data=None):
    r = subprocess.run(['/usr/bin/git', '-C', str(repo), *args], input=data,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
    assert not r.stderr and len(r.stdout) <= 256 * 1024 * 1024
    return r.stdout


def git_sources(repo, revision, saved, recipe_sha):
    assert re.fullmatch('[0-9a-f]{40}', revision)
    rows = []
    for line in git(repo, 'ls-tree', '-rz', '--full-tree', revision).split(b'\0')[:-1]:
        header, name = line.split(b'\t', 1)
        mode, kind, oid = header.decode().split()
        assert kind == 'blob' and mode in ('100644', '100755')
        rows.append((name.decode(), mode, oid))
    assert len(rows) == len(saved) and {n for n, _, _ in rows} == saved.keys()
    data = git(repo, 'cat-file', '--batch', data=''.join(o + '\n' for _, _, o in rows).encode())
    at = 0
    for name, mode, oid in rows:
        end = data.index(b'\n', at)
        got, kind, length = data[at:end].decode().split(); length = int(length)
        assert (got, kind) == (oid, 'blob') and 0 <= length <= CAP
        body = data[end + 1:end + 1 + length]
        assert data[end + 1 + length:end + 2 + length] == b'\n'
        assert hashlib.sha1(b'blob ' + str(length).encode() + b'\0' + body).hexdigest() == oid
        assert saved[name] == dict(bytes=length, mode=mode, sha256=sha(body))
        at = end + 2 + length
    assert at == len(data)
    assert saved[BUILD]['sha256'] == recipe_sha
    assert saved['evaluation/required-gates.py']['sha256'] == GATES_SHA
    assert saved['tools/unwind-oracle/bounded_command.py']['sha256'] == HELPER_SHA


def csv_bytes(rows, fields):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
    writer.writeheader(); writer.writerows({k: r.get(k) for k in fields} for r in rows)
    return stream.getvalue().encode()


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'inputs', 'new-output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--inputs-sha256', required=True)
    a = p.parse_args()
    assert a.repo.is_absolute() and a.repo.resolve(strict=True) == a.repo
    assert a.inputs.is_absolute() and a.inputs.is_relative_to(a.repo / 'ignored') and '..' not in a.inputs.parts
    assert a.new_output.is_absolute() and a.new_output.parent.resolve(strict=True) == a.new_output.parent
    assert a.new_output.is_relative_to(a.repo / 'ignored') and not a.new_output.exists() and not a.new_output.is_symlink()
    self_path = a.repo / SELF
    assert Path(__file__).absolute() == self_path
    self_before = read(self_path)
    collector_revision = git(a.repo, 'rev-parse', 'HEAD').decode().strip()
    assert git(a.repo, 'show', collector_revision + ':' + SELF) == self_before[0]
    assert not git(a.repo, 'diff', '--binary', 'HEAD'), 'clean tracked collector checkout required'
    index_before = read(a.inputs)
    assert re.fullmatch('[0-9a-f]{64}', a.inputs_sha256) and sha(index_before[0]) == a.inputs_sha256
    envelope = loads(index_before[0])
    assert envelope.keys() == {'schema', 'authority', 'attempt', 'test_review', 'roles', 'privacy_literals', 'files'}
    assert type(envelope['schema']) is int and envelope['schema'] == 1
    assert envelope['authority'] == 'CALLER_SELECTED_ONE_CLOSED_PLACEMENT_BUILD'
    attempt = envelope['attempt']
    assert attempt.keys() == {'revision', 'recipe_sha256', 'raw', 'launch', 'review_binding', 'review_references', 'review_revision_key'}
    assert re.fullmatch('[0-9a-f]{40}', attempt['revision']) and re.fullmatch('[0-9a-f]{64}', attempt['recipe_sha256'])
    assert attempt['revision'] != BASELINE_REVISION, 'new cohort, never relabel historical cbb'
    assert attempt['review_revision_key'] in ('tested_revision', 'revision', 'source_revision')
    attempts = [attempt]  # One cohort only; historical reports remain immutable.
    roots = [Path(attempt[k]) for k in ('raw', 'launch')]
    for d in roots:
        assert d.is_absolute() and d.resolve(strict=True) == d and d.is_dir()
        assert d.is_relative_to(a.repo / 'ignored') and d != a.repo / 'ignored'
        assert not a.new_output.is_relative_to(d) and not d.is_relative_to(a.new_output)
    assert roots[0] != roots[1] and all(not x.is_relative_to(y) for x in roots for y in roots if x != y)
    reviews = {attempt['review_binding'], attempt['review_references']}
    test_review = envelope['test_review']
    if test_review is not None:
        assert test_review.keys() == {'binding', 'checks', 'groups', 'baseline_binding', 'baseline_groups'}
        reviews.update(test_review.values())
    for n in reviews:
        q = Path(n)
        assert q.is_absolute() and q.parent.resolve(strict=True) == q.parent and q.is_relative_to(a.repo / 'ignored')
        assert all(not q.is_relative_to(d) for d in roots)
    expected = envelope['files']; assert 1 <= len(expected) <= 4096
    assert all(type(pin['bytes']) is int and 0 <= pin['bytes'] <= CAP for pin in expected.values())
    assert sum(pin['bytes'] for pin in expected.values()) <= 256 * 1024 * 1024, 'declared total must fit before any indexed read'
    blobs, owners = {}, {}
    for name, pin in expected.items():
        q = Path(name)
        # Only explicit saved records, never archived executable products or live target.
        assert name in reviews or any(q.is_relative_to(d) and 'artifacts' not in q.relative_to(d).parts for d in roots)
        assert pin.keys() == {'sha256', 'bytes'} and re.fullmatch('[0-9a-f]{64}', pin['sha256'])
        blobs[name], owners[name] = read(q)
        assert len(blobs[name]) == pin['bytes'] and sha(blobs[name]) == pin['sha256']
    assert sum(map(len, blobs.values())) <= 256 * 1024 * 1024
    def raw(path):
        return blobs[str(path)]
    def obj(path):
        return loads(raw(path))
    roles = envelope['roles']
    assert 4 <= len(roles) <= 64 and len(set(roles.values())) == len(roles)
    assert roles['${REPO}'] == str(a.repo)
    assert all(len(k) <= 64 for k in roles), 'bounded role tokens before normalization'
    assert all(re.fullmatch(r'\$\{[A-Z][A-Z0-9_]*\}', k) and isinstance(v, str) and v.startswith('/') and len(v) > 1 for k, v in roles.items())
    tokens = re.compile('|'.join(re.escape(k) for k in roles))
    locations = re.compile('|'.join(re.escape(v) for v in sorted(roles.values(), key=len, reverse=True)))
    inverse = {v: k for k, v in roles.items()}
    def normalize(value):
        if isinstance(value, str):
            assert not tokens.search(value), 'literal role collision'
            result = locations.sub(lambda m: inverse[m[0]], value)
            assert tokens.sub(lambda m: roles[m[0]], result) == value
            return result
        if isinstance(value, list): return [normalize(v) for v in value]
        if isinstance(value, dict):
            result = {normalize(k): normalize(v) for k, v in value.items()}
            assert len(result) == len(value)
            return result
        return value
    reports, commands, stages, gates, inventories, artifacts = [], [], [], [], [], []
    for attempt in attempts:
        ident, revision = 'placement-build', attempt['revision']
        recipe_sha = attempt['recipe_sha256']
        base, launch = Path(attempt['raw']), Path(attempt['launch'])
        review = obj(attempt['review_binding'])
        assert review[attempt['review_revision_key']] == revision
        review_refs = Path(attempt['review_references'])
        assert review_refs.parent == Path(attempt['review_binding']).parent
        pin = review['files'][review_refs.name]
        assert pin['sha256'] == sha(raw(review_refs)) and pin['bytes'] == len(raw(review_refs))
        ref_map = {}
        for name, record in obj(review_refs).items():
            path = Path(name) if Path(name).is_absolute() else a.repo / name
            assert '..' not in path.parts and str(path) not in ref_map
            ref_map[str(path)] = record
        for name in blobs:
            if Path(name).is_relative_to(base) or Path(name).is_relative_to(launch):
                assert ref_map[name]['sha256'] == sha(blobs[name]) and ref_map[name]['bytes'] == len(blobs[name]), 'raw record is not bound by the selected independent review'
        summary, source = obj(base / 'summary.json'), obj(base / 'source.json')
        assert summary['revision'] == source['revision'] == revision
        assert source == obj(base / 'source-after.json')
        git_sources(a.repo, revision, source['files'], recipe_sha)
        source_digest = sha(json.dumps(source['files'], sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
        for kind in ('tools', 'configs'):
            assert obj(base / (kind + '.json')) == obj(base / (kind + '-after.json'))
        assert summary['planned_stages'] == obj(base / 'stage-inventory.json') == STAGES
        results = obj(base / 'results.json')
        assert 1 <= len(results) <= 12 and [r['name'] for r in results] == STAGES[:len(results)]
        assert summary['observed_stages'] == len(results) and summary['unrun_stages'] == STAGES[len(results):]
        assert type(summary['completed']) is bool
        assert review['verdict'] == ('CLOSED_BUILD_AND_STATIC_INVENTORIES_PASS_EXECUTION_RECORD_SCOPE' if summary['completed'] else 'FAILED_BUILD_RETAINED_NO_LATER_STAGE_CREDIT')
        assert review.get('findings') == [], 'unresolved independent review cannot publish'
        assert all(type(summary[k]) is int for k in ('observed_stages', 'cells_complete', 'rewriting_runs', 'native_application_runs'))
        assert summary['qualification_complete'] is summary['original_execution_credit'] is False
        assert summary['rewriting_runs'] == summary['native_application_runs'] == 0
        closed, launched = obj(launch / 'closed.json'), obj(launch / 'command.json')
        assert closed['parent_wait_returned'] is True and type(closed['exit']) is int
        assert launched['source_revision'] == revision and launched['recipe_sha256'] == recipe_sha
        assert launched['cwd'] == str(a.repo) and launched['inner_limits_unchanged'] is True
        args = launched['argv']; assert len(args) == 17 and args[1:3] == ['-B', str(a.repo / BUILD)]
        assert args[3::2] == ['--raw', '--toolchain', '--user-home', '--cargo-home', '--inputs', '--inputs-sha256', '--allocation-profile']
        assert args[16] == PROFILE_NAME
        assert args[4] == str(base) and args[14] == sha(raw(base / 'inputs.json'))
        build_inputs = obj(base / 'inputs.json')
        policy = obj(base / 'prospective-policy.json')
        assert policy == dict(limits=[1048576, 64, 256, 8388608, 2048, 16777216, 12582912, 512, 1073741824], search=[64, 256, 64, 256, 4096], allocation_profile=PROFILE_NAME, domain_start=65536, domain_bytes=1073741824, slot_bytes=65536, max_candidates=65536, carrier=536870912, cells=[[h, s, v] for h in ('null', 'journal') for s in ('jump-site', 'heap-write') for v in ('unstripped', 'stripped')], no_post_refusal_limit_change=True)
        assert launched['env'] == ENV
        toolchain, home, cargo_home = args[6], args[8], args[10]
        build_env = dict(ENV, HOME=home, CARGO_HOME=cargo_home, PATH=toolchain + '/bin:/usr/bin:/bin',
                         RUSTC=toolchain + '/bin/rustc', RUSTDOC=toolchain + '/bin/rustdoc',
                         RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='', CARGO_BUILD_JOBS='4',
                         CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true', CARGO_TARGET_DIR=str(a.repo / 'target'), RUST_TEST_THREADS='4')
        for k in ('stdout', 'stderr'): assert closed[k + '_sha256'] == sha(raw(launch / (k + '.txt')))
        seconds(closed['operational_seconds'])
        assert (closed['exit'] == 0) == summary['completed']
        commands.append(dict(attempt=ident, kind='launcher', command=launched,
                             result=closed, command_sha256=sha(raw(launch / 'command.json'))))
        failure_phase = None if summary['failure'] is None else summary['failure']['phase']
        assert (failure_phase is None) == summary['completed']
        assert failure_phase is None or failure_phase in STAGES[:min(len(results) + 1, 12)]
        for i, name in enumerate(STAGES):
            row = dict(attempt=ident, revision=revision, stage=name, status='UNRUN')
            if i >= len(results) and name == failure_phase:
                row['status'] = 'FAILED_BEFORE_RESULT'
            if i < len(results):
                r = results[i]; directory = base / name
                assert r == obj(directory / 'result.json')
                command = obj(directory / 'command.json')
                assert r == dict(command, exit=r['exit'], elapsed_seconds=r['elapsed_seconds'], parent_timeout=r['parent_timeout'])
                assert type(r['exit']) is int and type(r['parent_timeout']) is bool
                compiler = name in ('native-compile', 'common-sites-compile')
                assert r['cwd'] == str(a.repo) and r['env'] == dict(build_env if compiler or name == 'required' else ENV, TMPDIR=str(directory / 'tmp'))
                if name == 'required':
                    assert r['argv'] == [args[0], '-B', str(a.repo / 'evaluation/required-gates.py'), '--repo', str(a.repo), '--output', str(directory / 'gates')]
                    assert r['outer_argv'] == r['argv'] and r['outer_env'] == r['env'] and r['parent_timeout_seconds'] == 1000
                if compiler:
                    suffix = ['-p', 'liteinst2', '-p', 'liteinst-rewrite', '--bin', 'elf-exec-oracle', '--bin', 'liteinst-rewrite'] if name == 'native-compile' else ['-p', 'liteinst-rewrite', '--example', 'common_sites']
                    assert r['argv'] == [toolchain + '/bin/cargo', 'build', *suffix, '--offline', '--locked', '--message-format=json']
                row.update(exit=r['exit'], outer_seconds=seconds(r['elapsed_seconds']), result_sha256=sha(raw(directory / 'result.json')))
                row['status'] = 'FAILED_COMMAND' if r['exit'] != 0 or r['parent_timeout'] else ('FAILED_POSTCHECK' if name == failure_phase else 'PASS_RECORDED_STAGE')
                receipt = None
                if name != 'required':
                    request = obj(directory / 'request.json'); receipt = obj(directory / 'receipt.json')
                    assert request == r['request']
                    assert request == dict(argv=r['argv'], cwd=str(a.repo), env=r['env'], stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'), cpu_seconds=60 if compiler else 20, wall_seconds=90 if compiler else 30, file_bytes=(128 if compiler else 16) * 1024 * 1024)
                    assert r['outer_argv'] == ['/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', '100s' if compiler else '40s', '/usr/bin/python3.9', '-B', str(a.repo / 'tools/unwind-oracle/bounded_command.py'), '--request', str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
                    assert r['outer_env'] == ENV and r['parent_timeout_seconds'] == (115 if compiler else 55)
                    assert receipt.keys() == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout', 'unexpected_descendants', 'absence_proof', 'stdout_sha256', 'stderr_sha256', 'elapsed_seconds', 'cleanup_events', 'cleanup_error', 'aborted', 'inputs_unchanged'}
                    assert receipt['request_sha256'] == sha(raw(directory / 'request.json')) and receipt['helper_sha256'] == HELPER_SHA
                    assert type(receipt['exit']) is int and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
                    assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
                    assert receipt['cleanup_error'] is receipt['aborted'] is None
                    assert not r['parent_timeout'] and r['exit'] == (0 if receipt['exit'] == 0 else 1)
                    assert seconds(receipt['elapsed_seconds']) <= request['wall_seconds']
                    terminal = dict(exit=receipt['exit'], wall_timeout=False, absence_proof='ECHILD', descendants=0, success=receipt['exit'] == 0)
                    assert raw(directory / 'helper.stdout') == (json.dumps(terminal) + '\n').encode() and not raw(directory / 'helper.stderr')
                    for k in ('stdout', 'stderr'): assert receipt[k + '_sha256'] == sha(raw(directory / (k + '.txt')))
                    row.update(child_exit=receipt['exit'], helper_seconds=receipt['elapsed_seconds'], receipt_sha256=sha(raw(directory / 'receipt.json')))
                row.update(stdout_sha256=sha(raw(directory / 'stdout.txt')), stderr_sha256=sha(raw(directory / 'stderr.txt')))
                commands.append(dict(attempt=ident, kind='stage', name=name, command=command, result=r, receipt=receipt))
            stages.append(row)
        gate_record = obj(base / 'required/gates/commands.json')
        assert gate_record['head'] == revision and gate_record['tracked_diff_sha256'] == sha(b'')
        assert gate_record['source_sha256'] == {k: v['sha256'] for k, v in source['files'].items()}
        records = gate_record['records']; assert 1 <= len(records) <= 4
        assert all(x['exit'] == 0 for x in records[:-1])
        inherited = dict(results[0]['env'], CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_TARGET_DIR=str(a.repo / 'target'), RUST_TEST_THREADS='4', CARGO_NET_OFFLINE='true', TMPDIR=str(base / 'required/gates'))
        for i, (name, argv, timeout) in enumerate(GATES):
            row = dict(attempt=ident, revision=revision, gate=name, status='UNRUN', planned_argv=argv, timeout_seconds=timeout)
            if i < len(records):
                r = records[i]; assert r['name'] == name and r['argv'] == argv and r['timeout_seconds'] == timeout
                assert type(r['exit']) is int or r['exit'] == 'timeout'
                log = base / 'required/gates' / (name + '.log')
                assert a.repo / r['log'] == log and sha(raw(log)) == r['sha256']
                row.update(status='PASS' if r['exit'] == 0 else 'FAILED', exit=r['exit'], seconds=seconds(r['seconds']), log_sha256=r['sha256'])
                commands.append(dict(attempt=ident, kind='required-gate', name=name, record=r, cwd=str(a.repo), effective_env=inherited,
                                     env_provenance='Derived from saved parent env plus exact pinned required-gates.py overrides; not a captured /proc environment.'))
            gates.append(row)
        assert (results[0]['exit'] == 0) == (len(records) == 4 and all(r['exit'] == 0 for r in records))
        cells = obj(base / 'cells.json'); assert cells.keys() <= set(CELLS) and len(cells) == summary['cells_complete']
        tables, sites_by_style = None, {}
        for key in CELLS:
            stage_status = next(r['status'] for r in stages if r['stage'] == 'inventory-' + key)
            row = dict(attempt=ident, revision=revision, cell=key, status=stage_status if stage_status != 'PASS_RECORDED_STAGE' else 'NO_COMPLETED_INVENTORY', heads=None, sites=None)
            if key in cells:
                c = cells[key]; d = base / 'inventories' / key; run = base / ('inventory-' + key)
                assert c['directory'] == str(d) and c['run_directory'] == str(run)
                contents = {n: raw(d / n) for n in INVENTORY}
                names = sorted(INVENTORY - {'COMPLETE'})
                assert contents['COMPLETE'].decode().splitlines() == ['LI2COMMONFILES\t1'] + [f'{sha(contents[n])}\t{len(contents[n])}\t{n}' for n in names]
                assert obj(run / 'inventory-files.json') == {n: dict(sha256=sha(b), bytes=len(b)) for n, b in contents.items()}
                lines = contents['status.tsv'].decode().splitlines(); assert lines[0] == 'LI2COMMONRESULT\t1' and len(lines) == 12
                pairs = [line.split('\t') for line in lines[1:]]; status = dict(pairs); assert len(status) == len(pairs)
                hook, style, variant = key.split('-', 1)[0], ('jump-site' if '-jump-site-' in key else 'heap-write'), key.rsplit('-', 1)[1]
                heads, selected = contents['instructions.tsv'].count(b'\n') - 1, contents['sites.tsv'].count(b'\n') - 1
                assert heads == 87 and selected == (9 if style == 'jump-site' else 1) and status['instruction_heads'] == str(heads) and status['selected_sites'] == str(selected)
                assert status['complete_static_policy'] == 'true' and status['qualification_complete'] == 'false'
                assert status['hook'] == hook and status['style'] == style
                assert status['policy_sha256'] == sha(contents['policy.txt']) and status['target_sha256'] == sha(contents['target.txt'])
                assert status['selection_sha256'] == sha(contents['selection.txt']) and status['caller_provenance_sha256'] == sha(raw(c['provenance']))
                original = build_inputs['preparation']['originals'][variant]
                assert status['original_sha256'] == build_inputs['files'][original]['sha256']
                request = obj(run / 'request.json')
                assert request['argv'][1:] == [original, str(base / 'policies' / (variant + '.txt')), str(base / 'target/stdout.txt'), style, hook, str(d)]
                assert contents['policy.txt'] == raw(request['argv'][2]) and contents['target.txt'] == raw(base / 'target/stdout.txt')
                assert contents['policy.txt'].startswith(b'LI2COMMON 2\n')
                assert b'placement original-derived-v1 65536 1073741824\n' in contents['policy.txt']
                assert b'arena selected 65536 65536\n' in contents['policy.txt'] and b'arena victim 65536 65536\n' in contents['policy.txt']
                assert raw(run / 'stdout.txt') == f'common sites: heads={heads} selected={selected} style={style} hook={hook} complete_static_policy=true qualification_complete=false\n'.encode()
                assert not raw(run / 'stderr.txt')
                current = {n: contents[n] for n in ('instructions.tsv', 'memory-writes.tsv', 'blocks.tsv', 'padding.tsv', 'target.txt')}
                if tables is None: tables = current
                assert tables == current
                if style not in sites_by_style: sites_by_style[style] = contents['sites.tsv']
                assert sites_by_style[style] == contents['sites.tsv']
                row.update(status='COMPLETE_STATIC_POLICY_RECORDED', heads=heads, sites=selected, complete_sha256=sha(contents['COMPLETE']))
            inventories.append(row)
        archives = obj(base / 'artifacts.json'); assert archives.keys() <= {'native-compile', 'common-sites-compile'}
        for phase, archive in archives.items():
            assert archive == obj(base / phase / 'artifact-archive.json')
            assert archive['source_revision'] == revision
            assert archive['source_files_sha256'] == source_digest
            assert archive['cargo_stdout_sha256'] == sha(raw(base / phase / 'stdout.txt'))
            assert archive['command_result_sha256'] == sha(raw(base / phase / 'result.json'))
            for selected in archive['selected'].values():
                assert selected['product'] in archive['artifacts'].values() and selected['depfile'] in archive['artifacts'].values()
                assert all(source['files'][n] == v for n, v in selected['source_bindings'].items())
            messages = [loads(line) for line in raw(base / phase / 'stdout.txt').splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            assert sum(m.get('reason') == 'build-finished' for m in messages) == 1
            assert all(m.get('reason') in ('compiler-artifact', 'build-script-executed', 'build-finished') for m in messages)
            reported = {p for m in messages if m['reason'] == 'compiler-artifact' for p in m['filenames']}
            depfiles = set()
            expected_selected = {'elf-exec-oracle', 'liteinst-rewrite'} if phase == 'native-compile' else {'common_sites'}
            assert archive['selected'].keys() == expected_selected
            for name, selected in archive['selected'].items():
                cargo = selected['cargo']
                assert cargo in messages and cargo['target']['name'] == name
                assert cargo['profile'] == dict(opt_level='0', debuginfo=2, debug_assertions=True, overflow_checks=True, test=False)
                assert cargo['features'] == [] and cargo['executable'] in cargo['filenames']
                assert archive['artifacts'][cargo['executable']] == selected['product']
                dep = str(Path(cargo['executable']).with_suffix('.d')); depfiles.add(dep)
                assert archive['artifacts'][dep] == selected['depfile']
                assert str(Path(cargo['target']['src_path']).relative_to(a.repo)) in selected['source_bindings']
            assert archive['artifacts'].keys() == reported | depfiles
            for original_path, product in archive['artifacts'].items():
                assert re.fullmatch('[0-9a-f]{64}', product['sha256']) and type(product['bytes']) is int and product['bytes'] >= 0
                assert '..' not in Path(original_path).parts and '..' not in Path(product['path']).parts
                assert Path(original_path).is_relative_to(a.repo / 'target')
                assert Path(product['path']).is_relative_to(base / 'artifacts' / phase)
                retained = ref_map[product['path']]
                assert retained['sha256'] == product['sha256'] and retained['bytes'] == product['bytes']
                artifacts.append(dict(attempt=ident, revision=revision, phase=phase, reported_path=original_path, archive_path=product['path'], bytes=product['bytes'], sha256=product['sha256']))
        if 'native-compile' in archives and any(r['name'] == 'target' for r in results):
            assert obj(base / 'target/request.json')['argv'] == [archives['native-compile']['selected']['elf-exec-oracle']['product']['path'], 'target']
        if cells:
            common_sites = archives['common-sites-compile']['selected']['common_sites']['product']['path']
            assert all(obj(base / ('inventory-' + key) / 'request.json')['argv'][0] == common_sites for key in cells)
        assert summary['completed'] == (failure_phase is None and len(results) == 12 and len(cells) == 8 and all(r['exit'] == 0 and not r['parent_timeout'] for r in results))
        hardware = obj(base / 'hardware.json'); assert hardware['host_label'] == 'AMD EPYC Zen 5 dev host'
        reports.append(dict(id=ident, tested_revision=revision, summary=summary, hardware=hardware,
                            source_files=len(source['files']), source_map_sha256=source_digest,
                            selected_tools={k:dict(resolved=v['resolved'], sha256=v['sha256']) for k,v in obj(base / 'tools.json').items()},
                            script_hashes={n: source['files'][n]['sha256'] for n in (BUILD, 'evaluation/required-gates.py', 'tools/unwind-oracle/bounded_command.py')},
                            parent_closure_sha256=sha(raw(launch / 'closed.json')), independent_review_sha256=sha(raw(attempt['review_binding'])),
                            independent_review_references_sha256=sha(raw(review_refs)),
                            independent_review_verdict=review['verdict'], raw_summary_sha256=sha(raw(base / 'summary.json')),
                            raw_inputs_sha256=sha(raw(base / 'inputs.json')),
                            source_record_sha256=sha(raw(base / 'source.json')), tools_sha256=sha(raw(base / 'tools.json')),
                            configs_sha256=sha(raw(base / 'configs.json')), config_scope=obj(base / 'config-scope.json'),
                            archive_record_sha256=sha(raw(base / 'artifacts.json')), recorded_artifacts=sum(len(v['artifacts']) for v in archives.values())))
    test_counts = None
    passed_test = next(g for g in gates if g['gate'] == 'test')['status'] == 'PASS'
    assert (test_review is not None) == passed_test
    if test_review is not None:
        def review_member(binding, key):
            p = Path(test_review[key]); assert p.parent == Path(test_review['binding']).parent
            assert binding['files'][p.name] == dict(sha256=sha(raw(p)), bytes=len(raw(p)))
            return obj(p)
        log_binding = obj(test_review['binding'])
        assert log_binding['status'] == 'PASS_SAVED_TEST_LOG_ACCOUNTING_ONLY' and log_binding['revision'] == revision and log_binding['findings'] == []
        checks = review_member(log_binding, 'checks'); groups = review_member(log_binding, 'groups')
        assert checks['revision'] == revision and checks['raw_log_sha256'] == sha(raw(base / 'required/gates/test.log'))
        assert checks['findings'] == [] and checks['nested_passes_aggregated'] is False
        assert sha(raw(test_review['baseline_binding'])) == BASELINE_BINDING_SHA
        assert sha(raw(test_review['baseline_groups'])) == BASELINE_GROUPS_SHA
        baseline = obj(test_review['baseline_binding']); assert baseline['revision'] == BASELINE_REVISION
        assert baseline['files'][Path(test_review['baseline_groups']).name] == dict(sha256=BASELINE_GROUPS_SHA, bytes=len(raw(test_review['baseline_groups'])))
        def identities(items):
            result, counts = {}, [0] * 5
            assert len({g['identity'] for g in items}) == len(items)
            for g in items:
                c = g['summary'][1]; assert len(c) == 5 and all(type(v) is int and v >= 0 for v in c)
                counts = [a + b for a, b in zip(counts, c)]
                assert len(g['cases']) == c[0] + c[1] + c[2]
                statuses = [r['status'] for r in g['cases'].values()]
                assert all(v == 'ok' or v.startswith('ignored') for v in statuses)
                assert statuses.count('ok') == c[0] and sum(v.startswith('ignored') for v in statuses) == c[2] and c[1] == 0
                for name, row in g['cases'].items():
                    key = (g['identity'], name); assert key not in result
                    result[key] = row['status']
            return result, dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered_out'), counts))
        baseline_groups = obj(test_review['baseline_groups'])
        assert {g['identity'] for g in baseline_groups} <= {g['identity'] for g in groups}, 'all prior outer groups retained'
        old, old_counts = identities(baseline_groups)
        current, counts = identities(groups)
        assert len(old) == 1689 and old_counts == dict(passed=1685, failed=0, ignored=4, measured=0, filtered_out=0)
        assert all(current.get(k) == v for k, v in old.items()), 'every cbb outer identity/status retained'
        assert counts == checks['outer_counts'] == log_binding['outer_counts']
        assert counts['failed'] == counts['measured'] == counts['filtered_out'] == 0 and counts['ignored'] == 4
        assert len(groups) == checks['outer_groups'] == log_binding['outer_groups']
        assert len(current) == checks['outer_named_cases'] == log_binding['outer_named_cases']
        assert len(checks['nested_completed_summaries']) == log_binding['nested_completed_summaries']
        assert checks['child_starts_without_separate_terminal'] == log_binding['child_starts_without_separate_terminal']
        test_counts = dict(outer_groups=len(groups), outer_counts=counts, outer_named_cases=len(current), retained_cbb_cases=len(old), added_cases=[dict(group=k[0], name=k[1], status=current[k]) for k in sorted(current.keys()-old.keys())], nested_completed_summaries=checks['nested_completed_summaries'], child_starts_without_separate_terminal=checks['child_starts_without_separate_terminal'], nested_passes_aggregated=False, review_sha256=sha(raw(test_review['binding'])), complete_case_inventory_sha256=sha(raw(test_review['groups'])), baseline_revision=BASELINE_REVISION, baseline_inventory_sha256=BASELINE_GROUPS_SHA)
    public_summary = dict(schema=1, scope='Build/gate/static-inventory reporting only. Artifact bytes and full log/content validation remain in the separately identified independent reviews.',
                          collector_revision=collector_revision, collector_sha256=sha(self_before[0]), input_index_sha256=a.inputs_sha256,
                          allocation_profile=PROFILE_NAME, test_identity_retention=test_counts, operational_durations_are_benchmarks=False,
                          build=reports[0], qualification_complete=False, state_equivalence=False,
                          source_or_runtime_result_transfer=False, raw_logs_and_products_private=True,
                          command_inverse='Complete decoded objects under literal symbolic path roles. Original JSON key order is not preserved; raw file hashes bind original bytes.',
                          source_map_hash_semantics='SHA256 of sorted compact JSON path-to-{bytes,mode,sha256}, without a trailing newline; identical to the build archive source digest. Public source-files.json uses indented JSON and has its own whole-file hash.',
                          artifact_hash_scope='Copied from reviewed saved archive records; this collector does not reopen products, target files or binaries.')
    public = {'summary.json': encoded(normalize(public_summary)), 'commands.json': encoded(normalize(commands)),
              'source-files.json': encoded(source['files']),
              'stages.csv': csv_bytes(normalize(stages), ['attempt', 'revision', 'stage', 'status', 'exit', 'child_exit', 'outer_seconds', 'helper_seconds', 'result_sha256', 'receipt_sha256', 'stdout_sha256', 'stderr_sha256']),
              'gates.csv': csv_bytes(normalize(gates), ['attempt', 'revision', 'gate', 'status', 'exit', 'seconds', 'timeout_seconds', 'log_sha256']),
              'inventories.csv': csv_bytes(inventories, ['attempt', 'revision', 'cell', 'status', 'heads', 'sites', 'complete_sha256']),
              'artifacts.csv': csv_bytes(normalize(artifacts), ['attempt', 'revision', 'phase', 'reported_path', 'archive_path', 'bytes', 'sha256'])}
    assert isinstance(envelope['privacy_literals'], list) and envelope['privacy_literals'] and all(isinstance(s, str) and len(s) >= 3 for s in envelope['privacy_literals'])
    for content in public.values():
        text = content.decode()
        assert '/home/' not in text and '/data/users/' not in text
        assert not any(x in text for x in envelope['privacy_literals']), 'private username/host/path remains'
    public['files.json'] = encoded({n: dict(bytes=len(b), sha256=sha(b)) for n, b in public.items()})
    # Re-read every held record, collector and exact envelope before any output.
    for name, content in blobs.items(): assert read(name) == (content, owners[name])
    assert read(a.inputs) == index_before and read(self_path) == self_before
    assert git(a.repo, 'rev-parse', 'HEAD').decode().strip() == collector_revision and not git(a.repo, 'diff', '--binary', 'HEAD')
    private = dict(schema=1, authority='TRANSFORMATION_ONLY_NOT_INDEPENDENT_CONTENT_REVIEW', inputs_sha256=a.inputs_sha256,
                   roles=roles, read_records={n: dict(sha256=sha(b), bytes=len(b), owner=owners[n]) for n, b in blobs.items()},
                   collector=dict(revision=collector_revision, sha256=sha(self_before[0]), owner=self_before[1]), public_files=loads(public['files.json']))
    private_bytes = encoded(private)
    assert all(len(content) <= CAP for content in public.values()) and len(private_bytes) <= CAP, 'encoded per-file output limit'
    assert sum(map(len, public.values())) + len(private_bytes) <= 256 * 1024 * 1024, 'encoded aggregate output limit'
    a.new_output.mkdir(); (a.new_output / 'public').mkdir()
    for name, content in public.items():
        with (a.new_output / 'public' / name).open('xb') as stream: stream.write(content)
    with (a.new_output / 'private-binding.json').open('xb') as stream: stream.write(private_bytes)
    print('PASS closed placement-build reporting: one cohort; no new validation credit')


if __name__ == '__main__':
    main()
