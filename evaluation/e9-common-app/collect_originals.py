#!/usr/bin/env python3
"""Report the reviewed sixteen original observations; never execute an observer."""
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

SELF = 'evaluation/e9-common-app/collect_originals.py'
REVISION = 'b0d94f009196b4dea433ea2a5b267fa94f9512b0'
PREPARATION = 'ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05'
RECIPE = 'evaluation/e9-common-app/observe_originals.py'
RECIPE_SHA = '3edebec0e1444412c9bce4877f1690beeb4bb8b85fb8140584b817b6216da4f7'
OBSERVER_SHA = 'faec58111347cc1c0d41c0fa47862207ae8938f7b4caddad98b4afc3043699ae'
AUDITOR = 'evaluation/e9-common-app/audit_originals.py'
AUDITOR_SHA = 'dcb00d49359b5bb736602c2ddf28ec189c82e8b73f42adac1f7c9ff952c8c2ae'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
AUDIT_SHA = '2e4fdeb48f8e9e387d535794a547d331ac7d94c48c0b85f4e8db4d21f096ef99'
AUDIT_BINDING_SHA = '524a2fceb5fdf5df09be481b97a209513c64db5639363919e60a388280b51824'
REVIEW_SHA = '81b04b30d6b530eaba2df582ff07edfb9e09d5b0c5e931ab43afb183d02cfa11'
DATASETS = ['empty', 'singleton', 'pair-reverse', 'equal-17', 'sorted-17', 'reverse-17', 'duplicates-17', 'mixed-64']
NAMES = [f'observe-{variant}-{dataset}' for variant in ('unstripped', 'stripped') for dataset in DATASETS]
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
CAP = 64 * 1024 * 1024
LIVE_ONLY = [
    'Full RX mapping bytes, bytes read at each executed instruction PC, and the actual eight-byte breakpoint restoration were asserted live, not serialized.',
    'Intermediate complete registers, actual RSP, actual stack return words, and call argument register values were asserted live, not serialized.',
    'Recorded callee RSP and store register values are observer reports; this audit rechecks their saved arithmetic and stream relationships, not absent raw registers.',
    'Single-task membership and live proc-exe/FD/path identity checks are source-attested; saved provider/map records permit the joins reported separately.',
    'No architectural state equivalence, manual replay, rewritten/E9 execution, performance or full-A3 qualification follows.']


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
    assert a.new_output.is_absolute() and a.new_output.parent.resolve(strict=True) == a.new_output.parent
    assert a.new_output.is_relative_to(a.repo / 'ignored') and not a.new_output.exists() and not a.new_output.is_symlink()
    assert Path(__file__).absolute() == a.repo / SELF
    self_before = read(a.repo / SELF)
    reporter_revision = git(a.repo, 'rev-parse', 'HEAD').decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', reporter_revision)
    assert git(a.repo, 'show', reporter_revision + ':' + SELF) == self_before[0]
    assert not git(a.repo, 'diff', '--binary', 'HEAD'), 'clean tracked reporter checkout required'
    index_before = read(a.inputs)
    assert re.fullmatch('[0-9a-f]{64}', a.inputs_sha256) and sha(index_before[0]) == a.inputs_sha256
    envelope = loads(index_before[0])
    assert envelope.keys() == {'schema', 'authority', 'records', 'roles', 'privacy_literals', 'files'}
    assert type(envelope['schema']) is int and envelope['schema'] == 1
    assert envelope['authority'] == 'CALLER_SELECTED_REVIEWED_ORIGINAL_OBSERVATION_RECORDS'
    records = envelope['records']
    assert records.keys() == {'observations', 'recipe_launch', 'audit_output', 'audit_root', 'review'}
    roots = {k: Path(v) for k, v in records.items()}
    assert len(set(roots.values())) == 5
    for root in roots.values():
        assert root.is_absolute() and root.resolve(strict=True) == root and root.is_dir()
        assert root.is_relative_to(a.repo / 'ignored') and not a.new_output.is_relative_to(root)
    assert all(not x.is_relative_to(y) for x in roots.values() for y in roots.values() if x != y)
    expected = envelope['files']
    assert 1 <= len(expected) <= 1024
    assert all(pin.keys() == {'bytes', 'sha256'} and type(pin['bytes']) is int and 0 <= pin['bytes'] <= CAP and re.fullmatch('[0-9a-f]{64}', pin['sha256']) for pin in expected.values())
    assert sum(pin['bytes'] for pin in expected.values()) <= 128 * 1024 * 1024
    blobs, owners = {}, {}
    for name, pin in expected.items():
        q = Path(name)
        assert any(q.is_relative_to(root) for root in roots.values())
        assert q.suffix in ('.json', '.tsv', '.txt') or q.name in ('helper.stdout', 'helper.stderr'), 'saved reporting records only'
        assert 'artifacts' not in q.parts and 'target' not in q.parts, 'no product or target reads'
        if 'captures' in q.parts:
            assert q.name in ('coverage.tsv', 'observations.tsv', 'complete.tsv', 'budget.tsv')
        blobs[name], owners[name] = read(q)
        assert len(blobs[name]) == pin['bytes'] and sha(blobs[name]) == pin['sha256']
    def raw(path):
        return blobs[str(path)]
    def obj(path):
        return loads(raw(path))
    roles = envelope['roles']
    assert 6 <= len(roles) <= 32 and len(set(roles.values())) == len(roles)
    assert roles['${REPO}'] == str(a.repo)
    assert all(len(k) <= 64 and re.fullmatch(r'\$\{[A-Z][A-Z0-9_]*\}', k) and isinstance(v, str) and 1 < len(v) <= 4096 and v.startswith('/') for k, v in roles.items())
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
    base, launch, audit_dir, audit_root, review_dir = (roots[k] for k in ('observations', 'recipe_launch', 'audit_output', 'audit_root', 'review'))
    review = obj(review_dir / 'binding.json')
    assert sha(raw(review_dir / 'binding.json')) == REVIEW_SHA
    refs_bytes = raw(review_dir / 'references.json')
    assert review['files']['references.json'] == dict(bytes=len(refs_bytes), sha256=sha(refs_bytes))
    refs = loads(refs_bytes)
    assert len(refs) == review['reference_count'] == 3512
    assert review['verdict'] == 'CLOSED_ORIGINAL_OBSERVATIONS_AND_SAVED_CONTENT_PASS' and review['findings'] == []
    assert review['tested_revision'] == REVISION and review['source_files'] == 1512
    assert review['source_and_input_owner_drift'] is False
    for name, data in blobs.items():
        q = Path(name)
        if q.is_relative_to(review_dir):
            if q.name != 'binding.json':
                assert review['files'][q.name]['sha256'] == sha(data) and review['files'][q.name]['bytes'] == len(data)
        else:
            assert refs[name]['sha256'] == sha(data) and refs[name]['bytes'] == len(data), 'reporting record outside the closed review'
    audit, audit_binding = obj(audit_dir / 'audit.json'), obj(audit_dir / 'binding.json')
    assert sha(raw(audit_dir / 'audit.json')) == audit_binding['audit_sha256'] == review['audit_sha256'] == AUDIT_SHA
    assert sha(raw(audit_dir / 'binding.json')) == AUDIT_BINDING_SHA
    assert audit_binding['read_inputs_sha256'] == sha(raw(audit_dir / 'read-inputs.json'))
    assert audit_binding['inputs_sha256'] == review['audit_input_sha256']
    assert audit['status'] == audit_binding['status'] == review['audit_status'] == 'PASS_SAVED_CONTENT'
    assert audit['completed'] is audit_binding['completed'] is review['audit_completed'] is True
    assert audit['source_attested_not_independently_saved'] == audit_binding['source_attested_not_independently_saved'] == review['source_attested_not_independently_saved'] == LIVE_ONLY
    assert audit_binding['auditor_sha256'] == review['content_auditor_sha256'] == AUDITOR_SHA
    assert audit['recipe_sha256'] == RECIPE_SHA and audit['observer_source_sha256'] == OBSERVER_SHA
    assert audit['observation_revision'] == audit['build_revision'] == REVISION and audit['preparation_revision'] == PREPARATION
    assert audit['qualification_complete'] is audit['full_architectural_equivalence'] is False
    assert audit_binding['qualification_complete'] is review['qualification_complete'] is review['performance_claim'] is review['full_loader_or_configuration_closure'] is False
    assert review['rewritten_or_e9_execution_credit'] == 0 and review['old_failures_relabelled'] is False
    summary, source, hardware = (obj(base / n) for n in ('summary.json', 'source.json', 'hardware.json'))
    assert sha(raw(base / 'summary.json')) == audit['observation_summary_sha256']
    assert sha(raw(base / 'hardware.json')) == audit['hardware_sha256']
    assert hardware.keys() == {'architecture', 'cpu_model', 'host_label', 'kernel_release', 'libc', 'logical_cpus'}
    assert hardware['architecture'] == 'x86_64' and hardware['host_label'] == 'AMD EPYC Zen 5 dev host'
    assert summary['revision'] == source['revision'] == REVISION and summary['preparation_revision'] == PREPARATION
    assert summary['completed'] is summary['selected_owners_unchanged'] is True and summary['fatal'] is None
    assert summary['planned_stages'] == summary['successful_observations'] == audit['successful_content_cases'] == 16
    assert summary['unrun_stages'] == [] and summary['capture_content_audit_required'] is True
    assert summary['full_architectural_equivalence'] is summary['qualification_complete'] is False
    assert summary['rewritten_application_runs'] == summary['e9_application_runs'] == 0
    source_hash = sha(json.dumps(source['files'], sort_keys=True, separators=(',', ':')).encode())
    assert source_hash == audit['source_files_sha256'] and len(source['files']) == 1512
    tree = git(a.repo, 'ls-tree', '-rz', '--full-tree', REVISION).split(b'\0')[:-1]
    rows = []
    for line in tree:
        header, name = line.split(b'\t'); mode, kind, oid = header.decode().split()
        assert kind == 'blob' and mode in ('100644', '100755')
        rows.append((name.decode(), mode, oid))
    assert {n for n, _, _ in rows} == source['files'].keys()
    data = git(a.repo, 'cat-file', '--batch', data=''.join(oid + '\n' for _, _, oid in rows).encode()); at = 0
    for name, mode, oid in rows:
        end = data.index(b'\n', at); got, kind, size = data[at:end].decode().split(); size = int(size)
        assert (got, kind) == (oid, 'blob') and 0 <= size <= CAP
        body = data[end + 1:end + 1 + size]
        assert len(body) == size and data[end + 1 + size:end + 2 + size] == b'\n'
        assert hashlib.sha1(b'blob ' + str(size).encode() + b'\0' + body).hexdigest() == oid
        assert source['files'][name] == dict(bytes=size, mode=mode, sha256=sha(body))
        at = end + 2 + size
    assert at == len(data)
    for name, digest in ((RECIPE, RECIPE_SHA), (AUDITOR, AUDITOR_SHA), ('tests/support/e9_common_app.rs', OBSERVER_SHA), ('tools/unwind-oracle/bounded_command.py', HELPER_SHA)):
        assert source['files'][name]['sha256'] == digest
    commands, cases, coverage = [], [], []
    def helper_command(directory, label, kind, request, command, parent, outer_key):
        assert request.keys() == {'argv', 'cwd', 'env', 'cpu_seconds', 'wall_seconds', 'file_bytes', 'stdout', 'stderr'}
        assert request['cwd'] == str(a.repo) and request['stdout'] == str(directory / 'stdout.txt') and request['stderr'] == str(directory / 'stderr.txt')
        assert command['cwd'] == str(a.repo)
        want = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', str(request['wall_seconds'] + 10) + 's', '/usr/bin/python3.9', '-B', str(a.repo / 'tools/unwind-oracle/bounded_command.py'), '--request', str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
        assert command[outer_key] == want and command['parent_timeout_seconds'] == request['wall_seconds'] + 25
        receipt = obj(directory / 'receipt.json')
        assert receipt.keys() == set('request_sha256 helper_sha256 exit wall_timeout unexpected_descendants absence_proof stdout_sha256 stderr_sha256 elapsed_seconds cleanup_events cleanup_error aborted inputs_unchanged'.split())
        assert receipt['request_sha256'] == sha(raw(directory / 'request.json')) and receipt['helper_sha256'] == HELPER_SHA
        assert type(receipt['exit']) is int and receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
        assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == [] and receipt['aborted'] is receipt['cleanup_error'] is None
        assert 0 <= seconds(receipt['elapsed_seconds']) <= request['wall_seconds']
        assert parent['exit'] == 0 and parent['parent_timeout'] is False and 0 <= seconds(parent['operational_seconds']) <= command['parent_timeout_seconds']
        for stream in ('stdout', 'stderr'):
            assert receipt[stream + '_sha256'] == sha(raw(directory / (stream + '.txt'))) and len(raw(directory / (stream + '.txt'))) <= request['file_bytes']
        assert raw(directory / 'stderr.txt') == raw(directory / 'helper.stderr') == b''
        assert raw(directory / 'helper.stdout') == (json.dumps(dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)) + '\n').encode()
        commands.append(dict(name=label, kind=kind, request=request, command=command, parent=parent, receipt=receipt,
                             request_sha256=sha(raw(directory / 'request.json')), command_sha256=sha(raw(directory / 'command.json')), receipt_sha256=sha(raw(directory / 'receipt.json'))))
    launched, closed = obj(launch / 'command.json'), obj(launch / 'closed.json')
    assert launched['source_revision'] == REVISION and launched['recipe_sha256'] == RECIPE_SHA and launched['inner_limits_unchanged'] is True
    assert launched['cwd'] == str(a.repo) and launched['env'] == ENV
    assert len(launched['argv']) == 9 and launched['argv'][:3] == ['/usr/bin/python3.9', '-B', str(a.repo / RECIPE)]
    assert launched['argv'][3::2] == ['--inputs', '--inputs-sha256', '--raw'] and launched['argv'][8] == str(base)
    assert launched['argv'][6] == sha(raw(base / 'inputs.json'))
    observed_inputs = obj(base / 'inputs.json')
    assert observed_inputs['tools'] == dict(git='/usr/bin/git', python='/usr/bin/python3.9', helper_python='/usr/bin/python3.9', timeout='/usr/bin/timeout')
    assert closed['exit'] == review['original_recipe_parent_exit'] == 0 and closed['parent_wait_returned'] is review['original_recipe_parent_wait_returned'] is True
    assert closed['pid'] == review['original_recipe_parent_pid'] and seconds(closed['operational_seconds']) >= 0
    for stream in ('stdout', 'stderr'): assert closed[stream + '_sha256'] == sha(raw(launch / (stream + '.txt')))
    assert raw(launch / 'stderr.txt') == b''
    commands.append(dict(name='original-recipe-launch', kind='recipe-parent', command=launched, parent=closed,
                         command_sha256=sha(raw(launch / 'command.json')), parent_sha256=sha(raw(launch / 'closed.json'))))
    results = obj(base / 'results.json')
    assert obj(base / 'stage-inventory.json') == NAMES and set(results) == set(audit['cases']) == set(audit['recorded_recipe_results']) == set(NAMES)
    assert results == audit['recorded_recipe_results']
    head_identity = None
    driver = None
    for name in NAMES:
        directory, capture = base / name, base / name / 'captures'
        variant = name.split('-')[1]; dataset = name[len('observe-' + variant + '-'):]
        request, command, parent = (obj(directory / n) for n in ('request.json', 'command.json', 'outer.json'))
        assert request['cpu_seconds'] == 60 and request['wall_seconds'] == 90 and request['file_bytes'] == 67108864
        assert request['env'] == dict(ENV, TMPDIR=str(directory / 'tmp')) and command['outer_env'] == ENV and command['request'] == request
        assert len(request['argv']) == 10 and request['argv'][1] == 'observe-common-app' and request['argv'][8:] == [dataset, str(capture)]
        if driver is None: driver = request['argv'][0]
        assert request['argv'][0] == driver and driver in observed_inputs['files']
        helper_command(directory, name, 'original-observation', request, command, parent, 'outer_argv')
        case = audit['cases'][name]; result = obj(directory / 'result.json')
        assert result == results[name] == case['recipe_result'] and result['status'] == 'PASS_COMMAND_AND_CAPTURE_SCHEMA'
        assert result['exit'] == 0 and result['reason'] == '' and result['strict_closure'] is True
        assert result['receipt_sha256'] == case['receipt_sha256'] == sha(raw(directory / 'receipt.json'))
        assert case['status'] == 'PASS_SAVED_CONTENT' and case['static_heads'] == 87 and case['static_jump_sites'] == 9 and case['static_heap_sites'] == 1
        index = obj(directory / 'capture-files.json')
        assert len(index) == case['capture_files'] == result['capture_files'] == 57 and sha(raw(directory / 'capture-files.json')) == case['capture_index_sha256']
        for filename, owner in index.items():
            assert '/' not in filename and filename not in ('.', '..')
            assert owner['path'] == owner['resolved'] == str(capture / filename)
            assert owner['sha256'] == refs[owner['path']]['sha256'] and owner['stat'][3] == refs[owner['path']]['bytes']
        assert sha(raw(capture / 'coverage.tsv')) == index['coverage.tsv']['sha256'] == case['coverage_sha256']
        for filename, field in (('jump-pcs.bin', 'jump_stream_sha256'), ('heap-pcs.bin', 'heap_stream_sha256')):
            assert index[filename]['sha256'] == case[field]
        text = raw(capture / 'coverage.tsv').decode(); reader = csv.DictReader(io.StringIO(text), delimiter='\t')
        assert reader.fieldnames == ['id', 'pc', 'jump_site', 'heap_write', 'visits']
        current = list(reader); assert len(current) == 87 and [int(x['id']) for x in current] == list(range(1, 88))
        identity = [{k: row[k] for k in ('id', 'pc', 'jump_site', 'heap_write')} for row in current]
        if head_identity is None: head_identity = identity
        assert identity == head_identity
        for row in current:
            assert row['jump_site'] in ('true', 'false') and row['heap_write'] in ('true', 'false')
            assert re.fullmatch('[0-9]+', row['visits']) and int(row['visits']) >= 0 and int(row['pc'], 16) > 0
            coverage.append(dict(case=name, variant=variant, dataset=dataset, **row))
        assert sum(int(r['visits']) == 0 for r in current) == case['zero_visit_heads']
        assert sum(r['jump_site'] == 'true' for r in current) == 9 and sum(r['heap_write'] == 'true' for r in current) == 1
        assert sum(int(r['visits']) for r in current if r['jump_site'] == 'true') == case['jump_visits']
        assert sum(int(r['visits']) for r in current if r['heap_write'] == 'true') == case['store_calls']
        assert raw(capture / 'complete.tsv') == raw(capture / 'observations.tsv')
        pairs = [line.split('\t') for line in raw(capture / 'complete.tsv').decode().splitlines()]; complete = dict(pairs)
        assert len(complete) == len(pairs) and complete['status'] == 'passed' and complete['dataset'] == dataset
        assert complete['original_only'] == 'true' and complete['full_architectural_equivalence'] == 'false'
        for k in ('static_heads', 'static_jump_sites', 'static_heap_sites', 'steps', 'events', 'heap_calls', 'store_calls'): assert int(complete[k]) == case[k]
        budget = [line.split('\t') for line in raw(capture / 'budget.tsv').decode().splitlines()]
        assert [r[0] for r in budget] == ['n', 'sift_calls', 'sift_iterations', 'store_calls', 'per_head', 'derived_steps', 'hard_steps', 'wall_seconds', 'bridge_steps']
        assert all(len(r) == (4 if r[0] == 'per_head' else 2) for r in budget)
        numeric = {r[0]: int(r[1]) for r in budget if r[0] != 'per_head'}
        assert all(v >= 0 for v in numeric.values()) and numeric['n'] == [0, 1, 2, 17, 17, 17, 17, 64][DATASETS.index(dataset)]
        assert numeric['hard_steps'] == 1048576 and numeric['wall_seconds'] == 60 and numeric['bridge_steps'] == 128
        assert case['steps'] <= numeric['derived_steps'] <= numeric['hard_steps'] and case['store_calls'] <= numeric['store_calls']
        item = {k: v for k, v in case.items() if k != 'recipe_result'}
        for filename, field in (('stdout', 'original_stdout_sha256'), ('stderr', 'original_stderr_sha256'), ('journal.bin', 'journal_sha256'), ('events.bin', 'events_sha256'), ('all-pcs.bin', 'all_pcs_sha256')):
            item[field] = index[filename]['sha256']
        item.update(case=name, variant=variant, dataset=dataset, n=numeric['n'], derived_steps=numeric['derived_steps'], hard_steps=numeric['hard_steps'], observer_wall_seconds=numeric['wall_seconds'], bridge_steps=numeric['bridge_steps'], sift_calls_bound=numeric['sift_calls'], sift_iterations_bound=numeric['sift_iterations'], store_calls_bound=numeric['store_calls'], per_head_store_bound=int(budget[4][1]), per_head_sift_bound=int(budget[4][2]), per_head_sort_bound=int(budget[4][3]))
        cases.append(item)
    for label, cpu, wall, filecap in (('assembly', 30, 45, 16777216), ('audit', 60, 90, 67108864)):
        directory = audit_root / label
        request, command, parent = (obj(directory / n) for n in ('request.json', 'command.json', 'parent-closed.json'))
        assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (cpu, wall, filecap)
        assert request['env'] == command['env'] == ENV and command['request_sha256'] == sha(raw(directory / 'request.json'))
        assert parent['parent_wait_returned'] is True
        assert parent == review['assembly_and_audit_parent_closures'][label]['parent']
        assert sha(raw(directory / 'receipt.json')) == review['assembly_and_audit_parent_closures'][label]['receipt_sha256']
        if label == 'audit':
            assert request['argv'][:3] == ['/usr/bin/python3.9', '-B', str(a.repo / AUDITOR)] and len(request['argv']) == 9
            assert request['argv'][3::2] == ['--inputs', '--inputs-sha256', '--raw'] and request['argv'][6] == audit_binding['inputs_sha256'] and request['argv'][8] == str(audit_dir)
            assert raw(directory / 'stdout.txt') == (json.dumps(dict(status='PASS_SAVED_CONTENT', completed=True, audit_sha256=AUDIT_SHA), sort_keys=True) + '\n').encode()
        else:
            assert len(request['argv']) == 3 and request['argv'][:2] == ['/usr/bin/python3.9', '-B']
        helper_command(directory, 'saved-content-' + label, 'reporting-preparation' if label == 'assembly' else 'saved-content-audit', request, command, parent, 'argv')
    assert len(commands) == 19 and len(cases) == 16 and len(coverage) == 1392
    for key, reported in (('steps', 'saved_steps'), ('events', 'saved_events'), ('call_records', 'saved_call_records'), ('store_calls', 'saved_store_records'), ('jump_visits', 'saved_jump_visits'), ('capture_files', 'capture_files')):
        assert sum(row[key] for row in cases) == review[reported]
    normalized = normalize(commands)
    public_summary = dict(schema=1, scope='Reviewed original-observation streams and memory content; finite fixture only', tested_revision=REVISION,
        preparation_revision=PREPARATION, observer_origin_revision=audit['observer_origin_revision'], reporter_revision=reporter_revision,
        reporter_sha256=sha(self_before[0]), recipe_sha256=RECIPE_SHA, observer_sha256=OBSERVER_SHA, auditor_sha256=AUDITOR_SHA, helper_sha256=HELPER_SHA,
        observer_executable_sha256=observed_inputs['files'][driver]['sha256'], build_revision=audit['build_revision'],
        selected_tool_hashes={k: observed_inputs['files'][v]['sha256'] for k, v in observed_inputs['tools'].items()},
        saved_hardware=hardware, hardware_sha256=audit['hardware_sha256'], source_files_sha256=source_hash,
        mandatory_original_cases=16, static_heads_per_case=87, jump_sites_per_case=9, heap_sites_per_case=1, coverage_rows=1392,
        capture_files=912, command_rows=19, audit_status='PASS_SAVED_CONTENT', audit_sha256=AUDIT_SHA, audit_binding_sha256=AUDIT_BINDING_SHA,
        saved_stream_counts={k: sum(row[k] for row in cases) for k in ('steps', 'events', 'call_records', 'store_calls', 'jump_visits')},
        independent_review_sha256=REVIEW_SHA, review_reference_map_sha256=sha(refs_bytes), reviewed_reference_records=3512,
        reread_reporting_records=len(blobs), read_scope='Reporting records and coverage TSV only; selected whole capture bytes were independently authenticated by the bound prior audit/review.',
        successful_observations=16, failed_cases=[], unrun_cases=[], full_architectural_equivalence=False, rewritten_application_runs=0, e9_application_runs=0,
        performance_claim=False, qualification_complete=False, full_loader_or_configuration_closure=False,
        source_attested_not_independently_saved=LIVE_ONLY,
        timings='Per-command operational diagnostics only; no aggregate duration, throughput or performance inference.',
        parent_authority='Exact saved parent waits and strict helper receipts are distinct; this reporter creates no new execution authority.',
        historical_attempts='Earlier failures remain in their separate records; this exact successful cohort does not relabel or supersede them.')
    case_fields = ['case', 'variant', 'dataset'] + sorted(set(cases[0]) - {'case', 'variant', 'dataset'})
    command_rows = []
    for c in normalized:
        receipt = c.get('receipt')
        command_rows.append(dict(name=c['name'], kind=c['kind'], tested_revision=REVISION, exit=c['parent']['exit'], status='PASS',
            receipt_sha256=c.get('receipt_sha256'), request_sha256=c.get('request_sha256'), command_sha256=c['command_sha256'],
            cpu_seconds=c.get('request', {}).get('cpu_seconds'), wall_seconds=c.get('request', {}).get('wall_seconds'), file_bytes=c.get('request', {}).get('file_bytes'),
            operational_seconds=c['parent']['operational_seconds'], helper_seconds=None if receipt is None else receipt['elapsed_seconds']))
    public = {'summary.json': encoded(public_summary), 'cases.csv': csv_bytes(cases, case_fields),
              'coverage.csv': csv_bytes(coverage, ['case', 'variant', 'dataset', 'id', 'pc', 'jump_site', 'heap_write', 'visits']),
              'commands.json': encoded(normalized), 'commands.csv': csv_bytes(command_rows, list(command_rows[0])),
              'source-files.json': encoded(dict(revision=REVISION, files=source['files']))}
    public['files.json'] = encoded({n: dict(bytes=len(b), sha256=sha(b)) for n, b in public.items()})
    privacy = envelope['privacy_literals']
    assert isinstance(privacy, list) and 2 <= len(privacy) <= 64 and len(set(privacy)) == len(privacy)
    assert all(isinstance(s, str) and 3 <= len(s) <= 512 for s in privacy)
    for data in public.values():
        assert b'/home/' not in data and b'/Users/' not in data and b'facebook.com' not in data
        assert all(s.encode() not in data for s in privacy)
    private = encoded(dict(schema=1, input_index_sha256=a.inputs_sha256, input_index_owner=index_before[1], input_files=expected,
        current_record_owners=owners, private_roles=roles, privacy_literals=privacy, command_contexts=commands,
        normalized_command_contexts=normalized, reporter_revision=reporter_revision, reporter_sha256=sha(self_before[0]),
        reporter_invocation=dict(argv=sys.argv, cwd=str(Path.cwd())), public_files={n: dict(bytes=len(b), sha256=sha(b)) for n, b in public.items()},
        actual_reporter_parent_closure=None, scope='Deterministic reporting transform; caller must record and review this actual invocation separately.'))
    assert all(len(b) <= CAP for b in list(public.values()) + [private])
    assert sum(map(len, public.values())) + len(private) <= 256 * 1024 * 1024, 'encoded output bound before directory creation'
    for name, before in owners.items():
        data, now = read(name)
        assert data == blobs[name] and now == before, 'saved reporting input drift'
    assert read(a.inputs) == index_before and read(a.repo / SELF) == self_before
    assert git(a.repo, 'rev-parse', 'HEAD').decode().strip() == reporter_revision and not git(a.repo, 'diff', '--binary', 'HEAD')
    a.new_output.mkdir(mode=0o700); (a.new_output / 'public').mkdir(mode=0o700)
    for name, data in public.items():
        with (a.new_output / 'public' / name).open('xb') as stream: stream.write(data)
    with (a.new_output / 'private-binding.json').open('xb') as stream: stream.write(private)
    print(json.dumps(dict(status='REPORTED_REVIEWED_ORIGINALS', cases=16, coverage_rows=1392, commands=19, public_files=7), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
