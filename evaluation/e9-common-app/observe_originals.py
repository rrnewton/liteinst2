#!/usr/bin/env python3
"""Observe all sixteen original common-app cases; no rewrite/equivalence claim."""
import argparse
import csv
import io
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import stat
import struct
import subprocess
import sys
import time

HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
PREPARED = 'ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05'
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
CAP = 128 * 1024 * 1024
FILE_CAP = 64 * 1024 * 1024
DATASETS = ('empty', 'singleton', 'pair-reverse', 'equal-17', 'sorted-17', 'reverse-17', 'duplicates-17', 'mixed-64')
FUNCTIONS = ('li2_array_store', 'li2_sift_down', 'li2_heap_sort')
INVENTORY_FILES = {'COMPLETE', 'instructions.tsv', 'sites.tsv', 'memory-writes.tsv', 'blocks.tsv', 'padding.tsv', 'policy.txt', 'target.txt', 'status.tsv', 'selection.txt'}
PROFILE = dict(opt_level='0', debuginfo=2, debug_assertions=True, overflow_checks=True, test=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def loads(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, 'duplicate JSON key'
            value[key] = item
        return value
    def invalid(value):
        raise AssertionError('non-JSON constant ' + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def path(value):
    p = Path(value)
    assert p.is_absolute() and str(p) == value and '..' not in p.parts
    assert p.parent.resolve(strict=True) == p.parent, 'canonical parent required'
    return p


def read(value):
    p = path(str(value))
    six = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= CAP
        data = stream.read(CAP + 1)
        after = os.fstat(stream.fileno())
        assert six(before) == six(after) and len(data) == before.st_size
        assert six(p.lstat()) == six(after), 'path still owns the opened regular file'
    return data, dict(path=str(p), resolved=str(p.resolve(strict=True)), sha256=sha(data),
        stat=six(before))


def write(p, value):
    data = value if type(value) is bytes else json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b'\n'
    with path(str(p)).open('xb') as stream:
        stream.write(data)


def git(repo, *args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], timeout=15,
                                   env=ENV, stdin=subprocess.DEVNULL)


def source(repo):
    revision = git(repo, 'rev-parse', 'HEAD').decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', revision)
    assert git(repo, 'diff', 'HEAD', '--') == b'', 'clean tracked source required'
    rows, owners = {}, {}
    for item in git(repo, 'ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
        if not item:
            continue
        metadata, name = item.split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        name = name.decode()
        assert mode in ('100644', '100755') and kind == 'blob' and not Path(name).is_absolute()
        data, owner = read(repo / name)
        assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid
        assert bool(owner['stat'][2] & 0o111) == (mode == '100755')
        rows[name] = dict(sha256=sha(data), bytes=len(data), mode=mode)
        owners[name] = owner
    return dict(revision=revision, files=rows, owners=owners)


def fields(data, magic):
    lines = data.decode().splitlines()
    assert data.endswith(b'\n') and lines[0] == magic
    result = {}
    for line in lines[1:]:
        key, value = line.split('\t')
        assert key not in result
        result[key] = value
    return result


def tsv(data):
    assert data.endswith(b'\n')
    rows = list(csv.DictReader(io.StringIO(data.decode()), delimiter='\t'))
    assert rows and all(None not in r and all(v is not None for v in r.values()) for r in rows)
    return rows


def receipt(directory, request):
    assert request.keys() == {'argv', 'cwd', 'env', 'stdout', 'stderr', 'cpu_seconds', 'wall_seconds', 'file_bytes'}
    assert request['stdout'] == str(directory / 'stdout.txt') and request['stderr'] == str(directory / 'stderr.txt')
    assert type(request['env']) is dict and all(type(k) is str and type(v) is str for k, v in request['env'].items())
    assert all(type(request[k]) is int and request[k] > 0 for k in ('cpu_seconds', 'wall_seconds', 'file_bytes'))
    assert request['cpu_seconds'] <= 120 and request['wall_seconds'] <= 180 and request['file_bytes'] <= 256 * 1024 * 1024
    raw, _ = read(directory / 'receipt.json')
    r = loads(raw)
    assert r.keys() == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout', 'unexpected_descendants', 'absence_proof', 'stdout_sha256', 'stderr_sha256', 'elapsed_seconds', 'cleanup_events', 'cleanup_error', 'aborted', 'inputs_unchanged'}
    assert type(r['exit']) is int and r['request_sha256'] == sha(read(directory / 'request.json')[0]) and r['helper_sha256'] == HELPER_SHA
    assert r['wall_timeout'] is False and r['inputs_unchanged'] is True and r['absence_proof'] == 'ECHILD'
    assert r['unexpected_descendants'] == r['cleanup_events'] == [] and r['aborted'] is None and r['cleanup_error'] is None
    assert type(r['elapsed_seconds']) in (int, float) and math.isfinite(r['elapsed_seconds']) and 0 <= r['elapsed_seconds'] <= request['wall_seconds']
    for stream in ('stdout', 'stderr'):
        data = read(directory / (stream + '.txt'))[0]
        assert r[stream + '_sha256'] == sha(data) and len(data) <= request['file_bytes']
    return r


def proc_text(p, limit):
    with p.open('rb') as stream:
        data = stream.read(limit + 1)
    assert 0 < len(data) <= limit and data.endswith(b'\n') and b'\0' not in data
    return data.decode()


def provider(fdinfo, mountinfo, inode):
    assert len(fdinfo.encode()) <= 4096 and fdinfo.endswith('\n')
    def number(key):
        rows = [line[len(key):].strip() for line in fdinfo.splitlines() if line.startswith(key)]
        assert len(rows) == 1 and re.fullmatch('[0-9]+', rows[0])
        return int(rows[0])
    ident = number('mnt_id:')
    assert ident > 0 and number('ino:') == inode > 0
    assert len(mountinfo.encode()) <= 1024 * 1024 and mountinfo.endswith('\n')
    selected = []
    for line in mountinfo.splitlines():
        f = line.split()
        assert f and re.fullmatch('[0-9]+', f[0])
        if int(f[0]) != ident:
            continue
        assert len(f) >= 10 and f.count('-') == 1
        sep = f.index('-')
        assert sep >= 6 and sep + 4 == len(f) and re.fullmatch('[0-9]+', f[1]) and int(f[1]) > 0
        assert f[3].startswith('/') and f[4].startswith('/') and re.fullmatch('[0-9]+:[0-9]+', f[2])
        selected.append(dict(mount_id=ident, device=list(map(int, f[2].split(':'))), mount_record=line + '\n'))
    assert len(selected) == 1
    return selected[0]


def stat8(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns // 10**9,
            s.st_mtime_ns % 10**9, s.st_ctime_ns // 10**9, s.st_ctime_ns % 10**9]


def runtime_owner(value):
    p = path(value)
    assert p.resolve(strict=True) == p and value.isascii() and not any(c.isspace() for c in value)
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 16 * 1024 * 1024
        data = stream.read(16 * 1024 * 1024 + 1)
        observed = os.readlink(os.fsencode('/proc/self/fd/' + str(stream.fileno())))
        assert observed == os.fsencode(p), 'descriptor pathname must equal the admitted canonical path'
        fdinfo = proc_text(Path('/proc/self/fdinfo') / str(stream.fileno()), 4096)
        mountinfo = proc_text(Path('/proc/self/mountinfo'), 1024 * 1024)
        identity, pathname = stat8(os.fstat(stream.fileno())), stat8(p.stat())
        assert stat8(before) == identity == pathname and len(data) == before.st_size
    return dict(path=value, sha256=sha(data), bytes=len(data), descriptor_stat=identity,
                pathname_stat=pathname, observed_path_hex=observed.hex(),
                provider=provider(fdinfo, mountinfo, before.st_ino)), fdinfo


def runtime_observation(value):
    identity, fdinfo = runtime_owner(value)
    return dict(identity=identity, fdinfo=fdinfo)


def interpreter(data):
    assert len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', data, 16) == (2, 62, 1)
    assert struct.unpack_from('<HH', data, 52) == (64, 56)
    off, count = struct.unpack_from('<Q', data, 32)[0], struct.unpack_from('<H', data, 56)[0]
    assert 1 <= count <= 128 and off + 56 * count <= len(data)
    rows = [struct.unpack_from('<IIQQQQQQ', data, off + 56 * i) for i in range(count)]
    selected = [r for r in rows if r[0] == 3]
    assert len(selected) == 1
    r = selected[0]
    assert 1 < r[5] <= 4096 and r[2] + r[5] <= len(data)
    value = data[r[2]:r[2] + r[5]]
    assert value[-1:] == b'\0' and b'\0' not in value[:-1]
    return value[:-1].decode()


def lookup(value):
    p = Path(value)
    assert p.is_absolute() and '..' not in p.parts
    parts = []
    for i in range(2, len(p.parts) + 1):
        q = Path(*p.parts[:i])
        s = q.lstat()
        parts.append(dict(path=str(q), stat=stat8(s), link=os.readlink(q) if stat.S_ISLNK(s.st_mode) else None))
    return dict(path=value, resolved=str(p.resolve(strict=True)), components=parts)


def inventories(cells, originals, common_sites, bound):
    assert set(cells) == {'-'.join((h, s, v)) for h in ('null', 'journal') for s in ('jump-site', 'heap-write') for v in ('unstripped', 'stripped')}
    tables, styles, admitted = None, {}, {}
    for key, cell in cells.items():
        hook, style, variant = key.split('-', 1)[0], None, None
        for s in ('jump-site', 'heap-write'):
            for v in ('unstripped', 'stripped'):
                if key == '-'.join((hook, s, v)):
                    style, variant = s, v
        assert cell.keys() == {'directory', 'run_directory', 'provenance'}
        directory, run = path(cell['directory']), path(cell['run_directory'])
        assert directory.resolve(strict=True) == directory and {p.name for p in directory.iterdir()} == INVENTORY_FILES
        data = {n: bound(str(directory / n)) for n in INVENTORY_FILES}
        assert data['COMPLETE'].decode().splitlines() == ['LI2COMMONFILES\t1'] + [f'{sha(data[n])}\t{len(data[n])}\t{n}' for n in sorted(INVENTORY_FILES - {'COMPLETE'})]
        instructions, sites = tsv(data['instructions.tsv']), tsv(data['sites.tsv'])
        assert [int(r['id']) for r in instructions] == list(range(1, len(instructions) + 1))
        assert 0 < len(instructions) <= 4096 and 0 < len(sites) <= 64
        flag = 'jump_site' if style == 'jump-site' else 'heap_write'
        assert all(r[flag] in ('true', 'false') for r in instructions)
        selected = [r for r in instructions if r[flag] == 'true']
        assert sites == [{k: r[k] for k in ('id', 'pc', 'length', 'file_offset', 'function')} | dict(style=style) for r in selected]
        assert all(r['function'] in FUNCTIONS for r in instructions)
        selection = [r.split() for r in data['selection.txt'].decode().splitlines()]
        assert selection[0] == ['LI2TOOL', '1']
        sites_in_selection = [r for r in selection if r and r[0] == 'site']
        assert [(int(r[1]), int(r[2], 0), int(r[3]), int(r[4])) for r in sites_in_selection] == [(int(r['id']), int(r['pc'], 0), int(r['length']), int(r['file_offset'])) for r in sites]
        status = fields(data['status.tsv'], 'LI2COMMONRESULT\t1')
        assert status == dict(original_sha256=sha(originals[variant]), policy_sha256=sha(data['policy.txt']), caller_provenance_sha256=sha(bound(cell['provenance'])), target_sha256=sha(data['target.txt']), style=style, hook=hook, instruction_heads=str(len(instructions)), selected_sites=str(len(sites)), complete_static_policy='true', qualification_complete='false', selection_sha256=sha(data['selection.txt']))
        request = loads(bound(str(run / 'request.json')))
        assert len(request['argv']) == 7
        assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (20, 30, 16 * 1024 * 1024)
        assert request['argv'][0] == common_sites and request['argv'][4:] == [style, hook, str(directory)]
        assert bound(request['argv'][1]) == originals[variant]
        assert bound(request['argv'][2]) == data['policy.txt'] and bound(request['argv'][3]) == data['target.txt']
        for n in ('receipt.json', 'stdout.txt', 'stderr.txt'):
            bound(str(run / n))
        assert receipt(run, request)['exit'] == 0
        assert bound(str(run / 'stdout.txt')) == f'common sites: heads={len(instructions)} selected={len(sites)} style={style} hook={hook} complete_static_policy=true qualification_complete=false\n'.encode()
        assert not bound(str(run / 'stderr.txt'))
        current = {n: data[n] for n in ('instructions.tsv', 'memory-writes.tsv', 'blocks.tsv', 'padding.tsv', 'target.txt')}
        if tables is None:
            tables = current
        assert current == tables, 'no omitted heads/writers or changed target between eight cells'
        if style not in styles:
            styles[style] = data['sites.tsv']
        assert styles[style] == data['sites.tsv']
        admitted[key] = dict(directory=str(directory), instructions=instructions, sites=sites)
    return admitted


def capture_index(directory):
    if not directory.exists():
        return {}
    assert directory.resolve(strict=True) == directory
    paths = sorted(directory.iterdir())
    assert len(paths) <= 256 and all(p.is_file() and not p.is_symlink() for p in paths)
    result = {p.name: read(p)[1] for p in paths}
    assert all(r['stat'][3] <= FILE_CAP for r in result.values())
    return result


def owner_captures(directory, expected):
    # An owner mismatch is fatal even when an application already failed.
    for i, row in enumerate(expected):
        p = directory / f'owner-{i}.txt'
        if not p.exists():
            continue
        b = read(p)[0]
        first, second, length, rest = b.split(b'\n', 3)
        assert first == ('path_hex\t' + row['observed_path_hex']).encode()
        assert second.startswith(b'stat\t') and loads(second.split(b'\t', 1)[1]) == row['descriptor_stat']
        assert length.startswith(b'fdinfo_bytes\t')
        n = int(length.split(b'\t')[1]); fdinfo, rest = rest[:n], rest[n:]
        length, mount = rest.split(b'\n', 1)
        assert length.startswith(b'mount_record_bytes\t') and len(mount) == int(length.split(b'\t')[1])
        assert provider(fdinfo.decode(), mount.decode(), row['descriptor_stat'][1]) == row['provider']


def capture_schema(directory, dataset, inv, owners):
    def b(name):
        return read(directory / name)[0]
    assert b('inputs-unchanged') == b'complete\n'
    assert b('complete.tsv') == b('observations.tsv')
    row = fields(b('observations.tsv'), 'status\tpassed')
    assert row.keys() == {'dataset', 'static_heads', 'static_jump_sites', 'static_heap_sites', 'steps', 'events', 'heap_calls', 'store_calls', 'original_only', 'full_architectural_equivalence'}
    assert row['dataset'] == dataset['name'] and row['original_only'] == 'true' and row['full_architectural_equivalence'] == 'false'
    heads = inv['instructions']
    assert int(row['static_heads']) == len(heads) and int(row['static_jump_sites']) == sum(r['jump_site'] == 'true' for r in heads)
    assert int(row['static_heap_sites']) == sum(r['heap_write'] == 'true' for r in heads) == 1 and row['heap_calls'] == '1'
    assert all(re.fullmatch('[0-9]+', row[k]) for k in ('steps', 'events', 'store_calls'))
    assert 0 < int(row['steps']) <= 1_048_576 and 0 < int(row['events']) <= int(row['steps']) + 8
    assert len(b('all-pcs.bin')) == int(row['steps']) * 8 and len(b('events.bin')) == int(row['events']) * 40
    assert len(b('jump-pcs.bin')) % 8 == 0 and len(b('heap-pcs.bin')) == int(row['store_calls']) * 8
    coverage = tsv(b('coverage.tsv'))
    assert len(coverage) == len(heads)
    for observed, static in zip(coverage, heads):
        assert observed.keys() == {'id', 'pc', 'jump_site', 'heap_write', 'visits'}
        assert all(observed[k] == static[k] for k in ('id', 'pc', 'jump_site', 'heap_write'))
        assert re.fullmatch('[0-9]+', observed['visits']), 'zero-visit rows remain present'
    assert b('stdout') == dataset['expected_stdout'].encode() and not b('stderr')
    zero = struct.pack('<8Q', 0x6c69326a6f75726e, 1, 16384, 0, 0, 0, 0, 0) + bytes(16384 * 8) + struct.pack('<Q', 0x7265636f72647321)
    assert b('journal.bin') == zero
    assert all((directory / f'owner-{i}.txt').is_file() for i in range(len(owners)))
    return dict(static_heads=len(heads), static_jump_sites=int(row['static_jump_sites']), static_heap_sites=1,
                steps=int(row['steps']), events=int(row['events']), store_calls=int(row['store_calls']),
                zero_visit_heads=sum(r['visits'] == '0' for r in coverage), content_audit_required=True)


def main():
    assert not sys.flags.optimize, 'assertions required'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--raw', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo / 'evaluation/e9-common-app/observe_originals.py'
    raw = path(str(args.raw))
    assert raw.is_relative_to(repo / 'ignored') and not raw.exists() and not raw.is_symlink()
    input_bytes, input_owner = read(args.inputs)
    assert re.fullmatch('[0-9a-f]{64}', args.inputs_sha256) and sha(input_bytes) == args.inputs_sha256
    inputs = loads(input_bytes)
    assert inputs.keys() == {'schema', 'preparation', 'build_admission', 'runtime_admission', 'tools', 'files'}
    assert type(inputs['schema']) is int and inputs['schema'] == 1
    watched = {str(args.inputs): input_owner}
    def bound(value):
        assert value in inputs['files'], 'all consumed inputs must be caller-pinned'
        data, owner = read(value)
        row = inputs['files'][value]
        assert row.keys() == {'sha256', 'bytes'} and type(row['bytes']) is int
        assert row == dict(sha256=sha(data), bytes=len(data))
        if value in watched:
            assert watched[value] == owner, 'no implicit owner refresh'
        watched[value] = owner
        return data
    for value in inputs['files']:
        bound(value)
    tools = inputs['tools']
    assert tools.keys() == {'python', 'helper_python', 'timeout', 'git'} and tools['git'] == '/usr/bin/git'
    assert str(Path(sys.executable).resolve(strict=True)) == tools['python']
    for p in tools.values():
        bound(p)
        assert path(p).stat().st_mode & 0o111
    tracked = source(repo)
    assert 'evaluation/e9-common-app/observe_originals.py' in tracked['files']
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    assert sha(bound(str(helper))) == HELPER_SHA
    prep = inputs['preparation']
    assert prep.keys() == {'summary', 'source', 'source_after', 'review_binding', 'originals'}
    summary = loads(bound(prep['summary']))
    assert summary['revision'] == PREPARED and summary['completed'] is True and summary['qualified'] is False
    assert (summary['planned_stages'], summary['observed_stages'], summary['ordinary_original_runs'], summary['required_refusals'], summary['rewriting_runs']) == (30, 30, 16, 6, 0)
    assert bound(prep['source']) == bound(prep['source_after'])
    old_source = loads(bound(prep['source']))
    assert old_source['revision'] == PREPARED
    prepared_members = {p: h for p, h in old_source['files'].items() if p.startswith('evaluation/e9-common-app/')}
    assert len(prepared_members) == 17
    assert all(tracked['files'][p]['sha256'] == h for p, h in prepared_members.items()), 'all original preparation files remain literal'
    previous = loads(bound(prep['review_binding']))
    assert previous['verdict'] == 'CLOSED_ORIGINAL_PREPARATION_PASS_EXECUTION_RECORD_SCOPE' and previous['revision'] == PREPARED
    assert prep['originals'].keys() == {'unstripped', 'stripped'}
    originals = {v: bound(p) for v, p in prep['originals'].items()}
    assert all(summary['artifacts'][v] == dict(sha256=sha(b), bytes=len(b)) for v, b in originals.items())
    datasets = loads(bound(str(repo / 'evaluation/e9-common-app/datasets.json')))['datasets']
    assert [d['name'] for d in datasets] == list(DATASETS) and [d['id'] for d in datasets] == list(range(8))
    for d in datasets:
        assert d['expected'] == sorted(d['input']) and len(d['input']) <= 64
        assert bound(str(repo / 'evaluation/e9-common-app/expected' / (d['name'] + '.stdout'))) == d['expected_stdout'].encode()

    # The caller must authenticate the actual compiler/archive review. The
    # production admission of core/common_sites alone grants no driver authority.
    build = loads(bound(inputs['build_admission']))
    assert build.keys() == {'schema', 'authority', 'scope', 'source_revision', 'source_files_sha256', 'driver', 'common_sites', 'directory', 'review_binding', 'evidence_files'}
    assert type(build['schema']) is int and build['schema'] == 1 and build['authority'] == 'CALLER_AUTHENTICATED_OBSERVER_BUILD'
    assert build['scope'] == 'original-common-app-observer-build-only'
    assert build['source_revision'] == tracked['revision'] and build['source_files_sha256'] == sha(encode(tracked['files']))
    assert build['review_binding'] in build['evidence_files'] and len(set(build['evidence_files'])) == len(build['evidence_files']) >= 4
    for value in build['evidence_files']:
        bound(value)
    root = path(build['directory'])
    assert not raw.is_relative_to(root) and not raw.is_relative_to(Path(prep['summary']).parent), 'new run cannot be nested in prior evidence'
    build_summary = loads(bound(str(root / 'summary.json')))
    assert build_summary['revision'] == tracked['revision'] and build_summary['completed'] is True and build_summary['failure'] is None
    assert build_summary['observed_stages'] == len(build_summary['planned_stages']) == 12 and build_summary['cells_complete'] == 8
    assert build_summary['unrun_stages'] == [] and build_summary['qualification_complete'] is False
    assert bound(str(root / 'source.json')) == bound(str(root / 'source-after.json'))
    built_source = loads(bound(str(root / 'source.json')))
    assert built_source['revision'] == tracked['revision'] and built_source['files'] == tracked['files']
    archives = loads(bound(str(root / 'artifacts.json')))
    for name, archive in archives.items():
        assert bound(str(root / name / 'artifact-archive.json')) == (json.dumps(archive, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        assert archive['source_revision'] == tracked['revision'] and archive['source_files_sha256'] == build['source_files_sha256']
        assert archive['command_result_sha256'] == sha(bound(str(root / name / 'result.json')))
        assert archive['cargo_stdout_sha256'] == sha(bound(str(root / name / 'stdout.txt')))
        for row in archive['artifacts'].values():
            assert sha(bound(row['path'])) == row['sha256'] and read(row['path'])[1]['stat'] == row['archive_owner']
        for selected in archive['selected'].values():
            assert all(tracked['files'][p] == row for p, row in selected['source_bindings'].items())
    for name, phase, product, package, kind, source_path in (
        ('elf-exec-oracle', 'native-compile', build['driver'], '', 'bin', 'tests/support/elf_exec_driver.rs'),
        ('common_sites', 'common-sites-compile', build['common_sites'], 'tools/elf-rewrite', 'example', 'tools/elf-rewrite/examples/common_sites.rs')):
        selected = archives[phase]['selected'][name]
        assert selected['product']['path'] == product and source_path in selected['source_bindings']
        cargo = selected['cargo']
        assert cargo['target']['name'] == name and cargo['target']['kind'] == [kind] and cargo['target']['crate_types'] == ['bin']
        assert cargo['target']['src_path'] == str(repo / source_path) and cargo['target']['edition'] == '2024'
        assert cargo['manifest_path'] == str(repo / package / 'Cargo.toml') and cargo['profile'] == PROFILE and cargo['features'] == []
        package_name = 'liteinst2' if not package else 'liteinst-rewrite'
        assert cargo['package_id'] == 'path+' + (repo / package).as_uri() + '#' + package_name + '@0.1.0'
        assert sha(bound(product)) == selected['product']['sha256'] and path(product).stat().st_mode & 0o111
        bound(selected['depfile']['path'])
    layout_path = str(root / 'observer-layout.tsv')
    geometry = loads(bound(str(root / 'geometry.json')))
    layout = ['LI2COMMONOBSERVER\t1']
    for tag, names in (('function', FUNCTIONS + ('main',)), ('marker', ('li2_before_sort', 'li2_after_sort')), ('object', ('li2_run', 'li2_journal'))):
        for name in names:
            s = geometry['symbols'][name]
            layout.append(f"{tag}\t{name}\t0x{s['address']:x}\t{s['bytes']}")
    assert bound(layout_path) == ('\n'.join(layout + ['END']) + '\n').encode()
    for image in originals.values():
        for s in geometry['symbols'].values():
            assert s['bytes'] > 0 and s['file_offset'] + s['bytes'] <= len(image)
            assert sha(image[s['file_offset']:s['file_offset'] + s['bytes']]) == s['sha256']
    cells = loads(bound(str(root / 'cells.json')))
    inv = inventories(cells, originals, build['common_sites'], bound)

    runtime = loads(bound(inputs['runtime_admission']))
    assert runtime.keys() == {'schema', 'authority', 'source_revision', 'observer_sha256', 'variants', 'evidence_files', 'scope'}
    assert type(runtime['schema']) is int and runtime['schema'] == 1 and runtime['authority'] == 'CALLER_AUTHENTICATED_ORIGINAL_RUNTIME_OWNERS'
    assert runtime['scope'] == 'selected-original-interpreter-library-owners-only'
    assert runtime['source_revision'] == tracked['revision'] and runtime['observer_sha256'] == sha(bound(build['driver']))
    assert runtime['variants'].keys() == originals.keys() and runtime['evidence_files']
    for p in runtime['evidence_files']:
        bound(p)
    for variant, row in runtime['variants'].items():
        assert row.keys() == {'owners_file', 'owners', 'interpreter_lookup'} and 2 <= len(row['owners']) <= 16
        owners = row['owners']
        assert owners[0]['path'] == prep['originals'][variant]
        assert len({x['path'] for x in owners}) == len({tuple(x['descriptor_stat'][:2]) for x in owners}) == len(owners)
        owner_text = bound(row['owners_file'])
        assert len(owner_text) <= 65536 and owner_text == ('LI2COMMONOWNERS\t1\n' + ''.join(x['path'] + '\n' for x in owners)).encode()
        assert row['interpreter_lookup']['path'] == interpreter(originals[variant])
        assert lookup(row['interpreter_lookup']['path']) == row['interpreter_lookup']
        assert row['interpreter_lookup']['resolved'] in [x['path'] for x in owners[1:]]
        for expected in owners:
            assert expected.keys() == {'path', 'sha256', 'bytes', 'descriptor_stat', 'pathname_stat', 'observed_path_hex', 'provider'}
            assert type(expected['bytes']) is int and 0 < expected['bytes'] <= 16 * 1024 * 1024
            assert all(type(expected[k]) is list and len(expected[k]) == 8 and all(type(x) is int for x in expected[k]) for k in ('descriptor_stat', 'pathname_stat'))
            pro = expected['provider']
            assert pro.keys() == {'mount_id', 'device', 'mount_record'} and type(pro['mount_id']) is int and pro['mount_id'] > 0
            assert type(pro['device']) is list and len(pro['device']) == 2 and all(type(x) is int and x >= 0 for x in pro['device'])
            bound(expected['path'])
            observed, _ = runtime_owner(expected['path'])
            assert observed == expected, 'caller-pinned runtime descriptor/path/provider epoch'

    def snapshot():
        for cell in cells.values():
            directory = path(cell['directory'])
            assert directory.resolve(strict=True) == directory and {p.name for p in directory.iterdir()} == INVENTORY_FILES
        return dict(owners={p: read(p)[1] for p in sorted(watched)}, source=source(repo),
                    runtime={v: dict(owners=[runtime_observation(x['path']) for x in r['owners']], interpreter_lookup=lookup(r['interpreter_lookup']['path'])) for v, r in runtime['variants'].items()})
    def stable(value):
        assert value['owners'] == watched and value['source'] == tracked, 'source/input/tool drift; stop without refresh'
        for v, r in runtime['variants'].items():
            actual = value['runtime'][v]
            assert [x['identity'] for x in actual['owners']] == r['owners'] and actual['interpreter_lookup'] == r['interpreter_lookup'], 'runtime owner/provider/lookup drift; stop'
    def freeze(p):
        value = str(p)
        owner = read(p)[1]
        if value in watched:
            assert watched[value] == owner
        watched[value] = owner
    baseline = snapshot(); stable(baseline)
    raw.mkdir(mode=0o700)
    write(raw / 'inputs.json', input_bytes)
    write(raw / 'source.json', tracked)
    write(raw / 'before.json', baseline)
    write(raw / 'hardware.json', dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(), cpu_model=next(r.split(':', 1)[1].strip() for r in Path('/proc/cpuinfo').read_text().splitlines() if r.startswith('model name')), logical_cpus=os.cpu_count(), kernel_release=platform.release(), libc=platform.libc_ver()))
    cases = [(v, d) for v in ('unstripped', 'stripped') for d in datasets]
    names = ['observe-' + v + '-' + d['name'] for v, d in cases]
    assert len(names) == len(set(names)) == 16
    write(raw / 'stage-inventory.json', names)
    results = {n: dict(name=n, status='UNRUN', reason='not yet launched') for n in names}
    for p in raw.iterdir():
        freeze(p)
    fatal, phase = None, None
    try:
        for name, (variant, dataset) in zip(names, cases):
            phase = name
            directory = raw / name; directory.mkdir(); (directory / 'tmp').mkdir()
            captures = directory / 'captures'
            jump = inv['null-jump-site-' + variant]; heap = inv['null-heap-write-' + variant]
            argv = [build['driver'], 'observe-common-app', prep['originals'][variant], layout_path,
                    jump['directory'] + '/instructions.tsv', jump['directory'] + '/sites.tsv', heap['directory'] + '/sites.tsv',
                    runtime['variants'][variant]['owners_file'], dataset['name'], str(captures)]
            request = dict(argv=argv, cwd=str(repo), env=dict(ENV, TMPDIR=str(directory / 'tmp')), cpu_seconds=60, wall_seconds=90,
                           file_bytes=FILE_CAP, stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'))
            write(directory / 'request.json', request)
            outer = [tools['timeout'], '--signal=TERM', '--kill-after=10s', '100s', tools['helper_python'], '-B', str(helper), '--request', str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
            write(directory / 'command.json', dict(request=request, outer_argv=outer, outer_env=ENV, cwd=str(repo), parent_timeout_seconds=115))
            freeze(directory / 'request.json'); freeze(directory / 'command.json')
            before = snapshot(); write(directory / 'before.json', before); stable(before)
            results[name] = dict(name=name, status='FAILED', reason='launch/strict closure pending', strict_closure=False)
            started = time.monotonic(); code = None; timed_out = False
            try:
                with (directory / 'helper.stdout').open('xb') as out, (directory / 'helper.stderr').open('xb') as err:
                    process = subprocess.Popen(outer, cwd=repo, env=ENV, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
                    try:
                        code = process.wait(timeout=115)
                    except subprocess.TimeoutExpired:
                        timed_out = True; os.killpg(process.pid, signal.SIGKILL); code = process.wait()
            finally:
                write(directory / 'outer.json', dict(exit=code, parent_timeout=timed_out, operational_seconds=time.monotonic() - started))
            after = snapshot(); write(directory / 'after.json', after); stable(after)
            assert not timed_out, 'parent backstop; no subsequent case'
            r = receipt(directory, request)
            assert code == (0 if r['exit'] == 0 else 1), 'outer/helper exit mismatch'
            terminal = dict(exit=r['exit'], wall_timeout=False, absence_proof='ECHILD', descendants=0, success=r['exit'] == 0)
            assert read(directory / 'helper.stdout')[0] == (json.dumps(terminal) + '\n').encode() and not read(directory / 'helper.stderr')[0]
            results[name].update(strict_closure=True, exit=r['exit'], receipt_sha256=sha(read(directory / 'receipt.json')[0]), reason='observer exited nonzero')
            owner_captures(captures, runtime['variants'][variant]['owners'])
            index = capture_index(captures); write(directory / 'capture-files.json', index)
            if r['exit'] == 0:
                try:
                    assert read(directory / 'stdout.txt')[0] == f"PASS original common-app dataset={dataset['name']} complete static inventory and ordered jump/store observations\n".encode()
                    assert not read(directory / 'stderr.txt')[0]
                    detail = capture_schema(captures, dataset, jump, runtime['variants'][variant]['owners'])
                    write(directory / 'capture-schema.json', detail)
                    results[name].update(status='PASS_COMMAND_AND_CAPTURE_SCHEMA', reason='', capture_files=len(index))
                except Exception as error:
                    results[name].update(reason='output/schema: ' + repr(error))
            write(directory / 'result.json', results[name])
            for p in directory.iterdir():
                if p.is_file():
                    freeze(p)
            for p in captures.iterdir() if captures.exists() else []:
                freeze(p)
            print(name, results[name]['status'], r['exit'], flush=True)
    except BaseException as error:
        fatal = dict(stage=phase, type=type(error).__name__, message=str(error))
        if phase is not None and results[phase]['status'] != 'UNRUN':
            results[phase].update(status='FAILED', reason='fatal closure/ownership: ' + repr(error))
            # Preserve even a partial capture tree when strict closure or an
            # owner check fails. An unsafe/unreadable tree is recorded as such.
            if not (raw / phase / 'capture-files.json').exists():
                try:
                    write(raw / phase / 'capture-files.json', capture_index(raw / phase / 'captures'))
                except Exception as capture_error:
                    write(raw / phase / 'capture-index-error.json', dict(error=repr(capture_error)))
        raise
    finally:
        write(raw / 'results.json', results)
        final_ok = False
        try:
            after = snapshot(); write(raw / 'after.json', after); stable(after)
            final_ok = True
        except BaseException as error:
            write(raw / 'closure-error.json', dict(type=type(error).__name__, message=str(error)))
        passed = sum(r['status'] == 'PASS_COMMAND_AND_CAPTURE_SCHEMA' for r in results.values())
        complete = final_ok and fatal is None and passed == 16
        write(raw / 'summary.json', dict(schema=1, revision=tracked['revision'], preparation_revision=PREPARED,
            completed=complete, planned_stages=16, successful_observations=passed, fatal=fatal,
            unrun_stages=[n for n, r in results.items() if r['status'] == 'UNRUN'], selected_owners_unchanged=final_ok,
            parent_closed_reaped_authority='Separate caller observation required; this script does not infer it.',
            capture_content_audit_required=True, full_architectural_equivalence=False, rewritten_application_runs=0,
            e9_application_runs=0, qualification_complete=False,
            scope='Original application command/receipt and capture schema only; no state equivalence. Caller-selected runtime owners, not full loader/configuration closure.'))
    assert complete, 'all sixteen mandatory observations and final owners must pass'
    print('PASS sixteen original common-app command/capture schemas; independent capture-content audit required')


if __name__ == '__main__':
    main()
