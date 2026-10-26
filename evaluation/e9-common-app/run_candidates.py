#!/usr/bin/env python3
"""Run the fixed 192 ordinary candidate cases against audited original streams."""
import argparse
import collections
import csv
import hashlib
import io
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
ADAPTER_SHA = '794c6c12d43caac42a8ceb3e756bd05b075060dba44e79a9b7d9be9dc7cb7394'
PREPARED = 'ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05'
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
CAP = 128 * 1024 * 1024
DATASETS = ('empty', 'singleton', 'pair-reverse', 'equal-17', 'sorted-17', 'reverse-17', 'duplicates-17', 'mixed-64')
FUNCTIONS = ('li2_array_store', 'li2_sift_down', 'li2_heap_sort')
LANES = ('core', 'stock-algorithm', 'bootstrap-patched-reference')
INVENTORY_FILES = {'COMPLETE', 'instructions.tsv', 'sites.tsv', 'memory-writes.tsv', 'blocks.tsv', 'padding.tsv', 'policy.txt', 'target.txt', 'status.tsv', 'selection.txt'}
CELLS = [(h, s, v) for h in ('null', 'journal') for s in ('jump-site', 'heap-write') for v in ('unstripped', 'stripped')]
KEYS = ['-'.join(c) for c in CELLS]
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

def journal(pcs):
    assert type(pcs) is bytes and len(pcs) % 8 == 0 and len(pcs) // 8 <= 16384
    return (struct.pack('<8Q', 0x6c69326a6f75726e, 1, 16384, 0, len(pcs) // 8, 0, 0, 0)
            + pcs + bytes(131072 - len(pcs)) + struct.pack('<Q', 0x7265636f72647321))


def indexed(root, value, bound):
    assert type(value) is dict and value
    for name, row in value.items():
        rel = Path(name)
        assert not rel.is_absolute() and rel.parts and '..' not in rel.parts and str(rel) == name
        data = bound(str(root / rel))
        assert row['sha256'] == sha(data) and row['bytes'] == len(data)
        if 'stat' in row:
            assert row['stat'] == read(root / rel)[1]['stat']


def admitted(value, authority, scope, revision, bound):
    assert type(value['schema']) is int and value['schema'] == 1
    assert value['authority'] == authority and value['scope'] == scope
    assert value['source_revision'] == revision
    assert value['review_binding'] in value['evidence_files']
    assert len(set(value['evidence_files'])) == len(value['evidence_files']) >= 2
    for p in value['evidence_files']:
        bound(p)
    # This is an explicit caller admission backed by actual review records. A
    # command marker, supplied executable hash, or this recipe is not that review.


def build_inputs(build, tracked, repo, bound):
    admitted(build, 'CALLER_AUTHENTICATED_OBSERVER_BUILD', 'original-common-app-observer-build-only', tracked['revision'], bound)
    assert build['source_files_sha256'] == sha(encode(tracked['files']))
    root = path(build['directory'])
    summary = loads(bound(str(root / 'summary.json')))
    assert summary['revision'] == tracked['revision'] and summary['completed'] is True and summary['failure'] is None
    assert summary['observed_stages'] == len(summary['planned_stages']) == 12 and summary['cells_complete'] == 8
    assert summary['unrun_stages'] == [] and summary['qualification_complete'] is False
    assert bound(str(root / 'source.json')) == bound(str(root / 'source-after.json'))
    built = loads(bound(str(root / 'source.json')))
    assert built['revision'] == tracked['revision'] and built['files'] == tracked['files']
    archives = loads(bound(str(root / 'artifacts.json')))
    assert archives.keys() == {'native-compile', 'common-sites-compile'}
    products = {}
    for phase, archive in archives.items():
        assert loads(bound(str(root / phase / 'artifact-archive.json'))) == archive
        assert archive['source_revision'] == tracked['revision'] and archive['source_files_sha256'] == build['source_files_sha256']
        assert archive['command_result_sha256'] == sha(bound(str(root / phase / 'result.json')))
        assert archive['cargo_stdout_sha256'] == sha(bound(str(root / phase / 'stdout.txt')))
        for row in archive['artifacts'].values():
            assert sha(bound(row['path'])) == row['sha256'] and read(row['path'])[1]['stat'] == row['archive_owner']
        for name, selected in archive['selected'].items():
            assert all(tracked['files'][p] == row for p, row in selected['source_bindings'].items())
            assert sha(bound(selected['product']['path'])) == selected['product']['sha256']
            assert sha(bound(selected['depfile']['path'])) == selected['depfile']['sha256']
            assert selected['cargo']['profile'] == PROFILE and selected['cargo']['features'] == []
            products[name] = selected['product']['path']
    assert products.keys() == {'elf-exec-oracle', 'liteinst-rewrite', 'common_sites'}
    for name, phase, package, kind, source_path in (
        ('elf-exec-oracle', 'native-compile', '', 'bin', 'tests/support/elf_exec_driver.rs'),
        ('liteinst-rewrite', 'native-compile', 'tools/elf-rewrite', 'bin', 'tools/elf-rewrite/src/main.rs'),
        ('common_sites', 'common-sites-compile', 'tools/elf-rewrite', 'example', 'tools/elf-rewrite/examples/common_sites.rs')):
        archive = archives[phase]; selected = archive['selected'][name]; cargo = selected['cargo']
        assert selected['product'] in archive['artifacts'].values() and selected['depfile'] in archive['artifacts'].values()
        assert source_path in selected['source_bindings'] and path(selected['product']['path']).stat().st_mode & 0o111
        assert cargo['target']['name'] == name and cargo['target']['kind'] == [kind] and cargo['target']['crate_types'] == ['bin']
        assert cargo['target']['src_path'] == str(repo / source_path) and cargo['target']['edition'] == '2024'
        assert cargo['manifest_path'] == str(repo / package / 'Cargo.toml')
        package_name = 'liteinst2' if not package else 'liteinst-rewrite'
        assert cargo['package_id'] == 'path+' + (repo / package).as_uri() + '#' + package_name + '@0.1.0'
        assert archive['artifacts'][cargo['executable']] == selected['product'] and cargo['filenames'] == [cargo['executable']]
        messages = [loads(line) for line in bound(str(root / phase / 'stdout.txt')).splitlines()]
        assert messages.count(cargo) == 1 and messages[-1] == dict(reason='build-finished', success=True)
    assert products['elf-exec-oracle'] == build['driver'] and products['common_sites'] == build['common_sites']
    return root, products


def observed_streams(audit, tracked, build_root, cells, inv, datasets, bound):
    admitted(audit, 'CALLER_ADMITTED_ORIGINAL_OBSERVATION_CONTENT_AUDIT',
             'all-sixteen-original-capture-contents-and-ordered-pc-streams', tracked['revision'], bound)
    assert audit['build_directory'] == str(build_root) and audit['architectural_equivalence_claim'] is False
    assert audit['parent_closed_reaped'] is True and audit['parent_observation'] in audit['evidence_files']
    root = path(audit['directory'])
    saved_source = loads(bound(str(root / 'source.json')))
    assert saved_source['revision'] == tracked['revision'] and saved_source['files'] == tracked['files']
    assert loads(bound(str(root / 'after.json')))['source'] == saved_source
    summary = loads(bound(str(root / 'summary.json')))
    assert summary['revision'] == tracked['revision'] and summary['preparation_revision'] == PREPARED
    assert summary['completed'] is True and summary['fatal'] is None and summary['selected_owners_unchanged'] is True
    assert summary['planned_stages'] == summary['successful_observations'] == 16 and summary['unrun_stages'] == []
    assert summary['capture_content_audit_required'] is True, 'schema success is not the separate content admission'
    results = loads(bound(str(root / 'results.json')))
    expected_names = ['observe-' + v + '-' + d['name'] for v in ('unstripped', 'stripped') for d in datasets]
    assert set(results) == set(audit['cases']) == set(expected_names)
    assert loads(bound(str(root / 'stage-inventory.json'))) == expected_names
    observation_inputs = loads(bound(str(root / 'inputs.json')))
    observer_build = loads(bound(observation_inputs['build_admission']))
    assert observer_build['directory'] == str(build_root) and observer_build['source_revision'] == tracked['revision']
    assert loads(bound(str(build_root / 'cells.json'))) == cells
    streams = {}
    for variant in ('unstripped', 'stripped'):
        heads = inv['null-jump-site-' + variant]['instructions']
        for d in datasets:
            name = 'observe-' + variant + '-' + d['name']
            row, case = results[name], audit['cases'][name]
            assert row['status'] == 'PASS_COMMAND_AND_CAPTURE_SCHEMA' and row['strict_closure'] is True and row['exit'] == 0
            run = root / name; captures = run / 'captures'
            assert case.keys() == {'capture_directory', 'capture_files_sha256', 'jump_pcs_sha256', 'heap_pcs_sha256'}
            assert case['capture_directory'] == str(captures)
            index_bytes = bound(str(run / 'capture-files.json')); index = loads(index_bytes)
            assert sha(index_bytes) == case['capture_files_sha256'] and set(index) == {p.name for p in captures.iterdir()}
            for filename, owner in index.items():
                assert re.fullmatch('[A-Za-z0-9_.-]+', filename)
                bound(str(captures / filename))
                assert read(captures / filename)[1] == owner
            request = loads(bound(str(run / 'request.json')))
            for n in ('receipt.json', 'stdout.txt', 'stderr.txt'):
                bound(str(run / n))
            assert receipt(run, request)['exit'] == 0
            assert row['receipt_sha256'] == sha(bound(str(run / 'receipt.json')))
            assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (60, 90, 64 * 1024 * 1024)
            assert request['argv'][0] == observer_build['driver'] and request['argv'][1] == 'observe-common-app'
            assert request['argv'][-2:] == [d['name'], str(captures)]
            coverage = tsv(bound(str(captures / 'coverage.tsv')))
            assert len(coverage) == len(heads)
            for c, h in zip(coverage, heads):
                assert c.keys() == {'id', 'pc', 'jump_site', 'heap_write', 'visits'}
                assert all(c[k] == h[k] for k in ('id', 'pc', 'jump_site', 'heap_write'))
                assert re.fullmatch('[0-9]+', c['visits']), 'all zero-visit heads remain in the complete table'
            for style, stem, flag in (('jump-site', 'jump', 'jump_site'), ('heap-write', 'heap', 'heap_write')):
                data = bound(str(captures / (stem + '-pcs.bin')))
                assert sha(data) == case[stem + '_pcs_sha256'] and len(data) % 8 == 0
                counts = collections.Counter(x[0] for x in struct.iter_unpack('<Q', data))
                selected = {int(h['pc'], 0) for h in heads if h[flag] == 'true'}
                assert set(counts) <= selected
                assert {pc: counts[pc] for pc in selected} == {int(c['pc'], 0): int(c['visits']) for c in coverage if c[flag] == 'true'}
                # Preserve the complete audited order, including duplicate PCs.
                streams[(variant, d['name'], style)] = data
            assert bound(str(captures / 'stdout')) == d['expected_stdout'].encode() and not bound(str(captures / 'stderr'))
            assert bound(str(captures / 'journal.bin')) == journal(b'')
    return root, streams


def core_candidate(directory, inv, original, bound):
    index = bound(str(directory / 'bundle-index.tsv'))
    marker = bound(str(directory / 'COMPLETE')).decode().splitlines()
    assert len(marker) == 4 and marker[:2] == ['LI2TOOL-DIRECTORY 1', 'index_sha256 ' + sha(index)]
    assert marker[3] == 'qualification_complete false' and marker[2] in ('candidate_complete true', 'candidate_complete false')
    complete = marker[2] == 'candidate_complete true'
    lines = index.decode().splitlines()
    assert lines[:4] == ['LI2BUNDLE\t1', 'original_sha256\t' + sha(original), 'qualification_complete\tfalse', 'consumer_action\tRuntimeScan-while-gated-until-qualified']
    names = []
    for line in lines[4:]:
        tag, name, length, digest = line.split('\t')
        assert tag == 'file' and re.fullmatch('[A-Za-z0-9_.-]+', name) and name not in names
        data = bound(str(directory / name))
        assert len(data) == int(length) and sha(data) == digest
        names.append(name)
    assert set(names) | {'COMPLETE', 'bundle-index.tsv'} == {p.name for p in directory.iterdir()}
    assert ('candidate.elf' in names) == complete
    selection = bound(inv['directory'] + '/selection.txt')
    assert bound(str(directory / 'selection.txt')) == selection
    lines = bound(str(directory / 'report.tsv')).decode().splitlines()
    assert lines[:5] == ['LI2REPORT\t1', 'original_sha256\t' + sha(original), 'selection_sha256\t' + sha(selection),
                          'candidate_complete\t' + str(complete).lower(), 'qualification_complete\tfalse']
    rows = tsv(('\n'.join(lines[5:]) + '\n').encode())
    assert [(int(r['site']), int(r['pc']), int(r['file_offset']), int(r['length'])) for r in rows] == [
        (int(r['id']), int(r['pc'], 0), int(r['file_offset']), int(r['length'])) for r in inv['sites']]
    assert all(r['candidate_emitted'] == str(complete).lower() for r in rows)
    return dict(eligible=complete, candidate=str(directory / 'candidate.elf') if complete else None,
                reason='' if complete else 'core refused complete candidate; no executable artifact',
                source_report_sha256=sha(bound(str(directory / 'report.tsv'))), site_rows=rows)


def reference_candidate(directory, lane, cell_result, inv, original, bound):
    binding = loads(bound(str(directory / 'inventory/producer-binding.json')))
    wire = bound(str(directory / 'inventory/sites.tsv'))
    envelope_bytes = bound(str(directory / 'envelope.json')); envelope = loads(envelope_bytes)
    candidate = str(directory / 'candidate.elf'); image = bound(candidate)
    assert binding == cell_result['adapter'] and binding['lane'] == lane
    assert binding['scope'] == 'STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY'
    assert binding['qualification_complete'] is False and binding['architectural_equivalence_proved'] is False
    assert binding['runtime_executed_by_adapter'] is False and binding['transport_witness_is_patch_success'] is False
    assert binding['candidate_sha256'] == sha(image) and binding['site_inventory_sha256'] == sha(wire)
    assert binding['envelope_sha256'] == sha(envelope_bytes) and binding['input_files'] == envelope['files']
    for role, row in envelope['files'].items():
        data = bound(row['path'])
        assert row == dict(path=row['path'], sha256=sha(data), bytes=len(data))
    assert envelope['files']['candidate']['path'] == candidate and bound(envelope['files']['original']['path']) == original
    assert bound(envelope['files']['selection']['path']) == bound(inv['directory'] + '/selection.txt')
    lines = wire.decode().splitlines()
    policy = binding['policy']
    assert lines[:6] == ['LI2E9SITES\t1'] + [k + '\t' + policy[k] for k in ('original_sha256', 'selection_sha256', 'e9_revision', 'instrumentation', 'selection_style')]
    assert policy['original_sha256'] == sha(original) and policy['selection_sha256'] == sha(bound(inv['directory'] + '/selection.txt'))
    rows = tsv(('\n'.join(lines[6:]) + '\n').encode())
    assert binding['selected_sites'] == len(rows) == len(inv['sites'])
    assert type(binding['rpc_instruction_records']) is int and binding['rpc_instruction_records'] >= len(rows), 'RPC also retains unselected eviction context'
    assert policy['selection_style'] == inv['sites'][0]['style']
    assert [(int(r['site']), int(r['pc']), int(r['file_offset']), int(r['length'])) for r in rows] == [
        (int(r['id']), int(r['pc'], 0), int(r['file_offset']), int(r['length'])) for r in inv['sites']]
    assert all(r['outcome'] in ('trampoline', 'trap', 'refused') for r in rows)
    for r in rows:
        reason = loads(bytes.fromhex(r['reason_hex']))
        assert reason['classification'] == r['outcome']
        assert reason['backend_record'] in binding['outcomes']
        assert reason['backend_record']['pc'] == int(r['pc']) and reason['backend_record']['length'] == int(r['length'])
    return dict(eligible=True, candidate=candidate, reason='', adapter_sha256=sha(bound(str(directory / 'inventory/producer-binding.json'))),
                source_inventory_sha256=sha(wire), site_rows=rows,
                site_outcomes={kind: sum(r['outcome'] == kind for r in rows) for kind in ('trampoline', 'trap', 'refused')},
                comparison=cell_result.get('comparison'), production_cell_status=cell_result['status'])


def production_inputs(admission, tracked, products, inv, originals, bound):
    admitted(admission, 'CALLER_ADMITTED_COMMON_PRODUCTION_ARTIFACTS', 'closed-production-artifacts-only', tracked['revision'], bound)
    assert admission['parent_closed_reaped'] is True and admission['parent_observation'] in admission['evidence_files']
    root = path(admission['directory'])
    summary = loads(bound(str(root / 'summary.json')))
    assert summary['revision'] == tracked['revision'] and summary['fatal'] is None, 'unclean production closure is not an artifact admission'
    assert type(summary['successful']) is bool and summary['planned_stages'] == 74
    assert summary['ordinary_dataset_executions'] == summary['native_executions'] == 0 and summary['qualification_complete'] is False
    assert bound(str(root / 'source-before.json')) == bound(str(root / 'source-after.json'))
    assert loads(bound(str(root / 'source-before.json')))['files'] == tracked['files']
    index = loads(bound(str(root / 'raw-files.json'))); indexed(root, index, bound)
    inputs = loads(bound(str(root / 'inputs.json')))
    build = loads(bound(inputs['build_admission']))
    assert build['authority'] == 'CALLER_AUTHENTICATED_BUILD_PRODUCTS' and build['scope'] == 'core-cli-and-common-sites-build-only'
    assert build['source_revision'] == tracked['revision'] and build['source_files_sha256'] == sha(encode(tracked['files']))
    assert build['products'] == dict(core=products['liteinst-rewrite'], common_sites=products['common_sites'])
    for p in build['required_products'] + build['evidence_files']:
        bound(p)
    expected = []
    for i, key in enumerate(KEYS):
        if i == 4:
            expected += ['hook-compile', 'hook-link']
        expected += [key + '-core']
        expected += [key + '-' + lane + '-' + phase for lane in LANES[1:] for phase in ('transport', 'producer', 'adapter', 'compare')]
    results = loads(bound(str(root / 'results.json')))
    assert len(expected) == 74 and [r['name'] for r in results] == expected
    by_name = {r['name']: r for r in results}
    for row in results:
        assert row['status'] in ('PASS', 'FAILED', 'UNRUN')
        if row['status'] == 'UNRUN':
            continue
        d = root / row['name']; request = loads(bound(str(d / 'request.json')))
        for n in ('receipt.json', 'stdout.txt', 'stderr.txt'):
            bound(str(d / n))
        r = receipt(d, request)
        assert r['exit'] == row['exit'] and sha(bound(str(d / 'receipt.json'))) == row['receipt_sha256']
    assert summary['successful'] == all(r['status'] == 'PASS' for r in results)
    cells = loads(bound(str(root / 'cells.json')))
    assert set(cells) <= set(KEYS)
    artifacts = {}
    for key, (_, _, variant) in zip(KEYS, CELLS):
        for lane in LANES:
            name = key + '-' + lane
            result = dict(eligible=False, candidate=None, reason='artifact prerequisite unavailable; no replacement inventory')
            if key in cells:
                cell = cells[key]
                if lane == 'core' and cell['core'] is not None:
                    result = core_candidate(root / key / 'core', inv[key], originals[variant], bound)
                    assert cell['core']['complete'] == result['eligible']
                    assert by_name[key + '-core']['exit'] == (0 if result['eligible'] else 2)
                elif lane != 'core':
                    ref = cell['references'].get(lane, {})
                    if ref.get('adapter') is not None:
                        assert by_name[name + '-adapter']['status'] == 'PASS', 'actual successful adapter required'
                        assert by_name[name + '-transport']['status'] == by_name[name + '-producer']['status'] == 'PASS'
                        adapter_run = root / (name + '-adapter')
                        adapter_request = loads(bound(str(adapter_run / 'request.json')))
                        assert adapter_request['argv'] == [inputs['tools']['python'], '-B', str(Path(__file__).resolve().parents[2] / 'tools/elf-rewrite/e9-sites.py'), str(root / key / lane / 'envelope.json'), str(root / key / lane / 'inventory'), '--envelope-sha256', sha(bound(str(root / key / lane / 'envelope.json')))]
                        assert loads(bound(str(adapter_run / 'postcheck.json'))) == dict(pass_=True)
                        result = reference_candidate(root / key / lane, lane, ref, inv[key], originals[variant], bound)
                        # Comparator status is retained, never an eligibility gate.
                        result['comparison_stage'] = by_name[name + '-compare']
            artifacts[name] = result
    return root, summary, results, artifacts


def main():
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported; assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--raw', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo / 'evaluation/e9-common-app/run_candidates.py'
    raw = path(str(args.raw))
    assert raw.is_relative_to(repo / 'ignored') and not raw.exists() and not raw.is_symlink()
    input_bytes, input_owner = read(args.inputs)
    assert re.fullmatch('[0-9a-f]{64}', args.inputs_sha256) and sha(input_bytes) == args.inputs_sha256
    inputs = loads(input_bytes)
    assert inputs.keys() == {'schema', 'source_epoch', 'preparation', 'build_admission', 'observation_content_admission', 'production_admission', 'runtime_admission', 'tools', 'files'}
    assert type(inputs['schema']) is int and inputs['schema'] == 1
    watched = {str(args.inputs): input_owner}
    def bound(value):
        assert value in inputs['files'], 'every consumed input needs the caller-pinned hash, length and six-stat epoch'
        data, owner = read(value); expected = inputs['files'][value]
        assert expected.keys() == {'sha256', 'bytes', 'stat'} and type(expected['bytes']) is int
        assert type(expected['stat']) is list and len(expected['stat']) == 6 and all(type(x) is int for x in expected['stat'])
        assert expected == dict(sha256=sha(data), bytes=len(data), stat=owner['stat'])
        assert not path(value).is_relative_to(raw), 'inputs cannot live in the new output tree'
        if value in watched:
            assert watched[value] == owner, 'no implicit input owner refresh'
        watched[value] = owner
        return data
    for value in inputs['files']:
        bound(value)
    tools = inputs['tools']
    assert tools.keys() == {'python', 'helper_python', 'timeout', 'git'} and tools['git'] == '/usr/bin/git'
    assert str(Path(sys.executable).resolve(strict=True)) == tools['python']
    for value in tools.values():
        bound(value)
        assert path(value).stat().st_mode & 0o111
    tracked = source(repo)
    assert loads(bound(inputs['source_epoch'])) == tracked, 'explicit current source/owner epoch, not a private inherited source'
    assert 'evaluation/e9-common-app/run_candidates.py' in tracked['files']
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    assert sha(bound(str(helper))) == HELPER_SHA
    assert sha(bound(str(repo / 'tools/elf-rewrite/e9-sites.py'))) == ADAPTER_SHA
    prep = inputs['preparation']
    assert prep.keys() == {'summary', 'source', 'source_after', 'review_binding', 'originals'}
    ps = loads(bound(prep['summary']))
    assert ps['revision'] == PREPARED and ps['completed'] is True and ps['qualified'] is False
    assert (ps['planned_stages'], ps['observed_stages'], ps['ordinary_original_runs'], ps['required_refusals'], ps['rewriting_runs']) == (30, 30, 16, 6, 0)
    assert bound(prep['source']) == bound(prep['source_after'])
    old = loads(bound(prep['source'])); assert old['revision'] == PREPARED
    prefix = {p: h for p, h in old['files'].items() if p.startswith('evaluation/e9-common-app/')}
    assert len(prefix) == 17 and all(tracked['files'][p]['sha256'] == h for p, h in prefix.items())
    pr = loads(bound(prep['review_binding']))
    assert pr['revision'] == PREPARED and pr['verdict'] == 'CLOSED_ORIGINAL_PREPARATION_PASS_EXECUTION_RECORD_SCOPE'
    assert prep['originals'].keys() == {'unstripped', 'stripped'}
    originals = {v: bound(p) for v, p in prep['originals'].items()}
    assert all(ps['artifacts'][v] == dict(sha256=sha(b), bytes=len(b)) for v, b in originals.items())
    datasets = loads(bound(str(repo / 'evaluation/e9-common-app/datasets.json')))['datasets']
    assert [d['name'] for d in datasets] == list(DATASETS) and [d['id'] for d in datasets] == list(range(8))
    for d in datasets:
        assert d['expected'] == sorted(d['input']) and len(d['input']) <= 64
        assert bound(str(repo / 'evaluation/e9-common-app/expected' / (d['name'] + '.stdout'))) == d['expected_stdout'].encode()
    build = loads(bound(inputs['build_admission']))
    build_root, products = build_inputs(build, tracked, repo, bound)
    cells = loads(bound(str(build_root / 'cells.json')))
    inv = inventories(cells, originals, build['common_sites'], bound)
    audit = loads(bound(inputs['observation_content_admission']))
    observation_root, streams = observed_streams(audit, tracked, build_root, cells, inv, datasets, bound)
    production = loads(bound(inputs['production_admission']))
    production_root, production_summary, production_results, artifacts = production_inputs(production, tracked, products, inv, originals, bound)
    for old_root in (build_root, observation_root, production_root, Path(prep['summary']).parent):
        assert not raw.is_relative_to(old_root) and not old_root.is_relative_to(raw), 'separate new output owner'

    runtime = loads(bound(inputs['runtime_admission']))
    assert runtime.keys() == {'schema', 'authority', 'scope', 'source_revision', 'owners', 'interpreter_lookups', 'evidence_files'}
    assert type(runtime['schema']) is int and runtime['schema'] == 1
    assert runtime['authority'] == 'CALLER_PINNED_ORDINARY_RUNTIME_EPOCH' and runtime['source_revision'] == tracked['revision']
    assert runtime['scope'] == 'selected-interpreter-library-cache-owners-only-not-process-maps'
    assert 2 <= len(runtime['owners']) <= 32 and runtime['evidence_files']
    assert len({r['path'] for r in runtime['owners']}) == len(runtime['owners'])
    for p in runtime['evidence_files']:
        bound(p)
    for row in runtime['owners']:
        bound(row['path'])
        assert runtime_owner(row['path'])[0] == row
    runtime_paths = {r['path'] for r in runtime['owners']}
    assert '/etc/ld.so.cache' in runtime_paths, 'selected cache epoch is explicit; not a full loader/configuration closure'
    lookups = runtime['interpreter_lookups']
    assert type(lookups) is dict and lookups
    for name, row in lookups.items():
        assert row['path'] == name and lookup(name) == row and row['resolved'] in runtime_paths
    for image in list(originals.values()) + [bound(a['candidate']) for a in artifacts.values() if a['eligible']]:
        assert interpreter(image) in lookups

    def snapshot():
        for cell in cells.values():
            directory = path(cell['directory'])
            assert directory.resolve(strict=True) == directory and {p.name for p in directory.iterdir()} == INVENTORY_FILES
        return dict(owners={p: read(p)[1] for p in sorted(watched)}, source=source(repo),
                    runtime=[runtime_observation(r['path']) for r in runtime['owners']],
                    interpreter_lookups={n: lookup(n) for n in lookups})
    def stable(value):
        assert value['owners'] == watched and value['source'] == tracked, 'input/source/tool/copy drift: stop without refresh'
        assert [r['identity'] for r in value['runtime']] == runtime['owners'] and value['interpreter_lookups'] == lookups, 'selected runtime epoch drift'
    def freeze(p):
        value = str(p); owner = read(p)[1]
        if value in watched:
            assert watched[value] == owner
        watched[value] = owner
    baseline = snapshot(); stable(baseline)
    cases = [(key, h, s, v, lane, d) for key, (h, s, v) in zip(KEYS, CELLS) for lane in LANES for d in datasets]
    names = ['run-' + key + '-' + lane + '-' + d['name'] for key, _, _, _, lane, d in cases]
    assert len(names) == len(set(names)) == 192
    results = {n: dict(name=n, artifact=key + '-' + lane, hook=h, style=s, variant=v, lane=lane, dataset=d['name'], status='UNRUN', reason='not yet launched', launched=False, strict_closure=False) for n, (key, h, s, v, lane, d) in zip(names, cases)}
    raw.mkdir(mode=0o700); (raw / 'executables').mkdir(mode=0o700)
    write(raw / 'inputs.json', input_bytes); write(raw / 'source.json', tracked); write(raw / 'before.json', baseline)
    write(raw / 'hardware.json', dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(), cpu_model=next(r.split(':', 1)[1].strip() for r in Path('/proc/cpuinfo').read_text().splitlines() if r.startswith('model name')), kernel_release=platform.release(), logical_cpus=os.cpu_count(), libc=platform.libc_ver()))
    write(raw / 'stage-inventory.json', names)
    write(raw / 'artifact-prerequisites.json', artifacts)
    write(raw / 'production-status.json', dict(summary=production_summary, stages=production_results,
        note='Historical production status is retained even when an eligible independent reference runs.'))
    for p in raw.iterdir():
        if p.is_file():
            freeze(p)
    copies = {}; fatal = None; phase = None
    try:
        for name, (key, hook, style, variant, lane, dataset) in zip(names, cases):
            phase = name; artifact_name = key + '-' + lane; artifact = artifacts[artifact_name]
            row = results[name]
            row.update(artifact=artifact_name, hook=hook, style=style, variant=variant, lane=lane, dataset=dataset['name'])
            if not artifact['eligible']:
                row['reason'] = artifact['reason']; continue
            original_pcs = streams[(variant, dataset['name'], style)]
            row['original_pc_stream_sha256'] = sha(original_pcs)
            row['original_pc_stream_count'] = len(original_pcs) // 8
            pcs = original_pcs if hook == 'journal' else b''
            row['expected_record_count'] = len(pcs) // 8
            row['expected_pc_stream_sha256'] = sha(pcs)
            if len(pcs) // 8 > 16384:
                row['reason'] = 'full audited stream exceeds fixed journal capacity; no truncation or subset'; continue
            if artifact_name not in copies:
                stable(snapshot())
                original = path(artifact['candidate']); data, old_owner = read(original)
                assert old_owner == watched[str(original)], 'copy only the admitted immutable candidate'
                copied = raw / 'executables' / (artifact_name + '.elf')
                with os.fdopen(os.open(copied, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as out:
                    out.write(data)
                assert read(copied)[0] == data and read(original)[1] == old_owner
                before_mode = read(copied)[1]
                assert before_mode['stat'][:2] != old_owner['stat'][:2]
                os.chmod(copied, 0o500, follow_symlinks=False)
                image, copy_owner = read(copied)
                assert image == data and read(original)[1] == old_owner and stat.S_IMODE(copy_owner['stat'][2]) == 0o500
                copy_record = dict(source=old_owner, independent_copy=copy_owner, before_chmod=before_mode,
                    descriptor_provider=runtime_owner(str(copied))[0], source_bytes=len(data), source_sha256=sha(data))
                write(raw / 'executables' / (artifact_name + '.json'), copy_record)
                freeze(copied); freeze(raw / 'executables' / (artifact_name + '.json'))
                copies[artifact_name] = str(copied)
            directory = raw / name; directory.mkdir(); (directory / 'tmp').mkdir()
            output_journal = directory / 'journal.bin'
            assert not output_journal.exists() and not output_journal.is_symlink()
            request = dict(argv=[copies[artifact_name], dataset['name'], str(output_journal)], cwd=str(repo),
                env=dict(ENV, TMPDIR=str(directory / 'tmp')), cpu_seconds=20, wall_seconds=30, file_bytes=16 * 1024 * 1024,
                stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'))
            write(directory / 'request.json', request)
            outer = [tools['timeout'], '--signal=TERM', '--kill-after=10s', '40s', tools['helper_python'], '-B', str(helper), '--request', str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
            write(directory / 'command.json', dict(request=request, outer_argv=outer, outer_env=ENV, cwd=str(repo), parent_timeout_seconds=55))
            freeze(directory / 'request.json'); freeze(directory / 'command.json')
            before = snapshot(); write(directory / 'before.json', before); stable(before)
            row.update(status='FAILED', reason='launch/strict closure pending', launched=True)
            started = time.monotonic(); code = None; timed_out = False
            try:
                with (directory / 'helper.stdout').open('xb') as out, (directory / 'helper.stderr').open('xb') as err:
                    process = subprocess.Popen(outer, cwd=repo, env=ENV, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
                    try:
                        code = process.wait(timeout=55)
                    except subprocess.TimeoutExpired:
                        timed_out = True; os.killpg(process.pid, signal.SIGKILL); code = process.wait()
            finally:
                write(directory / 'outer.json', dict(exit=code, parent_timeout=timed_out, operational_seconds=time.monotonic() - started))
            after = snapshot(); write(directory / 'after.json', after); stable(after)
            assert not timed_out, 'parent backstop reached; no later case'
            r = receipt(directory, request)
            assert code == (0 if r['exit'] == 0 else 1)
            terminal = dict(exit=r['exit'], wall_timeout=False, absence_proof='ECHILD', descendants=0, success=r['exit'] == 0)
            assert read(directory / 'helper.stdout')[0] == (json.dumps(terminal) + '\n').encode() and not read(directory / 'helper.stderr')[0]
            row.update(strict_closure=True, exit=r['exit'], receipt_sha256=sha(read(directory / 'receipt.json')[0]))
            try:
                assert r['exit'] == 0, 'ordinary process exited nonzero'
                assert read(directory / 'stdout.txt')[0] == dataset['expected_stdout'].encode(), 'whole sorted stdout differs'
                assert not read(directory / 'stderr.txt')[0], 'ordinary stderr is nonempty'
                actual = read(output_journal)[0]; expected = journal(pcs)
                assert len(actual) == len(expected) == 131144 and actual == expected, 'complete journal/header/guards/ordered PCs/unused bytes differ'
                row.update(status='PASS_ORDINARY_OUTPUT_AND_JOURNAL', reason='', journal_sha256=sha(actual), journal_bytes=len(actual))
            except Exception as error:
                row.update(reason='ordinary output/journal failure: ' + repr(error))
            write(directory / 'result.json', row)
            for p in directory.iterdir():
                if p.name != 'tmp':
                    assert not p.is_symlink() and p.is_file(), 'unexpected case output owner'
                    freeze(p)
            print(name, row['status'], r['exit'], flush=True)
    except BaseException as error:
        fatal = dict(stage=phase, type=type(error).__name__, message=str(error))
        if phase is not None:
            results[phase].update(status='FAILED', reason='fatal closure/input/copy owner: ' + repr(error))
        for row in results.values():
            if row['status'] == 'UNRUN' and row['reason'] == 'not yet launched':
                row['reason'] = 'campaign stopped after fatal closure/input failure'
    finally:
        final_ok = False
        try:
            final = snapshot(); write(raw / 'after.json', final); stable(final)
            final_ok = True
        except BaseException as error:
            write(raw / 'closure-error.json', dict(type=type(error).__name__, message=str(error)))
        try:
            write(raw / 'source-after.json', source(repo))
        except BaseException as error:
            final_ok = False
            write(raw / 'source-after-error.json', dict(type=type(error).__name__, message=str(error)))
        write(raw / 'results.json', [results[n] for n in names])
        passed = sum(r['status'] == 'PASS_ORDINARY_OUTPUT_AND_JOURNAL' for r in results.values())
        ordinary_complete = final_ok and fatal is None and passed == 192
        successful = ordinary_complete and production_summary['successful']
        write(raw / 'summary.json', dict(schema=1, revision=tracked['revision'], preparation_revision=PREPARED,
            planned_cases=192, artifact_cells=24, datasets_per_artifact=8, passed_cases=passed,
            attempted_cases=sum(r['launched'] for r in results.values()), failed_cases=sum(r['status'] == 'FAILED' for r in results.values()),
            unrun_cases=[n for n, r in results.items() if r['status'] == 'UNRUN'], fatal=fatal, selected_owners_unchanged=final_ok,
            ordinary_cases_complete=ordinary_complete, production_successful=production_summary['successful'], successful=successful,
            qualification_complete=False, full_a3=False, architectural_equivalence=False, process_maps_attested=False,
            scope='Ordinary full-output and exact ordered journal only. Complete original selections retained. No state, performance or full loader closure claim.',
            parent_closed_reaped_authority='Separate caller observation required; never inferred by this recipe.',
            timings='Operational diagnostics only, not performance measurements'))
        index = {}
        for directory, dirs, files in os.walk(raw, followlinks=False):
            assert all(not (Path(directory) / n).is_symlink() for n in dirs + files)
            for n in files:
                p = Path(directory) / n; data, owner = read(p)
                index[str(p.relative_to(raw))] = dict(sha256=sha(data), bytes=len(data), stat=owner['stat'])
        write(raw / 'raw-files.json', index)
    return 0 if successful else 1


if __name__ == '__main__':
    raise SystemExit(main())
