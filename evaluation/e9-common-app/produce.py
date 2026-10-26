#!/usr/bin/env python3
"""Produce the fixed common corpus; never execute an application candidate."""
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
import signal
import stat
import struct
import subprocess
import sys
import time

HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
ADAPTER_SHA = '5904a13ec1fcb8b6801dcff12ac1fe5a1154b884555bbd9fbc24521f9bc6949f'
COMPARE_SHA = '797b396392ec3459a21a37f4a41b15a47b9f478dfe92c5d2cf436041d282876f'
PREPARED_REVISION = 'ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05'
REFERENCE = dict(reference_commit='0d5d36e4c4edcac37ca2499694d64302a391136f',
    reference_tree='b833c9dedd0aaaf8ed60ad1c041bd1535c55ccce',
    archive_sha256='b9d82420ee00a7240f574645c229d91fb993d1f24305258e3cdc294e6df44f0f',
    capstone_revision='e3f106739a6ae78d47772dff31062d644ea21078',
    abi_delta_patch_sha256='66bfd1bbef8fd9f33656a8956d21fbe5cba6c27b6ff034be0084db76bafd9e0d')
PRODUCTS = {
    'stock_frontend': '36b05e9a47c9193041d71ed4e14dda87e835e0e2b47e4a82a7d30a7c0d4eeb5e',
    'stock_backend': '890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb',
    'stock_loader': '4d39f324ab8a3a9420d2436129ba941e17fd78aa2c4e35eff3d27311e0683477',
    'transport_frontend': '0fea3c8bc0701dffeb16b524e7159e458be9add11bcf3df5f47b9714c1005acc',
    'abi_backend': '3750339187ffc4a084d075de77d1c653c255abd96e396870ea691b495f0c5453',
    'abi_loader': '126b6143c5668e4d390e0b9626824f5007b54d56e47a07bb72b415757b51773c'}
LANES = ('stock-algorithm', 'bootstrap-patched-reference')
FUNCTIONS = ('li2_array_store', 'li2_sift_down', 'li2_heap_sort')
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
CAP = 128 * 1024 * 1024
PAGE = 4096


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


def file_row(p):
    data, _ = read(p)
    return dict(path=str(p), sha256=sha(data), bytes=len(data))


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


def elf(data, kind):
    assert 64 <= len(data) <= 16 * 1024 * 1024
    assert data[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<HHI', data, 16) == (kind, 62, 1)
    phoff = struct.unpack_from('<Q', data, 32)[0]
    assert struct.unpack_from('<HH', data, 52) == (64, 56)
    count = struct.unpack_from('<H', data, 56)[0]
    assert 0 < count <= 128 and 64 <= phoff and phoff + 56 * count <= len(data)
    headers = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * 56) for i in range(count)]
    for tag, flags, off, va, _, fs, ms, align in headers:
        assert off + fs <= len(data) and va + ms < 1 << 47
        if tag == 1:
            assert fs <= ms and flags & ~7 == 0 and flags & 3 != 3
            assert align in (0, 1) or (align & (align - 1) == 0 and off % align == va % align)
    assert any(p[0] == 1 for p in headers)
    return headers


def sections(data):
    off = struct.unpack_from('<Q', data, 40)[0]
    width, count = struct.unpack_from('<HH', data, 58)
    assert width == 64 and 0 < count <= 4096 and off + width * count <= len(data)
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, off + i * width) for i in range(count)]
    assert all(row[1] == 8 or row[4] + row[5] <= len(data) for row in rows)
    return rows


def symbols(data, tag):
    sec = sections(data)
    tables = [r for r in sec if r[1] == tag]
    assert len(tables) == 1
    table = tables[0]
    assert table[9] == 24 and table[5] % 24 == 0 and table[6] < len(sec)
    strings = sec[table[6]]
    assert strings[1] == 3
    names = data[strings[4]:strings[4] + strings[5]]
    result = []
    for off in range(table[4], table[4] + table[5], 24):
        n, info, other, section, value, size = struct.unpack_from('<IBBHQQ', data, off)
        assert n < len(names) and b'\0' in names[n:]
        result.append(dict(name=names[n:].split(b'\0', 1)[0].decode('ascii'), info=info,
                           other=other, section=section, value=value, bytes=size))
    return result


def owned(data, headers, address, length, flags):
    owners = [p for p in headers if p[0] == 1 and p[3] <= address and address + length <= p[3] + p[5]]
    assert len(owners) == 1 and owners[0][1] == flags
    p = owners[0]
    off = p[2] + address - p[3]
    return off, data[off:off + length]


def original_pair(a, b):
    ha, hb = elf(a, 2), elf(b, 2)
    assert ha == hb and sum(p[0] == 3 for p in ha) == 1, 'ordinary dynamic-loader input'
    for p in ha:
        if p[0] != 1:
            continue
        x, y = bytearray(a[p[2]:p[2] + p[5]]), bytearray(b[p[2]:p[2] + p[5]])
        for position in list(range(40, 48)) + list(range(60, 64)):
            if p[2] <= position < p[2] + p[5]:
                x[position - p[2]] = y[position - p[2]] = 0
        assert x == y
    assert not any(s[1] == 2 for s in sections(b))
    syms = symbols(a, 2)
    journal = [s for s in syms if s['name'] == 'li2_journal']
    assert len(journal) == 1
    journal = journal[0]
    assert journal['value'] == 0x4040a0 and journal['bytes'] == 131144 and journal['info'] & 15 == 1
    expected = struct.pack('<8Q', 0x6c69326a6f75726e, 1, 16384, 0, 0, 0, 0, 0) + bytes(16384 * 8) + struct.pack('<Q', 0x7265636f72647321)
    assert owned(a, ha, journal['value'], journal['bytes'], 6)[1] == expected
    assert owned(b, hb, journal['value'], journal['bytes'], 6)[1] == expected
    return ha, syms, journal


def hook_elf(data, original_headers):
    headers = elf(data, 3)
    assert struct.unpack_from('<Q', data, 24)[0] == 0, 'pinned hook entry policy'
    sec = sections(data)
    assert all(s[5] == 0 for s in sec if s[1] in (4, 9)), 'no relocation sections'
    syms = symbols(data, 11)
    assert all(s['section'] != 0 or (s['name'] == '' and s['value'] == s['bytes'] == 0) for s in syms), 'no external symbols'
    assert not any(s['name'] in ('init', 'mmap') for s in syms), 'no custom loader hooks'
    selected = [s for s in syms if s['name'] == 'li2_e9_record']
    assert len(selected) == 1
    entry = selected[0]
    assert entry['info'] == 0x12 and entry['bytes'] > 0
    owned(data, headers, entry['value'], entry['bytes'], 5)
    dynamic = [s for s in sec if s[1] == 6]
    assert len(dynamic) == 1 and dynamic[0][9] == 16 and dynamic[0][5] % 16 == 0
    tags = [struct.unpack_from('<qQ', data, off) for off in range(dynamic[0][4], dynamic[0][4] + dynamic[0][5], 16)]
    assert any(tag == 0 for tag, _ in tags)
    assert all(tag not in (1, 12, 13, 25, 26, 32) for tag, _ in tags), 'no dependencies or init/fini arrays'
    assert all(value == 0 for tag, value in tags if tag in (2, 7, 8, 17, 18, 23, 35, 36)), 'no dynamic relocations'
    # e9tool.cpp: file_addr=elf.free_addr+0x1000000; then add eight pages and round up.
    base = (max(p[3] + p[6] for p in original_headers) + 0x1000000 + 8 * PAGE + PAGE - 1) // PAGE * PAGE
    loads = [p for p in headers if p[0] == 1]
    assert all(0 < p[6] <= 16 * 1024 * 1024 and base + p[3] + p[6] < 1 << 31 for p in loads)
    for i, p in enumerate(loads):
        lo, hi = (base + p[3]) // PAGE * PAGE, (base + p[3] + p[6] + PAGE - 1) // PAGE * PAGE
        assert all(hi <= q[3] // PAGE * PAGE or (q[3] + q[6] + PAGE - 1) // PAGE * PAGE <= lo for q in original_headers if q[0] == 1)
        assert all(p[3] + p[6] <= q[3] or q[3] + q[6] <= p[3] for q in loads[:i])
    return dict(symbol='li2_e9_record', base=base, entry=entry['value']), dict(headers=headers, dynamic=tags, symbols=syms, sha256=sha(data))


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


def inventory(directory, original, syms, style, hook, bound):
    names = {'policy.txt', 'target.txt', 'instructions.tsv', 'memory-writes.tsv', 'sites.tsv',
             'blocks.tsv', 'padding.tsv', 'status.tsv', 'selection.txt', 'COMPLETE'}
    assert directory.resolve(strict=True) == directory and {p.name for p in directory.iterdir()} == names
    data = {name: bound(str(directory / name)) for name in names}
    lines = data['COMPLETE'].decode().splitlines()
    assert lines[0] == 'LI2COMMONFILES\t1'
    assert lines[1:] == [f'{sha(data[n])}\t{len(data[n])}\t{n}' for n in sorted(names - {'COMPLETE'})]
    status = fields(data['status.tsv'], 'LI2COMMONRESULT\t1')
    assert status.keys() == {'original_sha256', 'policy_sha256', 'caller_provenance_sha256', 'target_sha256', 'style', 'hook', 'instruction_heads', 'selected_sites', 'complete_static_policy', 'qualification_complete', 'selection_sha256'}
    assert (status['style'], status['hook'], status['complete_static_policy'], status['qualification_complete']) == (style, hook, 'true', 'false')
    assert status['original_sha256'] == sha(original) and status['policy_sha256'] == sha(data['policy.txt'])
    assert status['target_sha256'] == sha(data['target.txt']) and status['selection_sha256'] == sha(data['selection.txt'])
    policy = [line.split() for line in data['policy.txt'].decode().splitlines()]
    assert policy[0] == ['LI2COMMON', '1'] and policy[1] == ['original', sha(original)]
    assert policy[2] == ['target', sha(data['target.txt'])] and policy[3] == ['provenance', status['caller_provenance_sha256']]
    functions = [r for r in policy if r[0] == 'function']
    assert [r[1] for r in functions] == list(FUNCTIONS)
    headers = elf(original, 2)
    ranges = []
    for row in functions:
        assert len(row) == 5
        name, address, length, digest = row[1], int(row[2], 0), int(row[3], 0), row[4]
        symbol = [s for s in syms if s['name'] == name]
        assert len(symbol) == 1 and (symbol[0]['value'], symbol[0]['bytes']) == (address, length)
        assert sha(owned(original, headers, address, length, 5)[1]) == digest
        ranges.append((address, address + length))
    instructions, sites = tsv(data['instructions.tsv']), tsv(data['sites.tsv'])
    assert len(instructions) == int(status['instruction_heads']) and 0 < len(instructions) <= 4096
    assert len(sites) == int(status['selected_sites']) and 0 < len(sites) <= 1024
    assert [int(r['id']) for r in instructions] == list(range(1, len(instructions) + 1))
    for name, (begin, end) in zip(FUNCTIONS, ranges):
        members = [r for r in instructions if r['function'] == name]
        cursor = begin
        for r in members:
            pc, length, off = int(r['pc'], 0), int(r['length']), int(r['file_offset'])
            assert pc == cursor and 1 <= length <= 15
            actual_off, actual = owned(original, headers, pc, length, 5)
            assert actual_off == off and actual.hex() == r['bytes']
            cursor += length
        assert cursor == end
    assert all(r['function'] in FUNCTIONS for r in instructions)
    flag = 'jump_site' if style == 'jump-site' else 'heap_write'
    assert all(r[flag] in ('true', 'false') for r in instructions)
    expected = [r for r in instructions if r[flag] == 'true']
    assert [int(r['id']) for r in sites] == [int(r['id']) for r in expected]
    for a, b in zip(sites, expected):
        assert all(a[k] == b[k] for k in ('id', 'pc', 'length', 'file_offset', 'function')) and a['style'] == style
    selection = [r.split() for r in data['selection.txt'].decode().splitlines() if r]
    selected = [r for r in selection if r[0] == 'site']
    assert len(selected) == len(sites)
    assert [(int(r[1], 0), int(r[2], 0), int(r[3], 0), int(r[4], 0)) for r in selected] == [
        (int(r['id']), int(r['pc'], 0), int(r['length']), int(r['file_offset'])) for r in sites]
    return dict(sites=sites, status=status, ranges=ranges, data=data)


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


def core_product(directory, inv, original):
    marker = read(directory / 'COMPLETE')[0].decode().splitlines()
    assert len(marker) == 4 and marker[0] == 'LI2TOOL-DIRECTORY 1'
    index = read(directory / 'bundle-index.tsv')[0]
    assert marker[1] == 'index_sha256 ' + sha(index) and marker[3] == 'qualification_complete false'
    assert marker[2] in ('candidate_complete true', 'candidate_complete false')
    complete = marker[2].endswith('true')
    rows = index.decode().splitlines()
    assert rows[:4] == ['LI2BUNDLE\t1', 'original_sha256\t' + sha(original), 'qualification_complete\tfalse', 'consumer_action\tRuntimeScan-while-gated-until-qualified']
    names = []
    for line in rows[4:]:
        tag, name, length, digest = line.split('\t')
        assert tag == 'file' and re.fullmatch('[A-Za-z0-9_.-]+', name) and name not in names
        data, _ = read(directory / name)
        assert len(data) == int(length) and sha(data) == digest
        names.append(name)
    assert set(names) | {'bundle-index.tsv', 'COMPLETE'} == {p.name for p in directory.iterdir()}
    assert read(directory / 'selection.txt')[0] == inv['data']['selection.txt']
    assert ('candidate.elf' in names) == complete
    text = read(directory / 'report.tsv')[0].decode().splitlines()
    assert text[:5] == ['LI2REPORT\t1', 'original_sha256\t' + sha(original),
        'selection_sha256\t' + sha(inv['data']['selection.txt']), 'candidate_complete\t' + str(complete).lower(), 'qualification_complete\tfalse']
    rows = tsv(('\n'.join(text[5:]) + '\n').encode())
    assert [(int(r['site']), int(r['pc']), int(r['length']), int(r['file_offset'])) for r in rows] == [
        (int(r['id']), int(r['pc'], 0), int(r['length']), int(r['file_offset'])) for r in inv['sites']]
    assert all(r['candidate_emitted'] == str(complete).lower() for r in rows)
    return complete


def main():
    assert not sys.flags.optimize, 'assertions required'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--raw', type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo / 'evaluation/e9-common-app/produce.py'
    raw = path(str(args.raw))
    assert raw.is_relative_to(repo / 'ignored') and not raw.exists() and not raw.is_symlink()
    input_bytes, input_owner = read(args.inputs)
    assert sha(input_bytes) == args.inputs_sha256 and re.fullmatch('[0-9a-f]{64}', args.inputs_sha256)
    inputs = loads(input_bytes)
    assert inputs.keys() == {'schema', 'preparation', 'build_admission', 'cells', 'products', 'tools', 'files'} and type(inputs['schema']) is int and inputs['schema'] == 1
    assert inputs['tools'].keys() == {'gcc', 'python', 'helper_python', 'timeout', 'git'}
    assert inputs['tools']['git'] == '/usr/bin/git'
    watched = {str(args.inputs): input_owner}
    def bound(value):
        assert value in inputs['files'], 'every input must be independently caller-pinned'
        row = inputs['files'][value]
        assert row.keys() == {'sha256', 'bytes'}
        data, owner = read(value)
        assert sha(data) == row['sha256'] and type(row['bytes']) is int and len(data) == row['bytes']
        watched[value] = owner
        return data
    for value in inputs['files']:
        bound(value)
    for value in inputs['tools'].values():
        assert path(value).stat().st_mode & 0o111
        bound(value)
    tracked = source(repo)
    assert 'evaluation/e9-common-app/produce.py' in tracked['files']
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    adapter = repo / 'tools/elf-rewrite/e9-sites.py'
    comparator = repo / 'tools/elf-rewrite/compare-sites.py'
    for p, digest in ((helper, HELPER_SHA), (adapter, ADAPTER_SHA), (comparator, COMPARE_SHA)):
        assert sha(bound(str(p))) == digest
    for name in ('e9_hook.c', 'journal.h'):
        bound(str(repo / 'evaluation/e9-common-app' / name))
    assert inputs['products'].keys() == PRODUCTS.keys()
    for role, digest in PRODUCTS.items():
        assert sha(bound(inputs['products'][role])) == digest
    build = loads(bound(inputs['build_admission']))
    assert build.keys() == {'schema', 'authority', 'source_revision', 'source_files_sha256', 'products', 'required_products', 'evidence_files', 'scope'}
    assert type(build['schema']) is int and build['schema'] == 1 and build['authority'] == 'CALLER_AUTHENTICATED_BUILD_PRODUCTS'
    assert build['scope'] == 'core-cli-and-common-sites-build-only'
    assert build['source_revision'] == tracked['revision'] and build['source_files_sha256'] == sha(encode(tracked['files']))
    assert build['products'].keys() == {'core', 'common_sites'}
    assert len(set(build['products'].values())) == 2
    assert len(build['required_products']) >= 2 and len(build['evidence_files']) >= 4
    assert len(set(build['required_products'])) == len(build['required_products'])
    assert len(set(build['evidence_files'])) == len(build['evidence_files'])
    assert set(build['products'].values()) <= set(build['required_products'])
    for value in build['required_products'] + build['evidence_files']:
        bound(value)
    for value in build['products'].values():
        assert path(value).stat().st_mode & 0o111
    prep = inputs['preparation']
    assert prep.keys() == {'summary', 'source', 'source_after', 'review_binding', 'originals'}
    summary = loads(bound(prep['summary']))
    assert summary['revision'] == PREPARED_REVISION and summary['completed'] is True
    assert (summary['planned_stages'], summary['observed_stages'], summary['ordinary_original_runs'], summary['required_refusals'], summary['rewriting_runs']) == (30, 30, 16, 6, 0)
    assert summary['qualified'] is False
    assert bound(prep['source']) == bound(prep['source_after'])
    prepared_source = loads(bound(prep['source']))
    assert prepared_source['revision'] == PREPARED_REVISION
    for name in ('heap_sort.c', 'journal.h', 'datasets.h', 'datasets.json', 'e9_hook.c'):
        rel = 'evaluation/e9-common-app/' + name
        assert tracked['files'][rel]['sha256'] == prepared_source['files'][rel], 'original fixture source remains exact'
    preparation_review = loads(bound(prep['review_binding']))
    assert preparation_review['verdict'] == 'CLOSED_ORIGINAL_PREPARATION_PASS_EXECUTION_RECORD_SCOPE'
    assert preparation_review['revision'] == PREPARED_REVISION and preparation_review['qualification_complete'] is False
    assert (preparation_review['stages'], preparation_review['ordinary_original_runs'], preparation_review['required_refusals']) == (30, 16, 6)
    assert prep['originals'].keys() == {'unstripped', 'stripped'}
    originals = {v: bound(p) for v, p in prep['originals'].items()}
    assert all(summary['artifacts'][v] == dict(sha256=sha(b), bytes=len(b)) for v, b in originals.items())
    original_headers, syms, journal = original_pair(originals['unstripped'], originals['stripped'])
    cells = [(hook, style, variant) for hook in ('null', 'journal') for style in ('jump-site', 'heap-write') for variant in ('unstripped', 'stripped')]
    keys = ['-'.join(c) for c in cells]
    assert inputs['cells'].keys() == set(keys)
    inventories = {}
    for key, (hook, style, variant) in zip(keys, cells):
        cell = inputs['cells'][key]
        assert cell.keys() == {'directory', 'run_directory', 'provenance'}
        directory, run = path(cell['directory']), path(cell['run_directory'])
        inv = inventory(directory, originals[variant], syms, style, hook, bound)
        assert sha(bound(cell['provenance'])) == inv['status']['caller_provenance_sha256']
        request = loads(bound(str(run / 'request.json')))
        assert len(request['argv']) == 7
        actual = request['argv']
        assert [actual[i] for i in (0, 1, 4, 5, 6)] == [build['products']['common_sites'], prep['originals'][variant], style, hook, str(directory)]
        # Authenticate the actual input coordinates, which precede the output directory.
        assert bound(actual[2]) == inv['data']['policy.txt'] and bound(actual[3]) == inv['data']['target.txt']
        for name in ('receipt.json', 'stdout.txt', 'stderr.txt'):
            bound(str(run / name))
        r = receipt(run, request)
        assert r['exit'] == 0 and request['cwd'] == str(repo) and request['env']['LC_ALL'] == 'C'
        expected = f"common sites: heads={len(tsv(inv['data']['instructions.tsv']))} selected={len(inv['sites'])} style={style} hook={hook} complete_static_policy=true qualification_complete=false\n"
        assert bound(str(run / 'stdout.txt')) == expected.encode() and not bound(str(run / 'stderr.txt'))
        inventories[key] = inv
    for key in keys[1:]:
        for name in ('target.txt', 'instructions.tsv', 'memory-writes.tsv', 'blocks.tsv', 'padding.tsv'):
            assert inventories[key]['data'][name] == inventories[keys[0]]['data'][name], 'same complete kernel and target in every cell'
    # One fixed complete selection per cell; no subset or retry is generated.
    planned = []
    for key in keys:
        if key == keys[4]:
            planned += ['hook-compile', 'hook-link']
        planned.append(key + '-core')
        for lane in LANES:
            planned += [key + '-' + lane + '-' + phase for phase in ('transport', 'producer', 'adapter', 'compare')]
    assert len(planned) == 74 and len(set(planned)) == 74
    raw.mkdir(mode=0o700)
    write(raw / 'inputs.json', input_bytes)
    write(raw / 'source-before.json', tracked)
    hardware = dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(),
        cpu_model=next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),
        kernel_release=platform.release(), libc=platform.libc_ver(), logical_cpus=os.cpu_count())
    assert hardware['architecture'] == 'x86_64' and 'AMD EPYC' in hardware['cpu_model']
    write(raw / 'hardware.json', hardware)
    write(raw / 'stage-inventory.json', planned)
    write(raw / 'input-owners.json', watched)
    write(raw / 'build-authority.json', dict(admission=inputs['build_admission'], sha256=sha(bound(inputs['build_admission'])),
        authority='Caller-authenticated build records, not inferred from executable hashes', source_revision=build['source_revision']))
    results = {name: dict(name=name, status='UNRUN', reason='not reached') for name in planned}
    cells_result, fatal = {}, None
    def freeze(p):
        if p.is_dir():
            assert p.resolve(strict=True) == p
            for child in sorted(p.iterdir()):
                assert not child.is_symlink()
                freeze(child)
        else:
            _, identity = read(p)
            if str(p) in watched:
                assert watched[str(p)] == identity
            watched[str(p)] = identity
    def snapshot():
        value = {p: read(p)[1] for p in sorted(watched)}
        assert value == watched, 'input owner/byte drift; no implicit refresh'
        now = source(repo)
        assert now == tracked, 'source revision/bytes changed'
        return dict(owners=value, source_sha256=sha(encode(now)))
    def execute(name, argv, tmp, compiler=False):
        assert results[name]['status'] == 'UNRUN'
        directory = raw / name
        directory.mkdir()
        request = dict(argv=list(map(str, argv)), cwd=str(repo), env=dict(ENV, TMPDIR=str(tmp)),
            cpu_seconds=60 if compiler else 20, wall_seconds=90 if compiler else 30,
            file_bytes=(128 if compiler else 16) * 1024 * 1024,
            stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'))
        write(directory / 'request.json', request)
        outer = [inputs['tools']['timeout'], '--signal=TERM', '--kill-after=10s', '100s' if compiler else '40s',
            inputs['tools']['helper_python'], '-B', str(helper), '--request', str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
        command = dict(request=request, outer_argv=outer, outer_env=ENV, cwd=str(repo), parent_timeout_seconds=115 if compiler else 55)
        write(directory / 'command.json', command)
        freeze(directory / 'request.json')
        freeze(directory / 'command.json')
        write(directory / 'before.json', snapshot())
        started = time.monotonic()
        with (directory / 'helper.stdout').open('xb') as out, (directory / 'helper.stderr').open('xb') as err:
            process = subprocess.Popen(outer, cwd=repo, env=ENV, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
            timed_out = False
            try:
                code = process.wait(timeout=command['parent_timeout_seconds'])
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
        row = dict(name=name, status='FAILED', reason='postchecks pending', parent_exit=code,
                   parent_timeout=timed_out, operational_seconds=time.monotonic() - started,
                   result_scope='Bounded command; separate postcheck.json and final results.json govern the stage')
        results[name] = row
        write(directory / 'outer.json', row)
        write(directory / 'after.json', snapshot())
        assert not timed_out, 'parent wall backstop'
        r = receipt(directory, request)
        assert code == (0 if r['exit'] == 0 else 1)
        terminal = dict(exit=r['exit'], wall_timeout=False, absence_proof='ECHILD', descendants=0, success=r['exit'] == 0)
        assert read(directory / 'helper.stdout')[0] == (json.dumps(terminal) + '\n').encode() and not read(directory / 'helper.stderr')[0]
        row.update(exit=r['exit'], receipt_sha256=sha(read(directory / 'receipt.json')[0]), reason='command exited nonzero' if r['exit'] else '')
        row['status'] = 'PASS' if r['exit'] == 0 else 'FAILED'
        write(directory / 'result.json', row)
        for n in ('receipt.json', 'stdout.txt', 'stderr.txt', 'helper.stdout', 'helper.stderr', 'outer.json', 'result.json', 'before.json', 'after.json'):
            freeze(directory / n)
        print(name, row['status'], r['exit'], flush=True)
        return directory, r['exit']
    def checked(name, function):
        # A finite output/schema failure stays attached to this stage. It never
        # manufactures a replacement site inventory or erases the raw output.
        try:
            value = function()
            write(raw / name / 'postcheck.json', dict(pass_=True))
            return value
        except Exception as error:
            results[name].update(status='FAILED', reason=str(error) or type(error).__name__)
            write(raw / name / 'postcheck.json', dict(pass_=False, error=repr(error)))
            return None
    hook = None
    try:
        for key, (hook_kind, style, variant) in zip(keys, cells):
            if key == keys[4]:
                hook_dir = raw / 'hook'
                hook_dir.mkdir()
                (hook_dir / 'tmp').mkdir()
                obj, image = hook_dir / 'e9_hook.o', hook_dir / 'e9_hook'
                args_compile = [inputs['tools']['gcc'], '-fno-stack-protector', '-fpie', '-O2', '-c', '-Wall',
                    '-DLI2_JOURNAL_ADDRESS=' + hex(journal['value']) + 'ULL', str(repo / 'evaluation/e9-common-app/e9_hook.c'), '-o', str(obj)]
                d, code = execute('hook-compile', args_compile, hook_dir / 'tmp', True)
                def compile_check():
                    assert code == 0 and not read(d / 'stdout.txt')[0] and not read(d / 'stderr.txt')[0]
                    freeze(obj)
                    return True
                if checked('hook-compile', compile_check):
                    d, code = execute('hook-link', [inputs['tools']['gcc'], obj, '-o', image, '-pie', '-nostdlib', '-Wl,-z', '-Wl,max-page-size=4096', '-Wl,--export-dynamic', '-Wl,--entry=0x0', '-Wl,--strip-all'], hook_dir / 'tmp', True)
                    def link_check():
                        assert code == 0 and not read(d / 'stdout.txt')[0] and not read(d / 'stderr.txt')[0]
                        result, evidence = hook_elf(read(image)[0], original_headers)
                        write(hook_dir / 'validated.json', dict(hook=result, journal_symbol=journal, elf=evidence))
                        freeze(image)
                        freeze(hook_dir / 'validated.json')
                        return result
                    hook = checked('hook-link', link_check)
                else:
                    results['hook-link']['reason'] = 'hook compile failed'
            cell_dir = raw / key
            cell_dir.mkdir()
            (cell_dir / 'tmp').mkdir()
            inv = inventories[key]
            selection = Path(inputs['cells'][key]['directory']) / 'selection.txt'
            original = prep['originals'][variant]
            core_dir = cell_dir / 'core'
            policy_path = cell_dir / 'comparison-policy.json'
            policy = dict(schema=1, original_sha256=sha(originals[variant]), selection_sha256=sha(inv['data']['selection.txt']),
                e9_revision=REFERENCE['reference_commit'], instrumentation='null' if hook_kind == 'null' else 'real-hook', selection_style=style)
            write(policy_path, policy)
            freeze(policy_path)
            name = key + '-core'
            d, code = execute(name, [build['products']['core'], 'prepare', original, selection, core_dir], cell_dir / 'tmp')
            def core_check():
                assert code in (0, 2) and not read(d / 'stderr.txt')[0]
                complete = core_product(core_dir, inv, originals[variant])
                assert code == (0 if complete else 2)
                assert read(d / 'stdout.txt')[0] == f'candidate_complete={str(complete).lower()} qualification_complete=false sites={len(inv["sites"])}\n'.encode()
                freeze(core_dir)
                return dict(complete=complete, report=str(core_dir / 'report.tsv'))
            core = checked(name, core_check)
            cells_result[key] = dict(core=core, references={})
            for lane in LANES:
                prefix = key + '-' + lane
                lane_dir = cell_dir / lane
                lane_dir.mkdir()
                (lane_dir / 'tmp').mkdir()
                if hook_kind == 'journal' and hook is None:
                    for phase in ('transport', 'producer', 'adapter', 'compare'):
                        results[prefix + '-' + phase]['reason'] = 'hook build/validation failed'
                    cells_result[key]['references'][lane] = dict(status='UNRUN', reason='hook prerequisite failed')
                    continue
                candidate = lane_dir / 'candidate.elf'
                match = 'asm=j.*' if style == 'jump-site' else 'addr=^(' + '|'.join(hex(int(r['pc'], 0)) for r in inv['sites']) + ')$'
                instrumentation = 'passthru' if hook_kind == 'null' else 'call[clean,before]li2_e9_record(instrAddr)@' + str(raw / 'hook/e9_hook')
                common = ['--action=' + match + ':' + instrumentation, '--executable', '--compression=9',
                          '--start=' + hex(min(r[0] for r in inv['ranges'])), '--end=' + hex(max(r[1] for r in inv['ranges']))]
                frontend = inputs['products']['stock_frontend' if lane == LANES[0] else 'transport_frontend']
                backend = inputs['products']['stock_backend' if lane == LANES[0] else 'abi_backend']
                loader = inputs['products']['stock_loader' if lane == LANES[0] else 'abi_loader']
                transport, tc = execute(prefix + '-transport', [inputs['products']['transport_frontend'], *common, '--format=json', '--output=-', original], lane_dir / 'tmp')
                if tc != 0:
                    for phase in ('producer', 'adapter', 'compare'):
                        results[prefix + '-' + phase]['reason'] = 'transport failed'
                    cells_result[key]['references'][lane] = dict(status='FAILED', phase='transport')
                    continue
                producer, pc = execute(prefix + '-producer', [frontend, *common, '--format=binary', '--output=' + str(candidate), '--backend=' + backend, '--option=--debug', original], lane_dir / 'tmp')
                if pc != 0:
                    for phase in ('adapter', 'compare'):
                        results[prefix + '-' + phase]['reason'] = 'producer failed'
                    cells_result[key]['references'][lane] = dict(status='FAILED', phase='producer')
                    continue
                def envelope_check():
                    assert not read(transport / 'stderr.txt')[0]
                    freeze(candidate)
                    roles = dict(original=original, selection=str(selection), policy=str(policy_path), candidate=str(candidate), frontend=frontend,
                        backend=backend, loader=loader, transport_frontend=inputs['products']['transport_frontend'], helper=str(helper))
                    for phase, directory in (('transport', transport), ('producer', producer)):
                        for role, filename in (('request', 'request.json'), ('receipt', 'receipt.json'), ('stdout', 'stdout.txt'), ('stderr', 'stderr.txt')):
                            roles[phase + '_' + role] = str(directory / filename)
                    if hook_kind == 'journal':
                        roles['hook_elf'] = str(raw / 'hook/e9_hook')
                    envelope = dict(schema=1, lane=lane, common_argv=common, hook=hook if hook_kind == 'journal' else None,
                                    files={r: file_row(Path(p)) for r, p in roles.items()}, **REFERENCE)
                    output = lane_dir / 'envelope.json'
                    write(output, envelope)
                    freeze(output)
                    return output
                envelope = checked(prefix + '-producer', envelope_check)
                if envelope is None:
                    for phase in ('adapter', 'compare'):
                        results[prefix + '-' + phase]['reason'] = 'producer output ownership failed'
                    cells_result[key]['references'][lane] = dict(status='FAILED', phase='producer-output')
                    continue
                output = lane_dir / 'inventory'
                d, code = execute(prefix + '-adapter', [inputs['tools']['python'], '-B', adapter, envelope, output, '--envelope-sha256', sha(read(envelope)[0])], lane_dir / 'tmp')
                def adapter_check():
                    assert code == 0 and not read(d / 'stderr.txt')[0]
                    assert read(d / 'stdout.txt')[0] == f'E9 actual-site inventory: {len(inv["sites"])} requested sites; structural scope only\n'.encode()
                    assert {p.name for p in output.iterdir()} == {'sites.tsv', 'producer-binding.json'}
                    value = loads(read(output / 'producer-binding.json')[0])
                    assert value['selected_sites'] == len(inv['sites']) and value['candidate_sha256'] == sha(read(candidate)[0])
                    assert value['qualification_complete'] is False and value['architectural_equivalence_proved'] is False
                    assert value['site_inventory_sha256'] == sha(read(output / 'sites.tsv')[0])
                    freeze(output)
                    return value
                outcome = checked(prefix + '-adapter', adapter_check)
                if outcome is None or core is None:
                    results[prefix + '-compare']['reason'] = 'adapter failed' if outcome is None else 'core report unavailable'
                    cells_result[key]['references'][lane] = dict(status='FAILED', phase='adapter' if outcome is None else 'core-report', adapter=outcome)
                    continue
                comparison = lane_dir / 'comparison.json'
                d, code = execute(prefix + '-compare', [inputs['tools']['python'], '-B', comparator, selection, core['report'], output / 'sites.tsv', policy_path, comparison, '--policy-sha256', sha(read(policy_path)[0])], lane_dir / 'tmp')
                def comparison_check():
                    assert code in (0, 2) and not read(d / 'stdout.txt')[0] and not read(d / 'stderr.txt')[0]
                    value = loads(read(comparison)[0])
                    assert value['selected_sites'] == len(inv['sites']) and value['comparison_policy'] == policy
                    assert value['qualification_complete'] is False and value['scope'] == 'STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY'
                    assert code == (2 if value['lost_e9_trampoline_sites'] else 0)
                    freeze(comparison)
                    return value
                compared = checked(prefix + '-compare', comparison_check)
                cells_result[key]['references'][lane] = dict(status='PASS' if compared is not None and code == 0 else 'FAILED', adapter=outcome, comparison=compared)
    except Exception as error:
        fatal = repr(error)
        for row in results.values():
            if row['status'] == 'UNRUN':
                row['reason'] = 'campaign stopped: ' + fatal
    finally:
        try:
            final = snapshot()
            write(raw / 'input-owners-after.json', final)
            write(raw / 'source-after.json', source(repo))
        except (AssertionError, ValueError, OSError, subprocess.SubprocessError) as error:
            fatal = (fatal or '') + '; final input check: ' + repr(error)
        rows = [results[name] for name in planned]
        successful = fatal is None and all(r['status'] == 'PASS' for r in rows)
        write(raw / 'results.json', rows)
        write(raw / 'cells.json', cells_result)
        write(raw / 'summary.json', dict(schema=1, revision=tracked['revision'], completed_traversal=len(cells_result) == 8,
            successful=successful, fatal=fatal, planned_stages=74, attempted_stages=sum(r['status'] != 'UNRUN' for r in rows),
            core_cells=8, reference_cells_per_lane=8, ordinary_dataset_executions=0, native_executions=0,
            qualification_complete=False, scope='Artifact production and complete structural comparison only',
            parent_closed_reaped_authority='Must be recorded separately by the invoking root process',
            build_authority='Caller-admitted source/build/product records; this recipe does not compile the core or decoder',
            timings='Operational diagnostics only, not performance measurements'))
        index = {}
        for directory, dirs, files in os.walk(raw, followlinks=False):
            assert all(not (Path(directory) / name).is_symlink() for name in dirs + files)
            for name in files:
                p = Path(directory) / name
                data, owner = read(p)
                index[str(p.relative_to(raw))] = dict(sha256=sha(data), bytes=len(data), stat=owner['stat'])
        write(raw / 'raw-files.json', index)
    return 0 if successful else 1


if __name__ == '__main__':
    raise SystemExit(main())
