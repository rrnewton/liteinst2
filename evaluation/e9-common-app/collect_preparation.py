#!/usr/bin/env python3
"""Summarize one closed original heap-sort preparation; never run the fixture."""
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
import struct
import subprocess
import sys

REVISION = 'ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05'
RECIPE = '79945a0bfdc7ffa9b1ea2ed265669709e278bb6d82c5676731dab547eadc278c'
HELPER = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
DATASETS = ['empty', 'singleton', 'pair-reverse', 'equal-17', 'sorted-17', 'reverse-17', 'duplicates-17', 'mixed-64']
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
MAX_FILE = 16 * 1024 * 1024
SOURCE = 'evaluation/e9-common-app/'
REFUSALS = [('usage', 64, b'usage: heap-sort DATASET NEW_JOURNAL_FILE\n'),
            ('dataset', 65, b'dataset or page-size refusal\n'),
            ('overwrite', 67, b'journal output failure\n')]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def loads(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            assert key not in out, 'duplicate JSON key'
            out[key] = value
        return out
    def invalid(value):
        raise AssertionError('non-JSON constant: ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        assert stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE
        raw = stream.read(MAX_FILE + 1)
        assert len(raw) == before.st_size and fields(before) == fields(os.fstat(stream.fileno()))
        return raw, fields(before)


def duration(value, maximum=None):
    assert type(value) in (int, float) and math.isfinite(value) and value >= 0
    assert maximum is None or value <= maximum
    return value


def git_sources(repo, revision, saved):
    # Only read-only Git commands; no checkout, compiler or authored module.
    command = ['/usr/bin/git', '-C', str(repo)]
    tree = subprocess.check_output(command + ['ls-tree', '-rz', '--full-tree', revision], timeout=30)
    rows = []
    for row in tree.split(b'\0'):
        if not row:
            continue
        header, name = row.split(b'\t', 1)
        mode, kind, oid = header.decode().split()
        name = name.decode()
        assert kind == 'blob' and mode in ('100644', '100755')
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        rows.append((name, mode, oid))
    assert {r[0] for r in rows} == saved.keys() and len(rows) == len(saved)
    batch = subprocess.run(command + ['cat-file', '--batch'], input=''.join(r[2] + '\n' for r in rows).encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
    assert not batch.stderr
    offset, bodies, records = 0, {}, {}
    for name, mode, oid in rows:
        stop = batch.stdout.index(b'\n', offset)
        header = batch.stdout[offset:stop].decode().split()
        assert header[:2] == [oid, 'blob'] and len(header) == 3
        length = int(header[2]); assert 0 <= length <= MAX_FILE
        raw = batch.stdout[stop + 1:stop + 1 + length]
        assert len(raw) == length and batch.stdout[stop + 1 + length:stop + 2 + length] == b'\n'
        assert hashlib.sha1(b'blob ' + str(length).encode() + b'\0' + raw).hexdigest() == oid
        assert sha(raw) == saved[name]
        records[name] = dict(sha256=sha(raw), bytes=length, mode=mode, git_blob=oid)
        if name.startswith(SOURCE) or name == 'tools/unwind-oracle/bounded_command.py':
            bodies[name] = raw
        offset = stop + 2 + length
    assert offset == len(batch.stdout)
    assert sha(bodies[SOURCE + 'prepare_subject.py']) == RECIPE
    assert sha(bodies['tools/unwind-oracle/bounded_command.py']) == HELPER
    return records, bodies


def elf(raw):
    assert 64 <= len(raw) <= 4 * 1024 * 1024 and raw[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', raw, 16) == (2, 62, 1)
    assert struct.unpack_from('<HH', raw, 52) == (64, 56)
    off, n = struct.unpack_from('<Q', raw, 32)[0], struct.unpack_from('<H', raw, 56)[0]
    assert 1 <= n <= 64 and off + n * 56 <= len(raw)
    ph = [struct.unpack_from('<IIQQQQQQ', raw, off + i * 56) for i in range(n)]
    assert sum(p[0] == 3 for p in ph) == 1
    assert all(p[2] + p[5] <= len(raw) and p[5] <= p[6] and p[1] & 3 != 3 and p[2] % 4096 == p[3] % 4096 for p in ph if p[0] == 1)
    shoff = struct.unpack_from('<Q', raw, 40)[0]
    width, count, names = struct.unpack_from('<HHH', raw, 58)
    assert width == 64 and 1 <= count <= 4096 and names < count and shoff + count * width <= len(raw)
    sh = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff + i * width) for i in range(count)]
    def section_bytes(s):
        assert s[4] + s[5] <= len(raw)
        return raw[s[4]:s[4] + s[5]]
    strings = section_bytes(sh[names])
    def string(table, at):
        assert at < len(table) and b'\0' in table[at:]
        return table[at:].split(b'\0', 1)[0].decode()
    text = [s for s in sh if string(strings, s[0]) == '.text']
    assert len(text) == 1 and text[0][1] == 1 and text[0][2] & 6 == 6
    symbols = {}
    tables = [s for s in sh if s[1] == 2]
    for table in tables:
        assert table[9] == 24 and table[5] % 24 == 0 and table[6] < count
        names_data = section_bytes(sh[table[6]])
        for start in range(0, len(section_bytes(table)), 24):
            name, info, other, section, va, length = struct.unpack_from('<IBBHQQ', raw, table[4] + start)
            name = string(names_data, name)
            if section and name in ('main', 'li2_array_store', 'li2_sift_down', 'li2_heap_sort', 'li2_before_sort', 'li2_after_sort', 'li2_null_hook', 'li2_record_hook', 'li2_journal', 'li2_run'):
                assert name not in symbols
                symbols[name] = (va, length, info & 15)
    return ph, text[0], tables, symbols


def slice_owner(raw, ph, va, length, executable):
    owners = [p for p in ph if p[0] == 1 and p[3] <= va and va + length <= p[3] + p[5]]
    assert len(owners) == 1 and length > 0 and (not executable or owners[0][1] & 1)
    off = owners[0][2] + va - owners[0][3]
    return off, raw[off:off + length]


def main():
    assert not sys.flags.optimize, 'assertions required'
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'raw', 'launch', 'input-index', 'new-output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--input-index-sha256', required=True)
    p.add_argument('--parent-session', type=int, required=True)
    p.add_argument('--parent-closed-reaped', action='store_true', required=True)
    a = p.parse_args()
    assert a.parent_closed_reaped and a.parent_session > 0
    for path in (a.repo, a.raw, a.launch):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert a.raw != a.launch and a.raw.is_relative_to(a.repo / 'ignored') and a.launch.is_relative_to(a.repo / 'ignored')
    assert not a.raw.is_relative_to(a.launch) and not a.launch.is_relative_to(a.raw)
    assert a.new_output.is_absolute() and a.new_output.parent.resolve(strict=True) == a.new_output.parent
    assert not a.new_output.exists() and not a.new_output.is_symlink()
    assert not a.new_output.is_relative_to(a.raw) and not a.new_output.is_relative_to(a.launch)
    collector_path = a.repo / (SOURCE + 'collect_preparation.py')
    assert Path(__file__).absolute() == collector_path and collector_path.resolve(strict=True) == collector_path
    collector_bytes, collector_owner = read(collector_path)
    git = ['/usr/bin/git', '-C', str(a.repo)]
    collector_revision = subprocess.check_output(git + ['rev-parse', 'HEAD'], timeout=15).decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', collector_revision)
    assert subprocess.check_output(git + ['show', collector_revision + ':' + SOURCE + 'collect_preparation.py'], timeout=15) == collector_bytes
    index_raw, index_owner = read(a.input_index)
    assert re.fullmatch('[0-9a-f]{64}', a.input_index_sha256) and sha(index_raw) == a.input_index_sha256
    index = loads(index_raw)
    assert index.keys() == {'schema', 'raw', 'launch', 'files'} and index['schema'] == 1
    assert index['raw'] == str(a.raw) and index['launch'] == str(a.launch)
    blobs, owners = {}, {}
    for name, expected in index['files'].items():
        path = Path(name)
        assert path.is_absolute() and (path.is_relative_to(a.raw) or path.is_relative_to(a.launch))
        assert '..' not in path.parts and path.parent.resolve(strict=True) == path.parent
        blobs[name], owners[name] = read(path)
        assert sha(blobs[name]) == expected
    def raw(name):
        return blobs[str(a.raw / name)]
    def record(name):
        return loads(raw(name))
    def launched(name):
        return blobs[str(a.launch / name)]
    roles = {'$RAW': str(a.raw), '$LAUNCH': str(a.launch), '$REPO': str(a.repo)}
    tokens = re.compile('|'.join(re.escape(k) for k in roles))
    locations = re.compile('|'.join(re.escape(v) for v in sorted(roles.values(), key=len, reverse=True)))
    backwards = {v: k for k, v in roles.items()}
    def normalize(text):
        assert not tokens.search(text), 'literal role text would destroy injectivity'
        value = locations.sub(lambda m: backwards[m[0]], text)
        assert tokens.sub(lambda m: roles[m[0]], value) == text
        return value
    def normalized(value):
        if isinstance(value, str):
            return normalize(value)
        if isinstance(value, list):
            return [normalized(v) for v in value]
        if isinstance(value, dict):
            return {normalize(k): normalized(v) for k, v in value.items()}
        return value
    inverses = {}
    def object_copy(data, label):
        # Preserve exact JSON source bytes, including whitespace, privately.
        strings = {json.dumps(v)[1:-1]: json.dumps(k)[1:-1] for k, v in roles.items()}
        pattern = re.compile('|'.join(re.escape(v) for v in sorted(strings, key=len, reverse=True)))
        text = data.decode(); assert not tokens.search(text)
        template = pattern.sub(lambda m: strings[m[0]], text)
        inverse = tokens.sub(lambda m: json.dumps(roles[m[0]])[1:-1], template)
        assert inverse.encode() == data
        value = normalized(loads(data)); assert loads(template) == value
        inverses[label] = dict(sha256=sha(data), template=template)
        return value
    before, after = record('source.json'), record('source-after.json')
    assert before == after and before.keys() == {'revision', 'files'} and before['revision'] == REVISION
    sources, source = git_sources(a.repo, REVISION, before['files'])
    datasets = loads(source[SOURCE + 'datasets.json'])['datasets']
    assert [d['name'] for d in datasets] == DATASETS
    for i, d in enumerate(datasets):
        assert d['id'] == i and len(d['input']) <= 64 and all(type(x) is int and 0 <= x < 1 << 64 for x in d['input'])
        text = f"case={d['name']} n={len(d['input'])} sorted=" + ','.join(map(str, sorted(d['input']))) + '\n'
        assert d['expected'] == sorted(d['input']) and d['expected_stdout'] == text
        assert source[SOURCE + 'expected/' + d['name'] + '.stdout'] == text.encode()
    hardware, tools = record('hardware.json'), record('tools.json')
    assert hardware.keys() == {'host_label', 'architecture', 'cpu_model', 'kernel_release', 'libc', 'logical_cpus'}
    assert hardware['host_label'] == 'AMD EPYC Zen 5 dev host' and hardware['architecture'] == 'x86_64' and 'AMD EPYC' in hardware['cpu_model']
    assert type(hardware['logical_cpus']) is int and hardware['logical_cpus'] > 0
    assert tools.keys() == {'/usr/bin/' + n for n in ('gcc', 'strip', 'readelf', 'nm')}
    assert all(v.keys() == {'resolved', 'sha256'} and re.fullmatch('[0-9a-f]{64}', v['sha256']) for v in tools.values())
    launch, parent = loads(launched('launch.json')), loads(launched('result.json'))
    assert launch == dict(argv=['/usr/bin/python3.9', '-B', str(a.repo / (SOURCE + 'prepare_subject.py')), '--raw', str(a.raw)], cwd=str(a.repo), env=ENV,
                          revision=REVISION, recipe_sha256=RECIPE, parent_owns_wait_and_reap=True, whole_recipe_timeout=None)
    assert parent.keys() == {'exit', 'elapsed_seconds', 'wait_completed', 'child_reaped_by_parent', 'stdout_sha256', 'stderr_sha256'}
    assert type(parent['exit']) is int and parent['exit'] == 0 and parent['wait_completed'] is True and parent['child_reaped_by_parent'] is True
    duration(parent['elapsed_seconds'])
    assert parent['stdout_sha256'] == sha(launched('stdout.txt')) and parent['stderr_sha256'] == sha(launched('stderr.txt')) and not launched('stderr.txt')
    plans = [('gcc-version', ['/usr/bin/gcc', '--version'], 0), ('strip-version', ['/usr/bin/strip', '--version'], 0)]
    original = a.raw / 'original-unstripped'
    gcc = ['/usr/bin/gcc', '-std=c11', '-O2', '-fomit-frame-pointer', '-fno-optimize-sibling-calls', '-fno-pie', '-no-pie', '-fno-lto', '-fno-toplevel-reorder', '-fno-reorder-blocks-and-partition', '-fno-stack-protector', '-fcf-protection=none', '-Wall', '-Wextra', '-Werror', '-MD', '-MF', str(a.raw / 'compile.d'), '-Wl,-Map,' + str(a.raw / 'link.map'), str(a.repo / (SOURCE + 'heap_sort.c')), '-o', str(original)]
    plans += [('compile', gcc, 0), ('strip', ['/usr/bin/strip', '--strip-all', '-o', str(a.raw / 'original-stripped'), str(original)], 0)]
    for variant in ('unstripped', 'stripped'):
        exe = str(a.raw / ('original-' + variant))
        plans += [(variant + '-readelf', ['/usr/bin/readelf', '--wide', '--headers', '--program-headers', '--sections', '--symbols', exe], 0), (variant + '-nm', ['/usr/bin/nm', '-S', '--defined-only', '--format=posix', exe], 0)]
        plans += [(variant + '-' + d['name'], [exe, d['name'], str(a.raw / (variant + '-' + d['name'] + '.journal'))], 0) for d in datasets]
        plans += [(variant + '-refuse-' + name, [exe] if name == 'usage' else [exe, 'not-a-dataset' if name == 'dataset' else 'mixed-64', str(a.raw / (variant + '-refuse-' + name + '.journal'))], code) for name, code, _ in REFUSALS]
    assert len(plans) == 30 and record('stage-inventory.json') == [n for n, _, _ in plans]
    commands, cases, observed_results = [], [], []
    for ordinal, (name, argv, code) in enumerate(plans, 1):
        compiler = name == 'compile'; directory = a.raw / name
        req = dict(argv=argv, cwd=str(a.repo), env=dict(ENV, TMPDIR=str(directory / 'tmp')), stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'), cpu_seconds=60 if compiler else 20, wall_seconds=90 if compiler else 30, file_bytes=(128 if compiler else 16) * 1024 * 1024)
        command = dict(name=name, request=req, expected_exit=code, outer_argv=['/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', '100s' if compiler else '40s', '/usr/bin/python3.9', '-B', str(a.repo / 'tools/unwind-oracle/bounded_command.py'), '--request', str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')], outer_env=ENV, parent_timeout_seconds=115 if compiler else 55)
        assert record(name + '/request.json') == req and record(name + '/command.json') == command
        result = record(name + '/result.json'); expected_parent = 0 if code == 0 else 1
        assert type(result['parent_exit']) is int and result['parent_timeout'] is False
        assert result == dict(command, parent_exit=expected_parent, parent_timeout=False, operational_seconds=result['operational_seconds'])
        duration(result['operational_seconds']); observed_results.append(result)
        receipt = record(name + '/receipt.json')
        assert receipt.keys() == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout', 'unexpected_descendants', 'absence_proof', 'stdout_sha256', 'stderr_sha256', 'elapsed_seconds', 'cleanup_events', 'cleanup_error', 'aborted', 'inputs_unchanged'}
        assert type(receipt['exit']) is int and receipt['exit'] == code
        assert receipt['request_sha256'] == sha(raw(name + '/request.json')) and receipt['helper_sha256'] == HELPER
        assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True and receipt['absence_proof'] == 'ECHILD'
        assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == [] and receipt['cleanup_error'] is None and receipt['aborted'] is None
        duration(receipt['elapsed_seconds'], req['wall_seconds'])
        for stream in ('stdout', 'stderr'):
            assert receipt[stream + '_sha256'] == sha(raw(name + '/' + stream + '.txt'))
        terminal = dict(exit=code, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=code == 0)
        assert raw(name + '/helper.stdout') == (json.dumps(terminal) + '\n').encode() and not raw(name + '/helper.stderr')
        status = 'required_refusal' if code else 'completed_success'
        commands.append(dict(ordinal=ordinal, stage=name, status=status, command=object_copy(raw(name + '/command.json'), name + '/command'), result=object_copy(raw(name + '/result.json'), name + '/result'), request=object_copy(raw(name + '/request.json'), name + '/request'), receipt=receipt, receipt_sha256=sha(raw(name + '/receipt.json'))))
    assert record('results.json') == observed_results
    assert launched('stdout.txt') == ''.join(n + ' ' + str(0 if c == 0 else 1) + '\n' for n, _, c in plans).encode()
    for name in ('gcc-version', 'strip-version'):
        assert raw(name + '/stdout.txt') and not raw(name + '/stderr.txt')
    for name in ('compile', 'strip'):
        assert not raw(name + '/stdout.txt') and not raw(name + '/stderr.txt')
    zero_journal = struct.pack('<8Q', 0x6c69326a6f75726e, 1, 16384, 0, 0, 0, 0, 0) + bytes(16384 * 8) + struct.pack('<Q', 0x7265636f72647321)
    checks = ['Exact original LOAD parity with only e_shoff/e_shnum/e_shstrndx masked in ELF header']
    for variant in ('unstripped', 'stripped'):
        assert raw(variant + '-readelf/stdout.txt') and not raw(variant + '-readelf/stderr.txt')
        if variant == 'stripped':
            assert not raw(variant + '-nm/stdout.txt') and raw(variant + '-nm/stderr.txt') == ('/usr/bin/nm: ' + str(a.raw / 'original-stripped') + ': no symbols\n').encode()
        else:
            assert raw(variant + '-nm/stdout.txt') and not raw(variant + '-nm/stderr.txt')
        for d in datasets:
            name = variant + '-' + d['name']
            assert raw(name + '/stdout.txt') == d['expected_stdout'].encode() and not raw(name + '/stderr.txt')
            assert raw(name + '.journal') == zero_journal and len(zero_journal) == 131144
            checks.append(variant + '/' + d['name'] + ': exact complete sorted output and zero journal')
            cases.append(dict(stage=name, variant=variant, case=d['name'], status='original_output_and_zero_journal_equal', expected_exit=0, elements=len(d['input']), stdout_sha256=sha(raw(name + '/stdout.txt')), journal_sha256=sha(zero_journal), journal_bytes=len(zero_journal)))
        for name, code, stderr in REFUSALS:
            stage = variant + '-refuse-' + name
            assert not raw(stage + '/stdout.txt') and raw(stage + '/stderr.txt') == stderr
            journal = a.raw / (stage + '.journal')
            if name == 'overwrite':
                assert raw(stage + '.journal') == b'preserve existing journal\n'
            else:
                assert str(journal) not in blobs and not journal.exists() and not journal.is_symlink()
            checks.append(variant + '/' + name + ': exact required refusal')
            cases.append(dict(stage=stage, variant=variant, case=name, status='required_refusal', expected_exit=code, elements=None, stdout_sha256=sha(b''), journal_sha256=sha(raw(stage + '.journal')) if name == 'overwrite' else None, journal_bytes=26 if name == 'overwrite' else 0))
    assert record('checks.json') == checks
    left, right = raw('original-unstripped'), raw('original-stripped')
    ph, text, tables, symbols = elf(left)
    ph2, text2, tables2, _ = elf(right)
    # Strip changes .text's sh_name string-table index, not its geometry.
    # Each index was independently resolved to the exact name above.
    assert ph == ph2 and text[1:] == text2[1:] and len(tables) == 1 and not tables2
    for row in ph:
        if row[0] != 1:
            continue
        off, size = row[2], row[5]
        l, r = bytearray(left[off:off + size]), bytearray(right[off:off + size])
        for at in list(range(40, 48)) + list(range(60, 64)):
            if off <= at < off + size:
                l[at - off] = r[at - off] = 0
        assert l == r
    facts = {k: dict(sha256=sha(v), bytes=len(v)) for k, v in [('unstripped', left), ('stripped', right)]}
    assert record('artifacts.json') == facts
    slices = []
    assert len(symbols) == 10
    nm = {}
    for line in raw('unstripped-nm/stdout.txt').decode().splitlines():
        f = line.split()
        if f and f[0] in symbols:
            assert len(f) == 4 and f[0] not in nm
            nm[f[0]] = (int(f[2], 16), int(f[3], 16))
    assert nm == {name: (v[0], v[1]) for name, v in symbols.items()}
    for name, (va, size, kind) in [('text', (text[3], text[5], 2)), *sorted(symbols.items())]:
        off, data = slice_owner(left, ph, va, size, kind == 2)
        off2, data2 = slice_owner(right, ph2, va, size, kind == 2)
        assert off == off2 and data == data2
        slices.append(dict(name=name, virtual_address=hex(va), file_offset=hex(off), bytes=size, sha256=sha(data), owner_kind='section' if name == 'text' else 'function' if kind == 2 else 'object'))
    assert symbols['li2_array_store'][1:] == (5, 2)
    assert slice_owner(left, ph, symbols['li2_array_store'][0], 5, True)[1] == bytes.fromhex('488914f7c3')
    observation = loads(launched('compiled-observation.json'))
    assert observation['revision'] == REVISION
    by_name = {v['name']: v for v in slices}
    assert [v['name'] for v in observation['functions']] == ['text', 'li2_array_store', 'li2_sift_down', 'li2_heap_sort', 'li2_before_sort', 'li2_after_sort', 'main']
    for v in observation['functions']:
        s = by_name[v['name']]
        assert (int(v['va'], 16), int(v['offset'], 16), v['size'], v['sha256']) == (int(s['virtual_address'], 16), int(s['file_offset'], 16), s['bytes'], s['sha256'])
        if v['bytes_hex'] is not None:
            assert bytes.fromhex(v['bytes_hex']) == left[int(s['file_offset'], 16):int(s['file_offset'], 16) + s['bytes']]
    saved_summary = record('summary.json')
    assert saved_summary == dict(schema=1, revision=REVISION, hardware=hardware, completed=True, last_phase='stripped refusal overwrite', planned_stages=30, observed_stages=30, checks=checks, artifacts=facts, ordinary_original_runs=16, required_refusals=6, rewriting_runs=0, qualified=False, scope='Original fixture build/output only; no rewrite, decoder, site-retention, journal-hook, or architectural-state qualification')
    metadata = {name: dict(sha256=sha(raw(name)), bytes=len(raw(name))) for name in ['compile.d', 'link.map'] + [v + '-' + t + '/stdout.txt' for v in ('unstripped', 'stripped') for t in ('readelf', 'nm')]}
    summary = dict(schema=1, status='COMPLETE_ORIGINAL_PREPARATION', tested_revision=REVISION, hardware=hardware, source_files=len(sources), saved_source_before_after_equal=True, committed_git_blobs_equal=True, stages=30, completed_success=24, required_refusal=6, ordinary_original_runs=16, rewriting_runs=0, qualification_complete=False, full_A3=False,
                   timing_scope='Operational diagnostics only; no performance comparison or aggregate timing claim.',
                   parent_closure_scope='Saved launch record plus explicit caller confirmation; collector does not observe live processes.',
                   limitations=['Original dynamic-loader application outputs and zero journals only.', 'No rewritten application, complete instruction inventory, selected-site comparison, recording-hook or architectural-state qualification.', 'Compiler depfile, link map and readelf/nm outputs are retained metadata, not a complete compiler/configuration/dependency closure.', 'Tool record is the recipe-selected four-tool hash observation; no retrospective current-owner refresh.', 'Symbol/file slices are decoded ELF metadata, not independent instruction/dataflow classification.'],
                   collection=dict(source_sha256=sha(collector_bytes), source_path=SOURCE + 'collect_preparation.py', tested_revision=collector_revision, input_index_sha256=sha(index_raw)))
    public = {'summary.json': encoded(summary), 'commands.json': encoded(dict(schema=1, role_symbols=list(roles), recipe_invocation=object_copy(launched('launch.json'), 'launch'), parent_result=object_copy(launched('result.json'), 'parent-result'), stages=commands)),
              'artifacts.json': encoded(dict(schema=1, artifacts=facts, program_headers=[list(r) for r in ph], slices=slices, metadata=metadata, tools=normalized(tools), stripping='Exact LOAD bytes except e_shoff/e_shnum/e_shstrndx; all program headers and section-entry width unchanged.')),
              'source-files.json': encoded(dict(schema=1, tested_revision=REVISION, files=sources))}
    def csv_bytes(rows, columns):
        stream = io.StringIO(newline='')
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator='\n')
        writer.writeheader(); writer.writerows(rows)
        return stream.getvalue().encode()
    csv_commands = []
    for c in commands:
        req, res, rec = c['request'], c['result'], c['receipt']
        csv_commands.append(dict(ordinal=c['ordinal'], stage=c['stage'], status=c['status'], expected_exit=c['command']['expected_exit'], child_exit=rec['exit'], helper_parent_exit=res['parent_exit'], helper_seconds=rec['elapsed_seconds'], parent_operational_seconds=res['operational_seconds'], cpu_seconds=req['cpu_seconds'], wall_seconds=req['wall_seconds'], file_bytes=req['file_bytes'], argv_json=json.dumps(req['argv']), cwd=req['cwd'], env_json=json.dumps(req['env'], sort_keys=True), request_sha256=rec['request_sha256'], receipt_sha256=c['receipt_sha256'], stdout_sha256=rec['stdout_sha256'], stderr_sha256=rec['stderr_sha256']))
    public['commands.csv'] = csv_bytes(csv_commands, list(csv_commands[0]))
    public['cases.csv'] = csv_bytes(cases, list(cases[0]))
    public['README.md'] = ('# Original heap-sort preparation\n\nThe recorded source revision is `' + REVISION + '`. This preparation built and stripped one dynamically loaded ET_EXEC fixture, then checked all eight complete dataset outputs and full zero journals for each original. All 30 bounded stages completed as specified: 24 returned zero, and six required refusals returned their exact 64/65/67 statuses. Refusals are labelled separately. There were zero rewrites.\n\n`commands.json` retains every stage request, outer command, result and strict receipt, plus the enclosing recipe invocation. `commands.csv` presents the 30 ordered stage rows; `cases.csv` separates 16 original-output checks and six required refusals. Times are operational diagnostics, not benchmarks. `$REPO`, `$RAW` and `$LAUNCH` are injective path symbols with a private inverse.\n\n`artifacts.json` reports binary, metadata and original ELF slice hashes without publishing binaries, logs or journals. `source-files.json` binds the saved before/after map to every Git blob at the tested revision. This does not establish instruction/dataflow completeness, rewritten execution, hook equivalence, architectural state or full A3 qualification. The collector source revision is recorded separately and its running bytes must equal the tracked Git blob before and after collection.\n').encode()
    for name, data in public.items():
        text = data.decode()
        assert not locations.search(text)
        assert not re.search(r'/home/|/Users/|/root/|[A-Za-z0-9_-]+\.(?:facebook\.com|internal|internalfb\.com)', text)
        assert not name.startswith('/') and len(data) <= MAX_FILE
    public['files.json'] = encoded({name: sha(data) for name, data in sorted(public.items())})
    for path, data in blobs.items():
        now, owner = read(Path(path)); assert now == data and owner == owners[path]
    assert read(a.input_index) == (index_raw, index_owner)
    assert subprocess.check_output(git + ['rev-parse', 'HEAD'], timeout=15).decode().strip() == collector_revision
    assert read(collector_path) == (collector_bytes, collector_owner)
    assert subprocess.check_output(git + ['show', collector_revision + ':' + SOURCE + 'collect_preparation.py'], timeout=15) == collector_bytes
    binding = dict(schema=1, input_index_sha256=sha(index_raw), input_files=index['files'], input_owners=owners, roles=roles, exact_json_inverses=inverses, public_files={name: sha(data) for name, data in public.items()}, tested_source_revision=REVISION, parent_confirmation=dict(session_id=a.parent_session, closed_and_reaped=a.parent_closed_reaped, source='explicit caller observation; saved launch result cross-checked'), collector_source_sha256=sha(collector_bytes), collector_source_path=SOURCE + 'collect_preparation.py', collector_tested_revision=collector_revision, qualification_complete=False)
    a.new_output.mkdir(mode=0o700)
    (a.new_output / 'public').mkdir(mode=0o755)
    for name, data in public.items():
        with (a.new_output / 'public' / name).open('xb') as stream:
            stream.write(data)
    with (a.new_output / 'private-binding.json').open('xb') as stream:
        stream.write(encoded(binding))
    print('preparation collection: 30 stages / 16 original outputs / 6 required refusals / 0 rewrites')


if __name__ == '__main__':
    main()
