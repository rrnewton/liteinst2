#!/usr/bin/env python3
"""Build current common-corpus tools and inventory originals; never rewrite/run them."""
import argparse
import errno
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

PREPARED = 'ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
LIMITS = [1048576, 64, 256, 8388608, 2048, 16777216, 12582912, 512, 1073741824]
SEARCH = [64, 256, 64, 256, 4096]
ARENAS = [('selected', 0x10000000), ('victim', 0x18000000)]
DERIVED_DOMAIN = (65536, 1073741824)
RUNTIME = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
FUNCTIONS = ['li2_array_store', 'li2_sift_down', 'li2_heap_sort']
SYMBOLS = FUNCTIONS + ['main', 'li2_before_sort', 'li2_after_sort', 'li2_null_hook', 'li2_record_hook', 'li2_run', 'li2_journal']
PROFILE = dict(opt_level='0', debuginfo=2, debug_assertions=True, overflow_checks=True, test=False)
CAP = 128 * 1024 * 1024


# This is orthogonal to allocation/planning/router profiles. Absence is legacy.
DEBUG0_BUILD_PROFILE = 'dev-debug0-v1'
DEBUG0_PROFILE = dict(opt_level='0', debuginfo=0, debug_assertions=True, overflow_checks=True, test=False)
DEBUG0_ENV = dict(CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
    CARGO_PROFILE_DEV_OPT_LEVEL='0', CARGO_PROFILE_TEST_OPT_LEVEL='0',
    CARGO_PROFILE_DEV_DEBUG_ASSERTIONS='true', CARGO_PROFILE_TEST_DEBUG_ASSERTIONS='true',
    CARGO_PROFILE_DEV_OVERFLOW_CHECKS='true', CARGO_PROFILE_TEST_OVERFLOW_CHECKS='true')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def loads(data):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            assert k not in result, 'duplicate JSON key'
            result[k] = v
        return result
    def invalid(value):
        raise AssertionError('non-JSON constant ' + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def path(value, directory=False):
    p = Path(value)
    assert p.is_absolute() and str(p) == str(value) and '..' not in p.parts
    assert p.parent.resolve(strict=True) == p.parent
    if directory:
        assert p.resolve(strict=True) == p and p.is_dir()
    return p


def read(p):
    p = path(str(p))
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        a = os.fstat(stream.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= CAP
        data = stream.read(CAP + 1)
        b = os.fstat(stream.fileno())
    fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    assert fields(a) == fields(b) == fields(p.stat()) and len(data) == a.st_size
    return data, fields(a)


def write(p, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    with path(str(p)).open('xb') as stream:
        stream.write(data)


def git(repo, *args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], env=RUNTIME, timeout=30)


def source(repo):
    revision = git(repo, 'rev-parse', 'HEAD').decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', revision) and not git(repo, 'diff', 'HEAD', '--')
    files, owners = {}, {}
    for row in git(repo, 'ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
        if not row:
            continue
        metadata, name = row.split(b'\t', 1)
        mode, kind, oid = metadata.decode().split()
        name = name.decode()
        assert kind == 'blob' and mode in ('100644', '100755') and not Path(name).is_absolute() and '..' not in Path(name).parts
        data, owner = read(repo / name)
        assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid
        assert bool(owner[2] & 0o111) == (mode == '100755')
        files[name] = dict(sha256=sha(data), bytes=len(data), mode=mode)
        owners[name] = owner
    assert 'evaluation/e9-common-app/build_inventory.py' in files
    assert 'evaluation/required-gates.py' in files and 'BRIEF-li2core.md' not in files
    return dict(revision=revision, files=files, owners=owners)


def elf(data):
    assert 64 <= len(data) <= LIMITS[0] and data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', data, 16) == (2, 62, 1)
    assert struct.unpack_from('<HH', data, 52) == (64, 56)
    off = struct.unpack_from('<Q', data, 32)[0]
    count = struct.unpack_from('<H', data, 56)[0]
    assert 1 <= count <= 128 and off + 56 * count <= len(data)
    ph = [struct.unpack_from('<IIQQQQQQ', data, off + 56 * i) for i in range(count)]
    assert sum(p[0] == 3 for p in ph) == 1
    for p in ph:
        if p[0] == 1:
            assert p[5] <= p[6] and p[2] + p[5] <= len(data) and p[3] + p[6] < 1 << 47
            assert p[1] in (4, 5, 6) and p[2] % 4096 == p[3] % 4096
    off = struct.unpack_from('<Q', data, 40)[0]
    width, count, names = struct.unpack_from('<HHH', data, 58)
    assert width == 64 and 0 < count <= 4096 and names < count and off + 64 * count <= len(data)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, off + 64 * i) for i in range(count)]
    assert all(s[1] == 8 or s[4] + s[5] <= len(data) for s in sections)
    string_table = sections[names]
    strings = data[string_table[4]:string_table[4] + string_table[5]]
    def string(table, at):
        assert at < len(table) and b'\0' in table[at:]
        return table[at:].split(b'\0', 1)[0].decode('ascii')
    text = [s for s in sections if string(strings, s[0]) == '.text']
    assert len(text) == 1 and text[0][1] == 1 and text[0][2] & 6 == 6
    symbols = {}
    tables = [s for s in sections if s[1] == 2]
    for s in tables:
        assert s[9] == 24 and s[5] % 24 == 0 and s[6] < count
        t = sections[s[6]]
        names = data[t[4]:t[4] + t[5]]
        for at in range(s[4], s[4] + s[5], 24):
            n, info, _, section, va, length = struct.unpack_from('<IBBHQQ', data, at)
            name = string(names, n)
            if name in SYMBOLS:
                assert section and name not in symbols and length > 0
                symbols[name] = dict(address=va, bytes=length, kind=info & 15)
    return ph, text[0], tables, symbols


def original_geometry(left, right):
    ph, text, tables, symbols = elf(left)
    ph2, text2, tables2, _ = elf(right)
    assert ph == ph2 and text[1:] == text2[1:] and len(tables) == 1 and not tables2
    for p in ph:
        if p[0] != 1:
            continue
        a, b = bytearray(left[p[2]:p[2] + p[5]]), bytearray(right[p[2]:p[2] + p[5]])
        for at in list(range(40, 48)) + list(range(60, 64)):
            if p[2] <= at < p[2] + p[5]:
                a[at - p[2]] = b[at - p[2]] = 0
        assert a == b, 'original section-table-only strip mask'
    assert symbols.keys() == set(SYMBOLS)
    for name, row in symbols.items():
        expected_kind = 1 if name in ('li2_run', 'li2_journal') else 2
        assert row['kind'] == expected_kind
        p = [p for p in ph if p[0] == 1 and p[3] <= row['address'] and row['address'] + row['bytes'] <= p[3] + p[5]]
        assert len(p) == 1 and p[0][1] == (6 if expected_kind == 1 else 5)
        offset = p[0][2] + row['address'] - p[0][3]
        a = left[offset:offset + row['bytes']]
        assert a == right[offset:offset + row['bytes']]
        row.update(file_offset=offset, sha256=sha(a))
    assert symbols['li2_array_store']['bytes'] == 5
    p = symbols['li2_array_store']['file_offset']
    assert left[p:p + 5] == bytes.fromhex('488914f7c3')
    for name in ('li2_before_sort', 'li2_after_sort', 'li2_null_hook'):
        s = symbols[name]
        assert s['bytes'] == 1 and left[s['file_offset']:s['file_offset'] + 1] == b'\xc3'
    assert symbols['li2_run']['bytes'] == 88 and symbols['li2_journal']['bytes'] == 131144
    assert left[text[4]:text[4] + text[5]] == right[text[4]:text[4] + text[5]]
    return dict(program_headers=ph, text=dict(address=text[3], file_offset=text[4], bytes=text[5], sha256=sha(left[text[4]:text[4] + text[5]])), symbols=symbols)


def depfile_rules(text):
    # Exact rustc/Cargo Make-style tokens; no substring source or target match.
    assert text.endswith('\n') and '\r' not in text and '\0' not in text
    rules = []
    for line in text.splitlines():
        if not line.strip():
            continue
        words, token, index = [], '', 0
        while index < len(line):
            char = line[index]
            if char == '\\':
                index += 1
                assert index < len(line) and line[index] in '\\ \t:#'
                token += line[index]
            elif char == '$':
                index += 1
                assert index < len(line) and line[index] == '$'
                token += '$'
            elif char in ' \t:':
                if token:
                    words.append(token)
                    token = ''
                if char == ':':
                    words.append(None)
            else:
                assert char != '#'
                token += char
            index += 1
        if token:
            words.append(token)
        assert words.count(None) == 1 and words.index(None) == 1
        rules.append((words[0], words[2:]))
    assert rules
    return rules


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home', 'inputs'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--allocation-profile', choices=('fixed-v1', 'original-derived-v1'), default='fixed-v1')
    parser.add_argument('--build-profile', choices=('legacy', DEBUG0_BUILD_PROFILE), default='legacy')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert git(repo, 'rev-parse', '--show-toplevel').decode().strip() == str(repo)
    raw = path(str(args.raw))
    assert raw.is_relative_to(repo / 'ignored') and not raw.exists() and not raw.is_symlink()
    for p in (args.toolchain, args.user_home, args.cargo_home):
        path(str(p), directory=True)
    before = source(repo)
    revision = before['revision']
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    assert sha(read(helper)[0]) == HELPER_SHA
    input_bytes, input_owner = read(args.inputs)
    assert re.fullmatch('[0-9a-f]{64}', args.inputs_sha256) and sha(input_bytes) == args.inputs_sha256
    inputs = loads(input_bytes)
    if args.build_profile == 'legacy':
        assert inputs.keys() == {'schema', 'preparation', 'collector_binding', 'files'} and inputs['schema'] == 1
    else:
        assert inputs.keys() == {'schema', 'preparation', 'collector_binding', 'files', 'build_profile'}
        assert type(inputs['schema']) is int and inputs['schema'] == 1
        assert inputs['build_profile'] == args.build_profile == DEBUG0_BUILD_PROFILE
    build_extra = {} if args.build_profile == 'legacy' else dict(build_profile=DEBUG0_BUILD_PROFILE)
    watched = {str(args.inputs): (input_bytes, input_owner)}
    def bound(name):
        expected = inputs['files'][name]
        assert expected.keys() == {'sha256', 'bytes'}
        data, owner = read(name)
        assert sha(data) == expected['sha256'] and type(expected['bytes']) is int and len(data) == expected['bytes']
        if name in watched:
            assert watched[name] == (data, owner), 'input owner continuity, never refreshed'
        watched[name] = (data, owner)
        return data
    for name in inputs['files']:
        bound(name)
    prep = inputs['preparation']
    assert prep.keys() == {'summary', 'source', 'source_after', 'review_binding', 'originals'}
    summary = loads(bound(prep['summary']))
    assert summary['revision'] == PREPARED and summary['completed'] is True
    assert (summary['planned_stages'], summary['observed_stages'], summary['ordinary_original_runs'], summary['required_refusals'], summary['rewriting_runs']) == (30, 30, 16, 6, 0)
    assert summary['qualified'] is False and bound(prep['source']) == bound(prep['source_after'])
    prepared_source = loads(bound(prep['source']))
    assert prepared_source['revision'] == PREPARED
    for name, digest in prepared_source['files'].items():
        if name.startswith('evaluation/e9-common-app/'):
            assert before['files'][name]['sha256'] == digest, 'original fixture and preparation source retained'
    preparation_review = loads(bound(prep['review_binding']))
    assert preparation_review['verdict'] == 'CLOSED_ORIGINAL_PREPARATION_PASS_EXECUTION_RECORD_SCOPE'
    assert preparation_review['revision'] == PREPARED and preparation_review['qualification_complete'] is False
    assert (preparation_review['stages'], preparation_review['ordinary_original_runs'], preparation_review['required_refusals']) == (30, 16, 6)
    collector = loads(bound(inputs['collector_binding']))
    assert collector['schema'] == 1 and collector['tested_source_revision'] == PREPARED and collector['qualification_complete'] is False
    assert re.fullmatch('[0-9a-f]{40}', collector['collector_tested_revision'])
    for name, digest in collector['input_files'].items():
        assert sha(bound(name)) == digest
    for name in (prep['summary'], prep['source'], prep['source_after'], *prep['originals'].values()):
        assert name in collector['input_files']
    collected = path(inputs['collector_binding']).parent / 'public'
    assert set(collector['public_files']) == {'summary.json', 'commands.json', 'artifacts.json', 'source-files.json', 'commands.csv', 'cases.csv', 'README.md', 'files.json'}
    for name, digest in collector['public_files'].items():
        assert sha(bound(str(collected / name))) == digest
    collected_summary = loads(bound(str(collected / 'summary.json')))
    assert collected_summary['tested_revision'] == PREPARED and collected_summary['rewriting_runs'] == 0
    assert collected_summary['collection']['tested_revision'] == collector['collector_tested_revision']
    assert collected_summary['collection']['source_sha256'] == collector['collector_source_sha256']
    assert prep['originals'].keys() == {'unstripped', 'stripped'}
    originals = {v: bound(p) for v, p in prep['originals'].items()}
    for v, data in originals.items():
        assert summary['artifacts'][v] == dict(sha256=sha(data), bytes=len(data))
    geometry = original_geometry(originals['unstripped'], originals['stripped'])
    tool = args.toolchain / 'bin'
    env = dict(CARGO_BUILD_JOBS='4', CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true', CARGO_TARGET_DIR=str(repo / 'target'), CARGO_HOME=str(args.cargo_home), HOME=str(args.user_home), RUSTC=str(tool / 'rustc'), RUSTDOC=str(tool / 'rustdoc'), RUSTC_WORKSPACE_WRAPPER='', RUSTC_WRAPPER='', RUST_TEST_THREADS='4', LC_ALL='C', PATH=str(tool) + ':/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1')
    if build_extra:
        env.update(DEBUG0_ENV)
    tool_paths = [tool / n for n in ('cargo', 'rustc', 'rustdoc', 'rustfmt', 'clippy-driver')] + [Path('/usr/bin') / n for n in ('python3.9', 'timeout', 'git')]
    def tool_snapshot():
        result = {}
        for p in tool_paths:
            resolved = p.resolve(strict=True)
            data, owner = read(resolved)
            assert owner[2] & 0o111
            result[str(p)] = dict(resolved=str(resolved), sha256=sha(data), stat=owner)
        return result
    tools = tool_snapshot()
    config_paths = sorted({p / '.cargo' / n for p in (repo, *repo.parents) for n in ('config', 'config.toml')} | {args.cargo_home / n for n in ('config', 'config.toml')})
    def config_snapshot():
        result = {}
        for p in config_paths:
            try:
                exists = p.exists()
            except PermissionError as error:
                assert error.errno in (errno.EPERM, errno.EACCES)
                result[str(p)] = dict(observation='READ_DENIED', operation='metadata_lookup', errno=error.errno, exists=None, content_sha256=None)
                continue
            if not exists and not p.is_symlink():
                result[str(p)] = dict(exists=False)
            else:
                resolved = p.resolve(strict=True)
                data, owner = read(resolved)
                link = p.lstat()
                result[str(p)] = dict(exists=True, resolved=str(resolved), sha256=sha(data), stat=owner, lstat=[link.st_dev, link.st_ino, link.st_mode, link.st_size, link.st_mtime_ns, link.st_ctime_ns])
        return result
    configs = config_snapshot()
    cells_order = [(h, s, v) for h in ('null', 'journal') for s in ('jump-site', 'heap-write') for v in ('unstripped', 'stripped')]
    stages = ['required', 'native-compile', 'common-sites-compile', 'target'] + ['inventory-' + '-'.join(c) for c in cells_order]
    assert len(stages) == 12
    raw.mkdir(mode=0o700)
    for d in ('artifacts', 'policies', 'inventories'):
        (raw / d).mkdir()
    write(raw / 'inputs.json', input_bytes)
    write(raw / 'source.json', before)
    write(raw / 'tools.json', tools)
    write(raw / 'configs.json', configs)
    write(raw / 'config-scope.json', dict(invocation_cwd=str(repo), lookup='cwd and ancestors plus explicit CARGO_HOME; no changed compiler cwd', denied_lookup_is_absent=False, consumed_configuration_attested=False, scope='Observed lookup identities only; denied content remains unknown and a later open/read denial fails.'))
    write(raw / 'geometry.json', geometry)
    write(raw / 'stage-inventory.json', stages)
    placement = dict(arenas=ARENAS, stride=65536)
    if args.allocation_profile == 'original-derived-v1':
        placement = dict(allocation_profile=args.allocation_profile, domain_start=DERIVED_DOMAIN[0], domain_bytes=DERIVED_DOMAIN[1])
    write(raw / 'prospective-policy.json', dict(limits=LIMITS, search=SEARCH, **placement, slot_bytes=65536, max_candidates=65536, carrier=0x20000000, cells=cells_order, no_post_refusal_limit_change=True))
    write(raw / 'hardware.json', dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(), cpu_model=next(r.split(':', 1)[1].strip() for r in Path('/proc/cpuinfo').read_text().splitlines() if r.startswith('model name')), logical_cpus=os.cpu_count(), kernel_release=platform.release(), libc=platform.libc_ver()))
    results, archives, cells, products = [], {}, {}, {}
    completed = False
    failure = None
    phase = 'required'

    def execute(name, argv, environment, compiler=False, required=False):
        assert name == stages[len(results)]
        directory = raw / name
        directory.mkdir()
        (directory / 'tmp').mkdir()
        environment = dict(environment, TMPDIR=str(directory / 'tmp'))
        command = dict(name=name, argv=list(map(str, argv)), cwd=str(repo), env=environment)
        if required:
            actual, outer_env, timeout = command['argv'], environment, 1000
            out, err = 'stdout.txt', 'stderr.txt'
        else:
            req = dict(argv=command['argv'], cwd=str(repo), env=environment, stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'), cpu_seconds=60 if compiler else 20, wall_seconds=90 if compiler else 30, file_bytes=(128 if compiler else 16) * 1024 * 1024)
            write(directory / 'request.json', req)
            actual = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', '100s' if compiler else '40s', '/usr/bin/python3.9', '-B', str(helper), '--request', str(directory / 'request.json'), '--receipt', str(directory / 'receipt.json')]
            command['request'] = req
            outer_env, timeout, out, err = RUNTIME, 115 if compiler else 55, 'helper.stdout', 'helper.stderr'
        command.update(outer_argv=actual, outer_env=outer_env, parent_timeout_seconds=timeout)
        write(directory / 'command.json', command)
        started = time.monotonic()
        timed_out = False
        with (directory / out).open('xb') as stdout, (directory / err).open('xb') as stderr:
            process = subprocess.Popen(actual, cwd=repo, env=outer_env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
                timed_out = True
        row = dict(command, exit=code, elapsed_seconds=time.monotonic() - started, parent_timeout=timed_out)
        results.append(row)
        write(directory / 'result.json', row)
        print(name, code, flush=True)
        if not required:
            r = loads(read(directory / 'receipt.json')[0])
            assert r.keys() == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout', 'unexpected_descendants', 'absence_proof', 'stdout_sha256', 'stderr_sha256', 'elapsed_seconds', 'cleanup_events', 'cleanup_error', 'aborted', 'inputs_unchanged'}
            assert type(r['exit']) is int and r['request_sha256'] == sha(read(directory / 'request.json')[0]) and r['helper_sha256'] == HELPER_SHA
            assert r['wall_timeout'] is False and r['inputs_unchanged'] is True and r['absence_proof'] == 'ECHILD'
            assert r['unexpected_descendants'] == r['cleanup_events'] == [] and r['cleanup_error'] is r['aborted'] is None
            assert type(r['elapsed_seconds']) in (int, float) and math.isfinite(r['elapsed_seconds']) and 0 <= r['elapsed_seconds'] <= req['wall_seconds']
            assert (directory / 'helper.stdout').read_bytes() == (json.dumps(dict(exit=r['exit'], wall_timeout=False, absence_proof='ECHILD', descendants=0, success=r['exit'] == 0)) + '\n').encode()
            assert not (directory / 'helper.stderr').read_bytes()
            for key in ('stdout', 'stderr'):
                assert r[key + '_sha256'] == sha((directory / (key + '.txt')).read_bytes())
            assert r['exit'] == 0, 'nonzero child retained; later stages unrun'
        assert not timed_out and code == 0, 'failed stage retained; later stages unrun'
        return directory

    def archive(compilation, selected):
        messages = [loads(line) for line in read(compilation / 'stdout.txt')[0].splitlines()]
        assert 1 <= len(messages) <= 512 and messages[-1] == dict(reason='build-finished', success=True)
        assert sum(r.get('reason') == 'build-finished' for r in messages) == 1
        assert all(r.get('reason') in ('compiler-artifact', 'build-script-executed', 'build-finished') for r in messages)
        assert not any(line.startswith(('warning:', 'error:')) for line in read(compilation / 'stderr.txt')[0].decode().splitlines())
        dest = raw / 'artifacts' / compilation.name
        dest.mkdir()
        copied = {}
        def copy(p):
            p = path(str(p))
            assert p.is_relative_to(repo / 'target')
            data, owner = read(p)
            if str(p) not in copied:
                to = dest / ('product-' + str(len(copied)))
                write(to, data)
                os.chmod(to, stat.S_IMODE(owner[2]))
                assert read(p) == (data, owner) and read(to)[0] == data
                copied[str(p)] = dict(path=str(to), sha256=sha(data), bytes=len(data), original_owner=owner, archive_owner=read(to)[1])
            else:
                assert owner == copied[str(p)]['original_owner'] and sha(data) == copied[str(p)]['sha256']
            return copied[str(p)]
        for row in messages:
            if row['reason'] == 'compiler-artifact':
                assert type(row['fresh']) is bool and row['filenames']
                for p in row['filenames']:
                    copy(p)
        chosen = {}
        for name, package, kind, relative_source in selected:
            rows = [r for r in messages if r['reason'] == 'compiler-artifact' and r['target']['name'] == name and r.get('executable')]
            assert len(rows) == 1
            row = rows[0]
            expected = repo / 'target/debug' / ('examples/' + name if kind == 'example' else name)
            assert row['manifest_path'] == str(repo / package / 'Cargo.toml')
            package_name = 'liteinst2' if not package else 'liteinst-rewrite'
            assert row['package_id'] == 'path+' + (repo / package).as_uri() + '#' + package_name + '@0.1.0'
            assert row['target']['kind'] == [kind] and row['target']['crate_types'] == ['bin']
            assert row['target']['edition'] == '2024'
            assert row['target']['src_path'] == str(repo / relative_source)
            if not build_extra:
                assert row['profile'] == PROFILE and row['features'] == []
            else:
                assert row['profile'] == DEBUG0_PROFILE and row['features'] == []
                assert all(type(row['profile'][k]) is type(v) for k, v in DEBUG0_PROFILE.items())
            assert row['filenames'] == [str(expected)] and row['executable'] == str(expected)
            product = copy(expected)
            assert product['original_owner'][2] & 0o111
            dep = expected.with_suffix('.d')
            saved_dep = copy(dep)
            rules = depfile_rules(read(dep)[0].decode())
            assert len(rules) == 1 and rules[0][0] == str(expected) and rules[0][1]
            bindings = {}
            for spelling in rules[0][1]:
                p = Path(spelling)
                assert p.is_absolute() and p.resolve(strict=True) == p and p.is_relative_to(repo)
                member = p.relative_to(repo).as_posix()
                assert member in before['files'] and member not in bindings
                data, _ = read(p)
                assert sha(data) == before['files'][member]['sha256']
                bindings[member] = before['files'][member]
            assert relative_source in bindings
            chosen[name] = dict(cargo=row, product=product, depfile=saved_dep, source_bindings=bindings)
            products[name] = product['path']
        report = dict(schema=1, source_revision=revision, source_files_sha256=sha(encode(before['files'])), command_result_sha256=sha(read(compilation / 'result.json')[0]), cargo_stdout_sha256=sha(read(compilation / 'stdout.txt')[0]), artifacts=copied, selected=chosen,
                      scope='Complete Cargo-reported products and exact selected Cargo alias depfiles/source members; not a whole target, system-header, configuration or loader closure.')
        report.update(build_extra)
        write(compilation / 'artifact-archive.json', report)
        archives[compilation.name] = report

    try:
        d = execute('required', ['/usr/bin/python3.9', '-B', repo / 'evaluation/required-gates.py', '--repo', repo, '--output', raw / 'required/gates'], env, required=True)
        gates = loads(read(d / 'gates/commands.json')[0])
        assert gates['head'] == revision and gates['source_sha256'] == {n: r['sha256'] for n, r in before['files'].items()}
        assert [(r['name'], r['exit']) for r in gates['records']] == [('fmt', 0), ('clippy', 0), ('test', 0), ('check', 0)]
        assert [r['timeout_seconds'] for r in gates['records']] == [180, 180, 360, 180]
        for r in gates['records']:
            assert sha(read(repo / r['log'])[0]) == r['sha256']
        phase = 'native-compile'
        d = execute(phase, [tool / 'cargo', 'build', '-p', 'liteinst2', '-p', 'liteinst-rewrite', '--bin', 'elf-exec-oracle', '--bin', 'liteinst-rewrite', '--offline', '--locked', '--message-format=json'], env, compiler=True)
        archive(d, [('elf-exec-oracle', '', 'bin', 'tests/support/elf_exec_driver.rs'), ('liteinst-rewrite', 'tools/elf-rewrite', 'bin', 'tools/elf-rewrite/src/main.rs')])
        phase = 'common-sites-compile'
        d = execute(phase, [tool / 'cargo', 'build', '-p', 'liteinst-rewrite', '--example', 'common_sites', '--offline', '--locked', '--message-format=json'], env, compiler=True)
        archive(d, [('common_sites', 'tools/elf-rewrite', 'example', 'tools/elf-rewrite/examples/common_sites.rs')])
        phase = 'target'
        d = execute(phase, [products['elf-exec-oracle'], 'target'], RUNTIME)
        target = read(d / 'stdout.txt')[0]
        assert len(target) <= 4096 and target.isascii() and target.endswith(b'\n') and target.count(b'\n') == 1
        assert re.fullmatch(rb'target xsave64 [0-9]+(?: [0-9]+:[0-9]+:[0-9]+)*\n', target)
        assert not read(d / 'stderr.txt')[0]
        symbols, text = geometry['symbols'], geometry['text']
        layout = ['LI2COMMONOBSERVER\t1']
        for n in FUNCTIONS + ['main']:
            s = symbols[n]
            layout.append(f"function\t{n}\t0x{s['address']:x}\t{s['bytes']}")
        for n in ('li2_before_sort', 'li2_after_sort'):
            s = symbols[n]
            layout.append(f"marker\t{n}\t0x{s['address']:x}\t{s['bytes']}")
        for n in ('li2_run', 'li2_journal'):
            s = symbols[n]
            layout.append(f"object\t{n}\t0x{s['address']:x}\t{s['bytes']}")
        write(raw / 'observer-layout.tsv', ('\n'.join(layout + ['END']) + '\n').encode())
        policies = {}
        for variant in ('unstripped', 'stripped'):
            provenance = raw / 'policies' / (variant + '-provenance.json')
            provenance_placement = dict(arenas=ARENAS) if args.allocation_profile == 'fixed-v1' else placement
            write(provenance, dict(schema=1, authority='CALLER_PINNED_ORIGINAL_PREPARATION_AND_COLLECTOR', input_envelope_sha256=sha(input_bytes), prepared_revision=PREPARED, current_build_revision=revision, preparation_summary_sha256=sha(bound(prep['summary'])), collector_binding_sha256=sha(bound(inputs['collector_binding'])), original_sha256=sha(originals[variant]), target_sha256=sha(target), geometry=geometry, prospective_limits=LIMITS, search=SEARCH, carrier=0x20000000, **provenance_placement, qualification_complete=False))
            version = 1 if args.allocation_profile == 'fixed-v1' else 2
            lines = [f'LI2COMMON {version}', 'original ' + sha(originals[variant]), 'target ' + sha(target), 'provenance ' + sha(read(provenance)[0]), f"text 0x{text['address']:x} {text['file_offset']} {text['bytes']} {text['sha256']}"]
            for n in FUNCTIONS:
                s = symbols[n]
                lines.append(f"function {n} 0x{s['address']:x} {s['bytes']} {s['sha256']}")
            for ident, n in [(2, 'li2_null_hook'), (3, 'li2_record_hook')]:
                s = symbols[n]
                lines.append(f"hook {ident} 0x{s['address']:x} {s['bytes']} {s['sha256']}")
            lines += ['carrier 0x20000000']
            if args.allocation_profile == 'fixed-v1':
                lines += [f'arena {name} 0x{base:x} 65536 65536 65536' for name, base in ARENAS]
            else:
                lines += [f'placement original-derived-v1 {DERIVED_DOMAIN[0]} {DERIVED_DOMAIN[1]}']
                lines += [f'arena {name} 65536 65536' for name, _ in ARENAS]
            lines += ['limits ' + ' '.join(map(str, LIMITS)), 'search ' + ' '.join(map(str, SEARCH)), 'END']
            policy = raw / 'policies' / (variant + '.txt')
            write(policy, ('\n'.join(lines) + '\n').encode())
            policies[variant] = (policy, provenance)
        tables = None
        site_tables = {}
        for hook, style, variant in cells_order:
            key = '-'.join((hook, style, variant))
            phase = 'inventory-' + key
            output = raw / 'inventories' / key
            policy, provenance = policies[variant]
            d = execute(phase, [products['common_sites'], prep['originals'][variant], policy, raw / 'target/stdout.txt', style, hook, output], RUNTIME)
            expected = {'COMPLETE', 'instructions.tsv', 'sites.tsv', 'memory-writes.tsv', 'blocks.tsv', 'padding.tsv', 'policy.txt', 'target.txt', 'status.tsv', 'selection.txt'}
            assert {p.name for p in output.iterdir()} == expected
            data = {}
            for name in sorted(expected):
                p = output / name
                data[name], owner = read(p)
                assert stat.S_IMODE(owner[2]) == 0o600
            rows = data['COMPLETE'].decode().splitlines()
            assert rows[0] == 'LI2COMMONFILES\t1'
            assert rows[1:] == [f"{sha(data[name])}\t{len(data[name])}\t{name}" for name in sorted(expected - {'COMPLETE'})]
            assert data['policy.txt'] == read(policy)[0] and data['target.txt'] == target
            rows = data['status.tsv'].decode().splitlines()
            assert rows[0] == 'LI2COMMONRESULT\t1' and len(rows) == 12
            status = {}
            for row in rows[1:]:
                k, v = row.split('\t')
                assert k not in status
                status[k] = v
            heads = data['instructions.tsv'].count(b'\n') - 1
            sites = data['sites.tsv'].count(b'\n') - 1
            assert heads > 0 and 0 < sites <= LIMITS[1]
            assert status == dict(original_sha256=sha(originals[variant]), policy_sha256=sha(data['policy.txt']), caller_provenance_sha256=sha(read(provenance)[0]), target_sha256=sha(target), style=style, hook=hook, instruction_heads=str(heads), selected_sites=str(sites), complete_static_policy='true', qualification_complete='false', selection_sha256=sha(data['selection.txt']))
            assert data['selection.txt'].startswith(b'LI2TOOL 1\n')
            assert read(d / 'stdout.txt')[0] == f'common sites: heads={heads} selected={sites} style={style} hook={hook} complete_static_policy=true qualification_complete=false\n'.encode()
            assert not read(d / 'stderr.txt')[0]
            current = {n: data[n] for n in ('instructions.tsv', 'memory-writes.tsv', 'blocks.tsv', 'padding.tsv')}
            if tables is None:
                tables = current
            assert current == tables, 'all styles/hooks/strip forms retain every same decoded head, writer, block and padding byte'
            if style not in site_tables:
                site_tables[style] = data['sites.tsv']
            assert data['sites.tsv'] == site_tables[style], 'whole same-style site rows remain identical across hooks and strip forms'
            cells[key] = dict(directory=str(output), run_directory=str(d), provenance=str(provenance))
            write(d / 'inventory-files.json', {n: dict(sha256=sha(b), bytes=len(b)) for n, b in data.items()})
        completed = True
    except BaseException as error:
        failure = dict(phase=phase, type=type(error).__name__, message=str(error))
        raise
    finally:
        write(raw / 'results.json', results)
        write(raw / 'cells.json', cells)
        write(raw / 'artifacts.json', archives)
        after = source(repo)
        write(raw / 'source-after.json', after)
        tools_after = tool_snapshot()
        write(raw / 'tools-after.json', tools_after)
        configs_after = config_snapshot()
        write(raw / 'configs-after.json', configs_after)
        for p, value in watched.items():
            assert read(p) == value, 'original preparation/collector input owner or bytes changed'
        assert after == before and tools_after == tools and configs_after == configs
        for archive_record in archives.values():
            for row in archive_record['artifacts'].values():
                data, owner = read(row['path'])
                assert sha(data) == row['sha256'] and owner == row['archive_owner']
        write(raw / 'summary.json', dict(schema=1, revision=revision, completed=completed, failure=failure, last_phase=phase, planned_stages=stages, observed_stages=len(results), unrun_stages=stages[len(results):], cells_complete=len(cells), preparation_revision=PREPARED, original_execution_credit=False, rewriting_runs=0, native_application_runs=0, target_observation_only=True, qualification_complete=False, source_before_after_equal=True, selected_tools_before_after_equal=True, source_scope='Current exact clean committed build and static inventory; prior original preparation remains a separate revision.', archive_scope='Cargo-reported files and selected depfile/source joins only; full archive review and caller admission remain separate.', **build_extra))
    assert completed
    evidence = [str(p) for p in sorted(raw.rglob('*')) if p.is_file() and not p.is_relative_to(raw / 'artifacts')]
    required_products = sorted({r['path'] for a in archives.values() for r in a['artifacts'].values()})
    write(raw / 'build-admission-proposal.json', dict(schema=1, authority='CALLER_AUTHENTICATED_BUILD_PRODUCTS', source_revision=revision, source_files_sha256=sha(encode(before['files'])), products=dict(core=products['liteinst-rewrite'], common_sites=products['common_sites']), required_products=required_products, evidence_files=evidence, scope='core-cli-and-common-sites-build-only', **(dict(directory=str(raw), **build_extra) if build_extra else {})))
    print('PASS common build and eight complete original inventories; no rewrite or native application execution')


if __name__ == '__main__':
    main()
