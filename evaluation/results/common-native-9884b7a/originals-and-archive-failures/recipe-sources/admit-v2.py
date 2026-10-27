#!/usr/bin/env python3
"""Admit retained verifier copies in a new explicit owner epoch; no compilation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

CAP = 128 * 1024 * 1024
FROZEN_SHA = 'afb243e34bf17184603eca126e62d993dd502661910eec72508d8c967c8150be'
HELPER = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
PROFILE = dict(opt_level='0', debuginfo=2, debug_assertions=True, overflow_checks=True, test=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def fields(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path):
    path = Path(path)
    assert path.is_absolute() and path.parent.resolve(strict=True) == path.parent
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= CAP
        data = f.read(CAP + 1)
        assert len(data) == before.st_size and fields(before) == fields(os.fstat(f.fileno())) == fields(path.lstat())
        return data, fields(before)


def loads(data):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            assert k not in result
            result[k] = v
        return result
    def invalid(value):
        raise AssertionError(value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def depfile_rules(text):
    # Literal existing build_inventory.py parser; representation change is below.
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


def source_alias(repo, spelling, expected, git_bytes):
    """Walk actual lexical directories, never normalize past an unchecked owner."""
    prefix = str(repo) + '/'
    assert spelling.startswith(prefix), 'exact repository prefix required'
    parts = spelling[len(prefix):].split('/')
    assert parts and all(p not in ('', '.') for p in parts) and parts[-1] != '..'
    descriptors, stack, proofs = [], [], []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    def hold(path, name=None, parent=None):
        fd = os.open(path if name is None else name, flags, dir_fd=parent)
        descriptors.append(fd)
        st = os.fstat(fd); assert stat.S_ISDIR(st.st_mode)
        assert fields(st) == fields(os.stat(path, follow_symlinks=False))
        proofs.append((str(path), fd, fields(st)))
        return fd
    def stable():
        for path, fd, owner in proofs:
            assert fields(os.fstat(fd)) == fields(os.stat(path, follow_symlinks=False)) == owner, 'directory drift'
    try:
        current = Path('/'); fd = hold(current)
        for part in repo.parts[1:]:
            current = current / part; fd = hold(current, part, fd)
        stack = [(repo, fd)]
        for part in parts[:-1]:
            if part == '..':
                assert len(stack) > 1, 'lexical escape, even if later returning'
                parent = stack[-2]
                up = hold(parent[0], '..', stack[-1][1])
                assert fields(os.fstat(up)) == fields(os.fstat(parent[1]))
                stack.pop()
            else:
                parent_path, parent_fd = stack[-1]
                child_path = parent_path / part
                stack.append((child_path, hold(child_path, part, parent_fd)))
        canonical = stack[-1][0] / parts[-1]
        member = canonical.relative_to(repo).as_posix()
        assert member == expected['canonical_member']
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=stack[-1][1])
        with os.fdopen(fd, 'rb') as f:
            before = os.fstat(f.fileno())
            assert stat.S_ISREG(before.st_mode) and before.st_size == expected['bytes'] <= CAP
            data = f.read(CAP + 1)
            assert fields(before) == fields(os.fstat(f.fileno())) == fields(canonical.lstat())
            assert data == git_bytes and sha(data) == expected['sha256'] and len(data) == expected['bytes']
            assert bool(before.st_mode & 0o111) == (expected['mode'] == '100755')
            stable()
            # Read the original, unnormalized spelling as well. All intermediates
            # were held above; compare the resulting leaf's whole bytes and owner.
            with os.fdopen(os.open(spelling, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as alias:
                assert fields(os.fstat(alias.fileno())) == fields(before)
                assert alias.read(CAP + 1) == data
                assert fields(os.fstat(alias.fileno())) == fields(before)
            stable()
            assert fields(canonical.lstat()) == fields(before)
            return dict(spelling=spelling, canonical_member=member, sha256=sha(data), bytes=len(data),
                        mode=expected['mode'], fresh_owner=fields(before),
                        directory_observations=[dict(path=p, owner=s) for p, _, s in proofs])
    finally:
        for fd in reversed(descriptors): os.close(fd)


def unique_bindings(rows):
    assert len({r['canonical_member'] for r in rows}) == len(rows)
    assert len({tuple(r['fresh_owner'][:2]) for r in rows}) == len(rows), 'duplicate physical source alias'


def main():
    assert not sys.flags.optimize
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--new-output', type=Path, required=True)
    a = p.parse_args(); repo = a.repo
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert a.new_output.is_absolute() and a.new_output.parent.resolve(strict=True) == a.new_output.parent
    assert a.new_output.is_relative_to(repo / 'ignored') and not a.new_output.exists() and not a.new_output.is_symlink()
    self_before = read(Path(__file__).absolute())
    frozen_path = Path(__file__).absolute().with_name('FROZEN.json')
    frozen_before = read(frozen_path); assert sha(frozen_before[0]) == FROZEN_SHA
    frozen = loads(frozen_before[0]); raw = repo / frozen['raw']; d = raw / 'verifier-compile'
    assert not a.new_output.is_relative_to(raw)
    records = {}
    for pin in frozen['records']:
        path = repo / pin['path']; records[str(path)] = read(path)
        assert sha(records[str(path)][0]) == pin['sha256'] and len(records[str(path)][0]) == pin['bytes']
    def obj(path): return loads(records[str(path)][0])
    def git(*args):
        r = subprocess.run(['/usr/bin/git', '-C', str(repo), *args], env=dict(PATH='/usr/bin:/bin', LC_ALL='C'),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
        assert not r.stderr and len(r.stdout) <= CAP
        return r.stdout
    revision = frozen['revision']; assert git('rev-parse', 'HEAD').decode().strip() == revision
    assert not git('diff', '--binary', 'HEAD')
    source = obj(raw / 'source.json'); assert source['revision'] == revision
    request = obj(d / 'request.json'); old = obj(repo / 'ignored/a3/e9-common-build-b0d94f0-v1/common-sites-compile/request.json')
    expected_request = loads(encoded(old)); assert expected_request['argv'][5] == 'common_sites'
    expected_request['argv'][5] = 'verify_common_core'
    for k in ('stdout', 'stderr'): expected_request[k] = str(d / (k + '.txt'))
    expected_request['env']['TMPDIR'] = str(d / 'tmp')
    assert request == expected_request
    result = obj(d / 'result.json'); receipt = obj(d / 'receipt.json')
    assert result == dict(obj(d / 'command.json'), exit=0, elapsed_seconds=result['elapsed_seconds'], parent_timeout=False)
    assert receipt.keys() == {'request_sha256','helper_sha256','exit','wall_timeout','unexpected_descendants','absence_proof','stdout_sha256','stderr_sha256','elapsed_seconds','cleanup_events','cleanup_error','aborted','inputs_unchanged'}
    assert type(receipt['exit']) is int and receipt['exit'] == 0 and receipt['request_sha256'] == sha(records[str(d / 'request.json')][0])
    assert receipt['helper_sha256'] == HELPER and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
    assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
    assert receipt['cleanup_error'] is receipt['aborted'] is None and 0 <= receipt['elapsed_seconds'] <= 90
    for k in ('stdout', 'stderr'): assert receipt[k + '_sha256'] == sha(records[str(d / (k + '.txt'))][0])
    assert not records[str(d / 'helper.stderr')][0]
    assert records[str(d / 'helper.stdout')][0] == (json.dumps(dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True))+'\n').encode()
    messages = [loads(line) for line in records[str(d / 'stdout.txt')][0].splitlines()]
    assert len(messages) == 27 and messages[-1] == dict(reason='build-finished', success=True)
    assert [sum(m['reason'] == k for m in messages) for k in ('compiler-artifact','build-script-executed','build-finished')] == [23,3,1]
    assert not any(line.startswith(('warning:', 'error:')) for line in records[str(d / 'stderr.txt')][0].decode().splitlines())
    paths = []
    for m in messages:
        if m['reason'] == 'compiler-artifact':
            assert type(m['fresh']) is bool and m['filenames']
            for name in m['filenames']:
                if name not in paths: paths.append(name)
    selected = [m for m in messages if m.get('target', {}).get('name') == 'verify_common_core' and m.get('executable')]
    assert len(selected) == 1; selected = selected[0]
    product = repo / 'target/debug/examples/verify_common_core'
    assert selected['manifest_path'] == str(repo / 'tools/elf-rewrite/Cargo.toml')
    assert selected['package_id'] == 'path+' + (repo / 'tools/elf-rewrite').as_uri() + '#liteinst-rewrite@0.1.0'
    assert selected['target']['kind'] == ['example'] and selected['target']['crate_types'] == ['bin'] and selected['target']['edition'] == '2024'
    assert selected['target']['src_path'] == str(repo / 'tools/elf-rewrite/examples/verify_common_core.rs')
    assert selected['profile'] == PROFILE and selected['features'] == [] and selected['filenames'] == [str(product)] and selected['executable'] == str(product)
    assert len(paths) == 42; paths.append(str(product.with_suffix('.d')))
    assert paths == [p['cargo_path'] for p in frozen['artifacts']]
    assert {p.name for p in (raw / 'artifacts/verifier-compile').iterdir()} == {f'product-{i}' for i in range(43)}
    adopted, held = [], {}
    for i, (name, pin) in enumerate(zip(paths, frozen['artifacts'])):
        target, copy = Path(name), repo / pin['copy']
        assert target.is_relative_to(repo / 'target') and '..' not in target.parts
        assert pin['ordinal'] == i and copy == raw / 'artifacts/verifier-compile' / f'product-{i}'
        # These are the only target reads: exact reported filenames plus selected alias depfile.
        b, current_owner = read(target); c, copy_owner = read(copy)
        assert b == c and len(c) == pin['bytes'] and sha(c) == pin['sha256']
        assert stat.S_IMODE(current_owner[2]) == stat.S_IMODE(copy_owner[2]) == pin['mode']
        held[str(target)] = (sha(b), current_owner); held[str(copy)] = (sha(c), copy_owner)
        adopted.append(dict(cargo_path=name, path=str(copy), bytes=len(c), sha256=sha(c), current_target_owner=current_owner,
                            retained_copy_owner=copy_owner, compiler_time_original_owner=None))
    assert adopted[41]['current_target_owner'][2] & 0o111
    rules = depfile_rules(read(repo / frozen['artifacts'][42]['copy'])[0].decode())
    assert len(rules) == 1 and rules[0][0] == str(product) and rules[0][1] == [x['spelling'] for x in frozen['dependencies']]
    assert len(rules[0][1]) == 46
    bindings, inodes = [], set()
    for pin in frozen['dependencies']:
        member = pin['canonical_member']; saved = source['files'][member]
        assert saved == {k: pin[k] for k in ('bytes','sha256','mode')}
        body = git('show', revision + ':' + member)
        tree = git('ls-tree', revision, '--', member).decode().split('\t', 1)
        assert tree[1].rstrip('\n') == member and tree[0].split()[0] == saved['mode']
        row = source_alias(repo, pin['spelling'], pin, body)
        identity = tuple(row['fresh_owner'][:2]); assert identity not in inodes, 'duplicate physical source alias'
        inodes.add(identity); bindings.append(row)
    assert len({x['canonical_member'] for x in bindings}) == 46
    unique_bindings(bindings)
    assert 'tools/elf-rewrite/examples/verify_common_core.rs' in {x['canonical_member'] for x in bindings}
    for path, before in records.items(): assert read(path) == before
    for path, (digest, owner) in held.items():
        data, current = read(path); assert current == owner and sha(data) == digest
    for pin, first in zip(frozen['dependencies'], bindings):
        assert source_alias(repo, pin['spelling'], pin, git('show', revision + ':' + pin['canonical_member'])) == first
    assert read(frozen_path) == frozen_before and read(Path(__file__).absolute()) == self_before
    assert git('rev-parse', 'HEAD').decode().strip() == revision and not git('diff', '--binary', 'HEAD')
    report = dict(schema=1, status='RETAINED_ARCHIVE_ADMITTED_AT_NEW_OWNER_EPOCH', revision=revision,
                  compiler_status='PASS_RETAINED_RECEIPT', original_archive_status='FAILED_CANONICAL_SPELLING_CHECK',
                  original_archive_failure_record_sha256=sha(records[str(raw / 'archive-failure-caller-observation.json')][0]),
                  admission_source_sha256=sha(self_before[0]), frozen_sha256=FROZEN_SHA, artifacts=adopted,
                  cargo=selected, source_bindings=bindings, target_reads_exact=paths,
                  old_original_owner_map_reconstructed=False, tools_configs_reobserved=False,
                  compiler_or_application_executed=False, qualification_complete=False,
                  scope='Fresh selected target/copy/source identity admission only; old failure and copies remain untouched. No full target/tool/configuration closure.')
    a.new_output.mkdir()
    for name, value in [('admission.json', report), ('read-records.json', {p:dict(sha256=sha(b),owner=o) for p,(b,o) in records.items()})]:
        with (a.new_output / name).open('xb') as f: f.write(encoded(value))
    print('PASS retained verifier archive admission: 43 copies, 46 complete source bindings; new owner epoch only')


if __name__ == '__main__':
    main()
