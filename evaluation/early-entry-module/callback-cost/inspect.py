#!/usr/bin/env python3
"""Inspect three pinned ELF functions; never execute or build the subject."""
import sys
if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('require unoptimized Python -I -B')
import argparse
import hashlib
import importlib.util
import json
import os
import re
import resource
import stat
import struct
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
ELF = ROOT / 'target/release/frontend-native-oracle'
CAP = 1 << 20
ROLES = ('after_published', 'qualification_snapshot', 'qualification_snapshot_into')
TOOLS = {
    'owner': (ROOT / 'evaluation/admission/processes.py', 15760,
              '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'),
    'prlimit': (Path('/usr/bin/prlimit'), 28416,
                '942bcd8596c242d4d33dca657372a83e1f55908afd59b525389362cd6d282933'),
    'objdump': (Path('/usr/bin/objdump'), 423000,
                '0a1b558f444ed2bca7fb467dede7416a651bc490b1abc77705ab470d99c527c1'),
}


def stamp(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def pin(path, cap, expected=None):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        digest = hashlib.sha256()
        count = 0
        while True:
            block = f.read(min(CAP, cap + 1 - count))
            if not block:
                break
            count += len(block)
            assert count <= cap
            digest.update(block)
        assert count == before.st_size
        assert stamp(before) == stamp(os.fstat(f.fileno())) == stamp(os.lstat(path))
    value = dict(bytes=count, sha256=digest.hexdigest(), stat=stamp(before))
    if expected is not None:
        assert (count, value['sha256']) == expected
    return value


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def select_symbols(expected):
    """Bounded ELF64 table reads, adapted from cost-codegen-v3; no code dump."""
    selected = {role: [] for role in ROLES}
    with os.fdopen(os.open(ELF, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        assert stamp(os.fstat(f.fileno())) == expected['stat']
        length = expected['bytes']

        def read_at(offset, size):
            assert 0 <= offset <= length and 0 <= size <= (16 << 20)
            assert offset + size <= length
            f.seek(offset)
            value = f.read(size)
            assert len(value) == size
            return value

        header = read_at(0, 64)
        assert header[:6] == b'\x7fELF\x02\x01'
        assert struct.unpack_from('<HH', header, 16) == (3, 62)
        offset = struct.unpack_from('<Q', header, 40)[0]
        size, count = struct.unpack_from('<HH', header, 58)
        assert size == 64 and 0 < count <= 4096
        table = read_at(offset, size * count)
        sections = [struct.unpack_from('<IIQQQQIIQQ', table, i * size) for i in range(count)]
        tables = [s for s in sections if s[1] == 2]
        assert len(tables) == 1
        symbols = tables[0]
        assert symbols[9] == 24 and symbols[5] % 24 == 0 and symbols[5] // 24 <= 200000
        assert symbols[6] < count
        strings = sections[symbols[6]]
        assert strings[1] == 3
        names = read_at(strings[4], strings[5])
        entries = read_at(symbols[4], symbols[5])
        for at in range(0, len(entries), 24):
            name, info, _, section, address, extent = struct.unpack_from('<IBBHQQ', entries, at)
            if info & 15 != 2 or not extent or not 0 < section < count:
                continue
            assert name < len(names)
            end = names.find(b'\0', name)
            assert end >= name
            raw = names[name:end].decode('ascii')
            for role in ROLES:
                # Exact v0 method suffix: snapshot must not select snapshot_into.
                if (raw.startswith('_RNv') and 'early_entry' in raw
                        and '13qualification' in raw
                        and raw.endswith(str(len(role)) + role)):
                    s = sections[section]
                    relative = address - s[3]
                    assert s[2] & 4 and 0 <= relative and relative + extent <= s[5]
                    assert s[4] + relative + extent <= length and extent <= 65536
                    selected[role].append(dict(raw_name=raw, start=address,
                                               end_exclusive=address + extent, bytes=extent))
                    assert len(selected[role]) <= 2
        assert stamp(os.fstat(f.fileno())) == expected['stat'] == stamp(os.lstat(ELF))
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=('before', 'after'))
    parser.add_argument('--name', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--elf-sha256', required=True)
    parser.add_argument('--elf-bytes', required=True, type=int)
    args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,31}', args.name)
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    assert re.fullmatch('[0-9a-f]{64}', args.elf_sha256)
    assert 0 < args.elf_bytes <= (32 << 20)
    assert len(os.sched_getaffinity(0)) == 1
    for which, limit in ((resource.RLIMIT_CPU, 10), (resource.RLIMIT_AS, 256 << 20),
                         (resource.RLIMIT_FSIZE, CAP), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(which, (limit, limit))
    out = ROOT / 'ignored/early-entry-module-callback-cost' / args.name
    logs = ROOT / 'target/evaluation/early-entry-callback-cost-codegen-v1' / args.name
    assert not out.exists() and not logs.exists()
    out.mkdir(parents=True)
    rows = [dict(role=role, status='UNOBSERVED') for role in ROLES]
    result = dict(status='FAILED', analysis_only=True, subject_executions=0,
                  phase=args.phase, asserted_revision=args.revision, rows=rows,
                  revision_join='Root must independently join revision to the Cargo artifact/source receipt.',
                  argv=sys.argv, cpus=sorted(os.sched_getaffinity(0)))
    active = None
    try:
        paths = {name: item[0].resolve(strict=True) for name, item in TOOLS.items()}
        frozen = {name: pin(paths[name], CAP, (item[1], item[2])) for name, item in TOOLS.items()}
        source = pin(Path(__file__).resolve(), CAP)
        binary = pin(ELF, 32 << 20, (args.elf_bytes, args.elf_sha256))
        result.update(source=source, tools={n: dict(path=str(paths[n]), **p) for n, p in frozen.items()},
                      elf_before=binary)
        selected = select_symbols(binary)
        result['symbols'] = selected
        assert all(len(values) <= 1 for values in selected.values()), 'ambiguous role'
        assert len(selected['after_published']) == 1
        if args.phase == 'before':
            assert len(selected['qualification_snapshot']) == 1
            assert not selected['qualification_snapshot_into']
        else:
            assert len(selected['qualification_snapshot_into']) == 1
        spec = importlib.util.spec_from_file_location('callback_cost_owner', paths['owner'])
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        logs.mkdir(parents=True)

        def unchanged():
            assert pin(Path(__file__).resolve(), CAP) == source
            for name, path in paths.items():
                assert pin(path, CAP) == frozen[name]
            assert pin(ELF, 32 << 20) == binary

        for row in rows:
            active = row
            if not selected[row['role']]:
                row['status'] = 'MISSING_SYMBOL'
                row['limit'] = 'Expected absent before helper addition, or unused public wrapper; no optimization credit.'
                continue
            symbol = selected[row['role']][0]
            unchanged()
            command = [str(paths['prlimit']), '--cpu=10', '--as=268435456',
                       '--fsize=1048576', '--core=0', '--', str(paths['objdump']),
                       '-d', '-z', '-C', '--no-show-raw-insn', '-M', 'intel',
                       '--start-address=' + hex(symbol['start']),
                       '--stop-address=' + hex(symbol['end_exclusive']), str(ELF)]
            row.update(status='DISPATCHED', command=command, wall_seconds=30, capture_bytes=CAP)
            log = logs / (row['role'] + '.log')
            record = owner.run_command(command, dict(PATH='/usr/bin:/bin', LC_ALL='C'), log, 30, CAP)
            row['owner'] = record
            save(out / (row['role'] + '-owner.json'), row)
            assert record['cleanup_complete'] is True
            capture = pin(log, CAP)
            assert capture['sha256'] == record['private_log_sha256']
            retained = out / (row['role'] + '.log')
            with retained.open('xb') as f:
                data = log.read_bytes()
                assert len(data) == capture['bytes'] and hashlib.sha256(data).hexdigest() == capture['sha256']
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            assert pin(log, CAP) == capture
            row['capture'] = dict(path=str(retained), **pin(retained, CAP, (capture['bytes'], capture['sha256'])))
            unchanged()
            assert record['exit_code'] == 0 and record['termination'] is None and record['reaped_descendants'] == 0
            row['status'] = 'CLOSED_ZERO'
        unchanged()
        result['elf_after'] = pin(ELF, 32 << 20)
        result['status'] = 'INSPECTION_COMPLETE'
    except BaseException as error:
        if active is not None:
            active['status'] = 'FAILED'
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        result['limits'] = 'Static code only; no native qualification, timing, memcpy runtime attribution or strict20k fit claim.'
        save(out / 'closed.json', result)
    print(json.dumps(dict(status=result['status'], closed=pin(out / 'closed.json', CAP))))
    return 0 if result['status'] == 'INSPECTION_COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
