#!/usr/bin/env python3
"""Pinned E9 structural site inventory. Reads evidence; never launches a tool."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys

if sys.flags.optimize:
    raise SystemExit('optimized Python disables E9 inventory checks')
MAX_FILE = 16 * 1024 * 1024
MAX_MESSAGES = 4096
PAGE = 4096
U64 = (1 << 64) - 1
REVISION = '0d5d36e4c4edcac37ca2499694d64302a391136f'
TREE = 'b833c9dedd0aaaf8ed60ad1c041bd1535c55ccce'
ARCHIVE = 'b9d82420ee00a7240f574645c229d91fb993d1f24305258e3cdc294e6df44f0f'
CAPSTONE = 'e3f106739a6ae78d47772dff31062d644ea21078'
ABI_PATCH = '66bfd1bbef8fd9f33656a8956d21fbe5cba6c27b6ff034be0084db76bafd9e0d'
TRANSPORT = '0fea3c8bc0701dffeb16b524e7159e458be9add11bcf3df5f47b9714c1005acc'
PRODUCERS = {
    'stock-algorithm': (
        '36b05e9a47c9193041d71ed4e14dda87e835e0e2b47e4a82a7d30a7c0d4eeb5e',
        '890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb',
        '4d39f324ab8a3a9420d2436129ba941e17fd78aa2c4e35eff3d27311e0683477'),
    'bootstrap-patched-reference': (
        TRANSPORT,
        '3750339187ffc4a084d075de77d1c653c255abd96e396870ea691b495f0c5453',
        '126b6143c5668e4d390e0b9626824f5007b54d56e47a07bb72b415757b51773c'),
}
# The bootstrap patch changes the saved-register/restore pairing in e9elf.cpp.
# Select exactly one order from the authenticated backend/loader lane; accepting
# either suffix would hide a mismatched startup ABI.
RESTORE_SUFFIX = {
    'stock-algorithm': bytes.fromhex('5f5e5a594159415a415b415c415d415e415f4158ffe0'),
    'bootstrap-patched-reference': bytes.fromhex('5f5e5a5941584159415a415b415c415d415e415fffe0'),
}
ADDRESS = r'(?:\[absolute\] )?-?0x[0-9a-f]+'
LOADER_ADDRESS = 0x20FEDC000
SHORT_T3_OWNERSHIP_PROFILE = 'elf-disassembly-null-jumps-short-t3-ownership-v1'
SHORT_T3_PENDING_PROFILE = 'elf-disassembly-null-jumps-short-t3-pending-v1'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def loads(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, 'duplicate JSON key'
            value[key] = item
        return value
    def invalid(value):
        raise AssertionError('non-JSON constant: ' + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def digest(value):
    assert type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'digest'
    return value


def number(value):
    assert type(value) is str and re.fullmatch(r'(?:0|[1-9][0-9]*|0x[0-9a-fA-F]+)', value), 'number'
    result = int(value, 16 if value.startswith('0x') else 10)
    assert 0 <= result <= U64
    return result


def rpc_integer(value):
    # e9frontend.cpp::sendInteger: int32 JSON number, otherwise signed hex string.
    if type(value) is int:
        assert -(1 << 31) <= value < (1 << 31), 'RPC integer representation'
        return value
    assert type(value) is str and re.fullmatch('-?0x[0-9a-f]+', value), 'RPC integer'
    result = int(value, 16)
    assert -(1 << 63) < result < (1 << 63) and not -(1 << 31) <= result < (1 << 31)
    return result


def address(value):
    assert re.fullmatch(ADDRESS, value), 'debug address'
    result = int(value.removeprefix('[absolute] '), 16)
    assert -(1 << 63) < result < (1 << 63)
    return result


def elf(data, kind):
    assert 64 <= len(data) <= MAX_FILE and data[:7] == b'\x7fELF\x02\x01\x01', 'ELF identity'
    assert struct.unpack_from('<HHI', data, 16) == (kind, 62, 1), 'ELF type/machine'
    entry, phoff = struct.unpack_from('<QQ', data, 24)
    ehsize, phsize, count = struct.unpack_from('<HHH', data, 52)
    assert ehsize == 64 and phsize == 56 and 1 <= count <= 4096
    assert phoff >= 64 and phoff + count * phsize <= len(data)
    rows = []
    for i in range(count):
        row = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
        tag, flags, off, va, pa, fs, ms, alignment = row
        assert off + fs <= len(data) and va + ms <= U64
        if tag == 1:
            assert fs <= ms and flags & ~7 == 0
            assert alignment in (0, 1) or alignment & (alignment - 1) == 0
            assert alignment in (0, 1) or off % alignment == va % alignment
        rows.append(row)
    assert any(p[0] == 1 for p in rows)
    return dict(entry=entry, phoff=phoff, rows=rows)


def owner(image, pc, length, executable=False):
    assert 0 < length <= MAX_FILE and 0 <= pc <= U64 - length
    owners = [p for p in image['rows'] if p[0] == 1 and p[3] <= pc and pc + length <= p[3] + p[5]]
    assert len(owners) == 1, 'unique file-backed ELF owner'
    p = owners[0]
    assert not executable or p[1] & 1, 'executable owner'
    return p[2] + pc - p[3]



def dynamic_symbol(data, name, optional=False):
    shoff = struct.unpack_from('<Q', data, 40)[0]
    width, count = struct.unpack_from('<HH', data, 58)
    assert width == 64 and 1 <= count <= 4096 and shoff + count * width <= len(data)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * width) for i in range(count)]
    tables = [r for r in sections if r[1] == 11]
    assert len(tables) == 1
    table = tables[0]
    assert table[9] == 24 and table[5] % 24 == 0 and table[5] // 24 <= 4096 and table[4] + table[5] <= len(data)
    assert table[6] < count
    strings = sections[table[6]]
    assert strings[1] == 3 and strings[4] + strings[5] <= len(data)
    names = data[strings[4]:strings[4] + strings[5]]
    found = []
    for off in range(table[4], table[4] + table[5], 24):
        n, info, other, section, value, size = struct.unpack_from('<IBBHQQ', data, off)
        assert n < len(names) and b'\0' in names[n:]
        if names[n:].split(b'\0', 1)[0] == name.encode():
            assert section != 0 and info & 15 == 2 and info >> 4 in (1, 2)
            found.append(value)
    assert len(found) <= 1 and (found or optional), 'unique defined dynamic function'
    return found[0] if found else None


def executable_page_owner(image, pc, length, file_length):
    assert pc % PAGE == length % PAGE == 0 and 0 < length <= MAX_FILE
    offsets = []
    for page in range(pc, pc + length, PAGE):
        rows = [p for p in image['rows'] if p[0] == 1 and p[3] // PAGE * PAGE <= page
                and page < (p[3] + p[5] + PAGE - 1) // PAGE * PAGE]
        assert len(rows) == 1 and rows[0][1] & 1, 'original executable page owner'
        p = rows[0]
        assert p[2] % PAGE == p[3] % PAGE
        offsets.append(p[2] // PAGE * PAGE + page - p[3] // PAGE * PAGE)
    assert offsets == list(range(offsets[0], offsets[0] + length, PAGE))
    assert offsets[0] + length <= (file_length + PAGE - 1) // PAGE * PAGE
    return offsets[0]


def selection(raw, original, policy_raw):
    return _selection(raw, original, policy_raw, None)


def selection_short_t3_ownership(raw, original, policy_raw):
    return _selection(raw, original, policy_raw, SHORT_T3_OWNERSHIP_PROFILE)


def selection_short_t3_pending(raw, original, policy_raw):
    return _selection(raw, original, policy_raw, SHORT_T3_PENDING_PROFILE)


def _selection(raw, original, policy_raw, selection_profile):
    assert selection_profile in (None, SHORT_T3_OWNERSHIP_PROFILE, SHORT_T3_PENDING_PROFILE), 'selection profile'
    assert 0 < len(raw) <= 1024 * 1024 and raw.endswith(b'\n'), 'selection length/newline'
    policy = loads(policy_raw)
    assert policy.keys() == {'schema', 'original_sha256', 'selection_sha256', 'e9_revision', 'instrumentation', 'selection_style'}
    assert type(policy['schema']) is int and policy['schema'] == 1
    assert policy['original_sha256'] == sha(original) and policy['selection_sha256'] == sha(raw)
    assert policy['e9_revision'] == REVISION
    assert policy['instrumentation'] in ('null', 'real-hook')
    assert policy['selection_style'] in ('jump-site', 'heap-write', 'forced-puzzle')
    lines = raw.decode().splitlines()
    if selection_profile == SHORT_T3_PENDING_PROFILE:
        prefix = ['LI2TOOL 1', 'original ' + sha(original),
                  'neighbor-victims short-only', 'neighbor-ownership inherited-t3',
                  'pending-selected full-instruction-ownership']
        assert b'\r' not in raw and raw.startswith(('\n'.join(prefix) + '\n').encode()), 'pending selection prefix'
        assert lines[:5] == prefix, 'pending selection prefix'
        for line in lines[5:]:
            fields = line.split()
            assert not fields or fields[0] not in ('neighbor-victims', 'neighbor-ownership', 'pending-selected'), 'duplicate/misplaced pending selection mode'
        # Full raw bytes and the authenticated policy remain the public identity.
        lines = lines[:2] + lines[5:]
    elif selection_profile is not None:
        prefix = ['LI2TOOL 1', 'original ' + sha(original),
                  'neighbor-victims short-only', 'neighbor-ownership inherited-t3']
        assert b'\r' not in raw and raw.startswith(('\n'.join(prefix) + '\n').encode()), 'owned selection prefix'
        assert lines[:4] == prefix, 'owned selection prefix'
        for line in lines[4:]:
            fields = line.split()
            assert not fields or fields[0] not in ('neighbor-victims', 'neighbor-ownership'), 'duplicate/misplaced selection mode'
        # Only this private line view changes. Full raw identity and policy above
        # remain authoritative; the stripped view is never returned or rehashed.
        lines = lines[:2] + lines[4:]
    assert lines[0] == 'LI2TOOL 1'
    globals_, records, sites = {}, set(), []
    allowed = {'hook', 'site', 'entries', 'resumes', 'search', 'allocation'}
    for line in lines[1:]:
        if line == '':
            continue
        f = line.split()
        assert f, 'whitespace-only selection record'
        if f[0] in ('original', 'target', 'domain', 'carrier', 'limits'):
            assert f[0] not in globals_
            globals_[f[0]] = f[1:]
        else:
            assert f[0] in allowed and len(f) >= 3, 'unknown/short selection record'
            key = (f[0], number(f[1]), f[2] if f[0] == 'allocation' else '')
            assert key not in records, 'duplicate selection record'
            records.add(key)
            if f[0] == 'site':
                assert len(f) == 14
                sid, pc, length, off = map(number, f[1:5])
                assert 1 <= length <= 15, 'selected instruction length'
                sites.append(dict(site=sid, pc=pc, length=length, file_offset=off))
    assert globals_.keys() == {'original', 'target', 'domain', 'carrier', 'limits'}
    assert globals_['original'] == [sha(original)]
    assert 0 < len(sites) <= 1024 and len({p['pc'] for p in sites}) == len(sites)
    assert len({p['file_offset'] for p in sites}) == len(sites)
    for p in sites:
        assert owner(elf(original, 2), p['pc'], p['length'], True) == p['file_offset']
    # All non-site text stays digest-bound. This is a site adapter, not a second
    # implementation of the core selection/planner validation contract.
    return sites, policy


def hook_template(target):
    # Exact clean,before,one-instrAddr template from sendELFTrampoline.
    return list(bytes.fromhex('488da42400c0ffff415341525041514150515256570f90c09f50')) + [
        0x48, 0x8d, 0x3d, {'rel32': '.Linstruction'}, 0xe8, {'rel32': target}
    ] + list(bytes.fromhex('58047f9e5f5e5a594158415958415a415b488da42400400000')) + ['$instruction', '$continue']


def rpc(raw, original, sites, original_path, policy, hook, hook_bytes, trap_all):
    lines = raw.decode().splitlines()
    assert raw.endswith(b'\n') and 5 <= len(lines) <= MAX_MESSAGES and all(lines)
    rows = [loads(line) for line in lines]
    for i, row in enumerate(rows):
        assert row.keys() == {'jsonrpc', 'method', 'params', 'id'}
        assert row['jsonrpc'] == '2.0' and type(row['id']) is int and row['id'] == i
        assert type(row['params']) is dict
    assert rows[0]['method'] == 'binary' and rows[0]['params'] == {'filename': original_path, 'mode': 'exe'}
    assert rows[-1]['method'] == 'emit' and rows[-1]['params'] == {'filename': 'a.out', 'format': 'binary', 'mapping_size': PAGE}
    image = elf(original, 2)
    instructions, patches, templates, reserves = {}, [], {}, []
    started = False
    for row in rows[1:-1]:
        method, p = row['method'], row['params']
        if method == 'instruction':
            started = True
            assert p.keys() == {'address', 'length', 'offset'}
            pc, length, off = [rpc_integer(p[k]) for k in ('address', 'length', 'offset')]
            assert 1 <= length <= 15 and owner(image, pc, length, True) == off
            assert off not in instructions and all(off + length <= x or x + y[1] <= off for x, y in instructions.items()), 'duplicate/overlapping RPC instruction'
            instructions[off] = (pc, length)
        elif method == 'patch':
            started = True
            expected_keys = {'trampoline', 'offset'} | ({'metadata'} if policy['instrumentation'] == 'real-hook' else set())
            assert p.keys() == expected_keys, 'unexpected patch metadata'
            if 'metadata' in p:
                assert p['metadata'] == {}, 'instrAddr has no data metadata'
            off = rpc_integer(p['offset'])
            assert off in instructions and p['trampoline'] in templates
            patches.append((off, p['trampoline']))
        elif method == 'trampoline':
            assert not started and p.keys() == {'name', 'template'} and type(p['name']) is str
            assert p['name'] not in templates and type(p['template']) is list
            templates[p['name']] = p['template']
        elif method == 'reserve':
            assert not started and p.keys() == {'address', 'protection', 'bytes'}, 'init/custom mmap/unknown reserve unsupported'
            va = rpc_integer(p['address'])
            assert re.fullmatch('[r-][w-][x-]', p['protection']) and p['protection'] != 'rwx'
            assert type(p['bytes']) is list and 0 < len(p['bytes']) <= MAX_FILE
            assert all(type(b) is int and 0 <= b <= 255 for b in p['bytes'])
            reserves.append((va, p['protection'], bytes(p['bytes'])))
        else:
            raise AssertionError('unsupported RPC method: ' + str(method))
    expected = sorted(sites, key=lambda p: p['file_offset'], reverse=True)
    assert [off for off, _ in patches] == [p['file_offset'] for p in expected], 'complete descending patch list'
    assert all(instructions[p['file_offset']] == (p['pc'], p['length']) for p in sites), 'selected RPC geometry'
    assert len(templates) == 1 and len({name for _, name in patches}) == 1
    name, template = next(iter(templates.items()))
    prefix = [0xcc] if trap_all else []
    if policy['instrumentation'] == 'null':
        assert hook is None and not reserves and hook_bytes is None
        assert (name, template) in (('passthru', prefix + ['$instruction', '$continue']), ('trap', prefix + [0xcc]))
    else:
        assert hook is not None and hook.keys() == {'symbol', 'base', 'entry'}
        assert re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', hook['symbol'])
        assert type(hook['base']) is int and type(hook['entry']) is int
        h = elf(hook_bytes, 3)
        owner(h, hook['entry'], 1, True)
        assert dynamic_symbol(hook_bytes, hook['symbol']) == hook['entry'], 'hook dynamic symbol owner'
        assert dynamic_symbol(hook_bytes, 'init', optional=True) is None and dynamic_symbol(hook_bytes, 'mmap', optional=True) is None, 'custom init/mmap unsupported'
        expected_reserves = []
        for p in h['rows']:
            if p[0] == 1:
                protection = ''.join(c if p[1] & bit else '-' for c, bit in zip('rwx', (4, 2, 1)))
                expected_reserves.append((hook['base'] + p[3], protection, hook_bytes[p[2]:p[2] + p[5]] + bytes(p[6] - p[5])))
        assert reserves == expected_reserves, 'whole hook LOAD reserve ownership'
        target = hook['base'] + hook['entry']
        encoded = target if -(1 << 31) <= target < 1 << 31 else hex(target)
        assert template == prefix + hook_template(encoded), 'clean before instrAddr template'
    return dict(instructions=instructions, patches=patches, reserves=reserves,
                trap=(name == 'trap' or trap_all), messages=len(rows), template_name=name)


def debug(raw, sites):
    outcomes, maps, bypass = [], [], []
    success = re.compile(r'debug: patched instruction (0x[0-9a-f]+) \[size=([0-9]+), tactic=(B1|B2|T1|T2|T3), trampoline=(' + ADDRESS + r')\.\.(' + ADDRESS + r')\]')
    failure = re.compile(r'debug: failed to patch instruction at address (0x[0-9a-f]+) \(([0-9]+)\)')
    mapping = re.compile(r'debug: load (trampoline|refactoring): mmap\((' + ADDRESS + r'), ([0-9]+), ((?:PROT_READ \| )?(?:PROT_WRITE \| )?(?:PROT_EXEC \| )?0), MAP_FIXED \| MAP_PRIVATE, fd, \+([0-9]+)\)')
    skip = re.compile(r'debug: bypass (0x[0-9a-f]+) and jump directly to (' + ADDRESS + ')')
    for line in raw.decode().splitlines():
        m = success.fullmatch(line)
        if m:
            pc, length, tactic, lo, hi = m.groups()
            assert lo.startswith('[absolute] ') == hi.startswith('[absolute] ')
            low, high = address(lo), address(hi)
            assert 0 < high - low <= MAX_FILE
            outcomes.append(dict(pc=int(pc, 16), length=int(length), tactic=tactic, low=low, high=high))
            continue
        m = failure.fullmatch(line)
        if m:
            outcomes.append(dict(pc=int(m[1], 16), length=int(m[2]), tactic=None))
            continue
        m = mapping.fullmatch(line)
        if m:
            kind, va, length, protection, off = m.groups()
            prot = sum(bit for text, bit in [('PROT_READ', 1), ('PROT_WRITE', 2), ('PROT_EXEC', 4)] if text in protection)
            maps.append(dict(kind=kind, va=address(va), length=int(length), prot=prot, offset=int(off)))
            continue
        m = skip.fullmatch(line)
        assert m, 'unrecognized backend stderr: ' + line
        bypass.append((int(m[1], 16), address(m[2])))
    expected = sorted(sites, key=lambda p: p['file_offset'], reverse=True)
    assert [(r['pc'], r['length']) for r in outcomes] == [(r['pc'], r['length']) for r in expected], 'exact per-site debug outcomes'
    assert len(maps) <= MAX_MESSAGES
    return outcomes, maps, bypass


def loader_mmap(row, previous):
    va, length, prot, off = (row[k] for k in ('va', 'length', 'prot', 'offset'))
    out = b'\xbf' + struct.pack('<i', va) if 0 <= va < 1 << 31 else b'\x48\xbf' + struct.pack('<q', va)
    if length != previous[0]:
        out += b'\xbe' + struct.pack('<i', length)
    if prot != previous[1]:
        out += b'\xba' + struct.pack('<i', prot)
    if off != previous[2]:
        out += b'\x41\xb9' + struct.pack('<i', off) if off < 1 << 31 else b'\x49\xb9' + struct.pack('<q', off)
    out += bytes.fromhex('4489e80f054839f8740341ffe6')
    return out, (length, prot, off)


def extent_fragments(image, maps, pc, size, file_length, executable=True, mapped_only=False):
    # Partition at every ownership boundary. A partial MAP_FIXED override must
    # never disappear into a whole-span LOAD fallback. File aliases are allowed;
    # ambiguous virtual ownership is not. Callers validate complete maps first.
    assert 0 < size <= MAX_FILE and -(1 << 63) < pc <= U64
    assert (pc & U64) <= U64 - size, 'view address overflow'
    end = pc + size
    boundaries = {pc, end}
    ranges = [(r['va'], r['length']) for r in maps]
    ranges += [(p[3], p[5]) for p in image['rows'] if p[0] == 1]
    for start, length in ranges:
        boundaries.update(edge for edge in (start, start + length) if pc < edge < end)
    points = sorted(boundaries)
    result = []
    for low, high in zip(points, points[1:]):
        rows = [r for r in maps if r['va'] <= low and high <= r['va'] + r['length']]
        assert len(rows) <= 1, 'ambiguous mapped fragment'
        mapping = rows[0] if rows else None
        if mapping is not None:
            assert not executable or mapping['prot'] & 4, 'executable mapped fragment'
            assert not mapped_only or mapping['kind'] == 'trampoline', 'trampoline fragment owner'
            at = mapping['offset'] + low - mapping['va']
        else:
            assert not mapped_only, 'actual executable trampoline extent owner'
            at = owner(image, low, high - low, executable)
        assert 0 <= at and at + high - low <= file_length, 'fragment file bounds'
        result.append((low, high, at, mapping))
    return result


def artifact(original, candidate, loader, intent, outcomes, maps, bypass, *, lane):
    assert lane in PRODUCERS and sha(loader) == PRODUCERS[lane][2], 'pinned loader lane'
    old, new = elf(original, 2), elf(candidate, 2)
    assert old['phoff'] == new['phoff'] and len(old['rows']) == len(new['rows'])
    changed = [i for i, pair in enumerate(zip(old['rows'], new['rows'])) if pair[0] != pair[1]]
    assert len(changed) == 1 and old['rows'][changed[0]][0] == 4, 'one PT_NOTE becomes loader'
    index = changed[0]
    p = new['rows'][index]
    assert p[:2] == (1, 5) and p[3:5] == (LOADER_ADDRESS, 0) and p[5] == p[6] and p[7] == PAGE
    assert p[2] % PAGE == 0 and p[2] >= (len(original) + PAGE - 1) // PAGE * PAGE
    assert p[2] + p[5] == len(candidate) and new['entry'] == LOADER_ADDRESS
    assert owner(new, LOADER_ADDRESS, p[5], True) == p[2]
    stream = loader + bytes.fromhex('ba0500000041ba12000000')
    previous = (-1, 5, -1)
    loader_progress = ''
    for row in maps:
        assert row['va'] % PAGE == row['length'] % PAGE == row['offset'] % PAGE == 0
        assert 0 < row['length'] <= MAX_FILE and row['offset'] + row['length'] <= p[2]
        assert row['offset'] >= 0, 'mapping file offset'
        assert -(1 << 63) < row['va'] <= (1 << 63) - row['length'], 'mapping signed address overflow'
        assert (row['va'] & U64) <= U64 - row['length'], 'mapping address overflow'
        assert row['prot'] in (1, 2, 3, 4, 5, 6), 'no RWX or empty mapping'
        encoded, previous = loader_mmap(row, previous)
        stream += encoded
        extra = len(encoded) - 18
        loader_progress += '\x1b[36m0\x1b[0m' if extra <= 0 else chr((ord('0') if extra < 10 else ord('A')) + extra)
    stream += bytes.fromhex('4c89c7b8030000000f05')
    entry = old['entry']
    stream += b'\xb8' + struct.pack('<I', entry) if entry < 1 << 31 else b'\x48\xb8' + struct.pack('<Q', entry)
    stream += RESTORE_SUFFIX[lane]
    assert candidate[p[2]:] == stream, 'whole pinned loader/mmap/old-entry bytes'
    physical = set()
    refactors = [r for r in maps if r['kind'] == 'refactoring']
    trampolines = [r for r in maps if r['kind'] == 'trampoline']
    assert maps == trampolines + refactors, 'loader mapping order'
    for i, r in enumerate(maps):
        assert all(r['va'] + r['length'] <= x['va'] or x['va'] + x['length'] <= r['va'] for x in maps[:i]), 'overlapping loader owners'
        if r['kind'] == 'trampoline':
            physical.update(range(r['offset'], r['offset'] + r['length'], PAGE))
            assert not any(x[0] == 1 and r['va'] < x[3] + x[6] and x[3] < r['va'] + r['length'] for x in new['rows']), 'trampoline collides with original/loader LOAD'
        else:
            assert r['prot'] == 5
            executable_page_owner(old, r['va'], r['length'], len(original))
    tail = (len(original) + PAGE - 1) // PAGE * PAGE
    for r in sorted(refactors, key=lambda x: x['offset']):
        assert r['offset'] == tail, 'contiguous refactored-page storage'
        tail += r['length']
    assert physical == set(range(tail, p[2], PAGE)), 'complete appended backing ownership'
    assert candidate[len(original):(len(original) + PAGE - 1) // PAGE * PAGE] == bytes((-len(original)) % PAGE), 'input padding'
    phstart = old['phoff'] + index * 56
    permitted = set(range(24, 32)) | set(range(phstart, phstart + 56))
    for off, (_, length) in intent['instructions'].items():
        permitted.update(range(off, off + length))
    assert all(a == b or i in permitted for i, (a, b) in enumerate(zip(original, candidate[:len(original)]))), 'unowned original-file change'
    def view(pc, size, executable=True):
        fragments = extent_fragments(new, maps, pc, size, len(candidate), executable)
        return b''.join(candidate[at:at + high - low] for low, high, at, _ in fragments)
    for r in refactors:
        off = executable_page_owner(old, r['va'], r['length'], len(original))
        data = view(r['va'], r['length'])
        padded = original + bytes((-len(original)) % PAGE)
        assert all(a == b or off + i in permitted for i, (a, b) in enumerate(zip(padded[off:off + r['length']], data))), 'unowned refactored source change'
    for va, protection, data in intent['reserves']:
        cursor = 0
        while cursor < len(data):
            rows = [r for r in trampolines if r['va'] <= va + cursor < r['va'] + r['length']]
            assert len(rows) == 1 and rows[0]['prot'] == sum(bit for ch, bit in zip(protection, (1, 2, 4)) if ch != '-')
            amount = min(len(data) - cursor, rows[0]['va'] + rows[0]['length'] - va - cursor)
            assert view(va + cursor, amount, False) == data[cursor:cursor + amount], 'whole reserved hook bytes'
            cursor += amount
    witnesses = []
    for row in outcomes:
        if row['tactic'] is None:
            continue
        pc, low, high = row['pc'], row['low'], row['high']
        fragments = extent_fragments(new, trampolines, low, high - low, len(candidate), mapped_only=True)
        at = pc
        if row['tactic'] == 'T3':
            b = view(at, 2)
            assert b[0] == 0xeb, 'T3 source gateway'
            at += 2 + struct.unpack('<b', b[1:])[0]
        prefix = 0
        while prefix < 3 and view(at + prefix, 1) != b'\xe9':
            assert view(at + prefix, 1)[0] == (0x48, 0x26, 0x36)[prefix], 'pinned E9 redundant prefix'
            prefix += 1
        b = view(at + prefix, 5)
        assert b[0] == 0xe9
        if row['tactic'] in ('B1', 'B2'):
            assert prefix == 0
        if row['tactic'] == 'T1':
            assert 1 <= prefix < row['length']
        target = at + prefix + 5 + struct.unpack_from('<i', b, 1)[0]
        assert target == low, 'source gateway reaches reported emitted trampoline'
        body = b''.join(candidate[off:off + stop - start] for start, stop, off, _ in fragments)
        assert bool(body[0] == 0xcc) == intent['trap'], 'trap cannot be relabelled as trampoline'
        witness = dict(pc=pc, trampoline_start=low, trampoline_end=high, bytes_sha256=sha(body))
        if len(fragments) == 1:
            witness['mapping'] = fragments[0][3]  # Preserve the old single-map shape.
        else:
            witness['fragments'] = [dict(start=start, end=stop, file_offset=off, mapping=mapping,
                bytes_sha256=sha(candidate[off:off + stop - start])) for start, stop, off, mapping in fragments]
        witnesses.append(witness)
    for pc, _ in bypass:
        assert any(address_ == pc for address_, _ in intent['instructions'].values()), 'bypass source owner'
    return dict(loader_offset=p[2], loader_bytes=p[5], loader_sha256=sha(stream), loader_progress=loader_progress, mappings=maps,
                physical_pages=len(physical), virtual_pages=sum(r['length'] // PAGE for r in trampolines),
                site_witnesses=witnesses, input_bytes=len(original), output_bytes=len(candidate))


def statistics(raw, outcomes, ownership, original_path):
    out = raw.decode()
    delimiter = '\n\n-----------------------------------------------\n'
    assert out.count(delimiter) == 1
    progress, table = out.split(delimiter)
    assert table.endswith('-----------------------------------------------\n')
    rows = table.splitlines()[:-1]
    facts = {}
    for row in rows:
        m = re.fullmatch(r'([a-zA-Z0-9_]+) += (.+)', row)
        assert m and m[1] not in facts, 'unknown/duplicate statistic'
        facts[m[1]] = m[2]
    assert facts.keys() == {'input_binary', 'input_mode', 'num_patched', 'num_patched_B1', 'num_patched_B2', 'num_patched_T1', 'num_patched_T2', 'num_patched_T3', 'num_virtual_mappings', 'num_physical_mappings', 'num_virtual_bytes', 'num_physical_bytes', 'input_file_size', 'output_file_size', 'time_elapsed'}
    assert facts['input_binary'] == original_path and facts['input_mode'] == 'EXECUTABLE'
    n = len(outcomes)
    successes = sum(r['tactic'] is not None for r in outcomes)
    for name, count in [('num_patched', successes)] + [('num_patched_' + t, sum(r['tactic'] == t for r in outcomes)) for t in ('B1', 'B2', 'T1', 'T2', 'T3')]:
        percent = format(count / n * 100, '.2f')
        approx = '~' if name == 'num_patched' and count != n and percent == '100.00' else ''
        assert facts[name] == f'{count} / {n} ({approx}{percent}%)', 'contradictory per-site total'
    def ratio(key, a, b):
        if b:
            assert facts[key] == f'{a} ({a / b * 100:.2f}%)'
        else:
            assert a == 0 and facts[key] in ('0 (-nan%)', '0 (nan%)')
    virtual, physical = ownership['virtual_pages'], ownership['physical_pages']
    assert facts['num_virtual_mappings'] == str(virtual)
    ratio('num_physical_mappings', physical, virtual)
    assert facts['num_virtual_bytes'] == str(virtual * PAGE)
    ratio('num_physical_bytes', physical * PAGE, virtual * PAGE)
    assert facts['input_file_size'] == str(ownership['input_bytes'])
    ratio('output_file_size', ownership['output_bytes'], ownership['input_bytes'])
    assert re.fullmatch('[0-9]+ms', facts['time_elapsed'])
    expected_progress = ''.join('\x1b[32m.\x1b[0m' if r['tactic'] else '\x1b[31mX\x1b[0m' for r in outcomes)
    assert progress.startswith(expected_progress + '\n'), 'complete ordered site progress'
    remainder = progress[len(expected_progress) + 1:]
    # Compression/key records have no site-success authority; loader counters
    # are independently derived from each authenticated mmap instruction span.
    parts = remainder.split('\n')
    assert len(parts) == 3 and parts[2] == ownership['loader_progress']
    assert re.fullmatch(r'(?:\+|\x1b\[32mM\x1b\[0m)*', parts[0])
    assert re.fullmatch(r'(?:\[\x1b\[33m[0-9A-F]{16}\x1b\[0m\])*', parts[1])
    assert len(re.findall(r'\[\x1b\[33m[0-9A-F]{16}\x1b\[0m\]', parts[1])) == physical
    return facts


def wire(sites, policy, outcomes, trapped):
    by_pc = {r['pc']: r for r in outcomes}
    lines = ['LI2E9SITES\t1']
    for key in ('original_sha256', 'selection_sha256', 'e9_revision', 'instrumentation', 'selection_style'):
        lines.append(key + '\t' + policy[key])
    lines.append('site\tpc\tfile_offset\tlength\toutcome\treason_hex')
    for site in sites:
        row = by_pc[site['pc']]
        outcome = 'refused' if row['tactic'] is None else 'trap' if trapped else 'trampoline'
        reason = dict(backend_record=row, classification=outcome)
        lines.append('\t'.join(map(str, [site['site'], site['pc'], site['file_offset'], site['length'], outcome, canonical(reason).hex()])))
    return ('\n'.join(lines) + '\n').encode()


def receipt(raw, request_raw, helper, stdout, stderr):
    value, request = loads(raw), loads(request_raw)
    assert value.keys() == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout', 'unexpected_descendants', 'absence_proof', 'stdout_sha256', 'stderr_sha256', 'elapsed_seconds', 'cleanup_events', 'cleanup_error', 'aborted', 'inputs_unchanged'}
    assert value['request_sha256'] == sha(request_raw) and value['helper_sha256'] == helper
    assert type(value['exit']) is int and value['exit'] == 0, 'incomplete/failed producer is not a site inventory'
    assert value['wall_timeout'] is False and value['inputs_unchanged'] is True
    assert value['unexpected_descendants'] == [] and value['cleanup_events'] == []
    assert value['absence_proof'] == 'ECHILD' and value['aborted'] is None and value['cleanup_error'] is None
    assert value['stdout_sha256'] == sha(stdout) and value['stderr_sha256'] == sha(stderr)
    elapsed = value['elapsed_seconds']
    assert type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= request['wall_seconds']
    return request


def read_bound(row):
    assert row.keys() == {'path', 'sha256', 'bytes'}
    digest(row['sha256'])
    path = Path(row['path'])
    assert path.is_absolute() and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_size == row['bytes']
        data = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
        assert before == after and sha(data) == row['sha256'] and len(data) == row['bytes'], 'input identity'
    return data, [before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns]


def _selection_for_profile(raw, original, policy_raw, selection_profile):
    if selection_profile is None:
        return selection(raw, original, policy_raw)
    if selection_profile == SHORT_T3_PENDING_PROFILE:
        return selection_short_t3_pending(raw, original, policy_raw)
    assert selection_profile == SHORT_T3_OWNERSHIP_PROFILE, 'selection profile'
    return selection_short_t3_ownership(raw, original, policy_raw)


def _selection_binding(result, selection_profile):
    assert selection_profile in (None, SHORT_T3_OWNERSHIP_PROFILE, SHORT_T3_PENDING_PROFILE), 'selection profile'
    assert 'selection_profile' not in result, 'duplicate selection profile binding'
    if selection_profile is not None:
        result['selection_profile'] = selection_profile
    return result


def validate(envelope, blobs):
    return _validate(envelope, blobs, None)


def _validate(envelope, blobs, selection_profile):
    assert selection_profile in (None, SHORT_T3_OWNERSHIP_PROFILE, SHORT_T3_PENDING_PROFILE), 'selection profile'
    assert envelope.keys() == {'schema', 'lane', 'reference_commit', 'reference_tree', 'archive_sha256', 'capstone_revision', 'abi_delta_patch_sha256', 'common_argv', 'hook', 'files'}
    assert type(envelope['schema']) is int and envelope['schema'] == 1
    assert (envelope['reference_commit'], envelope['reference_tree'], envelope['archive_sha256'], envelope['capstone_revision'], envelope['abi_delta_patch_sha256']) == (REVISION, TREE, ARCHIVE, CAPSTONE, ABI_PATCH)
    lane, files = envelope['lane'], envelope['files']
    assert lane in PRODUCERS
    roles = {'original', 'selection', 'policy', 'candidate', 'frontend', 'backend', 'loader', 'transport_frontend', 'helper'} | {p + '_' + r for p in ('transport', 'producer') for r in ('request', 'receipt', 'stdout', 'stderr')}
    assert files.keys() == roles | ({'hook_elf'} if envelope['hook'] is not None else set())
    assert tuple(sha(blobs[r]) for r in ('frontend', 'backend', 'loader')) == PRODUCERS[lane], 'pinned producer lane'
    assert sha(blobs['transport_frontend']) == TRANSPORT
    sites, policy = _selection_for_profile(blobs['selection'], blobs['original'], blobs['policy'], selection_profile)
    common = envelope['common_argv']
    assert type(common) is list and all(type(v) is str and '\0' not in v for v in common)
    singles, actions = set(), []
    for item in common:
        if item.startswith('--action='):
            actions.append(item[len('--action='):])
        else:
            key = item.split('=', 1)[0]
            assert key in ('--start', '--end', '--compression', '--executable', '--static-loader', '--trap-all') and key not in singles
            singles.add(key)
            if key in ('--start', '--end'):
                assert item.startswith(key + '=') and len(item) > len(key) + 1
            else:
                assert item == ('--compression=9' if key == '--compression' else key)
    assert len(actions) == 1 and '--executable' in common and '--compression=9' in common
    if policy['instrumentation'] == 'null':
        assert actions[0].endswith((':passthru', ':trap'))
    else:
        assert actions[0].endswith(':call[clean,before]' + envelope['hook']['symbol'] + '(instrAddr)@' + files['hook_elf']['path'])
    requests = {}
    for phase in ('transport', 'producer'):
        requests[phase] = receipt(blobs[phase + '_receipt'], blobs[phase + '_request'], sha(blobs['helper']), blobs[phase + '_stdout'], blobs[phase + '_stderr'])
        r = requests[phase]
        assert r.keys() == {'argv', 'cwd', 'env', 'cpu_seconds', 'wall_seconds', 'file_bytes', 'stdout', 'stderr'}
        assert r['stdout'] == files[phase + '_stdout']['path'] and r['stderr'] == files[phase + '_stderr']['path']
        assert type(r['env']) is dict and r['env'].get('LC_ALL') == 'C'
        assert all(type(k) is str and type(v) is str for k, v in r['env'].items())
        assert type(r['cwd']) is str and Path(r['cwd']).is_absolute()
        assert len(blobs[phase + '_stdout']) <= r['file_bytes'] and len(blobs[phase + '_stderr']) <= r['file_bytes']
        for key in ('cpu_seconds', 'wall_seconds', 'file_bytes'):
            assert type(r[key]) is int and r[key] > 0
    assert {k: v for k, v in requests['transport'].items() if k not in ('argv', 'stdout', 'stderr')} == {k: v for k, v in requests['producer'].items() if k not in ('argv', 'stdout', 'stderr')}, 'only explicit request-coordinate differences'
    assert requests['transport']['argv'] == [files['transport_frontend']['path'], *common, '--format=json', '--output=-', files['original']['path']]
    assert requests['producer']['argv'] == [files['frontend']['path'], *common, '--format=binary', '--output=' + files['candidate']['path'], '--backend=' + files['backend']['path'], '--option=--debug', files['original']['path']]
    assert blobs['transport_stderr'] == b'', 'transport warnings/errors'
    intent = rpc(blobs['transport_stdout'], blobs['original'], sites, files['original']['path'], policy, envelope['hook'], blobs.get('hook_elf'), '--trap-all' in common)
    if policy['instrumentation'] == 'real-hook':
        assert intent['template_name'] == 'call_CB_' + envelope['hook']['symbol'] + '_' + files['hook_elf']['path']
    outcomes, maps, bypass = debug(blobs['producer_stderr'], sites)
    ownership = artifact(blobs['original'], blobs['candidate'], blobs['loader'], intent, outcomes, maps, bypass, lane=lane)
    stats = statistics(blobs['producer_stdout'], outcomes, ownership, files['original']['path'])
    tsv = wire(sites, policy, outcomes, intent['trap'])
    result = dict(schema=1, scope='STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY', lane=lane,
        policy=policy, selected_sites=len(sites), outcomes=outcomes, rpc_messages=intent['messages'],
        rpc_instruction_records=len(intent['instructions']), producer_statistics=stats, ownership=ownership,
        site_inventory_sha256=sha(tsv), candidate_sha256=sha(blobs['candidate']),
        qualification_complete=False, runtime_executed_by_adapter=False,
        architectural_equivalence_proved=False, transport_witness_is_patch_success=False)
    return tsv, _selection_binding(result, selection_profile)


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('envelope', type=Path)
    parser.add_argument('new_output', type=Path)
    parser.add_argument('--envelope-sha256', required=True)
    parser.add_argument('--selection-profile', choices=(SHORT_T3_OWNERSHIP_PROFILE, SHORT_T3_PENDING_PROFILE), action='append')
    values = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(values)
    if args.selection_profile is not None:
        options = values[:values.index('--')] if '--' in values else values
        assert len(args.selection_profile) == 1 and sum(
            value.split('=', 1)[0] == '--selection-profile' for value in options
        ) == 1, 'one exact selection-profile option required'
        args.selection_profile = args.selection_profile[0]
    return args


def main():
    args = arguments()
    assert args.envelope.is_file() and not args.envelope.is_symlink()
    raw = args.envelope.read_bytes()
    assert 0 < len(raw) <= MAX_FILE and sha(raw) == digest(args.envelope_sha256)
    envelope = loads(raw)
    blobs, owners = {}, {}
    for role, row in envelope['files'].items():
        blobs[role], owners[role] = read_bound(row)
    tsv, result = _validate(envelope, blobs, args.selection_profile)
    for role, row in envelope['files'].items():
        current, identity = read_bound(row)
        assert current == blobs[role] and identity == owners[role], 'inputs changed during adapter read'
    assert args.envelope.read_bytes() == raw
    result['envelope_sha256'] = sha(raw)
    result['input_files'] = envelope['files']
    result['input_owners'] = owners
    # This private binding carries paths. Only sites.tsv is comparator wire data.
    args.new_output.mkdir(parents=False, exist_ok=False)
    with (args.new_output / 'sites.tsv').open('xb') as f:
        f.write(tsv)
    with (args.new_output / 'producer-binding.json').open('xb') as f:
        f.write(json.dumps(result, indent=2, sort_keys=True, allow_nan=False).encode() + b'\n')
    print('E9 actual-site inventory: ' + str(result['selected_sites']) + ' requested sites; structural scope only')


if __name__ == '__main__':
    main()
