#!/usr/bin/env python3
"""Finite synthetic site-adapter controls; never invokes E9 or rewritten code."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True

if sys.flags.optimize:
    raise SystemExit('optimized Python disables E9 inventory controls')
path = Path(__file__).with_name('e9-sites.py')
spec = importlib.util.spec_from_file_location('e9_sites', path)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def fixture(failed=False, trap=False):
    # Independently authored little-endian ELF and two exact MOV instructions.
    # CONTROL-LOADER is synthetic: this exercises the pure ownership parser;
    # production validate() separately requires an actual pinned loader digest.
    original = bytearray(4096)
    original[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', original, 16, 2, 62, 1, 0x400200, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', original, 64, 1, 5, 0, 0x400000, 0x400000, 4096, 4096, 4096)
    struct.pack_into('<IIQQQQQQ', original, 120, 4, 4, 384, 0x400180, 0, 16, 16, 4)
    original[512:517] = bytes.fromhex('b801000000')
    original[528:533] = bytes.fromhex('b802000000')
    original = bytes(original)
    selection = ('LI2TOOL 1\noriginal ' + a.sha(original) + '\ntarget fxsave64\ndomain 1\ncarrier none\nlimits 4096 2 2 4096 2 16384 12288 4 16777216\n'
                 'site 101 0x400200 5 512 0 0 0 0 0 0 0 0 0\n'
                 'site 202 0x400210 5 528 0 0 0 0 0 0 0 0 0\n').encode()
    policy = dict(schema=1, original_sha256=a.sha(original), selection_sha256=a.sha(selection), e9_revision=a.REVISION, instrumentation='null', selection_style='forced-puzzle')
    name = 'trap' if trap else 'passthru'
    params = [('binary', {'filename': '/fixture/original', 'mode': 'exe'}),
              ('trampoline', {'name': name, 'template': [204] if trap else ['$instruction', '$continue']}),
              ('instruction', {'address': 0x400210, 'length': 5, 'offset': 528}),
              ('instruction', {'address': 0x400200, 'length': 5, 'offset': 512}),
              ('patch', {'trampoline': name, 'offset': 528}),
              ('patch', {'trampoline': name, 'offset': 512}),
              ('emit', {'filename': 'a.out', 'format': 'binary', 'mapping_size': 4096})]
    rpc = b''.join(json.dumps(dict(jsonrpc='2.0', method=m, params=p, id=i)).encode() + b'\n' for i, (m, p) in enumerate(params))
    loader = b'CONTROL-LOADER'
    # Whole stage-2 literal: one mmap(0x600000,4096,RX,offset4096), close,
    # original entry 0x400200, full saved-register restoration, JMP RAX.
    stage2 = bytes.fromhex('ba0500000041ba12000000bf00006000be0010000041b9001000004489e80f054839f8740341ffe64c89c7b8030000000f05b8000240005f5e5a594159415a415b415c415d415e415f4158ffe0')
    candidate = bytearray(original + bytes(4096) + loader + stage2)
    struct.pack_into('<Q', candidate, 24, 0x20FEDC000)
    struct.pack_into('<IIQQQQQQ', candidate, 120, 1, 5, 8192, 0x20FEDC000, 0, len(loader + stage2), len(loader + stage2), 4096)
    outcomes = []
    for pc, off, target, omit in [(0x400210, 528, 0x600010, failed), (0x400200, 512, 0x600000, False)]:
        if omit:
            outcomes.append(f'debug: failed to patch instruction at address {pc:#x} (5)\n')
            continue
        candidate[off:off + 5] = b'\xe9' + struct.pack('<i', target - pc - 5)
        body = b'\xcc' if trap else original[off:off + 5] + b'\xe9' + struct.pack('<i', pc + 5 - target - 10)
        at = 4096 + target - 0x600000
        candidate[at:at + len(body)] = body
        outcomes.append(f'debug: patched instruction {pc:#x} [size=5, tactic=B1, trampoline={target:#x}..{target + len(body):#x}]\n')
    stderr = (''.join(outcomes) + 'debug: load trampoline: mmap(0x600000, 4096, PROT_READ | PROT_EXEC | 0, MAP_FIXED | MAP_PRIVATE, fd, +4096)\n').encode()
    success = 1 if failed else 2
    progress = ('\x1b[31mX\x1b[0m' if failed else '\x1b[32m.\x1b[0m') + '\x1b[32m.\x1b[0m\n+\n[\x1b[33m0000000000000001\x1b[0m]\nL'
    facts = ['input_binary          = /fixture/original', 'input_mode            = EXECUTABLE',
             f'num_patched           = {success} / 2 ({success / 2 * 100:.2f}%)',
             f'num_patched_B1        = {success} / 2 ({success / 2 * 100:.2f}%)',
             'num_patched_B2        = 0 / 2 (0.00%)', 'num_patched_T1        = 0 / 2 (0.00%)',
             'num_patched_T2        = 0 / 2 (0.00%)', 'num_patched_T3        = 0 / 2 (0.00%)',
             'num_virtual_mappings  = 1', 'num_physical_mappings = 1 (100.00%)',
             'num_virtual_bytes     = 4096', 'num_physical_bytes    = 4096 (100.00%)',
             'input_file_size       = 4096', f'output_file_size      = {len(candidate)} ({len(candidate) / 4096 * 100:.2f}%)',
             'time_elapsed          = 0ms']
    stdout = (progress + '\n\n-----------------------------------------------\n' + '\n'.join(facts) + '\n-----------------------------------------------\n').encode()
    return dict(original=original, selection=selection, policy=json.dumps(policy).encode(), rpc=rpc,
                candidate=bytes(candidate), loader=loader, stdout=stdout, stderr=stderr)


def run_case(f):
    sites, policy = a.selection(f['selection'], f['original'], f['policy'])
    intent = a.rpc(f['rpc'], f['original'], sites, '/fixture/original', policy, None, None, False)
    outcomes, maps, bypass = a.debug(f['stderr'], sites)
    ownership = synthetic_artifact(f, intent, outcomes, maps, bypass)
    a.statistics(f['stdout'], outcomes, ownership, '/fixture/original')
    return a.wire(sites, policy, outcomes, intent['trap']).decode().splitlines()[7:]


def synthetic_artifact(f, intent, outcomes, maps, bypass):
    # Only this synthetic control call substitutes the loader digest. Production
    # artifact()/validate() and both real lane tuples remain unchanged on return.
    assert f['loader'] == b'CONTROL-LOADER'
    saved = a.PRODUCERS
    lane = 'stock-algorithm'
    a.PRODUCERS = {**saved, lane: (*saved[lane][:2], a.sha(f['loader']))}
    try:
        return a.artifact(f['original'], f['candidate'], f['loader'], intent, outcomes, maps, bypass, lane=lane)
    finally:
        a.PRODUCERS = saved


def fragment_fixture(alias=False, change=None):
    f = fixture()
    maps = [dict(kind='trampoline', va=0x600000 + i * 4096, length=4096,
                 prot=5, offset=4096 if alias else (i + 1) * 4096) for i in range(2)]
    loader_offset = 8192 if alias else 12288
    candidate = bytearray(f['original'] + bytes(loader_offset - len(f['original'])))
    outcomes = []
    for pc, off, low in [(0x400210, 528, 0x600010), (0x400200, 512, 0x600ffb)]:
        candidate[off:off + 5] = b'\xe9' + struct.pack('<i', low - pc - 5)
        body = f['original'][off:off + 5] + b'\xe9' + struct.pack('<i', pc + 5 - low - 10)
        # Independent per-byte placement: the second page may alias the first.
        for i, byte in enumerate(body):
            page = (low + i - 0x600000) // 4096
            at = maps[page]['offset'] + (low + i) % 4096
            candidate[at] = byte
        outcomes.append(f'debug: patched instruction {pc:#x} [size=5, tactic=B1, trampoline={low:#x}..{low + 10:#x}]\n')
    if change is not None:
        change(maps)
    # Independent encoding of the finite fixture's complete mmap/close/restore
    # stream, including coherent hostile map rows. No production encoder call.
    stream = f['loader'] + bytes.fromhex('ba0500000041ba12000000')
    previous = (-1, 5, -1)
    for m in maps:
        va, length, prot, off = (m[k] for k in ('va', 'length', 'prot', 'offset'))
        stream += b'\xbf' + struct.pack('<i', va) if 0 <= va < 1 << 31 else b'\x48\xbf' + struct.pack('<q', va)
        if length != previous[0]: stream += b'\xbe' + struct.pack('<i', length)
        if prot != previous[1]: stream += b'\xba' + struct.pack('<i', prot)
        if off != previous[2]: stream += b'\x41\xb9' + struct.pack('<i', off)
        stream += bytes.fromhex('4489e80f054839f8740341ffe6')
        previous = (length, prot, off)
    stream += bytes.fromhex('4c89c7b8030000000f05b8000240005f5e5a594159415a415b415c415d415e415f4158ffe0')
    candidate += stream
    struct.pack_into('<Q', candidate, 24, 0x20FEDC000)
    struct.pack_into('<IIQQQQQQ', candidate, 120, 1, 5, loader_offset, 0x20FEDC000, 0, len(stream), len(stream), 4096)
    f['candidate'] = bytes(candidate)
    for m in maps:
        protection = ''.join(text + ' | ' for text, bit in [('PROT_READ', 1), ('PROT_WRITE', 2), ('PROT_EXEC', 4)] if m['prot'] & bit) + '0'
        outcomes.append(f"debug: load trampoline: mmap({m['va']:#x}, {m['length']}, {protection}, MAP_FIXED | MAP_PRIVATE, fd, +{m['offset']})\n")
    f['stderr'] = ''.join(outcomes).encode()
    # Statistics are used only for the two unmutated positive fixtures.
    physical = 1 if alias else 2
    replacements = [
        (b'\nL\n\n', b'\nL\x1b[36m0\x1b[0m\n\n' if alias else b'\nL6\n\n'),
        (b'num_virtual_mappings  = 1', b'num_virtual_mappings  = 2'),
        (b'num_physical_mappings = 1 (100.00%)', f'num_physical_mappings = {physical} ({physical / 2 * 100:.2f}%)'.encode()),
        (b'num_virtual_bytes     = 4096', b'num_virtual_bytes     = 8192'),
        (b'num_physical_bytes    = 4096 (100.00%)', f'num_physical_bytes    = {physical * 4096} ({physical / 2 * 100:.2f}%)'.encode()),
    ]
    if not alias:
        replacements.append((b'[\x1b[33m0000000000000001\x1b[0m]', b'[\x1b[33m0000000000000001\x1b[0m][\x1b[33m0000000000000002\x1b[0m]'))
    for old, new in replacements:
        assert old in f['stdout']; f['stdout'] = f['stdout'].replace(old, new, 1)
    lines = f['stdout'].decode().splitlines()
    lines = [f'output_file_size      = {len(candidate)} ({len(candidate) / 4096 * 100:.2f}%)' if line.startswith('output_file_size ') else line for line in lines]
    f['stdout'] = ('\n'.join(lines) + '\n').encode()
    return f


def fragment_controls():
    def ownership(f):
        sites, policy = a.selection(f['selection'], f['original'], f['policy'])
        intent = a.rpc(f['rpc'], f['original'], sites, '/fixture/original', policy, None, None, False)
        outcomes, maps, bypass = a.debug(f['stderr'], sites)
        return synthetic_artifact(f, intent, outcomes, maps, bypass)
    def rejects(reason, action):
        try:
            action()
        except AssertionError as error:
            assert str(error) == reason, (reason, str(error))
        else:
            raise AssertionError('fragment negative accepted: ' + reason)
    saved = a.PRODUCERS
    for alias in (False, True):
        f = fragment_fixture(alias)
        assert [r.split('\t')[4] for r in run_case(f)] == ['trampoline', 'trampoline']
        result = ownership(f)
        single, split = result['site_witnesses']
        assert single.keys() == {'pc', 'trampoline_start', 'trampoline_end', 'bytes_sha256', 'mapping'}
        assert split.keys() == {'pc', 'trampoline_start', 'trampoline_end', 'bytes_sha256', 'fragments'}
        parts = split['fragments']
        assert [(r['start'], r['end'], r['file_offset']) for r in parts] == [
            (0x600ffb, 0x601000, 8187), (0x601000, 0x601005, 4096 if alias else 8192)]
        assert [r['mapping'] for r in parts] == result['mappings']
        body = b''.join(f['candidate'][r['file_offset']:r['file_offset'] + r['end'] - r['start']] for r in parts)
        expected = bytes.fromhex('b801000000') + b'\xe9' + struct.pack('<i', 0x400205 - 0x601005)
        assert body == expected and split['bytes_sha256'] == a.sha(expected)
        assert all(r['bytes_sha256'] == a.sha(expected[i * 5:(i + 1) * 5]) for i, r in enumerate(parts))
        assert (result['physical_pages'], result['virtual_pages']) == (1 if alias else 2, 2)
    for reason, change in [
        ('actual executable trampoline extent owner', lambda m: m[1].__setitem__('va', 0x602000)),
        ('overlapping loader owners', lambda m: m[1].__setitem__('va', 0x600000)),
        ('executable mapped fragment', lambda m: m[1].__setitem__('prot', 1)),
        ('mapping signed address overflow', lambda m: m[1].update(va=(1 << 63) - 4096, length=8192, offset=4096)),
        ('mapping address overflow', lambda m: m[1].__setitem__('va', -4096)),
        ('', lambda m: m[1].__setitem__('offset', 12288)),
    ]:
        rejects(reason, lambda: ownership(fragment_fixture(change=change)))
    f = fragment_fixture()
    replace(f, 'stderr', b'0x600ffb..0x601005', b'0x600ffb..0x602005')
    rejects('actual executable trampoline extent owner', lambda: ownership(f))
    assert a.PRODUCERS is saved, 'synthetic lane always restored'
    rejects('pinned loader lane', lambda: a.artifact(b'', b'', b'CONTROL-LOADER', {}, [], [], [], lane='stock-algorithm'))

    # Exercise the same production fragment walker with an interior override,
    # LOAD fallback on both sides, adjacent LOADs, partial ambiguity and holes.
    base, page = 0x400000, 4096
    data = b'A' * page + b'B' * page + b'C' * page + b'D' * page
    image = {'rows': [(1, 5, 0, base, 0, 3 * page, 3 * page, page)]}
    maps = [dict(kind='refactoring', va=base + page, length=page, offset=3 * page, prot=5)]
    def view(img=image, ms=maps, pc=base + page - 2, size=page + 4, executable=True, mapped_only=False):
        parts = a.extent_fragments(img, ms, pc, size, len(data), executable, mapped_only)
        return b''.join(data[off:off + hi - lo] for lo, hi, off, _ in parts)
    assert view() == b'AA' + b'D' * page + b'CC'
    adjacent = {'rows': [(1, 5, i * page, base + i * page, 0, page, page, page) for i in range(3)]}
    assert view(img=adjacent, ms=[]) == b'AA' + b'B' * page + b'CC'
    ambiguous = {'rows': image['rows'] + [(1, 5, 0, base + page - 1, 0, 2, 2, 1)]}
    rejects('unique file-backed ELF owner', lambda: view(img=ambiguous, ms=[]))
    rejects('unique file-backed ELF owner', lambda: view(img={'rows': adjacent['rows'][::2]}, ms=[]))
    rejects('executable owner', lambda: view(img={'rows': [(1, 4, 0, base, 0, 3 * page, 3 * page, page)]}, ms=[]))
    rejects('ambiguous mapped fragment', lambda: view(ms=maps + maps))
    rejects('ambiguous mapped fragment', lambda: view(ms=maps + [{**maps[0], 'va': base + page + 1, 'length': 2}]))
    rejects('executable mapped fragment', lambda: view(ms=[{**maps[0], 'prot': 1}]))
    assert view(ms=[{**maps[0], 'prot': 1}], executable=False) == b'AA' + b'D' * page + b'CC'
    rejects('actual executable trampoline extent owner', lambda: view(mapped_only=True))
    rejects('trampoline fragment owner', lambda: view(pc=base + page, size=page, mapped_only=True))
    rejects('fragment file bounds', lambda: view(ms=[{**maps[0], 'offset': len(data) - 1}]))
    rejects('view address overflow', lambda: view(pc=a.U64 - 1, size=2))
    print('e9-sites fragment controls: adjacent/alias/override positives and exact ownership refusals; synthetic only')


def replace(f, key, old, new):
    assert old in f[key]
    f[key] = f[key].replace(old, new, 1)
    return f


def rpc_edit(f, action):
    rows = [json.loads(x) for x in f['rpc'].splitlines()]
    action(rows)
    for i, row in enumerate(rows):
        row['id'] = i
    f['rpc'] = b''.join(json.dumps(r).encode() + b'\n' for r in rows)
    return f


def refused(name, f):
    try:
        run_case(f)
    except (AssertionError, ValueError, KeyError, IndexError, struct.error):
        print('refused ' + name)
    else:
        raise AssertionError('negative control was accepted: ' + name)


def main():
    for name, failed, trap, expected in [
        ('complete-two-sites', False, False, ['trampoline', 'trampoline']),
        ('explicit-refusal-retained', True, False, ['trampoline', 'refused']),
        ('explicit-traps-retained', False, True, ['trap', 'trap']),
    ]:
        rows = run_case(fixture(failed, trap))
        assert [r.split('\t')[4] for r in rows] == expected
        assert [list(map(int, r.split('\t')[:4])) for r in rows] == [[101, 0x400200, 512, 5], [202, 0x400210, 528, 5]]
        assert all(r.split('\t')[5] for r in rows)
        print('accepted ' + name)
    refused('missing-patch', rpc_edit(fixture(), lambda r: r.pop(4)))
    refused('extra-patch', rpc_edit(fixture(), lambda r: r.insert(5, copy.deepcopy(r[4]))))
    refused('wrong-descending-order', rpc_edit(fixture(), lambda r: r.__setitem__(slice(4, 6), list(reversed(r[4:6])))))
    refused('duplicate-instruction', rpc_edit(fixture(), lambda r: r.insert(3, copy.deepcopy(r[2]))))
    refused('changed-pc', rpc_edit(fixture(), lambda r: r[2]['params'].__setitem__('address', 0x400211)))
    refused('changed-length', rpc_edit(fixture(), lambda r: r[2]['params'].__setitem__('length', 4)))
    refused('wrong-file-offset', rpc_edit(fixture(), lambda r: r[2]['params'].__setitem__('offset', 529)))
    refused('stale-original', replace(fixture(), 'original', bytes.fromhex('b801000000'), bytes.fromhex('b803000000')))
    refused('stale-selection', replace(fixture(), 'selection', b'site 101 ', b'site 103 '))
    f = fixture(); p = json.loads(f['policy']); p['e9_revision'] = '0' * 40; f['policy'] = json.dumps(p).encode()
    refused('stale-producer-revision', f)
    refused('missing-debug-site', replace(fixture(), 'stderr', b'debug: patched instruction 0x400210 [size=5, tactic=B1, trampoline=0x600010..0x60001a]\n', b''))
    line = b'debug: patched instruction 0x400210 [size=5, tactic=B1, trampoline=0x600010..0x60001a]\n'
    refused('duplicate-debug-site', replace(fixture(), 'stderr', line, line + line))
    refused('extra-debug-site', replace(fixture(), 'stderr', line, line + line.replace(b'0x400210', b'0x400220')))
    refused('debug-length-disagreement', replace(fixture(), 'stderr', b'size=5', b'size=4'))
    refused('contradictory-statistics', replace(fixture(), 'stdout', b'2 / 2 (100.00%)', b'1 / 2 (50.00%)'))
    refused('unknown-warning', replace(fixture(), 'stderr', b'debug: load trampoline:', b'warning: ignored\ndebug: load trampoline:'))
    refused('absent-mapping-owner', replace(fixture(), 'stderr', b'debug: load trampoline: mmap(0x600000, 4096, PROT_READ | PROT_EXEC | 0, MAP_FIXED | MAP_PRIVATE, fd, +4096)\n', b''))
    refused('loader-map-disagreement', replace(fixture(), 'candidate', bytes.fromhex('bf00006000'), bytes.fromhex('bf00106000')))
    refused('trampoline-extent-outside-owner', replace(fixture(), 'stderr', b'0x600010..0x60001a', b'0x601010..0x60101a'))
    f = fixture(); b = bytearray(f['candidate']); b[513] ^= 1; f['candidate'] = bytes(b)
    refused('gateway-wrong-target', f)
    f = fixture(); b = bytearray(f['candidate']); b[300] = 1; f['candidate'] = bytes(b)
    refused('unowned-original-byte-change', f)
    f = fixture(); b = bytearray(f['candidate']); b[4096] = 0xcc; f['candidate'] = bytes(b)
    refused('trap-not-declared', f)
    f = fixture(False, True); b = bytearray(f['candidate']); b[4096] = 0x90; f['candidate'] = bytes(b)
    refused('trap-request-not-emitted', f)
    # The pure controls never manufacture a pinned producer success or a receipt.
    # Independently exercise the production envelope's producer refusal boundary.
    f = fixture()
    envelope = dict(schema=1, lane='stock-algorithm', reference_commit=a.REVISION, reference_tree=a.TREE,
                    archive_sha256=a.ARCHIVE, capstone_revision=a.CAPSTONE, abi_delta_patch_sha256=a.ABI_PATCH,
                    common_argv=[], hook=None, files={})
    roles = {'original', 'selection', 'policy', 'candidate', 'frontend', 'backend', 'loader', 'transport_frontend', 'helper'} | {p + '_' + r for p in ('transport', 'producer') for r in ('request', 'receipt', 'stdout', 'stderr')}
    envelope['files'] = dict.fromkeys(roles, {})
    try:
        a.validate(envelope, dict.fromkeys(roles, b'not-a-pinned-tool'))
    except AssertionError as e:
        assert str(e) == 'pinned producer lane'
        print('refused stale-producer-bytes')
    else:
        raise AssertionError('unowned producer accepted')
    print('e9-sites controls: 3 accepted / 24 refused; synthetic only')
    fragment_controls()


if __name__ == '__main__':
    main()

# Additive owned-short adapter controls. These reuse supplied synthetic bytes;
# they are not pinned producer captures or an importer/native witness.
def owned_rebind(f, raw):
    f = dict(f)
    f['selection'] = raw
    policy = json.loads(f['policy'])
    policy['selection_sha256'] = a.sha(raw)
    f['policy'] = json.dumps(policy).encode()
    return f


def owned_adapt(f):
    lines = f['selection'].split(b'\n')
    lines[2:2] = [b'neighbor-victims short-only', b'neighbor-ownership inherited-t3']
    return owned_rebind(f, b'\n'.join(lines))


def owned_case(f):
    raw = f['selection']
    sites, policy = a.selection_short_t3_ownership(raw, f['original'], f['policy'])
    assert policy == json.loads(f['policy']) and policy['selection_sha256'] == a.sha(raw)
    intent = a.rpc(f['rpc'], f['original'], sites, '/fixture/original', policy, None, None, False)
    outcomes, maps, bypass = a.debug(f['stderr'], sites)
    saved = a.PRODUCERS
    try:
        ownership = synthetic_artifact(f, intent, outcomes, maps, bypass)
    finally:
        assert a.PRODUCERS is saved, 'synthetic lane restored on success or refusal'
    a.statistics(f['stdout'], outcomes, ownership, '/fixture/original')
    wire = a.wire(sites, policy, outcomes, intent['trap'])
    assert f['selection'] == raw
    return sites, policy, wire


def owned_reject(name, action, reason=None):
    try:
        action()
    except AssertionError as error:
        if reason is not None:
            assert str(error) == reason, (name, reason, str(error))
    else:
        raise AssertionError('owned-short negative accepted: ' + name)


def owned_selection_controls():
    mode = b'neighbor-victims short-only\nneighbor-ownership inherited-t3\n'
    for failed, trap, expected in [
        (False, False, ['trampoline', 'trampoline']),
        (True, False, ['trampoline', 'refused']),
        (False, True, ['trap', 'trap']),
    ]:
        legacy = fixture(failed, trap)
        f = owned_adapt(legacy)
        sites, policy, wire = owned_case(f)
        rows = wire.decode().splitlines()
        assert rows[7:] == run_case(legacy)
        assert [r.split('\t')[4] for r in rows[7:]] == expected
        assert sites == [dict(site=101, pc=0x400200, length=5, file_offset=512),
                         dict(site=202, pc=0x400210, length=5, file_offset=528)]
        assert rows[2] == 'selection_sha256\t' + a.sha(f['selection'])
        assert a.sha(f['selection']) != a.sha(legacy['selection'])
        assert set(r.split('\t')[0] for r in rows[1:6]) == {
            'original_sha256', 'selection_sha256', 'e9_revision', 'instrumentation', 'selection_style'}
        assert len(rows) == 9 and 'selection_profile' not in wire.decode()
        assert policy == json.loads(f['policy'])
        owned_reject('legacy route refuses mode rows', lambda: a.selection(f['selection'], f['original'], f['policy']), 'unknown/short selection record')
        owned_reject('new route refuses legacy', lambda: a.selection_short_t3_ownership(legacy['selection'], legacy['original'], legacy['policy']), 'owned selection prefix')
    f = owned_adapt(fixture())
    raw = f['selection']
    family, ownership = mode.splitlines(keepends=True)
    hostile = [
        ('missing family', raw.replace(family, b'')),
        ('missing ownership', raw.replace(ownership, b'')),
        ('duplicate family', raw.replace(family, family + family)),
        ('duplicate ownership', raw.replace(ownership, ownership + ownership)),
        ('reordered modes', raw.replace(mode, ownership + family)),
        ('relocated family', raw.replace(family, b'') + family),
        ('relocated ownership', raw.replace(ownership, b'') + ownership),
        ('late duplicate family', raw + family),
        ('late duplicate ownership', raw + ownership),
        ('wrong family', raw.replace(family, b'neighbor-victims long-only\n')),
        ('wrong ownership', raw.replace(ownership, b'neighbor-ownership local-only\n')),
        ('extra mode token', raw.replace(ownership, b'neighbor-ownership inherited-t3 extra\n')),
        ('leading mode space', raw.replace(family, b' ' + family)),
        ('trailing mode space', raw.replace(family, family[:-1] + b' \n')),
        ('CRLF', raw.replace(b'\n', b'\r\n')),
        ('noncanonical original', raw.replace(b'original ', b'original\t', 1)),
        ('noncanonical header', raw.replace(b'LI2TOOL 1\n', b'LI2TOOL 1 \n', 1)),
    ]
    for name, changed in hostile:
        bad = owned_rebind(f, changed)
        assert json.loads(bad['policy'])['selection_sha256'] == a.sha(changed)
        owned_reject(name, lambda bad=bad: a.selection_short_t3_ownership(bad['selection'], bad['original'], bad['policy']))
    for name, changed in [
        ('duplicate site ID', raw.replace(b'site 202 ', b'site 101 ')),
        ('duplicate PC', raw.replace(b'0x400210', b'0x400200')),
        ('duplicate file offset', raw.replace(b'5 528 ', b'5 512 ')),
        ('no sites', b'\n'.join(line for line in raw.split(b'\n') if not line.startswith(b'site '))),
    ]:
        bad = owned_rebind(f, changed)
        owned_reject(name, lambda bad=bad: owned_case(bad))
    for name, changed in [
        ('missing site against full RPC', b'\n'.join(line for line in raw.split(b'\n') if not line.startswith(b'site 202 '))),
        ('extra site against full RPC', raw + b'site 303 0x400220 5 544 0 0 0 0 0 0 0 0 0\n'),
    ]:
        bad = owned_rebind(f, changed)
        owned_reject(name, lambda bad=bad: owned_case(bad), 'complete descending patch list')
    changed = dict(f, selection=raw.replace(b'site 101 ', b'site 103 '))
    owned_reject('stale full selection identity', lambda: owned_case(changed))
    original = bytearray(f['original']); original[512] ^= 1
    changed = dict(f, original=bytes(original))
    owned_reject('stale original identity', lambda: owned_case(changed))
    for name, change in [
        ('stripped-view policy identity', dict(selection_sha256=a.sha(raw.replace(mode, b'')))),
        ('wrong policy original', dict(original_sha256='0' * 64)),
        ('wrong policy producer', dict(e9_revision='0' * 40)),
        ('extra policy key', dict(selection_profile=a.SHORT_T3_OWNERSHIP_PROFILE)),
        ('wrong policy schema', dict(schema=True)),
    ]:
        policy = json.loads(f['policy']); policy.update(change)
        bad = dict(f, policy=json.dumps(policy).encode())
        owned_reject(name, lambda bad=bad: owned_case(bad))
    cap = 1024 * 1024
    exact = owned_rebind(f, raw + b'\n' * (cap - len(raw)))
    sites, policy = a.selection_short_t3_ownership(exact['selection'], exact['original'], exact['policy'])
    assert len(sites) == 2 and policy['selection_sha256'] == a.sha(exact['selection'])
    oversized = owned_rebind(f, exact['selection'] + b'\n')
    assert len(oversized['selection']) == cap + 1 and len(oversized['selection']) - len(mode) < cap
    owned_reject('full cap precedes private view', lambda: a.selection_short_t3_ownership(oversized['selection'], oversized['original'], oversized['policy']), 'selection length/newline')
    print('owned selection controls: full-mode structural fixtures, exact identity/cap and required refusals; synthetic only')


def owned_producer_scope_controls():
    saved = a.PRODUCERS
    f = owned_adapt(fixture())
    owned_case(f)
    assert a.PRODUCERS is saved
    gateway = bytearray(f['candidate']); gateway[513] ^= 1
    owned_reject('gateway target', lambda: owned_case(dict(f, candidate=bytes(gateway))), 'source gateway reaches reported emitted trampoline')
    loader = bytearray(f['candidate']); loader[-1] ^= 1
    owned_reject('whole loader bytes', lambda: owned_case(dict(f, candidate=bytes(loader))), 'whole pinned loader/mmap/old-entry bytes')
    gap = owned_adapt(fragment_fixture(change=lambda maps: maps[1].__setitem__('va', 0x602000)))
    owned_reject('mapping extent owner', lambda: owned_case(gap), 'actual executable trampoline extent owner')
    uncovered = owned_adapt(fragment_fixture(change=lambda maps: maps[1].__setitem__('offset', 4096)))
    owned_reject('complete backing ownership', lambda: owned_case(uncovered), 'complete appended backing ownership')
    trap = owned_adapt(fixture(False, True)); candidate = bytearray(trap['candidate']); candidate[4096] = 0x90
    owned_reject('trap cannot become trampoline', lambda: owned_case(dict(trap, candidate=bytes(candidate))), 'trap cannot be relabelled as trampoline')
    lines = f['stderr'].splitlines(keepends=True)
    owned_reject('subset debug outcomes', lambda: owned_case(dict(f, stderr=b''.join(lines[1:]))), 'exact per-site debug outcomes')
    owned_reject('empty debug outcomes', lambda: owned_case(dict(f, stderr=b''.join(lines[2:]))), 'exact per-site debug outcomes')
    assert a.PRODUCERS is saved, 'synthetic substitutions restore exact producer object after refusals'
    # No synthetic producer digest or successful production envelope is installed.
    roles = {'original', 'selection', 'policy', 'candidate', 'frontend', 'backend', 'loader', 'transport_frontend', 'helper'} | {p + '_' + r for p in ('transport', 'producer') for r in ('request', 'receipt', 'stdout', 'stderr')}
    for lane in saved:
        envelope = dict(schema=1, lane=lane, reference_commit=a.REVISION, reference_tree=a.TREE,
                        archive_sha256=a.ARCHIVE, capstone_revision=a.CAPSTONE, abi_delta_patch_sha256=a.ABI_PATCH,
                        common_argv=[], hook=None, files=dict.fromkeys(roles, {}))
        blobs = dict.fromkeys(roles, b'not-a-pinned-tool')
        blobs.update({key: f[key] for key in ('original', 'selection', 'policy', 'candidate')})
        owned_reject('new route retains producer guard ' + lane,
                     lambda: a._validate(envelope, blobs, a.SHORT_T3_OWNERSHIP_PROFILE), 'pinned producer lane')
    assert a.PRODUCERS is saved
    # Receipt syntax alone is not producer evidence. These supplied values never
    # enter validate() and never stand in for actual captured execution outcomes.
    request = json.dumps(dict(wall_seconds=1)).encode()
    helper, stdout, stderr = a.sha(b'synthetic-helper'), b'synthetic-stdout', b'synthetic-stderr'
    record = dict(request_sha256=a.sha(request), helper_sha256=helper, exit=0, wall_timeout=False,
                  unexpected_descendants=[], absence_proof='ECHILD', stdout_sha256=a.sha(stdout),
                  stderr_sha256=a.sha(stderr), elapsed_seconds=0, cleanup_events=[], cleanup_error=None,
                  aborted=None, inputs_unchanged=True)
    assert a.receipt(json.dumps(record).encode(), request, helper, stdout, stderr) == dict(wall_seconds=1)
    for name, change in [
        ('abnormal exit', dict(exit=1)), ('boolean exit', dict(exit=False)),
        ('timeout', dict(wall_timeout=True)), ('descendants', dict(unexpected_descendants=[1])),
        ('cleanup events', dict(cleanup_events=['synthetic'])), ('cleanup error', dict(cleanup_error='synthetic')),
        ('abort', dict(aborted='synthetic')), ('changed inputs', dict(inputs_unchanged=False)),
        ('changed request hash', dict(request_sha256='0' * 64)), ('changed helper hash', dict(helper_sha256='0' * 64)),
        ('changed stdout hash', dict(stdout_sha256='0' * 64)), ('changed stderr hash', dict(stderr_sha256='0' * 64)),
        ('missing absence proof', dict(absence_proof='none')), ('elapsed bound', dict(elapsed_seconds=2)),
    ]:
        encoded = json.dumps(dict(record, **change)).encode()
        owned_reject(name, lambda encoded=encoded: a.receipt(encoded, request, helper, stdout, stderr))
    print('owned producer scope controls: unchanged guards and structural helper refusals; no pinned producer acceptance')


def owned_cli_controls():
    argv = ['/fixture/envelope', '/fixture/new-output', '--envelope-sha256', 'a' * 64]
    legacy = a.arguments(argv)
    assert legacy.envelope == Path(argv[0]) and legacy.new_output == Path(argv[1])
    assert legacy.envelope_sha256 == 'a' * 64 and legacy.selection_profile is None
    supplied = a.arguments(argv + ['--selection-profile', a.SHORT_T3_OWNERSHIP_PROFILE])
    assert supplied.selection_profile == a.SHORT_T3_OWNERSHIP_PROFILE
    equals = a.arguments(argv + ['--selection-profile=' + a.SHORT_T3_OWNERSHIP_PROFILE])
    assert equals.selection_profile == supplied.selection_profile
    # Existing abbreviated envelope option and flag-shaped paths after -- stay legacy.
    assert a.arguments(['/fixture/e', '/fixture/o', '--envelope-sha', 'a' * 64]).selection_profile is None
    paths = a.arguments(['--envelope-sha256', 'a' * 64, '--', '--selection-profile', '/fixture/o'])
    assert paths.envelope == Path('--selection-profile') and paths.selection_profile is None
    for extra, expected_exception in [
        (['--selection-profile', a.SHORT_T3_OWNERSHIP_PROFILE] * 2, AssertionError),
        (['--selection-profile=unknown'], SystemExit),
        (['--selection-profile'], SystemExit),
        (['--selection-p', a.SHORT_T3_OWNERSHIP_PROFILE], AssertionError),
    ]:
        try:
            a.arguments(argv + extra)
        except expected_exception as error:
            if isinstance(error, SystemExit):
                assert error.code == 2
        else:
            raise AssertionError('invalid actual CLI arguments accepted: ' + str(extra))
    f = owned_adapt(fixture())
    sites, policy = a._selection_for_profile(f['selection'], f['original'], f['policy'], supplied.selection_profile)
    assert len(sites) == 2 and policy['selection_sha256'] == a.sha(f['selection'])
    owned_reject('omitted flag never infers ownership', lambda: a._selection_for_profile(f['selection'], f['original'], f['policy'], legacy.selection_profile), 'unknown/short selection record')
    original = fixture()
    assert a._selection_for_profile(original['selection'], original['original'], original['policy'], None) == a.selection(original['selection'], original['original'], original['policy'])
    owned_reject('explicit mode never falls back', lambda: a._selection_for_profile(original['selection'], original['original'], original['policy'], supplied.selection_profile), 'owned selection prefix')
    owned_reject('closed dispatch vocabulary', lambda: a._selection_for_profile(f['selection'], f['original'], f['policy'], 'unknown'), 'selection profile')
    seed = dict(scope='STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY')
    assert a._selection_binding(dict(seed), None) == seed
    assert a._selection_binding(dict(seed), supplied.selection_profile) == dict(seed, selection_profile=a.SHORT_T3_OWNERSHIP_PROFILE)
    owned_reject('private binding has closed mode', lambda: a._selection_binding(dict(seed), 'unknown'), 'selection profile')
    owned_reject('private binding cannot relabel', lambda: a._selection_binding(dict(seed, selection_profile='legacy'), supplied.selection_profile), 'duplicate selection profile binding')
    print('owned CLI controls: actual argument/dispatch/binding helpers and full raw selection identity')


if __name__ == '__main__':
    owned_selection_controls()
    owned_producer_scope_controls()
    owned_cli_controls()


# Pending-mode structural controls are additive to every owned/legacy control.
# Their supplied forced-puzzle bytes are not sealed importer or producer evidence.
def pending_adapt(f):
    lines = f['selection'].split(b'\n')
    lines[2:2] = [b'neighbor-victims short-only', b'neighbor-ownership inherited-t3',
                  b'pending-selected full-instruction-ownership']
    return owned_rebind(f, b'\n'.join(lines))


def pending_case(f):
    raw = f['selection']
    sites, policy = a.selection_short_t3_pending(raw, f['original'], f['policy'])
    assert policy == json.loads(f['policy']) and policy['selection_sha256'] == a.sha(raw)
    intent = a.rpc(f['rpc'], f['original'], sites, '/fixture/original', policy, None, None, False)
    outcomes, maps, bypass = a.debug(f['stderr'], sites)
    saved = a.PRODUCERS
    try:
        ownership = synthetic_artifact(f, intent, outcomes, maps, bypass)
    finally:
        assert a.PRODUCERS is saved, 'synthetic lane restored on success or refusal'
    a.statistics(f['stdout'], outcomes, ownership, '/fixture/original')
    wire = a.wire(sites, policy, outcomes, intent['trap'])
    assert f['selection'] == raw
    return sites, policy, wire


def pending_reject(name, action, reason=None):
    try:
        action()
    except AssertionError as error:
        if reason is not None:
            assert str(error) == reason, (name, reason, str(error))
    else:
        raise AssertionError('pending-short negative accepted: ' + name)


def pending_selection_controls():
    mode = (b'neighbor-victims short-only\nneighbor-ownership inherited-t3\n'
            b'pending-selected full-instruction-ownership\n')
    for failed, trap, expected in [
        (False, False, ['trampoline', 'trampoline']),
        (True, False, ['trampoline', 'refused']),
        (False, True, ['trap', 'trap']),
    ]:
        legacy = fixture(failed, trap)
        owned = owned_adapt(legacy)
        f = pending_adapt(legacy)
        sites, policy, wire = pending_case(f)
        rows = wire.decode().splitlines()
        assert rows[7:] == run_case(legacy) == owned_case(owned)[2].decode().splitlines()[7:]
        assert [r.split('\t')[4] for r in rows[7:]] == expected
        assert sites == [dict(site=101, pc=0x400200, length=5, file_offset=512),
                         dict(site=202, pc=0x400210, length=5, file_offset=528)]
        assert rows[2] == 'selection_sha256\t' + a.sha(f['selection'])
        assert len({a.sha(x['selection']) for x in (legacy, owned, f)}) == 3
        assert set(r.split('\t')[0] for r in rows[1:6]) == {
            'original_sha256', 'selection_sha256', 'e9_revision', 'instrumentation', 'selection_style'}
        assert len(rows) == 9 and 'selection_profile' not in wire.decode()
        assert policy == json.loads(f['policy']) and f['selection'].count(mode) == 1
        pending_reject('legacy refuses pending projection',
                       lambda: a.selection(f['selection'], f['original'], f['policy']),
                       'unknown/short selection record')
        pending_reject('owned refuses pending projection',
                       lambda: a.selection_short_t3_ownership(f['selection'], f['original'], f['policy']),
                       'unknown/short selection record')
        single_family = owned_rebind(owned, owned['selection'].replace(
            b'neighbor-ownership inherited-t3\n', b''))
        for prior in (legacy, owned, single_family):
            pending_reject('pending refuses incomplete mode',
                           lambda prior=prior: a.selection_short_t3_pending(prior['selection'], prior['original'], prior['policy']),
                           'pending selection prefix')
    f = pending_adapt(fixture())
    raw = f['selection']
    modes = mode.splitlines(keepends=True)
    for index, row in enumerate(modes):
        key = row.split()[0]
        hostile = [
            ('missing', raw.replace(row, b'')),
            ('duplicate prefix', raw.replace(row, row + row)),
            ('duplicate late', raw + row),
            ('relocated after sites', raw.replace(row, b'') + row),
            ('relocated after globals', raw.replace(row, b'').replace(b'site 101 ', row + b'site 101 ', 1)),
            ('wrong value', raw.replace(row, key + b' wrong-mode\n')),
            ('extra token', raw.replace(row, row[:-1] + b' extra\n')),
            ('leading whitespace', raw.replace(row, b' ' + row)),
            ('trailing whitespace', raw.replace(row, row[:-1] + b' \n')),
        ]
        for other in range(len(modes)):
            if other != index:
                changed = list(modes); changed[index], changed[other] = changed[other], changed[index]
                hostile.append(('reordered ' + str(other), raw.replace(mode, b''.join(changed))))
        for name, changed in hostile:
            bad = owned_rebind(f, changed)
            assert json.loads(bad['policy'])['selection_sha256'] == a.sha(changed)
            pending_reject(key.decode() + ' ' + name,
                           lambda bad=bad: a.selection_short_t3_pending(bad['selection'], bad['original'], bad['policy']))
    for name, changed in [
        ('CRLF', raw.replace(b'\n', b'\r\n')),
        ('noncanonical header', raw.replace(b'LI2TOOL 1\n', b'LI2TOOL 1 \n', 1)),
        ('noncanonical original', raw.replace(b'original ', b'original\t', 1)),
        ('late mode with whitespace', raw + b'\tpending-selected full-instruction-ownership\n'),
    ]:
        bad = owned_rebind(f, changed)
        pending_reject(name, lambda bad=bad: a.selection_short_t3_pending(bad['selection'], bad['original'], bad['policy']))
    for name, changed in [
        ('duplicate site ID', raw.replace(b'site 202 ', b'site 101 ')),
        ('duplicate PC', raw.replace(b'0x400210', b'0x400200')),
        ('duplicate file offset', raw.replace(b'5 528 ', b'5 512 ')),
        ('no sites', b'\n'.join(line for line in raw.split(b'\n') if not line.startswith(b'site '))),
    ]:
        bad = owned_rebind(f, changed)
        pending_reject(name, lambda bad=bad: pending_case(bad))
    for name, changed in [
        ('missing site against full RPC', b'\n'.join(line for line in raw.split(b'\n') if not line.startswith(b'site 202 '))),
        ('extra site against full RPC', raw + b'site 303 0x400220 5 544 0 0 0 0 0 0 0 0 0\n'),
    ]:
        bad = owned_rebind(f, changed)
        pending_reject(name, lambda bad=bad: pending_case(bad), 'complete descending patch list')
    pending_reject('stale full selection identity',
                   lambda: pending_case(dict(f, selection=raw.replace(b'site 101 ', b'site 103 '))))
    original = bytearray(f['original']); original[512] ^= 1
    pending_reject('stale original identity', lambda: pending_case(dict(f, original=bytes(original))))
    stripped_legacy = raw.replace(mode, b'')
    stripped_owned = raw.replace(modes[2], b'')
    for name, change in [
        ('stripped legacy identity', dict(selection_sha256=a.sha(stripped_legacy))),
        ('stripped owned identity', dict(selection_sha256=a.sha(stripped_owned))),
        ('wrong policy original', dict(original_sha256='0' * 64)),
        ('wrong producer revision', dict(e9_revision='0' * 40)),
        ('unknown instrumentation', dict(instrumentation='unknown')),
        ('unknown selection style', dict(selection_style='unknown')),
        ('extra policy mode key', dict(selection_profile=a.SHORT_T3_PENDING_PROFILE)),
        ('boolean policy schema', dict(schema=True)),
    ]:
        policy = json.loads(f['policy']); policy.update(change)
        bad = dict(f, policy=json.dumps(policy).encode())
        pending_reject(name, lambda bad=bad: pending_case(bad))
    cap = 1024 * 1024
    exact = owned_rebind(f, raw + b'\n' * (cap - len(raw)))
    assert len(exact['selection']) == cap
    sites, policy = a.selection_short_t3_pending(exact['selection'], exact['original'], exact['policy'])
    assert len(sites) == 2 and policy['selection_sha256'] == a.sha(exact['selection'])
    oversized = owned_rebind(f, exact['selection'] + b'\n')
    assert len(oversized['selection']) == cap + 1 and len(oversized['selection']) - len(mode) < cap
    pending_reject('full cap before private view',
                   lambda: a.selection_short_t3_pending(oversized['selection'], oversized['original'], oversized['policy']),
                   'selection length/newline')
    print('pending selection controls: three-row identity, complete structural outcomes and exact-cap refusals; synthetic only')


def pending_producer_scope_controls():
    saved = a.PRODUCERS
    f = pending_adapt(fixture())
    pending_case(f)
    assert a.PRODUCERS is saved
    gateway = bytearray(f['candidate']); gateway[513] ^= 1
    pending_reject('gateway target', lambda: pending_case(dict(f, candidate=bytes(gateway))), 'source gateway reaches reported emitted trampoline')
    loader = bytearray(f['candidate']); loader[-1] ^= 1
    pending_reject('whole loader bytes', lambda: pending_case(dict(f, candidate=bytes(loader))), 'whole pinned loader/mmap/old-entry bytes')
    gap = pending_adapt(fragment_fixture(change=lambda maps: maps[1].__setitem__('va', 0x602000)))
    pending_reject('mapping extent owner', lambda: pending_case(gap), 'actual executable trampoline extent owner')
    uncovered = pending_adapt(fragment_fixture(change=lambda maps: maps[1].__setitem__('offset', 4096)))
    pending_reject('complete backing ownership', lambda: pending_case(uncovered), 'complete appended backing ownership')
    trap = pending_adapt(fixture(False, True)); candidate = bytearray(trap['candidate']); candidate[4096] = 0x90
    pending_reject('trap classification', lambda: pending_case(dict(trap, candidate=bytes(candidate))), 'trap cannot be relabelled as trampoline')
    lines = f['stderr'].splitlines(keepends=True)
    pending_reject('subset debug outcomes', lambda: pending_case(dict(f, stderr=b''.join(lines[1:]))), 'exact per-site debug outcomes')
    pending_reject('empty debug outcomes', lambda: pending_case(dict(f, stderr=b''.join(lines[2:]))), 'exact per-site debug outcomes')
    assert a.PRODUCERS is saved, 'synthetic substitutions restored after all refusals'
    # Actual production validation must refuse the synthetic tool tuples in both
    # lanes. Never install fake producer authority to reach the transport guard.
    roles = {'original', 'selection', 'policy', 'candidate', 'frontend', 'backend', 'loader', 'transport_frontend', 'helper'} | {p + '_' + r for p in ('transport', 'producer') for r in ('request', 'receipt', 'stdout', 'stderr')}
    for lane in saved:
        envelope = dict(schema=1, lane=lane, reference_commit=a.REVISION, reference_tree=a.TREE,
                        archive_sha256=a.ARCHIVE, capstone_revision=a.CAPSTONE, abi_delta_patch_sha256=a.ABI_PATCH,
                        common_argv=[], hook=None, files=dict.fromkeys(roles, {}))
        blobs = dict.fromkeys(roles, b'not-a-pinned-tool')
        blobs.update({key: f[key] for key in ('original', 'selection', 'policy', 'candidate')})
        pending_reject('pending real producer guard ' + lane,
                       lambda: a._validate(envelope, blobs, a.SHORT_T3_PENDING_PROFILE), 'pinned producer lane')
    assert a.PRODUCERS is saved
    # Supplied receipt syntax is checked directly, never used as actual closure.
    request = json.dumps(dict(wall_seconds=1)).encode()
    helper, stdout, stderr = a.sha(b'synthetic-helper'), b'synthetic-stdout', b'synthetic-stderr'
    record = dict(request_sha256=a.sha(request), helper_sha256=helper, exit=0, wall_timeout=False,
                  unexpected_descendants=[], absence_proof='ECHILD', stdout_sha256=a.sha(stdout),
                  stderr_sha256=a.sha(stderr), elapsed_seconds=0, cleanup_events=[], cleanup_error=None,
                  aborted=None, inputs_unchanged=True)
    assert a.receipt(json.dumps(record).encode(), request, helper, stdout, stderr) == dict(wall_seconds=1)
    for name, change in [
        ('nonzero exit', dict(exit=1)), ('bool exit', dict(exit=False)),
        ('timeout', dict(wall_timeout=True)), ('descendants', dict(unexpected_descendants=[1])),
        ('cleanup events', dict(cleanup_events=['synthetic'])), ('cleanup error', dict(cleanup_error='synthetic')),
        ('abort', dict(aborted='synthetic')), ('changed inputs', dict(inputs_unchanged=False)),
        ('request hash', dict(request_sha256='0' * 64)), ('helper hash', dict(helper_sha256='0' * 64)),
        ('stdout hash', dict(stdout_sha256='0' * 64)), ('stderr hash', dict(stderr_sha256='0' * 64)),
        ('missing ECHILD', dict(absence_proof='none')), ('elapsed overflow', dict(elapsed_seconds=2)),
    ]:
        encoded = json.dumps(dict(record, **change)).encode()
        pending_reject(name, lambda encoded=encoded: a.receipt(encoded, request, helper, stdout, stderr))
    print('pending producer controls: original guards and actual helper refusals; no pinned producer acceptance')


def pending_cli_controls():
    argv = ['/fixture/envelope', '/fixture/new-output', '--envelope-sha256', 'a' * 64]
    legacy = a.arguments(argv)
    assert legacy.envelope == Path(argv[0]) and legacy.new_output == Path(argv[1])
    assert legacy.envelope_sha256 == 'a' * 64 and legacy.selection_profile is None
    for profile in (a.SHORT_T3_OWNERSHIP_PROFILE, a.SHORT_T3_PENDING_PROFILE):
        supplied = a.arguments(argv + ['--selection-profile', profile])
        assert supplied.selection_profile == profile
        assert a.arguments(argv + ['--selection-profile=' + profile]).selection_profile == profile
    assert a.arguments(['/fixture/e', '/fixture/o', '--envelope-sha', 'a' * 64]).selection_profile is None
    paths = a.arguments(['--envelope-sha256', 'a' * 64, '--', '--selection-profile', '/fixture/o'])
    assert paths.envelope == Path('--selection-profile') and paths.selection_profile is None
    pending = a.SHORT_T3_PENDING_PROFILE
    for extra, exception in [
        (['--selection-profile', pending] * 2, AssertionError),
        (['--selection-profile=' + pending] * 2, AssertionError),
        (['--selection-profile', a.SHORT_T3_OWNERSHIP_PROFILE, '--selection-profile', pending], AssertionError),
        (['--selection-profile', pending, '--selection-profile=' + a.SHORT_T3_OWNERSHIP_PROFILE], AssertionError),
        (['--selection-profile=unknown'], SystemExit),
        (['--selection-profile'], SystemExit),
        (['--selection-p', pending], AssertionError),
    ]:
        try:
            a.arguments(argv + extra)
        except exception as error:
            if isinstance(error, SystemExit):
                assert error.code == 2
        else:
            raise AssertionError('invalid pending CLI arguments accepted: ' + str(extra))
    base = fixture(); owned = owned_adapt(base); f = pending_adapt(base)
    assert a._selection_for_profile(base['selection'], base['original'], base['policy'], None) == a.selection(base['selection'], base['original'], base['policy'])
    assert a._selection_for_profile(owned['selection'], owned['original'], owned['policy'], a.SHORT_T3_OWNERSHIP_PROFILE) == a.selection_short_t3_ownership(owned['selection'], owned['original'], owned['policy'])
    sites, policy = a._selection_for_profile(f['selection'], f['original'], f['policy'], pending)
    assert sites == a.selection_short_t3_pending(f['selection'], f['original'], f['policy'])[0]
    assert len(sites) == 2 and policy['selection_sha256'] == a.sha(f['selection'])
    for wrong in (None, a.SHORT_T3_OWNERSHIP_PROFILE):
        pending_reject('no inferred pending mode', lambda wrong=wrong: a._selection_for_profile(f['selection'], f['original'], f['policy'], wrong), 'unknown/short selection record')
    for old in (base, owned):
        pending_reject('pending never falls back', lambda old=old: a._selection_for_profile(old['selection'], old['original'], old['policy'], pending), 'pending selection prefix')
    pending_reject('closed dispatch vocabulary', lambda: a._selection_for_profile(f['selection'], f['original'], f['policy'], 'unknown'), 'selection profile')
    seed = dict(scope='STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY')
    assert a._selection_binding(dict(seed), None) == seed
    for profile in (a.SHORT_T3_OWNERSHIP_PROFILE, pending):
        assert a._selection_binding(dict(seed), profile) == dict(seed, selection_profile=profile)
    pending_reject('closed private binding', lambda: a._selection_binding(dict(seed), 'unknown'), 'selection profile')
    pending_reject('no private relabel', lambda: a._selection_binding(dict(seed, selection_profile=a.SHORT_T3_OWNERSHIP_PROFILE), pending), 'duplicate selection profile binding')
    print('pending CLI controls: explicit route, unchanged legacy/owned behavior and full-identity private binding')


if __name__ == '__main__':
    pending_selection_controls()
    pending_producer_scope_controls()
    pending_cli_controls()
