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
    ownership = a.artifact(f['original'], f['candidate'], f['loader'], intent, outcomes, maps, bypass)
    a.statistics(f['stdout'], outcomes, ownership, '/fixture/original')
    return a.wire(sites, policy, outcomes, intent['trap']).decode().splitlines()[7:]


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


if __name__ == '__main__':
    main()
