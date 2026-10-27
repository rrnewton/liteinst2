#!/usr/bin/env python3
"""Offline saved-content audit of one complete caller-admitted core-null artifact."""
import runpy
from types import SimpleNamespace
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

REVISION = 'b0d94f009196b4dea433ea2a5b267fa94f9512b0'
RUNNER_SHA = '80d070c100ff7e6bc2375e2cd17798bdf34584de4c6550ed71056bb0e17ec78e'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
MIB, MASK, DEBUG = 1048576, (1 << 64) - 1, (1 << 8) | (1 << 16)
A, E = 0x600000000000, 0x600000100008
SS, SE = E - 32776, E + 32760
LO, HI, HOOK = 0x400000, 0x425000, 0x401960
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
REGS = 'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()
INHERITED = 'cs ss ds es fs gs fs_base gs_base'.split()
LOADS = [(0, 0x400000, 0x8b0, 0x8b0, 4), (0x1000, 0x401000, 0xa51, 0xa51, 5),
         (0x2000, 0x402000, 0xe1c, 0xe1c, 4), (0x3e00, 0x403e00, 0x20358, 0x20390, 6)]
CELLS = ('null-heap-write-unstripped', 'null-heap-write-stripped', 'null-jump-site-unstripped', 'null-jump-site-stripped')
ORIGINALS = ('987b20efe393a0a2ca0293cd5601ba323b3f8292c9f1b5fab8a22b3124d3cff8',
             '1c7c66c58376c98df1dc3e5fd76d3c22a82ad7e96ef7aee1543a7c5b90a6f529')
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
VERIFY_OUT = b'core null witness complete: heads=87 normal=174 faults=2 execution=false qualification_complete=false\n'
PAIR_OUT = b'core null pairs complete: heads=87 normal=174 faults=2 comparisons=528 E9=UNIMPLEMENTED_UNRUN qualification_complete=false\n'
COMPLETE = (b'LI2COMMONCOREPAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\n'
            b'comparisons\t528\nfiles\t8636\nE9\tUNIMPLEMENTED_UNRUN\nrecording_hooks\tUNIMPLEMENTED_UNRUN\n'
            b'normal_loader_validation\tfalse\nqualification_complete\tfalse\n')
LIVE_ONLY = [
    'The no-repair sequence, one hardware reference instruction, ptrace stop provenance, per-child timing/stop limits and task-count checks are live source assertions; saved states and ordered trace edges are rechecked here.',
    'Intermediate prefix full registers/stack and the literal hook return word are not serialized. The admitted verifier proves the prefix route and scratch bound; this audit checks saved route bytes/edges and full states at before/restored/after boundaries.',
    'The observed fault signal/code/address tuple is saved in both child completion records and checked exactly. The unused full siginfo structure and wait syscall records are not retained; reaped_echild is a child assertion, with independent helper descendant closure.',
    'Live CPUID/XGETBV enumeration and initial parent context are not separately captured. The complete admitted target/component table is joined to every raw and canonical XSAVE image; inherited selectors/bases are checked uniformly across all 352 children.',
    'Anonymous NOREPLACE reservation and live input descriptor stability are source-attested. Saved maps, page bytes, owner records, request/receipt hashes and before/after observations are independently joined.',
]
ERRORS = (AssertionError, ValueError, KeyError, IndexError, OSError, struct.error, TypeError, OverflowError, UnicodeError)


# Explicit profiles are inactive until the final reviewed source binding and
# exact private runner are pinned. A proposal digest is not a build authority.
PROFILE_SOURCE_BINDING_SHA = None
PROFILE_RUNNER_SHA = None
PLANNING = ('legacy', 'owned-foreign-neighbors-v1')
ROUTERS = ('absent', 'linux-x86-64-private-altstack-v1')
PLANNING_BYTES = b'LI2PLANNING\t1\nprofile\towned-foreign-neighbors-v1\nqualification_complete\tfalse\n'
PROFILE_SOURCES = (
    'evaluation/e9-common-app/prepare_subject.py',
    'evaluation/e9-common-app/produce.py',
    'evaluation/e9-common-app/run_candidates.py',
    'tests/support/elf_exec_driver.rs',
    'tests/support/quiescent_oracle.rs',
    'tests/support/e9_common_image.rs',
    'tests/support/e9_common_core.rs',
    'tests/support/e9_common_core_pages.rs',
    'tests/support/e9_common_seed.rs',
    'tests/support/e9_common_seed.instructions.tsv',
    'tests/support/e9_common_planning_profile.rs',
    'tests/support/e9_common_router_contract.rs',
    'tests/support/e9_common_router_native.rs',
    'tests/support/e9_common_router_controls.rs',
    'tools/elf-rewrite/examples/verify_common_core.rs',
    'tools/elf-rewrite/examples/support/common_core_foreign.rs',
    'tools/elf-rewrite/examples/support/common_core_router.rs',
    'tools/elf-rewrite/src/lib.rs',
    'tools/elf-rewrite/src/main.rs',
    'tools/unwind-oracle/bounded_command.py',
)


# This is orthogonal to allocation/planning/router profiles. Absence is legacy.
DEBUG0_BUILD_PROFILE = 'dev-debug0-v1'
DEBUG0_PROFILE = dict(opt_level='0', debuginfo=0, debug_assertions=True, overflow_checks=True, test=False)
DEBUG0_ENV = dict(CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
    CARGO_PROFILE_DEV_OPT_LEVEL='0', CARGO_PROFILE_TEST_OPT_LEVEL='0',
    CARGO_PROFILE_DEV_DEBUG_ASSERTIONS='true', CARGO_PROFILE_TEST_DEBUG_ASSERTIONS='true',
    CARGO_PROFILE_DEV_OVERFLOW_CHECKS='true', CARGO_PROFILE_TEST_OVERFLOW_CHECKS='true')


def same_build_profile(*records):
    assert records
    if 'build_profile' not in records[0]:
        assert all('build_profile' not in row for row in records), 'legacy build profile must be absent'
        return None
    assert all(row['build_profile'] == DEBUG0_BUILD_PROFILE for row in records), 'explicit build profile mismatch'
    return DEBUG0_BUILD_PROFILE


def build_input_profile(admission, root, bound):
    # Authenticate the builder's actual input identity before either profile.
    # This also rejects an isolated new-profile label in a legacy envelope.
    inputs = loads(bound(str(root / 'inputs.json')))
    summary = loads(bound(str(root / 'summary.json')))
    archives = loads(bound(str(root / 'artifacts.json')))
    keys = {'schema', 'preparation', 'collector_binding', 'files'}
    if 'build_profile' in admission:
        keys = keys | {'build_profile'}
    assert set(inputs) == keys and type(inputs['schema']) is int and inputs['schema'] == 1
    assert archives.keys() == {'native-compile', 'common-sites-compile'}
    return same_build_profile(admission, inputs, summary, *archives.values())



def debug0_build_profile(admission, root, bound):
    # All reads go through the caller's existing complete watched catalog.
    summary = loads(bound(str(root / 'summary.json')))
    inputs = loads(bound(str(root / 'inputs.json')))
    assert inputs.keys() == {'schema', 'preparation', 'collector_binding', 'files', 'build_profile'}
    assert type(inputs['schema']) is int and inputs['schema'] == 1
    assert same_build_profile(admission, summary, inputs) == DEBUG0_BUILD_PROFILE
    assert summary['completed'] is True and summary['failure'] is None
    assert summary['observed_stages'] == len(summary['planned_stages']) == 12
    assert summary['cells_complete'] == 8 and summary['unrun_stages'] == []
    if 'source_revision' in admission:
        assert admission['source_revision'] == summary['revision']
    if 'revision' in admission:
        assert admission['revision'] == summary['revision']
    archives = loads(bound(str(root / 'artifacts.json')))
    assert archives.keys() == {'native-compile', 'common-sites-compile'}
    for phase, archive in archives.items():
        assert loads(bound(str(root / phase / 'artifact-archive.json'))) == archive
        assert same_build_profile(admission, archive) == DEBUG0_BUILD_PROFILE
        assert archive['source_revision'] == summary['revision']
        assert archive['selected'].keys() == ({'elf-exec-oracle', 'liteinst-rewrite'} if phase == 'native-compile' else {'common_sites'})
        for selected in archive['selected'].values():
            assert selected['cargo']['profile'] == DEBUG0_PROFILE and selected['cargo']['features'] == []
            assert all(type(selected['cargo']['profile'][k]) is type(v) for k, v in DEBUG0_PROFILE.items())
    if 'products' in admission:
        assert admission['products'] == dict(core=archives['native-compile']['selected']['liteinst-rewrite']['product']['path'], common_sites=archives['common-sites-compile']['selected']['common_sites']['product']['path'])
        assert admission['required_products'] == sorted({row['path'] for archive in archives.values() for row in archive['artifacts'].values()})
    environments = []
    for phase in ('required', 'native-compile', 'common-sites-compile'):
        command = loads(bound(str(root / phase / 'command.json')))
        env = dict(command['env'])
        assert env.pop('TMPDIR') == str(root / phase / 'tmp')
        assert {k: v for k, v in env.items() if k.startswith('CARGO_PROFILE_')} == DEBUG0_ENV
        assert env.keys() == {'CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL', 'CARGO_NET_OFFLINE',
            'CARGO_TARGET_DIR', 'CARGO_HOME', 'HOME', 'RUSTC', 'RUSTDOC', 'RUSTC_WORKSPACE_WRAPPER',
            'RUSTC_WRAPPER', 'RUST_TEST_THREADS', 'LC_ALL', 'PATH', 'PYTHONDONTWRITEBYTECODE'} | DEBUG0_ENV.keys()
        assert env['CARGO_BUILD_JOBS'] == env['RUST_TEST_THREADS'] == '4'
        assert env['CARGO_INCREMENTAL'] == '0' and env['CARGO_NET_OFFLINE'] == 'true'
        assert env['RUSTC_WORKSPACE_WRAPPER'] == env['RUSTC_WRAPPER'] == ''
        assert env['LC_ALL'] == 'C' and env['PYTHONDONTWRITEBYTECODE'] == '1'
        assert Path(command['cwd']).is_absolute() and root.is_relative_to(Path(command['cwd']) / 'ignored')
        assert env['CARGO_TARGET_DIR'] == str(Path(command['cwd']) / 'target')
        tool = Path(env['RUSTC']).parent
        assert Path(env['RUSTC']).is_absolute() and Path(env['RUSTC']).name == 'rustc'
        assert env['RUSTDOC'] == str(tool / 'rustdoc') and env['PATH'] == str(tool) + ':/usr/bin:/bin'
        assert all(Path(env[k]).is_absolute() for k in ('CARGO_TARGET_DIR', 'CARGO_HOME', 'HOME'))
        if phase != 'required':
            request = loads(bound(str(root / phase / 'request.json')))
            assert command['request'] == request and request['env'] == command['env']
        environments.append(env)
    assert environments[0] == environments[1] == environments[2]
    return DEBUG0_BUILD_PROFILE



def profile_arguments(profiles):
    assert set(profiles) == {'planning_profile', 'entry_router'}
    p, r = profiles['planning_profile'], profiles['entry_router']
    assert p in PLANNING and r in ROUTERS
    return (['--planning-profile=' + p] if p != 'legacy' else []) + (
        ['--entry-router=' + r] if r != 'absent' else [])


def profile_activation(saved, envelope, profiles, old_pins):
    if PROFILE_SOURCE_BINDING_SHA is None or PROFILE_RUNNER_SHA is None:
        raise SystemExit('profile activation requires final reviewed source/build and runner pins')
    assert all(type(d) is str and re.fullmatch('[0-9a-f]{64}', d)
               for d in (PROFILE_SOURCE_BINDING_SHA, PROFILE_RUNNER_SHA))
    assert (VERIFIER_CAPABILITY!='legacy' or RECORDING or profile_arguments(profiles)) and envelope['profiles'] == profiles
    b = saved.read(envelope['source_binding']); assert sha(b) == PROFILE_SOURCE_BINDING_SHA
    epoch = loads(b)
    assert set(epoch) == {'schema', 'revision', 'prepared_revision', 'sources'}
    assert type(epoch['schema']) is int and epoch['schema'] == 1
    assert all(type(epoch[k]) is str and re.fullmatch('[0-9a-f]{40}', epoch[k])
               for k in ('revision', 'prepared_revision'))
    assert set(epoch['sources']) == set(PROFILE_SOURCES)
    assert all(type(d) is str and re.fullmatch('[0-9a-f]{64}', d) for d in epoch['sources'].values())
    # Whole source ownership is still checked against the saved build/run epoch.
    # The unchanged descriptor and helper bytes cannot be redefined by activation.
    for p in ('tests/support/e9_common_seed.rs', 'tests/support/e9_common_seed.instructions.tsv',
              'tools/unwind-oracle/bounded_command.py'):
        assert epoch['sources'][p] == old_pins[p]
    pins = dict(epoch['sources'])
    pins['tests/support/elf_exec_oracle.rs'] = old_pins['tests/support/elf_exec_oracle.rs']
    return dict(profiles=profiles, epoch=epoch, pins=pins)


def profile_records(saved, envelope, inputs, source, summary, profile):
    profiles = profile['profiles']
    assert inputs['profiles'] == profiles and inputs['source_binding'] == envelope['source_binding']
    verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING,inputs,summary)
    if RECORDING:
        assert inputs['recording_profile']==summary['recording_profile']==envelope['recording_profile']==RECORDING_PROFILE
        assert saved.json(Path(envelope['run'])/'recording-profile.json')==dict(profile=RECORDING_PROFILE,cell=summary['cell'],mandatory_pairs=2112,core_null_pairs=704)
    assert saved.pins[inputs['source_binding']] == inputs['files'][inputs['source_binding']]
    expected = dict(profiles=profiles, source_binding_sha256=PROFILE_SOURCE_BINDING_SHA)
    assert saved.json(Path(envelope['run'])/'profiles.json') == expected
    assert all(summary[k] == v for k, v in expected.items())
    assert source['revision'] == profile['epoch']['revision']
    cell = saved.json(inputs['cell_admission'])
    assert all(cell[k] == v for k, v in expected.items())
    # Preserve every preceding attempt, including failures. This is a source
    # and profile join, not an assertion that prior attempts all succeeded.
    for path in inputs['prior_cells']:
        prior = saved.json(path)
        verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING,prior)
        if RECORDING:
            assert prior['recording_profile']==RECORDING_PROFILE
        assert all(prior[k] == v for k, v in expected.items())
        if prior['summary'] is not None:
            prior_summary = saved.json(prior['summary'])
            assert all(prior_summary[k] == v for k, v in expected.items())


def source_ranges(heads):
    ranges = []
    for name in ('Store', 'Sift', 'Heap'):
        group = [h for h in heads if h['function'] == name]
        assert group and all(a['pc'] + a['length'] == b['pc'] for a, b in zip(group, group[1:]))
        ranges.append((group[0]['pc'], group[-1]['pc'] + group[-1]['length']))
    assert ranges == [(0x401840, 0x401845), (0x401850, 0x4018cf), (0x4018d0, 0x401951)]
    return ranges


def router_routes(rows, cursor, enabled, heads, pages, ledger):
    routes = []
    if enabled:
        assert rows[cursor] == ['router-profile', ROUTERS[1]]; cursor += 1
        while rows[cursor][0] == 'router':
            row = rows[cursor]; assert len(row) == 6
            pc, dest, lo, hi = map(num, row[1:5]); fetch = trace_hex(row[5])
            assert (lo, hi) in source_ranges(heads) and lo <= pc < hi
            assert any(h['pc'] == pc and h['flow'] != 'Call' for h in heads)
            assert pc != dest and dest > 0 and not LO <= dest < HI
            assert pages[dest & ~4095][0] == 5
            if fetch[:1] == b'\x62':
                assert len(fetch) == 15 and pc % 4096 <= 4081 and pc + 15 <= hi and fetch[2] & 4 == 0
            else:
                assert len(fetch) == 1 and fetch[0] in (6,7,14,22,23,30,31,39,47,55,63,96,97,206)
            assert at(pages, pc, len(fetch)) == fetch
            routes.append(dict(pc=pc, target=dest, lo=lo, hi=hi, fetch=fetch)); cursor += 1
    assert len(routes) <= 87 and [r['pc'] for r in routes] == sorted({r['pc'] for r in routes})
    declarations = [r for r in ledger if r[0] == 'entry-router-required']
    assert all(len(r) == 5 for r in declarations)
    assert len(declarations) == len(routes)
    assert sorted((num(r[3]), num(r[4])) for r in declarations) == [(r['pc'], r['target']) for r in routes]
    return cursor, routes


def router_ledger(ledger, routes, heads, opages, cpages):
    """Reconstruct the full current function reads and original-derived B1 edits.

    The existing verifier still owns all other image/relocation contracts. This
    independently binds the new router declarations and plan-wide requirement 6.
    """
    ranges = source_ranges(heads)
    current = {p: bytearray(at(opages, p, z-p)) for p, z in ranges}
    declarations = [r for r in ledger if r[0] == 'entry-router-required']
    images = [r for r in ledger if r[0] == 'image']
    assert all(len(r) == 7 for r in images)
    assert len(images) == len({num(r[1]) for r in images})
    steps = [r for r in ledger if r[0] == 'step']; seen = set()
    def owner(pc, n):
        matches = [(a, b) for a, b in ranges if a <= pc and pc+n <= b]
        assert len(matches) == 1 and n > 0
        return matches[0]
    for step in steps:
        assert len(step) == 8
        key = step[1:3]; pair = tuple(map(num, key)); assert pair not in seen; seen.add(pair)
        relevant = lambda kind: [r for r in ledger if r[0] == kind and r[1:3] == key]
        routed = relevant('entry-router-required')
        reads, writes = relevant('step-read'), relevant('semantic-write')
        for r in reads:
            assert len(r) == 5
            pc, b = num(r[3]), trace_hex(r[4]); lo, _ = owner(pc, len(b))
            assert b == current[lo][pc-lo:pc-lo+len(b)]
        if routed:
            assert step[3] == 'relocation'
            physical, lo, hi = map(num, step[5:8]); assert physical == lo and hi-lo >= 5
            start, end = owner(lo, hi-lo)
            expected_pcs = {h['pc'] for h in heads if lo < h['pc'] < hi}
            assert {num(r[3]) for r in routed} == expected_pcs
            assert reads == [['step-read', *key, str(start), bytes(current[start]).hex()]]
            assert current[start][lo-start:hi-start] == at(opages, lo, hi-lo)
            assert relevant('entry-preserved') == [['entry-preserved', *key, str(physical)]]
            assert relevant('live-prerequisites-not-receipts') == [
                ['live-prerequisites-not-receipts', *key, 'true', 'true', 'true']]
            owned_ids = {r[1] for r in images if r[2] == step[1]}
            entry = [r for r in ledger if r[0] == 'route' and r[1] in owned_ids and num(r[2]) == physical]
            assert len(entry) == 1 and len(entry[0]) == 4
            delta = num(entry[0][3]) - physical - 5; assert -(1 << 31) <= delta < 1 << 31
            patch = bytearray(at(opages, lo, hi-lo)); patch[:5] = b'\xe9' + struct.pack('<i', delta)
            for pc in sorted(expected_pcs, reverse=True):
                if pc >= physical+5:
                    offset = pc-physical; patch[offset] = 0x62
                    combined = patch + current[start][hi-start:]
                    if pc % 4096 > 4081 or end-pc < 15 or offset+2 >= len(combined) or combined[offset+2] & 4:
                        patch[offset] = 0x60
            assert writes == [['semantic-write', *key, str(physical), patch.hex()]]
        for r in writes:
            assert len(r) == 5
            pc, b = num(r[3]), trace_hex(r[4]); lo, _ = owner(pc, len(b))
            current[lo][pc-lo:pc-lo+len(b)] = b
    for r in ledger:
        if r[0] in ('entry-router-required', 'step-read', 'semantic-write'):
            assert tuple(map(num, r[1:3])) in seen
    for lo, hi in ranges:
        assert bytes(current[lo]) == at(cpages, lo, hi-lo)
    for route in routes:
        declared = [r for r in declarations if num(r[3]) == route['pc']]
        assert len(declared) == 1
        site = declared[0][1]
        owners = [r for r in images if r[2] == site and num(r[3]) <= route['target'] < num(r[3])+num(r[4])]
        assert len(owners) == 1
        assert [r for r in ledger if r[0] == 'route' and r[1] == owners[0][1] and num(r[2]) == route['pc']] == [
            ['route', owners[0][1], str(route['pc']), str(route['target'])]]
    for image_row in images:
        image_id, site = image_row[1:3]
        actual = [r for r in ledger if r[0] == 'unmet-requirement' and r[1] == image_id and r[2] == '6']
        expected = [['unmet-requirement', image_id, '6', '0']] if any(r[1] == site for r in declarations) else []
        assert actual == expected, ('plan-wide router requirement', image_id)


def router_code(code, base):
    """Decode only the exact finite handler/restorer instruction program.

    Conditional branches permit their two architectural displacement widths;
    every destination, immediate, operand, byte and final extent is checked.
    This is not a general instruction decoder or an executable code generator.
    """
    assert 0 < len(code) <= 512 and 0 < base < (1 << 47)
    literals = {0:'f30f1efa',1:'cc',2:'83ff04',4:'4885f6',6:'4885d2',
        8:'833e04',10:'837e0802',12:'4883bac800000006',14:'4c8b82a8000000',
        15:'4c394610',18:'4d85c9',21:'4885c9',23:'4883f957',25:'4d3901',
        27:'4983c110',28:'48ffc9',31:'498b4108',32:'488982a8000000',33:'c3',
        34:'bf7c000000',35:'b8e7000000',36:'0f05',37:'0f0b',38:'48c7c00f000000',39:'0f05',40:'0f0b'}
    branches = {3:(0x75,34),5:(0x74,34),7:(0x74,34),9:(0x75,34),11:(0x75,34),
        13:(0x75,34),16:(0x75,34),19:(0x74,34),22:(0x74,34),24:(0x77,34),
        26:(0x74,31),29:(0x75,25),30:(0xeb,34)}
    cursor, insns, targets, globals_ = 0, [], {}, {}
    for i in range(41):
        start = cursor
        if i in literals:
            b = trace_hex(literals[i]); assert code[cursor:cursor+len(b)] == b; cursor += len(b)
        elif i in (17,20):
            prefix = trace_hex('4c8b0d' if i == 17 else '488b0d')
            assert code[cursor:cursor+3] == prefix and cursor+7 <= len(code)
            cursor += 7; globals_[i] = base+cursor+struct.unpack_from('<i', code, cursor-4)[0]
            assert 0 < globals_[i] < (1 << 47) and globals_[i] % 8 == 0
        else:
            opcode, target_index = branches[i]
            if code[cursor:cursor+1] == bytes([opcode]):
                assert cursor+2 <= len(code); cursor += 2
                displacement = struct.unpack_from('<b', code, cursor-1)[0]
            else:
                prefix = b'\xe9' if opcode == 0xeb else bytes([0x0f, opcode+0x10])
                assert code[cursor:cursor+len(prefix)] == prefix and cursor+len(prefix)+4 <= len(code)
                cursor += len(prefix)+4; displacement = struct.unpack_from('<i', code, cursor-4)[0]
            targets[i] = (base+cursor+displacement, target_index)
        insns.append((base+start, code[start:cursor]))
    assert cursor == len(code) and globals_[17] != globals_[20]
    for destination, index in targets.values():
        assert destination == insns[index][0]
    return dict(instructions=insns, table_global=globals_[17], count_global=globals_[20],
                captured=insns[2][0], restorer=insns[38][0], syscall=insns[39][0])


def trace_hex(value):
    assert type(value) is str and re.fullmatch('(?:[0-9a-f]{2})*', value)
    return bytes.fromhex(value)


def trace_registers(value):
    b = trace_hex(value); assert len(b) == 216 and value == b.hex()
    return dict(zip(REGS, struct.unpack('<27Q', b)))


def register_equality(actual, expected):
    assert set(actual) == set(expected) == set(REGS)
    for k in REGS:
        mask = MASK ^ DEBUG if k == 'eflags' else MASK
        assert actual[k] & mask == expected[k] & mask, ('router register', k)


def router_mapping_rows(data, private, code_start, code_len, globals_, added):
    assert 0 < len(data) <= MIB and data.endswith(b'\n')
    rows = [line.split() for line in data.decode().splitlines()]
    spans = [(int(r[0].split('-')[0],16), int(r[0].split('-')[1],16), r) for r in rows]
    assert all(a < b and (i == 0 or spans[i-1][1] <= a) for i,(a,b,_) in enumerate(spans))
    guard, table = private
    owned = [(guard,guard+4096,'---p'),(guard+4096,guard+135168,'rw-p'),
             (guard+135168,guard+139264,'---p'),(table,table+4096,'r--p')]
    forbidden = [(LO,HI),(A-4096,A+8192),(SS-4096,SE+4096)] + [(p,p+4096) for p,_ in added]
    assert guard % 4096 == table % 4096 == 0
    assert all(0 < a < b < (1 << 47) for a,b,_ in owned)
    assert table+4096 <= guard or guard+139264 <= table
    assert all(b <= x or y <= a for a,b,_ in owned for x,y in forbidden)
    matched = []
    def one(a,b):
        got = [r for lo,hi,r in spans if lo <= a and b <= hi]; assert len(got) == 1
        return got[0]
    for a,b,permission in owned:
        for p in range(a,b,4096):
            row = one(p,p+4096)
            assert len(row) == 5 and row[1:] == [permission,'00000000','00:00','0']
            matched.append(row)
    for page in range(code_start & ~4095, (code_start+code_len+4095)&~4095, 4096):
        row = one(page,page+4096); assert row[1] == 'r-xp'; matched.append(row)
    for address in globals_:
        row = one(address,address+8); assert row[1][0] == 'r'; matched.append(row)
    return matched


def router_trace(data, routes, walk, trap, body, finish, operation, before, components, map_bytes, added):
    """Whole ordered trace, including all actual delivery and return observations."""
    rows = tab(data); cursor = 0
    def take(name, length):
        nonlocal cursor
        row = rows[cursor]; cursor += 1
        assert len(row) == length and row[0] == name, ('router trace row', name, row)
        return row
    assert rows[0] == ['phase','before_pc','after_pc','bytes']; cursor += 1
    assert take('router_bootstrap',2)[1] == ROUTERS[1]
    st = take('router_stack',4); guard, usable, size = map(num,st[1:])
    assert usable == guard+4096 and size == 131072
    tr = take('router_table',4); table, table_len = map(num,tr[1:3]); table_bytes = trace_hex(tr[3])
    expected_table = b''.join(struct.pack('<QQ',r['pc'],r['target']) for r in routes)
    expected_table += bytes(4096-len(expected_table))
    assert 1 <= len(routes) <= 87 and table_len == 4096 and table_bytes == expected_table
    action = take('router_action',5); handler, flags, restorer, mask = map(num,action[1:])
    assert flags == 0x0c000004 and mask == 0
    prior_mask = num(take('router_mask',2)[1]); assert prior_mask & 8 == 0
    code = trace_hex(take('router_code',2)[1]); program = router_code(code,handler)
    assert restorer == program['restorer']
    prior = take('router_prior',2)[1]
    match = re.fullmatch(r'Action \{ handler: 0, flags: ([0-9]+), restorer: ([0-9]+), mask: ([0-9]+) \}',prior)
    assert match and all(0 <= int(n) <= MASK for n in match.groups())
    assert take('router_scope',2)[1] == 'controlled_single_thread_child_only'
    assert take('router-layout',7)[1:] == ['128','968','16','40','224','296']
    def observed(phase):
        r = take('router-observed',6)
        assert r[1] == phase and trace_hex(r[2]) == expected_table and trace_hex(r[3]) == code
        assert num(r[4]) == table and num(r[5]) == len(routes)
    observed('before')
    mapping = [router_mapping_rows(b,(guard,table),handler,len(code),
               (program['table_global'],program['count_global']),added) for b in map_bytes]
    assert len(mapping) == 3 and mapping[0] == mapping[1] == mapping[2]
    contains = lambda address,length: usable <= address and length > 0 and address+length <= usable+size
    charged = 0
    for index,(pc,dest,fetch) in enumerate(walk):
        if trap and index == 0:
            route_index = [r['pc'] for r in routes].index(pc); route = routes[route_index]
            assert route['target'] == dest and route['fetch'] == fetch and before['r']['rip'] == pc
            assert take('router-fault',4)[1:] == ['4','2',str(pc)]
            entry = take('router-entry',6)
            entered_row = take('router-entry-state',3); assert num(entered_row[1]) == (5 << 8) | 0x7f
            entered = trace_registers(entered_row[2])
            assert entry[1:] == [str(entered[k]) for k in ('rip','rsp','rsi','rdx')] + ['128']
            assert entered['rip'] == program['captured'] and entered['rdi'] == 4
            assert contains(entered['rsp'],8) and contains(entered['rsi'],128) and contains(entered['rdx'],968)
            assert all(entered[k] == before['r'][k] for k in INHERITED)
            # Linux x86 signal_64 setup_rt_frame clears AX and changes only
            # the handler arguments/stack/IP; handle_signal clears DF/RF/TF.
            # The existing DEBUG mask remains the sole flag comparison mask.
            register_equality(entered,dict(before['r'],rax=0,rdi=4,rsi=entered['rsi'],
                rdx=entered['rdx'],rsp=entered['rsp'],rip=program['captured'],
                eflags=before['r']['eflags'] & ~(0x400 | DEBUG)))
            # Independently execute the fixed branch decisions: validation is
            # successful, then exactly route_index mismatches and one match.
            order = list(range(2,25))
            for _ in range(route_index): order += [25,26,27,28,29]
            order += [25,26,31,32,33]
            insns = program['instructions']
            assert len(order) <= 458
            for j, inst in enumerate(order):
                p,b = insns[inst]; nxt = insns[order[j+1]][0] if j+1 < len(order) else restorer
                assert take('router-step',4)[1:] == [str(p),str(nxt),b.hex()]
            rr = take('router-restorer',5); pre,post = trace_registers(rr[1]),trace_registers(rr[2])
            expected = dict(entered,r8=pc,r9=table+16*route_index,rcx=len(routes)-route_index,
                            rax=dest,rsp=entered['rsp']+8,rip=restorer,
                            eflags=(entered['eflags'] & ~0x8d5) | 0x44)
            register_equality(pre,expected)
            register_equality(post,dict(pre,rax=15,rip=program['syscall']))
            assert trace_hex(rr[3]) == insns[38][1]
            info = trace_hex(rr[4]); assert len(info) == 128
            assert struct.unpack_from('<iii',info) == (5,0,2)
            assert struct.unpack_from('<Q',info,16)[0] == program['syscall']
            se = take('router-syscall-entry',3); sx = take('router-syscall-exit',3)
            assert num(se[1]) == num(sx[1]) == ((5 | 128) << 8) | 0x7f
            entry_regs,exit_regs = trace_registers(se[2]),trace_registers(sx[2])
            # get_flags hides precisely TIF_FORCED_TF; PTRACE_SYSCALL's
            # user_disable_single_step clears precisely that TF before resume.
            # SYSCALL then clears RF and copies the exact remaining flags to
            # R11. This is a derived value, not an R11/debug-bit exemption.
            expected_entry = dict(post,orig_rax=15,rax=MASK-37,rip=program['syscall']+2,
                                  rcx=program['syscall']+2,r11=post['eflags'] & ~(1 << 16))
            register_equality(entry_regs,expected_entry)
            register_equality(exit_regs,dict(before['r'],rip=dest))
            assert take('router',4)[1:] == [str(pc),str(dest),fetch.hex()]
            frame_row = take('router-frame',6)
            assert num(frame_row[1]) == entered['rdx']
            signal_info,frame,changed,fp = (trace_hex(v) for v in frame_row[2:])
            assert len(signal_info) == 128 and len(frame) == len(changed) == 968
            assert struct.unpack_from('<iii',signal_info) == (4,0,2)
            assert struct.unpack_from('<Q',signal_info,16)[0] == pc
            assert struct.unpack_from('<Q',frame,16)[0] == usable
            assert struct.unpack_from('<i',frame,24)[0] == 0 and struct.unpack_from('<Q',frame,32)[0] == size
            assert struct.unpack_from('<Q',frame,296)[0] == prior_mask
            greg_names = 'r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx rsp rip eflags'.split()
            for j,name in enumerate(greg_names):
                actual = struct.unpack_from('<Q',frame,40+8*j)[0]
                mask_ = MASK ^ DEBUG if name == 'eflags' else MASK
                assert actual & mask_ == before['r'][name] & mask_, ('saved ucontext',name)
            assert struct.unpack_from('<Q',frame,200)[0] == 6
            expected_frame = bytearray(frame); expected_frame[168:176] = struct.pack('<Q',dest)
            assert changed == expected_frame
            fp_address = struct.unpack_from('<Q',frame,224)[0]
            assert 580 <= len(fp) <= 65536 and contains(fp_address,len(fp))
            magic,extended = struct.unpack_from('<II',fp,464)
            xstate_size = struct.unpack_from('<I',fp,480)[0]
            assert magic == 0x46505853 and extended == len(fp) and 576 <= xstate_size <= extended-4
            assert struct.unpack_from('<I',fp,len(fp)-4)[0] == 0x46505845
            assert canonical(fp,components) == signal_frame_expected(before['canonical'],fp,components)
            after_fp = take('router-fp-after',3)
            assert num(after_fp[1]) == fp_address and trace_hex(after_fp[2]) == fp
            assert take('trap-prefix',4)[1:] == [str(pc),str(dest),fetch.hex()]
            charged += len(order)+5
        else:
            assert take('prefix',4)[1:] == [str(pc),str(dest),fetch.hex()]
            charged += 1
    assert take('original',4)[1:] == [str(body),str(finish),operation.hex()]
    observed('after'); assert cursor == len(rows)
    base_bytes = len(tsv([['phase','before_pc','after_pc','bytes']] +
        [['prefix',p,n,b.hex()] for p,n,b in walk] + [['original',body,finish,operation.hex()]]))
    assert len(data) <= base_bytes+MIB and charged+1 <= 20000
    return charged+1


def sha(b):
    return hashlib.sha256(b).hexdigest()


def loads(b):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            assert k not in out, ('duplicate key', k)
            out[k] = v
        return out
    def bad(v):
        raise ValueError(('nonfinite JSON', v))
    return json.loads(b, object_pairs_hook=unique, parse_constant=bad)


def six(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read_file(value):
    p = Path(value)
    assert p.is_absolute() and str(p) == value and '..' not in p.parts
    assert p.parent.resolve(strict=True) == p.parent
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        a = os.fstat(f.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= 128 * MIB
        b = f.read(a.st_size + 1)
        assert six(a) == six(os.fstat(f.fileno())) == six(p.lstat()) and len(b) == a.st_size
    return b, dict(path=value, resolved=value, sha256=sha(b), stat=six(a))


class Saved:
    def __init__(self, pins, repo):
        self.pins, self.repo, self.seen = pins, Path(repo), {}
        assert self.repo.is_absolute() and self.repo.resolve(strict=True) == self.repo
    def read(self, value):
        value = str(value)
        assert value in self.pins and not Path(value).is_relative_to(self.repo / 'target')
        b, owner = read_file(value)
        assert self.pins[value] == dict(sha256=owner['sha256'], bytes=len(b), stat=owner['stat']), ('pin/owner', value)
        if value in self.seen:
            assert self.seen[value] == owner, ('drift', value)
        self.seen[value] = owner
        return b
    def json(self, p):
        return loads(self.read(p))
    def stable(self):
        for p in sorted(self.seen):
            self.read(p)


def tab(b):
    assert b.endswith(b'\n') and b'\r' not in b and b'\0' not in b
    return [r.split('\t') for r in b.decode('ascii').splitlines()]


def kv(b):
    result = {}
    for row in tab(b):
        assert len(row) == 2 and row[0] not in result
        result[row[0]] = row[1]
    return result


def tsv(rows):
    return ''.join('\t'.join(map(str, row)) + '\n' for row in rows).encode()


def num(s):
    assert re.fullmatch('[0-9]+', s)
    n = int(s); assert 0 <= n <= MASK
    return n


def names():
    out = ['original.elf', 'instructions.tsv', 'runtime-target.tsv', 'core-witness.tsv', 'original-pages.bin',
           'bundle-inputs.tsv', 'input-owners.tsv', 'candidate-pages.bin', 'page-plan.tsv', 'planned-cases.tsv', 'capture-inventory.tsv', 'complete.tsv']
    suffix = ['regs', 'xstate', 'xstate-raw', 'data', 'stack', 'stack-owned', 'loads', 'maps']
    for i in range(176):
        c = f'case-{i:03}/'
        out += [c + n for n in ('pair.tsv', 'witness.tsv')]
        out += [c + 'original/' + n for n in ('seed.tsv', 'complete.tsv')]
        out += [c + f'original/{s}.{x}' for s in ('before', 'after') for x in suffix]
        out += [c + 'candidate/' + n for n in ('trace.tsv', 'complete.tsv')]
        out += [c + f'candidate/{s}.{x}' for s in ('before', 'restored', 'after') for x in suffix + ['generated']]
    assert len(out) == len(set(out)) == 8636
    return out


def tree(root):
    files, dirs = set(), set()
    assert root.resolve(strict=True) == root
    for current, children, members in os.walk(root, followlinks=False):
        for n in children + members:
            assert not (Path(current) / n).is_symlink()
        dirs |= {str((Path(current) / n).relative_to(root)) for n in children}
        files |= {str((Path(current) / n).relative_to(root)) for n in members}
    return files, dirs


def indexed(saved, root, index):
    for name, row in index.items():
        p = Path(name)
        assert not p.is_absolute() and '..' not in p.parts and str(p) == name
        b = saved.read(root / name)
        assert row == dict(sha256=sha(b), bytes=len(b), stat=saved.seen[str(root / name)]['stat'])


def image(data):
    assert len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', data, 16) == (2, 62, 1)
    assert struct.unpack_from('<HH', data, 52) == (64, 56)
    off, count = struct.unpack_from('<Q', data, 32)[0], struct.unpack_from('<H', data, 56)[0]
    assert 1 <= count <= 512 and off + count * 56 <= len(data)
    loads_, pages = [], {}
    for i in range(count):
        kind, flags, offset, va, _, fs, ms, align = struct.unpack_from('<IIQQQQQQ', data, off + i * 56)
        assert offset + fs <= len(data)
        if kind != 1:
            continue
        assert flags in (4, 5, 6) and 0 < ms and fs <= ms and align == 4096 and offset % 4096 == va % 4096
        lo, hi = va & ~4095, (va + ms + 4095) & ~4095
        assert 0 < lo < hi <= 1 << 47 and hi - lo <= 2048 * 4096
        loads_.append((offset, va, fs, ms, flags))
        for page in range(lo, hi, 4096):
            assert page not in pages
            at = (offset & ~4095) + page - lo; b = bytearray(4096)
            if page < (va + fs + 4095) & ~4095:
                n = min(4096, max(0, len(data) - at)); b[:n] = data[at:at+n]
            if ms > fs and page + 4096 > va + fs:
                start = max(0, va + fs - page); b[start:] = bytes(4096 - start)
            pages[page] = (flags, bytes(b))
    original_addresses = {row[1] for row in LOADS}
    assert [row for row in loads_ if row[1] in original_addresses] == LOADS
    assert set(range(LO, HI, 4096)) <= pages.keys()
    assert len(loads_) <= 261 and len(pages) <= 37 + 2048 and max(pages) + 4096 - min(pages) <= 1073741824
    assert all(flags != 6 for p, (flags, _) in pages.items() if not LO <= p < HI)
    base = b''.join(pages[p][1] for p in range(LO, HI, 4096))
    return loads_, pages, base


def at(pages, pc, length):
    out = bytearray()
    for a in range(pc, pc + length):
        flags, b = pages[a & ~4095]; assert flags == 5
        out.append(b[a & 4095])
    return bytes(out)


def target(b):
    rows = tab(b); assert rows[:2] == [['LI2TARGET', '1'], ['os', 'linux']]
    fixed = dict(isa='x86-64-legacy-evex', cet='unqualified', page_bytes='4096', bias_domain='1',
                 format='xsave64-standard', allocation_bytes='2496', image_bytes='2440', xcr0_mask='743', qualification_complete='false')
    assert rows[2:11] == [[k, v] for k, v in fixed.items()]
    components = [(4, 576, 256), (32, 832, 64), (64, 896, 512), (128, 1408, 1024), (512, 2432, 8)]
    assert rows[11:] == [['component', *map(str, r)] for r in components]
    return [(mask.bit_length() - 1, off, size) for mask, off, size in components]


def canonical(raw, components):
    assert 2440 <= len(raw) <= 65536 and raw[520:528] == bytes(8)
    used = struct.unpack_from('<Q', raw, 512)[0]
    x87 = raw[:24] if used & 1 else b'\x7f\x03' + bytes(22)
    out = x87[:5] + x87[6:24]
    out += b''.join(raw[32+16*i:42+16*i] if used & 1 else bytes(10) for i in range(8))
    out += raw[24:28] + (raw[160:416] if used & 2 else bytes(256))
    for bit, off, size in components:
        assert off >= 576 and off + size <= len(raw)
        out += struct.pack('<IQ', bit, size) + (raw[off:off+size] if used & (1 << bit) else bytes(size))
    assert len(out) == 2287
    return out


def signal_frame_expected(expected, frame, components):
    """Exact supported Linux signal-frame representation, not a PKRU exemption.

    Component 9 is a 32-bit PKRU plus four padding bytes (Linux v6.12
    asm/fpu/types.h). update_pkru_in_sigframe writes only unsigned int.
    This router initializes every alternate-stack byte to 0xa6. Require
    that exact saved padding, and still compare all 32 architectural bits.
    Ptrace canonicalization and full before/after frame equality stay intact.
    """
    assert components == [(2,576,256),(5,832,64),(6,896,512),(7,1408,1024),(9,2432,8)]
    assert len(expected) == 2287 and expected[-20:-8] == struct.pack('<IQ',9,8)
    assert expected[-4:] == bytes(4)
    assert len(frame) >= 2440 and struct.unpack_from('<Q',frame,512)[0] & (1 << 9)
    assert frame[2436:2440] == b'\xa6' * 4
    return expected[:-4] + b'\xa6' * 4


def seeded_xstate(seed, components):
    b = bytearray(2440); b[:2] = b'\x7f\x03'; b[4] = 255; b[24:28] = struct.pack('<I', 0x1f80)
    for i in range(8):
        b[32+16*i:40+16*i] = struct.pack('<Q', 0x8000000000000000 | seed | i)
        b[40+16*i:42+16*i] = b'\xff\x3f'
    b[160:416] = bytes((i * 29 + seed) & 255 for i in range(256))
    used = 3
    for bit, off, size in components:
        if bit in (2, 5, 6, 7):
            b[off:off+size] = bytes((i * 17 + seed + bit) & 255 for i in range(size)); used |= 1 << bit
    b[512:520] = struct.pack('<Q', used)
    return canonical(b, components)


def seed_case(i, heads):
    fault, hindex, state = i >= 174, (0 if i >= 174 else i // 2), i & 1
    h = heads[hindex]; seed = SEEDS[state]; array = ((13, 5, 21, 8), (7, 19, 3, 29))[state]
    r, value = {}, seed
    for reg in 'rax rbx rcx rdx rbp r8 r9 r10 r11 r12 r13 r14 r15'.split():
        value ^= (value << 13) & MASK; value ^= value >> 7; value ^= (value << 17) & MASK; r[reg] = value
    r.update(rsi=A+512, rdi=A, rsp=E+h['depth'], rip=h['pc'], eflags=(0x202, 0xad7)[state], orig_rax=MASK)
    saved = r.copy()
    overrides = {
        0x401840:dict(rdi=A,rsi=(1,3)[state],rdx=(0x1122334455667788,0x8877665544332211)[state]),
        0x401854:dict(rdi=A),0x401859:dict(rsi=4),0x401860:dict(rsi=4),0x40185c:dict(r12=4),0x401863:dict(rdx=0),
        0x401867:dict(rdx=0,r12=2),0x40186e:dict(r13=A,rbp=4,r12=2,rsi=0,rbx=1,rdx=array[1],r14=array[0]),
        0x401870:dict(r13=A),0x40187e:dict(r13=A),0x401873:dict(rdi=A,rsi=0,rdx=array[1]),0x401878:dict(r14=array[0]),
        0x40187b:dict(rbx=1),0x40188b:dict(rbx=1),0x401881:dict(rdi=A,rsi=1,rdx=array[0]),0x401886:dict(rbx=1,r12=2),
        0x40188e:dict(rsi=0),0x401892:dict(rsi=0),0x401896:dict(rax=0),0x40189a:dict(rax=0),0x40189e:dict(r13=A,rbx=1),
        0x4018a3:dict(rax=2,rbp=4),0x4018a8:dict(rcx=1),0x4018ac:dict(r13=A,rcx=16),0x4018b1:dict(rcx=array[2],rdx=array[1]),
        0x4018b6:dict(rcx=array[2]),0x4018b9:dict(rax=2),0x4018bc:dict(r13=A,rsi=0),0x4018c1:dict(r14=array[0],rdx=array[1]),
        0x4018d0:dict(rsi=4),0x4018d8:dict(rsi=4),0x4018e3:dict(rsi=4),0x4018dc:dict(r12=4),0x4018df:dict(rdi=A),
        0x4018e6:dict(rbp=A,rbx=4,r12=2),0x401907:dict(rbp=A,rbx=4,r12=2),0x4018f0:dict(r12=2),0x4018f4:dict(rbx=4),
        0x4018f7:dict(rbp=A),0x40191f:dict(rbp=A),0x40192d:dict(rbp=A),0x40193a:dict(rbp=A),0x4018fa:dict(r12=1),
        0x401902:dict(r12=1),0x4018fd:dict(rdi=A,rsi=4,rdx=1),0x401910:dict(rbp=A,rbx=4),0x401915:dict(rbp=A),
        0x40191b:dict(rbx=4),0x401922:dict(rdi=A,rsi=0,rdx=array[3]),0x401927:dict(r12=array[0]),0x40192a:dict(rbx=3),
        0x401937:dict(rbx=3),0x401942:dict(rbx=3),0x401930:dict(rdi=A,rsi=3,rdx=array[0]),0x40193d:dict(rdi=A,rsi=3,rdx=0),
    }
    r.update(overrides.get(h['pc'], {}))
    data = bytearray((n * 37 + (seed & 255)) & 255 for n in range(4096)); data[:32] = struct.pack('<4Q', *array)
    stack = bytearray((n * 29 + (seed & 255)) & 255 for n in range(65536))
    slots = {'Store':(), 'Sift':((-40,'rbx'),(-32,'rbp'),(-24,'r12'),(-16,'r13'),(-8,'r14')), 'Heap':((-24,'rbx'),(-16,'rbp'),(-8,'r12'))}
    for off, reg in slots[h['function']]:
        struct.pack_into('<Q', stack, E+off-SS, saved[reg])
    struct.pack_into('<Q', stack, E-SS, 0x401878)
    memory, effect, rsp = h['memory'], None, r['rsp']; kind = memory['kind']
    if kind == 'ArrayLoad':
        addr = r[memory['base']] + (r[memory['index']] if memory['index'] else 0) * memory['scale'] + memory['displacement']
        assert A <= addr and addr+8 <= A+32
        effect = ('Read', 'Array', addr, bytes(data[addr-A:addr-A+8]))
    elif kind == 'ArrayStore':
        addr = r['rdi'] + 8*r['rsi']; assert A <= addr and addr+8 <= A+32
        effect = ('FaultingWrite' if fault else 'Write', 'Array', addr, struct.pack('<Q', r['rdx']))
    elif kind in ('Push', 'Call'):
        rsp -= 8; value = r[memory['reg']] if kind == 'Push' else h['pc'] + h['length']
        effect = ('Write', 'Stack', rsp, struct.pack('<Q', value))
    elif kind in ('Pop', 'Return'):
        effect = ('Read', 'Stack', rsp, bytes(stack[rsp-SS:rsp-SS+8])); rsp += 8
    else:
        assert kind == 'None'
    if effect and effect[1] == 'Stack':
        assert E-128 <= effect[2] and effect[2]+8 <= E+8
    flow, cf, zf = h['flow'], bool(r['eflags'] & 1), bool(r['eflags'] & 64)
    pc = h['pc'] + h['length']
    if flow in ('Call','Jump') or (flow=='Jb' and cf) or (flow=='Jae' and not cf) or (flow=='Jbe' and (cf or zf)) or (flow=='Jne' and not zf):
        pc = h['target']
    if flow == 'Return':
        pc = struct.unpack('<Q', effect[3])[0]
    if fault:
        pc, rsp = h['pc'], r['rsp']
    assert pc in {h['pc'] for h in heads}
    after_data, after_stack = data.copy(), stack.copy()
    if effect and effect[0] == 'Write':
        buf, base = (after_data,A) if effect[1]=='Array' else (after_stack,SS)
        buf[effect[2]-base:effect[2]-base+8] = effect[3]
    fault_text = f'Some((11, 2, {effect[2]}))' if fault else 'None'
    effect_text = 'None' if not effect else f'Some(MemoryEffect {{ access: {effect[0]}, domain: {effect[1]}, address: {effect[2]}, bytes: {list(effect[3])} }})'
    completion = f'Fault {{ pc: {pc}, rsp: {rsp}, signal: 11, code: 2, address: {effect[2]} }}' if fault else f'OriginalPc {{ pc: {pc}, rsp: {rsp} }}'
    seed_rows = [('case',i),('head',hindex),('state',state),('seed',seed),('pc',h['pc']),('rsp',r['rsp']),('rflags',r['eflags']),('array',A),('frame',E),('stack_start',SS),('stack_end',SE),('comparison_start',E-128),('effect',effect_text),('completion',completion)]
    return dict(index=i,head=hindex,state=state,seed=seed,registers=r,data=bytes(data),stack=bytes(stack),after_data=bytes(after_data),after_stack=bytes(after_stack),pc=pc,rsp=rsp,fault=fault,fault_text=fault_text,seed_tsv=tsv(seed_rows))


def maps(b, fault, added):
    assert 0 < len(b) <= MIB and b.endswith(b'\n')
    rows = []
    for line in b.decode().splitlines():
        f = line.split(); assert len(f) >= 5
        lo, hi = (int(s,16) for s in f[0].split('-'))
        assert lo < hi and re.fullmatch('[r-][w-][x-][ps]',f[1])
        assert re.fullmatch('[0-9a-f]+:[0-9a-f]+',f[3]) and f[4].isdigit()
        assert not rows or rows[-1][1] <= lo
        rows.append((lo,hi,f))
    expected = [(va & ~4095,(va+ms+4095)&~4095,{4:'r--p',5:'r-xp',6:'rw-p'}[flags]) for _,va,_,ms,flags in LOADS]
    expected += [(A,A+4096,'r--p' if fault else 'rw-p'),(SS,SE,'rw-p'),(A-4096,A,'---p'),(A+4096,A+8192,'---p'),(SS-4096,SS,'---p'),(SE,SE+4096,'---p')]
    expected += [(p,p+4096,'r-xp' if flag==5 else 'r--p') for p,flag in added]
    for lo,hi,permission in expected:
        for p in range(lo,hi,4096):
            matches = [f for a,z,f in rows if a <= p and p+4096 <= z]
            assert len(matches)==1
            f=matches[0]; assert len(f)==5 and f[1]==permission and int(f[2],16)==0 and f[3:] == ['00:00','0']


def state(saved, root, stem, physical, logical, spec, components, base, generated, added):
    b = {n:saved.read(root/(stem+'.'+n)) for n in ('regs','xstate','xstate-raw','data','stack','stack-owned','loads','maps')}
    assert len(b['regs'])==216 and len(b['data'])==4096 and len(b['stack'])==32888 and len(b['stack-owned'])==65536
    r=dict(zip(REGS,struct.unpack('<27Q',b['regs']))); assert r['rip']==physical
    assert b['xstate']==canonical(b['xstate-raw'],components)
    assert b['stack']==b['stack-owned'][E-128-SS:] and b['loads']==base
    maps(b['maps'],spec['fault'],added)
    if generated is not None:
        assert saved.read(root/(stem+'.generated'))==generated
    return dict(r=r,logical=logical,canonical=b['xstate'],raw=b['xstate-raw'],data=b['data'],fixed=b['stack'],stack=b['stack-owned'])


def compare(a,b):
    assert a['logical']==b['logical']
    for reg in REGS:
        if reg=='rip':
            continue  # Physical RIP has already matched its exact predeclared boundary.
        mask=MASK ^ DEBUG if reg=='eflags' else MASK
        assert a['r'][reg]&mask==b['r'][reg]&mask, (reg,a['logical'])
    for k in ('canonical','data','fixed'):
        assert a[k]==b[k], (k,a['logical'])


def outside(a,b,scratch):
    assert len(a)==len(b)==65536
    if scratch is None:
        assert a==b
    else:
        start,end=scratch; assert SS<=start<end<=E-128
        assert a[:start-SS]==b[:start-SS] and a[end-SS:]==b[end-SS:]


def case(saved,captures,i,heads,witness,components,original_base,candidate_base,generated,added,context,router=None):
    spec=seed_case(i,heads); h=heads[spec['head']]; w=witness[spec['head']]; d=captures/f'case-{i:03}'
    fault=spec['fault']; pc=spec['pc']
    finish=w['body'] if fault else (w['body']+len(w['bytes']) if h['flow']=='Next' else pc if h['flow']=='Return' else w['target'] if h['flow'] in ('Call','Jump') or pc==h['target'] else w['body']+len(w['bytes']))
    assert saved.read(d/'original/seed.tsv')==spec['seed_tsv']
    assert saved.read(d/'witness.tsv')==tsv([('original',h['pc']),('body',w['body']),('completion',finish),('logical',pc),('bytes',w['bytes'].hex())])
    ob=state(saved,d/'original','before',h['pc'],h['pc'],spec,components,original_base,None,[])
    oa=state(saved,d/'original','after',pc,pc,spec,components,original_base,None,[])
    cb=state(saved,d/'candidate','before',h['pc'],h['pc'],spec,components,candidate_base,generated,added)
    after_base=candidate_base
    if RECORDING:
        after_base=recording.journal_after(candidate_base,w['journal_at'],h['pc'] if any(p==recording.CORE_HOOK for p,_,_ in w['walk']) else None)
    cr=state(saved,d/'candidate','restored',w['body'],h['pc'],spec,components,after_base,generated,added)
    ca=state(saved,d/'candidate','after',finish,pc,spec,components,after_base,generated,added)
    for reg,value in spec['registers'].items():
        mask=MASK ^ DEBUG if reg=='eflags' else MASK
        assert ob['r'][reg]&mask==value&mask
    inherited=[ob['r'][r] for r in INHERITED]
    if not context:
        context.extend([inherited,len(ob['raw'])])
    assert context==[inherited,len(ob['raw'])]
    for s in (ob,oa,cb,cr,ca):
        assert [s['r'][r] for r in INHERITED]==inherited and len(s['raw'])==context[1]
    assert ob['canonical']==seeded_xstate(spec['seed'],components)==oa['canonical']
    assert ob['data']==spec['data'] and ob['stack']==cb['stack']==spec['stack']
    assert oa['data']==spec['after_data'] and oa['stack']==spec['after_stack'] and oa['r']['rsp']==spec['rsp']
    compare(ob,cb); compare(ob,cr); compare(oa,ca)
    scratch=None
    if any(n==(recording.CORE_HOOK if RECORDING else HOOK) for _,n,_ in w['walk']):
        s=spec['registers']['rsp']; scratch=(((s-304)&~63)-2496-8,s-128)
    outside(cr['stack'],ob['stack'],scratch); outside(ca['stack'],oa['stack'],scratch)
    if fault:
        compare(ob,oa); compare(cr,ca)
    trace=[['phase','before_pc','after_pc','bytes']]+[['prefix',p,n,b.hex()] for p,n,b in w['walk']]+[['original',w['body'],finish,w['bytes'].hex()]]
    if RECORDING:
        trace_bytes,extra_steps=recording.core_trace(saved.read(d/'candidate/trace.tsv'),w['walk'],h['pc'])
        if not router:
            assert trace_bytes==tsv(trace)
            steps=len(w['walk'])+1+extra_steps
        else:
            steps=router_trace(trace_bytes,router,w['walk'],w['trap'],w['body'],finish,w['bytes'],cb,components,
                               [saved.read(d/'candidate'/(s+'.maps')) for s in ('before','restored','after')],added)+extra_steps
        assert steps<=20000
    else:
        if not router:
            assert saved.read(d/'candidate/trace.tsv')==tsv(trace) and len(w['walk'])+1<=20000
        else:
            steps=router_trace(saved.read(d/'candidate/trace.tsv'),router,w['walk'],w['trap'],w['body'],finish,w['bytes'],cb,components,
                               [saved.read(d/'candidate'/(s+'.maps')) for s in ('before','restored','after')],added)
    assert saved.read(d/'original/complete.tsv')==tsv([('LI2ORIGINALREFERENCE',1),('case',i),('steps',1),('normal',str(not fault).lower()),('fault',spec['fault_text']),('reaped_echild','true'),('paired_replay','UNIMPLEMENTED_UNRUN'),('qualification_complete','false')])
    if not router and not RECORDING:
        assert saved.read(d/'candidate/complete.tsv')==tsv([('LI2COREPAIRCHILD',1),('case',i),('steps',len(w['walk'])+1),('physical_completion',finish),('logical_completion',pc),('fault',spec['fault_text']),('comparisons',3),('reaped_echild','true'),('qualification_complete','false')])
    else:
        assert saved.read(d/'candidate/complete.tsv')==tsv([('LI2COREPAIRCHILD',1),('case',i),('steps',steps),('physical_completion',finish),('logical_completion',pc),('fault',spec['fault_text']),('comparisons',3),('reaped_echild','true'),('qualification_complete','false')])
    assert saved.read(d/'pair.tsv')==tsv([('LI2COREPAIR',1),('case',i),('comparisons',3),('children',2),('E9','UNIMPLEMENTED_UNRUN'),('normal_loader_validation','false'),('qualification_complete','false')])
    return dict(status='PASS_SAVED_CONTENT',comparisons=3,head=spec['head'],state=spec['state'],fault=fault,physical_completion=finish,logical_completion=pc,helper_scratch=scratch)


def receipt(saved,d,request):
    r=saved.json(d/'receipt.json')
    assert set(r)=={'request_sha256','helper_sha256','exit','wall_timeout','unexpected_descendants','absence_proof','stdout_sha256','stderr_sha256','elapsed_seconds','cleanup_events','cleanup_error','aborted','inputs_unchanged'}
    assert type(r['exit']) is int and r['exit']==0 and r['request_sha256']==sha(saved.read(d/'request.json')) and r['helper_sha256']==HELPER_SHA
    assert r['wall_timeout'] is False and r['inputs_unchanged'] is True and r['absence_proof']=='ECHILD'
    assert r['unexpected_descendants']==r['cleanup_events']==[] and r['aborted'] is None and r['cleanup_error'] is None
    assert type(r['elapsed_seconds']) in (int,float) and math.isfinite(r['elapsed_seconds']) and 0<=r['elapsed_seconds']<=request['wall_seconds']
    for name in ('stdout','stderr'):
        b=saved.read(d/(name+'.txt'));assert sha(b)==r[name+'_sha256'] and len(b)<=request['file_bytes']
    return r


def audit(saved,envelope,heads,pins,report,profile=None):
    run=Path(envelope['run']); cap=run/'captures'
    assert run.is_relative_to(saved.repo/'ignored')
    inputs=saved.json(run/'inputs.json'); source=saved.json(run/'source.json'); summary=saved.json(run/'summary.json')
    if profile is None:
        assert source['revision']==summary['revision']==REVISION and summary['recipe_sha256']==RUNNER_SHA and summary['cell'] in CELLS
    else:
        assert source['revision']==summary['revision']==profile['epoch']['revision'] and summary['recipe_sha256']==PROFILE_RUNNER_SHA and summary['cell'] in CELLS
        profile_records(saved,envelope,inputs,source,summary,profile)
    assert summary['command_capture_schema_complete'] is True and summary['selected_owners_unchanged'] is True and summary['fatal'] is None
    for k,v in dict(cases=176,normal_cases=174,fault_cases=2,heads=87,planned_children=352,planned_comparisons=528,capture_files=8636,qualification_complete=False,full_a3=False,normal_loader_validation=False,independent_content_review_required=True).items():
        assert summary[k]==v
    assert set(envelope['sources'])==set(pins)
    for name,digest in pins.items():
        assert sha(saved.read(envelope['sources'][name]))==source['files'][name]['sha256']==digest
    assert saved.json(inputs['source_epoch'])==source
    for p,owner in inputs['files'].items():
        saved.read(p); assert saved.pins[p]==owner
    if profile is None:
        assert any(row['sha256']==RUNNER_SHA for row in inputs['files'].values())
    else:
        assert any(row['sha256']==PROFILE_RUNNER_SHA for row in inputs['files'].values())
    evidence=envelope['evidence']
    assert set(evidence)=={'source_review','build_review','verifier_review','runner_review','parent_closure'}
    for key,values in evidence.items():
        assert type(values) is list and values and len(values)==len(set(values))
        for p in values:
            saved.read(p)
    assert len(evidence['parent_closure'])==1
    parent=saved.json(evidence['parent_closure'][0]); assert type(parent['exit']) is int and parent['exit']==0 and parent['parent_wait_returned'] is True
    # The pinned envelope is caller authority for these already reviewed joins;
    # bytes/hashes alone do not manufacture independent build/verifier approval.
    assert envelope['authority']=='CALLER_ADMITTED_CLOSED_CORE_PAIR_CAPTURE'
    rawindex=saved.json(run/'raw-files.json'); indexed(saved,run,rawindex)
    assert tree(run)[0]==set(rawindex)|{'raw-files.json'}
    captureindex=saved.json(run/'capture-files.json'); assert set(captureindex)==set(names())
    assert {k[9:]:v for k,v in rawindex.items() if k.startswith('captures/')}==captureindex
    assert tree(cap)==(set(names()),{str(p) for n in names() for p in Path(n).parents if str(p)!='.'})
    assert saved.read(cap/'capture-inventory.tsv')==saved.read(run/'expected-captures.tsv')==(''.join(n+'\n' for n in names())).encode()
    assert saved.read(cap/'complete.tsv')==COMPLETE
    previous={}
    for p in [run/'before.json',run/'verify/before.json',run/'verify/after.json',run/'replay/before.json',run/'replay/after.json',run/'after.json']:
        snap=saved.json(p); assert snap['source']==source
        if previous:
            assert all(snap['owners'][k]==v for k,v in previous['owners'].items())
            assert {k:v for k,v in snap.items() if k!='owners'}=={k:v for k,v in previous.items() if k!='owners'}
        for path,row in snap['owners'].items():
            saved.read(path);assert saved.seen[path]==row
        previous=snap
    results=saved.json(run/'results.json'); assert [r['name'] for r in results]==['verify','replay']
    assert saved.json(run/'stage-inventory.json')==['verify','replay']
    requests=[]
    for i,name in enumerate(('verify','replay')):
        d=run/name; q=saved.json(d/'request.json'); command=saved.json(d/'command.json'); rr=receipt(saved,d,q)
        cpu,wall,limit,outer,wait=(20,30,16*MIB,40,55) if i==0 else (60,90,64*MIB,100,115)
        assert set(q)=={'argv','cwd','env','cpu_seconds','wall_seconds','file_bytes','stdout','stderr'}
        assert q['cwd']==str(saved.repo) and q['env']==dict(ENV,TMPDIR=str(d/'tmp'))
        assert (q['cpu_seconds'],q['wall_seconds'],q['file_bytes'])==(cpu,wall,limit)
        assert q['stdout']==str(d/'stdout.txt') and q['stderr']==str(d/'stderr.txt')
        expected_outer=[inputs['tools']['timeout'],'--signal=TERM','--kill-after=10s',str(outer)+'s',inputs['tools']['helper_python'],'-B',str(saved.repo/'tools/unwind-oracle/bounded_command.py'),'--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')]
        assert command==dict(request=q,outer_argv=expected_outer,outer_env=ENV,cwd=str(saved.repo),parent_timeout_seconds=wait)
        o=saved.json(d/'outer.json');assert o['exit']==0 and o['parent_timeout'] is False and math.isfinite(o['operational_seconds']) and 0<=o['operational_seconds']<=wait
        assert saved.read(d/'stdout.txt')==(VERIFY_OUT if i==0 else PAIR_OUT) and not saved.read(d/'stderr.txt')
        terminal=dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True)
        assert saved.read(d/'helper.stdout')==(json.dumps(terminal)+'\n').encode() and not saved.read(d/'helper.stderr')
        row=saved.json(d/'result.json');assert row==results[i] and row['exit']==0 and row['strict_closure'] is True and row['launched'] is True and row['receipt_sha256']==sha(saved.read(d/'receipt.json'))
        assert row['status']==('PASS_STRUCTURAL_WITNESS' if i==0 else 'PASS_COMMAND_AND_CAPTURE_SCHEMA')
        requests.append(q)
    if profile is not None:
        suffix=profile_arguments(profile['profiles'])+([RECORDING_FLAG] if RECORDING else [])
        if suffix:
            for q in requests:
                assert q['argv'][-len(suffix):]==suffix
            requests=[dict(q,argv=q['argv'][:-len(suffix)]) for q in requests]
        else:
            assert VERIFIER_CAPABILITY==RECORDING_PROFILE and not RECORDING
            assert profile['profiles']==dict(planning_profile='legacy',entry_router='absent')
    v,r=(q['argv'] for q in requests);assert len(v)==7 and len(r)==8 and r[1]=='replay-common-core'
    assert v[1:4]==r[2:5] and v[5:]==r[5:7] and r[7]==str(cap) and r[6]==str(run/'core-witness.tsv')
    cell=saved.json(inputs['cell_admission']);verifier=saved.json(inputs['verifier_admission']);runtime=saved.json(inputs['runtime_admission'])
    build=saved.json(inputs['build_admission'])
    build_input_profile(build,Path(build['directory']),saved.read)
    same_build_profile(build,summary,cell,verifier)
    if 'build_profile' in build:
        assert verifier['scope']=='direct-rustc-canonical-input-epoch-dev-debug0-v1'
        debug0_build_profile(build,Path(build['directory']),saved.read)
        report['build_profile']=DEBUG0_BUILD_PROFILE
    else:
        assert verifier['scope']!='direct-rustc-canonical-input-epoch-dev-debug0-v1'
    if profile is None:
        assert cell['authority']=='CALLER_ADMITTED_CORE_NULL_PAIR_INPUTS' and cell['source_revision']==REVISION and cell['eligible'] is True
    else:
        if RECORDING:
            assert cell['authority']=='CALLER_ADMITTED_CORE_RECORDING_PAIR_INPUTS' and cell['scope']=='one-complete-core-recording-artifact' and cell['source_revision']==profile['epoch']['revision'] and cell['eligible'] is True
            assert cell['recording_profile']==verifier['recording_profile']==RECORDING_PROFILE
        else:
            assert cell['authority']=='CALLER_ADMITTED_CORE_NULL_PAIR_INPUTS' and cell['source_revision']==profile['epoch']['revision'] and cell['eligible'] is True
    assert cell['cell']==summary['cell'] and cell['bundle']==r[5] and cell['original']==r[2] and cell['inventory']==v[4] and cell['target']==r[4]
    assert r[3]==v[4]+'/instructions.tsv'
    verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING,cell)
    if VERIFIER_CAPABILITY!='legacy': assert verifier['recording_profile']==VERIFIER_CAPABILITY
    assert cell['driver_sha256']==sha(saved.read(r[0])) and cell['verifier_sha256']==sha(saved.read(v[0]))
    if profile is None:
        assert verifier['authority']=='CALLER_ADMITTED_COMMON_CORE_VERIFIER' and verifier['source_revision']==REVISION and verifier['verifier']==v[0]
    else:
        assert verifier['authority']=='CALLER_ADMITTED_COMMON_CORE_VERIFIER' and verifier['source_revision']==profile['epoch']['revision'] and verifier['verifier']==v[0]
    assert runtime['authority']=='CALLER_PINNED_PAIR_HOST_RUNTIME_EPOCH' and runtime['executables']==dict(driver=r[0],verifier=v[0])
    assert cell['production_admission_sha256']==sha(saved.read(inputs['production_admission']))
    assert saved.json(run/'obligations.json')==inputs['obligations']
    report['recorded_obligations']=inputs['obligations']
    report['recorded_production_status']=saved.json(run/'production-status.json')
    report['recorded_prior_cells']=saved.json(run/'prior-cells.json')
    if RECORDING:
        denominators=dict(original=16,production=74,ordinary=192,core_null=704,E9_null=1408,recording_pairs=2112)
        assert set(inputs['obligations'])==set(denominators)
        for name,count in denominators.items():
            item=inputs['obligations'][name]
            assert set(item)=={'denominator','status','record'} and item['denominator']==count
            assert item['status'] in ('UNRUN','FAILED','PARTIAL','CLOSED_REVIEWED')
            if item['record'] is None: assert item['status']=='UNRUN'
            else: saved.read(item['record'])
        ordinary=saved.json(inputs['obligations']['ordinary']['record'])
        assert ordinary['authority']=='CALLER_ADMITTED_COMMON_ORDINARY_CONTENT' and ordinary['source_revision']==source['revision']
        assert ordinary['scope']=='closed-192-case-output-and-journal-records' and ordinary['parent_closed_reaped'] is True
        observation=saved.json(inputs['observation_content_admission'])
        assert observation['authority']=='CALLER_ADMITTED_ORIGINAL_OBSERVATION_CONTENT_AUDIT' and observation['source_revision']==source['revision']
        assert observation['parent_closed_reaped'] is True and observation['architectural_equivalence_claim'] is False
        root=Path(ordinary['directory']);rows=saved.json(root/'results.json');old_summary=saved.json(root/'summary.json')
        assert saved.json(run/'ordinary-status.json')==dict(summary=old_summary,cases=rows)
        assert len(rows)==192 and old_summary['planned_cases']==192 and old_summary['artifact_cells']==24 and old_summary['datasets_per_artifact']==8
        assert all(row['status'] in ('PASS_ORDINARY_OUTPUT_AND_JOURNAL','FAILED','UNRUN') for row in rows)
        datasets=saved.json(saved.repo/'evaluation/e9-common-app/datasets.json')['datasets']
        assert [d['name'] for d in datasets]==['empty','singleton','pair-reverse','equal-17','sorted-17','reverse-17','duplicates-17','mixed-64']
        selected=[row for row in rows if row['artifact']==summary['cell']+'-core']
        assert [row['dataset'] for row in selected]==[d['name'] for d in datasets]
        for row,dataset in zip(selected,datasets):
            assert row['status']=='PASS_ORDINARY_OUTPUT_AND_JOURNAL' and row['strict_closure'] is True and row['exit']==0
            stage=root/row['name'];request=saved.json(stage/'request.json');receipt(saved,stage,request)
            assert row['receipt_sha256']==sha(saved.read(stage/'receipt.json'))
            assert saved.read(stage/'stdout.txt')==dataset['expected_stdout'].encode() and not saved.read(stage/'stderr.txt')
            recording.ordinary_journal(saved.read,saved.json,observation,row,stage,summary['cell'].rsplit('-',1)[1],'heap-write' if '-heap-write-' in summary['cell'] else 'jump-site')

    for n,p in [('original.elf',r[2]),('instructions.tsv',r[3]),('runtime-target.tsv',r[4]),('core-witness.tsv',r[6])]:
        assert saved.read(cap/n)==saved.read(p)
    variant=summary['cell'].rsplit('-',1)[1]; original=saved.read(cap/'original.elf')
    assert sha(original)==ORIGINALS[0 if variant=='unstripped' else 1]
    instructions=saved.read(cap/'instructions.tsv'); assert sha(instructions)==pins['tests/support/e9_common_seed.instructions.tsv']
    rows=tab(instructions);assert len(rows)==88 and len(rows[0])==14
    _,opages,original_base=image(original);assert len(opages)==37
    journal_at=None
    if RECORDING:
        original_base,journal_at=recording.journal_seed(original_base,LO,LOADS[3][1],LOADS[3][1]+LOADS[3][3])
    assert saved.read(cap/'original-pages.bin')==original_base
    for h,row in zip(heads,rows[1:]):
        assert int(row[1],0)==h['pc'] and int(row[2])==h['length'] and row[5]==h['bytes']
        assert original[h['file_offset']:h['file_offset']+h['length']]==at(opages,h['pc'],h['length'])==bytes.fromhex(h['bytes'])
    components=target(saved.read(cap/'runtime-target.tsv')); bundle=Path(r[5]); wb=saved.read(cap/'core-witness.tsv'); wr=tab(wb)
    assert len(wb)<=16*MIB and len(wr)<=40000
    if RECORDING:
        assert wr[:2]==[['LI2COMMONCORE','1'],['scope','STRUCTURAL_CORE_RECORDING_WITNESSES_ONLY']]
    else:
        assert wr[:2]==[['LI2COMMONCORE','1'],['scope','STRUCTURAL_CORE_NULL_WITNESSES_ONLY']]
    candidate=saved.read(bundle/'candidate.elf')
    assert cell['candidate_sha256']==sha(candidate) and cell['target_sha256']==sha(saved.read(cap/'runtime-target.tsv'))
    assert results[0]['witness_sha256']==sha(wb) and results[1]['capture_index_sha256']==sha(saved.read(run/'capture-files.json'))
    assert wr[2:8]==[[k,x] for k,x in [('original_sha256',sha(original)),('instructions_sha256',sha(instructions)),('target_sha256',sha(saved.read(cap/'runtime-target.tsv'))),('selection_sha256',sha(saved.read(Path(v[4])/'selection.txt'))),('candidate_sha256',sha(candidate)),('qualification_complete','false')]]
    cursor=8; file_rows=[]
    while wr[cursor][0]=='file':
        row=wr[cursor];assert len(row)==4 and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]*',row[1])
        data=saved.read(bundle/row[1]);assert len(data)==num(row[2]) and sha(data)==row[3]
        file_rows.append(row);cursor+=1
    assert len(file_rows)==len({x[1] for x in file_rows})<=330
    assert tree(bundle)==({x[1] for x in file_rows},set())
    assert saved.read(cap/'bundle-inputs.tsv')==tsv(file_rows)
    if profile is not None:
        marker=[row for row in file_rows if row[1]=='planning-profile.tsv']
        owned=profile['profiles']['planning_profile']!=PLANNING[0]
        assert marker==([['file','planning-profile.tsv',str(len(PLANNING_BYTES)),sha(PLANNING_BYTES)]] if owned else [])
        if owned:
            assert saved.read(bundle/'planning-profile.tsv')==PLANNING_BYTES
    assert saved.read(bundle/'target.tsv')==saved.read(cap/'runtime-target.tsv')
    assert saved.read(bundle/'ledger.tsv').startswith(saved.read(bundle/'plan-ledger.tsv'))
    cloads,cpages,candidate_base=image(candidate);declared=[]
    if RECORDING:
        candidate_base,candidate_journal=recording.journal_seed(candidate_base,LO,LOADS[3][1],LOADS[3][1]+LOADS[3][3])
        assert candidate_journal==journal_at
    while wr[cursor][0]=='load':
        row=wr[cursor];assert len(row)==6;declared.append(tuple(map(num,row[1:])));cursor+=1
    assert declared==cloads
    router=[]
    if profile is not None:
        ledger=tab(saved.read(bundle/'plan-ledger.tsv'))
        cursor,router=router_routes(wr,cursor,profile['profiles']['entry_router']!=ROUTERS[0],heads,cpages,ledger)
        router_ledger(ledger,router,heads,opages,cpages)
    added=[(p,flag) for p,(flag,_) in cpages.items() if not LO <= p < HI];assert 0<len(added)<=2048
    generated=b''.join(cpages[p][1] for p,_ in added)
    resource=saved.json(run/'resource-actual.json')
    assert resource['added_page_bytes']==len(generated) and resource['witness_bytes']==len(wb)
    if RECORDING:
        assert resource['recording_trace_reserve_bytes']==recording.TRACE_RESERVE
        assert resource['recording_live_reserve_bytes']==recording.TRACE_LIVE
    if profile is not None and profile['profiles']['entry_router']!=ROUTERS[0]:
        assert resource['router_trace_reserve_bytes']==176*MIB
        assert resource['router_live_reserve_bytes']==2*(143360+MIB)
    assert saved.read(cap/'candidate-pages.bin')==candidate_base+generated
    assert saved.read(cap/'page-plan.tsv')==tsv([(p,flag,HI-LO+4096*i) for i,(p,flag) in enumerate(added)])
    witness=[]; used_routes=set()
    for h in heads:
        row=wr[cursor];assert len(row)==5 and row[:2]==['head',str(h['pc'])];cursor+=1
        body,dest=num(row[2]),num(row[3]);code=bytes.fromhex(row[4]);assert 1<=len(code)<=15 and at(cpages,body,len(code))==code
        walks=[];pc=h['pc'];trap=False
        if profile is None:
            while wr[cursor][0]=='walk':
                row=wr[cursor];assert len(row)==5 and row[:3]==['walk',str(h['pc']),str(pc)]
                nxt=num(row[3]);b=bytes.fromhex(row[4]);assert 1<=len(b)<=15 and at(cpages,pc,len(b))==b
                walks.append((pc,nxt,b));pc=nxt;cursor+=1;assert len(walks)<20000
        else:
            while wr[cursor][0]=='walk' or (RECORDING and wr[cursor][0]=='record-hook') or (profile['profiles']['entry_router']!=ROUTERS[0] and wr[cursor][0]=='trap'):
                row=wr[cursor]; assert len(row)==5 and row[1:3]==[str(h['pc']),str(pc)]
                nxt=num(row[3]);b=bytes.fromhex(row[4])
                if RECORDING and row[0]=='record-hook':
                    assert pc==recording.CORE_HOOK and len(b)==recording.CORE_HOOK_BYTES
                    assert at(cpages,pc,len(b))==at(opages,pc,len(b))==b
                    assert walks and walks[-1][1]==pc and walks[-1][2][:1]==b'\xe8'
                    assert len(walks[-1][2])==5 and nxt==walks[-1][0]+5
                else:
                    assert 1<=len(b)<=15 and at(cpages,pc,len(b))==b
                if row[0]=='trap':
                    assert pc==h['pc'] and not walks and not trap
                    matches=[q for q in router if q['pc']==pc]; assert len(matches)==1
                    assert (nxt,b)==(matches[0]['target'],matches[0]['fetch']) and pc not in used_routes
                    used_routes.add(pc);trap=True
                walks.append((pc,nxt,b));pc=nxt;cursor+=1;assert len(walks)<20000
        assert pc==body
        if h['flow']=='Call':
            assert body==h['pc'] and not walks and code==bytes.fromhex(h['bytes']) and dest==h['target']
        if RECORDING:
            assert sum(p==recording.CORE_HOOK for p,_,_ in walks)<=1
        witness.append(dict(body=body,target=dest,bytes=code,walk=walks,trap=trap,journal_at=journal_at))
    assert wr[cursor:]==[['complete','87','174','2','E9_UNIMPLEMENTED_UNRUN']]
    assert used_routes=={q['pc'] for q in router}
    owners=kv(saved.read(cap/'input-owners.tsv'));assert owners.pop('whole_hash_and_structural_witness_admission')=='CALLER_REQUIRED'
    owner_paths=dict(original=r[2],instructions=r[3],target=r[4],witness=r[6],**{row[1]:str(bundle/row[1]) for row in file_rows})
    assert set(owners)==set(owner_paths)
    for key,path in owner_paths.items():
        s=saved.pins[path]['stat'];mt,mn=divmod(s[4],1000000000);ct,cn=divmod(s[5],1000000000)
        assert loads(owners[key])==[s[0],s[1],s[2],s[3],mt,mn,ct,cn]
    plan=[['case','head','state','original_pc','body_pc','completion_pc','logical_completion']]
    context=[]
    for i in range(176):
        spec=seed_case(i,heads);h=heads[spec['head']];w=witness[spec['head']];pc=spec['pc']
        finish=w['body'] if spec['fault'] else (w['body']+len(w['bytes']) if h['flow']=='Next' else pc if h['flow']=='Return' else w['target'] if h['flow'] in ('Call','Jump') or pc==h['target'] else w['body']+len(w['bytes']))
        plan.append([i,spec['head'],spec['state'],h['pc'],w['body'],finish,pc])
        try:
            report['cases'][i]=case(saved,cap,i,heads,witness,components,original_base,candidate_base,generated,added,context,router)
        except ERRORS as error:
            report['cases'][i]=dict(status='CONTENT_FAILURE',comparisons=0,error=repr(error))
    assert saved.read(cap/'planned-cases.tsv')==tsv(plan)
    report['completed_cases']=sum(c['status']=='PASS_SAVED_CONTENT' for c in report['cases'])
    report['comparisons']=sum(c['comparisons'] for c in report['cases'])
    if profile is None:
        report.update(cell=summary['cell'],candidate_sha256=sha(candidate),witness_sha256=sha(wb),generated_page_bytes=len(generated),source_revision=REVISION)
    else:
        report.update(cell=summary['cell'],candidate_sha256=sha(candidate),witness_sha256=sha(wb),generated_page_bytes=len(generated),source_revision=profile['epoch']['revision'],
                      profiles=profile['profiles'],source_binding_sha256=PROFILE_SOURCE_BINDING_SHA,router_routes=len(router),
                      saved_router_evidence='Complete v3 ordered stop/register/frame/FP/table/code observations; live ptrace causality remains source-attested')
    if RECORDING:
        report['recording_profile']=RECORDING_PROFILE
        report['mandatory_recording_pairs']=2112
        report['source_attested_not_independently_saved']=LIVE_ONLY+['Callback ISA decoding, intermediate RSP/argument/return-word checks are live source assertions; saved exact callback bytes/path and complete journal/state/stack are independently checked.']
    report['completed']=report['completed_cases']==176 and report['comparisons']==528
    report['status']='PASS_SAVED_CONTENT' if report['completed'] else 'CONTENT_FAILURE'


# A distinct explicit mode. Final source activation is still mandatory.
RECORDING = False
RECORDING_PROFILE = 'bounded-journal-v1'
RECORDING_FLAG = '--recording-profile=' + RECORDING_PROFILE
RECORDING_HELPER_SHA = '3d3290740ca465adb7827efdf921d1b2f74942ca078956f818c92371e3397a23'
RECORDING_SOURCES = ('tests/support/e9_common_recording.rs',
                     'tests/support/e9_common_recording_native.rs',
                     'evaluation/e9-common-app/recording_pairs.py')
recording = None


def load_recording(path, read_bytes):
    global recording
    b = read_bytes(path)
    assert hashlib.sha256(b).hexdigest() == RECORDING_HELPER_SHA
    recording = SimpleNamespace(**runpy.run_path(str(path), run_name='bounded_recording_contract'))
    assert recording.PROFILE == RECORDING_PROFILE


VERIFIER_CAPABILITY = 'legacy'


def verifier_capability_fields(capability, record, *records):
    assert capability in ('legacy', RECORDING_PROFILE) and type(record) is bool
    assert not record or capability == RECORDING_PROFILE
    for row in records:
        if capability == 'legacy':
            assert 'verifier_capability' not in row
        else:
            assert row['verifier_capability'] == capability
        if record:
            assert row['recording_profile'] == RECORDING_PROFILE
        else:
            assert 'recording_profile' not in row
    return capability != 'legacy'


def main():
    global RECORDING, CELLS, PROFILE_SOURCES, VERIFY_OUT, PAIR_OUT, COMPLETE, VERIFIER_CAPABILITY
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported; assertions are required')
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--inputs',required=True);ap.add_argument('--inputs-sha256',required=True);ap.add_argument('--raw',required=True)
    ap.add_argument('--planning-profile',choices=PLANNING,default='legacy');ap.add_argument('--entry-router',choices=ROUTERS,default='absent')
    ap.add_argument('--recording-profile',choices=[RECORDING_PROFILE])
    ap.add_argument('--verifier-capability',choices=['legacy',RECORDING_PROFILE],default='legacy')
    args=ap.parse_args();ib,io=read_file(args.inputs);assert sha(ib)==args.inputs_sha256 and re.fullmatch('[0-9a-f]{64}',args.inputs_sha256)
    RECORDING=args.recording_profile is not None
    VERIFIER_CAPABILITY=args.verifier_capability
    capable=verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING)
    if capable: PROFILE_SOURCES=PROFILE_SOURCES+RECORDING_SOURCES
    if RECORDING:
        CELLS=tuple(k.replace('null-','journal-',1) for k in CELLS)
        VERIFY_OUT=b'core recording witness complete: heads=87 normal=174 faults=2 execution=false qualification_complete=false\n'
        PAIR_OUT=b'core recording pairs complete: heads=87 normal=174 faults=2 comparisons=528 qualification_complete=false\n'
        COMPLETE=b'LI2COMMONCORERECORDINGPAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\ncomparisons\t528\nfiles\t8636\nrecording_profile\tbounded-journal-v1\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n'
    profiles=dict(planning_profile=args.planning_profile,entry_router=args.entry_router);profiled=capable or RECORDING or bool(profile_arguments(profiles))
    if not profiled:
        envelope=loads(ib);assert set(envelope)=={'schema','authority','repo','run','files','sources','evidence'} and type(envelope['schema']) is int and envelope['schema']==1
    else:
        if capable:
            envelope=loads(ib)
            assert set(envelope)=={'schema','authority','repo','run','files','sources','evidence','profiles','source_binding','verifier_capability'}|({'recording_profile'} if RECORDING else set())
            assert type(envelope['schema']) is int and envelope['schema']==1
            verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING,envelope)
        else:
            if RECORDING:
                envelope=loads(ib); assert set(envelope)=={'schema','authority','repo','run','files','sources','evidence','profiles','source_binding','recording_profile'} and type(envelope['schema']) is int and envelope['schema']==1
                assert envelope['recording_profile']==RECORDING_PROFILE
            else:
                envelope=loads(ib); assert set(envelope)=={'schema','authority','repo','run','files','sources','evidence','profiles','source_binding'} and type(envelope['schema']) is int and envelope['schema']==1
    saved=Saved(envelope['files'],envelope['repo']);out=Path(args.raw);run=Path(envelope['run'])
    assert out.is_absolute() and out.parent.resolve(strict=True)==out.parent and not out.exists() and out.is_relative_to(saved.repo/'ignored')
    assert '..' not in out.parts and not out.is_relative_to(run) and not run.is_relative_to(out)
    script=Path(__file__).resolve();support={n:read_file(str(script.parent/n)) for n in ('core-pair-heads.json','core-pair-source-pins.json')};sb,so=read_file(str(script))
    descriptor=loads(support['core-pair-heads.json'][0]);pins=loads(support['core-pair-source-pins.json'][0]);heads=descriptor['heads']
    assert len(heads)==87 and descriptor['source_sha256']==pins['tests/support/e9_common_seed.rs'] and descriptor['instructions_sha256']==pins['tests/support/e9_common_seed.instructions.tsv']
    assert len({h['pc'] for h in heads})==87 and sum(h['memory']['kind']!='None' for h in heads)==32
    profile=profile_activation(saved,envelope,profiles,pins) if profiled else None
    if RECORDING:
        load_recording(saved.repo/'evaluation/e9-common-app/recording_pairs.py',saved.read)
    if profile is not None:
        pins=profile['pins']
    out.mkdir(mode=0o700)
    report=dict(schema=1,status='INCOMPLETE',completed=False,cases=[dict(status='UNCHECKED',comparisons=0) for _ in range(176)],completed_cases=0,comparisons=0,expected_cases=176,expected_comparisons=528,expected_capture_files=8636,qualification_complete=False,normal_loader_validation=False,full_a3=False,E9_pairs='MANDATORY_SEPARATE',recording_pairs='MANDATORY_SEPARATE',source_attested_not_independently_saved=LIVE_ONLY)
    try:
        assert saved.read(script)==sb
        for n,(b,_) in support.items():
            assert saved.read(script.parent/n)==b
        report['recorded_runner_results']=saved.json(run/'results.json')
        report['recorded_runner_summary']=saved.json(run/'summary.json')
        for p in sorted(saved.pins):
            saved.read(p)
        audit(saved,envelope,heads,pins,report,profile)
    except ERRORS as error:
        report.update(status='INPUT_OR_CONTENT_FAILURE',completed=False,error=repr(error))
    try:
        saved.stable();assert read_file(args.inputs)==(ib,io) and read_file(str(script))==(sb,so)
        for n,old in support.items():
            assert read_file(str(script.parent/n))==old
    except ERRORS as error:
        report.update(status='INPUT_DRIFT',completed=False,drift_error=repr(error))
    def write(name,obj):
        b=(json.dumps(obj,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
        with (out/name).open('xb') as f:
            f.write(b)
        return sha(b)
    read_sha=write('read-inputs.json',dict(envelope=io,files=saved.seen,script=so,support={n:o for n,(_,o) in support.items()}))
    audit_sha=write('audit.json',report)
    write('binding.json',dict(schema=1,status=report['status'],completed=report['completed'],auditor_sha256=sha(sb),inputs_sha256=sha(ib),read_inputs_sha256=read_sha,audit_sha256=audit_sha,scope=('One caller-admitted complete core-recording artifact, 176 of 2112 required pairs; saved content only.' if RECORDING else 'One caller-admitted complete core-null artifact: saved content only; independent actual review remains separate.'),qualification_complete=False))
    print(json.dumps(dict(status=report['status'],completed=report['completed'],audit_sha256=audit_sha),sort_keys=True))
    return 0 if report['completed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
