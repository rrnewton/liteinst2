#!/usr/bin/env python3
"""One complete caller-admitted core-null artifact; never a case-filtered run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import signal
import stat
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

REVISION = 'cbb189d1d17f947c97194842129b66eb68b0531f'
SUPPORT_SHA = '523ce6007068c5764be6bf007d67f8093aaedf4054b1beb3b7465bed95f1196f'
# Activation requires a separately reviewed literal digest of final formatted
# source-binding JSON. None is deliberate: no proposed source is a build epoch.
PROFILE_SOURCE_BINDING_SHA = None
# A separate source-reviewed activation pins the final canonical producer.
# None refuses this scope before any compiler evidence can be admitted.
CANONICAL_PRODUCER_SHA = None
CANONICAL_EPOCH_RELATIVE = None
RECORDING_CANONICAL_PRODUCER_SHA = None
RECORDING_CANONICAL_EPOCH_RELATIVE = None
CANONICAL_ENTRY_SHA = '70c4f0ec1cfc2f0b0b74c00199927f83e5a7cfbe4bb2d2ce2e3295e9ecea1ee0'
CANONICAL_MEMBERS = {'src/common_core_foreign.rs': 'tools/elf-rewrite/examples/support/common_core_foreign.rs', 'src/common_core_router.rs': 'tools/elf-rewrite/examples/support/common_core_router.rs', 'src/e9_common_planning_profile.rs': 'tests/support/e9_common_planning_profile.rs', 'src/e9_common_router_contract.rs': 'tests/support/e9_common_router_contract.rs', 'src/e9_common_seed.instructions.tsv': 'tests/support/e9_common_seed.instructions.tsv', 'src/e9_common_seed.rs': 'tests/support/e9_common_seed.rs', 'src/verify_common_core.rs': 'tools/elf-rewrite/examples/verify_common_core.rs'}
CANONICAL_REWRITES = ((b'#[path = "../../../tests/support/e9_common_seed.rs"]', b'#[path = "e9_common_seed.rs"]'), (b'#[path = "support/common_core_foreign.rs"]', b'#[path = "common_core_foreign.rs"]'), (b'#[path = "../../../tests/support/e9_common_planning_profile.rs"]', b'#[path = "e9_common_planning_profile.rs"]'), (b'#[path = "support/common_core_router.rs"]', b'#[path = "common_core_router.rs"]'), (b'#[path = "../../../tests/support/e9_common_router_contract.rs"]', b'#[path = "e9_common_router_contract.rs"]'))
RECORDING_PROFILE = 'bounded-journal-v1'
RECORDING_SOURCE = 'tests/support/e9_common_recording.rs'
RECORDING_SOURCE_PIN = {'sha256': 'd0419f184093a5c1ef658028c7a8a2869dea8c849a5da44cd1f191c3b5085bc7', 'bytes': 15513}
RECORDING_REWRITE = (b'#[path = "../../../tests/support/e9_common_recording.rs"]', b'#[path = "e9_common_recording.rs"]')

def recording_identity(profile, *records):
    assert type(profile) is str and profile in ('legacy', RECORDING_PROFILE)
    assert records
    if profile == 'legacy':
        assert all('recording_profile' not in row for row in records)
        return False
    assert all(row['recording_profile'] == RECORDING_PROFILE and type(row['recording_profile']) is str for row in records)
    return True

def recording_members(profile, legacy):
    assert type(profile) is str and profile in ('legacy', RECORDING_PROFILE)
    assert len(legacy) == 7 and 'src/e9_common_recording.rs' not in legacy
    if profile == 'legacy':
        return legacy
    members = dict(legacy, **{'src/e9_common_recording.rs': RECORDING_SOURCE})
    assert len(members) == 8
    return members

def recording_source(data, legacy_transform):
    # Apply all five original exact rewrites, then the one explicit new member.
    derived = legacy_transform(data)
    old, new = RECORDING_REWRITE
    assert derived.count(old) == 1 and new not in derived
    out = derived.replace(old, new)
    assert out.count(new) == 1 and out.replace(new, old) == derived
    return out

PLANNING = ('legacy', 'owned-foreign-neighbors-v1')
ROUTERS = ('absent', 'linux-x86-64-private-altstack-v1')
PLANNING_MARKER = 'planning-profile.tsv'
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
ORDER = ('null-heap-write-unstripped', 'null-heap-write-stripped',
         'null-jump-site-unstripped', 'null-jump-site-stripped')
MIB = 1048576
DENOMINATORS = {'original': 16, 'production': 74, 'ordinary': 192,
                'E9_null': 1408, 'recording_pairs': 2112}
VERIFY_OUT = b'core null witness complete: heads=87 normal=174 faults=2 execution=false qualification_complete=false\n'
PAIR_OUT = b'core null pairs complete: heads=87 normal=174 faults=2 comparisons=528 E9=UNIMPLEMENTED_UNRUN qualification_complete=false\n'
COMPLETE = (b'LI2COMMONCOREPAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\n'
            b'comparisons\t528\nfiles\t8636\nE9\tUNIMPLEMENTED_UNRUN\nrecording_hooks\tUNIMPLEMENTED_UNRUN\n'
            b'normal_loader_validation\tfalse\nqualification_complete\tfalse\n')


def read(p):
    p = Path(p)
    assert p.is_absolute() and str(p) == os.fspath(p) and '..' not in p.parts
    assert p.parent.resolve(strict=True) == p.parent
    six = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        a = os.fstat(f.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= 128 * MIB
        data = f.read(128 * MIB + 1)
        assert six(a) == six(os.fstat(f.fileno())) == six(p.lstat()) and len(data) == a.st_size
    return data, dict(path=str(p), resolved=str(p.resolve(strict=True)),
                      sha256=hashlib.sha256(data).hexdigest(), stat=six(a))


def profile_arguments(profiles):
    assert profiles.keys() == {'planning_profile', 'entry_router'}
    planning, router = profiles['planning_profile'], profiles['entry_router']
    assert planning in PLANNING and router in ROUTERS
    # Rust pops router first, then planning. There is no inferred profile.
    return (['--planning-profile=' + planning] if planning != 'legacy' else []) + (
        ['--entry-router=' + router] if router != 'absent' else [])


def profile_envelope(inputs, profiles):
    assert VERIFIER_CAPABILITY!="legacy" or RECORDING or profile_arguments(profiles), 'this is the explicit opt-in schema only'
    old = {'schema', 'repo', 'source_epoch', 'preparation', 'build_admission',
           'observation_content_admission', 'production_admission', 'verifier_admission',
           'cell_admission', 'prior_cells', 'obligations', 'runtime_admission',
           'capacity_admission', 'tools', 'files'}
    if VERIFIER_CAPABILITY!='legacy':
        extra={'verifier_capability'}|({'recording_profile'} if RECORDING else set())
        assert inputs.keys()==old|{'profiles','source_binding'}|extra
        verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING,inputs)
    else:
        if RECORDING:
            assert inputs.keys() == old | {'profiles', 'source_binding', 'recording_profile'}
            assert inputs['recording_profile'] == RECORDING_PROFILE
        else:
            assert inputs.keys() == old | {'profiles', 'source_binding'}
    assert inputs['profiles'] == profiles, 'caller/CLI profile mismatch'
    assert type(inputs['source_binding']) is str and inputs['source_binding'] in inputs['files']


def profile_epoch(inputs, repo):
    if PROFILE_SOURCE_BINDING_SHA is None:
        raise SystemExit('profile source activation is pending final reviewed source/build pins')
    assert re.fullmatch('[0-9a-f]{64}', PROFILE_SOURCE_BINDING_SHA)
    data, _ = read(inputs['source_binding'])
    assert hashlib.sha256(data).hexdigest() == PROFILE_SOURCE_BINDING_SHA
    # This exact whole file is source-pinned before loading any support code.
    value = json.loads(data)
    assert value.keys() == {'schema', 'revision', 'prepared_revision', 'sources'}
    assert type(value['schema']) is int and value['schema'] == 1
    assert all(type(value[k]) is str and re.fullmatch('[0-9a-f]{40}', value[k])
               for k in ('revision', 'prepared_revision'))
    assert value['sources'].keys() == set(PROFILE_SOURCES)
    for name, digest in value['sources'].items():
        assert type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest)
        assert hashlib.sha256(read(repo / name)[0]).hexdigest() == digest
    return value


def witness_profiles(rows, profiles):
    profile_arguments(profiles)
    marker = [r for r in rows if r[:2] == ['file', PLANNING_MARKER]]
    expected = [['file', PLANNING_MARKER, str(len(PLANNING_BYTES)),
                 hashlib.sha256(PLANNING_BYTES).hexdigest()]]
    assert marker == (expected if profiles['planning_profile'] != 'legacy' else [])
    declared = [r for r in rows if r[0] == 'router-profile']
    routes = [r for r in rows if r[0] == 'router']
    traps = [r for r in rows if r[0] == 'trap']
    if profiles['entry_router'] == 'absent':
        assert declared == routes == traps == [], 'no implicit router admission'
        return
    assert declared == [['router-profile', profiles['entry_router']]]
    cursor = max(i for i, r in enumerate(rows) if r[0] == 'load') + 1
    assert rows[cursor:cursor + 1 + len(routes)] == declared + routes
    assert len(routes) <= 87 and all(len(r) == 6 for r in routes)
    pcs = [int(r[1]) for r in routes]
    assert pcs == sorted(set(pcs))
    assert all(len(r) == 5 for r in traps)
    assert {(r[2], r[3], r[4]) for r in traps} == {(r[1], r[2], r[5]) for r in routes}
    # Full owner/ISA/requirement/route reconstruction is the pinned verifier and
    # native consumer's job. The saved-content auditor independently checks it.


def capture_names():
    names = ['original.elf', 'instructions.tsv', 'runtime-target.tsv', 'core-witness.tsv',
             'original-pages.bin', 'bundle-inputs.tsv', 'input-owners.tsv', 'candidate-pages.bin',
             'page-plan.tsv', 'planned-cases.tsv', 'capture-inventory.tsv', 'complete.tsv']
    suffixes = ['regs', 'xstate', 'xstate-raw', 'data', 'stack', 'stack-owned', 'loads', 'maps']
    for i in range(176):
        case = f'case-{i:03}'
        names += [case + '/' + n for n in ('pair.tsv', 'witness.tsv')]
        names += [case + '/original/' + n for n in ('seed.tsv', 'complete.tsv')]
        names += [f'{case}/original/{s}.{x}' for s in ('before', 'after') for x in suffixes]
        names += [case + '/candidate/' + n for n in ('trace.tsv', 'complete.tsv')]
        names += [f'{case}/candidate/{s}.{x}' for s in ('before', 'restored', 'after') for x in suffixes + ['generated']]
    assert len(names) == len(set(names)) == 8636
    return names


def elf_rows(data):
    assert len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', data, 16) in ((2, 62, 1), (3, 62, 1))
    assert struct.unpack_from('<HH', data, 52) == (64, 56)
    off, n = struct.unpack_from('<Q', data, 32)[0], struct.unpack_from('<H', data, 56)[0]
    assert 1 <= n <= 512 and off + 56 * n <= len(data)
    rows = [struct.unpack_from('<IIQQQQQQ', data, off + 56 * i) for i in range(n)]
    assert all(r[2] + r[5] <= len(data) for r in rows)
    return rows


def load_plan(original, candidate):
    def loads(data):
        assert struct.unpack_from('<H', data, 16)[0] == 2
        return [r for r in elf_rows(data) if r[0] == 1]
    old, new = loads(original), loads(candidate)
    assert len(old) == 4 and 5 <= len(new) <= 261 and new[:4] == old
    pages, old_pages = set(), set()
    for i, r in enumerate(new):
        _, flags, off, va, _, size, memory, align = r
        assert flags in (4, 5, 6) and 0 < memory and size <= memory
        assert align == 4096 and off % 4096 == va % 4096
        lo, hi = va & ~4095, (va + memory + 4095) & ~4095
        assert 0 < lo < hi <= 1 << 47 and hi - lo <= 2048 * 4096
        selected = set(range(lo, hi, 4096))
        assert not pages & selected
        pages |= selected
        if i < 4:
            old_pages |= selected
    assert len(old_pages) == 37 and 0 < len(pages - old_pages) <= 2048
    assert max(pages) + 4096 - min(pages) <= 1073741824
    return [[r[2], r[3], r[5], r[6], r[1]] for r in new], 4096 * len(pages - old_pages)


def verifier_product(c, admission, tracked, repo, bound):
    c.admitted(admission, 'CALLER_ADMITTED_COMMON_CORE_VERIFIER', 'retained-verifier-build-and-fresh-archive-epoch', REVISION, bound)
    a = c.loads(bound(admission['archive_admission']))
    review = c.loads(bound(admission['review_binding']))
    assert review['admission_output_sha256'] == c.sha(bound(admission['archive_admission']))
    assert review['status'] == 'CLOSED_CONTROLS_AND_FRESH_ARCHIVE_ADMISSION_PASS'
    assert a['revision'] == REVISION and a['status'] == 'RETAINED_ARCHIVE_ADMITTED_AT_NEW_OWNER_EPOCH'
    assert a['compiler_status'] == 'PASS_RETAINED_RECEIPT' and a['original_archive_status'] == 'FAILED_CANONICAL_SPELLING_CHECK'
    assert a['old_original_owner_map_reconstructed'] is False
    assert c.sha(bound(admission['archive_failure_observation'])) == a['original_archive_failure_record_sha256'] == review['original_archive_failure_record_sha256']
    assert len(a['artifacts']) == 43 and len(a['source_bindings']) == 46
    for row in a['artifacts']:
        data = bound(row['path'])
        assert row['sha256'] == c.sha(data) and row['bytes'] == len(data)
        assert read(row['path'])[1]['stat'] == row['retained_copy_owner']
        assert row['compiler_time_original_owner'] is None
    for row in a['source_bindings']:
        assert tracked['files'][row['canonical_member']] == {k: row[k] for k in ('sha256', 'bytes', 'mode')}
    cargo = a['cargo']; target = cargo['target']
    assert target['name'] == 'verify_common_core' and target['kind'] == ['example'] and target['crate_types'] == ['bin']
    assert target['edition'] == '2024' and target['src_path'] == str(repo / 'tools/elf-rewrite/examples/verify_common_core.rs')
    assert cargo['manifest_path'] == str(repo / 'tools/elf-rewrite/Cargo.toml') and cargo['profile'] == c.PROFILE and cargo['features'] == []
    assert cargo['package_id'] == 'path+' + (repo / 'tools/elf-rewrite').as_uri() + '#liteinst-rewrite@0.1.0'
    assert cargo['filenames'] == [cargo['executable']]
    compiler = c.path(admission['compiler_directory'])
    request = c.loads(bound(str(compiler / 'request.json')))
    result = c.loads(bound(str(compiler / 'result.json')))
    assert request['argv'][1:] == ['build', '-p', 'liteinst-rewrite', '--example', 'verify_common_core', '--offline', '--locked', '--message-format=json']
    assert request['cwd'] == str(repo) and (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (60, 90, 128 * MIB)
    assert request['env']['CARGO_BUILD_JOBS'] == '4' and request['env']['CARGO_INCREMENTAL'] == '0'
    assert request['env']['CARGO_TARGET_DIR'] == str(repo / 'target') and request['env']['CARGO_NET_OFFLINE'] == 'true'
    for n in ('receipt.json', 'stdout.txt', 'stderr.txt'):
        bound(str(compiler / n))
    assert c.receipt(compiler, request)['exit'] == 0
    assert result['request'] == request and result['exit'] == 0 and result['parent_timeout'] is False
    messages = [c.loads(line) for line in bound(str(compiler / 'stdout.txt')).splitlines()]
    assert messages.count(cargo) == 1 and messages[-1] == dict(reason='build-finished', success=True)
    selected = [r for r in a['artifacts'] if r['cargo_path'] == cargo['executable']]
    assert len(selected) == 1 and selected[0]['path'] == admission['verifier']
    # Cargo/current_target_owner fields are metadata. Never open their target paths.
    return selected[0]['path']


def verifier_depfile_rules(text):
    # Literal reviewed admission parser, apart from its name/comment.
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


def verifier_aliases(c, rows, spellings, tracked, repo, bound):
    # Validate saved component-wise no-follow proofs, not a lexical normpath
    # exemption. The actual opens and stable directory checks are archive-review
    # authority; this runner never opens a target path or the alias spelling.
    assert [r['spelling'] for r in rows] == spellings and spellings
    members, identities, directories = set(), set(), {}
    for row in rows:
        spelling = row['spelling']; prefix = str(repo) + '/'
        assert spelling.startswith(prefix)
        parts = spelling[len(prefix):].split('/')
        assert parts and all(p not in ('', '.') for p in parts) and parts[-1] != '..'
        path = Path('/'); expected = [str(path)]
        for p in repo.parts[1:]:
            path /= p; expected.append(str(path))
        stack = [repo]
        for p in parts[:-1]:
            if p == '..':
                assert len(stack) > 1, 'no leave-and-return outside the repository'
                stack.pop()
            else:
                stack.append(stack[-1] / p)
            expected.append(str(stack[-1]))
        member = (stack[-1] / parts[-1]).relative_to(repo).as_posix()
        assert member == row['canonical_member'] and member not in members
        members.add(member)
        canonical = str(repo / member); data = bound(canonical)
        saved = tracked['files'][member]; owner = tracked['owners'][member]['stat']
        assert {k: row[k] for k in ('sha256', 'bytes', 'mode')} == saved
        assert c.sha(data) == row['sha256'] and len(data) == row['bytes']
        assert row['fresh_owner'] == row['alias_owner'] == owner
        assert row['alias_sha256'] == row['sha256'] and row['alias_bytes'] == row['bytes']
        assert stat.S_ISREG(owner[2]) and bool(owner[2] & 0o111) == (row['mode'] == '100755')
        identity = tuple(owner[:2]); assert identity not in identities
        identities.add(identity)
        proofs = row['directory_observations']; assert [p['path'] for p in proofs] == expected
        for p in proofs:
            s = p['owner']
            assert len(s) == 6 and all(type(n) is int and n >= 0 for n in s) and stat.S_ISDIR(s[2])
            assert p['path'] not in directories or directories[p['path']] == s
            directories[p['path']] = s
    return {r['canonical_member']: {k: r[k] for k in ('sha256', 'bytes', 'mode')} for r in rows}


def fresh_verifier_product(c, admission, tracked, repo, bound, build_root, tools):
    c.admitted(admission, 'CALLER_ADMITTED_COMMON_CORE_VERIFIER', 'fresh-verifier-build-and-archive-epoch', REVISION, bound)
    assert 'archive_failure_observation' not in admission
    a = c.loads(bound(admission['archive_admission']))
    review = c.loads(bound(admission['review_binding']))
    assert set(a) == {'schema', 'revision', 'status', 'compiler_status', 'archive_status', 'parent_closed_reaped', 'parent_observation', 'records_index', 'archive_source', 'source_before', 'source_after', 'tools_before', 'tools_after', 'configs_before', 'configs_after', 'archive_record', 'target_owners_before', 'target_owners_after', 'source_aliases_before', 'source_aliases_after'}
    assert a['schema'] == 1 and a['revision'] == REVISION
    assert a['status'] == 'FRESH_VERIFIER_BUILD_AND_ARCHIVE_COMPLETE'
    assert a['compiler_status'] == 'PASS_STRICT_RECEIPT' and a['archive_status'] == 'PASS_FRESH_ARCHIVE'
    assert review['status'] == 'CLOSED_FRESH_VERIFIER_BUILD_AND_ARCHIVE_PASS_EXECUTION_RECORD_SCOPE'
    assert review['revision'] == REVISION and review['findings'] == []
    assert review['admission_output_sha256'] == c.sha(bound(admission['archive_admission']))
    assert a['parent_closed_reaped'] is True and a['parent_observation'] in admission['evidence_files']
    closed = c.loads(bound(a['parent_observation']))
    assert type(closed['exit']) is int and closed['exit'] == 0 and closed['parent_wait_returned'] is True
    records = c.loads(bound(a['records_index']))
    assert review['records_index_sha256'] == c.sha(bound(a['records_index']))
    for p, pin in records.items():
        data = bound(p); assert pin == dict(sha256=c.sha(data), bytes=len(data))
    def record(p):
        assert p in records
        return bound(p)
    record(a['parent_observation'])
    assert review['archive_source_sha256'] == c.sha(record(a['archive_source']))
    assert record(a['source_before']) == record(a['source_after'])
    assert c.loads(record(a['source_before'])) == tracked, 'complete current Git bytes, modes and owner epoch'
    assert review['source_epoch_sha256'] == c.sha(record(a['source_before']))
    for kind in ('tools', 'configs'):
        before, after = record(a[kind + '_before']), record(a[kind + '_after'])
        assert before == after and c.loads(before) == c.loads(bound(str(build_root / (kind + '.json'))))
    compiler = c.path(admission['compiler_directory'])
    request = c.loads(record(str(compiler / 'request.json')))
    expected = c.loads(bound(str(build_root / 'common-sites-compile/request.json')))
    assert expected['argv'][1:] == ['build', '-p', 'liteinst-rewrite', '--example', 'common_sites', '--offline', '--locked', '--message-format=json']
    expected['argv'][5] = 'verify_common_core'
    expected['env']['TMPDIR'] = str(compiler / 'tmp')
    for name in ('stdout', 'stderr'):
        expected[name] = str(compiler / (name + '.txt'))
    assert request == expected
    assert request['cwd'] == str(repo) and (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (60, 90, 128 * MIB)
    command = c.loads(record(str(compiler / 'command.json')))
    expected_outer = [tools['timeout'], '--signal=TERM', '--kill-after=10s', '100s', tools['helper_python'], '-B', str(repo / 'tools/unwind-oracle/bounded_command.py'), '--request', str(compiler / 'request.json'), '--receipt', str(compiler / 'receipt.json')]
    assert command == dict(argv=request['argv'], cwd=str(repo), env=request['env'], request=request, outer_argv=expected_outer, outer_env=c.ENV, parent_timeout_seconds=115)
    result = c.loads(record(str(compiler / 'result.json')))
    assert type(result['elapsed_seconds']) in (int, float) and 0 <= result['elapsed_seconds'] <= 115
    assert result == dict(command, exit=0, elapsed_seconds=result['elapsed_seconds'], parent_timeout=False)
    for name in ('receipt.json', 'stdout.txt', 'stderr.txt', 'helper.stdout', 'helper.stderr'):
        record(str(compiler / name))
    assert c.receipt(compiler, request)['exit'] == 0
    terminal = dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
    assert record(str(compiler / 'helper.stdout')) == (json.dumps(terminal) + '\n').encode()
    assert not record(str(compiler / 'helper.stderr'))
    messages = [c.loads(line) for line in record(str(compiler / 'stdout.txt')).splitlines()]
    assert 1 <= len(messages) <= 512 and messages[-1] == dict(reason='build-finished', success=True)
    assert sum(m.get('reason') == 'build-finished' for m in messages) == 1
    assert all(m.get('reason') in ('compiler-artifact', 'build-script-executed', 'build-finished') for m in messages)
    assert not any(line.startswith(('warning:', 'error:')) for line in record(str(compiler / 'stderr.txt')).decode().splitlines())
    paths = []
    for m in messages:
        if m['reason'] == 'compiler-artifact':
            assert type(m['fresh']) is bool and m['filenames']
            for p in m['filenames']:
                assert str(Path(p)) == p and Path(p).is_absolute() and '..' not in Path(p).parts and Path(p).is_relative_to(repo / 'target')
                if p not in paths: paths.append(p)
    selected = [m for m in messages if m.get('target', {}).get('name') == 'verify_common_core' and m.get('executable')]
    assert len(selected) == 1; cargo = selected[0]; target = cargo['target']
    executable = str(repo / 'target/debug/examples/verify_common_core')
    assert target['kind'] == ['example'] and target['crate_types'] == ['bin'] and target['edition'] == '2024'
    assert target['src_path'] == str(repo / 'tools/elf-rewrite/examples/verify_common_core.rs')
    assert cargo['manifest_path'] == str(repo / 'tools/elf-rewrite/Cargo.toml') and cargo['profile'] == c.PROFILE and cargo['features'] == []
    assert cargo['package_id'] == 'path+' + (repo / 'tools/elf-rewrite').as_uri() + '#liteinst-rewrite@0.1.0'
    assert cargo['filenames'] == [executable] and cargo['executable'] == executable
    depfile = str(Path(executable).with_suffix('.d'))
    if depfile not in paths: paths.append(depfile)
    archive = c.loads(record(a['archive_record']))
    assert set(archive) == {'schema', 'source_revision', 'source_files_sha256', 'command_result_sha256', 'cargo_stdout_sha256', 'artifacts', 'selected', 'scope'}
    assert review['archive_record_sha256'] == c.sha(record(a['archive_record']))
    assert archive['schema'] == 1 and archive['source_revision'] == REVISION
    assert archive['source_files_sha256'] == c.sha(c.encode(tracked['files']))
    assert archive['command_result_sha256'] == c.sha(record(str(compiler / 'result.json')))
    assert archive['cargo_stdout_sha256'] == c.sha(record(str(compiler / 'stdout.txt')))
    assert set(archive['artifacts']) == set(paths) and archive['selected'].keys() == {'verify_common_core'}
    original_before, original_after = record(a['target_owners_before']), record(a['target_owners_after'])
    assert original_before == original_after
    originals = c.loads(original_before); assert set(originals) == set(paths)
    copy_owners = set()
    for i, p in enumerate(paths):
        row = archive['artifacts'][p]; copy = str(compiler.parent / 'artifacts/verifier-compile' / ('product-' + str(i)))
        assert row['path'] == copy
        data = record(copy); owner = read(copy)[1]['stat']
        assert row['sha256'] == c.sha(data) and row['bytes'] == len(data) and row['archive_owner'] == owner
        s = row['original_owner']
        assert len(s) == 6 and all(type(n) is int and n >= 0 for n in s) and stat.S_ISREG(s[2]) and s[3] == len(data)
        assert stat.S_IMODE(s[2]) == stat.S_IMODE(owner[2])
        assert originals[p] == dict(sha256=row['sha256'], bytes=row['bytes'], stat=s)
        assert tuple(owner[:2]) not in copy_owners; copy_owners.add(tuple(owner[:2]))
    chosen = archive['selected']['verify_common_core']
    assert chosen['cargo'] == cargo and messages.count(cargo) == 1
    assert chosen['product'] == archive['artifacts'][executable] and chosen['depfile'] == archive['artifacts'][depfile]
    assert chosen['product']['original_owner'][2] & 0o111
    rules = verifier_depfile_rules(record(chosen['depfile']['path']).decode())
    assert len(rules) == 1 and rules[0][0] == executable and rules[0][1]
    aliases_before, aliases_after = record(a['source_aliases_before']), record(a['source_aliases_after'])
    assert aliases_before == aliases_after
    bindings = verifier_aliases(c, c.loads(aliases_before), rules[0][1], tracked, repo, record)
    assert chosen['source_bindings'] == bindings and 'tools/elf-rewrite/examples/verify_common_core.rs' in bindings
    assert review['artifacts'] == len(paths) and review['source_dependencies'] == len(bindings)
    assert chosen['product']['path'] == admission['verifier']
    # Target owners above are saved metadata only. The archive's independent
    # review authenticates their capture; this function never opens those paths.
    return chosen['product']['path']


def canonical_epoch(repo, relative):
    assert type(relative) is str
    rel = Path(relative)
    assert not rel.is_absolute() and str(rel) == relative and '..' not in rel.parts
    epoch = repo / rel
    assert epoch.parent == repo / 'ignored/a3'
    assert epoch.name != 'common-native-epoch-v1'
    return epoch


def canonical_epoch_member(epoch, value):
    path = Path(value)
    assert path.is_absolute() and str(path) == os.fspath(value) and '..' not in path.parts
    assert path != epoch and path.is_relative_to(epoch)
    return path


def canonical_source(data):
    original = data
    for old, new in CANONICAL_REWRITES:
        assert data.count(old) == 1 and new not in data
        data = data.replace(old, new)
        assert data.count(new) == 1
    inverse = data
    for old, new in reversed(CANONICAL_REWRITES):
        inverse = inverse.replace(new, old)
    assert inverse == original
    return data


def canonical_verifier_product(c, admission, tracked, repo, bound, build_root, tools, recording='legacy'):
    recording_profile = recording
    recording = recording_identity(recording_profile, admission)
    members = recording_members(recording_profile, CANONICAL_MEMBERS)
    source_count = 8 if recording else 7
    producer_sha = RECORDING_CANONICAL_PRODUCER_SHA if recording else CANONICAL_PRODUCER_SHA
    epoch_relative = RECORDING_CANONICAL_EPOCH_RELATIVE if recording else CANONICAL_EPOCH_RELATIVE
    if producer_sha is None or epoch_relative is None:
        raise SystemExit('canonical verifier admission awaits a reviewed final producer source pin')
    assert re.fullmatch('[0-9a-f]{64}', producer_sha)
    c.build_input_profile(admission, build_root, bound)
    debug0 = admission['scope'] == 'direct-rustc-canonical-input-epoch-dev-debug0-v1'
    build_summary = c.loads(bound(str(build_root / 'summary.json')))
    if debug0:
        c.admitted(admission, 'CALLER_ADMITTED_COMMON_CORE_VERIFIER',
                   'direct-rustc-canonical-input-epoch-dev-debug0-v1', REVISION, bound)
        assert c.same_build_profile(admission, build_summary) == c.DEBUG0_BUILD_PROFILE
    else:
        assert c.same_build_profile(admission, build_summary) is None
        c.admitted(admission, 'CALLER_ADMITTED_COMMON_CORE_VERIFIER',
                   'direct-rustc-canonical-input-epoch', REVISION, bound)
    if recording:
        expected_keys=set(['authority', 'compiler_directory', 'entry_source', 'evidence_files', 'producer_caller', 'producer_launch', 'producer_references', 'producer_source', 'review_binding', 'review_references', 'schema', 'scope', 'source_revision', 'verifier'])|{'recording_profile'}
        if debug0: expected_keys.add('build_profile')
        assert set(admission)==expected_keys
    elif not debug0:
        assert set(admission) == {'schema', 'authority', 'scope', 'source_revision', 'verifier',
            'compiler_directory', 'producer_source', 'entry_source', 'producer_caller',
            'producer_references', 'producer_launch', 'review_binding', 'review_references', 'evidence_files'}
    else:
        assert set(admission) == {'schema', 'authority', 'scope', 'source_revision', 'verifier',
            'compiler_directory', 'producer_source', 'entry_source', 'producer_caller',
            'producer_references', 'producer_launch', 'review_binding', 'review_references', 'evidence_files', 'build_profile'}
    epoch = canonical_epoch(repo, epoch_relative)
    assert epoch.resolve(strict=True) == epoch
    compiler = c.path(admission['compiler_directory']); raw = canonical_epoch_member(epoch, compiler.parent)
    canonical_epoch_member(epoch, build_root)
    assert compiler.name == 'compile'
    assert raw.resolve(strict=True) == raw and not raw.is_relative_to(repo / 'target')
    producer = c.path(admission['producer_source']); entry_source = c.path(admission['entry_source'])
    assert entry_source == producer.parent / 'compiler_entry.py'
    assert c.sha(bound(str(producer))) == producer_sha
    assert c.sha(bound(str(entry_source))) == CANONICAL_ENTRY_SHA
    assert admission['producer_references'] == str(producer.parent / 'references.json')
    review_path = c.path(admission['review_binding']); review = c.loads(bound(str(review_path)))
    assert review['verdict'] == 'CLOSED_DIRECT_RUSTC_VERIFIER_PRODUCTION_METADATA_AND_ROOT_BYTE_CHECK_VERIFIED'
    assert review['revision'] == REVISION and review['findings'] == []
    c.same_build_profile(admission, review)
    recording_identity(recording_profile, review)
    assert review['epoch_root'] == str(epoch) and review['build_directory'] == str(build_root)
    assert review['producer_sha256'] == producer_sha and review['entry_sha256'] == CANONICAL_ENTRY_SHA
    assert review['consumer_admission_created'] is False and review['qualification_complete'] is False
    assert review['existing_cargo_admission_compatible'] is False
    assert review['prior_four_archive_attempts'] == review['prior_canonical_v1'] == 'FAILED_UNCHANGED'
    assert review['root_byte_check_passed'] is True and review['before_after_exact'] is True
    assert admission['review_references'] == str(review_path.parent / 'references.json')
    reference_bytes = bound(admission['review_references'])
    assert c.sha(reference_bytes) == review['references_sha256']
    refs = c.loads(reference_bytes); assert len(refs) == review['references'] and refs
    def fact(p, expected):
        data = bound(str(p)); owner = read(p)[1]['stat']
        assert expected == dict(sha256=c.sha(data), bytes=len(data), stat=owner)
        return data
    for p, row in refs.items():
        assert not c.path(p).is_relative_to(repo / 'target')
        fact(p, row)
    def evidence(p):
        p = str(p); assert p in refs
        return fact(p, refs[p])
    index_path = raw / 'raw-files.json'; index = c.loads(evidence(index_path))
    assert review['raw_files_sha256'] == c.sha(evidence(index_path))
    assert index and set(index) <= set(refs)
    actual = set()
    for parent, dirs, names in os.walk(raw, followlinks=False):
        for name in dirs:
            assert stat.S_ISDIR((Path(parent) / name).lstat().st_mode)
        for name in names:
            p = Path(parent) / name
            assert stat.S_ISREG(p.lstat().st_mode)
            if p != index_path: actual.add(str(p))
    assert actual == set(index), 'complete saved raw membership, not selected successful rows'
    for p, row in index.items():
        assert c.path(p).is_relative_to(raw) and row == refs[p]
        fact(p, row)
    def record(name):
        p = str(raw / name); assert p in index
        return evidence(p)
    complete = c.loads(record('complete.json'))
    c.same_build_profile(admission, complete)
    recording_identity(recording_profile, complete)
    if recording:
        expected_keys=set(['application_or_verifier_executions', 'archive_status', 'compiler_status', 'dependency_archive_records', 'dependency_copies', 'direct_source_dependencies', 'existing_cargo_admission_compatible', 'prior_four_archive_attempts', 'products', 'qualification_complete', 'revision', 'schema', 'source_transform', 'status'])|{'recording_profile'}
        if debug0: expected_keys.add('build_profile')
        assert set(complete)==expected_keys
    elif not debug0:
        assert set(complete) == {'schema', 'revision', 'status', 'compiler_status', 'archive_status',
            'dependency_archive_records', 'dependency_copies', 'direct_source_dependencies', 'source_transform',
            'products', 'application_or_verifier_executions', 'prior_four_archive_attempts',
            'existing_cargo_admission_compatible', 'qualification_complete'}
    else:
        assert set(complete) == {'schema', 'revision', 'status', 'compiler_status', 'archive_status',
            'dependency_archive_records', 'dependency_copies', 'direct_source_dependencies', 'source_transform',
            'products', 'application_or_verifier_executions', 'prior_four_archive_attempts',
            'existing_cargo_admission_compatible', 'qualification_complete', 'build_profile'}
    assert type(complete['schema']) is int and complete['schema'] == 1 and complete['revision'] == REVISION
    assert complete['status'] == 'DIRECT_RUSTC_VERIFIER_PRODUCED_REVIEW_REQUIRED'
    assert complete['compiler_status'] == 'PASS_STRICT_RECEIPT' and complete['archive_status'] == 'PASS_FRESH_DIRECT_ARCHIVE'
    assert complete['application_or_verifier_executions'] == 0 and complete['qualification_complete'] is False
    assert complete['prior_four_archive_attempts'] == 'FAILED_UNCHANGED' and complete['existing_cargo_admission_compatible'] is False
    assert str(raw / 'failure.json') not in index
    assert record('source.json') == record('source-after.json')
    assert c.loads(record('source.json')) == tracked
    assert review['source_epoch_sha256'] == c.sha(record('source.json'))
    saved_build = c.loads(bound(str(build_root / 'source.json')))
    assert saved_build['revision'] == REVISION and saved_build['files'] == tracked['files']
    assert saved_build['owners'] == {p: row['stat'] for p, row in tracked['owners'].items()}
    for kind in ('tools', 'configs'):
        assert record(kind + '.json') == record(kind + '-after.json')
        assert c.loads(record(kind + '.json')) == c.loads(bound(str(build_root / (kind + '.json'))))
    caller_bytes = evidence(admission['producer_caller']); caller = c.loads(caller_bytes)
    assert record('caller.json') == caller_bytes
    c.same_build_profile(admission, caller)
    recording_identity(recording_profile, caller)
    if recording:
        expected_keys=set(['authority', 'capacity_record', 'entry_sha256', 'linker', 'producer_sha256', 'raw', 'references_sha256', 'revision', 'schema'])|{'recording_profile'}
        if debug0: expected_keys.add('build_profile')
        assert set(caller)==expected_keys
    elif not debug0:
        assert set(caller) == {'schema', 'authority', 'revision', 'raw', 'producer_sha256', 'entry_sha256',
                               'references_sha256', 'linker', 'capacity_record'}
    else:
        assert set(caller) == {'schema', 'authority', 'revision', 'raw', 'producer_sha256', 'entry_sha256',
                               'references_sha256', 'linker', 'capacity_record', 'build_profile'}
    assert type(caller['schema']) is int and caller['schema'] == 1
    assert caller['authority'] == 'ROOT_AUTHORIZED_DIRECT_RUSTC_VERIFIER_PRODUCTION'
    assert caller['revision'] == REVISION and caller['raw'] == str(raw)
    assert caller['producer_sha256'] == producer_sha and caller['entry_sha256'] == CANONICAL_ENTRY_SHA
    producer_refs_bytes = evidence(admission['producer_references'])
    assert c.sha(producer_refs_bytes) == caller['references_sha256']
    producer_refs = c.loads(producer_refs_bytes)
    for name, row in producer_refs.items():
        rel = Path(name); assert not rel.is_absolute() and '..' not in rel.parts and str(rel) == name
        fact(repo / rel, row)
    assert set(members.values()) <= set(producer_refs)
    for name in ('linker', 'capacity_record'):
        row = caller[name]; assert set(row) == {'path', 'sha256', 'bytes', 'stat'}
        assert not c.path(row['path']).is_relative_to(raw)
        fact(row['path'], {k: row[k] for k in ('sha256', 'bytes', 'stat')})
    linker = caller['linker']; assert c.path(linker['path']).resolve(strict=True) == Path(linker['path'])
    assert linker['stat'][2] & 0o111 and c.loads(record('linker.json')) == linker
    assert c.loads(record('linker-after.json')) == {k: linker[k] for k in ('sha256', 'bytes', 'stat')}
    archive = c.loads(record('original-build-archive.json'))
    assert archive == c.loads(bound(str(build_root / 'common-sites-compile/artifact-archive.json')))
    assert archive['source_revision'] == REVISION and archive['source_files_sha256'] == c.sha(c.encode(tracked['files']))
    cargo_bytes = bound(str(build_root / 'common-sites-compile/stdout.txt'))
    cargo = [c.loads(line) for line in cargo_bytes.splitlines()]
    assert 1 <= len(cargo) <= 512 and cargo[-1] == dict(reason='build-finished', success=True)
    assert sum(x.get('reason') == 'build-finished' for x in cargo) == 1
    assert all(x.get('reason') in ('compiler-artifact', 'build-script-executed', 'build-finished') for x in cargo)
    assert all(type(x['fresh']) is bool and x['filenames'] for x in cargo if x['reason'] == 'compiler-artifact')
    assert archive['cargo_stdout_sha256'] == c.sha(cargo_bytes)
    assert archive['command_result_sha256'] == c.sha(bound(str(build_root / 'common-sites-compile/result.json')))
    assert set(archive['selected']) == {'common_sites'}
    selected = archive['selected']['common_sites']; assert cargo.count(selected['cargo']) == 1
    reported = {p for row in cargo if row['reason'] == 'compiler-artifact' for p in row['filenames']}
    assert set(archive['artifacts']) == reported | {str(Path(selected['cargo']['executable']).with_suffix('.d'))}
    deps = c.loads(record('dependencies.json')); assert set(deps) == {'originals', 'copies', 'externs'}
    originals, expected_copies = {}, {}
    for spelling, row in archive['artifacts'].items():
        p = c.path(row['path']); assert p.is_relative_to(build_root / 'artifacts/common-sites-compile')
        owner = dict(sha256=row['sha256'], bytes=row['bytes'], stat=row['archive_owner'])
        fact(p, owner); originals[str(p)] = owner
        base = Path(spelling).name
        if base.endswith(('.rlib', '.rmeta')):
            assert base.startswith('lib') and base not in expected_copies
            copy = str(raw / 'inputs/deps' / base); assert copy in index
            expected_copies[base] = dict(source=str(p), original=owner, copy=index[copy])
            assert index[copy]['sha256'] == owner['sha256'] and index[copy]['bytes'] == owner['bytes']
    assert len(originals) == len(archive['artifacts'])
    assert deps['originals'] == c.loads(record('dependencies-after.json')) == originals
    assert deps['copies'] == expected_copies and expected_copies
    externs = {}
    for alias, name in [('formats', 'liteinst_artifact'), ('li2core', 'liteinst2'),
                        ('liteinst_rewrite', 'liteinst_rewrite'), ('iced_x86', 'iced_x86')]:
        rows = [x for x in cargo if x['reason'] == 'compiler-artifact' and x['target']['name'] == name and x['target']['kind'] == ['lib']]
        assert len(rows) == 1
        libs = [Path(x).name for x in rows[0]['filenames'] if x.endswith('.rlib')]
        assert len(libs) == 1 and libs[0] in expected_copies
        externs[alias] = 'deps/' + libs[0]
    assert deps['externs'] == externs
    transforms = c.loads(record('source-transform.json'))
    assert transforms == complete['source_transform'] and set(transforms) == set(members)
    private_files = {}
    for relative, member in members.items():
        original = bound(str(repo / member)); source = tracked['files'][member]
        owner = dict(sha256=source['sha256'], bytes=source['bytes'], stat=tracked['owners'][member]['stat'])
        fact(repo / member, owner)
        if recording and member == RECORDING_SOURCE:
            assert {k: owner[k] for k in ('sha256','bytes')} == RECORDING_SOURCE_PIN
        compiled = (recording_source(original, canonical_source) if recording else canonical_source(original)) if relative == 'src/verify_common_core.rs' else original
        path = str(raw / 'inputs' / relative); assert record('inputs/' + relative) == compiled
        expected = dict(original_member=member, original_owner=owner, original_mode=source['mode'],
                        compiled=index[path], transformation=('six-path-literals' if recording else 'five-path-literals') if relative == 'src/verify_common_core.rs' else 'byte-identical')
        assert transforms[relative] == expected
        private_files[relative] = index[path]
    private_files.update({'deps/' + name: row['copy'] for name, row in expected_copies.items()})
    assert len({tuple(row['stat'][:2]) for row in private_files.values()}) == len(private_files)
    assert all(stat.S_ISREG(row['stat'][2]) and stat.S_IMODE(row['stat'][2]) == 0o444 for row in private_files.values())
    original_inodes = {tuple(row['stat'][:2]) for row in originals.values()}
    original_inodes |= {tuple(tracked['owners'][name]['stat'][:2]) for name in members.values()}
    assert not original_inodes & {tuple(row['stat'][:2]) for row in private_files.values()}
    assert record('private-before.json') == record('private-after.json')
    private = c.loads(record('private-before.json'))
    assert set(private) == {'directories', 'path_directories', 'entries', 'files', 'opened_files'}
    dirs = private['directories']; assert set(dirs) == {'', 'src', 'deps'} and private['path_directories'] == dirs
    entries = {'': ['deps', 'src'], **{name: sorted(p.split('/')[1] for p in private_files if p.startswith(name + '/')) for name in ('src', 'deps')}}
    assert private['entries'] == entries and private['files'] == private['opened_files'] == private_files
    six = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    for name, owner in dirs.items():
        p = raw / 'inputs' / name
        assert stat.S_ISDIR(owner[2]) and stat.S_IMODE(owner[2]) == 0o555
        assert six(p.lstat()) == owner and sorted(os.listdir(p)) == entries[name]
        assert six(p.lstat()) == owner
    base = c.loads(bound(str(build_root / 'common-sites-compile/request.json')))
    assert base['argv'][1:] == ['build', '-p', 'liteinst-rewrite', '--example', 'common_sites', '--offline', '--locked', '--message-format=json']
    assert (base['cpu_seconds'], base['wall_seconds'], base['file_bytes']) == (60, 90, 128 * MIB)
    tool_map = c.loads(record('tools.json')); rustc = tool_map[base['env']['RUSTC']]
    for tool in tool_map.values():
        fact(tool['resolved'], dict(sha256=tool['sha256'], bytes=tool['stat'][3], stat=tool['stat']))
        assert tool['stat'][2] & 0o111
    expected_argv = [rustc['resolved'], '--crate-name', 'verify_common_core', '--edition=2024', '--crate-type=bin',
        '-C', 'opt-level=0', '-C', 'debuginfo=2', '-C', 'debug-assertions=yes', '-C', 'overflow-checks=yes',
        '-C', 'codegen-units=4', '-C', 'linker=' + linker['path'],
        '--emit=link=' + str(raw / 'output/verify_common_core') + ',dep-info=' + str(raw / 'output/verify_common_core.d'),
        '--out-dir', str(raw / 'output'), '-L', 'dependency=deps']
    if debug0:
        assert expected_argv[7:9] == ['-C', 'debuginfo=2']
        expected_argv[8] = 'debuginfo=0'
    for name, path in sorted(externs.items()): expected_argv += ['--extern', name + '=' + path]
    expected_argv += ['src/verify_common_core.rs']
    env = dict(base['env']); del env['CARGO_TARGET_DIR']; env['TMPDIR'] = str(raw / 'tmp')
    job_bytes = record('compiler-job.json'); job = c.loads(job_bytes)
    assert job == dict(schema=1, scope='DIRECT_RUSTC_CANONICAL_PRIVATE_INPUTS', input_root=str(raw / 'inputs'),
        directories=dirs, files=private_files, rustc=rustc, argv=expected_argv, env=env, entry=str(raw / 'compiler-entry.json'))
    entry = c.loads(record('compiler-entry.json'))
    assert type(entry['pid']) is int and entry['pid'] > 0
    assert entry == dict(schema=1, job_sha256=c.sha(job_bytes), pid=entry['pid'], cwd=str(raw / 'inputs'),
        cwd_owner=dirs[''], directories=dirs, files=private_files, rustc=rustc, argv=expected_argv, env=env,
        scope='pre-exec authentication only; compiler receipt and parent closure remain required')
    request = dict(argv=[tools['helper_python'], '-B', str(entry_source), '--job', str(raw / 'compiler-job.json'), '--job-sha256', c.sha(job_bytes)],
        cwd=str(repo), env=c.ENV, stdout=str(compiler / 'stdout.txt'), stderr=str(compiler / 'stderr.txt'), cpu_seconds=60, wall_seconds=90, file_bytes=128 * MIB)
    assert c.loads(record('compile/request.json')) == request
    outer = [tools['timeout'], '--signal=TERM', '--kill-after=10s', '100s', tools['helper_python'], '-B',
        str(repo / 'tools/unwind-oracle/bounded_command.py'), '--request', str(compiler / 'request.json'), '--receipt', str(compiler / 'receipt.json')]
    command = dict(request=request, argv=outer, cwd=str(repo), env=c.ENV, parent_timeout_seconds=115)
    assert c.loads(record('compile/command.json')) == command
    result = c.loads(record('compile/result.json')); started = c.loads(record('compile/started.json'))
    assert type(result['pid']) is int and result['pid'] > 0
    assert started == dict(pid=result['pid'], source=producer_sha, command_sha256=c.sha(record('compile/command.json')))
    assert type(result['elapsed_seconds']) in (int, float) and 0 <= result['elapsed_seconds'] <= 115
    assert result == dict(command, pid=result['pid'], exit=0, parent_wait_returned=True, parent_timeout=False, elapsed_seconds=result['elapsed_seconds'])
    assert c.receipt(compiler, request)['exit'] == 0
    terminal = (json.dumps(dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)) + '\n').encode()
    assert record('compile/helper.stdout') == terminal
    assert record('compile/stdout.txt') == record('compile/stderr.txt') == record('compile/helper.stderr') == b''
    launch = c.path(admission['producer_launch']); assert not launch.is_relative_to(raw)
    producer_request = dict(argv=[tools['helper_python'], '-B', str(producer), '--caller', admission['producer_caller'], '--caller-sha256', c.sha(caller_bytes)],
        cwd=str(repo), env=c.ENV, stdout=str(launch / 'stdout.txt'), stderr=str(launch / 'stderr.txt'), cpu_seconds=120, wall_seconds=180, file_bytes=128 * MIB)
    if recording: producer_request['argv'].append('--recording-profile='+RECORDING_PROFILE)
    assert c.loads(evidence(launch / 'request.json')) == producer_request
    assert c.receipt(launch, producer_request)['exit'] == 0
    producer_command_bytes = evidence(launch / 'command.json'); producer_command = c.loads(producer_command_bytes)
    assert producer_command['cwd'] == str(repo) and producer_command['env'] == c.ENV
    assert producer_command['parent_timeout_seconds'] == 205
    assert producer_command['whole_producer_outer_bounds'] == [120, 180, 128 * MIB]
    assert producer_command['compiler_bounds_unchanged'] == [60, 90, 128 * MIB]
    assert producer_command['source_review_sha256'] == review['producer_source_review_sha256']
    assert c.sha(evidence(review['producer_source_review'])) == review['producer_source_review_sha256']
    assert producer_command['argv'][:4] == [tools['timeout'], '--signal=TERM', '--kill-after=10s', '190s']
    suffix = [tools['helper_python'], '-B', str(repo / 'tools/unwind-oracle/bounded_command.py'),
              '--request', str(launch / 'request.json'), '--receipt', str(launch / 'receipt.json')]
    assert producer_command['argv'][-len(suffix):] == suffix
    assert review['producer_command_sha256'] == c.sha(producer_command_bytes)
    assert review['producer_outer_argv'] == producer_command['argv']
    # The exact optional namespace prefix is separately source-reviewed caller
    # provenance. Neither this byte join nor a receipt creates runtime authority.
    middle = producer_command['argv'][4:-len(suffix)]
    assert middle == review['producer_namespace_prefix']
    assert bool(middle) == bool(review['producer_namespace_records'])
    for p in review['producer_namespace_records']: evidence(p)
    closed_bytes = evidence(launch / 'closed.json'); closed = c.loads(closed_bytes)
    assert set(closed) == {'exit', 'parent_error', 'parent_wait_returned', 'pid', 'seconds', 'stderr_sha256', 'stdout_sha256'}
    assert type(closed['exit']) is int and closed['exit'] == 0 and closed['parent_error'] is None and closed['parent_wait_returned'] is True
    assert type(closed['pid']) is int and closed['pid'] > 0 and 0 <= closed['seconds'] <= 205
    assert c.loads(evidence(launch / 'started.json')) == dict(pid=closed['pid'], command_sha256=c.sha(producer_command_bytes))
    assert closed['stdout_sha256'] == c.sha(evidence(launch / 'controller.stdout'))
    assert closed['stderr_sha256'] == c.sha(evidence(launch / 'controller.stderr'))
    assert not evidence(launch / 'controller.stderr')
    assert evidence(review['producer_helper_stdout']) == terminal and not evidence(review['producer_helper_stderr'])
    if middle:
        helper_root = c.path(review['producer_helper_stdout']).parent
        assert review['producer_helper_stdout'] == str(helper_root / 'stdout.txt')
        assert review['producer_helper_stderr'] == str(helper_root / 'stderr.txt')
        helper_closed = c.loads(evidence(helper_root / 'closed.json'))
        helper_spec = c.loads(evidence(helper_root / 'command-spec.json'))
        assert helper_spec['argv'] == suffix and helper_spec['cwd'] == str(repo) and helper_spec['env'] == c.ENV
        assert helper_spec['scope'] == 'CALLER_PINNED_PRIVATE_CACHE_COMMAND'
        assert helper_spec['entry_proof'] in review['producer_namespace_records']
        evidence(helper_spec['entry_proof'])
        assert type(helper_closed['exit']) is int and helper_closed['exit'] == 0 and helper_closed['parent_wait_returned'] is True
        assert helper_closed['stdout_sha256'] == c.sha(evidence(review['producer_helper_stdout']))
        assert helper_closed['stderr_sha256'] == c.sha(evidence(review['producer_helper_stderr']))
        assert c.loads(evidence(helper_root / 'started.json')) == dict(pid=helper_closed['pid'])
        controller = c.loads(evidence(launch / 'controller.stdout'))
        assert controller == dict(label=helper_root.name, exit=0, seconds=controller['seconds']) and 0 <= controller['seconds'] <= 205
    else:
        assert review['producer_helper_stdout'] == str(launch / 'controller.stdout')
        assert review['producer_helper_stderr'] == str(launch / 'controller.stderr')
    assert review['producer_parent_sha256'] == c.sha(closed_bytes)
    assert not evidence(launch / 'stderr.txt')
    expected_products = {'verify_common_core', 'verify_common_core.d'}
    assert set(complete['products']) == expected_products
    for directory in ('output', 'archive'):
        assert {p.name for p in (raw / directory).iterdir()} == expected_products
    for name, row in complete['products'].items():
        assert set(row) == {'original_path', 'original', 'path', 'archive'}
        assert row['original_path'] == str(raw / 'output' / name) and row['path'] == str(raw / 'archive' / name)
        assert row['original'] == index[row['original_path']] and row['archive'] == index[row['path']]
        assert record('output/' + name) == record('archive/' + name)
        assert stat.S_IMODE(row['original']['stat'][2]) == stat.S_IMODE(row['archive']['stat'][2])
        assert row['original']['stat'][:2] != row['archive']['stat'][:2]
    product = complete['products']['verify_common_core']
    assert product['path'] == admission['verifier'] and product['archive']['stat'][2] & 0o111
    rules = verifier_depfile_rules(record('archive/verify_common_core.d').decode())
    nonempty = [(target, values) for target, values in rules if values]; empty = [target for target, values in rules if not values]
    assert len(nonempty) == 2 and {target for target, values in nonempty} == {str(raw / 'output' / name) for name in expected_products}
    for target, values in nonempty: assert len(values) == len(set(values)) == source_count and set(values) == set(members)
    assert len(empty) == len(set(empty)) == source_count and set(empty) == set(members)
    assert complete['dependency_archive_records'] == review['dependency_archives'] == len(originals)
    assert complete['dependency_copies'] == review['dependency_copies'] == len(expected_copies)
    assert complete['direct_source_dependencies'] == review['private_source_copies'] == source_count
    assert review['source_files'] == len(tracked['files']) and review['private_leaf_rows'] == len(private_files)
    assert review['archive_products'] == complete['products'] and review['application_or_verifier_executions'] == 0
    assert review['compiler_exit'] == review['producer_exit'] == 0
    assert review['compiler_strict_receipt_verified'] is review['producer_strict_receipt_verified'] is True
    assert evidence(launch / 'stdout.txt') == (json.dumps(dict(status=complete['status'], products=complete['products'], qualification_complete=False), sort_keys=True) + '\n').encode()
    join = c.loads(evidence(review_path.parent / 'root-byte-check-join.json'))
    checks = c.loads(evidence(review['byte_check_result'])); parent = c.loads(evidence(review['byte_check_parent']))
    assert join['checks'] == checks and join['parent'] == parent
    assert join['checker_source'] == refs[review['byte_check_source']]
    check_command = c.loads(evidence(review['byte_check_command']))
    assert join['namespace_command'] == check_command
    assert check_command['argv'] == [tools['helper_python'], '-B', review['byte_check_source']]
    assert check_command['cwd'] == str(repo) and check_command['env'] == c.ENV
    assert join['root_executed_byte_verification'] is True and join['synthetic_helper_receipt_created'] is False
    assert checks['status'] == 'PASS_CURRENT_BYTES_AND_SAVED_OWNER_CHECKS' and checks['revision'] == REVISION
    c.same_build_profile(admission, checks)
    recording_identity(recording_profile, checks)
    assert checks['original_dependency_products'] == len(originals) and checks['copied_libraries'] == len(expected_copies)
    assert checks['private_leaves'] == len(private_files) and checks['raw_files'] == len(index) and checks['source_files'] == len(tracked['files'])
    assert checks['source_transform'] == 'whole_inverse' and checks['application_or_verifier_executions'] == 0
    assert all(checks[name] is True for name in ('exact_depfile_rules', 'output_archive_bytes_equal', 'prior_failed_attempts_unchanged', 'private_directories_unchanged'))
    assert checks['qualification_complete'] is join['qualification_complete'] is False
    assert type(parent['exit']) is int and parent['exit'] == 0 and parent['parent_wait_returned'] is True
    assert parent['stdout_sha256'] == c.sha(evidence(review['byte_check_stdout']))
    assert parent['stderr_sha256'] == c.sha(evidence(review['byte_check_stderr']))
    assert not evidence(review['byte_check_stderr'])
    for p in review['byte_check_records']: evidence(p)
    assert len(set(review['byte_check_records'])) == len(review['byte_check_records'])
    assert all(review[name] in review['byte_check_records'] for name in ('byte_check_result', 'byte_check_parent', 'byte_check_source', 'byte_check_command', 'byte_check_stdout', 'byte_check_stderr'))
    # All source/tool/private observations are retained. This is a distinct
    # direct-rustc product profile, never a Cargo alias or native qualification.
    return product['path']


def admitted_verifier_product(c, admission, tracked, repo, bound, build_root, tools, recording='legacy'):
    recording_profile = recording
    recording = recording_identity(recording_profile, admission)
    if recording:
        assert admission['scope'] in ('direct-rustc-canonical-input-epoch', 'direct-rustc-canonical-input-epoch-dev-debug0-v1')
        return canonical_verifier_product(c, admission, tracked, repo, bound, build_root, tools, recording_profile)
    c.build_input_profile(admission, build_root, bound)
    summary = c.loads(bound(str(build_root / 'summary.json')))
    if 'build_profile' in summary:
        assert summary['build_profile'] == c.DEBUG0_BUILD_PROFILE
        assert admission['scope'] == 'direct-rustc-canonical-input-epoch-dev-debug0-v1'
        return canonical_verifier_product(c, admission, tracked, repo, bound, build_root, tools)
    assert 'build_profile' not in admission
    if admission['scope'] == 'direct-rustc-canonical-input-epoch':
        return canonical_verifier_product(c, admission, tracked, repo, bound, build_root, tools)
    if admission['scope'] == 'fresh-verifier-build-and-archive-epoch':
        return fresh_verifier_product(c, admission, tracked, repo, bound, build_root, tools)
    return verifier_product(c, admission, tracked, repo, bound)



def production(c, admission, tracked, products, inv, originals, selected, bound, planning='legacy', profiled=False):
    c.admitted(admission, 'CALLER_ADMITTED_COMMON_PRODUCTION_ARTIFACTS', 'closed-production-artifacts-only', REVISION, bound)
    assert admission['parent_closed_reaped'] is True and admission['parent_observation'] in admission['evidence_files']
    root = c.path(admission['directory'])
    summary = c.loads(bound(str(root / 'summary.json')))
    assert summary['revision'] == REVISION and summary['planned_stages'] == 74
    assert summary['ordinary_dataset_executions'] == summary['native_executions'] == 0 and summary['qualification_complete'] is False
    assert bound(str(root / 'source-before.json')) == bound(str(root / 'source-after.json'))
    assert c.loads(bound(str(root / 'source-before.json')))['files'] == tracked['files']
    index = c.loads(bound(str(root / 'raw-files.json'))); c.indexed(root, index, bound)
    inputs = c.loads(bound(str(root / 'inputs.json')))
    build = c.loads(bound(inputs['build_admission']))
    assert build['authority'] == 'CALLER_AUTHENTICATED_BUILD_PRODUCTS' and build['source_revision'] == REVISION
    assert build['source_files_sha256'] == c.sha(c.encode(tracked['files']))
    assert build['products'] == dict(core=products['liteinst-rewrite'], common_sites=products['common_sites'])
    for p in build['required_products'] + build['evidence_files']:
        bound(p)
    names = []
    for i, key in enumerate(c.KEYS):
        if i == 4:
            names += ['hook-compile', 'hook-link']
        names += [key + '-core'] + [key + '-' + lane + '-' + step for lane in c.LANES[1:] for step in ('transport', 'producer', 'adapter', 'compare')]
    rows = c.loads(bound(str(root / 'results.json')))
    assert len(names) == 74 and [r['name'] for r in rows] == names
    assert all(r['status'] in ('PASS', 'FAILED', 'UNRUN') for r in rows)
    assert summary['successful'] == all(r['status'] == 'PASS' for r in rows)
    assert c.loads(bound(str(root / 'stage-inventory.json'))) == names
    # Unrelated failures, fatal metadata and unrun tails are retained verbatim.
    # Their closure is caller-admitted; they are not silently made successes.
    cells = c.loads(bound(str(root / 'cells.json')))
    variant = selected.rsplit('-', 1)[1]; bundle = root / selected / 'core'
    if profiled:
        c.production_profile(admission, root, summary, inputs, index, planning, bound)
        artifact = c.profiled_core_candidate(bundle, inv[selected], originals[variant], bound, planning)
    else:
        artifact = c.core_candidate(bundle, inv[selected], originals[variant], bound)
    assert selected in cells and cells[selected]['core']['complete'] is True and artifact['eligible'] is True
    row = rows[names.index(selected + '-core')]; d = root / (selected + '-core')
    assert row['status'] == 'PASS' and row['exit'] == 0
    request = c.loads(bound(str(d / 'request.json')))
    if profiled:
        c.core_profile_request(request, root, selected, variant, inputs, products, inv, originals, planning, bound)
    else:
        assert request['argv'] == [products['liteinst-rewrite'], 'prepare', inputs['preparation']['originals'][variant], inv[selected]['directory'] + '/selection.txt', str(bundle)]
    assert bound(request['argv'][2]) == originals[variant]
    assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (20, 30, 16 * MIB)
    for name in ('receipt.json', 'stdout.txt', 'stderr.txt'):
        bound(str(d / name))
    assert c.receipt(d, request)['exit'] == 0 and row['receipt_sha256'] == c.sha(bound(str(d / 'receipt.json')))
    return root, bundle, summary, rows


def ordinary(c, admission, tracked, repo, producer, artifacts, selected, datasets, bound, streams=None):
    c.admitted(admission, 'CALLER_ADMITTED_COMMON_ORDINARY_CONTENT',
               'closed-192-case-output-and-journal-records', tracked['revision'], bound)
    assert admission['parent_closed_reaped'] is True and admission['parent_observation'] in admission['evidence_files']
    root = c.path(admission['directory'])
    c.indexed(root, c.loads(bound(str(root / 'raw-files.json'))), bound)
    source = c.loads(bound(str(root / 'source.json')))
    assert source == tracked and c.loads(bound(str(root / 'source-after.json'))) == source
    assert c.loads(bound(str(root / 'after.json')))['source'] == source
    supplied = c.loads(bound(str(root / 'inputs.json')))
    assert supplied['production_admission'] == producer
    summary = c.loads(bound(str(root / 'summary.json')))
    assert summary['revision'] == tracked['revision'] and summary['planned_cases'] == 192
    assert summary['artifact_cells'] == 24 and summary['datasets_per_artifact'] == 8
    assert summary['selected_owners_unchanged'] is True and summary['qualification_complete'] is False
    rows = c.loads(bound(str(root / 'results.json')))
    names = ['run-' + key + '-' + lane + '-' + d['name'] for key in c.KEYS for lane in c.LANES for d in datasets]
    assert [r['name'] for r in rows] == names and len(names) == 192
    assert c.loads(bound(str(root / 'stage-inventory.json'))) == names
    assert c.loads(bound(str(root / 'artifact-prerequisites.json'))) == artifacts
    assert all(r['status'] in ('PASS_ORDINARY_OUTPUT_AND_JOURNAL', 'FAILED', 'UNRUN') for r in rows)
    assert summary['passed_cases'] == sum(r['status'] == 'PASS_ORDINARY_OUTPUT_AND_JOURNAL' for r in rows)
    assert summary['failed_cases'] == sum(r['status'] == 'FAILED' for r in rows)
    assert summary['unrun_cases'] == [r['name'] for r in rows if r['status'] == 'UNRUN']
    assert summary['attempted_cases'] == sum(r['launched'] for r in rows)
    assert summary['ordinary_cases_complete'] == (summary['fatal'] is None and summary['passed_cases'] == 192)
    assert summary['successful'] == (summary['ordinary_cases_complete'] and summary['production_successful'])
    selected_rows = [r for r in rows if r['artifact'] == selected]
    assert [r['dataset'] for r in selected_rows] == list(c.DATASETS)
    for row, dataset in zip(selected_rows, datasets):
        assert row['status'] == 'PASS_ORDINARY_OUTPUT_AND_JOURNAL' and row['strict_closure'] is True and row['exit'] == 0
        run = root / row['name']; request = c.loads(bound(str(run / 'request.json')))
        copied = str(root / 'executables' / (selected + '.elf'))
        assert bound(copied) == bound(artifacts[selected]['candidate'])
        assert request['argv'] == [copied, dataset['name'], str(run / 'journal.bin')]
        assert request['cwd'] == str(repo)
        assert request['env'] == dict(c.ENV, TMPDIR=str(run / 'tmp'))
        assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (20, 30, 16 * MIB)
        assert request['stdout'] == str(run / 'stdout.txt') and request['stderr'] == str(run / 'stderr.txt')
        for name in ('receipt.json', 'stdout.txt', 'stderr.txt'):
            bound(str(run / name))
        receipt = c.receipt(run, request)
        assert receipt['exit'] == 0 and row['receipt_sha256'] == c.sha(bound(str(run / 'receipt.json')))
        assert bound(str(run / 'stdout.txt')) == dataset['expected_stdout'].encode() and not bound(str(run / 'stderr.txt'))
        if RECORDING:
            key = selected.removesuffix('-core'); variant = key.rsplit('-',1)[1]
            style = 'heap-write' if '-heap-write-' in key else 'jump-site'
            pcs = streams[(variant,dataset['name'],style)]
            assert len(pcs) % 8 == 0 and len(pcs)//8 <= 16384
            assert bound(str(run / 'journal.bin')) == c.journal(pcs)
            assert row['journal_bytes'] == 131144 and row['journal_sha256'] == c.sha(c.journal(pcs))
            assert row['expected_record_count'] == len(pcs)//8 and row['expected_pc_stream_sha256'] == c.sha(pcs)
            assert row['original_pc_stream_sha256'] == c.sha(pcs) and row['original_pc_stream_count'] == len(pcs)//8
        else:
            assert bound(str(run / 'journal.bin')) == c.journal(b'')
            assert row['journal_bytes'] == 131144 and row['journal_sha256'] == c.sha(c.journal(b''))
            assert row['expected_record_count'] == 0 and row['expected_pc_stream_sha256'] == c.sha(b'')
    return root, summary, rows


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
    global REVISION, SUPPORT_SHA, RECORDING, ORDER, PROFILE_SOURCES, VERIFY_OUT, PAIR_OUT, COMPLETE, DENOMINATORS, VERIFIER_CAPABILITY
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported; assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--cell', choices=ORDER + tuple(k.replace('null-', 'journal-', 1) for k in ORDER), required=True)
    parser.add_argument('--recording-profile', choices=[RECORDING_PROFILE])
    parser.add_argument('--verifier-capability', choices=['legacy',RECORDING_PROFILE],default='legacy')
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--planning-profile', choices=PLANNING, default='legacy')
    parser.add_argument('--entry-router', choices=ROUTERS, default='absent')
    args = parser.parse_args()
    RECORDING = args.recording_profile is not None
    VERIFIER_CAPABILITY=args.verifier_capability
    capable=verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING)
    if capable: PROFILE_SOURCES=PROFILE_SOURCES+RECORDING_SOURCES
    if RECORDING:
        ORDER = tuple(k.replace('null-', 'journal-', 1) for k in ORDER)
        DENOMINATORS=dict(DENOMINATORS,core_null=704)
        VERIFY_OUT = b'core recording witness complete: heads=87 normal=174 faults=2 execution=false qualification_complete=false\n'
        PAIR_OUT = b'core recording pairs complete: heads=87 normal=174 faults=2 comparisons=528 qualification_complete=false\n'
        COMPLETE = b'LI2COMMONCORERECORDINGPAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\ncomparisons\t528\nfiles\t8636\nrecording_profile\tbounded-journal-v1\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n'
    assert args.cell in ORDER
    profiles = dict(planning_profile=args.planning_profile, entry_router=args.entry_router)
    extra_arguments = profile_arguments(profiles) + ([RECORDING_FLAG] if RECORDING else [])
    profiled = capable or bool(extra_arguments)
    ib, io = read(args.inputs)
    assert hashlib.sha256(ib).hexdigest() == args.inputs_sha256
    bootstrap = json.loads(ib); repo = Path(bootstrap['repo'])
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    activation = None
    if profiled:
        profile_envelope(bootstrap, profiles)
        activation = profile_epoch(bootstrap, repo)
        REVISION = activation['revision']
        SUPPORT_SHA = activation['sources']['evaluation/e9-common-app/run_candidates.py']
    support = repo / 'evaluation/e9-common-app/run_candidates.py'
    assert hashlib.sha256(read(support)[0]).hexdigest() == SUPPORT_SHA
    # Only the pinned, guarded source's definitions are loaded. Its main is not called.
    c = SimpleNamespace(**runpy.run_path(str(support), run_name='common_pair_admission_support'))
    inputs = c.loads(ib)
    if profiled:
        profile_envelope(inputs, profiles)
    else:
        assert inputs.keys() == {'schema', 'repo', 'source_epoch', 'preparation', 'build_admission', 'observation_content_admission', 'production_admission', 'verifier_admission', 'cell_admission', 'prior_cells', 'obligations', 'runtime_admission', 'capacity_admission', 'tools', 'files'}
    assert type(inputs['schema']) is int and inputs['schema'] == 1
    raw = c.path(str(args.raw)); script = Path(__file__).resolve(strict=True)
    assert raw.is_relative_to(repo / 'ignored') and not raw.exists() and not raw.is_symlink()
    watched = {str(args.inputs): io}
    def bound(value):
        p = c.path(value)
        assert not p.is_relative_to(repo / 'target') and not p.is_relative_to(raw)
        data, owner = read(p); expected = inputs['files'][value]
        assert expected == dict(sha256=c.sha(data), bytes=len(data), stat=owner['stat'])
        if value in watched:
            assert watched[value] == owner, 'no implicit input owner refresh'
        watched[value] = owner
        return data
    for p in inputs['files']:
        bound(p)
    bound(str(script)); assert c.sha(bound(str(support))) == SUPPORT_SHA
    if RECORDING:
        load_recording(repo / 'evaluation/e9-common-app/recording_pairs.py', lambda p: bound(str(p)))
    tools = inputs['tools']
    assert tools.keys() == {'python', 'helper_python', 'timeout', 'git'} and tools['git'] == '/usr/bin/git'
    assert str(Path(sys.executable).resolve(strict=True)) == tools['python']
    for p in tools.values():
        bound(p); assert c.path(p).stat().st_mode & 0o111
    tracked = c.source(repo)
    assert tracked['revision'] == REVISION and c.loads(bound(inputs['source_epoch'])) == tracked
    assert all(str(repo / p) in inputs['files'] for p in tracked['files'])
    if profiled:
        assert c.sha(bound(inputs['source_binding'])) == PROFILE_SOURCE_BINDING_SHA
        assert c.loads(bound(inputs['source_binding'])) == activation
        assert activation['prepared_revision'] == c.PREPARED
        assert all(tracked['files'][p]['sha256'] == digest
                   and c.sha(bound(str(repo / p))) == digest for p, digest in activation['sources'].items())
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    assert c.sha(bound(str(helper))) == c.HELPER_SHA
    prep = inputs['preparation']; ps = c.loads(bound(prep['summary']))
    assert ps['revision'] == c.PREPARED and ps['completed'] is True and ps['qualified'] is False
    assert (ps['planned_stages'], ps['observed_stages'], ps['ordinary_original_runs'], ps['required_refusals'], ps['rewriting_runs']) == (30, 30, 16, 6, 0)
    assert bound(prep['source']) == bound(prep['source_after'])
    old = c.loads(bound(prep['source']))
    kept = {p: h for p, h in old['files'].items() if p.startswith('evaluation/e9-common-app/')}
    assert len(kept) == 17 and all(tracked['files'][p]['sha256'] == h for p, h in kept.items())
    pr = c.loads(bound(prep['review_binding']))
    assert pr['revision'] == c.PREPARED and pr['verdict'] == 'CLOSED_ORIGINAL_PREPARATION_PASS_EXECUTION_RECORD_SCOPE'
    assert prep['originals'].keys() == {'unstripped', 'stripped'}
    originals = {v: bound(p) for v, p in prep['originals'].items()}
    assert all(ps['artifacts'][v] == dict(sha256=c.sha(b), bytes=len(b)) for v, b in originals.items())
    build = c.loads(bound(inputs['build_admission'])); build_root, products = c.build_inputs(build, tracked, repo, bound)
    build_extra = {} if 'build_profile' not in build else dict(build_profile=c.DEBUG0_BUILD_PROFILE)
    cells = c.loads(bound(str(build_root / 'cells.json')))
    inv = c.inventories(cells, originals, products['common_sites'], bound)
    datasets = c.loads(bound(str(repo / 'evaluation/e9-common-app/datasets.json')))['datasets']
    assert [d['name'] for d in datasets] == list(c.DATASETS) and [d['id'] for d in datasets] == list(range(8))
    observation, streams = c.observed_streams(c.loads(bound(inputs['observation_content_admission'])), tracked, build_root, cells, inv, datasets, bound)
    producer, bundle, production_summary, production_rows = production(c, c.loads(bound(inputs['production_admission'])), tracked, products, inv, originals, args.cell, bound, args.planning_profile, profiled)
    c.same_build_profile(build, production_summary, c.loads(bound(inputs['production_admission'])))
    ordinary_root = None
    if profiled:
        pr, ps, rows, artifacts = c.production_inputs(c.loads(bound(inputs['production_admission'])),
            tracked, products, inv, originals, bound, args.planning_profile)
        assert (pr, ps, rows) == (producer, production_summary, production_rows)
        o = inputs['obligations']['ordinary']; assert o['record'] is not None
        ordinary_admission = c.loads(bound(o['record']))
        ordinary_root, ordinary_summary, ordinary_rows = ordinary(c, ordinary_admission, tracked, repo,
            inputs['production_admission'], artifacts, args.cell + '-core', datasets, bound, streams)
        ordinary_inputs = c.loads(bound(str(ordinary_root / 'inputs.json')))
        c.planning_profile(ordinary_inputs, args.planning_profile)
        if args.planning_profile == 'legacy':
            assert 'planning_profile' not in ordinary_admission and 'planning_profile' not in ordinary_summary
        else:
            assert ordinary_admission['planning_profile'] == args.planning_profile
            assert ordinary_summary['planning_profile'] == c.profile_record(args.planning_profile)
        c.same_build_profile(build, ordinary_summary, ordinary_admission, c.loads(bound(ordinary_inputs['build_admission'])))
        assert ordinary_summary['production_successful'] == production_summary['successful']
        ordinary_status = 'CLOSED_REVIEWED' if ordinary_summary['ordinary_cases_complete'] else 'FAILED'
        assert o == dict(denominator=192, status=ordinary_status, record=inputs['obligations']['ordinary']['record'])
    verifier_info = c.loads(bound(inputs['verifier_admission']))
    if capable:
        verifier = admitted_verifier_product(c, verifier_info, tracked, repo, bound, build_root, tools, recording=VERIFIER_CAPABILITY)
        assert verifier_info['recording_profile']==VERIFIER_CAPABILITY
    else:
        verifier = admitted_verifier_product(c, verifier_info, tracked, repo, bound, build_root, tools)
    driver = products['elf-exec-oracle']
    for p in (driver, verifier):
        assert c.path(p).stat().st_mode & 0o111
    cell = c.loads(bound(inputs['cell_admission']))
    if RECORDING:
        c.admitted(cell, 'CALLER_ADMITTED_CORE_RECORDING_PAIR_INPUTS', 'one-complete-core-recording-artifact', REVISION, bound)
        assert cell['recording_profile'] == verifier_info['recording_profile'] == RECORDING_PROFILE
    else:
        c.admitted(cell, 'CALLER_ADMITTED_CORE_NULL_PAIR_INPUTS', 'one-complete-core-null-artifact', REVISION, bound)
    verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING,cell)
    assert cell['cell'] == args.cell and cell['eligible'] is True and cell['bundle'] == str(bundle)
    if profiled:
        assert cell['profiles'] == profiles and cell['source_binding_sha256'] == PROFILE_SOURCE_BINDING_SHA
    assert cell['production_admission_sha256'] == c.sha(bound(inputs['production_admission']))
    assert cell['driver_sha256'] == c.sha(bound(driver)) and cell['verifier_sha256'] == c.sha(bound(verifier))
    c.same_build_profile(build, cell, verifier_info)
    variant = args.cell.rsplit('-', 1)[1]; original = prep['originals'][variant]
    directory = inv[args.cell]['directory']; instructions = directory + '/instructions.tsv'
    assert cell['original'] == original and cell['inventory'] == directory
    target = cell['target']; tb = bound(target)
    compact = bound(directory + '/target.txt')
    assert compact == b'target xsave64 743 4:576:256 32:832:64 64:896:512 128:1408:1024 512:2432:8\n'
    expected_target = ('LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t1\nformat\txsave64-standard\nallocation_bytes\t2496\nimage_bytes\t2440\nxcr0_mask\t743\nqualification_complete\tfalse\n'
        + ''.join('component\t' + x.replace(':', '\t') + '\n' for x in compact.decode().split()[3:])).encode()
    assert tb == expected_target and cell['target_sha256'] == c.sha(tb)
    candidate = bound(str(bundle / 'candidate.elf'))
    assert cell['candidate_sha256'] == c.sha(candidate)
    loads, g = load_plan(originals[variant], candidate)
    assert len(inputs['prior_cells']) == ORDER.index(args.cell)
    prior = []
    for key, value in zip(ORDER, inputs['prior_cells']):
        a = c.loads(bound(value))
        c.admitted(a, 'CALLER_REVIEWED_COMPLETE_CORE_PAIR_CELL', 'closed-complete-176-case-content-review', REVISION, bound)
        assert a['cell'] == key and a['parent_closed_reaped'] is True and a['parent_observation'] in a['evidence_files']
        summary = c.loads(bound(a['summary']))
        assert summary['revision'] == REVISION and summary['cell'] == key and summary['command_capture_schema_complete'] is True
        assert summary['cases'] == 176 and summary['capture_files'] == 8636
        if profiled:
            assert a['profiles'] == summary['profiles'] == profiles
            assert a['source_binding_sha256'] == summary['source_binding_sha256'] == PROFILE_SOURCE_BINDING_SHA
        c.same_build_profile(build, a, summary)
        verifier_capability_fields(VERIFIER_CAPABILITY,RECORDING,a,summary)
        if RECORDING:
            assert a['recording_profile'] == summary['recording_profile'] == RECORDING_PROFILE
        assert a['capture_index_sha256'] == c.sha(bound(a['capture_index']))
        prior.append(a)
    assert inputs['obligations'].keys() == DENOMINATORS.keys()
    for key, n in DENOMINATORS.items():
        o = inputs['obligations'][key]
        assert o.keys() == {'denominator', 'status', 'record'} and o['denominator'] == n
        assert o['status'] in ('UNRUN', 'FAILED', 'PARTIAL', 'CLOSED_REVIEWED')
        if o['record'] is None:
            assert o['status'] == 'UNRUN'
        else:
            bound(o['record'])
    assert inputs['obligations']['original'] == dict(denominator=16, status='CLOSED_REVIEWED', record=inputs['observation_content_admission'])
    assert inputs['obligations']['production'] == dict(denominator=74,
        status='CLOSED_REVIEWED' if production_summary['successful'] else 'FAILED', record=inputs['production_admission'])
    runtime = c.loads(bound(inputs['runtime_admission']))
    c.admitted(runtime, 'CALLER_PINNED_PAIR_HOST_RUNTIME_EPOCH', 'selected-host-executable-interpreter-library-cache-owners', REVISION, bound)
    assert runtime['executables'] == dict(driver=driver, verifier=verifier)
    assert '/etc/ld.so.cache' in runtime['owners'] and len(set(runtime['owners'])) == len(runtime['owners']) >= 2
    for p in runtime['owners']:
        bound(p)
    lookups = runtime['interpreter_lookups']
    for p in (driver, verifier, tools['python'], tools['helper_python']):
        data = bound(p); interp = [r for r in elf_rows(data) if r[0] == 3]
        assert len(interp) == 1
        r = interp[0]; name = data[r[2]:r[2] + r[5]]
        assert name.endswith(b'\0') and b'\0' not in name[:-1]
        name = name[:-1].decode(); assert name in lookups and c.lookup(name) == lookups[name]
        assert lookups[name]['resolved'] in runtime['owners']
    capacity = c.loads(bound(inputs['capacity_admission']))
    assert capacity['schema'] == 1 and capacity['authority'] == 'CALLER_RESERVED_CORE_PAIR_RESOURCES'
    assert capacity['source_revision'] == REVISION and capacity['cell'] == args.cell and capacity['exclusive_slot_writer'] is True
    bound(capacity['observation'])
    assert capacity['slot_cap_bytes'] == 20000000000
    for k in ('slot_used_bytes', 'free_disk_bytes', 'free_memory_bytes'):
        assert type(capacity[k]) is int and capacity[k] >= 0
    bundle_names = sorted(p.name for p in bundle.iterdir())
    sizes = [len(bound(str(bundle / n))) for n in bundle_names]
    b, f = sum(sizes), max(sizes)
    def resource(w):
        disk = 880 * (256575 + 65536) + 880 * MIB + 529 * g + 64 * MIB + 512 * MIB
        memory = 2 * (b + max(f, w, len(originals[variant])) + w + 4 * g + 32 * MIB + 237568 + g)
        if RECORDING:
            disk += recording.TRACE_RESERVE
            memory += recording.TRACE_LIVE
        if args.entry_router != 'absent':
            # Additional reservation, not a larger file/CPU/wall limit. See RESOURCE.md.
            disk += 176 * MIB
            memory += 2 * (143360 + MIB)
        assert capacity['slot_used_bytes'] + disk <= capacity['slot_cap_bytes'] and capacity['free_disk_bytes'] >= disk
        assert capacity['free_memory_bytes'] >= memory
        fs = os.statvfs(raw.parent); assert fs.f_bavail * fs.f_frsize >= disk
        return dict(added_page_bytes=g, bundle_bytes=b, largest_member_bytes=f, witness_bytes=w,
                    required_growth_bytes=disk, live_payload_allowance_bytes=memory,
                    allocation_reserve_bytes=512 * MIB, rss_enforced=False, arbitrary_failure_disk_guarantee=False,
                    **(dict(recording_trace_reserve_bytes=recording.TRACE_RESERVE, recording_live_reserve_bytes=recording.TRACE_LIVE) if RECORDING else {}),
                    **(dict(router_trace_reserve_bytes=176 * MIB, router_live_reserve_bytes=2 * (143360 + MIB))
                       if args.entry_router != 'absent' else {}))
    estimate = resource(16 * MIB)
    old_roots = [build_root, observation, producer, Path(prep['summary']).parent, Path(verifier_info['compiler_directory']).parent]
    old_roots += [Path(a['summary']).parent for a in prior]
    if ordinary_root is not None:
        old_roots.append(ordinary_root)
    for old_root in old_roots:
        assert not raw.is_relative_to(old_root) and not old_root.is_relative_to(raw)
    def snapshot():
        return dict(owners={p: read(p)[1] for p in sorted(watched)}, source=c.source(repo),
                    interpreter_lookups={n: c.lookup(n) for n in lookups}, bundle_names=sorted(p.name for p in bundle.iterdir()),
                    inventory_names={k: sorted(p.name for p in c.path(v['directory']).iterdir()) for k, v in cells.items()})
    def stable(s):
        assert s['owners'] == watched and s['source'] == tracked and s['interpreter_lookups'] == lookups and s['bundle_names'] == bundle_names
        assert all(names == sorted(c.INVENTORY_FILES) for names in s['inventory_names'].values())
    def freeze(p):
        owner = read(p)[1]
        if str(p) in watched:
            assert watched[str(p)] == owner
        watched[str(p)] = owner
    before = snapshot(); stable(before)
    raw.mkdir(mode=0o700)
    rows = [dict(name=n, status='UNRUN', launched=False, strict_closure=False, reason='not yet launched') for n in ('verify', 'replay')]
    c.write(raw / 'inputs.json', ib); c.write(raw / 'source.json', tracked); c.write(raw / 'before.json', before)
    c.write(raw / 'resource-before.json', estimate)
    c.write(raw / 'production-status.json', dict(summary=production_summary, stages=production_rows))
    c.write(raw / 'prior-cells.json', prior); c.write(raw / 'obligations.json', inputs['obligations'])
    if profiled:
        c.write(raw / 'profiles.json', dict(profiles=profiles, source_binding_sha256=PROFILE_SOURCE_BINDING_SHA))
        c.write(raw / 'ordinary-status.json', dict(summary=ordinary_summary, cases=ordinary_rows))
    if RECORDING:
        c.write(raw / 'recording-profile.json', dict(profile=RECORDING_PROFILE,cell=args.cell,mandatory_pairs=2112,core_null_pairs=704))
    c.write(raw / 'stage-inventory.json', ['verify', 'replay'])
    c.write(raw / 'expected-captures.tsv', ('\n'.join(capture_names()) + '\n').encode())
    c.write(raw / 'cell-plan.json', [dict(cell=k, cases=176, status='PRIOR_REVIEW_ADMITTED' if i < ORDER.index(args.cell) else 'UNRUN') for i, k in enumerate(ORDER)])
    c.write(raw / 'hardware.json', dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(), kernel_release=platform.release(),
            cpu_model=next(s.split(':', 1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')), logical_cpus=os.cpu_count()))
    for p in raw.iterdir():
        freeze(p)
    witness = raw / 'core-witness.tsv'; captures = raw / 'captures'
    commands = ([verifier, original, instructions, target, directory, str(bundle), str(witness)],
                [driver, 'replay-common-core', original, instructions, target, str(bundle), str(witness), str(captures)])
    commands = tuple(argv + extra_arguments for argv in commands)
    fatal, phase, complete, capture_index = None, None, False, None
    try:
        for i, argv in enumerate(commands):
            row = rows[i]; phase = row['name']; d = raw / phase; d.mkdir(); (d / 'tmp').mkdir()
            cpu, wall, file_bytes, outer_s, wait = (20, 30, 16 * MIB, 40, 55) if i == 0 else (60, 90, 64 * MIB, 100, 115)
            request = dict(argv=argv, cwd=str(repo), env=dict(c.ENV, TMPDIR=str(d / 'tmp')), cpu_seconds=cpu, wall_seconds=wall,
                           file_bytes=file_bytes, stdout=str(d / 'stdout.txt'), stderr=str(d / 'stderr.txt'))
            outer = [tools['timeout'], '--signal=TERM', '--kill-after=10s', str(outer_s) + 's', tools['helper_python'], '-B', str(helper), '--request', str(d / 'request.json'), '--receipt', str(d / 'receipt.json')]
            c.write(d / 'request.json', request); c.write(d / 'command.json', dict(request=request, outer_argv=outer, outer_env=c.ENV, cwd=str(repo), parent_timeout_seconds=wait))
            freeze(d / 'request.json'); freeze(d / 'command.json')
            s = snapshot(); c.write(d / 'before.json', s); stable(s)
            row.update(status='FAILED', launched=True, reason='launch or strict closure pending')
            started, code, timeout = time.monotonic(), None, False
            try:
                with (d / 'helper.stdout').open('xb') as out, (d / 'helper.stderr').open('xb') as err:
                    process = subprocess.Popen(outer, cwd=repo, env=c.ENV, stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
                    try:
                        code = process.wait(timeout=wait)
                    except subprocess.TimeoutExpired:
                        timeout = True; os.killpg(process.pid, signal.SIGKILL); code = process.wait()
                    except BaseException:
                        # Allow the existing helper's TERM cleanup on caller
                        # interruption; the same ten-second outer grace applies.
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            code = process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid, signal.SIGKILL); code = process.wait()
                        raise
            finally:
                c.write(d / 'outer.json', dict(exit=code, parent_timeout=timeout, operational_seconds=time.monotonic() - started))
            s = snapshot(); c.write(d / 'after.json', s); stable(s)
            assert not timeout
            receipt = c.receipt(d, request)
            assert code == (0 if receipt['exit'] == 0 else 1)
            terminal = dict(exit=receipt['exit'], wall_timeout=False, absence_proof='ECHILD', descendants=0, success=receipt['exit'] == 0)
            assert read(d / 'helper.stdout')[0] == (json.dumps(terminal) + '\n').encode() and not read(d / 'helper.stderr')[0]
            row.update(strict_closure=True, exit=receipt['exit'], receipt_sha256=c.sha(read(d / 'receipt.json')[0]))
            assert receipt['exit'] == 0 and read(d / 'stdout.txt')[0] == (VERIFY_OUT if i == 0 else PAIR_OUT) and not read(d / 'stderr.txt')[0]
            if i == 0:
                wb = read(witness)[0]; wr = [x.split('\t') for x in wb.decode().splitlines()]
                assert len(wb) <= 16 * MIB and wb.endswith(b'\n') and len(wr) <= 40000
                if RECORDING:
                    assert wr[:2] == [['LI2COMMONCORE', '1'], ['scope', 'STRUCTURAL_CORE_RECORDING_WITNESSES_ONLY']]
                else:
                    assert wr[:2] == [['LI2COMMONCORE', '1'], ['scope', 'STRUCTURAL_CORE_NULL_WITNESSES_ONLY']]
                assert wr[2:8] == [[k, v] for k, v in [('original_sha256', c.sha(originals[variant])), ('instructions_sha256', c.sha(bound(instructions))),
                    ('target_sha256', c.sha(tb)), ('selection_sha256', c.sha(bound(directory + '/selection.txt'))), ('candidate_sha256', c.sha(candidate)), ('qualification_complete', 'false')]]
                files = [r for r in wr if r[0] == 'file']
                assert len(files) == len(bundle_names) and {r[1] for r in files} == set(bundle_names)
                for _, n, length, digest in files:
                    data = bound(str(bundle / n)); assert len(data) == int(length) and c.sha(data) == digest
                assert [list(map(int, r[1:])) for r in wr if r[0] == 'load'] == loads
                assert len([r for r in wr if r[0] == 'head']) == 87 and wr[-1] == ['complete', '87', '174', '2', 'E9_UNIMPLEMENTED_UNRUN']
                if profiled:
                    witness_profiles(wr, profiles)
                freeze(witness); c.write(raw / 'resource-actual.json', resource(len(wb))); freeze(raw / 'resource-actual.json')
                row.update(status='PASS_STRUCTURAL_WITNESS', reason='', witness_sha256=c.sha(wb))
            else:
                names = capture_names(); actual, actual_dirs = {}, set()
                for directory_name, dirs, files in os.walk(captures, followlinks=False):
                    assert all(not (Path(directory_name) / n).is_symlink() for n in dirs + files)
                    actual_dirs |= {str((Path(directory_name) / n).relative_to(captures)) for n in dirs}
                    for n in files:
                        p = Path(directory_name) / n; data, owner = read(p)
                        actual[str(p.relative_to(captures))] = dict(sha256=c.sha(data), bytes=len(data), stat=owner['stat'])
                assert set(actual) == set(names) and read(captures / 'capture-inventory.tsv')[0] == ('\n'.join(names) + '\n').encode()
                assert actual_dirs == {str(p) for n in names for p in Path(n).parents if str(p) != '.'}
                assert read(captures / 'complete.tsv')[0] == COMPLETE
                sizes = dict(regs=216, xstate=2287, data=4096, stack=32888, **{'stack-owned': 65536, 'loads': 151552, 'generated': g})
                for n, owner in actual.items():
                    suffix = n.rsplit('.', 1)[-1]
                    if suffix in sizes:
                        assert owner['bytes'] == sizes[suffix]
                    elif suffix == 'maps':
                        assert 0 < owner['bytes'] <= MIB
                    elif suffix == 'xstate-raw':
                        assert 576 <= owner['bytes'] <= 65536
                assert actual['original-pages.bin']['bytes'] == 151552 and actual['candidate-pages.bin']['bytes'] == 151552 + g
                for n, expected in [('original.elf', originals[variant]), ('instructions.tsv', bound(instructions)), ('runtime-target.tsv', tb), ('core-witness.tsv', read(witness)[0])]:
                    assert read(captures / n)[0] == expected
                c.write(raw / 'capture-files.json', actual)
                capture_index = actual
                row.update(status='PASS_COMMAND_AND_CAPTURE_SCHEMA', reason='', capture_files=8636,
                           content_review_required=True, capture_index_sha256=c.sha(read(raw / 'capture-files.json')[0]))
            c.write(d / 'result.json', row)
            for p in d.iterdir():
                if p.is_file():
                    freeze(p)
            print(phase, row['status'], flush=True)
        complete = True
    except BaseException as error:
        fatal = dict(stage=phase, type=type(error).__name__, message=str(error))
        if phase is not None:
            rows[['verify', 'replay'].index(phase)].update(status='FAILED', reason=repr(error))
    finally:
        stable_end = False
        try:
            s = snapshot(); c.write(raw / 'after.json', s); stable(s); stable_end = True
        except BaseException as error:
            c.write(raw / 'closure-error.json', dict(type=type(error).__name__, message=str(error)))
        for row in rows:
            if row['status'] == 'UNRUN':
                row['reason'] = 'not reached after failed admission, verifier or closure'
        c.write(raw / 'results.json', rows)
        c.write(raw / 'summary.json', dict(schema=1, revision=REVISION, recipe_sha256=c.sha(read(script)[0]), cell=args.cell,
            cases=176, normal_cases=174, fault_cases=2, heads=87, planned_children=352, planned_comparisons=528,
            capture_files=8636 if complete else None, command_capture_schema_complete=complete and stable_end and fatal is None,
            selected_owners_unchanged=stable_end, fatal=fatal, independent_content_review_required=True,
            production_successful=production_summary['successful'], qualification_complete=False, full_a3=False,
            normal_loader_validation=False, E9_pairs='MANDATORY_SEPARATE', recording_pairs='MANDATORY_SEPARATE',
            ordinary_cases=192, parent_closure='Separate caller observation required', operational_timings_not_performance=True,
            **(dict(profiles=profiles, source_binding_sha256=PROFILE_SOURCE_BINDING_SHA) if profiled else {}), **build_extra, **(dict(recording_profile=RECORDING_PROFILE) if RECORDING else {}), **(dict(verifier_capability=VERIFIER_CAPABILITY) if capable else {})))
        index = {}
        for directory_name, dirs, files in os.walk(raw, followlinks=False):
            assert all(not (Path(directory_name) / n).is_symlink() for n in dirs + files)
            for n in files:
                p = Path(directory_name) / n; data, owner = read(p)
                index[str(p.relative_to(raw))] = dict(sha256=c.sha(data), bytes=len(data), stat=owner['stat'])
        if capture_index is not None:
            assert {n[len('captures/'):]: r for n, r in index.items() if n.startswith('captures/')} == capture_index
        c.write(raw / 'raw-files.json', index)
    return 0 if complete and stable_end and fatal is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
