#!/usr/bin/env python3
"""One complete admitted E9-null artifact: bounded witness, then 176 native pairs."""
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

SUPPORT_SHA = '523ce6007068c5764be6bf007d67f8093aaedf4054b1beb3b7465bed95f1196f'
WITNESS_SHA = '562dc107c3aca9fa92a92973934eb01fc852981dd72743168b4701bbed08a081'
TABLE_SHA = '74afc406acb8eb7742695afdf0e610a7e77afbaa6fb1498463a9e8ae85901fcd'
SEED_SHA = 'df1678dc0d0a5eede05d76d592048d5065d983fa44ba42c6d5dd7da9d297c2e3'
LANES = ('stock-algorithm', 'bootstrap-patched-reference')
CELLS = ('null-heap-write-unstripped', 'null-heap-write-stripped',
         'null-jump-site-unstripped', 'null-jump-site-stripped')
ORDER = tuple(cell + '-' + lane for cell in CELLS for lane in LANES)
MIB = 1048576
DENOMINATORS = {'original': 16, 'production': 74, 'ordinary': 192,
                'core_null': 704, 'E9_null': 1408, 'recording_pairs': 2112}
SOURCE_PATHS = ('tests/support/elf_exec_driver.rs', 'tests/support/elf_exec_oracle.rs',
                'tests/support/quiescent_oracle.rs', 'tests/support/e9_common_image.rs',
                'tests/support/e9_common_core_pages.rs', 'tests/support/e9_common_e9.rs',
                'tests/support/e9_common_seed.rs', 'tests/support/e9_common_seed.instructions.tsv',
                'tools/elf-rewrite/e9-null-witness.py', 'tools/elf-rewrite/e9-sites.py',
                'tools/unwind-oracle/bounded_command.py', 'evaluation/e9-common-app/run_candidates.py')
COMPACT = b'target xsave64 743 4:576:256 32:832:64 64:896:512 128:1408:1024 512:2432:8\n'
TARGET = ('LI2TARGET\t1\nos\tlinux\nisa\tx86-64-legacy-evex\ncet\tunqualified\npage_bytes\t4096\nbias_domain\t1\nformat\txsave64-standard\nallocation_bytes\t2496\nimage_bytes\t2440\nxcr0_mask\t743\nqualification_complete\tfalse\n'
          + ''.join('component\t' + x.replace(':', '\t') + '\n' for x in COMPACT.decode().split()[3:])).encode()


def read(p):
    p = Path(p)
    assert p.is_absolute() and '..' not in p.parts and p.parent.resolve(strict=True) == p.parent
    six = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        a = os.fstat(f.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= 128 * MIB
        data = f.read(128 * MIB + 1)
        assert six(a) == six(os.fstat(f.fileno())) == six(p.lstat()) and len(data) == a.st_size
    return data, dict(path=str(p), resolved=str(p.resolve(strict=True)),
                      sha256=hashlib.sha256(data).hexdigest(), stat=six(a))


def host_interpreter(data):
    # Host driver/Python admission only. Subject and candidate ET_EXEC checks are unchanged.
    assert len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', data, 16) in ((2, 62, 1), (3, 62, 1))
    assert struct.unpack_from('<HH', data, 52) == (64, 56)
    off, count = struct.unpack_from('<Q', data, 32)[0], struct.unpack_from('<H', data, 56)[0]
    assert 1 <= count <= 128 and off + 56 * count <= len(data)
    rows = [struct.unpack_from('<IIQQQQQQ', data, off + 56 * i) for i in range(count)]
    selected = [r for r in rows if r[0] == 3]
    assert len(selected) == 1
    r = selected[0]
    assert 1 < r[5] <= 4096 and r[2] + r[5] <= len(data)
    value = data[r[2]:r[2] + r[5]]
    assert value[-1:] == b'\0' and b'\0' not in value[:-1]
    return value[:-1].decode()


def capture_names(expanded):
    assert type(expanded) is list and expanded == sorted(set(expanded)) and len(expanded) <= 12
    assert all(type(i) is int and 0 <= i < 174 for i in expanded)
    names = ['original.elf', 'instructions.tsv', 'runtime-target.tsv', 'e9-witness.json',
             'e9-native.tsv', 'original-pages.bin', 'bundle-inputs.tsv', 'input-owners.tsv',
             'candidate-pages.bin', 'page-plan.tsv', 'planned-cases.tsv', 'capture-inventory.tsv', 'complete.tsv']
    suffixes = ['regs', 'xstate', 'xstate-raw', 'data', 'stack', 'stack-owned', 'loads', 'maps']
    for i in range(176):
        case = f'case-{i:03}'
        names += [case + '/' + n for n in ('pair.tsv', 'witness.tsv')]
        names += [case + '/original/' + n for n in ('seed.tsv', 'complete.tsv')]
        names += [f'{case}/original/{s}.{x}' for s in ('before', 'after') for x in suffixes]
        names += [case + '/candidate/' + n for n in ('trace.tsv', 'complete.tsv')]
        stems = ['before', 'restored', 'after'] + (['operation-00'] if i in expanded else [])
        names += [f'{case}/candidate/{s}.{x}' for s in stems for x in suffixes + ['generated']]
    assert len(names) == len(set(names)) == 8637 + 9 * len(expanded)
    return names


def capture_index(c, root):
    result, directories = {}, set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        assert all(not (Path(directory) / n).is_symlink() for n in dirs + files)
        directories |= {str((Path(directory) / n).relative_to(root)) for n in dirs}
        for name in files:
            p = Path(directory) / name; data, owner = read(p)
            result[str(p.relative_to(root))] = dict(sha256=c.sha(data), bytes=len(data), stat=owner['stat'])
    return result, directories


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
            key,lane=next((k,l) for k in CELLS for l in LANES if k+'-'+l==selected)
            variant=key.rsplit('-',1)[1];style='heap-write' if '-heap-write-' in key else 'jump-site'
            pcs=streams[(variant,dataset['name'],style)]
            assert len(pcs)%8==0 and len(pcs)//8<=16384
            assert bound(str(run/'journal.bin'))==c.journal(pcs)
            assert row['journal_bytes']==131144 and row['journal_sha256']==c.sha(c.journal(pcs))
            assert row['expected_record_count']==len(pcs)//8 and row['expected_pc_stream_sha256']==c.sha(pcs)
            assert row['original_pc_stream_sha256']==c.sha(pcs) and row['original_pc_stream_count']==len(pcs)//8
        else:
            assert bound(str(run / 'journal.bin')) == c.journal(b'')
            assert row['journal_bytes'] == 131144 and row['journal_sha256'] == c.sha(c.journal(b''))
            assert row['expected_record_count'] == 0 and row['expected_pc_stream_sha256'] == c.sha(b'')
    return root, summary, rows


def prior_attempts(c, values, selected, revision, bound):
    assert len(values) == ORDER.index(selected)
    prior = []
    for key, path in zip(ORDER, values):
        a = c.loads(bound(path))
        c.admitted(a, 'CALLER_REVIEWED_E9_PAIR_ATTEMPT', 'closed-whole-artifact-attempt-with-content-review-if-complete', revision, bound)
        assert a['cell'] == key and a['parent_closed_reaped'] is True and a['parent_observation'] in a['evidence_files']
        if RECORDING:
            assert a['recording_profile']==RECORDING_PROFILE
            assert a['recording_source_binding_sha256']==RECORDING_SOURCE_BINDING_SHA
        if a['summary'] is None:
            # Explicit reviewed prelaunch hold, not a fabricated recipe result.
            assert a['status'] == 'UNRUN' and a['reason'] and a['results'] is None
            assert a['content_audit_passed'] is False and a['content_review_binding'] is None
            assert a['capture_index'] is None and a['capture_index_sha256'] is None
            record = c.loads(bound(a['attempt_record']))
            assert record.keys() == {'schema', 'source_revision', 'cell', 'status', 'recipe_launched', 'reason', 'blocking_records'}
            assert record['schema'] == 1 and record['source_revision'] == revision and record['cell'] == key
            assert record['status'] == 'UNRUN' and record['recipe_launched'] is False and record['reason'] == a['reason']
            assert record['blocking_records'] and a['attempt_record'] in a['evidence_files']
            for p in record['blocking_records']:
                assert p in a['evidence_files']; bound(p)
            prior.append(a)
            continue
        assert a['attempt_record'] is None
        summary = c.loads(bound(a['summary'])); rows = c.loads(bound(a['results']))
        assert summary['revision'] == revision and summary['cell'] == key
        assert summary['cases'] == 176 and summary['heads'] == 87 and summary['planned_comparisons'] == 528
        assert [r['name'] for r in rows] == ['verify', 'replay']
        assert summary['qualification_complete'] is False and summary['independent_content_review_required'] is True
        assert a['status'] in ('PASS_CONTENT_REVIEWED', 'FAILED', 'UNRUN') and type(a['reason']) is str
        if summary['command_capture_schema_complete']:
            assert type(a['content_audit_passed']) is bool
            assert a['status'] == ('PASS_CONTENT_REVIEWED' if a['content_audit_passed'] else 'FAILED')
            assert (a['reason'] == '') == a['content_audit_passed']
            assert rows[0]['status'] == 'PASS_STRUCTURAL_WITNESS' and rows[1]['status'] == 'PASS_COMMAND_AND_CAPTURE_SCHEMA'
            assert summary['capture_files'] == 8637 + 9 * summary['call_intermediate_checks']
            assert a['content_review_binding'] in a['evidence_files']
            assert a['capture_index_sha256'] == c.sha(bound(a['capture_index']))
        else:
            assert a['status'] in ('FAILED', 'UNRUN') and a['reason']
            assert a['content_audit_passed'] is False
            assert a['content_review_binding'] is None and a['capture_index_sha256'] is None and a['capture_index'] is None
            assert all(r['status'] in ('UNRUN', 'FAILED', 'PASS_STRUCTURAL_WITNESS', 'PASS_COMMAND_AND_CAPTURE_SCHEMA') for r in rows)
        prior.append(a)
    return prior


def witness_result(c, output, expected_inputs, lane, original, candidate, selection, projection, bound):
    assert {p.name for p in output.iterdir()} == {'witness.json', 'native.tsv', 'sites.tsv', 'files.json'}
    data = {n: read(output / n)[0] for n in ('witness.json', 'native.tsv', 'sites.tsv')}
    index = c.loads(read(output / 'files.json')[0])
    assert index == {n: dict(bytes=len(b), sha256=c.sha(b)) for n, b in data.items()}
    assert all(len(b) <= 16 * MIB for b in data.values())
    report = c.loads(data['witness.json'])
    canonical = json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    assert data['witness.json'] == canonical
    assert data['native.tsv'] == projection(report, data['witness.json'])
    if RECORDING:
        assert report['format']=='LI2COMMONE9-1' and report['scope']=='STRUCTURAL_E9_RECORDING_COMPLETION_WITNESSES_ONLY'
        assert report['recording_profile']==RECORDING_PROFILE
    else:
        assert report['format'] == 'LI2COMMONE9-1' and report['scope'] == 'STRUCTURAL_E9_NULL_COMPLETION_WITNESSES_ONLY'
    assert report['lane'] == lane and report['reader_source_sha256'] == WITNESS_SHA
    assert report['native_admission'] is False and report['qualification_complete'] is False and report['actual_runtime'] is None
    assert (report['required_heads'], report['required_cases']) == (87, 176)
    assert len(report['heads']) == 87 and [h['id'] for h in report['heads']] == list(range(1, 88))
    assert len(report['cases']) == 176 and [r['case'] for r in report['cases']] == list(range(176))
    if RECORDING:
        assert report['inputs'].keys()==expected_inputs.keys() and len(expected_inputs)==24 and 'producer/hook_elf' in expected_inputs
    else:
        assert report['inputs'].keys() == expected_inputs.keys() and len(expected_inputs) == 23
    for role, path in expected_inputs.items():
        value, owner = read(path)
        # Generated caller input was frozen locally; every other role is envelope-bound.
        if role != 'inputs':
            assert value == bound(path)
        assert report['inputs'][role] == dict(path=path, bytes=len(value), sha256=c.sha(value), owner=owner['stat'])
    assert report['original_sha256'] == c.sha(original) and report['candidate_sha256'] == c.sha(candidate)
    assert report['selection_sha256'] == c.sha(selection) and report['instructions_sha256'] == TABLE_SHA
    assert report['source_seed_sha256'] == SEED_SHA and report['target_sha256'] == c.sha(TARGET)
    assert report['selected_site_wire_sha256'] == c.sha(data['sites.tsv'])
    assert report['limits'] == dict(input_bytes=16 * MIB, mapped_pages=2048, prefix_edges=32, operation_edges=2,
                                    existing_native_seconds=15, existing_native_stops=20000)
    rows = [line.split('\t') for line in data['native.tsv'].decode('ascii').splitlines()]
    assert rows[:4] == [['LI2COMMONE9NATIVE', '1'], ['status', report['status']],
                        ['witness_json_sha256', c.sha(data['witness.json'])], ['scope', report['scope']]]
    # Exact pinned projection is rechecked above. This is not an independent
    # semantic validator; native and the saved-content auditor rejoin all rows.
    if not report['witness_complete']:
        assert report['status'] == 'REQUIRED_UNRESOLVED' and (report['unresolved_heads'] or report['global_issues'])
        assert rows[-1] == ['required', '87', '174', '2', 'UNRESOLVED']
        return report, None, None
    assert report['status'] == 'COMPLETE_BYTE_WITNESSES' and not report['unresolved_heads'] and not report['global_issues']
    assert all(h['status'] == 'BYTE_WITNESS_COMPLETE' for h in report['heads'])
    assert all(r['required'] is True and r['status'] == 'BYTE_WITNESS_COMPLETE' for r in report['cases'])
    assert rows[-1] == ['complete', '87', '174', '2']
    expanded = [r['case'] for r in report['cases'] if len(r['operation']) == 2]
    assert all(len(r['operation']) in (1, 2) for r in report['cases'])
    assert len(expanded) <= 12 and all(i < 174 and report['heads'][i // 2]['flow'] == 'Call' for i in expanded)
    assert {i ^ 1 for i in expanded} == set(expanded)
    pages = report['final_pages']; addresses = [p['va'] for p in pages]
    assert addresses == sorted(set(addresses)) and 37 <= len(pages) <= 2048
    assert set(range(0x400000, 0x425000, 4096)) <= set(addresses)
    assert all(p['va'] % 4096 == 0 and p['flags'] in (4, 5, 6) for p in pages)
    g = 4096 * (len(pages) - 37)
    assert 0 <= g <= 2011 * 4096
    return report, expanded, g


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


RECORDING_SOURCE_BINDING_SHA = None


def recording_epoch(inputs,repo):
    if RECORDING_SOURCE_BINDING_SHA is None:
        raise SystemExit('recording source activation requires final reviewed integrated source/build pins')
    b,_=read(inputs['recording_source_binding'])
    assert hashlib.sha256(b).hexdigest()==RECORDING_SOURCE_BINDING_SHA
    value=json.loads(b)
    assert value.keys()=={'schema','revision','prepared_revision','sources'} and type(value['schema']) is int and value['schema']==1
    assert all(type(value[k]) is str and re.fullmatch('[0-9a-f]{40}',value[k]) for k in ('revision','prepared_revision'))
    assert value['sources'].keys()==set(SOURCE_PATHS)
    for name,digest in value['sources'].items():
        assert re.fullmatch('[0-9a-f]{64}',digest) and hashlib.sha256(read(repo/name)[0]).hexdigest()==digest
    return value


def main():
    global RECORDING, CELLS, ORDER, SOURCE_PATHS, SUPPORT_SHA, WITNESS_SHA
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported; assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--cell', choices=ORDER+tuple(k.replace('null-','journal-',1) for k in ORDER), required=True)
    parser.add_argument('--recording-profile', choices=[RECORDING_PROFILE])
    parser.add_argument('--planning-profile',choices=['legacy','owned-foreign-neighbors-v1'],default='legacy')
    parser.add_argument('--raw', type=Path, required=True)
    args = parser.parse_args()
    RECORDING=args.recording_profile is not None
    if RECORDING:
        CELLS=tuple(k.replace('null-','journal-',1) for k in CELLS)
        ORDER=tuple(k+'-'+lane for k in CELLS for lane in LANES)
        SOURCE_PATHS=SOURCE_PATHS+RECORDING_SOURCES
    assert args.cell in ORDER
    assert RECORDING or args.planning_profile=='legacy'
    ib, io = read(args.inputs)
    assert len(ib) <= 16 * MIB and re.fullmatch('[0-9a-f]{64}', args.inputs_sha256)
    assert hashlib.sha256(ib).hexdigest() == args.inputs_sha256
    repo = Path(json.loads(ib)['repo'])
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    recording_activation=None
    if RECORDING:
        recording_activation=recording_epoch(json.loads(ib),repo)
        SUPPORT_SHA=recording_activation['sources']['evaluation/e9-common-app/run_candidates.py']
        WITNESS_SHA=recording_activation['sources']['tools/elf-rewrite/e9-null-witness.py']
    support = repo / 'evaluation/e9-common-app/run_candidates.py'
    assert hashlib.sha256(read(support)[0]).hexdigest() == SUPPORT_SHA
    # Load the exact reviewed whole support module; its main() is not called.
    c = SimpleNamespace(**runpy.run_path(str(support), run_name='e9_pair_admission_support'))
    inputs = c.loads(ib)
    if RECORDING:
        assert inputs.keys() == {'planning_profile', 'recording_profile', 'recording_source_binding', 'schema', 'repo', 'activation', 'source_epoch', 'preparation', 'build_admission',
            'observation_content_admission', 'production_admission', 'ordinary_content_admission', 'cell_admission',
            'prior_cells', 'obligations', 'runtime_admission', 'capacity_admission', 'tools', 'files'}
        assert inputs['recording_profile']==RECORDING_PROFILE
        assert inputs['planning_profile']==args.planning_profile
    else:
        assert inputs.keys() == {'schema', 'repo', 'activation', 'source_epoch', 'preparation', 'build_admission',
            'observation_content_admission', 'production_admission', 'ordinary_content_admission', 'cell_admission',
            'prior_cells', 'obligations', 'runtime_admission', 'capacity_admission', 'tools', 'files'}
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
        load_recording(repo/'evaluation/e9-common-app/recording_pairs.py',lambda p:bound(str(p)))
        assert c.sha(bound(inputs['recording_source_binding']))==RECORDING_SOURCE_BINDING_SHA
    tools = inputs['tools']
    assert tools.keys() == {'python', 'helper_python', 'timeout', 'git'} and tools['git'] == '/usr/bin/git'
    assert str(Path(sys.executable).resolve(strict=True)) == tools['python']
    for p in tools.values():
        bound(p); assert c.path(p).stat().st_mode & 0o111
    tracked = c.source(repo); revision = tracked['revision']
    assert c.loads(bound(inputs['source_epoch'])) == tracked
    if RECORDING:
        assert recording_activation['revision']==revision and recording_activation['prepared_revision']==c.PREPARED
        assert all(tracked['files'][p]['sha256']==digest for p,digest in recording_activation['sources'].items())
    assert all(str(repo / p) in inputs['files'] for p in tracked['files'])
    activation = c.loads(bound(inputs['activation']))
    c.admitted(activation, 'CALLER_REVIEWED_COMMITTED_E9_PAIR_SOURCE', 'exact-reviewed-source-and-runner-activation', revision, bound)
    assert re.fullmatch('[0-9a-f]{40}', activation['source_revision'])
    assert activation['status'] == 'REVIEWED_COMMITTED' and activation['source_files_sha256'] == c.sha(c.encode(tracked['files']))
    assert activation['runner'] == str(script) and activation['runner_sha256'] == c.sha(bound(str(script)))
    assert activation['source_pins'].keys() == set(SOURCE_PATHS)
    assert activation['source_pins'] == {p: tracked['files'][p] for p in SOURCE_PATHS}
    if RECORDING:
        assert activation['recording_profile']==RECORDING_PROFILE
        assert activation['recording_source_binding_sha256']==RECORDING_SOURCE_BINDING_SHA
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    reader = repo / 'tools/elf-rewrite/e9-null-witness.py'; adapter = repo / 'tools/elf-rewrite/e9-sites.py'
    assert c.sha(bound(str(helper))) == c.HELPER_SHA and c.sha(bound(str(reader))) == WITNESS_SHA
    assert c.sha(bound(str(adapter))) == c.ADAPTER_SHA
    assert c.sha(bound(str(repo / 'tests/support/e9_common_seed.rs'))) == SEED_SHA
    assert c.sha(bound(str(repo / 'tests/support/e9_common_seed.instructions.tsv'))) == TABLE_SHA
    projection = runpy.run_path(str(reader), run_name='e9_pair_projection_support')['native_projection']
    prep = inputs['preparation']; ps = c.loads(bound(prep['summary']))
    assert prep.keys() == {'summary', 'source', 'source_after', 'review_binding', 'originals'}
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
    archives = c.loads(bound(str(build_root / 'artifacts.json')))
    driver_sources = archives['native-compile']['selected']['elf-exec-oracle']['source_bindings']
    assert all(driver_sources[p] == tracked['files'][p] for p in SOURCE_PATHS if p.startswith('tests/'))
    cells = c.loads(bound(str(build_root / 'cells.json')))
    inv = c.inventories(cells, originals, products['common_sites'], bound)
    datasets = c.loads(bound(str(repo / 'evaluation/e9-common-app/datasets.json')))['datasets']
    assert [d['name'] for d in datasets] == list(c.DATASETS) and [d['id'] for d in datasets] == list(range(8))
    observation, streams = c.observed_streams(c.loads(bound(inputs['observation_content_admission'])), tracked, build_root, cells, inv, datasets, bound)
    if RECORDING:
        producer, production_summary, production_rows, artifacts = c.production_inputs(
            c.loads(bound(inputs['production_admission'])), tracked, products, inv, originals, bound, args.planning_profile)
    else:
        producer, production_summary, production_rows, artifacts = c.production_inputs(
            c.loads(bound(inputs['production_admission'])), tracked, products, inv, originals, bound)
    ordinary_root, ordinary_summary, ordinary_rows = ordinary(c, c.loads(bound(inputs['ordinary_content_admission'])),
        tracked, repo, inputs['production_admission'], artifacts, args.cell, datasets, bound, streams)
    assert ordinary_summary['production_successful'] == production_summary['successful']
    if RECORDING:
        ordinary_inputs=c.loads(bound(str(ordinary_root/'inputs.json')))
        c.planning_profile(ordinary_inputs,args.planning_profile)
        c.same_build_profile(build,production_summary,ordinary_summary,c.loads(bound(inputs['production_admission'])),c.loads(bound(inputs['ordinary_content_admission'])))
    key, lane = next((k, lane) for k in CELLS for lane in LANES if k + '-' + lane == args.cell)
    variant = key.rsplit('-', 1)[1]; original = prep['originals'][variant]
    directory = inv[key]['directory']; instructions = directory + '/instructions.tsv'
    artifact = artifacts[args.cell]
    assert artifact['eligible'] is True, 'complete actual producer/transport/adapter artifact required'
    candidate = bound(artifact['candidate']); product_dir = producer / key / lane
    envelope_path = str(product_dir / 'envelope.json'); envelope = c.loads(bound(envelope_path))
    if RECORDING:
        assert envelope['lane']==lane and envelope['hook']['symbol']=='li2_e9_record' and len(envelope['files'])==18
        assert 'hook_elf' in envelope['files']
    else:
        assert envelope['lane'] == lane and envelope['hook'] is None and len(envelope['files']) == 17
    assert envelope['files']['original']['path'] == original and envelope['files']['candidate']['path'] == artifact['candidate']
    driver = products['elf-exec-oracle']; assert c.path(driver).stat().st_mode & 0o111
    cell = c.loads(bound(inputs['cell_admission']))
    if RECORDING:
        c.admitted(cell, 'CALLER_ADMITTED_E9_RECORDING_PAIR_INPUTS', 'one-complete-e9-recording-artifact', revision, bound)
        assert cell['recording_profile']==RECORDING_PROFILE
        assert cell['recording_source_binding_sha256']==RECORDING_SOURCE_BINDING_SHA
    else:
        c.admitted(cell, 'CALLER_ADMITTED_E9_NULL_PAIR_INPUTS', 'one-complete-e9-null-artifact', revision, bound)
    assert cell['cell'] == args.cell and cell['eligible'] is True and cell['structural_envelope'] == envelope_path
    assert cell['original'] == original and cell['inventory'] == directory and cell['candidate'] == artifact['candidate']
    for name in ('production_admission', 'ordinary_content_admission', 'observation_content_admission', 'build_admission'):
        assert cell[name + '_sha256'] == c.sha(bound(inputs[name]))
    assert cell['driver_sha256'] == c.sha(bound(driver)) and cell['witness_reader_sha256'] == WITNESS_SHA
    assert cell['candidate_sha256'] == c.sha(candidate)
    if RECORDING:
        assert cell['planning_profile']==args.planning_profile
        c.same_build_profile(build,cell)
    target = cell['target']; tb = bound(target)
    assert tb == TARGET and cell['target_sha256'] == c.sha(tb) and bound(directory + '/target.txt') == COMPACT
    assert bound(instructions) == bound(str(repo / 'tests/support/e9_common_seed.instructions.tsv'))
    prior = prior_attempts(c, inputs['prior_cells'], args.cell, revision, bound)
    assert inputs['obligations'].keys() == DENOMINATORS.keys()
    for key_name, n in DENOMINATORS.items():
        o = inputs['obligations'][key_name]
        assert o.keys() == {'denominator', 'status', 'record'} and o['denominator'] == n
        assert o['status'] in ('UNRUN', 'FAILED', 'PARTIAL', 'CLOSED_REVIEWED')
        if o['record'] is None:
            assert o['status'] == 'UNRUN'
        else:
            bound(o['record'])
    assert inputs['obligations']['original'] == dict(denominator=16, status='CLOSED_REVIEWED', record=inputs['observation_content_admission'])
    assert inputs['obligations']['production'] == dict(denominator=74,
        status='CLOSED_REVIEWED' if production_summary['successful'] else 'FAILED', record=inputs['production_admission'])
    assert inputs['obligations']['ordinary'] == dict(denominator=192,
        status='CLOSED_REVIEWED' if ordinary_summary['ordinary_cases_complete'] else 'FAILED', record=inputs['ordinary_content_admission'])
    runtime = c.loads(bound(inputs['runtime_admission']))
    c.admitted(runtime, 'CALLER_PINNED_PAIR_HOST_RUNTIME_EPOCH', 'selected-host-executable-interpreter-library-cache-owners', revision, bound)
    assert runtime['executables'] == dict(driver=driver, python=tools['python'], helper_python=tools['helper_python'])
    assert '/etc/ld.so.cache' in runtime['owners'] and len(set(runtime['owners'])) == len(runtime['owners']) >= 2
    for p in runtime['owners']:
        bound(p)
    lookups = runtime['interpreter_lookups']
    for p in runtime['executables'].values():
        name = host_interpreter(bound(p))
        assert name in lookups and c.lookup(name) == lookups[name] and lookups[name]['resolved'] in runtime['owners']
    capacity = c.loads(bound(inputs['capacity_admission']))
    assert capacity['schema'] == 1 and capacity['authority'] == 'CALLER_RESERVED_E9_PAIR_RESOURCES'
    assert capacity['source_revision'] == revision and capacity['cell'] == args.cell and capacity['exclusive_slot_writer'] is True
    bound(capacity['observation'])
    assert capacity['slot_cap_bytes'] == 20000000000
    for k in ('slot_used_bytes', 'free_disk_bytes', 'free_memory_bytes'):
        assert type(capacity[k]) is int and capacity[k] >= 0
    expected_inputs = dict(structural_envelope=envelope_path, instructions=instructions, target=target,
                           structural_reader=str(adapter), witness_reader=str(reader))
    expected_inputs.update({'producer/' + k: row['path'] for k, row in envelope['files'].items()})
    if RECORDING:
        assert len(expected_inputs)==23 and 'producer/hook_elf' in expected_inputs
    else:
        assert len(expected_inputs) == 22
    for p in expected_inputs.values():
        assert len(bound(p)) <= 16 * MIB
    def descriptor(p):
        b = bound(p); return dict(path=p, sha256=c.sha(b), bytes=len(b))
    witness_inputs = dict(schema=1, structural_envelope=descriptor(envelope_path),
                          instructions=descriptor(instructions), target=descriptor(target))
    if RECORDING:
        witness_inputs['recording_profile']=RECORDING_PROFILE
    old_roots = [build_root, observation, producer, ordinary_root, Path(prep['summary']).parent]
    old_roots += [Path(a['summary']).parent for a in prior if a['summary'] is not None]
    for old_root in old_roots:
        assert not raw.is_relative_to(old_root) and not old_root.is_relative_to(raw)
    product_names = sorted(p.name for p in product_dir.iterdir())
    def snapshot():
        return dict(owners={p: read(p)[1] for p in sorted(watched)}, source=c.source(repo),
                    interpreter_lookups={n: c.lookup(n) for n in lookups}, product_names=sorted(p.name for p in product_dir.iterdir()),
                    inventory_names={k: sorted(p.name for p in c.path(v['directory']).iterdir()) for k, v in cells.items()})
    def stable(s):
        assert s['owners'] == watched and s['source'] == tracked and s['interpreter_lookups'] == lookups and s['product_names'] == product_names
        assert all(names == sorted(c.INVENTORY_FILES) for names in s['inventory_names'].values())
    def freeze(p):
        owner = read(p)[1]
        if str(p) in watched:
            assert watched[str(p)] == owner
        watched[str(p)] = owner
    before = snapshot(); stable(before)
    metadata = 12 * (len(c.encode(before)) + 65536) + 8 * len(ib) + 16 * MIB + 9000 * (len(str(raw)) + 256)
    payload = sum(len(bound(p)) for p in expected_inputs.values())
    def resource(g, expanded, witness_bytes):
        # 37 LOAD pages + array + 27 registers + fixed and whole owned stack.
        snapshots = 880 + expanded
        growth = (64 * MIB + metadata if g is None else
                  snapshots * (254288 + 2287 + 65536 + MIB) + (529 + expanded) * g + 2 * witness_bytes + 64 * MIB + metadata)
        reserve = 64 * MIB if g is None else 512 * MIB
        if RECORDING:
            growth += recording.TRACE_RESERVE
        disk = growth + reserve
        memory = 2 * (payload + witness_bytes + 4 * (2011 * 4096 if g is None else g) + 32 * MIB + 237568)
        if RECORDING:
            memory += recording.TRACE_LIVE
        assert capacity['slot_used_bytes'] + disk <= capacity['slot_cap_bytes'] and capacity['free_disk_bytes'] >= disk
        assert capacity['free_memory_bytes'] >= memory
        fs = os.statvfs(raw.parent); assert fs.f_bavail * fs.f_frsize >= disk
        return dict(added_page_bytes=g, expanded_call_cases=expanded if g is not None else None,
                    snapshots=snapshots if g is not None else None, input_payload_bytes=payload,
                    witness_bytes=witness_bytes, metadata_bound_bytes=metadata, logical_growth_bound_bytes=growth,
                    required_growth_bytes=disk, live_payload_allowance_bytes=memory, allocation_reserve_bytes=reserve,
                    canonical_xstate_bytes=2287, raw_xstate_max_bytes=65536, maps_max_bytes=MIB,
                    rss_enforced=False, arbitrary_failure_disk_guarantee=False,
                    **(dict(recording_trace_reserve_bytes=recording.TRACE_RESERVE,recording_live_reserve_bytes=recording.TRACE_LIVE) if RECORDING else {}))
    estimate = resource(None, 12, 48 * MIB)
    raw.mkdir(mode=0o700)
    rows = [dict(name=n, status='UNRUN', launched=False, strict_closure=False, reason='not yet launched') for n in ('verify', 'replay')]
    c.write(raw / 'inputs.json', ib); c.write(raw / 'source.json', tracked); c.write(raw / 'before.json', before)
    c.write(raw / 'resource-before.json', estimate)
    c.write(raw / 'production-status.json', dict(summary=production_summary, stages=production_rows))
    c.write(raw / 'ordinary-status.json', dict(summary=ordinary_summary, cases=ordinary_rows))
    c.write(raw / 'prior-cells.json', prior); c.write(raw / 'obligations.json', inputs['obligations'])
    c.write(raw / 'stage-inventory.json', ['verify', 'replay'])
    c.write(raw / 'cell-plan.json', [dict(cell=k, cases=176, status=prior[i]['status'] if i < len(prior) else 'UNRUN',
        reason=prior[i]['reason'] if i < len(prior) else 'not yet completed') for i, k in enumerate(ORDER)])
    c.write(raw / 'hardware.json', dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(), kernel_release=platform.release(),
            cpu_model=next(s.split(':', 1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')), logical_cpus=os.cpu_count()))
    c.write(raw / 'witness-inputs.json', witness_inputs)
    expected_inputs['inputs'] = str(raw / 'witness-inputs.json')
    for p in raw.iterdir():
        freeze(p)
    witness = raw / 'witness'; captures = raw / 'captures'
    commands = ([tools['python'], '-B', str(reader), str(raw / 'witness-inputs.json'), str(witness),
                 '--inputs-sha256', c.sha(read(raw / 'witness-inputs.json')[0]), '--structural-reader', str(adapter)],
                [driver, 'replay-common-e9', original, instructions, target, str(witness / 'witness.json'), str(witness / 'native.tsv'), str(captures)])
    if RECORDING:
        commands=tuple(argv+[RECORDING_FLAG] for argv in commands)
    fatal, phase, complete, captured, expanded, g = None, None, False, None, None, None
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
            assert not read(d / 'stderr.txt')[0]
            if i == 0:
                assert receipt['exit'] in (0, 2)
                report, expanded, g = witness_result(c, witness, expected_inputs, lane, originals[variant], candidate,
                                                    bound(directory + '/selection.txt'), projection, bound)
                if RECORDING:
                    assert read(d / 'stdout.txt')[0] == ('E9 recording witnesses: 87 required heads; 176 required cases; ' + report['status'] + '\n').encode()
                else:
                    assert read(d / 'stdout.txt')[0] == ('E9 null witnesses: 87 required heads; 176 required cases; ' + report['status'] + '\n').encode()
                assert receipt['exit'] == (0 if report['witness_complete'] else 2)
                row.update(witness_status=report['status'], witness_sha256=c.sha(read(witness / 'witness.json')[0]),
                           native_tsv_sha256=c.sha(read(witness / 'native.tsv')[0]))
                for p in witness.iterdir():
                    freeze(p)
                assert report['witness_complete'], 'required witness unresolved; native replay remains UNRUN'
                assert read(witness / 'sites.tsv')[0] == bound(str(product_dir / 'inventory/sites.tsv'))
                structural = c.loads(bound(str(product_dir / 'inventory/producer-binding.json')))
                assert report['structural'] == {k: v for k, v in structural.items() if k not in ('envelope_sha256', 'input_files', 'input_owners')}
                c.write(raw / 'resource-actual.json', resource(g, len(expanded), sum(p.stat().st_size for p in witness.iterdir())))
                c.write(raw / 'expected-captures.tsv', ('\n'.join(capture_names(expanded)) + '\n').encode())
                freeze(raw / 'resource-actual.json'); freeze(raw / 'expected-captures.tsv')
                row.update(status='PASS_STRUCTURAL_WITNESS', reason='', call_intermediate_checks=len(expanded), added_page_bytes=g)
            else:
                e = len(expanded); names = capture_names(expanded)
                assert receipt['exit'] == 0
                if RECORDING:
                    assert read(d / 'stdout.txt')[0] == f'E9 recording pairs complete: heads=87 normal=174 faults=2 comparisons=528 call_intermediates={e} files={len(names)} qualification_complete=false\n'.encode()
                else:
                    assert read(d / 'stdout.txt')[0] == f'E9 null pairs complete: heads=87 normal=174 faults=2 comparisons=528 call_intermediates={e} files={len(names)} qualification_complete=false\n'.encode()
                captured, dirs = capture_index(c, captures)
                assert set(captured) == set(names) and read(captures / 'capture-inventory.tsv')[0] == ('\n'.join(names) + '\n').encode()
                assert dirs == {str(p) for n in names for p in Path(n).parents if str(p) != '.'}
                expected_complete = (f'LI2COMMONE9PAIRS\t1\nheads\t87\nnormal_pairs\t174\nfault_pairs\t2\nchildren\t352\ncomparisons\t528\ncall_intermediate_checks\t{e}\nsnapshots\t{880+e}\nfiles\t{len(names)}\nrecording_hooks\tUNIMPLEMENTED_UNRUN\nnormal_loader_validation\tfalse\nqualification_complete\tfalse\n').encode()
                if RECORDING:
                    expected_complete=expected_complete.replace(b'LI2COMMONE9PAIRS',b'LI2COMMONE9RECORDINGPAIRS').replace(b'recording_hooks\tUNIMPLEMENTED_UNRUN',b'recording_profile\tbounded-journal-v1')
                assert read(captures / 'complete.tsv')[0] == expected_complete
                sizes = dict(regs=216, xstate=2287, data=4096, stack=32888, **{'stack-owned': 65536, 'loads': 151552, 'generated': g})
                for n, owner in captured.items():
                    suffix = n.rsplit('.', 1)[-1]
                    if suffix in sizes:
                        assert owner['bytes'] == sizes[suffix]
                    elif suffix == 'maps':
                        assert 0 < owner['bytes'] <= MIB
                    elif suffix == 'xstate-raw':
                        assert 576 <= owner['bytes'] <= 65536
                assert captured['original-pages.bin']['bytes'] == 151552 and captured['candidate-pages.bin']['bytes'] == 151552 + g
                for n, expected in [('original.elf', originals[variant]), ('instructions.tsv', bound(instructions)), ('runtime-target.tsv', tb),
                    ('e9-witness.json', read(witness / 'witness.json')[0]), ('e9-native.tsv', read(witness / 'native.tsv')[0])]:
                    assert read(captures / n)[0] == expected
                c.write(raw / 'capture-files.json', captured)
                row.update(status='PASS_COMMAND_AND_CAPTURE_SCHEMA', reason='', capture_files=len(names), call_intermediate_checks=e,
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
            s = snapshot(); c.write(raw / 'after.json', s); stable(s)
            c.write(raw / 'source-after.json', s['source']); stable_end = True
        except BaseException as error:
            c.write(raw / 'closure-error.json', dict(type=type(error).__name__, message=str(error)))
        for row in rows:
            if row['status'] == 'UNRUN':
                row['reason'] = 'not reached after failed admission, witness or closure'
            if row['launched'] and not (raw / row['name'] / 'result.json').exists():
                c.write(raw / row['name'] / 'result.json', row)
        c.write(raw / 'results.json', rows)
        c.write(raw / 'summary.json', dict(schema=1, revision=revision, recipe_sha256=c.sha(read(script)[0]), cell=args.cell,
            cases=176, normal_cases=174, fault_cases=2, heads=87, planned_children=352, planned_comparisons=528,
            call_intermediate_checks=len(expanded) if expanded is not None else None,
            snapshots=880+len(expanded) if complete else None, capture_files=len(captured) if complete else None,
            command_capture_schema_complete=complete and stable_end and fatal is None,
            selected_owners_unchanged=stable_end, fatal=fatal, independent_content_review_required=True,
            production_successful=production_summary['successful'], ordinary_cases_complete=ordinary_summary['ordinary_cases_complete'],
            qualification_complete=False, full_a3=False, normal_loader_validation=False,
            core_pairs='MANDATORY_SEPARATE', recording_pairs='MANDATORY_SEPARATE',
            ordinary_cases=192, parent_closure='Separate caller observation required', operational_timings_not_performance=True,
            **(dict(recording_profile=RECORDING_PROFILE,recording_source_binding_sha256=RECORDING_SOURCE_BINDING_SHA,planning_profile=args.planning_profile,**({} if 'build_profile' not in build else dict(build_profile=c.DEBUG0_BUILD_PROFILE))) if RECORDING else {})))
        index, _ = capture_index(c, raw)
        if complete:
            assert {n[len('captures/'):]: r for n, r in index.items() if n.startswith('captures/')} == captured
        c.write(raw / 'raw-files.json', index)
    return 0 if complete and stable_end and fatal is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
