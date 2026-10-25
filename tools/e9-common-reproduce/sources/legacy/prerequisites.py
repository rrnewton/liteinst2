#!/usr/bin/env python3
"""Read-only completion gates for the corrected six; never launches a process."""
import hashlib
import math
import os
from pathlib import Path
import stat
import sys

if sys.flags.optimize:
    raise SystemExit('optimized Python disables prerequisite checks')
from audit import CASE_IDS, authenticate_case, loads

MAX_BINDING_FILE = 256 * 1024 * 1024
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
EMISSION_SHA = 'c424ddce366fdc8357d06909aadcf67f92bcfe604688243ac8ae8ab7d7b0b025'
NATIVE_SHA = '0b79ff3785992ad715aa069a79d8fd4416caf1f3936fc87451caa167e50551e5'
STATE_SHA = 'e9dcca5b52151ec96f99614237dc222cb69e25b013bf487434e6b7c99ee52a83'
COHORT_SHA = '95db4f471262643ca658019dc2f76bc015259eb73cd2c32b9761952483668fd2'
SELECTED_SHA = '9585334f9b767fff93bac9e8488658522123d798ee5df9089ea0797843c46043'
EMITTED_SHA = '36e95f821568d1dca758932836df9080dff46e5b70278d540ebe4de9a0d2ab5f'
INPUT_FREEZE_SHA = 'd5cf602f62f387a0eaa93ad291106050e858d540c5d16ba16be28c05f5d2d1a2'
TOTALS = dict(traces=144, points=360, hook_witnesses=24, file_pages=816)


def hash_file(path):
    path = Path(path)
    assert path.is_absolute() and not path.is_symlink()
    before = path.stat()
    assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= MAX_BINDING_FILE
    h = hashlib.sha256()
    size = 0
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            size += len(chunk)
            assert size <= MAX_BINDING_FILE
            h.update(chunk)
    after = path.stat()
    assert size == before.st_size == after.st_size
    assert (before.st_dev, before.st_ino, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_mtime_ns)
    return h.hexdigest()


def require_gate_summary(summary):
    expected = dict(status='FRESH_CORRECTED_CORE_EMISSION_NATIVE_STATE_COMPLETE',
        original_cohort_sha256=COHORT_SHA, selected_manifest_sha256=SELECTED_SHA,
        emitted_cohort_sha256=EMITTED_SHA, emitted_B1=6, refused=0,
        original_baselines=4, rewritten_native=36, state_totals=TOTALS,
        state_phases=[48, 48, 48], captured_files=2642, captured_directories=702,
        qualification_complete=False, backend_ABI_defect_resolved=False,
        E9_native_enabled=False)
    def exact(actual, required):
        assert type(actual) is type(required)
        if isinstance(required, dict):
            assert actual.keys() == required.keys()
            for key in required:
                exact(actual[key], required[key])
        elif isinstance(required, list):
            assert len(actual) == len(required)
            for left, right in zip(actual, required):
                exact(left, right)
        else:
            assert actual == required
    exact(summary, expected)
    return True


def validate(root, pins):
    """Require actual fresh completions before producing any runnable manifest."""
    root = Path(root).resolve()
    join = root / 'ignored/a3/corrected-core-join-v1'
    state = join / 'state-binding-v2'
    # A missing/failed/uncompleted state gate is an unconditional refusal.
    assert (state / 'audit/complete.json').is_file(), 'fresh corrected state audit is not complete'
    snapshot = {}

    def bind(path, expected=None):
        path = Path(path)
        actual = hash_file(path)
        if expected is not None:
            assert actual == expected, str(path)
        if str(path) in snapshot:
            assert snapshot[str(path)] == actual
        snapshot[str(path)] = actual
        return actual

    def obj(path, expected=None):
        bind(path, expected)
        assert Path(path).stat().st_size <= 16 * 1024 * 1024
        return loads(Path(path).read_bytes())

    for path, expected in pins.items():
        bind(Path(path), expected)
    emission = obj(join / 'emission/run/emitted-cohort.json', EMITTED_SHA)
    assert emission['status'] == 'NEW_SIX_CORE_ARTIFACTS_STRUCTURALLY_CHECKED_NATIVE_AND_STATE_PENDING'
    assert emission['source_manifest_sha256'] == EMISSION_SHA
    assert emission['original_cohort_sha256'] == COHORT_SHA
    assert emission['emitted_B1'] == 6 and emission['refused'] == 0
    assert emission['qualification_complete'] is False
    assert emission['native_baselines'] == emission['native_rewritten'] == emission['state_traces'] == 0
    assert [row['input']['id'] for row in emission['records']] == CASE_IDS
    declared = obj(join / 'e9-design/prospective-manifest.json')
    assert declared['input_cohort_sha256'] == COHORT_SHA
    assert declared['selected_manifest_sha256'] == SELECTED_SHA
    assert [row['id'] for row in declared['cases']] == CASE_IDS
    cases = []
    for row, requested in zip(emission['records'], declared['cases']):
        facts, result = row['input'], row['result']
        for key in ('id', 'label', 'name', 'input', 'input_sha256', 'pc', 'file_offset', 'hook', 'value', 'symbol', 'selected_id', 'init'):
            assert facts[key] == requested[key], key
        assert requested['instruction_length'] == 5 and requested['required_tactic'] == 'B1' and requested['required_patch_count'] == 1
        assert row['candidate'] == requested['planned_core_output']
        assert result == obj(Path(row['audit']), row['audit_sha256'])
        assert result['candidate_complete'] is True and result['qualification_complete'] is False
        assert result['corrected_input_sha256'] == facts['input_sha256']
        bind(Path(facts['input']), facts['input_sha256'])
        bind(Path(row['candidate']), result['candidate_sha256'])
        output = Path(row['candidate']).parent
        assert {p.name for p in output.iterdir()} == result['files'].keys()
        for name, expected in result['files'].items():
            assert Path(name).name == name
            bind(output / name, expected)
        case = dict(facts, core_output=row['candidate'], core_output_sha256=result['candidate_sha256'])
        authenticate_case(case)
        cases.append(case)

    def helper(directory, name, expected_request):
        request_path = directory / (name + '.request.json')
        receipt_path = directory / (name + '.receipt.json')
        request = obj(request_path)
        assert request == expected_request
        receipt = obj(receipt_path)
        assert receipt.keys() == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout',
            'unexpected_descendants', 'absence_proof', 'stdout_sha256', 'stderr_sha256',
            'elapsed_seconds', 'cleanup_events', 'cleanup_error', 'aborted', 'inputs_unchanged'}
        assert receipt['request_sha256'] == bind(request_path)
        assert receipt['helper_sha256'] == HELPER_SHA
        assert type(receipt['exit']) is int and receipt['exit'] == 0
        assert receipt['wall_timeout'] is False and receipt['aborted'] is None
        assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['absence_proof'] == 'ECHILD' and receipt['cleanup_error'] is None
        assert receipt['inputs_unchanged'] is True
        elapsed = receipt['elapsed_seconds']
        assert type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= request['wall_seconds'] + 5
        bind(Path(request['stdout']), receipt['stdout_sha256'])
        bind(Path(request['stderr']), receipt['stderr_sha256'])
        return receipt

    native = obj(join / 'native/run/complete.json')
    assert native['status'] == 'FRESH_CORRECTED_COHORT_4_PLUS_36_PASS'
    assert native['source_manifest_sha256'] == NATIVE_SHA and native['qualification_complete'] is False
    assert (native['original_baselines'], native['rewritten_native'], native['state_traces']) == (4, 36, 0)
    ids = []
    for label in ('unstripped', 'stripped'):
        ids += ['baseline-' + label + '-' + name for name in ('pie', 'exec')]
        ids += [f'native-{label}-{mode}-{name}-{repeat}' for mode in ('both', 'main-only', 'library-only')
            for name in ('pie', 'exec') for repeat in range(3)]
    assert [row['case'] for row in native['reports']] == ids and len(ids) == 40
    plan = obj(join / 'native/run/plan.json')
    assert plan['emitted_cohort_sha256'] == EMITTED_SHA and plan['source_manifest_sha256'] == NATIVE_SHA
    assert [row['id'] for row in plan['cases']] == ids
    by_id = {case['id']: case for case in cases}
    for report, planned in zip(native['reports'], plan['cases']):
        assert report == obj(Path(planned['audit']))
        assert report['qualification_complete'] is False
        assert report['baseline'] is planned['baseline'] and report['baseline'] == planned['id'].startswith('baseline-')
        assert report['request_sha256'] == planned['request_sha256']
        assert report['receipt_sha256'] == bind(Path(planned['receipt']))
        assert report['plan_sha256'] == bind(join / 'native/run/plan.json')
        req = obj(Path(planned['request']), planned['request_sha256'])
        # Native join uses request.json/receipt.json, not phase-name prefixes.
        receipt = obj(Path(planned['receipt']))
        assert receipt['exit'] == 0 and type(receipt['exit']) is int
        assert receipt['request_sha256'] == planned['request_sha256'] and receipt['helper_sha256'] == HELPER_SHA
        assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['wall_timeout'] is False and receipt['aborted'] is None and receipt['cleanup_error'] is None and receipt['inputs_unchanged'] is True
        bind(Path(req['stdout']), receipt['stdout_sha256']); bind(Path(req['stderr']), receipt['stderr_sha256'])
        assert Path(req['stdout']).read_bytes() == bytes.fromhex('63617272696572206d6978206f6b0a00') and Path(req['stderr']).read_bytes() == b''
        assert report['files'] == planned['files']
        for f in report['files']:
            expected = by_id[f['input_id']]
            assert f['source'] == expected['core_output' if f['changed'] else 'input']
            assert f['sha256'] == expected['core_output_sha256' if f['changed'] else 'input_sha256']
            bind(Path(f['path']), f['sha256']); bind(Path(f['source']), f['sha256'])
    native_root = obj(join / 'native/root-execution-v1/root-audit.json')
    assert native_root['status'] == 'PASS_FOUR_BASELINES_36_REWRITTEN_LOADER_EXECUTIONS'
    assert native_root['baselines'] == 4 and native_root['rewritten'] == 36 and native_root['full_A3_complete'] is False
    assert native_root['source_manifest_sha256'] == NATIVE_SHA
    for path, expected in native_root['files'].items():
        relative = Path(path)
        assert not relative.is_absolute() and '..' not in relative.parts
        bind(join / 'native/run' / relative, expected)

    source = obj(state / 'manifest.json', STATE_SHA)
    assert source['status'] == 'SOURCE_ONLY_RECIPE_NO_EXECUTION'
    for rel, expected in source['source_sha256'].items():
        bind(state / rel, expected)
    for path, expected in source['external_sha256'].items():
        bind(Path(path), expected)
    binary = obj(state / 'build/binary.json')
    assert binary['status'] == 'FRESH_BINARY_REQUIRES_INDEPENDENT_NATIVE_BINDING_REVIEW'
    assert binary['source_manifest_sha256'] == STATE_SHA and binary['input_freeze_sha256'] == INPUT_FREEZE_SHA
    assert binary['path'] == str(state / 'build/oracle')
    bind(Path(binary['path']), binary['sha256'])
    for name, expected in binary['build_receipts'].items():
        assert Path(name).name == name
        bind(state / 'build' / name, expected)
    inventory = obj(join / 'state/run/input-inventory.json')
    assert inventory['prior_structural_receipt_sha256'] == EMITTED_SHA and inventory['selected_manifest_sha256'] == SELECTED_SHA
    assert inventory['required_traces'] == [48, 48, 48]
    assert inventory['required_points'] == 360 and inventory['required_hook_witnesses'] == 24 and inventory['expected_file_pages'] == 816
    assert [item['name'] for item in inventory['fixtures']] == CASE_IDS
    for item, case in zip(inventory['fixtures'], cases):
        assert (item['original_path'], item['original_sha256'], item['output_path'], item['output_sha256']) == (case['input'], case['input_sha256'], case['core_output'], case['core_output_sha256'])
        assert (item['source_pc'], item['source_file_offset'], item['hook_pc']) == (case['pc'], case['file_offset'], case['hook'])
    terminals = []
    for phase in ('native', 'audit'):
        directory = state / phase
        terminal = obj(directory / 'complete.json')
        assert terminal['status'] == ('NATIVE_FINISHED_CAPTURE_AUDIT_PENDING' if phase == 'native' else 'ACTUAL_NEW_ELF_STATE_PASS_MANUAL_LOAD_QUALIFICATION_INCOMPLETE')
        assert terminal['source_manifest_sha256'] == STATE_SHA and terminal['binary_binding_sha256'] == bind(state / 'build/binary.json')
        assert terminal['qualification_complete'] is False
        assert {p.name for p in directory.iterdir() if p.is_file()} == terminal['files'].keys() | {'complete.json'}
        for name, expected in terminal['files'].items():
            assert Path(name).name == name
            bind(directory / name, expected)
        request = binary[phase + '_request']
        assert request['cpu_seconds'] == (60 if phase == 'native' else 20)
        assert request['wall_seconds'] == (90 if phase == 'native' else 30) and request['file_bytes'] == 16 * 1024 * 1024
        assert request['argv'] == ([binary['path'], str(state / 'native/captures')] if phase == 'native' else
            [source['python']['path'], str(join / 'state/run/audit.py'), str(state / 'native/captures'), str(state / 'audit/capture-audit.json')])
        helper(directory, phase, request)
        outer = obj(directory / (phase + '.outer-receipt.json'))
        assert outer['helper_exit'] == 0 and outer['aborted'] is None
        assert outer['helper_watchdog_timeout'] is False and outer['grace_timeout'] is False
        assert outer['outer_unexpected_descendants'] == [] and outer['outer_absence_proof'] == 'ECHILD'
        assert outer['outer_cleanup_error'] is None and outer['authentication_error'] is None
        assert outer['request_sha256'] == bind(directory / (phase + '.request.json'))
        assert outer['receipt_sha256'] == bind(directory / (phase + '.receipt.json'))
        assert Path(request['stderr']).read_bytes() == b''
        terminals.append(terminal)
    assert (state / 'native/native.stdout').read_text() == source['expected_native_stdout']
    capture_audit = obj(state / 'audit/capture-audit.json')
    assert capture_audit['status'] == 'EXACT_CAPTURE_AUDIT_PASS' and capture_audit['totals'] == TOTALS
    assert capture_audit['source_inventory_sha256'] == bind(join / 'state/run/input-inventory.json')
    assert capture_audit['manual_fixture_load'] is True and capture_audit['loader_admission'] is False and capture_audit['qualification_complete'] is False
    assert terminals[0]['captured_sha256'] == terminals[1]['captured_sha256'] == capture_audit['captured_sha256']
    captures = state / 'native/captures'
    pending, files, directories, entries = [captures], {}, 0, 0
    while pending:
        directory = pending.pop()
        assert directory.is_dir() and not directory.is_symlink()
        with os.scandir(directory) as children:
            for child in children:
                entries += 1; assert entries <= 3344
                path = Path(child.path); mode = child.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    directories += 1; pending.append(path)
                else:
                    assert stat.S_ISREG(mode)
                    files[str(path.relative_to(captures))] = bind(path)
    assert len(files) == 2642 and directories == 702 and entries == 3344
    assert files == capture_audit['captured_sha256']
    summary = dict(status='FRESH_CORRECTED_CORE_EMISSION_NATIVE_STATE_COMPLETE',
        original_cohort_sha256=COHORT_SHA, selected_manifest_sha256=SELECTED_SHA,
        emitted_cohort_sha256=EMITTED_SHA, emitted_B1=6, refused=0,
        original_baselines=4, rewritten_native=36, state_totals=TOTALS,
        state_phases=[48, 48, 48], captured_files=2642, captured_directories=702,
        qualification_complete=False, backend_ABI_defect_resolved=False, E9_native_enabled=False)
    require_gate_summary(summary)
    # Close the read interval: every byte authenticated above must remain exact.
    for path, expected in snapshot.items():
        assert hash_file(Path(path)) == expected, path
    return cases, summary, snapshot
