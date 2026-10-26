"""Read-only capture auditor. No subprocesses, loading, publication or retries."""
import sys
if sys.flags.optimize:
    raise SystemExit('optimized Python is forbidden')
import argparse
from collections import Counter
import json
import math
import os
from pathlib import Path
import re
from guard import HERE, read, sha, verify, verify_records
from backing_records import backing_records

SUMMARY = re.compile(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$', re.M)
HELPER_STDOUT = b'{"exit": 0, "wall_timeout": false, "absence_proof": "ECHILD", "descendants": 0, "success": true}\n'
CAPTURE_FILES = {'after.maps', 'after.threads.txt', 'before.maps', 'before.threads.txt',
                 'complete.txt', 'declared-bounds.txt', 'parent-result.txt', 'stderr.txt', 'stdout.txt'}


def summaries(text):
    rows = SUMMARY.findall(text)
    assert rows and len(re.findall(r'^test result:', text, re.M)) == len(rows)
    for row in rows:
        assert math.isfinite(float(row[5])) and float(row[5]) >= 0
    return [tuple(map(int, row[:5])) for row in rows]


def result_names(text, expected, panics=()):
    rows = re.findall(r'^test ([A-Za-z0-9_:]+)( - should panic)? \.\.\. ok$', text, re.M)
    assert len(rows) == len(expected)
    assert Counter(name for name, _ in rows) == Counter(expected)
    assert {name for name, tag in rows if tag} == set(panics)


def capture_maps(path, image, backing):
    data = path.read_text()
    assert len(data) < 2 * 1024 * 1024
    matching = []
    for line in data.splitlines():
        fields = line.split()
        assert len(fields) >= 5
        if len(fields) != 6 or fields[5] != image['resolved']:
            continue
        left, right = (int(v, 16) for v in fields[0].split('-'))
        major, minor = (int(v, 16) for v in fields[3].split(':'))
        assert (major, minor, int(fields[4])) == backing
        matching.append((left, right, fields[1], int(fields[2], 16)))
    assert matching
    bases = set()
    for segment in image['elf']['loads']:
        if segment['flags'] & 1 == 0:
            continue
        assert segment['flags'] == 5 and segment['file_size'] > 0
        pieces = []
        for left, right, permissions, offset in matching:
            first = max(offset, segment['file_offset'])
            last = min(offset + right - left, segment['file_offset'] + segment['file_size'])
            if first < last:
                assert permissions == 'r-xp'
                bases.add(left + segment['file_offset'] - offset - segment['virtual_address'])
                pieces.append((first, last))
        next_byte = segment['file_offset']
        for first, last in sorted(pieces):
            assert first == next_byte, 'missing or multiply owned executable bytes'
            next_byte = last
        assert next_byte == segment['file_offset'] + segment['file_size']
    assert len(bases) == 1
    return next(iter(bases))


def capture(step, inputs, expected):
    request = read(step['request'])
    top = Path(request['env']['LITEINST_UNWIND_CONSUMER_MAIN_THREAD_CAPTURES'])
    assert top.is_dir() and not top.is_symlink()
    entries = list(top.iterdir())
    assert len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink()
    folder = entries[0]
    assert re.fullmatch(r'[1-9][0-9]*-' + re.escape(step['cohort']), folder.name)
    assert {p.name for p in folder.iterdir()} == CAPTURE_FILES
    assert all(p.is_file() and not p.is_symlink() for p in folder.iterdir())
    assert (folder / 'stdout.txt').read_bytes() == b''
    assert (folder / 'declared-bounds.txt').read_text() == 'cpu=20\nwall=30\ntrace_wall=15\ntrace_steps=20000\n'
    assert (folder / 'complete.txt').read_text() == 'completed-cohort:' + step['cohort'] + '\n'
    driver = inputs['binary']['consumer-main']['path']
    assert (folder / 'parent-result.txt').read_text() == (
        f"cohort={step['cohort']}\ndriver={driver}\ncpu_seconds=20\nwall_seconds=30\n"
        'peek=Some(Exit { code: 1, status: 0 })\nseen_peers={}\npeer_reaps=[]\n'
        'direct_reap=Some(0)\ncleanup_error=None\nleader_reaped_last=true\n')
    text = (folder / 'stderr.txt').read_text()
    assert len(inputs['interpreters']) == 1
    interpreter = next(iter(inputs['interpreters'].values()))
    images = dict(main=inputs['binary']['consumer-main'], interpreter=interpreter, libgcc=inputs['libgcc'])
    validation_count = 2 if step['kind'] == 'postwrite-negative' else 3
    backing = backing_records(text, images, validation_count)
    census = []
    for phase in ('before', 'after'):
        raw = (folder / (phase + '.threads.txt')).read_text()
        found = re.fullmatch(r'pid=([1-9][0-9]*)\ntid=([1-9][0-9]*)\ncount=1\ntasks=\["([1-9][0-9]*)"\]\n', raw)
        assert found and len(set(found.groups())) == 1
        census.append(found.group(1))
        capture_maps(folder / (phase + '.maps'), inputs['binary']['consumer-main'], backing['main'])
        for image in inputs['interpreters'].values():
            capture_maps(folder / (phase + '.maps'), image, backing['interpreter'])
        base = capture_maps(folder / (phase + '.maps'), inputs['libgcc'], backing['libgcc'])
        if phase == 'before':
            consumer_base = base
        else:
            assert base == consumer_base
    assert census[0] == census[1]
    text = (folder / 'stderr.txt').read_text()
    identity = re.findall(r'^consumer_identity path=(\S+) base=(0x[0-9a-f]+) bytes=(\d+) exported_symbols=6 executable_segments=(\d+) file_mapping_bytes_exact=true$', text, re.M)
    assert identity
    assert len(identity) == validation_count
    segments = sum(bool(s['flags'] & 1) for s in inputs['libgcc']['elf']['loads'])
    for path, base, size, count in identity:
        assert (path, int(base, 16), int(size), int(count)) == (inputs['libgcc']['resolved'], consumer_base, inputs['libgcc']['size'], segments)
    profile = 'frame-pointer' if step['cohort'].endswith('frame-pointer') else 'frameless'
    if step['kind'] == 'postwrite-negative':
        marker = 'required_keep_gated source_written=true lease_poisoned=true code_cfi_source_retained=true no_subject_reentry=true'
        assert text.splitlines().count(marker) == 1 and not re.search(r'^profile=', text, re.M)
    else:
        positive = step['kind'] == 'positive'
        marker = f'profile={profile} subjects=6 real_backtraces=8 generated_crossings={2 if positive else 0} strict_original=2 strict_installed=2 strict_retired=2 source_restored=true registered={str(positive).lower()}'
        assert [l for l in text.splitlines() if l.startswith('profile=')] == [marker]
        assert 'required_keep_gated ' not in text
    outer_stderr = Path(request['stderr']).read_text()
    assert outer_stderr == f"unwind-consumer main-thread {step['cohort']}: {folder}\n" + text
    return dict(folder=str(folder), single_main_thread=int(census[0]),
                files_sha256={p.name: sha(p) for p in folder.iterdir()},
                summary=marker, counts_asserted_by_frozen_fixture=True,
                raw_architectural_snapshots_reconstructed_by_auditor=False)


def one(step, inputs, expected):
    request = read(step['request'])
    result = read(step['receipt'])
    assert sha(step['request']) == step['request_sha256'] == result['request_sha256']
    assert result['helper_sha256'] == inputs['helper']['sha256']
    assert result['exit'] == 0 and result['wall_timeout'] is False
    assert result['aborted'] is None and result['cleanup_error'] is None
    assert result['unexpected_descendants'] == result['cleanup_events'] == []
    assert result['absence_proof'] == 'ECHILD' and result['inputs_unchanged'] is True
    assert math.isfinite(result['elapsed_seconds']) and 0 <= result['elapsed_seconds'] < request['wall_seconds']
    assert sha(request['stdout']) == result['stdout_sha256'] and sha(request['stderr']) == result['stderr_sha256']
    assert Path(step['helper_stdout']).read_bytes() == HELPER_STDOUT
    assert Path(step['helper_stderr']).read_bytes() == b''
    text = Path(request['stdout']).read_text()
    name = step['name']
    if name == 'launcher-list':
        lines = [line for line in text.splitlines() if line]
        assert lines == [n + ': test' for n in expected['launcher']] + ['32 tests, 0 benchmarks']
        assert Path(request['stderr']).read_bytes() == b''
    elif name == 'consumer-models':
        assert summaries(text) == [(6, 0, 0, 0, 184)]
        result_names(text, expected['consumer_models'])
        assert Path(request['stderr']).read_bytes() == b''
    elif name == 'shared-calibrations':
        assert summaries(text) == [(26, 0, 0, 0, 0)]
        result_names(text, expected['shared_calibrations'], expected['should_panic'])
        assert Path(request['stderr']).read_bytes() == b''
    elif name == 'full-library':
        counts = summaries(text)
        assert counts[-1] == (189, 0, 1, 0, 0)
        assert counts[:-1] == [(1, 0, 0, 0, 189)] * 2
        assert Counter(re.findall(r'\btest ([A-Za-z0-9_:]+) \.\.\.', text)) == Counter(expected['full_library_name_counts'])
        assert re.findall(r'^running (\d+) tests?$', text, re.M) == ['190', '1', '1', '1']
        ignored = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ignored, ([^\n]+)$', text, re.M)
        assert dict(ignored) == expected['full_library_ignored'] and len(ignored) == 1
    else:
        assert summaries(text) == [(1, 0, 0, 0, 31)]
        result_names(text, [step['test']])
    row = dict(name=name, request_sha256=sha(step['request']), receipt_sha256=sha(step['receipt']),
               stdout_sha256=sha(request['stdout']), stderr_sha256=sha(request['stderr']),
               elapsed_seconds=result['elapsed_seconds'])
    if 'cohort' in step:
        row['capture'] = capture(step, inputs, expected)
    return row


def audit_through(name=None):
    inputs = verify()
    plan, expected = read(HERE / 'plan.json'), read(HERE / 'expected.json')
    stop = len(plan['steps']) if name is None else next(i + 1 for i, s in enumerate(plan['steps']) if s['name'] == name)
    rows = [one(step, inputs, expected) for step in plan['steps'][:stop]]
    if name is None:
        required = set()
        for step in plan['steps']:
            request = read(step['request'])
            required.update([request['stdout'], request['stderr'], step['receipt'], step['helper_stdout'], step['helper_stderr']])
        for row in rows:
            if 'capture' in row:
                folder = Path(row['capture']['folder'])
                required.update(str(folder / n) for n in CAPTURE_FILES)
        output = Path(plan['output_directory'])
        assert {str(p) for p in output.rglob('*') if p.is_file()} == required
        assert not any(p.is_symlink() for p in output.rglob('*'))
    verify()
    return dict(status='ALL_FIXED_QUALIFICATION_RECORDS_PASS' if name is None else 'ORDERED_PREFIX_RECORDS_PASS',
                manifest_sha256=sha(HERE / 'manifest.json'), rows=rows,
                positive_totals=expected['inventory']['positive_totals'] if name is None else None,
                prewrite_totals=expected['inventory']['positive_mode_prewrite_refusals'] if name is None else None,
                no_fde_totals=expected['inventory']['no_fde_calibration_totals'] if name is None else None,
                keep_gated_totals=expected['inventory']['keep_gated_calibration_totals'] if name is None else None,
                fresh_72_row_consumer_parity_required=True,
                general_asynchronous_or_exception_unwind_qualified=False)


def audit_closed(name=None):
    inputs = verify_records()
    plan, expected = read(HERE / 'plan.json'), read(HERE / 'expected.json')
    stop = len(plan['steps']) if name is None else next(i + 1 for i, s in enumerate(plan['steps']) if s['name'] == name)
    rows = [one(step, inputs, expected) for step in plan['steps'][:stop]]
    if name is None:
        required = set()
        for step in plan['steps']:
            request = read(step['request'])
            required.update([request['stdout'], request['stderr'], step['receipt'], step['helper_stdout'], step['helper_stderr']])
        for row in rows:
            if 'capture' in row:
                folder = Path(row['capture']['folder'])
                required.update(str(folder / n) for n in CAPTURE_FILES)
        output = Path(plan['output_directory'])
        assert {str(p) for p in output.rglob('*') if p.is_file()} == required
        assert not any(p.is_symlink() for p in output.rglob('*'))
    verify_records()
    return dict(status='ALL_FIXED_QUALIFICATION_RECORDS_PASS' if name is None else 'ORDERED_PREFIX_RECORDS_PASS',
                manifest_sha256=sha(HERE / 'manifest.json'), rows=rows,
                positive_totals=expected['inventory']['positive_totals'] if name is None else None,
                prewrite_totals=expected['inventory']['positive_mode_prewrite_refusals'] if name is None else None,
                no_fde_totals=expected['inventory']['no_fde_calibration_totals'] if name is None else None,
                keep_gated_totals=expected['inventory']['keep_gated_calibration_totals'] if name is None else None,
                fresh_72_row_consumer_parity_required=True,
                general_asynchronous_or_exception_unwind_qualified=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--through')
    args = parser.parse_args()
    print(json.dumps(audit_through(args.through), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
