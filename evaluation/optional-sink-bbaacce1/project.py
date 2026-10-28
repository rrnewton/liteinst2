#!/usr/bin/env python3
"""Project pinned CLOSED metadata; never open binaries, logs, or export streams."""
import argparse
import csv
import hashlib
import io
import json
import re
from pathlib import Path
import subprocess
import sys

HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
STAGES = ('c-build build oracle native exact-build exact-oracle '
          'exact-short-k24 exact-short-k1 exact-short-k10 '
          'exact-long-k24 exact-long-k1 exact-long-k10 '
          'exact-alternating-k24 exact-alternating-k1 exact-alternating-k10 '
          'exact-late-long-k24 exact-late-long-k1 exact-late-long-k10 '
          'concurrent-oracle concurrent-test-build concurrent-native timed-native '
          'retirement-sixteen-epochs retirement-function-closed drain-native '
          'streamed-native history-native optional-fast-state optional-slow-state '
          'optional-functional optional-backoff-native').split()


def digest(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def pick(value, *keys):
    return {key: value[key] for key in keys}


def check_parent(parent, code):
    assert parent['exit_code'] == code and parent['termination'] is None
    assert parent['cleanup_complete'] is True and parent['reaped_descendants'] == 0


def check_helper(helper, code):
    assert helper['helper_sha256'] == HELPER_SHA
    assert helper['exit'] == code and helper['wall_timeout'] is False
    assert helper['absence_proof'] == 'ECHILD' and helper['inputs_unchanged'] is True
    assert helper['unexpected_descendants'] == helper['cleanup_events'] == []
    assert helper['cleanup_error'] is None and helper['aborted'] is None


def main():
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'manifest', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--failure-summary', type=Path)
    parser.add_argument('--failure-sha256')
    args = parser.parse_args()
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    assert re.fullmatch('[0-9a-f]{64}', args.manifest_sha256)
    assert (args.failure_summary is None) == (args.failure_sha256 is None)
    manifest_bytes = args.manifest.read_bytes()
    assert digest(manifest_bytes)['sha256'] == args.manifest_sha256
    manifest = json.loads(manifest_bytes)
    assert manifest['revision'] == args.revision
    blobs = {}
    for member in manifest['members']:
        path = Path(member['path'])
        assert not path.is_absolute() and '..' not in path.parts and member['path'] not in blobs
        data = (args.repo / path).read_bytes()
        assert digest(data) == pick(member, 'bytes', 'sha256')
        blobs[member['path']] = data
    roots = [p[:-len('public/receipt.json')] for p in blobs if p.endswith('/public/receipt.json')]
    assert len(roots) == 1
    base = roots[0]
    get = lambda name: json.loads(blobs[base + name])
    receipt, result = get('public/receipt.json'), get('prerequisite/result.json')
    assert receipt['revision'] == result['revision'] == args.revision
    assert receipt['profile'] == 'optional-pre-context'
    policy = dict(mode='bounded-poll-window', retry_ns=1000000, poll_ns=250000)
    assert receipt['sink_backpressure'] == policy
    assert '--optional' in receipt['reproduce'] and '--sink-backpressure' in receipt['reproduce']
    worker_wait = '--worker-backpressure' in receipt['reproduce']
    assert receipt.get('worker_backpressure') == ('bounded-wait' if worker_wait else None)
    suffix = '-both-wait' if worker_wait else '-sink-wait'
    route = 'optional-backoff-work-both-wait' if worker_wait else 'optional-backoff-work-sink-wait'
    cases = receipt['cases']
    assert [c['k'] for c in cases] == [10, 1000]
    statuses = [c['status'] for c in cases]
    assert statuses in (['PASS', 'PASS'], ['FAILED', 'UNRUN'], ['PASS', 'FAILED'])
    passed = statuses == ['PASS', 'PASS']
    assert receipt['status'] == ('PASS' if passed else 'FAILED')
    assert receipt['stage'] == ('complete' if passed else 'optional-backoff-k'+str(cases[statuses.index('FAILED')]['k'])+suffix)
    assert result['status'] == 'PASS' and result['stage'] == 'complete'
    assert receipt['prerequisite']['status'] == 'PASS' and receipt['prerequisite']['stages'] == len(STAGES) == 31
    required = {'public/receipt.json', 'public/cases.csv', 'prerequisite/result.json',
                'prerequisite-parent/parent-closed.json', 'prerequisite/optional-backoff-control.csv',
                'prerequisite/optional-functional.csv'}
    for stage in STAGES:
        required.update('prerequisite/'+stage+'/'+name for name in ('receipt.json', 'parent-closed.json'))
    for case in cases:
        if case['status'] != 'UNRUN':
            label = 'optional-backoff-k'+str(case['k'])+suffix
            required.update((label+'/receipt.json', label+'-parent/parent-closed.json'))
    assert set(blobs) == {base+name for name in required}
    table = list(csv.DictReader(io.StringIO(blobs[base+'public/cases.csv'].decode())))
    assert len(table) == 2
    assert all(row == {key: str(case.get(key, '')) for key in row} for row, case in zip(table, cases))
    assert receipt['prerequisite']['result'] == digest(blobs[base + 'prerequisite/result.json'])
    assert receipt['prerequisite']['parent'] == digest(blobs[base + 'prerequisite-parent/parent-closed.json'])
    assert len(result['commands']) == 31 and receipt['sources']
    assert receipt['sources']['tools/unwind-oracle/bounded_command.py']['sha256'] == HELPER_SHA
    assert receipt['tools'] == result['tools'] and receipt['versions'] == result['versions']
    assert receipt['artifacts'] == dict(result['build']['artifacts'], libtest=result['concurrent_epochs']['test_artifact'])
    assert receipt['dso'] == result['dso']
    assert all(receipt['sources'][path] == pin for path, pin in result['sources'].items())
    for path, expected in receipt['sources'].items():
        data = subprocess.check_output(['git', '-C', str(args.repo), 'show', args.revision + ':' + path])
        assert digest(data) == expected
    check_parent(get('prerequisite-parent/parent-closed.json'), 0)
    rows = []
    for index, (stage, command) in enumerate(zip(STAGES, result['commands']), 1):
        measured = result[stage]
        helper = get('prerequisite/' + stage + '/receipt.json')
        parent = get('prerequisite/' + stage + '/parent-closed.json')
        check_helper(helper, 0)
        check_parent(parent, 0)
        assert measured['process_exit'] == 0 and measured['strict_cleanup'] is True
        rows.append([index, stage, 'PASS', measured['cpu_seconds'], measured['wall_seconds'],
                     measured['file_bytes'], 0, 0, True, 'ECHILD', 0,
                     helper['elapsed_seconds'], parent['seconds'], json.dumps(command, separators=(',', ':'))])
    control = result['optional_backoff_control']
    assert control['status'] == 'PASS' and control['protocol'] == receipt['optional_control']['protocol']
    for name, expected in [('optional-backoff-control', control['protocol']),
                           ('optional-functional', result['optional_frontend']['functional'])]:
        table = list(csv.DictReader(io.StringIO(blobs[base + 'prerequisite/' + name + '.csv'].decode())))
        assert len(table) == 1
        assert all(table[0][key] == str(expected[key]) for key in table[0])
    trials = []
    assert len(receipt['commands']) == 1 + sum(c['status'] != 'UNRUN' for c in cases)
    for case in cases:
        if case['status'] == 'UNRUN':
            trials.append(pick(case, 'k', 'status'))
            continue
        label = 'optional-backoff-k'+str(case['k'])+suffix
        helper_bytes = blobs[base+label+'/receipt.json']
        parent_bytes = blobs[base+label+'-parent/parent-closed.json']
        helper, parent = json.loads(helper_bytes), json.loads(parent_bytes)
        assert type(helper['exit']) is int and 0 <= helper['exit'] <= 255
        assert type(parent['exit_code']) is int and 0 <= parent['exit_code'] <= 255
        check_helper(helper, helper['exit'])
        check_parent(parent, parent['exit_code'])
        command = receipt['commands'][len(trials)+1]
        assert command == ['$REPO/target/release/ordinary-interval', route,
            '$RAW/prerequisite/candidate.so', '$RAW/prerequisite/trusted.so', str(case['k']),
            '520', '100000', '$RAW/'+label+'/export.txt']
        if case['status'] == 'PASS':
            check_helper(helper, 0)
            check_parent(parent, 0)
            assert case['receipt'] == digest(helper_bytes) and case['parent'] == digest(parent_bytes)
            assert case['request']['sha256'] == helper['request_sha256']
            assert helper['stderr_sha256'] == hashlib.sha256(b'').hexdigest()
            assert (case['cpu_seconds'], case['wall_seconds'], case['file_bytes']) == (20, 30, 64*1048576)
            assert (case['sink_backpressure'], case['sink_retry_ns'], case['sink_poll_ns']) == ('bounded-poll-window', 1000000, 250000)
            assert case['worker_backpressure'] == ('bounded-wait' if worker_wait else 'immediate')
            assert (case['epoch_limit'], case['call_limit'], case['arms'], case['reports']) == (520, 100000, 520, 520)
            assert case['written_bytes'] == case['export']['bytes']
        trials.append(dict(k=case['k'], status=case['status'], helper_receipt=digest(helper_bytes),
            parent_receipt=digest(parent_bytes), helper_exit=helper['exit'], parent_exit=parent['exit_code']))
        rows.append([len(rows)+1, label, case['status'], 20, 30, 64*1048576,
            helper['exit'], parent['exit_code'], True, 'ECHILD', 0,
            helper['elapsed_seconds'], parent['seconds'], json.dumps(command, separators=(',', ':'))])
    failure_pin = None
    if args.failure_summary is not None:
        assert not passed and re.fullmatch('[0-9a-f]{64}', args.failure_sha256)
        failure_bytes = args.failure_summary.read_bytes()
        failure_pin = digest(failure_bytes)
        assert failure_pin['sha256'] == args.failure_sha256
        failure = json.loads(failure_bytes)
        assert failure['revision'] == args.revision and failure['status'] == 'FAILED'
        # Private diagnoses are not copied or invented by this projector.
    modes = result['optional_frontend']['state_modes']
    assert sum(modes[m]['comparisons'] for m in ('fast', 'slow')) == 1956
    counts = {
        'checksum': pick(result, 'originals', 'calls', 'completed', 'unsampled', 'reports'),
        'ordinary_state': pick(result['oracle'], 'pairs', 'children', 'comparisons'),
        'exact_state': pick(result['exact_work']['oracle'], 'pairs', 'children', 'comparisons',
                            'original_instructions', 'conditional_branches', 'taken_branches', 'input_reads', 'return_reads'),
        'exact_populations': pick(result['exact_work'], 'fresh_processes', 'originals', 'calls', 'sampled', 'closed'),
        'concurrent_state': pick(result['concurrent_epochs']['oracle'], 'pairs', 'children', 'comparisons', 'scope'),
        'forced_concurrent': pick(result['concurrent_epochs']['forced_native'], 'calls', 'sampled', 'closed', 'removed', 'inflight_rearm', 'writer_contentions', 'registry_contentions'),
        'timed': pick(result['concurrent_epochs']['timed'], 'originals', 'calls', 'sampled', 'unsampled', 'coverage'),
        'retirement': [{k: v for k, v in case.items() if k not in ('test',)} for case in result['epoch_retirement']['cases']],
        'completed_drain': pick(result['completed_drain'], 'originals', 'calls', 'sampled', 'batches', 'events', 'report_records', 'capacity_refusals', 'empty_drains'),
        'streamed': pick(result['streamed_epochs'], 'originals', 'calls', 'epochs', 'slots', 'replacements', 'batches', 'events', 'sampled', 'unsampled', 'coverage'),
        'history': pick(result['history_stream']['protocol'], 'actions', 'history_batches', 'epochs', 'retired', 'calls', 'sampled', 'old_prefix', 'new_prefix'),
        'optional_state': {mode: pick(modes[mode], 'status', 'pairs', 'children', 'comparisons', 'observer_entries', 'helper_joins', 'controller_transitions') for mode in ('fast', 'slow')},
        'optional_functional': {k: v for k, v in result['optional_frontend']['functional'].items() if k != 'scope'},
    }
    output = {
        'schema': 1, 'revision': args.revision, 'status': 'PREREQUISITES_PASS_TIMED_CAMPAIGN_'+receipt['status'],
        'authority': {'closed_manifest': digest(manifest_bytes), 'root_failure_summary': failure_pin,
                      'prerequisite_result': digest(blobs[base + 'prerequisite/result.json']),
                      'source_descriptors_checked_against_git': len(receipt['sources'])},
        'scope': 'Projection of pinned CLOSED JSON/CSV metadata and source hashes, not independent stream/state replay. Whole input, journal, Report and return checks in controls are source-attested; timed trials check journal contents and Report counts.',
        'prerequisites': {'passed': 31, 'failed': 0, 'unrun': 0, 'counts': counts},
        'native_state_qualification': result['native_state_qualification'],
        'native_setup': result['native_setup'],
        'optional_frontend_scope': result['optional_frontend']['scope'],
        'optional_control': {'status': control['status'], 'protocol_in': 'receipt.json#/optional_control/protocol', 'source_attested': control['source_attested']},
        'sink_backpressure': policy,
        'timed_trials': trials,
        'timed_status_authority': 'Pinned wrapper receipt and source-attested complete terminal predicates; no independent stream replay.',
        'gates': {'status': 'NOT_INCLUDED', 'scope': 'Separate validation evidence; no gate outcome inferred here.'},
    }
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\n')
    writer.writerow(['index', 'stage', 'status', 'cpu_limit_s', 'wall_limit_s', 'file_limit_bytes',
                     'helper_exit', 'parent_exit', 'cleanup_complete', 'absence_proof', 'rescued_descendants',
                     'helper_elapsed_s', 'parent_elapsed_s', 'command_argv'])
    writer.writerows(rows)
    products = {'receipt.json': blobs[base + 'public/receipt.json'], 'cases.csv': blobs[base + 'public/cases.csv'],
                'commands.csv': stream.getvalue().encode(),
                'qualification.json': (json.dumps(output, indent=2, sort_keys=True) + '\n').encode()}
    args.out.mkdir(parents=True, exist_ok=False)
    for name, data in products.items():
        (args.out / name).write_bytes(data)


if __name__ == '__main__':
    main()
