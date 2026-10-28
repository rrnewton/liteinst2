#!/usr/bin/env python3
"""Project pinned CLOSED metadata; never open binaries, logs, or export streams."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys

HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
REVISION = '398203e80d7784b3ee62c7ed84933c09e0e56b73'
MANIFEST_SHA = 'c14b8fa6a50185f47597a9774828777b3bb05c94f08a5bb11175c79ef8a75606'
FAILURE_SHA = '430c49a90293b58bdd41f40abb837730332e039f7af4f4c82337f1f2d23a1340'
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
    for name in ('repo', 'manifest', 'failure-summary', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    manifest_bytes = args.manifest.read_bytes()
    failure_bytes = args.failure_summary.read_bytes()
    assert digest(manifest_bytes)['sha256'] == MANIFEST_SHA
    assert digest(failure_bytes)['sha256'] == FAILURE_SHA
    manifest, failure = json.loads(manifest_bytes), json.loads(failure_bytes)
    assert manifest['revision'] == failure['revision'] == REVISION
    assert len(manifest['members']) == 70
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
    assert receipt['revision'] == result['revision'] == REVISION
    assert receipt['status'] == 'FAILED' and receipt['stage'] == 'optional-backoff-k10'
    assert receipt['cases'] == [{'k': 10, 'status': 'FAILED'}, {'k': 1000, 'status': 'UNRUN'}]
    assert result['status'] == 'PASS' and receipt['prerequisite']['stages'] == len(STAGES) == 31
    assert receipt['prerequisite']['result'] == digest(blobs[base + 'prerequisite/result.json'])
    assert receipt['prerequisite']['parent'] == digest(blobs[base + 'prerequisite-parent/parent-closed.json'])
    assert len(result['commands']) == 31 and len(receipt['sources']) == 93
    assert receipt['sources']['tools/unwind-oracle/bounded_command.py']['sha256'] == HELPER_SHA
    assert receipt['tools'] == result['tools'] and receipt['versions'] == result['versions']
    for path, expected in receipt['sources'].items():
        data = subprocess.check_output(['git', '-C', str(args.repo), 'show', REVISION + ':' + path])
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
    helper, parent = get('optional-backoff-k10/receipt.json'), get('optional-backoff-k10-parent/parent-closed.json')
    check_helper(helper, 101)
    check_parent(parent, 1)
    assert failure['status'] == 'FAILED' and failure['error'] == 'Full' and failure['k1000'] == 'UNRUN'
    assert failure['phase'] == 'controller-to-sink Calls export' and failure['deadline_diagnostic'] is None
    assert failure['physical'] == failure['fast'] + failure['slow'] == 3441
    assert failure['slow'] == failure['sampled'] + failure['unsampled'] == 1602
    assert failure['stderr']['sha256'] == helper['stderr_sha256']
    failure['stderr'] = pick(failure['stderr'], 'bytes', 'sha256')
    failure['closure'] = {
        'helper': pick(helper, 'exit', 'wall_timeout', 'elapsed_seconds', 'absence_proof', 'inputs_unchanged', 'cleanup_events', 'unexpected_descendants'),
        'parent': pick(parent, 'exit_code', 'termination', 'seconds', 'cleanup_complete', 'reaped_descendants'),
        'helper_receipt': digest(blobs[base + 'optional-backoff-k10/receipt.json']),
        'parent_receipt': digest(blobs[base + 'optional-backoff-k10-parent/parent-closed.json']),
    }
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
        'schema': 1, 'revision': REVISION, 'status': 'PREREQUISITES_PASS_TIMED_CAMPAIGN_FAILED',
        'authority': {'closed_manifest': digest(manifest_bytes), 'root_failure_summary': digest(failure_bytes),
                      'prerequisite_result': digest(blobs[base + 'prerequisite/result.json']),
                      'source_descriptors_checked_against_git': 93},
        'scope': 'Projection of pinned CLOSED JSON/CSV metadata and source hashes, not independent stream/state replay. Whole input, journal, Report and return checks in controls are source-attested; timed trials check journal contents and Report counts.',
        'prerequisites': {'passed': 31, 'failed': 0, 'unrun': 0, 'counts': counts},
        'native_state_qualification': result['native_state_qualification'],
        'native_setup': result['native_setup'],
        'optional_control': {'status': control['status'], 'protocol_in': 'receipt.json#/optional_control/protocol', 'source_attested': control['source_attested']},
        'timed_trial_failure': failure,
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
