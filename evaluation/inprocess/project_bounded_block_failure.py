#!/usr/bin/env python3
"""Project the closed failed PB owner attempt; no imports/replay of evaluators.

Run from any directory with --output FRESH_PRIVATE_DIRECTORY. The two retained
receipts are fixed whole-file inputs. Every command capture is rehashed, but
this projection does not rerun readers or upgrade the recorded DATA outcome.
"""
import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import platform

ROOT = Path(__file__).resolve().parents[2]
REVISION = 'e899fc337040e5f7bd8f488f66b4ba72b9c76713'
RECEIPT = 'target/evaluation/inprocess/bounded-block-owner-attempt-1/receipt.json'
COHORT = 'target/page-region-next/bounded-block-runtime-cohort-attempt-1/receipt.json'
RECEIPT_FACT = dict(bytes=1492056, sha256='a42719325a6b985334575d140abda780dadf04e34a11df46bf3437d0695b6b41')
COHORT_FACT = dict(bytes=2210, sha256='8daa1dc7eee07616f43586fd11410ee7f6f8d6d5c2eb4515494b353fcb784bc0')
# Canonical JSON of all101 ordered (name, profile) pairs, independently joined
# to the literal COMMAND_SCHEDULE in the recorded 0bbfe6b3 owner helper.
SCHEDULE_SHA256 = '33067efaed07360de8798c6611d3689f5aaebce3ace1d1a9557657bf52930f3d'
CONTROL_ERROR = 'ValueError: accepted supplied PB owner corruption epoch0_after_UC'
COHORT_ERROR = 'ValueError: all three actual loop outcomes required without skipped or relabelled failures'
OUTER_ERROR = "RuntimeError('bounded_block failed; no dependent stage launched')"
LANES = ('native', 'maintained', 'differential')
ELAPSED_NS = (155065086, 5211392165, 7577679200)
HARDWARE_FIELDS = ('architecture', 'vendor_id', 'model name', 'cpu family',
    'model', 'stepping', 'microcode', 'kernel_version', 'kernel_release_sha256',
    'probe_cpu', 'affinity_cpu_count')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=digest(data))


def load(path, expected):
    data = path.read_bytes()
    need(dict(bytes=len(data), sha256=digest(data)) == expected, 'exact retained receipt')
    return json.loads(data)


def capture(directory, value):
    name = value['file']
    need(type(name) is str and name and Path(name).name == name,
         'one local capture basename')
    expected = {key: value[key] for key in ('bytes', 'sha256')}
    need(fact(directory / name) == expected, 'whole retained capture bytes')
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='fresh directory for the compact JSON and CSV')
    args = parser.parse_args()
    need(not args.output.exists(), 'fresh output; never overwrite historical evidence')
    receipt_path, cohort_path = ROOT / RECEIPT, ROOT / COHORT
    r, outer = load(receipt_path, RECEIPT_FACT), load(cohort_path, COHORT_FACT)
    need(r['schema'] == 1 and r['profile'] == 'bounded-block-owner-v1' and
         r['status'] == outer['status'] == 'failed' and
         r['revision'] == outer['revision'] == REVISION and
         r['cpu'] == outer['cpu'] == 3, 'exact failed observation and source/CPU')
    need(r['error'] == COHORT_ERROR and outer['error'] == OUTER_ERROR and
         r['final_errors'] == [] and r['whole_profile_qualified'] is False,
         'original failures and no qualification retained')
    closure_keys = ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')
    need(all(r[key] is True for key in closure_keys) and
         r['source']['revision'] == REVISION and
         r['source']['tracked_clean'] is True and r['source']['head_sources_match'] is True,
         'closed clean-source/input/cleanup record')
    need(r['hardware']['probe_cpu'] == 3 and r['hardware']['affinity_cpu_count'] == 1,
         'actual singleton CPU observation')

    commands = r['commands']
    schedule = [(row['name'], row['profile']) for row in commands]
    need(len(commands) == 101 and len({row['name'] for row in commands}) == 101 and
         digest(compact(schedule)) == SCHEDULE_SHA256, 'whole fixed101-command schedule')
    capture_ledger = []
    for row in commands:
        need(row['exit'] == 0 and row['expected_exit'] in (None, 0) and
             row['timed_out'] is False and row['reaped'] is True and
             row['error'] is None and row['cleanup_errors'] == [] and
             all(item['closed'] is True for item in row['descriptors']) and
             row['bounds'] == r['bounds'][row['profile']], 'closed command and original bound')
        streams = {'stdout', 'stderr'}
        if row['name'] in ('subject-maintained-0-0', 'subject-differential-0-0'):
            streams.add('record')
        need(set(row['captures']) == streams, 'complete exact command capture population')
        for stream in sorted(streams):
            observed = capture(receipt_path.parent, row['captures'][stream])
            capture_ledger.append(dict(command=row['name'], stream=stream, **observed))
    need(len(capture_ledger) == 204 and sum(x['bytes'] for x in capture_ledger) == 5136132,
         'whole actual raw-capture inventory')

    stages = outer['stages']
    need([row['name'] for row in stages] == ['native41', 'bounded_block'] and
         [row['exit'] for row in stages] == [0, 1], 'dependent program stage never launched')
    direct = r['direct_prerequisite']
    need(direct['status'] == 'passed' and direct['commands'] == 139 and
         direct['whole_profile_qualified'] is False and
         stages[0]['result']['status'] == 'passed' and
         stages[0]['result']['receipt'] == direct['file'] and
         stages[0]['receipt'] == {key: direct[key] for key in ('bytes', 'sha256')} and
         fact(ROOT / direct['file']) == stages[0]['receipt'], 'actual native41 prerequisite identity')
    expected_commands = [
        ['-B', 'evaluation/inprocess/direct_frontier_loop.py', '--expect-revision', REVISION],
        ['-B', 'evaluation/inprocess/bounded_block_owner.py', '--expect-revision', REVISION,
         '--cpu', '3', '--direct-receipt', direct['file'], '--direct-receipt-sha256',
         direct['sha256'], '--output', str(Path(RECEIPT).parent)],
    ]
    stages_out = []
    for row, wanted in zip(stages, expected_commands, strict=True):
        need(row['argv'][1:] == wanted and type(row['duration_ns']) is int and
             row['duration_ns'] > 0 and set(row['captures']) == {'stdout', 'stderr'},
             'exact outer invocation and capture population')
        captures = {}
        for stream, value in row['captures'].items():
            need(fact(cohort_path.parent / (row['name'] + '.' + stream)) == value,
                 'whole outer capture bytes')
            captures[stream] = value
        stages_out.append(dict(name=row['name'], process_exit=row['exit'],
            validation_duration_ns=row['duration_ns'], captures=captures))

    subjects = []
    need([case['lane'] for case in r['cases']] == list(LANES), 'all three subjects retained')
    for index, case in enumerate(r['cases']):
        lane = LANES[index]
        label = 'subject-' + lane + '-0-0'
        row = next(value for value in commands if value['name'] == label)
        expected_status = 'observed_native_bounded_block' if index == 0 else 'failed'
        need(case['label'] == label and case['mode'] == case['control'] == 0 and
             case['launched'] is True and case['status'] == expected_status and
             case['exit'] == case['expected_exit'] == 0 and case['timed_out'] is False and
             case['whole_process_ns'] == row['duration_ns'] == ELAPSED_NS[index] and
             case.get('error') == (None if index == 0 else CONTROL_ERROR),
             'exact actual lane result, duration and failure')
        captures = {stream: {key: value[key] for key in ('bytes', 'sha256')}
                    for stream, value in row['captures'].items()}
        need(case['captures'] == captures, 'subject and command capture joins')
        subjects.append(dict(lane=lane, status=case['status'], process_exit=case['exit'],
            timed_out=case['timed_out'], validation_duration_ns=case['whole_process_ns'],
            error=case.get('error'), captures=captures))

    hardware = {key: r['hardware'][key] for key in HARDWARE_FIELDS}
    hardware.update(isa_flags_count=len(r['hardware']['isa_flags']),
                    isa_flags_sha256=digest(compact(r['hardware']['isa_flags'])))
    result = dict(schema=1, profile='bounded-block-owner-failed-attempt', status='failed',
        revision=REVISION, source=r['source'], cpu=3, hardware=hardware,
        scope='Historical failed finite PB owner validation; all three processes exited zero, but both gated lanes accepted the supplied epoch0_after_UC corruption.',
        failure=dict(cohort=r['error'], gated_control=CONTROL_ERROR, outer=outer['error']),
        qualification_credit=False, performance_credit=False, native_equivalence_credit=False,
        whole_program_credit=False, within_10x_dynamorio_established=False,
        real_program_probe=dict(status='not_run', subjects_launched=0),
        receipts=dict(owner=RECEIPT_FACT, cohort=COHORT_FACT,
                      native41_public=stages[0]['receipt'], native41_raw=direct['receipt']),
        closure={key: r[key] for key in closure_keys}, final_errors=r['final_errors'],
        command_summary=dict(scheduled=101, recorded=101,
            exit_counts=dict(Counter(str(row['exit']) for row in commands)),
            profile_counts=dict(Counter(row['profile'] for row in commands)),
            reaped=101, timed_out=0, schedule_sha256=SCHEDULE_SHA256),
        raw_capture_inventory=dict(count=len(capture_ledger), bytes=sum(x['bytes'] for x in capture_ledger),
            sha256=digest(compact(capture_ledger)),
            hash_format='SHA256 of canonical JSON ordered by command schedule, then stream; each row has command, stream, bytes, sha256. Raw payloads remain private.'),
        stages=stages_out, subjects=subjects, bounds=r['bounds'],
        bounds_order=['cpu_seconds', 'memory_bytes', 'file_size_bytes', 'wall_seconds'],
        timing_scope='Validation process durations only; no benchmark, speedup or completed LS/true measurement.',
        reproducer=dict(revision=REVISION,
            precondition='Reserve CPU3 externally from an eligible broad parent and keep singleton affinity throughout. Use fresh output paths.',
            python='python3 denotes the recorded interpreter, not a host path.',
            interpreter=fact(stages[0]['argv'][0]),
            commands=[
                'python3 -B evaluation/inprocess/direct_frontier_loop.py --expect-revision ' + REVISION,
                'python3 -B evaluation/inprocess/bounded_block_owner.py --expect-revision ' + REVISION +
                ' --cpu 3 --direct-receipt <FRESH_NATIVE41_PUBLIC_RECEIPT> --direct-receipt-sha256 <FRESH_SHA256>' +
                ' --output target/evaluation/inprocess/<FRESH_PB_CHILD>',
            ]))
    need(stages[0]['argv'][0] == stages[1]['argv'][0] and
         fact(stages[0]['argv'][0]) == r['inputs'][str(Path(stages[0]['argv'][0]).resolve())],
         'same exact retained Python executable')
    json_bytes = compact(result) + b'\n'
    table = io.StringIO()
    fields = ['revision', 'cpu', 'cohort_status', 'lane', 'subject_status', 'process_exit',
              'validation_duration_ns', 'error', 'source_unchanged', 'inputs_unchanged',
              'cleanup_complete', 'qualification_credit', 'performance_credit']
    for stream in ('stdout', 'stderr', 'record'):
        fields += [stream + '_bytes', stream + '_sha256']
    writer = csv.DictWriter(table, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    for subject in subjects:
        row = dict(revision=REVISION, cpu=3, cohort_status='failed', lane=subject['lane'],
            subject_status=subject['status'], process_exit=subject['process_exit'],
            validation_duration_ns=subject['validation_duration_ns'], error=subject['error'] or '',
            qualification_credit=False, performance_credit=False,
            **{key: r[key] for key in closure_keys})
        for stream, value in subject['captures'].items():
            row[stream + '_bytes'], row[stream + '_sha256'] = value['bytes'], value['sha256']
        writer.writerow(row)
    csv_bytes = table.getvalue().encode()
    need(len(json_bytes) + len(csv_bytes) < 10 * 1024, 'compact JSON plus CSV below10KiB')
    payload = json_bytes + csv_bytes
    forbidden = (str(ROOT), str(Path.home()), platform.node(), '/home/', '/usr/local/', 'devbig', 'fbcode')
    need(all(not text or text.encode() not in payload for text in forbidden),
         'no host paths or hostnames in public projection')
    need(fact(receipt_path) == RECEIPT_FACT and fact(cohort_path) == COHORT_FACT,
         'original failed receipts unchanged before output')
    args.output.mkdir(parents=True, exist_ok=False)
    stem = '20261101-bounded-block-owner-failed-e899fc337040'
    for suffix, data in (('.json', json_bytes), ('.csv', csv_bytes)):
        with (args.output / (stem + suffix)).open('xb') as output:
            output.write(data)
    print(json.dumps({stem + suffix: fact(args.output / (stem + suffix))
                      for suffix in ('.json', '.csv')}, sort_keys=True))


if __name__ == '__main__':
    main()
