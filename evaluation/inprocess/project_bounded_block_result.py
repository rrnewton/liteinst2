#!/usr/bin/env python3
"""Compact projection of one CLOSED PB owner receipt, without reader replay.

Requires the exact private receipt SHA. Rehashes retained command captures;
copies recorded statuses, errors, pair values and control populations without
turning partial reader results into acceptance. No evaluator modules imported.
"""
import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import platform
import re

ROOT = Path(__file__).resolve().parents[2]
SCHEDULE_SHA256 = '33067efaed07360de8798c6611d3689f5aaebce3ace1d1a9557657bf52930f3d'
BOUNDS = {
    'build': [120, 2147483648, 134217728, 150],
    'finite': [5, 536870912, 16777216, 15],
    'inspect': [10, 268435456, 4194304, 20],
    'metadata': [30, 536870912, 67108864, 60],
    'program': [30, 536870912, 16777216, 60],
    'release_build': [30, 536870912, 16777216, 60],
    'seed': [5, 536870912, 16777216, 15],
}
LANES = ('native', 'maintained', 'differential')
ACCEPTED = dict(native='observed_native_bounded_block',
    maintained='observed_generated_bounded_block_maintained',
    differential='observed_generated_bounded_block_differential')
CONTROL_COUNTS = dict(application_controls=40, owner_reader_controls=204,
    pair_controls=36, terminal_controls=73, repeat_tls_controls=33,
    native_probe_controls=22, subentry_controls=19, effect_controls=12)
PAIR = dict(observed_bounded_block=1, plan_version=10,
    unsupported_root_cancellations=1, ordinary_resumptions=1, invocations=1,
    generated_completed=3, cold_publications=2, warm_entries=1, dual_entries=1,
    retained_generations=2, shared_domain_lifetimes=1, joint_source_pairs=2,
    joint_source_pages=4, joint_closed_pages=34, modeled_joint_retired_instructions=11,
    modeled_final_frontier_instructions=1, modeled_cross_certificate_transfers=5,
    measured_interior_signals=0, native_instructions=20, native_full_frames=12,
    lifetime_mode=2, registration_epoch=0, registration_calls=0, word_observed=0,
    word_available=False, qualification_credit=False)
HARDWARE = ('architecture', 'vendor_id', 'model name', 'cpu family', 'model',
    'stepping', 'microcode', 'kernel_version', 'kernel_release_sha256',
    'probe_cpu', 'affinity_cpu_count')
CLOSURE = ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=sha(data))


def safe_text(value):
    """Preserve errors literally or refuse publication; never silently redact."""
    need(value is None or type(value) is str, 'recorded optional text')
    if value is not None:
        forbidden = (str(ROOT), str(Path.home()), platform.node(), '/home/',
                     '/usr/local/', '/tmp/', 'devbig', 'fbcode')
        need(all(not token or token not in value for token in forbidden),
             'error contains private path/host information; retain original privately')
    return value


def optional_int(value):
    need(value is None or type(value) is int, 'recorded optional integer')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True, help='fresh output directory')
    args = parser.parse_args()
    need(re.fullmatch('[0-9a-f]{64}', args.receipt_sha256) is not None,
         'explicit lowercase whole receipt SHA256')
    need(not args.output.exists(), 'fresh output; historical projections remain intact')
    path = args.receipt.resolve(strict=True)
    data = path.read_bytes()
    receipt_fact = dict(bytes=len(data), sha256=sha(data))
    need(receipt_fact['sha256'] == args.receipt_sha256, 'exact supplied receipt')
    r = json.loads(data)
    need(r['schema'] == 1 and r['profile'] == 'bounded-block-owner-v1' and
         r['status'] in ('failed', 'observed_unqualified') and
         r['whole_profile_qualified'] is False and canonical(r['bounds']) == canonical(BOUNDS),
         'separate PB owner schema, unchanged original bounds, no qualification')
    revision, cpu = r['revision'], r['cpu']
    need(re.fullmatch('[0-9a-f]{40}', revision) is not None and
         type(cpu) is int and cpu >= 0 and all(type(r[key]) is bool for key in CLOSURE),
         'actual source/CPU and closure fields')
    source = r['source']
    if source is not None:
        need(set(source) == {'revision', 'tree', 'source_manifest_sha256',
                            'tracked_clean', 'head_sources_match'}, 'source projection fields')
    error = safe_text(r['error'])
    final_errors = [safe_text(value) for value in r['final_errors']]
    hardware = {key: r['hardware'][key] for key in HARDWARE}
    hardware.update(isa_flags_count=len(r['hardware']['isa_flags']),
                    isa_flags_sha256=sha(canonical(r['hardware']['isa_flags'])))

    commands = r['commands']
    need(type(commands) is list and len(commands) <= 101 and
         len({row['name'] for row in commands}) == len(commands), 'unique bounded command rows')
    schedule = [(row['name'], row['profile']) for row in commands]
    schedule_hash = sha(canonical(schedule))
    if len(commands) == 101:
        need(schedule_hash == SCHEDULE_SHA256, 'complete fixed101 command order/profiles')
    ledger, by_name, command_errors = [], {}, []
    exit_counts = Counter()
    for row in commands:
        need(re.fullmatch('[a-zA-Z0-9_-]+', row['name']) is not None and
             row['bounds'] == BOUNDS[row['profile']], 'source command identity and bound')
        optional_int(row.get('exit'))
        optional_int(row.get('duration_ns'))
        exit_counts['not_recorded' if row.get('exit') is None else str(row['exit'])] += 1
        for key in ('error',):
            safe_text(row.get(key))
        cleanup_errors = [safe_text(value) for value in row.get('cleanup_errors', [])]
        if row.get('error') is not None or cleanup_errors:
            command_errors.append(dict(name=row['name'], error=row.get('error'),
                                       cleanup_errors=cleanup_errors))
        captures = {}
        need(set(row.get('captures', {})) <= {'stdout', 'stderr', 'record'},
             'known exact capture streams')
        for stream, value in sorted(row.get('captures', {}).items()):
            name = value['file']
            need(type(name) is str and name and Path(name).name == name,
                 'local raw capture basename')
            observed = fact(path.parent / name)
            need(observed == {key: value[key] for key in ('bytes', 'sha256')},
                 'whole retained raw capture hash')
            captures[stream] = observed
            ledger.append(dict(command=row['name'], stream=stream, **observed))
        by_name[row['name']] = (row, captures)

    need([case['lane'] for case in r['cases']] == list(LANES), 'all three original case slots')
    subjects = []
    for case in r['cases']:
        lane = case['lane']
        name = 'subject-' + lane + '-0-0'
        need(case['label'] == name and case['mode'] == case['control'] == 0 and
             case['expected_exit'] == 0 and type(case['launched']) is bool and
             case['status'] in ('unexecuted', 'failed', ACCEPTED[lane]),
             'unchanged subject identity and literal recorded outcome')
        row, captures = by_name.get(name, ({}, {}))
        need(case.get('captures', {}) == captures, 'case/command raw capture facts')
        need(case.get('exit') == row.get('exit') and
             case.get('whole_process_ns') == row.get('duration_ns') and
             case.get('timed_out') == row.get('timed_out') and
             case['launched'] == (type(row.get('pid')) is int), 'case/command actual process fields')
        controls = {}
        present = {key for key in case if key.endswith('_controls')}
        need(present <= set(CONTROL_COUNTS), 'known separate control cohorts')
        for key in CONTROL_COUNTS:
            value = case.get(key)
            if value is None:
                controls[key] = None
                continue
            names = value['refusals']
            need(type(names) is list and all(type(name) is str and name for name in names) and
                 len(set(names)) == len(names) and value['native_operations'] == 0,
                 'recorded unique supplied controls, no native operations')
            controls[key] = len(names)
        pair = case.get('pair')
        need(pair is None or (set(pair) == set(PAIR) and
             all(type(value) in (int, bool) for value in pair.values())),
             'complete numeric PB pair shape when recorded')
        subject = dict(lane=lane, status=case['status'], launched=case['launched'],
            process_exit=optional_int(case.get('exit')), timed_out=case.get('timed_out'),
            validation_duration_ns=optional_int(case.get('whole_process_ns')),
            error=safe_text(case.get('error')), captures=captures,
            recorded_pair=pair, recorded_control_counts=controls,
            complete_lane_accepted=case['status'] == ACCEPTED[lane])
        if subject['complete_lane_accepted']:
            need(subject['launched'] and subject['process_exit'] == 0 and
                 subject['timed_out'] is False and subject['error'] is None and
                 type(subject['validation_duration_ns']) is int and subject['validation_duration_ns'] > 0,
                 'recorded accepted lane has a successful bounded process')
            expected = {'application_controls': 40} if lane == 'native' else {
                key: count for key, count in CONTROL_COUNTS.items() if key != 'application_controls'}
            need({key: value for key, value in controls.items() if value is not None} == expected and
                 (pair is None if lane == 'native' else canonical(pair) == canonical(PAIR)),
                 'all original accepted-lane pair and control populations')
        subjects.append(subject)

    accepted = r['status'] == 'observed_unqualified'
    if accepted:
        need(source is not None and source['revision'] == revision and
             source['tracked_clean'] is True and source['head_sources_match'] is True and
             hardware['probe_cpu'] == cpu and hardware['affinity_cpu_count'] == 1 and
             all(r[key] is True for key in CLOSURE) and error is None and not final_errors and
             len(commands) == 101 and all(subject['complete_lane_accepted'] for subject in subjects) and
             all(row.get('exit') == 0 and row.get('timed_out') is False and row.get('reaped') is True and
                 row.get('error') is None and row.get('cleanup_errors') == [] and
                 all(item['closed'] is True for item in row['descriptors']) for row in commands),
             'literal accepted receipt retains every complete finite gate')
    direct = r.get('direct_prerequisite')
    prerequisite = None
    if direct is not None:
        public_path = Path(direct['file'])
        need(not public_path.is_absolute() and '..' not in public_path.parts and
             public_path.parts[:3] == ('evaluation', 'inprocess', 'results'),
             'natural public native41 receipt path')
        observed = fact(ROOT / public_path)
        need(observed == {key: direct[key] for key in ('bytes', 'sha256')},
             'whole retained native41 public receipt bytes')
        prerequisite = dict(public_receipt=observed, status=direct['status'],
                            commands=direct['commands'])
    need(not accepted or prerequisite is not None and prerequisite['status'] == 'passed' and
         prerequisite['commands'] == 139, 'accepted PB keeps complete original native41 prerequisite')

    result = dict(schema=1, profile='bounded-block-owner-result-projection', status=r['status'],
        revision=revision, cpu=cpu, source=source, hardware=hardware, receipt=receipt_fact,
        error=error, final_errors=final_errors, closure={key: r[key] for key in CLOSURE},
        scope='Finite PB20 owner validation only. Recorded pair/control fields on failed lanes are partial results, not accepted equivalence.',
        recorded_finite_cohort_accepted=accepted, whole_profile_qualified=False,
        qualification_credit=False, performance_credit=False, whole_program_credit=False,
        within_10x_dynamorio_established=False,
        timing_scope='Validation process durations only; no performance prediction or LS/true measurement.',
        command_summary=dict(planned=101, recorded=len(commands), exit_counts=dict(exit_counts),
            profile_counts=dict(Counter(row['profile'] for row in commands)),
            reaped=sum(row.get('reaped') is True for row in commands),
            timed_out=sum(row.get('timed_out') is True for row in commands),
            outcome_not_recorded=sum(row.get('exit') is None for row in commands),
            ordered_schedule_sha256=schedule_hash, errors=command_errors),
        raw_capture_inventory=dict(count=len(ledger), bytes=sum(row['bytes'] for row in ledger),
            sha256=sha(canonical(ledger)),
            hash_format='Canonical JSON of command/stream/bytes/sha256 rows, command order then sorted stream. Raw captures remain private.'),
        subjects=subjects, native41_prerequisite=prerequisite, bounds=r['bounds'],
        bounds_order=['cpu_seconds', 'memory_bytes', 'file_size_bytes', 'wall_seconds'],
        reproduction=dict(revision=revision, cpu=cpu,
            precondition='Reserve this CPU externally and retain singleton affinity. Use a clean checkout of this exact revision and fresh output paths.',
            commands=[
                'python3 -B evaluation/inprocess/direct_frontier_loop.py --expect-revision ' + revision,
                'python3 -B evaluation/inprocess/bounded_block_owner.py --expect-revision ' + revision +
                ' --cpu ' + str(cpu) + ' --direct-receipt <FRESH_SAME_SOURCE_NATIVE41_PUBLIC_RECEIPT>' +
                ' --direct-receipt-sha256 <FRESH_SHA256> --output target/evaluation/inprocess/<FRESH_PB_CHILD>',
            ]))
    output_json = canonical(result) + b'\n'
    table = io.StringIO()
    fields = ['revision', 'cpu', 'cohort_status', 'lane', 'subject_status', 'launched',
        'process_exit', 'validation_duration_ns', 'timed_out', 'error', *CLOSURE,
        'qualification_credit', 'performance_credit', *CONTROL_COUNTS,
        'recorded_pair_sha256', 'stdout_bytes', 'stdout_sha256', 'stderr_bytes',
        'stderr_sha256', 'record_bytes', 'record_sha256']
    writer = csv.DictWriter(table, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    for subject in subjects:
        row = dict(revision=revision, cpu=cpu, cohort_status=r['status'], lane=subject['lane'],
            subject_status=subject['status'], launched=subject['launched'],
            process_exit=subject['process_exit'], validation_duration_ns=subject['validation_duration_ns'],
            timed_out=subject['timed_out'], error=subject['error'],
            qualification_credit=False, performance_credit=False,
            **{key: r[key] for key in CLOSURE}, **subject['recorded_control_counts'],
            recorded_pair_sha256=None if subject['recorded_pair'] is None else sha(canonical(subject['recorded_pair'])))
        for stream, value in subject['captures'].items():
            row[stream + '_bytes'], row[stream + '_sha256'] = value['bytes'], value['sha256']
        writer.writerow(row)
    output_csv = table.getvalue().encode()
    payload = output_json + output_csv
    need(len(payload) < 10 * 1024, 'combined compact JSON/CSV below10KiB')
    safe_text(payload.decode())
    need(fact(path) == receipt_fact, 'retained receipt unchanged before output')
    args.output.mkdir(parents=True, exist_ok=False)
    stem = '20261101-bounded-block-owner-' + revision[:12] + '-' + args.receipt_sha256[:12]
    for suffix, data in (('.json', output_json), ('.csv', output_csv)):
        with (args.output / (stem + suffix)).open('xb') as output:
            output.write(data)
    print(json.dumps({stem + suffix: fact(args.output / (stem + suffix))
                      for suffix in ('.json', '.csv')}, sort_keys=True))


if __name__ == '__main__':
    main()
