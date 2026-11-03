#!/usr/bin/env python3
"""Optional diagnostic of the unchanged current 366-case/four-worker recorder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import sys

ROOT = Path(__file__).resolve().parents[3]
ADMISSION = ROOT / 'evaluation/admission'
sys.path.insert(0, str(ADMISSION))
import run as admission

PINS = {
    'evaluation/inprocess/diagnostics/recorder_timing.py': 'c8102f3d282efd432ab1853f8db8656252d69341b66b174bbb4e8636e4fd7b21',
    'evaluation/admission/recorder_parallel.py': 'a30f938577e1e4038d314295d58e118dc39618d50ee0863ed510412f03635861',
    'evaluation/admission/run.py': 'd9462b5ec03f3085564907d0fa1d42e882d49900651e05899d5b3f4122ddab3f',
    'evaluation/admission/processes.py': '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f',
}


def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def source():
    state = admission.source_state()
    admission.require(state['tracked_clean'] and state['head_sources_match'], 'dirty_tracked_source')
    for name in admission.git('ls-files', '--others', '--exclude-standard').decode().splitlines():
        admission.require(name == 'BRIEF-li2adm.md' or name.startswith(
            ('evaluation/admission/results/', 'evaluation/inprocess/results/')), 'untracked_input')
    admission.require(all(state['source_sha256'].get(path) == digest for path, digest in PINS.items()),
                      'changed_observer_or_command_owner')
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    admission.require(__debug__ and re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact_revision')
    cpus = sorted(os.sched_getaffinity(0))
    admission.require(len(cpus) == 4, 'exact_four_reserved_cpus')
    os.chdir(ROOT)
    out = ROOT / 'target/evaluation/inprocess/recorder-current-timing-attempt-1'
    out.mkdir(); (out / 'tmp').mkdir()
    log = out / 'recorder_tests.log'
    record = dict(schema=1, profile='current-recorder-timing-diagnostic-v1', status='failed',
        expected_revision=args.expect_revision, cpus=cpus, driver=fact(__file__), source=None,
        command=None, error=None, source_unchanged=False, configuration_unchanged=False,
        inputs_unchanged=False, affinity_unchanged=False, qualification_credit=False,
        required_check_credit=False, retry=False, workers=4, expected_cases=366,
        bounds=dict(wall_seconds=180, log_bytes=8 << 20), case_timings=[])
    env = None
    try:
        record['source'] = source()
        admission.require(record['source']['revision'] == args.expect_revision, 'revision_differs')
        env = admission.controlled_environment(os.environ, out / 'tmp')
        record['environment'] = env
        record['configuration'] = admission.cargo_configuration(env)
        record['hardware'] = admission.hardware()
        executable = Path(shutil.which('python3', path=env['PATH'])).resolve(strict=True)
        admission.require(executable == Path(sys.executable).resolve(), 'actual_python_identity')
        record['python'] = dict(path=str(executable), version=sys.version, **fact(executable))
        record['inputs'] = {name: fact(ROOT / name) for name in (*PINS, 'evaluation/admission/corpus.json')}
        corpus = json.loads((ADMISSION / 'corpus.json').read_bytes())
        admission.require(corpus['schema_version'] == 1 and corpus['recorder_tests'] ==
                          admission.core_cc846_inventory.RECORDER_TESTS == 366, 'changed_recorder_corpus')
        admission.backing_cleanup_query.require_inventory(corpus)
        admission.precontext_native.require_inventory(corpus)
        admission.core_cc846_inventory.require_current(corpus)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        record['inherited_limits'] = {name: resource.getrlimit(getattr(resource, name)) for name in
                                     ('RLIMIT_CPU', 'RLIMIT_AS', 'RLIMIT_FSIZE', 'RLIMIT_CORE')}
        argv = ['python3', 'evaluation/inprocess/diagnostics/recorder_timing.py']
        record['command'] = dict(id='recorder_tests', argv=argv, status='running')
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        record['command'].update(admission.run_command(argv, env, log, 180, max_log_bytes=8 << 20))
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        record['child_usage_seconds'] = dict(user=after.ru_utime-before.ru_utime,
                                             system=after.ru_stime-before.ru_stime)
        command = record['command']
        command['status'] = ('passed' if command['exit_code'] == 0 and command['termination'] is None
                             and command['cleanup_complete'] else 'failed')
        output = log.read_text(errors='replace')
        admission.command_evidence(command, output, corpus)
        for line in output.splitlines():
            match = re.fullmatch(r'\[worker ([0-3])\] CASE_TIMING (.+)', line)
            if match:
                row = json.loads(match[2])
                admission.require(type(row) is dict and set(row) == {'identity', 'wall_ns', 'cpu_ns'}
                    and type(row['identity']) is str and all(type(row[k]) is int and row[k] >= 0
                    for k in ('wall_ns', 'cpu_ns')), 'typed_case_timing')
                record['case_timings'].append(dict(worker=int(match[1]), **row))
        identities = [row['identity'] for row in record['case_timings']]
        admission.require(len(identities) == len(set(identities)) <= 366, 'unique_completed_timings')
        if command['status'] == 'passed':
            rows = [json.loads(line.removeprefix('RECORDER_AGGREGATE '))
                    for line in output.splitlines() if line.startswith('RECORDER_AGGREGATE ')]
            admission.require(len(rows) == 1 and rows[0]['workers'] == 4 and rows[0]['tests_run'] == 366
                and len(identities) == 366 and sorted(identities) == sorted(rows[0]['identities']),
                'timing_joins_complete_original_aggregate')
            record['status'] = 'observed_complete_diagnostic_only'
    except (Exception, KeyboardInterrupt) as error:
        record['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            record['source_unchanged'] = record['source'] is not None and source() == record['source']
            record['configuration_unchanged'] = env is not None and admission.cargo_configuration(env) == record['configuration']
            record['inputs_unchanged'] = ('inputs' in record and all(fact(ROOT / name) == value for
                name, value in record['inputs'].items()) and fact(__file__) == record['driver']
                and fact(Path(record['python']['path'])) == {k: record['python'][k] for k in ('bytes', 'sha256')})
            record['affinity_unchanged'] = sorted(os.sched_getaffinity(0)) == cpus
        except (Exception, KeyboardInterrupt) as error:
            record['closure_error'] = type(error).__name__ + ': ' + str(error)
        if record['error'] or not all(record[k] for k in ('source_unchanged', 'configuration_unchanged',
                                                         'inputs_unchanged', 'affinity_unchanged')):
            record['status'] = 'failed'
        if log.exists(): record['log'] = fact(log)
        (out / 'receipt.json').write_text(json.dumps(record, sort_keys=True, allow_nan=False) + '\n')
    print(json.dumps(dict(status=record['status'], command=record['command'], error=record['error'],
                         timings=len(record['case_timings']), receipt=fact(out / 'receipt.json'))), flush=True)
    return int(record['status'] != 'observed_complete_diagnostic_only')


if __name__ == '__main__':
    raise SystemExit(main())
