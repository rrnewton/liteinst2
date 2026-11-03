#!/usr/bin/env python3
"""Time the original complete serial command; never grant six-gate credit.

Run from a clean checkout on four reserved CPUs with Python 3.12. This portable
entrypoint may live outside that checkout. Output must be fresh under its
target/evaluation/ tree. Shared command, evidence and cleanup remain mandatory.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import sys
import time

ROOT = Path.cwd().resolve()
INPUTS = (
    'evaluation/inprocess/checks.py', 'evaluation/inprocess/run.py',
    'evaluation/admission/run.py', 'evaluation/admission/processes.py',
    'evaluation/admission/parsing.py', 'evaluation/admission/corpus.json',
    'evaluation/admission/core_cc846_inventory.py',
)
ARGV = ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--',
        '--test-threads=1', '--nocapture']
USAGE_FIELDS = ('ru_utime', 'ru_stime', 'ru_minflt', 'ru_majflt',
                'ru_inblock', 'ru_oublock', 'ru_nvcsw', 'ru_nivcsw')


def require(value, message):
    if not value:
        raise ValueError(message)


def authenticate(expected=None):
    facts = {}
    for name in INPUTS:
        path = ROOT / name
        require(path.resolve() == path and path.is_file(), 'input_path_changed')
        raw = path.read_bytes()
        facts[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                       'mode': path.stat().st_mode & 0o777}
    if expected is not None:
        require(facts == expected, 'inputs_changed')
    return facts


def usage(who):
    result = resource.getrusage(who)
    return {key: getattr(result, key) for key in USAGE_FIELDS}


def usage_delta(before, after):
    return {key: after[key] - before[key] for key in USAGE_FIELDS}


def harness_times(output, rows, parsing):
    """Join original outer elapsed lines to the unchanged strict parser's rows."""
    current = None
    last = {}
    for number, line in enumerate(output.splitlines(), 1):
        identity = parsing.harness_id(line)
        if identity is not None:
            current = identity
        match = parsing.SUMMARY.fullmatch(line)
        if match is not None and current is not None:
            counts = dict(zip(('passed', 'failed', 'ignored', 'measured', 'filtered'),
                              (int(match[i]) for i in range(2, 7))))
            last[current] = (counts | {'result': match[1]}, number, line, match[7])
    result = []
    for row in rows:
        item = {key: row[key] for key in ('id', 'status', 'expected_tests', 'expected_ignored')}
        item.update(elapsed_seconds=None, original_elapsed_line=None, log_line=None)
        if row['outer'] is not None:
            summary, number, line, seconds = last[row['id']]
            require(summary == row['outer'] and row['status'] == 'complete', 'outer_timing_join')
            item.update(elapsed_seconds=float(seconds), original_elapsed_line=line, log_line=number)
        result.append(item)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(len(args.expect_revision) == 40 and all(c in '0123456789abcdef'
            for c in args.expect_revision), 'unexpected_revision')
    require(sys.version_info[:2] == (3, 12) and not sys.flags.optimize, 'python312_assertions')
    require(len(os.sched_getaffinity(0)) == 4, 'requires_original_four_cpu_affinity')
    inputs = authenticate()
    os.chdir(ROOT)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / 'evaluation/inprocess'))
    import checks
    import parsing
    for module, path in ((checks, 'evaluation/inprocess/checks.py'),
                         (checks.admission, 'evaluation/admission/run.py'),
                         (parsing, 'evaluation/admission/parsing.py'),
                         (sys.modules[checks.file_digest.__module__], 'evaluation/inprocess/run.py'),
                         (sys.modules[checks.admission.run_command.__module__], 'evaluation/admission/processes.py')):
        require(Path(module.__file__).resolve() == ROOT / path, 'module_path_changed')
    require([(key, argv, seconds) for key, argv, seconds in checks.COMMANDS if key == 'serial_launch']
            == [('serial_launch', ARGV, 180)], 'serial_command_changed')
    private = args.output.resolve()
    require(private.is_relative_to(ROOT / 'target/evaluation') and
            private != ROOT / 'target/evaluation', 'private_output_required')
    private.mkdir(parents=True, exist_ok=False)
    temporary = private / 'tmp'
    temporary.mkdir()
    command = {'id': 'serial_launch', 'argv': ARGV, 'timeout_seconds': 180, 'status': 'not_run',
               'environment_delta': {'LITEINST_EVALUATION': '1'}, 'max_log_bytes': 8 * 1024 * 1024}
    record = {'schema': 1, 'profile': 'serial-timing-v1', 'status': 'preflight',
              'expected_revision': args.expect_revision, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'runner_sha256': checks.file_digest(Path(__file__)), 'inputs': inputs,
              'whole_profile_qualified': False, 'qualification_credit': False,
              'source_unchanged': False, 'configuration_unchanged': False, 'inputs_unchanged': False,
              'runner_unchanged': False,
              'commands': [command], 'affinity_cpus': sorted(os.sched_getaffinity(0)),
              'measurement_scope': 'One unchanged full serial command, including its normal capture and cleanup. No retries, sampler, ptrace, per-test wrapper, or altered poll cadence.'}
    env = None
    try:
        record['source'] = checks.source()
        require(record['source']['revision'] == args.expect_revision, 'source_revision')
        env = checks.admission.controlled_environment(os.environ, temporary)
        record['configuration'] = checks.admission.cargo_configuration(env)
        record['hardware'] = checks.hardware(min(os.sched_getaffinity(0)))
        record['toolchain'] = {name: checks.admission.tool_version(name, env) for name in ('rustc', 'cargo')}
        record['environment'] = checks.admission.ENV | {'CARGO_TARGET_DIR': 'target',
            'TMPDIR': 'private_run/tmp', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'RLIMIT_CORE': 0}
        data = (ROOT / 'evaluation/admission/corpus.json').read_bytes()
        record['corpus_sha256'] = checks.admission.sha(data)
        corpus = json.loads(data)
        require(corpus['schema_version'] == 1 and corpus['recorder_tests']
                == checks.admission.core_cc846_inventory.RECORDER_TESTS, 'changed_recorder_corpus')
        checks.admission.backing_cleanup_query.require_inventory(corpus)
        checks.admission.precontext_native.require_inventory(corpus)
        checks.admission.core_cc846_inventory.require_current(corpus)
        inventory = corpus['harness_test_counts']['serial_launch']
        require(len(inventory) == 27 and sum(row['tests'] for row in inventory.values()) == 1039
                and sum(row['ignored'] for row in inventory.values()) == 0, 'serial_population_changed')
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        clock = time.get_clock_info('monotonic')
        record['clock'] = {key: getattr(clock, key) for key in
                           ('implementation', 'resolution', 'monotonic', 'adjustable')}
        record['status'] = 'running'
        log = private / 'serial_launch.log'
        child_before, self_before = usage(resource.RUSAGE_CHILDREN), usage(resource.RUSAGE_SELF)
        begin = time.monotonic_ns()
        try:
            command.update(checks.admission.run_command(ARGV, env | command['environment_delta'],
                                                       log, 180, max_log_bytes=8 * 1024 * 1024))
        finally:
            end = time.monotonic_ns()
            child_after, self_after = usage(resource.RUSAGE_CHILDREN), usage(resource.RUSAGE_SELF)
            record['usage'] = {'monotonic_begin_ns': begin, 'monotonic_end_ns': end,
                'wall_nanoseconds': end - begin, 'children_before': child_before,
                'children_after': child_after, 'children_delta': usage_delta(child_before, child_after),
                'self_before': self_before, 'self_after': self_after,
                'self_delta': usage_delta(self_before, self_after)}
        command['status'] = ('passed' if command['exit_code'] == 0 and command['termination'] is None
                             and command['cleanup_complete'] else 'failed')
        output = log.read_text(errors='replace')
        checks.admission.command_evidence(command, output, corpus)
        record['harness_timings'] = harness_times(output, command.get('harnesses', []), parsing)
        record['status'] = 'serial_' + command['status'] + '_diagnostic_only'
    except (Exception, KeyboardInterrupt) as error:
        record['status'] = 'diagnostic_failed'
        record['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        try:
            record['source_unchanged'] = checks.source() == record.get('source')
            record['configuration_unchanged'] = (env is not None and
                checks.admission.cargo_configuration(env) == record.get('configuration'))
            authenticate(inputs)
            record['inputs_unchanged'] = True
            record['runner_unchanged'] = checks.file_digest(Path(__file__)) == record['runner_sha256']
        except (Exception, KeyboardInterrupt) as error:
            record['closure_error'] = type(error).__name__ + ': ' + str(error)
        if not all(record[key] for key in ('source_unchanged', 'configuration_unchanged',
                                           'inputs_unchanged', 'runner_unchanged')):
            record['status'] = 'diagnostic_failed'
        for field in checks.DETAILS:
            for row in command.get(field, []):
                row['qualified_run'] = False
        checks.compact(command)
        (private / 'receipt.json').write_text(json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n')
        print(json.dumps({'receipt': str((private / 'receipt.json').relative_to(ROOT)),
                          'status': record['status'], 'serial_status': command['status'],
                          'usage': record.get('usage'), 'qualification_credit': False}), flush=True)
    return 0 if record['status'] == 'serial_passed_diagnostic_only' else 1


if __name__ == '__main__':
    raise SystemExit(main())
