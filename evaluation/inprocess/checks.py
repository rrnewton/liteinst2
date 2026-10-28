#!/usr/bin/env python3
"""New required-check profile; old 360-second admission failures stay failed."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import sys

from run import Refusal, file_digest, hardware

ROOT = Path(__file__).resolve().parents[2]
ADMISSION = ROOT / 'evaluation/admission'
sys.path.insert(0, str(ADMISSION))
spec = importlib.util.spec_from_file_location('admission_validation', ADMISSION / 'run.py')
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)
COMMANDS = [(name, argv, 900 if name == 'workspace_tests' else seconds)
            for name, argv, seconds in admission.COMMANDS]
DETAILS = ('native_cases', 'dynamic_admission_fixtures', 'dynamic_matrix_cases',
           'native_validation_fixtures', 'backing_cleanup_harnesses')


def source():
    git = admission.git
    state = admission.source_state()
    admission.require(state['tracked_clean'] and state['head_sources_match'], 'dirty_tracked_source')
    for name in git('ls-files', '--others', '--exclude-standard').decode().splitlines():
        admission.require(name == 'BRIEF-li2adm.md' or name.startswith(
            ('evaluation/admission/results/', 'evaluation/inprocess/results/')), 'untracked_input')
    return {key: state[key] for key in
            ('revision', 'tree', 'source_manifest_sha256', 'tracked_clean', 'head_sources_match')}


def compact(command):
    for field in DETAILS:
        if field in command:
            rows = command.pop(field)
            command[field + '_count'] = {'catalog_rows': len(rows),
                                        'qualified': sum(row.get('qualified_run') is True for row in rows)}
    if 'harnesses' in command:
        rows = command.pop('harnesses')
        observed = [row['outer'] for row in rows if row['outer'] is not None]
        command['harness_totals'] = {
            'expected_harnesses': len(rows), 'complete_harnesses': sum(row['status'] == 'complete' for row in rows),
            'expected_tests': sum(row['expected_tests'] for row in rows),
            'expected_ignored': sum(row['expected_ignored'] for row in rows),
            'observed': {key: sum(row[key] for row in observed) for key in
                         ('passed', 'failed', 'ignored', 'measured', 'filtered')} if observed else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    admission.require(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision),
                      'invalid_expected_revision')
    os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp + '-checks-' + args.expect_revision[:12]
    private = ROOT / 'target/evaluation/inprocess' / name
    private.mkdir(parents=True, exist_ok=False)
    temporary = private / 'tmp'
    temporary.mkdir()
    public = ROOT / 'evaluation/inprocess/results' / (name + '.json')
    admission.require(not public.exists(), 'duplicate_run_id')
    record = {'schema_version': 1, 'profile': 'inprocess-required-checks-v1', 'status': 'preflight',
              'expected_revision': args.expect_revision, 'source': None, 'source_unchanged': None,
              'configuration_unchanged': None, 'started_utc': stamp, 'backing_cleanup_required': True, 'backing_cleanup_query_required': True,
              'runner_sha256': file_digest(Path(__file__)),
              'environment': admission.ENV | {'CARGO_TARGET_DIR': 'target', 'TMPDIR': 'private_run/tmp',
                                               'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'RLIMIT_CORE': 0},
              'scope': 'New 900-second workspace profile; no historical result is relabelled.',
              'log_limit_bytes_per_command': 8 * 1024 * 1024,
              'reproduce': ['python3', 'evaluation/inprocess/checks.py', '--expect-revision', args.expect_revision],
              'commands': [{'id': key, 'argv': argv, 'timeout_seconds': seconds, 'status': 'not_run',
                            'environment_delta': {'LITEINST_EVALUATION': '1'} if key == 'serial_launch' else {}}
                           for key, argv, seconds in COMMANDS]}
    try:
        record['source'] = source()
        admission.require(record['source']['revision'] == args.expect_revision, 'revision_differs')
        env = admission.controlled_environment(os.environ, temporary)
        record['configuration'] = admission.cargo_configuration(env)
        record['hardware'] = hardware(min(os.sched_getaffinity(0)))
        record['toolchain'] = {tool: admission.tool_version(tool, env) for tool in ('rustc', 'cargo')}
        data = (ADMISSION / 'corpus.json').read_bytes()
        record['corpus_sha256'] = admission.sha(data)
        corpus = json.loads(data)
        admission.require(corpus['schema_version'] == 1 and corpus['recorder_tests'] == admission.core_cc846_inventory.RECORDER_TESTS, 'changed_recorder_corpus')
        admission.backing_cleanup_query.require_inventory(corpus)
        admission.core_cc846_inventory.require_current(corpus)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        record['status'] = 'running'
        for command in record['commands']:
            log = private / (command['id'] + '.log')
            command.update(admission.run_command(command['argv'], env | command['environment_delta'],
                                                 log, command['timeout_seconds']))
            command['status'] = ('passed' if command['exit_code'] == 0 and command['termination'] is None
                                 and command['cleanup_complete'] else 'failed')
            admission.command_evidence(command, log.read_text(errors='replace'), corpus)
            print(json.dumps({key: command[key] for key in ('id', 'status', 'exit_code', 'seconds')}), flush=True)
            if command['status'] != 'passed':
                break
        record['source_unchanged'] = source() == record['source']
        record['configuration_unchanged'] = admission.cargo_configuration(env) == record['configuration']
        admission.qualify(record)
    except (Exception, KeyboardInterrupt) as error:
        record['status'] = 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed'
        record['error'] = str(error) if isinstance(error, (admission.InvalidEvidence, Refusal)) else type(error).__name__
        for command in record['commands']:
            for field in DETAILS:
                for row in command.get(field, []):
                    row['qualified_run'] = False
    finally:
        for command in record['commands']:
            compact(command)
        text = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n'
        (private / 'receipt.json').write_text(text)
        markers = {str(Path.home()), str(ROOT), platform.node()}
        if any(value and len(value) > 1 and value in text for value in markers):
            raise RuntimeError('public receipt contains private location data')
        public.parent.mkdir(parents=True, exist_ok=True)
        with public.open('x') as receipt:
            receipt.write(text)
        print(public.relative_to(ROOT))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
