#!/usr/bin/env python3
"""Committed-source, optimized one-child raw-fork continuation and custody checks."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys

sys.dont_write_bytecode = True
from checks import source
from dynamic import invoke, completed
import fork_cohort as cohort
from fork_supervise import ENV
from run import file_digest, hardware, invalid_constant, pairs, require

ROOT = Path(__file__).resolve().parents[2]
BUILD = Path('target/page-entry')
BINARIES = ('bridge-loader.so', 'fork-probe', 'fork-carrier', 'continuation-probe',
            'continuation-carrier', 'continuation-gpr-probe', 'continuation-gpr-carrier',
            'continuation-redzone-probe', 'continuation-redzone-carrier', 'supervisor-probe')


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=pairs, parse_constant=invalid_constant)


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def labels():
    return ([mode + '-' + case for case in cohort.CASES for mode in ('native', 'gated')]
            + ['native-child-failure'] + ['gated-child-failure-' + str(n) for n in range(1, 5)]
            + ['default-refusal'] + [mode + '-continuation-' + kind for kind in ('positive', 'gpr', 'redzone')
                                     for mode in ('native', 'gated')]
            + ['supervisor-' + name for name in cohort.controls.NAMES])


def error(value):
    # Exception messages and private process/file identities remain in target/.
    return None if value is None else {'type': value['type'], 'errno': value.get('errno'),
                                      'details_sha256': hashed(value)}


def project(row):
    result = {key: row[key] for key in ('label', 'exit_code', 'timeout', 'cleanup_complete',
              'leader_reaped', 'leader_pin_lost', 'echild', 'duration_seconds')}
    result.update(command_sha256=hashed(row['command']), failure=error(row['failure']),
                  secondary_errors=[error(value) for value in row['secondary_errors']],
                  adopted_exit_codes=[value['exit_code'] for value in row['adopted_reaps']],
                  kill_results=[{'result': value['result'], 'errno': value['errno'],
                                 'before_leader_reap': value['before_leader_reap']} for value in row['kills']],
                  closed_fds=sum(value['state'] == 'closed' for value in row['fds']),
                  unresolved_fds=sum(value['state'] != 'closed' for value in row['fds']),
                  captures=row['captures'])
    if row['reports']:
        result['runtime'] = [{key: report[key] for key in ('role', 'status', 'failure_code',
            'attempted', 'returned', 'child_ready', 'setup_started', 'setup_complete', 'gate_observed')}
            | {'inherited_counters': report['inherited'], 'current_counters': report['current']}
            for report in row['reports']]
    return result


def namespace(row, directory, binaries, pins):
    observed, launch = read(directory / 'namespace.json'), read(directory / 'launch.json')
    argv = row['command']
    split = argv.index('--')
    carrier, original = Path(argv[split - 2]), Path(argv[split - 1])
    require(carrier.parent == original.parent == ROOT / BUILD and carrier.name in BINARIES
            and original.name in BINARIES, 'namespace_binary_paths')
    require(observed['schema_version'] == launch['schema_version'] == 1
            and observed['status'] == launch['status'] == 'prepared_not_executed'
            and observed['scope'] == 'explicit_sealed_dependency_namespace'
            and observed['original'] == str(original)
            and observed['original_sha256'] == binaries[original.name]
            and launch['carrier_sha256'] == binaries[carrier.name]
            and launch['argv'] == argv[split + 1:]
            and observed['directory'] == str(directory)
            and observed['roots'] == [str(Path('/usr/lib64').resolve())], 'namespace_binding')
    objects = observed['objects']
    require(type(objects) is list and 1 <= len(objects) <= 32, 'namespace_objects')
    fds = [value['fd'] for value in objects]
    require(launch['dependency_fds'] == fds and len(set(fds)) == len(fds)
            and all(type(fd) is int and fd > 2 for fd in fds), 'namespace_fd_binding')
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
                   'LD_LIBRARY_PATH': str(directory), 'LD_BIND_NOW': '1',
                   'LI2_DEPENDENCY_FDS': ','.join(map(str, fds))}
    if row['mode'] == 'gated':
        report_fds = [next(value['fd'] for value in row['fds'] if value['name'] == 'report-' + str(n) + '-write')
                      for n in (0, 1)]
        environment.update(LI2_RAW_FORK='1', LI2_FORK_REPORT_FDS=','.join(map(str, report_fds)))
        if row['failure_step']:
            environment['LI2_FORK_CHILD_FAILURE'] = str(row['failure_step'])
    require(launch['environment'] == environment, 'namespace_environment')
    for value in objects:
        require(type(value['size']) is int and 0 < value['size'] <= 16*1024**2 and value['seals'] == 15,
                'namespace_sealed_extent')
        path = Path(value['source'])
        require(path.is_absolute() and path.resolve().is_relative_to(Path('/usr/lib64').resolve())
                and file_digest(path) == value['sha256'] and path.stat().st_size == value['size'], 'namespace_source_identity')
        require(path not in pins or pins[path] == value['sha256'], 'namespace_source_changed')
        pins[path] = value['sha256']
    interpreter = Path(observed['interpreter'])
    require(file_digest(interpreter) == observed['interpreter_sha256'], 'namespace_interpreter_identity')
    require(interpreter not in pins or pins[interpreter] == observed['interpreter_sha256'], 'interpreter_changed')
    pins[interpreter] = observed['interpreter_sha256']
    return {'objects': len(objects), 'namespace_sha256': file_digest(directory / 'namespace.json'),
            'launch_sha256': file_digest(directory / 'launch.json'),
            'object_sha256': [value['sha256'] for value in objects]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    require(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision),
            'invalid_expected_revision')
    os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp + '-fork-' + args.expect_revision[:12]
    private = ROOT / 'target/evaluation/inprocess' / name
    private.mkdir(parents=True, exist_ok=False)
    public = Path('evaluation/inprocess/results') / (name + '.json')
    require(not public.exists(), 'receipt_already_exists')
    affinity = os.sched_getaffinity(0)
    cpu = min(affinity)
    record = {'schema_version': 1, 'profile': 'first-entry-raw-fork-v1', 'status': 'failed',
              'revision': args.expect_revision, 'started_utc': stamp, 'source': None,
              'source_unchanged': None, 'binaries_unchanged': None,
              'tools_and_dependencies_unchanged': None, 'source_patches': 0,
              'build_profile': 'optimized-C-O2', 'planned_commands': 39,
              'original_commands': 24, 'continuation_commands': 6, 'supervisor_commands': 9,
              'environment': ENV, 'preparation': [], 'commands': [],
              'scope': 'One raw SYS_fork and bounded wait4 in a sealed first-entry namespace; two singleton address spaces. Kernel traps and NX, no clone/libc-fork/exec/thread or general B3 claim.',
              'timing_scope': 'Diagnostic whole-command durations including namespace preparation; no performance or instrumentation-overhead claim.',
              'cleanup_scope': 'Expected close/reap error controls retain cleanup=false; their separate controls require actual terminal ownership. Other commands require cleanup=true.',
              'runner_sha256': file_digest(Path(__file__)),
              'build_command': ['sh', 'tools/page-entry/build.sh'],
              'workload_command_recipe': {
                  'native': ['target/page-entry/{fixture}-probe', '{fixture_arguments}'],
                  'gated': ['python3', 'tools/page-entry/carrier.py', 'exec-fork', '--library-root', '/usr/lib64',
                            '--namespace', '{private_namespace}', '--report-parent', '{parent_report_fd}',
                            '--report-child', '{child_report_fd}', '{optional_child_failure_args}',
                            'target/page-entry/{fixture}-carrier', 'target/page-entry/{fixture}-probe', '--',
                            'target/page-entry/{fixture}-probe', '{fixture_arguments}'],
                  'default': 'exec-loader with no fork-report or failure arguments',
                  'supervisor': ['target/page-entry/supervisor-probe', '{mode}', '{report_0_fd}', '{report_1_fd}', '{supervisor_pid}'],
                  'actual_argv': 'Private command.json; each public row retains its exact argv hash.'},
              'workload_bounds': {'cpu_seconds': 5, 'address_bytes': 512*1024*1024,
                  'per_file_bytes_including_captures': 16*1024*1024, 'accepted_capture_bytes': 65536,
                  'accepted_report_bytes': 4096, 'wall_seconds': 15, 'cleanup_seconds': 2,
                  'process_count_override': None},
              'reproduce': ['python3', 'evaluation/inprocess/fork.py', '--expect-revision', args.expect_revision]}
    pins, raw, preparation = {}, None, []
    try:
        record['source'] = source()
        require(record['source']['revision'] == args.expect_revision, 'revision_differs')
        os.sched_setaffinity(0, {cpu})
        record['hardware'] = hardware(cpu)
        record['toolchain'] = {}
        for tool, path in (('cc', shutil.which('cc', path=ENV['PATH'])),
                           ('python3', sys.executable),
                           ('build_python3', shutil.which('python3', path=ENV['PATH'])),
                           ('sh', shutil.which('sh', path=ENV['PATH']))):
            require(path is not None, 'tool_not_found')
            pins[Path(path).resolve()] = file_digest(Path(path).resolve())
            record['toolchain'][tool] = {'sha256': pins[Path(path).resolve()]}
            if tool == 'sh':
                continue
            row, stdout, stderr = invoke([path, '--version'], ENV, Path('.'), private, tool + '-version', cpu, build=True)
            preparation.append(row)
            record['preparation'].append({key: row[key] for key in ('label', 'exit_code', 'timed_out',
                'leader_reaped', 'stdout_sha256', 'stdout_bytes', 'stderr_sha256', 'stderr_bytes')})
            require(completed(row) and not row['capture_errors'] and stdout.stat().st_size + stderr.stat().st_size <= 16384,
                    'tool_version_failed')
            banner = (stdout.read_bytes() + stderr.read_bytes()).decode('utf-8').splitlines()
            version = re.search(r'(?<![0-9])([0-9]+\.[0-9]+(?:\.[0-9]+)*)(?![0-9])', banner[0] if banner else '')
            require(version is not None, 'numeric_tool_version_missing')
            record['toolchain'][tool]['version'] = version[1]
        row, _, _ = invoke(['sh', 'tools/page-entry/build.sh'], ENV, Path('.'), private, 'build', cpu, build=True)
        preparation.append(row)
        record['preparation'].append({key: row[key] for key in ('label', 'exit_code', 'timed_out',
            'leader_reaped', 'stdout_sha256', 'stdout_bytes', 'stderr_sha256', 'stderr_bytes')})
        require(completed(row) and not row['capture_errors'], 'fork_release_build_failed')
        binaries = {name: file_digest(BUILD / name) for name in BINARIES}
        record['binaries'] = binaries
        raw = {}
        code = cohort.main(['--library-root', '/usr/lib64', '--output', str(private / 'cohort')], raw)
        require(read(private / 'cohort/receipt.json') == raw, 'private_cohort_receipt_differs')
        record['private_receipt_sha256'] = file_digest(private / 'cohort/receipt.json')
        record['cohort_failure'] = error(raw['failure'])
        record['cohort_secondary_errors'] = [error(value) for value in raw['secondary_errors']]
        require([row['label'] for row in raw['commands']] == labels()[:len(raw['commands'])], 'cohort_order_or_duplicate')
        record['commands'] = [project(row) for row in raw['commands']]
        for row, compact in zip(raw['commands'], record['commands']):
            folder = private / 'cohort' / row['label']
            require(read(folder / 'command.json') == row, 'attempted_row_differs')
            compact['private_command_sha256'] = file_digest(folder / 'command.json')
            require(row['resource_profile'] == record['workload_bounds'], 'workload_bounds_changed')
            require(set(row['captures']) <= {'stdout', 'stderr', 'report-0', 'report-1', 'state-0', 'state-1'}, 'unknown_capture')
            for filename, observed in row['captures'].items():
                path = folder / filename
                require(observed == {'bytes': path.stat().st_size, 'sha256': file_digest(path)}, 'capture_changed')
            if row['mode'] in ('gated', 'default'):
                compact['namespace'] = namespace(row, folder / 'namespace', binaries, pins)
        record['supervisor_controls'] = raw.get('supervisor_controls', [])
        record['continuation'] = [{key: value for key, value in summary.items()
                                   if key not in ('native_pids', 'gated_pids', 'gated_fork_result')}
                                  for summary in raw.get('continuation', [])]
        record['supplied_continuation_controls'] = raw.get('supplied_continuation_controls')
        require(code == 0 and raw['passed'] is True and raw['source_unchanged'] is True
                and raw['failure'] is None and raw['secondary_errors'] == [] and len(raw['commands']) == 39
                and raw['planned_commands'] == 39 and raw['original_commands'] == 24
                and raw['continuation_commands'] == 6 and raw['supervisor_commands'] == 9
                and raw['supplied_continuation_controls'] == 30 and len(raw['supervisor_controls']) == 9,
                'fork_cohort_failed')
        require(raw['binaries'] == {str(BUILD / name): value for name, value in binaries.items()}, 'cohort_binary_binding')
        record['status'] = 'passed'
    except BaseException as failure:
        record['failure'] = {'type': type(failure).__name__, 'errno': getattr(failure, 'errno', None)}
    finally:
        # The shared in-memory owner survives even a failed private receipt
        # write. Preserve its actual attempted prefix without inventing a file.
        if raw and 'commands' in raw:
            record['cohort_failure'] = error(raw['failure'])
            record['cohort_secondary_errors'] = [error(value) for value in raw['secondary_errors']]
            for row in raw['commands'][len(record['commands']):]:
                record['commands'].append(project(row))
        try:
            (private / 'preparation.json').write_text(json.dumps(preparation, indent=2) + '\n')
            record['preparation_sha256'] = file_digest(private / 'preparation.json')
        except BaseException as failure:
            record['status'] = 'failed'
            record['preparation_save_error'] = {'type': type(failure).__name__, 'errno': getattr(failure, 'errno', None)}
        try:
            record['source_unchanged'] = record['source'] is not None and source() == record['source']
            record['binaries_unchanged'] = ('binaries' in record and
                {name: file_digest(BUILD / name) for name in BINARIES} == record['binaries'])
            record['tools_and_dependencies_unchanged'] = all(file_digest(path) == value for path, value in pins.items())
        except BaseException as failure:
            record['source_unchanged'] = None
            record['final_observation_error'] = {'type': type(failure).__name__, 'errno': getattr(failure, 'errno', None)}
        if not all(record.get(key) is True for key in ('source_unchanged', 'binaries_unchanged', 'tools_and_dependencies_unchanged')):
            record['status'] = 'failed'
        try:
            os.sched_setaffinity(0, affinity)
        except OSError as failure:
            record['status'] = 'failed'
            record['affinity_restore_errno'] = failure.errno
        record['not_run'] = labels()[len(raw['commands']) if raw and 'commands' in raw else 0:]
        data = json.dumps(record, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
        require(not any(len(value) > 1 and value in data for value in
                        (str(Path.home()), str(ROOT), platform.node())), 'private_receipt_data')
        public.parent.mkdir(parents=True, exist_ok=True)
        with public.open('x') as handle:
            handle.write(data)
        print(public)
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
