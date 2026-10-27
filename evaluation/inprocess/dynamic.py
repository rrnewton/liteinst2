#!/usr/bin/env python3
"""Release comparison of a real dynamic program under post-constructor page mode."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import statistics
import subprocess
import select
import time

from run import Refusal, file_digest, hardware, invalid_constant, output, pairs, require

SOURCE_FILES = tuple('tools/page-mode/' + name for name in
                     ('preload.c', 'gateway.S', 'probe_api.h', 'probe.c', 'build.sh', 'README.md',
                      'lifecycle.c', 'lifecycle.h', 'lifecycle_probe.c', 'lifecycle_dso.c', 'LIFECYCLE.md'))
METRIC_KEYS = {'version', 'scope', 'source_patches', 'status', 'failure_code', 'failure_detail_abs',
               'gated_pages', 'main_pages', 'nx_faults', 'nx_service_ns_total', 'nx_service_ns_max',
               'cpuid_traps', 'rdtsc_traps', 'rdtscp_traps', 'selfcheck_cpuid', 'selfcheck_rdtsc',
               'selfcheck_syscall', 'capability_checks', 'syscall_traps', 'forwarded_syscalls',
               'mmap_calls', 'mprotect_calls', 'munmap_calls', 'active_ns'}
STEADY_KEYS = {'version', 'iterations', 'warm_iterations', 'elapsed_ns', 'snapshot_present',
               'nx_before', 'nx_after', 'syscalls', 'forwarded'}
CASES = (('ls_directory', ['/bin/ls', '-d', '.']),
         ('ls_numeric_listing', ['/bin/ls', '-ln', '--color=never', '.']),
         ('mapping_probe', ['../dynamic_probe']))
SETTINGS = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C', 'TZ': 'UTC', 'LD_BIND_NOW': '1'}
BOUNDS = {'cpu_seconds': 3, 'address_space_bytes': 256 * 1024**2,
          'capture_file_bytes': 1024**2, 'wall_seconds': 10}


def invoke(argv, environment, cwd, private, label, cpu, build=False, pass_fds=()):
    stdout = private / (label + '.stdout')
    stderr = private / (label + '.stderr')
    seconds = 60 if build else BOUNDS['wall_seconds']
    row = {'label': label, 'argv': argv, 'cwd': cwd.as_posix(), 'affinity_cpu': cpu,
           'timeout_seconds': seconds, 'exit_code': None, 'timed_out': False,
           'leader_reaped': False, 'killpg_requested': False, 'killpg_errno': None,
           'error': None, 'error_errno': None, 'capture_errors': {}}
    process = None
    pidfd = None
    started = time.perf_counter_ns()

    def limits():
        os.sched_setaffinity(0, {cpu})
        resource.setrlimit(resource.RLIMIT_CPU, (30, 30) if build else (3, 3))
        memory = 1024**3 if build else BOUNDS['address_space_bytes']
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        size = 16 * 1024**2 if build else BOUNDS['capture_file_bytes']
        resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    def exited(timeout):
        return bool(select.select([pidfd], [], [], timeout)[0])

    def stop_and_reap():
        # A completed wait may set returncode before an interrupt updates the row.
        # Never signal a numeric PID after the child has already been reaped.
        if process.returncode is not None:
            row['exit_code'] = process.returncode
            row['leader_reaped'] = True
            return
        # Even an exited, unreaped leader can leave children in its group.
        # Its retained identity still prevents reuse of the numeric PID.
        row['killpg_requested'] = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError as error:
            row['killpg_errno'] = error.errno
        try:
            if pidfd is not None and not exited(5):
                row['error'] = row['error'] or 'leader_reap_timeout'
                return
            row['exit_code'] = process.wait(timeout=5)
            row['leader_reaped'] = True
        except subprocess.TimeoutExpired:
            row['error'] = row['error'] or 'leader_reap_timeout'
        except OSError as error:
            row['error'] = row['error'] or 'leader_reap_failed'
            row['error_errno'] = error.errno

    try:
        with stdout.open('xb') as out, stderr.open('xb') as err:
            process = subprocess.Popen(argv, env=environment, cwd=cwd, stdout=out, stderr=err,
                                       start_new_session=True, preexec_fn=limits, pass_fds=pass_fds)
            pidfd = os.pidfd_open(process.pid)
            # Event-driven exit readiness avoids timed-wait polling in measurements.
            if exited(seconds):
                row['exit_code'] = process.wait()
                row['leader_reaped'] = True
            else:
                row['timed_out'] = True
                stop_and_reap()
    except (OSError, subprocess.SubprocessError) as error:
        row['error'] = 'spawn_or_capture_failed' if process is None else 'process_wait_failed'
        row['error_errno'] = getattr(error, 'errno', None)
        if process is not None and not row['leader_reaped']:
            stop_and_reap()
    except KeyboardInterrupt:
        row['error'] = 'interrupted'
        if process is not None and not row['leader_reaped']:
            stop_and_reap()
    finally:
        if pidfd is not None:
            os.close(pidfd)
    row['wall_ns'] = time.perf_counter_ns() - started
    for name, path in (('stdout', stdout), ('stderr', stderr)):
        try:
            row[name + '_sha256'] = file_digest(path)
            row[name + '_bytes'] = path.stat().st_size
        except OSError as error:
            row[name + '_sha256'] = None
            row[name + '_bytes'] = None
            row['capture_errors'][name] = error.errno
            row['error'] = row['error'] or 'capture_read_failed'
    return row, stdout, stderr


def completed(command):
    return command['exit_code'] == 0 and not command['timed_out'] and command['leader_reaped'] and command['error'] is None


def object_row(line, prefix):
    require(line.startswith(prefix), 'missing_diagnostic_prefix')
    row = json.loads(line[len(prefix):], object_pairs_hook=pairs, parse_constant=invalid_constant)
    require(type(row) is dict, 'diagnostic_not_object')
    return row


def metric_row(line):
    row = object_row(line, 'LI2_DYNAMIC ')
    require(set(row) == METRIC_KEYS, 'dynamic_metric_keys')
    require(row['scope'] == 'post_constructor', 'dynamic_scope')
    for key in METRIC_KEYS - {'scope'}:
        require(type(row[key]) is int and 0 <= row[key] <= 2**64 - 1, 'dynamic_numeric_metric')
    require(row['version'] == 1 and row['source_patches'] == 0, 'dynamic_backend')
    require(row['status'] == 0 and row['failure_code'] == 0 and row['failure_detail_abs'] == 0,
            'dynamic_refusal_or_failure')
    require(0 < row['main_pages'] <= row['gated_pages'] and 0 < row['nx_faults'] <= row['gated_pages'],
            'no_page_activation')
    require(all(row[key] == 1 for key in ('selfcheck_cpuid', 'selfcheck_rdtsc', 'selfcheck_syscall', 'capability_checks')),
            'semantic_capability_checks_missing')
    require(0 < row['syscall_traps'] == row['forwarded_syscalls'], 'syscall_forwarding_mismatch')
    require(0 <= row['nx_service_ns_max'] <= row['nx_service_ns_total'] and row['active_ns'] > 0,
            'timing_unavailable_or_inconsistent')
    return row


def observations(stderr, mode, case):
    lines = stderr.decode().splitlines()
    if case != 'mapping_probe':
        require(len(lines) == (1 if mode == 'instrumented' else 0), 'unexpected_ls_stderr')
        return {'metrics': metric_row(lines[0])} if lines else {}
    require(len(lines) == (2 if mode == 'instrumented' else 1), 'unexpected_probe_stderr')
    row = object_row(lines[0], 'LI2_STEADY ')
    require(set(row) == STEADY_KEYS, 'steady_keys')
    for key, value in (('version', 1), ('iterations', 1000), ('warm_iterations', 1)):
        require(type(row[key]) is int and row[key] == value, 'steady_identity')
    require(type(row['elapsed_ns']) is int and 0 < row['elapsed_ns'] <= 2**64 - 1, 'steady_time')
    require(row['snapshot_present'] is (mode == 'instrumented'), 'steady_counter_provenance')
    if mode == 'reference':
        require(all(row[key] is None for key in ('nx_before', 'nx_after', 'syscalls', 'forwarded')),
                'invented_reference_counters')
        return {'steady': row}
    require(all(type(row[key]) is int and 0 <= row[key] <= 2**64 - 1
                for key in ('nx_before', 'nx_after', 'syscalls', 'forwarded')), 'steady_numeric_metric')
    require(0 < row['nx_before'] == row['nx_after'] and row['syscalls'] == 4002 and row['forwarded'] == 4002,
            'steady_fault_or_syscall_mismatch')
    metrics = metric_row(lines[1])
    require(all(metrics[key] >= 1 for key in ('mmap_calls', 'mprotect_calls', 'munmap_calls', 'cpuid_traps', 'rdtsc_traps')),
            'missing_actual_dynamic_operation')
    return {'steady': row, 'metrics': metrics}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error('repeats must be in 1..20')
    revision = output(['git', 'rev-parse', 'HEAD'])
    if output(['git', 'status', '--porcelain', '--untracked-files=no']):
        parser.error('tracked source must be committed before measurement')
    source_names = SOURCE_FILES + ('evaluation/inprocess/dynamic.py', 'evaluation/inprocess/run.py')
    for name in source_names:
        if subprocess.run(['git', 'ls-files', '--error-unmatch', name], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=20).returncode != 0:
            parser.error('all measurement sources must be committed tracked files')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    private = Path('target/evaluation/inprocess') / (stamp + '-dynamic-' + revision[:12])
    private.mkdir(parents=True, exist_ok=False)
    destination = args.output or Path('evaluation/inprocess/results') / (stamp + '-dynamic-' + revision[:12] + '.json')
    if destination.exists():
        parser.error('output already exists')
    cpu = min(os.sched_getaffinity(0))
    record = {'schema_version': 1, 'status': 'failed', 'revision': revision,
              'tree': output(['git', 'rev-parse', 'HEAD^{tree}']), 'started_utc': stamp,
              'scope': 'post_constructor_kernel_traps_and_NX', 'source_patches': 0,
              'build_profile': 'release-O2', 'repeats': args.repeats, 'bounds': BOUNDS,
              'build_bounds': {'cpu_seconds': 30, 'address_space_bytes': 1024**3,
                               'file_bytes': 16 * 1024**2, 'wall_seconds': 60},
              'environment': SETTINGS, 'instrumented_environment_delta': {'LD_PRELOAD': '../libli2_dynamic.so'},
              'reproduce': ['python3', 'evaluation/inprocess/dynamic.py', '--repeats', str(args.repeats)],
              'wall_measurement': 'fresh child creation through reap, including harness overhead',
              'pair_order': ['reference', 'instrumented'], 'commands': [], 'rows': [],
              'source_unchanged': None}
    try:
        record['hardware'] = hardware(cpu)
        record['source_sha256'] = {name: file_digest(Path(name)) for name in source_names}
        compiler = shutil.which('cc', path=SETTINGS['PATH'])
        require(compiler is not None, 'compiler_not_found')
        record['toolchain'] = {'cc_version': subprocess.check_output([compiler, '--version'], env=SETTINGS,
                                                                    text=True, timeout=20).strip(),
                               'cc_sha256': file_digest(Path(compiler).resolve())}
        command, _, _ = invoke(['sh', 'tools/page-mode/build.sh'], SETTINGS, Path('.'), private, 'build', cpu, build=True)
        record['commands'].append(command)
        require(completed(command), 'release_build_failed')
        binaries = {}
        for name in ('libli2_dynamic.so', 'dynamic_probe'):
            built = Path('target/page-mode') / name
            expected = file_digest(built)
            shutil.copy2(built, private / name)
            require(file_digest(private / name) == expected and file_digest(built) == expected, 'binary_copy_changed')
            binaries[name] = expected
        record['executable_sha256'] = binaries | {'/bin/ls': file_digest(Path('/bin/ls'))}
        fixture = private / 'fixture'
        fixture.mkdir()
        (fixture / 'alpha.txt').write_bytes(b'alpha\n')
        (fixture / 'beta.txt').write_bytes(b'actual dynamic directory data\n')
        (fixture / 'subdirectory').mkdir()
        record['fixture'] = {'files': {name: file_digest(fixture / name) for name in ('alpha.txt', 'beta.txt')},
                             'directories': ['subdirectory'], 'actual_cwd': fixture.as_posix()}
        for case, argv in CASES:
            for repeat in range(args.repeats):
                pair = {'case': case, 'repeat': repeat, 'stdout_equal': False}
                record['rows'].append(pair)
                outputs = {}
                for mode in ('reference', 'instrumented'):
                    for name, expected in record['executable_sha256'].items():
                        path = Path(name) if name == '/bin/ls' else private / name
                        require(file_digest(path) == expected, 'executable_changed')
                    environment = SETTINGS.copy()
                    if mode == 'instrumented':
                        environment['LD_PRELOAD'] = '../libli2_dynamic.so'
                    command, stdout, stderr = invoke(argv, environment, fixture, private,
                                                     f'{case}-{repeat}-{mode}', cpu)
                    record['commands'].append(command)
                    pair[mode] = command.copy()
                    require(completed(command), case + '_' + mode + '_execution_failed')
                    require(command['stdout_bytes'] <= 65536 and command['stderr_bytes'] <= 65536,
                            'oversized_workload_output')
                    outputs[mode] = stdout.read_bytes()
                    pair[mode].update(observations(stderr.read_bytes(), mode, case))
                require(outputs['reference'] == outputs['instrumented'], case + '_stdout_differs')
                pair['stdout_equal'] = True
        record['summary'] = {
            case: {mode + '_median_wall_ns': int(statistics.median(
                row[mode]['wall_ns'] for row in record['rows'] if row['case'] == case))
                   for mode in ('reference', 'instrumented')}
            for case, _ in CASES}
        record['summary']['mapping_probe'].update({
            mode + '_median_steady_ns': int(statistics.median(
                row[mode]['steady']['elapsed_ns'] for row in record['rows'] if row['case'] == 'mapping_probe'))
            for mode in ('reference', 'instrumented')})
        for name, expected in record['executable_sha256'].items():
            require(file_digest(Path(name) if name == '/bin/ls' else private / name) == expected, 'executable_changed')
        record['status'] = 'passed'
    except Refusal as error:
        record['error'] = str(error)
    except (ValueError, KeyError, TypeError, UnicodeError):
        record['error'] = 'invalid_workload_json'
    except (OSError, subprocess.SubprocessError) as error:
        record['error'] = 'metadata_or_capture_failed'
        record['error_errno'] = getattr(error, 'errno', None)
    finally:
        try:
            record['source_unchanged'] = (output(['git', 'rev-parse', 'HEAD']) == revision and
                not output(['git', 'status', '--porcelain', '--untracked-files=no']) and
                all(file_digest(Path(name)) == expected for name, expected in record.get('source_sha256', {}).items()))
        except (OSError, subprocess.SubprocessError):
            record['source_unchanged'] = None
        if record['source_unchanged'] is not True:
            record['status'] = 'failed'
            record.setdefault('error', 'source_changed_or_unobserved')
        text = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n'
        private_markers = {str(Path.home()), str(Path.cwd()), platform.node()}
        if any(value and len(value) > 1 and value in text for value in private_markers):
            raise RuntimeError('public receipt contains private location data')
        (private / 'receipt.json').write_text(text)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x') as result:
            result.write(text)
        print(destination)
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
