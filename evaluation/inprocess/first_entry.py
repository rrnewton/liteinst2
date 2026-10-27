#!/usr/bin/env python3
"""Committed-source first-entry loader checks and whole-process comparisons."""
import argparse
from datetime import datetime, timezone
import errno
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import struct
import sys

sys.dont_write_bytecode = True
from checks import source
from dynamic import BOUNDS, invoke, object_row
from run import Refusal, file_digest, hardware, invalid_constant, pairs, require

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = Path('tools/page-entry')
BUILD = Path('target/page-entry')
SOURCE_NAMES = tuple('tools/page-entry/' + name for name in (
    'bridge.c', 'bridge.h', 'entry.S', 'sha256.h', 'runtime_loader.c',
    'lifecycle_loader.c', 'lifecycle_loader.h', 'carrier.py', 'namespace.py',
    'namespace_tests.py', 'build.sh', 'fixture_runtime.c', 'fixture-interpreter.S',
    'fixture-main.S', 'refusal_probe.c', 'refusal_thread.S')) + (
        'evaluation/inprocess/first_entry.py', 'evaluation/inprocess/dynamic.py',
        'evaluation/inprocess/checks.py', 'evaluation/inprocess/run.py')
BINARIES = ('bridge-loader.so', 'ls-carrier', 'refusal-probe', 'refusal-carrier',
            'bridge-fixture.so', 'fixture-interpreter.so', 'fixture-main', 'fixture-carrier')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
       'TZ': 'UTC', 'LD_BIND_NOW': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
METRIC_KEYS = set('version scope source_patches status failure_code detail_abs detail_negative '
                  'dependency_objects first_target_is_interpreter_entry interpreter_entry_faults '
                  'nx_faults main_faults interpreter_faults dependency_faults vdso_selected cpuid '
                  'rdtsc rdtscp syscalls forwarded tls_changes set_tid_address set_robust_list rseq '
                  'mappings generations retired admissions sync_core kernel_errors partial_errors '
                  'live_pages last_syscall last_mapping_syscall last_phase'.split())
FIXTURE = {'scope': 'first_entry_fixture', 'source_patches': 0,
           'main_initial_nx': True, 'logical_phdr_restored_in_place': True,
           'interpreter_first_cpuid': 1, 'main_first_rdtsc': 1,
           'nx_faults': 2, 'cpuid': 1, 'rdtsc': 1, 'syscalls': 3}
REFUSALS = (('thread', 210, 56, 56), ('gate_handler', 206, 13, 13),
            ('gate_mask', 206, 14, 14), ('gate_altstack', 207, 131, 131),
            ('unsealed_execute', 142, 0, 9), ('protected_write', 155, 0, 10),
            ('protected_unmap', 158, 0, 11), ('query_mask', 206, 14, 14),
            ('query_altstack', 207, 131, 131), ('query_segv', 206, 13, 13),
            ('query_sigsys', 206, 13, 13), ('query_segv_highbits', 206, 13, 13),
            ('query_sigsys_highbits', 206, 13, 13), ('fd_report_highbits', 204, 3, 3),
            ('fd_retained_highbits', 160, 3, 3), ('fd_original_highbits', 160, 3, 3))
CASES = (('ls_directory', ('-d', '.')), ('ls_numeric_listing', ('-ln', '.')))
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def relative(path, cwd):
    return os.path.relpath(path, cwd)


def completed(row, code):
    require(row['exit_code'] == code and not row['timed_out'] and row['leader_reaped']
            and row['error'] is None and not row['capture_errors'], 'command_did_not_complete')


def namespace_result(stdout, stderr):
    match = re.fullmatch(rb"(\.+)\n-{70}\nRan ([0-9]+) tests in [0-9]+\.[0-9]+s\n\nOK\n", stderr)
    require(stdout == b'' and match is not None, 'namespace_test_output')
    count = int(match[2])
    require(count == len(match[1]) == 5, 'namespace_test_cohort')
    return {'tests_run': count, 'passed': len(match[1]), 'exact_ok_terminal': True}


def loader_row(data):
    lines = data.decode('utf-8').splitlines()
    require(len(lines) == 1, 'loader_report_count')
    row = object_row(lines[0], 'LI2_LOADER ')
    require(set(row) == METRIC_KEYS and row['scope'] == 'sealed_dependency_namespace_first_entry',
            'loader_report_schema')
    require(all(type(row[k]) is int and 0 <= row[k] <= 2**64 - 1
                for k in METRIC_KEYS - {'scope'}), 'loader_report_numbers')
    require(row['version'] == 1 and row['source_patches'] == 0 and row['detail_negative'] in (0, 1),
            'loader_backend_identity')
    require(row['first_target_is_interpreter_entry'] in (0, 1), 'loader_entry_boolean')
    require(row['nx_faults'] == row['admissions'] == row['sync_core'] and
            row['nx_faults'] == row['main_faults'] + row['interpreter_faults'] + row['dependency_faults'],
            'loader_admission_counts')
    require(row['generations'] == row['retired'] + row['live_pages'] and
            row['forwarded'] <= row['syscalls'] and row['partial_errors'] <= row['kernel_errors'],
            'loader_lifetime_counts')
    return row


def entry_seen(row):
    require(row['first_target_is_interpreter_entry'] == row['interpreter_entry_faults'] == 1
            and row['main_faults'] > 0, 'actual_first_entry_missing')


def loader_success(row):
    entry_seen(row)
    require(row['status'] == row['failure_code'] == row['detail_abs'] == row['detail_negative'] == 0,
            'loader_report_failure')
    require(row['dependency_objects'] == 5 and row['dependency_faults'] > 0 and
            row['syscalls'] == row['forwarded'] > 0 and row['last_syscall'] == 231,
            'loader_execution_incomplete')
    require(row['tls_changes'] >= 1 and row['set_tid_address'] == row['set_robust_list'] == 1,
            'actual_loader_initialization_missing')


def fixture_row(data):
    lines = data.decode('utf-8').splitlines()
    require(len(lines) == 1, 'fixture_report_count')
    row = object_row(lines[0], 'LI2_FIRST_ENTRY ')
    require(set(row) == set(FIXTURE) and all(type(row[k]) is type(v) and row[k] == v
                                           for k, v in FIXTURE.items()), 'fixture_observations_differ')
    return row


def interpreter(path):
    data = path.read_bytes()
    require(64 <= len(data) <= 16 * 1024**2 and data[:7] == b'\x7fELF\x02\x01\x01', 'program_elf')
    offset, size, count = struct.unpack_from('<Q', data, 32)[0], *struct.unpack_from('<HH', data, 54)
    require(size == 56 and 0 < count <= 32 and offset + size * count <= len(data), 'program_headers')
    rows = [struct.unpack_from('<IIQQQQQQ', data, offset + i * size) for i in range(count)]
    rows = [p for p in rows if p[0] == 3]
    require(len(rows) == 1, 'program_interpreter_count')
    p = rows[0]
    value = data[p[2]:p[2] + p[5]]
    require(len(value) == p[5] and 2 <= len(value) <= 4096 and value[:1] == b'/' and
            value[-1:] == b'\0' and b'\0' not in value[:-1], 'program_interpreter_path')
    return Path(os.fsdecode(value[:-1]))


def namespace_evidence(directory, original, carrier_hash, expected_main, expected_interpreter, count, pin):
    # These are preparation records, never execution authority. Actual runtime
    # counters and exact native output are checked independently above.
    observed = json.loads((directory / 'namespace.json').read_text(), object_pairs_hook=pairs, parse_constant=invalid_constant)
    launch = json.loads((directory / 'launch.json').read_text(), object_pairs_hook=pairs, parse_constant=invalid_constant)
    require(observed['schema_version'] == 1 and observed['scope'] == 'explicit_sealed_dependency_namespace'
            and observed['status'] == 'prepared_not_executed' and
            observed['original'] == str(original.resolve()) and
            observed['original_sha256'] == expected_main and
            observed['interpreter_sha256'] == expected_interpreter,
            'namespace_original_binding')
    require(launch['schema_version'] == 1 and launch['status'] == 'prepared_not_executed' and
            launch['carrier_sha256'] == carrier_hash, 'namespace_carrier_binding')
    objects = observed['objects']
    require(type(objects) is list and len(objects) == count and 1 <= count <= 32,
            'namespace_object_count')
    require(launch['dependency_fds'] == [r['fd'] for r in objects] and
            all(type(fd) is int and fd > 2 for fd in launch['dependency_fds']) and
            len(set(launch['dependency_fds'])) == count, 'namespace_fd_binding')
    actual_directory = Path(observed['directory'])
    require(actual_directory.is_absolute() and actual_directory.resolve(strict=True) == directory.resolve(strict=True),
            'namespace_directory_binding')
    expected_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
                    'LD_LIBRARY_PATH': str(actual_directory), 'LD_BIND_NOW': '1',
                    'LI2_DEPENDENCY_FDS': ','.join(str(fd) for fd in launch['dependency_fds'])}
    require(launch['environment'] == expected_env and observed['roots'] == [str(Path('/usr/lib64').resolve())], 'namespace_environment')
    result = []
    for row in objects:
        require(type(row['size']) is int and 0 < row['size'] <= 16 * 1024**2 and row['seals'] == SEALS
                and type(row['names']) is list and row['names'] and
                all(type(name) is str and name not in ('.', '..') and len(name) <= 255 and
                    all(c.isascii() and (c.isalnum() or c in '._+-') for c in name) for name in row['names']),
                'namespace_object_shape')
        require(pin(Path(row['source'])) == row['sha256'], 'namespace_source_changed')
        result.append({k: row[k] for k in ('names', 'size', 'sha256', 'seals')})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    require(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision),
            'invalid_expected_revision')
    os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp + '-first-entry-' + args.expect_revision[:12]
    private = Path('target/evaluation/inprocess') / name
    private.mkdir(parents=True, exist_ok=False)
    destination = Path('evaluation/inprocess/results') / (name + '.json')
    require(not destination.exists(), 'receipt_already_exists')
    cpu = min(os.sched_getaffinity(0))
    record = {'schema_version': 1, 'status': 'failed', 'revision': args.expect_revision,
              'started_utc': stamp, 'scope': 'first_entry_sealed_namespace_kernel_traps_and_NX',
              'source_patches': 0, 'build_profile': 'release-O2', 'repeats': 5,
              'environment': ENV, 'bounds': BOUNDS,
              'gated_exec_environment': {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
                                         'LD_BIND_NOW': '1', 'LD_LIBRARY_PATH': 'per-command private namespace',
                                         'LI2_DEPENDENCY_FDS': 'actual inherited descriptors; private launch.json'},
              'build_bounds': {'cpu_seconds': 30, 'address_space_bytes': 1024**3,
                               'capture_file_bytes': 16 * 1024**2, 'wall_seconds': 60},
              'wall_measurement': 'fresh child creation through reap; gated time includes Python namespace copy/sealing and bridge preparation, not pure instrumentation overhead',
              'pair_order': ['native', 'gated'], 'vdso_NX_gated': False,
              'identity_policy': 'sealed copies, explicit paths, eager binding; not filesystem transparency',
              'reproduce': ['python3', 'evaluation/inprocess/first_entry.py', '--expect-revision', args.expect_revision],
              'planned': {'namespace_tests': 5, 'ls_pairs': 10, 'runtime_refusal_pairs': len(REFUSALS),
                          'supported_query_pairs': 1, 'ordinary_fd_pairs': 1, 'first_opcode_runs': 2,
                          'carrier_corruptions': 2, 'malformed_sealed_elf': 1},
              'commands': [], 'pairs': [], 'refusals': [], 'source': None,
              'source_unchanged': None, 'binaries_unchanged': None}
    pins = {}

    def pin(path):
        value = file_digest(path)
        if path in pins:
            require(pins[path] == value, 'pinned_input_changed')
        pins[path] = value
        return value

    def unchanged():
        require(all(file_digest(path) == value for path, value in pins.items()), 'pinned_input_changed')

    def run(label, argv, cwd=Path('.'), env=None, build=False, pass_fds=()):
        unchanged()
        command, stdout, stderr = invoke(argv, ENV if env is None else env, cwd, private, label, cpu,
                                         build=build, pass_fds=pass_fds)
        if env is not None:
            command['environment_delta'] = {key: value for key, value in env.items() if ENV.get(key) != value}
        if pass_fds:
            command['passed_fds'] = list(pass_fds)
        record['commands'].append(command)
        require(command['stdout_bytes'] is not None and command['stderr_bytes'] is not None and
                command['stdout_bytes'] <= (16 * 1024**2 if build else 65536) and
                command['stderr_bytes'] <= (16 * 1024**2 if build else 65536), 'capture_extent')
        unchanged()
        return command, stdout.read_bytes(), stderr.read_bytes()

    def carrier_argv(carrier, original, argv, namespace, cwd):
        return ['python3', relative(PRODUCT / 'carrier.py', cwd), 'exec-loader',
                '--library-root', '/usr/lib64', '--namespace', relative(namespace, cwd),
                relative(carrier, cwd), relative(original, cwd) if not original.is_absolute() else str(original),
                '--', *argv]

    try:
        record['source'] = source()
        require(record['source']['revision'] == args.expect_revision, 'revision_differs')
        record['source_sha256'] = {name: file_digest(Path(name)) for name in SOURCE_NAMES}
        record['hardware'] = hardware(cpu)
        record['toolchain'] = {}
        for tool in ('cc', 'python3', 'sh'):
            path = shutil.which(tool, path=ENV['PATH'])
            require(path is not None, 'tool_not_found')
            record['toolchain'][tool] = {'sha256': pin(Path(path))}
            require(pin(Path(path).resolve()) == record['toolchain'][tool]['sha256'], 'tool_resolution_changed')
            if tool != 'sh':
                command, stdout, stderr = run(tool + '-version', [tool, '--version'], build=True)
                completed(command, 0)
                version = (stdout + stderr).decode().strip()
                require(0 < len(version) <= 16384, 'tool_version_extent')
                record['toolchain'][tool]['version'] = version
        command, stdout, stderr = run('namespace-tests', ['python3', str(PRODUCT / 'namespace_tests.py')])
        completed(command, 0)
        record['namespace_tests'] = namespace_result(stdout, stderr)
        command, _, _ = run('build', ['sh', str(PRODUCT / 'build.sh')], build=True)
        completed(command, 0)
        artifacts = private / 'artifacts'
        artifacts.mkdir()
        record['binary_sha256'] = {}
        for name in BINARIES:
            built = BUILD / name
            value = pin(built)
            shutil.copy2(built, artifacts / name)
            require(pin(artifacts / name) == value, 'built_copy_changed')
            record['binary_sha256'][name] = value
        system = Path('/bin/ls')
        system_interpreter = interpreter(system)
        record['original_program_sha256'] = pin(system)
        record['original_interpreter_sha256'] = pin(system_interpreter)
        require(file_digest(interpreter(BUILD / 'refusal-probe')) == record['original_interpreter_sha256'],
                'refusal_interpreter_differs')

        command, stdout, stderr = run('fixture-native', [str(BUILD / 'fixture-main')])
        completed(command, 7)
        require(stdout == b'FIRST_ENTRY_OK\n' and stderr == b'', 'native_fixture_failed')
        command, stdout, stderr = run('fixture-gated', ['python3', str(PRODUCT / 'carrier.py'), 'exec',
                                                       str(BUILD / 'fixture-carrier')])
        completed(command, 7)
        require(stdout == b'FIRST_ENTRY_OK\n', 'gated_fixture_stdout')
        record['first_opcode_fixture'] = fixture_row(stderr)
        original = (BUILD / 'fixture-carrier').read_bytes()
        damaged = bytearray(original)
        magic, offset, size = struct.unpack_from('<8sQQ', damaged, len(damaged) - 24)
        require(magic == b'LI2END01' and offset + size == len(damaged) - 24 and size >= 144,
                'fixture_carrier_shape')
        damaged[offset + 80] ^= 1
        hash_bad = private / 'bad-original-hash'
        hash_bad.write_bytes(damaged)
        damaged = bytearray(original)
        offset = struct.unpack_from('<Q', damaged, 32)[0]
        count = struct.unpack_from('<H', damaged, 56)[0]
        require(offset + 56 * count <= len(damaged), 'fixture_table_extent')
        for index in range(count):
            at = offset + index * 56
            kind, flags = struct.unpack_from('<II', damaged, at)
            if kind == 1:
                struct.pack_into('<I', damaged, at + 4, flags | 1)
                break
        else:
            raise Refusal('fixture_has_no_load')
        execute_bad = private / 'bad-initial-execute'
        execute_bad.write_bytes(damaged)
        record['carrier_refusals'] = []
        for path, message in ((hash_bad, 'original main hash differs'),
                              (execute_bad, 'unauthorized PHDR mutation')):
            command, stdout, stderr = run(path.name, ['python3', str(PRODUCT / 'carrier.py'), 'exec', str(path)])
            completed(command, 125)
            require(stdout == b'' and stderr == ('LI2_FIRST_ENTRY refused: ' + message + '\n').encode(),
                    'carrier_corruption_not_refused')
            record['carrier_refusals'].append({'case': path.name, 'sha256': file_digest(path), 'exit_code': 125})

        fixture = private / 'directory'
        fixture.mkdir()
        (fixture / 'alpha').write_bytes(b'alpha\n')
        (fixture / 'beta').write_bytes(b'beta\n')
        record['fixture_sha256'] = {p.name: file_digest(p) for p in sorted(fixture.iterdir())}
        for case, args0 in CASES:
            for repeat in range(5):
                label = case + '-' + str(repeat)
                pair = {'case': case, 'repeat': repeat, 'stdout_equal': False}
                record['pairs'].append(pair)
                command, native, stderr = run(label + '-native', ['/bin/ls', *args0], cwd=fixture)
                pair['native_command'] = command['label']
                completed(command, 0)
                require(stderr == b'', 'native_ls_stderr')
                directory = private / ('namespace-' + label)
                command, gated, stderr = run(label + '-gated', carrier_argv(
                    BUILD / 'ls-carrier', system, ['/bin/ls', *args0], directory, fixture), cwd=fixture)
                pair['gated_command'] = command['label']
                completed(command, 0)
                observed = loader_row(stderr)
                pair['metrics'] = observed
                loader_success(observed)
                require(native == gated, 'ls_stdout_differs')
                pair['stdout_equal'] = True
                namespace = namespace_evidence(directory, system, record['binary_sha256']['ls-carrier'],
                                               record['original_program_sha256'],
                                               record['original_interpreter_sha256'], observed['dependency_objects'], pin)
                if 'dependencies' not in record:
                    record['dependencies'] = namespace
                require(namespace == record['dependencies'], 'dependency_set_changed')

        unsealed = private / 'unsealed-code'
        unsealed.write_bytes(bytes.fromhex('b82a000000c3') + bytes(4090))
        with unsealed.open('rb') as handle:
            try:
                fcntl.fcntl(handle.fileno(), fcntl.F_GET_SEALS)
            except OSError as error:
                require(error.errno == errno.EINVAL, 'unsealed_file_query_failed')
            else:
                raise Refusal('negative_file_supports_sealing')
        record['unsealed_file_sha256'] = file_digest(unsealed)
        for case, code, detail, number in REFUSALS + (('query_sigusr1', 0, 0, 231),
                                                     ('fd_ordinary_highbits', 0, 0, 231)):
            marker = ('ATTEMPT ' + case + '\n').encode()
            native_argv = [str(BUILD / 'refusal-probe'), case, str(unsealed)]
            command, stdout, stderr = run(case + '-native', native_argv)
            completed(command, 0)
            require(stdout == marker + ('NATIVE_OK ' + case + '\n').encode() and stderr == b'',
                    'native_control_failed')
            directory = private / ('namespace-' + case)
            command, stdout, stderr = run(case + '-gated', carrier_argv(
                BUILD / 'refusal-carrier', BUILD / 'refusal-probe', native_argv, directory, Path('.')))
            positive = code == 0
            completed(command, 0 if positive else 125)
            require(stdout == marker + (('NATIVE_OK ' + case + '\n').encode() if positive else b''),
                    'wrong_control_completion')
            observed = loader_row(stderr)
            if positive:
                key = {'query_sigusr1': 'supported_query', 'fd_ordinary_highbits': 'ordinary_fd'}[case]
                record[key] = {'case': case, 'metrics': observed}
            else:
                record['refusals'].append({'case': case, 'metrics': observed})
            entry_seen(observed)
            require(observed['status'] == (0 if positive else 125) and observed['failure_code'] == code and
                    observed['detail_abs'] == detail and observed['detail_negative'] == 0 and
                    observed['last_syscall'] == number and observed['syscalls'] == observed['forwarded'] + (0 if positive else 1),
                    'wrong_runtime_control')
            namespace_evidence(directory, BUILD / 'refusal-probe', record['binary_sha256']['refusal-carrier'],
                               record['binary_sha256']['refusal-probe'], record['original_interpreter_sha256'],
                               observed['dependency_objects'], pin)

        # A real sealed parser input, deliberately not a valid-program success.
        malformed = bytearray(4096)
        struct.pack_into('<16sHHIQQQIHHHHHH', malformed, 0,
                         b'\x7fELF\x02\x01\x01' + bytes(9), 3, 62, 1, 0, 64, 0, 0,
                         64, 56, 1, 0, 0, 0)
        struct.pack_into('<IIQQQQQQ', malformed, 64, 1, 4, 0, 0, 0, 1, 2**64 - 1, 4096)
        malformed_path = private / 'malformed-sealed-elf'
        malformed_path.write_bytes(malformed)
        fd = os.memfd_create('li2-malformed-extent', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            at = 0
            while at < len(malformed):
                written = os.write(fd, memoryview(malformed)[at:])
                require(written > 0, 'malformed_input_short_write')
                at += written
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
            seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
            require(seals == SEALS and os.fstat(fd).st_size == 4096, 'malformed_input_seals')
            command, stdout, stderr = run('malformed-sealed-elf',
                ['python3', str(PRODUCT / 'carrier.py'), 'exec', str(BUILD / 'ls-carrier'),
                 '/bin/ls', '-d', '.'], env=ENV | {'LI2_DEPENDENCY_FDS': str(fd)}, pass_fds=(fd,))
            completed(command, 125)
            require(stdout == b'', 'malformed_input_reached_program')
            observed = loader_row(stderr)
            record['malformed_elf'] = {'sha256': file_digest(malformed_path), 'bytes': len(malformed),
                                       'seals': seals, 'metrics': observed}
            require(observed['status'] == 125 and observed['failure_code'] == 175 and
                    observed['detail_abs'] == observed['detail_negative'] == 0 and
                    observed['dependency_objects'] == 1, 'wrong_malformed_refusal')
            require(all(observed[k] == 0 for k in ('first_target_is_interpreter_entry',
                    'interpreter_entry_faults', 'nx_faults', 'main_faults', 'interpreter_faults',
                    'dependency_faults', 'cpuid', 'rdtsc', 'rdtscp', 'syscalls', 'forwarded',
                    'admissions', 'sync_core', 'generations', 'mappings', 'live_pages')),
                    'malformed_input_reached_target')
        finally:
            primary_active = sys.exc_info()[0] is not None
            try:
                os.close(fd)
            except BaseException as error:
                record['malformed_input_close'] = {'complete': False, 'error': type(error).__name__,
                                                    'errno': getattr(error, 'errno', None)}
                if not primary_active:
                    raise
            else:
                record['malformed_input_close'] = {'complete': True, 'error': None, 'errno': None}
        require(len(record['pairs']) == 10 and len(record['refusals']) == 16 and
                record['supported_query']['case'] == 'query_sigusr1' and
                record['ordinary_fd']['case'] == 'fd_ordinary_highbits', 'incomplete_cohort')
        commands = {r['label']: r for r in record['commands']}
        require(len(commands) == len(record['commands']) == 65, 'command_cohort_differs')
        record['summary'] = {case: {mode + '_median_wall_ns': int(statistics.median(
            commands[r[mode + '_command']]['wall_ns'] for r in record['pairs'] if r['case'] == case))
            for mode in ('native', 'gated')} for case, _ in CASES}
        record['status'] = 'passed'
    except (Exception, KeyboardInterrupt) as error:
        record['status'] = 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed'
        record['error'] = str(error) if isinstance(error, Refusal) else type(error).__name__
        if isinstance(error, OSError):
            record['error_errno'] = error.errno
    finally:
        try:
            record['source_unchanged'] = source() == record['source'] if record['source'] is not None else None
            record['binaries_unchanged'] = all(file_digest(path) == value for path, value in pins.items())
        except Exception:
            record['source_unchanged'] = None
            record['binaries_unchanged'] = None
        if record['source_unchanged'] is not True or record['binaries_unchanged'] is not True:
            record['status'] = 'failed'
            record.setdefault('error', 'source_or_binary_changed_or_unobserved')
        text = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n'
        (private / 'receipt.json').write_text(text)
        markers = {str(Path.home()), str(ROOT), platform.node()}
        require(not any(value and len(value) > 1 and value in text for value in markers), 'private_receipt_text')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x') as receipt:
            receipt.write(text)
        print(destination)
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
