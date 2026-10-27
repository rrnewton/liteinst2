#!/usr/bin/env python3
"""Independent kernel-entry to fixture-interpreter ABI comparison; no timing claim."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys

sys.dont_write_bytecode = True
from checks import source
from first_entry import loader_row
import dynamic
from run import Refusal, file_digest, hardware, invalid_constant, pairs, require

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/page-entry/abi'))
import build
import compare
from controls import controls
from bounds_controls import controls as bounds_controls

ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
       'LD_BIND_NOW': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
ABI_BOUNDS = {'cpu_seconds': 3, 'address_space_bytes': 256 * 1024**2,
              'capture_file_bytes': 8 * 1024**2, 'wall_seconds': 10, 'process_count': 1}
CAPTURE_ACCEPTANCE_BYTES = 1024**2
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
SOURCE_NAMES = (tuple('tools/page-entry/abi/' + name for name in build.LOCAL) +
                tuple('tools/page-entry/' + name for name in build.PRODUCTION) +
                ('evaluation/inprocess/first_entry_abi.py', 'evaluation/inprocess/dynamic.py',
                 'evaluation/inprocess/run.py', 'evaluation/inprocess/checks.py',
                 'evaluation/inprocess/first_entry.py'))


def public_command(command):
    # The complete executable command is retained privately; public reproduction
    # uses this driver's fixed CLI, which reconstructs private build pathnames.
    result = command.copy()
    result['argv'] = [str(arg).replace(str(ROOT) + '/', '${REPO_ROOT}/') for arg in command['argv']]
    result['cwd'] = '.'
    return result


def close_fd(fd):
    try:
        os.close(fd)
        return {'complete': True, 'errno': None}
    except OSError as error:
        return {'complete': False, 'errno': error.errno}


def completed(row, expected):
    require(row['exit_code'] == expected and row['leader_reaped'] and not row['timed_out'] and
            row['error'] is None and not row['capture_errors'], 'command_did_not_complete')
    if 'bounds_override' in row:
        require(row['pidfd_close'] == {'complete': True, 'errno': None}, 'pidfd_close_failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    require(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision),
            'invalid_expected_revision')
    os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp + '-first-entry-abi-' + args.expect_revision[:12]
    private = Path('target/evaluation/inprocess') / name
    private.mkdir(parents=True, exist_ok=False)
    public = Path('evaluation/inprocess/results') / (name + '.json')
    require(not public.exists(), 'duplicate_run_id')
    cpu = min(os.sched_getaffinity(0))
    record = {'schema_version': 1, 'status': 'failed', 'expected_revision': args.expect_revision,
              'started_utc': stamp, 'scope': 'independent_kernel_to_fixture_interpreter_abi',
              'performance_claim': False, 'real_ld_so_entry_state_measured': False,
              'source': None, 'source_unchanged': None, 'input_bytes_unchanged': None,
              'bounds': ABI_BOUNDS, 'stdout_stderr_acceptance_bytes': CAPTURE_ACCEPTANCE_BYTES,
              'file_bound_scope': 'RLIMIT_FSIZE applies per file, including records and stdout/stderr',
              'process_bound_scope': 'RLIMIT_NPROC; fixture execs without fork; no escaped-descendant claim',
              'build_bounds': dynamic.command_bounds(build=True), 'environment': ENV,
              'reproduce': ['python3', 'evaluation/inprocess/first_entry_abi.py', '--expect-revision', args.expect_revision],
              'command_template_substitution': '${REPO_ROOT} is the absolute checkout root; only that derived prefix is replaced',
              'commands': [], 'endpoints': [], 'dependency_close': None,
              'supplied_record_controls': None, 'supplied_bounds_controls': None, 'error': None}
    dep = None
    binding = {}
    tools = {}
    private_commands = []

    def invoke(label, argv, build=False, env=None, pass_fds=(), expected=0):
        row, stdout, stderr = dynamic.invoke(
            argv, ENV if env is None else env, Path('.'), private, label, cpu,
            build=build, pass_fds=pass_fds, bounds=None if build else ABI_BOUNDS)
        if env is not None:
            row['environment_delta'] = {key: value for key, value in env.items() if ENV.get(key) != value}
        if pass_fds:
            row['passed_fds'] = list(pass_fds)
        private_commands.append(row)
        record['commands'].append(public_command(row))
        completed(row, expected)
        # The ABI file allowance is 8 MiB. This separate acceptance check is not
        # a claim of a physical 1 MiB stdout/stderr limit during execution.
        ceiling = 16 * 1024**2 if build else CAPTURE_ACCEPTANCE_BYTES
        require(all(row[key + '_bytes'] <= ceiling for key in ('stdout', 'stderr')), 'capture_too_large')
        return stdout.read_bytes(), stderr.read_bytes()

    def unchanged_inputs():
        return all(file_digest(Path(path)) == value for path, value in binding.items())

    def endpoint(label, argv, count, env):
        require(unchanged_inputs(), 'bound_input_changed')
        path = private / (label + '.records')
        item = {'name': label, 'expected_records': count, 'record_bytes': None,
                'record_sha256': None, 'record_close': None, 'record_observation_error': None, 'comparison': None}
        record['endpoints'].append(item)
        fd = None
        primary = None
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            stdout, stderr = invoke(label, argv, env=env | {'LI2_ABI_FD': str(fd)},
                                    pass_fds=(fd, dep), expected=23)
            require(stdout == b'', 'unexpected_endpoint_output')
            if label == 'native':
                require(stderr == b'', 'unexpected_native_stderr')
            else:
                actual = loader_row(stderr)
                item['loader'] = actual
                require(actual['status'] == 23 and actual['failure_code'] == actual['detail_abs'] ==
                        actual['detail_negative'] == 0, 'loader_endpoint_failure')
                require(actual['first_target_is_interpreter_entry'] == actual['interpreter_entry_faults'] == 1
                        and actual['dependency_objects'] == 1 and actual['main_faults'] == 0
                        and actual['syscalls'] == actual['forwarded'] > 0 and actual['last_syscall'] == 231,
                        'loader_endpoint_transfer_missing')
        except BaseException as error:
            primary = error
        finally:
            if fd is not None:
                item['record_close'] = close_fd(fd)
            try:
                if path.exists():
                    item['record_bytes'] = path.stat().st_size
                    item['record_sha256'] = file_digest(path)
            except BaseException as error:
                item['record_observation_error'] = {'kind': type(error).__name__,
                                                     'errno': getattr(error, 'errno', None)}
                if primary is None:
                    primary = error
        if primary is not None:
            raise primary
        require(item['record_close'] == {'complete': True, 'errno': None}, 'record_close_failed')
        require(item['record_bytes'] == count * compare.SIZE, 'missing_or_extra_endpoint_record')
        raw = path.read_bytes()
        require(len(raw) == count * compare.SIZE and hashlib.sha256(raw).hexdigest() == item['record_sha256'],
                'record_changed_during_read')
        return [compare.record(raw[i * compare.SIZE:(i + 1) * compare.SIZE], cap) for i in range(count)]

    try:
        record['source'] = source()
        require(record['source']['revision'] == args.expect_revision, 'revision_differs')
        record['hardware'] = hardware(cpu)
        record['source_sha256'] = {name: file_digest(Path(name)) for name in SOURCE_NAMES}
        binding.update(record['source_sha256'])
        record['supplied_bounds_controls'] = bounds_controls(dynamic)
        record['tools'] = {}
        for name in ('cc', 'readelf', 'nm', 'python3'):
            path = shutil.which(name, path=ENV['PATH'])
            require(path is not None, 'required_tool_absent')
            tools[name] = path
            binding[path] = file_digest(Path(path))
            version, _ = invoke(name + '-version', [path, '--version'], build=True)
            record['tools'][name] = {'path': path, 'sha256': binding[path],
                                     'version': version.decode('utf-8').strip()}
        python = tools['python3']
        actual_python = str(Path(sys.executable).resolve(strict=True))
        binding[actual_python] = file_digest(Path(actual_python))
        record['runner_python'] = {'sha256': binding[actual_python], 'version': sys.version.split()[0]}
        built = private / 'build'
        cap = build.perform(ROOT, built, tools, invoke,
                            lambda data: json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant))
        record['capability'] = cap
        record['binaries'] = {}
        for path in sorted(built.iterdir()):
            if path.is_file():
                binding[str(path)] = file_digest(path)
                record['binaries'][path.name] = {'sha256': binding[str(path)], 'bytes': path.stat().st_size}
        # This libc object is metadata for registration, not executed by the
        # capture interpreter. Preserve its actual sealed bytes and FD lifetime.
        library = Path('/usr/lib64/libc.so.6').resolve(strict=True)
        require(0 < library.stat().st_size <= 16 * 1024**2, 'dependency_extent')
        data = library.read_bytes()
        require(0 < len(data) <= 16 * 1024**2, 'dependency_extent')
        binding[str(library)] = hashlib.sha256(data).hexdigest()
        require(file_digest(library) == binding[str(library)], 'dependency_changed')
        dep = os.memfd_create('abi-explicit-libc-metadata', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        at = 0
        while at < len(data):
            count = os.write(dep, data[at:])
            require(count > 0, 'dependency_short_write')
            at += count
        fcntl.fcntl(dep, fcntl.F_ADD_SEALS, SEALS)
        require(fcntl.fcntl(dep, fcntl.F_GET_SEALS) == SEALS and os.fstat(dep).st_size == len(data), 'dependency_seal')
        require(os.pread(dep, len(data), 0) == data, 'dependency_copy_changed')
        record['dependency'] = {'sha256': binding[str(library)], 'bytes': len(data), 'seals': SEALS}
        env = ENV | {'LI2_DEPENDENCY_FDS': str(dep)}
        reference = endpoint('native', [str(built / 'positive-main')], 1, env)[0]
        compare.native(reference, cap, (built / 'positive-interpreter.so').read_bytes(),
                       (built / 'positive-main').read_bytes())
        record['endpoints'][-1]['comparison'] = 'kernel_defined_fields_and_actual_entry_passed'
        carrier_cli = [python, 'tools/page-entry/carrier.py', 'exec']
        pre, post = endpoint('positive', [*carrier_cli, str(built / 'positive-carrier')], 2, env)
        compare.kernel_state(pre)
        images = [(built / p).read_bytes() for p in ('bridge-abi.so', 'positive-interpreter.so',
                                                    'positive-carrier', 'positive-main')]
        compare.pair(pre, post, cap, *images)
        record['endpoints'][-1]['comparison'] = 'complete_same_process_endpoint_equality_passed'
        record['comparison_extent'] = {'registers': 16, 'stack_bytes': len(post['stack']),
                                       'phdr_bytes': len(post['phdr']), 'raw_xsave_bytes': 65536,
                                       'qualified_xstate_components': [key for key, _ in compare.architectural_state(post, cap)],
                                       'stack_exception': 'one_unique_entry_authenticated_AT_BASE_value'}
        names = controls(pre, post, cap, *images)
        record['supplied_record_controls'] = {'count': len(names), 'names': names}
        for variant, reason in [('gpr-negative', 'GPR mismatch'),
                                ('stack-negative', 'stack bytes changed outside authenticated AT_BASE')]:
            observed = endpoint(variant, [*carrier_cli, str(built / (variant + '-carrier'))], 2, env)
            images = [(built / p).read_bytes() for p in ('bridge-abi.so', variant + '-interpreter.so',
                                                        variant + '-carrier', variant + '-main')]
            # Authenticate both actual entry symbols before the intentional early
            # GPR comparator refusal can otherwise short-circuit entry validation.
            compare.entry(observed[0], images[0])
            compare.entry(observed[1], images[1], negative_prefix=True)
            compare.kernel_state(observed[0])
            try:
                compare.pair(*observed, cap, *images, negative_prefix=True)
            except compare.Refusal as error:
                require(str(error) == reason, 'wrong_actual_negative_refusal')
                record['endpoints'][-1]['comparison'] = reason
            else:
                raise Refusal('actual_entry_corruption_accepted')
        require(unchanged_inputs(), 'bound_input_changed')
        record['input_bytes_unchanged'] = True
        record['source_unchanged'] = source() == record['source']
        require(record['source_unchanged'], 'source_changed')
        record['status'] = 'passed'
    except (Exception, KeyboardInterrupt) as error:
        record['error'] = str(error) if isinstance(error, (Refusal, compare.Refusal)) else type(error).__name__
        record['status'] = 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed'
    finally:
        if dep is not None:
            record['dependency_close'] = close_fd(dep)
            if not record['dependency_close']['complete']:
                record['error'] = record['error'] or 'dependency_close_failed'
                record['status'] = 'failed'
        if record['source'] is not None:
            try:
                record['source_unchanged'] = source() == record['source']
                record['input_bytes_unchanged'] = unchanged_inputs()
                require(record['source_unchanged'] and record['input_bytes_unchanged'], 'final_inputs_changed')
            except Exception as error:
                record['error'] = record['error'] or (str(error) if isinstance(error, Refusal) else type(error).__name__)
                record['status'] = 'failed'
        # Bound every partial prefix too, without promoting an incomplete attempt.
        (private / 'commands.json').write_text(json.dumps(private_commands, indent=2, sort_keys=True) + '\n')
        (private / 'input-bindings.json').write_text(json.dumps(binding, indent=2, sort_keys=True) + '\n')
        text = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n'
        (private / 'receipt.json').write_text(text)
        markers = {str(Path.home()), str(ROOT), platform.node()}
        if any(value and len(value) > 1 and value in text for value in markers):
            raise RuntimeError('public receipt contains private location data')
        public.parent.mkdir(parents=True, exist_ok=True)
        with public.open('x') as receipt:
            receipt.write(text)
        print(public)
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
