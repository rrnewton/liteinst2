#!/usr/bin/env python3
"""Optimized real dlopen/JIT lifecycle and exact refusal controls; no retries."""
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
import dynamic
from checks import source
from run import Refusal, file_digest, hardware, output, require

EXTRA = {'lifecycle_' + name for name in (
    'transactions', 'mappings', 'generations', 'retired', 'admissions', 'kernel_errors',
    'partial_errors', 'materialized', 'sync_core', 'live_pages', 'records',
    'last_operation', 'last_syscall', 'last_errno', 'last_result_negative', 'last_phase')}
NEGATIVES = {'wx': 136, 'shared': 140, 'unsealed': 142, 'alias': 119,
             'protected': 155, 'unknown': 157, 'thread': 30, 'stale': 40,
             'capacity': 121, 'post_effect': 170, 'partial_alias': 119, 'brk_hole': 181}
EXPECTED_OUTPUT = (b'sealed_dlopen=40,40\nsealed_partial_vma=rx,rw\n'
                   b'jit_generations=17,29,41\ncross_page=53,67\n'
                   b'partial_r=ENOMEM,73\npartial_rx=ENOMEM,73\n'
                   b'kernel_errors=EINVAL,EINVAL\n')


def report(data, expected_code):
    lines = data.decode().splitlines()
    require(len(lines) == 1, 'lifecycle_diagnostic_count')
    row = dynamic.object_row(lines[0], 'LI2_DYNAMIC ')
    require(set(row) == dynamic.METRIC_KEYS | EXTRA, 'lifecycle_diagnostic_keys')
    require(row['scope'] == 'post_constructor', 'lifecycle_scope')
    require(all(type(row[key]) is int and 0 <= row[key] < 2**64
                for key in set(row) - {'scope'}), 'lifecycle_numeric_metric')
    require(row['version'] == 1 and row['source_patches'] == 0, 'lifecycle_backend')
    require(row['failure_code'] == expected_code and row['status'] == (125 if expected_code else 0),
            'lifecycle_failure_identity')
    require(all(row[key] == 1 for key in ('selfcheck_cpuid', 'selfcheck_rdtsc',
                                        'selfcheck_syscall', 'capability_checks')), 'lifecycle_activation')
    if expected_code == 0:
        dynamic.metric_row('LI2_DYNAMIC ' + json.dumps({key: row[key] for key in dynamic.METRIC_KEYS}))
        for key, expected in {'mappings': 15, 'generations': 52, 'retired': 52,
                              'admissions': 14, 'kernel_errors': 4, 'partial_errors': 2,
                              'sync_core': 14, 'live_pages': 0, 'records': 52}.items():
            require(row['lifecycle_' + key] == expected, 'lifecycle_positive_counts')
    return row


def main():
    revision = output(['git', 'rev-parse', 'HEAD'])
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp + '-lifecycle-' + revision[:12]
    private = Path('target/evaluation/inprocess') / name
    private.mkdir(parents=True, exist_ok=False)
    public = Path('evaluation/inprocess/results') / (name + '.json')
    cpu = min(os.sched_getaffinity(0))
    record = {'schema_version': 1, 'revision': revision, 'started_utc': stamp,
              'build_profile': 'optimized_c_O2', 'source': None, 'source_unchanged': None,
              'runner_sha256': file_digest(Path(__file__)), 'status': 'failed', 'commands': [],
              'rows': [], 'reproduce': ['python3', 'evaluation/inprocess/lifecycle.py'],
              'bounds': dynamic.BOUNDS, 'environment': dynamic.SETTINGS,
              'scope': 'Post-constructor singleton; sealed DSO dlopen and private anonymous JIT. Kernel traps, zero source patches. No general loader, thread or signal claim.'}
    fd = None
    try:
        record['source'] = source()
        require(record['source']['revision'] == revision, 'revision_changed_before_build')
        record['hardware'] = hardware(cpu)
        compiler = shutil.which('cc', path=dynamic.SETTINGS['PATH'])
        require(compiler is not None, 'compiler_not_found')
        record['toolchain'] = {
            'cc_version': subprocess.check_output([compiler, '--version'], env=dynamic.SETTINGS,
                                                  text=True, timeout=20).strip(),
            'cc_sha256': file_digest(Path(compiler).resolve())}
        command, _, _ = dynamic.invoke(['sh', 'tools/page-mode/build.sh'], dynamic.SETTINGS,
                                      Path('.'), private, 'build', cpu, build=True)
        record['commands'].append(command)
        require(dynamic.completed(command), 'lifecycle_release_build_failed')
        binaries = {name: file_digest(Path('target/page-mode') / name)
                    for name in ('libli2_dynamic.so', 'lifecycle_dso.so', 'lifecycle_probe')}
        record['binaries'] = binaries
        fd = os.memfd_create('li2-lifecycle-fixture', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        contents = memoryview(Path('target/page-mode/lifecycle_dso.so').read_bytes())
        require(hashlib.sha256(contents).hexdigest() == binaries['lifecycle_dso.so'], 'sealed_source_changed')
        while contents:
            count = os.write(fd, contents)
            require(count > 0, 'lifecycle_memfd_no_progress')
            contents = contents[count:]
        seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals == seals, 'lifecycle_seals')
        record['sealed_fixture_sha256'] = binaries['lifecycle_dso.so']
        record['seals'] = seals
        reference = None
        for case, instrumented in (('positive', False), ('positive', True), *((key, True) for key in NEGATIVES)):
            require(all(file_digest(Path('target/page-mode') / name) == value for name, value in binaries.items()),
                    'lifecycle_binary_changed')
            label = case + ('-lifecycle' if instrumented else '-reference')
            env = dict(dynamic.SETTINGS)
            if instrumented:
                env.update(LD_PRELOAD='target/page-mode/libli2_dynamic.so', LI2_LIFECYCLE_FD=str(fd))
                if case == 'post_effect':
                    env['LI2_LIFECYCLE_FAIL_AFTER_MPROTECT'] = '1'
            command, stdout, stderr = dynamic.invoke(
                ['target/page-mode/lifecycle_probe', case, str(fd)], env, Path('.'), private,
                label, cpu, pass_fds=(fd,))
            command['environment_delta'] = {key: value for key, value in env.items() if key not in dynamic.SETTINGS}
            record['commands'].append(command)
            expected_code = 0 if case == 'positive' else NEGATIVES[case]
            require(command['exit_code'] == (125 if expected_code else 0)
                    and command['leader_reaped'] and not command['timed_out'] and command['error'] is None,
                    'lifecycle_process_outcome')
            observed = {'case': case, 'instrumented': instrumented, 'expected_failure_code': expected_code}
            if case == 'positive':
                require(stdout.read_bytes() == EXPECTED_OUTPUT, 'lifecycle_output_differs')
                if instrumented:
                    require(stdout.read_bytes() == reference, 'lifecycle_native_output_differs')
                    observed['native_output_equal'] = True
                else:
                    reference = stdout.read_bytes()
            else:
                require(stdout.read_bytes() == b'', 'refusal_resumed_application')
            if instrumented:
                observed['metrics'] = report(stderr.read_bytes(), expected_code)
                if case == 'post_effect':
                    require(observed['metrics']['lifecycle_last_errno'] == 0
                            and observed['metrics']['lifecycle_last_phase'] == 3
                            and observed['metrics']['lifecycle_admissions'] == 0, 'post_effect_fail_stop')
                if case == 'partial_alias':
                    require(observed['metrics']['lifecycle_last_errno'] == 12
                            and observed['metrics']['lifecycle_last_result_negative'] == 1
                            and observed['metrics']['lifecycle_last_syscall'] == 10
                            and observed['metrics']['lifecycle_last_phase'] == 4
                            and observed['metrics']['lifecycle_partial_errors'] == 1
                            and observed['metrics']['lifecycle_admissions'] == 0, 'partial_alias_actual_error')
                if case == 'brk_hole':
                    require(observed['metrics']['failure_detail_abs'] == 12
                            and observed['metrics']['lifecycle_live_pages'] == 1
                            and observed['metrics']['lifecycle_admissions'] == 1
                            and observed['metrics']['lifecycle_last_operation'] == 2
                            and observed['metrics']['lifecycle_last_phase'] == 7
                            and observed['metrics']['syscall_traps'] == observed['metrics']['forwarded_syscalls'] + 1,
                            'brk_shrink_refused_before_effect')
            else:
                require(stderr.read_bytes() == b'', 'native_stderr')
            record['rows'].append(observed)
        require(len(record['rows']) == 14, 'lifecycle_case_count')
        record['status'] = 'passed'
    except Refusal as error:
        record['error'] = str(error)
    except Exception as error:
        record['error'] = type(error).__name__
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError as error:
                record['status'] = 'failed'
                record['close_error_errno'] = error.errno
                record.setdefault('error', 'sealed_descriptor_close_failed')
        try:
            record['source_unchanged'] = record['source'] is not None and source() == record['source']
        except Exception:
            record['source_unchanged'] = None
        if record['source_unchanged'] is not True:
            record['status'] = 'failed'
            record.setdefault('error', 'source_changed_or_unobserved')
        data = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n'
        require(not any(len(value) > 1 and value in data
                        for value in (str(Path.home()), str(Path.cwd()), platform.node())), 'private_receipt_data')
        public.parent.mkdir(parents=True, exist_ok=True)
        with public.open('x') as receipt:
            receipt.write(data)
        print(public)
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
