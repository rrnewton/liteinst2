#!/usr/bin/env python3
"""Private serial E9 artifact calibration. Never runs rewritten applications."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

if sys.flags.optimize:
    raise SystemExit("optimized Python disables frozen calibration checks")
from audit import (CASE_IDS, MANIFEST_SHA256, MAX_FILE, authenticate_case, backend_stats,
                   digest, elf64, loads, read_file, validate_helper_receipt, validate_rpc)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
RUNS = HERE / 'runs'
# This value is independently pinned by frozen() before any command.
MANIFEST_SHA256 = digest(read_file(HERE / 'manifest.json'))
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
LIMITS = {'cpu_seconds': 20, 'wall_seconds': 45, 'file_bytes': MAX_FILE}


def write_new(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as stream: stream.write(raw)
    return raw


def capture(path):
    assert path.is_file() and not path.is_symlink()
    assert path.stat().st_size <= MAX_FILE
    raw = path.read_bytes(); assert len(raw) <= MAX_FILE
    return raw


def inventory(directory):
    result = {}
    pending = [directory]
    seen = 0
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                seen += 1
                assert seen <= 512, 'bounded artifact inventory exceeded'
                path = Path(entry.path)
                assert not path.is_symlink()
                if path.is_dir():
                    pending.append(path)
                    continue
                assert path.is_file()
                result[str(path.relative_to(directory))] = dict(bytes=path.stat().st_size, sha256=digest(capture(path)))
    return result


def frozen(source_path, expected_sha):
    source_raw = read_file(source_path)
    assert digest(source_raw) == expected_sha
    source = loads(source_raw)
    assert source['status'] == 'FRESH_CORRECTED_CORE_PREREQUISITES_FROZEN_E9_PENDING'
    assert source['calibration_manifest_sha256'] == MANIFEST_SHA256
    for path, expected in source['source_sha256'].items():
        assert digest(read_file(HERE / path)) == expected, path
    for path, expected in source['reference_sha256'].items():
        assert digest(read_file(Path(path))) == expected, path
    # Exact pre-reviewed completion bytes, binaries and all new state captures.
    # The separate hash reader handles large immutable build artifacts without
    # changing the 16 MiB RPC/output parser or tool file limits.
    from prerequisites import hash_file, require_gate_summary
    for path, expected in source['prerequisite_snapshot'].items():
        assert hash_file(Path(path)) == expected, path
    require_gate_summary(source['core_prerequisites'])
    python = source['python']
    assert Path(sys.executable).resolve() == Path(python['path'])
    assert digest(read_file(Path(python['path']))) == python['sha256']
    raw = read_file(HERE / 'manifest.json'); assert digest(raw) == MANIFEST_SHA256
    manifest = loads(raw)
    assert manifest['e9_commit'] == '0d5d36e4c4edcac37ca2499694d64302a391136f'
    assert [case['id'] for case in manifest['cases']] == CASE_IDS
    assert manifest['expected'] == dict(selected_sites=6, rewrites=6, one_exact_rpc_patch_per_file=True,
        B1_successes=6, other_tactics=0, original_baseline_runs=4, rewritten_native_runs=36,
        stdout_hex='63617272696572206d6978206f6b0a00', source_mutations=0)
    assert manifest['limits'] == dict(cpu_seconds_per_process=20, wall_seconds_per_command=45,
                                    output_file_bytes=MAX_FILE, parallel_commands=1)
    assert manifest['qualification_complete'] is False
    assert manifest['backend_ABI_defect_resolved'] is False
    assert manifest['stage1_executes_applications'] is False
    assert manifest['E9_native_enabled'] is False
    assert manifest['core_prerequisites'] == source['core_prerequisites']
    for tool in manifest['tools'].values():
        assert digest(read_file(tool['path'])) == tool['sha256']
    for case in manifest['cases']: authenticate_case(case)
    corpus = Path(manifest['cases'][0]['input']).parent.parent
    assert digest(read_file(corpus/'selected-manifest.json')) == manifest['selected_manifest_sha256']
    assert digest(read_file(ROOT/'ignored/a3/corrected-core-join-v1/native/run/complete.json')) == manifest['loader_bound_core_receipt_sha256']
    assert digest(read_file(ROOT/'ignored/a3/corrected-core-join-v1/state-binding-v2/audit/complete.json')) == manifest['core_state_audit_receipt_sha256']
    assert [row['name'] for row in source['required_calibrations']] == [
        'calibrate', 'supervisor_calibrate', 'calibrate_prerequisites']
    for row in source['required_calibrations']:
        request_raw = read_file(row['request'])
        assert digest(request_raw) == row['request_sha256']
        request = loads(request_raw)
        stdout = capture(Path(request['stdout'])); stderr = capture(Path(request['stderr']))
        expected = read_file(row['expected_stdout'])
        assert digest(expected) == row['expected_stdout_sha256']
        assert stdout == expected and stderr == b''
        validate_helper_receipt(loads(read_file(row['receipt'])), request_raw,
            'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44', stdout, stderr)
    return source, manifest


def command_plan(manifest, directory):
    commands = []
    for case in manifest['cases']:
        cwd = directory / case['id']
        rpc = cwd / 'request.json'
        frontend = [manifest['tools']['e9tool']['path'], '--format', 'json', '--output', str(rpc),
                    '--action', f"addr=0x{case['pc']:x}:passthru", case['input']]
        backend = [manifest['tools']['e9patch']['path'], '--debug', '--input', str(rpc)]
        for name, argv in [('frontend', frontend), ('backend', backend)]:
            commands.append(dict(case=case['id'], name=name, request=dict(argv=argv, cwd=str(cwd),
                env={**ENV, 'TMPDIR': str(cwd)}, stdout=str(cwd/f'{name}.stdout'),
                stderr=str(cwd/f'{name}.stderr'), **LIMITS)))
    assert len(commands) == 12
    return commands


def bind_helper(path, expected_sha, source_sha):
    # Execution stays pending until root freezes and independently reviews this
    # exact binding. A missing/unknown helper is never replaced by direct Popen.
    raw = read_file(path); assert digest(raw) == expected_sha
    binding = loads(raw)
    assert binding.keys() == {'status', 'source_manifest_sha256', 'path', 'sha256', 'receipt_schema'}
    assert binding['status'] == 'REVIEWED_BOUNDED_HELPER'
    assert binding['source_manifest_sha256'] == source_sha
    assert binding['receipt_schema'] == 'bounded-command-v1'
    helper = Path(binding['path'])
    assert helper.is_absolute() and helper.resolve().is_relative_to(ROOT/'ignored')
    assert digest(read_file(helper)) == binding['sha256']
    return binding


class FailureSignals:
    def __init__(self):
        self.previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}

    def ignore(self):
        for sig in self.previous:
            signal.signal(sig, signal.SIG_IGN)

    def restore(self):
        for sig, handler in self.previous.items():
            signal.signal(sig, handler)


def helper_command(item, source, binding, verify, failure_signals):
    case = Path(item['request']['cwd']); name = item['name']
    request_path = case/f'{name}.request.json'; receipt_path = case/f'{name}.receipt.json'
    request_raw = write_new(request_path, item['request'])
    command = [source['python']['path'], binding['path'], '--request', str(request_path), '--receipt', str(receipt_path)]
    verify()  # Full source/tool/input/helper check immediately before every launch.
    started = time.monotonic(); child = None; interrupted = None
    helper_watchdog_timeout = False; terminate_sent = False; kill_sent = False
    termination_grace_timeout = False; post_kill_wait_timeout = False
    cleanup_error = None; helper_receipt_validated = False
    old_handlers = {}
    def stop(signum, frame):
        raise KeyboardInterrupt(f'calibration interrupted by signal {signum}')
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT): old_handlers[sig] = signal.signal(sig, stop)
    try:
        with (case/f'{name}.supervisor.stdout').open('xb') as out, (case/f'{name}.supervisor.stderr').open('xb') as err:
            child = subprocess.Popen(command, cwd=case, env=ENV, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            # E9 retains wall45 and the helper cleanup retains five seconds.
            # A separate fixed55-second watchdog also bounds helper receipt/I/O
            # overhead. It never extends E9's requested wall or CPU allowance.
            try:
                status = child.wait(timeout=55)
            except subprocess.TimeoutExpired:
                helper_watchdog_timeout = True
                raise
        assert status == 0, 'bounded helper failed; retained output is not a success'
        stdout = capture(Path(item['request']['stdout'])); stderr = capture(Path(item['request']['stderr']))
        receipt = loads(read_file(receipt_path))
        validate_helper_receipt(receipt, request_raw, binding['sha256'], stdout, stderr)
        helper_receipt_validated = True
        verify()
        return stdout, stderr
    except BaseException as error:
        interrupted = type(error).__name__ + ': ' + str(error)
        # Repeated catchable signals cannot interrupt the finite failure path.
        failure_signals.ignore()
        try:
            if child is not None and child.poll() is None:
                try:
                    child.terminate(); terminate_sent = True
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    termination_grace_timeout = True
                    # SIGKILL is not descendant-collection evidence. Even if
                    # the direct helper reaps, external ownership stays pending
                    # unless its exact successful cleanup receipt was verified.
                    try:
                        child.kill(); kill_sent = True
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        post_kill_wait_timeout = True
        except BaseException as cleanup_failure:
            cleanup_error = type(cleanup_failure).__name__ + ': ' + str(cleanup_failure)
        # Keep these signals ignored through both the supervisor receipt below
        # and run()'s failed-incomplete receipt. run() restores the original
        # dispositions only after that terminal failure evidence is written.
        raise
    finally:
        try:
            write_new(case/f'{name}.supervisor.json', dict(argv=command, elapsed_seconds=time.monotonic()-started,
                exit=None if child is None else child.returncode, interrupted=interrupted,
                request_sha256=digest(request_raw), helper_sha256=binding['sha256'],
                helper_watchdog_seconds=55, termination_grace_seconds=10, post_kill_wait_seconds=5,
                helper_watchdog_timeout=helper_watchdog_timeout, terminate_sent=terminate_sent,
                termination_grace_timeout=termination_grace_timeout, kill_sent=kill_sent,
                post_kill_wait_timeout=post_kill_wait_timeout, cleanup_error=cleanup_error,
                helper_receipt_validated=helper_receipt_validated,
                unresolved_ownership=child is not None and not helper_receipt_validated,
                external_cleanup_required=child is not None and not helper_receipt_validated,
                child_pid=None if child is None else child.pid))
        finally:
            if interrupted is None:
                for sig, handler in old_handlers.items(): signal.signal(sig, handler)


def run(args):
    source_path = HERE/'source-manifest.json'
    source, manifest = frozen(source_path, args.source_manifest_sha256)
    target = args.output.absolute()
    assert RUNS.is_dir() and not RUNS.is_symlink(), 'root must prepare the ignored runs directory'
    assert target.parent.resolve() == RUNS.resolve() and not target.exists()
    assert target.name not in ('', '.', '..') and target.name.isascii()
    binding = None
    if args.mode == 'stage1':
        assert args.helper_binding and args.helper_binding_sha256, 'stage1 requires reviewed root subreaper binding'
        binding = bind_helper(args.helper_binding, args.helper_binding_sha256, args.source_manifest_sha256)
    target.mkdir()
    commands = command_plan(manifest, target)
    write_new(target/'command-plan.json', dict(stage=1, commands=commands, application_execution=False))
    with (target/'calibration-manifest.json').open('xb') as stream: stream.write(read_file(HERE/'manifest.json'))
    write_new(target/'source-binding.json', dict(source_manifest_sha256=args.source_manifest_sha256,
        calibration_manifest_sha256=MANIFEST_SHA256, source=source))
    if args.mode == 'prepare':
        write_new(target/'prepared.json', dict(status='PREPARED_NOT_EXECUTED', tool_invocations=0,
            rewritten_app_invocations=0, cleanup_helper_binding='pending', required_tool_commands=12))
        return
    assert binding is not None
    def verify():
        current_source, current_manifest = frozen(source_path, args.source_manifest_sha256)
        assert current_source == source and current_manifest == manifest
        assert bind_helper(args.helper_binding, args.helper_binding_sha256, args.source_manifest_sha256) == binding
    completed = []
    failure_signals = FailureSignals()
    try:
        for index, case in enumerate(manifest['cases']):
            directory = target/case['id']; directory.mkdir()
            original, original_elf = authenticate_case(case)
            front, back = commands[2*index:2*index+2]
            _, frontend_stderr = helper_command(front, source, binding, verify, failure_signals)
            assert b'warning:' not in frontend_stderr and b'error:' not in frontend_stderr
            rpc_path = directory/'request.json'; rpc = read_file(rpc_path)
            rpc_result = validate_rpc(rpc, case, original, original_elf)
            write_new(directory/'rpc-audit.json', rpc_result)
            rpc_path.chmod(0o444)  # Preserve exact frontend bytes, never reserialize.
            assert not (directory/'a.out').exists()
            assert digest(read_file(rpc_path)) == rpc_result['rpc_sha256']
            stdout, stderr = helper_command(back, source, binding, verify, failure_signals)
            assert read_file(rpc_path) == rpc
            output = read_file(directory/'a.out')
            stats = backend_stats(stdout, stderr, case, original, output)
            output_elf = elf64(output)
            assert output_elf['kind'] == original_elf['kind']
            write_new(directory/'elf-inventory.json', dict(original=original_elf, output=output_elf,
                loader_hooks_inventory_only=True, loader_admission=False, application_execution=False))
            write_new(directory/'backend-audit.json', stats)
            verify()
            artifacts = inventory(directory)
            expected_artifacts = {'request.json', 'rpc-audit.json', 'a.out', 'elf-inventory.json', 'backend-audit.json'}
            for phase in ('frontend', 'backend'):
                expected_artifacts.update(phase + suffix for suffix in
                    ('.request.json', '.receipt.json', '.stdout', '.stderr', '.supervisor.stdout', '.supervisor.stderr', '.supervisor.json'))
            assert artifacts.keys() == expected_artifacts, 'unexpected or missing generated artifact'
            result = dict(id=case['id'], input_sha256=case['input_sha256'], core_output_sha256=case['core_output_sha256'],
                e9_output_sha256=digest(output), e9_output_bytes=len(output), rpc_sha256=digest(rpc),
                selected=rpc_result['selected'], backend=stats, artifacts=artifacts,
                status='B1_ARTIFACT_GENERATED_NATIVE_NOT_RUN')
            write_new(directory/'case-result.json', result); completed.append(result)
        assert [case['id'] for case in completed] == CASE_IDS
        assert len(completed) == 6
        verify()
        write_new(target/'stage1-complete.json', dict(status='B1_ARTIFACT_CALIBRATION_COMPLETE_NATIVE_NOT_RUN',
            source_manifest_sha256=args.source_manifest_sha256, calibration_manifest_sha256=MANIFEST_SHA256,
            helper_binding_sha256=args.helper_binding_sha256, rewrites=6, B1_successes=6, other_tactics=0,
            source_mutations=0, tool_commands=12, actual_baseline_runs=0, actual_rewritten_native_runs=0,
            pending_stage2=dict(enabled=False, backend_ABI_defect_resolved=False,
                                required_baselines=4, required_rewritten_native_runs=36,
                                stdout_hex=manifest['expected']['stdout_hex'], loader_audit_required=True),
            cases=completed, artifacts=inventory(target)))
    except BaseException as error:
        failure_signals.ignore()
        supervisors = []
        for item in commands:
            path = Path(item['request']['cwd']) / (item['name'] + '.supervisor.json')
            if path.exists():
                # A signal on the formerly successful path may have interrupted
                # this receipt before it became a failure. Preserve its bytes
                # and mark unknown ownership; never let parsing suppress the
                # top-level failed-incomplete evidence.
                try:
                    raw = capture(path)
                    receipt = loads(raw)
                    assert type(receipt['unresolved_ownership']) is bool
                    assert type(receipt['external_cleanup_required']) is bool
                    supervisors.append(dict(path=str(path), sha256=digest(raw), receipt=receipt))
                except BaseException as receipt_error:
                    supervisors.append(dict(path=str(path), receipt_error=type(receipt_error).__name__+': '+str(receipt_error),
                        receipt=dict(unresolved_ownership=True, external_cleanup_required=True)))
        write_new(target/'failed-incomplete.json', dict(status='FAILED_INCOMPLETE_NO_RETRY',
            completed_cases=[case['id'] for case in completed], error=type(error).__name__+': '+str(error),
            traceback=traceback.format_exc(), rewritten_app_executed=False,
            supervisor_receipts=supervisors,
            unresolved_ownership=any(row['receipt']['unresolved_ownership'] for row in supervisors),
            external_cleanup_required=any(row['receipt']['external_cleanup_required'] for row in supervisors)))
        raise
    finally:
        failure_signals.restore()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('mode', choices=['prepare','stage1'])
    parser.add_argument('--source-manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--helper-binding', type=Path)
    parser.add_argument('--helper-binding-sha256')
    run(parser.parse_args())

if __name__ == '__main__': main()
