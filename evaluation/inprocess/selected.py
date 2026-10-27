#!/usr/bin/env python3
"""Release native-output oracles for real selected-instruction source patches.

Native random samples are checked against architectural outcome rules, never
against an independently drawn sample. Supplied outcomes and unsupported RSP
forms remain separate preparation controls. Complete output stays in target/.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import sys

sys.dont_write_bytecode = True
from run import (Refusal, completed, file_digest, hardware, invalid_constant,
                 invoke, output, pairs, require, TIMES)
from checks import admission, source

REGISTERS = ('rax', 'rcx', 'rdx', 'rbx', 'rbp', 'rsi', 'rdi',
             'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
PREFIX = {
    'prefix_rdrand16_rax': ('rdrand', 16, 'rax'),
    'prefix_rdrand64_r8': ('rdrand', 64, 'r8'),
    'prefix_rdseed16_r9': ('rdseed', 16, 'r9'),
    'prefix_rdseed64_r15': ('rdseed', 64, 'r15'),
    'prefix_rdpid_rax': ('rdpid', 64, 'rax'),
    'prefix_rdpid_r8': ('rdpid', 64, 'r8'),
    'prefix_rdtscp_operand': ('rdtscp', None, None),
    'prefix_rdtscp_rexw': ('rdtscp', None, None),
}
CASES = {f'{kind}{width}_{reg}': (kind, width, reg)
         for kind in ('rdrand', 'rdseed') for width in (16, 32, 64) for reg in REGISTERS}
CASES.update({f'rdpid_{reg}': ('rdpid', 64, reg) for reg in REGISTERS})
CASES['rdtscp'] = ('rdtscp', None, None)
CASES.update({f'masked_{kind}': (kind, None if kind == 'rdtscp' else 64,
                               None if kind == 'rdtscp' else 'rax')
              for kind in ('rdrand', 'rdseed', 'rdpid', 'rdtscp')})
CASES.update(PREFIX)
BOOLS = ('first_logical_pc_match', 'last_logical_pc_match', 'published_verified',
         'source_unchanged_outside_plan', 'disarmed')
KEYS = {'schema_version', 'profile', 'case', 'status', 'class', 'width', 'destination',
        'iterations', 'batches', 'native_calls', 'patched_calls', 'entered', 'completed',
        'carry_clear', 'native_carry', 'first_carry', 'last_carry', 'cpuid_mask',
        'native_state_checks', 'patched_state_checks', 'register_words', 'xstate_mask',
        'xstate_compared_bytes', 'red_zone_bytes', 'faults', 'admitted_pages',
        'native_steady_ns', 'patched_steady_ns', *BOOLS, *TIMES}


def integer(value):
    return type(value) is int and 0 <= value < 2**64


def native_row(data, case, iterations):
    row = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    require(type(row) is dict and set(row) == KEYS, 'selected_row_keys')
    require(row['case'] == case and row['profile'] == 'native_outputs'
            and row['status'] == 'passed', 'selected_row_identity')
    kind, width, destination = CASES[case]
    require((row['class'], row['width'], row['destination']) == (kind, width, destination)
            and (row['width'] is None or type(row['width']) is int), 'selected_operand')
    for key, value in {'schema_version': 1, 'iterations': iterations, 'batches': 17,
                       'native_calls': 17 * iterations + 1, 'patched_calls': 17 * iterations + 2,
                       'entered': 17 * iterations + 2, 'completed': 17 * iterations + 2,
                       'native_state_checks': 1, 'patched_state_checks': 2,
                       'register_words': 17, 'red_zone_bytes': 128, 'faults': 1,
                       'admitted_pages': 2 if case in PREFIX else 1}.items():
        require(type(row[key]) is int and row[key] == value, 'selected_counts')
    require(all(row[key] is True for key in BOOLS), 'selected_semantic_checks')
    require(integer(row['carry_clear']) and row['carry_clear'] <= row['completed'], 'selected_carry_count')
    random = kind in ('rdrand', 'rdseed')
    for key in ('native_carry', 'first_carry', 'last_carry'):
        require(type(row[key]) is bool if random else row[key] is None, 'selected_carry_type')
    if random:
        require(row['carry_clear'] >= int(not row['first_carry']) + int(not row['last_carry']),
                'selected_carry_observations')
    else:
        require(row['carry_clear'] == 0, 'nonrandom_carry_count')
    require(integer(row['xstate_mask']) and integer(row['xstate_compared_bytes'])
            and row['xstate_compared_bytes'] > 0, 'selected_state_extent')
    require(all(integer(row[key]) and row[key] > 0 for key in TIMES), 'selected_time')
    require(row['handler_max_first_touch_ns'] == row['handler_first_touch_ns'], 'selected_single_fault_time')
    for key in ('native_steady_ns', 'patched_steady_ns'):
        require(type(row[key]) is list and len(row[key]) == 17
                and all(integer(value) and value > 0 for value in row[key]), 'selected_batch_times')
    mask = row['cpuid_mask']
    if case.startswith('masked_'):
        leaf, register, bit = {'rdrand': (1, 2, 30), 'rdseed': (7, 1, 18),
                               'rdpid': (7, 2, 22), 'rdtscp': (0x80000001, 3, 27)}[kind]
        require(type(mask) is dict and set(mask) == {'leaf', 'subleaf', 'outputs', 'calls', 'feature_bit_clear'},
                'cpuid_mask_keys')
        require(all(type(mask[key]) is int and mask[key] == value
                    for key, value in (('leaf', leaf), ('subleaf', 0), ('calls', 1)))
                and mask['feature_bit_clear'] is True, 'cpuid_mask_identity')
        require(type(mask['outputs']) is list and len(mask['outputs']) == 4
                and all(type(value) is int and 0 <= value <= 0xffffffff for value in mask['outputs'])
                and mask['outputs'][register] & (1 << bit) == 0, 'actual_cpuid_feature_bit')
    else:
        require(mask is None, 'unexpected_cpuid_mask')
    return row


def refusal_row(data):
    row = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    expected = {'schema_version': 1, 'profile': 'preparation_refusals', 'case': 'refusal_controls',
                'status': 'passed', 'rsp_refusals': 7, 'invalid_refusals': 6,
                'source_unchanged': True, 'native_executions': 0}
    require(type(row) is dict and row == expected
            and all(type(row[key]) is type(value) for key, value in expected.items()), 'selected_refusal_controls')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iterations', type=int, default=1000)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100000:
        parser.error('iterations must be in 1..100000')
    revision = output(['git', 'rev-parse', 'HEAD'])
    if output(['git', 'status', '--porcelain', '--untracked-files=no']):
        parser.error('tracked source must be committed before validation')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp + '-selected-' + revision[:12]
    private = Path('target/evaluation/inprocess') / name
    private.mkdir(parents=True, exist_ok=False)
    temporary = private / 'tmp'
    temporary.mkdir()
    destination = Path('evaluation/inprocess/results') / (name + '.json')
    env = admission.controlled_environment(os.environ, temporary.resolve())
    cpu = min(os.sched_getaffinity(0))
    record = {'schema_version': 1, 'revision': revision, 'tree': output(['git', 'rev-parse', 'HEAD^{tree}']),
              'started_utc': stamp, 'build_profile': 'release', 'source': None, 'source_unchanged': None,
              'runner_sha256': file_digest(Path(__file__)), 'status': 'failed', 'commands': [], 'rows': [],
              'environment': admission.ENV | {'CARGO_TARGET_DIR': 'target', 'TMPDIR': 'private_run/tmp',
                                             'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'},
              'reproduce': ['python3', 'evaluation/inprocess/selected.py', '--iterations', str(args.iterations)],
              'scope': 'Owned immutable regions; real eager core source patches; 118 native cases and 13 explicit preparation refusals. RSP output remains unsupported. No whole-program claim.'}
    try:
        require(len(CASES) == 118, 'selected_case_catalog')
        record['source'] = source()
        require(record['source']['revision'] == revision, 'revision_changed_before_build')
        record['hardware'] = hardware(cpu)
        record['configuration'] = admission.cargo_configuration(env)
        record['toolchain'] = {tool: admission.tool_version(tool, env) for tool in ('rustc', 'cargo')}
        command, _ = invoke(['cargo', 'build', '--release', '--locked', '--offline', '-p',
                             'liteinst-inprocess', '--example', 'selected_probe'], env, private, 'build', 600)
        record['commands'].append(command)
        require(completed(command), 'selected_release_build_failed')
        executable = Path('target/release/examples/selected_probe')
        expected = file_digest(executable)
        record['executable_sha256'] = expected
        for case in ('refusal_controls', *CASES):
            require(file_digest(executable) == expected, 'selected_executable_changed')
            iterations = 1 if case == 'refusal_controls' else args.iterations
            command, stdout = invoke([str(executable), case, str(iterations)], env, private, case, 60, cpu)
            record['commands'].append(command)
            require(completed(command), 'selected_case_execution_failed')
            require(command['stdout_bytes'] <= 65536, 'selected_oversized_output')
            data = stdout.read_bytes()
            record['rows'].append(refusal_row(data) if case == 'refusal_controls' else native_row(data, case, iterations))
        require(file_digest(executable) == expected, 'selected_executable_changed')
        require(admission.cargo_configuration(env) == record['configuration'], 'configuration_changed')
        record['status'] = 'passed'
    except (Refusal, admission.InvalidEvidence) as error:
        record['error'] = str(error)
    except Exception as error:
        record['error'] = type(error).__name__
    finally:
        try:
            record['source_unchanged'] = record['source'] is not None and source() == record['source']
        except Exception:
            record['source_unchanged'] = None
        if record['source_unchanged'] is not True:
            record['status'] = 'failed'
            record.setdefault('error', 'source_changed')
        attempted = {command['label'] for command in record['commands']}
        record['not_run_cases'] = [case for case in ('refusal_controls', *CASES) if case not in attempted]
        data = json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n'
        require(not any(len(value) > 1 and value in data
                        for value in (str(Path.home()), str(Path.cwd()), platform.node())), 'private_receipt_data')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('x') as receipt:
            receipt.write(data)
        print(destination)
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
