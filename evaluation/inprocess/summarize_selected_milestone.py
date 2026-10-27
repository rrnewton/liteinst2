#!/usr/bin/env python3
"""Project existing receipts; this does not run or replace a qualification gate."""
import argparse
import copy
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read(path):
    data = path.read_bytes()
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    return data, value


def columns(rows):
    keys = sorted({key for row in rows for key in row})
    # Presence remains explicit: a missing key is not converted to an observed null.
    return {'columns': keys,
            'rows': [[row.get(key) for key in keys] for row in rows],
            'present': [sum(1 << i for i, key in enumerate(keys) if key in row) for row in rows]}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', action='append', required=True, help='Allowed exact native source revision; repeat for retained historical cohorts.')
    ap.add_argument('--historical-timing', type=Path, required=True)
    ap.add_argument('--timing', type=Path, action='append', required=True)
    ap.add_argument('--checks', type=Path, action='append', default=[])
    ap.add_argument('--pending-check-revision')
    ap.add_argument('--preflight', type=Path, action='append', default=[])
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('native_receipts', type=Path, nargs='+')
    args = ap.parse_args()
    paths = args.native_receipts + args.timing + args.checks + args.preflight + [args.historical_timing]
    if len({p.resolve() for p in paths}) != len(paths):
        raise ValueError('duplicate receipt input')
    sys.dont_write_bytecode = True
    helper = Path('evaluation/inprocess/summarize_selected.py')
    spec = importlib.util.spec_from_file_location('existing_projection', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    groups = {}
    for path in args.native_receipts:
        _, receipt = read(path)
        revision = receipt['expected_revision']
        if revision not in args.revision:
            raise ValueError('unlisted native revision: ' + path.name)
        groups.setdefault(revision, []).append(path)
    if set(groups) != set(args.revision):
        raise ValueError('unused or missing native source revision')
    summary = {'schema_version': 2, 'tables': {name: [] for name in (
        'hardware', 'environments', 'tools', 'bounds')}, 'runs': [],
        'summary_script_sha256': digest(helper.read_bytes())}
    summary['profile'] = 'selected-milestone-projection-v2'
    summary['projection_script_sha256'] = digest(Path(__file__).read_bytes())
    summary['scope'] = ('Projection only, not a new qualification gate. Finite controls and '
                        'real-program failures remain distinct. No new completion, qualification '
                        'or speedup is inferred. Per-case diagnostic counters and derived TSC statistics are omitted; all raw intervals, totals, exits and failure labels remain. Full scope and predicates remain '
                        'in the bound original receipts and evaluator sources.')
    summary['column_encoding'] = 'Rows follow columns; present is a bit mask distinguishing absent keys from observed null.'
    summary['command_exit_count_semantics'] = 'Actual process exits, not semantic failure counts; RNG and required negative controls can exit nonzero.'
    tables = summary['tables']
    tables['sources'] = []
    tables['tool_binaries'] = []
    tables['operation_labels'] = []

    def intern(name, value):
        if value not in tables[name]:
            tables[name].append(value)
        return tables[name].index(value)

    def associate(path, row):
        data, original = read(path)
        private_path = Path('target/evaluation/inprocess') / path.stem / 'receipt.json'
        private_data, private = read(private_path)
        binding = {'bytes': len(private_data), 'sha256': digest(private_data)}
        if original.get('private_receipt', binding) != binding:
            raise ValueError('private receipt binding: ' + path.name)
        if (private['status'] != original['status'] or private['source'] != original['source']
                or private['expected_revision'] != original['expected_revision']):
            raise ValueError('public/private source or status: ' + path.name)
        row['expected_revision'] = original['expected_revision']
        row['receipt'] = {'name': path.name, 'bytes': len(data), 'sha256': digest(data)}
        row['private_receipt'] = binding
        row['source_index'] = intern('sources', original['source'])
        row['provenance'] = {k: v for k, v in original.items() if k.endswith('_sha256')}
        if 'tool_hashes' in original:
            row['tool_binaries_index'] = intern('tool_binaries', original['tool_hashes'])
        commands = private['commands']
        actual = len(commands)
        if row.get('command_count', actual) != actual:
            raise ValueError('command count: ' + path.name)
        row['command_count'] = actual
        executed = [c for c in commands if c.get('exit', c.get('exit_code')) is not None]
        row['attempted_command_count'] = len(executed)
        row['not_run_command_rows'] = sum(c.get('status') == 'not_run' for c in commands)
        row['actual_command_exit_counts'] = dict(sorted(
            {str(code): sum(c.get('exit', c.get('exit_code')) == code for c in executed)
             for code in {c.get('exit', c.get('exit_code')) for c in executed}}.items()))
        # Native RNG exits and expected terminal controls are not failure counts.
        if original['status'] == 'failed' and executed:
            row['terminal_command'] = {k: executed[-1][k] for k in (
                'name', 'id', 'exit', 'exit_code', 'expected_exit', 'timed_out',
                'reaped', 'cleanup_complete', 'status') if k in executed[-1]}
        row.pop('scope', None)
        if 'cases' in row:
            original_cases = original['cases']
            if len(original_cases) != len(row['cases']):
                raise ValueError('case inventory')
            for case, full in zip(row['cases'], original_cases):
                for key in ('actual_failed_operation', 'verified_preopen_refusal', 'selected_outcome'):
                    if key in full:
                        case[key] = full[key]
                if original['profile'] in ('page-selected-bnd-jmp-oracle-v1', 'page-selected-pmaxud-oracle-v1'):
                    for key in ('record', 'query_evidence'):
                        if key in full:
                            case[key] = full[key]
            if original['profile'] != 'page-selected-register-real-v1':
                # Detailed per-case counters remain in the hash-bound original.
                # Public totals, dispositions, exits and raw intervals stay here.
                for case in row['cases']:
                    for key in ('counters', 'register', 'repeat'):
                        case.pop(key, None)
            for case in row['cases']:
                if 'process_outcome' in case:
                    case['operation_label_index'] = intern('operation_labels', case.pop('process_outcome'))
                if original['profile'] == 'page-selected-register-perf-v1':
                    for lane in case['outcome']['timing'].values():
                        for key in tuple(lane):
                            if key not in ('first_interval_ticks', 'steady_interval_ticks', 'steady_count'):
                                del lane[key]
            for key in ('counters', 'register', 'repeat'):
                values = [case.get(key) for case in row['cases']]
                if any(isinstance(value, dict) for value in values):
                    row['case_' + key] = columns([
                        {'value': value} if not isinstance(value, dict) else value
                        for value in values])
                    for case in row['cases']:
                        case.pop(key, None)
            row['cases'] = columns(row['cases'])
        if 'native_commands' in row:
            row['native_commands'] = columns(row['native_commands'])
        return original, private

    summary['native_inventory'] = []
    for revision, paths in groups.items():
        group = module.summarize(paths, revision)
        for path, row in zip(paths, group['runs']):
            for name in ('hardware', 'environments', 'tools', 'bounds'):
                row[name + '_index'] = intern(name, group['tables'][name][row[name + '_index']])
            associate(path, row)
            summary['runs'].append(row)
        summary['native_inventory'].append({
            'revision': revision, 'evaluators': len(group['runs']),
            'status_counts': {status: sum(row['status'] == status for row in group['runs'])
                              for status in sorted({row['status'] for row in group['runs']})},
            'commands': sum(row['command_count'] for row in group['runs'])})
    summary['observer_runs'] = []
    for historical, path in [(True, args.historical_timing)] + [(False, p) for p in args.timing]:
        _, original = read(path)
        row = {k: copy.deepcopy(original[k]) for k in (
            'profile', 'status', 'started_utc', 'reproduce', 'cpu', 'source_unchanged',
            'build_status', 'failure_type', 'final_error_count', 'cleanup_complete',
            'qualification', 'timing', 'selection', 'selected_configuration', 'programs',
            'workload', 'command_count') if k in original}
        if historical:
            if original['status'] != 'failed' or not any(p.get('whole_process_ns') is not None for p in row['programs']):
                raise ValueError('historical timing omission requires a failed receipt with exposed durations')
            for program in row['programs']:
                program.pop('whole_process_ns', None)
            row['historical_correction'] = {
                'omitted_public_field': 'programs[].whole_process_ns',
                'reason': 'Historical failed-run projection exposed diagnostic elapsed time. '
                          'It is not valid qualified timing and is deliberately not republished.',
                'corrected_projection': 'whole-process timing requires global pass and program completion'}
        if not historical and original['status'] != 'passed' and (
                row['timing'] is not None or any(p.get('whole_process_ns') is not None for p in row['programs'])):
            raise ValueError('unqualified real timing in failed receipt')
        for table, key in [('hardware', 'hardware'), ('tools', 'tool_versions'), ('bounds', 'bounds')]:
            row[table + '_index'] = intern(table, original.get(key))
        row['interval_scope'] = ('Finite synthetic qualification only: each [API ns, service ns] '
                                 'pair is CLOCK_MONOTONIC_RAW; all retained pairs are copied. '
                                 'No measured real-program site was selected.'
                                 if original['timing'] is None else original['interval_scope'])
        associate(path, row)
        summary['observer_runs'].append(row)
    summary['check_attempts'] = []
    for path in args.checks:
        _, original = read(path)
        row = {k: original[k] for k in (
            'profile', 'status', 'reproduce', 'source_unchanged', 'configuration_unchanged',
            'commands', 'environment', 'configuration', 'backing_cleanup_required', 'error') if k in original}
        for table, key in [('hardware', 'hardware'), ('tools', 'toolchain')]:
            row[table + '_index'] = intern(table, original.get(key))
        associate(path, row)
        summary['check_attempts'].append(row)
    summary['preflight_failures'] = []
    for path in args.preflight:
        _, original = read(path)
        row = {k: copy.deepcopy(original[k]) for k in (
            'profile', 'status', 'reproduce', 'source_unchanged', 'build_status',
            'failure_type', 'final_error_count', 'error', 'totals') if k in original}
        associate(path, row)
        if row['attempted_command_count'] or original['source'] is not None or original['status'] != 'failed':
            raise ValueError('not a zero-command preflight failure')
        summary['preflight_failures'].append(row)
    summary['pending_checks'] = ({'revision': args.pending_check_revision,
        'status': 'pending_fresh_qualification'} if args.pending_check_revision else None)
    old_hardware, tables['hardware'] = tables['hardware'], []
    for row in summary['runs'] + summary['observer_runs'] + summary['check_attempts']:
        hardware = copy.deepcopy(old_hardware[row['hardware_index']])
        if hardware is not None:
            row['hardware_probe_cpu'] = hardware.pop('probe_cpu', None)
            row['affinity_cpu_count'] = hardware.pop('affinity_cpu_count', None)
        row['hardware_index'] = intern('hardware', hardware)
    tables['case_tables'] = []
    tables['totals'] = []
    tables['native_command_tables'] = []
    for row in summary['runs']:
        for key, table in [('cases', 'case_tables'), ('totals', 'totals'), ('native_commands', 'native_command_tables')]:
            if key in row:
                row[key + '_index'] = intern(table, row.pop(key))
    summary['runs'] = columns(summary['runs'])
    data = encoded(summary) + b'\n'
    if re.search(rb"/home/|devbig[0-9]+|internalfb\.com", data):
        raise ValueError('private-location marker in public summary')
    for marker in (str(Path.home()), str(Path.cwd())):
        if marker.encode() in data:
            raise ValueError('private path in projection')
    args.output.write_bytes(data)
    print(json.dumps({'bytes': len(data), 'sha256': digest(data),
                      'native_inventory': summary['native_inventory']}))


if __name__ == '__main__':
    main()
