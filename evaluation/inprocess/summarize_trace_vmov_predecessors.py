#!/usr/bin/env python3
"""Compact predecessor observations; pure projection, never a validation gate."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def selected(value, keys):
    return {key: value[key] for key in keys if key in value}


TOP = '''profile status expected_revision started_utc reproduce command_count cohort_command_count
source_unchanged configuration_unchanged failure_type final_error_count cleanup_complete
qualification programs selection timing completed_cases accepted_cases required_cases
required_native_processes attempted_native_processes'''.split()
CASE = '''name status exit actual_exit native_exit gated_exit process_outcome operation_completed
verified_memory_fault accepted classification expected_operation environment_delta counters
outcome chain cache_counts first_touch_ns steady_state_ns whole_process_ns last_opcode environment'''.split()
PROFILES = {'page-selected-' + suffix for suffix in (
    'vmovdqu64-oracle-v1', 'chain-oracle-v1', 'vpbroadcast-oracle-v1', 'generic-oracle-v1',
    'maps-v1', 'register-controls-v1', 'register-connected-v1', 'register-time-v1', 'chain-real-v1')}


def project(path):
    raw = path.read_bytes()
    helper = Path('evaluation/inprocess/summarize_selected.py')
    initial = json.loads(raw)
    if sha(helper.read_bytes()) != initial['summary_reader_sha256']:
        raise ValueError('summary reader changed')
    spec = importlib.util.spec_from_file_location('predecessor_reader', helper)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    inputs = json.loads(raw, object_pairs_hook=reader.unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite input')))
    tables = {key: [] for key in ('sources', 'hardware', 'totals', 'real_cases', 'connected_cases')}

    def intern(key, value):
        if value not in tables[key]:
            tables[key].append(value)
        return tables[key].index(value)

    rows, seen = [], set()
    for supplied in inputs['predecessor_receipts']:
        name = supplied['name']
        if Path(name).name != name or name in seen:
            raise ValueError('receipt basename/duplicate')
        seen.add(name)
        original = Path('evaluation/inprocess/results') / name
        data, receipt = reader.read(original)
        if len(data) != supplied['bytes'] or sha(data) != supplied['sha256']:
            raise ValueError('predecessor receipt changed')
        revision = receipt['source']['revision']
        if (not re.fullmatch('[0-9a-f]{40}', revision) or revision != supplied['revision']
                or receipt['expected_revision'] != revision or receipt['status'] != supplied['status']
                or receipt['profile'] not in PROFILES):
            raise ValueError('predecessor identity/status changed')
        private_path = Path('target/evaluation/inprocess') / original.stem / 'receipt.json'
        private_data, private = reader.read(private_path)
        binding = receipt['private_receipt']
        if (len(private_data) != binding['bytes'] or sha(private_data) != binding['sha256']
                or private['status'] != receipt['status'] or private['source'] != receipt['source']
                or private['expected_revision'] != revision):
            raise ValueError('private predecessor receipt changed')
        row = selected(receipt, TOP)
        row['receipt'] = {'name': name, 'bytes': len(data), 'sha256': sha(data)}
        row['source_index'] = intern('sources', receipt['source'])
        hardware = dict(receipt['hardware']) if receipt['hardware'] is not None else None
        if hardware is not None:
            for key in ('probe_cpu', 'affinity_cpu_count'):
                if key in hardware:
                    row[key] = hardware.pop(key)
        row['hardware_index'] = intern('hardware', hardware)
        restored = dict(hardware) if hardware is not None else None
        if restored is not None:
            restored.update({key: row[key] for key in ('probe_cpu', 'affinity_cpu_count') if key in row})
        if restored != receipt['hardware'] or sha(encoded(restored)) != sha(encoded(receipt['hardware'])):
            raise ValueError('hardware interning changed observations')
        row['hardware_sha256'] = sha(encoded(restored))
        row['original_evidence'] = selected(receipt, (
            'private_receipt', 'commands_sha256', 'command_rows_sha256', 'cases_sha256', 'case_rows_sha256'))
        if 'totals' in receipt:
            row['totals_index'] = intern('totals', receipt['totals'])
        for profile, table in (('page-selected-chain-real-v1', 'real_cases'),
                               ('page-selected-register-connected-v1', 'connected_cases')):
            if receipt['profile'] == profile:
                row['case_indices'] = [intern(table, selected(case, CASE)) for case in receipt['cases']]
        rows.append(row)
    if type(inputs['predecessor_count']) is not int or len(rows) != inputs['predecessor_count']:
        raise ValueError('predecessor inventory differs')
    return {'schema_version': 1, 'profile': 'merged-trace-vmov-predecessors-v1',
            'scope': 'Exact numeric projection of prior cycles; original statuses and real failures retained. No final-source qualification. Per-case full oracle objects remain in original receipts.',
            'hardware_binding': 'Readable hardware table plus per-run probe_cpu/affinity_cpu_count reconstructs the exact original object; SHA256 uses sorted compact JSON.',
            'projection_script_sha256': sha(Path(__file__).read_bytes()),
            'input_manifest_sha256': sha(raw), 'summary_reader_sha256': inputs['summary_reader_sha256'],
            'tables': tables, 'runs': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    value = project(args.inputs)
    data = encoded(value) + b'\n'
    if re.search(rb'/home/|devbig[0-9]+|internalfb\.com', data):
        raise ValueError('private-location marker')
    if len(data) > 35000:
        raise ValueError('predecessor projection exceeds 35,000 bytes; do not omit observations')
    with args.output.open('xb') as output:
        output.write(data)
    print(json.dumps({'runs': len(value['runs']), 'bytes': len(data), 'sha256': sha(data)}))


if __name__ == '__main__':
    main()
