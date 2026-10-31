#!/usr/bin/env python3
"""Publish the compact summary and CSV from one closed startup profile.

This projection preserves a failed target outcome. Sample shares describe
user CPU in that run; they are neither wall-time shares nor event counts.
"""
import argparse
import csv
import hashlib
import io
import json
import platform
from pathlib import Path


def need(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--expect-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.summary.read_bytes()
    need(hashlib.sha256(data).hexdigest() == args.expect_sha256,
         'exact closed summary digest')
    value = json.loads(data)
    need(value['schema'] == 1 and value['status'] == 'observed_unqualified'
         and value['qualification'] is False and value['performance_credit'] is False
         and value['target_outcome'] == 'failed_prefix' and value['target_exit'] != 0,
         'failed prefix remains failed and unqualified')
    need(all(value[k] is True for k in ('source_unchanged', 'cleanup_complete',
                                      'namespace_complete', 'loss_free', 'exec_envelope'))
         and value['final_error_count'] == 0 and value['error_type'] is None,
         'closed complete observation')
    count = value['sample_count']
    totals = value['phases']['totals']
    need(type(count) is int and count > 0
         and sum(row['samples'] for row in totals) == count,
         'whole sample population')
    rows = [('phase', row['phase'], row) for row in totals]
    rows += [('leaf_function', row['key'], row) for row in value['top_functions']]
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator='\n')
    writer.writerow(('revision', 'target_outcome', 'target_exit', 'target_wall_ns',
                     'kind', 'key', 'samples', 'total_samples', 'sampled_period'))
    for kind, key, row in rows:
        need(type(row['samples']) is int and 0 <= row['samples'] <= count
             and type(row['period']) is int and row['period'] >= 0,
             'bounded actual sample projection')
        writer.writerow((value['source_revision'], value['target_outcome'],
                         value['target_exit'], value['target_wall_ns'], kind, key,
                         row['samples'], count, row['period']))
    output = stream.getvalue().encode()
    combined = data + output
    need(len(combined) <= 32768 and all(token.encode() not in combined for token in
         ('/home/', str(Path.cwd().resolve()), platform.node()) if len(token) > 1),
         'compact public projection without host paths or hostname')
    need(args.output.suffix == '.json' and not args.output.exists()
         and not args.output.with_suffix('.csv').exists(), 'fresh JSON/CSV destination')
    args.output.write_bytes(data)
    args.output.with_suffix('.csv').write_bytes(output)
    print(json.dumps({'json_bytes': len(data), 'csv_bytes': len(output),
                      'target_outcome': value['target_outcome']}))


if __name__ == '__main__':
    main()
