#!/usr/bin/env python3
"""Copy one closed counter summary and flatten its independent cells to CSV."""
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


def cells(value, key='counts'):
    if isinstance(value, dict):
        for name, item in sorted(value.items()):
            yield from cells(item, key+'.'+name)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from cells(item, key+'['+str(index)+']')
    else:
        need(value is None or type(value) is int and 0 <= value < 1 << 64,
             'independent unsigned counter cell or explicitly unavailable value')
        yield key, value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--expect-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.summary.read_bytes()
    need(hashlib.sha256(data).hexdigest() == args.expect_sha256, 'exact closed summary')
    value = json.loads(data)
    need(value['schema'] == 1 and value['profile'] == 'startup-final-counter-diagnostic-v1'
         and value['status'] == 'observed_unqualified'
         and value['qualification'] is False and value['performance_credit'] is False
         and value['target_outcome'] == 'failed_prefix' and value['target_exit'] != 0,
         'failed prefix remains failed and unqualified')
    need(all(value[k] is True for k in ('source_unchanged', 'cleanup_complete', 'namespace_complete'))
         and value['final_error_count'] == 0 and value['error_type'] is None,
         'closed complete observation')
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator='\n')
    writer.writerow(('revision', 'target_outcome', 'target_exit', 'target_wall_ns', 'cell', 'value'))
    for key, item in cells(value['counts']):
        writer.writerow((value['source_revision'], value['target_outcome'], value['target_exit'],
                         value['target_wall_ns'], key, 'unavailable' if item is None else item))
    output = stream.getvalue().encode()
    need(len(data+output) <= 32768 and all(token.encode() not in data+output for token in
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
