#!/usr/bin/env python3
"""Expand a schema-5 campaign summary; this is presentation, not qualification."""
import hashlib
import json
import sys
from pathlib import Path


def columns(table):
    return [dict(zip((table['columns'][i] for i in table['layouts'][layout]), values,
                     strict=True)) for layout, values in table['rows']]


def expand(encoded):
    result = dict(encoded)
    encoding = result.pop('columnar')
    if result['schema'] != 5 or encoding['encoding'] != 'named-columns-and-metadata-v1':
        raise ValueError('unsupported campaign presentation')
    result['schema'] = encoding['decoded_schema']
    metadata = result.pop('metadata')
    result['stages'] = columns(result['stages'])
    for stage in result['stages']:
        for key in ('cases', 'components'):
            if isinstance(stage.get(key), dict):
                stage[key] = columns(stage[key])
        for key in ('closure', 'result_sha256'):
            if key in stage:
                stage[key] = metadata[stage[key]]
    result['bounds'] = {
        key: {profile: metadata[index] for profile, index in value['map'].items()}
        if 'map' in value else metadata[value['value']]
        for key, value in result['bounds'].items()
    }
    for key in ('populations', 'controls'):
        table = result[key]
        result[key] = dict(zip(table['keys'], columns(table['table']), strict=True))
    canonical = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if hashlib.sha256(canonical).hexdigest() != encoding['decoded_sha256']:
        raise ValueError('expanded summary digest differs')
    return result


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: expand_campaign_summary.py SUMMARY.json')
    print(json.dumps(expand(json.loads(Path(sys.argv[1]).read_bytes())), indent=2, sort_keys=True))
