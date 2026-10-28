#!/usr/bin/env python3
"""Add only actual raw-boundary hooks to an exact old generated support file."""
import argparse
import hashlib
import json
from pathlib import Path

INPUTS = {
    'ecf5a0a0ad92a5ab88ba46c2b11eaff5bba0ff07fb0dfd466c237bc9324f833c': 'positive',
    '49f738fab848dc56e64f4d3e52cc9f0e1320d4c968953dfdeaca474c3138f31d': 'controls',
}
OLD = b'long raw(long n,long a,long b,long c,long d,long e,long f) {'
NEW = b'#include "maps_phase.h"\nstatic long maps_fixture_kernel_raw(long n,long a,long b,long c,long d,long e,long f) {'
AFTER = b'#define RAW(n,a,b,c,d,e,f) raw(n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))'
WRAPPER = b'long raw(long n,long a,long b,long c,long d,long e,long f) {\n    return li2_maps_raw(maps_fixture_kernel_raw,n,a,b,c,d,e,f);\n}\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    before = args.source.read_bytes()
    digest = hashlib.sha256(before).hexdigest()
    if digest not in INPUTS or before.count(OLD) != 1 or before.count(AFTER) != 1:
        raise ValueError('exact old generated support required')
    after = before.replace(OLD, NEW).replace(AFTER, WRAPPER + AFTER)
    if after.replace(WRAPPER + AFTER, AFTER).replace(NEW, OLD) != before:
        raise ValueError('raw adapter exact inverse')
    with args.output.open('xb') as output:
        output.write(after)
    if args.source.read_bytes() != before or args.output.read_bytes() != after:
        raise ValueError('support changed')
    print(json.dumps({'scope': INPUTS[digest], 'before_sha256': digest,
                      'after_sha256': hashlib.sha256(after).hexdigest(),
                      'bytes': len(after)}, sort_keys=True))


if __name__ == '__main__':
    main()
