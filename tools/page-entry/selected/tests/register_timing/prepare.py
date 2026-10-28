#!/usr/bin/env python3
"""Exact small adapters; the old complete comparison function is unchanged."""
import argparse
import hashlib
import json
from pathlib import Path
SOURCE_SHA256 = '6d4e551426006b33ebd38cceff1ab48762ab19d310a07cbb74e42a94497f44c1'
GENERATED_SHA256 = 'd265cd2e551923ce99017316a5651ecbd35df981be9f470f3b6bff1f6a7dbc26'
ADAPTER_SHA256 = '7280b13680f80740e5f4642072a0660814d7222c9b61537330a04696552ac1e3'

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=Path);ap.add_argument('output',type=Path)
    args=ap.parse_args();before=args.source.read_bytes()
    adapters=Path(__file__).with_name('ADAPTERS.json').read_bytes()
    if hashlib.sha256(before).hexdigest()!=SOURCE_SHA256 or hashlib.sha256(adapters).hexdigest()!=ADAPTER_SHA256:
        raise ValueError('exact reviewed source/adapter required')
    operations=json.loads(adapters);after=before
    for op in operations:
        a,b=op['old'].encode(),op['new'].encode()
        if after.count(a)!=1:raise ValueError('one literal adapter required')
        after=after.replace(a,b)
    restored=after
    for op in reversed(operations):restored=restored.replace(op['new'].encode(),op['old'].encode(),1)
    if restored!=before or hashlib.sha256(after).hexdigest()!=GENERATED_SHA256:
        raise ValueError('exact reversible generated support')
    with args.output.open('xb') as f:f.write(after)
    if args.source.read_bytes()!=before or args.output.read_bytes()!=after:raise ValueError('source/generated mutation')
    print(json.dumps(dict(source_sha256=SOURCE_SHA256,generated_sha256=GENERATED_SHA256,bytes=len(after)),sort_keys=True))
if __name__=='__main__':main()
