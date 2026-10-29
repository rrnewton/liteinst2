#!/usr/bin/env python3
"""Exact test-only PF-write and aligned-GP extension; all other bytes retained."""
import argparse,hashlib,json
from pathlib import Path

def prepare(selected,output):
    raw=(selected/'tests/generic/fixture.c').read_bytes()
    if hashlib.sha256(raw).hexdigest()!='b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910':raise ValueError('exact complete common fixture')
    operations=json.loads((Path(__file__).parent/'ADAPTERS.json').read_bytes())
    result=raw
    for op in operations:
        before,after=op['old'].encode(),op['new'].encode()
        if result.count(before)!=1:raise ValueError('unique complete native fault predicate')
        result=result.replace(before,after)
    inverse=result
    for op in reversed(operations):
        if inverse.count(op['new'].encode())!=1:raise ValueError('unique inverse predicate')
        inverse=inverse.replace(op['new'].encode(),op['old'].encode())
    if inverse!=raw:raise ValueError('whole original common fixture inverse')
    output.mkdir(parents=True,exist_ok=True)
    with(output/'common.inc').open('xb')as f:f.write(result)
    return dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--selected',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
    print(json.dumps(prepare(a.selected,a.output_dir),sort_keys=True))
