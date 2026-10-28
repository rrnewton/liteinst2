#!/usr/bin/env python3
"""Exact test-only common adapter: retain the full native write-fault predicate."""
import argparse,hashlib,json
from pathlib import Path

def prepare(selected,output):
    path=selected/'tests/generic/fixture.c';raw=path.read_bytes()
    expected='b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910'
    if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('exact complete common fixture')
    before=b'g[REG_TRAPNO]==14&&g[REG_ERR]==4,47);s->native_fault=1;'
    after=b'g[REG_TRAPNO]==14&&g[REG_ERR]==store_fault_error,47);s->native_fault=1;'
    if raw.count(before)!=1:raise ValueError('unique native-fault error predicate')
    result=raw.replace(before,after)
    if result.replace(after,before)!=raw:raise ValueError('exact adapter inverse')
    output.mkdir(parents=True,exist_ok=True)
    with (output/'common.inc').open('xb')as f:f.write(result)
    return dict(bytes=len(result),sha256=hashlib.sha256(result).hexdigest())

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--selected',type=Path,required=True)
    ap.add_argument('--output-dir',type=Path,required=True);args=ap.parse_args()
    print(json.dumps(prepare(args.selected,args.output_dir),sort_keys=True))
