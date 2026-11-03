#!/usr/bin/env python3
"""Retain the original positive app; generate only the seven causal subjects."""
import argparse,hashlib,json
from pathlib import Path

DONOR='a44c2da97e3a6231a1fe756cb2bc06824ea8667e678006827792d5093a9cd966'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--donor',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();raw=a.donor.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=DONOR:
        raise ValueError('exact unchanged two-activation positive source')
    source=raw.decode();start=source.index('static void boundary(void){\n')
    end=source.index('\nint main(int argc,char **argv){',start)
    spans=[('static void need(int yes,unsigned n){if(!yes)die(n);}',
            'static void need(int yes,unsigned n){if(!yes)die(n);}\n#include "controls.h"'),
           (source[start:end],'static void boundary(void){rrx_boundary();}\n'),
           (' unsigned char original_stack[4096] __attribute__((aligned(64)));',
            ' rrx_prepare(argv[0]);\n unsigned char original_stack[4096] __attribute__((aligned(64)));')]
    for before,after in spans:
        if source.count(before)!=1:raise ValueError('unique whole causal source seam')
        source=source.replace(before,after,1)
    restored=source
    for before,after in reversed(spans):
        if restored.count(after)!=1:raise ValueError('unique inverse causal source seam')
        restored=restored.replace(after,before,1)
    if restored.encode()!=raw:raise ValueError('complete unchanged donor outside causal seams')
    if a.output.exists():raise ValueError('fresh exclusive generated source')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x')as f:f.write(source)
    print(json.dumps(dict(donor_sha256=DONOR,source_bytes=len(source.encode()),
        source_sha256=hashlib.sha256(source.encode()).hexdigest(),whole_inverse=True,
        replaced_boundaries=1,positive_source_unchanged=True),sort_keys=True))

if __name__=='__main__':main()
