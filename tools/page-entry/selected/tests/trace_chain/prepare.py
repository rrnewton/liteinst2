#!/usr/bin/env python3
"""Only three exact support adapters; no copied production runtime tree."""
import argparse
import hashlib
import json
from pathlib import Path

SOURCE_SHA256='b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910'
GENERATED_SHA256='3f21a0ed42e34c459d3a510471dd1056f9282bbf2897b0dd583997ec7517cdb0'
OPERATIONS=[(b'static int dump(void) {\n    result.header_bytes=sizeof(result);result.sample_bytes=sizeof(struct sample);\n    return write_all(3,&result,sizeof(result)) && write_all(3,samples,sizeof(samples)) &&\n           write_all(3,&negative_sample,sizeof(negative_sample)) && write_all(3,&refused_last,sizeof(refused_last));\n}', b'static int dump(void) { return chain_dump(); }'), (b'long raw(long n,long a,long b,long c,long d,long e,long f) {', b'static long fixture_kernel_raw(long n,long a,long b,long c,long d,long e,long f) {'), (b'int fd=sealed_elf();const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};', b'int fd=chain_sealed_elf();const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};')]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();before=a.source.read_bytes();generated=before
    if hashlib.sha256(before).hexdigest()!=SOURCE_SHA256:raise ValueError('exact generic source')
    for old,new in OPERATIONS:
        if generated.count(old)!=1:raise ValueError('unique exact adapter')
        generated=generated.replace(old,new)
    if hashlib.sha256(generated).hexdigest()!=GENERATED_SHA256:raise ValueError('exact generated source')
    with a.output.open('xb') as f:f.write(generated)
    if a.source.read_bytes()!=before or a.output.read_bytes()!=generated:raise ValueError('source/generated closure')
    print(json.dumps(dict(source_sha256=SOURCE_SHA256,generated_sha256=GENERATED_SHA256,
                         source_bytes=len(before),generated_bytes=len(generated)),sort_keys=True,separators=(',',':')))

if __name__=='__main__':main()
