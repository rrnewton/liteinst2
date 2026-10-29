#!/usr/bin/env python3
"""Two exact definition renames; complete first-slice code remains present."""
import sys
sys.dont_write_bytecode=True
import argparse
import hashlib
import json
from pathlib import Path
SOURCE_SHA256 = '99d974697c724ea6a50727947972c11a519519aee8a2f7c80ca389395fda64bf'
GENERATED_SHA256 = '956807ee1e2e91ed8a89699ffb918d297710482c70466e4096cfabd3407f8896'
OPERATIONS = [(b'static int tr_dump(void) {', b'static int tr_dump_base(void) {'), (b'int fixture_main(unsigned long *stack) {', b'int ru_unused_fixture_main(unsigned long *stack) {')]

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('source',type=Path);ap.add_argument('output',type=Path)
    a=ap.parse_args();before=a.source.read_bytes()
    if hashlib.sha256(before).hexdigest()!=SOURCE_SHA256:raise ValueError('exact first-slice fixture source')
    generated=before
    for old,new in OPERATIONS:
        if generated.count(old)!=1:raise ValueError('unique definition-only adapter')
        generated=generated.replace(old,new)
    if hashlib.sha256(generated).hexdigest()!=GENERATED_SHA256:raise ValueError('exact two-definition support')
    with a.output.open('xb') as f:f.write(generated)
    if a.source.read_bytes()!=before or a.output.read_bytes()!=generated:raise ValueError('source/output changed')
    print(json.dumps(dict(source_sha256=SOURCE_SHA256,generated_sha256=GENERATED_SHA256,
        source_bytes=len(before),generated_bytes=len(generated)),sort_keys=True,separators=(',',':')))
if __name__=='__main__':raise SystemExit(main())
