#!/usr/bin/env python3
"""Generate two support includes with the three reviewed control adapters."""
import argparse
import hashlib
import json
from pathlib import Path

DUMP_OLD = b'static int dump(void) {\n    result.header_bytes=sizeof(result);result.sample_bytes=sizeof(struct sample);\n    return write_all(3,&result,sizeof(result)) && write_all(3,samples,sizeof(samples)) &&\n           write_all(3,&negative_sample,sizeof(negative_sample)) && write_all(3,&refused_last,sizeof(refused_last));\n}'
DUMP_NEW = b'static int dump(void) { return register_dump(); }'
ADAPTERS = [
  {
    "input": "fixture.c",
    "output": "positive_support.inc",
    "substitutions": [
      [
        "static int register_dump(void) {",
        "static int positive_dump(void) {"
      ],
      [
        "int fixture_main(unsigned long *stack) {",
        "int unchanged_register_positive_main(unsigned long *stack) {"
      ]
    ],
    "before_sha256": "6d4e551426006b33ebd38cceff1ab48762ab19d310a07cbb74e42a94497f44c1",
    "after_sha256": "bae491633d24aaeb03c59e533d2cb3eae77100d801341d97eb04585309748d7f"
  },
  {
    "input": "run_support.inc",
    "output": "run_support.inc",
    "substitutions": [
      [
        "const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};",
        "const struct li2_lifecycle_hooks hooks={raw,control_lifecycle_fail,protected_range};"
      ]
    ],
    "before_sha256": "ecf5a0a0ad92a5ab88ba46c2b11eaff5bba0ff07fb0dfd466c237bc9324f833c",
    "after_sha256": "49f738fab848dc56e64f4d3e52cc9f0e1320d4c968953dfdeaca474c3138f31d"
  }
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('generic', type=Path)
    parser.add_argument('positive', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    generic, positive = args.generic.read_bytes(), args.positive.read_bytes()
    if sha(generic) != 'b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910' or generic.count(DUMP_OLD) != 1:
        raise ValueError('exact unchanged generic fixture required')
    run = generic.replace(DUMP_OLD, DUMP_NEW)
    values = {'fixture.c': positive, 'run_support.inc': run}
    result = {}
    for edit in ADAPTERS:
        data = values[edit['input']]
        if sha(data) != edit['before_sha256']:
            raise ValueError('exact reviewed adapter predecessor required')
        for old, new in edit['substitutions']:
            old, new = old.encode(), new.encode()
            if data.count(old) != 1:
                raise ValueError('exact single reviewed control adapter required')
            data = data.replace(old, new)
        if sha(data) != edit['after_sha256']:
            raise ValueError('exact reviewed adapter result required')
        name = 'control_support.inc' if edit['output'] == 'positive_support.inc' else edit['output']
        target = args.output/name
        with target.open('xb') as output:
            output.write(data)
        if target.read_bytes() != data:
            raise ValueError('generated support changed')
        result[name] = {'bytes': len(data), 'sha256': sha(data)}
    if args.generic.read_bytes() != generic or args.positive.read_bytes() != positive:
        raise ValueError('support source changed')
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
