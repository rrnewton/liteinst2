#!/usr/bin/env python3
"""Export a closed checks-only receipt and hash-matched logs as compact JSON."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--closed', required=True, type=Path)
    p.add_argument('--sha256', required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    raw = (a.closed / 'receipt.json').read_bytes()
    assert sha(raw) == a.sha256
    d = json.loads(raw)
    assert d['revision'] == a.revision and d['recipe'].endswith(' --checks-only')
    out = {k: d[k] for k in ('schema', 'status', 'revision', 'recipe', 'scope', 'hardware',
           'parallelism', 'compiler_jobs', 'kernel_version', 'rustc', 'runner_sha256', 'helper_sha256')}
    out.update(source_receipt_sha256=a.sha256, projector_sha256=sha(Path(__file__).read_bytes()),
        count_policy='Last libtest terminal per Cargo Running/Doc-tests group. Nested summaries excluded. Custom cleanup harness has no libtest terminal. Failed or incomplete runs are not complete workspace totals.',
        commands=[])
    names = ['fmt', 'clippy', 'check', 'workspace-default', 'serial-launch', 'staged-allocation', 'prefixed-pun']
    assert [c['name'] for c in d['commands']] == names[:len(d['commands'])]
    for c in d['commands']:
        b = (a.closed / (c['name'] + '.log')).read_bytes()
        assert sha(b) == c['closed']['private_log_sha256']
        groups, raw_count = [], 0
        for line in b.decode().splitlines():
            if re.match(r'^\s+(?:Running|Doc-tests) ', line):
                groups.append([])
            m = re.match(r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', line)
            if m:
                assert groups
                groups[-1].append(tuple(map(int, m.groups())))
                raw_count += 1
        terminals = [g[-1] for g in groups if g]
        counts = dict(zip(('passed', 'failed', 'ignored'), (sum(t[i] for t in terminals) for i in range(3))))
        out['commands'].append({k: c[k] for k in ('name', 'argv', 'wall_limit_seconds', 'closed')} |
            dict(libtest=dict(**counts, cargo_groups=len(groups), terminal_groups=len(terminals),
                             excluded_nested=raw_count-len(terminals))))
    out['unrun'] = names[len(d['commands']):]
    if d['status'] == 'PASS':
        assert not out['unrun']
        for c in out['commands']:
            v = c['closed']
            assert v['exit_code'] == 0 and v['termination'] is None
            assert v['cleanup_complete'] is True and v['reaped_descendants'] == 0
            assert c['libtest']['failed'] == 0
    encoded = json.dumps(out, sort_keys=True, separators=(',', ':')) + '\n'
    assert '/home/' not in encoded and '.facebook.com' not in encoded
    with a.output.open('x') as f:
        f.write(encoded)


if __name__ == '__main__':
    main()
