#!/usr/bin/env python3
"""Reproduce deadline-failures.csv from this attempt's closed ignored captures.

This extracts recorded diagnostics. It neither launches a subject nor establishes
new campaign/native acceptance. For a new run use the public freeze/launch recipe.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--capture', type=Path, required=True)
parser.add_argument('--raw', type=Path, required=True)
a = parser.parse_args()
receipt = json.loads(Path(__file__).with_name('session.json').read_bytes())


def read(path, expected):
    data = path.read_bytes()
    assert len(data) == expected['bytes']
    assert hashlib.sha256(data).hexdigest() == expected['sha256']
    return data


owner = json.loads(read(a.capture / 'result.json', receipt['owner_result']))
closed = owner['closed']
assert closed['cleanup_complete'] and closed['termination'] is None
assert closed['exit_code'] == 1 and closed['reaped_descendants'] == 0
result = json.loads(read(a.raw / 'result.json', receipt['raw_result']))
assert result['custody_closed'] and result['retention_verified']
assert result['revision'] == owner['revision'] == receipt['revision']
assert result['qualifications'] == receipt['qualifications']
rows = []
for item in result['installed']:
    if item['status'] != 'FAILED':
        continue
    attempt, k, case = item['attempt'], item['k'], item['case']
    suffix = f'/attempt-{attempt}-k{k}-case-{case:02}-app/stderr.txt'
    pins = [v for p, v in result['retained'].items() if p.endswith(suffix)]
    assert len(pins) == 1
    text = read(a.raw / suffix[1:], pins[0]).decode('ascii')
    match = re.match(r'normal-call-pair-session FAILED: clock poll: Deadline committed=(\d+) completed=(\d+) pending=None elapsed_ns=(\d+) poll_gap_ns=(\d+) last_wait_ns=(None|Some\(\(\d+, \d+\)\)) ', text)
    assert match and match[1] == match[2]
    usage = re.search(r'rusage_delta=Value\(Usage \{ user_us: (\d+), system_us: (\d+), voluntary: (\d+), involuntary: (\d+), minor_faults: (\d+), major_faults: (\d+) \}\)', text)
    assert usage
    wait = re.fullmatch(r'Some\(\((\d+), (\d+)\)\)', match[5])
    rows.append(dict(attempt=attempt, k=k, case=case, kind='clock_poll_deadline',
        committed=int(match[1]), elapsed_ns=int(match[3]), poll_gap_ns=int(match[4]),
        requested_wait_ns='' if wait is None else int(wait[1]),
        actual_wait_ns='' if wait is None else int(wait[2]),
        user_us=int(usage[1]), system_us=int(usage[2]), involuntary_switches=int(usage[4]),
        stderr_sha256=pins[0]['sha256']))
assert rows == receipt['failures'] and len(rows) == 5
writer = csv.DictWriter(sys.stdout, fieldnames=list(rows[0]), lineterminator='\n')
writer.writeheader()
writer.writerows(rows)
