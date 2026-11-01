"""Reproduce the historical failed CALL/RET programme and its exact-binary profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
REVISION = '9fb789544f604732d94fddccbda57993273bf765'
ROOT = Path.cwd().resolve()
HERE = Path(__file__).resolve().parent
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
assert not sys.flags.optimize and sorted(os.sched_getaffinity(0)) == [3]
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == REVISION
assert not subprocess.check_output(['git', 'status', '--porcelain', '-uno'])
base = args.output.resolve()
assert base.is_relative_to(ROOT/'target/evaluation/inprocess') and not base.exists()
base.mkdir()
record = dict(schema=1, revision=REVISION, cpu=3, status='running', stages=[],
              no_retries=True, original_bounds_unchanged=True, performance_credit=False)

def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def save():
    (base/'cohort.json').write_text(json.dumps(record, indent=2)+'\n')

def stage(name, script, extra):
    assert sorted(os.sched_getaffinity(0)) == [3]
    argv = [sys.executable, '-B', str(script), *map(str, extra)]
    row = dict(name=name, argv=argv, script=fact(script), exit=None)
    record['stages'].append(row)
    save()
    start = time.monotonic_ns()
    with (base/(name+'.stdout')).open('xb') as out, (base/(name+'.stderr')).open('xb') as err:
        row['exit'] = subprocess.run(argv, stdout=out, stderr=err, check=False).returncode
    row['duration_ns'] = time.monotonic_ns()-start
    row['captures'] = {s: fact(base/(name+'.'+s)) for s in ('stdout', 'stderr')}
    save()
    return row

def public_result(name):
    lines = (base/(name+'.stdout')).read_text().splitlines()
    result = json.loads(lines[-1])
    path = ROOT/result['receipt']
    assert path.parent == ROOT/'evaluation/inprocess/results' and path.suffix == '.json'
    value = json.loads(path.read_bytes())
    private = ROOT/'target/evaluation/inprocess'/path.stem/'receipt.json'
    assert fact(private) == value['receipt']
    return path, private, value

try:
    owner = base/'owner'
    row = stage('owner', 'evaluation/inprocess/reproduce_ret_owner.py',
                ['--expect-revision', REVISION, '--cpu', 3, '--output', owner])
    assert row['exit'] == 0
    owner_receipt = owner/'ret_owner/receipt.json'
    owner_value = json.loads(owner_receipt.read_bytes())
    assert owner_value['status'] == 'passed' and owner_value['source_unchanged']
    row = stage('native41', 'evaluation/inprocess/direct_frontier_loop.py',
                ['--expect-revision', REVISION])
    assert row['exit'] == 0
    native, _, value = public_result('native41')
    assert value['status'] == 'passed' and value['source_unchanged']
    row = stage('program', 'evaluation/inprocess/cached_ret_program.py',
                ['--expect-revision', REVISION, '--direct-receipt', native,
                 '--ret-owner-receipt', owner_receipt,
                 '--ret-owner-receipt-sha256', fact(owner_receipt)['sha256']])
    public, origin, value = public_result('program')
    # The profile recipe deliberately studies this failure. It never relabels
    # failed target completion as a successful application or qualification.
    assert row['exit'] == 1 and value['status'] == 'failed'
    row = stage('profile', HERE/'run.py',
                ['--expect-revision', REVISION, '--expect-origin-revision', REVISION,
                 '--origin-receipt', origin, '--expect-origin-sha256', fact(origin)['sha256'],
                 '--output', base/'profile'])
    assert row['exit'] == 0
    result = json.loads((base/'profile/receipt.json').read_bytes())
    assert result['status'] == 'observed_unqualified' and result['target_outcome'] == 'failed_prefix'
    assert result['source_unchanged'] and result['cleanup_complete'] and not result['final_errors']
    record.update(status='observation_completed_target_failed', target_completed=False,
                  profile=fact(base/'profile/receipt.json'))
except BaseException as error:
    record.update(status='failed', error=repr(error))
    raise
finally:
    save()
