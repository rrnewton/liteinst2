"""Fixed public recipe sequence under one externally held CPU reservation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path.cwd()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--expect-revision', required=True)
ap.add_argument('--cpu', type=int, required=True)
ap.add_argument('--output', type=Path, required=True)
args = ap.parse_args()
assert not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision)
assert sorted(os.sched_getaffinity(0)) == [args.cpu]
assert subprocess.run(['git', 'rev-parse', 'HEAD'], check=True, capture_output=True).stdout.decode().strip() == args.expect_revision
assert not subprocess.run(['git', 'status', '--porcelain', '--untracked-files=no'], check=True, capture_output=True).stdout
base = args.output.resolve()
assert base.is_relative_to(ROOT/'target/evaluation/inprocess') and not base.exists()
base.mkdir()
record = dict(schema=1, revision=args.expect_revision, cpu=args.cpu, status='running', stages=[],
              no_retries=True, original_child_bounds_unchanged=True)

def save():
    (base/'cohort.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def stage(name, script, extra, expected):
    assert sorted(os.sched_getaffinity(0)) == [args.cpu]
    directory = base/name
    argv = [sys.executable, '-B', script, '--expect-revision', args.expect_revision,
            *map(str, extra), '--output', str(directory)]
    row = dict(name=name, argv=argv, script_sha256=sha(script), exit=None, status='running')
    record['stages'].append(row); save()
    begin = time.monotonic_ns()
    with (base/(name+'.stdout')).open('xb') as out, (base/(name+'.stderr')).open('xb') as err:
        row['exit'] = subprocess.run(argv, stdout=out, stderr=err, check=False).returncode
    row['duration_ns'] = time.monotonic_ns()-begin
    row['stdout_sha256'] = sha(base/(name+'.stdout'))
    row['stderr_sha256'] = sha(base/(name+'.stderr'))
    receipt = directory/'receipt.json'
    row['receipt_sha256'] = sha(receipt) if receipt.is_file() else None
    value = json.loads(receipt.read_bytes()) if receipt.is_file() else {}
    row['status'] = value.get('status', 'no_receipt')
    save(); print(json.dumps(row), flush=True)
    assert row['exit'] == 0 and row['status'] == expected, name+' failed; no retry or downstream substitution'
    assert value['source_unchanged'] is True and value['inputs_unchanged'] is True and value['cleanup_complete'] is True
    assert value['revision'] == args.expect_revision and value['cpu'] == args.cpu
    return receipt, value

try:
    ar, av = stage('archive', 'evaluation/inprocess/call_owner/prepare_archive.py',
                   ['--cpu', args.cpu], 'passed')
    archive = Path(av['build']['artifacts']['decoder.a']['path'])
    assert archive.is_relative_to(base/'archive') and archive.is_file()
    cp, cv = stage('call217', 'evaluation/inprocess/call_push_native/run.py', [], 'observed_unqualified')
    cm, mv = stage('components', 'evaluation/inprocess/call_dispatch_component/run.py',
                   ['--cpu', args.cpu, '--archive', archive, '--archive-sha256', sha(archive)], 'components_passed')
    nd, nv = stage('native136', 'evaluation/inprocess/call_dispatch_native/run.py',
                   ['--cpu', args.cpu, '--archive-receipt', ar, '--archive-receipt-sha256', sha(ar),
                    '--components-receipt', cm, '--components-receipt-sha256', sha(cm),
                    '--call217-receipt', cp, '--call217-receipt-sha256', sha(cp)], 'passed')
    rt, rv = stage('ret', 'evaluation/inprocess/ret_dispatch/run.py',
                   ['--cpu', args.cpu, '--archive', archive, '--archive-sha256', sha(archive),
                    '--call217-receipt', cp, '--call217-receipt-sha256', sha(cp)], 'finite_experiments_passed')
    rs, sv = stage('ret15', 'evaluation/inprocess/ret_resume_native/run.py',
                   ['--cpu', args.cpu, '--ret-receipt', rt, '--ret-receipt-sha256', sha(rt)], 'observed_unqualified')
    ow, ov = stage('owner', 'evaluation/inprocess/call_owner/run.py',
                   ['--cpu', args.cpu, '--archive-receipt', ar, '--archive-receipt-sha256', sha(ar),
                    '--components-receipt', cm, '--components-receipt-sha256', sha(cm),
                    '--native136-receipt', nd, '--native136-receipt-sha256', sha(nd)], 'passed')
    record['status'] = 'all_seven_recipes_completed'
except BaseException as error:
    record['status'] = 'failed'
    record['error'] = repr(error)
    raise
finally:
    save()
