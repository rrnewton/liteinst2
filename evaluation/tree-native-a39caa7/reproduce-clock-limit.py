#!/usr/bin/env python3
"""Reproduce finite-CPU-limit accounting observations, with both process owners."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
out = args.output.resolve()
assert repo.joinpath('evaluation/admission/processes.py').is_file()
assert repo.joinpath('ignored') in out.parents, 'new output must be under ignored/'
out.mkdir(); (out/'tmp').mkdir()
logs=repo/'target/evaluation/clock-limit-probe'/out.relative_to(repo/'ignored')
logs.mkdir(parents=True)
source = Path(__file__).with_name('clock-limit-probe.c')
env = {key: os.environ[key] for key in ('HOME', 'PATH') if key in os.environ}
env.update(LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', TMPDIR=str(out/'tmp'))
os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
spec = importlib.util.spec_from_file_location('proc', repo/'evaluation/admission/processes.py')
proc = importlib.util.module_from_spec(spec); spec.loader.exec_module(proc)
def closed(result):
    assert result['exit_code'] == 0 and result['termination'] is None
    assert result['cleanup_complete'] and result['reaped_descendants'] == 0
def save(name, value):
    with (out/name).open('x') as f: json.dump(value, f, indent=2); f.write('\n')
argv = ['/usr/bin/gcc', '-O3', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(out/'probe')]
compiled = proc.run_command(argv, env, logs/'build.log', 30, 1048576)
save('build.json', dict(argv=argv, result=compiled)); closed(compiled)
(out/'build.log').write_bytes((logs/'build.log').read_bytes())
request = dict(argv=[str(out/'probe')], cpu_seconds=20, wall_seconds=30, file_bytes=1048576,
    cwd=str(repo), env=env, stdout=str(out/'stdout.txt'), stderr=str(out/'stderr.txt'))
save('request.json', request)
argv = [sys.executable, '-B', str(repo/'tools/unwind-oracle/bounded_command.py'),
    '--request', str(out/'request.json'), '--receipt', str(out/'receipt.json')]
result = proc.run_command(argv, env, logs/'parent.log', 55, 1048576)
save('parent.json', dict(argv=argv, result=result)); closed(result)
(out/'parent.log').write_bytes((logs/'parent.log').read_bytes())
receipt = json.loads((out/'receipt.json').read_text())
assert receipt['exit'] == 0 and not receipt['wall_timeout'] and receipt['inputs_unchanged']
assert receipt['absence_proof'] == 'ECHILD'
assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
assert receipt['cleanup_error'] is receipt['aborted'] is None
assert (out/'stderr.txt').read_bytes() == b''
for stream in ('stdout', 'stderr'):
    assert hashlib.sha256((out/(stream+'.txt')).read_bytes()).hexdigest() == receipt[stream+'_sha256']
print((out/'stdout.txt').read_text(), end='')
