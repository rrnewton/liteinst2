"""Apply and verify the missing per-worker PID cap before executing a workload.

The installed parallel runner's Python capability table gates off pids.max even
though its CLI accepts --pids. Keep its CPU/memory/time/tree-cleanup containment;
set the cap only in this already delegated seed worker's own cgroup.
"""
import os
from pathlib import Path
import sys

if sys.flags.optimize:
    raise SystemExit('Resource bootstrap requires active Python assertions; refusing optimized mode.')

assert len(sys.argv) >= 4, 'usage: boxed-worker.py PID_LIMIT COMMAND ARG...'
limit = int(sys.argv[1])
assert 4 <= limit <= 128
line = next(line for line in Path('/proc/self/cgroup').read_text().splitlines()
            if line.startswith('0::'))
root = Path('/sys/fs/cgroup').resolve()
group = (root / line[3:].lstrip('/')).resolve()
assert group.is_relative_to(root)
assert group.name.startswith('step-seed.')
assert group.parent.name.startswith('parallel-experiment-')
assert group.parent.name.endswith('.scope')
cap = group / 'pids.max'
previous = cap.read_text().strip()
if previous != 'max':
    limit = min(limit, int(previous))
cap.write_text(str(limit))
assert cap.read_text().strip() == str(limit)
print(f'WORKER_PID_CAP_CONFIRMED={limit}', flush=True)
os.execvp(sys.argv[2], sys.argv[2:])
