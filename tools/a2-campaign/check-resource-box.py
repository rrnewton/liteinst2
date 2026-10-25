"""Read the effective ancestor resource limits inside a runner worker."""
import json
from pathlib import Path
import sys

if sys.flags.optimize:
    raise SystemExit('Resource verification requires active Python assertions; refusing optimized mode.')

line = next(line for line in Path('/proc/self/cgroup').read_text().splitlines()
            if line.startswith('0::'))
root = Path('/sys/fs/cgroup')
group = root / line[3:].lstrip('/')
rows = []
while True:
    row = {'group': str(group)}
    for name in ['cpu.max', 'memory.max', 'pids.max']:
        path = group / name
        row[name] = path.read_text().strip() if path.exists() else None
    rows.append(row)
    if group == root:
        break
    group = group.parent
assert any(row['pids.max'] not in (None, 'max') and int(row['pids.max']) <= 32
           for row in rows), rows
assert any(row['memory.max'] not in (None, 'max') and int(row['memory.max']) <= 256 * 1024 * 1024
           for row in rows), rows
assert any(row['cpu.max'] is not None and row['cpu.max'].split()[0] != 'max'
           and int(row['cpu.max'].split()[0]) <= int(row['cpu.max'].split()[1])
           for row in rows), rows
print(json.dumps(rows, indent=2))
print('RESOURCE_BOX_CONFIRMED')
