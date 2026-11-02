"""Data/custody utilities; process ownership remains in admission/processes.py."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys

M = 1024**2
CEILINGS = (19_994_091_520, 19_061_190_371)
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
BASE_ENV = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')


def write(path, data):
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def save(path, obj):
    write(path, (json.dumps(obj, sort_keys=True, indent=2, allow_nan=False) + '\n').encode())


def pin(path, cap=128*M):
    path = path.resolve(strict=True); before = path.stat()
    stamp = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    assert stat.S_ISREG(before.st_mode) and before.st_size <= cap
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(M), b''): digest.update(block)
    assert stamp(before) == stamp(path.stat())
    return dict(path=str(path), bytes=before.st_size, sha256=digest.hexdigest(), stat=stamp(before))


def payload(path, expected=None, cap=16*M):
    before = pin(path, cap)
    if expected:
        assert all(before[k] == expected[k] for k in ('bytes', 'sha256'))
    data = path.read_bytes(); assert pin(path, cap) == before
    return data


def load(path, expected=None):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result; result[key] = value
        return result
    return json.loads(payload(path, expected), object_pairs_hook=unique)


def clean_owner(owner):
    return owner['cleanup_complete'] is True and owner['reaped_descendants'] == 0


def successful(owner):
    return clean_owner(owner) and owner['exit_code'] == 0 and owner['termination'] is None


def closed(path, digest, status):
    authority = pin(path, 16*M); assert authority['sha256'] == digest
    record = load(path, authority)
    assert record['status'] == status and record['cleanup_complete'] is True
    # Authenticate every durable owner before touching its capture or any product.
    for row in record['results']:
        actual = load(path.parent / (row['name'] + '-owner.json'))
        assert actual == row['owner'] and successful(actual) and row['status'] == 'PASS'
    for row in record['results']:
        assert row['capture']['sha256'] == row['owner']['private_log_sha256']
        payload(path.parent / (row['name'] + '.log'), row['capture'], 8*M)
    assert record['postflight_passed'] is True
    return record, authority


class Run:
    def __init__(self, args, env, phase, reserve):
        self.root = Path.cwd().resolve(); self.args = args; self.env = env; self.reserve = reserve
        self.work = args.work.absolute(); self.logs = self.root / 'target/evaluation/direct-program' / self.work.name
        assert re.fullmatch('[0-9a-f]{40}', args.revision) and len(os.sched_getaffinity(0)) == 1
        assert self.work == self.work.resolve() and self.work.is_relative_to(self.root / 'ignored')
        assert self.work != self.root / 'ignored' and self.work.parent.is_dir()
        assert not self.work.exists() and not self.logs.exists()
        self.cpu = next(iter(os.sched_getaffinity(0))); self.safe = True; self.before = None
        helper = self.root / 'evaluation/admission/processes.py'
        sources = [Path(__file__).resolve(), Path(__file__).with_name('reproduce.py'), Path(__file__).with_name('direct_data.py'), Path(__file__).with_name('native_exec.py')]
        self.frozen = {str(p.resolve()): pin(p) for p in [helper, Path(sys.executable), *sources, *[Path('/usr/bin')/n for n in ('git', 'du', 'prlimit', 'env')]]}
        assert self.frozen[str(helper)]['sha256'] == OWNER_SHA
        for source in sources: assert self.git('ls-files', '--error-unmatch', str(source.relative_to(self.root))).strip()
        self.unchanged()
        spec = importlib.util.spec_from_file_location('direct_owner', helper)
        self.owner = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.owner)
        self.work.mkdir(mode=0o700); self.logs.mkdir(parents=True, mode=0o700); (self.work/'tmp').mkdir()
        self.record = dict(status='FAILED', phase=phase, revision=args.revision, tree=self.git('rev-parse', 'HEAD^{tree}').decode().strip(),
                           cpus=[self.cpu], environment=env, inputs=self.frozen, results=[], load_before=os.getloadavg(),
                           slot_ceilings=CEILINGS, reserve_bytes=reserve, reserve_is_quota=False,
                           complete_code_premise='caller supplied; not proven by catalog', qualification_complete=False,
                           external_cpu_reservation='root-owned; affinity checked, allocator not reimplemented')

    def git(self, *args):
        return subprocess.check_output(['/usr/bin/git', '--no-optional-locks', '-c', 'index.threads=1', '-c', 'core.preloadIndex=false', *args], env=BASE_ENV, timeout=15)

    def unchanged(self):
        assert self.safe, 'incomplete cleanup: no reads or further subprocesses'
        assert self.git('rev-parse', 'HEAD').decode().strip() == self.args.revision
        assert not self.git('status', '--porcelain', '--untracked-files=no')
        assert os.sched_getaffinity(0) == {self.cpu}
        assert all(pin(Path(p)) == q for p, q in self.frozen.items())

    def freeze(self, path, expected=None, cap=128*M):
        q = pin(path, cap)
        if expected: assert (q['bytes'], q['sha256']) == tuple(expected)
        self.frozen[q['path']] = q
        return q

    def scope(self):
        unit = self.args.unit; assert re.fullmatch(r'li2core-direct-cat-[A-Za-z0-9-]+', unit)
        line = Path('/proc/self/cgroup').read_text().strip()
        assert line.startswith('0::/') and '\n' not in line and '..' not in Path(line[3:]).parts
        assert line.endswith('/' + unit + '.scope')
        cg = Path('/sys/fs/cgroup') / line[4:]
        values = {n: (cg/n).read_text().strip() for n in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max', 'cpuset.cpus.effective')}
        assert [values[n] for n in ('memory.max', 'memory.swap.max', 'pids.max', 'cpuset.cpus.effective')] == [str(1024*M), '0', '64', str(self.cpu)]
        quota, period = map(int, values['cpu.max'].split()); assert quota == period and period > 0
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        assert hard == resource.RLIM_INFINITY or hard >= 36*1024*M
        return dict(path=str(cg), properties=values, memory_events=(cg/'memory.events').read_text(), memory_peak=(cg/'memory.peak').read_text())

    def run(self, name, argv, bounds, cwd=None, env=None):
        self.unchanged()
        if self.args.phase == 'functional': self.scope()
        cpu, wall, address, filecap, logcap = bounds
        command = ['/usr/bin/prlimit', '--cpu='+str(cpu), '--as='+str(address), '--fsize='+str(filecap), '--core=0', '--', '/usr/bin/env', '--chdir='+str(cwd or self.root), '--', *map(str, argv)]
        row = dict(name=name, command=command, environment=env or self.env, bounds=dict(cpu=cpu, wall=wall, address_space=address, file_bytes=filecap, log_bytes=logcap), status='DISPATCHED_UNKNOWN')
        self.record['results'].append(row); save(self.work/(name+'-intent.json'), row)
        self.safe = False
        owner = self.owner.run_command(command, env or self.env, self.logs/(name+'.log'), wall, logcap)
        save(self.work/(name+'-owner.json'), owner); row['owner'] = owner
        self.safe = owner['cleanup_complete'] is True
        assert self.safe, 'incomplete cleanup: no payload or follow-up process'
        data = payload(self.logs/(name+'.log'), cap=logcap)
        assert hashlib.sha256(data).hexdigest() == owner['private_log_sha256']
        write(self.work/(name+'.log'), data); row['capture'] = pin(self.work/(name+'.log'), logcap)
        row['status'] = 'PASS' if successful(owner) else 'FAILED'
        self.unchanged()
        if self.args.phase == 'functional': self.scope()
        return row, data

    def capacity(self, tag):
        totals, charge = [], []
        for apparent in (False, True):
            argv = ['/usr/bin/du', '--block-size=1', '--count-links', '--max-depth=1'] + (['--apparent-size'] if apparent else [])
            row, raw = self.run(tag+('-apparent' if apparent else '-allocated'), argv+[str(self.root), str(self.work), str(self.logs)], (30, 180, 256*M, 65536, M))
            assert row['status'] == 'PASS'
            pairs = [line.split('\t') for line in raw.decode().splitlines()]
            assert all(len(p) == 2 and p[0].isdigit() for p in pairs) and len({p[1] for p in pairs}) == len(pairs)
            values = {p: int(n) for n, p in pairs}; totals.append(values[str(self.root)]); charge.append(values[str(self.work)]+values[str(self.logs)])
        self.record[tag+'_capacity'] = dict(slot=totals, namespace=charge)
        assert all(n < cap for n, cap in zip(totals, CEILINGS)) and max(charge) <= self.reserve
        if self.before is None:
            assert all(n+self.reserve < cap for n, cap in zip(totals, CEILINGS)), 'declared reserve unavailable'
            self.before = totals
        else:
            assert all(n-b <= self.reserve for n, b in zip(totals, self.before)), 'declared incremental reserve exceeded'

    def finish(self, passed):
        for row in [*self.record.get('stages', {}).values(), *self.record.get('cases', [])]:
            if row['status'] == 'UNOBSERVED': row.setdefault('reason', 'A required input or earlier global guard did not pass; no fallback or retry')
        if 'cases' in self.record: self.record['observed_cases'] = sum(row['status'] in ('PASS', 'FAILED') for row in self.record['cases'])
        if self.safe and self.before is not None:
            try:
                self.capacity('after'); self.unchanged()
                if self.args.phase == 'functional': self.record['scope_after'] = self.scope()
                self.record['postflight_passed'] = True
            except BaseException as error: self.record['postflight_error'] = type(error).__name__+': '+str(error)
        if passed and self.record.get('postflight_passed') and 'error' not in self.record and 'postflight_error' not in self.record:
            self.record['status'] = 'READY_BUILT_UNEXECUTED' if self.args.phase == 'build' else 'PASS'
        self.record.update(cleanup_complete=self.safe, load_after=os.getloadavg())
        save(self.work/'closed.json', self.record)
        return int(self.record['status'] not in ('READY_BUILT_UNEXECUTED', 'PASS'))
