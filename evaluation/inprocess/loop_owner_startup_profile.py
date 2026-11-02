#!/usr/bin/env python3
"""One fresh maintained0/0 startup diagnostic; never owner qualification.

Reserve one CPU. Keep the original child limits and launcher, attach passive
cpu-clock:u perf sampling, retain wait4 CPU usage and bounded /proc snapshots.
No candidate reader/model imports, builds, ptrace stops, or active-run reads.
"""
import argparse
import collections
import csv
import io
import platform
import re
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
LAUNCH = 'tools/page-entry/selected/tests/tunables_loop_paired_app/launch.py'
SUBJECT = [30, 512 << 20, 16 << 20, 60]
TOOL = [10, 512 << 20, 16 << 20, 65]
ENV = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fact(path):
    path = Path(path)
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and not path.is_symlink(), 'regular pinned input')
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda: f.read(1 << 20), b''):
            h.update(data)
    after = path.lstat()
    need((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'stable input read')
    return dict(bytes=st.st_size, sha256=h.hexdigest(), mode=stat.S_IMODE(st.st_mode))


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


def source(root, expected):
    common = ['/usr/bin/git', '--no-replace-objects', '-C', str(root), '-c', 'index.threads=1',
              '-c', 'core.preloadIndex=false', '-c', 'core.fsmonitor=false', '-c', 'maintenance.auto=false']
    def read(args):
        p = subprocess.run(common + args, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        need(p.returncode == 0 and not p.stderr, 'system Git preflight')
        return p.stdout
    revision = read(['rev-parse', 'HEAD']).decode().strip()
    need(re.fullmatch('[0-9a-f]{40}', expected) and revision == expected, 'exact requested diagnostic source')
    need(not read(['status', '--porcelain', '--untracked-files=no']), 'clean tracked source')
    return dict(revision=revision, tree=read(['rev-parse', 'HEAD^{tree}']).decode().strip(), tracked_clean=True)


class Child:
    """One process group; retain the unreaped leader until group cleanup."""
    def __init__(self, name, argv, bounds, directory, cpu, commands, children, env=ENV, record=False):
        self.p = None
        self.pidfd = None
        self.paths = {k: directory / (name + '.' + k) for k in ('stdout', 'stderr')}
        self.row = dict(name=name, argv=argv, bounds=bounds, environment=env, exit=None,
                        launched=False, timed_out=False, reaped=False, cleanup_errors=[], error=None,
                        start_ns=time.monotonic_ns())
        commands.append(self.row)
        children.append(self)
        descriptors = []
        try:
            if record:
                self.paths['record'] = directory / (name + '.record')
                fd = os.open(self.paths['record'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                descriptors.append(fd)
                need(fd == 3, 'fresh observer is actual FD3')
                st = os.fstat(fd)
                self.row['observer'] = dict(fd=3, device=st.st_dev, inode=st.st_ino, mode=stat.S_IMODE(st.st_mode))
            def limits():
                os.sched_setaffinity(0, {cpu})
                for kind, value in ((resource.RLIMIT_CPU, bounds[0]), (resource.RLIMIT_AS, bounds[1]),
                                    (resource.RLIMIT_FSIZE, bounds[2]), (resource.RLIMIT_CORE, 0)):
                    resource.setrlimit(kind, (value, value))
            with self.paths['stdout'].open('xb') as out, self.paths['stderr'].open('xb') as err:
                self.p = subprocess.Popen(argv, cwd=directory, env=env, stdout=out, stderr=err,
                    start_new_session=True, pass_fds=tuple(descriptors), preexec_fn=limits)
            self.row.update(pid=self.p.pid, launched=True)
            self.pidfd = os.pidfd_open(self.p.pid)
        except BaseException as exc:
            self.row['error'] = repr(exc)
            self.finish()
            raise
        finally:
            for fd in descriptors:
                os.close(fd)
            self.row['record_descriptor_closed_in_parent'] = not record or all(
                not Path('/proc/self/fd/' + str(fd)).exists() for fd in descriptors)

    def ready(self, seconds=0):
        return self.pidfd is not None and bool(select.select([self.pidfd], [], [], max(0, seconds))[0])

    def finish(self, interrupt=False):
        if self.row['reaped'] or not self.row['launched']:
            return self.row
        try:
            if interrupt and not self.ready():
                os.killpg(self.p.pid, signal.SIGINT)
                self.row['stop_requested'] = 'SIGINT after subject closure for perf flush'
                if not self.ready(3):
                    self.row['interrupt_flush_timed_out'] = True
            elif not interrupt:
                remaining = self.row['bounds'][3] - (time.monotonic_ns() - self.row['start_ns']) / 1e9
                if not self.ready(remaining):
                    self.row['timed_out'] = True
            # Never poll/wait first: the unreaped leader still pins the PGID.
            try:
                os.killpg(self.p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 3
            pid, status, usage = os.wait4(self.p.pid, os.WNOHANG)
            while pid == 0 and time.monotonic() < deadline:
                select.select([], [], [], .02)
                pid, status, usage = os.wait4(self.p.pid, os.WNOHANG)
            need(pid == self.p.pid, 'killed child reaped')
            self.p.returncode = os.waitstatus_to_exitcode(status)
            self.row.update(exit=self.p.returncode, reaped=True, wait_status=status,
                user_cpu_ns=round(usage.ru_utime * 1e9), system_cpu_ns=round(usage.ru_stime * 1e9),
                max_rss_kib=usage.ru_maxrss, minor_faults=usage.ru_minflt, major_faults=usage.ru_majflt,
                voluntary_switches=usage.ru_nvcsw, involuntary_switches=usage.ru_nivcsw)
        except BaseException as exc:
            self.row['cleanup_errors'].append(repr(exc))
        finally:
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None
            self.row['duration_ns'] = time.monotonic_ns() - self.row['start_ns']
            self.row['captures'] = {k: fact(p) for k, p in self.paths.items() if p.is_file()}
        return self.row


def proc_snapshot(pid, start):
    result = dict(time_ns=time.monotonic_ns() - start, pid=pid, coherent_state=False)
    for name in ('stat', 'status', 'syscall', 'maps'):
        try:
            with open('/proc/' + str(pid) + '/' + name, 'rb', buffering=0) as f:
                data = f.read(65537)
            need(len(data) <= 65536, 'bounded process snapshot')
            result[name] = data.decode()
        except OSError as exc:
            result[name + '_error'] = dict(errno=exc.errno, detail=str(exc))
    return result


def perf_counts(path):
    data = path.read_bytes()
    need(104 <= len(data) <= 16 << 20 and data[:8] == b'PERFILE2', 'bounded perf header')
    start, size = struct.unpack_from('<QQ', data, 40)
    need(start >= 104 and start <= len(data) and size <= len(data) - start, 'perf data extent')
    cursor, end, samples, lost = start, start + size, 0, 0
    kinds = {}
    while cursor < end:
        need(cursor + 8 <= end, 'perf record header')
        kind, _, extent = struct.unpack_from('<IHH', data, cursor)
        need(extent >= 8 and cursor + extent <= end and kind != 81, 'perf record extent/compression')
        kinds[str(kind)] = kinds.get(str(kind), 0) + 1
        if kind == 9:
            samples += 1
        elif kind == 2:
            need(extent >= 24, 'perf lost record')
            lost += struct.unpack_from('<Q', data, cursor + 16)[0]
        elif kind == 13:
            need(extent >= 16, 'perf lost samples record')
            lost += struct.unpack_from('<Q', data, cursor + 8)[0]
        cursor += extent
    need(cursor == end and samples > 0, 'actual perf samples')
    return dict(samples=samples, lost=lost, record_types=kinds, data_bytes=size)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def authenticate(root, args, current, output, pins):
    """Authenticate the closed identities used by this one duplicate, not a qualification replay."""
    def pin(path, expected=None):
        p = Path(path)
        value = fact(p)
        if expected is not None:
            need(all(value[k] == expected[k] for k in ('bytes', 'sha256')), 'whole recorded input: ' + str(p))
            need('mode' not in expected or value['mode'] == expected['mode'], 'recorded artifact mode')
        need(str(p) not in pins or pins[str(p)] == value, 'stable diagnostic input')
        pins[str(p)] = value
        return p
    path = args.owner_receipt.absolute()
    need(path.name == 'receipt.json' and path.parent.parent == root/'target/evaluation/inprocess', 'closed owner receipt location')
    pin(path)
    need(re.fullmatch('[0-9a-f]{64}', args.owner_receipt_sha256) and
         pins[str(path)]['sha256'] == args.owner_receipt_sha256, 'explicit whole owner receipt SHA')
    owner = json.loads(path.read_bytes())
    permitted = {'persistent-loop-owner-v1': ('failed', 'observed_focal_unqualified'),
                 'persistent-loop-owner-diagnostic-v1': ('failed', 'observed_loop_owner_diagnostic')}
    need(owner['profile'] in permitted and owner['status'] in permitted[owner['profile']] and
         owner['source_unchanged'] is owner['inputs_unchanged'] is owner['cleanup_complete'] is True and
         owner['final_errors'] == [] and owner['source']['revision'] == owner['revision'] == args.expect_revision and
         owner['source']['tree'] == current['tree'] and owner['source']['tracked_clean'] is True and
         owner['source']['head_sources_match'] is True, 'closed original owner and exact current source')
    need(owner['status'] == 'failed' or owner['error'] is None, 'literal original successful owner status')
    def owned(container, p):
        p = Path(p)
        wanted = container['artifacts'].get(str(p), container['inputs'].get(str(p)))
        need(wanted is not None, 'actual receipt owns diagnostic input: ' + str(p))
        return pin(p, wanted)
    def command(name):
        rows = [c for c in owner['commands'] if c['name'] == name]
        need(len(rows) == 1, 'one original named command')
        c = rows[0]
        need(c['reaped'] is True and c['cleanup_errors'] == [] and c['error'] is None and
             all(d['closed'] is True for d in c['descriptors']), 'original command cleanup')
        p = owned(owner, path.parent/(name+'.json'))
        need(json.loads(p.read_bytes()) == c, 'whole actual original command row')
        for v in c['captures'].values():
            need(Path(v['file']).name == v['file'], 'local original capture')
            p = owned(owner, path.parent/v['file'])
            need(all(pins[str(p)][k] == v[k] for k in ('bytes', 'sha256')), 'whole original command capture')
        return c
    proof = owner['loop_native_prerequisite']
    supplied = owner['prerequisite_inputs']['loop_native']
    native_path = root/proof['file']
    need(native_path.name == 'receipt.json' and native_path.parent.parent == root/'target/evaluation/inprocess' and
         str(native_path) == supplied['path'] and proof['sha256'] == supplied['sha256'] and
         proof['status'] == 'verified_prerequisite' and proof['revision'] == args.expect_revision and
         proof['coverage'] == dict(native_controls=True, native_full_state=True, native_v2_all_cases_and_placements=True),
         'original actual native prerequisite identity and coverage')
    owned(owner, native_path)
    need(all(pins[str(native_path)][k] == proof[k] for k in ('bytes', 'sha256')), 'whole native proof receipt join')
    native = json.loads(native_path.read_bytes())
    need(native['profile'] == 'persistent-loop-native-v2' and native['status'] == 'observed_native_references' and
         native['source'] == owner['source'] and native['cpu'] == owner['cpu'] == proof['cpu'] and
         native['hardware'] == owner['hardware'] and digest(native['hardware']) == proof['hardware_sha256'] and
         digest(native['source']) == proof['source_sha256'] and
         native['source_unchanged'] is native['inputs_unchanged'] is native['cleanup_complete'] is True and
         native['error'] is None and native['final_errors'] == [] and len(native['commands']) == 82 and
         [(c['lane'], c['mode'], c['placement']) for c in native['cases']] == [(0,c,p) for c in range(7) for p in range(4)] and
         all(c['status'] == 'observed_native_reference' and c['exit'] == c['expected_exit'] == 0 and
             c['timed_out'] is False for c in native['cases']), 'closed native source/population; no new native qualification')
    old = command('subject-maintained-0-0')
    need(old['bounds'] == SUBJECT and old['capture_limit'] == 16 << 20 and old['environment'] == ENV and
         old['expected_exit'] == 0 and type(old['exit']) is int and type(old['timed_out']) is bool and
         set(old['captures']) == {'stdout', 'stderr', 'record'}, 'original fixed0/0 outcome and unchanged bounds')
    cases = [c for c in owner['cases'] if c['label'] == old['name']]
    need(len(cases) == 1 and cases[0]['launched'] is True and cases[0]['exit'] == old['exit'] and
         cases[0]['timed_out'] == old['timed_out'] and cases[0]['whole_process_ns'] == old['duration_ns'],
         'original case row literal outcome')
    lane = owner['lanes']['maintained']
    need(lane['release_build']['status'] == 'passed', 'closed maintained build')
    original = Path(lane['namespace_plan']['original'])
    interpreter = Path(lane['namespace_plan']['interpreter'])
    carrier_row = command('maintained-carrier')
    link_row = command('maintained-persistent-group-release-link')
    need(carrier_row['exit'] == link_row['exit'] == 0 and not carrier_row['timed_out'] and
         not link_row['timed_out'] and link_row['argv'] == lane['release_build']['argv'] and
         link_row['argv'][-2] == '-o', 'actual successful retained build and carrier commands')
    bridge = Path(link_row['argv'][-1])
    carrier = Path(carrier_row['argv'][-1])
    need(carrier_row['argv'][1:] == ['-B', str(root/'tools/page-entry/carrier.py'), 'make',
         str(original), str(bridge), str(carrier)], 'actual carrier consumes exact original and bridge')
    for label, p in (('original',original), ('interpreter',interpreter), ('bridge',bridge), ('carrier',carrier)):
        owned(owner, p)
        need(all(pins[str(p)][k] == lane['subject_artifacts'][label][k] for k in ('bytes','sha256')),
             'whole subject artifact authority')
    for p in (original, interpreter):
        owned(native, p)
    for rel in (LAUNCH, 'evaluation/inprocess/page_selected_process.py', 'tools/page-entry/carrier.py', 'tools/page-entry/namespace.py'):
        owned(owner, root/rel)
    binding = lane['release_build']['persistent_binding']['manifest']
    owned(owner, binding['path'])
    need(all(pins[binding['path']][k] == binding[k] for k in ('bytes','sha256')), 'actual build binding identity')
    original_directory = path.parent/'subject-maintained-0-0'
    prep = original_directory/'preparation.json'
    for v in lane['runtime_libraries'].values():
        owned(owner, v['path'])
        need(all(pins[v['path']][k] == v[k] for k in ('bytes','sha256')), 'actual sealed runtime library')
    python = Path(old['argv'][0])
    owned(owner, python.resolve(strict=True))
    roots = lane['namespace_plan']['roots']
    expected_argv = [str(python), '-B', str(root/LAUNCH), '--root', str(root), '--role', 'gated',
        '--case', '0', '--placement', '0', '--control', '0', '--original', str(original),
        '--preparation', str(prep)]
    for directory in roots:
        expected_argv += ['--library-root', directory]
    expected_argv += ['--carrier', str(carrier), '--namespace', str(original_directory/'namespace'), '--record-fd', '3']
    need(old['argv'] == expected_argv, 'whole original subject argv, no extra or hidden argument')
    argv = list(old['argv'])
    argv[argv.index('--preparation')+1] = str(output/'preparation.json')
    argv[argv.index('--namespace')+1] = str(output/'namespace')
    # Failed subjects may stop before the collector registers preparation
    # files. Do not treat those unreceipted files as historical authorities.
    # The exact pinned launcher plus these closed lane facts define the fresh
    # namespace contract. This fixed freestanding fixture has no dependencies.
    need(set(lane['runtime_libraries']) == {interpreter.name} and
         lane['runtime_libraries'][interpreter.name]['path'] == str(interpreter), 'exact freestanding fixture namespace')
    launch_contract = dict(schema_version=1, scope='first_entry_loader_candidate', status='prepared_not_executed',
        carrier_sha256=lane['subject_artifacts']['carrier']['sha256'],
        carrier_size=lane['subject_artifacts']['carrier']['bytes'], argv=[str(original),'1','0','0'], dependency_fds=[],
        environment=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC',
            LD_LIBRARY_PATH=str(output/'namespace'), LD_BIND_NOW='1', LI2_DEPENDENCY_FDS='',
            LI2_PERSISTENT_LOOP_APP_CASE='0', LI2_PERSISTENT_LOOP_APP_PLACEMENT='0', LI2_PERSISTENT_LOOP_APP_LANE='1',
            GLIBC_TUNABLES='glibc.pthread.rseq=0'))
    namespace_contract = dict(schema_version=1, scope='explicit_sealed_dependency_namespace', status='prepared_not_executed',
        identity_policy='sealed copies and private paths; not filesystem transparency',
        search_policy='explicit roots; no RPATH/RUNPATH/cache emulation', directory=str(output/'namespace'),
        original=str(original), original_sha256=lane['subject_artifacts']['original']['sha256'],
        interpreter=str(interpreter), interpreter_sha256=lane['subject_artifacts']['interpreter']['sha256'], roots=roots, objects=[])
    for p in (Path(__file__).resolve(), Path('/usr/bin/perf').resolve(), Path('/usr/bin/git').resolve(), Path(sys.executable).resolve()):
        pin(p)
    return dict(old=old, argv=argv, native=native, launch_contract=launch_contract, namespace_contract=namespace_contract,
        tools=dict(subject_python=dict(name=python.name, **pins[str(python.resolve(strict=True))]),
                   perf=dict(name='perf', **pins[str(Path('/usr/bin/perf').resolve())])),
        old_path=str(path.parent/'subject-maintained-0-0.json'), modules={str(p):label for p,label in
            ((bridge,'bridge'), (original,'application'), (interpreter,'interpreter'), (carrier,'carrier'))},
        origin=dict(owner_receipt=dict(path=str(path), **pins[str(path)]), owner_profile=owner['profile'],
            owner_status=owner['status'], owner_error=owner['error'], native_receipt=dict(path=str(native_path), **pins[str(native_path)]),
            reauthenticated_scope='Closed metadata and exact duplicate launch/build assets; no full reader/control replay.'))


def hardware(cpu):
    rows = [dict((k.strip(),v.strip()) for line in block.splitlines() for k,sep,v in [line.partition(':')] if sep)
            for block in Path('/proc/cpuinfo').read_text().split('\n\n')]
    row = next(x for x in rows if x.get('processor') == str(cpu))
    release = platform.release()
    return {k:row.get(k) for k in ('vendor_id','model name','cpu family','model','stepping','microcode')} | dict(
        cpu=cpu, architecture=platform.machine(), kernel_version=re.match(r'[0-9.]+',release)[0],
        kernel_release_sha256=hashlib.sha256(release.encode()).hexdigest(),
        isa_flags_sha256=digest(row.get('flags','').split()))


def functions(path, pid, expected, modules):
    counts = collections.Counter()
    for line in path.read_text().splitlines():
        m = re.fullmatch(r'\s*(\d+)/(\d+)\s+([0-9.]+):\s+([0-9a-fA-F]+)\s+(.+?)\s+\((.*)\)\s*', line)
        need(m is not None and int(m[1]) == int(m[2]) == pid, 'all rendered samples belong to actual child')
        symbol, dso = m[5], m[6]
        if not re.fullmatch(r'[A-Za-z0-9_.$@+:\[\]-]{1,160}', symbol):
            symbol = 'unresolved-symbol-' + hashlib.sha256(symbol.encode()).hexdigest()[:16]
        module = modules.get(dso, 'unresolved-module-' + hashlib.sha256(dso.encode()).hexdigest()[:16])
        counts[module,symbol] += 1
    need(sum(counts.values()) == expected, 'all rendered samples join complete perf sample count')
    return [dict(module=m, function=f, samples=n, percent=100*n/expected)
            for (m,f),n in sorted(counts.items(), key=lambda item:(-item[1],item[0]))]


def publish(output, root, result, args):
    """Bounded public projection only; no raw IPs, paths, maps or host names."""
    subject = next((c for c in result['commands'] if c['name'] == 'subject'), {})
    def portable(argv):
        answer = []
        for i, arg in enumerate(argv):
            if i == 0:
                answer.append('$PYTHON')
            elif arg == str(root) or arg.startswith(str(root) + '/'):
                answer.append('$ROOT' + arg[len(str(root)):])
            elif os.path.isabs(arg):
                answer.append('$EXTERNAL_' + hashlib.sha256(arg.encode()).hexdigest()[:16])
            else:
                answer.append(arg)
        return answer
    rows = result.get('functions', [])
    top = rows[:20]
    out = io.StringIO(newline='')
    writer = csv.writer(out, lineterminator='\n')
    writer.writerow(['module','function','samples','percent'])
    for row in top:
        writer.writerow([row['module'],row['function'],row['samples'],format(row['percent'],'.6f')])
    if len(rows) > 20:
        n = sum(row['samples'] for row in rows[20:])
        writer.writerow(['other','all_remaining_functions',n,format(100*n/result['perf']['samples'],'.6f')])
    csv_bytes = out.getvalue().encode()
    origin = result.get('origin', {})
    public = dict(schema=1, profile=result['profile'], status=result['status'], diagnostic_only=True,
        qualification_credit=False, performance_credit=False, owner_subject_credit=False,
        historical_failures_reclassified=False, source=result['source'], cpu=result['cpu'],
        hardware=result.get('sampling_hardware'), tools=result.get('tools'), script=result.get('script'),
        private_receipt=fact(output/'receipt.json'),
        original_owner={k:origin.get(k) for k in ('owner_profile','owner_status')},
        owner_receipt={k:v for k,v in origin.get('owner_receipt',{}).items() if k!='path'},
        native_receipt={k:v for k,v in origin.get('native_receipt',{}).items() if k!='path'},
        original_subject={k:result.get('original_command',{}).get(k) for k in ('exit','timed_out','duration_ns','captures')},
        sampled_subject={k:subject.get(k) for k in ('expected_exit','exit','timed_out','duration_ns','user_cpu_ns',
            'system_cpu_ns','max_rss_kib','reaped','captures')},
        subject_argv=portable(subject.get('argv', [])), subject_environment=subject.get('environment'),
        subject_argv_sha256=digest(subject.get('argv', [])),
        argv_encoding='ROOT substitutes the exact checkout prefix; PYTHON is the pinned executable. Each EXTERNAL_<16 hex> substitutes one complete absolute token whose UTF-8 SHA256 has that prefix; recover its exact value from the original owner command. Actual child argv is unchanged.',
        subject_bounds=result['subject_bounds'], perf_bounds=result['perf_bounds'], requested_hz=99, event='cpu-clock:u',
        perf=result.get('perf'), top_functions=top, remaining_function_samples=sum(x['samples'] for x in rows[20:]),
        cleanup_complete=result['cleanup_complete'], inputs_unchanged=result['inputs_unchanged'],
        source_unchanged=result['source_unchanged'], error_types=[e['type'] for e in result['errors']],
        final_error_count=len(result['final_errors']), limitations=[result['observation'],result['wait4_note'],
            'One diagnostic child; no full qualification, performance comparison or replay of original reader controls.',
            'The original fixed sampler measurement remains a separate receipt; this script records only its own execution.'],
        reproduce=dict(argv=['$PYTHON','-B','$COPIED_DRIVER','--expect-revision',args.expect_revision,
            '--owner-receipt',str(args.owner_receipt.absolute()).replace(str(root),'$ROOT'),
            '--owner-receipt-sha256',args.owner_receipt_sha256,
            '--output','$ROOT/target/evaluation/inprocess/loop-owner-startup-profile-fresh'],
            notes='Reserve one CPU. ROOT is the clean checkout at the exact receipt revision; PYTHON is the original pinned Python executable. Copy this exact script outside the checkout when profiling an older revision. Use a fresh absolute output. Outer bounds:150s wall,60s CPU,512MiB AS,16MiB file.'),
        csv=dict(bytes=len(csv_bytes),sha256=hashlib.sha256(csv_bytes).hexdigest()))
    encoded = (json.dumps(public,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    need(len(encoded)+len(csv_bytes) <= 16 << 10 and not any(x in encoded for x in
         (b'/home/',b'facebook.com',b'git.vip',b'devbig',b'://')), 'compact public privacy and size')
    with (output/'summary.csv').open('xb') as f:
        f.write(csv_bytes)
    with (output/'summary.json').open('xb') as f:
        f.write(encoded)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--owner-receipt', type=Path, required=True)
    ap.add_argument('--owner-receipt-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    root = Path.cwd().resolve(strict=True)
    cpus = sorted(os.sched_getaffinity(0))
    need(not sys.flags.optimize and len(cpus) == 1, 'one reserved CPU and assertions enabled')
    cpu = cpus[0]
    output = args.output.absolute()
    need(output.parent == root / 'target/evaluation/inprocess' and not output.exists(), 'fresh direct private output')
    current = source(root, args.expect_revision)
    output.mkdir(mode=0o700)
    commands, children, pins = [], [], {}
    def interrupted(number, frame):
        raise InterruptedError('diagnostic parent signal ' + str(number))
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    result = dict(schema=1, profile='loop-owner-startup-perf-diagnostic-v1', status='failed',
        diagnostic_only=True, qualification_credit=False, performance_credit=False,
        historical_failures_reclassified=False, owner_subject_credit=False, subject_count=1,
        source=current, cpu=cpu, commands=commands, snapshots=[], errors=[], final_errors=[],
        subject_bounds=SUBJECT, perf_bounds=TOOL, requested_hz=99, event='cpu-clock:u',
        observation='Passive perf and noncoherent proc observations; sampling perturbs timing.',
        wait4_note='Observed CPU usage and signal only; no kernel kill-cause attribution.')
    try:
        context = authenticate(root, args, current, output, pins)
        old, argv, native = (context[k] for k in ('old', 'argv', 'native'))
        result['origin'] = context['origin']
        result['tools'] = context['tools']
        result['original_command'] = dict(path=context['old_path'], fact=pins[context['old_path']],
            exit=old['exit'], timed_out=old['timed_out'], duration_ns=old['duration_ns'],
            captures=old['captures'], reaped=old['reaped'])
        result['original_hardware'] = native['hardware']
        result['original_subject_cpu'] = native['cpu']
        result['sampling_hardware'] = hardware(cpu)
        result['script'] = fact(Path(__file__).resolve())
        result['script_path'] = str(Path(__file__).resolve())
        result['script_identity_separate_from_sampled_revision'] = True
        result['script_revision_note'] = 'Script identity is independent of the sampled checkout; it may be copied outside an older clean checkout.'
        private_env = dict(ENV, PERF_CONFIG_NOSYSTEM='1', PERF_CONFIG_NOGLOBAL='1', DEBUGINFOD_URLS='')
        for key, name in (('PERF_BUILDID_DIR', 'buildids'), ('XDG_CACHE_HOME', 'cache'), ('TMPDIR', 'tmp')):
            (output / name).mkdir()
            private_env[key] = str(output / name)
        subject = Child('subject', argv, SUBJECT, output, cpu, commands, children, record=True)
        subject.row['expected_exit'] = 0
        # Attach to our own exact child, never an original-run PID. No ptrace or
        # signal interception. Any attach failure is retained and is not a pass.
        early_exit = subject.ready(.1)
        result['actual_attach_delay_ns'] = time.monotonic_ns() - subject.row['start_ns']
        need(not early_exit, 'subject exited before perf attach')
        perf_argv = ['/usr/bin/perf', 'record', '--no-buildid', '--no-buildid-cache',
            '-e', 'cpu-clock:u', '-F', '99', '-m', '16', '-o', str(output / 'perf.data'), '-p', str(subject.p.pid)]
        profiler = Child('perf', perf_argv, TOOL, output, cpu, commands, children, private_env)
        due = subject.row['start_ns'] + 1_000_000_000
        while not subject.ready():
            remaining = SUBJECT[3] - (time.monotonic_ns() - subject.row['start_ns']) / 1e9
            if remaining <= 0:
                break
            if subject.ready(min(remaining, max(0, (due-time.monotonic_ns())/1e9))):
                break
            result['snapshots'].append(proc_snapshot(subject.p.pid, subject.row['start_ns']))
            need(len(result['snapshots']) <= 60 and len(json.dumps(result['snapshots'])) <= 4 << 20,
                 'bounded snapshot population and output')
            due += 1_000_000_000
        subject.finish()
        profiler.finish(interrupt=True)
        need(subject.row['reaped'] and not subject.row['cleanup_errors'] and subject.row['error'] is None,
             'fresh subject cleanup')
        prep_path = output / 'preparation.json'
        prep = json.loads(prep_path.read_bytes())
        obs = subject.row['observer']
        need((prep['role'], prep['lane'], prep['case'], prep['placement'], prep['control'], prep['pid'],
              prep['cpu'], prep['reset_mask'], prep['launch_mask'], prep['default_rseq']) ==
             ('gated', 1, 0, 0, 0, subject.p.pid, [cpu], 0, 0, False) and
             prep['observer'] == {k:obs[k] for k in ('fd', 'device', 'inode')} and
             [v['signal'] for v in prep['dispositions']] == [i for i in range(1,65) if i not in (9,19)] and
             all(v['after'] == 0 for v in prep['dispositions']), 'actual new preparation')
        result['preparation'] = {str(p.relative_to(output)): fact(p) for p in
            (prep_path, output/'namespace/namespace.json', output/'namespace/launch.json')}
        launch = json.loads((output/'namespace/launch.json').read_bytes())
        namespace = json.loads((output/'namespace/namespace.json').read_bytes())
        need(launch == context['launch_contract'] and namespace == context['namespace_contract'],
             'whole actual fresh namespace and environment match pinned launcher plus closed lane identities')
        need(profiler.row['reaped'] and not profiler.row['cleanup_errors'] and profiler.row['error'] is None and
             profiler.row['exit'] in (0, -signal.SIGINT) and not profiler.row.get('interrupt_flush_timed_out'),
             'perf attach and flush succeeded')
        result['perf'] = perf_counts(output / 'perf.data')
        result['perf']['file'] = fact(output/'perf.data')
        # Bounded postmortem rendering only, with no call-chain claims. Raw
        # addresses/maps are retained privately when symbols cannot resolve.
        render = Child('perf-script', ['/usr/bin/perf', 'script', '-i', str(output/'perf.data'),
            '-F', 'time,pid,tid,ip,sym,dso'], [10,512<<20,16<<20,20], output, cpu, commands, children, private_env)
        render.finish()
        need(render.row['exit'] == 0 and render.row['reaped'] and not render.row['timed_out'] and
             not render.row['cleanup_errors'], 'bounded perf rendering')
        result['functions'] = functions(output/'perf-script.stdout', subject.p.pid, result['perf']['samples'], context['modules'])
        result['status'] = 'observed_startup_diagnostic'
    except BaseException as exc:
        result['errors'].append(dict(type=type(exc).__name__, detail=str(exc)))
    finally:
        for child in reversed(children):
            child.finish(interrupt=child.row['name'] == 'perf')
        after = {}
        for name in pins:
            try:
                after[name] = fact(name)
            except BaseException as exc:
                result['final_errors'].append(repr(exc))
        result['inputs_before'], result['inputs_after'] = pins, after
        result['inputs_unchanged'] = pins == after
        result['cleanup_complete'] = all((not c.row['launched'] or c.row['reaped']) and
                                        not c.row['cleanup_errors'] for c in children)
        try:
            result['source_after'] = source(root, args.expect_revision)
        except BaseException as exc:
            result['source_after'] = None
            result['final_errors'].append(repr(exc))
        result['source_unchanged'] = result['source_after'] == current
        if not result['inputs_unchanged'] or not result['cleanup_complete'] or not result['source_unchanged']:
            result['final_errors'].append('diagnostic closure failed')
        if result['errors'] or result['final_errors']:
            result['status'] = 'failed'
        save(output/'receipt.json', result)
        print(json.dumps(dict(status=result['status'], receipt=str(output/'receipt.json'),
                              errors=result['errors'], final_errors=result['final_errors']), sort_keys=True))
    try:
        publish(output, root, result, args)
    except BaseException as exc:
        print(json.dumps(dict(public_projection_error=repr(exc), receipt=str(output/'receipt.json')), sort_keys=True))
        return 1
    return 0 if result['status'] == 'observed_startup_diagnostic' else 1


if __name__ == '__main__':
    raise SystemExit(main())
