"""Separate diagnostic owner; no baseline timing or qualification credit."""
import ctypes, errno, hashlib, json, os, resource, select, signal, subprocess, sys, time
from pathlib import Path

TARGET = (30, 512 << 20, 16 << 20, 60)
PERF = (30, 1 << 30, 128 << 20, 80)
LIMITS = (resource.RLIMIT_CPU, resource.RLIMIT_AS, resource.RLIMIT_FSIZE)


def need(ok, why):
    if not ok: raise ValueError(why)


def identity(path):
    p = Path(path); b = p.read_bytes(); s = p.stat()
    return dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest(), mode=s.st_mode,
                device=s.st_dev, inode=s.st_ino)


def child(config, ready, release):
    c = json.loads(Path(config).read_bytes()); s = os.fstat(1)
    need(dict(os.environ) == c['environment'], 'exact target environment before exec')
    need(sorted(os.sched_getaffinity(0)) == [c['cpu']], 'exact target CPU')
    need([list(resource.getrlimit(k)) for k in LIMITS] == [[n, n] for n in TARGET[:3]],
         'unchanged target CPU/address/file limits')
    need(resource.getrlimit(resource.RLIMIT_CORE) == (0, 0), 'zero target core limit')
    observed = dict(pid=os.getpid(), parent=os.getppid(), group=os.getpgrp(),
        stdout=[s.st_dev, s.st_ino, s.st_mode], argv=c['argv'], environment=dict(os.environ),
        cpu=sorted(os.sched_getaffinity(0)), ready_ns=time.monotonic_ns())
    data = json.dumps(observed, sort_keys=True).encode()+b'\n'
    need(len(data) < 65536 and os.write(ready, data) == len(data), 'complete ready identity')
    os.close(ready)
    need(os.read(release, 1) == b'G' and os.read(release, 1) == b'', 'one explicit exec release')
    os.close(release)
    # Reproduce Popen restore_signals after the Python wrapper's own startup.
    for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
        if hasattr(signal, name): signal.signal(getattr(signal, name), signal.SIG_DFL)
    os.execve(c['argv'][0], c['argv'], c['environment'])


def profile(row, directory, cpu, bridge, bridge_fact, *, perf='/usr/bin/perf'):
    """One fresh exact launch. Caller still validates source/namespace/terminal reports."""
    import page_default_ls_release_provenance as provenance
    observe, same = provenance.observe, provenance.same
    from page_cost_profile_read import summarize
    directory = Path(directory).resolve(); directory.mkdir(exist_ok=False)
    python = str(Path(sys.executable).resolve()); perf = str(Path(perf).resolve()); bridge = Path(bridge).resolve()
    need(tuple(row['bounds']) == TARGET and row['capture_limit'] == 16 << 20,
         'original target limits/capture bound')
    need(row['argv'] and all(type(x) is str for x in row['argv']) and
         Path(row['argv'][0]).is_absolute() and type(row['environment']) is dict,
         'exact already-bound argv and environment; fresh namespace supplied by caller')
    def child_state():
        try: return os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError as exc:
            need(exc.errno == errno.ECHILD, 'exact no-child result')
            return False
    need(os.readlink('/proc/self') == str(os.getpid()), 'same numeric proc/process PID namespace')
    need(len(list(Path('/proc/self/task').iterdir())) == 1 and child_state() is False,
         'standalone single-thread owner with exact ECHILD/no children')
    libc = ctypes.CDLL(None, use_errno=True); old = ctypes.c_int()
    need(libc.prctl(37, ctypes.byref(old), 0, 0, 0) == 0 and old.value == 0, 'standalone prior subreaper state')
    procs = {}; pidfds = {}; fds = set(); streams = {}; error = None
    before = {str(Path(p).resolve()): identity(p) for p in
              (perf, python, __file__, Path(__file__).with_name('page_cost_profile_read.py'), provenance.__file__, bridge)}
    need(all(before[str(Path(bridge).resolve())][k] == bridge_fact[k] for k in ('bytes', 'sha256')),
         'independently supplied actual bridge fact')
    result = dict(format='page-cost-profile-v1', benchmark_credit=False, qualification=False,
        target=row, perf=dict(bounds=list(PERF)), inputs_before=before, cleanup_errors=[],
        adopted=[], children_before='ECHILD', children_after=None, target_bounds=list(TARGET), cpu=cpu, owner_pid=os.getpid())
    row.update(pid=None, exit=None, reaped=False, timed_out=False, error=None, cleanup_errors=[])

    def pipe():
        a, b = os.pipe2(os.O_CLOEXEC); fds.update((a, b)); return a, b
    def close(fd):
        fds.remove(fd); os.close(fd)
    def prepare(bounds):
        os.sched_setaffinity(0, {cpu})
        for k, n in zip(LIMITS, bounds[:3]): resource.setrlimit(k, (n, n))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if row.get('nproc') is not None: resource.setrlimit(resource.RLIMIT_NPROC, (row['nproc'],)*2)
    def spawn(name, argv, env, passed, bounds):
        streams[name] = tuple((directory/(name+'.'+k)).open('xb') for k in ('stdout', 'stderr'))
        p = subprocess.Popen(argv, cwd=row['cwd'], env=env, stdin=subprocess.DEVNULL,
            stdout=streams[name][0], stderr=streams[name][1], pass_fds=passed,
            start_new_session=True, preexec_fn=lambda: prepare(bounds))
        procs[name] = p; result[name]['pid'] = p.pid; pidfds[name] = os.pidfd_open(p.pid); return p
    def captures():
        observed = {}
        for p in directory.iterdir():
            if p.is_file() and p.name != 'owner.json':
                try: observed[p.name] = identity(p)
                except BaseException as exc: result['cleanup_errors'].append('capture '+p.name+': '+repr(exc))
        return observed
    def group(name):
        try: os.killpg(procs[name].pid, signal.SIGKILL)
        except ProcessLookupError: pass
    def line(fd, deadline):
        data = b''
        while not data.endswith(b'\n'):
            left = deadline-time.monotonic(); need(left > 0, 'readiness/control deadline')
            ready = select.select([fd, *pidfds.values()], [], [], left)[0]
            need(fd in ready, 'child exited before readiness/control acknowledgement')
            part = os.read(fd, 4096); need(part and len(data)+len(part) <= 65536, 'bounded complete control line')
            data += part
        return data
    try:
        need(libc.prctl(36, 1, 0, 0, 0) == 0, 'exclusive subreaper ownership')
        config = directory/'launch.json'
        config.write_text(json.dumps(dict(argv=row['argv'], environment=row['environment'], cpu=cpu), sort_keys=True)+'\n')
        rr, rw = pipe(); gr, gw = pipe(); cr, cw = pipe(); ar, aw = pipe()
        # Parent owns the exact normal-open stdout descriptor consumed by the old reader.
        streams['target'] = tuple((directory/('target.'+k)).open('xb') for k in ('stdout', 'stderr'))
        row['stdout_provenance_before'] = observe(streams['target'][0].fileno())
        row['process_start_ns'] = time.monotonic_ns(); start = row['process_start_ns']/1e9
        result['wrapper_argv'] = [python, '-I', str(Path(__file__).resolve()), '--child', str(config), str(rw), str(gr)]
        target = subprocess.Popen(result['wrapper_argv'], cwd=row['cwd'], env=row['environment'],
            stdout=streams['target'][0], stderr=streams['target'][1],
            pass_fds=(rw, gr), start_new_session=True, preexec_fn=lambda: prepare(TARGET))
        procs['target'] = target; pidfds['target'] = os.pidfd_open(target.pid); row['pid'] = target.pid
        close(rw); close(gr)
        ready_bytes = line(rr, start+8); close(rr); ready = json.loads(ready_bytes)
        (directory/'ready.json').write_bytes(ready_bytes); result['ready'] = ready
        pre = row['stdout_provenance_before']['identity']
        need(ready['pid'] == ready['group'] == target.pid and ready['parent'] == os.getpid() and
             ready['stdout'] == [pre[0], pre[1], pre[5]] and ready['argv'] == row['argv'] and
             ready['environment'] == row['environment'] and ready['cpu'] == [cpu], 'actual same-PID/stdout launch identity')
        perf_argv = [str(perf), 'record', '-e', 'cpu-clock', '-F', '99', '--strict-freq',
            '--mmap-pages=256', '--timestamp', '--sample-cpu', '--period', '--clockid=mono',
            '--delay=-1', '--control=fd:'+str(cr)+','+str(aw), '--pid', str(target.pid),
            '--output', str((directory/'perf.data').resolve())]
        env = dict(row['environment'], PERF_CONFIG='/dev/null')
        result['perf'].update(argv=perf_argv, environment=env, start_ns=time.monotonic_ns())
        profiler = spawn('perf', perf_argv, env, (cr, aw), PERF); close(cr); close(aw)
        need(os.write(cw, b'enable\n') == 7, 'complete enable command'); need(line(ar, start+8) == b'ack\n', 'exact perf enable acknowledgement')
        result['enabled_ns'] = time.monotonic_ns()
        result['release_ns'] = time.monotonic_ns(); need(os.write(gw, b'G') == 1, 'one release'); close(gw)
        remaining = start+TARGET[3]-time.monotonic()
        need(remaining > 0, 'unchanged wall bound includes attach preparation')
        done = select.select(list(pidfds.values()), [], [], remaining)[0]
        row['timed_out'] = not done
        need(pidfds['target'] in done, 'target wall bound or profiler stopped before target exit')
        result['target_exit_ready_ns'] = time.monotonic_ns()
        # Hold unreaped PID identities through group cleanup and perf's final drain.
        group('target'); row['exit'] = target.wait(timeout=3); row['reaped'] = True
        row['process_reaped_ns'] = time.monotonic_ns()
        if not select.select([pidfds['perf']], [], [], 0)[0]: os.kill(profiler.pid, signal.SIGINT)
        need(select.select([pidfds['perf']], [], [], min(10, PERF[3]-(time.monotonic_ns()-result['perf']['start_ns'])/1e9))[0],
             'bounded perf final drain')
        group('perf'); result['perf']['exit'] = profiler.wait(timeout=3)
        need(result['perf']['exit'] == 0, 'actual profiler success; never substitute target status')
    except BaseException as exc:
        error = type(exc).__name__+': '+str(exc); row['error'] = error
    finally:
        for name, proc in procs.items():
            if proc.returncode is None:
                try: group(name); status = proc.wait(timeout=3)
                except BaseException as exc: result['cleanup_errors'].append(name+': '+repr(exc)); continue
            else: status = proc.returncode
            if name == 'target':
                row.update(exit=status, reaped=True); row.setdefault('process_reaped_ns', time.monotonic_ns())
            else: result['perf'].update(exit=status, reaped=True, reaped_ns=time.monotonic_ns())
        end = time.monotonic()+3
        try:
            while True:
                state = child_state()
                if state is False:
                    result['children_after'] = 'ECHILD'; break
                need(time.monotonic() < end, 'adopted-child cleanup deadline')
                if state is not None:
                    got, status = os.waitpid(state.si_pid, os.WNOHANG)
                    need(got == state.si_pid, 'reap the actual observed zombie without signaling')
                    result['adopted'].append([got, status]); continue
                if error is None and not result['cleanup_errors']:
                    result['cleanup_errors'].append('unexpected running adopted descendant')
                # Failure cleanup only: one proc level, then each candidate's direct status.
                with os.scandir('/proc') as entries:
                    for entry in entries:
                        if time.monotonic() >= end: break
                        if not entry.name.isdecimal(): continue
                        try:
                            fields = dict(x.split(':', 1) for x in (Path(entry.path)/'status').read_text().splitlines() if ':' in x)
                            if int(fields['PPid']) != os.getpid(): continue
                            fd = os.pidfd_open(int(entry.name))
                            try:
                                observed = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                                if observed is None: signal.pidfd_send_signal(fd, signal.SIGKILL)
                            finally: os.close(fd)
                        except (FileNotFoundError, ProcessLookupError, ChildProcessError, PermissionError): continue
                time.sleep(.01)
        except BaseException as exc: result['cleanup_errors'].append('adopted cleanup: '+repr(exc))
        for fd in list(fds)+list(pidfds.values()):
            try: os.close(fd)
            except OSError as exc: result['cleanup_errors'].append('fd close: '+repr(exc))
        try:
            row['stdout_provenance_after'] = observe(streams['target'][0].fileno())
            same(row['stdout_provenance_before'], row['stdout_provenance_after'])
        except BaseException as exc: result['cleanup_errors'].append('stdout identity: '+repr(exc))
        for pair in streams.values():
            for stream in pair: stream.close()
        if libc.prctl(36, 0, 0, 0, 0) != 0: result['cleanup_errors'].append('subreaper restore')
        result['inputs_after'] = {}
        for p in before:
            try: result['inputs_after'][p] = identity(p)
            except BaseException as exc: result['cleanup_errors'].append('input '+p+': '+repr(exc))
        if before != result['inputs_after']: result['cleanup_errors'].append('source/tool/bridge changed')
        result['captures'] = captures()
        if any(result['captures'].get(n+'.'+k, {}).get('bytes', 0) > TARGET[2] for n in ('target', 'perf') for k in ('stdout', 'stderr')):
            result['cleanup_errors'].append('ordinary capture bound')
        if 'process_reaped_ns' in row:
            row['process_ns'] = row['process_reaped_ns']-row['process_start_ns']
            if not 0 < row['process_ns'] <= TARGET[3]*1_000_000_000: result['cleanup_errors'].append('full target process wall bound')
        result['error'] = error; result['closed'] = all(p.returncode is not None for p in procs.values()) and not result['cleanup_errors']
        (directory/'owner.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    need(result['closed'] and error is None, 'profile ownership/protocol failed; retained owner.json')
    try:
        result['sampling'] = summarize(directory/'perf.data', Path(bridge), row['pid'], cpu, directory,
                                       result['release_ns'], result['target_exit_ready_ns'])
        need(all(result['sampling']['bridge'][k] == bridge_fact[k] for k in ('bytes', 'sha256')),
             'sample symbol ELF equals independently bound actual bridge')
    except BaseException as exc:
        result['error'] = 'sampling: '+type(exc).__name__+': '+str(exc)
        raise
    finally:
        result['captures'] = captures()
        (directory/'owner.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    return (directory/'target.stdout').read_bytes(), (directory/'target.stderr').read_bytes(), result


if __name__ == '__main__':
    need(len(sys.argv) == 5 and sys.argv[1] == '--child', 'internal held-exec child only')
    child(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
