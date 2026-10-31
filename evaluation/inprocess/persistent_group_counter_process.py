#!/usr/bin/env python3
"""One bounded group diagnostic; final shared values never replace target status."""
import ctypes,fcntl,json,os,resource,select,signal,struct,subprocess,time
from pathlib import Path
from page_selected import ENV,fact,need,save
from page_selected_process import Action
import page_default_ls_release_provenance as provenance
from page_native_pair_performance import decode,H,PROGRAM_ENV
MAGIC=0x31434f554e544750
NATIVE_NAMES=('attempts','admissions','closed','blocked','low_address_refusals')
GROUP_NAMES=('offers','publications','hits','cold_attempts','cancelled','retirements','permit_claims','entries','completed','unexpected')
MAP_NAMES=('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch','active','valid','poisoned','reserved')
VIEW_NAMES=('queries','hits','refreshes','updates','invalidations','comparisons','mismatches','unexplained','stack_probes','enabled','differential','poisoned','reserved')


def final_counter_prefix(data, initial, pid, seals):
    need(type(pid) is int and pid>0 and type(data) is bytes and len(data)==4096 and seals==23, 'whole final sealed counter backing')
    h=struct.unpack_from('<16Q',data)
    need(h[:8]==initial and h[8:12]==(pid,pid,6,23) and 4096<=h[12]<1<<47 and h[12]%4096==0 and
         h[13:]==(1,1,1) and not any(data[752:]) and not any(data[596:600]), 'exact initialized/protected/closed/ready final counter header and zero tail')
    ingress=struct.unpack_from('<6Q',data,128)
    group=dict(zip(GROUP_NAMES,struct.unpack_from('<10Q',data,176),strict=True))
    misses=list(struct.unpack_from('<18Q',data,256))
    maps=dict(zip(MAP_NAMES,struct.unpack_from('<6Q4I',data,400),strict=True))
    view=dict(zip(VIEW_NAMES,struct.unpack_from('<9Q4I',data,464),strict=True))
    native=dict(zip(NATIVE_NAMES,struct.unpack_from('<5Q',data,552),strict=True))
    # Deliberately no transaction arithmetic. A kill can split adjacent updates.
    return dict(events=ingress[0],signals=list(ingress[1:]),group=group,misses=misses,maps=maps,view=view,native=native)


def program_invoke(row, directory, cpu, record=False, step=False):
    need(record is False and step is False and row['bounds'] == [30, 512<<20, 16<<20, 60],
         'counter observation keeps the exact single release subject bounds')
    counter_ro = None; counter_initial = None; counter_rw = None
    row['counter_observation'] = dict(usable=False, scope='final per-cell prefix after actual reap; no terminal or qualification claim')
    process = None
    pidfd = None
    descriptors = []
    start = time.monotonic_ns()
    row.update(exit=None, timed_out=False, reaped=False, error=None, cleanup_errors=[], descriptors=[])
    bounds = row['bounds']
    paths = {name: directory/(row['name']+'.'+name) for name in ('stdout', 'stderr')}
    record_fd = prep_fd = None
    libc = None

    def reset_signals():
        previous = ctypes.c_uint64(0)
        empty = ctypes.c_uint64(0)
        actual = ctypes.c_uint64(1)
        zero, before, after = Action(), Action(), Action()
        if libc.syscall(14, 2, ctypes.byref(empty), ctypes.byref(previous), 8) != 0:
            os._exit(120)
        observations = []
        for number in range(1, 65):
            if number in (9, 19):
                continue
            if libc.syscall(13, number, None, ctypes.byref(before), 8) != 0:
                os._exit(121)
            if libc.syscall(13, number, ctypes.byref(zero), None, 8) != 0:
                os._exit(122)
            if libc.syscall(13, number, None, ctypes.byref(after), 8) != 0 or after.handler:
                os._exit(123)
            observations.append({'signal': number, 'before': int(before.handler or 0),
                                 'after': int(after.handler or 0)})
        if libc.syscall(14, 2, None, ctypes.byref(actual), 8) != 0 or actual.value != 0:
            os._exit(123)
        data = json.dumps({'previous_mask': previous.value, 'mask': actual.value,
                           'dispositions': observations}, separators=(',', ':')).encode()
        if os.write(prep_fd, data) != len(data):
            os._exit(124)
        os.close(prep_fd)

    def prepare():
        os.sched_setaffinity(0, {cpu})
        if step:
            reset_signals()
        for key, value in ((resource.RLIMIT_CPU, bounds[0]), (resource.RLIMIT_AS, bounds[1]),
                           (resource.RLIMIT_FSIZE, bounds[2]), (resource.RLIMIT_CORE, 0)):
            resource.setrlimit(key, (value, value))
        if row.get('nproc') is not None:
            resource.setrlimit(resource.RLIMIT_NPROC, (row['nproc'], row['nproc']))

    def own(name):
        path = directory/(row['name']+'.'+name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        state = {'name': name, 'fd': fd, 'closed': False}
        descriptors.append((fd, state))
        row['descriptors'].append(state)
        paths[name] = path
        return fd

    def close_group():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as exc:
            row['cleanup_errors'].append('kill: '+repr(exc))

    try:
        need(row['argv'].count('{counter_fd}') == row['argv'].count('{counter_nonce}') == 1,
             'one explicit diagnostic fd and nonce argument')
        counter_rw = os.memfd_create('li2-group-final-counters', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        counter_state = dict(name='counter_rw', fd=counter_rw, closed=False)
        descriptors.append((counter_rw, counter_state)); row['descriptors'].append(counter_state)
        os.ftruncate(counter_rw, 4096); os.fchmod(counter_rw, 0o600)
        cs = os.fstat(counter_rw); nonce = int.from_bytes(os.urandom(8), 'little') or 1
        counter_initial = (MAGIC, 2, 752, 4096, nonce, os.getpid(), cs.st_dev, cs.st_ino)
        initial = struct.pack('<8Q', *counter_initial)+bytes(4096-64)
        need(os.pwrite(counter_rw, initial, 0) == 4096, 'whole initial counter page')
        fcntl.fcntl(counter_rw, fcntl.F_ADD_SEALS, 6)
        need(fcntl.fcntl(counter_rw, fcntl.F_GET_SEALS) == 6, 'exact grow/shrink seals before target writer')
        # Reopening makes a genuine read-only description. dup() would retain RW.
        counter_ro = os.open('/proc/self/fd/'+str(counter_rw), os.O_RDONLY | os.O_CLOEXEC)
        counter_read_state = dict(name='counter_ro', fd=counter_ro, closed=False)
        row['descriptors'].append(counter_read_state)
        rs = os.fstat(counter_ro)
        need((rs.st_dev, rs.st_ino, rs.st_size) == (cs.st_dev, cs.st_ino, 4096) and
             fcntl.fcntl(counter_ro, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
             'parent holds same backing through genuine read-only descriptor, never a writable mapping')
        row['counter_input'] = dict(bytes=4096, logical_bytes=752, nonce=nonce, parent=os.getpid(),
                                   device=cs.st_dev, inode=cs.st_ino, initial_seals=6, child_fd=counter_rw)
        row['argv'] = [str(counter_rw) if x == '{counter_fd}' else str(nonce) if x == '{counter_nonce}' else x
                       for x in row['argv']]
        # Resolve libc before fork inside the retained attempt. Only this
        # diagnostic child's preparation uses it; target handlers do not.
        if step:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.syscall.restype = ctypes.c_long
        if record:
            record_fd = own('record')
            if step:
                need(record_fd == 3, 'standalone step requires actual fixed fd 3')
                prep_fd = own('preparation')
        row['argv'] = [str(record_fd) if value == '{record_fd}' else str(value) for value in row['argv']]
        with paths['stdout'].open('xb') as stdout, paths['stderr'].open('xb') as stderr:
            row['stdout_provenance_before']=provenance.observe(stdout.fileno())
            try:
                row['process_start_ns'] = time.monotonic_ns()
                process = subprocess.Popen(row['argv'], cwd=directory, env=row.get('environment', ENV),
                                           stdout=stdout, stderr=stderr, start_new_session=True,
                                           pass_fds=tuple(fd for fd, _ in descriptors), preexec_fn=prepare)
                row['pid'] = process.pid
                # Only the target retains a writable description after spawn.
                # Remove before close to avoid any later reuse/double-close.
                found = [(i, item) for i, item in enumerate(descriptors) if item[0] == counter_rw]
                need(len(found) == 1, 'one parent-owned counter writer descriptor')
                descriptors.pop(found[0][0]); closing = counter_rw; counter_rw = None
                os.close(closing); counter_state['closed'] = True
                pidfd = os.pidfd_open(process.pid)
                if not select.select([pidfd], [], [], bounds[3])[0]:
                    row['timed_out'] = True
                    raise TimeoutError('component wall bound')
                # The unreaped leader pins the process-group number until cleanup.
                close_group()
                row['exit'] = process.wait(timeout=3)
                row['reaped'] = True
                row.setdefault('process_reaped_ns', time.monotonic_ns())
            finally:
                try:
                    row['stdout_provenance_after']=provenance.observe(stdout.fileno())
                    provenance.same(row['stdout_provenance_before'],row['stdout_provenance_after'])
                except BaseException as exc:
                    row['cleanup_errors'].append('parent descriptor identity: '+repr(exc))
    except BaseException as exc:
        row['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if process is not None and process.returncode is None:
            close_group()
            try:
                row['exit'] = process.wait(timeout=3)
                row['reaped'] = True
                row.setdefault('process_reaped_ns', time.monotonic_ns())
            except BaseException as exc:
                row['cleanup_errors'].append('wait: '+repr(exc))
        elif process is not None:
            row['exit'] = process.returncode
            row['reaped'] = True
            row.setdefault('process_reaped_ns', time.monotonic_ns())
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as exc:
                row['cleanup_errors'].append('pidfd_close: '+repr(exc))
        # Each descriptor leaves the close list before its close is attempted;
        # a failure cannot trigger a later close of a reused numeric descriptor.
        while descriptors:
            fd, state = descriptors.pop()
            try:
                os.close(fd)
                state['closed'] = True
            except BaseException as exc:
                state['error'] = repr(exc)
                row['cleanup_errors'].append(state['name']+'_close: '+repr(exc))
        if counter_ro is not None:
            try:
                need(row['reaped'] is True and not row['cleanup_errors'], 'final read follows actual target/group cleanup')
                data = os.pread(counter_ro, 4097, 0)
                destination = directory/(row['name']+'.counters')
                with destination.open('xb') as stream: stream.write(data)
                paths['counters'] = destination
                rs = os.fstat(counter_ro)
                need(counter_initial is not None and (rs.st_dev, rs.st_ino, rs.st_size) ==
                     (counter_initial[6], counter_initial[7], 4096) and
                     fcntl.fcntl(counter_ro, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
                     'final read-only descriptor identity unchanged')
                seals = fcntl.fcntl(counter_ro, fcntl.F_GET_SEALS)
                row['counter_observation'].update(final_seals=seals, raw=fact(destination))
                value = final_counter_prefix(data, counter_initial, row['pid'], seals)
                row['counter_observation'].update(usable=True, **value)
            except BaseException as exc:
                row['counter_observation']['error'] = type(exc).__name__+': '+str(exc)
            finally:
                closing = counter_ro; counter_ro = None
                try: os.close(closing); counter_read_state['closed'] = True
                except BaseException as exc:
                    counter_read_state['error'] = repr(exc)
                    row['cleanup_errors'].append('counter_ro_close: '+repr(exc))
        if 'process_reaped_ns' in row:
            row['process_ns'] = row['process_reaped_ns']-row['process_start_ns']
        row['duration_ns'] = time.monotonic_ns()-start
        row['captures'] = {}
        for name, path in paths.items():
            try:
                row['captures'][name] = dict(fact(path), file=path.name)
            except BaseException as exc:
                row['cleanup_errors'].append(name+'_capture: '+repr(exc))
        try:
            save(directory/(row['name']+'.json'), row)
        except BaseException as exc:
            row['cleanup_errors'].append('command_record: '+repr(exc))
    need(row['reaped'] and not row['timed_out'] and not row['error'] and not row['cleanup_errors'],
         'component process/cleanup failed: '+row['name'])
    cap = row['capture_limit']
    need(all(row['captures'][name]['bytes'] <= cap for name in ('stdout', 'stderr')), 'capture limit')
    if record:
        need(row['captures']['record']['bytes'] <= bounds[2], 'private record limit')
    if step:
        data = json.loads(paths['preparation'].read_bytes())
        need(data['mask'] == 0 and [x['signal'] for x in data['dispositions']] ==
             [n for n in range(1, 65) if n not in (9, 19)] and
             all(x['after'] == 0 for x in data['dispositions']), 'actual standalone signal preparation')
    return paths['stdout'].read_bytes(), paths['stderr'].read_bytes()


def namespace_join(state,ns,binary,r,namespace,counter):
    observed=decode(binary(ns/'namespace.json').read_bytes());launch=decode(binary(ns/'launch.json').read_bytes())
    objects=state['objects'];description=state['description']
    need(all(observed[k]==v for k,v in description.items())and observed['directory']==str(ns)and
         observed['schema_version']==1 and observed['status']=='prepared_not_executed'and len(observed['objects'])==len(objects),
         'actual complete sealed namespace matches independent plan')
    fds=[]
    for obj,item in zip(observed['objects'],objects,strict=True):
        need(type(obj['fd'])is int and obj['fd']>2 and obj['fd']not in fds and
             obj['source']==str(item['path'])and obj['names']==item['names']and obj['needed']==item['info']['needed']and
             obj['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and
             obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and obj['seals']==namespace.SEALS and
             type(obj['device'])is int and obj['device']>0 and type(obj['inode'])is int and obj['inode']>0,
             'actual complete sealed dependency identity')
        fds.append(obj['fd'])
        for alias in obj['names']:
            path=ns/alias;value='/proc/self/fd/'+str(obj['fd'])
            need(path.is_symlink()and os.readlink(path)==value,'actual sealed dependency alias')
            r['namespace_aliases'][str(path)]=value
    expected_env={k:v for k,v in PROGRAM_ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
    expected_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)))
    need(type(counter) is dict and counter['child_fd'] not in fds and counter['initial_seals']==6 and
         counter['bytes']==4096 and counter['logical_bytes']==752, 'separate exact counter preparation channel')
    expected_env.update(LI2_GROUP_COUNTER_FD=str(counter['child_fd']), LI2_GROUP_COUNTER_NONCE=str(counter['nonce']))
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
        carrier_sha256=fact(state['carrier'])['sha256'],carrier_size=fact(state['carrier'])['bytes'],argv=state['argv'],
        environment=expected_env,dependency_fds=fds),'exact default-rseq launch/argv/environment/carrier/FD join')

