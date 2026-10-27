"""Bounded component children; retain first failure and every independent cleanup."""
import ctypes
import json
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import time
from page_selected import ENV, fact, need, save


class Action(ctypes.Structure):
    _fields_ = [('handler', ctypes.c_void_p), ('flags', ctypes.c_ulong),
                ('restorer', ctypes.c_void_p), ('mask', ctypes.c_uint64)]


def invoke(row, directory, cpu, record=False, step=False):
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
            process = subprocess.Popen(row['argv'], cwd=directory, env=row.get('environment', ENV),
                                       stdout=stdout, stderr=stderr, start_new_session=True,
                                       pass_fds=tuple(fd for fd, _ in descriptors), preexec_fn=prepare)
            row['pid'] = process.pid
            pidfd = os.pidfd_open(process.pid)
            if not select.select([pidfd], [], [], bounds[3])[0]:
                row['timed_out'] = True
                raise TimeoutError('component wall bound')
            # The unreaped leader pins the process-group number until cleanup.
            close_group()
            row['exit'] = process.wait(timeout=3)
            row['reaped'] = True
    except BaseException as exc:
        row['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if process is not None and process.returncode is None:
            close_group()
            try:
                row['exit'] = process.wait(timeout=3)
                row['reaped'] = True
            except BaseException as exc:
                row['cleanup_errors'].append('wait: '+repr(exc))
        elif process is not None:
            row['exit'] = process.returncode
            row['reaped'] = True
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
