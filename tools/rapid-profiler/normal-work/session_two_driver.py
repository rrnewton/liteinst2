#!/usr/bin/env python3
"""Fresh external two-caller cohort, absolute15s; outer20CPU/30wall/4MiB unchanged."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
from check_session_two import CAP, READY, check, integer
# Exact existing fixed-ELF authentication and absolute deadline helpers only.
# The old main/check and every old route are unchanged and are never called here.
from session_driver import authenticate, remaining, reap


def cohort(summary, mode):
    calls, flushes = {'full': (40, 5), 'stop': (64, 0), 'backpressure': (1024, 1)}[mode]
    assert summary['calls'] == calls and summary['flushes'] == flushes
    assert summary['accepted'] == calls+flushes and summary['detaches'] == summary['joins'] == 2
    assert [w['worker'] for w in summary['workers']] == [1, 2]
    assert [w['calls'] for w in summary['workers']] == [calls//2, calls//2]
    assert summary['stop_reason'] == ('Requested' if mode == 'stop' else 'EpochLimit')
    if mode != 'stop': assert summary['arms'] == 520 and summary['actions'] == 521
    if mode == 'full': assert all(w['maximum_entry_prefix'] >= 513 for w in summary['workers'])
    if mode == 'backpressure': assert summary['write_blocked_at_finalize'] > 0


def refusal(code, transcript, errors, mode):
    assert mode in ('duplicate', 'eof') and type(code) is int and code == 1
    assert b'DONE,' not in transcript and b'normal-session-two FAILED:' in errors
    assert (b'duplicate request ID' if mode == 'duplicate' else b'overlong or unterminated request') in errors
    return dict(control=mode, expected_refusal=True, exit_code=code)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'candidate', 'trusted', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--elf-va', type=int, required=True)
    parser.add_argument('--length', type=int, required=True)
    parser.add_argument('--k', type=int, choices=(10, 1000), required=True)
    parser.add_argument('--mode', choices=('full', 'stop', 'duplicate', 'eof', 'backpressure'), required=True)
    a = parser.parse_args()
    deadline = time.monotonic()+15
    assert not a.output.exists(); a.output.mkdir()
    cpus = sorted(os.sched_getaffinity(0))[:4]
    assert len(cpus) == 4; os.sched_setaffinity(0, cpus)
    authenticate(a.candidate, a.trusted, a.elf_va, a.length)
    epochs = 520
    argv = [str(a.binary), 'normal-session-two', str(a.candidate), str(a.trusted), str(a.elf_va), str(a.length), str(a.k), str(epochs)]
    expected, outgoing, transcript, errors, buffer = [], bytearray(), bytearray(), bytearray(), bytearray()
    sent, phase, prefix = 0, 0, 0
    flush_seen = set()
    hold_until = None
    def enqueue(command):
        if command[0] == 'CALL':
            _, id_, bound, data = command
            line = f'CALL {id_} {bound} {data.hex() if data else "-"}\n'
        else:
            line = ' '.join(map(str, command))+'\n'
        outgoing.extend(line.encode('ascii'))
        if command[0] != 'STOP': expected.append(command)
    def advance():
        nonlocal phase
        if a.mode != 'full': return
        if phase == 1 and 100 in flush_seen:
            enqueue(('CALL', 42, 0, b''))
            enqueue(('CALL', 13, 64, b'x'*63+b'\0'))
            enqueue(('CALL', 81, 64, b'x'*64))
            enqueue(('FLUSH', 101)); enqueue(('FLUSH', 102)); phase = 2
        if phase == 2 and 102 in flush_seen and prefix >= 50:
            for id_, data in [(83, b'x'*4096), (86, b'\0'+b'x'*4095), (89, b'x'*4095+b'\0')]:
                enqueue(('CALL', id_, 4096, data))
            enqueue(('FLUSH', 103)); phase = 3
        if phase == 3 and 103 in flush_seen and prefix >= 513:
            for i in range(32): enqueue(('CALL', 1000+i*7, 64, b'x'*64))
            enqueue(('FLUSH', 104)); phase = 4
    def on_line(raw):
        nonlocal phase, prefix, hold_until
        assert len(raw)+1 <= 350 and all(32 <= byte <= 126 for byte in raw)
        row = raw.decode('ascii').split(',')
        if row[0] == 'READY':
            assert phase == 0 and row == ['READY', 'normal-two-session-v1', str(a.k), '520']+READY
            if a.mode == 'duplicate':
                enqueue(('CALL', 42, 0, b'')); outgoing.extend(b'FLUSH 42\n')
            elif a.mode == 'eof':
                outgoing.extend(b'CALL 42 1 0')
            elif a.mode == 'stop':
                for i in range(64): enqueue(('CALL', 10000+i*3, 64, b'x'*64))
                enqueue(('STOP',))
            elif a.mode == 'backpressure':
                for i in range(1024): enqueue(('CALL', 10000+i*3, 64, b'x'*64))
                enqueue(('FLUSH', 9))
                selector.unregister(child.stdout)
                hold_until = time.monotonic()+0.250
            else:
                enqueue(('CALL', (1 << 64)-1, 3, b'a\0b'))
                enqueue(('CALL', 7, 1, b'\xff'))
                enqueue(('FLUSH', 100))
            phase = 1
        elif row[0] == 'FLUSHED':
            assert len(row) == 8
            id_ = integer(row[1]); assert id_ not in flush_seen
            flush_seen.add(id_)
        elif row[0] == 'HISTORY':
            assert len(row) == 5
            observed = integer(row[2]); assert observed == prefix+1
            prefix = observed
        advance()
    rescue, failure, selector = False, None, None
    summary = dict(status='FAILED', mode=a.mode, k=a.k, error='child setup incomplete')
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # A successful Popen is immediately guarded, including fd/selector setup.
        remaining(deadline)
        selector = selectors.DefaultSelector()
        for pipe, name in ((child.stdout, 'out'), (child.stderr, 'err')):
            os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, name)
        os.set_blocking(child.stdin.fileno(), False)
        while selector.get_map() or hold_until is not None:
            remaining(deadline)
            if hold_until is not None and time.monotonic() >= hold_until:
                selector.register(child.stdout, selectors.EVENT_READ, 'out'); hold_until = None
            if outgoing and not child.stdin.closed:
                try:
                    n = os.write(child.stdin.fileno(), outgoing[:8192]); sent += n; del outgoing[:n]
                except BlockingIOError: pass
                except BrokenPipeError: child.stdin.close()
            if a.mode == 'eof' and phase and not outgoing and not child.stdin.closed: child.stdin.close()
            for key, _ in selector.select(min(0.001, remaining(deadline))):
                try: data = os.read(key.fd, 8192)
                except BlockingIOError: continue
                if not data:
                    selector.unregister(key.fileobj); key.fileobj.close(); continue
                target = transcript if key.data == 'out' else errors
                assert len(target)+len(data) <= CAP
                target.extend(data)
                if key.data == 'out':
                    buffer.extend(data)
                    while b'\n' in buffer:
                        line, _, rest = buffer.partition(b'\n'); buffer = bytearray(rest); on_line(line)
                    assert len(buffer) < 350
        code = reap(child, deadline)
        assert not buffer and phase > 0
        try:
            os.waitpid(child.pid, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise AssertionError('direct child lacks ECHILD after normal reap')
        if a.mode in ('duplicate', 'eof'):
            summary = refusal(code, transcript, errors, a.mode)
        else:
            assert code == 0 and not errors and not outgoing
            summary = check(transcript.decode('ascii'), expected, a.k, epochs,
                'Requested' if a.mode == 'stop' else 'EpochLimit')
            cohort(summary, a.mode)
            if a.mode == 'full': assert phase == 4 and flush_seen == {100, 101, 102, 103, 104}
        authenticate(a.candidate, a.trusted, a.elf_va, a.length)
        remaining(deadline)
        summary.update(status='PASS', mode=a.mode, k=a.k, input_bytes=sent, normal_reaps=1,
            absence='ECHILD', rescues=0, transcript_sha256=hashlib.sha256(transcript).hexdigest(),
            transcript_bytes=len(transcript))
    except BaseException as error:
        failure = type(error).__name__+': '+str(error)
        summary = dict(status='FAILED', mode=a.mode, k=a.k, error=failure)
    finally:
        if selector is not None: selector.close()
        if not child.stdin.closed: child.stdin.close()
        if child.poll() is None:
            rescue = True; child.kill(); child.wait()
        for pipe in (child.stdout, child.stderr):
            if not pipe.closed: pipe.close()
        summary.update(child_exit=child.returncode, rescue=rescue)
        (a.output/'stdout.txt').write_bytes(transcript)
        (a.output/'stderr.txt').write_bytes(errors)
        if failure is None and time.monotonic() >= deadline:
            failure = 'producer absolute wall bound at final acceptance'
            summary.update(status='FAILED', error=failure)
        (a.output/'result.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary))
    assert failure is None and not rescue


if __name__ == '__main__':
    main()
