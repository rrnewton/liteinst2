#!/usr/bin/env python3
"""External finite producer and independent population/Report check (not timing truth).

Run under tools/unwind-oracle/bounded_command.py with20 CPU/30 wall seconds,
4 MiB file/output cap. A successful producer also requires its child to exit0,
normal direct reap, no rescue, and every intended request to be represented.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

CAP = 4 * 1024 * 1024
# This checker uses path-specific RET offsets from this exact admitted build.
# The outer recipe freshly rebuilds and independently authenticates its source,
# complete function extent and ELF selection before accepting this digest.
SUBJECT_SHA256 = '8a238b77d4cf32c3dcea5aa0fc2a9ec55e58dbc8dc233c7c9d4100e998bd491d'


def authenticate(candidate, trusted, elf_va, length):
    assert (elf_va, length) == (4096, 41)
    for path in (candidate, trusted):
        assert path.stat().st_size <= CAP
        assert hashlib.sha256(path.read_bytes()).hexdigest() == SUBJECT_SHA256


def remaining(deadline):
    left = deadline - time.monotonic()
    assert left > 0, 'producer absolute wall bound'
    return left


def reap(child, deadline):
    code = child.wait(timeout=remaining(deadline))
    remaining(deadline)
    return code


def refusal(mode, code, transcript, errors):
    """Accept only the declared normal exit, never a competing fatal exit."""
    assert mode in ('duplicate', 'eof')
    assert type(code) is int and code == 1
    assert b'DONE,' not in transcript and b'normal-session FAILED:' in errors
    assert (b'duplicate request ID' if mode == 'duplicate' else b'overlong or unterminated request') in errors
    return dict(control=mode, expected_refusal=True, exit_code=code)


def integer(s):
    assert s.isascii() and s.isdecimal() and (s == '0' or not s.startswith('0'))
    n = int(s)
    assert n <= (1 << 64)-1
    return n


def checksum(data):
    n = 0xcbf29ce484222325
    for b in data:
        n = ((n ^ b) * 0x100000001b3) & ((1 << 64)-1)
    return n


def check(text, expected, k, epochs, reason):
    assert text.endswith('\n') and all(c == '\n' or ' ' <= c <= '~' for c in text)
    rows = [line.split(',') for line in text[:-1].split('\n')]
    assert rows and rows[0] == ['READY', 'normal-session-v1', str(k), str(epochs), '10', '2', '4096', '4096', '4', '1']
    assert len(rows[-1]) == 12 and rows[-1][0:2] == ['DONE', reason]
    done = list(map(integer, rows[-1][2:]))
    arms, actions, accepted, calls, sampled, unsampled, batches, flushes, detach, joins = done
    assert detach == joins == 1 and actions == arms + 1 and 1 <= arms <= epochs
    assert (reason != 'EpochLimit' or arms == epochs)
    history = [(0, 'initial', 0)]
    reports, results, samples, returned = {}, [], {}, []
    seen_ids, batch_sizes = set(), collections.Counter()
    prior_batch = 0
    sampled_sequence = 0
    positions = {}
    owner_slots = collections.Counter()
    prior_prefix = 0
    write_blocked = None
    for row in rows[1:-1]:
        tag = row[0]
        if tag == 'HISTORY':
            assert len(row) == 5
            number, prefix, kind, generation = integer(row[1]), integer(row[2]), row[3], integer(row[4])
            assert number == prefix == len(history) and generation > 0
            assert kind in ('published', 'removed')
            if kind == 'removed':
                assert prefix == actions and history[-1][2] == generation
            else:
                assert prefix <= arms and generation > history[-1][2]
            history.append((prefix, kind, generation))
        elif tag == 'REPORT':
            assert len(row) == 3
            generation, count = map(integer, row[1:])
            assert generation not in reports and count <= k
            reports[generation] = count
        elif tag == 'RESULT':
            assert len(row) == 18
            id_, ordinal, bound, length, digest, value = map(integer, row[1:7])
            owner = row[7]
            generation, invocation, prefix, ret = map(integer, row[8:12])
            ack = row[12]
            start, end, start_aux, end_aux, batch = map(integer, row[13:])
            assert start_aux < 1 << 32 and end_aux < 1 << 32
            assert id_ not in seen_ids and ordinal == len(results)+1
            # Exact authenticated 41-byte FreeBSD strnlen build; both original RETs.
            assert ret in (34, 40) and owner in ('sampled', 'closed', 'removed', 'initial')
            assert ack in ('next', 'checkpoint') and batch in (prior_batch, prior_batch+1) and batch > 0
            if batch != prior_batch:
                if results:
                    assert results[-1]['ack'] == 'checkpoint'
                prior_batch = batch
            else:
                assert results[-1]['ack'] == 'next'
            assert prior_prefix <= prefix < len(history)
            prior_prefix = prefix
            _, kind, owner_generation = history[prefix]
            assert owner_generation == generation
            assert kind == {'sampled': 'published', 'closed': 'published', 'removed': 'removed', 'initial': 'initial'}[owner]
            assert (1 <= invocation <= k) if owner == 'sampled' else invocation == 0
            if owner == 'sampled':
                assert invocation == owner_slots[generation] + 1
                owner_slots[generation] += 1
            elif owner == 'closed':
                assert owner_slots[generation] == k
            expected_command = expected[len(returned)]
            assert expected_command[0] == 'CALL'
            _, wanted_id, wanted_bound, data = expected_command
            assert (id_, bound, length, digest) == (wanted_id, wanted_bound, len(data), checksum(data))
            scalar = data[:bound].find(b'\0')
            assert value == (bound if scalar < 0 else scalar)
            assert ret == (34 if bound == 0 or scalar >= 0 else 40)
            record = dict(id=id_, ordinal=ordinal, owner=owner, generation=generation, invocation=invocation,
                prefix=prefix, ack=ack, start=start, end=end, start_aux=start_aux, end_aux=end_aux,
                sequence=sampled_sequence, batch=batch)
            if owner == 'sampled':
                assert (generation, invocation-1) not in positions
                positions[generation, invocation-1] = record
                sampled_sequence += 1
            results.append(record)
            returned.append(('CALL', id_))
            seen_ids.add(id_)
            batch_sizes[batch] += 1
        elif tag == 'FLUSHED':
            assert len(row) == 5
            id_, batch, confirmed, completed = map(integer, row[1:])
            assert id_ not in seen_ids and expected[len(returned)] == ('FLUSH', id_)
            assert (batch, confirmed, completed) == (prior_batch, len(results), sampled_sequence)
            returned.append(('FLUSH', id_)); seen_ids.add(id_)
        elif tag == 'SAMPLE':
            assert len(row) == 8
            id_, generation, invocation, start, sequence = map(integer, row[1:6])
            kind, endpoint = row[6], integer(row[7])
            key = generation, invocation
            assert key not in samples and key in positions
            r = positions[key]
            assert (id_, start, sequence) == (r['id'], r['start'], r['sequence'])
            wanted = ('unavailable', 1) if r['start_aux'] != r['end_aux'] else (
                ('unavailable', 2) if r['end'] < r['start'] else ('value', r['end']))
            assert (kind, endpoint) == wanted
            samples[key] = id_
        elif tag == 'IO':
            assert len(row) == 2 and write_blocked is None and row is rows[-2]
            write_blocked = integer(row[1])
        else:
            raise AssertionError('unknown/duplicate terminal row '+tag)
    assert returned == [(r[0], r[1]) for r in expected]
    assert accepted == len(expected) and calls == len(results) and calls == sampled + unsampled
    assert sampled == sampled_sequence == len(samples) and set(samples) == set(positions)
    assert sum(reports.values()) == sampled and len(reports) == arms
    assert set(reports) == {row[2] for row in history if row[1] == 'published'}
    assert {g: sum(key[0] == g for key in samples) for g in reports} == reports
    assert actions + 1 == len(history) and history[-1][1] == 'removed'
    assert batches == prior_batch == len(batch_sizes) and all(1 <= n <= 4 for n in batch_sizes.values())
    assert flushes == sum(r[0] == 'FLUSH' for r in expected)
    if results: assert results[-1]['ack'] == 'checkpoint'
    assert write_blocked is not None
    return dict(arms=arms, actions=actions, accepted=accepted, calls=calls, sampled=sampled,
        unsampled=unsampled, batches=batches, flushes=flushes, detach=detach, joins=joins,
        owners=dict(collections.Counter(r['owner'] for r in results)),
        maximum_entry_prefix=max((r['prefix'] for r in results), default=0),
        maximum_batch_calls=max(batch_sizes.values(), default=0), stop_reason=reason,
        write_blocked_at_finalize=write_blocked)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'candidate', 'trusted', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--elf-va', type=int, required=True)
    parser.add_argument('--length', type=int, required=True)
    parser.add_argument('--k', type=int, choices=(10, 1000), required=True)
    parser.add_argument('--mode', choices=('full', 'stop', 'duplicate', 'eof', 'backpressure'), required=True)
    a = parser.parse_args()
    assert not a.output.exists(); a.output.mkdir()
    cpus = sorted(os.sched_getaffinity(0))[:4]
    assert len(cpus) == 4; os.sched_setaffinity(0, cpus)
    authenticate(a.candidate, a.trusted, a.elf_va, a.length)
    epochs = 520
    argv = [str(a.binary), 'normal-session', str(a.candidate), str(a.trusted), str(a.elf_va), str(a.length), str(a.k), str(epochs)]
    expected, outgoing, transcript, errors, buffer = [], bytearray(), bytearray(), bytearray(), bytearray()
    sent = 0
    def enqueue(command):
        nonlocal outgoing
        if command[0] == 'CALL':
            _, id_, bound, data = command
            line = f'CALL {id_} {bound} {data.hex() if data else "-"}\n'
        else:
            line = ' '.join(map(str, command))+'\n'
        outgoing += line.encode('ascii')
        if command[0] != 'STOP': expected.append(command)
    phase = 0
    hold_until = None
    def on_line(raw):
        nonlocal phase, hold_until
        row = raw.decode('ascii').split(',')
        if row[0] == 'READY':
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
                hold_until = time.monotonic() + 0.250
            else:
                enqueue(('CALL', (1 << 64)-1, 3, b'a\0b'))
                enqueue(('CALL', 7, 1, b'\xff'))
                enqueue(('FLUSH', 100))
            phase = 1
        elif a.mode == 'full' and row[:2] == ['FLUSHED', '100']:
            enqueue(('CALL', 42, 0, b''))
            enqueue(('CALL', 13, 64, b'x'*63+b'\0'))
            enqueue(('CALL', 81, 64, b'x'*64))
            enqueue(('FLUSH', 101)); enqueue(('FLUSH', 102))
        elif a.mode == 'full' and row[0] == 'HISTORY':
            prefix = integer(row[2])
            if phase == 1 and prefix >= 50:
                for id_, data in [(83, b'x'*4096), (86, b'\0'+b'x'*4095), (89, b'x'*4095+b'\0')]:
                    enqueue(('CALL', id_, 4096, data))
                enqueue(('FLUSH', 103)); phase = 2
            if phase == 2 and prefix >= 513:
                for i in range(32): enqueue(('CALL', 1000+i*7, 64, b'x'*64))
                enqueue(('FLUSH', 104)); phase = 3
    deadline = time.monotonic()+15
    rescue = False
    failure = None
    selector = None
    summary = dict(status='FAILED', mode=a.mode, k=a.k, error='child setup incomplete')
    # The child inherits all four CPUs before only this producer is narrowed.
    assert os.sched_getaffinity(0) == set(cpus), 'child inheritance affinity'
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # The successful Popen is immediately guarded, including all fd/selector setup.
        os.sched_setaffinity(0, {cpus[3]})
        assert os.sched_getaffinity(0) == {cpus[3]}, 'producer singleton affinity'
        remaining(deadline)
        selector = selectors.DefaultSelector()
        for pipe, name in ((child.stdout, 'out'), (child.stderr, 'err')):
            os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, name)
        os.set_blocking(child.stdin.fileno(), False)
        while selector.get_map() or hold_until is not None:
            remaining(deadline)
            if hold_until is not None and time.monotonic() >= hold_until:
                selector.register(child.stdout, selectors.EVENT_READ, 'out')
                hold_until = None
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
        code = reap(child, deadline)
        assert not buffer
        if a.mode in ('duplicate', 'eof'):
            summary = refusal(a.mode, code, transcript, errors)
        else:
            assert code == 0 and not errors and not outgoing
            summary = check(transcript.decode('ascii'), expected, a.k, epochs,
                'EpochLimit' if a.mode in ('full', 'backpressure') else 'Requested')
            if a.mode == 'full':
                assert phase == 3 and summary['maximum_entry_prefix'] >= 513
                assert summary['calls'] == 40 and summary['flushes'] == 5
            elif a.mode == 'backpressure':
                assert summary['calls'] == 1024 and summary['accepted'] == 1025 and summary['flushes'] == 1
                assert summary['write_blocked_at_finalize'] > 0
        authenticate(a.candidate, a.trusted, a.elf_va, a.length)
        remaining(deadline)
        summary.update(status='PASS', mode=a.mode, k=a.k, input_bytes=sent, normal_reaps=1, rescues=0,
            transcript_sha256=hashlib.sha256(transcript).hexdigest(), transcript_bytes=len(transcript))
    except BaseException as e:
        failure = type(e).__name__+': '+str(e)
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
