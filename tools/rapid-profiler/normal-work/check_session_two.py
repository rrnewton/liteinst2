#!/usr/bin/env python3
"""Strict two-worker scalar/population projection; not a replay of native state."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import collections

CAP = 4 * 1024 * 1024
U64 = (1 << 64) - 1
READY = ['10', '2', '4096', '4096', '2', '1', '2', '1', '4', '2', '4096']


def integer(s):
    assert s.isascii() and s.isdecimal() and (s == '0' or not s.startswith('0'))
    n = int(s)
    assert n <= U64
    return n


def checksum(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001b3) & U64
    return value


def check(text, expected, k, epochs, reason):
    assert type(k) is int and k in (10, 1000)
    assert type(epochs) is int and 1 <= epochs <= 4096
    assert reason in ('EpochLimit', 'Requested')
    assert isinstance(text, str) and text.endswith('\n') and len(text) <= CAP
    assert all(c == '\n' or ' ' <= c <= '~' for c in text)
    lines = text[:-1].split('\n')
    assert len(lines) <= 16392 and all(0 < len(line)+1 <= 350 for line in lines)
    rows = [line.split(',') for line in lines]
    assert rows[0] == ['READY', 'normal-two-session-v1', str(k), str(epochs)] + READY
    assert 1 <= len(expected) <= 4096
    by_id, assignment, barriers = {}, {1: [], 2: []}, []
    for command in expected:
        assert isinstance(command, tuple) and len(command) in (2, 4)
        tag, id_ = command[:2]
        assert type(id_) is int and 0 <= id_ <= U64 and id_ not in by_id
        if tag == 'CALL':
            assert len(command) == 4
            bound, data = command[2:]
            assert type(bound) is int and isinstance(data, bytes) and 0 <= bound <= len(data) <= 4096
            worker = 1 + sum(map(len, assignment.values())) % 2
            assignment[worker].append(id_)
            by_id[id_] = (worker, len(assignment[worker]), command)
        else:
            assert tag == 'FLUSH' and len(command) == 2
            by_id[id_] = (0, 0, command)
            barriers.append((id_, len(assignment[1]), len(assignment[2])))
    workers = {}
    for worker, row in zip((1, 2), rows[1:3]):
        assert len(row) == 4 and row[0] == 'WORKER'
        identity, registration, tid = map(integer, row[1:])
        assert identity == registration == worker and 0 < tid <= (1 << 31)-1
        workers[worker] = tid
    assert len(workers) == 2 and workers[1] != workers[2]
    assert len(rows[-1]) == 16 and rows[-1][:2] == ['DONE', reason]
    done = list(map(integer, rows[-1][2:]))
    arms, actions, accepted, calls, admitted, retained, dropped, unsampled, batches, flushes, cancelled, unfinished, detaches, joins = done
    assert cancelled == unfinished == 0 and detaches == joins == 2
    assert 1 <= arms <= epochs and actions == arms + 1
    assert reason != 'EpochLimit' or arms == epochs
    local = {w: dict(count=0, completed=0, batch=0, prefix=0, last=None, sizes=collections.Counter()) for w in (1, 2)}
    history, reports, results, positions, samples = [(0, 'initial', 0)], {}, {}, {}, {}
    flush_index, done_workers, write_blocked = 0, [], None
    for index, row in enumerate(rows[3:-1], 3):
        tag = row[0]
        if done_workers:
            assert tag in ('WORKER_DONE', 'IO')
        if tag == 'HISTORY':
            assert len(row) == 5
            chunk, prefix, kind, generation = integer(row[1]), integer(row[2]), row[3], integer(row[4])
            assert chunk == prefix == len(history) and generation > 0
            assert kind in ('published', 'removed')
            if kind == 'published':
                assert prefix <= arms and generation > history[-1][2]
            else:
                assert prefix == actions and history[-1][1] == 'published' and generation == history[-1][2]
            history.append((prefix, kind, generation))
        elif tag == 'RESULT':
            assert len(row) == 20
            id_, worker, registration, ordinal, bound, length, digest, value = map(integer, row[1:9])
            owner = row[9]
            generation, inv1, prefix, ret = map(integer, row[10:14])
            ack = row[14]
            start, end, start_aux, end_aux, batch = map(integer, row[15:])
            assert worker in local and registration == worker and id_ not in results
            s = local[worker]
            assert ordinal == s['count'] + 1 and ordinal <= len(assignment[worker])
            assert id_ == assignment[worker][ordinal-1]
            assert by_id[id_][:2] == (worker, ordinal)
            # A completed FLUSH is a global acceptance barrier; later calls cannot overtake it.
            if flush_index < len(barriers):
                assert ordinal <= barriers[flush_index][worker]
            _, _, wanted_bound, data = by_id[id_][2]
            assert (bound, length, digest) == (wanted_bound, len(data), checksum(data))
            zero = data[:bound].find(b'\0')
            assert value == (bound if zero < 0 else zero)
            assert ret == (34 if bound == 0 or zero >= 0 else 40)
            assert owner in ('sampled', 'closed', 'removed', 'initial')
            assert start_aux < 1 << 32 and end_aux < 1 << 32
            assert ack in ('next', 'checkpoint') and batch > 0 and batch in (s['batch'], s['batch']+1)
            if s['last'] is not None:
                assert s['last']['ack'] == ('next' if batch == s['batch'] else 'checkpoint')
            else:
                assert batch == 1
            assert s['prefix'] <= prefix <= actions
            assert prefix < len(history), 'RESULT precedes its HISTORY'
            assert (1 <= inv1 <= 4096) if owner == 'sampled' else inv1 == 0
            r = dict(id=id_, worker=worker, registration=registration, ordinal=ordinal, owner=owner,
                generation=generation, invocation=inv1-1 if inv1 else None, prefix=prefix, ack=ack,
                start=start, end=end, start_aux=start_aux, end_aux=end_aux, sequence=s['completed'], batch=batch)
            if owner == 'sampled':
                key = generation, inv1-1
                assert key not in positions
                positions[key] = r
                s['completed'] += 1
            results[id_] = r
            s.update(count=ordinal, batch=batch, prefix=prefix, last=r)
            s['sizes'][batch] += 1
            assert s['sizes'][batch] <= 4
        elif tag == 'FLUSHED':
            assert len(row) == 8 and flush_index < len(barriers)
            id_, c1, c2, b1, b2, a1, a2 = map(integer, row[1:])
            assert (id_, c1, c2) == barriers[flush_index]
            assert (c1, c2) == (local[1]['count'], local[2]['count'])
            assert (b1, b2, a1, a2) == (local[1]['batch'], local[2]['batch'], local[1]['completed'], local[2]['completed'])
            assert all(s['last'] is None or s['last']['ack'] == 'checkpoint' for s in local.values())
            flush_index += 1
        elif tag == 'REPORT':
            assert len(row) == 7
            generation, count, kept, lost, cancel, pending = map(integer, row[1:])
            assert generation > 0 and generation not in reports and count <= 4096
            assert any(kind == 'published' and g == generation for _, kind, g in history), 'REPORT precedes publication'
            assert cancel == pending == 0 and kept == min(k, count) and lost == count-kept
            reports[generation] = (count, kept, lost)
        elif tag == 'SAMPLE':
            assert len(row) == 13
            id_, worker, registration, generation, invocation, start, sequence = map(integer, row[1:8])
            disposition, rank, terminal, kind, endpoint = row[8], integer(row[9]), integer(row[10]), row[11], integer(row[12])
            key = generation, invocation
            assert worker in local and registration == worker and invocation < 4096 and key not in samples
            assert generation in reports and key in positions, 'SAMPLE precedes its REPORT or RESULT'
            assert disposition in ('retained', 'dropped') and kind in ('value', 'unavailable')
            assert (1 <= rank <= k) if disposition == 'retained' else rank == 0
            assert terminal == invocation
            samples[key] = (id_, worker, registration, start, sequence, disposition, rank, kind, endpoint)
        elif tag == 'WORKER_DONE':
            assert len(row) == 10
            worker, batch, entered, observed, confirmed, completed, unused, detached, joined = map(integer, row[1:])
            assert worker == len(done_workers)+1 and worker in local and detached == joined == 1
            s = local[worker]
            assert entered == observed == confirmed == s['count'] == len(assignment[worker])
            assert completed == s['completed'] and completed+unused == confirmed and batch == s['batch']
            assert s['last'] is None or s['last']['ack'] == 'checkpoint'
            done_workers.append(worker)
        elif tag == 'IO':
            assert len(row) == 2 and write_blocked is None and done_workers == [1, 2]
            assert index == len(rows)-2
            write_blocked = integer(row[1])
        else:
            raise AssertionError('unknown/duplicate protocol row '+tag)
    assert done_workers == [1, 2] and write_blocked is not None
    assert len(history) == actions+1 and history[-1][1] == 'removed'
    assert set(reports) == {g for _, kind, g in history if kind == 'published'} and len(reports) == arms
    assert set(samples) == set(positions)
    ranks = collections.defaultdict(set)
    disposition_counts = collections.Counter()
    for key, r in positions.items():
        id_, worker, registration, start, sequence, disposition, rank, kind, endpoint = samples[key]
        assert (id_, worker, registration, start, sequence) == (r['id'], r['worker'], r['registration'], r['start'], r['sequence'])
        wanted = ('unavailable', 1) if r['start_aux'] != r['end_aux'] else (
            ('unavailable', 2) if r['end'] < r['start'] else ('value', r['end']))
        assert (kind, endpoint) == wanted
        disposition_counts[key[0], disposition] += 1
        if disposition == 'retained':
            assert rank not in ranks[key[0]]
            ranks[key[0]].add(rank)
    for generation, (count, kept, lost) in reports.items():
        assert {slot for g, slot in positions if g == generation} == set(range(count))
        assert ranks[generation] == set(range(1, kept+1))
        assert (disposition_counts[generation, 'retained'], disposition_counts[generation, 'dropped']) == (kept, lost)
    for r in results.values():
        assert r['prefix'] < len(history)
        _, kind, generation = history[r['prefix']]
        assert generation == r['generation']
        assert kind == {'sampled': 'published', 'closed': 'published', 'removed': 'removed', 'initial': 'initial'}[r['owner']]
        if r['owner'] == 'closed': assert reports[generation][1] == k
    assert accepted == len(expected) and calls == len(results) == sum(map(len, assignment.values()))
    assert admitted == len(positions) == sum(s['completed'] for s in local.values())
    assert admitted == retained+dropped and calls == admitted+unsampled
    assert (admitted, retained, dropped) == tuple(sum(r[i] for r in reports.values()) for i in range(3))
    assert batches == sum(s['batch'] for s in local.values())
    assert all(set(s['sizes']) == set(range(1, s['batch']+1)) for s in local.values())
    assert flushes == flush_index == len(barriers)
    return dict(arms=arms, actions=actions, accepted=accepted, calls=calls, admitted=admitted,
        retained=retained, dropped=dropped, unsampled=unsampled, batches=batches, flushes=flushes,
        cancelled=cancelled, unfinished=unfinished, detaches=detaches, joins=joins,
        workers=[dict(worker=w, registration=w, tid=workers[w], calls=local[w]['count'],
            completed=local[w]['completed'], unsampled=local[w]['count']-local[w]['completed'], batches=local[w]['batch'],
            maximum_entry_prefix=local[w]['prefix']) for w in (1, 2)],
        owners=dict(collections.Counter(r['owner'] for r in results.values())),
        maximum_entry_prefix=max((r['prefix'] for r in results.values()), default=0),
        maximum_batch_calls=max((n for s in local.values() for n in s['sizes'].values()), default=0),
        stop_reason=reason, write_blocked_at_finalize=write_blocked)
