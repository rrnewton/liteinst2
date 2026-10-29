"""Fixed unfiltered timing population; qualification and execution stay separate."""
import hashlib
import json
import re
import statistics

OPERATIONS = (1, 256)
ORDER = tuple((n, pair, lane) for n in OPERATIONS for pair in range(5)
              for lane in (('native', 'gated') if pair % 2 == 0 else ('gated', 'native')))
PROFILE = {'native': 'native-timing', 'gated': 'gated-timing'}
DESCRIPTORS = ('record', 'go_read', 'go_write', 'notify_read', 'notify_write')
CAPTURES = {'stdout', 'stderr', 'record', 'preparation'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def command_name(operations, pair, lane):
    need(type(operations) is int and operations in OPERATIONS and
         type(pair) is int and 0 <= pair < 5 and lane in PROFILE,
         'literal operation count, pair and timing lane')
    return 'interval-' + str(operations) + '-' + str(pair) + '-' + lane


def summarize(receipt):
    """Join numeric samples to actual accepted children before aggregation.

    This projection is not the qualification reader: the enclosing runner must
    authenticate the complete finite receipt, source/build, launch and terminal
    predicates. A failed or incomplete batch never receives performance credit.
    """
    samples = receipt['samples']
    commands = receipt['commands']
    need(receipt['status'] in ('passed', 'failed') and type(receipt['cpu']) is int and
         receipt['cpu'] >= 0 and type(samples) is list and len(samples) <= len(ORDER) and
         type(commands) is list and type(receipt['final_errors']) is list and
         type(receipt['qualification_verified']) is bool and type(receipt['source_unchanged']) is bool,
         'typed status, CPU, final custody and bounded attempted population')
    need([(s['operations'], s['pair'], s['lane']) for s in samples] == list(ORDER[:len(samples)]),
         'exact fixed attempted prefix; no retry or sample replacement')
    names = [c['name'] for c in commands]
    need(len(names) == len(set(names)), 'unique actual command names')
    accepted = []
    previous_cleanup = 0
    for order, sample in enumerate(samples):
        n, pair, lane = ORDER[order]
        need(type(sample['operations']) is int and type(sample['pair']) is int and
             type(sample['order']) is int and sample['order'] == order and
             type(sample['accepted']) is bool, 'typed numeric sample identity')
        name = command_name(n, pair, lane)
        rows = [c for c in commands if c['name'] == name]
        need(len(rows) == 1, 'one actual attempted child row per sample')
        c = rows[0]
        need(c['profile'] == PROFILE[lane] and c['control'] == 'normal',
             'explicit unobserved timing profile and normal protocol')
        if not sample['accepted']:
            need(c.get('accepted') is not True, 'accepted child cannot be discarded')
            need(order == len(samples) - 1, 'stop on the first rejected child')
            continue
        need(c.get('accepted') is True and c['protocol_complete'] is True and
             c['reaped'] is True and c['timed_out'] is False and c['error'] is None and
             type(c['cleanup_errors']) is list and not c['cleanup_errors'] and
             type(c['exit']) is int and c['exit'] == 0 and
             type(c['pid']) is int and c['pid'] > 0,
             'successful real child, exact protocol and complete cleanup')
        need(c['bounds'] == [5, 512 << 20, 16 << 20, 15] and
             all(type(v) is int for v in c['bounds']), 'unchanged child limits')
        need(type(c['descriptors']) is list and [d['name'] for d in c['descriptors']] == list(DESCRIPTORS) and
             all(type(d['fd']) is int and d['closed'] is True for d in c['descriptors']) and
             len({d['fd'] for d in c['descriptors']}) == len(DESCRIPTORS) and
             c['descriptors'][0]['fd'] == 3 and all(d['fd'] > 3 for d in c['descriptors'][1:]),
             'all five real owned descriptors closed')
        need(set(c['captures']) == CAPTURES and all(
             type(v.get('bytes')) is int and 0 <= v['bytes'] <= 16 << 20 and
             type(v.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', v['sha256'])
             for v in c['captures'].values()) and c['captures']['record']['bytes'] == 0,
             'complete bounded captures and no observer record in timing')
        times = [c[k] for k in ('start_ns', 'candidate_go_ns', 'candidate_done_ns', 'deadline_ns', 'interval_ns')]
        need(all(type(v) is int for v in times), 'actual integer parent clock observations')
        start, go, done, deadline, interval = times
        need(0 < start <= go < done <= deadline and deadline - start == 15 * 10**9 and
             interval == done - go and interval > 0, 'literal GO-write through DONE-read interval')
        need(type(c['duration_ns']) is int and start + c['duration_ns'] > done and
             start > previous_cleanup, 'positive complete invocation duration and serial child order')
        previous_cleanup = start + c['duration_ns']
        t = c['terminal_validation']
        need(t['accepted'] is True and t['profile'] == PROFILE[lane] and
             type(t['operations']) is int and t['operations'] == n and
             type(t['pid']) is int and t['pid'] == c['pid'] and
             type(t['cpu']) is int and t['cpu'] == receipt['cpu'] and
             type(t['output_bytes']) is int and t['output_bytes'] == c['captures']['stdout']['bytes'] and
             t['output_sha256'] == c['captures']['stdout']['sha256'],
             'strict terminal result joins the actual process and output')
        need(type(sample['interval_ns']) is int and sample['interval_ns'] == interval and
             type(sample['pid']) is int and sample['pid'] == c['pid'] and
             sample['terminal_sha256'] == digest(t), 'numeric sample joins complete terminal result')
        accepted.append(sample)
    complete = receipt['status'] == 'passed'
    if complete:
        need(len(samples) == len(ORDER) == len(accepted) and
             names == [command_name(*row) for row in ORDER] and
             receipt['qualification_verified'] is True and receipt['source_unchanged'] is True and
             receipt['error'] is None and not receipt['final_errors'],
             'all twenty fixed children and final qualification/source custody')
    aggregates = None
    if complete:
        aggregates = []
        for n in OPERATIONS:
            for lane in PROFILE:
                values = [s['interval_ns'] for s in samples if s['operations'] == n and s['lane'] == lane]
                need(len(values) == 5, 'all five unfiltered samples in every population')
                aggregates.append(dict(operations=n, lane=lane, samples=5, min_ns=min(values),
                                       median_ns=int(statistics.median(values)), max_ns=max(values)))
    return dict(planned_subjects=len(ORDER), attempted_subjects=len(samples),
                accepted_subjects=len(accepted), all_samples_accepted=complete,
                aggregates=aggregates, performance_credit=complete,
                samples=samples, command_rows_sha256=digest(commands),
                interval='Parent clock immediately before GO write through complete DONE read; includes IPC, scheduling, read return, first fault/handler, body, close and finish.',
                labels={'1': 'first-entry workload round-trip', '256': 'eligible-operation batch'},
                limits='Five fixed alternating pairs per operation count. No discarded samples, overhead subtraction, cache-cold guarantee, isolated retirement or pure interior steady-state latency.')
