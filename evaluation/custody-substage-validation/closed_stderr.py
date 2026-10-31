"""Private uncommitted custody-substage candidate diagnostics, never a runtime acceptance predicate.

The caller must first authenticate closed ownership, raw stream/source pins and
the native outcome. `expected` is independently authenticated READY/retired
identity and NormalTotals, not values learned from this diagnostic header.
Returned original_stderr + diagnostic_stderr is always the unchanged input.
No file access, project imports, clock reads, process calls or outcome promotion.
"""
import re

REVISION = 'bcbbdfe2b54c58eae0d35ddf34c4bb9238b0c959'
STREAM_CAP = 8 * 1024 * 1024
BLOCK_CAP = 16 * 1024
U64 = (1 << 64) - 1
U128 = (1 << 128) - 1
D64 = r'(?:0|[1-9][0-9]{0,19})'
D128 = r'(?:0|[1-9][0-9]{0,38})'
OPTION = r'(?:none|' + D128 + r')'
TOTALS = ('entered', 'ret_observed', 'confirmed', 'completed', 'unsampled')
WORKER = ('receive', 'dispatch', 'input', 'setup', 'before_custody', 'invoke',
          'after_custody', 'checkpoint_custody', 'checkpoint', 'reply', 'cleanup')
CUSTODY_PARENTS = ('before_custody', 'after_custody', 'checkpoint_custody')
CUSTODY_STAGES = ('identity', 'maps_read', 'maps_parse', 'mapping', 'tasks', 'stamp',
                  'file_read', 'file_compare', 'live_bytes', 'remainder')
MARKS = ('poll', 'poll_returned', 'poll_arm', 'reply_history', 'retire', 'input',
         'dispatch', 'finalize', 'write', 'wait_bound', 'wait', 'end')
DECISIONS = ('arm', 'stop', 'wait', 'refused', 'other')
REPLIES = ('batch', 'flushed', 'finished', 'other')
BUCKET = (r'valid=(true|false) spans=(' + D64 + r') sum_ns=(' + D128 +
          r') min_ns=(' + OPTION + r') max_ns=(' + OPTION + r')')
RESERVED = re.compile(rb'(?m)^[ \t]*(?:worker_phase|worker_scope|custody_|controller_phase_totals|phase_totals)')


class DiagnosticError(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise DiagnosticError(reason)


def uint(value, maximum):
    need(type(value) is str and re.fullmatch(r'0|[1-9][0-9]*', value), 'decimal integer')
    need(len(value) <= len(str(maximum)), 'integer width')
    number = int(value)
    need(number <= maximum, 'integer overflow')
    return number


def optional(value):
    return None if value == 'none' else uint(value, U128)


def take(pattern, text):
    match = re.match(pattern, text)
    need(match is not None, 'exact field order or literal')
    return match.groups(), text[match.end():]


def literal(text, prefix):
    need(text.startswith(prefix), 'exact literal')
    return text[len(prefix):]


def bucket(text):
    values, rest = take(BUCKET, text)
    valid, count, total, low, high = values
    count, total, low, high = uint(count, U64), uint(total, U128), optional(low), optional(high)
    if count == 0:
        need(total == 0 and low is None and high is None, 'empty bucket')
    else:
        need(low is not None and high is not None and low <= high, 'bucket extrema')
        # Python integers do not wrap; do not impose a new overflow on products.
        need(count * low <= total <= count * high, 'bucket sum/extrema')
    return dict(valid=valid == 'true', spans=count, sum_ns=total, min_ns=low, max_ns=high), rest


def parenthesized(text):
    value, rest = bucket(literal(text, '('))
    return value, literal(rest, ')')


def count_map(text, names):
    result = {}
    for name in names:
        (raw,), text = take(re.escape(name) + r':(' + D64 + r'),', text)
        result[name] = uint(raw, U64)
    return result, text


def worker(lines, expected):
    unavailable = {
        'worker_phase_v1 status=UNAVAILABLE reason=completion_not_authenticated':
            ('UNAVAILABLE', 'completion_not_authenticated'),
        'worker_phase_v1 status=UNAVAILABLE reason=no_completed_snapshot':
            ('UNAVAILABLE', 'no_completed_snapshot'),
        'worker_phase_v1 status=INVALID reason=completion_identity_or_totals':
            ('INVALID', 'completion_identity_or_totals'),
    }
    if len(lines) == 1 and lines[0] in unavailable:
        status, reason = unavailable[lines[0]]
        return dict(status=status, reason=reason)
    need(len(lines) == 14, 'worker row count')
    pattern = r'worker_phase_v1 diagnostic_only=true pid=(' + D64 + r') tid=(' + D64 + r') terminal_totals=NormalTotals \{ '
    pattern += ', '.join(re.escape(name) + ': (' + D64 + ')' for name in TOTALS) + r' \}'
    fields, rest = take(pattern, lines[0])
    need(rest == '', 'worker header tail')
    pid, tid = uint(fields[0], (1 << 32) - 1), uint(fields[1], U64)
    totals = {name: uint(raw, U64) for name, raw in zip(TOTALS, fields[2:])}
    need(pid > 0 and tid > 0, 'positive identity')
    need(type(expected) is dict and set(expected) == {'pid', 'tid', 'totals'}, 'independent retired identity required')
    for name, maximum in (('pid', (1 << 32) - 1), ('tid', U64)):
        need(type(expected[name]) is int and 0 < expected[name] <= maximum, 'expected identity domain')
    need(type(expected['totals']) is dict and set(expected['totals']) == set(TOTALS), 'expected total fields')
    need(all(type(value) is int and 0 <= value <= U64 for value in expected['totals'].values()), 'expected total domain')
    need(expected == dict(pid=pid, tid=tid, totals=totals), 'retired identity/totals mismatch')
    need(lines[1] == 'worker_scope=after_ready_send_through_detach_postflight spans_not_operations=true wall_includes_observer_and_scheduler_cost=true', 'worker scope')
    fields, rest = take(r'worker_phases_v1 diagnostic_only status=(VALID|INVALID) bucket_scope=(complete_partition|retained_valid_prefix) window_start_ns=(' + OPTION + r') observed_end_ns=(' + OPTION + r') partition_ns=(' + OPTION + r')', lines[2])
    need(rest == '', 'worker window tail')
    status, scope, start, end, partition = fields
    start, end, partition = optional(start), optional(end), optional(partition)
    need(start in (None, 0) and (start is not None or end is None), 'worker start representation')
    buckets = {}
    for name, line in zip(WORKER, lines[3:]):
        value, rest = bucket(literal(line, 'worker_phase ' + name + ' '))
        need(rest == '', 'worker bucket tail')
        buckets[name] = value
    if status == 'VALID':
        need(scope == 'complete_partition' and start == 0 and end is not None and partition == end, 'worker complete window')
        need(all(value['valid'] for value in buckets.values()), 'invalid complete bucket')
        need(sum(value['sum_ns'] for value in buckets.values()) == partition, 'worker partition conservation')
    else:
        need(scope == 'retained_valid_prefix' and partition is None, 'invalid worker is not a partition')
    return dict(status=status, pid=pid, tid=tid, totals=totals, bucket_scope=scope,
                window_start_ns=start, observed_end_ns=end, partition_ns=partition, buckets=buckets)


def custody(lines, work):
    need(len(lines) == 14, 'custody row count')
    fields, rest = take(r'custody_substages_v1 status=(VALID|INVALID|UNAVAILABLE) started=(' + D64 + r') completed=(' + D64 + r') partition_ns=(' + OPTION + r') scope=nested_three_custody_phases_not_additive spans_not_operations=true', lines[0])
    need(rest == '', 'custody header tail')
    status, started, completed, partition = fields
    started, completed, partition = uint(started, U64), uint(completed, U64), optional(partition)
    parents, stages = {}, {}
    for names, rows, prefix, target in (
            (CUSTODY_PARENTS, lines[1:4], 'custody_parent ', parents),
            (CUSTODY_STAGES, lines[4:], 'custody_stage ', stages)):
        for name, line in zip(names, rows):
            value, tail = bucket(literal(line, prefix + name + ' '))
            need(tail == '', 'custody bucket tail')
            target[name] = value
    if status in ('VALID', 'UNAVAILABLE'):
        need(work['status'] == 'VALID', 'custody requires valid containing worker')
        need(started == completed, 'custody completed pass counts')
        need(all(b['valid'] for b in list(parents.values()) + list(stages.values())), 'invalid complete custody bucket')
        parent_sum, stage_sum = sum(b['sum_ns'] for b in parents.values()), sum(b['sum_ns'] for b in stages.values())
        need(parent_sum <= U128 and stage_sum == parent_sum, 'custody conservation/overflow')
        need(sum(b['spans'] for b in parents.values()) == completed, 'custody parent counts')
        for name, value in parents.items():
            outer = work['buckets'][name]
            need(value['spans'] == outer['spans'] and value['sum_ns'] <= outer['sum_ns'], 'custody parent containment')
        if status == 'VALID':
            need(completed > 0 and partition == parent_sum, 'custody complete partition')
        else:
            need(completed == 0 and partition is None, 'unavailable custody is not measured zero')
            need(all(b['spans'] == 0 for b in list(parents.values()) + list(stages.values())), 'unavailable custody has no spans')
    else:
        need(partition is None, 'invalid custody is only retained prefix')
    return dict(status=status, started=started, completed=completed, partition_ns=partition,
                parents=parents, stages=stages, scope='NESTED_NOT_ADDITIVE_WALL_SPANS')


def controller(line):
    if line == ' controller_phase_totals_v1=[status=UNAVAILABLE reason=disabled]':
        return dict(status='UNAVAILABLE', reason='disabled')
    fields, text = take(r' controller_phase_totals_v1=\[status=(OBSERVED|INVALID|UNAVAILABLE) started=(' + D64 + r') completed=(' + D64 + r') current=(0|1) zero_progress_completed=(' + D64 + r') reply_calls=(' + D64 + r') decisions=\{', line)
    status = fields[0]
    started, completed, current, zero, calls = (uint(raw, U64) for raw in fields[1:])
    decisions, text = count_map(text, DECISIONS)
    replies, text = count_map(literal(text, '} replies={'), REPLIES)
    text = literal(text, '} completed_boundary_spans_ns={')
    boundaries = {}
    for first, last in zip(MARKS, MARKS[1:]):
        name = first + '->' + last
        value, text = parenthesized(literal(text, name + ':'))
        text = literal(text, ',')
        boundaries[name] = value
    gap, text = parenthesized(literal(text, '} inter_iteration_end_to_poll_ns='))
    (unfinished,), text = take(r' unfinished_from=(none|' + '|'.join(MARKS[:-1]) + r') unfinished_through_error_ns=', text)
    if text.startswith('UNAVAILABLE'):
        tail, text = None, literal(text, 'UNAVAILABLE')
    else:
        tail, text = parenthesized(text)
    need(text == ' scope=controller_wall_observations_not_worker_or_performance]', 'controller tail')
    if current:
        need(unfinished in MARKS[1:-1], 'current last observed mark')
        last_index = MARKS.index(unfinished)
        if tail is not None:
            need(tail['spans'] == int(tail['valid']), 'unfinished tail count')
    else:
        need(unfinished == 'none' and tail is None, 'no invented current tail')
        last_index = 0
    if status in ('OBSERVED', 'UNAVAILABLE'):
        all_buckets = list(boundaries.values()) + [gap] + ([] if tail is None else [tail])
        need(all(value['valid'] for value in all_buckets), 'invalid observed controller bucket')
        need(started == completed + current and zero <= completed, 'controller iteration counts')
        need(sum(decisions.values()) == started and sum(replies.values()) <= started, 'controller branch counts')
        need(gap['spans'] == max(started - 1, 0), 'controller gap counts')
        for index, value in enumerate(boundaries.values()):
            need(value['spans'] == completed + int(current == 1 and index < last_index), 'controller boundary counts')
        if status == 'UNAVAILABLE':
            need(started == 0 and calls == 0, 'unavailable controller is not observed')
        else:
            need(started > 0, 'observed controller is empty')
    return dict(status=status, started=started, completed=completed, current=current,
                zero_progress_completed=zero, reply_calls=calls, decisions=decisions,
                replies=replies, boundaries=boundaries, gap=gap, unfinished_from=unfinished, tail=tail)


def parse(stderr, *, revision, runtime_status, expected=None):
    """Parse authenticated bytes only; preserve runtime_status verbatim.

    FAILED may have no diagnostic publication. PASS must have empty stderr and
    yields no data. A malformed suffix raises DiagnosticError, never success.
    """
    need(type(revision) is str and revision == REVISION, 'exact source revision required')
    need(type(stderr) is bytes and len(stderr) <= STREAM_CAP, 'stderr bytes/cap')
    need(type(runtime_status) is str and runtime_status in ('FAILED', 'PASS'), 'authenticated runtime outcome required')
    result = dict(revision=REVISION, runtime_status=runtime_status,
                  scope='DIAGNOSTIC_ONLY_NO_QUALIFICATION', attribution='UNAVAILABLE',
                  original_stderr=stderr, diagnostic_stderr=b'', worker=None, controller=None, custody=None)
    if runtime_status == 'PASS':
        need(stderr == b'', 'success stderr remains a refusal')
        result['reason'] = 'success_has_no_diagnostic_publication'
        return result
    marker = RESERVED.search(stderr)
    if marker is None:
        result['reason'] = 'no_diagnostic_publication'
        return result
    prefix, suffix = stderr[:marker.start()], stderr[marker.start():]
    need(0 < len(suffix) <= BLOCK_CAP and suffix.endswith(b'\n'), 'diagnostic cap/termination')
    try:
        text = suffix.decode('ascii')
    except UnicodeDecodeError as error:
        raise DiagnosticError('diagnostic ASCII') from error
    need('\r' not in text and '\0' not in text, 'diagnostic framing')
    lines = text[:-1].split('\n')
    result.update(original_stderr=prefix, diagnostic_stderr=suffix)
    if lines == ['phase_totals_v1 status=INVALID reason=format_bound']:
        result.update(attribution='INVALID', reason='format_bound')
        return result
    need(len(lines) in (2, 29), 'complete unique appended block')
    work = worker(lines[:14] if len(lines) == 29 else lines[:-1], expected)
    nested = custody(lines[14:-1], work) if len(lines) == 29 else None
    control = controller(lines[-1])
    states = (work['status'], control['status'], 'UNAVAILABLE' if nested is None else nested['status'])
    status = 'INVALID' if 'INVALID' in states else (
        'OBSERVED' if states == ('VALID', 'OBSERVED', 'VALID') else 'UNAVAILABLE')
    result.update(attribution=status, worker=work, controller=control, custody=nested)
    return result
