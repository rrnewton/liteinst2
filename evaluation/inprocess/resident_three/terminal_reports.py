"""Complete typed D3/flags terminal protocol; owner-frame equivalence is separate."""
import hashlib
import json
from page_selected import need
import persistent_direct_frontier_reports as prior

ORDER = '''MAPS_CURRENT_TF MAPS_VIEW LOADER NATIVE_PAIR NATIVE SELECTED_EFFECT
CPUID_NX REPEAT_LEASE ONESHOT RSEQ RSEQ_NATIVE RSEQ_BOUNDARY RSEQ_BTRFS_TTY_QUERY
CHAIN RUN RUN_REUSE TRACE_RUN UNROLLED_HASH SCALAR_REUSE SCALAR_REGION
LINKED_EPOCH_REUSE LINKED_EPOCH LINKED_NATIVE_PROBE PERSISTENT_SUBENTRY
PERSISTENT_UNREGISTERED FLAG_STACK'''.split()
FLAGS = 'version entries completed publications hits unexpected failure_code before_pc after_pc unplanned_pc'.split()
ZERO = 'status failure_code detail_abs detail_negative first_error first_detail_abs first_detail_negative error unexpected'.split()
PREFIX = b'LI2_FLAG_STACK '


def check(stderr, *, expected_repeat=None):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete runtime terminal stream')
    lines = stderr[:-1].split(b'\n')
    parts = [line.partition(b' ') for line in lines]
    names = [part[0] for part in parts]
    order = ['LI2_' + name for name in ORDER]
    repeat_present = b'LI2_REPEAT' in names
    need(expected_repeat is None or (type(expected_repeat) is bool and repeat_present == expected_repeat),
         'supplied control retains the actual original optional-row population')
    if repeat_present:
        order.insert(order.index('LI2_REPEAT_LEASE'), 'LI2_REPEAT')
    need(names == [name.encode() for name in order] and
         all(part[1] == b' ' and 0 < len(line) + 1 <= 4096 and b'\r' not in line
             for part, line in zip(parts, lines)),
         'whole exact source-owned report population and order, no unknown stderr')
    decode = prior.maps_view.pair.pair_reports.rseq.decode
    actual = {name.decode(): decode(body) for name, _, body in parts}
    for (name, _, _), line in zip(parts, lines):
        row = actual[name.decode()]
        need(type(row) is dict and name + b' ' +
             json.dumps(row, separators=(',', ':'), allow_nan=False).encode() == line,
             'complete canonical duplicate-free runtime row')
    flags = actual['LI2_FLAG_STACK']
    need(list(flags) == FLAGS and all(type(v) is int and 0 <= v < 1 << 64 for v in flags.values()) and
         flags['version'] == 1, 'exact complete typed flag-stack report')
    suffix = b'\n'.join(lines[:-1]) + b'\n'
    subentry, suffix = prior.subentry_split(suffix)
    native_probe, suffix = prior.probe_row_split(suffix)
    group, suffix = prior.split(suffix)
    linked, linked_reuse, suffix = prior.prior.split(suffix)
    scalar, scalar_reuse, suffix = prior.reuse.split(suffix)
    unrolled, suffix = prior.unrolled.split(suffix)
    current, suffix = prior.current.split_current(suffix)
    view, original = prior.maps_view.split_report(suffix, 'maintained')
    parsed = prior.old.reports(original)
    prior.old.extensions(parsed)
    # Keep every old typed parser and its actual startup/counter equations. Do
    # not invoke their other fixtures' full-state/operation-count comparators.
    parsed.update(subentry=subentry, native_probe=native_probe, group=group,
                  linked=linked, linked_reuse=linked_reuse, scalar_region=scalar,
                  scalar_reuse=scalar_reuse, unrolled=unrolled, current_tf=current,
                  maps_view=view, flag_stack=flags)
    for name, row in actual.items():
        need(all(type(row[k]) is int and row[k] == 0 for k in ZERO if k in row),
             'actual successful terminal outcome without hidden error: ' + name)
    need(flags['entries'] == flags['completed'] == flags['publications'] + flags['hits'] > 0 and
         flags['publications'] > 0 and flags['unexpected'] == flags['failure_code'] == flags['unplanned_pc'] == 0 and
         0 < flags['before_pc'] < (1 << 64) - 1 and flags['after_pc'] == flags['before_pc'] + 1,
         'each actual one-byte flag-stack entry completed at its original next PC')
    loader = parsed['loader']
    need(loader['last_syscall'] in (60, 231) and loader['step_route'] == 0 and
         loader['source_syscalls'] == loader['syscalls'] == loader['forwarded'] > 0,
         'successful original exit syscall and no pending execution route')
    # report() emits this row iff selected_repeat_attempts != 0. The unchanged
    # old parser validates the full row and positive attempts when it exists.
    need((parsed['repeat'] is not None) == (b'LI2_REPEAT' in names),
         'exact source-owned optional REP report presence')
    return dict(report_rows=len(lines), report_names=order, repeat_present=repeat_present,
                stderr_sha256=hashlib.sha256(stderr).hexdigest(), flag_stack=flags,
                loader_exit=loader['last_syscall'], semantic_audit_pending=True,
                qualification_credit=False, performance_credit=False)


def controls(stderr):
    """Causal supplied-stream controls; no guest/reader replay or native credit."""
    original = check(stderr)
    lines = stderr[:-1].split(b'\n')
    decode = prior.maps_view.pair.pair_reports.rseq.decode
    refused = []

    def reject(name, candidate):
        need(candidate != stderr, 'actual changed report stimulus: ' + name)
        try:
            check(candidate, expected_repeat=original['repeat_present'])
        except ValueError:
            refused.append(name)
        else:
            raise ValueError('accepted malformed terminal stream: ' + name)

    def stream(rows):
        return b'\n'.join(rows) + b'\n'

    for index, line in enumerate(lines):
        prefix, _, body = line.partition(b' ')
        label = prefix.decode()
        reject(label + '_missing', stream(lines[:index] + lines[index + 1:]))
        reject(label + '_duplicate', stream(lines[:index] + [line] + lines[index:]))
        row = decode(body)
        extra = dict(row); extra['unrecognized'] = 0
        reject(label + '_extra_field', stream(lines[:index] + [prefix + b' ' +
               json.dumps(extra, separators=(',', ':')).encode()] + lines[index + 1:]))
        wrong = dict(row); wrong['version'] = True
        reject(label + '_bool_version', stream(lines[:index] + [prefix + b' ' +
               json.dumps(wrong, separators=(',', ':')).encode()] + lines[index + 1:]))
    reject('truncated', stderr[:-1])
    reject('unknown_row', stderr + b'LI2_UNKNOWN {}\n')
    reject('wrong_order', stream([lines[1], lines[0]] + lines[2:]))
    reject('duplicate_key', stream(lines[:-1] + [lines[-1][:-1] + b',"version":1}']))
    flags = decode(lines[-1].partition(b' ')[2])
    for key in ('entries', 'completed', 'publications', 'hits', 'unexpected', 'failure_code',
                'before_pc', 'after_pc', 'unplanned_pc'):
        changed = dict(flags); changed[key] ^= 1
        reject('flags_' + key, stream(lines[:-1] + [PREFIX +
               json.dumps(changed, separators=(',', ':')).encode()]))
    for index, line in enumerate(lines):
        prefix, _, body = line.partition(b' '); row = decode(body)
        if 'status' in row:
            changed = dict(row); changed['status'] = 125
            reject(prefix.decode() + '_failed_status', stream(lines[:index] + [prefix + b' ' +
                   json.dumps(changed, separators=(',', ':')).encode()] + lines[index + 1:]))
    expected = 4 * len(lines) + 13 + sum('status' in decode(line.partition(b' ')[2]) for line in lines)
    need(len(refused) == len(set(refused)) == expected and check(stderr) == original,
         'all distinct causal controls and unchanged original terminal stream')
    return dict(controls=expected, refusals=refused, native_operations=0,
                stderr_sha256=original['stderr_sha256'])
