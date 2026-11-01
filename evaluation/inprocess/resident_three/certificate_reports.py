"""Additional SBC observations. Failed controls remain failed prefixes.

Successful callers must still apply every original D3 app/owner/pair/control
check to strip(stderr)[0]. This module grants no such frame or owner credit.
"""
import copy
import hashlib
import json
import struct
from page_selected import need
from resident_three import terminal_reports as terminal
from resident_three.terminal_reports import prior, ORDER, FLAGS

SIZE = 434176
MASK = 0xffffffffbffbfae7
COUNTERS = "version status failure_code differential bytes_per_complete_scan decisions hits misses full_scans full_scan_errors disagreements full_scan_bytes postseal_bytes issues invalidations abort_invalidations live_queries live_query_errors last_failure last_full_result".split()
COUNT_WORDS = "decisions hits misses full_scans full_scan_errors disagreements full_scan_bytes issues invalidations abort_invalidations live_queries live_query_errors postseal_bytes".split()
EVENT = "initialized stage fired complete stopped claim_token claim_id claim_serial claim_cell claim_member claimed_before claimed_after invalidated_epoch writer_token mirror_write_epoch issued_serial token phase slot bank generation domain_refs closed_before closed_after mirror_offset mirror_before mirror_after close_attempted close_result decision_result candidate_before candidate_after test_detail query_calls query_error".split()
TEST = "version status failure_code control event old current before after failed_query".split()
PREFIX = b"LI2_SEALED_BYTE_CERTIFICATE "
TEST_PREFIX = b"LI2_SEALED_BYTE_CERTIFICATE_TEST "
U64 = (1 << 64) - 1


def strip(stderr):
    need(type(stderr) is bytes and stderr.endswith(b"\n"), "complete SBC terminal bytes")
    lines = stderr[:-1].split(b"\n")
    positions = [i for i, line in enumerate(lines) if line.startswith(PREFIX)]
    need(len(positions) == 1, "one actual SBC counter row")
    at = positions[0]
    need(at + 2 < len(lines) and lines[at + 1].startswith(TEST_PREFIX) and
         lines[at + 2].startswith(b"LI2_PERSISTENT_SUBENTRY ") and
         sum(line.startswith(TEST_PREFIX) for line in lines) == 1,
         "exact counter/test rows immediately before original subentry row")
    decoded = []
    for line, prefix, keys in ((lines[at], PREFIX, COUNTERS), (lines[at + 1], TEST_PREFIX, TEST)):
        row = prior.maps_view.pair.pair_reports.rseq.decode(line[len(prefix):])
        need(len(line) + 1 <= 4096 and b"\r" not in line and type(row) is dict and
             list(row) == keys and prefix + json.dumps(row, separators=(",", ":"), allow_nan=False).encode() == line,
             "complete canonical ordered SBC observation")
        decoded.append(row)
    row, test = decoded
    need(all(type(v) is int and 0 <= v <= U64 for v in row.values()) and
         all(type(test[k]) is int and 0 <= test[k] <= U64 for k in TEST[:4]),
         "literal unsigned SBC fields")
    for key, count in (("event", len(EVENT)), ("old", 25), ("current", 25),
                       ("before", 15), ("after", 15), ("failed_query", 37)):
        need(type(test[key]) is list and len(test[key]) == count and
             all(type(v) is int and 0 <= v <= U64 for v in test[key]), "whole literal SBC array " + key)
    return b"\n".join(lines[:at] + lines[at + 2:]) + b"\n", row, test


def certificate(words, pid):
    c = dict(valid=words[0] & 0xffffffff, slot=words[0] >> 32,
             bank=words[1] & 0xffffffff, reserved=words[1] >> 32,
             serial=words[2], epoch=words[3], generation=words[4], build=words[5],
             owner=words[6], mirror=words[7], mirror_bytes=words[8],
             session=words[9:15], backing=words[15:])
    fd, device, inode, size, generation, code, proof, code_bytes, proof_bytes, live = c['backing']
    need(c['valid'] == 1 and c['slot'] < 2 and c['bank'] < 2 and c['reserved'] == 0 and
         all(c[k] > 0 for k in ('serial', 'epoch', 'generation', 'build', 'owner', 'mirror')) and
         c['mirror_bytes'] == 362656 and fd <= 0x7fffffff and inode > 0 and
         size == SIZE and generation == c['generation'] and code_bytes == 69632 and
         proof_bytes == 364544 and live == 0x100000001 and
         code > 0 and proof > 0 and not ((code | proof) & 4095) and
         code < (1 << 47) - code_bytes and proof < (1 << 47) - proof_bytes and
         (code + code_bytes <= proof or proof + proof_bytes <= code) and
         c['session'][0] == c['session'][1] == pid and pid > 0 and c['session'][2] == 0 and
         c['session'][3] & 96 == 96 and c['session'][4] == MASK and c['session'][5] == 0x100000001,
         'actual whole issued certificate/session/backing geometry')
    return c


def counts(words):
    c = dict(zip(COUNT_WORDS, words[:13]))
    c.update(initialized=words[13] & 0xffffffff, last_failure=words[13] >> 32,
             last_full_result=words[14] & 0xffffffff, reserved=words[14] >> 32)
    need(c['initialized'] == 1 and c['reserved'] == 0, 'actual initialized full counter snapshot')
    return c


def failed_prefix(stderr, *, expected_repeat=None):
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
    parsed = prior.old.reports(original, nx_page_boundary=True)
    prior.old.extensions(parsed)
    # Keep every old typed parser and its actual startup/counter equations. Do
    # not invoke their other fixtures' full-state/operation-count comparators.
    parsed.update(subentry=subentry, native_probe=native_probe, group=group,
                  linked=linked, linked_reuse=linked_reuse, scalar_region=scalar,
                  scalar_reuse=scalar_reuse, unrolled=unrolled, current_tf=current,
                  maps_view=view, flag_stack=flags)
    return actual, parsed


def check(stderr, *, exit_status, control, differential, pid):
    need(type(control) is int and control in range(4) and type(pid) is int and pid > 0 and type(differential) is bool and
         (control == 0 or differential), 'exact requested certificate experiment profile')
    base, c, t = strip(stderr); e = dict(zip(EVENT, t['event']))
    need(c['version'] == t['version'] == 1 and c['status'] == t['status'] == exit_status and
         t['control'] == control and c['differential'] == int(differential) and
         c['bytes_per_complete_scan'] == SIZE and c['decisions'] == c['hits'] + c['misses'] and
         c['full_scans'] == (c['decisions'] if differential else c['misses']) and
         c['full_scan_bytes'] == (c['full_scans'] - c['full_scan_errors']) * SIZE and
         c['postseal_bytes'] == c['issues'] * SIZE and c['issues'] > 0 and
         c['invalidations'] >= c['issues'] and
         c['live_queries'] >= 3 * c['issues'] + 3 * c['hits'] + c['live_query_errors'] and
         e['initialized'] == 1,
         'unchanged every-decision differential/full-byte counter equations')
    need(e['stage'] in (0, 4), 'replacement either absent or complete through real new issuance')
    if e['stage'] == 4:
        old = certificate(t['old'], pid); current = certificate(t['current'], pid)
        need(old['slot'] == current['slot'] and old['owner'] == current['owner'] and
             old['mirror'] == current['mirror'] and old['mirror_bytes'] == current['mirror_bytes'] and
             old['session'] == current['session'] and
             0 < e['claim_serial'] < e['claim_token'] == e['writer_token'] == current['build'] and
             e['claim_id'] > 0 and e['claim_cell'] < 3 and e['claim_member'] < 2 and
             e['claimed_before'] < 4 and not e['claimed_before'] & (1 << e['claim_member']) and
             e['claimed_after'] == e['claimed_before'] | (1 << e['claim_member']) and
             old['epoch'] + 1 == e['invalidated_epoch'] == e['mirror_write_epoch'] == current['epoch'] and
             old['serial'] < e['issued_serial'] == current['serial'] <= c['issues'] and
             old['generation'] < current['generation'] and old['build'] < current['build'],
             'genuine completion claim then invalidation before mirror write and advancing issue')
    else:
        need(t['old'] == [0] * 25 and all(e[k] == 0 for k in EVENT[5:16]),
             'no invented replacement witness')
    if control == 0:
        need(e['stage'] == 4, 'this experiment requires the complete actual replacement witness')
        need(exit_status == c['failure_code'] == t['failure_code'] == 0 and c['hits'] > 0 and
             c['full_scan_errors'] == c['disagreements'] == c['abort_invalidations'] ==
             c['live_query_errors'] == c['last_failure'] == c['last_full_result'] == 0 and
             all(e[k] == 0 for k in ('fired', 'complete', 'stopped')) and
             all(e[k] == 0 for k in EVENT[16:]) and t['before'] == t['after'] == [0] * 15 and
             t['failed_query'] == [0] * 37 and (e['stage'] == 4 or t['current'] == [0] * 25),
             'observational successful lane has qualifying hits and no injected control')
        terminal.check(base)
        return dict(scope='byte_certificate_success_observation', control=0, differential=differential,
                    counters=c, replacement_observed=e['stage'] == 4, full_state_audit_required=True,
                    independent_identity_join_required=True, retained_backing_query_credit=False,
                    avoided_scan_bytes=c['hits'] * SIZE if not differential else 0,
                    qualification_credit=False, performance_credit=False)
    current = certificate(t['current'], pid); before, after = counts(t['before']), counts(t['after'])
    need(exit_status == 125 and c['failure_code'] == t['failure_code'] == 3303 and
         e['fired'] == e['complete'] == e['stopped'] == e['closed_before'] == e['closed_after'] ==
         e['candidate_before'] == 1 and e['token'] >= current['build'] and e['phase'] in (7, 8) and
         e['slot'] == current['slot'] and e['bank'] == current['bank'] and
         e['generation'] == current['generation'] and current['serial'] <= c['issues'] and e['domain_refs'] <= 1 and
         e['test_detail'] == 192 + control,
         'actual selected closed/NX fault decision stops through ordinary failed-owner path')
    need(before['full_scan_errors'] == before['disagreements'] == before['live_query_errors'] ==
         before['abort_invalidations'] == before['last_failure'] == before['last_full_result'] == 0 and
         all(c[k] == after[k] for k in COUNT_WORDS if k != 'abort_invalidations') and
         c['last_failure'] == after['last_failure'] and c['last_full_result'] == after['last_full_result'] and
         after['abort_invalidations'] == 0 and c['abort_invalidations'] == 1,
         'complete pre-injection counters and unchanged decision-to-terminal counters except actual abort')
    delta = dict(decisions=1, hits=int(control == 2), misses=int(control != 2), full_scans=1,
                 full_scan_errors=int(control == 2), disagreements=int(control == 2),
                 full_scan_bytes=0 if control == 2 else SIZE, issues=0, invalidations=0,
                 abort_invalidations=0, live_queries={1: 0, 2: 3, 3: 1}[control],
                 live_query_errors=int(control == 3), postseal_bytes=0)
    need(all(after[k] == before[k] + value for k, value in delta.items()) and
         after['last_failure'] == {1: 0, 2: 2, 3: 3}[control] and
         after['last_full_result'] == (3303 if control == 2 else 0) and
         e['decision_result'] == (0 if control == 1 else 3303) and
         e['candidate_after'] == int(control != 1),
         'exact unchanged decision result and full-scan/query delta for the selected control')
    if control == 1:
        need(e['stage'] == 4 and current['build'] == e['claim_token'] == e['token'],
             'replayed old certificate comes from this genuine victim/replacement')
    if control == 2:
        need(e['mirror_offset'] == current['mirror_bytes'] - 1 and e['mirror_before'] < 256 and
             e['mirror_after'] == e['mirror_before'] ^ 1,
             'one observed comparison-relevant mirror byte changed under the trusted fault hook')
    else:
        need(e['mirror_offset'] == e['mirror_before'] == e['mirror_after'] == 0,
             'no mirror mutation in other controls')
    if control == 3:
        need(e['close_attempted'] == e['query_calls'] == 1 and e['close_result'] == 0 and
             e['query_error'] == 304, 'actual sealed fd close followed by actual identity-query refusal')
        # Literal complete initialized query after F_GET_SEALS/fstat both EBADF.
        # The query returns before maps acquisition; every other byte stays zero.
        expected = bytearray(296)
        struct.pack_into('<QQ', expected, 0, current['backing'][5], current['backing'][5] + 69632)
        struct.pack_into('<IIiii', expected, 40, 1, 0, 1, 0, 304)
        struct.pack_into('<q', expected, 64, 1)
        struct.pack_into('<II', expected, 160, 1, 1)
        struct.pack_into('<10Q', expected, 168, *current['backing'])
        struct.pack_into('<qq', expected, 256, -9, -9)
        need(struct.pack('<37Q', *t['failed_query']) == expected,
             'whole real failed sealed query including exact identity and untouched maps/alias fields')
    else:
        need(e['close_attempted'] == e['close_result'] == e['query_calls'] == e['query_error'] == 0 and
             t['failed_query'] == [0] * 37, 'no fd close/query failure in other controls')
    rows, parsed = failed_prefix(base)
    for row in rows.values():
        if 'status' in row:
            need(row['status'] == 125, 'all global report outcomes preserve actual failed prefix')
    group, loader = parsed['group'], parsed['loader']
    need(group['status'] == loader['status'] == 125 and
         group['failure_code'] == loader['failure_code'] == group['first_error'] == 3303 and
         group['detail_abs'] == loader['detail_abs'] == e['test_detail'] and
         group['detail_negative'] == loader['detail_negative'] == 0 and group['phase'] == 15 and
         group['active'] == group['unexpected'] == group['permit'] == 0 and group['busy'] == 1 and
         group['serial'] == e['token'] and group['selected_slot'] == e['slot'],
         'actual original owner and loader retain exact failed terminal identity')
    return dict(scope='byte_certificate_expected_refusal_prefix', control=control, differential=True,
                application_completed=False, exit_status=125, counters=c, event=e,
                native_or_full_frame_credit=False, qualification_credit=False, performance_credit=False)


def controls(stderr, *, exit_status, control, differential, pid):
    """Additive supplied-observation controls; all old D3 controls stay separate."""
    original = check(stderr, exit_status=exit_status, control=control, differential=differential, pid=pid)
    base, c, t = strip(stderr); refused = []
    lines = stderr[:-1].split(b'\n'); at = next(i for i, x in enumerate(lines) if x.startswith(PREFIX))
    def reject(name, row, test):
        changed = lines[:]
        changed[at] = PREFIX + json.dumps(row, separators=(',', ':')).encode()
        changed[at + 1] = TEST_PREFIX + json.dumps(test, separators=(',', ':')).encode()
        try:
            check(b'\n'.join(changed) + b'\n', exit_status=exit_status, control=control, differential=differential, pid=pid)
        except ValueError:
            refused.append(name)
        else:
            raise ValueError('accepted certificate supplied mutation ' + name)
    for key in ('version', 'status', 'failure_code', 'differential', 'bytes_per_complete_scan',
                'decisions', 'hits', 'misses', 'full_scans', 'full_scan_bytes', 'postseal_bytes',
                'issues', 'abort_invalidations', 'last_failure', 'last_full_result'):
        row = copy.deepcopy(c); row[key] ^= 1; reject('counter_' + key, row, copy.deepcopy(t))
    for key in ('version', 'status', 'failure_code', 'control'):
        test = copy.deepcopy(t); test[key] ^= 1; reject('test_' + key, copy.deepcopy(c), test)
    for key in ('initialized', 'fired', 'complete', 'stopped', 'closed_before', 'closed_after', 'test_detail'):
        test = copy.deepcopy(t); test['event'][EVENT.index(key)] ^= 1
        reject('event_' + key, copy.deepcopy(c), test)
    if control:
        for key in ('token', 'phase', 'slot', 'bank', 'generation', 'candidate_before', 'candidate_after'):
            test = copy.deepcopy(t); test['event'][EVENT.index(key)] = U64
            reject('identity_' + key, copy.deepcopy(c), test)
        for key in ('before', 'after'):
            test = copy.deepcopy(t); test[key][0] ^= 1
            reject('actual_decision_' + key, copy.deepcopy(c), test)
        test = copy.deepcopy(t); test['current'][20] ^= 1
        reject('actual_backing_alignment', copy.deepcopy(c), test)
        test = copy.deepcopy(t); test['failed_query'][32] ^= 1
        reject('actual_failed_query', copy.deepcopy(c), test)
        test = copy.deepcopy(t); test['event'][EVENT.index('decision_result')] ^= 1
        reject('actual_decision_result', copy.deepcopy(c), test)
    test = copy.deepcopy(t)
    for name in ('old', 'current'):
        if any(test[name]): test[name][13] ^= 1
    reject('exact_application_mask_both_certificates', copy.deepcopy(c), test)
    if control == 0:
        test = copy.deepcopy(t); test['old'] = test['current'] = [0] * 25
        test['event'][EVENT.index('stage')] = 0
        for name in EVENT[5:16]: test['event'][EVENT.index(name)] = 0
        reject('actual_replacement_cannot_be_omitted', copy.deepcopy(c), test)
    expected = 28 if control == 0 else 39
    need(len(refused) == len(set(refused)) == expected and
         check(stderr, exit_status=exit_status, control=control, differential=differential, pid=pid) == original,
         'complete distinct additive certificate controls and unchanged supplied input')
    return dict(controls=expected, refusals=refused, native_operations=0,
                stderr_sha256=hashlib.sha256(stderr).hexdigest())
