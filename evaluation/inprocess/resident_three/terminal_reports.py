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


def nx_page_boundary_controls():
    """Supplied typed-slot puzzles only; the full unchanged owner audit is separate."""
    import copy
    refused=[]
    for index in (0,1):
        c={('s'+str(i)+'_'+k):0 for i in (0,1) for k in prior.old.chain.SLOT}
        c.update(active=index,pending=0,error=0,proof_valid=0,fallbacks=1,event=2)
        successor=dict(phase=6,origin=2,fallback=7,generation=2,event=2,pc=0x4000,
            length=2,prepare=1,prepared=1,borrow=2,validations=1,release=1,released=1)
        predecessor=dict(phase=5,origin=1,generation=1,event=1,pc=0x2fff,length=2,
            owner_phase=5,open=3,opened=3,revoke=3,revoked=3,trace=1,post_pc=0x4000,
            borrow=1,query=1,queried=1,query_pc=0x4000,release=1,released=1)
        for i,row in ((index,successor),(index^1,predecessor)):
            c.update({('s'+str(i)+'_'+k):v for k,v in row.items()})
        need(prior.old.nx_page_boundary_slot(c,index),'complete supplied closed two-page boundary slot')
        changes=[('pending',1),('proof_valid',1),('active',index^1),('fallbacks',0)]
        changes += [('s'+str(index)+'_'+k,v) for k,v in
                    (('fallback',8),('phase',5),('origin',1),('prepared',0),('released',0),
                     ('held',1),('opened',1),('owner_phase',1),('validations',0),('borrow',1))]
        changes += [('s'+str(index^1)+'_'+k,v) for k,v in
                    (('released',0),('revoked',1),('trace',0),('query_pc',0x4001))]
        for key,value in changes:
            changed=copy.deepcopy(c);changed[key]=value
            need(changed!=c and not prior.old.nx_page_boundary_slot(changed,index),
                 'refuse malformed supplied boundary slot: '+str(index)+'/'+key)
            refused.append(str(index)+'/'+key)
        changed=copy.deepcopy(c)
        for i,key in ((index,'pc'),(index^1,'post_pc'),(index^1,'query_pc')):
            changed['s'+str(i)+'_'+key]=0x3000
        need(not prior.old.nx_page_boundary_slot(changed,index),
             'second genuinely opened page is not a new-page fallback')
        refused.append(str(index)+'/inside_second_opened_page')
    need(len(refused)==len(set(refused))==38,'all38 additional boundary-report refusals')
    return dict(controls=38,refusals=refused,native_operations=0)


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
    parsed = prior.old.reports(original, nx_page_boundary=True)
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
                stderr_sha256=original['stderr_sha256'], nx_page_boundary=nx_page_boundary_controls())


# The three old handler ledgers begin before the actual startup NOP NX/TRACE.
# D3 capture begins afterward. This is an exact source-derived offset, not an
# allowance for unexplained events. The raw SIGILL frame is not in the D3 wire.
RESIDENT_LEDGERS = ('LI2_UNROLLED_HASH', 'LI2_SCALAR_REGION', 'LI2_LINKED_EPOCH')
RESIDENT_ONESHOT_ONE = ('attempted', 'published', 'restored', 'completed', 'retired',
    'cpuid_patches', 'effect_started', 'effect_returned', 'last_completed_sequence',
    'backend_prepared', 'backend_completed', 'rseq_attempts', 'rseq_retired')
RESIDENT_ONESHOT_ZERO = ('status', 'failure_code', 'detail_abs', 'detail_negative',
    'refused', 'syscall_patches', 'rdtsc_patches', 'active_phase', 'resetting',
    'last_refused_sequence', 'rseq_phase', 'rseq_error')


def _resident_rows(stderr):
    check(stderr)  # Retain the complete original typed/ordered terminal gate.
    decode = prior.maps_view.pair.pair_reports.rseq.decode
    return {name.decode(): decode(body) for name, _, body in
            (line.partition(b' ') for line in stderr[:-1].split(b'\n'))}


def _resident_signal_join(rows, ingress):
    need(type(ingress) is tuple and len(ingress) == 6 and
         all(type(n) is int and 0 <= n < 1 << 64 for n in ingress),
         'complete typed D3 ingress vector')
    need(sum(ingress[1:]) == ingress[0] and ingress[1] >= 1 and ingress[2] >= 2 and
         ingress[3:] == (1, 0, 0), 'exact D3 partition with one owned SIGILL')
    one = rows['LI2_ONESHOT']; loader = rows['LI2_LOADER']
    need(all(type(one[k]) is int and one[k] == 1 for k in RESIDENT_ONESHOT_ONE),
         'exact one completed and retired CPUID one-shot lifecycle')
    need(all(type(one[k]) is int and one[k] == 0 for k in RESIDENT_ONESHOT_ZERO),
         'no other one-shot kind, refusal, error or pending phase')
    need(loader['source_patches'] == 1 and one['retained_records'] > 0 and
         one['generations'] == loader['generations'] == one['retained_records'] + 2,
         'same single restored source patch and two real generation advances')
    expected = (ingress[1] + 1, ingress[2] + 1) + ingress[3:]
    for name in RESIDENT_LEDGERS:
        row = rows[name]
        need(row['initialized'] == 1 and row['events'] == ingress[0] + 2 and
             row['signals'] == list(expected), 'exact startup-offset signal ledger: ' + name)
    return dict(ingress=list(ingress), startup_offset=[2, 1, 1, 0, 0, 0],
                ledgers={name: dict(events=rows[name]['events'], signals=rows[name]['signals'])
                         for name in RESIDENT_LEDGERS},
                runtime_authenticated_cpuid_sigill=1, completed_one_shot_sequence=1,
                raw_sigill_frame_retained=False, qualification_credit=False, performance_credit=False)


def resident_signals(stderr, ingress):
    """Cross-join the actual owner ingress and complete same-process reports.

    The successful one-shot path authenticates its actual #UD landing in the
    runtime. This join does not claim a retained landing PC/frame/global index.
    The owner reader separately requires adjacent entry/terminal/next events,
    so the sole SIGILL cannot be inside that exact focal interval.
    """
    return dict(_resident_signal_join(_resident_rows(stderr), ingress),
                stderr_sha256=hashlib.sha256(stderr).hexdigest())


def resident_signal_controls(stderr, ingress):
    """Additional supplied-data controls; the original terminal controls remain whole."""
    import copy
    rows = _resident_rows(stderr); original = resident_signals(stderr, ingress); refused = []

    def reject(name, changed_rows, changed_ingress, reason):
        need(changed_rows != rows or changed_ingress != ingress or
             type(changed_ingress) is not type(ingress) or
             any(type(a) is not type(b) for a, b in zip(changed_ingress, ingress)),
             'changed signal-join stimulus: ' + name)
        try:
            _resident_signal_join(changed_rows, changed_ingress)
        except ValueError as error:
            need(str(error) == reason, 'exact causal signal-join refusal: ' + name)
            refused.append(name)
        else:
            raise ValueError('accepted changed resident signal join: ' + name)
        changed_stream = b''.join(key.encode() + b' ' + json.dumps(value, separators=(',', ':')).encode() + b'\n'
                                  for key, value in changed_rows.items())
        try:
            resident_signals(changed_stream, changed_ingress)
        except ValueError:
            pass
        else:
            raise ValueError('accepted changed whole terminal/owner signal join: ' + name)

    typed = 'complete typed D3 ingress vector'
    partition = 'exact D3 partition with one owned SIGILL'
    for name, value in (('short', ingress[:-1]), ('long', ingress + (0,)), ('list', list(ingress)),
                        ('bool', (True,) + ingress[1:]), ('float', (float(ingress[0]),) + ingress[1:]),
                        ('negative', (-1,) + ingress[1:]), ('overflow', (1 << 64,) + ingress[1:])):
        reject('ingress_' + name, rows, value, typed)
    for i in range(6):
        value = list(ingress); value[i] ^= 1
        reject('ingress_word_' + str(i), rows, tuple(value), partition)
    first_ledger = 'exact startup-offset signal ledger: ' + RESIDENT_LEDGERS[0]
    for i in range(1, 6):
        value = list(ingress); value[0] += 1; value[i] += 1
        reject('coordinated_ingress_category_total_' + str(i), rows, tuple(value),
               first_ledger if i < 3 else partition)
    value = list(ingress); value[1] -= 1; value[2] += 1
    reject('ingress_segv_to_trace', rows, tuple(value), first_ledger)
    for keys, reason in ((RESIDENT_ONESHOT_ONE, 'exact one completed and retired CPUID one-shot lifecycle'),
                         (RESIDENT_ONESHOT_ZERO, 'no other one-shot kind, refusal, error or pending phase')):
        for key in keys:
            value = copy.deepcopy(rows); value['LI2_ONESHOT'][key] ^= 1
            reject('oneshot_' + key, value, ingress, reason)
    for count in (0, 2):
        value = copy.deepcopy(rows)
        for key in RESIDENT_ONESHOT_ONE:
            value['LI2_ONESHOT'][key] = count
        reject('coherent_oneshot_count_' + str(count), value, ingress,
               'exact one completed and retired CPUID one-shot lifecycle')
    for row, key in (('LI2_LOADER', 'source_patches'), ('LI2_LOADER', 'generations'),
                     ('LI2_ONESHOT', 'generations'), ('LI2_ONESHOT', 'retained_records')):
        value = copy.deepcopy(rows); value[row][key] += 1
        reject(row + '_' + key, value, ingress,
               'same single restored source patch and two real generation advances')
    for name in RESIDENT_LEDGERS:
        reason = 'exact startup-offset signal ledger: ' + name
        for key in ('initialized', 'events'):
            value = copy.deepcopy(rows); value[name][key] ^= 1
            reject(name + '_' + key, value, ingress, reason)
        for i in range(5):
            value = copy.deepcopy(rows); value[name]['signals'][i] ^= 1
            reject(name + '_signal_' + str(i), value, ingress, reason)
            value = copy.deepcopy(rows); value[name]['signals'][i] += 1; value[name]['events'] += 1
            reject(name + '_coordinated_category_total_' + str(i), value, ingress, reason)
    value = copy.deepcopy(rows)
    for name in RESIDENT_LEDGERS:
        value[name]['signals'][0] += 1; value[name]['events'] += 1
    reject('all_three_ledgers_coordinated_category_total', value, ingress, first_ledger)
    need(len(refused) == len(set(refused)) == 87 and resident_signals(stderr, ingress) == original,
         'all87 additive causal signal-join controls and unchanged original')
    return dict(count=87, refusals=refused, stderr_sha256=original['stderr_sha256'],
                ingress=list(ingress), native_operations=0)
