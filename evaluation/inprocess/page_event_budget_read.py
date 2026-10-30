"""Strict additive LI2_EVENT reader; all original COST/application gates remain."""
import copy
import hashlib
import json

import page_cost_counters as old

need = old.need
MASK = (1 << 64) - 1
KEYS = ('version initialized sealed valid error busy active depth clock handlers signals routes signal_ns route_ns '
        'region_calls region_returns exclusive_ns inclusive_ns maps maps_start maps_end owner_start owner_end raw '
        'site_total site_other site_unique site_retained site_start site_end site_sha256 sites').split()
REGIONS = ('handler_other maps_other maps_open maps_read maps_close maps_parse decoder_decode '
           'decoder_classify decoder_footprint decoder_scan native_policy admission_prepare '
           'admission_publish native_close').split()
RAW = ('openat read close pread64 fstat fcntl mprotect membarrier getpid gettid '
       'clock_gettime ptrace other').split()


def integers(value, count, name):
    need(type(value) is list and len(value) == count and
         all(type(x) is int and 0 <= x <= MASK for x in value),
         'complete unsigned event array ' + name)


def validate(event, parsed, cost, process_ns, process_start_ns, process_reaped_ns):
    need(type(event) is dict and list(event) == KEYS, 'exact ordered event schema')
    for key in KEYS[:8] + ['site_total', 'site_other', 'site_unique', 'site_retained', 'site_start', 'site_end']:
        need(type(event[key]) is int and 0 <= event[key] <= MASK,
             'exact unsigned event scalar ' + key)
    need([event[k] for k in KEYS[:8]] == [1, 1, 1, 1, 0, 0, 0, 0],
         'initialized sealed successful quiescent event diagnostic')
    for key, size in [('clock', 4), ('handlers', 3), ('signals', 5), ('routes', 7), ('signal_ns', 5), ('route_ns', 7),
                      *[(k, 14) for k in ('region_calls', 'region_returns', 'exclusive_ns', 'inclusive_ns')],
                      ('maps', 13), ('maps_start', 10), ('maps_end', 10), ('owner_start', 4), ('owner_end', 4)]:
        integers(event[key], size, key)
    need(type(event['raw']) is list and len(event['raw']) == 13, 'thirteen exact physical RAW classes')
    for index, row in enumerate(event['raw']):
        integers(row, 3, 'raw_' + RAW[index])
        need(row[0] == row[1] and row[2] <= row[1], 'actual RAW attempts/returns/negative-returns closure')
    c, h = event['clock'], event['handlers']
    calls, returns = event['region_calls'], event['region_returns']
    exclusive, inclusive = event['exclusive_ns'], event['inclusive_ns']
    need(all(type(x) is int for x in (process_ns, process_start_ns, process_reaped_ns)) and
         0 < process_ns == process_reaped_ns - process_start_ns <= 60_000_000_000,
         'actual original bounded pre-Popen through reap interval')
    need(c[0] == c[1] == 2 * sum(calls) > 0 and 0 < c[2] < c[3], 'actual complete monotonic observer clocks')
    need(process_start_ns <= c[2] < c[3] <= process_reaped_ns,
         'actual same-clock observer endpoints inside independently retained process lifetime')
    need(h[2] == 1 and h[0] == h[1] + 1 > 1, 'one terminal handler fence; no invented normal return')
    need(sum(event['signals']) == sum(event['routes']) == h[0] and event['signals'][4] == 0,
         'complete actual signal and pending-route populations')
    need(sum(event['signal_ns']) == sum(event['route_ns']) == inclusive[0] and
         all(n or t == 0 for n, t in zip(event['signals'], event['signal_ns'])) and
         all(n or t == 0 for n, t in zip(event['routes'], event['route_ns'])),
         'exact overlapping handler-body timing views and absent-class zero time')
    need(calls == returns and calls[0] == h[0], 'every entered region completed including terminal fence')
    need(all(e <= i for e, i in zip(exclusive, inclusive)) and
         all(n or (e == i == 0) for n, e, i in zip(calls, exclusive, inclusive)),
         'source region inclusive/exclusive and absent-region timing bounds')
    need(0 < sum(exclusive) == inclusive[0] <= c[3] - c[2] <= process_ns and
         all(n <= inclusive[0] for n in inclusive),
         'disjoint handler-time partition inside actual monotonic process envelope')
    m, start, end = event['maps'], event['maps_start'], event['maps_end']
    need(m[0] == m[1] == m[2] == m[3] == m[7] == m[8] == m[9] == m[10] == m[11] > 0 and
         m[4] == m[5] >= m[0] and m[6] > 0 and m[12] > 0,
         'every fresh maps read actually opened, read to EOF, closed and parsed')
    need(calls[1:6] == [m[0], m[2], m[4], m[8], m[10]], 'exact timed maps operation populations')
    need(all(a <= b for a, b in zip(start[:6], end[:6])) and
         all(x in (0, 1) for x in start[6:8] + end[6:8]) and
         start[8:] == end[8:] == [0, 0] and
         end[0] - start[0] == m[0] and end[1] - start[1] == m[1],
         'startup maps retained separately; measured acquisition deltas exact')
    need(cost is not None and end == cost['maps'], 'whole event/COST pre-report maps snapshot equality')
    before, after = event['owner_start'], event['owner_end']
    life = parsed['native_pair']['lifecycle']
    need(after == [parsed['chain']['event'], life[11], life[12], life[14]] and
         all(a <= b for a, b in zip(before, after)) and
         [b-a for a, b in zip(before, after)] == [h[0], calls[11], calls[12], calls[13]],
         'whole actual prearm/end owner counts and measured handler/admission/close deltas')
    need(0 <= event['site_start'] <= event['site_end'] == parsed['chain']['fallbacks'] and
         event['site_total'] == event['site_end'] - event['site_start'],
         'exact measured fallback population against original chain counter')
    need(type(event['sites']) is list and 0 <= event['site_unique'] <= 16384 and
         len(event['sites']) == min(event['site_unique'], 32), 'exact bounded highest-count source-site rows')
    integers(event['site_sha256'], 32, 'site_sha256')
    need(all(x <= 255 for x in event['site_sha256']), 'exact full-table SHA256 byte values')
    identities = set()
    for row in event['sites']:
        integers(row, 5, 'site')
        need(row[0] <= 33 and row[2] <= 0xffffffff and 1 <= row[3] <= 6 and
             row[4] > 0 and tuple(row[:4]) not in identities,
             'exact fallback enum, positive count and unique source-site tuple')
        identities.add(tuple(row[:4]))
    need(event['sites'] == sorted(event['sites'], key=lambda row: (-row[4], *row[:4])),
         'exact descending-count and ascending-source-key top-row ordering')
    need(sum(row[4] for row in event['sites']) <= event['site_retained'] and
         event['site_retained'] + event['site_other'] == event['site_total'] and
         event['site_retained'] >= event['site_unique'] and
         (event['site_other'] == 0 or event['site_unique'] == 16384) and
         (event['site_unique'] > 32 or sum(row[4] for row in event['sites']) == event['site_retained']),
         'retained table count plus exact explicit overflow; complete top population when at most32 keys')
    return dict(handler_ns=inclusive[0], observed_envelope_ns=c[3] - c[2],
                unmeasured_process_residual_ns=process_ns - inclusive[0],
                internal_c_raw_ptrace=event['raw'][11], external_ptrace_stops=None,
                site_rows=len(event['sites']), sites_sha256=old.digest(event['sites']),
                scope='Measured handler intervals only; inclusive paths overlap; residual is not trap cost')


def check(stdout, stderr, pid, exit_code, parent, images, image_bytes, carrier,
          carrier_bytes, *, workload, observed, process_ns, process_start_ns, process_reaped_ns):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete actual terminal report')
    prefix, event = stderr, None
    if observed:
        lines = [line + b'\n' for line in stderr[:-1].split(b'\n')]
        need(len(lines) > 2 and lines[-1].startswith(b'LI2_EVENT ') and
             len(lines[-1]) <= 8192 and b'\r' not in lines[-1] and
             sum(line.startswith(b'LI2_EVENT ') for line in lines) == 1,
             'unique complete bounded final event row')
        prefix = b''.join(lines[:-1])
        event = old.pair.pair_reports.rseq.decode(lines[-1][10:-1])
    parsed, summary, cost, _ = old.check(stdout, prefix, pid, exit_code, parent,
        images, image_bytes, carrier, carrier_bytes, workload=workload, observed=observed)
    event_summary = validate(event, parsed, cost, process_ns, process_start_ns, process_reaped_ns) if observed else None
    return parsed, summary, cost, event, event_summary, prefix


def controls(stdout, stderr, args, *, workload, observed, process_ns, process_start_ns, process_reaped_ns):
    parsed, _, cost, event, _, prefix = check(stdout, stderr, *args,
        workload=workload, observed=observed, process_ns=process_ns,
        process_start_ns=process_start_ns, process_reaped_ns=process_reaped_ns)
    before = hashlib.sha256(stderr).hexdigest()
    original = old.controls(stdout, prefix, args, workload=workload, observed=observed)
    trials = []
    def change(name, key, value, index=None):
        changed = copy.deepcopy(event)
        if index is None:
            changed[key] = value
        elif type(index) is tuple:
            changed[key][index[0]][index[1]] = value
        else:
            changed[key][index] = value
        need(changed != event, 'non-vacuous supplied event mutation ' + name)
        trials.append((name, prefix + b'LI2_EVENT ' +
            json.dumps(changed, separators=(',', ':'), allow_nan=False).encode() + b'\n'))
    if observed:
        for key in KEYS[:8]:
            change(key, key, event[key] ^ 1)
        for key in ('clock', 'handlers', 'signals', 'routes', 'signal_ns', 'route_ns', 'region_calls', 'region_returns',
                    'exclusive_ns', 'inclusive_ns', 'maps', 'maps_start', 'maps_end', 'owner_start', 'owner_end', 'raw'):
            change('short_' + key, key, event[key][:-1])
        change('clock_return', 'clock', event['clock'][1] + 1, 1)
        change('clock_reverse', 'clock', event['clock'][2] - 1, 3)
        change('clock_outside_process', 'clock', event['clock'][2] + process_ns + 1, 3)
        change('clock_before_launch', 'clock', process_start_ns - 1, 2)
        change('handler_returns', 'handlers', event['handlers'][1] + 1, 1)
        change('terminal_fence', 'handlers', 0, 2)
        change('signal_population', 'signals', event['signals'][0] + 1, 0)
        change('route_population', 'routes', event['routes'][0] + 1, 0)
        change('signal_time_partition', 'signal_ns', event['signal_ns'][0] + 1, 0)
        change('route_time_partition', 'route_ns', event['route_ns'][0] + 1, 0)
        # SIG other has no successful rows; preserve the sum while assigning it time.
        timings = list(event['signal_ns']); positive = next(i for i, n in enumerate(timings) if n)
        timings[positive] -= 1; timings[4] += 1
        change('absent_signal_time', 'signal_ns', timings)

        change('region_return', 'region_returns', event['region_returns'][0] + 1, 0)
        change('exclusive_partition', 'exclusive_ns', event['exclusive_ns'][0] + 1, 0)
        change('inclusive_partition', 'inclusive_ns', event['inclusive_ns'][0] + 1, 0)
        change('maps_eof', 'maps', event['maps'][7] + 1, 7)
        change('maps_start_delta', 'maps_start', event['maps_start'][0] + 1, 0)
        change('maps_end_cost', 'maps_end', event['maps_end'][2] + 1, 2)
        change('maps_poisoned', 'maps_end', 1, 8)
        change('owner_start_delta', 'owner_start', event['owner_start'][0] + 1, 0)
        change('owner_end_original', 'owner_end', event['owner_end'][1] + 1, 1)
        change('raw_short_row', 'raw', event['raw'][0][:-1], 0)
        change('raw_unreturned', 'raw', event['raw'][0][1] + 1, (0, 1))
        change('raw_negative_return_bound', 'raw', event['raw'][0][1] + 1, (0, 2))
        change('site_total', 'site_total', event['site_total'] + 1)
        change('site_other', 'site_other', event['site_other'] + 1)
        change('site_unique_bound', 'site_unique', 16385)
        change('site_start_delta', 'site_start', event['site_start'] + 1)
        change('site_end_original', 'site_end', event['site_end'] + 1)
        change('site_retained', 'site_retained', event['site_retained'] + 1)
        change('site_hash_shape', 'site_sha256', event['site_sha256'][:-1])
        change('site_hash_byte', 'site_sha256', 256, 0)
        if event['sites']:
            change('site_duplicate', 'sites', event['sites'] + [event['sites'][0]])
            change('site_fallback', 'sites', 7, (0, 3))
            change('site_count', 'sites', 0, (0, 4))
        line = stderr[len(prefix):]
        trials.extend([('missing', prefix), ('duplicate', stderr + line),
                       ('wrong_order', line + prefix), ('truncated', stderr[:-1]),
                       ('duplicate_key', prefix + line.replace(b'{', b'{"version":1,', 1))])
        need(len(trials) == (63 if event['sites'] else 60) and
             len({name for name, _ in trials}) == len(trials),
             'all fixed distinct event controls plus exact present-site controls')
        names = []
        for name, data in trials:
            refused = False
            try:
                check(stdout, data, *args, workload=workload, observed=True, process_ns=process_ns,
                      process_start_ns=process_start_ns, process_reaped_ns=process_reaped_ns)
            except ValueError:
                refused = True
            need(refused, 'complete event reader refuses supplied ' + name)
            names.append(name)
    else:
        names = []
    need(hashlib.sha256(stderr).hexdigest() == before, 'original complete evidence remains unchanged')
    return dict(original=original, event_refusals=names,
                scope='Supplied report corruptions only; no additional native subjects')


def clock_elf(path, symbols):
    """Bind the literal no-argument clock thunk to the actual original gateway."""
    import struct
    from page_selected import elf
    from page_selected_fast_memset import symbol
    data, head, loads = elf(path)
    need(head[1] == 3, 'actual shared release bridge')
    clock, clock_size = symbol(symbols, 'li2_event_clock_raw', 'Tt')
    raw, raw_size = symbol(symbols, 'li2_raw6', 'Tt')
    buffer, buffer_size = symbol(symbols, 'li2_event_clock_buffer', 'BbDd')
    def image(address, size, flags):
        owners = [p for p in loads if p[0] == 1 and p[1] == flags and
                  p[3] <= address and address + size <= p[3] + p[5]]
        need(len(owners) == 1, 'unique complete actual emitted RX byte owner')
        p = owners[0]
        return data[p[2] + address - p[3]:p[2] + address - p[3] + size]
    code = image(clock, clock_size, 5)
    need(clock_size == 37 and code[:13] == bytes.fromhex('bfe4000000be01000000488d15') and
         code[17:28] == bytes.fromhex('31c94531c04531c96a00e8') and
         code[32:] == bytes.fromhex('4883c408c3'),
         'exact stack-balanced literal clock argument and direct-call instruction bytes')
    need(clock + 17 + struct.unpack_from('<i', code, 13)[0] == buffer and
         clock + 32 + struct.unpack_from('<i', code, 28)[0] == raw,
         'actual RIP-relative fixed clock buffer and original direct gateway target')
    need(raw_size == 26 and image(raw, raw_size, 5) == bytes.fromhex(
         '4889f84889f74889d64889ca4d89c24d89c84c8b4c24080f05c3'),
         'unchanged complete register-moving original syscall/return gateway')
    need(buffer_size == 16 and buffer % 8 == 0 and
         sum(p[0] == 1 and p[1] == 6 and p[3] <= buffer and
             buffer + 16 <= p[3] + p[6] for p in loads) == 1,
         'actual exact sixteen-byte writable nonexecuting clock buffer')
    def label(name):
        rows = [line.split() for line in symbols.decode().splitlines() if line.split()[-1:] == [name]]
        need(len(rows) == 1 and len(rows[0]) in (3, 4), 'one actual emitted label ' + name)
        return int(rows[0][0], 16)
    first, end = label('li2_gateway_start'), label('li2_gateway_end')
    need(first == raw and raw + raw_size <= end and
         (clock + clock_size <= first or clock >= end),
         'clock thunk outside unchanged allowed syscall gateway range')
    return dict(clock_bytes=clock_size, clock_sha256=hashlib.sha256(code).hexdigest(),
                gateway_bytes=raw_size, gateway_sha256=hashlib.sha256(image(raw, raw_size, 5)).hexdigest(),
                buffer_bytes=16, syscall=228, clock_id=1,
                fixed_buffer_and_direct_original_gateway=True)
