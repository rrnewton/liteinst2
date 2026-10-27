"""Strict finite maps-record reader using retained ELF/DWARF layout only."""
from page_selected import need


def unpack(data, layout, at=0):
    size = layout['bytes']
    need(type(size) is int and 0 < size and 0 <= at <= len(data)-size, 'whole DWARF field extent')
    if layout['kind'] == 'scalar':
        need(size in (1, 2, 4, 8) and type(layout['signed']) is bool, 'closed scalar layout')
        return int.from_bytes(data[at:at+size], 'little', signed=layout['signed'])
    if layout['kind'] == 'array':
        element, count = layout['element'], layout['count']
        need(type(count) is int and 0 < count <= 65536 and size == count*element['bytes'], 'whole actual array')
        if element == dict(kind='scalar', bytes=1, signed=False):
            return data[at:at+size]
        return [unpack(data, element, at+i*element['bytes']) for i in range(count)]
    need(layout['kind'] == 'struct', 'closed struct layout')
    result, last = {}, 0
    for f in layout['fields']:
        need(type(f['name']) is str and f['name'] not in result and type(f['offset']) is int and
             last <= f['offset'] <= size-f['type']['bytes'], 'disjoint whole named fields')
        result[f['name']] = unpack(data, f['type'], at+f['offset'])
        last = f['offset']+f['type']['bytes']
    return result


def check(data, layout, case):
    need(len(data) == layout['bytes'] and len(data) < 16 << 20, 'exact complete private record')
    r = unpack(data, layout)
    need(r['magic'] == 0x3150414d32494c and r['version'] == 1 and r['bytes'] == len(data), 'maps record identity')
    for key in ('mode', 'verified', 'fixture_error', 'operation_failed', 'events'):
        need(r[key] == case[key], 'exact maps outcome '+key)
    for key, expected in (('source_changes', case['actual_source_changes']), ('real_signals', case['actual_signals']),
                          ('adapter_injections', case['nonissued_error_injections']),
                          ('state_injections', case['supplied_state_injections'])):
        need(r[key] == expected, 'exact actual/injected effect count')
    need(r['pid'] == r['tid'] > 0 and all(r[x] > 0 and r[x] % 4096 == 0 for x in ('source', 'probe', 'hole')) and
         r['cleanup_result'] == r['cleanup_sync'] == 0, 'singleton identity and actual final revoke/sync')
    stats, q, frames = r['stats'], r['query'], r['frames']
    need(len(stats) == len(q) == 8 and len(frames) == 3, 'closed finite arrays')
    need(all(s['reserved'] == 0 for s in stats) and not stats[7]['active'] and not stats[7]['valid'], 'final phase closed')
    mode = case['mode']
    need(stats[7]['poisoned'] == int(mode in (7, 8)), 'poison is an explicit failed scope')

    def io(p):
        need(p['opened'] == p['close_started'] == p['closed'] == 1 and p['fd'] >= 0 and
             p['last_read'] == p['close_result'] == 0 and 0 < p['bytes'] < 256 << 10 and
             0 < p['rows'] <= 2048 and p['observation']['acquisition_id'] > 0, 'complete real maps acquisition')

    def same(a, b):
        io(a); io(b)
        need(all(a[k] == b[k] for k in ('fd', 'last_read', 'close_result', 'bytes', 'rows', 'opened', 'close_started', 'closed')) and
             all(a['observation'][k] == b['observation'][k] for k in ('acquisition_id', 'handler_id', 'mutation_epoch')) and
             b['observation']['kind'] == 2 and b['observation']['io_performed'] == 0, 'same acquisition with honest reuse tag')

    def fresh(a, b):
        io(a); io(b)
        need(b['observation']['acquisition_id'] > a['observation']['acquisition_id'] and
             b['observation']['mutation_epoch'] > a['observation']['mutation_epoch'] and
             b['observation']['kind'] in (0, 1) and b['observation']['io_performed'] == 1, 'actual fresh acquisition after boundary')

    def query(index, address, prot, error=0):
        p = q[index]
        need(p['attempted'] == 1 and p['first'] == address and p['end'] == address+4096 and
             p['expected_prot'] == prot and p['result'] == error and p['complete'] == int(error == 0), 'exact fresh query outcome')
        if not error:
            need(p['pages_checked'] == 1 and p['actual_prot'] == prot and
                 p['first_vma'] <= address < address+4096 <= p['last_vma_end'], 'whole actual VMA inspected')
        return p['maps']

    source = r['fetch_before']['preparation']
    io(source)
    need(source['observation']['kind'] == source['observation']['io_performed'] == 1 and
         r['fetch_before']['held'] == r['fetch_before']['complete'] == 1 and
         r['fetch_before']['first_error'] == 0 and r['source_view']['page_count'] == 1 and
         r['source_view']['length'] == 15 and r['source_pages'][0]['address'] == r['source'], 'genuine held source preparation')
    need(r['borrow']['owner'] > 0 and r['borrow']['sequence'] == r['fetch_before']['sequence'] > 0 and
         r['fetch_before']['pages_copied'] == 1 and r['fetch_before']['bytes_copied'] == 15 and
         r['source_view']['pc'] == r['source'] and r['source_view']['identity_observed'] == 1 and
         r['source_view']['pid'] == r['source_view']['tid'] == r['pid'], 'actual source owner and request identity')
    same(source, query(0, r['probe'], 5))
    guard = r['guard']
    need(guard['attempted'] == guard['page_observed'] == guard['complete'] == 1 and guard['result'] == 0 and
         guard['page']['address'] == guard['pc'] == r['source']+4096 and
         guard['page']['generation'] != r['source_pages'][0]['generation'] and
         guard['page']['allocation'] == r['source_pages'][0]['allocation'] > 0 and
         guard['page']['offset'] == r['source_pages'][0]['offset']+4096, 'distinct guard ownership freshly checked')
    for page, backing in ((r['source_pages'][0], r['source_backing'][0]), (guard['page'], guard['backing'])):
        need(page['backing'] == 1 and page['logical'] == 5 and page['closed_prot'] == 1 and
             page['allocation'] > 0 and page['generation'] > 0 and page['vma_inode'] > 0 and
             page['vma_first'] <= page['address'] < page['address']+4096 <= page['vma_end'] and
             backing['retained_fd'] >= 0 and backing['seals_observed'] == backing['stat_observed'] == 1 and
             backing['seals'] == 15 and backing['stat_result'] == 0, 'independent closed page/backing proof')
    need(guard['backing']['retained_fd'] == r['source_backing'][0]['retained_fd'] and
         all(guard['backing']['stat'][k] == r['source_backing'][0]['stat'][k] for k in
             ('st_dev', 'st_ino', 'st_size', 'st_mode')) and guard['backing']['stat']['st_size'] == 3*4096, 'same sealed image with distinct page generation')
    same(q[0]['maps'], guard['maps'])
    need(stats[1]['acquisitions'] == stats[0]['acquisitions']+1 and stats[1]['reuses'] > stats[0]['reuses'] and
         stats[1]['active'] == stats[1]['valid'] == 1, 'one measured acquisition across different owners')
    need(r['source_before'] == bytes.fromhex('90e9fa0f0000909090909090909090'), 'complete literal source NOP/JMP bytes')
    for frame in frames:
        if not frame['observed']:
            continue
        need(frame['observed'] == 1 and frame['fp_address'] > 0 and frame['fp_address'] % 16 == 0 and
             512 <= frame['fp_bytes'] <= 65536, 'whole observed kernel FP pointer and extent')
        fp, n = frame['fp'], frame['fp_bytes']
        u32 = lambda at: int.from_bytes(fp[at:at+4], 'little')
        if u32(464) == 0x46505853:
            need(n == u32(468) and n >= 580 and 576 <= u32(480) <= n-4 and
                 u32(n-4) == 0x46505845, 'actual kernel extended FP framing')
        else:
            need(n == 512, 'legacy kernel FP framing')
        need(not any(fp[n:]), 'unused FP record tail is zero')
    f = frames[0]
    need(f['observed'] == 1 and 512 <= f['fp_bytes'] <= 65536 and f['fp_address'] > 0 and f['fp_address'] % 16 == 0 and
         f['greg'][16] == r['source'] and f['greg'][19:21] == [21, 14] and
         f['greg'][22] == r['source'] and f['greg'][18] & 0xffff == 0x33 and
         f['mask'] == ((1 << 64)-1) & ~sum(1 << (n-1) for n in (5, 9, 11, 19)), 'actual entry NX frame')
    if mode == 0:
        same(q[0]['maps'], query(1, r['probe']+4096, 5));fresh(q[1]['maps'], query(2, r['probe'], 5))
        need(r['operation_result'] >= 0, 'actual unknown-whitelist syscall result')
    elif mode == 1:
        need(r['operation_result'] == 0, 'actual permission mutation')
        fresh(q[0]['maps'], query(1, r['probe'], 5, 305))
    elif mode == 2:
        same(q[0]['maps'], query(1, r['hole'], 3));need(r['operation_result'] == -12, 'actual partial syscall ENOMEM')
        fresh(q[1]['maps'], query(2, r['hole'], 1));query(3, r['hole'], 3, 305)
        need(q[2]['maps']['observation']['kind'] == 0, 'post-error inspection uncached')
    elif mode == 3:
        query(3, r['probe'], 5);query(4, r['probe'], 5);fresh(q[3]['maps'], q[4]['maps'])
        need(q[4]['maps']['observation']['handler_id'] > q[3]['maps']['observation']['handler_id'] and
             stats[2]['active'] == stats[2]['valid'] == 1 and not stats[3]['active'] and not stats[3]['valid'], 'actual execution crossed a closed phase')
        g = frames[1]
        need(g['observed'] == 1 and g['greg'][16] == g['greg'][22] == r['source']+4096 and
             all(f['greg'][i] == g['greg'][i] for i in range(23) if i not in (16, 22)) and
             f['mask'] == g['mask'] and f['fp_bytes'] == g['fp_bytes'] and
             f['fp'][:f['fp_bytes']] == g['fp'][:g['fp_bytes']], 'literal NOP/JMP complete kernel-state continuation')
    elif mode == 4:
        need(stats[2]['active'] == stats[2]['valid'] == 1 and not stats[6]['active'] and not stats[6]['valid'] and
             frames[2]['observed'] == 1 and 512 <= frames[2]['fp_bytes'] <= 65536, 'retained actual nested frame and invalidated phase')
    elif mode == 5:
        need(r['fetch_after']['held'] == 1 and r['fetch_after']['first_error'] == 306 and
             r['source_before'][0] == 0x90 and r['source_after'][0] == 0x91 and
             r['source_before'][1:] == r['source_after'][1:], 'actual source corruption still rejected')
        fresh(source, r['fetch_after']['validation'])
    elif mode == 6:
        need(r['operation_result'] == -13, 'explicit nonissued adapter error')
        fresh(q[0]['maps'], query(1, r['probe'], 5));need(q[1]['maps']['observation']['kind'] == 0, 'adapter failure disables reuse')
    else:
        need(mode in (7, 8), 'closed state-control identity');query(1, r['probe'], 5, 303)
        need(stats[3]['poisoned'] == 1 and not stats[3]['active'] and not stats[3]['valid'] and
             stats[3]['fresh_calls'] == stats[2]['fresh_calls'] and stats[3]['acquisitions'] == stats[2]['acquisitions'] and
             stats[3]['invalidations' if mode == 7 else 'mutation_epoch'] == (1 << 64)-1 and
             not q[1]['maps']['opened'] and not q[1]['maps']['observation']['acquisition_id'], 'overflow refuses without I/O or wrap')
    if mode != 5:
        need(r['fetch_after']['held'] == 0 and r['fetch_after']['first_error'] == 0 and
             r['fetch_after']['sequence'] == r['borrow']['sequence'], 'original borrow genuinely released')
    return dict(mode=mode, accepted=True, operation_failed=bool(r['operation_failed']),
                operation_completed=not bool(r['operation_failed']), events=r['events'],
                source_changes=r['source_changes'], actual_signals=r['real_signals'],
                adapter_injections=r['adapter_injections'], supplied_state_injections=r['state_injections'],
                stats=stats, acquisition_tags=[p['maps']['observation'] for p in q if p['attempted']])
