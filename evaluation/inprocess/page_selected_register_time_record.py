"""Finite observer qualification. Offsets/extents are retained ELF/DWARF facts.

This replays the fixed two-MOV effect and full architectural endpoint equality;
unchanged C compare_run additionally checks all publication/owner invariants.
"""
from page_selected import need
from page_selected_maps_record import unpack

REGS = [13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7]
MASK64 = (1 << 64)-1


def u(value):
    return value & MASK64


def check(data, layout, mode):
    need(type(mode) is int and mode in (0, 1, 2) and set(layout) ==
         {'header','samples','li2_register_records','capacities','tail','li2_timing_record'}, 'exact finite layout roots')
    sizes = {k: v['bytes'] for k, v in layout.items()}
    need(layout['samples']['kind'] == 'array' and layout['samples']['count'] == 21 and
         layout['li2_register_records']['kind'] == 'array' and layout['li2_register_records']['count'] == 11 and
         layout['capacities']['kind'] == 'array' and layout['capacities']['count'] == 64, 'actual finite ELF array extents')
    sizes['samples'] = layout['samples']['element']['bytes']
    total = sum(sizes.values())
    need(0 < total == len(data) < 16 << 20 and sizes['header'] == 216 and sizes['capacities'] == 64*192,
         'complete record extent from retained ELF')
    decoded = {};at = 0
    for name in ('header','samples','li2_register_records','capacities','tail','li2_timing_record'):
        typ = layout[name]['element'] if name == 'samples' else layout[name]
        decoded[name] = unpack(data, typ, at);at += sizes[name]
    h, records, tail, r = (decoded[k] for k in ('header','li2_register_records','tail','li2_timing_record'))
    capacity_at = sizes['header']+sizes['samples']+sizes['li2_register_records']
    need(not any(data[capacity_at:capacity_at+sizes['capacities']]), 'no invented capacity records')
    if mode:
        records_at = sizes['header']+sizes['samples']
        one = layout['li2_register_records']['element']['bytes']
        need(not any(data[records_at+one:records_at+11*one]), 'only the genuine failed first invocation is retained')
    need(h['magic'] == 0x314e55525232494c and h['version'] == 1 and h['group'] == 4 and
         h['header_bytes'] == 216 and h['records_kept'] == 11 and h['record_bytes']*11 == sizes['li2_register_records'] and
         h['startup_bytes'] == sizes['samples'] and h['capacity_row_bytes'] == 192 and h['capacity_rows'] == 64 and
         h['tail_bytes'] == sizes['tail'] and h['refusals'] == 47 and 576 <= h['xsave_bytes'] <= 65536 and h['xcr0']&3 == 3,
         'actual finite header/startup/refusal/XSAVE facts')
    startup = decoded['samples']
    need(startup['selftest'] == startup['checked'] == startup['native_complete'] == startup['step_endpoint_seen'] == 1,
         'unchanged actual old startup pair')
    need(r['magic'] == 0x31454d495432494c and r['version'] == 1 and r['bytes'] == sizes['li2_timing_record'] and
         r['mode'] == mode and h['owner_failure'] == h['owner_detail_abs'] == h['owner_detail_negative'] == 0,
         'actual timing trailer and no concealed owner failure')
    need(r['expected_pid'] > 0 and 0 <= r['expected_uid'] <= 0xffffffff, 'actual session PID and raw getuid observation')
    if mode != 2:
        need(r['signal_observed'] == r['signal_number'] == r['signal_signo'] == r['signal_code'] ==
             r['signal_errno'] == r['signal_pid'] == r['signal_uid'] == 0, 'no invented signal observation')
    t = r['observation']
    need(t['initialized'] == t['finalized'] == 1 and t['config']['mode'] == 2 and
         t['config']['key']['offset'] == 128 and t['config']['key']['source_length'] == 8 and
         t['config']['key']['run_length'] == 6 and t['config']['key']['instructions'] == 2 and
         t['config']['key']['guard_length'] == 2 and
         t['config']['key']['source'] == bytes.fromhex('4889c14989ca01c0')+bytes(8) and
         t['resolution_result'] == 0 and t['resolution']['sec'] >= 0 and 0 <= t['resolution']['nsec'] < 1000000000 and
         t['resolution']['sec']*1000000000+t['resolution']['nsec'] > 0, 'actual raw monotonic clock resolution')
    need(h['completed_capacity'] == h['fallback_runs'] == h['fallback_trace_events'] == h['generated_trace_events'] == 0 and
         h['source_restorations'] == 1, 'no capacity churn, fallback or generated TRACE')
    completed = 11 if mode == 0 else 0
    need(h['completed_records'] == h['published_runs'] == r['completions'] == t['completed'] == completed and
         h['native_references'] == (11 if mode == 0 else 1) and h['hit_runs'] == (10 if mode == 0 else 0),
         'actual native references versus completed operations')
    if mode:
        need(not h['complete'] and not r['complete'] and not t['qualified'] and t['pending']['active'] == 1 and
             t['samples_complete'] == t['publications'] == t['hits'] == 0 and r['entries'] == 1 and
             not tail['history']['completed_runs'] and not records[0]['state']['step_endpoint_seen'],
             'failed operation retains pending prefix without completion credit')
        entry = r['entry']['frame'];source = records[0]['state']
        need(entry['initialized'] == entry['fp_bytes'] > 0 and entry['greg'][16] == source['pc'] and
             entry['greg'][19:21] == [21,14] and records[0]['state']['native_complete'] == 1,
             'real original NX entry and independent native reference')
        s = t['sample']
        if mode == 1:
            need(h['fixture_failure'] == t['first_error'] == 803 and t['first_detail'] == -22 and
                 t['clock_calls'] == s['clock_attempted'] == 1 and s['clock_complete'] == s['published'] == 0 and
                 s['clock_id'] == 2147483647 and s['clock_result'] == -22 and not any(s['ns']) and
                 r['publish_returns'] == r['interrupt_issued'] == r['nested_seen'] == 0 and
                 tail['cache']['attempts'] == 0 and s['maps_before'][0]['active'] == 1 and
                 s['maps_after'][0]['active'] == s['maps_after'][0]['valid'] == 0,
                 'actual invalid-clock EINVAL before publication; real phase failure')
        else:
            need(r['signal_observed'] == 1 and r['signal_number'] == r['signal_signo'] == 11 and
                 r['signal_code'] == -6 and r['signal_errno'] == 0 and
                 r['signal_pid'] == r['expected_pid'] and r['signal_uid'] == r['expected_uid'],
                 'actual SIGSEGV SI_TKILL from this process and observed UID')
            need(h['fixture_failure'] == 304 and t['first_error'] == 808 and t['first_detail'] == 11 and
                 t['clock_calls'] == s['clock_attempted'] == s['clock_complete'] == 2 and s['published'] == 1 and
                 s['complete'] == 0 and s['clock_id'] == 4 and s['clock_result'] == 0 and s['ns'][0] <= s['ns'][1] and s['ns'][2] == 0 and
                 r['publish_returns'] == r['interrupt_issued'] == r['nested_seen'] == 1 and
                 r['nested']['frame']['initialized'] == r['nested']['frame']['fp_bytes'] > 0 and
                 tail['cache']['first_error'] == 752 and tail['cache']['attempts'] == tail['cache']['slots_used'] == 1,
                 'real pending tgkill event with complete publication and no generated execution')
        return dict(operation='failed', completed=0, expected_failure_verified=True, retained_full_records=1,
                    native_references=1, observer_error=t['first_error'], clock_calls=t['clock_calls'], intervals=None)
    need(h['fixture_failure'] == 0 and h['complete'] == r['complete'] == t['qualified'] == 1 and
         t['first_error'] == t['first_detail'] == 0 and r['entries'] == r['publish_returns'] == 11 and
         not r['interrupt_issued'] and not r['nested_seen'] and t['publications'] == 1 and t['hits'] == 10 and
         t['samples_complete'] == 11 and t['clock_calls'] == 33 and not t['full_misses'] and not t['pending']['active'],
         'all eleven actual complete invocations and exact clock count')
    need(tail['decoder_before'] == tail['decoder_after'] and tail['decoder_after']['phase'] == 2,
         'unchanged sealed decoder allocation facts')
    first = records[0];previous = 0;intervals = []
    for index, rec in enumerate(records):
        s, o = rec['state'], rec['owner']
        need(rec['case_index'] == 3 and rec['repetition'] == index and rec['route'] == rec['checked'] == rec['reset_complete'] == 1 and
             rec['nx_entries'] == rec['nx_exits'] == rec['trap_events'] == 1 and rec['trace_events'] == 0 and
             s['pc'] == first['state']['pc'] and s['expected_post'] == s['pc']+6 and s['length'] == 8 and
             s['native_complete'] == s['step_endpoint_seen'] == s['checked'] == 1 and
             rec['publication_address'] == first['publication_address'] and rec['publication'] == first['publication'],
             'same original site, same immutable slot and eleven actual endpoint pairs')
        states = [s[n] for n in ('native_before','native_after','step_before','step_endpoint')]
        frames = [x['frame'] for x in states];before = [u(frames[0]['greg'][x]) for x in REGS]
        expected = list(before);expected[1] = expected[10] = expected[0]
        need([u(frames[2]['greg'][x]) for x in REGS] == before and
             all([u(frames[i]['greg'][x]) for x in REGS] == expected for i in (1,3)), 'literal sequential two-MOV effects')
        flags = s['initial_flags']
        need(flags & 0x10100 == 0 and [u(f['greg'][17]) for f in frames] == [flags|0x10000,flags,flags|0x10000,flags|0x10000] and
             frames[1]['greg'][16] == s['expected_post']+1 and frames[1]['greg'][19:21] == [0,3] and
             frames[3]['greg'][16] == s['expected_post'] and frames[3]['greg'][19:21] == [21,14],
             'all flags with only authentic reference INT3 and NX RF distinction')
        for i, (state, frame, live, fp) in enumerate(zip(states,frames,s['live'],s['actual_fp'])):
            need(state['stack'] == states[0]['stack'] and state['data'] == states[0]['data'] and
                 state['fs'] == states[0]['fs'] and state['gs'] == states[0]['gs'] and
                 frame['mask'] == frames[0]['mask'] and frame['initialized'] == frame['fp_bytes'] == frames[0]['fp_bytes'] and
                 frame['fp'] == frames[0]['fp'] and frame['greg'][18] == frames[0]['greg'][18],
                 'whole kernel FP, selectors, FS/GS, stack/data unchanged')
            need(live['started'] == live['complete'] == 1 and not live['reserved'] and live['rflags'] == flags and
                 live['gpr'] == [u(frame['greg'][x]) for x in REGS] and live['selectors'] == s['live'][0]['selectors'] and
                 fp == s['actual_fp'][0], 'independent post-sigreturn live state and full actual XSAVE buffer')
        need(o['phase'] == 7 and not o['first_error'] and o['exit_seen'] == o['release_complete'] == 1 and
             o['before']['greg'] == frames[2]['greg'] and o['after']['greg'] == frames[3]['greg'] and
             o['exit_query']['complete'] == 1 and o['final_fetch']['complete'] == 1 and not o['final_fetch']['held'] and
             rec['history_after'] == rec['history_before']+1 == index+1 and
             rec['copied_after'] == rec['copied_before']+2 == (index+1)*2,
             'genuine retained completed owner, released source and reset count')
        sample = t['samples'][index]
        need(sample['started'] == sample['published'] == sample['complete'] == 1 and sample['slot'] == 0 and
             sample['hit'] == int(index != 0) and sample['clock_attempted'] == sample['clock_complete'] == 3 and
             sample['clock_id'] == 4 and not sample['clock_result'] and sample['borrow'] == o['borrow']['sequence'] and
             previous <= sample['ns'][0] <= sample['ns'][1] <= sample['ns'][2], 'exact complete sequential clock endpoints')
        for a,b in zip(sample['maps_before'],sample['maps_after']):
            need(a == b and a['active'] == 1 and not a['poisoned'], 'actual private clock calls preserve active phase facts')
        previous = sample['ns'][2];intervals.append([sample['ns'][1]-sample['ns'][0],sample['ns'][2]-sample['ns'][0]])
    return dict(operation='completed', completed=11, retained_full_records=11, native_references=11,
                observer_error=0, clock_calls=33, intervals=intervals)
