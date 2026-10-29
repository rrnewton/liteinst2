"""Strict saved provider-app publication records; no process or import side effects.

The enclosing evaluator authenticates these exact sources, the observed bridge
ELF/DWARF, the original application/DSO, sealed carrier, namespace and captures.
Application PCs are joins to the trusted bootstrap object/file-offset policy;
they never select or authorize a source. Full native XSTATE remains a separate
mandatory join through the unchanged B2 comparator.
"""
import sys
sys.dont_write_bytecode = True
import hashlib
import struct

U64 = (1 << 64) - 1
PAGE = 4096
STACK = 16384
MAGIC = 0x31534f425041324c
KINDS = (1, 7, 5)
PUBLISH_KINDS = (3, 1, 2)
SAMPLES = tuple(range(9)) + tuple(range(8189, 8194)) + tuple(range(9212, 9216))


def need(ok, why):
    if not ok:
        raise ValueError(why)


def q(data):
    need(type(data) is bytes and len(data) % 8 == 0, 'whole retained u64 vector')
    return struct.unpack('<' + 'Q' * (len(data) // 8), data)


def uints(data):
    need(len(data) % 4 == 0, 'whole retained u32 vector')
    return struct.unpack('<' + 'I' * (len(data) // 4), data)


def exact(v, **fields):
    for name, want in fields.items():
        need(v.number(name, want < 0) == want, 'exact ' + v.name + '.' + name)


def zero(v, *names):
    for name in names:
        need(not any(v.blob(name)), 'zero ' + v.name + '.' + name)


def padding(v):
    """Only C owner padding, from the actual emitted DWARF field intervals.

    Kernel ucontext/siginfo/stat are opaque complete retained observations,
    never declared zero padding by this traversal.
    """
    fields = sorted(v.shape['fields'].items(), key=lambda item: item[1]['offset'])
    end = 0
    for name, f in fields:
        a, n = f['offset'], f['bytes']
        need(type(a) is int and type(n) is int and end <= a <= len(v.data) and
             0 < n <= len(v.data) - a, 'complete nonoverlapping actual DWARF fields')
        need(not any(v.data[end:a]), 'zero initialized private C padding')
        end = a + n
        if name == 'reserved' or name.startswith('reserved_'):
            need(not any(v.blob(name)), 'zero explicit private reserved field')
        child = v.layout['edges'].get(v.name, {}).get(name)
        if child is not None:
            for row in v.array(name, child):
                padding(row)
    need(not any(v.data[end:]), 'zero initialized private C trailing padding')


def address(value, size, first, length):
    need(all(type(x) is int for x in (value, size, first, length)) and
         0 < first <= U64 - length and 0 < size <= length and
         first <= value <= first + length - size, 'actual owned initialized address extent')


def frame(v, layout, root, signal, pc, facts):
    exact(v, signal=signal, complete=1, uc_bytes=layout['uc_bytes'], fp_bytes=facts['extent'] + 4)
    n = v.number('fp_bytes')
    si, uc, fp = v.blob('info'), v.blob('uc'), v.blob('fp')
    need(len(si) == layout['siginfo_bytes'] and not any(uc[layout['uc_bytes']:]) and
         not any(fp[n:]), 'complete kernel observations and unused capture capacity')
    uc = uc[:layout['uc_bytes']]
    views = ((v.number('info_address'), si), (v.number('frame_address'), uc),
             (v.number('fp_address'), fp[:n]))
    for a, data in views:
        address(a, len(data), root.number('altstack_address'), root.number('altstack_bytes'))
        for b, other in views:
            lo, hi = max(a, b), min(a + len(data), b + len(other))
            if lo < hi:
                need(data[lo-a:hi-a] == other[lo-b:hi-b], 'every physical signal-view alias byte')
    off = layout['offsets']
    need(v.number('fp_address') % 16 == 0 and
         struct.unpack_from('<Q', uc, off['fp_pointer'])[0] == v.number('fp_address') and
         tuple(struct.unpack_from('<i', si, off[k])[0] for k in
               ('siginfo_signo', 'siginfo_code', 'siginfo_errno')) == (signal, 2, 0) and
         struct.unpack_from('<Q', si, off['siginfo_address'])[0] == pc,
         'genuine NX/UD2 kernel frame origin and actual FP allocation')
    g = struct.unpack_from('<23Q', uc, off['greg'])
    need(g[16] == pc and g[19:21] == ((21, 14) if signal == 11 else (0, 6)),
         'exact real exception instruction/error/vector')
    return dict(uc=uc, fp=fp[:n], frame_address=v.number('frame_address'),
                fp_address=v.number('fp_address'), si=si, info_address=v.number('info_address'),
                g=g, capacity=fp)


def owner_frame(v, actual, mask):
    need(q(v.blob('greg')) == actual['g'] and v.number('mask') == mask and
         v.number('fp_address') == actual['fp_address'] and
         v.number('fp_bytes') == v.number('initialized') == len(actual['fp']) and
         v.blob('fp') == actual['capacity'], 'whole owner state joins the actual kernel endpoint')


def stat_join(a, b):
    """Same sealed FD metadata, except the precise Linux read-access timestamp.

    Bootstrap, instruction fetch and publication pread64 are separate real
    reads. All raw stat bytes stay retained; no timestamp is synthesized.
    """
    need(a.name == b.name == 'stat' and len(a.data) == len(b.data) == 144,
         'actual complete x86-64 stat ABI')
    f = a.shape['fields']['st_atim']
    need(f == b.shape['fields']['st_atim'] and f['bytes'] == 16,
         'one exact source-defined mutable access-time field')
    at = f['offset']
    need(a.data[:at] == b.data[:at] and a.data[at+16:] == b.data[at+16:],
         'all 128 other sealed stat bytes exact across actual reads')
    for st in (a, b):
        for name in ('st_atim', 'st_mtim', 'st_ctim'):
            need(len(st.blob(name)) == 16 and 0 <= int.from_bytes(st.blob(name)[8:], 'little', signed=True) < 10**9,
                 'actual timestamp ABI nanoseconds')


def backing(v, anchor, size, oi, *, same_fd=True):
    oi.backing(v, size)
    need((not same_fd or v.number('retained_fd', True) == anchor.number('retained_fd', True)) and
         v.number('seals') == anchor.number('seals'), 'same sealed object and, when retained, exact descriptor')
    stat_join(v.sub('stat', 'stat'), anchor.sub('stat', 'stat'))


def bootstrap(r, images, carrier, oi):
    b = r.sub('bootstrap', 'pab_state')
    exact(b, started=1, complete=1, main_original_bytes=images[0]['bytes'], main_carrier_bytes=carrier['bytes'])
    need(b.blob('main_source_hash').hex() == images[0]['sha256'], 'bootstrap original main source digest')
    modules = b.array('modules', 'pab_module')
    policies = r.array('policy_sites', 'pa_policy_site')
    need(len(modules) == 2 and len(policies) == 6, 'exact trusted two-object six-site policy')
    seen = set()
    for module, (v, image) in enumerate(zip(modules, images, strict=True)):
        bind = v.sub('binding', 'li2_effect_object_binding')
        exact(bind, complete=1)
        oid = bind.number('object_id')
        need(oid > 0 and oid not in seen and bind.number('registered_fd', True) > 3,
             'distinct lifetime object identities from registered descriptors')
        seen.add(oid)
        actual = bind.sub('actual', 'li2_fetch_backing')
        oi.backing(actual, carrier['bytes'] if module == 0 else image['bytes'])
        need(actual.number('retained_fd', True) == bind.number('registered_fd', True),
             'bootstrap accessor observes the exact already-registered supplied descriptor')
        exact(v, original_bytes=image['bytes'], page_vaddr=image['page'], page_offset=image['page_offset'],
              helper_vaddr=image['helper'], stack_vaddr=image['stack']-(STACK-256),
              capture_before=image['pre_endpoint'], capture_after=image['endpoint'], seed_x87=image['x87_pc'])
        need(v.blob('original_page') == image['source'] and
             q(v.blob('sites')) == tuple(x['pc'] for x in image['sites']) and
             q(v.blob('next')) == tuple(x['next_pc'] for x in image['sites']),
             'entire trusted original executable page and emitted symbols')
        for k, site in enumerate(image['sites']):
            exact(policies[3*module+k], object_id=oid, file_offset=site['file_offset'], kind=KINDS[k], reserved=0)
    p = r.sub('policy_terminal', 'pa_policy_context')
    exact(p, count=6, scripted=r.number('scripted'), rounds=r.number('rounds'), matched=6*r.number('rounds'),
          sites=r.number('policy_sites_address'))
    need(q(p.blob('visits')) == (r.number('rounds'),)*6, 'all policy sites actually invoked exact fixed times')
    return modules


def publication(row, root, module, image, pid, oi):
    before = row.sub('published', 'li2_oneshot_owner')
    o = row.sub('retired', 'li2_oneshot_owner')
    p = o.sub('plan', 'li2_oneshot_plan')
    source = row.sub('source', 'li2_fetch_page')
    backend = row.sub('backend_retired', 'li2_oneshot_lifecycle_progress')
    k = row.number('site') % 3
    exact(p, abi_version=1, kind=PUBLISH_KINDS[k], pc=row.number('pc'), next_pc=row.number('pc')+2,
          landing=row.number('landing'), page_count=1, reserved=0)
    zero(p, 'reserved_bytes')
    need(p.number('sequence') > 0 and p.number('landing_allocation') > 0 and p.number('landing_generation') == 1,
         'genuine reusable plan and protected landing identity')
    need(before.blob('plan') == p.data and before.blob('hooks') == o.blob('hooks') and
         before.number('session') == o.number('session') == root.number('session_address'),
         'same full original plan/hooks/session through retirement')
    pages = p.array('pages', 'li2_oneshot_page')
    need(len(pages) == 2 and not any(pages[1].data), 'one actual publication source page')
    page = pages[0]
    exact(page, address=source.number('address'), allocation=source.number('allocation'),
          generation=source.number('generation'), offset=image['page_offset'])
    need(page.number('allocation') > 0 and page.number('generation') > 0 and
         p.blob('original') == image['sites'][k]['original'], 'original allocation/generation and exact five-byte window')
    delta = p.number('landing') - p.number('pc') - 5
    need(-(1 << 31) <= delta < 1 << 31 and p.blob('redirect') == b'\xe9'+struct.pack('<i', delta),
         'actual signed E9 reaches the authenticated UD2 landing')
    expected = bytearray(image['source']); at = p.number('pc') & 4095
    expected[at:at+5] = p.blob('redirect')
    need(row.blob('source_before') == row.blob('source_after') == image['source'] and
         row.blob('source_published') == bytes(expected) and
         before.blob('original_pages') == o.blob('original_pages') == image['source']+bytes(PAGE),
         'every original, redirected and restored page byte')
    for value, phase, restored in ((before, 3, 0), (o, 8, 1)):
        exact(value, initialized=1, in_handler=0, transferred=1, source_copied=1, source_write_started=1,
              write_attempted_mask=31, write_completed_mask=31, landing_observed=restored,
              restore_started=restored, restore_attempted_mask=31*restored, restore_completed_mask=31*restored)
        exact(value.sub('state', 'li2_oneshot_admission_state'), phase=phase, first_error=0, first_detail=0,
              sequence=p.number('sequence'), mutation_started=1, published=1, restored=restored, reserved=0)
        t = value.sub('transfer', 'li2_oneshot_transfer')
        for name in ('call', 'old_release', 'acquire'):
            oi.call(t.sub(name, 'li2_oneshot_call'))
        exact(t, old_authenticated=1, old_borrow_live=0, transaction_live=1, reserved=0)
    need(o.number('landing_frame') == row.sub('ud', 'pao_frame').number('frame_address') and
         before.number('landing_frame') == 0, 'actual captured UD2 frame owns the restored handoff')
    generations = [(page.number('generation'), 0)]
    for j, v in enumerate(o.array('generation', 'li2_oneshot_generation')):
        oi.call(v.sub('call', 'li2_oneshot_call'))
        exact(v, restoring=j, attempted_mask=1, completed_mask=1, reserved=0)
        after = (backend.number('generation_epoch')+j+1, 0)
        need(q(v.blob('before')) == generations[-1] and q(v.blob('after')) == after and
             after[0] > generations[-1][0], 'actual exact in-place generation renewal without append')
        generations.append(after)
    need(before.array('generation', 'li2_oneshot_generation')[0].data == o.array('generation', 'li2_oneshot_generation')[0].data and
         not any(before.array('generation', 'li2_oneshot_generation')[1].data) and
         q(before.blob('current_generation')) == generations[1] and q(o.blob('current_generation')) == generations[2],
         'publication and restoration generation prefixes')
    rel = o.sub('release', 'li2_oneshot_release'); oi.call(rel.sub('call', 'li2_oneshot_call'))
    exact(rel, transaction_live=0, reserved=0)
    zero(before, 'release', 'after')
    protocol = ((1,0,3),(1,0,5),(2,0,0),(1,0,1),(2,0,0),(1,0,3),(1,0,1),(2,0,0))
    for value, count, observations in ((before, 3, 3), (o, 8, 7)):
        exact(value, operations=count, observations=observations)
        for j, v in enumerate(value.array('operation', 'li2_oneshot_operation')):
            if j >= count:
                need(not any(v.data), 'unused full operation row zero'); continue
            need(tuple(v.number(n) for n in ('kind','page','protection')) == protocol[j], 'exact protection/synchronization protocol')
            exact(v, reserved=0); oi.call(v.sub('call', 'li2_oneshot_call'))
        for j, (v, c) in enumerate(zip(value.array('observation','li2_oneshot_observation'),
                                        value.array('observation_call','li2_oneshot_call'), strict=True)):
            if j >= observations:
                need(not any(v.data+c.data), 'unused full observation row zero'); continue
            oi.call(c); pp = v.array('pages', 'li2_oneshot_page')
            exact(pp[0], address=page.number('address'), allocation=page.number('allocation'), offset=page.number('offset'),
                  generation=generations[(0,1,1,1,1,2,2)[j]][0])
            need(not any(pp[1].data) and uints(v.blob('protection')) == ((1,3,5,5,1,3,1)[j],0) and
                 uints(v.blob('private_mapping')) == (1,0) and not any(v.blob('writable_aliases')),
                 'exact fresh source permission and negative alias observation')
            exact(v, page_count=1, landing_protection=5, landing_private=1, landing_writable_aliases=0,
                  landing_page=p.number('landing')&~4095, landing_allocation=p.number('landing_allocation'),
                  landing_generation=1, pid=pid, tid=pid)
    exact(backend, prepared=1, held=0, released=1, first_error=0, first_detail=0, sequence=p.number('sequence'),
          pid=pid, tid=pid, maps_started=12, maps_returned=12, observations=7, generation_steps=2)
    for name in ('backing_started','backing_returned','backing_verified'):
        need(uints(backend.blob(name)) == (1,0), 'actual sealed backing read prefix')
    need(q(backend.blob('backing_result')) == (PAGE,0), 'actual full-page retained-FD pread result')
    acquisition_ids = []
    for m in backend.array('maps','li2_fetch_map_progress'):
        oi.maps(m, True)
        acquisition_ids.append(m.sub('observation','li2_maps_observation').number('acquisition_id'))
    need(len(acquisition_ids) == 12 and all(a < b for a,b in zip(acquisition_ids,acquisition_ids[1:])),
         'all twelve actual fresh map acquisitions have strictly ordered distinct identities')
    backings = backend.array('backing','li2_fetch_backing')
    need(not any(backings[1].data), 'unused backing fragment zero')
    binding = module.sub('binding','li2_effect_object_binding').sub('actual','li2_fetch_backing')
    size = binding.sub('stat','stat').number('st_size', True)
    current_backing = row.sub('backing','li2_fetch_backing')
    # bind_sealed_object observes its supplied original-or-retained FD. Fetch
    # and publication use the object's separate retained FD. Device/inode,
    # seals and all immutable stat bytes join those real descriptors; the
    # subsequent two actual retained observations must use the same FD.
    backing(current_backing, binding, size, oi, same_fd=False)
    backing(backings[0], current_backing, size, oi)
    lifecycle = row.sub('lifecycle_after','li2_lifecycle_counts')
    need(lifecycle.number('retained_records') == backend.number('records_epoch') and
         lifecycle.number('generations') == generations[2][0], 'no page-record append during actual publication/restoration')
    reuse = row.sub('reuse_after','li2_oneshot_reuse_stats')
    exact(reuse, reset_started=1, reset_complete=1, last_completed_sequence=p.number('sequence'))
    need(reuse.number('prepared') == reuse.number('completed')+reuse.number('refused') == p.number('sequence'),
         'actual reusable backend retirement accounts for every prepared attempt')
    return p, generations[2][0]


def data_identity(v, pid, address_, oi, *, direct=False):
    exact(v, address=address_, page=address_ & ~4095, pid=pid, tid=pid, attempted=1, complete=1, error=0, detail=0)
    need(v.number('allocation') > 0 and v.number('generation') > 0, 'actual owned rseq data allocation and generation')
    oi.maps(v.sub('maps','li2_fetch_map_progress'), direct)
    return tuple(v.number(k) for k in ('address','page','allocation','generation','offset','pid','tid'))


def rseq(row, application, plan, pid, oi):
    states = [row.sub(name, 'li2_rseq_state') for name in ('rseq_before','rseq_after')]
    pins = [row.sub(name, 'li2_rseq_publication_state') for name in ('pin_published','pin_restored','pin_retired')]
    address_, fs, gs = application['rseq'][4], *application['machine'][1:3]
    identity = None
    for s in states:
        exact(s, initialized=1, registered=1, held=1, phase=3, first_error=0, first_detail=0, pid=pid, tid=pid,
              address=address_, page=address_ & ~4095, length=32, signature=0x53053053, epoch=1,
              fs_base=fs, gs_base=gs, fs_result=0, gs_result=0, tls_attempted=1, tls_complete=1,
              calls=1, registrations=1, unregistrations=0, kernel_errors=0)
        got = data_identity(s.sub('data','li2_rseq_data'), pid, address_, oi)
        if identity is None:
            identity = got
        need(got == identity, 'complete original registration data identity remains held')
        t = s.sub('transaction','li2_rseq_transaction')
        exact(t, attempted=1, issued=1, returned=1, result=0, prior_registered=0, input_word_observed=1, input_word=0)
        args = q(t.blob('args'))
        need(args[:4] == (address_,32,0,0x53053053), 'actual successful default libc registration request')
        for name in ('before','after'):
            need(data_identity(t.sub(name,'li2_rseq_data'), pid, address_, oi, direct=True) == identity,
                 'original registration before/after exact data identity')
        need(s.blob('data') == t.blob('after'), 'entire original successful registration data receipt remains the state anchor')
        before_id = t.sub('before','li2_rseq_data').sub('maps','li2_fetch_map_progress').sub('observation','li2_maps_observation').number('acquisition_id')
        after_id = t.sub('after','li2_rseq_data').sub('maps','li2_fetch_map_progress').sub('observation','li2_maps_observation').number('acquisition_id')
        need(before_id < after_id, 'two genuine ordered registration map acquisitions')
    want = bytearray(states[0].data)
    if row.number('site') % 3 == 1:
        # getpid is the sole selected SYSCALL. The ordinary source guard adds
        # exactly one syscall check and clears its two prior span diagnostics.
        for name, value in (('syscall_checks',states[0].number('syscall_checks')+1),('last_first',0),('last_end',0)):
            f = states[0].shape['fields'][name]
            need(f['bytes'] == 8 and value <= U64, 'exact rseq scalar counter width')
            want[f['offset']:f['offset']+8] = value.to_bytes(8,'little')
    need(bytes(want) == states[1].data, 'every rseq owner byte follows the exact no-write/getpid transition')
    for i, p in enumerate(pins):
        exact(p, phase=4 if i == 0 else 6, checking=0, first_error=0, first_detail=0, unsafe_terminal=0,
              registered=1, entry_checked=int(i != 0), pid=pid, tid=pid, pc=plan.number('pc'),
              landing=plan.number('landing'), address=address_, page=address_ & ~4095,
              sequence=plan.number('sequence'), registration_epoch=1, length=32, signature=0x53053053,
              fs_before=fs, gs_before=gs, word_before=0, word_entry=0, word_restored=0)
        need(p.number('attempts') == p.number('retired')+p.number('cancelled')+1 and
             p.number('last_closed_sequence') < p.number('sequence'), 'actual new publication pin lifetime')
        need(data_identity(p.sub('before','li2_rseq_data'), pid, address_, oi, direct=True) == identity,
             'fresh pre-publication data observation retains original registration')
        if i == 0:
            zero(p, 'fs_after','gs_after','fs_entry','gs_entry','fs_restored','gs_restored','after')
        else:
            exact(p, fs_after=fs, gs_after=gs)
            need(p.blob('fs_entry') == p.blob('fs_restored') == (application['machine'][6]&0xffff).to_bytes(2,'little') and
                 p.blob('gs_entry') == p.blob('gs_restored') == (application['machine'][6]>>16).to_bytes(2,'little'),
                 'actual uninterrupted publication segment selectors')
            need(data_identity(p.sub('after','li2_rseq_data'), pid, address_, oi, direct=True) == identity,
                 'fresh post-restoration data observation before the effect')
            pre_id=p.sub('before','li2_rseq_data').sub('maps','li2_fetch_map_progress').sub('observation','li2_maps_observation').number('acquisition_id')
            post_id=p.sub('after','li2_rseq_data').sub('maps','li2_fetch_map_progress').sub('observation','li2_maps_observation').number('acquisition_id')
            need(after_id < pre_id < post_id, 'new actual publication queries follow the historical registration receipt')
    # Retirement copies the genuine RESTORED state before incrementing its
    # global retired counter. No per-effect registration or rseq word changes.
    need(pins[1].data == pins[2].data, 'entire actual restored pin is the retired history')
    for name in pins[0].shape['fields']:
        if name not in ('phase','entry_checked','fs_after','gs_after','fs_entry','gs_entry','fs_restored','gs_restored','after'):
            need(pins[0].blob(name) == pins[1].blob(name), 'unchanged full publication pin field '+name)


def decoded(v, row, image):
    k = row.number('site') % 3
    exact(v, pc=row.number('pc'), next_pc=row.number('pc')+2, abi_version=1, decode_status=0,
          code=(1948,870,1162)[k], kind=KINDS[k], destination=16, width_bits=0,
          step_disposition=8, available=15, length=2, reserved=0)
    at = row.number('pc') & 4095
    need(v.blob('bytes') == image['source'][at:at+15]+b'\0', 'all original decoded source bytes and initialized tail')


def effect(row, root, image, module, application, sample, plan, generation, nx, ud, app, seed_profile, seed_probe):
    e = row.sub('effect','effect_runtime'); o = e.sub('owner','li2_effect_owner')
    inp = e.sub('input','li2_effect_input'); decision = o.sub('decision','li2_effect_decision')
    kind = KINDS[sample['kind']]; scripted = int(application['policy'] == 'scripted')
    exact(e, busy=0, finished=1, stage=8, random_applied=0, random_backend_returned=0,
          random_backend_status=0, first_error=0, first_detail=0,
          frame=ud['frame_address'], fp_address=ud['fp_address'], fp_bytes=len(ud['fp']),
          before_initialized=len(ud['fp']), after_initialized=len(ud['fp']))
    need(e.number('sequence') == row.number('end_effect_sequence') == row.number('begin_effect_sequence')+1 and
         e.number('sequence') == e.number('attempts') == e.number('commits') == e.number('completed') and
         e.number('native_completed')+e.number('scripted_completed') == e.number('completed') and
         sum(q(e.blob('classes'))) == e.number('completed'), 'one real fresh committed effect after exact publication')
    exact(o, phase=9, first_error=0, callback_entered=1, callback_returned=1, callback_status=0,
          native_entered=1-scripted, native_returned=1-scripted, exit_entered=0, committed=1,
          post_guards_complete=1-scripted, post_callback_entered=0, post_callback_returned=0, post_callback_status=0)
    zero(o, 'fault'); exact(decision, action=2 if scripted else 1, reserved=0); zero(decision,'fault')
    binding = o.sub('binding','li2_effect_binding'); bias = root.number('bridge_bias'); symbols = root.layout['symbols']
    exact(binding, abi_version=1, reserved=0, callback=bias+symbols['pa_policy_callback'], post_native=0,
          context=root.number('policy_address'))
    exact(inp, abi_version=1, source_count=1, sequence=e.number('sequence'))
    need(o.blob('input') == inp.data and inp.blob('decoded') == row.blob('decoded'),
         'every original full provider input and exact original decode copied unchanged')
    decoded(inp.sub('decoded','li2_decoded'), row, image)
    sources = inp.array('source','li2_effect_source'); source = row.sub('source','li2_fetch_page')
    exact(sources[0], page=source.number('address'), object_id=module.sub('binding','li2_effect_object_binding').number('object_id'),
          allocation=source.number('allocation'), generation=generation, offset=image['page_offset'], backing=1, reserved=0)
    need(not any(sources[1].data), 'unused full provider source tuple zero')
    state = inp.sub('before','li2_effect_state'); applied = e.sub('applied','li2_effect_state')
    selectors = struct.pack('<6H',application['machine'][3],0,0,0,
                            application['machine'][6]&0xffff,application['machine'][6]>>16)
    for v, pc, registers in ((state,sample['site'],sample['before']),(applied,sample['next_pc'],sample['after'])):
        exact(v, pc=pc, logical_flags=app.FLAGS)
        need(q(v.blob('gpr')) == registers[:16] and v.blob('selectors') == selectors and
             v.blob('selectors_observed') == (49).to_bytes(2,'little') and not any(v.blob('reserved')) and
             not any(v.blob('xstate')), 'all provider scalar state and explicit XSTATE NONE, never synthetic full state')
    result = o.sub('result','li2_effect_result'); exact(result, kind=kind, carry=0, aux=0, reserved=0)
    if kind == 1:
        need(result.number('value') == 0 and uints(result.blob('cpuid')) ==
             tuple(sample['after'][i] for i in (0,3,1,2)), 'exact four architectural CPUID limbs')
    else:
        zero(result,'cpuid')
        exact(result, value=sample['after'][0] if kind == 7 else sample['after'][0]|sample['after'][2]<<32)
    if scripted:
        need(decision.blob('result') == result.data and not any(o.blob('native_result')), 'scripted typed result with no invented native effect')
    else:
        need(o.blob('native_result') == result.data and not any(decision.blob('result')), 'actual native result preserved with no fixture post-callback')
    raw = row.sub('raw','selected_effect_raw_prefix')
    if kind == 7:
        exact(raw, number=39, entered=1-scripted, returned=1-scripted, result=application['pid'] if not scripted else 0)
    else:
        need(not any(raw.data), 'no raw syscall issue invented for the selected builtin')
        builtin = row.sub('builtin','selected_builtin_prefix')
        exact(builtin, kind=kind, phase=7 if kind == 5 and not scripted else 0, enable_result=0, restore_result=0)
        limbs = (0,0,0,0) if scripted else uints(result.blob('cpuid')) if kind == 1 else (sample['after'][0],0,0,sample['after'][2])
        for name, value in zip(('a','b','c','d'),limbs,strict=True):
            exact(builtin, **{name:value})
    need(e.blob('before') == ud['uc'] and e.blob('before_fp') == e.blob('after_fp') == ud['capacity'] and
         e.blob('after') == e.blob('work'), 'whole genuine landed UC and initialized FP retained before/after commit')
    exact(row, ds_before=application['machine'][5]&0xffff, ds_after=application['machine'][5]&0xffff,
          es_before=application['machine'][5]>>16, es_after=application['machine'][5]>>16,
          fs_after=application['machine'][1], gs_after=application['machine'][2],
          fs_started=1, fs_returned=1, gs_started=1, gs_returned=1, fs_result=0, gs_result=0, tls_complete=1)
    pin = row.sub('pin_restored','li2_rseq_publication_state')
    before = {k: ud[k] for k in ('uc','fp','frame_address','fp_address')}
    before.update(ds=row.number('ds_before'),es=row.number('es_before'),fs_base=pin.number('fs_after'),gs_base=pin.number('gs_after'))
    after = dict(before, uc=e.blob('after'),fp=e.blob('after_fp')[:e.number('fp_bytes')],
                 ds=row.number('ds_after'),es=row.number('es_after'),fs_base=row.number('fs_after'),gs_base=row.number('gs_after'))
    frame_layout = dict(uc_bytes=root.layout['uc_bytes'],greg=root.layout['offsets']['greg'],
                        fp_pointer=root.layout['offsets']['fp_pointer'],sigmask=root.layout['offsets']['mask'])
    app.frame_join(sample,before,after,frame_layout,application['format'],machine=application['machine'],
                   landing_pc=plan.number('landing'),seed_profile=seed_profile,seed_probe=seed_probe)
    return dict(index=sample['index'],before=before,after=after,landing_pc=plan.number('landing'))


def sample_at(application, images, index, app):
    if application['mode'] == 'state':
        return application['rows'][index]
    iteration, site = divmod(index, 6); module, kind = divmod(site, 3)
    image = images[module]; bias = application['header'][12+module]
    before = [0x1111000000000000+(module<<40)+(iteration<<16)+(kind<<8)+i for i in range(16)]
    before[4] = bias+image['stack']; before.append(app.FLAGS)
    if kind == 0:
        before[0] = before[1] = 0
    elif kind == 1:
        before[0] = 39
    pc, npc = bias+image['sites'][kind]['pc'], bias+image['sites'][kind]['next_pc']
    clock = application['clocks'][module][iteration] if kind == 2 else 0
    after = app.expected(tuple(before), module, kind, application['policy']=='scripted', application['pid'],
                         application['format']['cpuid'][0][2:], clock, npc)
    return dict(index=index,module=module,kind=kind,site=pc,next_pc=npc,before=tuple(before),after=after,
                before_live=app.LIVE_SEED,after_live=app.LIVE_SEED,x87_pc=bias+image['x87_pc'])


def hooks(owner, root):
    h = owner.sub('hooks','li2_oneshot_hooks'); bias = root.number('bridge_bias'); symbols = root.layout['symbols']
    mapping = dict(context='os_slots',raw='raw',frame_range='selected_oneshot_frame_range',
                   transfer='li2_lifecycle_oneshot_transfer',advance_generation='li2_lifecycle_oneshot_advance',
                   observe='li2_lifecycle_oneshot_observe',release='li2_lifecycle_oneshot_release')
    for field, symbol in mapping.items():
        exact(h, **{field:bias+symbols[symbol]})


def source_page(row, module, image):
    v = row.sub('source','li2_fetch_page'); bind = module.sub('binding','li2_effect_object_binding')
    st = row.sub('backing','li2_fetch_backing').sub('stat','stat')
    exact(v, address=row.number('bias')+image['page'], offset=image['page_offset'], initial_extent=0,
          backing=1, object=bind.number('object_id')-1, logical=5, closed_prot=1)
    first, end, address_ = (v.number(k) for k in ('vma_first','vma_end','address'))
    need(first % PAGE == end % PAGE == 0 and first <= address_ and PAGE <= end-address_ and
         v.number('vma_offset')+address_-first == image['page_offset'], 'actual full file-backed RX segment mapping')
    dev = st.number('st_dev')
    major = ((dev >> 8)&0xfff)|((dev >> 32)&0xfffff000)
    minor = (dev&0xff)|((dev >> 12)&0xffffff00)
    exact(v, vma_major=major, vma_minor=minor, vma_inode=st.number('st_ino'))


def counter_delta(row):
    before, after = (row.sub(name,'oneshot_counts') for name in ('counts_before','counts_after'))
    selected = ('cpuid','syscall','rdtsc')[row.number('site')%3]
    increments = {'attempted','published','restored','completed','retired','effect_started','effect_returned',selected}
    for name in before.shape['fields']:
        need(after.number(name) == before.number(name)+int(name in increments),
             'exact actual publication counter delta '+name)


def terminal(r, pid, application):
    counts = r.sub('terminal_counts','oneshot_counts'); reuse = r.sub('terminal_reuse','li2_oneshot_reuse_stats')
    need(counts.number('published') == counts.number('restored') == counts.number('effect_started') == counts.number('completed')+1 and
         counts.number('completed') == counts.number('effect_returned') == counts.number('retired') and
         counts.number('attempted') == counts.number('published')+counts.number('refused') and
         counts.number('cpuid')+counts.number('syscall')+counts.number('rdtsc') == counts.number('published'),
         'honest global nonreturning exit prefix after complete fixture retirements')
    need(reuse.number('prepared') == counts.number('attempted') and
         reuse.number('completed') == counts.number('retired') and
         reuse.number('refused') == counts.number('refused') and
         reuse.number('prepared') == reuse.number('completed')+reuse.number('refused')+1,
         'last exit transaction remains restored but not retired')
    exact(r, terminal_active=1, terminal_resetting=0)
    owner = r.sub('terminal_publication','li2_oneshot_owner'); plan = owner.sub('plan','li2_oneshot_plan')
    state = owner.sub('state','li2_oneshot_admission_state')
    exact(state, phase=7, first_error=0, first_detail=0, sequence=plan.number('sequence'), mutation_started=1,
          published=1, restored=1, reserved=0)
    exact(owner, initialized=1, in_handler=0, session=r.number('session_address'), transferred=1,
          landing_observed=1, source_write_started=1, write_attempted_mask=31, write_completed_mask=31,
          restore_started=1, restore_attempted_mask=31, restore_completed_mask=31)
    hooks(owner,r)
    need(plan.number('kind') == 1 and plan.blob('original')[:2] == b'\x0f\x05' and
         plan.number('sequence') == reuse.number('prepared') and
         plan.number('sequence') > reuse.number('last_completed_sequence'), 'actual last original exit syscall publication')
    e = r.sub('terminal_effect','effect_runtime'); o = e.sub('owner','li2_effect_owner')
    exact(e, busy=1, finished=0, stage=4, first_error=0, first_detail=0,
          random_applied=0, random_backend_returned=0, random_backend_status=0, after_initialized=0)
    need(e.number('attempts') == e.number('sequence') == e.number('completed')+1 and
         e.number('completed') == e.number('commits') == e.number('native_completed')+e.number('scripted_completed') and
         sum(q(e.blob('classes'))) == e.number('completed'), 'exit is entered and uncompleted, never an extra completed sample')
    exact(o, phase=5, first_error=0, callback_entered=1, callback_returned=1, callback_status=0,
          native_entered=1, native_returned=0, exit_entered=1, committed=0, post_guards_complete=0,
          post_callback_entered=0, post_callback_returned=0, post_callback_status=0)
    zero(o,'native_result','result','fault')
    d=o.sub('decision','li2_effect_decision');exact(d,action=1,reserved=0);zero(d,'result','fault')
    inp=e.sub('input','li2_effect_input');need(o.blob('input') == inp.data,'whole terminal provider input retained')
    dec=inp.sub('decoded','li2_decoded');pre=inp.sub('before','li2_effect_state');g=q(pre.blob('gpr'))
    need(dec.number('kind') == 7 and dec.number('pc') == plan.number('pc') and
         dec.number('next_pc') == plan.number('next_pc') and dec.blob('bytes')[:2] == b'\x0f\x05' and
         g[0] in (60,231) and g[7] == 0, 'actual original normal exit operation and zero status')
    raw=r.sub('terminal_raw','selected_effect_raw_prefix')
    exact(raw,entered=0,returned=0,number=g[0],result=0)
    rs=r.sub('terminal_rseq','li2_rseq_state')
    exact(rs,initialized=1,registered=1,held=1,phase=3,first_error=0,first_detail=0,pid=pid,tid=pid,
          address=application['rseq'][4],page=application['rseq'][4]&~4095,length=32,signature=0x53053053,
          epoch=1,fs_base=application['machine'][1],gs_base=application['machine'][2],fs_result=0,gs_result=0,
          tls_attempted=1,tls_complete=1,calls=1,registrations=1,unregistrations=0,kernel_errors=0)
    last=r.array('rows','pao_row')[-1].sub('rseq_after','li2_rseq_state')
    need(rs.blob('data')==last.blob('data') and rs.blob('transaction')==last.blob('transaction'),
         'complete historical default registration remains the actual terminal owner')
    for name in ('instruction_checks','range_checks','repeat_checks','run_checks','syscall_checks'):
        need(rs.number(name)>=last.number(name),'terminal rseq counter retains actual later checks '+name)
    pin=r.sub('terminal_pin','li2_rseq_publication_state')
    exact(pin,phase=6,checking=0,first_error=0,unsafe_terminal=0,registered=1,entry_checked=1,
          sequence=plan.number('sequence'),pc=plan.number('pc'),landing=plan.number('landing'),
          pid=pid,tid=pid,address=application['rseq'][4],registration_epoch=1,
          word_before=0,word_entry=0,word_restored=0)
    need(pin.number('attempts') == pin.number('retired')+pin.number('cancelled')+1,
         'last actual rseq publication remains restored before nonreturning kernel exit')
    return {name:counts.number(name) for name in counts.shape['fields']}


def read(data, stdout, layout, images, carrier, app, old_record, oi, xstate, *,
         pid, cpu, mode, policy, exit_status, seed_raw, seed_elf, seed_pid, seed_probe):
    """Read an actual complete state18 or stress9216 observed execution.

    images are the two results of unchanged app.elf() on independently bound
    emitted files. carrier is the source-bound main sealed carrier bytes/SHA.
    seed_raw/seed_elf are actual prerequisite captures, not a caller-selected
    zero mode. The enclosing supervisor must independently authenticate all
    source/artifact/process/capture/namespace and original B2 prerequisites.
    """
    need(type(data) is bytes and 0 < len(data) < 16 << 20 and type(layout) is dict and
         layout['types']['pao_record']['bytes'] == len(data), 'complete actual emitted record with original cap')
    need(type(exit_status) is int and exit_status == 0 and
         type(pid) is int and pid > 0 and type(cpu) is int and cpu >= 0 and
         mode in ('state','stress') and policy in ('native','scripted') and
         type(images) is list and len(images) == 2 and
         type(carrier) is dict and set(carrier) == {'bytes','sha256'} and
         type(carrier['bytes']) is int and carrier['bytes'] >= images[0]['bytes'] and
         type(carrier['sha256']) is str and len(carrier['sha256']) == 64 and
         all(c in '0123456789abcdef' for c in carrier['sha256']), 'independently bound finite command/source identities')
    application=app.output(stdout,images,pid=pid,cpu=cpu,mode=mode,policy=policy,xstate=xstate)
    seed_profile=seed_probe.read(seed_raw,seed_elf,application['format'],xstate,cpu=cpu,pid=seed_pid)
    seed_probe.require(seed_profile,application['format'],cpu=cpu)
    r=old_record.View(data,layout,'pao_record');padding(r)
    rounds=3 if mode=='state' else 1536;operations=rounds*6
    exact(r,magic=MAGIC,version=2,bytes=len(data),row_bytes=layout['types']['pao_row']['bytes'],
          uc_bytes=layout['uc_bytes'],fp_capacity=65536,rounds=rounds,scripted=int(policy=='scripted'),
          initialized=1,hardware_initialized=1,terminal=1,status=0,code=0,detail_abs=0,detail_negative=0,
          begun=operations,published=operations,landed=operations,restored=operations,effect_completed=operations,
          retired=operations,sampled=18,pending=0,pending_index=operations-1,pending_site=5,pending_row=U64,pending_phase=0,
          tls_queries_started=36,tls_queries_returned=36)
    need(q(r.blob('module_seen')) == (1,1) and q(r.blob('module_bias')) == tuple(application['header'][12:14]) and
         q(r.blob('visits')) == (rounds,)*6 and 0 < r.number('max_retained_at_fixture_retire') <= 8192,
         'all exact finite effects and bounded actual page records, without append-count fallback')
    need(r.number('bridge_bias') > 0 and r.number('bridge_bias') % PAGE == 0 and
         r.number('policy_sites_address') > 0 and r.number('policy_sites_address') % PAGE == 0,
         'actual bridge and protected immutable policy page')
    for field,symbol in (('session_address','selected_session'),('owner_address','selected_oneshot_current'),('policy_address','pa_policy_context')):
        exact(r,**{field:r.number('bridge_bias')+layout['symbols'][symbol]})
    session=r.sub('session','li2_step_session')
    exact(session,pid=pid,tid=pid,initialized=1,self_test_complete=1,sync_register=0,application_mask=oi.MASK)
    need(session.number('sync_query',True) >= 0 and session.number('sync_query') & 96 == 96 and
         application['machine'][0] == oi.MASK, 'actual selected session and blocked asynchronous signal policy')
    hw=r.sub('hardware','li2_selected_hardware');exact(hw,abi_version=1,reserved=0)
    for field,words in zip(('leaf0','leaf1','leaf7'),application['format']['cpuid'][:3],strict=True):
        need(uints(hw.blob(field)) == words[2:], 'actual initialized selected hardware matches independent application/probe')
    modules=bootstrap(r,images,carrier,oi);rows=r.array('rows','pao_row')
    indices=tuple(range(18)) if mode=='state' else SAMPLES
    need(len(rows)==len(indices)==18,'exact fixed actual sample selection')
    frames=[];history=[];previous_sequence=0;previous_effect=0;previous_generation=0;landings={};retained_fds={}
    for row,index in zip(rows,indices,strict=True):
        site=index%6;module=site//3;image=images[module];sample=sample_at(application,images,index,app)
        exact(row,index=index,site=site,module=module,iteration=index//6,phase=7,pc=sample['site'],
              bias=application['header'][12+module],stack=application['header'][12+module]+image['stack']-(STACK-256),
              policy_before=index,policy_after=index+1)
        need(row.blob('stack_before') == row.blob('stack_after') == bytes([0x5a])*STACK,
             'every actual private-stack byte remains literal after the effect')
        decoded(row.sub('decoded','li2_decoded'),row,image);source_page(row,modules[module],image)
        retained_fd=row.sub('backing','li2_fetch_backing').number('retained_fd',True)
        if module in retained_fds:
            need(retained_fds[module] == retained_fd, 'same actual retained object FD for every sample')
        retained_fds[module]=retained_fd
        p,generation=publication(row,r,modules[module],image,pid,oi)
        need(p.number('sequence') > previous_sequence and row.number('end_effect_sequence') > previous_effect and
             generation > previous_generation, 'strict real global attempt/effect/generation history across fixed samples')
        previous_sequence=p.number('sequence');previous_effect=row.number('end_effect_sequence');previous_generation=generation
        identity=(p.number('landing'),p.number('landing_allocation'),p.number('landing_generation'))
        if module in landings:
            need(landings[module] == identity,'same protected landing reused for this actual sealed object')
        landings[module]=identity
        hooks(row.sub('published','li2_oneshot_owner'),r)
        nx=frame(row.sub('nx','pao_frame'),layout,r,11,row.number('pc'),application['format'])
        ud=frame(row.sub('ud','pao_frame'),layout,r,4,row.number('landing'),application['format'])
        need(all(nx[k]==ud[k] for k in ('frame_address','fp_address','info_address','capacity')) and nx['g'][22]==row.number('pc'),
             'same genuine full frame allocation/FP and actual NX CR2')
        want=bytearray(nx['uc']);go=layout['offsets']['greg']
        for register,value in ((16,row.number('landing')),(19,0),(20,6)):
            struct.pack_into('<Q',want,go+8*register,value)
        si=bytearray(nx['si']);struct.pack_into('<i',si,layout['offsets']['siginfo_signo'],4)
        struct.pack_into('<Q',si,layout['offsets']['siginfo_address'],row.number('landing'))
        need(bytes(si)==ud['si'],'entire actual siginfo exact exception origin transition')
        # The libc-sized UC view can physically include the adjacent siginfo.
        # frame() proves both endpoint aliases. Project the exact checked
        # signal-origin transition into that overlap without editing raw bytes.
        ua,sa=nx['frame_address'],nx['info_address']
        first,end=max(ua,sa),min(ua+len(want),sa+len(si))
        if first<end:want[first-ua:end-ua]=si[first-sa:end-sa]
        need(bytes(want)==ud['uc'],'entire NX-to-UD2 UC and its actual siginfo alias transition')
        for name in ('published','retired'):
            owner_frame(row.sub(name,'li2_oneshot_owner').sub('before','li2_step_frame'),nx,oi.MASK)
        owner_frame(row.sub('retired','li2_oneshot_owner').sub('after','li2_step_frame'),ud,oi.MASK)
        rseq(row,application,p,pid,oi);counter_delta(row)
        frames.append(effect(row,r,image,modules[module],application,sample,p,generation,nx,ud,app,seed_profile,seed_probe))
        history.append(dict(index=index,module=module,kind=KINDS[site%3],sequence=p.number('sequence'),
                            effect_sequence=row.number('end_effect_sequence'),source_generation=generation))
    need(landings[0] != landings[1],'distinct protected main/DSO landing identities')
    need(r.number('max_retained_at_fixture_retire') >= max(row.sub('lifecycle_after','li2_lifecycle_counts').number('retained_records') for row in rows),
         'whole-run retained-record high-water includes every actually captured sample')
    counts=terminal(r,pid,application)
    need(counts['completed']>=operations and counts['cpuid']>=2*rounds and counts['rdtsc']>=2*rounds and
         counts['syscall']>=2*rounds+1, 'global observations include every fixture effect and the honest exit prefix')
    return dict(accepted=True,scope='actual_provider_app_six_sites',application=application,seed_profile=seed_profile,frames=frames,history=history,
                frame_layout=dict(uc_bytes=layout['uc_bytes'],greg=layout['offsets']['greg'],
                                  fp_pointer=layout['offsets']['fp_pointer'],sigmask=layout['offsets']['mask']),
                operations=operations,sampled=len(rows),mode=mode,policy=policy,pid=pid,cpu=cpu,
                record_bytes=len(data),record_sha256=hashlib.sha256(data).hexdigest(),
                global_counts=counts,publication_qualified=True,native_xstate_joined=False,full_state_qualified=False,
                capacity_stress_qualified=mode=='stress',max_retained_at_fixture_retire=r.number('max_retained_at_fixture_retire'),
                external_all_seven_and_masked_cpuid_prerequisites_required=True)


def native_pair(reference, observed, native_reader, app, xstate, boundary, seed_probe):
    need(observed['accepted'] is True and observed['mode']=='state' and len(observed['frames'])==18,
         'actual complete18 publication and frame population before native pairing')
    # This original consumer invokes unchanged xstate.pair/fp_payload for every
    # actual before/after NT and signal state. No FIP, MXCSR, inactive payload,
    # component byte or arbitrary register is excluded here.
    joined=native_reader.pair(reference,observed['application'],observed['frames'],observed['frame_layout'],
                              app,xstate,boundary,seed_probe=seed_probe)
    return dict(scope='actual_provider_app_state18',publication_qualified=True,native_xstate_joined=True,full_state_qualified=True,
                operations=18,comparison=joined,external_all_seven_and_masked_cpuid_prerequisites_required=True)
