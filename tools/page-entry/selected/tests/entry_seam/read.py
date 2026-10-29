"""Same-process entry preservation and literal MOV oracle; no normalization.

The enclosing qualifier owns source/ELF/DWARF, process, namespace and captures.
`boundary.fp_payload` is the unchanged complete architectural XSAVE comparator.
This oracle does not qualify another first route or use its durations as samples.
"""
import hashlib
import struct

U64 = (1 << 64) - 1
FP, STACK = 65536, 2 << 20
GREG = (13, 11, 14, 12, 9, 8, 10, 15, 0, 1, 2, 3, 4, 5, 6, 7)
MASK = U64 & ~sum(1 << (s-1) for s in (4, 5, 9, 11, 19, 31))
ENTRY = bytes.fromhex('4889e7e8680d0000')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def q(b):
    need(len(b) % 8 == 0, 'whole scalar vector')
    return struct.unpack('<'+'Q'*(len(b)//8), b)


class V:
    def __init__(self, data, layout, name):
        self.data, self.layout, self.name = data, layout, name
        self.fields = layout['types'][name]['fields']
        need(len(data) == layout['types'][name]['bytes'], 'complete '+name)
    def b(self, name):
        f = self.fields[name]; a, n = f['offset'], f['bytes']
        need(type(a) is int and type(n) is int and 0 <= a <= len(self.data) and 0 < n <= len(self.data)-a,
             'actual complete DWARF field')
        return self.data[a:a+n]
    def n(self, name, signed=False):
        b = self.b(name); need(len(b) in (4, 8), 'actual integer width')
        return int.from_bytes(b, 'little', signed=signed)
    def sub(self, name, kind):
        return V(self.b(name), self.layout, kind)
    def array(self, name, kind):
        b = self.b(name); n = self.layout['types'][kind]['bytes']
        need(n > 0 and len(b) % n == 0, 'complete typed array')
        return [V(b[i:i+n], self.layout, kind) for i in range(0, len(b), n)]


def exact(v, **kw):
    for k, want in kw.items():
        need(v.n(k, want < 0) == want, 'exact '+v.name+'.'+k)


def address(a, n, first, size):
    need(0 < first <= U64-size and 0 < n <= size and first <= a <= first+size-n,
         'whole actual alternate-stack extent')


def frame(v, r, layout, facts, sig, pc):
    exact(v, complete=1, signal=sig, uc_bytes=layout['uc_bytes'], fp_bytes=facts['extent']+4)
    n = v.n('fp_bytes'); uc = v.b('uc')[:layout['uc_bytes']]; fp = v.b('fp')[:n]; si = v.b('info')
    need(len(si) == layout['siginfo_bytes'] == 128 and not any(v.b('uc')[len(uc):]) and
         not any(v.b('fp')[n:]), 'complete initialized views and zero unused capacities')
    views = ((v.n('info_address'), si), (v.n('frame_address'), uc), (v.n('fp_address'), fp))
    for a, raw in views:
        address(a, len(raw), r.n('altstack_address'), r.n('altstack_bytes'))
        for b, other in views:
            lo, hi = max(a, b), min(a+len(raw), b+len(other))
            if lo < hi:
                need(raw[lo-a:hi-a] == other[lo-b:hi-b], 'all actual signal-view aliases exact')
    need(struct.unpack_from('<Q', fp, 472)[0] == facts['mask'], 'exact Linux signal xfeatures authority')
    off = layout['offsets']; g = struct.unpack_from('<23Q', uc, off['greg'])
    need(struct.unpack_from('<Q', uc, off['fp_pointer'])[0] == v.n('fp_address') and
         not v.n('fp_address') % 16 and struct.unpack_from('<Q', uc, off['mask'])[0] == MASK,
         'actual FP pointer and exact application signal mask')
    need(struct.unpack_from('<i', si, off['siginfo_signo'])[0] == sig and
         struct.unpack_from('<i', si, off['siginfo_errno'])[0] == 0,
         'actual signal identity/error')
    if pc is not None:
        need(struct.unpack_from('<i', si, off['siginfo_code'])[0] == 2 and
             struct.unpack_from('<Q', si, off['siginfo_address'])[0] == pc and g[16] == pc and
             g[19:21] == ((21, 14) if sig == 11 else (0, 1)), 'genuine NX or hardware TRACE')
    return dict(g=g, uc=uc, si=si, fp=fp, view=v, views=views)


def initialized_seed(seed, facts):
    need(len(seed) == FP and not any(seed[facts['extent']:]), 'full independent live XSAVE and zero unused capacity')
    need(struct.unpack_from('<HHB', seed) == (0x37f, 0x3000, 0xc0) and
         seed[32:42] == bytes.fromhex('35c26821a2da0fc90040') and
         seed[48:58] == bytes.fromhex('0000000000000080ff3f') and
         struct.unpack_from('<I', seed, 24)[0] == 0x1f80,
         'independent nonempty literal x87 stack and MXCSR seed')
    need(q(seed[520:528]) == (0,) and not any(seed[528:576]) and
         q(seed[512:520])[0] & 0xe7 == 0xe7 and not q(seed[512:520])[0] & ~facts['mask'],
         'all seeded components active in exact standard XSAVE format')
    components = {bit: (a, b) for a, b, bit in facts['components']}
    vectors = bytes((37*i+11) & 255 for i in range(2048))
    for i in range(16):
        need(seed[160+16*i:176+16*i] == vectors[64*i:64*i+16] and
             seed[components[2][0]+16*i:components[2][0]+16*(i+1)] == vectors[64*i+16:64*i+32] and
             seed[components[6][0]+32*i:components[6][0]+32*(i+1)] == vectors[64*i+32:64*i+64],
             'every low16 ZMM byte independently seeded')
    need(seed[slice(*components[7])] == vectors[1024:] and
         q(seed[slice(*components[5])]) == tuple(0x8877665544332200+i for i in range(8)),
         'all high16 ZMM and all eight opmask registers independently seeded')


def whole_transition(before, after, layout, edits, signal, pc):
    """Apply only named architectural edits and their actual SI/UC intersection."""
    need(tuple(a for a, _ in before['views']) == tuple(a for a, _ in after['views']),
         'same complete physical kernel frame allocations')
    off = layout['offsets']; want = bytearray(before['uc']); si = bytearray(before['si'])
    for index, value in edits.items():
        struct.pack_into('<Q', want, off['greg']+8*index, value)
    struct.pack_into('<i', si, off['siginfo_signo'], signal)
    struct.pack_into('<Q', si, off['siginfo_address'], pc)
    need(after['si'] == bytes(si) and after['fp'] == before['fp'],
         'whole genuine siginfo and complete initialized FP transition')
    a, b = before['view'].n('frame_address'), before['view'].n('info_address')
    lo, hi = max(a, b), min(a+len(want), b+len(si))
    if lo < hi:
        want[lo-a:hi-a] = si[lo-b:hi-b]
    need(after['uc'] == bytes(want), 'every actual ucontext byte equals its explicit expected value')


def check(data, layout, mode, pid, cpu, image, boundary, xstate):
    need(type(mode) is int and mode in range(4) and type(data) is bytes and len(data) < 16 << 20,
         'fixed genuine entry case and original stream bound')
    r = V(data, layout, 'eso_record')
    # All private storage begins zero; copied opaque UC/siginfo/FP stay whole.
    def padding(v):
        intervals=sorted((f['offset'],f['offset']+f['bytes']) for f in v.fields.values())
        at=0
        for lo,hi in intervals:
            need(at<=lo<hi<=len(v.data) and not any(v.data[at:lo]), 'complete disjoint fields/zero private gaps')
            at=hi
        need(not any(v.data[at:]), 'zero trailing private padding')
    padding(r)
    exact(r, magic=0x314d41455349324c, version=1, bytes=len(data), mode=mode, initialized=1, terminal=1,
          status=0 if mode == 0 else 125, code=(0, 803, 803, 218)[mode],
          detail=(0, -22, -22, 11)[mode])
    fmt = q(r.b('format')); cp = [struct.unpack_from('<6I', r.b('cpuid'), 24*i) for i in range(67)]
    need(fmt[0] == fmt[12] == 1 and fmt[1] == fmt[5] == fmt[7] == fmt[9] == 0 and
         fmt[2] == fmt[10] == cpu and fmt[3] == fmt[11] and not any(fmt[13:]), 'complete actual pre-entry format observations')
    facts = xstate.profile(cp, fmt[4], fmt[6], fmt[8], cpu, fmt[3])
    need(facts['mask'] & 0xe7 == 0xe7, 'qualified all32 ZMM and opmask component domain')
    seed = r.b('seed_fp'); initialized_seed(seed, facts)
    regs = tuple(r.n('kernel_sp') if i == 7 else 0x1122334455667700+i for i in range(16)) + (0xad7,)
    need(q(r.b('seed_gpr')) == regs and r.n('seed_mask') == facts['mask'] and r.n('seed_mode') == 1,
         'independent actual live16 GPR/logical flags/XSAVE mode')
    a, b = r.array('saved', 'eso_saved')
    exact(a, complete=1, xmask=facts['mask'], xmode=1, target=r.n('source_pc'))
    need(q(a.b('gpr')) == regs and a.b('fp') == seed, 'real production _start saved every seeded byte before boot')
    need(mode == 1 and not any(b.data) or mode != 1 and b.data == a.data,
         'entire saved17/XSAVE/mask/mode/target byte-identical around actual timing call')
    pc = r.n('source_pc'); bias = r.n('source_bias')
    bridge_bias = r.n('bridge_start')-layout['symbols']['_start']
    need(bridge_bias > 0 and bridge_bias % 4096 == 0 and r.n('old_at_base')==bridge_bias, 'actual independent bridge load bias')
    session=r.sub('session','li2_step_session');padding(session)
    exact(session,pid=pid,tid=pid,initialized=1,self_test_complete=1,application_mask=MASK,sync_register=0)
    need(session.n('sync_query') & 96 == 96, 'actual registered sync capability')
    need(pc == bias+image['elf_entry'] and image['entry_bytes'] == ENTRY.hex() and
         r.n('source_file_offset') == image['entry_file_offset'] & ~4095,
         'actual interpreter target and independently mapped source backing offset')
    page = r.sub('page', 'li2_lifecycle_page_view');padding(page)
    exact(page, offset=r.n('source_file_offset'), logical=5, actual=1, backing=1, admitted=0)
    need(page.n('allocation') > 0 and page.n('generation') > 0, 'genuine current immutable allocation/generation')
    pages = r.b('pages'); need(pages[:4096] == image['page'], 'complete original source page')
    n = r.n('stack_bytes'); at = r.n('at_base_offset'); stacks = r.b('stacks')
    need(0 < n <= STACK and r.n('stack_end')-r.n('stack_first') == n and
         r.n('stack_first') <= r.n('kernel_sp') < r.n('stack_end') and 0 <= at <= n-8,
         'whole original kernel-stack mapping and exact original AT_BASE slot')
    raw_stack = [stacks[i*STACK:(i+1)*STACK] for i in range(6)]
    need(all(not any(s[n:]) for s in raw_stack), 'unused complete stack capture capacities remain zero')
    want = bytearray(raw_stack[0]); need(q(want[at:at+8]) == (r.n('old_at_base'),), 'actual original auxv base')
    struct.pack_into('<Q', want, at, bias)
    need(raw_stack[1] == bytes(want) and r.n('initial_mask') == 0 and r.n('mask_after_boot') == MASK,
         'real boot changes only exact AT_BASE stack slot and installs the declared mask')
    timing = r.sub('timing', 'entry_timing')
    exact(timing, initialized=1, mode=2, start_called=1, started=1, clock_attempted=1 if mode == 1 else 2,
          clock_complete=2 if mode == 0 else 0 if mode == 1 else 1,
          complete=int(mode == 0), ingress=int(mode != 1), armed=int(mode != 1),
          route=0 if mode == 1 else 4, instructions_known=int(mode != 1), instructions=int(mode != 1),
          repeat_iterations=0, native_pages=0, native_refaults=0,
          first_error=803 if mode in (1, 2) else 0,
          first_detail=-22 if mode in (1, 2) else 0)
    need(timing.b('source')==page.data, 'whole timing source page equals actual pre-restore source')
    ident = q(timing.b('identity')); closure = q(timing.b('closure'))
    need(ident[:7] == (pc, image['elf_entry'], pc & ~4095, page.n('allocation'), page.n('generation'),
                       r.n('source_file_offset'), 1) and closure[4] == 0,
         'whole timing source identity joined to actual entry and backing')
    results = q(timing.b('clock_result')); ns = q(timing.b('ns'))
    need(results == ((U64-21, 0) if mode == 1 else (0, U64-21) if mode == 2 else (0, 0)),
         'actual raw clock return prefix, including entered/unreturned nested case')
    before, after = timing.array('before', 'li2_maps_stats'), timing.array('after', 'li2_maps_stats')
    count = 1 if mode == 1 else 2
    for i in range(count):
        exact(before[i], active=i, poisoned=0, reserved=0)
        if mode == 3 and i == 1:
            need(not any(after[i].data), 'nested clock never returned to post-call observation')
        elif (mode==1 and i==0) or (mode==2 and i==1):
            # Actual ID -1 is outside maps_nonmutating: before + after + the
            # negative-result phase_end each invalidate once. No query occurs.
            want=bytearray(before[i].data)
            for name in ('invalidations','mutation_epoch'):
                f=before[i].fields[name];value=before[i].n(name)
                need(value<=U64-3, 'bounded actual failed-clock epoch advance')
                want[f['offset']:f['offset']+f['bytes']]=(value+3).to_bytes(f['bytes'],'little')
            for name in ('active','valid'):
                f=before[i].fields[name];want[f['offset']:f['offset']+f['bytes']]=bytes(f['bytes'])
            need(after[i].data==bytes(want), 'whole exact maps prefix of genuine invalid clock failure')
        else:
            need(after[i].data == before[i].data, 'whole actual clock maps-state equality')
    if mode == 1:
        exact(r,release_seen=0,release_count=0,fs_endpoint=0,gs_endpoint=0)
        need(not any(r.b('endpoint_selectors')), 'no endpoint selector observation before first-clock failure')
        need(not any(r.b('nx')+r.b('trace')+r.b('closed')+r.b('returned')+r.b('nested')+r.b('owner')+r.b('borrow')+r.b('released')) and
             not any(pages[4096:]+stacks[2*STACK:]) and not any(timing.b('after')[64:]+timing.b('before')[64:]) and
             ident[7:] == (0, 0) and not any(closure) and ns == (0, 0) and
             timing.n('origin_count')==0 and not any(timing.b('origins')), 'real first-clock failure has no target or endpoint credit')
    else:
        need(raw_stack[1] == raw_stack[2] == raw_stack[3] == raw_stack[4] and
             pages[:4*4096] == image['page']*4, 'every application-stack and source-page byte retained throughout both seams')
        c = frame(r.sub('nx', 'eso_frame'), r, layout, facts, 11, pc)
        d = frame(r.sub('trace', 'eso_frame'), r, layout, facts, 5, pc+3)
        e = frame(r.sub('closed', 'eso_frame'), r, layout, facts, 5, pc+3)
        need(tuple(c['g'][i] for i in GREG) == regs[:16] and c['g'][17] == regs[16] | 0x10000,
             'genuine initial NX contains all independently seeded original inputs')
        need(c['g'][18] == (0x2b << 48 | 0x33), 'actual CS/SS/GS/FS selectors')
        for f in (c, d, e):
            boundary.fp_payload(seed[:facts['extent']], f['fp'])
        want = list(c['g']); want[8] = regs[7]; want[16] = pc+3; want[17] = regs[16] | 0x100
        want[19:21] = (0, 1)
        need(d['g'] == tuple(want), 'independent original MOV RSP to RDI and complete register/exception result')
        whole_transition(c, d, layout, {8: regs[7], 16: pc+3, 17: regs[16] | 0x100, 19: 0, 20: 1}, 5, pc+3)
        whole_transition(d, e, layout, {17: regs[16]}, 5, pc+3)
        exact(r, release_seen=1, release_count=0)
        need(r.n('fs') == r.n('fs_endpoint') and r.n('gs') == r.n('gs_endpoint') and
             r.b('selectors') == r.b('endpoint_selectors'), 'actual complete TLS bases/selectors unchanged')
        owner = r.sub('owner', 'li2_step_owner'); ref = r.sub('borrow', 'li2_fetch_ref')
        exact(owner, phase=5, first_error=0, first_detail=0, in_handler=0, self_test=0, trace_seen=1,
              revoke_sync_started=1, open_sync=0, revoke_sync=0, destination=7, source=4, width=64, effect=2)
        padding(owner)
        exact(owner, session=bridge_bias+layout['symbols']['selected_session'],
              signal_number=5,signal_code=2,signal_errno=0,signal_address=pc+3,immediate=0)
        hooks=owner.sub('hooks','li2_step_hooks');padding(hooks)
        exact(hooks,context=0,authenticate=bridge_bias+layout['symbols']['selected_authenticate'],
              failure=bridge_bias+layout['symbols']['selected_step_failure'])
        request=owner.sub('request','li2_step_request');padding(request)
        exact(request,page_count=1,original_flags=regs[16])
        decoded=request.sub('decoded','li2_decoded');padding(decoded)
        exact(decoded,pc=pc,next_pc=pc+3,abi_version=1,decode_status=0,code=282,kind=0,
              destination=16,width_bits=0,step_disposition=1,available=15,length=3,reserved=0)
        source_at=image['entry_file_offset']%4096
        need(decoded.b('bytes')==image['page'][source_at:source_at+15]+b'\0', 'full original decoder window and zero tail')
        first,unused=request.array('pages','li2_step_page');padding(first)
        exact(first,address=pc&~4095,object=page.n('allocation'),generation=page.n('generation'),
              offset=page.n('offset'),closed_prot=1,open_prot=5)
        need(not any(unused.data), 'unused second request page remains zero')
        # x86 architectural register numbering is RDI=7, RSP=4 in the old owner.
        for name in ('open_started', 'opened', 'revoke_started', 'revoked'):
            need(struct.unpack('<2I', owner.b(name)) == (1, 0), 'one actual source page opened/revoked')
        need(not any(owner.b('open_result')+owner.b('revoke_result')), 'actual permission operations succeeded')
        for name, actual in (('before', c), ('after', d)):
            f = owner.sub(name, 'li2_step_frame');padding(f)
            need(q(f.b('greg')) == actual['g'] and f.n('mask') == MASK and
                 f.n('fp_address') == actual['view'].n('fp_address') and
                 f.n('fp_bytes') == f.n('initialized') == len(actual['fp']) and
                 f.b('fp') == actual['view'].b('fp'), 'complete actual owner frame joins genuine endpoint')
        release = r.sub('released', 'li2_fetch_progress')
        padding(release)
        exact(release, held=0, complete=1, first_error=0, first_detail=0, identity_observed=1,
              pages_copied=1,bytes_copied=15,sequence=ref.n('sequence'))
        need(release.n('validation_calls')>0, 'actual validate/release work retained')
        need(ref.n('owner') > 0 and ref.n('sequence') > 0 and
             closure[:3] == (ref.n('sequence'), ref.n('sequence'), pc+3) and
             ident[7] > 0 and ident[8] > 0 and closure[3] > ident[8] and ns[0] > 0,
             'same real borrow, actual later TRACE, complete release and clock prefix')
        if mode == 0:
            returned = frame(r.sub('returned', 'eso_frame'), r, layout, facts, 5, pc+3)
            need(returned['view'].data == e['view'].data and raw_stack[5] == raw_stack[4] and
                 pages[4*4096:] == image['page'] and
                 r.n('fs_returned')==r.n('fs_endpoint') and r.n('gs_returned')==r.n('gs_endpoint') and
                 r.b('returned_selectors')==r.b('endpoint_selectors'),
                 'whole actual frame/FP/stack/source unchanged after the real closure clock helper')
            need(ns[1] >= ns[0] and timing.n('origin_count') == 11, 'genuine second clock and all original recurring completions')
        else:
            need(not any(r.b('returned')+raw_stack[5]+pages[4*4096:]), 'failed helper has no returned state')
            need(not any(timing.b('origins')), 'no invented recurring origin rows before failed first entry')
            need(ns[1] == 0 and timing.n('origin_count') == 0, 'failed endpoint has no completed interval/sample')
    if mode != 0:
        exact(r,fs_returned=0,gs_returned=0)
        need(not any(r.b('returned_selectors')), 'unreturned helper has no later selector observation')
    if mode == 3:
        exact(r, nested_issued=1, nested_returned=0, nested_result=0)
        f = frame(r.sub('nested', 'eso_frame'), r, layout, facts, 11, None); off = layout['offsets']
        need(struct.unpack_from('<i', f['si'], off['siginfo_code'])[0] == -6 and
             struct.unpack_from('<i', f['si'], off['siginfo_pid'])[0] == pid,
             'actual same-process SI_TKILL interruption, not a supplied fault frame')
    else:
        exact(r, nested_issued=0, nested_returned=0, nested_result=0)
        need(not any(r.b('nested')), 'no fabricated nested event')
    return dict(mode=mode, status='accepted_actual_observation', source_pc=pc,
                source_allocation=page.n('allocation'), source_generation=page.n('generation'),
                source_file_offset=r.n('source_file_offset'), full_state=mode != 1,
                completed_entry=int(mode == 0), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
