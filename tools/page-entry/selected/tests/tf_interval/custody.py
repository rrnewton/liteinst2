"""Explicit custody interval authority; every ordinary frame check is shared.

Retained origins are never supplied as current maps receipts. Timing lanes
retain empty FD3 and make no binary/frame or BODY-local custody claim.
"""
import importlib.util
import json
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from page_selected import need

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), module.__dict__)
    return module

HERE = Path(__file__).resolve().parent
base = load('tci_interval_base', HERE / 'check.py')
authority = load('tci_custody_authority', HERE.parent / 'page_custody/check.py')
elf, native, output, control_output, PROFILES = base.elf, base.native, base.output, base.control_output, base.PROFILES
capture_identity = base.capture_identity
BODY, MAIN = base.BODY, base.MAIN
delta = authority._delta

class Reports:
    @staticmethod
    def reports(stderr):
        need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete actual custody reports')
        changed, rows = 0, []
        for line in stderr[:-1].split(b'\n'):
            prefix, sep, raw = line.partition(b' ')
            if prefix == b'LI2_LOADER':
                need(sep == b' ', 'actual loader row separator')
                value = base.reports.old.base.decode.decode(raw)
                need(value['scope'] == 'partial_selected_sealed_page_custody', 'one literal custody production scope')
                value['scope'] = 'partial_selected_same_page_tf_lease'
                line = prefix + b' ' + json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
                changed += 1
            rows.append(line)
        need(changed == 1, 'exactly one original custody loader row')
        return base.reports.reports(b'\n'.join(rows) + b'\n')
    completed = staticmethod(base.reports.completed)
    join = staticmethod(base.reports.join)

reports = Reports

class Reader(base.Reader):
    # These methods are reused from the independently reviewed custody reader.
    values = authority.Reader.values
    array = authority.Reader.array
    changed = authority.Reader.changed
    zero = authority.Reader.zero
    maps_fresh = authority.Reader.maps_fresh
    maps_state = authority.Reader.maps_state
    custody_state = authority.Reader.custody_state
    session = authority.Reader.session
    receipt = authority.Reader.receipt
    view = authority.Reader.view
    remember_backing = authority.Reader.remember_backing
    after_native_copy = authority.Reader.after_native_copy
    history = authority.Reader.history

    def __init__(self, data, layout, record):
        need(record == 'tfi_record', 'custody reader only for the explicit observed lane')
        self.retained_sequences = set()
        self.history_views, self.history_anchors = {}, {}
        self.origin = self.previous = self.session_bytes = None
        self.accepted_transfers = {}
        base.Reader.__init__(self, data, layout, record)

    def extra_names(self, names):
        return names | set('tci_record tci_row tci_meta li2_page_custody_stats li2_maps_stats li2_step_session li2_page_custody_receipt'.split())

    def extra_forms(self, forms):
        z = lambda t: self.types[t]['bytes']
        forms['tfi_record']['custody'] = z('tci_record')
        forms.update({
            'tci_meta': dict(h=128, argument=z('li2_fetch_ref'), published=z('li2_fetch_ref'), session=z('li2_step_session'), custody=z('li2_page_custody_stats'), maps=z('li2_maps_stats'), view=z('li2_fetch_rx_view')),
            'tci_row': dict(entry=z('li2_page_custody_stats'), returned=z('li2_page_custody_stats'), ready=z('li2_page_custody_stats'), entry_maps=z('li2_maps_stats'), returned_maps=z('li2_maps_stats'), ready_maps=z('li2_maps_stats'), stage=z('tci_meta'), commit=z('tci_meta'), ready_frame=z('tfi_trace_frame')),
            'tci_record': dict(h=128, rows=256*z('tci_row'), terminal=z('li2_page_custody_stats')),
            'li2_page_custody_stats': dict(epoch=8, seeds=8, retained_stages=8, retained_checks=8, commits=8, discards=8, phase=4, last_reason=4),
            'li2_maps_stats': dict(fresh_calls=8, acquisitions=8, reuses=8, invalidations=8, handler_id=8, mutation_epoch=8, active=4, valid=4, poisoned=4, reserved=4),
            'li2_step_session': dict(pid=8, tid=8, sync_register=8, sync_query=8, application_mask=8, initialized=4, self_test_complete=4),
            'li2_page_custody_receipt': dict(kind=4, provenance=4, slot=4, checks=4, epoch=8, origin_sequence=8, owner_generation=8, event=8, chain=8, owner=8, session=8, origin=z('li2_fetch_map_progress')),
            'li2_fetch_rx_view': dict(phase=4, complete=4, result=4, serial=8, before_sequence=8, after_sequence=8, pc=8, length=8, pid=8, tid=8, bytes=15, page=z('li2_fetch_page'), backing=z('li2_fetch_backing'), maps=z('li2_fetch_map_progress'), maps_observed=4, custody=z('li2_page_custody_receipt')),
        })
        need((z('li2_page_custody_stats'), z('li2_maps_stats'), z('li2_step_session'), z('li2_page_custody_receipt')) == (56, 64, 48, 160), 'exact custody core ABI extents')

    def padding_tree(self, b, t):
        base.Reader.padding_tree(self, b, t)
        children = {
            'tfi_record': dict(custody='tci_record'),
            'tci_record': dict(rows='tci_row', terminal='li2_page_custody_stats'),
            'tci_row': dict(entry='li2_page_custody_stats', returned='li2_page_custody_stats', ready='li2_page_custody_stats', entry_maps='li2_maps_stats', returned_maps='li2_maps_stats', ready_maps='li2_maps_stats', stage='tci_meta', commit='tci_meta', ready_frame='tfi_trace_frame'),
            'tci_meta': dict(argument='li2_fetch_ref', published='li2_fetch_ref', session='li2_step_session', custody='li2_page_custody_stats', maps='li2_maps_stats', view='li2_fetch_rx_view'),
            'li2_fetch_rx_view': dict(custody='li2_page_custody_receipt'),
            'li2_page_custody_receipt': dict(origin='li2_fetch_map_progress'),
        }.get(t, {})
        for key, child in children.items():
            for raw in self.array(b, t, key, child): self.padding_tree(raw, child)

    def preparation(self, b, ref):
        if self.integer(ref, 'li2_fetch_ref', 'sequence') in self.retained_sequences:
            self.zero(self.field(b, 'li2_fetch_progress', 'preparation'), 'authenticated retained borrow preparation')
        else:
            base.Reader.preparation(self, b, ref)

    def body_prepare(self, image, pid, opening, anchor, page_identity):
        I, F = self.integer, self.field
        self.image, self.pid, self.anchor, self.page_identity = image, pid, anchor, page_identity
        self.N = image['count']; self.opening = opening
        chain = I(opening, 'li2_tf_chain_slot', 'chain'); slot = I(opening, 'li2_tf_chain_slot', 'index')
        terminal = F(self.data, self.rt, 'terminal_chain')
        session = I(terminal, 'li2_tf_chain', 'session')
        owner = chain + self.types['li2_tf_chain']['fields']['slots']['offset'] + slot*self.types['li2_tf_chain_slot']['bytes'] + self.types['li2_tf_chain_slot']['fields']['owner']['offset'] + self.types['li2_tf_owner']['fields']['step']['offset']
        self.identity = dict(chain=chain, owner=owner, slot=slot, generation=I(opening, 'li2_tf_chain_slot', 'generation'), session=session)
        self.extra = F(self.data, self.rt, 'custody'); h = base.q(F(self.extra, 'tci_record', 'h'))
        need(h[:6] == (0x3159545344434954, 1, self.types['tci_record']['bytes'], self.N, self.N, 0) and h[6:9] == (I(terminal, 'li2_tf_chain', 'event_id'), chain, session) and not any(h[9:]), 'complete actual custody BODY and handler-end rows')
        self.rows = self.array(self.extra, 'tci_record', 'rows', 'tci_row')
        self.zero(b''.join(self.rows[self.N:]), 'unreached custody rows')
        self.body_start = self.custody_state(F(self.rows[0], 'tci_row', 'entry'))
        historical = F(F(self.data, self.rt, 'body_lease_before'), 'li2_tf_same_page', 'transfer')
        self.previous_serial = I(historical, 'li2_fetch_rx_view', 'serial')
        if any(historical):
            need(I(historical, 'li2_fetch_rx_view', 'pc') < BODY, 'pre-BODY history is only earlier fixed setup/WAIT code')
            old = self.history(historical, image, pid, dict(chain=chain, chain_session=session, event=I(opening, 'li2_tf_chain_slot', 'event_id'), custody=self.body_start))
            self.after_native_copy(old, anchor)

    def body_event(self, index, row):
        I, F = self.integer, self.field
        e = self.rows[index]; et = 'tfi_event'; rt = 'tci_row'; mt = 'tci_meta'; vt = 'li2_fetch_rx_view'
        bc = base.q(F(row, et, 'counts_before')); transfer = index+1 < self.N
        ob, oa = F(row, et, 'owner_before'), F(row, et, 'owner_after')
        before, after = F(ob, 'tfi_owner', 'ref'), F(oa, 'tfi_owner', 'ref')
        seq = I(before, 'li2_fetch_ref', 'sequence'); pc = BODY+4*(index+1)
        ident = dict(self.identity, event=bc[0])
        entry, returned, ready = (self.custody_state(F(e, rt, k)) for k in ('entry', 'returned', 'ready'))
        em, rm, hm = (self.maps_state(F(e, rt, k)) for k in ('entry_maps', 'returned_maps', 'ready_maps'))
        need(em['active'] == 1 and em['valid'] == 0, 'global maps invalid at every actual instruction entry')
        if self.previous is not None:
            delta(self.previous[0], entry, dict(phase=1), 'actual READY consumed by next ENTRY')
            delta(self.previous[1], em, dict(invalidations=3, mutation_epoch=3, handler_id=1, valid=-self.previous[1]['valid']), 'ordinary return/event maps invalidation remains unconditional')
        else:
            need(entry['phase'] == 0, 'first BODY has no inherited live certificate')

        def meta(raw, point, published):
            h = base.q(F(raw, mt, 'h'))
            need(h[:10] == (1, point, index, 0, ident['chain'], ident['owner'], ident['slot'], ident['generation'], ident['event'], ident['session']) and not any(h[10:]), 'actual outer API identity and zero successful result')
            need(F(raw, mt, 'argument') == before and F(raw, mt, 'published') == published, 'exact actual API input and published singleton references')
            session = self.session(F(raw, mt, 'session'), self.pid, self.session_bytes)
            self.session_bytes = session
            return F(raw, mt, 'view'), self.custody_state(F(raw, mt, 'custody')), self.maps_state(F(raw, mt, 'maps'))

        stage, ss, sm = meta(F(e, rt, 'stage'), 1, bytes(self.types['li2_fetch_ref']['bytes']))
        serial = I(stage, vt, 'serial')
        need(serial == self.previous_serial+1, 'each actual BODY stage consumes exactly the next RX serial after its retained predecessor')
        kind = 1 if index == 0 else 2
        proof, _, _ = self.view(stage, self.image, self.pid, ident, ss, self.origin, 2, seq, pc, int(kind == 2), self.anchor, self.page_identity)
        need(proof['kind'] == kind and ss['phase'] == 4, 'one actual FRESH stage followed only by RETAINED stages')
        if kind == 1:
            self.maps_fresh(F(stage, vt, 'maps'), sm)
            effects = ss['epoch']-entry['epoch']; need(effects >= 4, 'actual complete maps open/read/EOF/close prefix')
            delta(entry, ss, dict(epoch=effects, discards=effects, phase=4, last_reason=1-entry['last_reason']), 'fresh stage cannot claim committed/retained work')
            delta(em, sm, dict(fresh_calls=1, acquisitions=1, invalidations=2*effects+3, mutation_epoch=2*effects+3, handler_id=1, valid=1), 'complete fresh-map effect accounting')
        else:
            delta(entry, ss, dict(phase=2, retained_stages=1, retained_checks=1), 'one genuine retained stage and fresh backing check')
            delta(em, sm, dict(invalidations=2, mutation_epoch=2, handler_id=1), 'retained path preserves invalidation without maps I/O')
        actual = F(row, et, 'transfer')
        if transfer:
            commit, cs, cm = meta(F(e, rt, 'commit'), 2, after)
            self.view(commit, self.image, self.pid, ident, cs, None if kind == 1 else self.origin, 4, seq, pc, 2*int(kind == 2), self.anchor, self.page_identity)
            self.changed(stage, commit, vt, 'phase after_sequence custody')
            self.changed(F(stage, vt, 'custody'), F(commit, vt, 'custody'), 'li2_page_custody_receipt', 'checks')
            delta(ss, cs, dict(phase=1, retained_checks=int(kind == 2)), 'actual outer commit before publication')
            delta(sm, cm, dict(reuses=1) if kind == 1 else {}, 'original fresh commit or zero retained maps work')
            delta(cs, returned, dict(phase=1, seeds=int(kind == 1), commits=1), 'genuine publication to RETURN')
            need(rm == cm and actual == commit, 'complete actual committed view and no hidden post-commit maps work')
            delta(returned, ready, dict(phase=-5), 'only handler-end publishes READY')
            if kind == 2: self.retained_sequences.add(seq+1)
            preparation = F(F(oa, 'tfi_owner', 'progress'), 'li2_fetch_progress', 'preparation')
            need(preparation == (F(stage, vt, 'maps') if kind == 1 else bytes(self.types['li2_fetch_map_progress']['bytes'])), 'actual new borrow retains only its own preparation authority')
            self.origin = proof
        else:
            self.zero(F(e, rt, 'commit'), 'old-NOP miss never commits')
            self.changed(stage, actual, vt, 'phase')
            need(I(actual, vt, 'phase') == 5 and returned['phase'] == ready['phase'] == 0 and returned['epoch'] > ss['epoch'], 'actual cancellation, final close and complete certificate disposal')
            effects = returned['epoch']-ss['epoch']
            delta(ss, returned, dict(epoch=effects, discards=effects, phase=-4, last_reason=returned['last_reason']-ss['last_reason']), 'fallback changes only disposal metadata, never successful work counters')
            need(ready == returned, 'handler-end cannot revive disposed authority')
            self.origin = None
        need(hm == rm and F(e, rt, 'ready_frame') == F(row, et, 'after'), 'actual handler-end retains the complete TRACE frame and maps state')
        self.history_views[I(actual, vt, 'serial')] = actual
        self.accepted_transfers[index] = actual; self.previous = (ready, hm); self.last_event = bc[0]; self.previous_serial = serial

    def transfer_maps(self, tx, index):
        need(tx == self.accepted_transfers[index], 'whole original transfer equals the independently validated outer API observation')

    def body_complete(self):
        I, F = self.integer, self.field
        start, end = self.body_start, self.previous[0]
        wanted = dict(seeds=int(self.N == 256), retained_stages=255 if self.N == 256 else 0, retained_checks=509 if self.N == 256 else 0, commits=self.N-1)
        need({k: end[k]-start[k] for k in wanted} == wanted, 'source-derived exact BODY custody counts, including the final retained cancelled stage')
        terminal = self.custody_state(F(self.extra, 'tci_record', 'terminal'))
        need(terminal['phase'] == 0 and all(terminal[k] >= end[k] for k in ('epoch','seeds','retained_stages','retained_checks','commits','discards')), 'actual terminal has no live custody authority')
        chain = F(self.data, self.rt, 'terminal_chain')
        historical = F(F(chain, 'li2_tf_chain', 'lease'), 'li2_tf_same_page', 'transfer')
        known = I(historical, 'li2_fetch_rx_view', 'serial') in self.history_anchors
        if any(historical) and not known:
            need(self.image['symbols']['rn_finish'] <= I(historical, 'li2_fetch_rx_view', 'pc') < base.GUARD+4096 and I(chain, 'li2_tf_chain', 'event_id') > self.last_event,
                 'new terminal history belongs only to the later fixed GUARD/capture/finish path after the genuine BODY close')
        last = self.history(historical, self.image, self.pid, dict(chain=self.identity['chain'], chain_session=self.identity['session'], event=I(chain, 'li2_tf_chain', 'event_id'), custody=terminal))
        if last is not None and not known: self.after_native_copy(self.anchor, last)
        return dict(custody=dict(fresh_stages=1, **wanted))

def gated(data, layout, image, pid, exit_status, go_fd, notify_fd, cpu):
    return base.gated(data, layout, image, pid, exit_status, go_fd, notify_fd, cpu, Reader)

def pair(nrec, grec, nout, gout, layouts, image, npid, gpid, cpu, native_fds, gated_fds):
    return base.pair(nrec, grec, nout, gout, layouts, image, npid, gpid, cpu, native_fds, gated_fds, Reader)

def terminal(row, stdout, stderr, record, preparation, *, image, layout, cpu, expected_command, profile):
    return base.terminal(row, stdout, stderr, record, preparation, image=image, layout=layout, cpu=cpu,
                         expected_command=expected_command, profile=profile, reader=Reader, report_reader=Reports)
