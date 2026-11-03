"""Plain mixed11/12/13 LS/true acceptance, without counter storage.

The PF completed body below retains every resident/subentry/probe predicate.
Its sole semantic extension is exact release-versus-DIFF maps mode; the whole
maps parser independently checks every differential hit. The ordinary-chain
body retains the linked release's complete slots, generations, permissions,
leases and chronology, while counting actual probe GRAPH refaults and actual
persistent entries as distinct consumed segments (the current probe producer's
partition). No row is rewritten, no ABI3 prefix is fabricated and no old
linked-profile coverage is claimed. All original application controls remain.
The separate effects row is joined to the actual final PF generation/serial/hit
state; no counter bank is invented.

This source-only adapter has not qualified a subject. Any unsupported terminal
state fails the sample; it is never replaced by a smaller acceptance domain.
"""
import copy
import hashlib
import json

from page_selected import need
import page_cost_reports as cost
import persistent_fused_reports as rows
import persistent_fused_refusal_reports as pf
import persistent_fused_counter_terminal as pf_terminal
from persistent_terminal_extent import nx_extent
import persistent_loop_effects_terminal as loop
from persistent_loop_effects_counter_terminal import completed_choice
import linked_native_probe_reports as probe
import linked_epoch_cache_reports as cache_reports
import linked_true_repeat_reports as true_repeat
import scalar_span_trace_release_chain as chain_reports

H = lambda value: hashlib.sha256(value).hexdigest()
SUBENTRY_KEYS = pf_terminal.SUBENTRY_KEYS
BASE_COUNTS = {'ls': 60, 'true': 38}
EFFECTS_POPULATIONS = dict(effects_schema=42, effects_semantic=11, effects_events=6, choice_guard=14)
CONTROL_COUNTS = {'ls': 447, 'true': 480}


def _retained(d,s):
    need(d['selected_slot']in(0,1), 'actual selected retained slot')
    generations=(d['slot0_generation'],d['slot1_generation'])
    permits=(d['slot0_permit'],d['slot1_permit'])
    completed_serials=(d['slot0_completed_serial'],d['slot1_completed_serial'])
    installed=sum(g>0 for g in generations)
    need(all(0<=g<=d['publications'] for g in generations)and
         (not all(generations)or generations[0]!=generations[1])and
         max(generations)==d['publications']and
         permits==tuple(int(g>0)for g in generations)and
         all((0<c<=d['serial'])if g else c==0 for g,c in zip(generations,completed_serials,strict=True)),
         'actual distinct retained generations and their completed permits')
    need(d['generation']==generations[d['selected_slot']]and d['permit']==permits[d['selected_slot']]and
         d['retirements']==d['publications']-installed and
         d['permit_claims']==d['hits']+s['hits']+d['retirements']+d['dual_entries'] and
         d['dual_entries']==d['dual_completed'] and 0<=d['dual_entries']<=d['hits']+s['hits'],
         'two-slot publication/retirement accounting and selected generation identity')
    if d['generation']:
        need(0<d['build_serial']<=completed_serials[d['selected_slot']], 'selected immutable build precedes its actual completion')
    else:
        need(d['build_serial']==0, 'no invented selected-generation build serial')


def _members(d):
    need(d['domain_members'] in (1,2) if d['phase']==13 else d['domain_members']==0,
         'actual one/two-member domain or unbound cancellation')


def _completed(raw, lane, *, extent=nx_extent, retained=_retained, members=_members):
    """Whole PF terminal arithmetic; exact maps mode is selected by this profile."""
    f=raw['LI2_PF_REFUSALS']
    need(f['status']==f['failure_code']==0 and f['refused']==f['cancelled'],
         'successful PF refusal and genuine cancellation accounting')
    d=raw['LI2_PERSISTENT_UNREGISTERED'];l=raw['LI2_LINKED_EPOCH'];v=raw['LI2_MAPS_VIEW'];n=raw['LI2_NATIVE'];s=raw['LI2_PERSISTENT_SUBENTRY']
    need(all(row.get('status')==row.get('failure_code')==0 for row in (d,l,n,s)),
         'actual exit-zero terminal outcomes')
    need(d['detail_abs']==d['detail_negative']==d['first_error']==d['active']==d['busy']==
         d['unexpected']==d['guest_data_fault']==0, 'successful quiet resident observation')
    need(l.get('first_error')==l.get('active')==l.get('busy')==l.get('decoding')==
         l.get('closing')==l.get('resuming')==0 and l.get('events')==sum(l['signals']),
         'actual completed ingress census and quiet inherited owner')
    need(lane in ('release', 'differential') and v.get('enabled')==1 and
         v.get('differential')==int(lane=='differential') and
         v.get('poisoned')==v.get('mismatches')==v.get('reserved')==0 and
         v.get('comparisons')==(v.get('hits') if lane=='differential' else 0) and
         v.get('queries')==v.get('hits',0)+v.get('refreshes',0),
         'exact plain release or differential maintained-map counters')
    need(d['offers']==d['serial']==d['entries']+d['cancelled'] and
         d['entries']==d['completed']==d['publications']+d['hits']+s['hits'] and
         d['cold_attempts']==d['publications']+d['cancelled'] and
         d['misses'][0]==0 and sum(d['misses'])+f['cancelled']==d['cancelled'],
         'exact completed, cold and genuinely cancelled resident partitions')
    retained(d,s)
    if not d['offers']:
        need(d['phase']==d['opened_pages']==d['closed_pages']==d['anchor_released']==
             d['registration_rechecked']==d['recovery_complete']==d['domain_members']==0, 'actual unused resident owner')
    else:
        need(d['phase']in(13,14)and d['anchor_released']==d['registration_rechecked']==1,
             'last chosen epoch is actually closed or fully cancelled')
        extent(d)
        members(d)
    need(s['selections']>=s['hits']==s['entries']==s['completed'],
         'actual completed subentry selection/hit/entry partition')
    if d['phase']==13:
        need(s['complete']==1 and s['serial']==d['serial']and s['generation']==d['generation']and
             s['slot']==d['selected_slot']and s['bank']in(0,1)and s['head']<128 and
             0<s['root']<1<<47 and 0<s['pc']<1<<47 and ((s['head']==0)==(s['root']==s['pc'])),
             'actual final complete entry identity without inventing a certificate observation')
    else:
        need(all(s[k]==0 for k in SUBENTRY_KEYS[7:]),'no invented terminal entry after reset/cancellation')
    probe.completed(raw['LI2_LINKED_NATIVE_PROBE'],l,n,d,raw['LI2_CHAIN'],raw['LI2_NATIVE_PAIR'])


def _effects_completed(parsed):
    """Completed plain terminal facts, with no fabricated ABI4 backing cells."""
    effects = parsed['loop_effects']
    completed_choice(parsed['loop_runtime'], effects,
                     dict(persistent=parsed['group'], subentry=parsed['subentry']))
    # These are the protected effects-state inequalities and its successful
    # final-entry equality. History counts remain descriptive, not residuals.
    need(effects['chooser_selected'] + effects['chooser_no_envelope'] <= effects['chooser_attempts'] and
         effects['publications13'] <= effects['chooser_selected'] and
         effects['actual_entries13'] <= effects['entries_with13'] and
         effects['entries_with13'] == effects['completed_with13'],
         'complete actual effects chooser/publication/entry counter relations')


def _chain_completed(loader,c,span,domain,probe_row):
    # Actual probe GRAPH refaults and persistent entries are separate consumers.
    graph=probe_row['refaults']
    need(all(c[k]==span[k]==loader[k]==0 for k in
         ('status','failure_code','detail_abs','detail_negative'))and
         c['pending']==c['error']==c['unexpected']==c['proof_valid']==0 and
         c['attempts']==c['steps']==c['nx_entries']+c['trace_entries']>0 and
         c['sequence']==c['trace_entries']>0 and
         span['offers']==span['closed']==span['entries']+span['resumed']+span['refaults']+graph and
         span['entries']==span['completed']>0 and
         c['nx_entries']==c['fallbacks']+span['entries']+span['refaults']+graph+domain['entries'] and
         c['nx_entries']<=loader['nx_faults'],
         'release TRACE exact consumed-span segment partition')
    need(c['trace_entries']+c['fallbacks']<=c['preparations']<=2*(c['trace_entries']+c['fallbacks']),
         'release TRACE exact truncated-retry preparation domain')
    need(c['releases']==c['preparations']+c['nx_entries'],
         'release TRACE every prepared and incoming NX borrow released')
    slots=[chain_reports.old.slot(c,i)for i in (0,1)]
    need(sum(s['generation']for s in slots)==c['attempts']+c['fallbacks'],
         'release TRACE exact chain-next generation conservation')
    for s in slots:
        need(s['phase']in(5,6), 'release TRACE only completed or descriptive terminal slots')
        need(s['generation']>0 and 0<s['event']<=c['event'] and
             0<s['pc']<1<<64 and s['borrow']>0 and s['validations']>0 and
             s['held']==s['fetch_error']==s['owner_error']==s['unexpected']==0 and
             s['release']==s['released']==1,
             'release TRACE both actual slot borrows fully released')
        if s['phase']==5:
            pc,length=s['pc'],s['length']
            need(s['origin']in(1,2)and s['fallback']==0 and
                 s['prepare']==int(s['origin']==2)and s['prepared']==1 and
                 (s['origin']==2 or s['retry']==0)and
                 1<=length<=15 and pc<=(1<<64)-1-length and
                 s['owner_phase']==5 and s['trace']==s['query']==s['queried']==1 and
                 s['post_pc']==s['query_pc']>0,
                 'release TRACE complete actual closed slot query')
            mask=1 if pc//4096==(pc+length-1)//4096 else 3
            need(s['open']==s['opened']==s['revoke']==s['revoked']==mask,
                 'release TRACE exact closed slot permission masks')
        else:
            need(s['origin']==2 and 1<=s['fallback']<=6 and s['prepare']==s['prepared']==1 and
                 s['owner_phase']==s['open']==s['opened']==s['revoke']==s['revoked']==
                 s['trace']==s['post_pc']==s['query']==s['queried']==s['query_pc']==0,
                 'release TRACE descriptive fallback never executed or queried')
    active,previous=slots[c['active']],slots[c['active']^1]
    need(previous['event']<active['event'] and previous['borrow']<active['borrow'],
         'release TRACE actual resident slot chronology')
    if active['phase']==6:
        need(previous['phase']==5 and previous['post_pc']==previous['query_pc']==active['pc'],
             'release TRACE fallback retains its exact closed predecessor')
        selected=previous
    else:
        # Same-page leases may advance the decoded PC inside this generation.
        # An NX-origin slot is a separate real segment, with no invented edge.
        if active['origin']==2:
            start=previous['post_pc']
            need(previous['phase']==5 and (start==active['pc']or
                 (c['lease_transfers']>0 and start//4096==active['pc']//4096 and start<active['pc'])),
                 'release TRACE ordinary successor or actual forward same-page lease')
            if start!=active['pc']:chain_reports.advanced_lease(c,active)
        selected=active
    chain_reports.old.same_slot(loader,selected)
    need(loader['tf_pc']==selected['pc'] and loader['tf_length']==selected['length'] and
         loader['tf_code']==selected['code'],
         'release TRACE rich LOADER selects the actual source-defined terminal slot')
    t=span['transfer'];retained=slots[t[3]]
    need(0<t[2]<=c['event'] and 0<t[6]<=retained['generation'],
         'release TRACE last transfer is bounded by actual chain history')
    if t[6]==retained['generation']:
        need(retained['phase']==5 and retained['event']<t[2] and
             retained['borrow']==t[7] and retained['post_pc']==retained['query_pc']==t[9],
             'release TRACE resident transfer generation retains exact closed identity')
    return dict(scope='source-derived terminal reports only',protected_record_credit=False,
        consumed_spans=span['entries'],resumed_spans=span['resumed'],refaults=span['refaults'],
        truncated_retries=c['preparations']-c['trace_entries']-c['fallbacks'],
        selected_slot=c['active']if active['phase']==5 else c['active']^1)


def _parts(stderr, lane):
    need(lane in ('release', 'differential'), 'explicit plain mixed-policy lane')
    new, effects, original = loop.split(stderr)
    refusal, _ = pf.split(original)
    subentry, without = rows.subentry_split(original)
    native_probe, original_stream = rows.probe_row_split(without)
    group, suffix = rows.split(original_stream)
    linked, linked_reuse, suffix = rows.prior.split(suffix)
    scalar, scalar_reuse, suffix = rows.reuse.split(suffix)
    unrolled, suffix = rows.unrolled.split(suffix)
    current, suffix = rows.current.split_current(suffix)
    view, original = rows.maps_view.split_report(
        suffix, 'differential' if lane == 'differential' else 'maintained')
    parsed = rows.old.reports(original)
    rows.old.extensions(parsed)
    parsed.update(group=group, linked=linked, linked_reuse=linked_reuse,
                  scalar_region=scalar, scalar_reuse=scalar_reuse, unrolled=unrolled,
                  current_tf=current, subentry=subentry, native_probe=native_probe,
                  pf_refusals=refusal, loop_runtime=new, loop_effects=effects)
    return parsed, view, original


def _read(stdout, stderr, args, kind, lane, *, extent=nx_extent, retained=_retained, members=_members):
    need(kind in ('ls', 'true') and lane in ('release', 'differential') and
         type(args) is tuple and len(args) == 7,
         'exact plain LS/true lane and complete actual process/input arguments')
    parsed, view, original = _parts(stderr, lane)
    new = parsed['loop_runtime']
    need(new['status'] == new['failure_code'] == new['scope'] == 0,
         'successful actual LOOP/effects terminal has no scope or failed outcome')
    for name in ('loader', 'group', 'linked', 'linked_reuse', 'scalar_region',
                 'scalar_reuse', 'unrolled', 'current_tf'):
        value = parsed[name]
        need(all(value[key] == 0 for key in
                 ('status', 'failure_code', 'detail_abs', 'detail_negative',
                  'first_error', 'first_detail_abs', 'first_detail_negative',
                  'active', 'busy', 'decoding', 'closing', 'resuming',
                  'unexpected', 'pending', 'retiring') if key in value),
             'complete successful quiet actual owner row ' + name)
    raw = {label: parsed[name] for label, name in (
        ('LI2_PERSISTENT_UNREGISTERED', 'group'), ('LI2_LINKED_EPOCH', 'linked'),
        ('LI2_NATIVE', 'native'), ('LI2_PERSISTENT_SUBENTRY', 'subentry'),
        ('LI2_LINKED_NATIVE_PROBE', 'native_probe'), ('LI2_CHAIN', 'chain'),
        ('LI2_NATIVE_PAIR', 'native_pair'), ('LI2_PF_REFUSALS', 'pf_refusals'))}
    raw['LI2_MAPS_VIEW'] = view
    _completed(raw, lane, extent=extent, retained=retained, members=members)
    _effects_completed(parsed)
    need(parsed['linked']['events'] == parsed['scalar_region']['events'] ==
         parsed['unrolled']['events'] and
         parsed['linked']['signals'] == parsed['scalar_region']['signals'] ==
         parsed['unrolled']['signals'],
         'whole old preentry observers counted the same actual handler population')
    closure = lambda loader, chain: _chain_completed(
        loader, chain, parsed['linked'], parsed['group'], parsed['native_probe'])
    # The existing complete application reader owns stdout, exit, actual PID,
    # input/ELF identities, source binding, REP, effects and original native
    # gates. The explicit callback retains full ordinary-chain closure above.
    base, summary = cost.check(
        stdout, original, *args, workload=kind,
        cache_completed=cache_reports.completed, chain_closure=closure,
        true_repeat=true_repeat.PROFILE if kind == 'true' else None)
    need(all(parsed[key] == value for key, value in base.items()),
         'unchanged actual application rows through both complete readers')
    cost._retained_inputs(*args[3:])
    return parsed, view, original, summary, closure


def check(stdout, stderr, args, kind, lane, *, extent=nx_extent, retained=_retained, members=_members):
    parsed, view, _, _, _ = _read(stdout, stderr, args, kind, lane, extent=extent, retained=retained, members=members)
    return dict(
        application_completed=True, lane=lane, workload=kind,
        maps_view=view, loop_runtime=parsed['loop_runtime'], loop_effects=parsed['loop_effects'],
        pf_refusals=parsed['pf_refusals'], persistent=parsed['group'],
        subentry={key: parsed['subentry'][key] for key in
                  ('selections', 'hits', 'entries', 'completed')},
        linked_ingress=dict(events=parsed['linked']['events'],
                            signals=parsed['linked']['signals']),
        native_probe=parsed['native_probe'],
        ordinary={key: parsed['chain'][key] for key in
                  ('attempts', 'steps', 'nx_entries', 'trace_entries',
                   'preparations', 'releases', 'lease_transfers')},
        source_scope='actual terminal rows; no counter storage or internal-edge/iteration observation',
        count_scope='entries_with12/13 are activated member presence; actual_entries12/13 are source-authenticated redirects',
        full_state_credit=False, qualification_credit=False)


def controls(stdout, stderr, args, kind, lane, *, extent=nx_extent, retained=_retained, members=_members):
    parsed, view, original, _, closure = _read(stdout, stderr, args, kind, lane, extent=extent, retained=retained, members=members)
    inherited = cost.supplied_controls(
        stdout, original, *args, workload=kind,
        cache_completed=cache_reports.completed, chain_closure=closure,
        true_repeat=true_repeat.PROFILE if kind == 'true' else None)
    need(len(inherited['refusals']) == len(set(inherited['refusals'])) == BASE_COUNTS[kind],
         'all unchanged real-program input/effect/native/REP/output controls')
    names = ['application.' + name for name in inherited['refusals']]
    populations = {'application': len(names)}
    if kind == 'true':
        additions = inherited['positive_repeat_refusals']
        need(inherited['positive_repeat_profile'] == true_repeat.PROFILE and
             len(additions) == len(set(additions)) == true_repeat.POSITIVE_CONTROL_COUNT == 55,
             'all separately named original positive true REP controls')
        names.extend('positive_repeat.' + name for name in additions)
        populations['positive_repeat'] = len(additions)
    lines = stderr[:-1].split(b'\n')

    def reject(name, changed, *, expected=None):
        need(type(changed) is bytes and changed != stderr, 'actual plain mutation ' + name)
        try:
            _read(stdout, changed, args, kind, lane, extent=extent, retained=retained, members=members)
        except ValueError as error:
            need(expected is None or str(error) == expected, 'exact plain refusal cause ' + name)
            names.append(name)
        else:
            raise ValueError('accepted supplied plain terminal mutation ' + name)

    def position(prefix):
        places = [i for i, line in enumerate(lines) if line.startswith(prefix)]
        need(len(places) == 1, 'one exact actual mutation target')
        return places[0]

    def encoded(prefix, value):
        changed = list(lines)
        changed[position(prefix)] = prefix + json.dumps(
            value, separators=(',', ':'), allow_nan=False).encode()
        return b'\n'.join(changed) + b'\n'

    def change(name, prefix, value):
        reject(name, encoded(prefix, value))

    def schema(group, prefix, value):
        begin = len(names)
        for key in value:
            changed = dict(value); del changed[key]
            change(group + '.missing_' + key, prefix, changed)
            changed = copy.deepcopy(value)
            if type(changed[key]) is list:
                changed[key][0] = bool(changed[key][0])
            else:
                changed[key] = bool(changed[key])
            change(group + '.boolean_' + key, prefix, changed)
        changed = dict(value); changed['extra'] = 0
        change(group + '.extra_field', prefix, changed)
        changed = dict(reversed(list(value.items())))
        change(group + '.key_order', prefix, changed)
        index = position(prefix)
        changed_lines = list(lines)
        changed_lines[index] = lines[index][:-1] + b',"version":1}'
        reject(group + '.duplicate_key', b'\n'.join(changed_lines) + b'\n')
        reject(group + '.missing_row', b'\n'.join(lines[:index] + lines[index+1:]) + b'\n')
        reject(group + '.duplicate_row', b'\n'.join(lines[:index] + [lines[index]] + lines[index:]) + b'\n')
        changed_lines = list(lines)
        changed_lines[index-1], changed_lines[index] = changed_lines[index], changed_lines[index-1]
        reject(group + '.row_order', b'\n'.join(changed_lines) + b'\n')
        populations[group + '_schema'] = len(names) - begin

    for group, prefix, value in (
        ('loop', loop.PREFIX, parsed['loop_runtime']),
        ('pf', pf.PREFIX, parsed['pf_refusals']),
        ('persistent', rows.PREFIX, parsed['group']),
        ('subentry', rows.SUBENTRY_PREFIX, parsed['subentry']),
        ('probe', probe.PREFIX, parsed['native_probe'])):
        schema(group, prefix, value)

    begin = len(names)
    loop_value = parsed['loop_runtime']
    for key, value in (('version', 2), ('status', 125), ('failure_code', 1),
                       ('scope', 1), ('route', 14), ('choice_complete', 2)):
        changed = dict(loop_value); changed[key] = value
        change('loop.' + key, loop.PREFIX, changed)
    changed = dict(loop_value); changed['choice_complete'] ^= 1
    change('loop.unfinished_choice', loop.PREFIX, changed)
    populations['loop_semantic'] = len(names) - begin

    begin = len(names)
    refusal = parsed['pf_refusals']
    for key, value in (('version', 2), ('policy_version', 12), ('reason', 257),
                       ('status', 125), ('failure_code', 1),
                       ('refused', refusal['refused']+1), ('cancelled', refusal['cancelled']+1)):
        changed = dict(refusal); changed[key] = value
        change('pf.' + key, pf.PREFIX, changed)
    populations['pf_semantic'] = len(names) - begin

    begin = len(names)
    group = parsed['group']
    for key in ('status', 'failure_code', 'detail_abs', 'detail_negative',
                'first_error', 'active', 'busy', 'unexpected', 'guest_data_fault',
                'offers', 'serial', 'entries', 'completed', 'cold_attempts',
                'publications', 'hits', 'cancelled', 'retirements', 'permit_claims'):
        changed = copy.deepcopy(group); changed[key] += 1
        change('persistent.' + key, rows.PREFIX, changed)
    for index in range(18):
        changed = copy.deepcopy(group); changed['misses'][index] += 1
        change('persistent.miss_' + str(index), rows.PREFIX, changed)
    changed = dict(group); changed['phase'] = 99
    change('persistent.phase', rows.PREFIX, changed)
    populations['persistent_semantic'] = len(names) - begin

    begin = len(names)
    p = parsed['native_probe']
    for key, value in (('status', 125), ('errors', 1), ('pending', 1),
                       ('outcome_result_negative', 1), ('lookups', p['lookups']+1),
                       ('policy_checks', p['policy_checks']+1),
                       ('policy_blocked', p['policy_blocked']+1),
                       ('chosen', p['chosen']+1), ('next_nx', p['next_nx']+1),
                       ('admitted', p['admitted']+1), ('refused', p['refused']+1),
                       ('outcome_complete', 1-p['outcome_complete']), ('outcome_result_abs', 2)):
        changed = dict(p); changed[key] = value
        change('probe.' + key, probe.PREFIX, changed)
    changed = dict(p); changed['refaults'] = parsed['linked']['refusals'][2]+1
    change('probe.graph_class', probe.PREFIX, changed)
    changed = dict(parsed['chain']); changed['nx_entries'] += 1
    change('chain.missing_persistent_consumer', b'LI2_CHAIN ', changed)
    populations['probe_chain_semantic'] = len(names) - begin

    # Isolate the new consumer term before testing the complete actual stream.
    # All loader/chain/linked/probe values stay actual; the supplied owner count
    # alone cannot fit the source-defined ordinary-segment conservation law.
    changed = dict(group); changed['entries'] += 1
    try:
        _chain_completed(parsed['loader'], parsed['chain'], parsed['linked'],
                         changed, parsed['native_probe'])
    except ValueError as error:
        need(str(error) == 'release TRACE exact consumed-span segment partition',
             'persistent consumer mutation reaches its exact new chain equation')
    else:
        raise ValueError('accepted unrelated persistent consumer in ordinary-chain closure')

    begin = len(names)
    # Same23 maps stimuli and exact predicates as maps_view.controls; these
    # operate on the complete actual new stream instead of dropping its rows.
    prefix = rows.maps_view.PREFIX
    for key, value in (('version', 2), ('enabled', 0), ('differential', 1-view['differential']),
                       ('poisoned', 1), ('reserved', 1), ('mismatches', 1),
                       ('queries', view['queries']+1), ('comparisons', view['comparisons']+1),
                       ('hits', -1), ('refreshes', 1 << 64), ('unexplained', False), ('stack_probes', 1.0)):
        changed = dict(view); changed[key] = value
        change('maps.' + key, prefix, changed)
    for key in ('hits', 'refreshes', 'stack_probes', 'updates'):
        changed = dict(view); changed[key] = 0
        changed['queries'] = changed['hits'] + changed['refreshes']
        changed['comparisons'] = changed['hits'] if lane == 'differential' else 0
        change('maps.unused_' + key, prefix, changed)
    index = position(prefix)
    reject('maps.missing', b'\n'.join(lines[:index]+lines[index+1:]) + b'\n')
    reject('maps.duplicate', b'\n'.join(lines[:index]+[lines[index]]+lines[index:]) + b'\n')
    reject('maps.late', b'\n'.join(lines[:index]+lines[index+1:]+[lines[index]]) + b'\n')
    reject('maps.truncated', stderr[:-1])
    changed = dict(view); del changed['reserved']
    change('maps.short_schema', prefix, changed)
    changed_lines = list(lines)
    changed_lines[index] = lines[index][:-1]+b',"version":1}'
    reject('maps.duplicate_key', b'\n'.join(changed_lines)+b'\n')
    change('maps.wrong_order', prefix, dict(reversed(list(view.items()))))
    populations['maps'] = len(names) - begin
    expected_populations = dict(application=BASE_COUNTS[kind], loop_schema=36,
         pf_schema=20, persistent_schema=86, subentry_schema=36, probe_schema=46,
         loop_semantic=7, pf_semantic=7, persistent_semantic=38,
         probe_chain_semantic=15, maps=23)
    if kind == 'true':
        expected_populations['positive_repeat'] = 55
    need(populations == expected_populations,
         'exact inherited application and new plain-schema/semantic populations')
    need(len(names) == len(set(names)) == sum(populations.values()),
         'every supplied plain refusal is unique and observed')
    # All374 LS /407 true controls above are preserved before these separate
    # additions. Only the invalid old LOOP route stimulus is14 in this profile,
    # because13 is now a real separately selected policy, never an old-row alias.
    before_effects = len(names)
    schema('effects', loop.EFFECTS_PREFIX, parsed['loop_effects'])
    begin = len(names)
    effects = parsed['loop_effects']
    for key, value in (('version', 2), ('policy_version', 12), ('scalar_version', 2),
                       ('mov_version', 1), ('status', 125), ('failure_code', 1),
                       ('scope', 1), ('route', 14), ('choice_complete', 2)):
        changed = dict(effects); changed[key] = value
        change('effects.' + key, loop.EFFECTS_PREFIX, changed)
    changed = dict(effects); changed['choice_complete'] ^= 1
    change('effects.unfinished_choice', loop.EFFECTS_PREFIX, changed)
    index = position(loop.EFFECTS_PREFIX)
    changed_lines = list(lines)
    changed_lines[index] = lines[index].replace(b'{', b'{ ', 1)
    reject('effects.noncanonical', b'\n'.join(changed_lines) + b'\n')
    populations['effects_semantic'] = len(names) - begin

    begin = len(names)
    for key, value in (
        ('chooser_selected', effects['chooser_attempts'] + 1),
        ('chooser_no_envelope', effects['chooser_attempts'] + 1),
        ('publications13', effects['chooser_selected'] + 1),
        ('actual_entries13', effects['entries_with13'] + 1),
        ('completed_with13', effects['entries_with13'] + 1),
        ('entries_with13', effects['completed_with13'] + 1)):
        changed = dict(effects); changed[key] = value
        change('effects.event_' + key, loop.EFFECTS_PREFIX, changed)
    populations['effects_events'] = len(names) - begin

    begin = len(names)
    # Direct invalid argument controls isolate the exact new selection guards
    # after the complete actual positive stream. They are not synthetic warm
    # positives, counter pages, native executions or proof of a warm guest run.
    actual_terminal = dict(persistent=parsed['group'], subentry=parsed['subentry'])
    def choice_reject(name, route, choice, added, **fields):
        l = dict(loop_value, route=route, choice_complete=choice)
        e = dict(effects, route=route, choice_complete=added)
        d = dict(actual_terminal['persistent'], phase=13, generation=1,
                 serial=2, build_serial=1 if choice == 0 else 2, hits=1)
        sub = dict(actual_terminal['subentry'], hits=0)
        if 'subentry_hits' in fields:sub['hits'] = fields.pop('subentry_hits')
        d.update(fields)
        terminal = dict(actual_terminal, persistent=d, subentry=sub)
        need((l,e,terminal)!=(loop_value,effects,actual_terminal),
             'nonidentity supplied plain choice-guard control ' + name)
        try:completed_choice(l,e,terminal)
        except ValueError:names.append('choice_guard.' + name)
        else:raise ValueError('accepted supplied plain choice-guard mutation ' + name)
    choice_reject('warm_phase',13,0,0,phase=14)
    choice_reject('warm_generation',13,0,0,generation=0)
    choice_reject('warm_build_zero',13,0,0,build_serial=0)
    choice_reject('warm_same_build',13,0,0,build_serial=2)
    choice_reject('warm_future_build',13,0,0,build_serial=3)
    choice_reject('warm_no_hits',13,0,0,hits=0,subentry_hits=0)
    choice_reject('warm_effects_choice',13,0,1)
    choice_reject('cold_effects_choice',13,1,0)
    choice_reject('cold_phase',13,1,1,phase=0)
    choice_reject('cold_old_build',13,1,1,build_serial=1)
    choice_reject('cold_generation',13,1,1,generation=0)
    choice_reject('cold12_effects_choice',12,1,1)
    choice_reject('idle_effects_choice',0,0,1)
    choice_reject('idle_old_choice',0,1,0)
    populations['choice_guard'] = len(names) - begin
    need({key: populations[key] for key in EFFECTS_POPULATIONS} == EFFECTS_POPULATIONS and
         len(names) - before_effects == sum(EFFECTS_POPULATIONS.values()) == 73,
         'all separate effects schema/semantic/event and source-bound choice controls')
    need(populations == dict(expected_populations, **EFFECTS_POPULATIONS) and
         len(names) == len(set(names)) == sum(populations.values()) == CONTROL_COUNTS[kind],
         'all original374/407 and73 additive supplied refusals retained')
    return dict(refusals=names, populations=populations, native_operations=0,
                original_stdout_sha256=H(stdout), original_stderr_sha256=H(stderr),
                qualification_credit=False, full_state_credit=False)
