"""Completed count joins only; no capture, full-state or owner qualification."""
import json
from linked_frontier_census import need
import linked_native_probe_reports as probe
from persistent_group_counter_process import GROUP_NAMES
MISS_REASONS=('none','root_unsupported','source_invalid','source_truncated','source_overlap',
    'outside_pair','head_limit','exit_limit','queue_limit','no_exit','rip_reach',
    'branch_reach','fallthrough_reach','guard_rip_reach','guard_follow_reach','root_selected','single_member','link_limit')
SUBENTRY_KEYS=('version','status','failure_code','selections','hits','entries','completed',
    'serial','generation','root','pc','head','slot','bank','complete')
DOMAIN_KEYS=('version','status','failure_code','detail_abs','detail_negative','phase','serial',
    'generation','build_serial','offers','cold_attempts','publications','hits','cancelled','retirements',
    'permit_claims','entries','completed','unexpected','permit','opened_pages','closed_pages',
    'anchor_released','registration_rechecked','guest_data_fault','recovery_complete','first_error',
    'active','busy','selected_slot','slot0_generation','slot1_generation','slot0_permit','slot1_permit',
    'slot0_completed_serial','slot1_completed_serial','domain_members','dual_entries','dual_completed','misses')


def counters(stderr):
    """Whole actual numeric rows, retained even if a later outcome check fails."""
    def pairs(items):
        need(len(items)==len(dict(items)), 'no duplicate actual terminal keys')
        return dict(items)
    def uint(x):return type(x)is int and 0<=x<1<<64
    result={}
    for label in ('LI2_PERSISTENT_UNREGISTERED','LI2_PERSISTENT_SUBENTRY','LI2_LINKED_EPOCH','LI2_MAPS_VIEW','LI2_NATIVE'):
        prefix=(label+' ').encode();rows=[x for x in stderr.splitlines()if x.startswith(prefix)]
        need(len(rows)==1 and len(rows[0])<=4096, 'one complete '+label)
        value=json.loads(rows[0][len(prefix):],object_pairs_hook=pairs)
        need(type(value)is dict and value and all(uint(v)or type(v)is list and all(uint(x)for x in v)
             for v in value.values()), 'typed unsigned actual row '+label)
        need(prefix+json.dumps(value,separators=(',',':'),allow_nan=False).encode()==rows[0],
             'canonical complete actual row '+label)
        need(type(value.get('version'))is int and value['version']==1,
             'explicit unregistered/subentry or unchanged old-row version '+label)
        result[label]=value
    d=result['LI2_PERSISTENT_UNREGISTERED'];l=result['LI2_LINKED_EPOCH']
    need(tuple(d)==DOMAIN_KEYS and type(d['misses'])is list and len(d['misses'])==len(MISS_REASONS),
         'exact unregistered owner schema and source-classified reasons')
    need(type(l.get('signals'))is list and len(l['signals'])==5 and
         type(l.get('refusals'))is list and len(l['refusals'])==4,
         'actual old linked ingress buckets and refusal counters')
    need(not any(x.startswith((b'LI2_PERSISTENT_EPOCH ',b'LI2_PERSISTENT_DYNAMIC ',b'LI2_LINKED_PREEDGE ',
         b'LI2_LINKED_NATIVE_HINT ',b'LI2_LINKED_FRONTIER_CENSUS ',b'LI2_PERSISTENT_GROUP ',b'LI2_PERSISTENT_RESIDENT ',b'LI2_PERSISTENT_RETAINED_TWO ',b'LI2_PERSISTENT_ACTIVE_DOMAIN '))for x in stderr.splitlines()),
         'no old group, fixed, preedge, hint or observer population substituted for resident release')
    lines=stderr[:-1].split(b'\n')
    need(stderr.endswith(b'\n')and len(lines)>3 and lines[-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ')and
         lines[-2].startswith(b'LI2_PERSISTENT_SUBENTRY ')and lines[-3].startswith(probe.PREFIX),
         'exact final probe/subentry/unregistered terminal order')
    need(tuple(result['LI2_PERSISTENT_SUBENTRY'])==SUBENTRY_KEYS,'whole separate15-cell subentry schema')
    need(sum(x.startswith(probe.PREFIX)for x in lines)==1,'one actual native probe row')
    result['LI2_LINKED_NATIVE_PROBE']=probe.decode(lines[-3])
    result['LI2_CHAIN']=probe.chain_row(stderr)
    result['LI2_NATIVE_PAIR']=probe.pair_row(stderr)
    return result


def completed(raw):
    """Successful diagnostic arithmetic only; no full release acceptance claim."""
    d=raw['LI2_PERSISTENT_UNREGISTERED'];l=raw['LI2_LINKED_EPOCH'];v=raw['LI2_MAPS_VIEW'];n=raw['LI2_NATIVE'];s=raw['LI2_PERSISTENT_SUBENTRY']
    need(all(row.get('status')==row.get('failure_code')==0 for row in (d,l,n,s)),
         'actual exit-zero terminal outcomes')
    need(d['detail_abs']==d['detail_negative']==d['first_error']==d['active']==d['busy']==
         d['unexpected']==d['guest_data_fault']==0, 'successful quiet resident observation')
    need(l.get('first_error')==l.get('active')==l.get('busy')==l.get('decoding')==
         l.get('closing')==l.get('resuming')==0 and l.get('events')==sum(l['signals']),
         'actual completed ingress census and quiet inherited owner')
    need(v.get('enabled')==1 and v.get('differential')==v.get('poisoned')==v.get('mismatches')==
         v.get('comparisons')==v.get('reserved')==0 and v.get('queries')==v.get('hits',0)+v.get('refreshes',0),
         'actual nondifferential maintained-map counters')
    need(d['offers']==d['serial']==d['entries']+d['cancelled'] and
         d['entries']==d['completed']==d['publications']+d['hits']+s['hits'] and
         d['cold_attempts']==d['publications']+d['cancelled'] and
         d['misses'][0]==0 and sum(d['misses'])==d['cancelled'],
         'exact completed, cold and genuinely cancelled resident partitions')
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
    if not d['offers']:
        need(d['phase']==d['opened_pages']==d['closed_pages']==d['anchor_released']==
             d['registration_rechecked']==d['recovery_complete']==d['domain_members']==0, 'actual unused resident owner')
    else:
        need(d['phase']in(13,14)and d['anchor_released']==d['registration_rechecked']==1,
             'last chosen epoch is actually closed or fully cancelled')
        need((d['opened_pages'],d['closed_pages'],d['recovery_complete'])==
             ((17*d['domain_members'],17*d['domain_members'],1)if d['phase']==13 else(0,0,0)), 'exact executed versus unentered terminal extent')
        need(d['domain_members'] in (1,2) if d['phase']==13 else d['domain_members']==0,
             'actual one/two-member domain or unbound cancellation')
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



def completed_terminal(stderr,prefix):
    raw=counters(stderr);d=raw['LI2_PERSISTENT_UNREGISTERED'];l=raw['LI2_LINKED_EPOCH']
    need(all(d[k]==prefix['group'][k]for k in GROUP_NAMES)and d['misses']==prefix['misses'],
         'all completed persistent cells equal actual post-reap counter storage')
    need(l['events']==prefix['events']and l['signals']==prefix['signals'],
         'whole completed ingress census equals actual post-reap storage')
    need(all(raw['LI2_MAPS_VIEW'][k]==v for k,v in prefix['view'].items()),
         'whole completed maintained view equals actual post-reap storage')
    n=raw['LI2_NATIVE']
    need(all(n[k]==prefix['native'][k]for k in prefix['native']),
         'five actual native owner counters equal post-reap storage')
    completed(raw)
    return dict(subentry=raw['LI2_PERSISTENT_SUBENTRY'],persistent=d,
        scope='completed_count_accounting_only_no_capture_or_fullstate_qualification')
