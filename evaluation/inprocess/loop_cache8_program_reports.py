"""Complete original program checks with a distinct all-eight-slot terminal.

Counts describe actual protected producer fields. No row is rewritten and no
two-slot ownership theorem is attributed to the CACHE8 owner.
"""
import json
from functools import partial
from types import SimpleNamespace
from page_selected import need
from loop_ro_oracle_reports import row
import persistent_loop_effects_performance_reports as application
import loop_ro_certificate_reports as certificate
import loop_resident_rx_reports as rx

PREFIX=b'LI2_LOOP_CACHE8_COUNTS '
RX_PREFIX=b'LI2_LOOP_CACHE8_RX '
TRANSIT_PREFIX=b'LI2_LOOP_CACHE8_TRANSIT '
MEMBERS=tuple(range(1,9))
FIELDS=('version','status','failure_code','slots','members','receipts',
    'cold_calls','compact_build_calls','compact_validate_calls',
    'attach_attempts','accepted','source_declines')+tuple(
    'slot'+str(i)+'_'+name for i in range(8) for name in
    ('generation','permit','completed_serial'))+tuple(
    name+str(i) for i in range(9) for name in ('bound','entered','completed'))
DEFAULT=(application,certificate,rx,row)


def split(stderr,parse=row):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole actual CACHE8 program terminal')
    lines=stderr[:-1].split(b'\n')
    found=[i for i,x in enumerate(lines)if x.startswith(PREFIX)]
    need(len(FIELDS)==63 and len(found)==1 and 0<found[0]==len(lines)-3 and
         lines[found[0]-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ') and
         lines[-2].startswith(TRANSIT_PREFIX) and lines[-1].startswith(RX_PREFIX),
         'one complete CACHE8 count row at its exact terminal producer position')
    i=found[0];actual=parse(lines[i],PREFIX,FIELDS)
    need(actual['status']==actual['failure_code']==0 and
         (actual['slots'],actual['members'],actual['receipts'])==(8,8,9),
         'successful exact eight-slot/eight-member/nine-receipt count observation')
    return actual,b'\n'.join(lines[:i]+lines[i+1:])+b'\n'


def retained(counts,actual,d,s):
    """Successful full-program theorem from the actual slot and call arrays."""
    need(0<=d['selected_slot']<8,'actual selected CACHE8 retained slot')
    generations=tuple(counts['slot'+str(i)+'_generation']for i in range(8))
    permits=tuple(counts['slot'+str(i)+'_permit']for i in range(8))
    serials=tuple(counts['slot'+str(i)+'_completed_serial']for i in range(8))
    need(all(counts['slot'+str(i)+'_'+name]==d['slot'+str(i)+'_'+name]
             for i in range(2)for name in ('generation','permit','completed_serial')),
         'unchanged original two slot observations join their actual full-array positions')
    installed=sum(g>0 for g in generations)
    need(all(0<=g<=d['publications']for g in generations) and
         len({g for g in generations if g})==installed and max(generations)==d['publications'] and
         permits==tuple(int(g>0)for g in generations) and
         all((0<c<=d['serial'])if g else c==0 for g,c in zip(generations,serials,strict=True)),
         'all eight distinct actual generations and their completed permits')
    bound=tuple(counts['bound'+str(i)]for i in range(9))
    entered=tuple(counts['entered'+str(i)]for i in range(9))
    completed=tuple(counts['completed'+str(i)]for i in range(9))
    need(bound==entered==completed and bound[0]==0 and
         sum(entered)==d['entries']==d['completed'] and
         d['dual_entries']==entered[2] and d['dual_completed']==completed[2],
         'all successful CACHE8 bindings enter and complete at their exact member count')
    total=sum(i*entered[i]for i in MEMBERS)
    peers=sum((i-1)*entered[i]for i in MEMBERS)
    need(actual['entries']==total and actual['quiet_releases']==sum(completed) and
         counts['accepted']==peers and
         counts['attach_attempts']==counts['accepted']+counts['source_declines'],
         'actual weighted member activations and one-shot peer proposal partition')
    need(d['generation']==generations[d['selected_slot']] and d['permit']==permits[d['selected_slot']] and
         d['retirements']==d['publications']-installed and
         d['permit_claims']==d['hits']+s['hits']+d['retirements']+peers,
         'all-slot publication/retirement identity and primary plus every peer claim')
    if d['generation']:
        need(0<d['build_serial']<=serials[d['selected_slot']],
             'selected immutable build precedes its actual completion')
    else:
        need(d['build_serial']==0,'no invented selected-generation build serial')
    need(counts['cold_calls']==d['cold_attempts'] and
         counts['compact_build_calls']==counts['compact_validate_calls']==d['publications'],
         'actual cold and compact API calls for every successful publication')


def members(d):
    need(d['domain_members']in MEMBERS if d['phase']==13 else d['domain_members']==0,
         'actual one-to-eight-member CACHE8 domain or unbound cancellation')


def callbacks(counts,actual,dependencies):
    prior,ro,old,parse=dependencies
    options=dict(extent=old.extent(actual,members=MEMBERS),
                 retained=partial(retained,counts,actual),members=members)
    def check(stdout,stderr,args,kind,lane):
        result=prior.check(stdout,stderr,args,kind,lane,**options)
        total=sum(i*counts['entered'+str(i)]for i in MEMBERS)
        old.joined(actual,old.effects.counters(stderr),member_entries=total,members=MEMBERS)
        return result
    def controls(stdout,stderr,args,kind,lane):
        return prior.controls(stdout,stderr,args,kind,lane,**options)
    return check,controls


def check(stdout,stderr,args,kind,mode,*,dependencies=None):
    deps=DEFAULT if dependencies is None else dependencies
    prior,ro,old,parse=deps
    need(mode=='release','the separate CACHE8 program recipe is exactly release')
    counts,without=split(stderr,parse)
    transit,_=old.transit_row(without,prefix=TRANSIT_PREFIX,rx_prefix=RX_PREFIX,parse=parse)
    actual,original=old.split(without,prefix=RX_PREFIX,version=2,transit_prefix=TRANSIT_PREFIX,parse=parse)
    old.transit_joined(transit,actual)
    terminal,_=callbacks(counts,actual,deps)
    result=ro.check(stdout,original,args,kind,mode,terminal_check=terminal)
    result.update(rx=actual,transit=transit,cache8=counts,
                  profile='persistent-loop-cache8-program-v1',qualification_credit=False)
    return result


def count_controls(stderr,counts,persistent,validate):
    """Full-validator refusals; inequalities use a source-forbidden boundary."""
    lines=stderr[:-1].split(b'\n');index=len(lines)-3;refusals=[]
    def reject(label,value):
        need(value!=stderr,'actual supplied CACHE8 count mutation')
        try:validate(value)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted CACHE8 count mutation '+label)
    def replace(label,value):
        changed=list(lines);changed[index]=PREFIX+json.dumps(value,separators=(',',':')).encode()
        reject(label,b'\n'.join(changed)+b'\n')
    for name in FIELDS:
        value=dict(counts);del value[name];replace('missing.'+name,value)
        value=dict(counts);value[name]=bool(value[name]);replace('boolean.'+name,value)
        value=dict(counts)
        if name.startswith('slot') and name.endswith('_generation'):
            value[name]=persistent['publications']+1
        elif name.startswith('slot') and name.endswith('_completed_serial'):
            value[name]=persistent['serial']+1
        else:value[name]^=1
        replace('semantic.'+name,value)
    value=dict(counts);value['extra']=0;replace('extra',value)
    replace('key_order',dict(reversed(list(counts.items()))))
    changed=list(lines);changed[index]=lines[index][:-1]+b',"version":1}'
    reject('duplicate_key',b'\n'.join(changed)+b'\n')
    reject('missing_row',b'\n'.join(lines[:index]+lines[index+1:])+b'\n')
    reject('duplicate_row',b'\n'.join(lines[:index]+[lines[index]]+lines[index:])+b'\n')
    changed=list(lines);changed[index],changed[index+1]=changed[index+1],changed[index]
    reject('row_order',b'\n'.join(changed)+b'\n')
    reject('newline',stderr[:-1])
    changed=list(lines);changed[index]=lines[index].replace(b'{',b'{ ',1)
    reject('whitespace',b'\n'.join(changed)+b'\n')
    changed=list(lines);changed[index]+=b' '*4096
    reject('writer_bound',b'\n'.join(changed)+b'\n')
    # Preserve the three corresponding counts; their actual entry sum still
    # has to join the independently emitted original owner.
    for i in MEMBERS:
        value=dict(counts)
        for name in ('bound','entered','completed'):value[name+str(i)]+=1
        replace('coherent_count.'+str(i),value)
    # Preserve generation-to-permit correspondence while breaking the whole
    # all-slot publication and original first-two-slot observations.
    for i in range(8):
        value=dict(counts);base='slot'+str(i)+'_'
        value[base+'generation']=persistent['publications']+1
        value[base+'permit']=1;value[base+'completed_serial']=persistent['serial']
        replace('coherent_slot.'+str(i),value)
    need(len(refusals)==len(set(refusals))==214,'all63 field triples plus9 encoding and16 coherent count/slot refusals')
    return refusals


def controls(stdout,stderr,args,kind,mode,*,dependencies=None):
    deps=DEFAULT if dependencies is None else dependencies
    prior,ro,old,parse=deps
    baseline=check(stdout,stderr,args,kind,mode,dependencies=deps)
    counts,without=split(stderr,parse)
    actual,original=old.split(without,prefix=RX_PREFIX,version=2,transit_prefix=TRANSIT_PREFIX,parse=parse)
    terminal,terminal_controls=callbacks(counts,actual,deps)
    inherited=ro.controls(stdout,original,args,kind,mode,
        terminal_check=terminal,terminal_controls=terminal_controls)
    need(len(inherited['refusals'])==167 and
         len(inherited['inherited']['refusals'])==prior.CONTROL_COUNTS[kind],
         'all original447/480 application plus167 certificate controls retained')
    validate=lambda value:check(stdout,value,args,kind,mode,dependencies=deps)
    missing_rx=b'\n'.join(stderr[:-1].split(b'\n')[:-2])+b'\n'
    refusals=old.terminal_controls(stderr,actual,missing_rx,validate,prefix=RX_PREFIX)
    transit=old.transit_controls(stderr,validate,prefix=TRANSIT_PREFIX,rx_prefix=RX_PREFIX,
                                rx_version=2,preceding=PREFIX,parse=parse)
    return dict(inherited=inherited,refusals=refusals,transit_refusals=transit,
        cache8_refusals=count_controls(stderr,counts,baseline['persistent'],validate))


def configured(prior,ro,old,parse):
    dependencies=(prior,ro,old,parse)
    return SimpleNamespace(prior=prior,check=partial(check,dependencies=dependencies),
                           controls=partial(controls,dependencies=dependencies))
