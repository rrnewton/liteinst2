"""Distinct retained-RX terminal; common original predicates remain shared.

No old NX row is rewritten. Certificate DIFF is independent of maps DIFF.
The finite adapter adds count/identity evidence to a separate complete native
application comparison; it does not claim an independent whole owner capture.
"""
import json
from functools import partial
from types import SimpleNamespace
from page_selected import need
from loop_ro_oracle_reports import row
import loop_ro_certificate_reports as ro
import persistent_loop_effects_performance_reports as prior
import persistent_fused_counter_terminal as pf
import persistent_loop_effects_counter_terminal as effects

DEFAULT_DEPENDENCIES=(pf,prior,ro)

PREFIX = b'LI2_LOOP_RESIDENT_RX '
FIELDS = ('version','status','failure_code','entries','retained_entries','quiet_releases',
    'direct_offers','direct_steps','code_opens','code_revokes','code_writes','code_syncs',
    'metadata_permissions','metadata_syncs','terminal_attempts','terminal_closed',
    'last_complete','last_id','last_serial','last_count','last_retained_mask',
    'last_source_phase','last_entry','last_released_pc','last_root','last_head',
    'last_slot','last_bank','last_generation','revoke_cold','revoke_declined',
    'revoke_fetch','revoke_raw','revoke_native','revoke_return')
LAST = FIELDS[16:29]
REASONS = FIELDS[29:]


TRANSIT_PREFIX=b'LI2_LOOP_RX_TRANSIT '
TRANSIT_FIELDS=('version','status','failure_code','branch_limit','offers','steps','declined','limit_revokes')


def transit_row(stderr,*,oracle=False):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole actual transit terminal')
    lines=stderr[:-1].split(b'\n');found=[i for i,x in enumerate(lines) if x.startswith(TRANSIT_PREFIX)]
    need(len(found)==1 and 0<found[0]<len(lines)-1 and
         lines[found[0]-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ') and
         lines[found[0]+1].startswith(b'LI2_LOOP_RX_TRANSIT_TICKET ' if oracle else PREFIX),
         'one distinct transit row in its exact production or finite-observer position')
    i=found[0];actual=row(lines[i],TRANSIT_PREFIX,TRANSIT_FIELDS)
    need(actual['branch_limit']==2,'literal total budget of two original DIRECT branches')
    return actual,b'\n'.join(lines[:i]+lines[i+1:])+b'\n'


def transit_joined(transit,actual):
    need((transit['status'],transit['failure_code'])==(actual['status'],actual['failure_code']) and
         transit['offers']==transit['steps'] and transit['limit_revokes']<=transit['steps'] and
         transit['offers']+transit['declined']<=actual['direct_steps'],
         'actual second-branch closes and budget revocations; first-ticket meaning unchanged')


def transit_controls(stderr,validate,*,oracle=False):
    actual,_=transit_row(stderr,oracle=oracle);lines=stderr[:-1].split(b'\n')
    index=next(i for i,x in enumerate(lines) if x.startswith(TRANSIT_PREFIX));refusals=[]
    rx=row(lines[-1],PREFIX,FIELDS)
    def reject(label,changed):
        need(changed!=stderr,'actual supplied transit-row mutation')
        try:validate(changed)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted transit mutation '+label)
    for key in TRANSIT_FIELDS:
        for kind in ('missing','boolean','semantic'):
            changed=dict(actual)
            if kind=='missing':del changed[key]
            elif kind=='boolean':changed[key]=bool(changed[key])
            elif key=='declined':changed[key]=rx['direct_steps']+1
            elif key=='limit_revokes':changed[key]=actual['steps']+1
            else:changed[key]^=1
            copy=list(lines);copy[index]=TRANSIT_PREFIX+json.dumps(changed,separators=(',',':')).encode()
            reject(kind+'.'+key,b'\n'.join(copy)+b'\n')
    for label,copy in (('missing',lines[:index]+lines[index+1:]),
                       ('duplicate',lines[:index]+[lines[index]]+lines[index:]),
                       ('late',lines[:index]+lines[index+1:]+[lines[index]])):
        reject(label,b'\n'.join(copy)+b'\n')
    changed=dict(actual);changed['extra']=0;copy=list(lines)
    copy[index]=TRANSIT_PREFIX+json.dumps(changed,separators=(',',':')).encode()
    reject('extra',b'\n'.join(copy)+b'\n')
    need(len(refusals)==len(set(refusals))==28,'separate complete transit counter controls')
    return refusals


def split(stderr):
    _,stderr=transit_row(stderr)
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'whole RX terminal bytes')
    lines=stderr[:-1].split(b'\n')
    found=[i for i,x in enumerate(lines) if x.startswith(PREFIX)]
    need(found==[len(lines)-1] and len(lines)>1 and
         lines[-2].startswith(b'LI2_PERSISTENT_UNREGISTERED '),
         'one distinct RX row after the complete original terminal')
    actual=row(lines[-1],PREFIX,FIELDS)
    need(actual['status']==actual['failure_code']==0,
         'actual successful RX terminal, never a killed or exceptional prefix')
    return actual,b'\n'.join(lines[:-1])+b'\n'


def extent(actual):
    def check(d):
        if d['phase']==13:
            n=actual['last_count'];mask=actual['last_retained_mask']
            need(actual['last_complete']==1 and actual['last_id']>0 and
                 actual['last_serial']==d['serial'] and n==d['domain_members'] and
                 n in (1,2) and mask < 1<<n and actual['last_source_phase']==9 and
                 actual['last_generation']==d['generation'] and
                 actual['last_slot']==d['selected_slot'] and actual['last_bank']in(0,1),
                 'literal final completed RX cell identity and typed release')
            need((d['opened_pages'],d['closed_pages'],d['recovery_complete'])==
                 (17*(n-mask.bit_count()),0,1),
                 'actual newly opened members and no invented NX close operations')
        else:
            need(all(actual[k]==0 for k in LAST) and
                 (d['opened_pages'],d['closed_pages'],d['recovery_complete'])==(0,0,0),
                 'unused/cancelled owner has no invented completed RX cell')
    return check


def joined(actual,raw):
    d=raw['LI2_PERSISTENT_UNREGISTERED'];s=raw['LI2_PERSISTENT_SUBENTRY']
    extent(actual)(d)
    need(actual['entries']==d['entries']+d['dual_entries'] and
         actual['quiet_releases']==d['completed'] and
         actual['retained_entries']<=actual['entries'] and
         actual['code_opens']==3*(actual['entries']-actual['retained_entries']) and
         actual['direct_offers']==actual['direct_steps']<=d['completed'] and
         actual['code_syncs']==actual['code_opens']+actual['code_revokes']+actual['code_writes'] and
         actual['metadata_syncs']==actual['metadata_permissions'] and
         actual['terminal_attempts']==actual['terminal_closed']==1 and
         actual['code_revokes']>=3*sum(actual[k] for k in REASONS),
         'actual member activations, permission helper calls and completed direct steps')
    if d['phase']==13:
        need(actual['last_id']==d['completed'] and
             actual['last_entry']==actual['last_released_pc']==s['pc'] and
             all(actual['last_'+k]==s[k] for k in ('root','head','slot','bank','generation')),
             'current entry and released PC join independently of the compiled root')


def finite(stderr,mode,*,dependencies=None):
    """Count/typed-release checks only; caller owns complete native-state proof."""
    pf,prior,ro=DEFAULT_DEPENDENCIES if dependencies is None else dependencies
    transit,_=transit_row(stderr)
    actual,original=split(stderr)
    transit_joined(transit,actual)
    certificate,ordinary=ro.split(original,mode)
    raw=effects.counters(ordinary)
    pf.completed(raw,extent=extent(actual));joined(actual,raw)
    effects.completed_choice(raw['LI2_LOOP_RUNTIME'],raw['LI2_LOOP_EFFECTS'],
        dict(persistent=raw['LI2_PERSISTENT_UNREGISTERED'],subentry=raw['LI2_PERSISTENT_SUBENTRY']))
    need(certificate['byte_certificate']['issues']==raw['LI2_PERSISTENT_UNREGISTERED']['publications'] and
         certificate['history_certificate']['issues']==raw['LI2_PERSISTENT_UNREGISTERED']['completed'],
         'actual finite publication/completion certificate identity')
    return dict(rx=actual,transit=transit,certificate=certificate,counters=raw,
                scope='typed_release_and_count_checks_no_independent_whole_owner_capture',
                qualification_credit=False)


def callbacks(actual,dependencies=None):
    pf,prior,ro=DEFAULT_DEPENDENCIES if dependencies is None else dependencies
    def check(stdout,stderr,args,kind,lane):
        result=prior.check(stdout,stderr,args,kind,lane,extent=extent(actual))
        joined(actual,effects.counters(stderr))
        return result
    def controls(stdout,stderr,args,kind,lane):
        return prior.controls(stdout,stderr,args,kind,lane,extent=extent(actual))
    return check,controls


def check(stdout,stderr,args,kind,mode,*,dependencies=None):
    pf,prior,ro=DEFAULT_DEPENDENCIES if dependencies is None else dependencies
    transit,_=transit_row(stderr)
    actual,original=split(stderr);terminal,_=callbacks(actual,dependencies)
    transit_joined(transit,actual)
    result=ro.check(stdout,original,args,kind,mode,terminal_check=terminal)
    result.update(rx=actual,transit=transit,profile='persistent-loop-resident-rx-v1',qualification_credit=False)
    return result


def controls(stdout,stderr,args,kind,mode,*,dependencies=None):
    pf,prior,ro=DEFAULT_DEPENDENCIES if dependencies is None else dependencies
    check(stdout,stderr,args,kind,mode,dependencies=dependencies)
    actual,original=split(stderr);terminal,terminal_controls=callbacks(actual,dependencies)
    inherited=ro.controls(stdout,original,args,kind,mode,
        terminal_check=terminal,terminal_controls=terminal_controls)
    need(len(inherited['refusals'])==167 and
         len(inherited['inherited']['refusals'])==prior.CONTROL_COUNTS[kind],
         'all original447/480 application plus167 certificate controls retained')
    lines=stderr[:-1].split(b'\n');refusals=[]
    def reject(label,value):
        need(value!=stderr,'actual distinct RX mutation')
        try:check(stdout,value,args,kind,mode,dependencies=dependencies)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted RX terminal mutation '+label)
    def replace(label,value):
        reject(label,b'\n'.join(lines[:-1]+[PREFIX+json.dumps(value,separators=(',',':')).encode()])+b'\n')
    for key in FIELDS:
        changed=dict(actual);del changed[key];replace('missing.'+key,changed)
        changed=dict(actual);changed[key]=bool(changed[key]);replace('boolean.'+key,changed)
    changed=dict(actual);changed['extra']=0;replace('extra',changed)
    replace('key_order',dict(reversed(list(actual.items()))))
    reject('duplicate_key',b'\n'.join(lines[:-1]+[lines[-1][:-1]+b',"version":1}'])+b'\n')
    reject('missing_row',original)
    reject('duplicate_row',stderr+lines[-1]+b'\n')
    reject('row_order',b'\n'.join(lines[:-2]+[lines[-1],lines[-2]])+b'\n')
    reject('newline',stderr[:-1])
    reject('whitespace',b'\n'.join(lines[:-1]+[lines[-1].replace(b'{',b'{ ',1)])+b'\n')
    reject('writer_bound',stderr[:-1]+b' '*4096+b'\n')
    for key in ('version','status','failure_code','entries','retained_entries','quiet_releases',
                'direct_offers','direct_steps','code_opens','code_syncs','metadata_syncs',
                'terminal_attempts','terminal_closed'):
        changed=dict(actual);changed[key]^=1;replace('semantic.'+key,changed)
    for key in LAST:
        changed=dict(actual);changed[key]^=1;replace('semantic.'+key,changed)
    changed=dict(actual);changed['code_revokes']=0
    changed['revoke_cold']=1
    changed['code_syncs']=changed['code_opens']+changed['code_writes']
    replace('semantic.actual_revoke_calls',changed)
    need(len(refusals)==len(set(refusals))==106,'fixed complete additive RX controls')
    return dict(inherited=inherited,refusals=refusals,
        transit_refusals=transit_controls(stderr,
            lambda value:check(stdout,value,args,kind,mode,dependencies=dependencies)))


def configured(fused, application, certificate):
    """Bind authenticated private dependencies; never replace module globals."""
    dependencies=(fused,application,certificate)
    return SimpleNamespace(prior=application,dependencies=dependencies,
        finite=partial(finite,dependencies=dependencies),
        check=partial(check,dependencies=dependencies),
        controls=partial(controls,dependencies=dependencies))


def extent_controls():
    """Small synthetic lifecycle predicate check, never an owner observation."""
    positives=[];refusals=[]
    for phase,mask in ((13,0),(13,2),(0,0),(14,0),(15,0)):
        actual={name:0 for name in FIELDS}
        d=dict(phase=phase,serial=7,domain_members=2,generation=9,selected_slot=0,
               opened_pages=0,closed_pages=0,recovery_complete=0)
        if phase==13:
            actual.update(last_complete=1,last_id=3,last_serial=7,last_count=2,
                last_retained_mask=mask,last_source_phase=9,last_generation=9,last_slot=0,last_bank=1)
            d.update(opened_pages=17*(2-mask.bit_count()),recovery_complete=1)
        extent(actual)(d);positives.append([phase,mask])
        for field in LAST if phase!=13 else ('last_complete','last_count','last_serial','last_source_phase'):
            changed=dict(actual);changed[field]^=1
            try:extent(changed)(d)
            except ValueError:refusals.append(str(phase)+'.'+str(mask)+'.'+field)
            else:raise ValueError('accepted synthetic wrong RX completion '+field)
        for field in ('opened_pages','closed_pages','recovery_complete'):
            changed=dict(d);changed[field]^=1
            try:extent(actual)(changed)
            except ValueError:refusals.append(str(phase)+'.'+str(mask)+'.'+field)
            else:raise ValueError('accepted synthetic wrong permission extent '+field)
    need(len(positives)==5 and len(refusals)==len(set(refusals))==62,
         'closed/mixed-retained/unused/cancelled/exceptional extent controls')
    return dict(positives=positives,refusals=refusals,scope='synthetic predicate only',qualification_credit=False)
