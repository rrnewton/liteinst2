"""Strict CACHE8 terminal/status joins; no old two-member qualification cast."""
import json
import struct
from functools import partial
from types import SimpleNamespace
from page_selected import need
from loop_ro_oracle_reports import row
import loop_resident_rx_reports as rx
import loop_ro_certificate_reports as ro
import persistent_loop_effects_counter_terminal as effects

PREFIX=b'LI2_LOOP_CACHE8_RX '
TRANSIT=b'LI2_LOOP_CACHE8_TRANSIT '
DEFAULT=(row,rx,ro,effects)


def read(stderr,record,control,mode,*,dependencies=None):
    parse,prior,certificate,effect=DEFAULT if dependencies is None else dependencies
    need(type(stderr)is bytes and stderr.endswith(b'\n') and type(record)is bytes and
         len(record)==910432 and type(control)is int and control in(0,1) and
         mode in('release','differential') and (not control or mode=='differential'),
         'whole explicit CACHE8 terminal and independently validated wire')
    lines=stderr[:-1].split(b'\n');status,code=(125,3303)if control else(0,0)
    need(len(lines)>5 and lines[-1].startswith(PREFIX) and lines[-2].startswith(TRANSIT) and
         lines[-3].startswith(b'LI2_PERSISTENT_UNREGISTERED ') and
         sum(x.startswith(PREFIX)for x in lines)==sum(x.startswith(TRANSIT)for x in lines)==1,
         'exact distinct versioned CACHE8 terminal order')
    actual=parse(lines[-1],PREFIX,prior.FIELDS,version=2)
    transit=parse(lines[-2],TRANSIT,prior.TRANSIT_FIELDS)
    need((actual['status'],actual['failure_code'])==(transit['status'],transit['failure_code'])==(status,code),
         'actual child outcome agrees with both strict terminal rows')
    # Parse the three original certificate rows literally, including deliberate
    # failures. Do not apply the old successful two-member owner theorem.
    positions=[];cert=[]
    for prefix,fields in zip(certificate.PREFIXES,certificate.FIELDS,strict=True):
        found=[i for i,x in enumerate(lines[:-2])if x.startswith(prefix)]
        need(len(found)==1,'one original certificate row')
        positions.append(found[0]);cert.append(parse(lines[found[0]],prefix,fields))
    start=positions[0]
    need(positions==list(range(start,start+3)) and start>0 and start+3<len(lines)-2 and
         lines[start-1].startswith(b'LI2_PF_REFUSALS ') and
         lines[start+3].startswith(b'LI2_PERSISTENT_SUBENTRY '),'original certificate producer order')
    need(all((x['status'],x['failure_code'])==(status,code)for x in cert) and
         cert[0]['differential']==cert[2]['differential']==int(mode=='differential') and
         cert[0]['disagreements']==cert[2]['disagreements']==0,
         'actual certificate mode and no differential disagreement')
    ordinary=b'\n'.join(lines[:start]+lines[start+3:-2])+b'\n'
    raw=effect.counters(ordinary)
    need(all((v['status'],v['failure_code'])==(status,code)for v in raw.values()
             if 'status'in v and 'failure_code'in v),'every original typed terminal keeps the actual child outcome')
    d=raw['LI2_PERSISTENT_UNREGISTERED'];sub=raw['LI2_PERSISTENT_SUBENTRY']
    h=struct.unpack_from('<32Q',record);last=struct.unpack_from('<32Q',record,544+3*227264+256+3*256)
    need((d['status'],d['failure_code'],d['first_error'],d['detail_abs'],d['detail_negative'],d['active'],d['busy'])==
         (status,code,h[24],h[25],0,h[26],h[27]) and h[22:24]==(status,code),
         'whole real owner failure/detail/active/busy agrees with actual binary observer')
    need(d['phase']==15 if control else d['phase']in(13,14), 'literal failed or completed/cancelled terminal phase')
    for name,index in (('publications',6),('cold_attempts',7),('hits',8),('offers',9),('entries',10),('completed',11)):
        need(d[name]>=last[index] and (not control or d[name]==last[index]),
             'actual final owner counter includes every observed activation: '+name)
    for name,index in (('code_opens',12),('code_revokes',13),('code_writes',14),('code_syncs',15),
                       ('metadata_permissions',16),('metadata_syncs',17),('retained_entries',18)):
        need(actual[name]>=last[index],'actual final RX counter includes every observed activation: '+name)
    need(actual['quiet_releases']==d['completed'] and actual['retained_entries']<=actual['entries'] and
         actual['code_opens']==3*(actual['entries']-actual['retained_entries']) and
         actual['code_syncs']==actual['code_opens']+actual['code_revokes']+actual['code_writes'] and
         actual['metadata_syncs']==actual['metadata_permissions'] and
         actual['direct_offers']==actual['direct_steps']<=d['completed'] and
         actual['terminal_attempts']==actual['terminal_closed']==1,
         'shared actual member permission/release/call conservation, without two-member entry arithmetic')
    need(transit['branch_limit']==2 and transit['offers']==transit['steps'] and
         transit['limit_revokes']<=transit['steps'] and
         transit['offers']+transit['declined']<=actual['direct_steps'],
         'actual bounded DIRECT bridge conservation')
    if d['phase']==13:
        n=actual['last_count'];mask=actual['last_retained_mask']
        need(actual['last_complete']==1 and 1<=n<=8 and n==d['domain_members'] and mask<1<<n and
             actual['last_id']==d['completed'] and actual['last_serial']==d['serial'] and
             actual['last_source_phase']==9 and actual['last_generation']==d['generation'] and
             actual['last_slot']==d['selected_slot'] and actual['last_slot']<8 and actual['last_bank']<2 and
             (d['opened_pages'],d['closed_pages'],d['recovery_complete'])==(17*(n-mask.bit_count()),0,1) and
             actual['last_entry']==actual['last_released_pc']==sub['pc'] and
             all(actual['last_'+k]==sub[k]for k in('root','head','slot','bank','generation')),
             'typed version2 final completed cell and exact current subentry/source extent')
    else:
        need(all(actual[k]==0 for k in prior.LAST),'no invented completed cell on cancellation or failed abort')
    return dict(rx=actual,transit=transit,owner=d,certificate=cert,
                scope='typed terminal and focal wire joins only',qualification_credit=False)


def controls(stderr,record,control,mode,*,dependencies=None):
    deps=DEFAULT if dependencies is None else dependencies
    baseline=read(stderr,record,control,mode,dependencies=deps);lines=stderr[:-1].split(b'\n')
    tests=(('rx_version',-1,'version',1),('rx_status',-1,'status',baseline['rx']['status']^1),
           ('rx_failure',-1,'failure_code',baseline['rx']['failure_code']^1),
           ('code_opens',-1,'code_opens',baseline['rx']['code_opens']+1),
           ('code_syncs',-1,'code_syncs',baseline['rx']['code_syncs']+1),
           ('metadata_syncs',-1,'metadata_syncs',baseline['rx']['metadata_syncs']+1),
           ('terminal_closed',-1,'terminal_closed',0),('branch_limit',-2,'branch_limit',1),
           ('transit_steps',-2,'steps',baseline['transit']['steps']+1),
           ('owner_active',-3,'active',baseline['owner']['active']^1))
    refused=[]
    for name,index,key,value in tests:
        prefix=lines[index].split(b' ',1)[0]+b' ';fields=json.loads(lines[index][len(prefix):]);fields[key]=value
        changed=list(lines);changed[index]=prefix+json.dumps(fields,separators=(',',':')).encode()
        try:read(b'\n'.join(changed)+b'\n',record,control,mode,dependencies=deps)
        except ValueError:refused.append(name)
        else:raise ValueError('accepted CACHE8 terminal corruption '+name)
    need(len(refused)==len(set(refused))==10,'ten exact typed terminal and binary-join controls')
    return dict(refusals=refused,native_operations=0)


def configured(parse,prior,certificate,effect):
    dependencies=(parse,prior,certificate,effect)
    return SimpleNamespace(read=partial(read,dependencies=dependencies),
                           controls=partial(controls,dependencies=dependencies))
