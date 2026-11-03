"""Exact arena terminal joins over the unchanged shared CACHE8 theorem.

The separately bound observer validates the complete new wire. No historical
wire is synthesized and a deliberate causal abort is never program completion.
"""
import json
import struct
from functools import partial
from types import SimpleNamespace
from page_selected import need

WIRE,EPOCH,APPEND=3471320,227776,3190176
CONTROL_COUNT=23
ARENA_FIELDS=('detached','rebound','rebound_peers','cold_nodes','evicted',
              'epoch_invalidations','physical_checks','next_binding')


def q(data,offset=0,count=1):return struct.unpack_from('<'+'Q'*count,data,offset)


def read(stderr,record,control,mode,*,dependencies):
    parse,common,descriptor,observer=dependencies
    need(type(record)is bytes and len(record)==WIRE+64 and type(control)is int and control in(0,1,2) and
         mode in('release','differential') and (not control or mode=='differential'),
         'whole distinct arena observation and literal control/build mode')
    status,code=((0,0),(125,3303),(125,3309))[control]
    epochs=10 if control==2 else 14
    h=q(record,0,32);a=q(record,APPEND,32);last=q(record,544+(epochs-1)*EPOCH+256+3*384,48)
    need(h[:9]==(0x314f41544132494c,1,WIRE,EPOCH,control,8,8,9,14) and
         h[16:24]==(epochs,0,0,0,24 if control else 0,24 if control else 0,status,code) and
         h[24:28]==((3303,8971,1,1)if control==1 else (3309,9232,0,1)if control==2 else(0,0,0,0)),
         'exact actual arena outcome and distinct completed versus pre-admission causal states')
    footer=q(record,WIRE,8)
    need(footer[:4]==(0x314641544132494c,1,WIRE,WIRE) and 1<=footer[4]<=64 and
         0<footer[5]<=WIRE and footer[6:]==(status,code),
         'complete actual arena record/footer outcome')
    wanted=20 if control==1 else 12 if control==2 else 0
    need(a[:8]==(1,12,8,3,wanted,wanted,status,code) and a[8]==int(control!=0) and not any(a[17:]),
         'actual twelve-node/eight-binding arena owner and all distinct restored predicate outcomes')
    cache,without_cache,_=descriptor.split_cache(stderr,parse)
    actual,ordinary,_=descriptor.split(without_cache,parse)
    descriptor.join_cache(cache,actual)
    base=common.joined(ordinary,record,control,mode,last_epoch=epochs-1,
                       observation=observer.terminal_observation,transit_observation=observer.terminal_transit)
    need((actual['status'],actual['failure_code'])==(status,code) and actual['initialized']==1 and
         actual['poisoned']==int(control!=0) and actual['unclassified']==actual['overflows']==actual['disagreements']==0,
         'actual descriptor owner and deliberate abort poison without unexpected proof/gateway failure')
    need(actual['descriptor_id']==actual['issues']==actual['directory_writes']>0 and
         actual['directory_queries']==actual['issues']+actual['hits'] and
         1<=actual['writer_epoch']<=actual['raw_invalidations']+1 and
         actual['topology_differential']==(actual['topology_hits']if mode=='differential'else 0) and
         actual['common_differential']==(actual['common_hits']if mode=='differential'else 0),
         'actual descriptor publication/query conservation and every-hit differential proofs')
    owner=base['owner'];byte,ro,history=base['certificate']
    arena=dict(zip(ARENA_FIELDS,a[9:17],strict=True))
    for name,index in (('detached',32),('rebound',33),('rebound_peers',34),('cold_nodes',35),
                       ('evicted',36),('epoch_invalidations',37),('physical_checks',39),('next_binding',40)):
        expected=last[index]+int(control==2 and name=='epoch_invalidations')
        need(arena[name]>=expected and (not control or arena[name]==expected),
             'actual final arena counter includes each completed focal activation: '+name)
    need(last[41]==0 and arena['cold_nodes']==byte['issues']==owner['publications'] and
         arena['physical_checks']==arena['rebound']+arena['rebound_peers'] and
         arena['detached']<=owner['permit_claims'] and arena['evicted']<=owner['retirements'] and
         arena['next_binding']>=8,
         'fresh cold publication, completed physical rebind and actual claim-consumption conservation')
    need(byte['bytes_per_complete_scan']==106*4096 and
         byte['decisions']==byte['hits']+byte['misses'] and
         byte['full_scans']==(byte['decisions']if mode=='differential'else byte['misses']) and
         byte['full_scan_bytes']==byte['full_scans']*byte['bytes_per_complete_scan'] and
         byte['postseal_bytes']==byte['issues']*byte['bytes_per_complete_scan'] and
         byte['live_queries']==3*(byte['issues']+byte['hits']+arena['physical_checks']) and
         byte['invalidations']==byte['issues']==ro['mirror_opens']==ro['mirror_seals'],
         'complete old byte scans and three fresh code/proof queries per actual dormant-node preparation')
    need(history['issues']==owner['completed'] and
         history['decisions']==history['hits']+history['misses'] and
         history['full_calls']==history['misses']+int(mode=='differential')*history['hits'] and
         history['differential_checks']==int(mode=='differential')*history['hits'] and
         history['invalidations']==history['issues'] and history['misses']>=history['issues'] and
         actual['common_full']>=owner['completed'] and
         actual['history_fallbacks']<=history['misses']-history['issues'] and
         actual['common_hits']<=history['decisions']<=actual['common_hits']+actual['common_full'] and
         actual['common_full']+cache['revalidated_hits']>=owner['completed']+actual['history_fallbacks'],
         'every completed history proof, first full common proof and renewed-token coverage remains required')
    return dict(base,descriptor=actual,common_cache=cache,arena=arena,
                pending_direct=base['transit']['offers']-base['transit']['steps'],
                program_status='failed'if control else'completed',qualification_credit=False,
                performance_credit=False)


def controls(stderr,record,control,mode,*,dependencies):
    parse,common,descriptor,observer=dependencies
    baseline=read(stderr,record,control,mode,dependencies=dependencies)
    cache,without_cache,cache_index=descriptor.split_cache(stderr,parse)
    actual,ordinary,index=descriptor.split(without_cache,parse)
    if cache_index<=index:index+=1
    old=common.controls_joined(ordinary,record,control,mode,last_epoch=9 if control==2 else 13,
                              observation=observer.terminal_observation,transit_observation=observer.terminal_transit)
    need(len(old['refusals'])==len(set(old['refusals']))==10,'all ten original shared terminal controls')
    lines=stderr[:-1].split(b'\n');refusals=[]
    validate=partial(read,record=record,control=control,mode=mode,dependencies=dependencies)
    def reject(label,changed,wire=record):
        need(changed!=stderr or wire!=record,'distinct actual arena terminal corruption')
        try:read(changed,wire,control,mode,dependencies=dependencies)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted arena terminal corruption '+label)
    for key,value in (('version',0),('status',actual['status']^1),('initialized',0),
            ('poisoned',actual['poisoned']^1),('unclassified',1),('overflows',1),
            ('issues',actual['issues']+1),('directory_writes',actual['directory_writes']+1),
            ('directory_queries',actual['directory_queries']+1),
            ('common_differential',actual['common_differential']+1),
            ('topology_differential',actual['topology_differential']+1),('disagreements',1),
            ('hits',actual['hits']+1)):
        fields=dict(actual);fields[key]=value;changed=list(lines)
        changed[index]=descriptor.PREFIX+json.dumps(fields,separators=(',',':')).encode()
        reject('descriptor.'+key,b'\n'.join(changed)+b'\n')
    reject('descriptor.missing',b'\n'.join(lines[:index]+lines[index+1:])+b'\n')
    reject('descriptor.duplicate',b'\n'.join(lines[:index]+[lines[index]]+lines[index:])+b'\n')
    for name,word in (('version',0),('restored_population',5),('poisoned',8),('cold_nodes',12),('physical_checks',15)):
        changed=bytearray(record);struct.pack_into('<Q',changed,APPEND+8*word,q(record,APPEND+8*word)[0]^1)
        reject('arena.'+name,stderr,bytes(changed))
    positions=[i for i,line in enumerate(lines)if line.startswith(b'LI2_SEALED_BYTE_CERTIFICATE ')]
    need(len(positions)==1,'one actual original byte-certificate row for arena accounting controls')
    at=positions[0];prefix=b'LI2_SEALED_BYTE_CERTIFICATE '
    for key in ('live_queries','issues','decisions'):
        fields=json.loads(lines[at][len(prefix):]);fields[key]+=1;changed=list(lines)
        changed[at]=prefix+json.dumps(fields,separators=(',',':')).encode()
        reject('certificate.'+key,b'\n'.join(changed)+b'\n')
    need(len(refusals)==len(set(refusals))==CONTROL_COUNT,
         'fifteen descriptor, five actual arena and three fresh-certificate accounting refusals')
    pending_refusals=[]
    if control==2:
        for label,at,keys,delta in (
                ('direct_pair',-1,('direct_offers','direct_steps'),-1),
                ('transit_pair',-2,('offers','steps'),1),
                ('transit_declined',-2,('declined',),1),
                ('transit_limit',-2,('limit_revokes',),1)):
            prefix=lines[at].split(b' ',1)[0]+b' ';fields=json.loads(lines[at][len(prefix):])
            for key in keys:
                fields[key]+=delta
                need(0<=fields[key]<1<<64,'distinct bounded supplied pending-counter mutation')
            changed=list(lines);changed[at]=prefix+json.dumps(fields,separators=(',',':')).encode()
            supplied=b'\n'.join(changed)+b'\n'
            need(supplied!=stderr,'actual pending-counter mutation differs from the valid terminal')
            try:validate(supplied)
            except ValueError as error:
                need(str(error)=='terminal retains every actual pending-ticket counter without a fabricated completed step',
                     'coherent counter mutation reaches the exact actual pending-ticket join')
                pending_refusals.append(label)
            else:raise ValueError('accepted actual pending-counter mutation '+label)
    need(len(pending_refusals)==len(set(pending_refusals))==(4 if control==2 else 0),
         'four separate genuine pre-close counter-join controls for the aborted subject only')
    return dict(refusals=old['refusals'],arena_refusals=refusals,
                common_cache_refusals=descriptor.cache_controls(stderr,parse,validate),
                pending_counter_refusals=pending_refusals,native_operations=0)


def configured(parse,common,descriptor,observer):
    need(observer.WIRE==WIRE and callable(observer.terminal_observation) and callable(observer.terminal_transit),
         'exact arena observer supplies the typed live-wire projection')
    dependencies=(parse,common,descriptor,observer)
    return SimpleNamespace(read=partial(read,dependencies=dependencies),
        controls=partial(controls,dependencies=dependencies),CONTROL_COUNT=CONTROL_COUNT)
