"""Distinct descriptor terminal joins over the shared unchanged CACHE8 theorem.

The caller separately validates the complete version2 observer. No binary row
is rewritten into the old four-epoch schema, and no abort is program success.
"""
import json
import struct
from functools import partial
from types import SimpleNamespace
from page_selected import need

PREFIX=b'LI2_LOOP_GROUP_DESCRIPTOR '
HISTORY=b'LI2_LOOP_HISTORY '
FIELDS=('version','status','failure_code','initialized','poisoned','descriptor_id',
    'writer_epoch','raw_invalidations','unclassified','overflows','issues','hits',
    'topology_hits','topology_full','topology_differential','common_hits','common_full',
    'common_differential','history_fallbacks','directory_writes','directory_queries','disagreements')
COUNT_FIELDS=FIELDS[10:]
WIRE,APPEND,SNAPSHOT,RAW=1186576,1137632,2280,3216
CONTROL_COUNT=25
PREENTRY_PREFIX=b'LI2_LOOP_GROUP_DESCRIPTOR_PREENTRY '
PREENTRY_FIELDS=('version','status','failure_code','control','epochs','accepted',
    'ordinary_refusals','attempted','refused','restorations')+tuple(
    name+str(i)for name in('serial','refusal','restore')for i in range(5))
PREENTRY_CONTROL_COUNT=84


def q(data,offset=0,count=1):return struct.unpack_from('<'+'Q'*count,data,offset)


def split(stderr,parse):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole actual descriptor terminal')
    lines=stderr[:-1].split(b'\n');at=[i for i,line in enumerate(lines)if line.startswith(PREFIX)]
    need(len(at)==1 and 0<at[0]<len(lines)-1 and
         lines[at[0]-1].startswith(HISTORY) and
         lines[at[0]+1].startswith(b'LI2_PERSISTENT_SUBENTRY '),
         'one descriptor row immediately after original history and before subentry')
    i=at[0]
    return parse(lines[i],PREFIX,FIELDS),b'\n'.join(lines[:i]+lines[i+1:])+b'\n',i


def read(stderr,record,control,mode,*,dependencies):
    parse,common=dependencies
    need(type(record)is bytes and len(record)==WIRE+64 and type(control)is int and
         control in range(7) and mode in('release','differential') and
         (not control or mode=='differential'),'whole exact descriptor observer and literal mode')
    h=q(record,0,32);footer=q(record,WIRE,8);status,code=(125,3303)if control else(0,0)
    need(h[:9]==(0x314f38434132494c,2,WIRE,227264,control,8,8,9,5) and
         h[16:24]==(5,0,0,0,24 if control else 0,24 if control else 0,status,code) and
         h[24:28]==((3303,8990 if control==6 else 8971,1,1)if control else(0,0,0,0)) and
         footer[:4]==(0x314638434132494c,2,WIRE,WIRE) and footer[6:]==(status,code),
         'distinct version2 five-epoch observer and literal actual terminal outcome')
    actual,ordinary,_=split(stderr,parse)
    base=common.joined(ordinary,record,control,mode,last_epoch=4)
    need((actual['status'],actual['failure_code'])==(status,code) and
         actual['initialized']==1 and actual['poisoned']==int(control!=0) and
         actual['unclassified']==actual['overflows']==actual['disagreements']==0,
         'actual descriptor owner, deliberate abort poison and no unexpected gateway or proof failures')
    last=APPEND+128+(4*4+3)*SNAPSHOT
    snap=q(record,last,32);counts=q(record,last+256,16)
    need(actual['descriptor_id']>=snap[11]>0 and actual['writer_epoch']>=snap[13]>0 and
         all(actual[name]>=counts[i]for i,name in enumerate(COUNT_FIELDS)),
         'terminal includes every actual completed descriptor snapshot and identity')
    need(actual['issues']==actual['directory_writes'] and actual['issues']>0 and actual['hits']>0 and
         actual['directory_queries']==actual['issues']+actual['hits'] and
         actual['topology_differential']==(actual['topology_hits']if mode=='differential'else 0) and
         actual['common_differential']==(actual['common_hits']if mode=='differential'else 0),
         'actual issuance/write/query conservation and every-hit original differential proofs')
    raw=APPEND+128+20*SNAPSHOT
    if 1<=control<=5:
        final=q(record,raw+256+256+160+2*256,32)
        for name,index in (('common_hits',0),('common_full',1),('common_differential',2),
                           ('history_fallbacks',3),('topology_hits',9),('topology_full',10),
                           ('topology_differential',11),('directory_writes',12),('raw_invalidations',16)):
            need(actual[name]>=final[index],'terminal includes actual restored RAW-control counter '+name)
    result=dict(base)
    result.update(descriptor=actual,program_status='failed'if control else'completed',
                  qualification_credit=False,performance_credit=False)
    return result


def controls(stderr,record,control,mode,*,dependencies):
    parse,common=dependencies
    baseline=read(stderr,record,control,mode,dependencies=dependencies)
    actual,ordinary,at=split(stderr,parse);lines=stderr[:-1].split(b'\n')
    old=common.controls_joined(ordinary,record,control,mode,last_epoch=4)
    need(len(old['refusals'])==len(set(old['refusals']))==10,'all ten original CACHE8 terminal controls')
    tests=(('version',0),('status',actual['status']^1),('initialized',0),
           ('poisoned',actual['poisoned']^1),('unclassified',1),('overflows',1),
           ('issues',actual['issues']+1),('directory_writes',actual['directory_writes']+1),
           ('directory_queries',actual['directory_queries']+1),
           ('common_differential',actual['common_differential']+1),
           ('topology_differential',actual['topology_differential']+1),('disagreements',1),('hits',0))
    refused=list(old['refusals'])
    def reject(name,changed):
        try:read(changed,record,control,mode,dependencies=dependencies)
        except ValueError:refused.append('descriptor_'+name)
        else:raise ValueError('accepted descriptor terminal corruption '+name)
    for name,value in tests:
        fields=dict(actual);fields[name]=value;changed=list(lines)
        changed[at]=PREFIX+json.dumps(fields,separators=(',',':')).encode()
        reject(name,b'\n'.join(changed)+b'\n')
    reject('missing',b'\n'.join(lines[:at]+lines[at+1:])+b'\n')
    reject('duplicate',b'\n'.join(lines[:at]+[lines[at]]+lines[at:])+b'\n')
    need(len(refused)==len(set(refused))==CONTROL_COUNT,'all25 original and additive typed terminal controls')
    return dict(refusals=refused,native_operations=0)


def _preentry_split(stderr,parse):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole actual preentry terminal')
    lines=stderr[:-1].split(b'\n');positions=[i for i,line in enumerate(lines)if line.startswith(PREENTRY_PREFIX)]
    need(len(positions)==1 and 0<positions[0]<len(lines)-1 and
         lines[positions[0]-1].startswith(b'LI2_LOOP_CACHE8_TRANSIT ') and
         lines[positions[0]+1].startswith(b'LI2_LOOP_CACHE8_RX '),
         'one preentry row at the actual observer callback between TRANSIT and RX')
    at=positions[0]
    return parse(lines[at],PREENTRY_PREFIX,PREENTRY_FIELDS),b'\n'.join(lines[:at]+lines[at+1:])+b'\n',at


def read_preentry(stderr,record,control,mode,*,dependencies):
    parse,_=dependencies
    actual,ordinary,_=_preentry_split(stderr,parse)
    result=read(ordinary,record,control,mode,dependencies=dependencies)
    expected=dict(version=1,status=125 if control else 0,failure_code=3303 if control else 0,
        control=control,epochs=5,accepted=5,ordinary_refusals=5,
        attempted=75 if control else 0,refused=75 if control else 0,restorations=75 if control else 0)
    for i in range(5):expected['serial'+str(i)]=q(record,544+i*227264+5*8)[0]
    for name in('refusal','restore'):
        for i in range(5):expected[name+str(i)]=(1<<15)-1 if control else 0
    need(actual==expected,
         'five genuine incoming successes and ordinary refusals with every separate guard restored')
    result['preentry']=actual
    return result


def controls_preentry(stderr,record,control,mode,*,dependencies):
    parse,_=dependencies
    read_preentry(stderr,record,control,mode,dependencies=dependencies)
    actual,ordinary,at=_preentry_split(stderr,parse)
    result=controls(ordinary,record,control,mode,dependencies=dependencies)
    lines=stderr[:-1].split(b'\n');refusals=[]
    def reject(label,changed):
        need(changed!=stderr,'distinct supplied whole preentry terminal mutation')
        try:read_preentry(changed,record,control,mode,dependencies=dependencies)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted preentry terminal mutation '+label)
    def replace(label,fields):
        changed=list(lines);changed[at]=PREENTRY_PREFIX+json.dumps(fields,separators=(',',':')).encode()
        reject(label,b'\n'.join(changed)+b'\n')
    need(len(PREENTRY_FIELDS)==25,'literal preentry scalar schema')
    for name in PREENTRY_FIELDS:
        fields=dict(actual);del fields[name];replace('missing.'+name,fields)
        fields=dict(actual);fields[name]=bool(fields[name]);replace('boolean.'+name,fields)
        fields=dict(actual);fields[name]^=1;replace('value.'+name,fields)
    fields=dict(actual);fields['extra']=0;replace('extra',fields)
    replace('key_order',dict(reversed(list(actual.items()))))
    changed=list(lines);changed[at]=lines[at][:-1]+b',"version":1}'
    reject('duplicate_key',b'\n'.join(changed)+b'\n')
    reject('missing_row',b'\n'.join(lines[:at]+lines[at+1:])+b'\n')
    reject('duplicate_row',b'\n'.join(lines[:at]+[lines[at]]+lines[at:])+b'\n')
    changed=list(lines);changed[at],changed[at+1]=changed[at+1],changed[at]
    reject('row_order',b'\n'.join(changed)+b'\n')
    reject('newline',stderr[:-1])
    changed=list(lines);changed[at]=lines[at].replace(b'{',b'{ ',1)
    reject('whitespace',b'\n'.join(changed)+b'\n')
    changed=list(lines);changed[at]+=b' '*4096
    reject('writer_bound',b'\n'.join(changed)+b'\n')
    need(len(refusals)==len(set(refusals))==PREENTRY_CONTROL_COUNT,
         'all75 scalar and9 encoding preentry controls through the full terminal reader')
    result['preentry_refusals']=refusals
    return result



COMMON_PREFIX=b'LI2_LOOP_COMMON_REVALIDATION '
COMMON_FIELDS=('version','status','failure_code','control','epochs','serial','cell','id',
    'cell_serial','quiet_pairs','token_misses','token_restorations','token_mask',
    'guard_unissued','guard_restorations','guard_mask','raw_unissued','raw_restorations',
    'raw_mask','failed_full','failed_unissued','failed_restored','history_fallback')
COMMON_CONTROL_COUNT=78


def _common_split(stderr,parse):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole actual common-revalidation terminal')
    lines=stderr[:-1].split(b'\n');positions=[i for i,line in enumerate(lines)if line.startswith(COMMON_PREFIX)]
    need(len(positions)==1 and 0<positions[0]<len(lines)-1 and
         lines[positions[0]-1].startswith(b'LI2_LOOP_CACHE8_TRANSIT ') and
         lines[positions[0]+1].startswith(PREENTRY_PREFIX),
         'one common-revalidation row between actual TRANSIT and preentry observations')
    at=positions[0]
    return parse(lines[at],COMMON_PREFIX,COMMON_FIELDS),b'\n'.join(lines[:at]+lines[at+1:])+b'\n',at


def read_common(stderr,record,control,mode,*,dependencies):
    parse,_=dependencies
    actual,ordinary,_=_common_split(stderr,parse)
    result=read_preentry(ordinary,record,control,mode,dependencies=dependencies)
    expected=dict.fromkeys(COMMON_FIELDS,0)
    expected.update(version=1,status=125 if control else 0,failure_code=3303 if control else 0,
                    control=control)
    if control:
        fourth=APPEND+128+(3*4+3)*SNAPSHOT
        snapshot=q(record,fourth,32);cell=actual['cell']
        need(type(cell)is int and 0<=cell<9 and cell!=snapshot[8],
             'common-revalidation uses a distinct actual older completion cell')
        saved=q(record,fourth+1024+32*cell,4)
        need(0<saved[0]<snapshot[19] and 0<saved[1]<snapshot[1] and 1<=saved[2]<=8,
             'common-revalidation identity joins the earlier whole fourth-completion snapshot')
        expected.update(epochs=1,serial=snapshot[1],cell=cell,id=saved[0],cell_serial=saved[1],
            quiet_pairs=42,token_misses=31,token_restorations=31,token_mask=(1<<31)-1,
            guard_unissued=6,guard_restorations=6,guard_mask=63,
            raw_unissued=3,raw_restorations=3,raw_mask=7,
            failed_full=1,failed_unissued=1,failed_restored=1,history_fallback=1)
    need(actual==expected,
         'exact actual common-only misses, full reproofs, quiet reuse and unchanged historical fallback')
    result['common']=actual
    return result


def controls_common(stderr,record,control,mode,*,dependencies):
    parse,_=dependencies
    read_common(stderr,record,control,mode,dependencies=dependencies)
    actual,ordinary,at=_common_split(stderr,parse)
    result=controls_preentry(ordinary,record,control,mode,dependencies=dependencies)
    lines=stderr[:-1].split(b'\n');refusals=[]
    def reject(label,changed):
        need(changed!=stderr,'distinct supplied whole common-revalidation terminal mutation')
        try:read_common(changed,record,control,mode,dependencies=dependencies)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted common-revalidation terminal mutation '+label)
    def replace(label,fields):
        changed=list(lines);changed[at]=COMMON_PREFIX+json.dumps(fields,separators=(',',':')).encode()
        reject(label,b'\n'.join(changed)+b'\n')
    need(len(COMMON_FIELDS)==23,'literal separate common-revalidation schema')
    for name in COMMON_FIELDS:
        fields=dict(actual);del fields[name];replace('missing.'+name,fields)
        fields=dict(actual);fields[name]=bool(fields[name]);replace('boolean.'+name,fields)
        fields=dict(actual);fields[name]^=1;replace('value.'+name,fields)
    fields=dict(actual);fields['extra']=0;replace('extra',fields)
    replace('key_order',dict(reversed(list(actual.items()))))
    changed=list(lines);changed[at]=lines[at][:-1]+b',"version":1}'
    reject('duplicate_key',b'\n'.join(changed)+b'\n')
    reject('missing_row',b'\n'.join(lines[:at]+lines[at+1:])+b'\n')
    reject('duplicate_row',b'\n'.join(lines[:at]+[lines[at]]+lines[at:])+b'\n')
    changed=list(lines);changed[at],changed[at+1]=changed[at+1],changed[at]
    reject('row_order',b'\n'.join(changed)+b'\n')
    reject('newline',stderr[:-1])
    changed=list(lines);changed[at]=lines[at].replace(b'{',b'{ ',1)
    reject('whitespace',b'\n'.join(changed)+b'\n')
    changed=list(lines);changed[at]+=b' '*4096
    reject('writer_bound',b'\n'.join(changed)+b'\n')
    need(len(refusals)==len(set(refusals))==COMMON_CONTROL_COUNT,
         'all69 scalar and9 encoding common-revalidation mutations through the full terminal reader')
    result['common_refusals']=refusals
    return result



CACHE_PREFIX=b'LI2_LOOP_COMMON_CACHE '
CACHE_FIELDS=('version','status','failure_code','lhc_hits','revalidated_hits')
CACHE_CONTROL_COUNT=24


def split_cache(stderr,parse):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole actual common-cache accounting terminal')
    lines=stderr[:-1].split(b'\n');positions=[i for i,line in enumerate(lines)if line.startswith(CACHE_PREFIX)]
    need(len(positions)==1 and 0<positions[0]<len(lines)-1 and
         lines[positions[0]-1].startswith(HISTORY) and lines[positions[0]+1].startswith(PREFIX),
         'one separate common-cache accounting row between actual history and descriptor rows')
    at=positions[0]
    return parse(lines[at],CACHE_PREFIX,CACHE_FIELDS),b'\n'.join(lines[:at]+lines[at+1:])+b'\n',at


def join_cache(cache,actual):
    need(cache['version']==1 and cache['status']==actual['status'] and
         cache['failure_code']==actual['failure_code'] and
         cache['lhc_hits']+cache['revalidated_hits']==actual['common_hits'],
         'actual old-LHC and renewed-token hits exactly partition every common-cache hit')


def cache_controls(stderr,parse,validate):
    validate(stderr)
    actual,_,at=split_cache(stderr,parse)
    lines=stderr[:-1].split(b'\n');refusals=[]
    def reject(label,changed):
        need(changed!=stderr,'distinct supplied whole common-cache accounting mutation')
        try:validate(changed)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted common-cache accounting mutation '+label)
    def replace(label,fields):
        changed=list(lines);changed[at]=CACHE_PREFIX+json.dumps(fields,separators=(',',':')).encode()
        reject(label,b'\n'.join(changed)+b'\n')
    need(len(CACHE_FIELDS)==5,'literal separate common-cache accounting schema')
    for name in CACHE_FIELDS:
        fields=dict(actual);del fields[name];replace('missing.'+name,fields)
        fields=dict(actual);fields[name]=bool(fields[name]);replace('boolean.'+name,fields)
        fields=dict(actual);fields[name]^=1;replace('value.'+name,fields)
    fields=dict(actual);fields['extra']=0;replace('extra',fields)
    replace('key_order',dict(reversed(list(actual.items()))))
    changed=list(lines);changed[at]=lines[at][:-1]+b',"version":1}'
    reject('duplicate_key',b'\n'.join(changed)+b'\n')
    reject('missing_row',b'\n'.join(lines[:at]+lines[at+1:])+b'\n')
    reject('duplicate_row',b'\n'.join(lines[:at]+[lines[at]]+lines[at:])+b'\n')
    changed=list(lines);changed[at],changed[at+1]=changed[at+1],changed[at]
    reject('row_order',b'\n'.join(changed)+b'\n')
    reject('newline',stderr[:-1])
    changed=list(lines);changed[at]=lines[at].replace(b'{',b'{ ',1)
    reject('whitespace',b'\n'.join(changed)+b'\n')
    changed=list(lines);changed[at]+=b' '*4096
    reject('writer_bound',b'\n'.join(changed)+b'\n')
    need(len(refusals)==len(set(refusals))==CACHE_CONTROL_COUNT,
         'all15 scalar and9 encoding accounting mutations through the complete caller validator')
    return refusals


def read_cached(stderr,record,control,mode,*,dependencies):
    parse,_=dependencies
    cache,ordinary,_=split_cache(stderr,parse)
    result=read_common(ordinary,record,control,mode,dependencies=dependencies)
    join_cache(cache,result['descriptor'])
    need(cache['revalidated_hits']>=(43 if control else 0),
         'actual cache-hit total includes42 controlled quiet hits and the final whole receipt hit')
    result['common_cache']=cache
    return result


def controls_cached(stderr,record,control,mode,*,dependencies):
    parse,_=dependencies
    _,ordinary,_=split_cache(stderr,parse)
    result=controls_common(ordinary,record,control,mode,dependencies=dependencies)
    validate=partial(read_cached,record=record,control=control,mode=mode,dependencies=dependencies)
    result['common_cache_refusals']=cache_controls(stderr,parse,validate)
    return result


ISOLATION_PREFIX=b'LI2_LOOP_HISTORY_ISOLATION '
ISOLATION_FIELDS=('version','status','failure_code','control','epochs','cell','id','serial',
    'peer','peer_id','peer_serial','preserved','common_hit','history_hit',
    'raw_cell','raw_cell_mask','raw_bundle','raw_bundle_mask','stale_setup','stale_setup_mask',
    'extra_misses','extra_restorations','extra_mask')
ISOLATION_CONTROL_COUNT=78


def _isolation_split(stderr,parse):
    need(type(stderr)is bytes and stderr.endswith(b'\n'),'whole actual per-cell isolation terminal')
    lines=stderr[:-1].split(b'\n');positions=[i for i,line in enumerate(lines)if line.startswith(ISOLATION_PREFIX)]
    need(len(positions)==1 and 0<positions[0]<len(lines)-1 and
         lines[positions[0]-1].startswith(b'LI2_LOOP_CACHE8_TRANSIT ') and
         lines[positions[0]+1].startswith(COMMON_PREFIX),
         'one isolation row between actual TRANSIT and unchanged common observations')
    at=positions[0]
    return parse(lines[at],ISOLATION_PREFIX,ISOLATION_FIELDS),b'\n'.join(lines[:at]+lines[at+1:])+b'\n',at


def read_isolated(stderr,record,control,mode,*,dependencies):
    parse,_=dependencies
    actual,ordinary,_=_isolation_split(stderr,parse)
    result=read_cached(ordinary,record,control,mode,dependencies=dependencies)
    first=q(record,544,32);second=q(record,544+227264,32)
    need(first[6]==second[6]==1 and 0<=first[10]<9 and 0<=second[10]<9 and
         first[10]!=second[10] and 0<first[18]<second[18] and 0<first[5]<second[5],
         'isolation binds two distinct genuine single-member completed activations')
    expected=dict(version=1,status=125 if control else 0,failure_code=3303 if control else 0,
        control=control,epochs=2,cell=first[10],id=first[18],serial=first[5],
        peer=second[10],peer_id=second[18],peer_serial=second[5],
        preserved=1,common_hit=1,history_hit=1,
        raw_cell=1 if control else 0,raw_cell_mask=255 if control else 0,
        raw_bundle=1 if control else 0,raw_bundle_mask=255 if control else 0,
        stale_setup=1 if control else 0,stale_setup_mask=15 if control else 0,
        extra_misses=2 if control else 0,extra_restorations=2 if control else 0,
        extra_mask=3 if control else 0)
    need(actual==expected,
         'exact issued-peer preservation, real cell/bundle exposures and separate new epoch controls')
    result['isolation']=actual
    return result


def controls_isolated(stderr,record,control,mode,*,dependencies):
    parse,_=dependencies
    read_isolated(stderr,record,control,mode,dependencies=dependencies)
    actual,ordinary,at=_isolation_split(stderr,parse)
    result=controls_cached(ordinary,record,control,mode,dependencies=dependencies)
    lines=stderr[:-1].split(b'\n');refusals=[]
    def reject(label,changed):
        need(changed!=stderr,'distinct supplied whole per-cell isolation mutation')
        try:read_isolated(changed,record,control,mode,dependencies=dependencies)
        except ValueError:refusals.append(label)
        else:raise ValueError('accepted per-cell isolation mutation '+label)
    def replace(label,fields):
        changed=list(lines);changed[at]=ISOLATION_PREFIX+json.dumps(fields,separators=(',',':')).encode()
        reject(label,b'\n'.join(changed)+b'\n')
    need(len(ISOLATION_FIELDS)==23,'literal separate per-cell isolation schema')
    for name in ISOLATION_FIELDS:
        fields=dict(actual);del fields[name];replace('missing.'+name,fields)
        fields=dict(actual);fields[name]=bool(fields[name]);replace('boolean.'+name,fields)
        fields=dict(actual);fields[name]^=1;replace('value.'+name,fields)
    fields=dict(actual);fields['extra']=0;replace('extra',fields)
    replace('key_order',dict(reversed(list(actual.items()))))
    changed=list(lines);changed[at]=lines[at][:-1]+b',"version":1}'
    reject('duplicate_key',b'\n'.join(changed)+b'\n')
    reject('missing_row',b'\n'.join(lines[:at]+lines[at+1:])+b'\n')
    reject('duplicate_row',b'\n'.join(lines[:at]+[lines[at]]+lines[at:])+b'\n')
    changed=list(lines);changed[at],changed[at+1]=changed[at+1],changed[at]
    reject('row_order',b'\n'.join(changed)+b'\n')
    reject('newline',stderr[:-1])
    changed=list(lines);changed[at]=lines[at].replace(b'{',b'{ ',1)
    reject('whitespace',b'\n'.join(changed)+b'\n')
    changed=list(lines);changed[at]+=b' '*4096
    reject('writer_bound',b'\n'.join(changed)+b'\n')
    need(len(refusals)==len(set(refusals))==ISOLATION_CONTROL_COUNT,
         'all69 scalar and9 encoding isolation mutations through the full terminal reader')
    result['isolation_refusals']=refusals
    return result


def configured(parse,common):
    dependencies=(parse,common)
    return SimpleNamespace(read=partial(read_isolated,dependencies=dependencies),
        controls=partial(controls_isolated,dependencies=dependencies),CONTROL_COUNT=CONTROL_COUNT,
        PREENTRY_CONTROL_COUNT=PREENTRY_CONTROL_COUNT,COMMON_CONTROL_COUNT=COMMON_CONTROL_COUNT,
        CACHE_CONTROL_COUNT=CACHE_CONTROL_COUNT,ISOLATION_CONTROL_COUNT=ISOLATION_CONTROL_COUNT)
