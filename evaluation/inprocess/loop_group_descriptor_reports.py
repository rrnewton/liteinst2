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


def configured(parse,common):
    dependencies=(parse,common)
    return SimpleNamespace(read=partial(read_preentry,dependencies=dependencies),
        controls=partial(controls_preentry,dependencies=dependencies),CONTROL_COUNT=CONTROL_COUNT,
        PREENTRY_CONTROL_COUNT=PREENTRY_CONTROL_COUNT)
