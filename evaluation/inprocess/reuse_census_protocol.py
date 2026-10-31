#!/usr/bin/env python3
"""Pure synthetic census parser/descriptor controls; no guest or owner credit."""
import fcntl
import json
import os
import struct
import reuse_census as C

INITIAL=(C.MAGIC,1,C.BYTES,4096,17,123,4,5)
PID=456

def fixture():
    b=bytearray(C.BYTES)
    def q(offset,values):struct.pack_into('<'+'Q'*len(values),b,offset,*values)
    h=list(INITIAL)+( [PID,PID,6,23,0x1000000,1,1,1]+[0,8,4,5,1,10,0,10]+list(C.CAPS)+[2])
    q(0,h)
    addresses=(0x400000,0x401000,0x500000,0x501000,0x600000,0x601000,0x600000,0x601000)
    for i,address in enumerate(addresses):
        m=[0]*32;m[:3]=[address,1+i//6,1+i//6];m[9:11]=[address,address+4096]
        m[15]=3;m[22:24]=[1,1];q(C.OFFSETS[0]+i*C.SIZES[0],m)
        b[C.OFFSETS[0]+i*C.SIZES[0]+256:C.OFFSETS[0]+(i+1)*C.SIZES[0]]=b'\x90'*4096
    keys=[(0x400000,1,2,2,0,0,0,0),(0x500000,3,4,2,0,0,0,0),
          (0x600000,5,6,2,0,0,0,0),(0x600000,7,8,2,0,0,0,0)]
    for i,k in enumerate(keys):q(C.OFFSETS[1]+i*C.SIZES[1],k)
    q(C.OFFSETS[3],(1,0x800000,0x801000))
    # key, build serial, generation; each original graph has two exact heads.
    for i,(key,serial,generation)in enumerate(((1,1,1),(2,2,2),(3,5,3),(2,6,4),(4,8,5))):
        q(C.OFFSETS[2]+i*C.SIZES[2],(key,1,0,2,serial,generation,0x200000,0x210000))
        struct.pack_into('<2H',b,C.OFFSETS[2]+i*C.SIZES[2]+64,0,4)
    # pc,slot,kind,seen,pass,oldgraph,oldgen,last,key,plan,bound,victim,newgen,peer,peerslot
    rows=[(0x400000,0,0,8,8,0,0,0,1,4,1,0,1,0,2),
          (0x500000,1,0,24,8,0,0,0,2,4,2,0,2,0,2),
          (0x400000,0,1,1,1,1,1,1,1,1,1,0,1,0,2),
          (0x600000,1,0,56,8,2,2,2,3,3,0,0,0,0,2),
          (0x600000,1,0,56,8,2,2,2,3,4,3,2,3,0,2),
          (0x500000,0,0,56,8,1,1,3,2,4,4,1,4,0,2),
          (0x600004,1,2,52,36,3,3,5,3,2,3,0,3,0,2),
          (0x600000,1,1,1,1,3,3,7,4,4,5,3,5,0,2),
          (0x600000,1,1,1,1,5,5,8,4,1,5,0,5,4,0),
          (0x500000,0,1,1,1,4,4,9,2,1,4,0,4,0,2)]
    # Internal-entry source key differs only in the actual root. Reserve it in
    # a fifth key row so the source commit can never pretend a root hit.
    q(18*8,(5,));q(C.OFFSETS[1]+4*C.SIZES[1],(0x600004,5,6,2,0,0,0,0))
    for i,(pc,slot,kind,seen,passed,old,oldgen,last,key,plan,bound,victim,generation,peer,peerslot)in enumerate(rows):
        v=[0]*32;v[:9]=[i+1,pc,slot,0,kind|(seen<<8)|(passed<<16),old,oldgen,last,i+1]
        v[9:17]=[5 if i==6 else key,1,i+1,1,1,1,1,0];v[17]=plan
        if plan==3:v[18:21]=[1|(1<<32),pc,0]
        v[21:23]=[1023,1023]if plan in(1,2)else[31,15]if i==7 else[1,0]if not old else[31,15]
        if plan!=3:v[23:27]=[bound,victim,oldgen if victim else 0,generation]
        v[27:32]=[1 if plan==3 else 2,i+1,peer,0 if plan==3 else(2 if peer else 1)|(peerslot<<8),23 if plan==3 else 31]
        q(C.OFFSETS[4]+i*C.SIZES[4],v)
    return b

def parse(b):return C.read(bytes(b),INITIAL,PID,23)
def setq(b,offset,value):struct.pack_into('<Q',b,offset,value)
def attempt(n,word):return C.OFFSETS[4]+(n-1)*C.SIZES[4]+word*8

def main():
    b=fixture();r=parse(b)
    assert r['complete_census']and r['events']==dict(selected=10,cold_valid=5,publications=5,root_hits=3,
        completed=9,cold_refusals=1,repeat_exact_refusals=0,cancelled=1,retirements=3,
        repeat_exact_publications=1,recompiled_after_recorded_eviction=1,internal_hits=1,
        cold_on_selected_root=1,peer_touches=1)
    assert r['distinct_successful_key_distance']=={'0-1':3,'2-7':2}
    unknown=dict(status='unknown',first_unknown=dict(attempt=4,
        reason='unobserved alternative source/placement/root or completion state; all later LRU unknown'),
        admission_prediction=False,future_state_known=False)
    assert r['eight']==unknown
    # Selection precedes the plan outcome. After A/B publications and A's
    # hit, actual LRU selects B(slot1,last2) for C at4; eight slots select
    # empty slot2. A refusal at4 cannot prove that alternative placement's
    # outcome, nor may it retire or touch B. Unknown starts at4, not bind5.
    known=dict(status='prefix_identical_only',first_unknown=None,
        admission_prediction=False,future_state_known=True)
    prefix_cases=(
        ((2,1,1,1,1),dict(selected=1,cold_valid=1,publications=1,completed=1)),
        ((4,2,2,1,2),dict(selected=2,cold_valid=2,publications=2,completed=2)),
        ((4,2,2,1,3),dict(selected=3,cold_valid=2,publications=2,completed=3,root_hits=1)),
        ((6,3,2,1,4),dict(selected=4,cold_valid=2,publications=2,completed=3,root_hits=1,
            cold_refusals=1,repeat_exact_refusals=0,cancelled=1)),
        ((6,3,3,1,5),dict(selected=5,cold_valid=3,publications=3,completed=4,root_hits=1,
            cold_refusals=1,repeat_exact_refusals=0,cancelled=1,retirements=1)))
    for sizes,events in prefix_cases:
        x=bytearray(b);struct.pack_into('<5Q',x,17*8,*sizes);setq(x,23*8,sizes[4])
        # Remove every not-yet-published dictionary/attempt byte as well as
        # its header count; each prefix is a complete standalone input.
        for offset,size,capacity,count in zip(C.OFFSETS,C.SIZES,C.CAPS,sizes,strict=True):
            x[offset+size*count:offset+size*capacity]=bytes(size*(capacity-count))
        value=parse(x)
        assert value['complete_census']and value['finished']==sizes[4]
        assert value['actual_two_replay']=='exact_committed_prefix'and value['events']==events
        assert value['eight']==(known if sizes[4]<=3 else unknown)
    # The last prefix retains B's whole observed slot identity at5. These
    # coherent hypothetical effects of the prior refusal must both fail at
    # the actual two-slot history join, without weakening other row checks.
    for changed in('refusal_retired_B','refusal_touched_B'):
        y=bytearray(x)
        if changed=='refusal_retired_B':
            for word in(5,6,7,24,25):setq(y,attempt(5,word),0)
            setq(y,attempt(5,21),1);setq(y,attempt(5,22),0)
        else:setq(y,attempt(5,7),4)
        try:parse(y)
        except ValueError as e:
            assert str(e)=='replayed selected graph and actual last completion',(changed,str(e))
        else:raise AssertionError(changed)
    negatives=[]
    def reject(name,change,error):
        x=bytearray(b);change(x)
        try:parse(x)
        except ValueError as e:assert str(e)==error,(name,str(e));negatives.append(name)
        else:raise AssertionError(name)
    reject('source_key_entry',lambda x:setq(x,attempt(3,9),2),'source commit binds this actual entry')
    reject('root_priority',lambda x:setq(x,attempt(8,2),0),'replayed original PC-first two-slot selection')
    reject('eviction_victim',lambda x:setq(x,attempt(6,24),2),'actual cold publication and selected victim')
    reject('old_generation',lambda x:setq(x,attempt(6,6),99),'actual cold publication and selected victim')
    reject('refusal_cannot_retire',lambda x:setq(x,attempt(4,31),31),'actual completed bind identity')
    reject('unevaluated_selector',lambda x:setq(x,attempt(2,4),24<<8|24<<16|32<<8),'actual certified-head lookup observation')
    reject('selected_last_complete',lambda x:setq(x,attempt(6,7),2),'replayed selected graph and actual last completion')
    reject('missing_peer_touch',lambda x:setq(x,attempt(10,7),6),'replayed selected graph and actual last completion')
    reject('wrong_peer_graph',lambda x:setq(x,attempt(9,29),2),'actual peer completion touches its retained graph')
    reject('observed_predicate_gap',lambda x:setq(x,attempt(8,21),29),'only actually reached short-circuit predicates')
    reject('warm_predicate_refusal',lambda x:setq(x,attempt(3,22),511),'only actually reached short-circuit predicates')
    reject('warm_registry',lambda x:setq(x,attempt(3,10),0),'source commit binds this actual entry')
    reject('future_phase',lambda x:setq(x,attempt(10,31),63),'single unfinished final census transaction')
    reject('earlier_partial_phase',lambda x:setq(x,attempt(3,31),7),'single unfinished final census transaction')
    reject('finish_two_lag',lambda x:setq(x,23*8,8),'finish count may lag only its last committed row')
    reject('reserved_tail',lambda x:x.__setitem__(len(x)-1,1),'whole census reserved tail zero')
    reject('unused_dictionary',lambda x:x.__setitem__(C.OFFSETS[1]+6*C.SIZES[1],1),'zero unused census section beyond at most one interrupted append')
    def two_partial(x):
        setq(x,22*8,1);x[C.OFFSETS[0]+8*C.SIZES[0]]=1;x[C.OFFSETS[1]+5*C.SIZES[1]]=1
    reject('two_uncommitted_dictionaries',two_partial,'single writer can leave only one unpublished dictionary entry')
    reject('duplicate_key',lambda x:x.__setitem__(slice(C.OFFSETS[1]+C.SIZES[1],C.OFFSETS[1]+2*C.SIZES[1]),x[C.OFFSETS[1]:C.OFFSETS[1]+C.SIZES[1]]),'unique exact interned request keys')
    reject('high_head_offset',lambda x:struct.pack_into('<H',x,C.OFFSETS[2]+64,8192),'bounded publication source-page/head offset')
    reject('duplicate_head',lambda x:struct.pack_into('<H',x,C.OFFSETS[2]+66,0),'exact root and distinct certified head catalog')
    positives=[]
    for mask in(0,1,3,7,15):
        x=bytearray(b);setq(x,attempt(10,31),mask);setq(x,23*8,9);setq(x,22*8,1)
        # All later words retain arbitrary partially-written values. The
        # parser must not interpret their phase until its commit publishes.
        if not mask&4:setq(x,attempt(10,21),0xdead);setq(x,attempt(10,22),0xbeef)
        if not mask&8:setq(x,attempt(10,23),0xdead);setq(x,attempt(10,24),0xbeef)
        value=parse(x);assert not value['complete_census'];positives.append('split_'+str(mask))
    x=bytearray(b);setq(x,23*8,9);setq(x,22*8,1);assert not parse(x)['complete_census'];positives.append('finish_commit_before_count')
    x=bytearray(b);setq(x,22*8,1);x[C.OFFSETS[1]+5*C.SIZES[1]]=1
    assert not parse(x)['complete_census'];positives.append('uncommitted_dictionary')
    x=bytearray(b);setq(x,16*8,8);assert not parse(x)['complete_census'];positives.append('overflow_explicit')
    fd=os.memfd_create('li2-census-protocol',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    ro=None
    try:
        os.ftruncate(fd,C.BYTES);os.fchmod(fd,0o600);os.set_inheritable(fd,True)
        st=os.fstat(fd);initial=(C.MAGIC,1,C.BYTES,4096,19,os.getpid(),st.st_dev,st.st_ino)
        assert os.pwrite(fd,struct.pack('<8Q',*initial),0)==64
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,6)
        assert C.descriptor(fd,19,os.getpid())['bytes']==C.BYTES
        ro=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_CLOEXEC)
        for name,descriptor,nonce in(('read_only',ro,19),('wrong_nonce',fd,20)):
            try:C.descriptor(descriptor,nonce,os.getpid())
            except ValueError:negatives.append(name)
            else:raise AssertionError(name)
        os.set_inheritable(fd,False)
        try:C.descriptor(fd,19,os.getpid())
        except ValueError:negatives.append('cloexec')
        else:raise AssertionError('cloexec')
    finally:
        if ro is not None:os.close(ro)
        os.close(fd)
    assert len(negatives)==24 and len(set(negatives))==24 and len(positives)==8
    print(json.dumps(dict(scope='synthetic census parser/descriptor only',guest_executions=0,
        refusals=negatives,positive_splits=positives,complete_fixture_attempts=10),sort_keys=True))

if __name__=='__main__':main()
