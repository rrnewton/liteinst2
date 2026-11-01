#!/usr/bin/env python3
"""Additive PB wire/branch/split/descriptor controls; no owner or guest credit."""
import fcntl,json,os,struct
import bounded_block_census as C
from reuse_census_protocol import fixture as old_fixture, setq, attempt

INITIAL=(C.MAGIC,C.VERSION,C.BYTES,4096,17,123,4,5)
PID=456
REFUSALS=('old_version','unknown_header','scan_return_before_call','two_inflight_scans',
 'kind','member','slot','bank','head','exit','arm','graph','flags_TF','flags_RF','source_pc','target',
 'source_opcode','cancel_frontier','unused_frontier','reserved_tail','next_offer_pc',
 'descriptor_version','descriptor_nonce','descriptor_read_only','descriptor_cloexec','descriptor_tail')
POSITIVES=('complete','other_before_effect','cross_page_direct_encoding','split_0','split_1','split_3','split_7','split_15',
 'scan_inflight','recorder_error','full_attempt_capacity')
EXPECTED=dict(scope='PB census synthetic extension only',guest_executions=0,
 refusals=list(REFUSALS),positive_splits=list(POSITIVES),complete_fixture_attempts=10,
 old_protocol_required_separately=dict(refusals=24,positive_splits=8))

def row_offset(n,word=0):return C.FRONTIERS+(n-1)*40+word*8
def fixture():
    b=old_fixture();struct.pack_into('<8Q',b,0,*INITIAL)
    for page in range(8):
        start=C.OFFSETS[0]+page*C.SIZES[0]+256+4
        b[start:start+2]=b'\x75\x06' # exact JNZ; target +12 or fallthrough +6
    for i in range(10):
        v=struct.unpack_from('<32Q',b,attempt(i+1,0))
        if v[27]!=2:continue
        member=1 if i==8 else 0;slot=v[30]>>8 if member else v[2]
        graph=v[29] if member else v[23]
        g=struct.unpack_from('<8Q',b,C.OFFSETS[2]+(graph-1)*C.SIZES[2])
        key=struct.unpack_from('<8Q',b,C.OFFSETS[1]+(g[0]-1)*C.SIZES[1])
        pc=key[0]+4;arm=i%2;flags=0x10002|(0x40 if arm else 0)
        packed=1|(member<<8)|(slot<<16)|(1<<32)|(arm<<48)|(arm<<56)
        struct.pack_into('<5Q',b,row_offset(i+1),packed,graph,flags,pc,pc+(2 if arm else 8))
    # Counts are explicit synthetic call/return observations, not costs.
    struct.pack_into('<3Q',b,(40+7*3)*8,9,9,0)
    return b

def parse(b):return C.read(bytes(b),INITIAL,PID,23)
def main():
    b=fixture();r=parse(b)
    assert r['complete_census'] and r['diagnostic_status']=='COMPLETE' and r['finished']==10
    assert r['selected_frontiers']['counts']==dict(direct_branch_before=9,next_offer_observed=8,next_offer_matches_selected_target=0)
    assert r['full_byte_scans']['BOUND']==dict(calls=9,success=9,error=0)
    rejected=[]
    def reject(name,change):
        x=bytearray(b);change(x);assert x!=b,name
        try:parse(x)
        except ValueError:rejected.append(name)
        else:raise AssertionError('accepted corruption '+name)
    reject('old_version',lambda x:setq(x,8,1))
    reject('unknown_header',lambda x:setq(x,30*8,1))
    reject('scan_return_before_call',lambda x:setq(x,(40+7*3+1)*8,10))
    reject('two_inflight_scans',lambda x:setq(x,(40+7*3)*8,11))
    def packed(name,bit,width,value):
        original=struct.unpack_from('<Q',b,row_offset(1))[0]
        reject(name,lambda x:setq(x,row_offset(1),(original&~(((1<<width)-1)<<bit))|(value<<bit)))
    packed('kind',0,8,3);packed('member',8,8,1);packed('slot',16,8,1);packed('bank',24,8,1)
    packed('head',32,16,0);packed('exit',48,8,1);packed('arm',56,8,1)
    reject('graph',lambda x:setq(x,row_offset(1,1),2))
    reject('flags_TF',lambda x:setq(x,row_offset(1,2),0x10102))
    reject('flags_RF',lambda x:setq(x,row_offset(1,2),2))
    reject('source_pc',lambda x:setq(x,row_offset(1,3),0x400005))
    reject('target',lambda x:setq(x,row_offset(1,4),0x40000d))
    reject('source_opcode',lambda x:x.__setitem__(C.OFFSETS[0]+256+4,0x90))
    reject('cancel_frontier',lambda x:setq(x,row_offset(4),1))
    reject('unused_frontier',lambda x:setq(x,row_offset(11),1))
    reject('reserved_tail',lambda x:x.__setitem__(len(x)-1,1))
    reject('next_offer_pc',lambda x:setq(x,attempt(2,1),0x500001))
    positives=['complete']
    x=bytearray(b);setq(x,row_offset(10),2|(65535<<32));setq(x,row_offset(10,3),0x500005);setq(x,row_offset(10,4),0)
    assert parse(x)['complete_census'];positives.append('other_before_effect')
    x=bytearray(b);struct.pack_into('<H',x,C.OFFSETS[2]+66,4094)
    start=C.OFFSETS[0]+256
    x[start+4094:start+4096]=b'\x0f\x85'
    x[start+C.SIZES[0]:start+C.SIZES[0]+4]=b'\x06\x00\x00\x00'
    for number in(1,3):
        setq(x,row_offset(number,3),0x400ffe);setq(x,row_offset(number,4),0x40100a)
    assert parse(x)['complete_census'];positives.append('cross_page_direct_encoding')
    for mask in(0,1,3,7,15):
        x=bytearray(b);setq(x,attempt(10,31),mask);setq(x,23*8,9);setq(x,22*8,1)
        value=parse(x);assert value['diagnostic_status']=='PARTIAL' and not value['complete_census']
        positives.append('split_'+str(mask))
    x=bytearray(b);setq(x,(40+7*3)*8,10)
    assert parse(x)['diagnostic_status']=='PARTIAL' and parse(x)['pending_full_scan']==1
    positives.append('scan_inflight')
    x=bytearray(b);setq(x,16*8,25)
    assert parse(x)['partial_reason']=='recorder_error';positives.append('recorder_error')
    # A genuine-capacity-shaped stream: preserve all ten initial transactions,
    # then exact root hits with actual completion serials, never enlarge caps.
    x=bytearray(b);last=list(struct.unpack_from('<32Q',b,attempt(10,0)))
    for number in range(11,C.CAPS[4]+1):
        v=last.copy();v[0]=v[8]=v[11]=v[28]=number;v[7]=number-1
        struct.pack_into('<32Q',x,attempt(number,0),*v)
        x[row_offset(number):row_offset(number)+40]=b[row_offset(10):row_offset(10)+40]
    setq(x,21*8,C.CAPS[4]);setq(x,23*8,C.CAPS[4]);setq(x,16*8,8)
    value=parse(x)
    assert value['diagnostic_status']=='PARTIAL' and not value['complete_census'] and value['partial_reason']=='capacity'
    positives.append('full_attempt_capacity')
    fd=os.memfd_create('li2-pb-census-protocol',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);ro=None
    try:
        os.ftruncate(fd,C.BYTES);os.fchmod(fd,0o600);os.set_inheritable(fd,True)
        st=os.fstat(fd);initial=(C.MAGIC,C.VERSION,C.BYTES,4096,19,os.getpid(),st.st_dev,st.st_ino)
        assert os.pwrite(fd,struct.pack('<8Q',*initial),0)==64
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,6)
        assert C.descriptor(fd,19,os.getpid())['bytes']==C.BYTES
        ro=os.open('/proc/self/fd/'+str(fd),os.O_RDONLY|os.O_CLOEXEC)
        def refuse_descriptor(name,actual_fd=fd,nonce=19):
            try:C.descriptor(actual_fd,nonce,os.getpid())
            except ValueError:rejected.append(name)
            else:raise AssertionError(name)
        assert os.pwrite(fd,struct.pack('<Q',1),8)==8
        refuse_descriptor('descriptor_version');assert os.pwrite(fd,struct.pack('<Q',2),8)==8
        refuse_descriptor('descriptor_nonce',nonce=20);refuse_descriptor('descriptor_read_only',actual_fd=ro)
        os.set_inheritable(fd,False);refuse_descriptor('descriptor_cloexec');os.set_inheritable(fd,True)
        assert os.pwrite(fd,b'\x01',C.BYTES-1)==1;refuse_descriptor('descriptor_tail')
    finally:
        if ro is not None:os.close(ro)
        os.close(fd)
    assert tuple(rejected)==REFUSALS and tuple(positives)==POSITIVES
    print(json.dumps(EXPECTED,sort_keys=True))
if __name__=='__main__':main()
