#!/usr/bin/env python3
"""Explicit ABI3 loop-counter protocol checks; no guest execution or qualification.

Run separately under the existing finite 5 CPU/15 wall/512 MiB/16 MiB bounds.
The kernel portion uses only a private memfd and local mappings. It does not
construct native owner evidence. Original ABI2/native controls remain unchanged;
this is a separate additive ABI3 protocol population.
"""
import errno,fcntl,json,mmap,os,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'tools/page-entry'),str(ROOT/'evaluation/inprocess')]
from persistent_loop_counter_carrier import counter_descriptor
from carrier import counter_descriptor as old_descriptor
from persistent_loop_counter import final_counter_prefix,MAGIC,LOOP_NAMES
from persistent_group_counter_process import final_counter_prefix as old_prefix
from page_selected import need


def main():
    need(not sys.flags.optimize, 'protocol checks require assertions')
    refused=[]
    def value_error(name,call,message):
        try:call()
        except ValueError as error:need(str(error)==message,'exact refusal '+name)
        else:raise ValueError('accepted invalid '+name)
        refused.append(name)
    def denied(name,call,number):
        try:call()
        except OSError as error:need(error.errno==number,'actual kernel refusal '+name)
        else:raise ValueError('kernel accepted '+name)
        refused.append(name)
    initial=(MAGIC,3,824,4096,17,123,1,2);pid=124
    data=bytearray(4096)
    struct.pack_into('<16Q',data,0,*initial,pid,pid,6,23,0x100000,1,1,1)
    # Genuine kill prefixes may split an ingress bucket, cancellation or publication.
    struct.pack_into('<6Q',data,128,9,2,3,1,0,0)
    struct.pack_into('<10Q',data,176,5,2,1,4,1,1,2,2,1,0)
    struct.pack_into('<18Q',data,256,0,3,*([0]*16))
    struct.pack_into('<5Q',data,552,101,5,4,89,7)
    struct.pack_into('<9Q',data,752,71,5,67,3,2,11,7,89,4)
    accepted=final_counter_prefix(bytes(data),initial,pid,23)
    need(accepted['events']==9 and sum(accepted['signals'])==6 and
         accepted['group']['offers']==5 and accepted['group']['completed']==1 and
         sum(accepted['misses'])==3 and accepted['group']['cancelled']==1 and
         accepted['native']==dict(attempts=101,admissions=5,closed=4,blocked=89,low_address_refusals=7),
         'preserve exact split per-cell values without completed-transaction arithmetic')
    need(accepted['version']==3 and accepted['logical_bytes']==824 and
         accepted['loop']==dict(zip(LOOP_NAMES,(71,5,67,3,2,11,7,89,4),strict=True)),
         'nine actual independent fields; deliberately no completed-transaction equations')
    # A changed cell must be returned at its literal offset and leave all others exact.
    for i,name in enumerate(LOOP_NAMES):
        changed=bytearray(data);old=struct.unpack_from('<Q',changed,752+8*i)[0]
        struct.pack_into('<Q',changed,752+8*i,old^1)
        expected=dict(accepted);expected['loop']=dict(accepted['loop']);expected['loop'][name]=old^1
        need(bytes(changed)!=bytes(data) and final_counter_prefix(bytes(changed),initial,pid,23)==expected,
             'literal distinct ABI3 cell offset '+name)
    whole='whole final sealed counter backing'
    header='exact initialized/protected/closed/ready final counter header and zero tail'
    for name,changed in [('truncated',bytes(data[:-1])),('extended',bytes(data)+b'\0')]:
        value_error(name,lambda changed=changed:final_counter_prefix(changed,initial,pid,23),whole)
    for index in range(16):
        changed=bytearray(data);value=struct.unpack_from('<Q',changed,index*8)[0]
        struct.pack_into('<Q',changed,index*8,value^1)
        value_error('header_'+str(index),lambda changed=bytes(changed):final_counter_prefix(changed,initial,pid,23),header)
    changed=bytearray(data);changed[824]=1
    value_error('tail',lambda:final_counter_prefix(bytes(changed),initial,pid,23),header)
    value_error('wrong_seals',lambda:final_counter_prefix(bytes(data),initial,pid,6),whole)
    value_error('typed_pid',lambda:final_counter_prefix(bytes(data),initial,True,23),whole)
    changed=bytearray(data);changed[596]=1
    value_error('native_padding',lambda:final_counter_prefix(bytes(changed),initial,pid,23),header)
    initial_error='exact ABI3 initial identity'
    old_initial=(MAGIC,2,752,4096,*initial[4:])
    value_error('initial_abi2',lambda:final_counter_prefix(bytes(data),old_initial,pid,23),initial_error)
    changed=bytearray(data);struct.pack_into('<8Q',changed,0,*old_initial)
    value_error('coordinated_abi2',lambda:final_counter_prefix(bytes(changed),old_initial,pid,23),initial_error)
    value_error('initial_list',lambda:final_counter_prefix(bytes(data),list(initial),pid,23),initial_error)
    typed=initial[:4]+(True,)+initial[5:]
    value_error('initial_bool',lambda:final_counter_prefix(bytes(data),typed,pid,23),initial_error)
    value_error('abi2_reader',lambda:old_prefix(bytes(data),old_initial,pid,23),header)
    rw=ro=None;writer=None
    try:
        rw=os.memfd_create('li2-counter-protocol',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        os.ftruncate(rw,4096);os.fchmod(rw,0o600);os.set_inheritable(rw,True)
        st=os.fstat(rw);nonce=19
        setup=struct.pack('<8Q',MAGIC,3,824,4096,nonce,os.getpid(),st.st_dev,st.st_ino)+bytes(4096-64)
        need(os.pwrite(rw,setup,0)==4096,'whole protocol input')
        fcntl.fcntl(rw,fcntl.F_ADD_SEALS,6)
        counter_descriptor(rw,nonce,os.getpid())
        message='exact initial diagnostic memfd identity/seals/header'
        value_error('nonce',lambda:counter_descriptor(rw,nonce+1,os.getpid()),message)
        value_error('parent',lambda:counter_descriptor(rw,nonce,os.getpid()+1),message)
        os.set_inheritable(rw,False)
        value_error('cloexec',lambda:counter_descriptor(rw,nonce,os.getpid()),message)
        os.set_inheritable(rw,True)
        ro=os.open('/proc/self/fd/'+str(rw),os.O_RDONLY|os.O_CLOEXEC)
        need(fcntl.fcntl(ro,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY and
             (os.fstat(ro).st_dev,os.fstat(ro).st_ino)==(st.st_dev,st.st_ino),'real same-file RO reopen')
        os.set_inheritable(ro,True)
        value_error('read_only',lambda:counter_descriptor(ro,nonce,os.getpid()),message)
        os.set_inheritable(ro,False)
        prior=struct.pack('<8Q',MAGIC,2,752,4096,nonce,os.getpid(),st.st_dev,st.st_ino)+bytes(4096-64)
        need(os.pwrite(rw,prior,0)==4096,'whole ABI2 descriptor stimulus')
        value_error('descriptor_abi2',lambda:counter_descriptor(rw,nonce,os.getpid()),message)
        need(os.pwrite(rw,setup,0)==4096,'restore exact ABI3 descriptor input')
        value_error('old_descriptor',lambda:old_descriptor(rw,nonce,os.getpid()),message)
        writer=mmap.mmap(rw,4096,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
        denied('write_seal_with_writer',lambda:fcntl.fcntl(rw,fcntl.F_ADD_SEALS,8),errno.EBUSY)
        fcntl.fcntl(rw,fcntl.F_ADD_SEALS,0x17)
        need(fcntl.fcntl(ro,fcntl.F_GET_SEALS)==23,'exact future-write/size/final seals')
        value_error('already_sealed',lambda:counter_descriptor(rw,nonce,os.getpid()),message)
        denied('pwrite_sealed',lambda:os.pwrite(rw,b'x',128),errno.EPERM)
        denied('new_shared_writer',lambda:mmap.mmap(rw,4096,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE),errno.EPERM)
        denied('read_only_writer',lambda:mmap.mmap(ro,4096,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE),errno.EACCES)
        denied('grow',lambda:os.ftruncate(rw,8192),errno.EPERM)
        denied('shrink',lambda:os.ftruncate(rw,0),errno.EPERM)
        denied('add_after_seal',lambda:fcntl.fcntl(rw,fcntl.F_ADD_SEALS,8),errno.EPERM)
        os.close(rw);rw=None
        # Only the already-existing writer can still change the backing.
        writer[128:136]=struct.pack('<Q',37)
        writer[816:824]=struct.pack('<Q',53)
        need(os.pread(ro,8,128)==struct.pack('<Q',37) and os.pread(ro,8,816)==struct.pack('<Q',53),'existing writer retains old and appended cells')
        writer.close();writer=None
        need(os.pread(ro,8,128)==struct.pack('<Q',37) and os.pread(ro,8,816)==struct.pack('<Q',53),'RO backing survives last writer unmap')
    finally:
        if writer is not None:writer.close()
        if ro is not None:os.close(ro)
        if rw is not None:os.close(rw)
    print(json.dumps(dict(scope='loop_counter_protocol_only',version=3,guest_executions=0,parser_prefix=accepted,cell_offset_checks=9,
                         refusal_count=len(refused),refusals=refused),sort_keys=True))


if __name__=='__main__':main()
