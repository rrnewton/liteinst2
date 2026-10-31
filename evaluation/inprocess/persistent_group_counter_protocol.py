#!/usr/bin/env python3
"""Explicit final-counter protocol checks; no guest execution or qualification.

Run separately under the existing finite 5 CPU/15 wall/512 MiB/16 MiB bounds.
The kernel portion uses only a private memfd and local mappings. It does not
construct native owner evidence. No counter or native-control population changes.
"""
import errno,fcntl,json,mmap,os,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'tools/page-entry'),str(ROOT/'evaluation/inprocess')]
from carrier import counter_descriptor
from persistent_group_counter_process import final_counter_prefix,MAGIC
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
    initial=(MAGIC,2,752,4096,17,123,1,2);pid=124
    data=bytearray(4096)
    struct.pack_into('<16Q',data,0,*initial,pid,pid,6,23,0x100000,1,1,1)
    # Genuine kill prefixes may split an ingress bucket, cancellation or publication.
    struct.pack_into('<6Q',data,128,9,2,3,1,0,0)
    struct.pack_into('<10Q',data,176,5,2,1,4,1,1,2,2,1,0)
    struct.pack_into('<18Q',data,256,0,3,*([0]*16))
    struct.pack_into('<5Q',data,552,101,5,4,89,7)
    accepted=final_counter_prefix(bytes(data),initial,pid,23)
    need(accepted['events']==9 and sum(accepted['signals'])==6 and
         accepted['group']['offers']==5 and accepted['group']['completed']==1 and
         sum(accepted['misses'])==3 and accepted['group']['cancelled']==1 and
         accepted['native']==dict(attempts=101,admissions=5,closed=4,blocked=89,low_address_refusals=7),
         'preserve exact split per-cell values without completed-transaction arithmetic')
    whole='whole final sealed counter backing'
    header='exact initialized/protected/closed/ready final counter header and zero tail'
    for name,changed in [('truncated',bytes(data[:-1])),('extended',bytes(data)+b'\0')]:
        value_error(name,lambda changed=changed:final_counter_prefix(changed,initial,pid,23),whole)
    for index in range(16):
        changed=bytearray(data);value=struct.unpack_from('<Q',changed,index*8)[0]
        struct.pack_into('<Q',changed,index*8,value^1)
        value_error('header_'+str(index),lambda changed=bytes(changed):final_counter_prefix(changed,initial,pid,23),header)
    changed=bytearray(data);changed[752]=1
    value_error('tail',lambda:final_counter_prefix(bytes(changed),initial,pid,23),header)
    value_error('wrong_seals',lambda:final_counter_prefix(bytes(data),initial,pid,6),whole)
    value_error('typed_pid',lambda:final_counter_prefix(bytes(data),initial,True,23),whole)
    changed=bytearray(data);changed[596]=1
    value_error('native_padding',lambda:final_counter_prefix(bytes(changed),initial,pid,23),header)
    rw=ro=None;writer=None
    try:
        rw=os.memfd_create('li2-counter-protocol',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        os.ftruncate(rw,4096);os.fchmod(rw,0o600);os.set_inheritable(rw,True)
        st=os.fstat(rw);nonce=19
        setup=struct.pack('<8Q',MAGIC,2,752,4096,nonce,os.getpid(),st.st_dev,st.st_ino)+bytes(4096-64)
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
        need(os.pread(ro,8,128)==struct.pack('<Q',37),'existing writer remains authoritative')
        writer.close();writer=None
        need(os.pread(ro,8,128)==struct.pack('<Q',37),'RO backing survives last writer unmap')
    finally:
        if writer is not None:writer.close()
        if ro is not None:os.close(ro)
        if rw is not None:os.close(rw)
    print(json.dumps(dict(scope='counter_protocol_only',guest_executions=0,parser_prefix=accepted,
                         refusal_count=len(refused),refusals=refused),sort_keys=True))


if __name__=='__main__':main()
