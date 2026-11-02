#!/usr/bin/env python3
"""Additive ABI6 field/version/descriptor checks; old four protocols run first."""
import fcntl,json,os,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'tools/page-entry'),str(ROOT/'evaluation/inprocess')]
from page_selected import need
from loop_ro_retired_counter import final_counter_prefix,MAGIC,NAMES,AGE
from loop_ro_reason_counter import final_counter_prefix as old_prefix
from loop_ro_retired_carrier import counter_descriptor
from loop_ro_reason_carrier import counter_descriptor as old_descriptor

def main():
    need(not sys.flags.optimize,'protocol checks require assertions');refused=[]
    def reject(name,call):
        try:call()
        except ValueError:refused.append(name)
        else:raise ValueError('accepted '+name)
    initial=(MAGIC,6,2016,4096,17,123,1,2);pid=124;data=bytearray(4096)
    struct.pack_into('<16Q',data,0,*initial,pid,pid,6,23,0x100000,1,1,1)
    accepted=final_counter_prefix(bytes(data),initial,pid,23)
    coordinates=[(name,) for name in NAMES]+[('retirement_rank',i) for i in range(16)]+[('offer_age',n) for n in AGE]
    need(len(coordinates)==38,'all38 literal retired cells')
    for index,path in zip([*range(14),*range(16,40)],coordinates,strict=True):
        changed=bytearray(data);struct.pack_into('<Q',changed,1696+8*index,1)
        expected=json.loads(json.dumps(accepted));target=expected['retired']
        for part in path[:-1]:target=target[part]
        target[path[-1]]=1
        if index==0:expected['retired_prefix_usable']=False
        need(final_counter_prefix(bytes(changed),initial,pid,23)==expected,'exact ABI6 cell offset '+str(index))
    reject('truncated',lambda:final_counter_prefix(bytes(data[:-1]),initial,pid,23))
    reject('extended',lambda:final_counter_prefix(bytes(data)+b'\0',initial,pid,23))
    for i in range(16):
        changed=bytearray(data);v=struct.unpack_from('<Q',changed,8*i)[0];struct.pack_into('<Q',changed,8*i,v^1)
        reject('header_'+str(i),lambda changed=bytes(changed):final_counter_prefix(changed,initial,pid,23))
    for name,offset,value in [('tail',2016,1),('error_range',1696,8),('reserved0',1808,1),('reserved1',1816,1),('native_padding',596,1)]:
        changed=bytearray(data);changed[offset]=value
        reject(name,lambda changed=bytes(changed):final_counter_prefix(changed,initial,pid,23))
    reject('typed_pid',lambda:final_counter_prefix(bytes(data),initial,True,23))
    reject('wrong_seals',lambda:final_counter_prefix(bytes(data),initial,pid,6))
    prior=(MAGIC,5,1696,4096,*initial[4:])
    reject('abi5_initial',lambda:final_counter_prefix(bytes(data),prior,pid,23))
    changed=bytearray(data);struct.pack_into('<8Q',changed,0,*prior)
    reject('abi5_coordinated',lambda:final_counter_prefix(bytes(changed),prior,pid,23))
    reject('abi5_reader',lambda:old_prefix(bytes(data),prior,pid,23))
    fd=os.memfd_create('li2-retired-protocol',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        os.ftruncate(fd,4096);os.fchmod(fd,0o600);os.set_inheritable(fd,True);st=os.fstat(fd)
        def write(version,size):
            value=struct.pack('<8Q',MAGIC,version,size,4096,19,os.getpid(),st.st_dev,st.st_ino)+bytes(4096-64)
            need(os.pwrite(fd,value,0)==4096,'whole actual protocol memfd')
        write(6,2016);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,6)
        need(counter_descriptor(fd,19,os.getpid())['version']==6,'actual distinct ABI6 descriptor')
        reject('abi5_descriptor',lambda:old_descriptor(fd,19,os.getpid()))
        write(5,1696);need(old_descriptor(fd,19,os.getpid())['version']==5,'old descriptor remains exact')
        reject('descriptor_abi5',lambda:counter_descriptor(fd,19,os.getpid()))
    finally:os.close(fd)
    need(len(refused)==len(set(refused))==30,'all30 additive descriptor/parser refusals')
    print(json.dumps(dict(scope='loop_ro_retired_protocol_only',version=6,cell_offset_checks=38,
                         refusal_count=30,guest_executions=0),sort_keys=True))

if __name__=='__main__':main()
