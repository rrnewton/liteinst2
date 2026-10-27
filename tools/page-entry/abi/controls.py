"""Supplied-record controls derived from genuine complete endpoint records."""
import struct
from compare import Refusal,record,pair,q,XSAVE,STACK,SIZE

def controls(pre,post,cap,bridge,interpreter,carrier,original):
    names=[]
    def refused(name, changed):
        try:pair(pre,record(bytes(changed),cap),cap,bridge,interpreter,carrier,original)
        except Refusal:names.append(name)
        else:raise AssertionError('mutation accepted: '+name)
    def flip(name,at):
        changed=bytearray(post['raw']);changed[at]^=1;refused(name,changed)
    for i in range(16):flip('gpr_'+str(i),32+8*i)
    flip('rflags',160)
    for i in range(8):flip('fs_gs_selectors_'+str(i),192+8*i)
    # Each actual stack page, both edges, and argc/argv are independent samples.
    # The comparator still compares every byte, not just these samples.
    locations={0,len(post['stack'])-1,post['regs'][7]-post['first'],post['regs'][7]-post['first']+8}
    locations.update(range(0,len(post['stack']),4096))
    slot=post['slots'][7]
    for at in sorted(locations-set(range(slot,slot+8))):flip('stack_'+str(at),STACK+at)
    flip('wrong_at_base',STACK+slot)
    flip('stack_first',256);flip('stack_end',264);flip('pc',168)
    flip('actual_phdr',XSAVE+65536)
    flip('xcr0',176);flip('xcomp',XSAVE+520)
    for bit,at in [(0,0),(1,160)]+[(c['bit'],c['offset']) for c in cap['components'] if (1<<c['bit'])&0x2e7]:
        changed=bytearray(post['raw']);struct.pack_into('<Q',changed,XSAVE+512,q(changed,XSAVE+512)|(1<<bit));changed[XSAVE+at]^=1
        refused('xstate_component_'+str(bit),changed)
    flip('mxcsr',XSAVE+24)
    for count in (0,SIZE-1,SIZE+1):
        try:record(post['raw'][:count]+(b'\0' if count>SIZE else b''),cap)
        except Refusal:names.append('record_length_'+str(count))
        else:raise AssertionError('record extent accepted')
    # The actual runner separately requires exactly two fixed records and their
    # 1/0 endpoint order; supply duplicate/swapped endpoints to the same pair.
    for name,a,b in [('duplicate_pre',pre,pre),('duplicate_post',post,post),('reversed',post,pre)]:
        try:pair(a,b,cap,bridge,interpreter,carrier,original)
        except Refusal:names.append(name)
        else:raise AssertionError('endpoint order accepted')
    for name,index in [('bridge_entry',0),('interpreter_entry',1)]:
        images=[bridge,interpreter,carrier,original]
        changed=bytearray(images[index]);struct.pack_into('<Q',changed,24,q(changed,24)+1);images[index]=bytes(changed)
        try:pair(pre,post,cap,*images)
        except Refusal as error:
            if str(error)!='ELF entry differs from actual entry symbol':raise
            names.append(name)
        else:raise AssertionError('mutated ELF entry accepted')
    return names
