#!/usr/bin/env python3
"""Literal, fresh-exec rseq applications. No libc, constructors or host imports."""
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
import page_selected_images as elf
from page_selected_generic_images import Program

PAGE=4096
MAIN=0x401000
DATA=0x405000
AREA_PAGE=0x600000
AREA=AREA_PAGE+64
WORD=AREA+8
SIGNATURE=0x53053053
MAGIC=0x3150504151455352
OUTPUT=DATA+256
PATH=DATA+2048
NAMES=['registration', 'disjoint', 'nonzero_preissue', 'mov_overlap', 'zero_store_overlap',
       'trace_mov_overlap', 'sse_overlap', 'call_overlap', 'push_overlap', 'rep_overlap',
       'read_overlap', 'getrandom_overlap', 'munmap_overlap', 'mprotect_overlap',
       'pop_memory_unsupported', 'readv_unsupported', 'ioctl_unsupported']

class App(Program):
    def __init__(self):
        super().__init__(MAIN)
        self.results=[]
    def mov(self,name,reg,value):
        self.add(name,elf.mov64(reg,value&((1<<64)-1)),'old')
    def op(self,name,data):self.add(name,bytes.fromhex(data),'generic')
    def syscall(self,name,n,args,expected=None):
        for i,(reg,value) in enumerate(zip((7,6,2,10,8,9),args)):
            if value is not None:self.mov(name+'_a'+str(i),reg,value)
        self.mov(name+'_n',0,n)
        self.add(name,elf.SYSCALL,'syscall')
        if expected is not None:
            self.store(name+'_result',0,OUTPUT+8*len(self.results))
            self.results.append(dict(name=name,expected=expected))
            self.op(name+'_compare','483d'+struct.pack('<i',expected).hex())
            self.branch(name+'_check','0f85','failure')
    def rseq(self,name,flags=0,address=AREA,length=32,sig=SIGNATURE,expected=0):
        self.syscall(name,334,[address,length,flags,sig,0,0],expected)
    def observe_word(self,name):
        self.mov(name+'_address',7,WORD)
        self.op(name+'_load','488b07')
        self.store(name+'_save',0,OUTPUT+8*len(self.results))
        self.results.append(dict(name=name,expected=0))
    def observe_ids(self,name,value):
        self.mov(name+'_address',7,AREA);self.op(name+'_load','488b07')
        self.store(name+'_save',0,OUTPUT+8*len(self.results));self.results.append(dict(name=name,expected=value))
    def observe_at(self,name,address,value):
        self.mov(name+'_address',7,address);self.op(name+'_load','488b07')
        self.store(name+'_save',0,OUTPUT+8*len(self.results));self.results.append(dict(name=name,expected=value))
    def finish_app(self):
        self.op('restore_initial_rsp','4c89fc')
        self.syscall('write_output',1,[1,OUTPUT,512,0,0,0])
        self.syscall('exit',60,[0,0,0,0,0,0])
        self.label('failure')
        self.syscall('failure_write',1,[1,OUTPUT,512,0,0,0])
        self.syscall('failure_exit',60,[99,0,0,0,0,0])
        return self.finish()

def program(index,cpu,prefix_only=False):
    name=NAMES[index];p=App()
    p.op('save_initial_rsp','4989e7')
    p.syscall('map_owned',9,[AREA_PAGE,PAGE,3,0x100022,-1,0],AREA_PAGE)
    # Explicit observation, NOT proof of initial absence: a wrong tuple on an
    # already-registered task also returns EINVAL. Fresh exec+no libc and first
    # successful registration are the actual initial-registration evidence.
    p.rseq('initial_unregister',flags=1,expected=-22)
    if name in ('read_overlap','readv_unsupported','disjoint'):
        p.syscall('open_original',257,[-100,PATH,0,0,0,0])
        p.op('open_nonnegative','4883f800');p.branch('open_check','0f8c','failure')
        p.op('retain_read_fd','4989c5')
    if name=='nonzero_preissue':
        p.mov('nonzero_address',7,WORD);p.mov('nonzero_value',0,1)
        p.op('publish_before_registration','488907')
    else:
        p.rseq('register');p.observe_ids('registered_cpu_ids',cpu|(cpu<<32))
    if index<2:
        # Genuine registered cache route: the complete nine-byte window contains
        # two eligible MOVs followed by a real ordinary CMP guard. A following
        # ten-byte immediate MOV alone would leave too little fetch window.
        p.mov('registered_run_seed',10,0x5162738495a6b7c8)
        p.op('registered_run_first','4d89d3')
        p.op('registered_run_second','4d89dc')
        p.op('registered_run_guard','4839c0')
        p.op('registered_run_result','4c8925'+struct.pack('<i',OUTPUT+8*len(p.results)-(p.pc+7)).hex())
        p.results.append(dict(name='registered_run_literal',expected=0x5162738495a6b7c8))
    target=0;opnum=-1;expected_error=0;expected_detail=0;trap=14
    if name=='registration':
        for n,kw,e in [('duplicate',{},-16),('duplicate_pointer',dict(address=AREA+32),-22),
                       ('duplicate_length',dict(length=64),-22),('duplicate_signature',dict(sig=SIGNATURE^1),-1),
                       ('unregister_signature',dict(flags=1,sig=SIGNATURE^1),-1),
                       ('unregister_pointer',dict(flags=1,address=AREA+32),-22),
                       ('unregister_length',dict(flags=1,length=64),-22),
                       ('unregister',dict(flags=1),0),('already_unregistered',dict(flags=1),-22),
                       ('register_again',{},0),('unregister_again',dict(flags=1),0)]:
            p.rseq(n,expected=e,**kw)
        p.observe_word('final_word')
        p.observe_ids('unregistered_cpu_ids',0xffffffff00000000)
    elif name=='disjoint':
        p.mov('disjoint_pointer',7,AREA_PAGE+128);p.mov('literal',0,0x1122334455667788)
        p.op('disjoint_mov','488907');p.op('literal_push','50');p.op('literal_pop','58')
        p.branch('disjoint_call','e8','callee');return_pc=p.pc
        p.op('actual_call_word','488b4424f8');p.store('save_call_word',0,OUTPUT+8*len(p.results))
        p.results.append(dict(name='original_call_word',expected=return_pc))
        p.branch('skip_callee','e9','after_callee')
        p.label('callee');p.op('callee_return','c3');p.label('after_callee')
        p.mov('sse_input',7,DATA+1536);p.op('sse_load','f30f6f07')
        p.mov('sse_destination',7,AREA_PAGE+160);p.op('sse_store','f30f7f07')
        p.mov('rep_destination',7,AREA_PAGE+256);p.mov('rep_count',1,2)
        p.mov('rep_value',0,0x1122334455667788);p.op('rep_store','f348ab')
        p.op('read_fd','4c89ef');p.syscall('read_disjoint',0,[None,AREA_PAGE+512,8,0,0,0],8)
        p.syscall('random_disjoint',318,[AREA_PAGE+520,8,0,0,0,0],8)
        for label,address,value in [('mov_value',AREA_PAGE+128,0x1122334455667788),
             ('sse_low',AREA_PAGE+160,0x1122334455667788),('sse_high',AREA_PAGE+168,DATA+1024),
             ('rep_first',AREA_PAGE+256,0x1122334455667788),('rep_second',AREA_PAGE+264,0x1122334455667788),
             ('read_value',AREA_PAGE+512,0x00010102464c457f)]:p.observe_at(label,address,value)
        p.observe_word('disjoint_word');p.rseq('unregister',flags=1)
        p.observe_ids('unregistered_cpu_ids',0xffffffff00000000)
    else:
        expected_error=1205
        if name in ('mov_overlap','zero_store_overlap','trace_mov_overlap'):
            p.mov('target_address',7,WORD);p.mov('target_value',0,0 if name=='zero_store_overlap' else DATA+1024)
            if name=='trace_mov_overlap':
                p.op('actual_trace_predecessor','4883c001');trap=1
            target=p.pc;operation='488907'
        elif name=='sse_overlap':
            p.mov('vector_address',7,DATA+1536);p.op('vector_load','f30f6f07')
            p.mov('target_address',7,WORD-8);target=p.pc;operation='f30f7f07'
        elif name in ('call_overlap','push_overlap'):
            p.mov('target_stack',4,WORD+8);p.mov('target_value',0,DATA+1024)
            target=p.pc;operation=('e800000000' if name=='call_overlap' else '50')
        elif name=='rep_overlap':
            p.mov('target_address',7,WORD-8);p.mov('target_count',1,2);p.mov('target_value',0,DATA+1024)
            target=p.pc;operation='f348ab'
        elif name=='pop_memory_unsupported':
            p.mov('target_address',7,WORD);target=p.pc;operation='8f07';expected_error=1207;expected_detail=298
        else:
            vals={
              'read_overlap':(0,[None,WORD,8,0,0,0],1205,0),
              'getrandom_overlap':(318,[WORD,8,0,0,0,0],1205,0),
              'munmap_overlap':(11,[AREA_PAGE,PAGE,0,0,0,0],158,0),
              'mprotect_overlap':(10,[AREA_PAGE,PAGE,1,0,0,0],155,0),
              'readv_unsupported':(19,[None,DATA+1568,1,0,0,0],1207,19),
              'ioctl_unsupported':(16,[1,0x541b,WORD,0,0,0],1207,16),
              'nonzero_preissue':(334,[AREA,32,0,SIGNATURE,0,0],1209,2)}
            opnum,args,expected_error,expected_detail=vals[name]
            if name in ('read_overlap','readv_unsupported'):p.op('target_read_fd','4c89ef')
            for i,(reg,val) in enumerate(zip((7,6,2,10,8,9),args)):
                if val is not None:p.mov('target_arg'+str(i),reg,val)
            p.mov('target_number',0,opnum);target=p.pc;operation='0f05'
        # Distinct native prefix control deliberately stops before the target.
        # It neither executes a dangerous publication nor claims native refusal.
        if not prefix_only:p.op('forbidden_operation',operation)
        else:
            p.op('prefix_restore_rsp','4c89fc')
            if name=='nonzero_preissue':
                p.mov('prefix_word_address',7,WORD);p.op('prefix_word_read','488b07')
                p.store('prefix_word_save',0,OUTPUT+8*len(p.results));p.results.append(dict(name='preissue_word',expected=1))
            else:
                p.observe_word('prefix_word');p.rseq('prefix_unregister',flags=1)
        if not prefix_only:
            # A forbidden operation returning is a fixture failure, never pass.
            p.syscall('unexpected_completion',60,[98,0,0,0,0,0])
    code=p.finish_app()
    return dict(name=name,index=index,prefix_only=prefix_only,entry=MAIN,code=code,
                rows=p.rows,results=p.results,target_pc=target,operation_syscall=opnum,
                error=expected_error,detail=expected_detail,trap=trap,expected_exit=0 if index<2 or prefix_only else 125)

def emit_one(directory,spec):
    directory.mkdir(parents=True,exist_ok=False)
    interp=(directory/'interpreter.so').resolve();original=(directory/'original').resolve()
    dyn,strings=0x400,0x480
    idyn=b''.join(struct.pack('<qQ',t,v) for t,v in ((5,strings),(10,len(elf.SONAME)+1),(14,1),(0,0)))
    ip=[elf.segment(1,4,0,0,PAGE),elf.segment(1,5,PAGE,PAGE,PAGE),
        elf.segment(2,4,dyn,dyn,len(idyn),8),elf.segment(0x6474e551,6,0,0,0,16)]
    ic=elf.mov64(0,MAIN)+bytes.fromhex('ffe0')
    ih=elf.emit(interp,3,PAGE,ip,[(dyn,idyn),(strings,b'\0'+elf.SONAME),(PAGE,ic)],2*PAGE)
    (directory/elf.SONAME[:-1].decode()).write_bytes(interp.read_bytes())
    path=str(interp).encode()+b'\0';assert len(path)<=512
    md=b''.join(struct.pack('<qQ',t,v) for t,v in ((1,1),(5,0x400000+strings),(10,len(elf.SONAME)+1),(0,0)))
    ph=[elf.segment(6,4,elf.EH.size,0x400000+elf.EH.size,7*elf.PH.size,8),
        elf.segment(3,4,0x500,0x400500,len(path),1),elf.segment(1,4,0,0x400000,PAGE),
        elf.segment(1,5,PAGE,MAIN,3*PAGE),elf.segment(1,6,4*PAGE,DATA,PAGE),
        elf.segment(2,4,dyn,0x400000+dyn,len(md),8),elf.segment(0x6474e551,6,0,0,0,16)]
    data=bytearray(PAGE)
    struct.pack_into('<8Q',data,0,MAGIC,spec['index'],spec['target_pc'],spec['operation_syscall']&((1<<64)-1),AREA,AREA_PAGE,WORD,1)
    data[1536:1552]=struct.pack('<QQ',0x1122334455667788,DATA+1024)
    struct.pack_into('<QQ',data,1568,WORD,8)
    # Nonzero pointers are never consumed. Negative native controls stop before
    # publication; the gated route must refuse before executing the store.
    own_path=str(original).encode()+b'\0';assert len(own_path)<1024;data[2048:2048+len(own_path)]=own_path
    assert len(spec['code'])<3*PAGE
    mh=elf.emit(original,2,MAIN,ph,[(dyn,md),(strings,b'\0'+elf.SONAME),(0x500,path),(PAGE,spec['code']),(4*PAGE,bytes(data))],5*PAGE)
    return {k:v for k,v in spec.items() if k!='code'}|dict(code_hex=spec['code'].hex(),original=str(original),
       interpreter=str(interp),library_root=str(directory.resolve()),original_sha256=mh,interpreter_sha256=ih,
       data_sha256=__import__('hashlib').sha256(data).hexdigest())

def main():
    assert len(sys.argv)==3 and not sys.flags.optimize
    cpu=int(sys.argv[2]);assert 0<=cpu<1<<31
    out=Path(sys.argv[1]).resolve();out.mkdir(parents=True,exist_ok=False)
    rows=[]
    for i,n in enumerate(NAMES):
        actual=emit_one(out/n,program(i,cpu))
        prefix=emit_one(out/(n+'-native-prefix'),program(i,cpu,True)) if i>=2 else None
        rows.append(dict(actual=actual,native_prefix=prefix))
    (out/'images.json').write_text(json.dumps(rows,sort_keys=True,indent=2)+'\n')
if __name__=='__main__':main()
