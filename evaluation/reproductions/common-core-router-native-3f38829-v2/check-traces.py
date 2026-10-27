#!/usr/bin/env python3
"""Check one complete standalone synthetic trace set; execute no subject."""
import argparse,hashlib,json,os,re,stat,struct,sys
from pathlib import Path
REGS="r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs".split()
MASK=(1<<64)-1
DEBUG=(1<<8)|(1<<16)
def sha(b):return hashlib.sha256(b).hexdigest()

def router_code(code, base):
    """Decode only the exact finite handler/restorer instruction program.

    Conditional branches permit their two architectural displacement widths;
    every destination, immediate, operand, byte and final extent is checked.
    This is not a general instruction decoder or an executable code generator.
    """
    assert 0 < len(code) <= 512 and 0 < base < (1 << 47)
    literals = {0:'f30f1efa',1:'cc',2:'83ff04',4:'4885f6',6:'4885d2',
        8:'833e04',10:'837e0802',12:'4883bac800000006',14:'4c8b82a8000000',
        15:'4c394610',18:'4d85c9',21:'4885c9',23:'4883f957',25:'4d3901',
        27:'4983c110',28:'48ffc9',31:'498b4108',32:'488982a8000000',33:'c3',
        34:'bf7c000000',35:'b8e7000000',36:'0f05',37:'0f0b',38:'48c7c00f000000',39:'0f05',40:'0f0b'}
    branches = {3:(0x75,34),5:(0x74,34),7:(0x74,34),9:(0x75,34),11:(0x75,34),
        13:(0x75,34),16:(0x75,34),19:(0x74,34),22:(0x74,34),24:(0x77,34),
        26:(0x74,31),29:(0x75,25),30:(0xeb,34)}
    cursor, insns, targets, globals_ = 0, [], {}, {}
    for i in range(41):
        start = cursor
        if i in literals:
            b = trace_hex(literals[i]); assert code[cursor:cursor+len(b)] == b; cursor += len(b)
        elif i in (17,20):
            prefix = trace_hex('4c8b0d' if i == 17 else '488b0d')
            assert code[cursor:cursor+3] == prefix and cursor+7 <= len(code)
            cursor += 7; globals_[i] = base+cursor+struct.unpack_from('<i', code, cursor-4)[0]
            assert 0 < globals_[i] < (1 << 47) and globals_[i] % 8 == 0
        else:
            opcode, target_index = branches[i]
            if code[cursor:cursor+1] == bytes([opcode]):
                assert cursor+2 <= len(code); cursor += 2
                displacement = struct.unpack_from('<b', code, cursor-1)[0]
            else:
                prefix = b'\xe9' if opcode == 0xeb else bytes([0x0f, opcode+0x10])
                assert code[cursor:cursor+len(prefix)] == prefix and cursor+len(prefix)+4 <= len(code)
                cursor += len(prefix)+4; displacement = struct.unpack_from('<i', code, cursor-4)[0]
            targets[i] = (base+cursor+displacement, target_index)
        insns.append((base+start, code[start:cursor]))
    assert cursor == len(code) and globals_[17] != globals_[20]
    for destination, index in targets.values():
        assert destination == insns[index][0]
    return dict(instructions=insns, table_global=globals_[17], count_global=globals_[20],
                captured=insns[2][0], restorer=insns[38][0], syscall=insns[39][0])

def trace_hex(value):
    assert type(value) is str and re.fullmatch('(?:[0-9a-f]{2})*', value)
    return bytes.fromhex(value)

def trace_registers(value):
    b = trace_hex(value); assert len(b) == 216 and value == b.hex()
    return dict(zip(REGS, struct.unpack('<27Q', b)))

def register_equality(actual, expected):
    assert set(actual) == set(expected) == set(REGS)
    for k in REGS:
        mask = MASK ^ DEBUG if k == 'eflags' else MASK
        assert actual[k] & mask == expected[k] & mask, ('router register', k)

def control_trace(data, encoding, state):
    # This standalone control trace has no paired-snapshot header, trap-prefix,
    # original/NOP row, full maps, or original application-state dump.
    # Do not manufacture those records or invoke the complete corpus auditor.
    assert len(data) <= 355088 and data.endswith(b'\n')
    rows=[line.split('\t') for line in data.decode('ascii').splitlines()]
    assert len(rows)==48
    cursor=0
    def take(tag,n):
        nonlocal cursor
        row=rows[cursor]; cursor+=1
        assert len(row)==n and row[0]==tag,(tag,row)
        return row
    def number(s):
        assert re.fullmatch('0|[1-9][0-9]*',s)
        n=int(s); assert 0<=n<=MASK
        return n
    assert take('router_bootstrap',2)[1]=='linux-x86-64-private-altstack-v1'
    guard,usable,size=map(number,take('router_stack',4)[1:])
    assert guard%4096==0 and 0<guard<usable==guard+4096 and size==131072
    assert guard+139264 < (1<<47)
    r=take('router_table',4);table,table_len=map(number,r[1:3]);table_bytes=trace_hex(r[3])
    pc,dest=0x401100,0x500000
    expected_table=struct.pack('<QQ',pc,dest)+bytes(4096-16)
    assert table%4096==0 and 0<table<table+4096<(1<<47)
    assert table+4096<=guard or guard+139264<=table
    assert table_len==4096 and table_bytes==expected_table
    handler,flags,restorer,mask=map(number,take('router_action',5)[1:])
    assert flags==0x0c000004 and mask==0
    prior_mask=number(take('router_mask',2)[1]); assert prior_mask&8==0
    code=trace_hex(take('router_code',2)[1]);program=router_code(code,handler)
    assert restorer==program['restorer']
    prior=take('router_prior',2)[1]
    m=re.fullmatch(r'Action \{ handler: 0, flags: ([0-9]+), restorer: ([0-9]+), mask: ([0-9]+) \}',prior)
    assert m and all(0<=int(n)<=MASK for n in m.groups())
    assert take('router_scope',2)[1]=='controlled_single_thread_child_only'
    assert take('router-layout',7)[1:]==['128','968','16','40','224','296']
    def observed(phase):
        r=take('router-observed',6)
        assert r[1]==phase and trace_hex(r[2])==expected_table and trace_hex(r[3])==code
        assert number(r[4])==table and number(r[5])==1
    observed('before')
    contains=lambda p,n: usable<=p and n>0 and p+n<=usable+size
    assert take('router-fault',4)[1:]==['4','2',str(pc)]
    entry=take('router-entry',6)
    erow=take('router-entry-state',3);assert number(erow[1])==(5<<8)|127
    entered=trace_registers(erow[2])
    assert entry[1:]==[str(entered[k]) for k in ('rip','rsp','rsi','rdx')]+['128']
    assert entered['rip']==program['captured'] and entered['rdi']==4 and entered['rax']==0
    assert contains(entered['rsp'],8) and contains(entered['rsi'],128) and contains(entered['rdx'],968)
    order=list(range(2,25))+[25,26,31,32,33]
    assert len(order)==28
    for j,index in enumerate(order):
        p,b=program['instructions'][index]
        nxt=program['instructions'][order[j+1]][0] if j+1<len(order) else restorer
        assert take('router-step',4)[1:]==[str(p),str(nxt),b.hex()]
    rr=take('router-restorer',5);pre,post=trace_registers(rr[1]),trace_registers(rr[2])
    expected=dict(entered,r8=pc,r9=table,rcx=1,rax=dest,rsp=entered['rsp']+8,rip=restorer,
                  eflags=(entered['eflags']&~0x8d5)|0x44)
    register_equality(pre,expected)
    register_equality(post,dict(pre,rax=15,rip=program['syscall']))
    assert trace_hex(rr[3])==program['instructions'][38][1]
    info=trace_hex(rr[4]);assert len(info)==128 and struct.unpack_from('<iii',info)==(5,0,2)
    assert struct.unpack_from('<Q',info,16)[0]==program['syscall']
    se,sx=take('router-syscall-entry',3),take('router-syscall-exit',3)
    assert number(se[1])==number(sx[1])==((5|128)<<8)|127
    sysentry,sysexit=trace_registers(se[2]),trace_registers(sx[2])
    expected_entry=dict(post,orig_rax=15,rax=MASK-37,rip=program['syscall']+2,
                        rcx=program['syscall']+2,r11=post['eflags']&~(1<<16))
    register_equality(sysentry,expected_entry)
    # R11 is an exact full-word comparison. No debugger-bit exemption.
    assert sysentry['r11']==post['eflags']&~(1<<16)
    fetch=b'\x06' if encoding=='legacy' else b'\x62'+bytes(14)
    assert encoding in ('legacy','evex') and state in (0,1)
    assert take('router',4)[1:]==[str(pc),str(dest),fetch.hex()]
    fr=take('router-frame',6);assert number(fr[1])==entered['rdx']
    signal_info,frame,changed,fp=(trace_hex(v) for v in fr[2:])
    assert len(signal_info)==128 and len(frame)==len(changed)==968
    assert struct.unpack_from('<iii',signal_info)==(4,0,2)
    assert struct.unpack_from('<Q',signal_info,16)[0]==pc
    assert struct.unpack_from('<Q',frame,16)[0]==usable
    assert struct.unpack_from('<i',frame,24)[0]==0 and struct.unpack_from('<Q',frame,32)[0]==size
    assert struct.unpack_from('<Q',frame,296)[0]==prior_mask
    names='r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx rsp rip eflags'.split()
    frame_regs={name:struct.unpack_from('<Q',frame,40+8*j)[0] for j,name in enumerate(names)}
    assert frame_regs['rip']==pc and struct.unpack_from('<Q',frame,200)[0]==6
    expected_frame=bytearray(frame);expected_frame[168:176]=struct.pack('<Q',dest)
    assert changed==expected_frame
    # Independently check every register actually preserved in the saved frame.
    # Other register words have only handler/return self-consistency and the
    # executed native full-state comparison, not a saved original baseline.
    csgsfs=struct.unpack_from('<Q',frame,184)[0]
    selectors=dict(cs=csgsfs&65535,gs=(csgsfs>>16)&65535,fs=(csgsfs>>32)&65535,ss=(csgsfs>>48)&65535)
    assert selectors['cs']==0x33 and selectors['ss']==0x2b
    expected_entered=dict(entered,**frame_regs)
    expected_entered.update(rax=0,rdi=4,rsi=entered['rsi'],rdx=entered['rdx'],rsp=entered['rsp'],
                           rip=program['captured'],eflags=frame_regs['eflags']&~(0x400|DEBUG))
    register_equality(entered,expected_entered)
    expected_exit=dict(entered,**frame_regs)
    expected_exit.update(selectors);expected_exit.update(rip=dest,orig_rax=MASK)
    register_equality(sysexit,expected_exit)
    fp_address=struct.unpack_from('<Q',frame,224)[0]
    assert 580<=len(fp)<=65536 and contains(fp_address,len(fp))
    magic,extent=struct.unpack_from('<II',fp,464);xsize=struct.unpack_from('<I',fp,480)[0]
    assert magic==0x46505853 and extent==len(fp) and 576<=xsize<=extent-4
    assert struct.unpack_from('<I',fp,len(fp)-4)[0]==0x46505845
    after=take('router-fp-after',3)
    assert number(after[1])==fp_address and trace_hex(after[2])==fp
    observed('after');assert cursor==len(rows)
    return dict(encoding=encoding,state=state,bytes=len(data),sha256=sha(data),rows=len(rows),
      handler_instructions=41,handler_steps=len(order),router_stops=len(order)+5,
      final_control_NOP_source_attested=True,total_stops_source_attested=len(order)+6,
      route_pc=pc,route_target=dest,fetch=fetch.hex(),private_stack_bytes=size,
      table_bytes=4096,code_bytes=len(code),whole_uc_bytes=968,whole_fp_bytes=len(fp),fp_xstate_size=xsize,
      only_frame_RIP_changed=True,paired_FP_exact=True,observed_child_table_code_globals_equal=True,
      saved_frame_gprs_and_flags=18,saved_frame_selectors=selectors,
      original_full_27_register_baseline_saved=False,full_maps_saved=False,application_stack_saved=False,
      independent_canonical_original_xsave_comparison=False,
      syscall=dict(number=sysentry['orig_rax'],entry_status=int(se[1]),exit_status=int(sx[1]),
        post_MOV_EFLAGS=post['eflags'],entry_R11=sysentry['r11'],exact_R11_relation=True,
        exit_RIP=sysexit['rip'],exit_original_rax=sysexit['orig_rax']))

def read(path):
    assert path.is_absolute() and '..' not in path.parts and path.parent.resolve(strict=True)==path.parent
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        a=os.fstat(f.fileno());assert stat.S_ISREG(a.st_mode) and 0<=a.st_size<=1048576
        b=f.read(a.st_size+1);six=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
        assert len(b)==a.st_size and six(a)==six(os.fstat(f.fileno()))==six(path.lstat())
    return b,six(a)
def main():
    if sys.flags.optimize:raise SystemExit('assertions required')
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('traces','index','new-output'):ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--index-sha256',required=True);a=ap.parse_args()
    assert a.traces.is_absolute() and a.traces.resolve(strict=True)==a.traces and a.traces.is_dir()
    assert a.new_output.is_absolute() and a.new_output.parent.resolve(strict=True)==a.new_output.parent
    assert not a.new_output.exists() and not a.new_output.is_symlink() and not a.new_output.is_relative_to(a.traces)
    ib,_=read(a.index);assert sha(ib)==a.index_sha256;index=json.loads(ib)
    names={'complete.tsv','legacy-0.tsv','legacy-1.tsv','evex-0.tsv','evex-1.tsv'}
    assert set(index)==names and {p.name for p in a.traces.iterdir()}==names
    data={}
    for name in sorted(names):
        b,s=read(a.traces/name);pin=index[name]
        assert set(pin)=={'bytes','sha256','stat'} and pin==dict(bytes=len(b),sha256=sha(b),stat=s)
        data[name]=b
    assert data['complete.tsv']==b'LI2COMMONROUTERCONTROLS\t1\nsynthetic_roundtrips\t4\nfull_state_comparisons\t12\nrefused_deliveries\t2\nchildren\t10\ncommon_corpus_credit\tfalse\nqualification_complete\tfalse\n'
    rows=[]
    for encoding in ('legacy','evex'):
        for state in (0,1):
            name=f'{encoding}-{state}.tsv';r=control_trace(data[name],encoding,state)
            # Public projection omits memory bytes, addresses and owner tuples.
            rows.append(dict(trace=name,bytes=r['bytes'],sha256=r['sha256'],rows=r['rows'],handler_steps=r['handler_steps'],router_stops=r['router_stops'],source_attested_total_stops=r['total_stops_source_attested'],whole_ucontext_bytes=r['whole_uc_bytes'],whole_fp_bytes=r['whole_fp_bytes'],paired_FP_exact=r['paired_FP_exact'],only_saved_RIP_changed=r['only_frame_RIP_changed'],child_table_code_globals_equal=r['observed_child_table_code_globals_equal'],exact_R11_relation=r['syscall']['exact_R11_relation']))
    result=dict(schema=1,verdict='PASS_SAVED_SYNTHETIC_TRACE_BYTES',index_sha256=sha(ib),traces=rows,original_full_state_and_maps_saved=False,negative_results_source_attested=True,execution_closure_reviewed_by_this_script=False,common_corpus_credit=False,normal_loader_qualification=False,full_a3=False,qualification_complete=False)
    with a.new_output.open('x') as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(dict(verdict=result['verdict'],traces=4,rows=192),sort_keys=True))
if __name__=='__main__':main()
