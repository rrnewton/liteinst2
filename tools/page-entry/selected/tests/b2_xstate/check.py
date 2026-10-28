"""Read one real same-child NX signal/ptrace capture; never run an inferior.

This qualifies capture provenance and reports actual envelopes. It does not
equate unequal XSAVE components, synthesize missing bytes, or claim a B2 pass.
"""
import hashlib,json,struct,sys
from pathlib import Path
SIZE=140064
MAGIC=0x315053584232494c
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(11,9,19))
REGS=('r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')
GPRS=('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
GREG=(13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7)
def need(ok,why):
    if not ok:raise ValueError(why)
def q(b,at=0):return struct.unpack_from('<Q',b,at)[0]
def u32(b,at):return struct.unpack_from('<I',b,at)[0]
def inspect(data):
    need(type(data)is bytes and len(data)==SIZE,'complete fixed raw capture, partial file remains a failure')
    h=struct.unpack_from('<64Q',data);hw=struct.unpack_from('<32Q',data,512)
    need(h[:3]==(MAGIC,1,SIZE),'source-defined raw wire version')
    result={'scope':'same_subject_signal_and_ptrace_xstate_envelopes','bytes':len(data),
        'sha256':hashlib.sha256(data).hexdigest(),'capture_complete':False,
        'cross_mode_semantic_agreement':False,'parent_error':h[6],'child_error':h[27],
        'parent_phase':h[5],'hardware_error':hw[14],'terminal_wait_status':h[10]}
    if h[6] or h[27] or hw[14]:return result
    need(h[3]>0 and h[4]>0 and h[3]!=h[4] and hw[0]==h[4] and h[16]==h[4],
         'one actual fork result, child getpid, and physically reaped child')
    need(h[5]==4 and h[8]==((19<<8)|0x7f),'actual initial SIGSTOP and complete parent phase')
    need(h[9]==((11<<8)|0x7f) and h[10]==0 and not any(h[11:14]) and h[15]==0 and
         not any(h[17:20]) and h[22]==0 and h[25:28]==(1,1,0)and h[55]==1 and h[56]==0,
         'actual NX delivery stop, four successful read-only ptrace requests, delivered SIGSEGV and exit0')
    need(h[21]==4096 and h[20]>0 and h[20]%4096==0 and h[24]==131072 and h[23]>0,
         'actual owned RO/NX page and guarded alternate signal stack')
    need(h[28]==11 and h[32:34]==(968,128)and h[35:38]==(40,224,296)and
         h[26]==1 and not any(h[57:])and not any(hw[20:]),'exact actual compiled signal layout and initialized suffix')
    need(hw[1]==hw[6]==hw[8]==hw[10]==0 and hw[5]==hw[13]==1 and hw[16]==hw[18]==0 and
         hw[17]==hw[19]==h[45]==h[48]==MASK,'actual hardware/mask query results and exact pre-delivery/UC mask')
    need(h[38]==h[39]==h[42]==h[49]==h[51]==0 and h[40]==hw[7]and h[41]==hw[9]and
         hw[2]==hw[11]==h[43]and hw[3]==hw[12]==h[44],'same actual CPU and stable observed xcomponent permissions')
    cp=[struct.unpack_from('<6I',data,768+i*24)for i in range(67)]
    need([r[:2]for r in cp]==[(0,0),(1,0),(7,0)]+[(13,i)for i in range(64)],'all67 actual CPUID queries retained')
    need(cp[0][2]>=13 and cp[1][4]&0x0c000000==0x0c000000,'real XSAVE/OSXSAVE before actual XGETBV')
    need(576<=cp[3][3]<=cp[3][4]<=65536,'actual CPUID maximum standard extent fits capture capacity')
    at=2376;regs=dict(zip(REGS,struct.unpack_from('<27Q',data,at)));at+=216
    psi=data[at:at+128];at+=128;nt_storage=data[at:at+65536];at+=65536
    si=data[at:at+128];at+=128;uc_storage=data[at:at+2048];at+=2048
    fp_storage=data[at:at+65536];at+=65536;source=data[at:at+4096];at+=4096
    need(at==SIZE and 576<=h[14]<=65536 and 580<=h[34]<=65536,'both complete actual standard envelope extents')
    nt=nt_storage[:h[14]];fp=fp_storage[:h[34]];uc=uc_storage[:968]
    need(not any(nt_storage[h[14]:])and not any(fp_storage[h[34]:])and not any(uc_storage[968:]),'unused capture storage remains zero')
    need(psi==si and struct.unpack_from('<3i',si)==(11,0,2)and q(si,16)==h[20],
         'same actual unmodified SIGSEGV siginfo, not a synthesized signal')
    g=struct.unpack_from('<23Q',uc,40)
    need(g[20]==14 and g[19]==21 and g[22]==q(si,16)==g[16]==regs['rip']==h[20],
         'one exact NX instruction/trap/error/CR2 in ptrace and real signal frame')
    actual={name:g[index]for name,index in zip(GPRS,GREG)}
    actual.update(rip=g[16],eflags=g[17],cs=g[18]&65535,gs=(g[18]>>16)&65535,
        fs=(g[18]>>32)&65535,ss=g[18]>>48,fs_base=h[50],gs_base=h[52],ds=h[53],es=h[54])
    need(actual=={k:v for k,v in regs.items()if k!='orig_rax'},'all comparable GPR/flags/selector/base fields at the same fault')
    need(q(uc,224)==h[31]and q(uc,296)==MASK,'actual unchanged signal FP pointer and mask')
    for address,length in((h[29],968),(h[30],128),(h[31],h[34])):
        need(h[23]<=address and length<=h[24]and address-h[23]<=h[24]-length,'complete real SI/UC/FP within actual alternate stack')
    need(h[31]%16==0 and u32(fp,464)==0x46505853 and u32(fp,468)==len(fp)and
         u32(fp,480)==len(fp)-4 and u32(fp,len(fp)-4)==0x46505845,'genuine Linux signal XSAVE envelope')
    need(source==bytes.fromhex('900f0b')+bytes(4093),'original fault source page retained; no source patch or execution')
    user=cp[3][2]|(cp[3][5]<<32);supervisor=cp[4][4]|(cp[4][5]<<32)
    result.update(capture_complete=True,actual_child_count=1,actual_faults=1,actual_parent_reads=4,
        nt_bytes=len(nt),signal_bytes=len(fp),signal_xstate_bytes=u32(fp,480),
        nt_os_mask=q(nt,464),signal_layout_mask=q(fp,472),xcr0=hw[4],xcomp_supported=hw[7],xcomp_permitted=hw[9],
        nt_xstate_bv=q(nt,512),signal_xstate_bv=q(fp,512),nt_xcomp_bv=q(nt,520),signal_xcomp_bv=q(fp,520),
        cpuid_user_mask=user,cpuid_supervisor_mask=supervisor,cpuid_current_standard_bytes=cp[3][3],
        cpuid_max_standard_bytes=cp[3][4],components=[{'bit':i,'eax':cp[3+i][2],'ebx':cp[3+i][3],
            'ecx':cp[3+i][4],'edx':cp[3+i][5]}for i in range(2,64)if(user|supervisor)>>i&1],
        cpu=hw[2],node=hw[3],whole_program_or_b2_completion=False)
    return result
if __name__=='__main__':
    data=Path(sys.argv[1]).read_bytes()
    try:
        result=inspect(data);print(json.dumps(result,sort_keys=True));sys.exit(0 if result['capture_complete']else 1)
    except (ValueError,struct.error)as error:
        print(json.dumps({'capture_complete':False,'cross_mode_semantic_agreement':False,'bytes':len(data),
            'sha256':hashlib.sha256(data).hexdigest(),'error':str(error)},sort_keys=True));sys.exit(1)
