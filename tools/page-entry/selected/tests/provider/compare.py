"""Data-only independent oracle. It never calls the provider or decoder.
The expected destination/flags algebra is derived here from actual before state
and the single retained hardware outcome, or separately supplied scripted value.
"""
import struct
MAGIC=0x315246505332494c
FP=65536
UC=2048
GREG=[13,14,12,11,15,10,9,8,0,1,2,3,4,5,6,7]
ARITH=0x8d5
class Mismatch(Exception):
    def __init__(self,field):super().__init__(field);self.field=field

def need(ok,field):
    if not ok:raise Mismatch(field)
def u64(b,at=0):return struct.unpack_from('<Q',b,at)[0]

def read(data):
    at=0
    def take(n):
        nonlocal at
        out=data[at:at+n];at+=n;need(len(out)==n,'record.truncated');return out
    h=struct.unpack('<64Q',take(512))
    need(h[0]==MAGIC and h[1]==1,'record.version')
    components=[struct.unpack('<4I',take(16)) for _ in range(8)]
    pre=struct.unpack('<24Q',take(192));post=struct.unpack('<24Q',take(192))
    pre_fp,post_fp,kbefore,kafter=[take(FP) for _ in range(4)]
    ub,ua=take(UC),take(UC)
    sb,sa=take(512),take(512)
    source,request=take(16),take(16)
    hardware=struct.unpack('<14I',take(56))
    stats=struct.unpack('<4I4Q',take(48))
    need(at==len(data),'record.trailing')
    return locals()

def canonical(image,mask,components):
    need(len(image)>=576,'xstate.size')
    bv=u64(image,512)
    need(bv&~mask==0 and u64(image,520)==0,'xstate.header')
    # Reserved legacy padding is not architectural state. Defined x87, MXCSR,
    # SSE and each qualified standard component are compared, including init state.
    if bv&1:
        out=image[:5]+image[6:24]+b''.join(image[32+16*i:42+16*i] for i in range(8))
    else:
        out=b'\x7f\x03'+bytes(3+18+80)
    out+=image[24:28]
    out+=image[160:416] if bv&2 else bytes(256)
    seen=3
    for bit,off,size,reserved in components:
        if not size:
            need((bit,off,reserved)==(0,0,0),'xstate.empty_component');continue
        need(bit in (2,5,6,7,9) and mask&(1<<bit) and not seen&(1<<bit) and not reserved and off>=576 and off+size<=len(image),'xstate.component')
        seen|=1<<bit
        out+=image[off:off+size] if bv&(1<<bit) else bytes(size)
    need(seen==mask,'xstate.complete_mask')
    return out

def scripted_value(kind,width,cf0):
    if kind==4:return 0xc00dcafe,0
    if cf0:return 0,0
    return {16:0xbeef,32:0xface9876,64:0xfedcba9876543210}[width],1

def check(data,case):
    r=read(data);h=r['h'];pre=r['pre'];post=r['post'];ub=r['ub'];ua=r['ua']
    mech,kind,width,reg,control,layout,prefix=case['args']
    need(h[2:7]==(kind,width,reg,mech,control),'case.identity')
    need(h[35:37]==(layout,prefix),'case.layout')
    if 'encoding' in case:
        encoding=bytes.fromhex(case['encoding'])
        need(0<len(encoding)<=15 and h[15]==len(encoding),'case.encoding_length')
        expected_source=encoding+bytes(16-len(encoding))
        need(r['source']==r['request']==expected_source,'case.exact_encoding')
    need(h[11]==1 and h[12]==0 and h[27]==1 and h[28]==0,'owner.one_return')
    need(h[13]+h[15]==h[14] and 0<h[15]<=15 and h[16]==pre[16],'source.extent')
    need(h[18]==h[17]&0x2e7 and h[18]&3==3,'xstate.mask')
    need(pre[17]&h[17]&~h[18]==0 and post[17]&h[17]&~h[18]==0,'xstate.unknown_active')
    need(pre[20:22]==(0,0) and post[20:22]==(0,0),'segments.query')
    need(pre[18:24]==post[18:24],'segments.preserved')
    need(h[20]==h[21] and 512<=h[20]<=FP and h[22]==h[23] and h[22]!=0,'frame.fp_owner')
    need(r['kbefore']==r['kafter'],'frame.fp_payload')
    need(r['kbefore'][h[20]:]==bytes(FP-h[20]),'frame.fp_initialized_prefix')
    need(0<h[24]<=UC and h[25]+23*8<=h[24] and h[26]+8<=h[24],'frame.layout')
    need(u64(ub,h[26])==h[22] and u64(ua,h[26])==h[23],'frame.fp_pointer')
    need(ub[h[24]:]==ua[h[24]:]==bytes(UC-h[24]),'frame.initialized_prefix')
    need(r['sb']==r['sa'],'stack.full_512_bytes')
    need(r['stats']==(1,2,0,0,16*1024**2,h[37],h[38],h[39]),'decoder.sealed_statistics')
    hw=r['hardware'];need(hw[:2]==(1,0) and (hw[2],hw[8],hw[11],hw[12])==(h[40],h[41],h[42],h[43]),'hardware.binding')
    need(h[8]==h[44]==case['status'],'provider.status')
    if case['status']:
        need(h[10]==0 and h[9] in (0,1),'refusal.no_native_effect')
        need(ub==ua,'refusal.exact_frame')
        expected=list(pre[:16]);flags=pre[16]
    else:
        need(h[9]==4 and h[10]==(1 if mech==1 else 0),'provider.completion')
        if mech==1:
            need((kind==2 and hw[2]>=1 and hw[8]&(1<<30)) or
                 (kind==3 and hw[2]>=7 and hw[11]&(1<<18)) or
                 (kind==4 and hw[2]>=7 and hw[12]&(1<<22)),'native.actual_hardware')
            value,carry=h[29],h[30]
        else:
            value,carry=scripted_value(kind,width,case.get('cf0',False))
            need((h[29],h[30])==(value,carry),'scripted.outcome')
        maximum=(1<<width)-1
        need(value<=maximum and carry in (0,1),'outcome.width')
        if kind==4:need(value<=0xffffffff and carry==0,'rdpid.outcome')
        else:need(carry or value==0,'random.failure_zero')
        expected=list(pre[:16])
        expected[reg]=((pre[reg]&~0xffff)|value) if width==16 else value
        flags=pre[16] if kind==4 else (pre[16]&~ARITH)|carry
        need(h[31:33]==(expected[reg],flags),'outcome.derived')
        for i,slot in enumerate(GREG):need(u64(ub,h[25]+8*slot)==pre[i],f'entry.gpr.{i}')
        need(u64(ub,h[25]+17*8)==pre[16]|0x10000 and u64(ub,h[25]+16*8)==h[13],'entry.flags_pc')
        wanted=bytearray(ub)
        struct.pack_into('<Q',wanted,h[25]+GREG[reg]*8,expected[reg])
        struct.pack_into('<Q',wanted,h[25]+17*8,flags)
        struct.pack_into('<Q',wanted,h[25]+16*8,h[14])
        need(bytes(wanted)==ua,'frame.exact_write_set')
        need(r['source']==r['request'],'source.exact_request')
    for i,expected_reg in enumerate(expected):need(post[i]==expected_reg,f'post.gpr.{i}')
    need(post[16]==flags,'post.flags')
    before=canonical(r['pre_fp'],h[18],r['components'])
    need(canonical(r['kbefore'],h[18],r['components'])==before,'entry.xstate')
    need(canonical(r['post_fp'],h[18],r['components'])==before,'post.xstate')
    return {'status':case['status'],'kernel_fp_bytes':h[20],'qualified_xstate_bytes':len(before),'native_attempts':h[10],
            'value':h[29],'carry':h[30],'arena_high_water':h[37]}

def nested(data):
    need(len(data)==512,'nested.record_size');h=struct.unpack('<64Q',data)
    need(h[:8]==(MAGIC,2,11,2,2,1,0,1),'nested.actual_prefix')
    need(h[9]%4096==0 and h[9]<=h[8]<h[10]<=h[11] and h[11]-h[9]==4096,'nested.isolated_pc')
    need(h[12:14]==(14,21) and not any(h[14:]),'nested.fetch_fault')
    return {'phase':h[4],'native_attempts':h[5],'provider_returns':h[6],'trap':h[12],'error':h[13]}
