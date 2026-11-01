"""Independent bounded source decoder for chooser-history reconstruction.

The 131 old ready Codes and five added Codes are described from original
bytes, including complete operands/effects and canonical NONE facts. A small
explicit stop palette has complete refused descriptions. Anything outside
this implemented byte grammar raises CoverageError; it is never treated as
NO_ENVELOPE, an unsupported stop, or an execution permission.

No production decoder, planner, emitted code or captured descriptor is used
as a decoding oracle. Numeric Code identities are iced-x86 1.21.0 identities.
"""
import importlib.util
import struct
from pathlib import Path

_s=importlib.util.spec_from_file_location('loop_source_model_primitives',
    Path(__file__).resolve().parents[1]/'persistent_direct_frontier_owner/plan.py')
p=importlib.util.module_from_spec(_s);_s.loader.exec_module(p)
need,reg,imm,mem,ins=p.need,p.reg,p.imm,p.mem,p.ins
U64=(1<<64)-1
READ_FLAGS=(0x800,1,0x40,0x41,0x80,4,0x880,0x8c0)
ARITH=(0,0x8d5,0,0,0)
LOGIC=(0,0xc4,0,0x801,0x10)
ARITH_CODES={
    'add':(7,8,11,12,15,16,216,217,248,249),
    'or':(23,24,27,28,31,32,219,220,251,252),
    'and':(70,71,74,75,78,79,228,229,260,261),
    'sub':(83,84,87,88,91,92,231,232,263,264),
    'xor':(96,97,100,101,104,105,234,235,266,267),
    'cmp':(109,110,113,114,117,118,237,238,269,270),
    'test':(273,274,None,None,341,342,720,721,None,None)}
SHIFT_CODES={4:((447,380,479),(448,381,480)),
             5:((450,383,482),(451,384,483)),
             7:((456,389,488),(457,390,489))}
NOPS=tuple(bytes.fromhex(x)for x in('0f1f00','0f1f4000','0f1f440000',
                                 '0f1f8000000000','0f1f840000000000'))


class CoverageError(ValueError):
    """Unimplemented independent source grammar; never a policy result."""


def canonical(value):
    return 0<=value<(1<<47) or 0xffff800000000000<=value<=U64


def decode(pc,window):
    need(type(pc)is int and 4096<=pc<(1<<47) and type(window)is bytes and
         0<len(window)<=15 and pc+len(window)<(1<<47),
         'independent bounded canonical original source window')
    pos=0;rex=0
    if 0x40<=window[0]<=0x4f:rex=window[0];pos=1
    def take(n):
        nonlocal pos
        if pos+n>len(window):raise CoverageError('truncated independent source grammar at '+hex(pc))
        value=window[pos:pos+n];pos+=n;return value
    def integer(n,signed=False):return int.from_bytes(take(n),'little',signed=signed)
    def unknown():raise CoverageError('unimplemented independent source encoding at '+hex(pc))
    opcode_at=pos;opcode=integer(1);wide=bool(rex&8);width=64 if wide else 32
    family=None;encoding=None;code=None;ops=();flags=(0,0,0,0,0)
    flow=0;condition=16;target=0;step=0;decoded_kind=0
    tf=(1,1,1);old_ready=False;added=False;refusal=1
    address=None;reloc=0;mod=None;rm=rg=None;displacement=0;disp_at=disp_n=0
    base=index=16;scale=1;rip=False;immediate=0;im_bits=0
    def modrm():
        nonlocal mod,rm,rg,displacement,disp_at,disp_n,base,index,scale,rip
        m=integer(1);mod=m>>6;rm=(m&7)+(8 if rex&1 else 0);rg=((m>>3)&7)+(8 if rex&4 else 0)
        if mod==3:return m
        base=rm;index=16;scale=1
        if m&7==4:
            sib=integer(1);scale=1<<(sib>>6)
            index=((sib>>3)&7)+(8 if rex&2 else 0)
            if (sib>>3)&7==4 and not rex&2:index=16
            base=(sib&7)+(8 if rex&1 else 0)
            if mod==0 and sib&7==5:base=16;disp_n=4
        elif mod==0 and m&7==5:base=16;rip=True;disp_n=4
        if mod==1:disp_n=1
        elif mod==2:disp_n=4
        if disp_n:disp_at=pos;displacement=integer(disp_n,True)&U64
        return m
    def relative(count,cc=None):
        nonlocal target,flow,condition,code,ops,flags,tf,old_ready
        delta=integer(count,True);target=pc+pos+delta
        need(canonical(target),'nonwrapping canonical independent branch target')
        flow=2 if cc is None else 1;condition=16 if cc is None else cc
        code=(701 if count==1 else 696)if cc is None else(161 if count==1 else 1856)+3*cc
        ops=((target,4,0,64,1,8*count,0),)
        flags=(0 if cc is None else READ_FLAGS[cc//2],0,0,0,0)
        tf=(1,2,3);old_ready=not rex
    if opcode==0xeb:relative(1)
    elif opcode==0xe9:relative(4)
    elif 0x70<=opcode<=0x7f:relative(1,opcode&15)
    elif opcode==0x0f:
        second=integer(1)
        if 0x80<=second<=0x8f:relative(4,second&15)
        elif second==0xb6:
            family,encoding,code='movzx','regrm',2091 if wide else 2090;modrm()
        elif second==0x1f and not wide:
            m=modrm();code=1057;added=True
            if (m>>3)&7:unknown()
            refusal=4
            if window[:pos]in NOPS:refusal=0
        elif second==0xa2 and not rex:code=1948;decoded_kind=1;step=8;tf=(0,0,0);refusal=6
        elif second==5 and not rex:code=870;decoded_kind=7;step=5;tf=(0,0,0);refusal=6
        elif second==0xa3:
            code=1951 if wide else 1950;modrm()
        else:unknown()
    elif opcode in(0x89,0x8b,0x8d):
        family='lea'if opcode==0x8d else'mov';encoding='rmreg'if opcode==0x89 else'regrm'
        code=(281 if opcode==0x89 else 285 if opcode==0x8b else 291)+int(wide);modrm()
    elif 0xb8<=opcode<=0xbf:
        family,encoding,code='mov','regimm',358 if wide else 357
        rm=(opcode&7)+(8 if rex&1 else 0);im_bits=width;immediate=integer(width//8)
        step=6 if rm==4 else 1
    elif opcode==0xc7:
        family,encoding,code='mov','group32',405 if wide else 404;m=modrm()
        if (m>>3)&7:unknown()
        im_bits=32;immediate=integer(4,wide)&U64
    elif opcode in(0x01,0x03,0x05,0x09,0x0b,0x0d,0x21,0x23,0x25,
                   0x29,0x2b,0x2d,0x31,0x33,0x35,0x39,0x3b,0x3d,0x85,0xa9):
        family={0:'add',1:'or',4:'and',5:'sub',6:'xor',7:'cmp'}.get(opcode>>3,'test')
        if opcode in(0x85,0xa9):family='test'
        acc=opcode in(5,13,37,45,53,61,169)
        encoding='accimm'if acc else'regrm'if opcode&3==3 else'rmreg'
        index_code=4 if acc else 2 if encoding=='regrm'else 0
        code=ARITH_CODES[family][index_code+int(wide)]
        if acc:rm=0;im_bits=32;immediate=integer(4,wide)&U64
        else:modrm()
    elif opcode in(0x81,0x83,0xf7):
        m=modrm();group=(m>>3)&7
        family={0:'add',1:'or',4:'and',5:'sub',6:'xor',7:'cmp'}.get(group)
        if opcode==0xf7:family='test'if group==0 else None
        if family is None:unknown()
        encoding='group8'if opcode==0x83 else'group32'
        code=ARITH_CODES[family][(8 if opcode==0x83 else 6)+int(wide)]
        im_bits=8 if opcode==0x83 else 32
        immediate=integer(im_bits//8,im_bits<width)&((1<<width)-1)
    elif opcode in(0xd1,0xc1,0xd3):
        m=modrm();group=(m>>3)&7
        if group not in SHIFT_CODES:unknown()
        family={4:'shl',5:'shr',7:'sar'}[group]
        encoding={0xd1:'one',0xc1:'count8',0xd3:'cl'}[opcode]
        code=SHIFT_CODES[group][int(wide)][(0xd1,0xc1,0xd3).index(opcode)]
        if opcode!=0xd3:immediate=1 if opcode==0xd1 else integer(1);im_bits=0 if opcode==0xd1 else 8
    elif opcode==0x3c:
        code=115;immediate=integer(1);ops=(reg(0,8,1),imm(immediate,8,8));flags=ARITH;old_ready=not rex
    elif opcode==0x63 and wide:
        m=modrm();code=140;added=True;refusal=4
        if mod==3 and not rex&2:
            refusal=5 if rg==4 else 0;ops=(reg(rg,64,2),reg(rm,32,1))
    elif opcode in(0x84,0x38):
        m=modrm();code=271 if opcode==0x84 else 107;added=True;refusal=4
        if mod==3 and not rex&0x0a:
            refusal=5 if not rex and(rm>=4 or rg>=4)else 4 if rex==0x40 and rm<4 and rg<4 else 0
            ops=(reg(rm,8,1),reg(rg,8,1));flags=LOGIC if opcode==0x84 else ARITH
    elif opcode==0x80:
        m=modrm()
        if (m>>3)&7!=7:unknown()
        code=214;added=True;immediate=integer(1);refusal=4
        if mod!=3 and not rex&0x0c and rex!=0x40 and not(rex&1 and not 8<=base<16)and not(rex&2 and not 8<=index<16):
            refusal=0;ops=(mem(8),imm(immediate,8,8));flags=ARITH
            address=(displacement,base,index,scale,1,64,2 if base in(4,5)else 1,1,0)
    elif opcode==0xff:
        m=modrm();group=(m>>3)&7
        if group not in(2,4):unknown()
        code=759 if group==2 else 765;tf=(1,2,4 if group==2 else 3)
    elif opcode==0x66 and not rex:
        # Descriptive stop only. The companion's real before-effect m16 store
        # is outside both scalar domains and the guarded four-Code MOV domain.
        if integer(1)!=0x89:unknown()
        modrm()
        if mod==3:unknown()
        code=280;width=16
    elif opcode==0xc3 and not rex:code=396;tf=(1,2,5)
    elif opcode==0xc2 and not rex:code=393;integer(2);tf=(1,2,5)
    elif opcode==0xe8 and not rex:code=693;integer(4);tf=(1,2,4)
    elif opcode==0x90 and not rex:code=300;step=1
    elif opcode==0xcc and not rex:code=420;tf=(0,0,0)
    elif 0x50<=opcode<=0x5f:
        code=126 if opcode<0x58 else 129;tf=(1,1,2)
    elif opcode in(0x68,0x6a)and not rex:
        code=143 if opcode==0x68 else 149;integer(4 if opcode==0x68 else 1);tf=(1,1,2)
    elif opcode==0xc9 and not rex:code=413;tf=(1,1,2)
    elif opcode==0xf3 and not rex and window[:4]==bytes.fromhex('f30f1efa'):
        take(3);code=1054
    else:unknown()
    need(code is not None and 0<pos<=15,'complete literal independent decoded Code and width')
    if family is not None:
        is_address=mod is not None and mod!=3
        clear=family in('sub','xor')and mod==3 and encoding in('rmreg','regrm')and rm==rg
        first=2 if family in('mov','movzx','lea')or clear else 1 if family in('cmp','test')else 3
        def value(which,access,w=width):
            nonlocal address
            if which=='rm'and is_address:
                if access!=1:return None
                lea=family=='lea';n=0 if lea else 1 if family=='movzx'else width//8
                address=(displacement,base,index,scale,n,64,0 if lea else 2 if base in(4,5)else 1,7 if lea else 1,0)
                return(0,5 if lea else 2,0,64 if lea else 8*n,7 if lea else 1,0,0)
            r=rm if which=='rm'else rg
            return None if r==4 and access&2 else reg(r,w,access)
        dest='rg'if encoding=='regrm'else'rm'
        a=value(dest,first)
        if encoding=='rmreg':b=value('rg',0 if clear else 1)
        elif encoding=='regrm':b=value('rm',0 if clear else 1)
        elif encoding=='cl':b=reg(1,8,1)
        else:b=imm(immediate,8 if encoding in('one','count8')else width,im_bits)
        if family in('lea','movzx')and not is_address:b=None
        if family=='lea'and is_address:
            # LEA's address is descriptive and does not read memory.
            b=value('rm',1)
        old_ready=a is not None and b is not None
        ops=(a,b)if old_ready else()
        if family in('add','sub','cmp'):flags=ARITH
        elif family in('and','or','xor','test'):flags=LOGIC
        elif family in('shl','shr','sar'):
            n=2 if encoding=='cl'else immediate&(width-1)
            flags=(0,0xc5|(0x800 if n==1 else 0),0,0,0x10|(0x800 if n!=1 else 0))if n else(0,0,0,0,0)
        if clear:flags=(0,0,0x44,0x881 if family=='xor'else 0x891,0x10 if family=='xor'else 0)
        if family=='mov'and encoding in('rmreg','regrm'):
            destreg=rm if encoding=='rmreg'else rg
            step=0 if is_address else 6 if destreg==4 else 7 if rex&2 or rex==0x40 else 1
    if address is not None and rip:
        signed=displacement if displacement<1<<63 else displacement-(1<<64)
        target_address=pc+pos+signed;need(canonical(target_address),'independent complete next-PC-relative data address')
        address=(target_address,*address[1:]);reloc=disp_at
    row=ins(window[:pos],code,ops,flags,address,reloc,step,flow,target,condition)
    if not old_ready and not added:refusal=6 if decoded_kind else 1
    if old_ready:refusal=0
    # These are three distinct API results. The additive API resets an old
    # refusal before its five-Code check; the bridge preserves the whole old
    # refusal when both APIs refuse (for example MOV [RDI],RAX: old5/new1).
    old_refusal=(0 if old_ready else 6 if decoded_kind else
                 5 if family is not None else 4 if flow or code==115 else 1)
    old=bytearray(p.descriptor(row,pc,window,0,old_refusal))
    if decoded_kind:struct.pack_into('<I',old,28,decoded_kind)
    scalar=bytearray(p.descriptor(row,pc,window,0,refusal))
    struct.pack_into('<I',scalar,256,2)
    if decoded_kind:struct.pack_into('<I',scalar,28,decoded_kind)
    bridge=old if old_ready or refusal else scalar
    ready=not refusal
    if ready:
        need(tf[0]==1,'independent source TF classification')
        # A second byte/form condition is required for every potential writer.
        no_write=flow!=0 or family in('lea','cmp','test','movzx')or code in(115,140,214,271,107,1057)or(
            family in('mov','add','sub','and','or','xor','shl','shr','sar')and not(mod is not None and mod!=3 and encoding!='regrm'))
        need(no_write,'separate independent NONE source-form theorem')
    mov=bytearray(144)
    if not ready:
        struct.pack_into('<2Q6I',mov,0,pc,pc+pos,1,tf[0],code,pos,tf[1],tf[2])
        mov[40:56]=window+bytes(16-len(window))
        struct.pack_into('<4I',mov,80,1,0,1,len(window))
        store=family=='mov'and encoding in('rmreg','group32')and mod!=3 and mod is not None
        if store and tf[0]==1 and not(encoding=='group32'and rex&4):
            value=address[0]if address is not None else displacement
            if rip:
                delta=displacement if displacement<1<<63 else displacement-(1<<64)
                value=pc+pos+delta;need(canonical(value),'whole independent store RIP target')
            struct.pack_into('<3Q',mov,56,value,value if rip else 0,immediate if encoding=='group32'else 0)
            struct.pack_into('<16I',mov,80,1,1,0,len(window),width//8,
                2 if encoding=='group32'else 1,16 if encoding=='group32'else rg,
                base,index,scale,int(rip),disp_at,disp_n,opcode_at+1,opcode_at,0)
    kind=1 if ready else 2 if struct.unpack_from('<I',mov,84)[0]else 0
    return dict(pc=pc,next_pc=pc+pos,length=pos,code=code,flow=flow if kind==1 else 0,
                target=target,kind=kind,stop=0 if kind else 1,row=row,
                old=bytes(old),scalar=bytes(scalar),mov=bytes(mov),bridge=bytes(bridge),
                whole=bytes(scalar)+bytes(mov)+struct.pack('<2I',kind,0 if kind else 1))
