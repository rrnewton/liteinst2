"""Independent effects13 source descriptions; old domains stay separate.

The old grammar and whole descriptors are reused unchanged. Only the explicit
byte MOV and two-operand IMUL grammar below is added. An unimplemented encoding
still raises CoverageError; it never becomes a completed refusal witness.
"""
import importlib.util
import struct
from pathlib import Path

_s=importlib.util.spec_from_file_location('effects_old_source',
    Path(__file__).resolve().parents[1]/'persistent_loop_owner/source_decode.py')
old=importlib.util.module_from_spec(_s);_s.loader.exec_module(old)
need,p,U64,CoverageError=old.need,old.p,old.U64,old.CoverageError


def special(pc,window):
    need(type(pc)is int and 4096<=pc<(1<<47)and type(window)is bytes and
         0<len(window)<=15 and pc+len(window)<(1<<47),'bounded source-only effects window')
    if window[0]==0x9c:
        # Canonical unprefixed PUSHFQ is a descriptive stop, never NONE or MOV.
        # iced Code317 and old STEP_FLAGS_OBSERVED=2 retain the full refusal;
        # both TF/MOV APIs have policy/flow/family0 and refusal1 for this Code.
        row=p.ins(window[:1],317,step=2)
        oldrow=p.descriptor(row,pc,window,0,1);results=[]
        for scalar_version,mov_version in ((2,1),(3,2)):
            scalar=bytearray(oldrow);struct.pack_into('<I',scalar,256,scalar_version)
            mov=bytearray(144)
            struct.pack_into('<2Q6I',mov,0,pc,pc+1,1,0,317,1,0,0)
            mov[40:56]=window+bytes(16-len(window))
            struct.pack_into('<4I',mov,80,mov_version,0,1,len(window))
            results.append(dict(pc=pc,next_pc=pc+1,length=1,code=317,flow=0,target=0,
                kind=0,stop=1,row=row,old=oldrow,scalar=bytes(scalar),mov=bytes(mov),
                bridge=oldrow,whole=bytes(scalar)+bytes(mov)+struct.pack('<2I',0,1)))
        return tuple(results)
    at=int(0x40<=window[0]<=0x4f);rex=window[0]if at else 0
    if len(window)<=at:return None
    opcode=window[at]
    multiply=window[at:at+2]==b'\x0f\xaf'
    if opcode not in(0x88,0xc6)and not multiply:return None
    pos=at+(2 if multiply else 1)
    def take(n):
        nonlocal pos
        if pos+n>len(window):raise CoverageError('truncated independent effects source at '+hex(pc))
        b=window[pos:pos+n];pos+=n;return b
    m=take(1)[0];mod=m>>6;rg=((m>>3)&7)+8*bool(rex&4);rm=(m&7)+8*bool(rex&1)
    base,index,scale,rip=rm,16,1,False;displacement=0;dn=da=0
    if mod!=3:
        if m&7==4:
            sib=take(1)[0];scale=1<<(sib>>6);index=((sib>>3)&7)+8*bool(rex&2)
            if (sib>>3)&7==4 and not rex&2:index=16
            base=(sib&7)+8*bool(rex&1)
            if mod==0 and sib&7==5:base=16;dn=4
        elif mod==0 and m&7==5:base=16;rip=True;dn=4
        if mod==1:dn=1
        elif mod==2:dn=4
        if dn:da=pos;displacement=int.from_bytes(take(dn),'little',signed=True)&U64
    immediate=take(1)[0]if opcode==0xc6 else 0
    if opcode==0xc6 and (m>>3)&7:
        raise CoverageError('non-MOV C6 group has no independent effects description')
    code=(2072 if rex&8 else 2071)if multiply else 279 if opcode==0x88 else 401
    row=p.ins(window[:pos],code)
    oldrow=p.descriptor(row,pc,window,0,1)
    scalar=bytearray(oldrow);struct.pack_into('<I',scalar,256,2)
    mov=bytearray(144)
    struct.pack_into('<2Q6I',mov,0,pc,pc+pos,1,1,code,pos,1,1)
    mov[40:56]=window+bytes(16-len(window))
    struct.pack_into('<4I',mov,80,1,0,1,len(window))
    result=dict(pc=pc,next_pc=pc+pos,length=pos,code=code,flow=0,target=0,
        kind=0,stop=1,row=row,old=oldrow,scalar=bytes(scalar),mov=bytes(mov),bridge=oldrow,
        whole=bytes(scalar)+bytes(mov)+struct.pack('<2I',0,1))
    added=bytearray(scalar);struct.pack_into('<I',added,256,3)
    store=bytearray(mov);struct.pack_into('<I',store,80,2)
    if multiply:
        # Physical flags and both ordered register effects are independent
        # literal x86 semantics, including destination/source aliases.
        if code==2072:
            refusal=4 if not(mod==3 and 0x48<=rex<=0x4f and not rex&2 and pos==4)else 5 if rg==4 else 0
            r=p.ins(window[:pos],code,(p.reg(rg,64,3),p.reg(rm,64,1)),(0,0x801,0,0,0xd4))
            added=bytearray(p.descriptor(r,pc,window,0,refusal));struct.pack_into('<I',added,256,3)
            if not refusal:row=r
    elif mod!=3 and not rex&8 and not(opcode==0xc6 and rex&4)and not(rex&1 and not 8<=base<16)and not(rex&2 and not 8<=index<16):
        source=16 if opcode==0xc6 else rg
        low=opcode==0xc6 or bool(rex)or rg<4
        if low and not(rex==0x40 and not 4<=source<8):
            value=displacement
            if rip:
                value=pc+pos+(displacement if displacement<1<<63 else displacement-(1<<64))
                need(old.canonical(value),'canonical independent byte-store RIP target')
            struct.pack_into('<3Q',store,56,value,value if rip else 0,immediate)
            struct.pack_into('<16I',store,80,2,1,0,len(window),1,2 if opcode==0xc6 else 1,
                source,base,index,scale,int(rip),da,dn,at+1,at,0)
    ready=struct.unpack_from('<I',added,260)[0]
    kind=1 if ready else 2 if struct.unpack_from('<I',store,84)[0]else 0
    effects=dict(result,scalar=bytes(added),mov=bytes(144)if ready else bytes(store),
        bridge=bytes(added)if ready else oldrow,row=row,kind=kind,stop=0 if kind else 1)
    effects['whole']=effects['scalar']+effects['mov']+struct.pack('<2I',kind,effects['stop'])
    return result,effects


def decode12(pc,window):
    value=special(pc,window)
    return value[0]if value is not None else old.decode(pc,window)


def decode(pc,window):
    value=special(pc,window)
    if value is not None:return value[1]
    result=old.decode(pc,window)
    scalar=bytearray(result['scalar']);struct.pack_into('<I',scalar,256,3)
    mov=bytearray(result['mov'])
    # The source chooser consults the separate byte API only after the full
    # old MOV refusal. Its refused row retains TF identity and available bytes.
    if result['kind']==0:struct.pack_into('<I',mov,80,2)
    return dict(result,scalar=bytes(scalar),mov=bytes(mov),
        whole=bytes(scalar)+bytes(mov)+struct.pack('<2I',result['kind'],result['stop']))
