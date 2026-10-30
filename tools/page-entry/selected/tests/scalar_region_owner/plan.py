"""Independent finite encoding/graph/image reconstruction; never executes x86.

Accepted instructions are reconstructed from bytes, not from captured effects.
A valid unsupported boundary's old decoder Code/length remain observations of
that separately qualified decoder; no boundary instruction is emitted/executed.
Its complete source window, refusal-only state and exclusion from the finite
supported encoding domain are checked here, with full304 equality to a separate
bounded invocation of the exact decoder archive. This is not a general disassembler.
"""
import struct

U64=(1<<64)-1
PAGE=4096
CODES=((281,282),(285,286),(2090,2091),(260,261),(96,97),(273,274))
FLAGS=(2048,1,64,65,128,4,2176,2240)


def need(ok,why):
    if not ok:raise ValueError(why)


def canonical(n):return type(n)is int and (0<=n<1<<47 or (1<<64)-(1<<47)<=n<=U64)


def descriptor(source,offset,base):
    """Return the exact supported 304-byte row, or None for an outside form."""
    raw=source[offset:offset+15];pc=base+offset
    if not raw or not canonical(pc):return None
    def op(kind,reg=0,width=0,access=0,immediate=0,encoding=0):
        return (immediate,kind,reg,width,access,encoding,0)
    flow=0;condition=16;target=0;flags=(0,0,0,0,0);memory=None;step=0
    operands=[];at=0;rex=0;code=0
    if 0x70<=raw[0]<=0x7f or raw[0] in (0xeb,0xe9) or len(raw)>=2 and raw[0]==15 and 0x80<=raw[1]<=0x8f:
        near=raw[0] in (0xe9,15);condition=(raw[1]&15 if raw[0]==15 else raw[0]&15) if raw[0] not in (0xeb,0xe9) else 16
        flow=2 if condition==16 else 1;at=(2 if raw[0]==15 else 1)+(4 if near else 1)
        if len(raw)<at:return None
        delta=int.from_bytes(raw[at-(4 if near else 1):at],'little',signed=True);target=pc+at+delta
        if not canonical(pc+at) or not canonical(target):return None
        code=(696 if near else 701) if flow==2 else (1856 if near else 161)+3*condition
        operands=[op(4,width=64,access=1,immediate=target,encoding=32 if near else 8)]
        if flow==1:flags=(FLAGS[condition//2],0,0,0,0)
    elif raw[0]==0x3c:
        if len(raw)<2:return None
        at=2;code=115;operands=[op(1,width=8,access=1),op(3,width=8,access=1,immediate=raw[1],encoding=8)];flags=(0,0x8d5,0,0,0)
    else:
        if 0x40<=raw[0]<=0x4f:rex=raw[0];at=1
        if at>=len(raw):return None
        opcode=raw[at];at+=1
        if opcode==15:
            if at>=len(raw) or raw[at]!=0xb6:return None
            kind=2;at+=1
        elif opcode in (0x89,0x8b,0x83,0x31,0x85):kind={0x89:0,0x8b:1,0x83:3,0x31:4,0x85:5}[opcode]
        else:return None
        if at>=len(raw):return None
        modrm=raw[at];at+=1;mod=modrm>>6;reg=((modrm>>3)&7)+(8 if rex&4 else 0);rm=(modrm&7)+(8 if rex&1 else 0)
        width=64 if rex&8 else 32;code=CODES[kind][width==64]
        if kind==3 and modrm&0x38!=0x20:return None
        if mod!=3:
            if kind not in (1,2):return None
            base=rm;index=16;scale=1;dispbytes=1 if mod==1 else 4 if mod==2 else 0
            if modrm&7==4:
                if at>=len(raw):return None
                sib=raw[at];at+=1;scale=1<<(sib>>6);index=((sib>>3)&7)+(8 if rex&2 else 0)
                if index==4:index=16
                base=(sib&7)+(8 if rex&1 else 0)
                if mod==0 and sib&7==5:base=16;dispbytes=4
            elif mod==0 and modrm&7==5:return None # RIP relative
            if at+dispbytes>len(raw):return None
            displacement=int.from_bytes(raw[at:at+dispbytes],'little',signed=True) if dispbytes else 0;at+=dispbytes
            memory=(displacement&U64,base,index,scale,1 if kind==2 else width//8,64,2 if base in (4,5) else 1,1,0)
            dst=reg;src=None
        else:
            if kind==2:return None # only the qualified MOVZX memory form
            dst,src=(rm,reg) if kind in (0,3,4,5) else (reg,rm)
        equal_xor=kind==4 and dst==src
        access=1 if kind==5 else 2 if kind in (0,1,2) or equal_xor else 3
        if dst==4 and access&2:return None
        operands=[op(1,dst,width,access)]
        if memory:operands.append(op(2,width=memory[4]*8,access=1))
        elif kind==3:
            if at>=len(raw):return None
            immediate=int.from_bytes(raw[at:at+1],'little',signed=True)&((1<<width)-1);at+=1
            operands.append(op(3,width=width,access=1,immediate=immediate,encoding=8))
        else:operands.append(op(1,src,width,0 if equal_xor else 1))
        if kind in (3,4,5):flags=(0,0,68,0x881,16) if equal_xor else (0,196,0,2049,16)
        if kind in (0,1) and mod==3:step=7 if rex==0x40 or rex&2 else 1
    if not 0<at<=len(raw) or not canonical(pc+at):return None
    registers=[]
    for immediate,kind,reg,width,access,encoding,reserved in operands:
        if kind==1 and access:
            registers.extend([(reg,32,1,0),(reg,64,2,0)] if width==32 and access==3 else [(reg,64 if width==32 and access==2 else width,access,0)])
        elif kind==2:
            registers.extend((reg,64,1,0) for reg in memory[1:3] if reg!=16)
    if len(registers)>3:return None
    row=bytearray(304)
    struct.pack_into('<QQ10I',row,0,pc,pc+at,1,0,code,0,16,0,step,len(raw),at,0)
    row[56:56+len(raw)]=raw
    struct.pack_into('<Q',row,72,target)
    for i,value in enumerate(operands):struct.pack_into('<Q6I',row,80+32*i,*value)
    for i,value in enumerate(registers):struct.pack_into('<4I',row,144+16*i,*value)
    if memory:struct.pack_into('<Q8I',row,192,*memory)
    read=write=0
    for reg,width,access,reserved in registers:
        if access&1:read|=1<<reg
        if access&2:write|=1<<reg
    struct.pack_into('<18I',row,232,1,1,0,flow,condition,len(operands),len(registers),int(memory is not None),*flags,read,write,0,0,0)
    return bytes(row)


def boundary(row,source,offset,page,observations):
    """Retain the actual old decoded row without miscalling it an x86 oracle."""
    need(type(row)is bytes and len(row)==304,'whole boundary descriptor')
    pc,nxt,version,status,code,kind,destination,width,step,available,length,reserved=struct.unpack_from('<QQ10I',row)
    need((pc,version,status,available,reserved)==(page+offset,1,0,min(15,PAGE-offset),0) and
        1<=length<=available and nxt==pc+length and canonical(nxt) and code>0 and 0<=kind<=9 and 0<=step<=11,
        'actual complete valid boundary decoder observation')
    need(row[56:72]==source[offset:offset+available]+bytes(16-available),'complete boundary source window')
    need(observations.get((pc,available,row[56:72]))==row,
        'whole unsupported boundary equals separate actual archive observation')
    if kind in (2,3,4):need(destination<16 and width in (16,32,64),'selected boundary operand observation')
    else:need(destination==16 and width==0,'nonoperand boundary observation')
    expected=bytearray(304);expected[:72]=row[:72];struct.pack_into('<I',expected,232,1)
    refusal=struct.unpack_from('<I',row,240)[0]
    need(refusal in (1,4,5,6,7),'valid unsupported boundary refusal, never invalid/truncated')
    struct.pack_into('<I',expected,240,refusal)
    need(bytes(expected)==row,'whole unsupported boundary has no partial effects or ready state')
    need(descriptor(source,offset,page) is None,'no supported instruction skipped as a boundary')
    return row


def check(raw,page,source,entry,generated,observations,map_mutation=False):
    need(type(raw)is bytes and len(raw)==53024 and type(source)is bytes and len(source)==PAGE,'complete fixed plan/source')
    need(canonical(page) and canonical(page+PAGE-1) and canonical(generated) and canonical(generated+PAGE-1) and
        page<=U64-PAGE and generated<=U64-PAGE and
        page%PAGE==generated%PAGE==0 and generated!=page and page<=entry<page+PAGE,'actual disjoint canonical pages and entry')
    head=[];original=[];offset=entry-page;total=0
    while True:
        need(offset<PAGE,'actual same-page stop boundary')
        d=descriptor(source,offset,page)
        if d is None:
            reason=1;stop=boundary(raw[27728:28032],source,offset,page,observations);break
        length=struct.unpack_from('<I',d,48)[0]
        reason=2 if len(head)==64 else 3 if length>256-total else 0
        if reason:stop=d;break
        original.append(d);head.append([offset,length,0,0,0,[0,0],0]);offset+=length;total+=length
    count=len(head);need(1<=count<=64 and 0<total<=256,'nonempty complete bounded prefix')
    pcs={page+h[0]:i for i,h in enumerate(head)};exits=[];leaders={0};incoming=[0]*count
    def successor(pc):
        need(page<=pc<page+PAGE,'all exits remain in actual held source page')
        if entry<=pc<page+offset:
            need(pc in pcs,'internal exact instruction head');return pcs[pc]
        if pc not in exits:exits.append(pc)
        need(len(exits)<=8,'at most eight distinct original exits');return 64+exits.index(pc)
    for i,(h,d) in enumerate(zip(head,original)):
        flow,condition=struct.unpack_from('<II',d,244);nxt=page+h[0]+h[1]
        edges=[successor(nxt)] if flow==0 else [successor(struct.unpack_from('<Q',d,72)[0])]+([successor(nxt)] if flow==1 else [])
        h[4]=len(edges);h[5][:len(edges)]=edges
        if flow:
            if edges[0]<count:leaders.add(edges[0])
            if i+1<count:leaders.add(i+1)
        for e in edges:
            if e<count:incoming[e]+=1
    need(exits and len(leaders)<=8,'nonempty exits and at most eight basic blocks')
    blocks=0
    for i,h in enumerate(head):
        blocks+=int(i in leaders);h[6]=blocks-1
    # Independent DFS establishes whole reachability, rejects every cycle, and
    # computes the longest executed original-instruction path.
    active=set();done={};reached=set()
    def visit(i):
        need(i not in active,'acyclic whole retained graph')
        if i in done:return done[i]
        active.add(i);reached.add(i);best=0
        for e in head[i][5][:head[i][4]]:best=max(best,visit(e) if e<count else 0)
        active.remove(i);done[i]=best+1;return best+1
    longest=visit(0);need(reached==set(range(count)) and longest<=64,'every selected head reachable, no omitted island')
    at=0
    for h,d in zip(head,original):
        flow=struct.unpack_from('<I',d,244)[0];h[2]=at;h[3]=h[1] if flow==0 else 6 if flow==1 else 5;at+=h[3]
    tail=struct.unpack_from('<I',original[-1],244)[0]!=2;image=bytearray(b'\xcc'*PAGE);maps=[]
    def rel(next_pc,target):
        n=target-next_pc;need(-(1<<31)<=n<1<<31,'exact signed rel32 without wrapping');return struct.pack('<i',n)
    for i,(h,d) in enumerate(zip(head,original)):
        flow,condition=struct.unpack_from('<II',d,244);a=h[2]
        if not flow:image[a:a+h[3]]=source[h[0]:h[0]+h[1]]
        else:
            e=h[5][0];target=generated+head[e][2] if e<count else exits[e-64]
            opcode=bytes((15,0x80+condition)) if flow==1 else b'\xe9'
            image[a:a+h[3]]=opcode+rel(generated+a+h[3],target)
        maps.append((1,1,i,2 if flow else 1,h[0],h[1],a,h[3],page+h[0],generated+a))
    if tail:
        image[at:at+5]=b'\xe9'+rel(generated+at+5,page+offset)
        maps.append((1,1,count-1,3,offset,0,at,5,page+offset,generated+at))
    image_bytes=at+5*tail;need(image_bytes<=PAGE,'whole bounded generated image')
    result=bytearray(53024)
    struct.pack_into('<12I4Q',result,0,1,1,count,blocks,len(exits),len(maps),longest,reason,total,image_bytes,count+1+len(maps),0,page,entry,generated,page+offset)
    result[80:4176]=source;result[4176:8272]=image
    for i,d in enumerate(original):result[8272+304*i:8272+304*(i+1)]=d
    result[27728:28032]=stop
    for i,m in enumerate(maps):
        d=descriptor(image,m[6],generated);need(d is not None,'every emitted instruction independently in supported domain')
        result[28032+304*i:28032+304*(i+1)]=d
    for i,h in enumerate(head):struct.pack_into('<8I',result,47792+32*i,*h[:5],*h[5],h[6])
    for i,pc in enumerate(exits):struct.pack_into('<Q',result,49840+8*i,pc)
    for i,m in enumerate(maps):struct.pack_into('<8I2Q',result,49904+48*i,*m)
    if map_mutation:
        # Exactly the separate supplied-control corruption, never normal input.
        struct.pack_into('<Q',result,49904+32,entry+1)
    need(raw==result,'entire independently reconstructed plan including unused rows/padding/image')
    keys='version ready head_index kind source_offset source_length generated_offset generated_length original_pc generated_pc'.split()
    return dict(raw=raw,page=page,entry=entry,generated=generated,source=source,image=bytes(image),heads=head,original=original,
        maps=[dict(zip(keys,m)) for m in maps],exits=exits,gpr_written=_union(original,288),
        flags_written=_union(original,268)|_union(original,272)|_union(original,276)|_union(original,280))


def _union(rows,offset):
    value=0
    for row in rows:value|=struct.unpack_from('<I',row,offset)[0]
    return value


def failed(raw,page,source,entry,generated,observations):
    """Exact unpublished partial-state reconstruction, with zero RX authority.

    The independent success graph check above remains separate. Here ordering
    matters because the C planner retains its precise first-failure prefix.
    Unsupported/invalid instruction metadata comes only from the separately
    observed archive; it cannot manufacture a supported/executed descriptor.
    """
    need(len(raw)==53024 and len(source)==PAGE and page%PAGE==generated%PAGE==0 and page!=generated and
        canonical(page) and canonical(page+PAGE-1) and canonical(generated) and canonical(generated+PAGE-1) and
        page<=U64-PAGE and generated<=U64-PAGE and page<=entry<page+PAGE,
        'complete refused-workspace geometry')
    result=bytearray(53024);header=[1,0,0,0,0,0,0,0,0,0,0,0];stop_pc=0
    result[80:4176]=source;rows=[];heads=[];exits=[];maps=[];at=entry-page
    def put():
        struct.pack_into('<12I4Q',result,0,*header,page,entry,generated,stop_pc)
        for i,h in enumerate(heads):struct.pack_into('<8I',result,47792+32*i,*h)
        for i,p in enumerate(exits):struct.pack_into('<Q',result,49840+8*i,p)
    def end(status):
        put();need(status in (1,2402,2403,2404),'specific unsupported/boundary/graph/relocation refusal only')
        need(bytes(result)==raw,'entire exact unpublished first-failure workspace including all unused bytes')
        return status
    def observed(offset):
        n=min(15,PAGE-offset);window=source[offset:offset+n]+bytes(16-n);pc=page+offset
        d=observations.get((pc,n,window));need(type(d)is bytes and len(d)==304,'actual halted-workspace decoder observation')
        old=struct.unpack_from('<QQ10I',d)
        need((old[0],old[2],old[9],old[11])==(pc,1,n,0) and d[56:72]==window,'whole halted decoder source identity')
        expected=bytearray(304);expected[:72]=d[:72];struct.pack_into('<I',expected,232,1)
        refusal=struct.unpack_from('<I',d,240)[0];struct.pack_into('<I',expected,240,refusal)
        need(d==expected,'halted decoder row has no execution effects')
        if old[3] in (1,2):
            need(refusal==old[3]+1,'exact invalid/truncated descriptor classification');return d,False
        need(old[3]==0 and 1<=old[10]<=n and old[1]==pc+old[10],'actual valid halted decoder length')
        boundary(d,source,offset,page,observations);return d,True
    while True:
        if at>=PAGE:return end(2402)
        header[10]+=1;d=descriptor(source,at,page)
        if d is None:
            d,valid=observed(at)
            if not valid:return end(2402)
        length=struct.unpack_from('<I',d,48)[0];ready=struct.unpack_from('<I',d,236)[0]
        reason=1 if not ready else 2 if len(rows)==64 else 3 if length>256-header[8] else 0
        if reason:
            if not rows:return end(1)
            result[27728:28032]=d;stop_pc=page+at;header[7]=reason;break
        i=len(rows);rows.append(d);result[8272+304*i:8272+304*(i+1)]=d
        heads.append([at,length,0,0,0,0,0,0]);header[2]+=1;header[8]+=length;at+=length
    n=len(rows);leaders={0};incoming=[0]*n
    def successor(pc):
        if not page<=pc<page+PAGE:return None
        if entry<=pc<stop_pc:
            for i,h in enumerate(heads):
                if pc==page+h[0]:return i
            return None
        if pc not in exits:
            if len(exits)==8:return None
            exits.append(pc);header[4]=len(exits)
        return 64+exits.index(pc)
    for i,(h,d) in enumerate(zip(heads,rows)):
        flow=struct.unpack_from('<I',d,244)[0];targets=([page+h[0]+h[1]] if flow==0 else
            [struct.unpack_from('<Q',d,72)[0]]+([page+h[0]+h[1]] if flow==1 else []))
        h[4]=len(targets)
        for j,pc in enumerate(targets):
            e=successor(pc)
            if e is None:return end(2403)
            h[5+j]=e
            if flow and j==0:
                if e<n:leaders.add(e)
                if i+1<n:leaders.add(i+1)
        for e in h[5:5+h[4]]:
            if e<n:incoming[e]+=1
    for i,h in enumerate(heads):
        header[3]+=int(i in leaders);h[7]=header[3]-1
    if header[3]>8 or not exits:return end(2403)
    reached={0};done=set();distance=[0]*n;distance[0]=1
    for _ in range(n):
        available=[i for i in range(n) if i not in done and incoming[i]==0]
        if not available or available[0] not in reached:return end(2403)
        i=available[0];done.add(i);header[6]=max(header[6],distance[i])
        for e in heads[i][5:5+heads[i][4]]:
            if e<n:
                need(incoming[e]>0,'no impossible graph decrement');incoming[e]-=1;reached.add(e);distance[e]=max(distance[e],distance[i]+1)
    at=0
    for h,d in zip(heads,rows):
        flow=struct.unpack_from('<I',d,244)[0];h[2]=at;h[3]=h[1] if flow==0 else 6 if flow==1 else 5;at+=h[3]
    tail=struct.unpack_from('<I',rows[-1],244)[0]!=2;header[9]=at+5*tail;header[5]=n+tail
    image=bytearray(b'\xcc'*PAGE);result[4176:8272]=image
    def rel(next_pc,target):
        delta=target-next_pc
        return struct.pack('<i',delta) if -(1<<31)<=delta<1<<31 else None
    def save_image():result[4176:8272]=image
    for i,(h,d) in enumerate(zip(heads,rows)):
        flow,condition=struct.unpack_from('<II',d,244);a=h[2]
        if flow==0:image[a:a+h[3]]=source[h[0]:h[0]+h[1]]
        else:
            opcode=bytes((15,0x80+condition)) if flow==1 else b'\xe9';image[a:a+len(opcode)]=opcode
            e=h[5];target=generated+heads[e][2] if e<n else exits[e-64];delta=rel(generated+a+h[3],target)
            if delta is None:save_image();return end(2404)
            image[a+len(opcode):a+h[3]]=delta
        m=(1,1,i,2 if flow else 1,h[0],h[1],a,h[3],page+h[0],generated+a)
        struct.pack_into('<8I2Q',result,49904+48*i,*m)
    if tail:
        image[at]=0xe9;delta=rel(generated+at+5,stop_pc)
        if delta is None:save_image();return end(2404)
        image[at+1:at+5]=delta
    need(False,'unpublished workspace cannot omit a successful complete plan')
