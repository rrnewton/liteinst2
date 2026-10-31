"""Independent finite six-head graph, guard bytes and boundary-state model.
No decoder/model/native code is imported or executed by this reader."""
import struct
U64=(1<<64)-1

def need(ok,why):
    if not ok:raise ValueError(why)

def table(ranges,address):
    merged=[]
    for first,end in sorted(ranges):
        need(0<=first<end<=1<<47,'bounded complete exclusion')
        if merged and first<=merged[-1][1]:merged[-1][1]=max(end,merged[-1][1])
        else:merged.append([first,end])
    need(0<len(merged)<=131,'complete bounded exclusion set')
    nodes=[[a,b,0,0]for a,b in merged];height=0
    def tree(lo,hi,depth):
        nonlocal height
        if lo==hi:return 0
        m=(lo+hi)//2;height=max(height,depth)
        nodes[m][2]=tree(lo,m,depth+1);nodes[m][3]=tree(m+1,hi,depth+1)
        return address+32+32*m
    root=tree(0,len(nodes),1)
    return struct.pack('<4I2Q',1,1,len(nodes),height,address,root)+b''.join(struct.pack('<4Q',*n)for n in nodes)+bytes(32*(131-len(nodes)))

def guard(generated,spill,successor,root):
    """This actual fixture's MOV [RDI],RAX uses RAX/RCX/RDX/RBX scratch."""
    code=bytearray();rows=[];valid=dirty=flags=phase=0
    def emit(b):
        at=len(code);rows.append((at,len(b),valid,dirty,flags,phase));code.extend(b);return at
    def branch(condition):return emit(b'\xe9'+bytes(4)if condition==16 else bytes((15,128+condition))+bytes(4))
    def patch(at,target):
        n=5 if code[at]==233 else 6;code[at+n-4:at+n]=struct.pack('<i',target-at-n)
    def save(i,load):
        nonlocal valid,dirty
        emit(bytes((72,139 if load else 137,5+8*i))+struct.pack('<i',spill+8*i-generated-len(code)-7))
        if load:dirty&=~(1<<i)
        else:valid|=1<<i
    def restore():
        nonlocal dirty,flags
        emit(b'\x04\x7f');flags=1;emit(b'\x9e');flags=0
        for i in (1,2,3,0):save(i,True)
    for i in range(4):save(i,False)
    emit(b'\x48\x8d\x0f');dirty|=2
    emit(b'\x9f');dirty|=1;flags=1
    emit(b'\x0f\x90\xc0');flags=2
    emit(b'\x48\xbb'+struct.pack('<Q',root));dirty|=8
    emit(b'\x48\x8d\x51\x08');dirty|=4
    emit(b'\x48\x3b\xd1');overflow=branch(6)
    loop=len(code);emit(b'\x48\x85\xdb');accept_branch=branch(4)
    emit(b'\x48\x3b\x53\x00');left_branch=branch(6)
    emit(b'\x48\x3b\x4b\x08');right_branch=branch(3);reject_branch=branch(16)
    left=len(code);emit(b'\x48\x8b\x5b\x10');left_back=branch(16)
    right=len(code);emit(b'\x48\x8b\x5b\x18');right_back=branch(16)
    accept=len(code);restore();store=len(code);phase=1;emit(b'\x48\x89\x07');phase=2
    follow=branch(16);code[follow+1:follow+5]=struct.pack('<i',successor-generated-follow-5)
    reject=len(code);valid=dirty=15;flags=2;phase=0;restore();reject_offset=len(code);phase=3;emit(b'\x0f\x0b')
    for a,b in ((overflow,reject),(accept_branch,accept),(left_branch,left),(right_branch,right),(reject_branch,reject),(left_back,loop),(right_back,loop)):patch(a,b)
    need(len(rows)==37 and len(code)<=196,'fixed actual guard instruction extent')
    return bytes(code),tuple(rows),store,reject_offset

def image(page,generated,spill,table_bytes):
    root=struct.unpack_from('<Q',table_bytes,24)[0]
    g,rows,store,reject=guard(generated,spill,generated+512,root)
    slots=[g]
    def jump(at,target):return b'\xe9'+struct.pack('<i',target-at-5)
    for i,body,next_head in ((1,b'\x48\x83\xc0\x01',2),(2,b'\x48\x39\xc8',3)):
        slots.append(body+jump(generated+512*i+len(body),generated+512*next_head))
    at=generated+1536
    slots.append(b'\x0f\x82'+struct.pack('<i',generated+2048-at-6)+jump(at+6,page+0x210))
    slots.append(b'\x48\x83\xc7\x08'+jump(generated+2052,generated+2560))
    slots.append(jump(generated+2560,generated))
    code=b''.join(s+b'\xcc'*(512-len(s))for s in slots)+b'\xcc'*(32768-6*512)
    heads=((2,0,0x200,3,1,1,0,len(g)),(1,0,0x203,4,1,2,0,9),
        (1,0,0x207,3,1,3,0,8),(1,0,0x20a,6,2,4,64,11),
        (1,1,0x100,4,1,5,0,9),(1,1,0x104,5,1,0,0,5))
    return dict(code=code,heads=b''.join(struct.pack('<8I',*h)for h in heads)+bytes(32*58),
        guard=g,boundaries=b''.join(struct.pack('<6I',*r)for r in rows)+bytes(24*(64-len(rows))),
        store=store,reject=reject,rows=rows)


# Exact source-derived descriptor model. Code numbers are iced1.21.0; the
# old decoder/region/tf functions remain the actual production producers.
def reg(r,w,a):return (0,1,r,w,a,0,0)

def imm(v,w,b):return (v&U64,3,0,w,1,b,0)

def ins(raw,code,ops=(),flags=(0,0,0,0,0),address=None,reloc=0,step=0,flow=0,target=0,condition=16):
    return dict(raw=bytes.fromhex(raw) if isinstance(raw,str) else raw,code=code,ops=ops,flags=flags,address=address,reloc=reloc,step=step,flow=flow,target=target,condition=condition)

def descriptor(row,pc,source,offset,refusal=0):
    d=bytearray(336);raw=row['raw'];length=len(raw)
    struct.pack_into('<QQ10I',d,0,pc,pc+length,1,0,row['code'],0,16,0,row['step'],15,length,0)
    d[56:72]=source[offset:offset+15]+b'\0'
    struct.pack_into('<I',d,256,1)
    if refusal:struct.pack_into('<I',d,264,refusal);return bytes(d)
    struct.pack_into('<Q',d,72,row['target'])
    regs=[]
    for i,o in enumerate(row['ops']):
        struct.pack_into('<Q6I',d,80+i*32,*o)
        _,kind,r,w,a,_,_=o
        if kind==1 and a:
            if w==32 and a==3:regs += [(r,32,1,0),(r,64,2,0)]
            else:regs.append((r,64 if w==32 and a==2 else w,a,0))
        elif kind in (2,5):
            for r in row['address'][1:3]:
                if r!=16:regs.append((r,row['ops'][0][3] if kind==5 else 64,1,0))
    for i,r in enumerate(regs):struct.pack_into('<4I',d,144+i*16,*r)
    address=row['address'];memory=int(address is not None and address[7]==1)
    if address:struct.pack_into('<Q8I',d,208,*address)
    if row['reloc']:
        struct.pack_into('<Q',d,248,address[0]);struct.pack_into('<3I',d,320,1,row['reloc'],4)
    struct.pack_into('<9I',d,256,1,1,0,row['flow'],row['condition'],len(row['ops']),len(regs),memory,int(address is not None))
    struct.pack_into('<5I',d,292,*row['flags'])
    read=write=0
    for r,_,a,_ in regs:
        if a&1:read|=1<<r
        if a&2:write|=1<<r
    struct.pack_into('<2I',d,312,read,write)
    return bytes(d)

def descriptors(source,page):
    arithmetic=(0,0x8d5,0,0,0)
    rows=(ins('488907',282),ins('4883c001',249,(reg(0,64,3),imm(1,64,8)),arithmetic),
          ins('4839c8',110,(reg(0,64,1),reg(1,64,1)),arithmetic),
          ins(source[0x20a:0x210],1862,((page+0x1100,4,0,64,1,32,0),),(1,0,0,0,0),flow=1,target=page+0x1100,condition=2),
          ins('4883c708',249,(reg(7,64,3),imm(8,64,8)),arithmetic),
          ins(source[0x1104:0x1109],696,((page+0x200,4,0,64,1,32,0),),flow=2,target=page+0x200))
    offsets=(0x200,0x203,0x207,0x20a,0x1100,0x1104)
    # Actual scalar-span refusal codes: memory-destination MOV is OPERANDS5;
    # the indirect JMP frontier is UNSUPPORTED1. Neither is a ready NONE head.
    original=[]
    for i,(off,row) in enumerate(zip(offsets,rows,strict=True)):
        need(source[off:off+len(row['raw'])]==row['raw'],'actual fixed descriptor bytes')
        original.append(descriptor(row,page+off,source,off,refusal=5 if i==0 else 0))
    frontier=descriptor(ins('ff2500000000',765),page+0x210,source,0x210,refusal=1)
    return b''.join(original)+bytes(58*336),frontier+bytes(7*336)
