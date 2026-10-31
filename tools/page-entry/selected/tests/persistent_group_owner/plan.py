"""Independent65-head loop graph: two immutable images, two typed links, one original exit."""
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

def loop(source,page,layout):
    """Literal original source model, then separately assembled member/stub images."""
    a,b,stubs,slots,spill=layout
    need(len(source)==8192 and all(4096<=v<1<<47 and v%4096==0 for v in layout),'actual complete group geometry')
    offsets=list(range(0xe00,0xe78,4))+[0xe78]+list(range(0x1100,0x117c,4))+[0x117c,0xf00,0xf04]
    need(len(offsets)==65,'exact global BFS loop population')
    heads=[];descriptors=[];images=[bytearray(b'\xcc'*32768),bytearray(b'\xcc'*32768)]
    arithmetic=(0,0x8d5,0,0,0)
    def jump(pc,target):return b'\xe9'+struct.pack('<i',target-pc-5)
    for i,off in enumerate(offsets):
        pc=page+off;at=(a if i<64 else b)+512*(i%64)
        if i==30 or i==62:
            target=page+(0x1100 if i==30 else 0xf00)
            row=ins(b'\xe9'+struct.pack('<i',target-pc-5),696,((target,4,0,64,1,32,0),),flow=2,target=target)
            emitted=jump(at,a+512*(i+1));succ=(i+1,0);count=1
        elif i==64:
            target=page+0xe00
            row=ins(b'\x0f\x85'+struct.pack('<i',target-pc-6),1871,((target,4,0,64,1,32,0),),(0x40,0,0,0,0),flow=1,target=target,condition=5)
            emitted=b'\x0f\x85'+struct.pack('<i',stubs+6-at-6)+jump(at+6,page+0xf0a);succ=(0,128);count=2
        else:
            sub=i==63;raw=bytes.fromhex('4883e901'if sub else'4883c001');regno=1 if sub else 0
            row=ins(raw,264 if sub else 249,(reg(regno,64,3),imm(1,64,8)),arithmetic)
            emitted=raw+jump(at+4,stubs if sub else a+512*(i+1));succ=(i+1,0);count=1
        need(source[off:off+len(row['raw'])]==row['raw'],'complete actual loop head encoding')
        descriptors.append(descriptor(row,pc,source,off))
        heads.append(struct.pack('<8I',1,off//4096,off%4096,len(row['raw']),count,*succ,len(emitted)))
        images[i//64][512*(i%64):512*(i%64)+len(emitted)]=emitted
    frontier=descriptor(ins('4987ca',278),page+0xf0a,source,0xf0a,refusal=1)
    edge=struct.pack('<4I4Q',1,63,0,64,page+0xf04,b,stubs,slots)+struct.pack('<4I4Q',1,64,0,0,page+0xe00,a,stubs+6,slots+8)+bytes(6*48)
    stub=b'\xff\x25'+struct.pack('<i',slots-stubs-6)+b'\xff\x25'+struct.pack('<i',slots+8-stubs-12)+b'\xcc'*(4096-12)
    return dict(head=b''.join(heads)+bytes(63*32),original=b''.join(descriptors)+bytes(63*336),frontier=frontier+bytes(7*336),
                image=bytes(images[0]+images[1]),stub_image=stub,edge=edge,
                initial_slots=struct.pack('<2Q',b,a)+bytes(4080),terminal_slots=struct.pack('<2Q',page+0xf04,page+0xe00)+bytes(4080),source_bytes=264)
