"""Independent70-head resident graph and exact RDX dispatch image/recovery model."""
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

def dispatch(pc,source,offset,generated,spill,rows,images):
    """Fixed RDX form, literal instructions and pre-instruction recovery rows.
    The dynamic target is never guessed; the retained source row table supplies
    exact original-head membership. Neither this model nor metadata runs code.
    """
    def rel(prefix,at,next_,target):return bytes.fromhex(prefix)+struct.pack('<i',target-(generated+next_))
    bodies=(
      rel('488905',0,7,spill),rel('48890d',7,14,spill+8),rel('48891d',14,21,spill+16),rel('48892d',21,28,spill+24),
      bytes.fromhex('4889d59f0f90c0'),b'\x48\xb9'+struct.pack('<Q',rows),b'\x48\xbb'+bytes(8),
      bytes.fromhex('483b6900'),rel('0f84',59,65,generated+128),bytes.fromhex('4881c1500100004881c3010000004881fb46000000'),
      rel('0f82',86,92,generated+55),bytes.fromhex('047f9e'),
      rel('488b0d',95,102,spill+8),rel('488b1d',102,109,spill+16),rel('488b2d',109,116,spill+24),rel('488b05',116,123,spill),
      rel('e9',123,128,pc),bytes.fromhex('4881fb40000000'),rel('0f82',135,141,generated+163),bytes.fromhex('4881eb40000000'),
      b'\x48\xb9'+struct.pack('<Q',images[1]),rel('e9',158,163,generated+173),b'\x48\xb9'+struct.pack('<Q',images[0]),
      bytes.fromhex('48c1e3094803cb'),rel('48890d',180,187,spill+32),bytes.fromhex('047f9e'),
      rel('488b0d',190,197,spill+8),rel('488b1d',197,204,spill+16),rel('488b2d',204,211,spill+24),rel('488b05',211,218,spill),rel('ff25',218,224,spill+32))
    image=b''.join(bodies)
    boundary=(
      (0,7,0,0,0,0),(7,7,1,0,0,0),(14,7,3,0,0,0),(21,7,7,0,0,0),
      (28,3,15,0,0,0),(31,1,15,8,0,0),(32,3,15,9,1,0),(35,10,15,9,2,0),(45,10,15,11,2,0),
      (55,4,15,15,2,0),(59,6,15,15,2,0),(65,7,15,15,2,0),(72,7,15,15,2,0),(79,7,15,15,2,0),(86,6,15,15,2,0),
      (92,2,15,15,2,0),(94,1,15,15,1,0),(95,7,15,15,0,0),(102,7,15,13,0,0),(109,7,15,9,0,0),(116,7,15,1,0,0),(123,5,15,0,0,0),
      (128,7,15,15,2,0),(135,6,15,15,2,0),(141,7,15,15,2,0),(148,10,15,15,2,0),(158,5,15,15,2,0),(163,10,15,15,2,0),
      (173,4,15,15,2,0),(177,3,15,15,2,0),(180,7,15,15,2,0),(187,2,15,15,2,1),(189,1,15,15,1,1),
      (190,7,15,15,0,1),(197,7,15,13,0,1),(204,7,15,9,0,1),(211,7,15,1,0,1),(218,6,15,0,0,1))
    need(len(image)==224 and len(boundary)==38 and all(a+n==b for(a,n,*_), (b,*_)in zip(boundary,boundary[1:])),'whole fixed resident dispatch encoding/boundaries')
    original=descriptor(ins('ffe2',765),pc,source,offset,refusal=1)
    description=original[:72]+struct.pack('<QQ6I',pc,pc+2,1,1,765,2,2,3)+struct.pack('<8I',1,1,0,15,2,0,0,0)
    record=struct.pack('<12I',1,1,0,224,38,218,123,0,0,1,3,5)+b''.join(struct.pack('<6I',*r)for r in boundary)+bytes(26*24)
    need(len(description)==144 and len(record)==1584,'whole typed resident descriptor and recovery record')
    return image,description,record


def loop(source,page,layout,table_address):
    a,b,stubs,slots,spill=layout
    need(len(source)==8192 and all(4096<=v<1<<47 and v%4096==0 for v in layout),'actual complete resident geometry')
    offsets=list(range(0xe00,0xe78,4))+[0xe78]+list(range(0x1100,0x117c,4))+[0x117c,0xf00,0xf04,0xf0a,0xf0f,0xf12,0xf15,0xf18]
    need(len(offsets)==70,'exact global BFS resident population')
    rows=table_address-64576
    need(0<rows<1<<47 and rows%8==0,'actual immutable original-row relation')
    heads=[];descriptors=[];images=[bytearray(b'\xcc'*32768),bytearray(b'\xcc'*32768)]
    arithmetic=(0,0x8d5,0,0,0)
    def target(i):return(a if i<64 else b)+512*(i%64)
    def jump(pc,target):return b'\xe9'+struct.pack('<i',target-pc-5)
    instruction=bytearray(128*144);guards=bytearray(128*1584)
    for i,off in enumerate(offsets):
        pc=page+off;at=target(i);kind=1;refusal=0
        if i==30 or i==62:
            dest=page+(0x1100 if i==30 else 0xf00)
            row=ins(b'\xe9'+struct.pack('<i',dest-pc-5),696,((dest,4,0,64,1,32,0),),flow=2,target=dest)
            emitted=jump(at,target(i+1));succ=(i+1,0);count=1
        elif i==64:
            dest=page+0xe00
            row=ins(b'\x0f\x85'+struct.pack('<i',dest-pc-6),1871,((dest,4,0,64,1,32,0),),(0x40,0,0,0,0),flow=1,target=dest,condition=5)
            emitted=b'\x0f\x85'+struct.pack('<i',stubs+6-at-6)+jump(at+6,target(65));succ=(0,65);count=2
        elif i==65:
            row=ins('b902000000',357,(reg(1,32,2),imm(2,32,32)),step=1)
            emitted=row['raw']+jump(at+5,target(66));succ=(66,0);count=1
        elif 66<=i<=68:
            raw,dest,src=(('4989d2',10,2),('4889da',2,3),('4c89d3',3,10))[i-66]
            row=ins(raw,282,(reg(dest,64,2),reg(src,64,1)),step=1)
            emitted=row['raw']+jump(at+3,target(i+1));succ=(i+1,0);count=1
        elif i==69:
            kind=3;refusal=1;row=ins('ffe2',765);count=0;succ=(0,0)
            emitted,typed,record=dispatch(pc,source,off,at,spill,rows,(a,b))
            instruction[i*144:(i+1)*144]=typed;guards[i*1584:(i+1)*1584]=record
        else:
            sub=i==63;row=ins('4883e901'if sub else'4883c001',264 if sub else 249,(reg(1 if sub else 0,64,3),imm(1,64,8)),arithmetic)
            emitted=row['raw']+jump(at+4,stubs if sub else target(i+1));succ=(i+1,0);count=1
        need(source[off:off+len(row['raw'])]==row['raw'],'complete actual resident head encoding')
        descriptors.append(descriptor(row,pc,source,off,refusal=refusal));heads.append(struct.pack('<8I',kind,off//4096,off%4096,len(row['raw']),count,*succ,len(emitted)))
        images[i//64][512*(i%64):512*(i%64)+len(emitted)]=emitted
    edge=struct.pack('<4I4Q',1,63,0,64,page+0xf04,b,stubs,slots)+struct.pack('<4I4Q',1,64,0,0,page+0xe00,a,stubs+6,slots+8)+bytes(6*48)
    stub=b'\xff\x25'+struct.pack('<i',slots-stubs-6)+b'\xff\x25'+struct.pack('<i',slots+8-stubs-12)+b'\xcc'*(4096-12)
    return dict(head=b''.join(heads)+bytes(58*32),original=b''.join(descriptors)+bytes(58*336),frontier=descriptors[-1]+bytes(7*336),
        instruction=bytes(instruction),guard=bytes(guards),image=bytes(images[0]+images[1]),stub_image=stub,edge=edge,
        initial_slots=struct.pack('<2Q',b,a)+bytes(4080),terminal_slots=struct.pack('<2Q',page+0xf04,page+0xe00)+bytes(4080),source_bytes=280)
