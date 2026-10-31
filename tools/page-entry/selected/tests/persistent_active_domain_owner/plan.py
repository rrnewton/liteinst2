"""Independent A/B graphs and sealed-directory register-dispatch image model."""
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

def dispatch(pc,source,offset,generated,spill,directory,target):
    """Two literal fixture forms; all generated boundaries independently listed.
    Directory membership, never a guessed register target, determines a hit."""
    need(target in(2,3),'fixture dispatch uses only actual RDX/RBX forms')
    E=3 if target==2 else 2
    def rel(prefix,next_,dest):return bytes.fromhex(prefix)+struct.pack('<i',dest-generated-next_)
    def restore(at):
        return b'\x04\x7f\x9e'+rel('488b0d',at+10,spill+8)+rel('488b1d'if E==3 else'488b15',at+17,spill+16)+rel('488b2d',at+24,spill+24)+rel('488b05',at+31,spill)
    image=(rel('488905',7,spill)+rel('48890d',14,spill+8)+rel('48891d'if E==3 else'488915',21,spill+16)+rel('48892d',28,spill+24)+
        bytes.fromhex('4889d5'if target==2 else'4889dd')+bytes.fromhex('9f0f90c0')+b'\x48\xb9'+struct.pack('<Q',directory)+
        bytes.fromhex('488b5908'if E==3 else'488b5108')+bytes.fromhex('4881fb01000000'if E==3 else'4881fa01000000')+rel('0f82',62,generated+115)+
        bytes.fromhex('4881fb00010000'if E==3 else'4881fa00010000')+rel('0f87',75,generated+115)+bytes.fromhex('4881c120000000')+
        bytes.fromhex('48c1e3054803d9'if E==3 else'48c1e2054803d1')+bytes.fromhex('483b6900')+rel('0f84',99,generated+151)+
        bytes.fromhex('4881c120000000')+bytes.fromhex('483bcb'if E==3 else'483bca')+rel('0f82',115,generated+89)+restore(115)+rel('e9',151,pc)+
        bytes.fromhex('488b4908')+rel('48890d',162,spill+32)+restore(162)+rel('ff25',199,spill+32))
    boundary=(
        (0,7,0,0,0,0),(7,7,1,0,0,0),(14,7,3,0,0,0),(21,7,7,0,0,0),
        (28,3,15,0,0,0),(31,1,15,8,0,0),(32,3,15,9,1,0),(35,10,15,9,2,0),
        (45,4,15,11,2,0),(49,7,15,15,2,0),(56,6,15,15,2,0),(62,7,15,15,2,0),
        (69,6,15,15,2,0),(75,7,15,15,2,0),(82,4,15,15,2,0),(86,3,15,15,2,0),
        (89,4,15,15,2,0),(93,6,15,15,2,0),(99,7,15,15,2,0),(106,3,15,15,2,0),(109,6,15,15,2,0),
        (115,2,15,15,2,0),(117,1,15,15,1,0),(118,7,15,15,0,0),(125,7,15,13,0,0),(132,7,15,9,0,0),(139,7,15,1,0,0),(146,5,15,0,0,0),
        (151,4,15,15,2,0),(155,7,15,15,2,0),(162,2,15,15,2,1),(164,1,15,15,1,1),(165,7,15,15,0,1),(172,7,15,13,0,1),(179,7,15,9,0,1),(186,7,15,1,0,1),(193,6,15,0,0,1))
    need(len(image)==199 and len(boundary)==37 and all(a+n==b for(a,n,*_), (b,*_)in zip(boundary,boundary[1:])),'whole fixed domain dispatch encoding/boundaries')
    raw=bytes((0xff,0xe0+target));original=descriptor(ins(raw,765),pc,source,offset,refusal=1)
    description=original[:72]+struct.pack('<QQ6I',pc,pc+2,1,1,765,2,2,3)+struct.pack('<8I',2,1,0,15,target,0,0,0)
    record=struct.pack('<12I',2,1,0,199,37,193,146,0,0,1,E,5)+b''.join(struct.pack('<6I',*r)for r in boundary)+bytes(27*24)
    need(len(description)==144 and len(record)==1584,'whole typed domain descriptor and recovery record')
    return image,description,record

def graph(source,page,entry,layout):
    a,b,stubs,slots,spill,directory=layout
    need(len(source)==8192 and entry-page in(0x200,0x400)and all(4096<=v<1<<47 and v%4096==0 for v in layout),'actual complete domain source/bank geometry')
    offsets=(0x200,0x204)if entry-page==0x200 else(0x400,0x404,0x408,0x40d,0x40a)
    images=[bytearray(b'\xcc'*32768),bytearray(b'\xcc'*32768)];originals=[];heads=[]
    instructions=bytearray(128*144);guards=bytearray(128*1584);frontier=None
    def jump(at,dest):return b'\xe9'+struct.pack('<i',dest-at-5)
    for i,off in enumerate(offsets):
        pc=page+off;at=a+512*i;kind=1;count=1;succ=(i+1,0);refusal=0
        if off in(0x204,0x40d):
            kind=3;count=0;succ=(0,0);refusal=1;target=2 if off==0x204 else 3
            row=ins(bytes((0xff,0xe0+target)),765)
            emitted,typed,record=dispatch(pc,source,off,at,spill,directory,target)
            instructions[i*144:(i+1)*144]=typed;guards[i*1584:(i+1)*1584]=record
        elif off==0x408:
            row=ins('7503',176,((page+0x40d,4,0,64,1,8,0),),(0x40,0,0,0,0),flow=1,target=page+0x40d,condition=5)
            count=2;succ=(3,4);emitted=b'\x0f\x85'+struct.pack('<i',a+3*512-at-6)+jump(at+6,a+4*512)
        elif off==0x40a:
            row=ins('4889f3',282,(reg(3,64,2),reg(6,64,1)),step=1);succ=(3,0);emitted=row['raw']+jump(at+3,a+3*512)
        else:
            sub=off==0x404;constant=2 if off==0x400 else 1
            row=ins('4883e901'if sub else bytes.fromhex('4883c0')+bytes([constant]),264 if sub else 249,(reg(1 if sub else 0,64,3),imm(constant,64,8)),(0,0x8d5,0,0,0))
            emitted=row['raw']+jump(at+4,a+(i+1)*512)
        need(source[off:off+len(row['raw'])]==row['raw'],'complete actual domain head encoding')
        desc=descriptor(row,pc,source,off,refusal=refusal);originals.append(desc)
        if refusal:frontier=desc
        heads.append(struct.pack('<8I',kind,0,off,len(row['raw']),count,*succ,len(emitted)));images[0][512*i:512*i+len(emitted)]=emitted
    n=len(offsets);need(frontier is not None,'one real unknown-target dispatch exit')
    return dict(head=b''.join(heads)+bytes((128-n)*32),original=b''.join(originals)+bytes((128-n)*336),frontier=frontier+bytes(7*336),
        instruction=bytes(instructions),guard=bytes(guards),image=bytes(images[0]+images[1]),stub_image=b'\xcc'*4096,edge=bytes(8*48),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source_bytes=6 if n==2 else 15,heads=n,exit_pc=entry+(4 if n==2 else 13))
