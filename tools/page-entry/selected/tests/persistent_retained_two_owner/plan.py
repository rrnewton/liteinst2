"""Independent complete two-head ADD graph and real memory-JMP frontier model."""
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

def graph(source,page,entry,layout):
    """Exact A or B prefix; no target is inferred for the ordinary memory JMP."""
    a,b,stubs,slots,spill=layout
    need(len(source)==8192 and entry-page in(0x200,0x400) and
         all(4096<=v<1<<47 and v%4096==0 for v in layout),'actual complete retained source/bank geometry')
    root=entry-page;constant=1 if root==0x200 else 2
    images=[bytearray(b'\xcc'*32768),bytearray(b'\xcc'*32768)]
    rows=(ins(bytes.fromhex('4883c0')+bytes([constant]),249,(reg(0,64,3),imm(constant,64,8)),(0,0x8d5,0,0,0)),
          ins('4883c208',249,(reg(2,64,3),imm(8,64,8)),(0,0x8d5,0,0,0)))
    originals=[];heads=[]
    for i,row in enumerate(rows):
        off=root+4*i;pc=page+off;generated=a+512*i
        destination=a+512 if i==0 else entry+8
        need(source[off:off+4]==row['raw'],'actual complete retained ADD head')
        emitted=row['raw']+b'\xe9'+struct.pack('<i',destination-generated-9)
        images[0][512*i:512*i+9]=emitted
        originals.append(descriptor(row,pc,source,off))
        heads.append(struct.pack('<8I',1,0,off,4,1,1 if i==0 else 128,0,9))
    need(source[root+8:root+10]==b'\xff\x22','actual ordinary memory-JMP frontier')
    frontier=descriptor(ins('ff22',765),entry+8,source,root+8,refusal=1)
    return dict(head=b''.join(heads)+bytes(126*32),original=b''.join(originals)+bytes(126*336),
        frontier=frontier+bytes(7*336),instruction=bytes(128*144),guard=bytes(128*1584),
        image=bytes(images[0]+images[1]),stub_image=b'\xcc'*4096,edge=bytes(8*48),
        initial_slots=bytes(4096),terminal_slots=bytes(4096),source_bytes=8)
