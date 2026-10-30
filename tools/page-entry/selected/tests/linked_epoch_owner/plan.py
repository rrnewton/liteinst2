"""Fixed independent noncontiguous graph/image/40704-byte plan oracle.
This module never imports/calls an actual decoder or grants execution authority."""
import struct
U64=(1<<64)-1
CF,PF,AF,ZF,SF,OF=1,4,16,64,128,2048
ARITH=(0,CF|PF|AF|ZF|SF|OF,0,0,0)
def need(ok,why):
    if not ok:raise ValueError(why)

def reg(r,w,a):return (0,1,r,w,a,0,0)

def imm(v,w,b):return (v&U64,3,0,w,1,b,0)

def memory(base,index,scale,disp,width,lea=False):
    return (disp&U64,base,index,scale,width,64,0 if lea else 1,7 if lea else 1,0)

def ins(raw,code,ops=(),flags=(0,0,0,0,0),address=None,reloc=0,step=0,flow=0,target=0,condition=16):
    return dict(raw=bytes.fromhex(raw) if isinstance(raw,str) else raw,code=code,ops=ops,flags=flags,address=address,reloc=reloc,step=step,flow=flow,target=target,condition=condition)

def memop(w,lea=False):return (0,5 if lea else 2,0,w,7 if lea else 1,0,0)

def descriptor(row,pc,source,offset,refusal=False):
    d=bytearray(336);raw=row['raw'];length=len(raw)
    struct.pack_into('<QQ10I',d,0,pc,pc+length,1,0,row['code'],0,16,0,row['step'],15,length,0)
    d[56:72]=source[offset:offset+15]+b'\0'
    struct.pack_into('<I',d,256,1)
    if refusal:struct.pack_into('<I',d,264,1);return bytes(d)
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

ORDER=(0x200,0x205,0x207,0x400,0x20d,0x403,0x300,0x406,0x303,0x409,0x308,0x500,0x503,0x50a,0x50d,0x513)
SUCCESSORS=((1,),(2,),(3,4),(5,),(6,),(7,),(8,),(9,),(10,),(11,),(11,),(12,),(13,),(14,),(64,15),(65,))

def plan(source,page,entry,generated):
    need(type(source)is bytes and len(source)==4096 and entry==page+0x200 and
         page%4096==generated%4096==0 and 4096<=page<1<<31 and 4096<=generated<1<<31 and page!=generated,
         'exact finite source/generated placement; no relocation tolerance')
    def branch(raw,code,target,condition=16):
        return ins(raw,code,((page+target,4,0,64,1,32,0),),(ZF,0,0,0,0)if condition!=16 else(0,0,0,0,0),
                   flow=1 if condition!=16 else 2,target=page+target,condition=condition)
    rows={
      0x200:ins('b807000000',357,(reg(0,32,2),imm(7,32,32)),step=1),
      0x205:ins('85f6',273,(reg(6,32,1),reg(6,32,1)),(0,SF|ZF|PF,0,CF|OF,AF)),
      0x207:branch('0f84f3010000',1868,0x400,4),0x20d:branch('e9ee000000',696,0x300),
      0x300:ins('448b07',285,(reg(8,32,2),memop(32)),address=memory(7,16,1,0,4)),
      0x303:ins('488d444802',292,(reg(0,64,2),memop(64,True)),address=memory(0,1,2,2,0,True)),
      0x308:branch('e9f3010000',696,0x500),
      0x400:ins('448b07',285,(reg(8,32,2),memop(32)),address=memory(7,16,1,0,4)),
      0x403:ins('4531c9',96,(reg(9,32,2),reg(9,32,0)),(0,0,PF|ZF,CF|SF|OF,AF)),
      0x406:ins('4801d0',8,(reg(0,64,3),reg(2,64,1)),ARITH),0x409:branch('e9f2000000',696,0x500),
      0x500:ins('458b12',285,(reg(10,32,2),memop(32)),address=memory(10,16,1,0,4)),
      0x503:ins('448b1df6010000',285,(reg(11,32,2),memop(32)),address=memory(16,16,1,page+0x700,4),reloc=3),
      0x50a:ins('83f80f',269,(reg(0,32,1),imm(15,32,8)),ARITH),
      0x50d:branch('0f850d010000',1871,0x620,5),0x513:branch('e9e8000000',696,0x600)}
    sequence=[rows[x]for x in ORDER];offsets=[];at=0
    for row in sequence:offsets.append(at);at+=len(row['raw'])+(0 if row['flow']==2 else 5)
    need(at==129,'all69 original bytes and12 explicit continuation links')
    exits=(page+0x620,page+0x600);image=bytearray(b'\xcc'*4096);maps=[]
    def destination(index):return generated+offsets[index]if index<64 else exits[index-64]
    def original(index):return page+ORDER[index]if index<64 else exits[index-64]
    for i,(off,row,succ)in enumerate(zip(ORDER,sequence,SUCCESSORS,strict=True)):
        raw=row['raw'];g=offsets[i];n=len(raw)
        need(raw==source[off:off+n],'each actual source instruction, no gap instruction selected')
        if row['flow']:
            prefix=b'\x0f'+bytes([0x80+row['condition']])if row['flow']==1 else b'\xe9'
            raw=prefix+struct.pack('<i',destination(succ[0])-generated-g-n)
        elif row['reloc']:raw=raw[:3]+struct.pack('<i',page+0x700-generated-g-7)
        image[g:g+n]=raw;maps.append((1,1,i,2 if row['flow']else 4 if row['reloc']else 1,off,n,g,n,page+off,generated+g))
        if row['flow']!=2:
            k=succ[1]if row['flow']==1 else succ[0];image[g+n:g+n+5]=b'\xe9'+struct.pack('<i',destination(k)-generated-g-n-5)
            maps.append((1,1,i,3,original(k)-page,0,g+n,5,original(k),generated+g+n))
    need(len(maps)==28,'all actual and synthetic exact-PC rows')
    out=bytearray(40704);struct.pack_into('<10I3Q',out,0,1,1,16,2,28,12,69,129,46,0,page,entry,generated)
    out[64:4160]=source;out[4160:8256]=image
    for i,(off,row,succ)in enumerate(zip(ORDER,sequence,SUCCESSORS,strict=True)):
        out[8256+i*336:8256+(i+1)*336]=descriptor(row,page+off,source,off)
        struct.pack_into('<8I',out,32448+i*32,off,len(row['raw']),offsets[i],len(row['raw']),len(succ),*succ,*([0]*(2-len(succ))),i)
    for i,(off,row)in enumerate(((0x620,ins('ff2500000000',765)),(0x600,ins('6690',299,step=1)))):
        out[29760+i*336:29760+(i+1)*336]=descriptor(row,page+off,source,off,refusal=True)
    struct.pack_into('<2Q',out,34496,*exits)
    for i,row in enumerate(maps):struct.pack_into('<8I2Q',out,34560+i*48,*row)
    return bytes(out),bytes(image),{ORDER[i]:dict(head=i,offset=offsets[i],length=len(row['raw']))for i,row in enumerate(sequence)}
