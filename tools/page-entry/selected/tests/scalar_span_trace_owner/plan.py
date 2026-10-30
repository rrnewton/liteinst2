"""Fixed31-byte TRACE fixture model; never executes a decoder or guest data."""
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


OFFSETS=(0,5,10,13,16,23,27,29)
LENGTHS=(5,5,3,3,7,4,2,2)
GENERATED=(0,5,10,13,16,23,27,33)

def plan(source,page,entry,generated):
    need(type(source)is bytes and len(source)==4096 and entry==page+0x200 and page%4096==generated%4096==0 and 4096<=page<1<<31 and 4096<=generated<1<<31 and page!=generated,'exact fixture plan placement')
    rows=[ins('b807000000',357,(reg(0,32,2),imm(7,32,32)),step=1),
          ins('488d544803',292,(reg(2,64,2),memop(64,True)),address=memory(0,1,2,3,0,True)),
          ins('4801d0',8,(reg(0,64,3),reg(2,64,1)),ARITH),
          ins('448b07',285,(reg(8,32,2),memop(32)),address=memory(7,16,1,0,4)),
          ins('448b0d69000000',285,(reg(9,32,2),memop(32)),address=memory(16,16,1,page+0x280,4),reloc=3),
          ins('4883f80f',270,(reg(0,64,1),imm(15,64,8)),ARITH),
          ins('7453',173,((page+0x270,4,0,64,1,8,0),),(ZF,0,0,0,0),flow=1,target=page+0x270,condition=4),
          ins('eb31',701,((page+0x250,4,0,64,1,8,0),),flow=2,target=page+0x250)]
    image=bytearray(b'\xcc'*4096)
    for i,row in enumerate(rows):
        off=GENERATED[i];raw=row['raw'];need(raw==source[0x200+OFFSETS[i]:0x200+OFFSETS[i]+LENGTHS[i]],'each exact original instruction')
        if row['flow']:
            prefix=b'\x0f\x84'if row['flow']==1 else b'\xe9'
            raw=prefix+struct.pack('<i',row['target']-generated-off-len(prefix)-4)
        elif row['reloc']:raw=raw[:3]+struct.pack('<i',page+0x280-generated-off-7)
        image[off:off+len(raw)]=raw
    result=bytearray(57184)
    struct.pack_into('<12I4Q',result,0,1,1,8,2,2,8,8,1,31,38,17,0,page,entry,generated,entry+31)
    result[80:4176]=source;result[4176:8272]=image
    for i,row in enumerate(rows):
        off=OFFSETS[i];g=GENERATED[i];n=6 if i==6 else 5 if i==7 else LENGTHS[i]
        result[8272+i*336:8272+(i+1)*336]=descriptor(row,entry+off,source,0x200+off)
        emitted=dict(row,raw=bytes(image[g:g+n]))
        if row['flow']:emitted.update(code=1868 if i==6 else 696,ops=((row['target'],4,0,64,1,32,0),))
        result[30112+i*336:30112+(i+1)*336]=descriptor(emitted,generated+g,image,g)
        successors=(64,7)if i==6 else (65,)if i==7 else (i+1,)
        struct.pack_into('<8I',result,51952+i*32,0x200+off,LENGTHS[i],g,n,len(successors),*successors,*([0]*(2-len(successors))),int(i==7))
        struct.pack_into('<8I2Q',result,54064+i*48,1,1,i,2 if i>=6 else 4 if i==4 else 1,0x200+off,LENGTHS[i],g,n,entry+off,generated+g)
    result[29776:30112]=descriptor(ins('cc',420),entry+31,source,0x21f,True)
    struct.pack_into('<2Q',result,54000,page+0x270,page+0x250)
    return bytes(result),bytes(image)
