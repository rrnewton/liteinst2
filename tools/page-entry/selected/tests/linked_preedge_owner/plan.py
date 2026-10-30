"""Fixed independent noncontiguous graph/image/40744-byte plan oracle.
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
    struct.pack_into('<QQ10I',d,0,pc,pc+length,1,0,row['code'],0,16,0,row['step'],min(15,4096-offset),length,0)
    available=min(15,4096-offset);d[56:72]=source[offset:offset+available]+bytes(16-available)
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


def plan(source,page,entry,generated,mode):
    need(type(mode)is int and mode in range(4)and type(source)is bytes and len(source)==4096 and page%4096==generated%4096==0 and 4096<=page<1<<31 and 4096<=generated<1<<31 and page!=generated and entry==page+(4060 if mode<2 else 4064),'exact finite v2 placement and original source')
    start=entry-page;cut=entry+30;row=ins('b807000000',357,(reg(0,32,2),imm(7,32,32)),step=1)
    if mode<2:
        frontier=ins(b'\x0f\x85'+struct.pack('<i',3968-4096),1871,((page+3968,4,0,64,1,32,0),),(ZF,0,0,0,0),flow=1,target=page+3968,condition=5)
    elif mode==2:frontier=ins('31c0',96,(reg(0,32,2),reg(0,32,0)),(0,0,PF|ZF,CF|SF|OF,AF))
    else:frontier=ins('6690',299,step=1)
    need(source[start:start+30]==row['raw']*6 and source[cut-page:cut-page+len(frontier['raw'])]==frontier['raw'],'actual whole prefix and whole cut instruction')
    image=bytearray(b'\xcc'*4096);maps=[];heads={}
    for i in range(6):
        off=start+5*i;g=10*i;dest=generated+g+10 if i<5 else cut;original=page+off+5
        image[g:g+5]=row['raw'];image[g+5:g+10]=b'\xe9'+struct.pack('<i',dest-generated-g-10)
        maps += [(1,1,i,1,off,5,g,5,page+off,generated+g),(1,1,i,3,original-page,0,g+5,5,original,generated+g+5)]
        heads[off]=dict(head=i,offset=g,length=5)
    out=bytearray(40744);struct.pack_into('<12I3Q',out,0,2,40744,1,6,1,12,6,0,30,60,19,0,page,entry,generated)
    out[72:4168]=source;out[4168:8264]=image
    for i in range(6):
        off=start+5*i;out[8264+i*336:8264+(i+1)*336]=descriptor(row,page+off,source,off)
        struct.pack_into('<8I',out,32456+i*32,off,5,i*10,5,1,i+1 if i<5 else 64,0,i)
    out[29768:30104]=descriptor(frontier,cut,source,cut-page,refusal=mode==3)
    struct.pack_into('<Q',out,34504,cut)
    for i,m in enumerate(maps):struct.pack_into('<8I2Q',out,34568+i*48,*m)
    struct.pack_into('<I',out,40712,1 if mode==3 else 2)
    return bytes(out),bytes(image),heads
