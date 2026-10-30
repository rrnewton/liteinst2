"""Independent fixed hardware-puzzle descriptor/image model; no data execution."""
import struct
U64=(1<<64)-1
CF,PF,AF,ZF,SF,OF=1,4,16,64,128,2048
SHIFT_CODES=(((447, 380, 479), (448, 381, 480)), ((450, 383, 482), (451, 384, 483)), ((456, 389, 488), (457, 390, 489)))
ARITH=(0,CF|PF|AF|ZF|SF|OF,0,0,0)
LOGIC=(0,PF|ZF|SF,0,CF|OF,AF)

def reg(r,w,a):return (0,1,r,w,a,0,0)
def imm(v,w,b):return (v&U64,3,0,w,1,b,0)
def memory(base,index,scale,disp,width,lea=False):
    return (disp&U64,base,index,scale,width,64,0 if lea else 1,7 if lea else 1,0)
def ins(raw,code,ops=(),flags=(0,0,0,0,0),address=None,reloc=0,step=0,flow=0,target=0,condition=16):
    return dict(raw=bytes.fromhex(raw) if isinstance(raw,str) else raw,code=code,ops=ops,flags=flags,address=address,reloc=reloc,step=step,flow=flow,target=target,condition=condition)
def memop(w,lea=False):return (0,5 if lea else 2,0,w,7 if lea else 1,0,0)

def puzzle(h):
    mode,page,data=h[3],h[8],h[11];rows=[]
    def add(*a,**kw): rows.append(ins(*a,**kw))
    def rip(op,r,target):
        pc=page+0x100+sum(len(x['raw']) for x in rows)
        raw=bytes((0x48,op,5+8*r))+struct.pack('<i',target-pc-7)
        lea=op==0x8d
        add(raw,292 if lea else 286,(reg(r,64,2),memop(64,lea)),address=memory(16,16,1,target,0 if lea else 8,lea),reloc=3)
    if mode==0:
        add('4883c07f',249,(reg(0,64,3),imm(127,64,8)),ARITH)
        add('4883e8ff',264,(reg(0,64,3),imm(U64,64,8)),ARITH)
        add('480d00000080',32,(reg(0,64,3),imm(0xffffffff80000000,64,32)),LOGIC)
        add('4825ffffff7f',79,(reg(0,64,3),imm(0x7fffffff,64,32)),LOGIC)
        add('4831d8',97,(reg(0,64,3),reg(3,64,1)),LOGIC)
        add('4839d8',110,(reg(0,64,1),reg(3,64,1)),ARITH)
        add('48f7c001000080',721,(reg(0,64,1),imm(0xffffffff80000001,64,32)),LOGIC)
    elif mode==1:
        add('b801000080',357,(reg(0,32,2),imm(0x80000001,32,32)),step=1)
        add('48c7c300000080',405,(reg(3,64,2),imm(0xffffffff80000000,64,32)))
        add('49b80123456789abcdef',358,(reg(8,64,2),imm(0xefcdab8967452301,64,64)),step=1)
        add('4829c0',84,(reg(0,64,2),reg(0,64,0)),(0,0,PF|ZF,CF|AF|SF|OF,0))
        add('4531c0',96,(reg(8,32,2),reg(8,32,0)),(0,0,PF|ZF,CF|SF|OF,AF))
    elif mode==2:
        add('488d44caf9',292,(reg(0,64,2),memop(64,True)),address=memory(2,1,8,-7,0,True))
        add('8d4c8a11',291,(reg(1,32,2),memop(64,True)),address=memory(2,1,4,17,0,True))
    elif mode==3:
        add('03448af0',11,(reg(0,32,3),memop(32)),ARITH,memory(2,1,4,-16,4))
        add('482b4208',88,(reg(0,64,3),memop(64)),ARITH,memory(2,16,1,8,8))
        add('483b02',114,(reg(0,64,1),memop(64)),ARITH,memory(2,16,1,0,8))
        add('f7420cffffff7f',720,(memop(32),imm(0x7fffffff,32,32)),LOGIC,memory(2,16,1,12,4))
    elif mode in (4,5):
        rip(0x8b,0,page+(0xf00 if mode==4 else 0x20));rip(0x8d,3,data+8192)
    elif mode in (6,7):
        add('4885c0',274,(reg(0,64,1),reg(0,64,1)),LOGIC)
        add('7404',173,((page+0x109,4,0,64,1,8,0),),(ZF,0,0,0,0),flow=1,target=page+0x109,condition=4)
        add('4883c301',249,(reg(3,64,3),imm(1,64,8)),ARITH)
        add('4883cb80',252,(reg(3,64,3),imm(0xffffffffffffff80,64,8)),LOGIC)
    elif mode in (8,9):
        if mode==9:add('4883c001',249,(reg(0,64,3),imm(1,64,8)),ARITH)
        rip(0x8b,0,data+8192)
    else:
        group,variant=divmod(mode-10,8);width=64 if group%2 else 32;kind=group//2;field=(4,5,7)[kind]
        raw=bytes(([0x48] if width==64 else [])+[0xd1 if variant==0 else 0xc1 if variant<6 else 0xd3,0xc0+8*field+int(variant==7)])
        count=1 if variant==0 else (0,0,1,width-1,width,255)[variant] if variant<6 else None
        if 0<variant<6:raw+=bytes((count,))
        source=reg(1,8,1) if variant>=6 else imm(count,8,0 if variant==0 else 8)
        c=2 if count is None else count&(width-1)
        flags=(0,CF|PF|ZF|SF|(OF if c==1 else 0),0,0,AF|(OF if c!=1 else 0)) if c else (0,0,0,0,0)
        code=SHIFT_CODES[kind][int(width==64)][0 if variant==0 else 1 if variant<6 else 2]
        add(raw,code,(reg(int(variant==7),width,3),source),flags)
    source=bytearray(b'\xcc'*4096);at=0x100
    for row in rows:row['offset']=at;source[at:at+len(row['raw'])]=row['raw'];at+=len(row['raw'])
    source[at]=0x90
    if mode in (4,5):struct.pack_into('<Q',source,0xf00 if mode==4 else 0x20,0x8877665544332211)
    return rows,bytes(source),at

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

def plan(h):
    rows,source,end=puzzle(h);page,generated=h[8],h[9]
    image=bytearray(b'\xcc'*4096);at=0
    for row in rows:row['generated_offset']=at;at+=6 if row['flow']==1 else len(row['raw'])
    image_end=at+5;boundary=page+end;n=len(rows);jcc=h[3] in (6,7)
    for row in rows:
        off=row['generated_offset'];raw=row['raw']
        if row['flow']==1:raw=b'\x0f\x84'+struct.pack('<i',generated+rows[3]['generated_offset']-generated-off-6)
        elif row['reloc']:
            raw=raw[:row['reloc']]+struct.pack('<i',row['address'][0]-generated-off-len(raw))+raw[row['reloc']+4:]
        image[off:off+len(raw)]=raw
    image[at:at+5]=b'\xe9'+struct.pack('<i',boundary-generated-at-5)
    result=bytearray(57184)
    struct.pack_into('<12I4Q',result,0,1,1,n,3 if jcc else 1,1,n+1,n,1,end-0x100,image_end,2*n+2,0,page,page+0x100,generated,boundary)
    result[80:4176]=source;result[4176:8272]=image
    for i,row in enumerate(rows):result[8272+i*336:8272+(i+1)*336]=descriptor(row,page+row['offset'],source,row['offset'])
    boundary_row=ins('90',300,step=1)
    result[29776:30112]=descriptor(boundary_row,boundary,source,end,True)
    for i,row in enumerate(rows):
        off=row['generated_offset'];emitted=dict(row)
        if row['flow']==1:
            target=generated+rows[3]['generated_offset'];emitted.update(raw=bytes(image[off:off+6]),code=1868,target=target,ops=((target,4,0,64,1,32,0),))
        elif row['reloc']:emitted['raw']=bytes(image[off:off+len(row['raw'])])
        result[30112+i*336:30112+(i+1)*336]=descriptor(emitted,generated+off,image,off)
        successors=(3,2) if row['flow']==1 else ((i+1 if i+1<n else 64),)
        block=(0 if i<2 else 1 if i==2 else 2) if jcc else 0
        glen=6 if row['flow']==1 else len(row['raw'])
        struct.pack_into('<8I',result,51952+i*32,row['offset'],len(row['raw']),off,glen,len(successors),*successors,*([0]*(2-len(successors))),block)
        struct.pack_into('<8I2Q',result,54064+i*48,1,1,i,2 if row['flow'] else 4 if row['reloc'] else 1,row['offset'],len(row['raw']),off,glen,page+row['offset'],generated+off)
    tail=ins(bytes(image[at:at+5]),696,((boundary,4,0,64,1,32,0),),flow=2,target=boundary)
    result[30112+n*336:30112+(n+1)*336]=descriptor(tail,generated+at,image,at)
    struct.pack_into('<Q',result,54000,boundary)
    struct.pack_into('<8I2Q',result,54064+n*48,1,1,n-1,3,end,0,at,5,boundary,generated+at)
    return rows,source,bytes(image),bytes(result)
