"""Exact two-head root oracle; never calls a decoder or grants execution authority."""
import importlib.util,struct
from pathlib import Path
path=Path(__file__).resolve().parent.parent/'linked_preedge_owner/plan.py'
spec=importlib.util.spec_from_file_location('reuse65_descriptor_oracle',path)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
need=base.need

def plan(source,page,entry,generated):
    need(type(source)is bytes and len(source)==4096 and page%4096==generated%4096==0 and
         4096<=page<1<<31 and 4096<=generated<1<<31 and page!=generated and
         entry>=page+0x200 and entry<=page+0xa00 and (entry-page-0x200)%32==0,
         'exact65-root source/generated geometry')
    offset=entry-page;ordinal=(offset-0x200)//32;frontier=page+0xc00
    raw=b'\xb8'+struct.pack('<I',ordinal+1);jmp=b'\xe9'+struct.pack('<i',frontier-entry-10)
    need(source[offset:offset+10]==raw+jmp and source[offset-2:offset]==b'\x66\x90' and source[0xc00:0xc06]==b'\xff\x25\0\0\0\0','exact real root/predecessor/frontier bytes')
    rows=(base.ins(raw,357,(base.reg(0,32,2),base.imm(ordinal+1,32,32)),step=1),
          base.ins(jmp,696,((frontier,4,0,64,1,32,0),),flow=2,target=frontier))
    image=bytearray(b'\xcc'*4096);image[:5]=raw;image[5:10]=b'\xe9'+struct.pack('<i',0)
    image[10:15]=b'\xe9'+struct.pack('<i',frontier-generated-15)
    out=bytearray(40744);struct.pack_into('<12I3Q',out,0,2,40744,1,2,1,3,2,0,10,15,6,0,page,entry,generated)
    out[72:4168]=source;out[4168:8264]=image
    for i,(off,row,g,succ)in enumerate(((offset,rows[0],0,1),(offset+5,rows[1],10,64))):
        out[8264+i*336:8264+(i+1)*336]=base.descriptor(row,page+off,source,off)
        struct.pack_into('<8I',out,32456+i*32,off,5,g,5,1,succ,0,i)
    out[29768:30104]=base.descriptor(base.ins('ff2500000000',765),frontier,source,0xc00,refusal=True)
    struct.pack_into('<Q',out,34504,frontier)
    maps=((1,1,0,1,offset,5,0,5,entry,generated),
          (1,1,0,3,offset+5,0,5,5,entry+5,generated+5),
          (1,1,1,2,offset+5,5,10,5,entry+5,generated+10))
    for i,row in enumerate(maps):struct.pack_into('<8I2Q',out,34568+i*48,*row)
    struct.pack_into("<I",out,40712,1)
    return bytes(out),bytes(image),{offset:dict(head=0,offset=0,length=5),offset+5:dict(head=1,offset=10,length=5)}
