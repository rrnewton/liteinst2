#!/usr/bin/env python3
"""Bind schema15 observation selectors to the actual companion fixture ELF.

Mapped addresses and literal bytes restrict observation only. They never enter
production source selection, planner eligibility or entry authority.
"""
from pathlib import Path
import struct
import sys

A=bytes.fromhex('4883e9014883f9020f84f2feffff4885c975ed66894f084983ea0175faff2500000000')
B=bytes.fromhex('4c890f4983e9014c89c9e9f1000000')
PAGES=(0x4000000,0x700000000000)
ENTRIES=(512,256)
STEPS=(50,42)


def need(condition,message):
    if not condition:
        raise ValueError(message)


def configuration(data):
    def take(at,size):
        need(type(at)is int and type(size)is int and 0<=at<=len(data) and
             0<=size<=len(data)-at,'bounded actual observation ELF range')
        return data[at:at+size]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1:4]==(2,62,1) and
         h[8:10]==(64,56) and 0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,
         'bounded x86-64 ET_EXEC lifecycle fixture')
    programs=[struct.unpack('<IIQQQQQQ',take(h[5]+i*56,56))for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+i*64,64))for i in range(h[12])]
    tables=[s for s in sections if s[1]==2]
    need(len(tables)==1,'one full symbol table')
    t=tables[0]
    need(t[9]==24 and t[5]%24==0 and t[6]<len(sections),'complete table bounds')
    strings=sections[t[6]]
    need(strings[1]==3,'actual symbol string table')
    names=take(strings[4],strings[5]);found={}
    wanted={b'region_app_capture_high',b'lc_a_template',b'lc_b_template',
        b'lc_entry',b'lc_source_page',b'lc_base_offset',b'lc_b_offset',
        b'lc_cancel_offset',b'lc_c_offset',b'lc_stub_offset',b'lc_predecessor_offset',
        b'lc_steps',b'lc_a_back',b'lc_a_to_b'}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,address,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names) and b'\0'in names[n:],'complete symbol name')
        name=names[n:names.index(b'\0',n)]
        if name in wanted:
            need(section and section<len(sections) and name not in found,
                 'unique actual defined observation symbol')
            found[name]=(address,size,info&15)
    need(set(found)==wanted,'all explicit paired observation symbols')
    def actual(name,size,flags,kind,alignment):
        address,extent,typ=found[name]
        need(extent==size and typ==kind and address>=4096 and address+size<1<<47 and
             address%alignment==0,'exact actual symbol type/size/alignment '+name.decode())
        owners=[p for p in programs if p[0]==1 and p[1]==flags and p[5]<=p[6] and
                p[3]<=address and address-p[3]+size<=p[5]]
        need(len(owners)==1 and all(p==owners[0]for p in programs if p[0]==1 and
             p[3]<address+size and address<p[3]+p[6]),'one complete nonoverlapping load owner')
        p=owners[0]
        return take(p[2]+address-p[3],size)
    need(len(A)==35 and len(B)==15 and actual(b'lc_a_template',35,4,1,1)==A and
         actual(b'lc_b_template',15,4,1,1)==B,'whole exact original A/B instruction templates')
    fields=((b'lc_entry',ENTRIES,4),(b'lc_source_page',PAGES,8),(b'lc_steps',STEPS,4),
        (b'lc_a_back',(3,2),4),(b'lc_a_to_b',(3,2),4),(b'lc_base_offset',(512,),4),
        (b'lc_b_offset',(256,),4),(b'lc_cancel_offset',(19,),4),
        (b'lc_c_offset',(23,),4),(b'lc_stub_offset',(29,),4))
    for name,values,width in fields:
        need(actual(name,len(values)*width,4,1,width)==struct.pack('<'+
             ('I'if width==4 else'Q')*len(values),*values),'whole literal lifecycle table '+name.decode())
    need(actual(b'lc_predecessor_offset',4,4,1,4)==struct.pack('<i',-5),
         'both real E9 predecessors have zero displacement')
    high,size,kind=found[b'region_app_capture_high']
    need(size>0 and kind==2,'actual nonempty high capture function')
    actual(b'region_app_capture_high',size,5,2,1)
    need(all(page%4096==0 and 4096<=page and page+3*4096<1<<47 for page in PAGES) and
         512+23<=4096-15 and 512+43<8192,'whole pairs and original15-byte cold-root placement')
    def array(typ,name,values):
        return 'static const '+typ+' '+name+'['+str(len(values))+']={'+', '.join(
            '0x%xULL'%v if typ=='uint64_t' else str(v)for v in values)+'};\n'
    return ('#ifndef LI2_PERSISTENT_LOOP_LIFECYCLE_CAPTURE_CONFIG_H\n'
        '#define LI2_PERSISTENT_LOOP_LIFECYCLE_CAPTURE_CONFIG_H\n'
        '#define LI2_PLC_CAPTURE_VERSION 15\n#define LI2_PLC_APP_PROTOCOL 1\n'
        '#define LI2_PLC_HIGH_RVA 0x%xULL\n'%high+
        array('unsigned char','plc_a_template',A)+array('unsigned char','plc_b_template',B)+
        array('uint64_t','plc_source_pages',PAGES)+'#endif\n').encode()


def main():
    need(len(sys.argv)==3,'actual lifecycle image and existing output directory')
    image,output=(Path(x).resolve(strict=True)for x in sys.argv[1:])
    need(image.is_file() and output.is_dir(),'actual regular image and output directory')
    with(output/'persistent_loop_lifecycle_capture_config.h').open('xb')as stream:
        stream.write(configuration(image.read_bytes()))


if __name__=='__main__':
    main()
