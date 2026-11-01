#!/usr/bin/env python3
"""Bind policy14 observation selectors to the actual paired fixture ELF.

Mapped addresses and literal bytes restrict observation only. They never enter
production source selection, planner eligibility or entry authority.
"""
from pathlib import Path
import struct
import sys

TEMPLATE=bytes.fromhex(
    '4983c1014983e8804983f9250f8472ffffff418078f8004d63d175e4'
    '410fb6384084ff74db4c89cd4c89c64889d889f948c1e5070f1f4000'
    '0fb61084d274c138ca75bd0fb64e014883c6014883c00184c975e580383d75a8'
    '4585db7411418b40fc85c00f841303000083f802759249c1e207488d05470f0200'
    '42837c1030030f84e9020000488b3c2431f6e8b05fffff')
ENTRIES=(0,0,23,59,59,18,52)
PAGES=(0x4000000,0x4000000,0x700000000000,0x700000000000)
OFFSETS=(512,4022,512,4022)
STEPS=(106,25,35,13,13,1,2)
BACKWARDS=((1,1,0,1,1,1),(0,0,1,0,0,0),(0,0,0,0,1,0),
           (0,0,0,0,0,0),(0,0,0,0,0,0),(0,0,0,0,0,0),(0,0,0,0,0,0))
CUTS=((0,1),(1,0),(0,1),(0,1),(0,1),(0,0),(0,0))


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
         'bounded x86-64 ET_EXEC paired fixture')
    programs=[struct.unpack('<IIQQQQQQ',take(h[5]+i*56,56))for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+i*64,64))for i in range(h[12])]
    tables=[s for s in sections if s[1]==2]
    need(len(tables)==1,'one full symbol table')
    t=tables[0]
    need(t[9]==24 and t[5]%24==0 and t[6]<len(sections),'complete table bounds')
    strings=sections[t[6]]
    need(strings[1]==3,'actual symbol string table')
    names=take(strings[4],strings[5]);found={}
    wanted={b'loop_native_template',b'loop_native_template_end',b'region_app_capture_high',
        b'lp_entry',b'lp_source_page',b'lp_base_offset',b'lp_predecessor_offset',
        b'lp_steps',b'lp_backwards',b'lp_cuts'}
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
    need(len(TEMPLATE)==144 and actual(b'loop_native_template',144,4,1,1)==TEMPLATE and
         found[b'loop_native_template_end'][0]==found[b'loop_native_template'][0]+144 and
         found[b'loop_native_template_end'][1]==0,'whole literal loader template144')
    fields=((b'lp_entry',ENTRIES,4),(b'lp_source_page',PAGES,8),(b'lp_base_offset',OFFSETS,4),
            (b'lp_steps',STEPS,4),(b'lp_backwards',sum(BACKWARDS,()),4),
            (b'lp_cuts',sum(CUTS,()),4))
    for name,values,width in fields:
        need(actual(name,len(values)*width,4,1,width)==struct.pack('<'+
             ('I'if width==4 else'Q')*len(values),*values),'whole literal paired table '+name.decode())
    need(actual(b'lp_predecessor_offset',4,4,1,4)==struct.pack('<i',-5),
         'real five-byte predecessor ends at base')
    high,size,kind=found[b'region_app_capture_high']
    need(size>0 and kind==2,'actual nonempty high capture function')
    actual(b'region_app_capture_high',size,5,2,1)
    need(all(124<=offset and offset+102<8192 and
             all(offset+entry<=4096-15 for entry in ENTRIES)for offset in OFFSETS),
         'all cold roots retain page0 and the original one-page15-byte bound')
    def array(typ,name,values):
        return 'static const '+typ+' '+name+'['+str(len(values))+']={'+', '.join(
            '0x%xULL'%v if typ=='uint64_t' else str(v)for v in values)+'};\n'
    return ('#ifndef LI2_PERSISTENT_LOOP_CAPTURE_CONFIG_H\n'
        '#define LI2_PERSISTENT_LOOP_CAPTURE_CONFIG_H\n'
        '#define LI2_PLO_CAPTURE_VERSION 14\n#define LI2_PLO_APP_PROTOCOL 2\n'
        '#define LI2_PLO_HIGH_RVA 0x%xULL\n'%high+
        array('unsigned char','plo_template',TEMPLATE)+array('unsigned','plo_entries',ENTRIES)+
        array('uint64_t','plo_source_pages',PAGES)+array('unsigned','plo_base_offsets',OFFSETS)+
        '#endif\n').encode()


def main():
    need(len(sys.argv)==3,'actual paired image and existing output directory')
    image,output=(Path(x).resolve(strict=True)for x in sys.argv[1:])
    need(image.is_file() and output.is_dir(),'actual regular image and output directory')
    with(output/'persistent_loop_capture_config.h').open('xb')as stream:
        stream.write(configuration(image.read_bytes()))


if __name__=='__main__':
    main()
