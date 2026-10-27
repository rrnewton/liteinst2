#!/usr/bin/env python3
"""Append ten actual REP programs; old twenty-two images are unchanged."""
import json
from pathlib import Path
import struct
import sys
import page_selected_embedded_images as embedded

generic=embedded.generic
old=generic.old
PAGE,DATA,MAIN=generic.PAGE,generic.DATA,generic.MAIN


def streams():
    configs=[('repeat_'+str(n)+'_df'+str(df),n,df,None,False,False) for n in (0,1,3) for df in (0,1)]
    configs += [('repeat_cross',3,0,MAIN+PAGE-2,False,False),
                ('repeat_next_page',3,1,MAIN+PAGE-3,False,False),
                ('repeat_reuse',3,1,None,True,False),('repeat_write_fault',1,0,None,False,True)]
    result=[]
    for name,count,df,repeat_pc,multi,fault in configs:
        p=generic.Program();pieces=[];iterations=[];rows=[]
        p.add('value',old.mov64(0,0x1122334455667788),'old')
        todo=[(0,0),(count,df)] if multi else [(count,df)]
        for j,(n,direction) in enumerate(todo):
            suffix=str(j)
            pointer=DATA+(16 if direction else 0)
            p.add('count'+suffix,old.mov32(1,n),'old')
            p.add('destination'+suffix,old.mov32(7,pointer),'old')
            p.add('flags'+suffix,bytes.fromhex('83f9')+bytes([n]),'generic')
            p.add('direction'+suffix,bytes([0xfd if direction else 0xfc]),'generic')
            if repeat_pc is not None:
                p.branch('jump_repeat','e9',repeat_pc);pieces.append((p.base,p.finish()));rows+=p.rows
                p=generic.Program(repeat_pc)
            p.add('repeat'+suffix,bytes.fromhex('f348ab'),'repeat')
            iterations.append(dict(count=n,df=direction,rdi=pointer))
        executed_before_tail=[r['name'] for r in rows+p.rows]
        p.branch('zf_preserved','0f85','failure');p.branch('cf_preserved','0f82','failure')
        p.add('clear_df',b'\xfc','generic')
        for label,reg,address in (('rax',0,DATA+64),('rcx',1,DATA+72),('rdi',7,DATA+80)):
            p.add('save_'+label,bytes([0x48,0x89,0x05|(reg<<3)])+struct.pack('<i',address-(p.pc+7)),'generic')
        generic.tail(p,128);generic.poison(p)
        pieces.append((p.base,p.finish()));rows+=p.rows
        executed=executed_before_tail if fault else [r['name'] for r in rows if not r['name'].startswith('poison_')]
        by_name={r['name']:r for r in rows}
        counts={route:sum(by_name[n]['route']==route for n in executed) for route in ('old','generic','repeat','syscall')}
        counts['old']+=1;counts['generic']+=1;counts['main']=len(executed)
        result.append(dict(name=name,category='repeat_connected',entry=MAIN,pieces=pieces,rows=rows,
                           executed=executed,iterations=iterations,counters=counts,fault=fault))
    return result


def append(directory):
    embedded.append(directory)
    rows=json.loads((directory/'images.json').read_text());assert len(rows)==22
    for spec in streams():
        result=embedded.emit_stream(directory,spec)
        if result['fault']:
            p=Path(result['original']);image=bytearray(p.read_bytes())
            # Exact data PT_LOAD changes from RW to R for the genuine store fault.
            phoff=old.EH.unpack_from(image)[5]
            at=phoff+4*old.PH.size
            ph=list(old.PH.unpack_from(image,at));assert ph[:5]==[1,6,4*PAGE,DATA,DATA]
            ph[1]=4;old.PH.pack_into(image,at,*ph);p.write_bytes(image)
            import hashlib
            result['original_sha256']=hashlib.sha256(image).hexdigest()
        rows.append(result)
    assert len(rows)==32
    (directory/'images.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')


if __name__=='__main__':
    assert len(sys.argv)==2 and sys.flags.optimize==0
    append(Path(sys.argv[1]).resolve())
