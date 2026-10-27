#!/usr/bin/env python3
"""Append two real alternate-entry CPUID streams to the unchanged twenty."""
import json
from pathlib import Path
import struct
import sys
import page_selected_generic_images as generic

old=generic.old
PAGE,DATA,MAIN=generic.PAGE,generic.DATA,generic.MAIN
IMM=bytes.fromhex('0fa2eb0690909090')
LITERAL=int.from_bytes(IMM,'little')


def store_r10(p,name,address):
    p.add(name,bytes.fromhex('4c8915')+struct.pack('<i',address-(p.pc+7)),'generic')


def streams():
    result=[]
    for cross in (False,True):
        enclosing=MAIN+PAGE-3 if cross else MAIN
        p=generic.Program(enclosing)
        p.add('enclosing_mov',old.mov64(10,LITERAL),'old')
        p.add('skip_embedded_ret',bytes.fromhex('eb01'),'generic')
        p.add('embedded_ret',bytes.fromhex('c3'),'generic')
        assert p.pc==enclosing+13
        store_r10(p,'save_enclosing_literal',DATA+32)
        p.add('input_eax',old.mov32(0,0),'old')
        p.add('input_ecx',old.mov32(1,0),'old')
        p.add('flag_input',old.mov32(6,7),'old')
        p.add('flags_zf1_cf0',bytes.fromhex('83fe07'),'generic')
        if cross:
            p.add('indirect_target',old.mov64(11,enclosing+2),'old')
            p.add('call_embedded',bytes.fromhex('41ffd3'),'generic')
        else:
            p.branch('call_embedded','e8',enclosing+2)
        actual_return_pc=p.pc
        p.branch('zf_preserved','0f85','failure')
        p.branch('cf_preserved','0f82','failure')
        # RET consumed this real CALL word. Load it through an actual ordinary
        # instruction, then require the exact original call fallthrough.
        p.add('read_actual_call_word',bytes.fromhex('4c8b5c24f8'),'generic')
        p.add('compare_actual_return',bytes.fromhex('4981fb')+struct.pack('<I',actual_return_pc),'generic')
        p.branch('return_word_matches','0f85','failure')
        for label,reg,address in (('a',0,DATA),('b',3,DATA+8),('c',1,DATA+16),('d',2,DATA+24)):
            p.store('store_'+label,reg,address)
        store_r10(p,'store_r10_after',DATA+32)
        generic.tail(p,40)
        generic.poison(p)
        code=p.finish()
        linear=[r['name'] for r in p.rows if r['name']!='embedded_ret' and not r['name'].startswith('poison_')]
        call_at=linear.index('call_embedded')
        executed=linear[:call_at+1]+['embedded_cpuid','embedded_jump','embedded_ret']+linear[call_at+1:]
        # These rows intentionally overlap the enclosing MOV's immediate. The
        # emitted bytes exist once; heads are descriptive, not entry authority.
        p.rows.extend([
            dict(name='embedded_cpuid',pc=enclosing+2,bytes='0fa2',route='builtin'),
            dict(name='embedded_jump',pc=enclosing+4,bytes='eb06',route='generic')])
        by_name={r['name']:r for r in p.rows}
        assert len(by_name)==len(p.rows) and len(set(executed))==len(executed)
        for row in p.rows:
            start=row['pc']-enclosing;b=bytes.fromhex(row['bytes'])
            assert code[start:start+len(b)]==b
        overlap=[]
        for i,a in enumerate(p.rows):
            for b in p.rows[i+1:]:
                if max(a['pc'],b['pc'])<min(a['pc']+len(bytes.fromhex(a['bytes'])),b['pc']+len(bytes.fromhex(b['bytes']))):
                    overlap.append(sorted((a['name'],b['name'])))
        assert sorted(overlap)==sorted([sorted(('enclosing_mov','embedded_cpuid')),sorted(('enclosing_mov','embedded_jump'))])
        counts=dict(old=12 if cross else 11,generic=17,builtin=1,syscall=2,main=30 if cross else 29,interpreter=2)
        actual={k:sum(by_name[n]['route']==k for n in executed) for k in ('old','generic','builtin','syscall')}
        actual['old']+=1;actual['generic']+=1
        assert all(actual[k]==counts[k] for k in actual) and len(executed)==counts['main']
        call=by_name['call_embedded']
        result.append(dict(name='embedded_cpuid_cross_indirect' if cross else 'embedded_cpuid_direct',
            category='embedded_connected',entry=enclosing,pieces=[(enclosing,code)],rows=p.rows,executed=executed,
            builtin=1,output_words=5,counters=counts,
            embedded=dict(enclosing_pc=enclosing,selected_pc=enclosing+2,selected_hex='0fa2',
                          enclosing_hex=('49ba'+IMM.hex()),literal=LITERAL,overlap_pairs=overlap,
                          selected_crosses_page=cross,ret_pc=enclosing+12,setup_pc=enclosing+13),
            call=dict(pc=call['pc'],next_pc=actual_return_pc,target=enclosing+2,indirect=cross,
                      opcode_hex=call['bytes'],return_word_checked=True)))
    return result


def emit_stream(directory,spec):
    here=directory/spec['name'];here.mkdir()
    interp=(here/'interpreter.so').absolute();dynamic,strings=0x400,0x480
    dyn=b''.join(struct.pack('<qQ',t,v) for t,v in ((5,strings),(10,len(old.SONAME)+1),(14,1),(0,0)))
    interpreter_code=old.mov64(0,spec['entry'])+bytes.fromhex('ffe0')
    ip=[old.segment(1,4,0,0,PAGE),old.segment(1,5,PAGE,PAGE,2*PAGE),
        old.segment(2,4,dynamic,dynamic,len(dyn),8),old.segment(0x6474e551,6,0,0,0,16)]
    ih=old.emit(interp,3,PAGE,ip,[(dynamic,dyn),(strings,b'\0'+old.SONAME),(PAGE,interpreter_code)],3*PAGE)
    (here/old.SONAME[:-1].decode()).write_bytes(interp.read_bytes())
    path=str(interp).encode()+b'\0';assert len(path)<=512
    md=b''.join(struct.pack('<qQ',t,v) for t,v in ((1,1),(5,0x400000+strings),(10,len(old.SONAME)+1),(0,0)))
    mp=[old.segment(6,4,old.EH.size,0x400000+old.EH.size,7*old.PH.size,8),
        old.segment(3,4,0x500,0x400500,len(path),1),old.segment(1,4,0,0x400000,PAGE),
        old.segment(1,5,PAGE,MAIN,3*PAGE),old.segment(1,6,4*PAGE,DATA,PAGE),
        old.segment(2,4,dynamic,0x400000+dynamic,len(md),8),old.segment(0x6474e551,6,0,0,0,16)]
    pieces=[(dynamic,md),(strings,b'\0'+old.SONAME),(0x500,path),(4*PAGE,b'\xa5'*PAGE)]
    for pc,code in spec.pop('pieces'):
        assert MAIN<=pc<pc+len(code)<=MAIN+3*PAGE
        pieces.append((PAGE+pc-MAIN,code))
    original=here/'original';mh=old.emit(original,2,spec['entry'],mp,pieces,5*PAGE)
    return dict(spec,original=str(original.absolute()),interpreter=str(interp),library_root=str(here.absolute()),
        original_sha256=mh,interpreter_sha256=ih,soname_sha256=ih,entry_vaddr=PAGE,entry_file_offset=PAGE,
        exact_stream_hex=interpreter_code.hex(),data_address=DATA,data_initial_hex='a5'*PAGE)


def append(directory):
    # Execute the original generator unchanged and append only two new objects.
    generic.append(directory)
    rows=json.loads((directory/'images.json').read_text());assert len(rows)==20
    original_rows=json.dumps(rows,sort_keys=True,separators=(',',':'))
    rows.extend(emit_stream(directory,spec) for spec in streams())
    assert len(rows)==22 and json.dumps(rows[:20],sort_keys=True,separators=(',',':'))==original_rows
    (directory/'images.json').write_text(json.dumps(rows,indent=2,sort_keys=True)+'\n')


if __name__=='__main__':
    assert len(sys.argv)==2 and sys.flags.optimize==0
    append(Path(sys.argv[1]).resolve())
