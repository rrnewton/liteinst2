#!/usr/bin/env python3
"""Separate current-custody bridge; the original unrolled helper stays exact."""
import shutil,struct
from pathlib import Path
from maps_view import (need,fact,SELECTED,UNITS,MACROS,recipe,expand,headers,bridge_check,
    ENV,hidden_memset,body_check)
from unrolled_hash_build import capture_config


def prefix_config(path,output,pin,binary,original):
    path=pin(binary(path));data=path.read_bytes()
    need(fact(path)==original['image'],'same retained actual image for both source contracts')
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,
             'complete actual current-prefix ELF interval')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[1:4]==(2,62,1) and h[8:10]==(64,56) and
         0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,'complete bounded actual prefix ET_EXEC')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+i*56,56))for i in range(h[10])]
    ss=[struct.unpack('<IIQQQQIIQQ',take(h[6]+i*64,64))for i in range(h[12])]
    tables=[s for s in ss if s[1]==2]
    need(len(tables)==1 and tables[0][9]==24 and tables[0][5]%24==0 and
         0<tables[0][5]//24<=65536,'one complete actual prefix symtab')
    table=tables[0];need(table[6]<len(ss)and ss[table[6]][1]==3,'actual prefix string table')
    strings=ss[table[6]];names=take(strings[4],strings[5]);symbols={}
    wanted={b'unrolled_current_head',b'unrolled_current_end',b'unrolled_current_return_high'}
    for at in range(table[4],table[4]+table[5],24):
        n,info,other,section,pc,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names)and b'\0'in names[n:],'complete actual prefix symbol name')
        name=names[n:names.index(b'\0',n)]
        if name in wanted:
            need(name not in symbols and 0<section<len(ss),'unique defined current-prefix symbol')
            symbols[name]=pc
    need(set(symbols)==wanted,'all exact prefix and high-return symbols')
    head=symbols[b'unrolled_current_head'];end=symbols[b'unrolled_current_end'];exit=symbols[b'unrolled_current_return_high']
    need(4096<=head<1<<31 and head%4096==0 and end==head+4096 and head!=original['head_rva'] and
         0x200021000<=exit<=0x200022000-16,'distinct complete low source and actual high helper interior')
    def memory(pc,n):
        loads=[p for p in ph if p[0]==1 and p[1]==5 and p[5]<=p[6]and p[3]<=pc and pc-p[3]+n<=p[5]]
        need(len(loads)==1,'whole prefix/stub lies in one actual file-backed RX load')
        p=loads[0];return take(p[2]+pc-p[3],n)
    source=memory(head,4096);stub=memory(exit,16)
    need(source==bytes.fromhex('669066906690ff2500000000')+struct.pack('<Q',exit)+b'\xcc'*(4096-20),
         'all4096 actual prefix bytes and exact transparent high target')
    need(stub==bytes.fromhex('f390ff2500000000')+struct.pack('<Q',original['head_rva']),
         'actual PAUSE and transparent jump back to the unchanged hash head')
    header=output/'current_tf_capture_config.h'
    with header.open('x')as stream:
        stream.write('#define LI2_CURRENT_APP_HEAD_RVA 0x%xULL\n#define LI2_CURRENT_APP_EXIT_RVA 0x%xULL\n'%(head,exit))
    header=pin(binary(header))
    return dict(image=fact(path),head_rva=head,exit_rva=exit,source_bytes=4096,stub_bytes=16,header=fact(header),path=str(header))


def build_bridge(builder,products,private,pin,binary,aliases,run,r,extra,capture_image=None):
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    need(extra in ((),('MAPS_DIFFERENTIAL',)),
         'exact projected or every-hit differential current-custody profile')
    need(capture_image is not None and builder.extra_decoder_sources==() and builder.decoder_features==() and builder.record['decoder_features']==[],
         'actual current-custody capture requires the unchanged default-eight decoder and real app image')
    output=private/'release';output.mkdir();config=capture_config(capture_image,output,pin,binary);current_config=prefix_config(capture_image,output,pin,binary,config)
    bridge_recipe=pin(SELECTED/'build-current-custody.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit bounded unrolled release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output})
    argv[1:1]=['-DLI2_'+x+'=1'for x in extra];units=[str(SELECTED.parent/x)for x in UNITS]+[str(SELECTED/'unrolled_hash_plan.c')]
    need(argv[-2:]==['-o',str(output/'bridge-current-custody.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in extra+('MAPS_CURRENT_TF','CURRENT_TF_CAPTURE','UNROLLED_HASH_CAPTURE','UNROLLED_HASH','MAPS_MAINTAINED')+MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact19-TU current-custody recipe and explicit complete qualification macros')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv,capture_config=config,current_capture_config=current_config)
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    need(all(str((SELECTED/name).resolve())in state['headers']for name in
         ('maps_phase.inc','maps_view.inc','selected_unrolled_hash.inc','unrolled_hash.h',
          'unrolled_source.inc','unrolled_source.h','rseq_unrolled.inc',
          'maps_current_ticket.h','maps_current_ticket.inc','fetch_current_view.h','fetch_current_view.inc',
          'fetch_current_custody.h','fetch_current_custody.inc','current_tf_observe.h',
          'current_tf_observe.inc','current_tf_observe_lifecycle.inc')),
         'compiler observes all maintained-view and actual unrolled owner seams')
    need((str((SELECTED/'unrolled_hash_observe.inc').resolve())in state['headers'])==(config is not None),
         'compiler observes capture adapter only in capture profile')
    need(state['headers'].get(config['path'])==config['header'] and
         state['headers'].get(current_config['path'])==current_config['header'],
         'actual compiler observes both exact ELF-derived capture headers')
    bridge=Path(argv[-1]);run('release-bridge-link',argv,profile='release_build',env=builder.environment)
    state['bridge']=fact(binary(bridge));state['elf']=bridge_check(bridge)
    _,out,err=run('release-bridge-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(out==err==b'','actual effect bridge has no unresolved imports')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('release-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual objdump identity')
    _,symbols,err=run('release-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset symbol inspection')
    _,assembly,err=run('release-bridge-memset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset disassembly');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    state['status']='passed';return bridge
