#!/usr/bin/env python3
"""Exact release recipe observation for the distinct scalar-generation reuse profile."""
import shutil,struct
from pathlib import Path
from maps_view import (need,fact,SELECTED,UNITS,MACROS,recipe,expand,headers,bridge_check,
    ENV,hidden_memset,body_check)

def capture_config(path,output,pin,binary):
    """Derive the only capture macro from a retained ET_EXEC symbol and bytes."""
    path=pin(binary(path));data=path.read_bytes()
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,'bounded actual capture ELF range')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and h[8:10]==(64,56)and
         0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,'one actual bounded x86-64 ET_EXEC capture image')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+i*56,56))for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+i*64,64))for i in range(h[12])]
    tables=[s for s in sections if s[1]==2]
    need(len(tables)==1 and tables[0][9]==24 and tables[0][5]%24==0,'one complete actual capture symtab')
    t=tables[0];need(t[6]<len(sections),'capture symbol string index');strings=sections[t[6]];names=take(strings[4],strings[5]);heads=[]
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,pc,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names)and b'\0'in names[n:],'complete capture symbol name')
        if names[n:names.index(b'\0',n)]==b'region_app_head':
            need(section!=0,'actual defined capture head');heads.append(pc)
    need(len(heads)==1 and heads[0]>=4096 and heads[0]<(1<<47)and heads[0]%4096<=4096-15,'one actual application head with complete fetch15 in its page');pc=heads[0];page=pc&~4095
    owners=[s for s in ph if s[0]==1 and s[1]==5 and s[5]<=s[6]and s[3]<=page and page-s[3]+4096<=s[5]]
    need(len(owners)==1,'complete actual capture source page in one RX load');segment=owners[0]
    body=take(segment[2]+page-segment[3],4096)
    need(len(body)==4096 and pc-page<=4096-15,'full source page and original fetch15 in actual capture ELF')
    header=output/'scalar_region_capture_config.h';text='#define LI2_REGION_APP_HEAD_RVA 0x%xULL\n'%pc
    with header.open('x')as stream:stream.write(text)
    header=pin(binary(header))
    return dict(image=fact(path),head_rva=pc,header=fact(header),path=str(header))


def build_bridge(builder,products,private,pin,binary,aliases,run,r,extra,capture_image=None):
    need(builder.extra_decoder_sources==('region.rs',)and builder.decoder_features==('scalar-region',)and
         builder.record.get('decoder_features')==['scalar-region']and
         builder.environment.get('LI2_DECODER_FEATURES')=='scalar-region',
         'explicit scalar-region Build/archive feature and exact region source')
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    need(extra in ((),('MAPS_DIFFERENTIAL',),('SCALAR_REGION_CAPTURE',)),
         'one explicit scalar normal, differential or capture profile')
    need((capture_image is not None)==(extra==('SCALAR_REGION_CAPTURE',)),'capture image required only for exact capture profile')
    output=private/'release';output.mkdir();config=capture_config(capture_image,output,pin,binary)if capture_image is not None else None
    bridge_recipe=pin(SELECTED/'build-scalar-region-reuse.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit bounded unrolled release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output})
    argv[1:1]=['-DLI2_'+x+'=1'for x in extra];units=[str(SELECTED.parent/x)for x in UNITS]+[str(SELECTED/'unrolled_hash_plan.c'),str(SELECTED/'region_plan.c')]
    need(argv[-2:]==['-o',str(output/'bridge-scalar-region-reuse.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in extra+('SCALAR_REGION','SCALAR_REGION_REUSE','INITIAL_CODE_PROTECTION','UNROLLED_HASH','MAPS_MAINTAINED')+MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact20-TU scalar-region release recipe and explicitly selected diagnostic macros')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv,capture_config=config)
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    need(all(str((SELECTED/name).resolve())in state['headers']for name in
         ('maps_phase.inc','maps_view.inc','initial_code_protection.h','selected_unrolled_hash.inc','unrolled_hash.h',
          'unrolled_source.inc','unrolled_source.h','rseq_unrolled.inc','region_decode.h',
          'region_plan.h','region_source.h','region_source.inc','rseq_region.inc','selected_scalar_region.inc','selected_scalar_reuse.inc')),
         'compiler observes all maintained-view and actual unrolled owner seams')
    need((str((SELECTED/'scalar_region_observe.inc').resolve())in state['headers'])==(config is not None),
         'compiler observes capture adapter only in capture profile')
    if config is not None:need(state['headers'].get(config['path'])==config['header'],'actual compiler observes exact ELF-derived capture header')
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
