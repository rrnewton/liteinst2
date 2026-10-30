#!/usr/bin/env python3
"""Exact build binding for genuine-TRACE scalar-span and its distinct capture."""
import shutil,struct
from pathlib import Path
from maps_view import (need,fact,SELECTED,UNITS,MACROS,recipe,expand,headers,bridge_check,
    ENV,hidden_memset,body_check)

def capture_config(path,output,pin,binary):
    """Two exact actual ET_EXEC heads; no guessed or previous bridge geometry."""
    path=pin(binary(path));data=path.read_bytes()
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,'bounded actual fixture ELF range')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and h[8:10]==(64,56)and
         0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,'actual bounded ET_EXEC capture image')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56))for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64))for i in range(h[12])]
    tables=[x for x in sections if x[1]==2];need(len(tables)==1,'one complete actual fixture symbol table')
    t=tables[0];need(t[9]==24 and t[5]%24==0 and t[6]<len(sections),'whole symbol extent')
    table=sections[t[6]];need(table[1]==3,'actual symbol strings');strings=take(table[4],table[5]);symbols={}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,pc,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(strings)and b'\0'in strings[n:],'whole symbol name')
        name=strings[n:strings.index(b'\0',n)]
        if name in(b'region_app_head',b'region_app_miss_head'):
            need(section and name not in symbols,'unique actual defined head');symbols[name]=(pc,size)
    need(set(symbols)=={b'region_app_head',b'region_app_miss_head'},'both actual typed heads')
    pc,size=symbols[b'region_app_head'];miss,msize=symbols[b'region_app_miss_head'];page=pc&-4096
    need(pc-page==512 and size==31 and miss==page+768 and msize==2,'literal focal and refusal head geometry')
    owners=[p for p in ph if p[0]==1 and p[1]==5 and p[5]<=p[6]and p[3]<=page<page+4096<=p[3]+p[5]]
    need(len(owners)==1,'whole source in one actual RX load');p=owners[0];source=take(p[2]+page-p[3],4096)
    need(source[510:512]==b'\x66\x90'and source[766:770]==b'\x66\x90'*2,'actual NOP predecessors and refusal instruction')
    need(source[512:543]==bytes.fromhex('b807000000488d5448034801d0448b07448b0d690000004883f80f7453eb31'),'whole fixed31-byte span')
    header=output/'scalar_span_trace_capture_config.h'
    with header.open('x')as stream:stream.write('#define LI2_SPAN_APP_HEAD_RVA 0x%xULL\n#define LI2_SPAN_APP_MISS_RVA 0x%xULL\n'%(pc,miss))
    header=pin(binary(header));return dict(image=fact(path),head_rva=pc,miss_rva=miss,header=fact(header),path=str(header))


def build_bridge(builder,products,private,pin,binary,aliases,run,r,extra,capture_image=None):
    need(builder.extra_decoder_sources==('region.rs',)and builder.decoder_features==('scalar-region','scalar-span')and
         builder.record.get('decoder_features')==['scalar-region','scalar-span']and
         builder.environment.get('LI2_DECODER_FEATURES')=='scalar-span',
         'explicit scalar-span Build/archive feature and exact region source')
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    need(extra in ((),('MAPS_DIFFERENTIAL',),('SCALAR_SPAN_CAPTURE',)),
         'exact explicit span normal, differential or distinct capture profile')
    need((capture_image is not None)==(extra==('SCALAR_SPAN_CAPTURE',)),
         'fresh fixture image iff distinct span capture selected')
    output=private/'release';output.mkdir();config=capture_config(capture_image,output,pin,binary)if capture_image is not None else None
    bridge_recipe=pin(SELECTED/'build-scalar-span-trace.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit bounded unrolled release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output})
    argv[1:1]=['-DLI2_'+x+'=1'for x in extra];units=[str(SELECTED.parent/x)for x in UNITS]+[str(SELECTED/'unrolled_hash_plan.c'),str(SELECTED/'region_plan.c')]
    need(argv[-2:]==['-o',str(output/'bridge-scalar-span-trace.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in extra+('SCALAR_SPAN','SCALAR_SPAN_TRACE','MAPS_CURRENT_TF','SCALAR_REGION','SCALAR_REGION_REUSE','INITIAL_CODE_PROTECTION','UNROLLED_HASH','MAPS_MAINTAINED')+MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact20-TU typed span/current/reuse release recipe and diagnostic macros')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv,capture_config=config)
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    need(all(str((SELECTED/name).resolve())in state['headers']for name in
         ('maps_phase.inc','maps_view.inc','initial_code_protection.h','selected_unrolled_hash.inc','unrolled_hash.h',
          'unrolled_source.inc','unrolled_source.h','rseq_unrolled.inc','region_decode.h',
          'region_plan.h','region_source.h','region_source.inc','rseq_region.inc','selected_scalar_region.inc','selected_scalar_reuse.inc',
          'tf_span_transfer.h','tf_span_transfer.inc','span_fetch.h','span_fetch.inc','span_source.h','span_source.inc',
          'rseq_span.inc','selected_scalar_span.inc','selected_scalar_span_reuse.inc',
          'fetch_current_custody.h','fetch_current_custody.inc','maps_current_ticket.h')),
         'compiler observes all maintained-view and actual unrolled owner seams')
    need(all(str((SELECTED/name).resolve())not in state['headers']for name in
         ('scalar_region_observe.inc','unrolled_hash_observe.inc','current_tf_observe.inc')),
         'old capture adapters cannot describe the new span owner')
    for name in ('span_trace_observe.h','span_trace_observe.inc','span_trace_observe_memory.h','span_trace_observe_memory.inc','unrolled_hash_nested_fp.h'):
        need((str((SELECTED/name).resolve())in state['headers'])==(config is not None),
             'actual compiler observes every new capture seam iff selected')
    if config is not None:need(state['headers'].get(config['path'])==config['header'],'actual ELF-derived capture header in compiler-M')
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
    if config is not None:need(fact(capture_image)==config['image']and fact(config['path'])==config['header'],
        'fresh fixture and emitted capture header unchanged through link')
    state['status']='passed';return bridge
