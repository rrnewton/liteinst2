#!/usr/bin/env python3
"""Exact build binding for genuine-TRACE scalar-span and its distinct capture."""
import importlib.util,shutil,struct
from pathlib import Path
from maps_view import (need,fact,SELECTED,UNITS,MACROS,recipe,expand,headers,bridge_check,
    ENV,hidden_memset,body_check,observe_headers,elf,interpreter,resolved_libraries,PROGRAM_ENV,H,digest)

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


FAST_BYTES_BOUNDS=[5,512<<20,16<<20,15]
FAST_BYTES_STDOUT=b'{"version":1,"status":0,"lengths":23,"placements":993,"mismatches":2766,"overlaps":64,"zero_access":368,"fp_cases":3,"prefix_mismatches":98}\n'

def fast_bytes_completed(build,commands,binary):
    state=build['fast_bytes'];rows=[x for x in commands if x['name']==state['command']]
    need(state['status']=='passed'and len(rows)==1,'one mandatory actual-header byte oracle')
    row=rows[0]
    need(type(state['path'])is str and str(binary(state['path']))==state['path']and
         digest(fact(binary(state['path'])))==digest(state['executable'])and
         digest(row['argv'])==digest([state['path']])and
         type(row['expected_exit'])is int and row['expected_exit']==0,
         'actual oracle command names its one exact retained executable artifact')
    need(row['profile']=='finite'and digest(row['bounds'])==digest(FAST_BYTES_BOUNDS)and
         type(row['exit'])is int and row['exit']==0 and row['reaped']is True and
         row['timed_out']is False and row['error']is None and not row['cleanup_errors']and
         all(x['closed']is True for x in row['descriptors'])and
         digest({k:row['captures']['stdout'][k]for k in('bytes','sha256')})==
             digest(dict(bytes=len(FAST_BYTES_STDOUT),sha256=H(FAST_BYTES_STDOUT)))and
         digest({k:row['captures']['stderr'][k]for k in('bytes','sha256')})==digest(dict(bytes=0,sha256=H(b''))),
         'closed same-bound exact byte-oracle result; no optional or inferred pass')

def fast_bytes(builder,output,pin,binary,aliases,run,build):
    fixture=SELECTED/'tests/span_fast_bytes';output=output/'fast-bytes';output.mkdir()
    state=build['fast_bytes']=dict(status='failed')
    script=pin(fixture/'build.sh');unit=pin(fixture/'oracle.c');header=pin(SELECTED/'span_fast_bytes.h')
    observe_headers(script,{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$fixture':fixture,'$output':output},
        [],'span-bytes-headers',builder,pin,run,state,aliases)
    rows=state['header_observations'];need(len(rows)==1 and rows[0]['complete'],'one complete actual-header oracle recipe')
    argv=rows[0]['argv'];deps=rows[0]['headers']
    need([x for x in argv if x.endswith(('.c','.S'))]==[str(unit)]and
         [x for x in argv if x.startswith('-D')]==['-DLI2_SCALAR_SPAN_TRACE=1','-DLI2_SPAN_FAST_BYTES=1']and
         str(header)in deps and all(x in argv for x in('-O2','-g','-fno-builtin','-mgeneral-regs-only',
             '-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-Wall','-Wextra','-Werror'))and
         argv[-2:]==['-o',str(output/'span-fast-bytes')],'exact actual-header oracle compiler recipe')
    _,out,err=run('span-bytes-link',argv,profile='release_build',env=builder.environment)
    need(out==err==b'','complete byte-oracle build without diagnostics')
    executable=binary(output/'span-fast-bytes');state.update(path=str(executable),executable=fact(executable))
    data,head,segments=elf(executable)
    need(head[1]in(2,3)and any(p[0]==1 and p[1]==5 and p[3]<=head[4]<p[3]+p[6]for p in segments)and
         all(not(p[1]&1 and p[1]&2)for p in segments if p[0]in(1,0x6474e551)),
         'actual byte-oracle ELF entry with no writable executable segment or stack')
    interp=pin(interpreter(executable))
    spec=importlib.util.spec_from_file_location('span_bytes_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    need(pin(namespace.parse(data)['interpreter'])==interp,'exact byte-oracle interpreter alias')
    objects,description=namespace.plan(executable,[Path('/usr/lib64')],bytes.fromhex(H(data)),bytes.fromhex(fact(interp)['sha256']))
    expected={interp:set()}
    for obj in objects:
        path=pin(obj['path']);need(fact(path)['sha256']==H(obj['bytes']),'whole actual oracle dependency')
        expected.setdefault(path,set()).update(obj['names'])
    state['runtime_inputs']=dict(interpreter=fact(interp),dependencies=[dict(names=o['names'],**fact(o['path']))for o in objects])
    state['namespace_plan']=description
    _,out,err=run('span-bytes-native-libraries',[interp,'--list',executable],env=PROGRAM_ENV)
    need(not err,'actual oracle loader listing stderr');resolved_libraries(out,expected,interp,pin)
    row,out,err=run('span-bytes-oracle',[executable],profile='finite',env=PROGRAM_ENV)
    need(out==FAST_BYTES_STDOUT and err==b'','all actual-header byte cases and exact result')
    need(fact(header)=={k:deps[str(header)][k]for k in('bytes','sha256')},'actual header unchanged through oracle')
    state.update(status='passed',command=row['name']);fast_bytes_completed(build,[row],binary)

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
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in extra+('SCALAR_SPAN','SCALAR_SPAN_TRACE','SPAN_FAST_BYTES','MAPS_CURRENT_TF','SCALAR_REGION','SCALAR_REGION_REUSE','INITIAL_CODE_PROTECTION','UNROLLED_HASH','MAPS_MAINTAINED')+MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact20-TU typed span/current/reuse release recipe and diagnostic macros')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv,capture_config=config)
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    need(all(str((SELECTED/name).resolve())in state['headers']for name in
         ('maps_phase.inc','maps_view.inc','initial_code_protection.h','selected_unrolled_hash.inc','unrolled_hash.h',
          'unrolled_source.inc','unrolled_source.h','rseq_unrolled.inc','region_decode.h',
          'region_plan.h','region_source.h','region_source.inc','rseq_region.inc','selected_scalar_region.inc','selected_scalar_reuse.inc',
          'tf_span_transfer.h','tf_span_transfer.inc','span_fetch.h','span_fetch.inc','span_source.h','span_source.inc',
          'rseq_span.inc','selected_scalar_span.inc','selected_scalar_span_reuse.inc','span_fast_bytes.h',
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
    fast_bytes(builder,output,pin,binary,aliases,run,state)
    state['status']='passed';return bridge
