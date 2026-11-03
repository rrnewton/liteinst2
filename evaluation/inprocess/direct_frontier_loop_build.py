"""Exact emitted helper and unchanged complete-byte copy oracle for the direct fixture."""
import os,re,shlex,shutil
import namespace
from pathlib import Path
from page_selected import need,elf,ENV,fact
from page_selected_register_time_build import recipe,expand
from persistent_dynamic import H
from persistent_active_domain import COPY_COUNTS,COPY_STDOUT
FIXTURE=Path(__file__).resolve().parents[2]/'tools/page-entry/selected/tests/persistent_direct_frontier_app'

def inspect_application(builder,private,pin,binary,run,state,original,app_units, *, fixture=None):
    fixture=FIXTURE if fixture is None else Path(fixture).resolve(strict=True)
    _,head,segments=elf(original)
    need(head[1:4]==(2,62,1)and not any(s[0]==1 and s[1]&3==3 for s in segments),'actual non-PIE x86-64 app without WX')
    _,_,err=run('app-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',original],profile='inspect',env=builder.environment)
    need(not err,'actual complete app ELF inspection')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('app-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual app disassembler identity')
    _,out,err=run('app-symbols',[builder.tools['nm'],'-S','--defined-only',original],profile='inspect',env=builder.environment)
    need(not err,'actual emitted helper symbols');symbols={};bodies={}
    for name in ('main','collect','copy','same','ua_data_pattern','ua_stack_pattern'):
        found=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]==('t'if name=='collect'else'T'),'one complete actual app text symbol')
        address,size=int(found[0][0],16),int(found[0][1],16)
        need(size>0 and sum(p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]for p in segments)==1,'whole symbol in exact actual RX segment')
        if name not in ('main','collect'):need(0x200001000<=address<address+size<=0x200002000,'actual high full-range helper body')
        symbols[name]=dict(address=address,bytes=size)
        _,assembly,err=run('app-body-'+name,[objdump,'-d','-w','-M','att','--start-address='+hex(address),'--stop-address='+hex(address+size),original],profile='inspect',env=builder.environment)
        need(assembly and not err and ('<'+name+'>:').encode()in assembly,'complete emitted helper/caller inspection')
        emitted=[];cursor=address
        for line in assembly.decode().splitlines():
            matched=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
            if matched:
                chunk=bytes.fromhex(matched[2]);need(int(matched[1],16)==cursor and chunk and cursor+len(chunk)<=address+size,
                    'every emitted instruction byte lies contiguously inside the actual symbol')
                emitted.append(chunk);cursor+=len(chunk)
        segment=next(p for p in segments if p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5])
        offset=segment[2]+address-segment[3]
        need(cursor==address+size and b''.join(emitted)==original.read_bytes()[offset:offset+size],
             'complete actual nm-sized body bytes equal the retained ELF range')
        bodies[name]=assembly.decode()
    # This fixture keeps collect out of line. Bind its complete body and the
    # main-to-collect edge as well as every helper's actual full-width caller.
    callers={'copy':'main','same':'collect','ua_data_pattern':'main','ua_stack_pattern':'main','collect':'main'}
    for name,caller in callers.items():
        need(re.search(r'\bmovabsq?\s+\$0x'+format(symbols[name]['address'],'x')+r',',bodies[caller])is not None,
             'actual '+caller+' materializes full-width '+name+' address without truncated relocation')
    state['helper_callers']=callers
    effects=[x for x in state['argv'] if x.startswith('-DLI2_LOOP_CACHE8_EFFECT=')]
    if effects:state['real_effect']=effect_image(original,out,int(effects[0].rsplit('=',1)[1]))
    copy_oracle(builder,private,pin,binary,run,state,original,symbols['copy'],app_units,fixture=fixture)
    state.update(status='passed',artifact=fact(original),symbols=symbols);return original



def copy_oracle(builder,private,pin,binary,run,state,original,app_symbol,app_units, *, fixture=None):
    """Bound the actual fixture helper to an independent complete-byte oracle."""
    fixture=FIXTURE if fixture is None else Path(fixture).resolve(strict=True)
    arena='-DLI2_LOOP_TRANSLATION_ARENA_APP=1' in state['argv']
    cached_direct='-DLI2_LOOP_CACHED_DIRECT_CONTEXT_APP=1' in state['argv']
    need(not(arena and cached_direct),'one finite application selector')
    support=fixture.parent/'persistent_direct_frontier_app' if arena or cached_direct else fixture
    if arena:
        need(fixture.name=='loop_translation_arena_app' and
             state['argv'].count('-DLI2_LOOP_TRANSLATION_ARENA_APP=1')==1 and
             not any(x.startswith(('-DLI2_LOOP_RX_REFERENCE44=',
                 '-DLI2_LOOP_GROUP_DESCRIPTOR_APP=','-DLI2_LOOP_CACHE8_EFFECT='))for x in state['argv']),
             'one literal arena selector and the original shared copy-oracle source')
    if cached_direct:
        need(fixture.name=='loop_cached_direct_context_app' and
             state['argv'].count('-DLI2_LOOP_CACHED_DIRECT_CONTEXT_APP=1')==1 and
             not any(x.startswith(('-DLI2_LOOP_RX_REFERENCE44=',
                 '-DLI2_LOOP_GROUP_DESCRIPTOR_APP=','-DLI2_LOOP_CACHE8_EFFECT='))for x in state['argv']),
             'one literal cached DIRECT selector and the unchanged shared copy oracle')
    script=pin(support/'build-copy-oracle.sh');output=private/'active-app-copy-oracle'
    rows=recipe(script,'"$cc"');need(len(rows)==1,'one actual two-TU copy oracle recipe')
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':fixture,'$output':output})
    if arena or cached_direct:
        need(argv.count(str(fixture/'copy_oracle.c'))==1,'one explicit shared oracle translation unit')
        argv[argv.index(str(fixture/'copy_oracle.c'))]=str(pin(support/'copy_oracle.c'))
        need(argv.count('-DLI2_FAST_EQUAL=1')==1,'one original helper-equality selector')
        argv.insert(argv.index('-DLI2_FAST_EQUAL=1')+1,
            '-DLI2_LOOP_CACHED_DIRECT_CONTEXT_APP=1' if cached_direct else '-DLI2_LOOP_TRANSLATION_ARENA_APP=1')
    if arena or cached_direct:units=[str(pin(support/'copy_oracle.c')),str(pin(fixture/'pure.c'))]
    else:units=[str(pin(fixture/n))for n in ('copy_oracle.c','pure.c')]
    if '-DLI2_LOOP_RX_REFERENCE44=1' in state['argv']:
        argv.insert(argv.index('-Werror')+1,'-DLI2_LOOP_RX_REFERENCE44=1')
    if '-DLI2_LOOP_GROUP_DESCRIPTOR_APP=1' in state['argv']:
        argv.insert(argv.index('-Werror')+1,'-DLI2_LOOP_GROUP_DESCRIPTOR_APP=1')
    effects=[x for x in state['argv'] if x.startswith('-DLI2_LOOP_CACHE8_EFFECT=')]
    need(not effects or len(effects)==1 and effects[0] in tuple('-DLI2_LOOP_CACHE8_EFFECT='+str(i) for i in (2,3,4)),
         'one literal real-effect application compiler selector')
    if effects:argv.insert(argv.index('-Werror')+1,effects[0])
    need(not effects or '-DLI2_LOOP_GROUP_DESCRIPTOR_APP=1' not in state['argv'],
         'one distinct descriptor or real-effect application selector')
    flags=lambda args,inputs:[x for x in args[1:-2]if x not in inputs and not x.startswith('-Wl,')]
    app_flags=flags(state['argv'],app_units)
    interpreter_define='-DLI2_DIRECT_FRONTIER_INTERPRETER=\"'+str(original.parent/'fixture-interpreter.so')+'\"'
    need(app_flags.count('-nostdlib')==1 and app_flags.count(interpreter_define)==1,
         'only explicit freestanding link option and entry-only interpreter define')
    codegen_flags=[x for x in app_flags if x not in ('-nostdlib',interpreter_define)]
    need(argv[-2:]==['-o',str(output)]and[x for x in argv if x.endswith('.c')]==units and
         flags(argv,units)==codegen_flags and '-DNDEBUG'not in argv and
         '-Wl,-z,relro,-z,now,-z,noexecstack'in argv,
         'copy oracle uses exact actual application helper-affecting compiler flags')
    observed=state['copy_oracle']=dict(status='failed',recipe=fact(script),argv=argv,
        expected_counts=COPY_COUNTS,qualification_credit=False,performance_credit=False)
    _,out,err=run('app-copy-headers',[builder.tools['cc'],*flags(argv,units),'-M','-MT','li2_copy',*units],
        profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==2 and all(x.startswith('li2_copy: ')for x in lines),
         'whole actual two-TU copy oracle header closure')
    includes={str(pin(n)):fact(pin(n))for line in lines for n in shlex.split(line.split(':',1)[1])}
    need(set(units)|{str(support/'app.h')}<=set(includes)and
         includes[str(fixture/'pure.c')]==state['headers'][str(fixture/'pure.c')],
         'oracle and application use the same complete actual helper source')
    observed['headers']=includes
    # Actual preprocessing proves the entry-assembly define has no effect on
    # the complete helper TU; -nostdlib changes link startup only.
    _,app_pure,err=run('app-pure-preprocess',[builder.tools['cc'],*app_flags,'-E','-P',fixture/'pure.c'],
        profile='finite',env=builder.environment)
    need(app_pure and not err,'whole actual application helper preprocessing')
    _,oracle_pure,err=run('copy-pure-preprocess',[builder.tools['cc'],*flags(argv,units),'-E','-P',fixture/'pure.c'],
        profile='finite',env=builder.environment)
    need(app_pure==oracle_pure and not err,'whole helper preprocessing agrees in both exact compiler contexts')
    observed['preprocessed_helper']=dict(bytes=len(app_pure),sha256=H(app_pure))
    run('app-copy-link',argv,profile='finite',env=builder.environment)
    executable=binary(output);data,head,segments=elf(executable)
    need(head[1:4]==(2,62,1)and all(s[2]+s[5]<=len(data)and s[5]<=s[6]and s[1]&3!=3
         for s in segments if s[0]==1),'complete actual non-PIE copy oracle without WX')
    _,symbols,err=run('app-copy-symbols',[builder.tools['nm'],'-S','--defined-only',executable],
        profile='finite',env=builder.environment)
    found=[line.split()for line in symbols.splitlines()if line.split()[-1:]==[b'copy']]
    need(not err and len(found)==1 and len(found[0])==4 and found[0][2]==b'T'and int(found[0][1],16)>0,
         'one complete nonempty actual copy oracle text symbol')
    address,size=int(found[0][0],16),int(found[0][1],16)
    def body(image,at,n):
        raw,_,loads=elf(image)
        owners=[s for s in loads if s[0]==1 and s[1]==5 and s[3]<=at<at+n<=s[3]+s[5]]
        need(len(owners)==1 and n>0,'whole copy body lies in one actual RX load')
        item=owners[0];offset=item[2]+at-item[3];return raw[offset:offset+n]
    actual=body(executable,address,size);expected=body(original,app_symbol['address'],app_symbol['bytes'])
    need(actual==expected,'oracle executes the exact whole emitted application copy body')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,assembly,err=run('app-copy-body',[objdump,'-d','-w','-M','att',
        '--start-address='+hex(address),'--stop-address='+hex(address+size),executable],
        profile='finite',env=builder.environment)
    need(not err and b'<copy>:'in assembly,'actual complete copy disassembly')
    emitted=[];cursor=address;instructions=[]
    for line in assembly.decode().splitlines():
        match=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
        if match:
            chunk=bytes.fromhex(match[2]);need(int(match[1],16)==cursor and chunk and cursor+len(chunk)<=address+size,
                'complete contiguous actual copy instruction bytes')
            emitted.append(chunk);instructions.append(match[3]);cursor+=len(chunk)
    need(cursor==address+size and b''.join(emitted)==actual,'whole copy disassembly equals both actual ELFs')
    forbidden=r'\b(?:l?callq?|rep(?:e|ne|z|nz)?|(?:movs|stos|lods|scas|cmps|ins|outs)[bwlq]?)\b|%[xyz]?mm[0-9]+\b'
    need(all(re.search(forbidden,x)is None for x in instructions),
         'actual copy has no call, string, REP or vector instruction')
    observed['body']=dict(bytes=len(actual),sha256=H(actual))
    observed['app_symbol']=app_symbol;observed['oracle_symbol']=dict(address=address,bytes=size)
    interps=[s for s in segments if s[0]==3];need(len(interps)==1,'one actual copy oracle interpreter')
    item=interps[0];literal=data[item[2]:item[2]+item[5]]
    need(literal.startswith(b'/')and literal.endswith(b'\0')and b'\0'not in literal[:-1],
         'complete literal copy oracle interpreter')
    loader=pin(os.fsdecode(literal[:-1]));observed['runtime_libraries']={}
    _,out,err=run('app-copy-libraries',[loader,'--list',executable],profile='finite',env=builder.environment)
    need(not err,'actual complete copy oracle runtime library listing')
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'one resolved actual copy oracle library')
        path=pin(match[1]);need(path.name not in observed['runtime_libraries'],'unique copy oracle library name')
        observed['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in observed['runtime_libraries'].values()),
         'actual interpreter belongs to complete copy oracle runtime closure')
    observed['artifact']=fact(executable)
    label='app-copy-run'
    row,out,err=run(label,[executable],profile='finite',env=builder.environment)
    need(out==COPY_STDOUT and err==b''and row['exit']==0,'every exact copy oracle case completes')
    need(all(fact(path)==value for path,value in includes.items()),'copy oracle whole source closure unchanged')
    observed.update(status='passed',counts=COPY_COUNTS,exit=row['exit'],duration_ns=row['duration_ns'],
        bounds=row['bounds'],captures={k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()})


def compile_subject(builder,private,pin,binary,aliases,run,r, *, reference='direct41', fixture=None):
    fixture=FIXTURE if fixture is None else Path(fixture).resolve(strict=True)
    if reference=='cached-direct-ab146':
        need(fixture.name=='loop_cached_direct_context_app','exact two-root cached DIRECT fixture source')
    elif reference=='arena10-ab791':
        need(fixture.name=='loop_translation_arena_app','exact ten-root arena fixture source')
    elif reference=='cache8-abc255':
        need(fixture.name=='loop_cache8_app','exact additive three-phase descriptor fixture source')
    elif reference in ('cache8-effects2','cache8-effects3','cache8-effects4'):
        need(fixture.name=='loop_cache8_effects','exact additive real-effect fixture source')
    elif reference=='cache8-abc169':
        need(fixture.name=='loop_cache8_app','exact additive three-root/two-phase fixture source')
    else:
        need(reference in ('direct41','direct44'), 'explicit unchanged41 or additive44 seed recipe')
    output=private/'application';output.mkdir()
    script=pin(fixture/'build.sh');linker=pin(fixture/'app.ld')
    rows=recipe(script,'"$cc"');need(len(rows)==2,'exact interpreter and freestanding application recipes')
    values={'$cc':builder.tools['cc'],'$source_dir':fixture,'$output':output}
    interp_unit=pin(fixture/'fixture-interpreter.S')
    donor=pin(fixture.parents[2]/'fixture-interpreter.S')
    need(interp_unit.read_bytes()==donor.read_bytes(),'complete original source-owned fixture interpreter')
    interp_argv=expand(rows[0],values)
    expected=[str(builder.tools['cc']),'-nostdlib','-shared','-Wl,-e,_start,-z,noexecstack,--build-id=none',
              str(interp_unit),'-o',str(output/'fixture-interpreter.so')]
    need(interp_argv==expected,'exact original tiny-interpreter compiler recipe')
    _,out,err=run('app-interpreter-headers',[builder.tools['cc'],'-nostdlib','-shared','-M','-MT','li2_interp',interp_unit],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==1 and rules[0].startswith('li2_interp: '),'whole actual interpreter include rule')
    interp_headers={str(pin(n)):fact(pin(n))for n in shlex.split(rules[0].split(':',1)[1])}
    need(str(interp_unit)in interp_headers,'actual tiny-interpreter translation unit')
    _,out,err=run('app-interpreter-link',interp_argv,profile='release_build',env=builder.environment)
    need(out==err==b'','strict actual tiny-interpreter build')
    interpreter=pin(binary(interp_argv[-1]));data,head,segments=elf(interpreter)
    need(head[1:4]==(3,62,1)and all(p[2]+p[5]<=len(data)and p[5]<=p[6]and p[1]&3!=3
         for p in segments if p[0]==1)and not any(p[0]==3 for p in segments),
         'whole actual unchained ET_DYN interpreter without WX')
    info=namespace.parse(data)
    need(info==dict(elf_type=3,needed=[],soname=None,interpreter=None),
         'exact tiny interpreter has no external dynamic dependencies')
    _,out,err=run('app-interpreter-undefined',[builder.tools['nm'],'-u',interpreter],profile='inspect',env=builder.environment)
    need(out==err==b'','no unresolved actual tiny-interpreter imports')
    _,out,err=run('app-interpreter-symbols',[builder.tools['nm'],'-S','--defined-only',interpreter],profile='inspect',env=builder.environment)
    found=[line.split()for line in out.splitlines()if line.split()[-1:]==[b'_start']]
    need(not err and len(found)==1 and len(found[0])==4 and found[0][2]==b'T',
         'one exact source-owned interpreter entry symbol')
    start,size=int(found[0][0],16),int(found[0][1],16)
    owners=[p for p in segments if p[0]==1 and p[1]==5 and p[3]<=start<start+size<=p[3]+p[5]]
    expected_body=bytes.fromhex('0fa2488b0c24488d74cc1048ad4885c075f948ad4889c148ad4883f90974074885c975ee0f0bffe0')
    need(len(owners)==1 and size==len(expected_body)==40 and head[4]==start,
         'whole40-byte actual interpreter entry range')
    owner=owners[0];at=owner[2]+start-owner[3]
    need(data[at:at+size]==expected_body,'complete actual interpreter performs original auxv AT_ENTRY transfer')
    argv=expand(rows[1],values)
    if reference == 'direct44':argv.insert(argv.index('-Werror')+1,'-DLI2_LOOP_RX_REFERENCE44=1')
    if reference == 'cache8-abc255':argv.insert(argv.index('-Werror')+1,'-DLI2_LOOP_GROUP_DESCRIPTOR_APP=1')
    if reference in ('cache8-effects2','cache8-effects3','cache8-effects4'):
        argv.insert(argv.index('-Werror')+1,'-DLI2_LOOP_CACHE8_EFFECT='+reference[-1])
    if reference == 'cached-direct-ab146':
        need(argv.count('-DLI2_LOOP_CACHED_DIRECT_CONTEXT_APP=1')==1,
             'one literal standalone cached DIRECT application selector')
    if reference == 'arena10-ab791':
        need(argv.count('-DLI2_LOOP_TRANSLATION_ARENA_APP=1')==1,
             'one literal standalone arena application selector')
    units=[str(pin(fixture/n))for n in ('main.c','pure.c','machine.S','entry.S')]
    need([x for x in argv if x.endswith(('.c','.S'))]==units and
         argv[-2:]==['-o',str(output/'persistent-direct-frontier-app')]and
         '-Wl,-T,'+str(linker)in argv and '-DLI2_FAST_EQUAL=1'in argv and
         '-DLI2_DIRECT_FRONTIER_INTERPRETER="'+str(interpreter)+'"'in argv and
         all(f in argv for f in ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only',
             '-mcmodel=large','-fno-pie','-no-pie','-fno-builtin','-fno-strict-aliasing',
             '-fno-stack-protector','-fno-tree-vectorize','-nostdlib')),
         'exact whole freestanding application source and no-FP full-range recipe')
    state=r['application_build']=dict(status='failed',recipe=fact(script),argv=argv,
        interpreter=dict(path=str(interpreter),**fact(interpreter)),interpreter_source=fact(interp_unit),
        interpreter_headers=interp_headers,interpreter_argv=interp_argv,
        interpreter_entry=dict(address=start,bytes=size,sha256=H(expected_body)),
        linker=fact(linker),qualification_credit=False)
    flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
    _,out,err=run('app-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*units],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==4 and all(x.startswith('li2_app: ')for x in rules),
         'one complete include rule for every actual freestanding translation unit')
    includes={}
    for rule in rules:
        for name in shlex.split(rule.split(':',1)[1]):
            path=Path(name).absolute();resolved=str(pin(path))
            need(str(path)not in aliases or aliases[str(path)]==resolved,'unchanged application header alias')
            aliases[str(path)]=resolved;includes[resolved]=fact(resolved)
    need(set(units)|{str(fixture/'app.h')}<=set(includes),'all actual freestanding source/header inputs')
    state['headers']=includes
    _,out,err=run('app-link',argv,profile='release_build',env=builder.environment)
    need(out==err==b'','strict actual freestanding application build')
    image=binary(argv[-1]);info=namespace.parse(image.read_bytes())
    need(info==dict(elf_type=2,needed=[],soname=None,interpreter=interpreter),
         'actual application names only exact fresh source-owned interpreter and no dependencies')
    _,out,err=run('app-undefined',[builder.tools['nm'],'-u',image],profile='inspect',env=builder.environment)
    need(out==err==b'','no unresolved actual freestanding application imports')
    return inspect_application(builder,private,pin,binary,run,state,image,units,fixture=fixture)


def effect_image(original,actual_symbols,kind):
    """Literal actual fixture bytes, never an instruction/admission decoder."""
    import struct
    need(kind in (2,3,4),'one fixed actual real effect')
    symbols={}
    for line in actual_symbols.decode().splitlines():
        fields=line.split()
        if len(fields) in (3,4) and (fields[-1].startswith('region_app_') or fields[-1]=='lc8e_state'):
            name=fields[-1]
            need(name not in symbols,'unique actual application symbol names')
            symbols[name]=(int(fields[0],16),int(fields[1],16) if len(fields)==4 else 0,fields[-2])
    sites={'region_app_reset':0x416000,'region_app_head':0x410200,'region_app_block_b':0x412400,
           'lc8e_state':0x800000}
    if kind==2:sites.update(region_app_effect_syscall0=0x416048,region_app_effect_syscall1=0x41606f,
                           region_app_reset_jump=0x4160b3,region_app_effect_end=0x4160b8)
    elif kind==3:sites.update(region_app_effect_write=0x416000,region_app_reset_jump=0x416008,
                             region_app_effect_end=0x41600a)
    else:sites.update(region_app_effect_load=0x416000,region_app_effect_jump=0x416007,
                     region_app_reset_jump=0x416007,region_app_effect_end=0x416009)
    need(all(name in symbols and symbols[name][0]==value for name,value in sites.items()) and
         symbols['lc8e_state'][1:]==(256,'B'),'actual fixed effect sites and whole zero-initialized guest state')
    data,_,segments=elf(original)
    state=[x for x in segments if x[0]==1 and x[3]<=0x800000<x[3]+x[6]]
    need(len(state)==1 and state[0][1]==6 and state[0][3]==0x800000 and state[0][5]==0 and state[0][6]==4096,
         'actual separate whole original RW/NX zero-file state page')
    first=sites['region_app_reset'];end=sites['region_app_effect_end'];body=bytearray()
    def rip(op,target,tail=b''):
        body.extend(op+struct.pack('<i',target-(first+len(body)+len(op)+4+len(tail)))+tail)
    if kind==2:
        for op,offset in ((b'\x48\x89\x05',0),(b'\x48\x89\x0d',8),(b'\x48\x89\x15',16),
                          (b'\x48\x89\x35',24),(b'\x48\x89\x3d',32),(b'\x4c\x89\x1d',40)):
            rip(op,0x800000+offset)
        rip(b'\xc7\x05',0x800040,struct.pack('<I',1))
        body.extend(b'\xbf'+struct.pack('<I',0x412000)+b'\xbe'+struct.pack('<I',4096)+
                    b'\xba'+struct.pack('<I',1)+b'\xb8'+struct.pack('<I',10)+b'\x0f\x05')
        rip(b'\x48\x89\x05',0x800030)
        rip(b'\xc7\x05',0x800048,struct.pack('<I',1));rip(b'\xc7\x05',0x800050,struct.pack('<I',1))
        body.extend(b'\xba'+struct.pack('<I',5)+b'\xb8'+struct.pack('<I',10)+b'\x0f\x05')
        rip(b'\x48\x89\x05',0x800038);rip(b'\xc7\x05',0x800058,struct.pack('<I',1))
        for op,offset in ((b'\x48\x8b\x0d',8),(b'\x48\x8b\x15',16),(b'\x48\x8b\x35',24),
                          (b'\x48\x8b\x3d',32),(b'\x4c\x8b\x1d',40),(b'\x48\x8b\x05',0)):
            rip(op,0x800000+offset)
        body.extend(b'\x48\xc7\xc1\x08\x00\x00\x00');rip(b'\xe9',0x410200)
    elif kind==3:body.extend(bytes.fromhex('c60425002441005a0f0b'))
    else:rip(b'\x48\x8b\x05',0x800060);body.extend(b'\xff\xe0')
    owners=[x for x in segments if x[0]==1 and x[1]==5 and x[3]<=first<end<=x[3]+x[5]]
    need(len(owners)==1 and len(body)==end-first,'whole literal actual effect body extent')
    owner=owners[0];at=owner[2]+first-owner[3]
    need(data[at:at+len(body)]==body,'every actual guest effect opcode/displacement/immediate matches its fixed model')
    return dict(kind=kind,sites=sites,bytes=len(body),sha256=H(body),state_bytes=256,state_page_bytes=4096,
                reference='cache8-effects'+str(kind),total_instructions=195 if kind==2 else None,
                native_tf_events=167 if kind==2 else 83,guest_mapping_admission=kind==2)
