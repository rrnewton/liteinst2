"""Exact lifecycle-v1 native recipe, retained helper oracle and actual launch preparation."""
import ctypes,json,os,re,shlex,shutil
from pathlib import Path
from page_selected import need,elf,ENV,fact
from page_selected_register_time_build import recipe,expand
from persistent_dynamic import H,MASK,load
from persistent_active_domain import COPY_COUNTS,COPY_STDOUT
import namespace
ROOT=Path(__file__).resolve().parents[2]
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/tunables_lifecycle_app'
DONOR=SELECTED/'tests/persistent_direct_frontier_app'
APP_FLAGS=('-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-fno-builtin','-fno-strict-aliasing',
    '-fno-stack-protector','-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-mgeneral-regs-only',
    '-DLI2_FAST_EQUAL=1','-mcmodel=large','-fno-asynchronous-unwind-tables','-fno-unwind-tables',
    '-fno-pie','-no-pie','-nostdlib')


def inspect_application(builder,private,pin,binary,run,state,original,app_units):
    data,head,segments=elf(original)
    need(head[1:4]==(2,62,1)and not any(p[0]==1 and p[1]&3==3 for p in segments),
         'actual lifecycle-v1 application ET_EXEC without WX')
    _,_,err=run('app-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',original],profile='inspect',env=builder.environment)
    need(not err,'whole actual application ELF inspection')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('app-objdump-version',[objdump,'--version'],env=builder.environment)
    need(out and not err,'actual app disassembler identity')
    _,out,err=run('app-symbols',[builder.tools['nm'],'-S','--defined-only',original],profile='inspect',env=builder.environment)
    need(not err,'actual emitted lifecycle-v1 function symbols');symbols={};bodies={}
    for name in ('main','lc_inputs','lc_model_init','lc_advance','copy','same','ua_data_pattern','ua_stack_pattern'):
        found=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]=='T','one complete lifecycle-v1 function symbol')
        address,size=int(found[0][0],16),int(found[0][1],16)
        owners=[p for p in segments if p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]]
        need(size>0 and len(owners)==1,'whole emitted function in one actual RX file extent')
        if name in ('copy','same','ua_data_pattern','ua_stack_pattern'):
            need(0x200001000<=address<address+size<=0x200002000,'original complete pure helper page')
        symbols[name]=dict(address=address,bytes=size)
        _,assembly,err=run('app-body-'+name,[objdump,'-d','-w','-M','att','--start-address='+hex(address),
            '--stop-address='+hex(address+size),original],profile='inspect',env=builder.environment)
        need(assembly and not err and ('<'+name+'>:').encode()in assembly,'complete actual function inspection')
        emitted=[];cursor=address
        for line in assembly.decode().splitlines():
            match=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
            if match:
                chunk=bytes.fromhex(match[2]);need(int(match[1],16)==cursor and chunk and cursor+len(chunk)<=address+size,
                    'whole contiguous lifecycle-v1 function bytes');emitted.append(chunk);cursor+=len(chunk)
        p=owners[0];offset=p[2]+address-p[3]
        need(cursor==address+size and b''.join(emitted)==data[offset:offset+size],'nm/disassembly/ELF whole body equality')
        bodies[name]=assembly.decode()
    # This fixture initializes data through lc_inputs, not ua_data_pattern;
    # validate each actual main-to-helper edge and the complete new model TUs.
    callers={name:'main'for name in('copy','same','ua_stack_pattern','lc_inputs','lc_model_init','lc_advance')}
    for name,caller in callers.items():
        need(re.search(r'\bmovabsq?\s+\$0x'+format(symbols[name]['address'],'x')+r',',bodies[caller])is not None,
             'actual '+caller+' materializes full-width '+name+' address without truncated relocation')
    state['helper_callers']=callers
    copy_oracle(builder,private,pin,binary,run,state,original,symbols['copy'],app_units)
    state.update(status='passed',artifact=fact(original),symbols=symbols);return original


def compile_subject(builder,private,pin,binary,aliases,run,r):
    output=private/'application';output.mkdir()
    return application(builder,private,pin,binary,aliases,run,r)


def application(builder,private,pin,binary,aliases,run,r):
    """Same complete recipe/ELF oracle with a real runner or closed-row reader.

    This body creates no directory and writes no file itself. The prerequisite
    supplies only a strict recorded-command callback; the collector supplies the
    real bounded runner after creating its fresh application directory.
    """
    output=private/'application'
    script=pin(FIXTURE/'build.sh');linker=pin(DONOR/'app.ld')
    rows=recipe(script,'cc ');need(len(rows)==2,'exact interpreter and freestanding application recipes')
    need(all(row[0]=='cc'for row in rows),'literal source-owned compiler word')
    rows=[[str(builder.tools['cc']),*row[1:]]for row in rows]
    values={'$here':FIXTURE,'$old':DONOR,'$out':output}
    interp_unit=pin(DONOR/'fixture-interpreter.S')
    donor=pin(FIXTURE.parents[2]/'fixture-interpreter.S')
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
    units=[str(pin((FIXTURE if n in ('main.c','reference.c','machine.S')else DONOR)/n))for n in ('main.c','reference.c','pure.c','machine.S','entry.S')]
    need([x for x in argv if x.endswith(('.c','.S'))]==units and
         argv[-2:]==['-o',str(output/'tunables-lifecycle')]and
         '-Wl,-T,'+str(linker)in argv and '-DLI2_FAST_EQUAL=1'in argv and
         '-DLI2_DIRECT_FRONTIER_INTERPRETER="'+str(interpreter)+'"'in argv and
         all(f in argv for f in ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only',
             '-mcmodel=large','-fno-pie','-no-pie','-fno-builtin','-fno-strict-aliasing',
             '-fno-stack-protector','-fno-tree-vectorize','-nostdlib')),
         'exact whole freestanding application source and no-FP full-range recipe')
    need(argv==[str(builder.tools['cc']),*APP_FLAGS,'-DLI2_DIRECT_FRONTIER_INTERPRETER="'+str(interpreter)+'"',
        '-Wl,-z,noexecstack,--build-id=none,--no-undefined','-Wl,-T,'+str(linker),
        '-I'+str(DONOR),'-I'+str(FIXTURE),*units,'-o',str(output/'tunables-lifecycle')],
        'complete exact five-TU lifecycle-v1 compiler argv')
    state=r['application_build']=dict(status='failed',recipe=fact(script),argv=argv,
        interpreter=dict(path=str(interpreter),**fact(interpreter)),interpreter_source=fact(interp_unit),
        interpreter_headers=interp_headers,interpreter_argv=interp_argv,
        interpreter_entry=dict(address=start,bytes=size,sha256=H(expected_body)),
        linker=fact(linker),qualification_credit=False)
    flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
    _,out,err=run('app-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*units],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==5 and all(x.startswith('li2_app: ')for x in rules),
         'one complete include rule for every actual freestanding translation unit')
    includes={}
    for rule in rules:
        for name in shlex.split(rule.split(':',1)[1]):
            path=Path(name).absolute();resolved=str(pin(path))
            need(str(path)not in aliases or aliases[str(path)]==resolved,'unchanged application header alias')
            aliases[str(path)]=resolved;includes[resolved]=fact(resolved)
    need(set(units)|{str(DONOR/'app.h'),str(FIXTURE/'fixture.h')}<=set(includes),'all actual freestanding source/header inputs')
    state['headers']=includes
    _,out,err=run('app-link',argv,profile='release_build',env=builder.environment)
    need(out==err==b'','strict actual freestanding application build')
    image=binary(argv[-1]);info=namespace.parse(image.read_bytes())
    need(info==dict(elf_type=2,needed=[],soname=None,interpreter=interpreter),
         'actual application names only exact fresh source-owned interpreter and no dependencies')
    _,out,err=run('app-undefined',[builder.tools['nm'],'-u',image],profile='inspect',env=builder.environment)
    need(out==err==b'','no unresolved actual freestanding application imports')
    state['translation_units']=5
    return inspect_application(builder,private,pin,binary,run,state,image,units)


def copy_oracle(builder,private,pin,binary,run,state,original,app_symbol,app_units):
    """Bound the actual fixture helper to an independent complete-byte oracle."""
    script=pin(DONOR/'build-copy-oracle.sh');output=private/'active-app-copy-oracle'
    rows=recipe(script,'"$cc"');need(len(rows)==1,'one actual two-TU copy oracle recipe')
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':DONOR,'$output':output})
    units=[str(pin(DONOR/n))for n in('copy_oracle.c','pure.c')]
    # This new fixture has one extra source include root. Pass it to the actual
    # oracle too, then retain the unchanged exact whole flags/preprocessing/body joins.
    addition='-I'+str(FIXTURE)
    need(addition not in argv and argv.count('-I'+str(DONOR))==1,'one explicit lifecycle include addition')
    argv.insert(argv.index('-I'+str(DONOR))+1,addition)
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
        expected_counts=COPY_COUNTS,recipe_additions=[addition],qualification_credit=False,performance_credit=False)
    _,out,err=run('app-copy-headers',[builder.tools['cc'],*flags(argv,units),'-M','-MT','li2_copy',*units],
        profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==2 and all(x.startswith('li2_copy: ')for x in lines),
         'whole actual two-TU copy oracle header closure')
    includes={str(pin(n)):fact(pin(n))for line in lines for n in shlex.split(line.split(':',1)[1])}
    need(set(units)|{str(DONOR/'app.h')}<=set(includes)and
         includes[str(DONOR/'pure.c')]==state['headers'][str(DONOR/'pure.c')],
         'oracle and application use the same complete actual helper source')
    observed['headers']=includes
    # Actual preprocessing proves the entry-assembly define has no effect on
    # the complete helper TU; -nostdlib changes link startup only.
    _,app_pure,err=run('app-pure-preprocess',[builder.tools['cc'],*app_flags,'-E','-P',DONOR/'pure.c'],
        profile='finite',env=builder.environment)
    need(app_pure and not err,'whole actual application helper preprocessing')
    _,oracle_pure,err=run('copy-pure-preprocess',[builder.tools['cc'],*flags(argv,units),'-E','-P',DONOR/'pure.c'],
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


def reader_support(builder,private,pin,binary,run,r):
    reader=load('loop_lifecycle_native_read',FIXTURE/'read.py',pin)
    controls=load('loop_lifecycle_native_controls',FIXTURE/'controls.py',pin)
    policy=private/'native-policy.so';unit=pin(SELECTED/'native_policy.c')
    flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared']
    _,out,err=run('policy-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_policy',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_policy: '),'complete actual native-policy include rule')
    included={str(pin(p)):fact(pin(p))for p in shlex.split(lines[0].split(':',1)[1])}
    need({str(unit),str(SELECTED/'native_policy.h')}<=set(included),'whole original native-policy source closure')
    _,out,err=run('policy-link',[builder.tools['cc'],*flags,'-Wl,-z,noexecstack,--build-id=none',unit,'-o',policy],
        profile='release_build',env=builder.environment)
    need(out==err==b'','strict actual original native-policy build')
    r['reader_support']=dict(headers=included,native_policy=dict(path=str(binary(policy)),**fact(policy)))
    lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
    return reader,controls,lambda data:lib.li2_native_policy(data,len(data))


def observed_layout(builder,original,private,pin,binary,run,r,*,completed=False):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(FIXTURE/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment)
    need(out and not err,'actual native DWARF tool identity')
    _,out,err=run('native-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','--readnow','--se='+str(original),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one complete no-inferior DWARF observation')
    layout=json.loads(out);need(layout['record']=='lc_lifecycle_v1','distinct actual lifecycle-v1 schema')
    path=private/'native-dwarf-layout.json'
    if completed:need(path.read_bytes()==out,'whole retained actual lifecycle native layout')
    else:
        with path.open('xb')as stream:stream.write(out)
    binary(path)
    r['native_layout']=dict(path=str(path),artifact=fact(path),application=fact(original),observer=fact(script))
    return layout


def native_namespace(original,application,pin,r):
    interp=pin(application['interpreter']['path'])
    need(fact(interp)=={k:application['interpreter'][k]for k in ('bytes','sha256')}and
         namespace.parse(original.read_bytes())==dict(elf_type=2,needed=[],soname=None,interpreter=interp)and
         namespace.parse(interp.read_bytes())==dict(elf_type=3,needed=[],soname=None,interpreter=None),
         'fresh original and tiny source-owned interpreter have no hidden dynamic dependencies')
    objects,description=namespace.plan(original,[original.parent],bytes.fromhex(fact(original)['sha256']),
        bytes.fromhex(fact(interp)['sha256']))
    need(objects==[],'complete empty dependency namespace for actual freestanding native fixture')
    r['native_namespace']=dict(plan=description,original=dict(path=str(original),**fact(original)),
        interpreter=dict(path=str(interp),**fact(interp)),library_roots=[str(original.parent)])


def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,placement,control=case['lane'],case['mode'],case['placement'],case['control'];role='native'if lane==0 else'gated';prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(type(lane)is int and lane in(0,1)and type(mode)is int and mode in range(2)and
         type(placement)is int and placement in range(2)and control==0,'typed actual lifecycle launch case')
    common={'schema_version','status','role','pid','cpu','previous_mask','reset_mask','dispositions','observer',
            'argv','default_rseq','lane','case','placement','control','launch_mask'}
    need(set(prep)==common|({'environment'}if lane==0 else{'late_sonames','environment_source'})and
         type(prep['previous_mask'])is int and 0<=prep['previous_mask']<1<<64 and
         all(set(x)=={'signal','before','after'}and type(x['before'])is int and x['before']>=0
             for x in prep['dispositions']),'whole actual paired preparation grammar')
    need(not any(k in prep for k in('current_custody','current_control','physical_fallback')),'no unrelated launch profile')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==role and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane==0 else 0)and
        prep['argv']==[str(original),str(lane),str(mode),str(placement)]and prep['default_rseq']is False and
        prep['lane']==lane and prep['case']==mode and prep['placement']==placement and prep['control']==control and
        [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and all(x['after']==0 for x in prep['dispositions']),
        'actual exact launch signal/mode/environment preparation')
    if lane==0:
        need(prep['observer']is None and prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH=':'.join(map(str,roots))),'actual closed native exec environment')
        return None
    ns=directory/'namespace';manifest=json.loads(binary(ns/'namespace.json').read_bytes());launch=json.loads(binary(ns/'launch.json').read_bytes())
    need(all(manifest[k]==v for k,v in description.items())and len(manifest['objects'])==len(objects)and manifest['schema_version']==1 and
        manifest['scope']=='explicit_sealed_dependency_namespace'and manifest['status']=='prepared_not_executed'and manifest['directory']==str(ns)and
        manifest['search_policy']=='explicit roots; no RPATH/RUNPATH/cache emulation'and manifest['identity_policy']=='sealed copies and private paths; not filesystem transparency',
        'actual namespace matches complete independent source plan')
    fds=[]
    for observed,item in zip(manifest['objects'],objects,strict=True):
        need(observed['names']==item['names']and observed['needed']==item['info']['needed']and observed['source']==str(item['path'])and
            observed['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and observed['sha256']==H(item['bytes'])and
            observed['size']==len(item['bytes'])and observed['seals']==namespace.SEALS and type(observed['fd'])is int and observed['fd']>3 and observed['fd']not in fds and
            type(observed['device'])is int and observed['device']>0 and type(observed['inode'])is int and observed['inode']>0,'actual sealed dependency identity')
        fds.append(observed['fd'])
        for name in item['names']:
            p=ns/name;value='/proc/self/fd/'+str(observed['fd']);need(p.is_symlink()and os.readlink(p)==value,'actual sealed dependency alias');r['namespace_aliases'][str(p)]=value
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',argv=prep['argv'],dependency_fds=fds,
        carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],environment=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',
        LD_BIND_NOW='1',LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),GLIBC_TUNABLES='glibc.pthread.rseq=0',
        LI2_PERSISTENT_LOOP_LIFECYCLE_CASE=str(mode),LI2_PERSISTENT_LOOP_LIFECYCLE_PLACEMENT=str(placement),LI2_PERSISTENT_LOOP_LIFECYCLE_LANE='1'))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest


def native_preparation(path,row,original,mode,placement,cpu,binary):
    return preparation(dict(lane=0,mode=mode,placement=placement,control=0),row,path.parent,
        original,[original.parent],[],None,None,path.parent.parent,binary,dict(cpu=cpu))
