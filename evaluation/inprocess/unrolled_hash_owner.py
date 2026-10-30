#!/usr/bin/env python3
"""Fixed25 actual native/application-owner subjects; no throughput credit."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/unrolled_hash_app'
OWNER=SELECTED/'tests/unrolled_hash_owner'
sys.path[:0]=[str(HERE),str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,interpreter,need,save
from page_selected_generic_build import Build,PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand,recipe
from unrolled_hash_build import build_bridge
import namespace
import unrolled_hash_app_reports as reports
BOUNDS=dict(PROFILES,release_build=[30,512<<20,16<<20,60],program=[30,512<<20,16<<20,60],seed=[5,512<<20,16<<20,15])
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
H=lambda b:hashlib.sha256(b).hexdigest()
ORDER=tuple((lane,mode,0)for lane in('native','gated')for mode in range(9))+tuple(('gated',0,c)for c in range(1,8))


def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def load(name,path,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path));module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


def reader_support(builder,private,pin,binary,run,r):
    current=r.get('current_custody',False)
    reader=load('current_app_read'if current else 'unrolled_app_read',
        SELECTED/'tests/current_custody_app/read.py'if current else FIXTURE/'read.py',pin)
    owner=load('current_owner_read'if current else 'unrolled_owner_read',
        SELECTED/'tests/current_custody_owner/read.py'if current else OWNER/'read.py',pin)
    policy=private/'native-policy.so';unit=pin(SELECTED/'native_policy.c')
    flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared']
    _,out,err=run('policy-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_policy',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_policy: '),'complete policy include rule')
    headers={str(pin(path)):fact(pin(path))for path in shlex.split(lines[0].split(':',1)[1])}
    need(str(unit)in headers and str(SELECTED/'native_policy.h')in headers,'actual policy sources')
    run('policy-link',[builder.tools['cc'],*flags,'-Wl,-z,noexecstack,--build-id=none',unit,'-o',policy],profile='release_build',env=builder.environment)
    r['reader_support']=dict(headers=headers,native_policy=fact(binary(policy)))
    lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
    return reader,owner,lambda data:lib.li2_native_policy(data,len(data))


def compile_subject(builder,private,pin,binary,run,r):
    current=r.get('current_custody',False)
    script=pin(SELECTED/'tests/current_custody_app/build.sh'if current else FIXTURE/'build.sh')
    rows=recipe(script,'"$cc"');need(len(rows)==1,'one exact three-TU app recipe')
    output=private/'application';output.mkdir()
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':FIXTURE,'$output':output})
    sources=[str(pin(FIXTURE/x))for x in('main.c','pure.c','machine.S')]
    need(argv[-2:]==['-o',str(output/'unrolled-hash-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
         [x for x in argv if x.startswith('-D')]==(['-DLI2_FAST_EQUAL=1','-DLI2_CURRENT_TF_APP=1']if current else ['-DLI2_FAST_EQUAL=1'])and all(x in argv for x in
         ('-O2','-g','-Wall','-Wextra','-Werror','-fno-builtin','-mgeneral-regs-only','-mcmodel=large',
          '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-pie','-no-pie')),
         'actual release application source/whole-range helper configuration')
    linker=pin(FIXTURE/'pure.ld');need('-Wl,-T,'+str(linker)in argv,'exact retained helper-page linker source')
    state=r['application_build']=dict(status='failed',recipe=fact(script),linker=fact(linker),argv=argv)
    flags=[x for x in argv[1:-2]if x not in sources and not x.startswith('-Wl,')]
    _,out,err=run('app-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*sources],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==3 and all(x.startswith('li2_app: ')for x in lines),'complete actual three-TU app include closure')
    includes={}
    for line in lines:
        for name in shlex.split(line.split(':',1)[1]):p=pin(name);includes[str(p)]=fact(p)
    need(set(sources)|{str(FIXTURE/'app.h')}<=set(includes),'actual complete app header/source inputs before compilation')
    if current:need({str(SELECTED/'tests/current_custody_app'/x)for x in ('types.h','native.inc')}<=set(includes),
        'actual compiler observes the explicit complete current application profile')
    state['headers']=includes
    run('app-link',argv,profile='release_build',env=builder.environment)
    original=binary(output/'unrolled-hash-app');_,head,segments=elf(original)
    need(head[1:4]==(2,62,1)and not any(s[0]==1 and s[1]&3==3 for s in segments),'actual non-PIE x86-64 app without WX')
    _,_,err=run('app-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',original],profile='inspect',env=builder.environment)
    need(not err,'actual complete app ELF inspection')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('app-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual app disassembler identity')
    _,out,err=run('app-symbols',[builder.tools['nm'],'-S','--defined-only',original],profile='inspect',env=builder.environment)
    need(not err,'actual emitted helper symbols');symbols={}
    for name in ('main','copy','same','ua_data_pattern','ua_stack_pattern'):
        found=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]=='T','one complete actual app text symbol')
        address,size=int(found[0][0],16),int(found[0][1],16)
        need(size>0 and sum(p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]for p in segments)==1,'whole symbol in exact actual RX segment')
        if name!='main':need(0x200001000<=address<address+size<=0x200002000,'actual high full-range helper body')
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
        if name=='main':main_assembly=assembly.decode()
    for name in ('copy','same','ua_data_pattern','ua_stack_pattern'):
        need(re.search(r'\bmovabsq?\s+\$0x'+format(symbols[name]['address'],'x')+r',',main_assembly)is not None,
             'actual main materializes each full-width high helper address without truncated relocation')
    state.update(status='passed',artifact=fact(original),symbols=symbols);return original


def nested_emission(builder,bridge,pin,run,r):
    """Whole fresh ELF bytes, including every instruction after the last save."""
    objdump=pin(shutil.which('objdump',path=ENV['PATH']));data,_,segments=elf(bridge)
    need(data==bridge.read_bytes(),'same freshly retained bridge for emitted observation proof')
    _,out,err=run('nested-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(out and not err,'complete actual nested shim/gateway symbol inspection');bodies={}
    for name in ('uho_nested_raw','li2_raw6'):
        found=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]=='t','one actual hidden nested observation function')
        address,size=int(found[0][0],16),int(found[0][1],16)
        loads=[p for p in segments if p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]]
        need(0<size<=1024 and len(loads)==1,'whole bounded observation body in one actual RX load')
        _,assembly,err=run('nested-body-'+name,[objdump,'-d','-w','-M','att','--start-address='+hex(address),
            '--stop-address='+hex(address+size),bridge],profile='inspect',env=builder.environment)
        need(assembly and not err and ('<'+name+'>:').encode()in assembly,'complete actual nested body inspection')
        rows=[];cursor=address
        for line in assembly.decode().splitlines():
            match=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
            if match:
                chunk=bytes.fromhex(match[2]);need(int(match[1],16)==cursor and chunk and cursor+len(chunk)<=address+size,
                    'every nested instruction byte lies contiguously in its actual symbol')
                rows.append((cursor,chunk,re.sub(r'\s+','',match[3])));cursor+=len(chunk)
        offset=loads[0][2]+address-loads[0][3];raw=b''.join(x[1]for x in rows)
        need(cursor==address+size and raw==data[offset:offset+size],'whole emitted nested body equals retained ELF bytes')
        bodies[name]=(address,raw,rows)
    gateway=bodies['li2_raw6'];shim=bodies['uho_nested_raw']
    need(gateway[1]==bytes.fromhex('4889f84889f74889d64889ca4d89c24d89c84c8b4c24080f05c3'),
        'whole original scalar RAW7 gateway and exact syscall return offset25')
    # GNU AT&T spellings for fixed non-branch instructions. Branches additionally
    # use their actual encoded displacement, never a printed symbol annotation.
    expected='''mov%rdi,%r10|movq$0x1,0x8(%r10)|mov%rsp,0x28(%r10)|mov0x8(%rsp),%rax|mov%rax,0x70(%r10)|test%rax,%rax|jne
mov0x18(%r10),%rsi|cmp%rsi,%rsp|jbe|mov%rsp,%rax|sub%rsi,%rax|mov%rax,0x30(%r10)|add$0x10,%rax|cmp0x20(%r10),%rax|ja|cld
lea0x80(%r10),%rdi|xor%eax,%eax|mov$0x2000,%ecx|repstos%rax,%es:(%rdi)
lea0x10080(%r10),%rdi|mov$0xffffffffffffffff,%rax|mov$0x2000,%ecx|repstos%rax,%es:(%rdi)
lea0x10280(%r10),%rdi|xor%eax,%eax|mov$0x8,%ecx|repstos%rax,%es:(%rdi)
mov0x58(%r10),%rax|mov%rax,%rdx|shr$0x20,%rdx|xsave640x80(%r10)|movq$0x1,0x60(%r10)
mov0x58(%r10),%rax|mov%rax,%rdx|shr$0x20,%rdx|xsave640x10080(%r10)|movq$0x1,0x68(%r10)
mov0x18(%r10),%rsi|lea0x20080(%r10),%rdi|mov0x30(%r10),%rcx|repmovsb%ds:(%rsi),%es:(%rdi)|movq$0x1,0x10(%r10)
mov0x40(%r10),%rsi|mov0x48(%r10),%rdx|mov0x50(%r10),%rcx|xor%r8d,%r8d|xor%r9d,%r9d|mov$0xea,%edi|jmp
mov$0xffffffffffffffea,%rax|ret'''.replace('\n','|').split('|')
    rows=shim[2];need(len(rows)==len(expected),'every instruction of the complete fixed scalar snapshot/tail shim')
    bad=rows[-2][0]
    for (pc,chunk,text),want in zip(rows,expected,strict=True):
        if want in ('jne','jbe','ja','jmp'):
            short={'jne':0x75,'jbe':0x76,'ja':0x77,'jmp':0xeb}[want]
            near={'jne':b'\x0f\x85','jbe':b'\x0f\x86','ja':b'\x0f\x87','jmp':b'\xe9'}[want]
            need((len(chunk)==2 and chunk[0]==short)or(len(chunk)==len(near)+4 and chunk.startswith(near)),
                'exact conditional or direct branch opcode/extent')
            width=1 if len(chunk)==2 else 4;target=pc+len(chunk)+int.from_bytes(chunk[-width:],'little',signed=True)
            need(target==(gateway[0]if want=='jmp'else bad),'actual error branches and direct unchanged-gateway tail target')
        elif want=='ret':
            need(chunk==b'\xc3','exact one-byte near return, independent of ret/retq display spelling')
        else:need(text==want,'exact emitted scalar snapshot instruction '+want)
    need(sum(x=='xsave640x80(%r10)'for x in expected)==1 and sum(x=='xsave640x10080(%r10)'for x in expected)==1,
        'two exact standard64-bit saves, no compacted or optimized variant')
    r['nested_emission']=dict(status='passed',bridge=fact(bridge),functions={name:dict(address=v[0],bytes=len(v[1]),
        sha256=H(v[1]),instructions=len(v[2]))for name,v in bodies.items()})


def observed_layout(builder,bridge,private,pin,binary,run,r):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']=='uho_wire'and 0<layout['types']['uho_wire']['bytes']<4<<20,'actual retained owner wire')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout


def seed_prerequisite(builder,private,pin,binary,run,r):
    """One unchanged native seed probe; never an owner/application subject."""
    directory=SELECTED/'tests/provider_app/seed_probe'
    seed_reader=load('unrolled_seed_read',directory/'read.py',pin)
    xstate=load('unrolled_seed_xstate',SELECTED/'tests/b2_reference/xstate.py',pin)
    script=pin(directory/'build.sh');rows=recipe(script,'"${LI2_CC:')
    need(len(rows)==1,'one unchanged independent seed recipe')
    executable=private/'seed-probe'
    argv=expand(rows[0],{'${LI2_CC:?exact compiler required}':builder.tools['cc'],'$1':directory,'$2':executable})
    unit=str(pin(directory/'probe.c'));state=r['seed_prerequisite'];state['status']='failed'
    need(argv[-2:]==['-o',str(executable)]and[x for x in argv if x.endswith(('.c','.S'))]==[unit]and
         not any(x.startswith('-D')for x in argv)and all(x in argv for x in
         ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only','-fno-tree-vectorize',
          '-fno-tree-loop-distribute-patterns','-fno-builtin','-fno-pie','-no-pie')),
         'unchanged seed compiler/producer recipe')
    flags=[x for x in argv[1:-2]if x!=unit and not x.startswith('-Wl,')]
    _,out,err=run('seed-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_seed',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_seed: '),'complete seed include rule')
    headers={str(pin(p)):fact(pin(p))for p in shlex.split(lines[0].split(':',1)[1])}
    need({unit,str(directory/'record.h')}<=set(headers),'whole seed source/header closure before compilation')
    state.update(recipe=fact(script),argv=argv,headers=headers)
    run('seed-link',argv,profile='release_build',env=builder.environment)
    executable=binary(executable);_,head,segments=elf(executable)
    need(executable.stat().st_mode&0o111 and head[1:4]==(2,62,1)and
         not any(p[0]==1 and p[1]&3==3 for p in segments),'actual fixed seed ELF without WX')
    state['elf']=fact(executable)
    loader=pin(interpreter(executable))
    _,out,err=run('seed-libraries',[loader,'--list',executable],profile='inspect',env=builder.environment)
    need(not err,'actual seed library list');libraries={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'complete actual seed resolved library')
        path=pin(match[1]);need(path.name not in libraries,'unique seed library basename')
        libraries[path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in libraries.values()),'actual seed interpreter in resolved library closure')
    state['runtime_libraries']=libraries
    try:row,out,err=run('seed-prerequisite',[executable],profile='seed')
    finally:
        if r['commands'][-1]['name']=='seed-prerequisite':
            actual=r['commands'][-1]
            state.update(launched=type(actual.get('pid'))is int,exit=actual.get('exit'),pid=actual.get('pid'),
                         whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'))
            state['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
    need(not err and len(out)==seed_reader.SIZE,'complete unchanged seed output and empty stderr')
    # Derive the candidate format from the actual first machine observation;
    # unchanged read() validates both machines and all four complete FXSAVEs.
    h=struct.unpack_from('<16Q',out,128)
    cp=[struct.unpack_from('<6I',out,256+24*i)for i in range(67)]
    facts=xstate.profile(cp,h[8],h[10],h[12],h[5],h[6])
    profile=seed_reader.read(out,executable.read_bytes(),facts,xstate,cpu=r['cpu'],pid=row['pid'])
    need(seed_reader.require(profile,facts,cpu=r['cpu'])==bytes(16),'independently qualified exact zero seed pointers')
    state.update(status='passed',profile=profile,format=facts)
    return seed_reader,xstate,profile,facts


def prepare_inputs(original,bridge,builder,private,pin,binary,run,r):
    interp=pin(interpreter(original));roots=[original.parent,Path('/usr/lib64')]
    _,out,err=run('app-libraries',[interp,'--list',original],profile='inspect',env=dict(builder.environment,LD_LIBRARY_PATH=':'.join(map(str,roots))))
    need(not err,'actual native library list');r['runtime_libraries']={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        m=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(m is not None,'complete actual resolved library')
        p=pin(m[1]);need(p.name not in r['runtime_libraries'],'unique actual runtime basename');r['runtime_libraries'][p.name]=dict(path=str(p),**fact(p))
    need(any(v['path']==str(interp)for v in r['runtime_libraries'].values()),'actual interpreter in resolved library closure')
    objects,description=namespace.plan(original,roots,bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    for item in objects:
        need(fact(pin(item['path']))['sha256']==H(item['bytes'])and any(v['path']==str(item['path'])and v['sha256']==H(item['bytes'])for v in r['runtime_libraries'].values()),'same actual sealed source and loader-resolved input')
    r['namespace_plan']=description
    images,raws,known=[],[],{};directory=private/'external-inputs';directory.mkdir()
    for role,path in [('original',original),('interpreter',interp)]+[('dependency-'+str(i),o['path'])for i,o in enumerate(objects)]:
        data=pin(path).read_bytes();identity=dict(bytes=len(data),sha256=H(data));need(fact(path)==identity,'complete independently retained ELF')
        if identity['sha256']in known:
            i=known[identity['sha256']];need(raws[i]==data,'duplicate content equality');images[i]['roles'].append(role);continue
        p=directory/(str(len(images))+'.elf')
        with p.open('xb')as f:f.write(data)
        need(fact(binary(p))==identity,'whole retained input copy');known[identity['sha256']]=len(images)
        images.append(dict(identity,roles=[role]));raws.append(data)
    r['external_inputs']=images;carrier=private/'carrier'
    _,out,err=run('carrier',[builder.tools['python'],'-B',pin(SELECTED.parent/'carrier.py'),'make',original,bridge,carrier],profile='program')
    need(not err,'carrier construction stderr');binary(carrier);identity=json.loads(out)
    need(all(identity[k+'_sha256']==fact(p)['sha256']for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and interpreter(carrier)==bridge,'whole actual carrier source identities')
    r['subject_artifacts']={k:fact(p)for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier))}
    return interp,roots,objects,description,images,raws,carrier


def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,control=case['lane'],case['mode'],case['control'];prep=json.loads(binary(directory/'preparation.json').read_bytes())
    current=r.get('current_custody',False);physical=case.get('physical_fallback',False);current_control=case.get('current_control',0)
    need(type(physical)is bool and type(current_control)is int and current_control in(0,1) and
         (current or not(physical or current_control)),'exact additional current-custody launch scope')
    if current:
        need(prep.get('current_custody')is True and prep.get('current_control')==current_control and
             prep.get('physical_fallback')is physical,'actual explicit current-custody preparation profile')
    else:need(not any(k in prep for k in('current_custody','current_control','physical_fallback')),'old preparation has no hidden current-custody profile')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==lane and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['argv']==[str(original),str(mode),lane]+(['physical-fallback']if physical else [])and prep['default_rseq']is True and prep['mode']==mode and prep['control']==control and
        [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and all(x['after']==0 for x in prep['dispositions']),
        'actual exact launch signal/mode/environment preparation')
    if lane=='native':
        need(prep['observer']is None and prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',LD_LIBRARY_PATH=':'.join(map(str,roots))),'actual closed native exec environment')
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
        LD_BIND_NOW='1',LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),LI2_UNROLLED_CAPTURE_CONTROL=str(control),
        **({'LI2_CURRENT_TF_CONTROL':str(current_control)}if current else {})))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest


def image_inventory(original,interp,carrier,objects,manifest):
    n=len(objects);rows={}
    for i,(item,observed)in enumerate(zip(objects,manifest['objects'],strict=True)):
        rows[i]=dict(data=item['bytes'],carrier_bytes=len(item['bytes']),kind=0,
            backing=dict(launch_fd=observed['fd'],dev=observed['device'],ino=observed['inode'],size=observed['size'],seals=observed['seals']))
    rows[n]=dict(data=original.read_bytes(),carrier_bytes=carrier.stat().st_size,kind=1)
    rows[n+1]=dict(data=interp.read_bytes(),carrier_bytes=interp.stat().st_size,kind=2)
    return dict(objects=rows,main_object=n,interpreter_object=n+1,uid=os.getuid())


def control_reference(reader,native,gated,owner,control):
    """Actual native mode0 frame joins; all seven controls remain refused125."""
    nh,gh=native['header'],gated['header']
    need(control in range(1,8)and owner['control']==control and nh[4:6]==(0,1)and gh[4:6]==(0,0),
         'same actual mode0 native reference and required owner refusal')
    need(nh[8:19]==gh[8:19]and native['hardware']==gated['hardware']and
         all(native[k]==gated[k]for k in('seed','source','stack','data')),
         'all actual control/reference source, hardware and input bytes')
    need(native['machine'][0]==gated['machine'][0]==MASK and native['machine'][3:]==gated['machine'][3:]
         and len(native['frames'])==2 and gated['suffix']is None,'whole actual control launch and no application completion')
    def compare(actual,reference,observed_tls=True):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and
             len(actual['fp'])==reader.FP and actual['fp_bytes']==reference['header'][9]and actual['mask']==MASK,
             'complete typed actual control frame')
        want=list(reference['greg']);want[17]=(want[17]&~reader.TF)|reader.RF
        want[19],want[20],want[22]=21,14,want[16]
        need(actual['greg']==tuple(want)and actual['fp']==reference['fp'],
             'whole actual control GPR/flags/AF/FP joins original hardware reference')
        need((actual['fs'],actual['gs'])==(gated['machine'][1:3]if observed_tls else (0,0)),
             'actual observed control TLS or source-exact pre-TLS empty fields')
    entries=owner['entries'];need(len(entries)==(0 if control==6 else 1),'all actual focal control entry prefixes')
    if control==6:
        compare(owner['supplied_before'],native['frames'][0],False)
    else:
        entry=entries[0];compare(entry['before'],native['frames'][0])
        need(entry['source_page']==entry['terminal_source_page']==native['source'],'complete actual control source conservation')
        for memory in(entry['before_memory'],entry['after_memory']):
            need(memory['data']==native['data']and memory['stack']==native['stack'],'complete actual control data/stack conservation')
        if control in(3,7):
            compare(entry['after']if control==3 else entry['unexpected'],native['frames'][1])
    return dict(native_entry_joins=1,native_endpoint_joins=int(control in(3,7)),completed_applications=0,required_owner_refusals=1)


def cohort(builder,products,private,pin,binary,aliases,run,r):
    current=r.get('current_custody',False)
    adapter=load('current_custody_profile',HERE/'current_custody_profile.py',pin)if current else None
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    original=compile_subject(builder,private,pin,binary,run,r);app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','current')}
    if current:r['application_layout']['current']={k:v for k,v in app_layout['current'].items()if k!='source'}
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    bridge=(adapter.build_bridge(builder,products,private,pin,binary,aliases,run,r,(),capture_image=original)if current else
        build_bridge(builder,products,private,pin,binary,aliases,run,r,('UNROLLED_HASH_CAPTURE',),capture_image=original))
    nested_emission(builder,bridge,pin,run,r)
    layout=observed_layout(builder,bridge,private,pin,binary,run,r)
    if current:layout=adapter.observed_layout(builder,bridge,private,pin,binary,run,r,layout)
    interp,roots,objects,description,images,raws,carrier=prepare_inputs(original,bridge,builder,private,pin,binary,run,r)
    carrier_bytes=carrier.read_bytes();launcher=pin(FIXTURE/'launch.py');native_records={}
    for module in tuple(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).is_file():pin(path)
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed';directory=private/label;directory.mkdir()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',lane,'--mode',str(mode),'--control',str(control),
            '--original',original,'--preparation',directory/'preparation.json']
        if current:argv+=['--current-custody']
        for p in roots:argv+=['--library-root',p]
        if lane=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,out,err=run(label,argv,profile='program',expected=c['expected_exit'],record=lane=='gated')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1];c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            if lane=='native':
                need(err==b'','native stderr remains empty')
                parsed=reader.read(out,mode,True,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
                native_records[mode]=(out,row['pid']);c['status']='qualified_native_reference'
                if current:c['current_prefix']=dict(native_frames=len(parsed['current']['frames']),runtime_frames=0)
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected owner record')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                if current:image.update(current_elf=app_layout['current'],current_bridge=bridge.read_bytes())
                parsed=(reader.control_prefix(out,control,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)if control else
                        reader.read(out,mode,False,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference))
                actual_owner=owner_reader.read(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control)
                if current:adapter.case_summary(c,actual_owner)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader)
                terminal,c['terminal']=(adapter.reports.check_current if current else reports.check)(err,*terminal_args);r['terminal_reports'][label]=terminal
                c['terminal_controls']=(adapter.reports.controls_current if current else reports.controls)(err,*terminal_args)
                c['owner_summary']=actual_owner['summary']
                need(type(c['owner_summary'])is dict and c['owner_summary']and
                     all(type(k)is str and type(v)is int and 0<=v<1<<64 for k,v in c['owner_summary'].items()),
                     'compact actual numeric owner summary, no raw frame or guessed completion')
                if control:
                    need(0 in native_records,'actual mode0 native reference required for every control')
                    nout,npid=native_records[0]
                    native=reader.read(nout,0,True,0,app_layout,npid,r['cpu'],seed_reference)
                    c['control_reference']=control_reference(reader,native,parsed,actual_owner,control)
                    if current:c['current_prefix']=adapter.frames(native,parsed,actual_owner)
                    c['status']='qualified_required_owner_refusal'
                else:
                    need(mode in native_records,'same-mode complete native reference required')
                    nout,npid=native_records[mode]
                    def compare(n,g):
                        native=reader.read(n,mode,True,125 if mode>=7 else 0,app_layout,npid,r['cpu'],seed_reference)
                        gated=reader.read(g,mode,False,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
                        owner=owner_reader.read(record,layout,image,gated,row['pid'],r['cpu'],row['exit'],control=0)
                        result=reader.pair(native,gated,owner)
                        if current:adapter.frames(native,gated,owner)
                        return result
                    c['pair']=compare(nout,out);c['application_controls']=reader.controls(compare,nout,out,mode)
                    need(c['application_controls']==dict(supplied_refusals=26,native_operations=0),'all fixed app rejection controls')
                    if current:
                        native=reader.read(nout,mode,True,125 if mode>=7 else 0,app_layout,npid,r['cpu'],seed_reference)
                        c['current_prefix']=adapter.frames(native,parsed,actual_owner)
                        c['current_application_controls']=reader.current_controls(compare,nout,out,mode)
                        need(c['current_application_controls']==dict(supplied_refusals=15,native_operations=0),'all15 additive actual prefix controls')
                    c['status']='qualified_required_read_failure'if mode>=7 else 'qualified_application'
                c['owner_reader_controls']=owner_reader.controls(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control)
                want=48 if control==1 else 21 if control==6 else 28 if control in(2,4,5)else 29
                need(len(c['owner_reader_controls']['refusals'])==want and c['owner_reader_controls']['native_operations']==0 and
                     c['owner_reader_controls']['original_sha256']==H(record),'complete fixed actual owner-record refusal controls')
        except Exception as error:
            c['status']='failed';c['error_type']=type(error).__name__;c['error']=type(error).__name__+': '+str(error)
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and
                isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    if current:
        adapter.extras(sys.modules[__name__],builder,private,pin,binary,run,r,reader,owner_reader,original,app_layout,
            seed_reference,bridge,layout,interp,roots,objects,description,images,raws,carrier,carrier_bytes,launcher,native_records)
        adapter.complete(r,owner_reader)
    need(len(r['cases'])==25 and all(c['status'].startswith('qualified_')for c in r['cases'])and not r['error'],'all25 actual subjects qualify, no failed-prefix completion credit')
    need(sum(c.get('pair',{}).get('qualified_case',0)for c in r['cases'])==9 and
        sum(c.get('application_controls',{}).get('supplied_refusals',0)for c in r['cases'])==234 and
        sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==16*33+7*2 and
        sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==472,
        'all nine actual pairs and fixed application/terminal/owner-record refusal controls')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True)
    parser.add_argument('--current-custody',action='store_true',help='separate genuine current-TF profile; all original25 remain required')
    parser.add_argument('--component-receipt',type=Path)
    parser.add_argument('--current-component-receipt',type=Path)
    args=parser.parse_args()
    need(args.current_custody or(args.component_receipt is None and args.current_component_receipt is None),'current prerequisites require the explicit current profile')
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+('-current-custody-owner-'if args.current_custody else '-unrolled-hash-owner-')+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='unrolled-hash-owner-v1',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=125 if control or mode>=7 else 0,status='unexecuted',launched=False)for lane,mode,control in ORDER],
        namespace_aliases={},terminal_reports={},bounds=BOUNDS,error=None,final_errors=[],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,
            bounds=BOUNDS['seed'],owner_subjects=0,completed_applications=0,performance_credit=False))
    if args.current_custody:
        r.update(profile='current-custody-owner-v1',current_custody=True,
            current_cases=[dict(label='subject-current-'+name,lane='gated',mode=0,control=0,
                current_control=control,physical_fallback=fallback,expected_exit=expected,
                status='unexecuted',launched=False)for name,control,fallback,expected in
                (('stale',1,False,125),('physical-fallback',0,True,0))],
            current_qualification=dict(status='unexecuted',planned=27))
    def pin(path):
        alias = Path(os.path.abspath(path))
        p = alias.resolve(strict=True)
        value = fact(p)
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'stable input alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable input bytes')
        aliases[str(alias)], pins[str(p)] = str(p), value
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable retained artifact')
        artifacts[str(p)] = value
        return p

    def stable():
        need(all(fact(p) == value for p, value in pins.items()), 'all input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == value for p, value in aliases.items()), 'all input aliases unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == value
                 for p, value in artifacts.items()), 'all artifact bytes unchanged')
        need(all(os.path.lexists(p) == value for p, value in presence.items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p, value in r['namespace_aliases'].items()),
             'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        stable()
        need(not any(c['name'] == name for c in r['commands']), 'unique command/capture name')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                   profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if name.startswith('subject-') else invoke)(row, private, cpu, record=record)
            need(expected is None or row['exit'] == expected, 'actual command exit: ' + name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    p = private / item['file']
                    need(fact(binary(p)) == {k: item[k] for k in ('bytes', 'sha256')}, 'actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture ' + name + ': ' + repr(error))
            try:
                p = private / (name + '.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record ' + name + ': ' + repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder=Build(r,private,pin,binary,build_run)
    current_profile=None
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess']);need(not err,'source enumeration stderr')
        tracked={os.fsdecode(name)for name in names.split(b'\0')if name}
        required={str(p.relative_to(ROOT))for p in (Path(__file__),HERE/'unrolled_hash_app_reports.py',HERE/'unrolled_hash_build.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',OWNER/'read.py',OWNER/'layout.py')}
        required|={str((SELECTED/'tests/provider_app/seed_probe'/n).relative_to(ROOT))for n in('probe.c','record.h','read.py','build.sh')}
        required.add(str((SELECTED/'tests/b2_reference/xstate.py').relative_to(ROOT)))
        if args.current_custody:
            current_profile=load('current_custody_profile',HERE/'current_custody_profile.py',pin)
            current_profile.arguments(args)
            r['current_reproduce']=['--component-receipt',str(args.component_receipt.relative_to(ROOT)),
                '--current-component-receipt',str(args.current_component_receipt.relative_to(ROOT))]
            required.update(current_profile.REQUIRED)
        need(required<=tracked,'all application/owner/build/reader sources committed')
        for name in sorted(tracked):
            if not name.startswith('evaluation/inprocess/results/'):pin(ROOT/name)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        if args.current_custody:current_profile.prerequisites(args,r,pin,binary)
        temporary=private/'tmp';temporary.mkdir()
        _,out,err=run('namespace-controls',[pin(sys.executable),'-B','-m','unittest','discover','-s',SELECTED.parent,'-p','namespace*_tests.py','-v'],
            profile='program',env=dict(ENV,TMPDIR=str(temporary)))
        need(not out and re.search(rb'\nRan 12 tests in [0-9.]+s\n\nOK\n\Z',err)is not None,'all five existing and seven additive namespace controls')
        r['namespace_controls']=dict(status='passed',tests=12,existing=5,added=7)
        products=builder.prepare()
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).is_file():pin(path)
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==25 and all(c['status'].startswith('qualified_')for c in r['cases']),'all25 native/application/control attempts required')
        need(r['seed_prerequisite']['status']=='passed','independent seed prerequisite remains separately mandatory')
        r['status']='passed'
    except BaseException as error:
        if r['error']is None:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            for module in tuple(sys.modules.values()):
                path=getattr(module,'__file__',None)
                if path and Path(path).is_file():pin(path)
        except BaseException as error:
            r['final_errors'].append('final imported source closure: '+repr(error))
        for p in sorted(private.rglob('*')):
            if p.is_file() and not p.is_symlink():
                try:
                    binary(p)
                except BaseException as error:
                    r['final_errors'].append('partial artifact: ' + repr(error))
        for label, fn in (('build', builder.finish), ('closure', stable)):
            try:
                errors = fn()
                if errors:
                    r['final_errors'].extend(errors)
            except BaseException as error:
                r['final_errors'].append(label + ': ' + repr(error))
        try:
            r['source_after'] = source()
            need(r['source_after'] == r.get('source'), 'committed source unchanged')
        except BaseException as error:
            r['final_errors'].append('source: ' + repr(error))
        r['inputs'], r['aliases'], r['artifacts'] = pins, aliases, artifacts
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed,fn in(('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),
                                  ('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p in observed:
                try:r[table][p]=fn(p)
                except BaseException as error:r['final_errors'].append(table+' '+p+': '+type(error).__name__)
        r['source_unchanged'] = r.get('source') is not None and r.get('source_after') == r['source'] and \
            r['inputs_before']==r['inputs_after'] and r['aliases_before']==r['aliases_after']
        r['cleanup_complete'] = all(type(c.get('exit'))is int and c.get('reaped') is True and c.get('timed_out')is False and
            not c.get('error') and c.get('cleanup_errors')==[] and all(d['closed'] for d in c.get('descriptors', []))
            for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or r['artifacts_before']!=r['artifacts_after'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r['totals']=dict(planned=25,launched=sum(c['launched']for c in r['cases']),qualified=sum(c['status'].startswith('qualified_')for c in r['cases']),
            native=sum(c['lane']=='native'and c['status'].startswith('qualified_')for c in r['cases']),
            gated=sum(c['lane']=='gated'and not c['control']and c['status'].startswith('qualified_')for c in r['cases']),
            owner_controls=sum(c['status']=='qualified_required_owner_refusal'for c in r['cases']),
            qualified_pairs=sum(c.get('pair',{}).get('qualified_case',0)for c in r['cases']if c['status'].startswith('qualified_')),
            completed_applications=sum(c['status'].startswith('qualified_')and c['control']==0 and c['mode']<7 for c in r['cases']),
            required_read_faults=sum(c['status']=='qualified_required_read_failure'for c in r['cases']),
            required_reference_faults=sum(c['status']=='qualified_native_reference'and c['mode']>=7 for c in r['cases']),
            required_owner_refusals=sum(c['status']=='qualified_required_owner_refusal'for c in r['cases']),
            application_reader_refusals=sum(c.get('application_controls',{}).get('supplied_refusals',0)for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        public['cases']=[]
        for c in r['cases']:
            value={k:c[k]for k in('label','lane','mode','control','expected_exit','status','launched','exit','whole_process_ns','timed_out','captures','pair','owner_summary','control_reference','error_type')if k in c}
            value['terminal_control_count']=len(c.get('terminal_controls',{}).get('refusals',[]));value['terminal_controls_sha256']=digest(c.get('terminal_controls',{}))
            value['application_control_count']=c.get('application_controls',{}).get('supplied_refusals',0)
            value['owner_control_count']=len(c.get('owner_reader_controls',{}).get('refusals',[]));value['owner_controls_sha256']=digest(c.get('owner_reader_controls',{}))
            public['cases'].append(value)
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/unrolled_hash_owner.py','--expect-revision',args.expect_revision],
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,
            scope='Required25 subjects: nine actual native references, nine actual generated-owner pairs including two real read faults, and seven required owner refusals. One separate unchanged seed prerequisite qualifies exact zero FIP/FDP on the same CPU and complete actual format; it earns no owner/application/performance credit. Whole native/gated GPR, actual AF, FP, stack and data comparisons are mandatory. Failed operations never count as completed applications. This finite fixture qualifies this owner only; no general function/data-pointer authority or throughput claim.')
        if args.current_custody:
            if current_profile is not None:current_profile.project(public,r)
            else:
                public['current_custody']=dict(qualification=r['current_qualification'],cases=r['current_cases'])
                public['reproduce']+=['--current-custody']
                public['scope']='Current-custody source/prerequisite preparation failed; no native or custody credit.'
        columns=('lane','mode','control','status','expected_exit','exit','whole_process_ns','application_control_count','terminal_control_count','owner_control_count')
        stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(columns)
        for c in public['cases']:writer.writerow([c.get(k,'')for k in columns])
        if args.current_custody:
            for c in public['current_custody']['cases']:writer.writerow([c.get(k,'')for k in columns])
        raw=stream.getvalue().encode();public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'all25 compact outcome CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        if args.current_custody and current_profile is not None:public=current_profile.encode_public(public)
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
