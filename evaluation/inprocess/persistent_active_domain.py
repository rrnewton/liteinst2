#!/usr/bin/env python3
"""Native392 and separate maintained/differential shared-domain finite pairs.

Five fresh old prerequisites remain mandatory on the same source/CPU/archive.
Two source-owned components and each full-state pair remain separate from LS
and performance qualification. All original process/output/record bounds remain.
"""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys,types
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/persistent_active_domain_app'
OWNER=SELECTED/'tests/persistent_active_domain_owner'
sys.path[:0]=[str(HERE),str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,interpreter,need,save
from page_selected_generic_build import Build,PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand,recipe,headers
from persistent_active_domain_build import build_bridge
import namespace
import persistent_dynamic as previous
import persistent_active_domain_reports as reports
import persistent_resident as resident
import persistent_retained_two as retained
from persistent_retained_two_experiment import retained_prerequisite
from persistent_resident import group_prerequisite
from persistent_resident_experiment import resident_prerequisite
import persistent_group as group
from persistent_group import public_case,csv_projection,load,imported_sources,dynamic_prerequisite
from persistent_dynamic import (BOUNDS,MASK,H,digest,named,counts,control_table,
    seed_prerequisite,prepare_inputs,image_inventory,raw_emission,fixed_prerequisite)
ORDER=(('native',0,0),('maintained',0,0),('differential',0,0))
APP_COUNTS={0:24};OWNER_COUNTS={0:121}
PAIR_COUNTS={0:12};TERMINAL_COUNTS={(0,0):73}
PAIR_EXPECTED=dict(observed_active_domain_pair=1,invocations=1,generated_completed=3,
    cold_publications=2,warm_entries=1,dual_entries=1,retained_generations=2,
    shared_source_rseq_lifetimes=1,joint_closed_pages=34,architectural_joint_instructions=385,
    architectural_internal_transfers=127,measured_interior_signals=0,native_instructions=392,
    native_full_frames=12,qualification_credit=False)
EXPECTED_STATUS={('native',0):'observed_native_active_domain',
    ('maintained',0):'observed_generated_active_domain_maintained',
    ('differential',0):'observed_generated_active_domain_differential'}
COPY_COUNTS=dict(disjoint=2432,overlap=10032,guards=140,large=3)
COPY_STDOUT=b'active-app-copy disjoint=2432 overlap=10032 guards=140 large=3\n'
COMPONENT_ORDER=('active_authority','active_dispatch')
COMPONENT_INPUTS={'tests/persistent_active_domain/authority.c': {'bytes': 14511, 'sha256': '1f934a8708e9e44e194b9cf662a84f1d363a91a5ad39e5bfb8e659066ef50606'}, 'tests/persistent_active_domain/build-authority.sh': {'bytes': 1622, 'sha256': 'a1b94c84ed0f01c0fa1c76aa45735138ad90dbcfa4b24d40a7822776fcc0fdfd'}, 'tests/persistent_active_domain/build-dispatch.sh': {'bytes': 1057, 'sha256': '2cccefa5a9b8bab38769f140cbf421c90ea106601110fe2bca01f4e75affa351'}, 'tests/persistent_active_domain/dispatch.c': {'bytes': 11184, 'sha256': '7dd5b631264851945897d4c5d0dc77cebbeec62d397d95200cc2cb39451f7483'}, 'tests/persistent_active_domain/domain_model.c': {'bytes': 7488, 'sha256': '9776beb43b7d976d8502c9d5bc35abc989b02ce29e6b30e03c7bc98eae32b5df'}, 'tests/persistent_active_domain/prepare.py': {'bytes': 4041, 'sha256': 'd7a2e86f07c2de9aab525130758a2cd6175a7e5bf17999ead8b3704ca8e714a0'}}
COMPONENT_STDOUT={'active_authority': b'active-domain-authority positives=9 refusals=30 claims=2 reuse=3 bytes=2 blocked=3 directories=2 owners=17\n', 'active_dispatch': b'active-domain-dispatch proofs=2 descriptors=16 decoded=74 models=4930 handoffs=192 refusals=487 steps=416230 typed=43520\n'}
COMPONENT_SUMMARIES={
 'active_authority':dict(positives=9,refusals=30,claims=2,reuse=3,bytes=2,blocked=3,directories=2,owners=17,synthetic_observations=1,emitted_execution=0),
 'active_dispatch':dict(proofs=2,descriptors=16,decoded=74,models=4930,handoffs=192,refusals=487,steps=416230,typed=43520,synthetic_observations=1,emitted_execution=0)}
RETAINED_WIRE_BYTES=4161664

PROBE_INPUTS={'tests/linked_native_probe/oracle.c': {'bytes': 16859, 'sha256': '8542d8dc42fcb452eee31f81a7b3411c9f6b19ed3a597ed0408d6d64d792e434'}, 'tests/linked_native_probe/build.sh': {'bytes': 1786, 'sha256': 'b3e915e55786783eee7c1524fb9c04a20f1ace5acc517adb4983918c4860ec77'}}
PROBE_STDOUT=b'{"version":1,"component_only":1,"current_controls":25,"policy_controls":5,"refault_controls":6,"outcome_controls":27,"lifetime_cases":5,"terminal_controls":6,"actual_in_place_renewal":1,"raw_calls":0}\n'
PROBE_COUNTS={'version': 1, 'component_only': 1, 'current_controls': 25, 'policy_controls': 5, 'refault_controls': 6, 'outcome_controls': 27, 'lifetime_cases': 5, 'terminal_controls': 6, 'actual_in_place_renewal': 1, 'raw_calls': 0}
PROBE_PUBLIC_FIELDS=('status','launched','expected_exit','bounds','recipe','artifact','exit','duration_ns','timed_out','captures','counts','emitted_instruction_execution','hardware_subjects','performance_credit')
MAPS_PARSE_INPUTS = {'tests/maps_parse_memo/oracle.c': {'bytes': 11808, 'sha256': 'bf5df0a14673c7e0a6c0af6896d8935657b147ace9039d53e79f4a139eefdf71'}, 'tests/maps_parse_memo/build.sh': {'bytes': 848, 'sha256': '8e11ad01d85b8de4ef28dd36f706a6030d6036aa2fde24533bc01250481a6aca'}}
MAPS_PARSE_STDOUT = b'{"version":1,"cases":72,"byte_changes":52,"io_failures":3,"state_controls":5,"differential_controls":4}\n'
MAPS_PARSE_COUNTS = {'version': 1, 'cases': 72, 'byte_changes': 52, 'io_failures': 3, 'state_controls': 5, 'differential_controls': 4}
MAPS_PARSE_MACROS = ('LI2_MAPS_PHASE_REUSE=1','LI2_MAPS_MAINTAINED=1','LI2_MAPS_DIFFERENTIAL=1','LI2_MAPS_PARSE_MEMO=1','LI2_MAPS_PARSE_MEMO_TEST=1')




def reader_support(builder,private,pin,binary,run,r):
    reader=load('persistent_active_domain_app_read',FIXTURE/'read.py',pin)
    owner=load('persistent_active_domain_owner_read',OWNER/'read.py',pin)
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
    script=pin(FIXTURE/'build.sh')
    rows=recipe(script,'"$cc"');need(len(rows)==1,'one exact three-TU app recipe')
    output=private/'application';output.mkdir()
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':FIXTURE,'$output':output})
    sources=[str(pin(FIXTURE/x))for x in('main.c','pure.c','machine.S')]
    need(argv[-2:]==['-o',str(output/'persistent-active-domain-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
         [x for x in argv if x.startswith('-D')]==['-DLI2_FAST_EQUAL=1']and all(x in argv for x in
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
    state['headers']=includes
    run('app-link',argv,profile='release_build',env=builder.environment)
    original=binary(output/'persistent-active-domain-app');_,head,segments=elf(original)
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
    copy_oracle(builder,private,pin,binary,run,state,original,symbols['copy'])
    state.update(status='passed',artifact=fact(original),symbols=symbols);return original



def copy_oracle(builder,private,pin,binary,run,state,original,app_symbol):
    """Bound the actual fixture helper to an independent complete-byte oracle."""
    script=pin(FIXTURE/'build-copy-oracle.sh');output=private/'active-app-copy-oracle'
    rows=recipe(script,'"$cc"');need(len(rows)==1,'one actual two-TU copy oracle recipe')
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':FIXTURE,'$output':output})
    units=[str(pin(FIXTURE/n))for n in('copy_oracle.c','pure.c')]
    app_units=[str(FIXTURE/n)for n in('main.c','pure.c','machine.S')]
    flags=lambda args,inputs:[x for x in args[1:-2]if x not in inputs and not x.startswith('-Wl,')]
    need(argv[-2:]==['-o',str(output)]and[x for x in argv if x.endswith('.c')]==units and
         flags(argv,units)==flags(state['argv'],app_units)and '-DNDEBUG'not in argv and
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
    need(set(units)|{str(FIXTURE/'app.h')}<=set(includes)and
         includes[str(FIXTURE/'pure.c')]==state['headers'][str(FIXTURE/'pure.c')],
         'oracle and application use the same complete actual helper source')
    observed['headers']=includes
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


def observed_layout(builder,bridge,private,pin,binary,run,r):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']=='pdao_wire'and
        layout['types']['pdao_wire']['bytes']==r['release_build']['capture_extents']['wire']==RETAINED_WIRE_BYTES and
        r['release_build']['capture_extents']['stream']==RETAINED_WIRE_BYTES+64<4<<20,'actual retained owner wire and original4MiB record bound')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout



def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,control=case['lane'],case['mode'],case['control'];role='native'if lane=='native'else'gated';prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(not any(k in prep for k in('current_custody','current_control','physical_fallback')),'no unrelated launch profile')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==role and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['argv']==[str(original),str(mode),role]and prep['default_rseq']is False and prep['mode']==mode and prep['control']==control and
        [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and all(x['after']==0 for x in prep['dispositions']),
        'actual exact launch signal/mode/environment preparation')
    if lane=='native':
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
        LI2_PERSISTENT_ACTIVE_DOMAIN_APP_MODE=str(mode)))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest



def authority_component(builder,products,private,pin,binary,aliases,run,r):
    """Actual source-owned authority predicates; synthetic observations, no guest."""
    need(tuple(s['name']for s in r['component_oracles'])==COMPONENT_ORDER,
         'both separate mandatory active components')
    state=r['component_oracles'][0];state['status']='failed'
    for name,want in COMPONENT_INPUTS.items():
        need(digest(fact(pin(SELECTED/name)))==digest(want),'exact source-owned authority component '+name)
    fixture=SELECTED/'tests/persistent_active_domain';script=pin(fixture/'build-authority.sh');prepare=pin(fixture/'prepare.py')
    inputs=('persistent_group_controller.inc','linked_controller.inc','selected_register_run.inc',
            'span_source.inc','persistent_group_source.inc','lifecycle_loader.c','persistent_retained_two.inc',
            'persistent_active_domain.inc','persistent_active_domain_types.inc','persistent_group_runtime.h')
    state['runtime_inputs']={name:fact(pin(SELECTED/name))for name in inputs}
    output=private/'pure-components';output.mkdir();exe=output/'active-authority';unit=Path(str(exe)+'.c')
    need(not exe.exists()and not unit.exists(),'fresh generated authority TU and executable')
    rows=recipe(script,'"$python_bin"');need(len(rows)==1,'one source-owned pure extraction recipe')
    generate=expand(rows[0],{'$python_bin':builder.tools['python'],'$fixture':fixture,'$selected':SELECTED,'$output':exe})
    need(generate==list(map(str,(builder.tools['python'],'-I','-S','-B',prepare,SELECTED,unit))),
         'exact isolated source extraction; no module import or guest')
    _,out,err=run('component-active_authority-prepare',generate,profile='finite',env=builder.environment)
    need(out==err==b'','exact source extractor has no diagnostics')
    unit=pin(binary(unit));need(0<unit.stat().st_size<128<<10,'bounded retained generated actual runtime TU')
    rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one source-owned authority compile recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$output':exe})
    need(argv[-2:]==['-o',str(exe)]and[x for x in argv if x.endswith('.c')]==[str(unit)]and
         not any(x.endswith('.a')for x in argv)and '-DNDEBUG'not in argv and
         all(x in argv for x in('-DLI2_PERSISTENT_RETAINED_TWO=1','-DLI2_PERSISTENT_DISPATCH=1',
         '-DLI2_PERSISTENT_ACTIVE_DOMAIN=1','-DLI2_RSEQ_CURRENT_DATA=1',
         '-std=gnu11','-O2','-g','-fno-pie','-no-pie','-fno-builtin','-mgeneral-regs-only',
         '-Wall','-Wextra','-Werror','-Wl,-z,now,-z,relro,-z,noexecstack,--no-undefined')),
         'exact assertion-enabled actual authority compile, no decoder archive or guest')
    flags=[x for x in argv[1:-2]if x!=str(unit)and not x.startswith('-Wl,')]
    _,out,err=run('component-active_authority-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_retained',unit],
        profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_retained: '),'one complete actual generated-TU include rule')
    includes={str(pin(name)):fact(pin(name))for name in shlex.split(lines[0].split(':',1)[1])}
    required={str(unit)}|{str(SELECTED/name)for name in('persistent_retained_two.inc','persistent_active_domain_types.inc','persistent_group_runtime.h',
        'persistent_group_lifetime.h','persistent_group_compact.h','persistent_group_plan.h',
        'tests/persistent_active_domain/authority.c')}
    need(required<=set(includes),'actual runtime types, exact authority bodies and test in compiler closure')
    state.update(recipe=fact(script),extractor=fact(prepare),generated=fact(unit),argv=argv,headers=includes,
        synthetic_observations=True,decoder_archive_used=False)
    run('component-active_authority-build',argv,profile='finite',env=builder.environment)
    exe=binary(exe);data,head,segments=elf(exe)
    need(head[1]==2 and head[2:4]==(62,1)and
         all(s[2]+s[5]<=len(data)and s[5]<=s[6]and s[1]&3!=3 for s in segments if s[0]==1),
         'complete actual non-PIE x86-64 authority executable without WX')
    interps=[s for s in segments if s[0]==3];need(len(interps)==1,'one actual pure executable interpreter')
    item=interps[0];literal=data[item[2]:item[2]+item[5]]
    need(literal.startswith(b'/')and literal.endswith(b'\0')and b'\0'not in literal[:-1],'whole literal interpreter')
    loader=pin(os.fsdecode(literal[:-1]));state['runtime_libraries']={}
    _,out,err=run('component-active_authority-libraries',[loader,'--list',exe],profile='finite',env=builder.environment)
    need(not err,'actual pure-component loader listing')
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'one resolved actual pure-component library')
        path=pin(match[1]);need(path.name not in state['runtime_libraries'],'unique library basename')
        state['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in state['runtime_libraries'].values()),'actual interpreter in complete runtime closure')
    _,_,err=run('component-active_authority-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',exe],profile='finite',env=builder.environment)
    need(not err,'complete actual pure-component ELF inspection');state['artifact']=fact(exe)
    label='component-active_authority-run'
    try:row,out,err=run(label,[exe],profile='finite',env=builder.environment)
    finally:
        actual=r['commands'][-1]
        if actual['name']==label:
            state.update(exit=actual.get('exit'),duration_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),
                launched=type(actual.get('pid'))is int,captures={k:{n:v[n]for n in('bytes','sha256')}
                for k,v in actual.get('captures',{}).items()})
    need(type(row['exit'])is int and row['exit']==0 and err==b''and out==COMPONENT_STDOUT['active_authority'],
         'whole exact source-owned authority population, empty stderr and actual zero exit')
    need(all(fact(SELECTED/name)==value for name,value in state['runtime_inputs'].items()),
         'all actual extracted runtime source bytes stable through component execution')
    state.update(status='passed',summaries=[COMPONENT_SUMMARIES['active_authority']])


def dispatch_component(builder,products,private,pin,binary,aliases,run,r):
    """Execute unchanged pure recipes against this build's exact retained archive."""
    features=('scalar-region','scalar-span','linked-epoch','mov-guard')
    need(builder.mov_guard is True and builder.linked_epoch is True and builder.scalar_span is True and
         builder.extra_decoder_sources==('region.rs','mov_guard.rs')and builder.decoder_features==features and
         builder.record['decoder_features']==list(features)and
         builder.environment.get('LI2_DECODER_FEATURES')=='linked-epoch,mov-guard',
         'pure components use the same actual four-feature decoder as the persistent owner')
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         digest(fact(archive))==digest({k:retained[k]for k in('bytes','sha256')}),
         'active dispatch component consumes the fresh retained actual archive')
    # Generic Build's summary omits decode. Authenticate its actual text
    # definition from the same already-retained complete archive inspection.
    inspections=[c for c in r['commands']if c['name']=='archive-text-exports']
    need(len(inspections)==1,'one actual retained archive provider inspection')
    inspection=inspections[0]
    need(inspection['argv']==list(map(str,(builder.tools['nm'],'-g','--defined-only',archive)))and
         inspection['profile']=='inspect'and digest(inspection['bounds'])==digest(BOUNDS['inspect'])and
         type(inspection['exit'])is int and inspection['exit']==inspection['expected_exit']==0 and
         inspection['reaped']is True and inspection['timed_out']is False and not inspection.get('error')and
         inspection['cleanup_errors']==[]and all(d['closed']is True for d in inspection['descriptors']),
         'same actual tool/archive, original bounds and completed provider inspection')
    streams={}
    for key in('stdout','stderr'):
        capture=inspection['captures'][key];path=binary(private/capture['file'])
        need(fact(path)=={k:capture[k]for k in('bytes','sha256')},'whole retained provider inspection '+key)
        streams[key]=path.read_bytes()
    decode=[line.split()for line in streams['stdout'].splitlines()if line.split()[-1:]==[b'li2_decoder_decode']]
    need(streams['stderr']==b''and len(decode)==1 and decode[0][-2:]==[b'T',b'li2_decoder_decode'],
         'one actual decoder decode text definition in the same complete archive')
    need(all(type(builder.record['archive_text_exports'].get(n))is int and
         builder.record['archive_text_exports'][n]==1 for n in
         ('li2_decoder_region_describe','li2_decoder_span_describe','li2_decoder_link_none',
          'li2_decoder_mov_store','li2_decoder_tf_classify','li2_decoder_write_footprint')),
         'all actual pure-component decoder providers present exactly once')
    for name,expected in COMPONENT_INPUTS.items():
        need(digest(fact(pin(SELECTED/name)))==digest(expected),'unchanged complete pure component fixture '+name)
    output=private/'pure-components'
    need(output.is_dir(),'authority component already created the private component directory')
    def finite_run(name,argv,profile='metadata',env=None):return run(name,argv,profile='finite',env=env)
    for state in r['component_oracles'][1:]:
        name=state['name'];label='component-'+name;state['status']='failed'
        need(name=='active_dispatch','one exact directory-JMP integration component')
        fixture=SELECTED/'tests/persistent_active_domain';script=pin(fixture/'build-dispatch.sh');exe=output/name
        rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one exact active dispatch pure compile recipe')
        argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$fixture':fixture,
            '$archive':archive,'$output':exe})
        units=[str(fixture/'dispatch.c'),str(fixture/'domain_model.c'),str(SELECTED/'persistent_group_plan.c'),
            str(SELECTED/'persistent_group_compact.c'),str(SELECTED/'linked_jmp_dispatch.c'),
            str(SELECTED/'linked_mov_guard.c'),str(SELECTED/'tests/decoder/support.c')]
        defines=['-DLI2_PERSISTENT_GROUP=1','-DLI2_PERSISTENT_EPOCH=1','-DLI2_MOV_GUARD=1',
            '-DLI2_PERSISTENT_DISPATCH=1','-DLI2_PERSISTENT_ACTIVE_DOMAIN=1']
        wrappers=['-Wl,--wrap=li2_jd_recover']
        need(argv[-2:]==['-o',str(exe)]and[x for x in argv if x.startswith('-D')]==defines and
             [x for x in argv if x.startswith('-Wl,--wrap=')]==wrappers and
             [x for x in argv if x.endswith('.c')]==units and all(x in argv for x in
             ('-std=gnu11','-O2','-g','-fno-builtin','-fno-stack-protector','-fno-tree-loop-distribute-patterns',
              '-fno-tree-vectorize','-mgeneral-regs-only','-fno-asynchronous-unwind-tables','-fno-omit-frame-pointer',
              '-fstack-usage','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-Wl,-z,now,-z,relro,--no-undefined')),
             'exact separate pure recipe, assertions enabled, actual translation units and feature macros')
        state.update(recipe=fact(script),argv=argv,archive=fact(archive),features=list(features))
        headers(label+'-headers',argv,units,archive,builder,pin,aliases,finite_run,state)
        required={'decoder.h','linked_jmp_dispatch.h','linked_mov_guard.h','write_footprint.h','tf_owner.h','region_decode.h'}
        required|={'persistent_group_plan.h','persistent_group_compact.h','persistent_plan.h',
                       'persistent_compact.h','region_plan.h','linked_rseq.h','linked_jmp_domain.h'}
        need({str(pin(SELECTED/x))for x in required}<=set(state['headers']),
             'complete actual typed pure-component header closure, including compact successor')
        need(not exe.exists(),'new exclusive pure component executable')
        run(label+'-build',argv,profile='finite',env=builder.environment)
        exe=binary(exe);data,head,segments=elf(exe)
        need(head[1]in(2,3)and head[2:4]==(62,1)and
             all(s[2]+s[5]<=len(data)and s[5]<=s[6]and s[1]&3!=3 for s in segments if s[0]==1),
             'complete actual x86-64 pure executable loads without WX')
        interps=[s for s in segments if s[0]==3];need(len(interps)==1,'one actual pure executable interpreter')
        item=interps[0];literal=data[item[2]:item[2]+item[5]]
        need(literal.startswith(b'/')and literal.endswith(b'\0')and b'\0'not in literal[:-1],'whole literal interpreter')
        loader=pin(os.fsdecode(literal[:-1]));state['runtime_libraries']={}
        _,out,err=run(label+'-libraries',[loader,'--list',exe],profile='finite',env=builder.environment)
        need(not err,'actual pure-component loader listing')
        for line in out.decode().splitlines():
            if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
            match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
            need(match is not None,'one resolved actual pure-component library')
            path=pin(match[1]);need(path.name not in state['runtime_libraries'],'unique library basename')
            state['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
        need(any(v['path']==str(loader)for v in state['runtime_libraries'].values()),'actual interpreter in complete runtime closure')
        _,_,err=run(label+'-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',exe],profile='finite',env=builder.environment)
        need(not err,'complete actual pure-component ELF inspection')
        state['artifact']=fact(exe)
        try:row,out,err=run(label+'-run',[exe],profile='finite',env=builder.environment)
        finally:
            actual=r['commands'][-1]
            if actual['name']==label+'-run':
                state.update(exit=actual.get('exit'),duration_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),
                    launched=type(actual.get('pid'))is int,captures={k:{n:v[n]for n in('bytes','sha256')}
                    for k,v in actual.get('captures',{}).items()})
        need(type(row['exit'])is int and row['exit']==0 and err==b''and out.endswith(b"\n") and out.count(b"\n")==1,
             'exact complete source-owned pure stdout rows, empty stderr and actual zero exit')
        need(digest(fact(archive))==digest(state['archive']),'same actual archive through complete pure execution')
        need(out==COMPONENT_STDOUT[name],'whole literal source-owned pure population and all recovery/model counts')
        summary=COMPONENT_SUMMARIES[name]
        state.update(status='passed',summaries=[summary])
    need(tuple(s['name']for s in r['component_oracles'])==COMPONENT_ORDER and
         all(s['status']=='passed'and s['launched']is True for s in r['component_oracles']),
         'both active pure oracles mandatory before seed or any hardware subject')


def native_probe_component(builder,private,pin,binary,run,r):
    """Actual lifecycle predicates with supplied observations; no native permission credit."""
    state=r['native_probe_component'];state['status']='failed'
    fixture=SELECTED/'tests/linked_native_probe';script=pin(fixture/'build.sh')
    for name,want in PROBE_INPUTS.items():
        need(digest(fact(pin(SELECTED/name)))==digest(want),'exact native-probe component source '+name)
    output=private/'native-probe-component';output.mkdir();exe=output/'linked-native-probe-oracle'
    rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one actual native-probe two-TU recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$owner_context':SELECTED,
        '$selected_context':SELECTED,'$parent_context':SELECTED.parent,'$fixture_dir':fixture,'$output_dir':output})
    units=[str(pin(fixture/'oracle.c')),str(pin(SELECTED/'native_policy.c'))]
    need(argv[-2:]==['-o',str(exe)]and[x for x in argv if x.endswith('.c')]==units and
         [x for x in argv if x.startswith('-D')]==['-DLI2_LINKED_NATIVE_PROBE=1', '-DLI2_PERSISTENT_ACTIVE_DOMAIN=1', '-DLI2_RSEQ_CURRENT_DATA=1', '-DLI2_PERSISTENT_RETAINED_TWO=1', '-DLI2_PERSISTENT_DISPATCH=1', '-DLI2_PERSISTENT_GROUP=1', '-DLI2_PERSISTENT_EPOCH=1', '-DLI2_MOV_GUARD=1', '-DLI2_LINKED_EPOCH=1', '-DLI2_SCALAR_SPAN=1', '-DLI2_SCALAR_SPAN_TRACE=1', '-DLI2_SPAN_FAST_BYTES=1', '-DLI2_MAPS_CURRENT_TF=1', '-DLI2_SCALAR_REGION=1', '-DLI2_SCALAR_REGION_REUSE=1', '-DLI2_INITIAL_CODE_PROTECTION=1', '-DLI2_UNROLLED_HASH=1', '-DLI2_MAPS_MAINTAINED=1', '-DLI2_NATIVE_PAIR=1', '-DLI2_REPEAT_RX_LEASE=1', '-DLI2_RUN_CACHE_REUSE=1', '-DLI2_EFFECT_PROVIDER=1', '-DLI2_ONESHOT_REUSABLE=1', '-DLI2_ONESHOT_PUBLICATION=1', '-DLI2_TF_SEALED_CUSTODY=1', '-DLI2_TF_SAME_PAGE_LEASE=1', '-DLI2_TF_HANDOFF=1', '-DLI2_REGISTER_RUN=1', '-DLI2_MAPS_PHASE_REUSE=1', '-DLI2_RSEQ_INACTIVE=1', '-DLI2_NATIVE_PAGES=1', '-DLI2_CPUID_NX_ONLY=1', '-DLI2_RSEQ_NATIVE=1', '-DLI2_RSEQ_NATIVE_BOUNDARY=1', '-DLI2_RSEQ_TCGETS_BTRFS=1', '-DLI2_RSEQ_TIOCGWINSZ_BTRFS=1', '-DLI2_FAST_MEMSET=1', '-DLI2_FAST_EQUAL=1'] and
         not any(x.endswith('.a')for x in argv)and '-DNDEBUG'not in argv and all(x in argv for x in
         ('-std=gnu11','-O2','-g','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror',
          '-Wl,--gc-sections,-z,now,-z,relro,-z,noexecstack,--no-undefined')),
         'exact assertion-enabled actual lifecycle/native-policy component, no decoder archive')
    flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
    _,out,err=run('native-probe-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_probe',*units],
        profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==2 and all(x.startswith('li2_probe: ')for x in lines),
         'complete actual two-TU native-probe dependency rules')
    includes={str(pin(name)):fact(pin(name))for line in lines for name in shlex.split(line.split(':',1)[1])}
    need(set(units)|{str(SELECTED/n)for n in('lifecycle_loader.c','linked_native_probe.h','linked_native_probe.inc',
         'native_policy.h','span_source.inc','oneshot_reusable_generation.inc')}<=set(includes),
         'whole actual probe implementation, renewal, native policy and source in compiler closure')
    state.update(recipe=fact(script),argv=argv,headers=includes)
    run('native-probe-build',argv,profile='finite',env=builder.environment)
    exe=binary(exe);data,head,segments=elf(exe)
    need(head[1]in(2,3)and head[2:4]==(62,1)and
         all(s[2]+s[5]<=len(data)and s[5]<=s[6]and s[1]&3!=3 for s in segments if s[0]==1),
         'complete native-probe executable without WX loads')
    loader=pin(interpreter(exe));state['runtime_libraries']={}
    _,out,err=run('native-probe-libraries',[loader,'--list',exe],profile='finite',env=builder.environment)
    need(not err,'actual native-probe loader listing')
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'one resolved actual native-probe library')
        path=pin(match[1]);need(path.name not in state['runtime_libraries'],'unique native-probe library basename')
        state['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in state['runtime_libraries'].values()),
         'actual interpreter in complete native-probe runtime closure')
    state['artifact']=fact(exe)
    try:row,out,err=run('native-probe-run',[exe],profile='finite',env=builder.environment)
    finally:
        actual=r['commands'][-1]
        if actual['name']=='native-probe-run':
            state.update(exit=actual.get('exit'),duration_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),
                launched=type(actual.get('pid'))is int,captures={k:{n:v[n]for n in('bytes','sha256')}
                for k,v in actual.get('captures',{}).items()})
    need(row['exit']==0 and out==PROBE_STDOUT and err==b'','whole exact actual native-probe component population')
    need(all(fact(name)==value for name,value in includes.items()),'whole native-probe component inputs unchanged')
    state.update(status='passed',counts=PROBE_COUNTS)


def maps_parse_component(builder,private,pin,binary,run,r):
    """Actual lifecycle TU with scripted RAW acquisitions; no guest execution."""
    state=r['maps_parse_component'];state['status']='failed'
    fixture=SELECTED/'tests/maps_parse_memo';script=pin(fixture/'build.sh')
    for name,want in MAPS_PARSE_INPUTS.items():
        need(digest(fact(pin(SELECTED/name)))==digest(want),'exact maps-parse-memo component source '+name)
    output=private/'maps-parse-memo-component';output.mkdir();exe=output/'maps-parse-memo'
    rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one actual maps-parse-memo one-TU recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$fixture_dir':fixture,'$output_dir':output})
    units=[str(pin(fixture/'oracle.c'))]
    need(argv[-2:]==['-o',str(exe)]and[x for x in argv if x.endswith('.c')]==units and
         [x for x in argv if x.startswith('-D')]==['-D'+value for value in MAPS_PARSE_MACROS] and
         not any(x.endswith('.a')for x in argv)and '-DNDEBUG'not in argv and all(x in argv for x in
         ('-std=gnu11','-O2','-g','-fno-builtin','-mgeneral-regs-only','-Wall','-Wextra','-Werror','-fno-stack-protector',
          '-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-fno-asynchronous-unwind-tables',
          '-ffunction-sections','-fdata-sections','-Wl,--gc-sections,-z,noexecstack,--build-id=none')),
         'exact assertion-enabled actual maps parser component, no decoder archive')
    flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
    _,out,err=run('maps-parse-memo-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_maps_parse',*units],
        profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and all(x.startswith('li2_maps_parse: ')for x in lines),
         'complete actual one-TU maps-parse-memo dependency rule')
    includes={str(pin(name)):fact(pin(name))for line in lines for name in shlex.split(line.split(':',1)[1])}
    need(set(units)|{str(SELECTED/n)for n in('lifecycle_loader.c','maps_parse_memo.inc','maps_view.inc')}<=set(includes),
         'whole actual parser/memo/maintained-view implementation in compiler closure')
    state.update(recipe=fact(script),argv=argv,headers=includes)
    run('maps-parse-memo-build',argv,profile='finite',env=builder.environment)
    exe=binary(exe);data,head,segments=elf(exe)
    need(head[1]in(2,3)and head[2:4]==(62,1)and
         all(s[2]+s[5]<=len(data)and s[5]<=s[6]and s[1]&3!=3 for s in segments if s[0]==1),
         'complete maps-parse-memo executable without WX loads')
    loader=pin(interpreter(exe));state['runtime_libraries']={}
    _,out,err=run('maps-parse-memo-libraries',[loader,'--list',exe],profile='finite',env=builder.environment)
    need(not err,'actual maps-parse-memo loader listing')
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'one resolved actual maps-parse-memo library')
        path=pin(match[1]);need(path.name not in state['runtime_libraries'],'unique maps-parse-memo library basename')
        state['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in state['runtime_libraries'].values()),
         'actual interpreter in complete maps-parse-memo runtime closure')
    state['artifact']=fact(exe)
    try:row,out,err=run('maps-parse-memo-run',[exe],profile='finite',env=builder.environment)
    finally:
        actual=r['commands'][-1]
        if actual['name']=='maps-parse-memo-run':
            state.update(exit=actual.get('exit'),duration_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),
                launched=type(actual.get('pid'))is int,captures={k:{n:v[n]for n in('bytes','sha256')}
                for k,v in actual.get('captures',{}).items()})
    need(row['exit']==0 and out==MAPS_PARSE_STDOUT and err==b'','whole exact actual maps-parse-memo component population')
    need(all(fact(name)==value for name,value in includes.items()),'whole maps-parse-memo component inputs unchanged')
    state.update(status='passed',counts=MAPS_PARSE_COUNTS)



def repeat_setup_completed(stderr,image,summary,application,protected_tls):
    """Exact positive fixture site and observed-TLS identity; no row rewriting."""
    parsed={}
    for key,prefix in (('repeat_lease',b'LI2_REPEAT_LEASE '),('rseq',b'LI2_RSEQ ')):
        lines=[x for x in stderr.splitlines()if x.startswith(prefix)]
        need(len(lines)==1,'one actual positive fixture REP/rseq row')
        parsed[key]=reports.maps_view.pair.pair_reports.rseq.decode(lines[0][len(prefix):])
        need(prefix+json.dumps(parsed[key],separators=(',',':'),allow_nan=False).encode()==lines[0],
             'canonical actual fixture REP/rseq row')
    observed=reports.repeat_observed_identity(parsed,application['header'][6],application,protected_tls)
    need(summary['observed_tls']==observed,'whole actual observed-TLS REP summary')
    row=parsed['repeat_lease']
    setup=image['repeat_setup'];pc=setup['pc'];destination=setup['destination']
    binding=summary['source_binding']
    need(row['request'][:4]==[pc,setup['next_pc'],346,3]and
         row['request'][5]==0xab48f3 and row['request'][6]&0x400==0 and
         setup['count']==8 and setup['width']==8 and setup['value']==0x8877665544332211 and
         row['progress'][0]==8 and row['frames'][2:4]==[8,destination]and
         row['frames'][9:11]==[0,destination+64]and
         summary['last_code']==346 and summary['last_initial_count']==8 and
         summary['registration_scope']==reports.REPEAT_TLS_SCOPE and
         binding['module']==summary['source_module']==0 and
         binding['file_offset']==summary['source_file_offset']==setup['file_offset']and
         binding['emitted_bytes']=='f348ab'and binding['image_sha256']==image['sha256'],
         'actual positive REP is the exact low fixture STOSQ and complete eight-word destination')


def cohort(builder,products,private,pin,binary,aliases,run,r):
    authority_component(builder,products,private,pin,binary,aliases,run,r)
    dispatch_component(builder,products,private,pin,binary,aliases,run,r)
    native_probe_component(builder,private,pin,binary,run,r)
    maps_parse_component(builder,private,pin,binary,run,r)
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    original=compile_subject(builder,private,pin,binary,run,r)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','sources')}
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    subjects={}
    for lane in ('maintained','differential'):
        directory=private/(lane+'-build');directory.mkdir();holder=r['lanes'][lane]={}
        def lane_run(name,argv,profile='metadata',expected=0,env=None,record=False):
            return run(lane+'-'+name,argv,profile=profile,expected=expected,env=env,record=record)
        bridge=build_bridge(builder,products,directory,pin,binary,aliases,lane_run,holder,original,
            capture=True,differential=lane=='differential')
        raw_emission(builder,bridge,pin,lane_run,holder)
        layout=observed_layout(builder,bridge,directory,pin,binary,lane_run,holder)
        inputs=prepare_inputs(original,bridge,builder,directory,pin,binary,lane_run,holder)
        subjects[lane]=(bridge,layout,*inputs)
        need(holder['release_build']['status']=='passed'and
             holder['release_build']['profile']=='persistent-active-domain-'+('differential'if lane=='differential'else'capture')+'-v4'and
             holder['release_build']['active_domain']['differential']==(lane=='differential')and
             holder['release_build']['active_domain']['native_probe']is True and
             holder['release_build']['persistent_binding']['native_probe']is True and
             holder['release_build']['active_domain']['parse_memo']is True and
             holder['release_build']['persistent_binding']['parse_memo']is True,
             'separate exact maintained/differential actual builds')
    need(digest(r['lanes']['maintained']['subject_artifacts']['original'])==
         digest(r['lanes']['differential']['subject_artifacts']['original'])==digest(fact(original)),
         'one unchanged original image across both independently built lanes')
    launcher=pin(FIXTURE/'launch.py');native_records={}
    imported_sources(pin)
    need(digest(counts(reader.APP_CONTROL_COUNTS))==digest(counts(APP_COUNTS))and
         digest(counts(reader.PAIR_CONTROL_COUNTS))==digest(counts(PAIR_COUNTS))and
         digest(counts(owner_reader.CONTROL_COUNTS))==digest(counts(OWNER_COUNTS))and
         digest(control_table(reports.CONTROL_COUNTS))==digest(control_table(TERMINAL_COUNTS)),
         'literal complete native-app, protected-owner, pair and terminal refusal populations')
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed'
        directory=private/label;directory.mkdir();role='native'if lane=='native'else'gated'
        selected_lane='maintained'if lane=='native'else lane
        holder=r['lanes'][selected_lane]
        bridge,layout,interp,roots,objects,description,images,raws,carrier=subjects[selected_lane]
        carrier_bytes=carrier.read_bytes()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',role,'--mode',str(mode),'--control','0',
            '--original',original,'--preparation',directory/'preparation.json']
        for p in roots:argv+=['--library-root',p]
        if lane!='native':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,stdout,stderr=run(label,argv,profile='program',expected=c['expected_exit'],record=lane!='native')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1];c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            args=(stdout,mode,lane=='native',row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
            parsed=reader.read(*args)
            if lane=='native':
                need(stderr==b'','actual native reference stderr remains empty')
                c['application_controls']=reader.controls(*args)
                named(c['application_controls'],APP_COUNTS[mode],H(stdout));native_records[mode]=parsed
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(capture['bytes']==layout['types']['pdao_wire']['bytes']+64<4<<20 and
                    fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected active-domain record within original4MiB bound')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),persistent_binding=holder['release_build']['persistent_binding'],headers=holder['release_build']['headers'])
                owner_args=(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'])
                actual_owner=owner_reader.read(*owner_args)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=reports.check(stderr,*terminal_args,lane=lane,application=parsed);r['terminal_reports'][label]=terminal
                repeat_setup_completed(stderr,app_layout,c['terminal']['repeat_lease'],parsed,
                    tuple((x['before']['fs'],x['before']['gs'])for x in actual_owner['attempts']))
                c['repeat_tls_controls']=reports.repeat_tls_controls(stderr,terminal,row['pid'],images,raws,
                    fact(carrier),carrier_bytes,actual_owner,parsed)
                named(c['repeat_tls_controls'],reports.REPEAT_TLS_CONTROLS,H(stderr),hash_key='original_stderr_sha256')
                c['native_probe_controls']=reports.probe.controls(stderr,terminal)
                named(c['native_probe_controls'],reports.probe.CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['terminal_controls']=reports.controls(stderr,*terminal_args,lane=lane,application=parsed)
                named(c['terminal_controls'],TERMINAL_COUNTS[mode,0],H(stderr),hash_key='original_stderr_sha256')
                c['owner_summary']={k:actual_owner[k]for k in('mode','cold_publications','warm_entries','dual_entries','replacements','permit_claims','interior_signals','word','code','detail','status')}
                need(all(type(v)is int and 0<=v<1<<64 for v in c['owner_summary'].values()),'only actual bounded owner counters')
                mapping=actual_owner['rseq_mapping'];need(type(mapping)is list and len(mapping)==6 and
                    any(x['query_kind']==(3 if lane=='differential'else 4)for x in mapping),
                    'actual current-view rseq observation in each explicitly bound lane')
                c['rseq_mapping']=mapping
                need(mode==0 and mode in native_records,'actual same-mode complete native loop reference')
                c['pair']=reader.pair(native_records[mode],parsed,actual_owner)
                need(digest(c['pair'])==digest(PAIR_EXPECTED),'actual shared lifetime and full-state pair; no fault qualification')
                c['pair_controls']=reader.pair_controls(native_records[mode],parsed,actual_owner)
                names=c['pair_controls'];need(type(names['refusals'])is list and all(type(n)is str and n for n in names['refusals'])and
                    len(names['refusals'])==len(set(names['refusals']))==PAIR_COUNTS[mode]and
                    type(names['native_operations'])is int and names['native_operations']==0,'all exact cross-lane full-state controls')
                c['owner_reader_controls']=owner_reader.controls(*owner_args)
                named(c['owner_reader_controls'],OWNER_COUNTS[mode],H(record))
            c['status']=EXPECTED_STATUS[lane,mode]
        except Exception as error:
            c.update(status='failed',error_type=type(error).__name__,error=type(error).__name__+': '+str(error))
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    need(len(r['cases'])==3 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases'])and not r['error'],
         'all three actual loop outcomes required without skipped or relabelled failures')
    need(sum(c.get('pair',{}).get('observed_active_domain_pair',0)for c in r['cases'])==2 and
         sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases'])==APP_COUNTS[0] and
         sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==2*OWNER_COUNTS[0] and
         sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases'])==2*PAIR_COUNTS[0] and
         sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==2*TERMINAL_COUNTS[0,0],
         'two complete native/generated pairs and each separate exact supplied control population')
    need(sum(len(c.get('native_probe_controls',{}).get('refusals',[]))for c in r['cases'])==44 and
         reports.probe.CONTROL_COUNT==22,'both separate exact native-probe reader populations')
    need(sum(len(c.get('repeat_tls_controls',{}).get('refusals',[]))for c in r['cases'])==66 and
         reports.REPEAT_TLS_CONTROLS==33,'both separate exact observed-TLS REP reader populations')



def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True);parser.add_argument('--fixed-receipt',type=Path,required=True);parser.add_argument('--dynamic-receipt',type=Path,required=True);parser.add_argument('--group-receipt',type=Path,required=True);parser.add_argument('--resident-receipt',type=Path,required=True);parser.add_argument('--retained-receipt',type=Path,required=True)
    args=parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);args.fixed_receipt=args.fixed_receipt.resolve(strict=True)
    args.dynamic_receipt=args.dynamic_receipt.resolve(strict=True);args.group_receipt=args.group_receipt.resolve(strict=True);args.resident_receipt=args.resident_receipt.resolve(strict=True);args.retained_receipt=args.retained_receipt.resolve(strict=True)
    need(all(p.parent==HERE/'results'and p.suffix=='.json'for p in(args.fixed_receipt,args.dynamic_receipt,args.group_receipt,args.resident_receipt,args.retained_receipt)),
         'all five old prerequisites are actual repository public receipts')
    cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-persistent-active-domain-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='persistent-active-domain-finite-v4',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=0,status='unexecuted',launched=False)for lane,mode,control in ORDER],
        namespace_aliases={},terminal_reports={},lanes={},bounds=BOUNDS,error=None,final_errors=[],
        maps_parse_component=dict(status='unexecuted',launched=False,expected_exit=0,bounds=BOUNDS['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False),
        native_probe_component=dict(status='unexecuted',launched=False,expected_exit=0,bounds=BOUNDS['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False),
        component_oracles=[dict(name=n,status='unexecuted',launched=False,expected_exit=0,bounds=BOUNDS['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False)for n in COMPONENT_ORDER],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,
            bounds=BOUNDS['seed'],owner_subjects=0,completed_applications=0,performance_credit=False))
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

    builder=Build(r,private,pin,binary,build_run,extra_decoder_sources=('region.rs',),scalar_span=True,linked_epoch=True,mov_guard=True)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess']);need(not err,'source enumeration stderr')
        tracked={os.fsdecode(name)for name in names.split(b'\0')if name}
        required={str(p.relative_to(ROOT))for p in(Path(__file__),HERE/'persistent_active_domain_reports.py',HERE/'persistent_resident.py',HERE/'persistent_resident_reports.py',HERE/'persistent_resident_experiment.py',HERE/'persistent_group.py',HERE/'persistent_group_reports.py',
            HERE/'persistent_group_build.py',HERE/'persistent_active_domain_build.py',HERE/'persistent_dynamic.py',HERE/'persistent_dynamic_reports.py',
            HERE/'persistent_epoch.py',HERE/'persistent_epoch_reports.py',HERE/'persistent_epoch_build.py',
            HERE/'linked_epoch_reports.py',HERE/'linked_epoch_base_reports.py',HERE/'linked_epoch_build.py',HERE/'unrolled_hash_owner.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',
            OWNER/'read.py',OWNER/'layout.py',OWNER/'wire.py',OWNER/'plan.py')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in('persistent_group_plan.h','persistent_group_plan.c',
            'persistent_group_compact.h','persistent_group_compact.c','persistent_group_lifetime.h','persistent_group_runtime.h',
            'persistent_group_source.inc','persistent_group_rseq.inc','persistent_group_controller.inc',
            'persistent_resident_binding.py','build-persistent-resident.sh','persistent_resident_capture_binding.py',
            'build-persistent-active-domain-capture.sh','persistent_resident_observe.h','persistent_resident_observe.inc',
            'persistent_resident_observe_memory.h','persistent_resident_observe_memory.inc',
            'persistent_group_binding.py','linked_jmp_dispatch.h','linked_jmp_dispatch.c',
            'persistent_plan.h','persistent_compact.h','persistent_epoch_binding.py','linked_mov_guard.h','linked_mov_guard.c',
            'decoder/src/mov_guard.rs')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('persistent_active_domain.inc','persistent_active_domain_binding.py','build-persistent-active-domain.sh',
             'persistent_active_domain_capture_binding.py','build-persistent-active-domain-capture.sh',
             'persistent_active_domain_observe.h','persistent_active_domain_observe.inc',
             'persistent_active_domain_observe_memory.h','persistent_active_domain_observe_memory.inc')}
        required|={'evaluation/inprocess/persistent_retained_two.py','evaluation/inprocess/persistent_retained_two_experiment.py',
            'evaluation/inprocess/persistent_retained_two_reports.py','evaluation/inprocess/persistent_retained_two_build.py'}
        required|={str((FIXTURE/name).relative_to(ROOT))for name in ('copy_oracle.c','build-copy-oracle.sh')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('persistent_active_domain.h','persistent_active_domain_types.inc','linked_jmp_domain.h','linked_jmp_domain_emit.inc',
             'rseq_current_data.h','rseq_current_data.inc','persistent_retained_two.inc',
             'build-persistent-active-domain-differential.sh','linked_native_probe.h','linked_native_probe.inc')}
        required|={str((SELECTED/'tests/provider_app/seed_probe'/n).relative_to(ROOT))for n in('probe.c','record.h','read.py','build.sh')}
        required.add(str((SELECTED/'tests/b2_reference/xstate.py').relative_to(ROOT)))
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('span_fast_bytes.h','tests/span_fast_bytes/oracle.c','tests/span_fast_bytes/build.sh')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in COMPONENT_INPUTS}
        required|={str((SELECTED/name).relative_to(ROOT))for name in PROBE_INPUTS}
        required|={str((SELECTED/name).relative_to(ROOT))for name in MAPS_PARSE_INPUTS}
        required.add('tools/page-entry/selected/maps_parse_memo.inc')
        required|={'evaluation/inprocess/linked_native_probe_reports.py',
            'tools/page-entry/selected/linked_native_probe_report.inc'}
        need(required<=tracked,'all application/owner/build/reader sources committed')
        for name in sorted(tracked):
            if not name.startswith('evaluation/inprocess/results/'):pin(ROOT/name)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        temporary=private/'tmp';temporary.mkdir()
        _,out,err=run('namespace-controls',[pin(sys.executable),'-B','-m','unittest','discover','-s',SELECTED.parent,'-p','namespace*_tests.py','-v'],
            profile='program',env=dict(ENV,TMPDIR=str(temporary)))
        need(not out and re.search(rb'\nRan 12 tests in [0-9.]+s\n\nOK\n\Z',err)is not None,'all five existing and seven additive namespace controls')
        r['namespace_controls']=dict(status='passed',tests=12,existing=5,added=7)
        products=builder.prepare()
        imported_sources(pin)
        r['fixed_prerequisite']=fixed_prerequisite(args.fixed_receipt,r,pin,binary,products['archive'])
        r['dynamic_prerequisite']=dynamic_prerequisite(args.dynamic_receipt,r,pin,binary,products['archive'])
        r['group_prerequisite']=group_prerequisite(args.group_receipt,r,pin,binary,products['archive'])
        r['resident_prerequisite']=resident_prerequisite(args.resident_receipt,r,pin,binary,products['archive'],resident)
        r['retained_prerequisite']=retained_prerequisite(args.retained_receipt,r,pin,binary,products['archive'],retained)
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==3 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
             'all three exact active-domain outcomes required')
        need(all(s['status']=='passed'for s in r['component_oracles']),
             'both active components mandatory independently of the three hardware subjects')
        need(r['seed_prerequisite']['status']=='passed','independent seed prerequisite remains separately mandatory')
        need(r['native_probe_component']['status']=='passed','actual probe component mandatory before any hardware')
        need(r['maps_parse_component']['status']=='passed','actual maps parser component mandatory before any hardware')
        r['status']='passed'
    except BaseException as error:
        if r['error']is None:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            imported_sources(pin)
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
        r['totals']=dict(planned=3,launched=sum(c['launched']for c in r['cases']),
            observed=sum(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
            native_references=sum(c['status']=='observed_native_active_domain'for c in r['cases']),
            generated_loops=sum(c['status']in('observed_generated_active_domain_maintained','observed_generated_active_domain_differential')for c in r['cases']),
            observed_pairs=sum(c.get('pair',{}).get('observed_active_domain_pair',0)for c in r['cases']if c['status']in('observed_generated_active_domain_maintained','observed_generated_active_domain_differential')),
            application_reader_refusals=sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            native_probe_reader_refusals=sum(len(c.get('native_probe_controls',{}).get('refusals',[]))for c in r['cases']),
            repeat_tls_reader_refusals=sum(len(c.get('repeat_tls_controls',{}).get('refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']),
            pair_reader_refusals=sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases']),
            cold_publications=sum(c.get('owner_summary',{}).get('cold_publications',0)for c in r['cases']),
            warm_entries=sum(c.get('owner_summary',{}).get('warm_entries',0)for c in r['cases']),
            interior_signals=sum(c.get('owner_summary',{}).get('interior_signals',0)for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls','fixed_prerequisite','dynamic_prerequisite','group_prerequisite','resident_prerequisite','retained_prerequisite')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        public['component_oracles']=[{k:v for k,v in s.items()if k in
            ('name','status','launched','expected_exit','bounds','emitted_instruction_execution','hardware_subjects','performance_credit',
             'recipe','archive','features','artifact','exit','duration_ns','timed_out','captures','summaries')}for s in r['component_oracles']]
        public['native_probe_component']={k:v for k,v in r['native_probe_component'].items()if k in PROBE_PUBLIC_FIELDS}
        public['maps_parse_component']={k:v for k,v in r['maps_parse_component'].items()if k in PROBE_PUBLIC_FIELDS}
        public['copy_oracle']={k:v for k,v in r.get('application_build',{}).get('copy_oracle',{}).items()if k in ('status','expected_counts','counts','recipe','artifact','body','exit','duration_ns','bounds','captures','qualification_credit','performance_credit')}
        public['cases']=[public_case(c)for c in r['cases']]
        public['rseq_mapping']={c['lane']:c.get('rseq_mapping')for c in r['cases']if c['lane']!='native'}
        public['native_probe']={c['lane']:dict(row=c.get('terminal',{}).get('native_probe'),
            controls=c.get('native_probe_controls'))for c in r['cases']if c['lane']!='native'}
        public['repeat_tls']={c['lane']:dict(scope=c.get('terminal',{}).get('repeat_lease',{}).get('registration_scope'),
            controls=c.get('repeat_tls_controls'))for c in r['cases']if c['lane']!='native'}
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/persistent_active_domain.py','--expect-revision',args.expect_revision,'--fixed-receipt',str(args.fixed_receipt.resolve().relative_to(ROOT)),'--dynamic-receipt',str(args.dynamic_receipt.resolve().relative_to(ROOT)),'--group-receipt',str(args.group_receipt.resolve().relative_to(ROOT)),'--resident-receipt',str(args.resident_receipt.resolve().relative_to(ROOT)),'--retained-receipt',str(args.retained_receipt.resolve().relative_to(ROOT))],
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,group_fault_qualification=False,
            scope='Distinct active-domain finite proof: native392 with12 whole-state checkpoints; separate maintained and differential A cold/B cold/A joint lifetimes. Each pair models127 internal transfers and measures zero interior signals; no per-hit counter is invented. Five old prerequisites and all controls remain mandatory. No asynchronous fault, whole-LS or performance qualification.')
        raw=csv_projection(public['cases'])
        public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'three compact actual active-domain CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in raw.decode())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1



if __name__=='__main__':raise SystemExit(main())
