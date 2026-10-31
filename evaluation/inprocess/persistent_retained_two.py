#!/usr/bin/env python3
"""Native12/generated A→B→A with two retained certificates and real miss cancellation.

Requires fresh fixed5/dynamic5/group2/resident2 on identical source and CPU.
The authority component and whole-state native pair receive no fault, whole-LS
or performance qualification. All original process/output/record bounds remain.
"""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys,types
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/persistent_retained_two_app'
OWNER=SELECTED/'tests/persistent_retained_two_owner'
sys.path[:0]=[str(HERE),str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,interpreter,need,save
from page_selected_generic_build import Build,PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand,recipe,headers
from persistent_retained_two_build import build_bridge
import namespace
import persistent_dynamic as previous
import persistent_retained_two_reports as reports
import persistent_resident as resident
from persistent_resident import group_prerequisite
from persistent_resident_experiment import resident_prerequisite
import persistent_group as group
from persistent_group import public_case,csv_projection,load,imported_sources,dynamic_prerequisite
from persistent_dynamic import (BOUNDS,MASK,H,digest,named,counts,control_table,
    seed_prerequisite,prepare_inputs,image_inventory,raw_emission,fixed_prerequisite)
ORDER=(('native',0,0),('gated',0,0))
APP_COUNTS={0:24};OWNER_COUNTS={0:109}
PAIR_COUNTS={0:10};TERMINAL_COUNTS={(0,0):70}
PAIR_EXPECTED=dict(observed_retained_two_pair=1,invocations=1,generated_completed=3,
    cold_publications=2,warm_entries=1,classified_misses=2,retained_generations=2,
    interior_signals=0,qualification_credit=False)
EXPECTED_STATUS={('native',0):'observed_native_retained_two',('gated',0):'observed_generated_retained_two'}
COMPONENT_ORDER=('retained_authority',)
COMPONENT_INPUTS={'persistent_retained_two.inc': {'bytes': 11263, 'sha256': 'e47dbc5839de1b1937521e12dda43ceb7e9f220809a995949a188cb70c2d2d7b'}, 'tests/persistent_retained_two/prepare.py': {'bytes': 3151, 'sha256': '832919b3a0a40ba2bc89467acf596640e129ad3d05e20a7ec0247d1d6efe8d93'}, 'tests/persistent_retained_two/build.sh': {'bytes': 1553, 'sha256': '00710df709d458921301f56a236d93be5eec97ba22479f7a9b34da46cabe4034'}, 'tests/persistent_retained_two/metadata.c': {'bytes': 11284, 'sha256': '298d8c1b7976280ca00fff60785e2ab456dab824e5fa19aa46555f5a846723cf'}}
COMPONENT_STDOUT=b'retained-two positives=5 refusals=40 selections=8 blocked=2 bytes=2\n'
COMPONENT_SUMMARY=dict(positives=5,refusals=40,selections=8,blocked=2,bytes=2,synthetic_observations=1,emitted_execution=0)
RETAINED_WIRE_BYTES=4169600


def reader_support(builder,private,pin,binary,run,r):
    reader=load('persistent_retained_two_app_read',FIXTURE/'read.py',pin)
    owner=load('persistent_retained_two_owner_read',OWNER/'read.py',pin)
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
    need(argv[-2:]==['-o',str(output/'persistent-retained-two-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
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
    original=binary(output/'persistent-retained-two-app');_,head,segments=elf(original)
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



def observed_layout(builder,bridge,private,pin,binary,run,r):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']=='ptr2o_wire'and
        layout['types']['ptr2o_wire']['bytes']==r['release_build']['capture_extents']['wire']==RETAINED_WIRE_BYTES and
        r['release_build']['capture_extents']['stream']==RETAINED_WIRE_BYTES+64<4<<20,'actual retained owner wire and original4MiB record bound')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout



def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,control=case['lane'],case['mode'],case['control'];prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(not any(k in prep for k in('current_custody','current_control','physical_fallback')),'no unrelated launch profile')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==lane and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['argv']==[str(original),str(mode),lane]and prep['default_rseq']is False and prep['mode']==mode and prep['control']==control and
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
        LI2_PERSISTENT_RETAINED_TWO_APP_MODE=str(mode)))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest



def authority_component(builder,products,private,pin,binary,aliases,run,r):
    """Actual source-owned authority predicates; synthetic observations, no guest."""
    need(len(r['component_oracles'])==1 and r['component_oracles'][0]['name']=='retained_authority',
         'one separate mandatory retained authority component')
    state=r['component_oracles'][0];state['status']='failed'
    for name,want in COMPONENT_INPUTS.items():
        need(digest(fact(pin(SELECTED/name)))==digest(want),'exact source-owned authority component '+name)
    fixture=SELECTED/'tests/persistent_retained_two';script=pin(fixture/'build.sh');prepare=pin(fixture/'prepare.py')
    inputs=('persistent_group_controller.inc','linked_controller.inc','selected_register_run.inc',
            'span_source.inc','persistent_group_source.inc','lifecycle_loader.c','persistent_retained_two.inc')
    state['runtime_inputs']={name:fact(pin(SELECTED/name))for name in inputs}
    output=private/'pure-components';output.mkdir();exe=output/'retained-authority';unit=Path(str(exe)+'.c')
    need(not exe.exists()and not unit.exists(),'fresh generated authority TU and executable')
    rows=recipe(script,'"$python_bin"');need(len(rows)==1,'one source-owned pure extraction recipe')
    generate=expand(rows[0],{'$python_bin':builder.tools['python'],'$fixture':fixture,'$selected':SELECTED,'$output':exe})
    need(generate==list(map(str,(builder.tools['python'],'-I','-S','-B',prepare,SELECTED,unit))),
         'exact isolated source extraction; no module import or guest')
    _,out,err=run('component-retained_authority-prepare',generate,profile='finite',env=builder.environment)
    need(out==err==b'','exact source extractor has no diagnostics')
    unit=pin(binary(unit));need(0<unit.stat().st_size<128<<10,'bounded retained generated actual runtime TU')
    rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one source-owned authority compile recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$output':exe})
    need(argv[-2:]==['-o',str(exe)]and[x for x in argv if x.endswith('.c')]==[str(unit)]and
         not any(x.endswith('.a')for x in argv)and '-DNDEBUG'not in argv and
         all(x in argv for x in('-DLI2_PERSISTENT_RETAINED_TWO=1','-DLI2_PERSISTENT_DISPATCH=1',
         '-std=gnu11','-O2','-g','-fno-pie','-no-pie','-fno-builtin','-mgeneral-regs-only',
         '-Wall','-Wextra','-Werror','-Wl,-z,now,-z,relro,-z,noexecstack,--no-undefined')),
         'exact assertion-enabled actual authority compile, no decoder archive or guest')
    flags=[x for x in argv[1:-2]if x!=str(unit)and not x.startswith('-Wl,')]
    _,out,err=run('component-retained_authority-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_retained',unit],
        profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_retained: '),'one complete actual generated-TU include rule')
    includes={str(pin(name)):fact(pin(name))for name in shlex.split(lines[0].split(':',1)[1])}
    required={str(unit)}|{str(SELECTED/name)for name in('persistent_retained_two.inc','persistent_group_runtime.h',
        'persistent_group_lifetime.h','persistent_group_compact.h','persistent_group_plan.h',
        'tests/persistent_retained_two/metadata.c')}
    need(required<=set(includes),'actual runtime types, exact authority bodies and test in compiler closure')
    state.update(recipe=fact(script),extractor=fact(prepare),generated=fact(unit),argv=argv,headers=includes,
        synthetic_observations=True,decoder_archive_used=False)
    run('component-retained_authority-build',argv,profile='finite',env=builder.environment)
    exe=binary(exe);data,head,segments=elf(exe)
    need(head[1]==2 and head[2:4]==(62,1)and
         all(s[2]+s[5]<=len(data)and s[5]<=s[6]and s[1]&3!=3 for s in segments if s[0]==1),
         'complete actual non-PIE x86-64 authority executable without WX')
    interps=[s for s in segments if s[0]==3];need(len(interps)==1,'one actual pure executable interpreter')
    item=interps[0];literal=data[item[2]:item[2]+item[5]]
    need(literal.startswith(b'/')and literal.endswith(b'\0')and b'\0'not in literal[:-1],'whole literal interpreter')
    loader=pin(os.fsdecode(literal[:-1]));state['runtime_libraries']={}
    _,out,err=run('component-retained_authority-libraries',[loader,'--list',exe],profile='finite',env=builder.environment)
    need(not err,'actual pure-component loader listing')
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'one resolved actual pure-component library')
        path=pin(match[1]);need(path.name not in state['runtime_libraries'],'unique library basename')
        state['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in state['runtime_libraries'].values()),'actual interpreter in complete runtime closure')
    _,_,err=run('component-retained_authority-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',exe],profile='finite',env=builder.environment)
    need(not err,'complete actual pure-component ELF inspection');state['artifact']=fact(exe)
    label='component-retained_authority-run'
    try:row,out,err=run(label,[exe],profile='finite',env=builder.environment)
    finally:
        actual=r['commands'][-1]
        if actual['name']==label:
            state.update(exit=actual.get('exit'),duration_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),
                launched=type(actual.get('pid'))is int,captures={k:{n:v[n]for n in('bytes','sha256')}
                for k,v in actual.get('captures',{}).items()})
    need(type(row['exit'])is int and row['exit']==0 and err==b''and out==COMPONENT_STDOUT,
         'whole exact source-owned authority population, empty stderr and actual zero exit')
    need(all(fact(SELECTED/name)==value for name,value in state['runtime_inputs'].items()),
         'all actual extracted runtime source bytes stable through component execution')
    state.update(status='passed',summaries=[COMPONENT_SUMMARY])


def cohort(builder,products,private,pin,binary,aliases,run,r):
    authority_component(builder,products,private,pin,binary,aliases,run,r)
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    original=compile_subject(builder,private,pin,binary,run,r)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','sources')}
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,r,original,capture=True)
    raw_emission(builder,bridge,pin,run,r)
    layout=observed_layout(builder,bridge,private,pin,binary,run,r)
    interp,roots,objects,description,images,raws,carrier=prepare_inputs(original,bridge,builder,private,pin,binary,run,r)
    carrier_bytes=carrier.read_bytes();launcher=pin(FIXTURE/'launch.py');native_records={}
    imported_sources(pin)
    need(digest(counts(reader.APP_CONTROL_COUNTS))==digest(counts(APP_COUNTS))and
         digest(counts(reader.PAIR_CONTROL_COUNTS))==digest(counts(PAIR_COUNTS))and
         digest(counts(owner_reader.CONTROL_COUNTS))==digest(counts(OWNER_COUNTS))and
         digest(control_table(reports.CONTROL_COUNTS))==digest(control_table(TERMINAL_COUNTS)),
         'literal complete native-app, protected-owner, pair and terminal refusal populations')
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed';directory=private/label;directory.mkdir()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',lane,'--mode',str(mode),'--control','0',
            '--original',original,'--preparation',directory/'preparation.json']
        for p in roots:argv+=['--library-root',p]
        if lane=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,stdout,stderr=run(label,argv,profile='program',expected=c['expected_exit'],record=lane=='gated')
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
                need(capture['bytes']==layout['types']['ptr2o_wire']['bytes']+64<4<<20 and
                    fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected retained-two record within original4MiB bound')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),persistent_binding=r['release_build']['persistent_binding'],headers=r['release_build']['headers'])
                owner_args=(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'])
                actual_owner=owner_reader.read(*owner_args)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=reports.check(stderr,*terminal_args);r['terminal_reports'][label]=terminal
                c['terminal_controls']=reports.controls(stderr,*terminal_args)
                named(c['terminal_controls'],TERMINAL_COUNTS[mode,0],H(stderr),hash_key='original_stderr_sha256')
                c['owner_summary']={k:actual_owner[k]for k in('mode','cold_publications','warm_entries','replacements','permit_claims','interior_signals','word','code','detail','status')}
                need(all(type(v)is int and 0<=v<1<<64 for v in c['owner_summary'].values()),'only actual bounded owner counters')
                need(mode==0 and mode in native_records,'actual same-mode complete native loop reference')
                c['pair']=reader.pair(native_records[mode],parsed,actual_owner)
                need(digest(c['pair'])==digest(PAIR_EXPECTED), 'actual retained A/B/A full-state pair; no fault qualification')
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
    need(len(r['cases'])==2 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases'])and not r['error'],
         'both actual loop outcomes required without skipped or relabelled failures')
    need(sum(c.get('pair',{}).get('observed_retained_two_pair',0)for c in r['cases'])==1 and
         sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases'])==APP_COUNTS[0] and
         sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==OWNER_COUNTS[0] and
         sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases'])==PAIR_COUNTS[0] and
         sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==TERMINAL_COUNTS[0,0],
         'one complete native retained pair and each separate exact supplied control population')



def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True);parser.add_argument('--fixed-receipt',type=Path,required=True);parser.add_argument('--dynamic-receipt',type=Path,required=True);parser.add_argument('--group-receipt',type=Path,required=True);parser.add_argument('--resident-receipt',type=Path,required=True)
    args=parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);args.fixed_receipt=args.fixed_receipt.resolve(strict=True)
    args.dynamic_receipt=args.dynamic_receipt.resolve(strict=True);args.group_receipt=args.group_receipt.resolve(strict=True);args.resident_receipt=args.resident_receipt.resolve(strict=True)
    need(all(p.parent==HERE/'results'and p.suffix=='.json'for p in(args.fixed_receipt,args.dynamic_receipt,args.group_receipt,args.resident_receipt)),
         'all four old prerequisites are actual repository public receipts')
    cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-persistent-retained-two-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='persistent-retained-two-finite-v3',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=0,status='unexecuted',launched=False)for lane,mode,control in ORDER],
        namespace_aliases={},terminal_reports={},bounds=BOUNDS,error=None,final_errors=[],
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
        required={str(p.relative_to(ROOT))for p in(Path(__file__),HERE/'persistent_retained_two_reports.py',HERE/'persistent_resident.py',HERE/'persistent_resident_reports.py',HERE/'persistent_resident_experiment.py',HERE/'persistent_group.py',HERE/'persistent_group_reports.py',
            HERE/'persistent_group_build.py',HERE/'persistent_retained_two_build.py',HERE/'persistent_dynamic.py',HERE/'persistent_dynamic_reports.py',
            HERE/'persistent_epoch.py',HERE/'persistent_epoch_reports.py',HERE/'persistent_epoch_build.py',
            HERE/'linked_epoch_reports.py',HERE/'linked_epoch_base_reports.py',HERE/'linked_epoch_build.py',HERE/'unrolled_hash_owner.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',
            OWNER/'read.py',OWNER/'layout.py',OWNER/'wire.py',OWNER/'plan.py')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in('persistent_group_plan.h','persistent_group_plan.c',
            'persistent_group_compact.h','persistent_group_compact.c','persistent_group_lifetime.h','persistent_group_runtime.h',
            'persistent_group_source.inc','persistent_group_rseq.inc','persistent_group_controller.inc',
            'persistent_resident_binding.py','build-persistent-resident.sh','persistent_resident_capture_binding.py',
            'build-persistent-retained-two-capture.sh','persistent_resident_observe.h','persistent_resident_observe.inc',
            'persistent_resident_observe_memory.h','persistent_resident_observe_memory.inc',
            'persistent_group_binding.py','linked_jmp_dispatch.h','linked_jmp_dispatch.c',
            'persistent_plan.h','persistent_compact.h','persistent_epoch_binding.py','linked_mov_guard.h','linked_mov_guard.c',
            'decoder/src/mov_guard.rs')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('persistent_retained_two.inc','persistent_retained_two_binding.py','build-persistent-retained-two.sh',
             'persistent_retained_two_capture_binding.py','build-persistent-retained-two-capture.sh',
             'persistent_retained_two_observe.h','persistent_retained_two_observe.inc',
             'persistent_retained_two_observe_memory.h','persistent_retained_two_observe_memory.inc')}
        required|={str((SELECTED/'tests/provider_app/seed_probe'/n).relative_to(ROOT))for n in('probe.c','record.h','read.py','build.sh')}
        required.add(str((SELECTED/'tests/b2_reference/xstate.py').relative_to(ROOT)))
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('span_fast_bytes.h','tests/span_fast_bytes/oracle.c','tests/span_fast_bytes/build.sh')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in COMPONENT_INPUTS}
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
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==2 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
             'both exact retained-two outcomes required')
        need(all(s['status']=='passed'for s in r['component_oracles']),
             'retained authority component mandatory independently of the two hardware subjects')
        need(r['seed_prerequisite']['status']=='passed','independent seed prerequisite remains separately mandatory')
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
        r['totals']=dict(planned=2,launched=sum(c['launched']for c in r['cases']),
            observed=sum(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
            native_references=sum(c['status']=='observed_native_retained_two'for c in r['cases']),
            generated_loops=sum(c['status']=='observed_generated_retained_two'for c in r['cases']),
            observed_pairs=sum(c.get('pair',{}).get('observed_retained_two_pair',0)for c in r['cases']if c['status']=='observed_generated_retained_two'),
            application_reader_refusals=sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']),
            pair_reader_refusals=sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases']),
            cold_publications=sum(c.get('owner_summary',{}).get('cold_publications',0)for c in r['cases']),
            warm_entries=sum(c.get('owner_summary',{}).get('warm_entries',0)for c in r['cases']),
            interior_signals=sum(c.get('owner_summary',{}).get('interior_signals',0)for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls','fixed_prerequisite','dynamic_prerequisite','group_prerequisite','resident_prerequisite')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        public['component_oracles']=[{k:v for k,v in s.items()if k in
            ('name','status','launched','expected_exit','bounds','emitted_instruction_execution','hardware_subjects','performance_credit',
             'recipe','archive','features','artifact','exit','duration_ns','timed_out','captures','summaries')}for s in r['component_oracles']]
        public['cases']=[public_case(c)for c in r['cases']]
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/persistent_retained_two.py','--expect-revision',args.expect_revision,'--fixed-receipt',str(args.fixed_receipt.resolve().relative_to(ROOT)),'--dynamic-receipt',str(args.dynamic_receipt.resolve().relative_to(ROOT)),'--group-receipt',str(args.group_receipt.resolve().relative_to(ROOT)),'--resident-receipt',str(args.resident_receipt.resolve().relative_to(ROOT))],
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,group_fault_qualification=False,
            scope='Additive two-retained-certificate pair only: actual native12-step reference, A cold/B cold/A same-generation warm and real classified misses preserving both completed permits. Fresh fixed5/dynamic5/group2/resident2 and every old control remain mandatory. No retained fault, nested, partial cleanup, whole-program, trap-reduction or performance qualification; original bounds retained.')
        raw=csv_projection(public['cases'])
        public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'both compact actual retained-two CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in raw.decode())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1



if __name__=='__main__':raise SystemExit(main())
