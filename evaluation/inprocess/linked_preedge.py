#!/usr/bin/env python3
"""Finite pre-edge v2: metadata plus four full-state original-cut pairs."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/linked_preedge_app'
OWNER=SELECTED/'tests/linked_preedge_owner'
sys.path[:0]=[str(HERE),str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,interpreter,need,save
from page_selected_generic_build import Build,PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand,recipe
from linked_epoch_build import build_bridge
import namespace
import unrolled_hash_owner as donor
import linked_preedge_reports as reports
BOUNDS=dict(PROFILES,release_build=[30,512<<20,16<<20,60],program=[30,512<<20,16<<20,60],seed=[5,512<<20,16<<20,15],finite=[5,512<<20,16<<20,15])
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
H=lambda b:hashlib.sha256(b).hexdigest()
ORDER=tuple((lane,mode,0)for lane in('native','gated')for mode in range(4))
APP_COUNTS={m:36 for m in range(4)}
PAIR_COUNTS={m:4 for m in range(4)}
OWNER_COUNTS={(m,0):46 for m in range(4)}
TERMINAL_COUNTS={(m,0):320 for m in range(4)}
HINT_TERMINAL_COUNT=41
METADATA=SELECTED/'tests/linked_preedge'
METADATA_SUMMARY=dict(schema=2,plan_bytes=40744,cases=13,corruptions=18,jcc_outcome_descriptions=4,
    max_heads=64,max_frontiers=8,max_maps=128,postseal_equal=1,native_execution=0)
METADATA_STDOUT=(json.dumps(METADATA_SUMMARY,separators=(',',':'))+'\n').encode()
# These exact donor helpers retain source, namespace and native seed closure.
# This success-only primitive has no nested shim or nested-control credit.
seed_prerequisite=donor.seed_prerequisite
prepare_inputs=donor.prepare_inputs
image_inventory=donor.image_inventory


def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def load(name,path,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path));module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


def reader_support(builder,private,pin,binary,run,r):
    reader=load('preedge_app_read',FIXTURE/'read.py',pin)
    owner=load('preedge_owner_read',OWNER/'read.py',pin)
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
    need(argv[-2:]==['-o',str(output/'linked-preedge-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
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
    original=binary(output/'linked-preedge-app');_,head,segments=elf(original)
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


def raw_emission(builder,bridge,pin,run,r):
    """Actual complete hidden RAW gateway; no nested shim is claimed."""
    data,_,segments=elf(bridge);objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,symbols,err=run('capture-raw-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(symbols and not err,'complete actual capture gateway symbols')
    need(not any(line.split()[-1:]==[b'uho_nested_raw']for line in symbols.splitlines()),'no invented nested observation shim')
    rows=[line.split()for line in symbols.splitlines()if line.split()[-1:]==[b'li2_raw6']]
    need(len(rows)==1 and len(rows[0])==4 and rows[0][2]==b't','one whole actual hidden RAW gateway')
    address,size=int(rows[0][0],16),int(rows[0][1],16)
    owners=[p for p in segments if p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]]
    need(size==26 and len(owners)==1,'whole26-byte gateway in one actual RX file load')
    p=owners[0];offset=p[2]+address-p[3];expected=bytes.fromhex('4889f84889f74889d64889ca4d89c24d89c84c8b4c24080f05c3')
    need(data[offset:offset+size]==expected,'whole original syscall gateway and exact return offset25')
    _,assembly,err=run('capture-raw-body',[objdump,'-d','-w','-M','att','--start-address='+hex(address),
        '--stop-address='+hex(address+size),bridge],profile='inspect',env=builder.environment)
    need(assembly and not err and b'<li2_raw6>:'in assembly,'whole actual gateway disassembly')
    cursor=address;emitted=[]
    for line in assembly.decode().splitlines():
        m=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
        if m:
            raw=bytes.fromhex(m[2]);need(int(m[1],16)==cursor and raw and cursor+len(raw)<=address+size,'contiguous whole gateway instructions')
            cursor+=len(raw);emitted.append(raw)
    need(cursor==address+size and b''.join(emitted)==expected,'complete emitted gateway equals actual ELF bytes')
    r['raw_emission']=dict(status='passed',bridge=fact(bridge),address=address,bytes=size,sha256=H(expected),instructions=len(emitted),nested_credit=False)

def observed_layout(builder,bridge,private,pin,binary,run,r):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']=='lpeo_wire'and 0<layout['types']['lpeo_wire']['bytes']+64<16<<20,'actual retained owner wire')
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
        LI2_LINKED_PREEDGE_APP_MODE=str(mode)))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest


def metadata(builder,products,private,pin,binary,aliases,run,r):
    from page_selected_register_time_build import headers
    fixture=METADATA;script=pin(fixture/'build.sh');rows=recipe(script,'"$cc_bin"')
    need(len(rows)==1,'one exact linked metadata recipe');output=private/'metadata';output.mkdir()
    exe=output/'preedge-metadata';archive=pin(products['archive'])
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$fixture':fixture,'$archive':archive,'$output':exe})
    units=[str(pin(x))for x in(fixture/'metadata.c',SELECTED/'tests/decoder/support.c',SELECTED/'region_plan.c',SELECTED/'linked_plan.c',SELECTED/'linked_preedge_plan.c')]
    need(argv[-2:]==['-o',str(exe)]and[x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-D')]==['-DLI2_FAST_MEMSET=1','-DLI2_FAST_EQUAL=1','-DLI2_SCALAR_SPAN=1','-DLI2_LINKED_EPOCH=1','-DLI2_LINKED_PREEDGE=1']and
         all(x in argv for x in('-O2','-g','-fstack-usage','-mgeneral-regs-only','-fno-builtin','-fno-tree-vectorize','-Wall','-Wextra','-Werror')),
         'actual exact metadata compiler and feature tuple')
    state=r['preedge_metadata']=dict(status='failed',planned=1,launched=False,expected_exit=0,bounds=BOUNDS['finite'],recipe=fact(script),archive=fact(archive),argv=argv)
    headers('preedge-metadata-headers',argv,units,archive,builder,pin,aliases,run,state)
    need({str((SELECTED/x).resolve())for x in('linked_plan.h','region_plan.h','region_decode.h','decoder.h','event_profile.h','linked_preedge_plan.h')}<=set(state['headers']),
         'complete actual typed-v2 planner metadata header closure')
    run('preedge-metadata-link',argv,profile='release_build',env=builder.environment)
    exe=binary(exe);data,head,segments=elf(exe)
    need(head[1]in(2,3)and all(p[2]+p[5]<=len(data)and p[5]<=p[6]and p[1]&3!=3 for p in segments if p[0]==1),'whole actual metadata ELF without WX')
    interp=[p for p in segments if p[0]==3];need(len(interp)==1,'one actual metadata interpreter')
    item=interp[0];name=data[item[2]:item[2]+item[5]]
    need(name.startswith(b'/')and name.endswith(b'\0')and b'\0'not in name[:-1],'whole actual metadata PT_INTERP');loader=pin(os.fsdecode(name[:-1]))
    _,out,err=run('preedge-metadata-libraries',[loader,'--list',exe],profile='inspect',env=builder.environment);need(not err,'actual metadata loader inspection')
    libraries={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        m=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(m is not None,'one exact resolved metadata library')
        path=pin(m[1]);need(str(path)not in libraries,'unique metadata library');libraries[str(path)]=fact(path)
    need(str(loader)in libraries,'actual metadata loader in full closure')
    _,_,err=run('preedge-metadata-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',exe],profile='inspect',env=builder.environment);need(not err,'whole actual metadata ELF inspection')
    _,out,err=run('preedge-metadata-symbols',[builder.tools['nm'],'-S','--defined-only',exe],profile='inspect',env=builder.environment);need(not err,'whole metadata symbol output')
    for name in('li2_decoder_link_none','li2_decoder_span_describe','li2_decoder_write_footprint','li2_link_plan_page','li2_link_plan_validate','li2_preedge_plan_page','li2_preedge_plan_validate'):
        found=[x.split()for x in out.decode().splitlines()if x.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]in('T','t')and int(found[0][1],16)>0,'one actual metadata provider '+name)
    stack_files=sorted(output.glob('*.su'));need(stack_files,'actual metadata compiler C-stack observations')
    stack=[]
    for path in stack_files:
        path=binary(path);need(path.name.startswith('preedge-metadata-'),'each C-stack file belongs to the actual metadata executable')
        for line in path.read_text().splitlines():
            fields=line.split('\t');need(len(fields)==3 and re.fullmatch('[0-9]+',fields[1])and fields[2]in('static','dynamic,bounded'),'bounded actual metadata C frame')
            location,size,kind=fields;site=location.rsplit(':',3)
            need(len(site)==4 and site[1].isdigit()and site[2].isdigit()and str(pin(site[0]))in state['headers'],'C frame joins actual compiler source closure')
            stack.append(dict(file=path.name,function=site[3],bytes=int(size),kind=kind))
    need({'li2_preedge_plan_page','li2_preedge_plan_validate'}<=set(x['function']for x in stack),'actual typed-v2 planner C frame observations')
    state.update(artifact=fact(exe),runtime_libraries=libraries,c_stack=stack,c_stack_scope='observed C frames only; no inferred Rust, kernel or native owner qualification')
    try:row,out,err=run('subject-preedge-metadata',[exe],profile='finite',env=builder.environment)
    finally:
        if r['commands'][-1]['name']=='subject-preedge-metadata':
            row=r['commands'][-1];state.update(launched=type(row.get('pid'))is int,exit=row.get('exit'),pid=row.get('pid'),whole_process_ns=row.get('duration_ns'),timed_out=row.get('timed_out'))
            state['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in row.get('captures',{}).items()}
    need(type(row['exit'])is int and row['exit']==0 and err==b''and out==METADATA_STDOUT,
         'actual exact13 metadata cases and18 corruptions; no guest execution')
    summary=dict(METADATA_SUMMARY)
    state.update(status='passed',summary=summary,instruction_execution_credit=False)


def named(value,count,sha,key='refusals'):
    names=value[key]
    need(type(names)is list and len(names)==len(set(names))==count and all(type(n)is str and n for n in names)and
         type(value['native_operations'])is int and value['native_operations']==0 and
         value['original_sha256']==sha,'exact distinct supplied reader refusal ledger on actual bytes')


def control_table(value):
    need(type(value)is dict and all(type(k)is tuple and len(k)==2 and
         all(type(x)is int for x in k)and type(n)is int and n>0 for k,n in value.items()),
         'exact typed mode/control refusal table')
    return [[*key,value[key]]for key in sorted(value)]


def cohort(builder,products,private,pin,binary,aliases,run,r):
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    original=compile_subject(builder,private,pin,binary,run,r)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','sources')}
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,r,('LINKED_PREEDGE_CAPTURE',),
        capture_image=original,native_hint=True,preedge=True)
    raw_emission(builder,bridge,pin,run,r)
    layout=observed_layout(builder,bridge,private,pin,binary,run,r)
    interp,roots,objects,description,images,raws,carrier=prepare_inputs(original,bridge,builder,private,pin,binary,run,r)
    carrier_bytes=carrier.read_bytes();launcher=pin(FIXTURE/'launch.py');native_records={}
    for module in tuple(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).is_file():pin(path)
    need(digest(reader.APP_CONTROL_COUNTS)==digest(APP_COUNTS)and digest(reader.PAIR_CONTROL_COUNTS)==digest(PAIR_COUNTS)and
         digest(control_table(owner_reader.CONTROL_COUNTS))==digest(control_table(OWNER_COUNTS))and
         digest(control_table(reports.CONTROL_COUNTS))==digest(control_table(TERMINAL_COUNTS))and reports.HINT_TERMINAL_CONTROL_COUNT==HINT_TERMINAL_COUNT,
         'literal complete app, protected-owner and terminal refusal populations')
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed';directory=private/label;directory.mkdir()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',lane,'--mode',str(mode),'--control','0',
            '--original',original,'--preparation',directory/'preparation.json']
        for p in roots:argv+=['--library-root',p]
        if lane=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,out,err=run(label,argv,profile='program',expected=0,record=lane=='gated')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1];c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            parsed=reader.read(out,mode,lane=='native',row['exit'],app_layout,row['pid'],r['cpu'],seed_reference,control=0)
            if lane=='native':
                need(err==b'','native reference stderr remains empty');native_records[mode]=parsed
                c['application_controls']=reader.controls(out,mode,True,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
                named(c['application_controls'],APP_COUNTS[mode],H(out));c['status']='qualified_native_reference'
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected pre-edge record')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),binding=r['release_build']['linked_binding'],headers=r['release_build']['headers'])
                actual_owner=owner_reader.read(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=0)
                args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=reports.check(err,*args);r['terminal_reports'][label]=terminal
                c['terminal_controls']=reports.controls(err,*args);c['hint_terminal_controls']=reports.hint_controls(err,*args)
                for key,count,names in(('terminal_controls',TERMINAL_COUNTS[mode,0],'refusals'),('hint_terminal_controls',HINT_TERMINAL_COUNT,'hint_refusals')):
                    v=c[key];need(type(v[names])is list and all(type(n)is str and n for n in v[names])and len(v[names])==len(set(v[names]))==count and type(v['native_operations'])is int and v['native_operations']==0 and
                        v['original_stderr_sha256']==H(err),'exact complete source-owned supplied terminal controls')
                c['owner_summary']={k:v for k,v in actual_owner['summary'].items()if k not in('proof_arena','proof_registry')}
                need(c['owner_summary']and all(type(k)is str and type(v)is int and 0<=v<1<<64 for k,v in c['owner_summary'].items()),'only actual numeric owner counters')
                need(mode in native_records,'same-mode actual qualified native reference')
                c['pair']=reader.pair(native_records[mode],parsed,actual_owner)
                need(digest(c['pair'])==digest(dict(qualified_pair=1,invocations=1,generated_completed=1,
                    cut_kind=1 if mode==3 else 2,post_cut_completed=1,whole_profile_qualified=0)),
                    'complete real pre-edge pair, actual post-cut state and explicitly finite scope')
                c['pair_controls']=reader.pair_controls(native_records[mode],parsed,actual_owner)
                need(type(c['pair_controls']['refusals'])is list and all(type(n)is str and n for n in c['pair_controls']['refusals'])and
                     type(c['pair_controls']['native_operations'])is int and c['pair_controls']['native_operations']==0 and
                     len(c['pair_controls']['refusals'])==len(set(c['pair_controls']['refusals']))==PAIR_COUNTS[mode],
                     'all four distinct supplied full-state pair controls')
                c['owner_reader_controls']=owner_reader.controls(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=0)
                named(c['owner_reader_controls'],OWNER_COUNTS[mode,0],H(record));c['status']='qualified_preedge_pair'
        except Exception as error:
            c.update(status='failed',error_type=type(error).__name__,error=type(error).__name__+': '+str(error))
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    need(len(r['cases'])==8 and all(c['status']==('qualified_native_reference'if c['lane']=='native'else'qualified_preedge_pair')for c in r['cases'])and not r['error'],
         'all eight actual hardware subjects required with no skipped or relabelled failure')
    need(sum(c.get('pair',{}).get('qualified_pair',0)for c in r['cases'])==4 and
         sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases'])==144 and
         sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==184 and
         sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases'])==16 and
         sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==1280 and
         sum(len(c.get('hint_terminal_controls',{}).get('hint_refusals',[]))for c in r['cases'])==164,
         'all four pairs and exact144/184/16/1280/164 supplied controls')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True)
    args=parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-linked-preedge-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='linked-preedge-finite-v2',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=0,status='unexecuted',launched=False)for lane,mode,control in ORDER],
        namespace_aliases={},terminal_reports={},bounds=BOUNDS,error=None,final_errors=[],
        preedge_metadata=dict(status='unexecuted',planned=1,launched=False,expected_exit=0,bounds=BOUNDS['finite'],instruction_execution_credit=False),
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

    builder=Build(r,private,pin,binary,build_run,extra_decoder_sources=('region.rs',),scalar_span=True,linked_epoch=True)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess']);need(not err,'source enumeration stderr')
        tracked={os.fsdecode(name)for name in names.split(b'\0')if name}
        required={str(p.relative_to(ROOT))for p in (Path(__file__),HERE/'linked_preedge_reports.py',HERE/'linked_epoch_reports.py',
            HERE/'linked_epoch_terminal.py',HERE/'linked_epoch_base_reports.py',HERE/'linked_epoch_performance_reports.py',HERE/'linked_epoch_cache_reports.py',
            HERE/'linked_epoch_build.py',HERE/'unrolled_hash_owner.py',METADATA/'metadata.c',METADATA/'build.sh',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',
            OWNER/'read.py',OWNER/'layout.py',OWNER/'wire.py',OWNER/'plan.py')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in('linked_preedge_plan.h','linked_preedge_plan.c',
            'linked_preedge_source.h','linked_preedge_source.inc','linked_preedge_rseq.h','linked_preedge_rseq.inc','linked_preedge_proof.h',
            'linked_preedge_observe.h','linked_preedge_observe.inc','linked_preedge_observe_memory.h','linked_preedge_observe_memory.inc',
            'build-linked-preedge.sh','build-linked-preedge-capture.sh','linked_epoch_binding.py')}
        required|={str((SELECTED/'tests/provider_app/seed_probe'/n).relative_to(ROOT))for n in('probe.c','record.h','read.py','build.sh')}
        required.add(str((SELECTED/'tests/b2_reference/xstate.py').relative_to(ROOT)))
        required|={str((SELECTED/name).relative_to(ROOT))for name in
            ('span_fast_bytes.h','tests/span_fast_bytes/oracle.c','tests/span_fast_bytes/build.sh')}
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
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).is_file():pin(path)
        metadata(builder,products,private,pin,binary,aliases,run,r)
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(r['preedge_metadata']['status']=='passed'and len(r['cases'])==8 and all(c['status'].startswith('qualified_')for c in r['cases']),
             'metadata1 and all eight native/gated hardware attempts required')
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
        r['totals']=dict(planned=9,hardware_planned=8,metadata_qualified=int(r['preedge_metadata']['status']=='passed'),
            launched=sum(c['launched']for c in r['cases'])+int(r['preedge_metadata']['launched']),
            qualified=sum(c['status'].startswith('qualified_')for c in r['cases'])+int(r['preedge_metadata']['status']=='passed'),
            native=sum(c['status']=='qualified_native_reference'for c in r['cases']),gated=sum(c['status']=='qualified_preedge_pair'for c in r['cases']),
            qualified_pairs=sum(c.get('pair',{}).get('qualified_pair',0)for c in r['cases']if c['status']=='qualified_preedge_pair'),
            application_reader_refusals=sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            hint_terminal_reader_refusals=sum(len(c.get('hint_terminal_controls',{}).get('hint_refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']),
            pair_reader_refusals=sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        public['metadata']={k:v for k,v in r['preedge_metadata'].items()if k in('status','planned','launched','expected_exit','bounds','exit','pid','whole_process_ns','timed_out','captures','summary','instruction_execution_credit')}
        public['cases']=[]
        for c in r['cases']:
            value={k:c[k]for k in('label','lane','mode','control','expected_exit','status','launched','exit','whole_process_ns','timed_out','captures','pair','owner_summary','control_reference','error_type')if k in c}
            value['terminal_control_count']=len(c.get('terminal_controls',{}).get('refusals',[]));value['terminal_controls_sha256']=digest(c.get('terminal_controls',{}))
            value['application_control_count']=len(c.get('application_controls',{}).get('refusals',[]))
            value['pair_control_count']=len(c.get('pair_controls',{}).get('refusals',[]));value['pair_controls_sha256']=digest(c.get('pair_controls',{}))
            value['hint_terminal_control_count']=len(c.get('hint_terminal_controls',{}).get('hint_refusals',[]));value['hint_terminal_controls_sha256']=digest(c.get('hint_terminal_controls',{}))
            value['owner_control_count']=len(c.get('owner_reader_controls',{}).get('refusals',[]));value['owner_controls_sha256']=digest(c.get('owner_reader_controls',{}))
            public['cases'].append(value)
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/linked_preedge.py','--expect-revision',args.expect_revision],
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,
            scope='Distinct pre-edge v2 primitive: metadata13 cases/18 corruptions without native execution, plus four genuine native/gated pairs. Jcc taken/fallthrough, XOR NEXT and unsupported frontier preserve full state before the original in-page cut and after its actual execution. No old65, nested/fault, whole-program or performance qualification; all original bounds retained.')
        columns=('lane','mode','control','status','expected_exit','exit','whole_process_ns','application_control_count','terminal_control_count','owner_control_count','hint_terminal_control_count','pair_control_count')
        stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(columns)
        md=public['metadata'];writer.writerow(['metadata','','',md['status'],0,md.get('exit',''),md.get('whole_process_ns',''),0,0,0,0,0])
        for c in public['cases']:writer.writerow([c.get(k,'')for k in columns])
        raw=stream.getvalue().encode();public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'all nine compact metadata/hardware outcome CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1


if __name__=='__main__':raise SystemExit(main())
