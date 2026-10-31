#!/usr/bin/env python3
"""Five actual dynamic persistent subjects, with a separate mandatory fixed-five regression."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys,types
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/persistent_dynamic_app'
OWNER=SELECTED/'tests/persistent_dynamic_owner'
sys.path[:0]=[str(HERE),str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,interpreter,need,save
from page_selected_generic_build import Build,PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand,recipe,headers
from persistent_epoch_build import build_bridge
import namespace
import unrolled_hash_owner as donor
import persistent_dynamic_reports as reports
BOUNDS=dict(PROFILES,release_build=[30,512<<20,16<<20,60],program=[30,512<<20,16<<20,60],seed=[5,512<<20,16<<20,15],finite=[5,512<<20,16<<20,15])
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
H=lambda b:hashlib.sha256(b).hexdigest()
ORDER=(('native',0,0),('native',1,0),('gated',0,0),('gated',1,0),('gated',2,0))
APP_COUNTS={0:16,1:16};OWNER_COUNTS={0:55,1:30,2:30};PAIR_COUNTS={0:4,1:4}
TERMINAL_COUNTS={(m,0):60 for m in range(3)}
CASE_FIELDS=('label','lane','mode','control','expected_exit','status','launched','exit','whole_process_ns','timed_out','captures','pair','owner_summary','error_type')
CSV_FIELDS=('lane','mode','control','status','expected_exit','exit','whole_process_ns','application_control_count','terminal_control_count','owner_control_count','pair_control_count','selected_reason_control_count')
EXPECTED_STATUS={('native',0):'qualified_native_success',('native',1):'qualified_native_late_fault',
    ('gated',0):'qualified_generated_success',('gated',1):'qualified_generated_late_fault',('gated',2):'qualified_protected_word_rejection'}
LOADED=[]

# These pure oracles are prerequisites, never additional hardware subjects.
COMPONENT_ORDER=('mov_guard','persistent_plan_compact','dynamic_classifier')
COMPONENT_INPUTS={'tests/linked_mov_guard/build.sh': {'bytes': 705, 'sha256': 'defbb2795ac7d941bd65338ddf83b06f83f29e6f0b9a34cf8fcb0330a3d37a5d'}, 'tests/linked_mov_guard/metadata.c': {'bytes': 12126, 'sha256': '9b076910e6a3f9da7d7d0d8a60d421d1c6027e8b5b2dc8701a91fd4e01141484'}, 'tests/linked_mov_guard/model.c': {'bytes': 6081, 'sha256': 'cac232356cd6eabb4f1c81dda3ce496d318372b39c87e6a0835387cc170d17cc'}, 'tests/linked_mov_guard/model.h': {'bytes': 349, 'sha256': 'abc0641bdf3306548c7c48f133b4c7593b0c28ba9847ad057b906977eaf09370'}, 'tests/persistent_plan/build.sh': {'bytes': 873, 'sha256': '8757042e90d0994206a7b542e117f0f8fb240fa9cc9dc3f28f0ea5ef0f3d9206'}, 'tests/persistent_plan/metadata.c': {'bytes': 15765, 'sha256': 'f5740b30ef7d07e3f3cfef1aeb6a57eb285b7865de0d7de09c8d104cd390ba6c'}}
COMPONENT_INPUTS.update({'tests/persistent_dynamic_plan/build.sh': {'bytes': 987, 'sha256': 'd5270acb3c3006e774a7ddad263d7ab7ab6d6f338f5f6f4485498192e1a5f34a'}, 'tests/persistent_dynamic_plan/metadata.c': {'bytes': 21818, 'sha256': '5a2229a7b6368197929936298b030bbb0f4effe272b7d9867c311445fe61d54e'}})
COMPONENT_STDOUT={
    'dynamic_classifier':b'{"schema":1,"positives":2,"classified":14,"terminal":10,"corruptions":56,"whole_old_plans_equal":26,"postseal_equal":1,"emitted_execution":0,"placement_cases":42,"placement_ready":10,"selected_cases":116,"selected_terminals":19,"selected_corruptions":13}\n',
    'mov_guard':b'{"schema":1,"store_codes":4,"descriptors":704,"byte_models":3272,"refusals":15,"corruptions":19,"interval_edges":465,"max_tree_height":8,"postseal_equal":1,"emitted_instruction_execution":0}\n',
    'persistent_plan_compact':b'{"schema":1,"positives":3,"refusals":19,"corruptions":12,"recoveries":46,"postseal_equal":1}\n'
        b'{"compact_schema":1,"positives":3,"whole_guards":3,"recoveries":46,"refusals":13,"corruptions":12,"primary_bytes":182168}\n'}
seed_prerequisite=donor.seed_prerequisite
prepare_inputs=donor.prepare_inputs
image_inventory=donor.image_inventory


def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())

def public_case(c):
    value={k:c[k]for k in CASE_FIELDS if k in c}
    for prefix,key in(('terminal','terminal_controls'),('owner','owner_reader_controls'),('pair','pair_controls'),('selected_reason','selected_reason_controls')):
        value[prefix+'_control_count']=len(c.get(key,{}).get('refusals',[]))
        value[prefix+'_controls_sha256']=digest(c.get(key,{}))
    value['application_control_count']=len(c.get('application_controls',{}).get('refusals',[]))
    return value

def csv_projection(cases):
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(CSV_FIELDS)
    for c in cases:writer.writerow([c.get(k,'')for k in CSV_FIELDS])
    return stream.getvalue().encode()

def load(name,path,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path));module=importlib.util.module_from_spec(spec)
    LOADED.append(module);spec.loader.exec_module(module);return module

def reader_support(builder,private,pin,binary,run,r):
    reader=load('persistent_dynamic_app_read',FIXTURE/'read.py',pin)
    owner=load('persistent_dynamic_owner_read',OWNER/'read.py',pin)
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
    need(argv[-2:]==['-o',str(output/'persistent-dynamic-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
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
    original=binary(output/'persistent-dynamic-app');_,head,segments=elf(original)
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
    layout=json.loads(out);need(layout['record']=='pdo_wire'and 0<layout['types']['pdo_wire']['bytes']+64<4<<20,'actual retained owner wire')
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
        LI2_PERSISTENT_DYNAMIC_APP_MODE=str(mode)))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest

def named(value,count,sha,key='refusals',hash_key='original_sha256'):
    names=value[key]
    need(type(names)is list and len(names)==len(set(names))==count and all(type(n)is str and n for n in names)and
         type(value['native_operations'])is int and value['native_operations']==0 and
         value[hash_key]==sha,'exact distinct supplied reader refusal ledger on actual bytes')

def control_table(value):
    need(type(value)is dict and all(type(k)is tuple and len(k)==2 and
         all(type(x)is int for x in k)and type(n)is int and n>0 for k,n in value.items()),
         'exact typed mode/control refusal table')
    return [[*key,value[key]]for key in sorted(value)]


def imported_sources(pin):
    """Include modules loaded into globals even when absent from sys.modules."""
    pending=[m for m in sys.modules.values()if isinstance(m,types.ModuleType)]
    pending.extend(v for v in globals().values()if isinstance(v,types.ModuleType));pending.extend(LOADED);seen=set()
    while pending:
        module=pending.pop()
        if id(module)in seen:continue
        seen.add(id(module));path=getattr(module,'__file__',None)
        if path and Path(path).is_file():pin(path)
        pending.extend(v for v in vars(module).values()if isinstance(v,types.ModuleType))


def counts(value):
    need(type(value)is dict and all(type(k)is int and type(v)is int and v>0 for k,v in value.items()),
         'literal typed finite persistent refusal table')
    return [[k,value[k]]for k in sorted(value)]


def component_oracles(builder,products,private,pin,binary,aliases,run,r):
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
         'both pure components consume the fresh retained actual archive')
    need(all(type(builder.record['archive_text_exports'].get(n))is int and
         builder.record['archive_text_exports'][n]==1 for n in
         ('li2_decoder_region_describe','li2_decoder_span_describe','li2_decoder_link_none',
          'li2_decoder_mov_store','li2_decoder_tf_classify','li2_decoder_write_footprint')),
         'all actual pure-component decoder providers present exactly once')
    for name,expected in COMPONENT_INPUTS.items():
        need(digest(fact(pin(SELECTED/name)))==digest(expected),'unchanged complete pure component fixture '+name)
    shell_tools={n:dict(path=str(p),**fact(p))for n in('realpath','dirname')
        for p in[pin(shutil.which(n,path=builder.environment['PATH']))]}
    environment=dict(builder.environment,LI2_CC=str(builder.tools['cc']))
    def finite_run(name,argv,profile='metadata',env=None):
        return run(name,argv,profile='finite',env=env)
    output=private/'pure-components';output.mkdir()
    for state in r['component_oracles']:
        name=state['name'];label='component-'+name;state['status']='failed'
        fixture=SELECTED/'tests'/('linked_mov_guard'if name=='mov_guard'else'persistent_dynamic_plan'if name=='dynamic_classifier'else'persistent_plan')
        script=pin(fixture/'build.sh');exe=output/name
        rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one exact pure component compile recipe')
        argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$fixture':fixture,
            '$archive':archive,'$output':exe})
        units=[str(fixture/'metadata.c')]
        if name=='mov_guard':units+=[str(fixture/'model.c')]
        else:units+=[str(SELECTED/'persistent_plan.c')]+([]if name=='dynamic_classifier'else[str(SELECTED/'persistent_compact.c')])
        units+=[str(SELECTED/'tests/decoder/support.c'),str(SELECTED/'linked_mov_guard.c')]
        defines=['-DLI2_MOV_GUARD=1']if name=='mov_guard'else['-DLI2_PERSISTENT_EPOCH=1','-DLI2_MOV_GUARD=1']
        if name=='dynamic_classifier':defines+=['-DLI2_PERSISTENT_DYNAMIC=1']
        need(argv[-2:]==['-o',str(exe)]and[x for x in argv if x.startswith('-D')]==defines and
             [x for x in argv if x.endswith('.c')]==units and all(x in argv for x in
             ('-std=gnu11','-O2','-g','-fno-builtin','-fno-stack-protector','-fno-tree-loop-distribute-patterns',
              '-fno-tree-vectorize','-mgeneral-regs-only','-fno-asynchronous-unwind-tables','-fno-omit-frame-pointer',
              '-fstack-usage','-Wall','-Wextra','-Werror','-Wl,-z,now,-z,relro,--no-undefined')),
             'unchanged complete pure recipe, assertions enabled, exact translation units and feature macros')
        state.update(recipe=fact(script),argv=argv,archive=fact(archive),features=list(features),shell_tools=shell_tools)
        headers(label+'-headers',argv,units,archive,builder,pin,aliases,finite_run,state)
        required={'decoder.h','linked_mov_guard.h','write_footprint.h'}
        if name=='mov_guard':required.add('tests/linked_mov_guard/model.h')
        else:
            required|={'persistent_plan.h','region_plan.h','region_decode.h','linked_rseq.h'}
            required|={'persistent_dynamic_plan.h','persistent_dynamic_plan.inc'}if name=='dynamic_classifier'else{'persistent_compact.h'}
        need({str(pin(SELECTED/x))for x in required}<=set(state['headers']),
             'complete actual typed pure-component header closure, including compact successor')
        need(not exe.exists(),'new exclusive pure component executable')
        args=([SELECTED]if name=='mov_guard'else[])+[archive,exe]
        run(label+'-build',[builder.tools['sh'],script,*args],profile='finite',env=environment)
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
        need(type(row['exit'])is int and row['exit']==0 and err==b''and out==COMPONENT_STDOUT[name],
             'exact complete source-owned pure stdout rows, empty stderr and actual zero exit')
        need(digest(fact(archive))==digest(state['archive']),'same actual archive through complete pure execution')
        state.update(status='passed',summaries=[json.loads(line)for line in out.splitlines()])
    need(tuple(s['name']for s in r['component_oracles'])==COMPONENT_ORDER and
         all(s['status']=='passed'and s['launched']is True for s in r['component_oracles']),
         'all three complete pure oracles mandatory before seed or native hardware subjects')


def fixed_prerequisite(path,r,pin,binary,archive):
    """Reuse existing closed-data authentication, then require the exact fixed five."""
    import persistent_epoch as fixed
    from scalar_reuse_performance import closed
    from scalar_span_trace_build import fast_bytes_completed
    path=Path(path).resolve(strict=True)
    need(path.parent==HERE/'results'and path.suffix=='.json'and path.stat().st_size<=32<<10,
         'exact compact fixed-five public prerequisite')
    def pinned(p,want=None):
        result=pin(p)
        if want is not None:need(digest(fact(result))==digest(want),'exact retained fixed-five input')
        return result
    public,a=closed(path,r,pinned,binary)
    need(public['profile']==a['profile']=='persistent-epoch-finite-v1'and
         public['status']==a['status']=='passed'and type(a['cpu'])is int and a['cpu']==r['cpu']and
         digest(a['source'])==digest(a['source_after'])==digest(r['source'])and
         digest(a['hardware'])==digest(r['hardware']),
         'fresh successful fixed five on the same exact source and CPU')
    totals=dict(planned=5,launched=5,qualified=5,native_references=2,generated_success=1,
        generated_late_fault=1,protected_word_rejection=1,qualified_pairs=2,
        application_reader_refusals=32,terminal_reader_refusals=102,owner_reader_refusals=60,
        registry_reader_refusals=18,pair_reader_refusals=8)
    need(digest(a['totals'])==digest(totals)and digest(public['totals'])==digest(totals)and
         digest(a['bounds'])==digest(fixed.BOUNDS)==digest(BOUNDS)and
         public['performance_credit']is False and public['whole_ls_eligibility_credit']is False,
         'all original fixed-five outcomes, controls and resource bounds remain mandatory')
    need(digest(a['build']['decoder_features'])==digest(['scalar-region','scalar-span','linked-epoch','mov-guard'])and
         digest({k:a['build']['artifacts']['decoder.a'][k]for k in('bytes','sha256')})==digest(fact(archive))and
         digest(a['release_build']['archive'])==digest(fact(archive))and
         a['release_build']['status']=='passed'and a['release_build']['capture']is True and
         a['release_build']['profile']=='persistent-registered-two-page-v1',
         'same actual four-feature archive, distinct complete fixed-entry capture build')
    fast_bytes_completed(a['release_build'],a['commands'],binary)
    private=ROOT/'target/evaluation/inprocess'/path.stem
    commands={x['name']:x for x in a['commands']}
    for row in a['commands']:
        command=binary(private/(row['name']+'.json'))
        need(digest(json.loads(command.read_bytes()))==digest(row),'whole actual fixed-five retained command')
        for cap in row['captures'].values():
            need(digest(fact(binary(private/cap['file'])))==digest({k:cap[k]for k in('bytes','sha256')}),
                 'actual unchanged fixed-five capture bytes')
    need(digest([(c['lane'],c['mode'],c['control'])for c in a['cases']])==digest(fixed.ORDER),
         'original exact fixed-five schedule')
    for c in a['cases']:
        lane,mode=c['lane'],c['mode'];row=commands[c['label']];status=0 if mode==0 else 125
        need(c['status']==fixed.EXPECTED_STATUS[lane,mode]and c['launched']is True and
             digest([c['expected_exit'],c['exit'],row['expected_exit'],row['exit']])==digest([status]*4)and
             row['profile']=='program'and digest(row['bounds'])==digest(BOUNDS['program'])and
             c['timed_out']is False and c['whole_process_ns']==row['duration_ns']and
             digest(c['captures'])==digest({k:{n:v[n]for n in('bytes','sha256')}for k,v in row['captures'].items()}),
             'each actual fixed-five subject has its exact source-required result and captures')
        if lane=='native':fixed.named(c['application_controls'],16,row['captures']['stdout']['sha256'])
        else:
            fixed.named(c['owner_reader_controls'],20,row['captures']['record']['sha256'])
            fixed.named(c['registry_controls'],6,row['captures']['record']['sha256'])
            fixed.named(c['terminal_controls'],34,row['captures']['stderr']['sha256'],hash_key='original_stderr_sha256')
            if mode in(0,1):
                need(digest(c['pair'])==digest(dict(qualified_pair=1,invocations=1,generated_completed=int(mode==0),
                     required_late_store_fault=mode,interior_signals=0,whole_reuse_credit=0)),
                     'both complete original fixed native pairs')
                controls=c['pair_controls']
                need(type(controls['refusals'])is list and len(controls['refusals'])==len(set(controls['refusals']))==4 and
                     all(type(x)is str and x for x in controls['refusals'])and
                     type(controls['native_operations'])is int and controls['native_operations']==0,
                     'original fixed pair controls remain separately required')
            else:need('pair'not in c,'fixed protected-word rejection has no invented native reference')
    need(digest(public['cases'])==digest([fixed.public_case(c)for c in a['cases']])and
         path.with_suffix('.csv').read_bytes()==fixed.csv_projection(public['cases']),
         'complete actual fixed-five public numerical projection')
    states=a['component_oracles']
    need([s['name']for s in states]==list(fixed.COMPONENT_ORDER),'both original pure components remain required')
    for state in states:
        row=commands['component-'+state['name']+'-run']
        need(state['status']=='passed'and state['launched']is True and
             digest([state['exit'],state['expected_exit'],row['exit'],row['expected_exit']])==digest([0]*4)and
             row['profile']=='finite'and digest(row['bounds'])==digest(BOUNDS['finite'])and
             digest(state['archive'])==digest(fact(archive))and
             (private/row['captures']['stdout']['file']).read_bytes()==fixed.COMPONENT_STDOUT[state['name']]and
             (private/row['captures']['stderr']['file']).read_bytes()==b''and
             digest(state['summaries'])==digest([json.loads(x)for x in fixed.COMPONENT_STDOUT[state['name']].splitlines()]),
             'same-archive original pure components: full exact actual stdout, empty stderr and original bounds')
    seed=a['seed_prerequisite']
    need(seed['status']=='passed'and seed['launched']is True and
         digest([seed['exit'],seed['expected_exit']])==digest([0,0])and
         digest(seed['bounds'])==digest(BOUNDS['seed'])and a['namespace_controls']==dict(status='passed',tests=12,existing=5,added=7),
         'original actual seed and namespace controls also remain required')
    return dict(file=path.name,**fact(path),private_receipt=public['private_receipt'],status='passed',
        profile=a['profile'],totals=totals,archive=fact(archive),commands=len(a['commands']),
        commands_sha256=digest(a['commands']),component_summaries=[s['summaries']for s in states])


def cohort(builder,products,private,pin,binary,aliases,run,r):
    component_oracles(builder,products,private,pin,binary,aliases,run,r)
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    original=compile_subject(builder,private,pin,binary,run,r)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','sources')}
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,r,original,capture=True,dynamic=True)
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
                need(fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected persistent record')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),persistent_binding=r['release_build']['persistent_binding'],headers=r['release_build']['headers'])
                owner_args=(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'])
                actual_owner=owner_reader.read(*owner_args)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=reports.check(stderr,*terminal_args);r['terminal_reports'][label]=terminal
                c['terminal_controls']=reports.controls(stderr,*terminal_args)
                named(c['terminal_controls'],TERMINAL_COUNTS[mode,0],H(stderr),hash_key='original_stderr_sha256')
                c['selected_reason_controls']=reports.selected_reason_controls(stderr,*terminal_args)
                named(c['selected_reason_controls'],1,H(stderr),hash_key='original_stderr_sha256')
                c['owner_summary']={k:actual_owner[k]for k in('mode','classified_misses','cold_publications','warm_entries','replacements','permit_claims','interior_signals','word','code','detail','status')}
                need(all(type(v)is int and 0<=v<1<<64 for v in c['owner_summary'].values()),'only actual bounded owner counters')
                if mode in(0,1):
                    need(mode in native_records,'actual same-mode qualified full-state native reference')
                    c['pair']=reader.pair(native_records[mode],parsed,actual_owner)
                    need(digest(c['pair'])==digest(dict(qualified_pair=1,invocations=1,generated_completed=3 if mode==0 else 0,
                         required_late_store_fault=mode,interior_signals=0,classified_misses=int(mode==0),
                         warm_entries=int(mode==0),replacements=int(mode==0),whole_reuse_credit=0)),
                         'each actual generated boundary is paired with its same-mode complete native state')
                    c['pair_controls']=reader.pair_controls(native_records[mode],parsed,actual_owner)
                    names=c['pair_controls'];need(type(names['refusals'])is list and all(type(n)is str and n for n in names['refusals'])and
                        len(names['refusals'])==len(set(names['refusals']))==PAIR_COUNTS[mode]and
                        type(names['native_operations'])is int and names['native_operations']==0,'all four exact cross-lane full-state controls')
                else:need('pair'not in c,'protected-word rejection has no fabricated native counterpart')
                c['owner_reader_controls']=owner_reader.controls(*owner_args)
                named(c['owner_reader_controls'],OWNER_COUNTS[mode],H(record))
            c['status']=EXPECTED_STATUS[lane,mode]
        except Exception as error:
            c.update(status='failed',error_type=type(error).__name__,error=type(error).__name__+': '+str(error))
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    need(len(r['cases'])==5 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases'])and not r['error'],
         'all five actual persistent outcomes required without skipped or relabelled failures')
    need(sum(c.get('pair',{}).get('qualified_pair',0)for c in r['cases'])==2 and
         sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases'])==32 and
         sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==115 and
         sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases'])==8 and
         sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==180 and
         sum(len(c.get('selected_reason_controls',{}).get('refusals',[]))for c in r['cases'])==3,
         'two native full-state pairs, one independent protected-word rejection and exact controls')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True);parser.add_argument('--fixed-receipt',type=Path,required=True)
    args=parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);args.fixed_receipt=args.fixed_receipt.resolve(strict=True)
    need(args.fixed_receipt.parent==HERE/'results'and args.fixed_receipt.suffix=='.json','fixed-five prerequisite is an actual repository public receipt')
    cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-persistent-dynamic-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='persistent-dynamic-finite-v1',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=0 if mode==0 else 125,status='unexecuted',launched=False)for lane,mode,control in ORDER],
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
        required={str(p.relative_to(ROOT))for p in(Path(__file__),HERE/'persistent_dynamic_reports.py',HERE/'persistent_epoch.py',HERE/'persistent_epoch_reports.py',HERE/'persistent_epoch_build.py',
            HERE/'linked_epoch_reports.py',HERE/'linked_epoch_base_reports.py',HERE/'linked_epoch_build.py',HERE/'unrolled_hash_owner.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',
            OWNER/'read.py',OWNER/'layout.py',OWNER/'wire.py',OWNER/'plan.py')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in('persistent_plan.h','persistent_plan.c','persistent_compact.h','persistent_compact.c',
            'persistent_lifetime.h','persistent_runtime.h','persistent_source.inc','persistent_rseq.inc','persistent_controller.inc',
            'linked_mov_guard.h','linked_mov_guard.c','decoder/src/mov_guard.rs','persistent_epoch_binding.py',
            'persistent_epoch_observe.h','persistent_epoch_observe.inc','persistent_epoch_observe_memory.h','persistent_epoch_observe_memory.inc',
            'build-persistent-epoch.sh','build-persistent-epoch-capture.sh','persistent_dynamic_binding.py',
            'persistent_dynamic_capture_binding.py','build-persistent-dynamic.sh','build-persistent-dynamic-capture.sh',
            'persistent_dynamic_controller.inc','persistent_dynamic_plan.h','persistent_dynamic_plan.inc',
            'persistent_dynamic_observe.h','persistent_dynamic_observe.inc','persistent_dynamic_observe_memory.h','persistent_dynamic_observe_memory.inc')}
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
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==5 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
             'all five exact persistent hardware outcomes required')
        need(all(s['status']=='passed'for s in r['component_oracles']),
             'all three actual pure components mandatory independently of hardware totals')
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
        r['totals']=dict(planned=5,launched=sum(c['launched']for c in r['cases']),
            qualified=sum(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
            native_references=sum(c['status']in('qualified_native_success','qualified_native_late_fault')for c in r['cases']),
            generated_success=sum(c['status']=='qualified_generated_success'for c in r['cases']),
            generated_late_fault=sum(c['status']=='qualified_generated_late_fault'for c in r['cases']),
            protected_word_rejection=sum(c['status']=='qualified_protected_word_rejection'for c in r['cases']),
            qualified_pairs=sum(c.get('pair',{}).get('qualified_pair',0)for c in r['cases']if c['status']in('qualified_generated_success','qualified_generated_late_fault')),
            application_reader_refusals=sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            selected_reason_reader_refusals=sum(len(c.get('selected_reason_controls',{}).get('refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']),
            pair_reader_refusals=sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases']),
            classified_misses=sum(c.get('owner_summary',{}).get('classified_misses',0)for c in r['cases']),
            warm_entries=sum(c.get('owner_summary',{}).get('warm_entries',0)for c in r['cases']),
            completed_replacements=sum(c.get('owner_summary',{}).get('replacements',0)for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls','fixed_prerequisite')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        public['component_oracles']=[{k:v for k,v in s.items()if k in
            ('name','status','launched','expected_exit','bounds','emitted_instruction_execution','hardware_subjects','performance_credit',
             'recipe','archive','features','artifact','exit','duration_ns','timed_out','captures','summaries')}for s in r['component_oracles']]
        public['cases']=[public_case(c)for c in r['cases']]
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/persistent_dynamic.py','--expect-revision',args.expect_revision,'--fixed-receipt',str(args.fixed_receipt.resolve().relative_to(ROOT))],
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,
            scope='Separate dynamic five: real post-close classified miss and ordinary resume; A cold, A warm and B completed replacement; native/generated late-store fault; protected-word rejection. Original fixed five and all three pure components remain separately mandatory. Focal counts are distinct from global runtime totals. No65, whole-program or performance credit; original bounds retained.')
        raw=csv_projection(public['cases'])
        public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'all five compact actual persistent CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in raw.decode())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1


if __name__=='__main__':raise SystemExit(main())
