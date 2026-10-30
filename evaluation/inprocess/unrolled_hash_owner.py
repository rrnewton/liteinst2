#!/usr/bin/env python3
"""Fixed25 actual native/application-owner subjects; no throughput credit."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,sys
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
BOUNDS=dict(PROFILES,release_build=[30,512<<20,16<<20,60],program=[30,512<<20,16<<20,60])
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
H=lambda b:hashlib.sha256(b).hexdigest()
ORDER=tuple((lane,mode,0)for lane in('native','gated')for mode in range(9))+tuple(('gated',0,c)for c in range(1,8))


def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def load(name,path,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path));module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


def reader_support(builder,private,pin,binary,run,r):
    reader=load('unrolled_app_read',FIXTURE/'read.py',pin)
    owner=load('unrolled_owner_read',OWNER/'read.py',pin)
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
    script=pin(FIXTURE/'build.sh');rows=recipe(script,'"$cc"');need(len(rows)==1,'one exact three-TU app recipe')
    output=private/'application';output.mkdir()
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':FIXTURE,'$output':output})
    sources=[str(pin(FIXTURE/x))for x in('main.c','pure.c','machine.S')]
    need(argv[-2:]==['-o',str(output/'unrolled-hash-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
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


def observed_layout(builder,bridge,private,pin,binary,run,r):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']=='uho_wire'and 0<layout['types']['uho_wire']['bytes']<4<<20,'actual retained owner wire')
    path=private/'owner-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout


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
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==lane and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['argv']==[str(original),str(mode),lane]and prep['default_rseq']is True and prep['mode']==mode and prep['control']==control and
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
        LD_BIND_NOW='1',LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),LI2_UNROLLED_CAPTURE_CONTROL=str(control)))and
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
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    original=compile_subject(builder,private,pin,binary,run,r);app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k!='source'}
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,r,('UNROLLED_HASH_CAPTURE',),capture_image=original)
    layout=observed_layout(builder,bridge,private,pin,binary,run,r)
    interp,roots,objects,description,images,raws,carrier=prepare_inputs(original,bridge,builder,private,pin,binary,run,r)
    carrier_bytes=carrier.read_bytes();launcher=pin(FIXTURE/'launch.py');native_records={}
    for module in tuple(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).is_file():pin(path)
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed';directory=private/label;directory.mkdir()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',lane,'--mode',str(mode),'--control',str(control),
            '--original',original,'--preparation',directory/'preparation.json']
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
                parsed=reader.read(out,mode,True,row['exit'],app_layout,row['pid'],r['cpu'])
                native_records[mode]=(out,row['pid']);c['status']='qualified_native_reference'
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected owner record')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                parsed=(reader.control_prefix(out,control,row['exit'],app_layout,row['pid'],r['cpu'])if control else
                        reader.read(out,mode,False,row['exit'],app_layout,row['pid'],r['cpu']))
                actual_owner=owner_reader.read(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader)
                terminal,c['terminal']=reports.check(err,*terminal_args);r['terminal_reports'][label]=terminal
                c['terminal_controls']=reports.controls(err,*terminal_args)
                c['owner_summary']=actual_owner['summary']
                need(type(c['owner_summary'])is dict and c['owner_summary']and
                     all(type(k)is str and type(v)is int and 0<=v<1<<64 for k,v in c['owner_summary'].items()),
                     'compact actual numeric owner summary, no raw frame or guessed completion')
                if control:
                    need(0 in native_records,'actual mode0 native reference required for every control')
                    nout,npid=native_records[0]
                    native=reader.read(nout,0,True,0,app_layout,npid,r['cpu'])
                    c['control_reference']=control_reference(reader,native,parsed,actual_owner,control)
                    c['status']='qualified_required_owner_refusal'
                else:
                    need(mode in native_records,'same-mode complete native reference required')
                    nout,npid=native_records[mode]
                    def compare(n,g):
                        native=reader.read(n,mode,True,125 if mode>=7 else 0,app_layout,npid,r['cpu'])
                        gated=reader.read(g,mode,False,row['exit'],app_layout,row['pid'],r['cpu'])
                        owner=owner_reader.read(record,layout,image,gated,row['pid'],r['cpu'],row['exit'],control=0)
                        return reader.pair(native,gated,owner)
                    c['pair']=compare(nout,out);c['application_controls']=reader.controls(compare,nout,out,mode)
                    need(c['application_controls']==dict(supplied_refusals=26,native_operations=0),'all fixed app rejection controls')
                    c['status']='qualified_required_read_failure'if mode>=7 else 'qualified_application'
                c['owner_reader_controls']=owner_reader.controls(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control)
                want=32 if control==1 else 20 if control==6 else 27 if control in(2,4,5)else 28
                need(len(c['owner_reader_controls']['refusals'])==want and c['owner_reader_controls']['native_operations']==0 and
                     c['owner_reader_controls']['original_sha256']==H(record),'complete fixed actual owner-record refusal controls')
        except Exception as error:
            c['status']='failed';c['error_type']=type(error).__name__;c['error']=type(error).__name__+': '+str(error)
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and
                isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    need(len(r['cases'])==25 and all(c['status'].startswith('qualified_')for c in r['cases'])and not r['error'],'all25 actual subjects qualify, no failed-prefix completion credit')
    need(sum(c.get('pair',{}).get('qualified_case',0)for c in r['cases'])==9 and
        sum(c.get('application_controls',{}).get('supplied_refusals',0)for c in r['cases'])==234 and
        sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==16*33 and
        sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==441,
        'all nine actual pairs and fixed application/terminal/owner-record refusal controls')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True);args=parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-unrolled-hash-owner-'+args.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='unrolled-hash-owner-v1',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=125 if control or mode>=7 else 0,status='unexecuted',launched=False)for lane,mode,control in ORDER],
        namespace_aliases={},terminal_reports={},bounds=BOUNDS,error=None,final_errors=[])
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
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess']);need(not err,'source enumeration stderr')
        tracked={os.fsdecode(name)for name in names.split(b'\0')if name}
        required={str(p.relative_to(ROOT))for p in (Path(__file__),HERE/'unrolled_hash_app_reports.py',HERE/'unrolled_hash_build.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',OWNER/'read.py',OWNER/'layout.py')}
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
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==25 and all(c['status'].startswith('qualified_')for c in r['cases']),'all25 native/application/control attempts required')
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
            scope='Required25 subjects: nine actual native references, nine actual generated-owner pairs including two real read faults, and seven required owner refusals. Whole native/gated GPR, actual AF, FP, stack and data comparisons are mandatory. Failed operations never count as completed applications. This finite fixture qualifies this owner only; no general function/data-pointer authority or throughput claim.')
        columns=('lane','mode','control','status','expected_exit','exit','whole_process_ns','application_control_count','terminal_control_count','owner_control_count')
        stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(columns)
        for c in public['cases']:writer.writerow([c.get(k,'')for k in columns])
        raw=stream.getvalue().encode();public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'all25 compact outcome CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
