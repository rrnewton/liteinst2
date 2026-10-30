#!/usr/bin/env python3
"""Three additive supported-cut failures: native fault, ordinary fault, failed revoke."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/linked_preedge_failure_app'
OWNER=SELECTED/'tests/linked_preedge_failure_owner'
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
import linked_preedge_failure_reports as reports
BOUNDS=dict(PROFILES,release_build=[30,512<<20,16<<20,60],program=[30,512<<20,16<<20,60],seed=[5,512<<20,16<<20,15],finite=[5,512<<20,16<<20,15])
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
H=lambda b:hashlib.sha256(b).hexdigest()
ORDER=(('native',0,0),('gated',0,0),('gated',1,0))
APP_COUNTS={(0,True):40,(0,False):21,(1,False):21}
PAIR_COUNTS={0:6}
OWNER_COUNTS={(0,0):57,(1,0):52}
TERMINAL_COUNTS={(0,0):53,(1,0):53}
CASE_FIELDS=('label','lane','mode','control','expected_exit','status','launched','exit','whole_process_ns','timed_out','captures','pair','owner_summary','control_reference','error_type')
CSV_FIELDS=('lane','mode','control','status','expected_exit','exit','whole_process_ns','application_control_count','terminal_control_count','owner_control_count','pair_control_count')
EXPECTED_STATUS={('native',0):'qualified_native_fault_reference',('gated',0):'qualified_original_cut_fault',('gated',1):'qualified_cut_revoke_failure'}
# These exact donor helpers retain source, namespace and native seed closure.
# These required failures have no nested shim or nested-control credit.
seed_prerequisite=donor.seed_prerequisite
prepare_inputs=donor.prepare_inputs
image_inventory=donor.image_inventory


def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def public_case(c):
    value={k:c[k]for k in CASE_FIELDS if k in c}
    for prefix,key in(('terminal','terminal_controls'),('owner','owner_reader_controls'),('pair','pair_controls')):
        value[prefix+'_control_count']=len(c.get(key,{}).get('refusals',[]))
        value[prefix+'_controls_sha256']=digest(c.get(key,{}))
    value['application_control_count']=len(c.get('application_controls',{}).get('refusals',[]))
    return value


def csv_projection(cases):
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(CSV_FIELDS)
    for c in cases:writer.writerow([c.get(k,'')for k in CSV_FIELDS])
    return stream.getvalue().encode()


def prerequisite(path,r,pin,binary):
    """Closed same-source/CPU cut-failure3; no report or native replay."""
    import scalar_reuse_performance as prior
    from scalar_span_trace_build import fast_bytes_completed
    path=Path(path).resolve(strict=True)
    need(path.parent==HERE/'results'and path.suffix=='.json'and path.stat().st_size<=32<<10,'bounded public cut-failure3 receipt')
    def pinned(p,want=None):
        q=pin(p)
        if want is not None:need(digest(fact(q))==digest(want),'exact retained cut-failure input')
        return q
    public,a=prior.closed(path,r,pinned,binary)
    totals=dict(planned=3,launched=3,qualified=3,native_fault_reference=1,gated_data_fault=1,gated_revoke_failure=1,
        qualified_pairs=1,application_reader_refusals=82,terminal_reader_refusals=106,owner_reader_refusals=109,pair_reader_refusals=6)
    need(public['profile']==a['profile']=='linked-preedge-cut-failure-v2'and public['status']==a['status']=='passed'and
         digest(a['totals'])==digest(public['totals'])==digest(totals)and digest(a['bounds'])==digest(public['bounds'])==digest(BOUNDS)and
         digest(a['source'])==digest(r['source'])and digest(a['hardware'])==digest(r['hardware'])and type(a['cpu'])is int and a['cpu']==r['cpu']and
         public['performance_credit']is False and public['whole_ls_eligibility_credit']is False,'all exact same-source/CPU cut failures without whole-profile credit')
    need(digest([(c['lane'],c['mode'],c['control'])for c in a['cases']])==digest(ORDER),'exact three-case native-fault/gated-fault/revoke schedule')
    commands={c['name']:c for c in a['commands']};private=ROOT/'target/evaluation/inprocess'/path.stem
    layout_path=binary(private/'owner-dwarf-layout.json');layout=json.loads(layout_path.read_bytes())
    need(digest(fact(layout_path))==digest(a['owner_layout']['artifact'])and layout['record']=='lpec_wire'and
         type(layout['types']['lpec_wire']['bytes'])is int and 0<layout['types']['lpec_wire']['bytes']+64<16<<20,'actual captured DWARF extent under original cap')
    for c in a['cases']:
        lane,mode=c['lane'],c['mode'];row=commands[c['label']]
        need(c['status']==EXPECTED_STATUS[lane,mode]and c['launched']is True and c['timed_out']is False and
             digest([c['exit'],c['expected_exit'],row['exit'],row['expected_exit']])==digest([125]*4)and
             row['profile']=='program'and digest(row['bounds'])==digest(BOUNDS['program'])and
             type(c['whole_process_ns'])is int and c['whole_process_ns']==row['duration_ns']and
             digest(c['captures'])==digest({k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()}),
             'each required failure is a real exact completed command with original bounds')
        for cap in row['captures'].values():need(digest(fact(binary(private/cap['file'])))==digest({k:cap[k]for k in('bytes','sha256')}),'whole actual required-failure capture')
        need(row['captures']['stdout']['bytes']==(299288 if lane=='native'else 14720),'complete native reference or exact gated failure prefix')
        named(c['application_controls'],APP_COUNTS[mode,lane=='native'],row['captures']['stdout']['sha256'])
        if lane=='native':need(row['captures']['stderr']['bytes']==0,'native fault reference has empty stderr')
        else:
            need(row['captures']['record']['bytes']==layout['types']['lpec_wire']['bytes']+64 and row['captures']['stderr']['bytes']>0,'whole actual failed owner and terminal stream')
            named(c['owner_reader_controls'],OWNER_COUNTS[mode,0],row['captures']['record']['sha256'])
            named(c['terminal_controls'],TERMINAL_COUNTS[mode,0],row['captures']['stderr']['sha256'],hash_key='original_stderr_sha256')
            need(c['terminal']['application_completed']is False and c['terminal']['required_failure']==1 and
                 type(c['terminal']['required_failure'])is int and c['terminal']['whole_profile_qualified']==0 and
                 type(c['terminal']['whole_profile_qualified'])is int,'required failure never claims application or whole-profile completion')
            if mode==0:
                need(digest(c['pair'])==digest(dict(qualified_pair=1,invocations=1,generated_completed=1,cut_kind=2,
                    post_cut_completed=0,actual_data_fault=1,whole_profile_qualified=0)),'whole actual native/gated supported-cut data-fault pair')
                v=c['pair_controls'];need(type(v['refusals'])is list and len(v['refusals'])==len(set(v['refusals']))==6 and
                    all(type(n)is str and n for n in v['refusals'])and type(v['native_operations'])is int and v['native_operations']==0,'all six actual paired-state refusals')
            else:need('pair'not in c and 'pair_controls'not in c,'revoke failure never acquires invented native-pair credit')
    need(digest([public_case(c)for c in a['cases']])==digest(public['cases'])and
         pinned(path.with_suffix('.csv')).read_bytes()==csv_projection(public['cases']),'complete typed public cases and CSV equal actual outcomes')
    release=a['release_build'];binding=release['linked_binding'];archive={k:a['build']['artifacts']['decoder.a'][k]for k in('bytes','sha256')}
    need(release['status']==a['application_build']['status']=='passed'and release['native_hint']is True and
         digest(release['preedge'])==digest(dict(version=2,plan_bytes=40744,proof_payload_bytes=45288,capture=True,failure_capture=True))and
         release['argv'].count('-DLI2_LINKED_PREEDGE_FAILURE_CAPTURE=1')==release['argv'].count('-DLI2_LINKED_PREEDGE=1')==1 and
         digest(release['archive'])==digest(binding['archive'])==digest(archive)and
         digest(a['build']['decoder_features'])==digest(['scalar-region','scalar-span','linked-epoch'])and
         type(a['build']['archive_text_exports']['li2_decoder_link_none'])is int and a['build']['archive_text_exports']['li2_decoder_link_none']==1,
         'actual distinct failed-cut capture with the exact three-feature proof archive')
    fast_bytes_completed(release,a['commands'],binary)
    need(digest(fact(binary(binding['path'])))==digest(binding['header'])and
         digest(fact(binary(binding['manifest_path'])))==digest(binding['manifest']),'whole actual retained policy header and manifest')
    seed=a['seed_prerequisite'];command=commands['seed-prerequisite']
    need(seed['status']=='passed'and seed['launched']is True and digest([seed['exit'],seed['expected_exit'],command['exit'],command['expected_exit']])==digest([0]*4)and
         digest(seed['bounds'])==digest(BOUNDS['seed'])and a['raw_emission']['status']=='passed'and
         digest(a['raw_emission']['bridge'])==digest(release['bridge'])and a['raw_emission']['nested_credit']is False and
         digest(a['namespace_controls'])==digest(dict(status='passed',tests=12,existing=5,added=7)),
         'actual independent seed, RAW-only emission and unchanged namespace obligations')
    return dict(file=path.name,**fact(pinned(path)),private_receipt=public['private_receipt'],profile=a['profile'],status='passed',totals=totals,
        archive=archive,binding={k:binding[k]for k in('version','archive','policy_sha256','header')},commands=len(a['commands']),
        commands_sha256=digest(a['commands']),whole_profile_qualified=False)


def load(name,path,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path));module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


def reader_support(builder,private,pin,binary,run,r):
    reader=load('preedge_failure_app_read',FIXTURE/'read.py',pin)
    owner=load('preedge_failure_owner_read',OWNER/'read.py',pin)
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
    need(argv[-2:]==['-o',str(output/'linked-preedge-failure-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
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
    original=binary(output/'linked-preedge-failure-app');_,head,segments=elf(original)
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
    layout=json.loads(out);need(layout['record']=='lpec_wire'and 0<layout['types']['lpec_wire']['bytes']+64<16<<20,'actual retained owner wire')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout


def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,control=case['lane'],case['mode'],case['control'];prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(not any(k in prep for k in('current_custody','current_control','physical_fallback')),'no unrelated launch profile')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==lane and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['profile']=='linked-preedge-cut-failure-v2'and prep['argv']==[str(original),str(mode),lane]and prep['default_rseq']is False and prep['mode']==mode and prep['control']==control and
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
        LI2_LINKED_PREEDGE_FAILURE_APP_MODE=str(mode)))and
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


def app_table(value):
    need(type(value)is dict and all(type(k)is tuple and len(k)==2 and type(k[0])is int and
         type(k[1])is bool and type(n)is int and n>0 for k,n in value.items()),'exact typed failure app refusal table')
    return [[*key,value[key]]for key in sorted(value)]


def cohort(builder,products,private,pin,binary,aliases,run,r):
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    original=compile_subject(builder,private,pin,binary,run,r)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','sources')}
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    bridge=build_bridge(builder,products,private,pin,binary,aliases,run,r,('LINKED_PREEDGE_FAILURE_CAPTURE',),
        capture_image=original,native_hint=True,preedge=True)
    raw_emission(builder,bridge,pin,run,r)
    layout=observed_layout(builder,bridge,private,pin,binary,run,r)
    interp,roots,objects,description,images,raws,carrier=prepare_inputs(original,bridge,builder,private,pin,binary,run,r)
    carrier_bytes=carrier.read_bytes();launcher=pin(FIXTURE/'launch.py');native_record=None
    for module in tuple(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).is_file():pin(path)
    need(digest(app_table(reader.APP_CONTROL_COUNTS))==digest(app_table(APP_COUNTS))and
         digest(reader.PAIR_CONTROL_COUNTS)==digest(PAIR_COUNTS)and
         digest(control_table(owner_reader.CONTROL_COUNTS))==digest(control_table(OWNER_COUNTS))and
         digest(control_table(reports.CONTROL_COUNTS))==digest(control_table(TERMINAL_COUNTS)),
         'literal complete distinct app, protected-owner and pair refusal populations')
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed';directory=private/label;directory.mkdir()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',lane,'--mode',str(mode),'--control','0',
            '--original',original,'--preparation',directory/'preparation.json']
        for p in roots:argv+=['--library-root',p]
        if lane=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,stdout,stderr=run(label,argv,profile='program',expected=125,record=lane=='gated')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1];c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            parsed=reader.read(stdout,mode,lane=='native',row['exit'],app_layout,row['pid'],r['cpu'],seed_reference,control=0)
            c['application_controls']=reader.controls(stdout,mode,lane=='native',row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
            named(c['application_controls'],APP_COUNTS[mode,lane=='native'],H(stdout))
            if lane=='native':
                need(stderr==b'','native actual fault reference stderr remains empty');native_record=parsed
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected cut-failure record')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),binding=r['release_build']['linked_binding'],headers=r['release_build']['headers'])
                actual_owner=owner_reader.read(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=0)
                args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=reports.check(stderr,*args);r['terminal_reports'][label]=terminal
                c['terminal_controls']=reports.controls(stderr,*args)
                named(c['terminal_controls'],TERMINAL_COUNTS[mode,0],H(stderr),hash_key='original_stderr_sha256')
                c['owner_summary']={k:v for k,v in actual_owner['summary'].items()if k not in('proof_arena','proof_registry')}
                need(c['owner_summary']and all(type(k)is str and type(v)is int and 0<=v<1<<64 for k,v in c['owner_summary'].items()),'only actual numeric owner counters')
                if mode==0:
                    need(native_record is not None,'actual same-mode qualified full-state native fault reference')
                    c['pair']=reader.pair(native_record,parsed,actual_owner)
                    need(digest(c['pair'])==digest(dict(qualified_pair=1,invocations=1,generated_completed=1,cut_kind=2,
                        post_cut_completed=0,actual_data_fault=1,whole_profile_qualified=0)),
                        'actual supported-cut fault pair retains released-generated and failed-ordinary states separately')
                    c['pair_controls']=reader.pair_controls(native_record,parsed,actual_owner)
                    names=c['pair_controls'];need(type(names['refusals'])is list and all(type(n)is str and n for n in names['refusals'])and
                        len(names['refusals'])==len(set(names['refusals']))==PAIR_COUNTS[mode]and
                        type(names['native_operations'])is int and names['native_operations']==0,'all six exact cross-lane fault controls')
                c['owner_reader_controls']=owner_reader.controls(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=0)
                named(c['owner_reader_controls'],OWNER_COUNTS[mode,0],H(record))
            c['status']=EXPECTED_STATUS[lane,mode]
        except Exception as error:
            c.update(status='failed',error_type=type(error).__name__,error=type(error).__name__+': '+str(error))
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    need(len(r['cases'])==3 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases'])and not r['error'],
         'all three actual required failures, no skipped or relabelled failed qualification')
    need(sum(c.get('pair',{}).get('qualified_pair',0)for c in r['cases'])==1 and
         sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases'])==82 and
         sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==109 and
         sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases'])==6 and
         sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==106,
         'one fault pair, one independent revoke failure, exact82/109/6 and terminal controls')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True)
    args=parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-linked-preedge-cut-failure-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,profile='linked-preedge-cut-failure-v2',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=125,status='unexecuted',launched=False)for lane,mode,control in ORDER],
        namespace_aliases={},terminal_reports={},bounds=BOUNDS,error=None,final_errors=[],
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
        required={str(p.relative_to(ROOT))for p in (Path(__file__),HERE/'linked_preedge_failure_reports.py',HERE/'linked_preedge_reports.py',HERE/'linked_epoch_reports.py',
            HERE/'linked_epoch_terminal.py',HERE/'linked_epoch_base_reports.py',HERE/'linked_epoch_performance_reports.py',HERE/'linked_epoch_cache_reports.py',
            HERE/'linked_epoch_build.py',HERE/'unrolled_hash_owner.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',
            OWNER/'read.py',OWNER/'layout.py',OWNER/'wire.py',OWNER/'plan.py')}
        required|={str((SELECTED/name).relative_to(ROOT))for name in('linked_preedge_plan.h','linked_preedge_plan.c',
            'linked_preedge_source.h','linked_preedge_source.inc','linked_preedge_rseq.h','linked_preedge_rseq.inc','linked_preedge_proof.h',
            'linked_preedge_failure_observe.h','linked_preedge_failure_observe.inc','linked_preedge_failure_observe_memory.h','linked_preedge_failure_observe_memory.inc',
            'build-linked-preedge.sh','build-linked-preedge-failure-capture.sh','linked_epoch_binding.py')}
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
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==3 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
             'all three exact hardware required-failure outcomes required')
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
        r['totals']=dict(planned=3,launched=sum(c['launched']for c in r['cases']),
            qualified=sum(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases']),
            native_fault_reference=sum(c['status']=='qualified_native_fault_reference'for c in r['cases']),
            gated_data_fault=sum(c['status']=='qualified_original_cut_fault'for c in r['cases']),
            gated_revoke_failure=sum(c['status']=='qualified_cut_revoke_failure'for c in r['cases']),
            qualified_pairs=sum(c.get('pair',{}).get('qualified_pair',0)for c in r['cases']if c['status']=='qualified_original_cut_fault'),
            application_reader_refusals=sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']),
            pair_reader_refusals=sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases']))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        public['cases']=[public_case(c)for c in r['cases']]
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/linked_preedge_failure.py','--expect-revision',args.expect_revision],
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,
            scope='Three additive supported-cut required failures: native actual data-fault reference, released generated epoch then failed ordinary data load, and actual generated-page revoke failure at the original cut. No whole-profile, old65 or performance credit; original bounds retained.')
        raw=csv_projection(public['cases'])
        public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'all three compact actual required-failure CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in raw.decode())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1


if __name__=='__main__':raise SystemExit(main())
