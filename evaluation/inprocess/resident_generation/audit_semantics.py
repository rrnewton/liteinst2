"""Complete two-activation audit; every original build/namespace/full-state gate remains."""
import hashlib,json,os,re,shlex,stat,struct,sys
from pathlib import Path
from resident_three.audit_semantics import need, digest, fact, whole, unique, load, module, image_inventory, loaded_application_relation, gated_controls
H=lambda b:hashlib.sha256(b).hexdigest()
BUILD=[30,512<<20,16<<20,60]
NATIVE=[5,512<<20,16<<20,15]
INSPECT=[10,256<<20,4<<20,20]
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1')

def check(root,here,r,path,old,pin,capture,closed):
    from page_selected_register_time_build import recipe,expand
    from page_selected import bridge_check
    from scalar_span_trace_build import fast_bytes_completed
    from resident_three import native_prerequisites,terminal_reports,certificate_reports
    contract=load(pin(here/'CONTRACT.json'));selected=root/'tools/page-entry/selected'
    cpu=old['cpu'];effect=old['effect'];commands={v['name']:v for v in old['commands']}
    need([v['name']for v in old['commands']]==contract['commands'] and len(commands)==22,
         'entire fixed fresh build/seed/native/gated schedule')
    releases={'app-0-link','app-1-link','bridge-link','span-bytes-link','seed-link'}
    finite={'span-bytes-oracle','native-fixture'}
    for name,row in commands.items():
        bounds=NATIVE if name in finite|{'seed-prerequisite'}else INSPECT if name in ('seed-headers','seed-libraries')else BUILD
        profile='release_build'if name in releases else'finite'if name in finite else'seed'if name=='seed-prerequisite'else'inspect'if name=='seed-libraries'else'program'if name in ('carrier','gated-fixture')else'metadata'
        env=dict(ENV)
        if name=='dwarf':env.update(MALLOC_ARENA_MAX='1',XDG_CACHE_HOME=str(path.parent/'gdb-cache'))
        if name in ('span-bytes-native-libraries','span-bytes-oracle'):env['LD_BIND_NOW']='1'
        closed(row,125 if name=='gated-fixture'and effect else 0,bounds)
        need(row['profile']==profile and row['environment']==env,'exact actual command profile and closed environment')
        need(set(row['captures'])==({'stdout','stderr','record'}if name=='gated-fixture'else{'stdout','stderr'}),
             'complete actual command capture population')
    for name in ('run.py','build.py','audit.py','audit_semantics.py','CONTRACT.json'):
        q=pin(here/name);need(old['inputs'][str(q)]==whole(q),'actual entire generation reproduction source: '+name)
    for name in ('native_prerequisites.py','terminal_reports.py','certificate_reports.py','certificate_baseline.py','native_launch.py','launch.py'):
        q=pin(here.parent/'resident_three'/name);need(old['inputs'][str(q)]==whole(q),'whole unchanged shared reproduction source: '+name)
    for relative in contract['reader_paths']:
        q=pin(root/relative);need(old['inputs'][str(q)]==whole(q),'actual installed full semantic reader dependency')
    app=pin(old['application']['path'],old['application']);interp=pin(old['interpreter']['path'],old['interpreter'])
    bridge=pin(old['builds']['bridge']['output']['path'],old['builds']['bridge']['output'])
    need(old['elf']==bridge_check(bridge),'whole unchanged bridge ELF validation')
    need(old['application']==old['builds']['app-1']['output']and old['interpreter']==old['builds']['app-0']['output'],
         'same complete newly built app/interpreter for both subjects')
    source_dir=selected/'tests/resident_generation_app';application=path.parent/'application';output=path.parent/'resident'
    application_rows=recipe(pin(source_dir/'build.sh'),'"$cc"');need(len(application_rows)==2,'two complete app compiler recipes')
    bridge_rows=recipe(pin(selected/'build-resident-generation.sh'),'"$cc_bin"');need(len(bridge_rows)==1,'one full bridge recipe')
    archive_path=old['flags_native_prerequisite']['receipt']['path']
    flags_receipt=load(pin(archive_path));archive=pin(flags_receipt['archive']['path'])
    for key,script in [('app-0',application_rows[0]),('app-1',application_rows[1]),('bridge',bridge_rows[0])]:
        build=old['builds'][key];cc=pin(build['argv'][0])
        expected=expand(script,{'$cc':cc,'$source_dir':source_dir,'$output':application,'$effect':str(effect)} if key!='bridge'else
            {'$cc_bin':cc,'$selected_dir':selected,'$parent_dir':selected.parent,'$archive':archive,'$output':output})
        need(build['argv']==commands[key+'-link']['argv']==expected,'whole exact installed compiler recipe: '+key)
        if key=='bridge':
            need([x for x in expected if x.startswith('-D')]==contract['macros']and
                 [x for x in expected if x.endswith(('.c','.S'))]==[str(root/p)for p in contract['translation_units']],
                 'complete source-owned28-TU sequence and exact feature definitions')
        units=[x for x in expected if x.endswith(('.c','.S'))]
        flags=[x for x in expected[1:-2]if x not in units and not x.endswith(('.a','.o'))and not x.startswith('-Wl,')]
        row=commands[key+'-headers']
        need(row['argv']==[expected[0],*flags,'-M','-MT','li2_resident',*units],
             'complete actual compiler-M invocation agrees with exact effective recipe')
        lines=capture(path.parent,row,'stdout').decode().replace('\\\n',' ').splitlines()
        need(len(lines)==len(units)and not capture(path.parent,row,'stderr'),'one full actual dependency rule per TU')
        observed=set()
        for line,unit in zip(lines,units,strict=True):
            need(line.startswith('li2_resident: '),'literal compiler-M target')
            names=shlex.split(line.split(':',1)[1]);need(names and names[0]==unit,'actual TU heads its rule');observed.update(names)
        need(observed==set(build['headers']),'all and only actual compiler-M inputs')
        for p,v in build['headers'].items():pin(p,v)
        need(not capture(path.parent,commands[key+'-link'],'stdout')and not capture(path.parent,commands[key+'-link'],'stderr'),
             'strict original compiler diagnostics')
    headers={p:{k:v[k]for k in ('bytes','sha256')}for p,v in old['builds']['bridge']['headers'].items()}
    binding_path=pin(output/'resident_three_binding.json');binding=load(binding_path)
    need(old['artifacts'][str(binding_path)]==whole(binding_path)and
         [v['path']for v in binding['sources']]==contract['policy']and
         binding['original']['image']==fact(app)and binding['archive']==fact(archive),
         'actual generated binding source policy and app/archive identities')
    for member in binding['sources']:
        q=Path(member['path']);need(not q.is_absolute()and ('..'not in q.parts or member['path']=='../bridge.c'),
             'bounded declared policy source with exact parent bridge exception')
        actual=pin(selected/q,member)
        if member['path']=='../bridge.c':need(actual==pin(selected.parent/'bridge.c')and headers[str(actual)]==fact(actual),
             'sole parent policy member is the whole actual bridge compiler source')
    for name,value in binding['headers'].items():
        need(Path(name).name==name,'literal generated header basename');q=pin(output/name,value)
        need(headers[str(q)]==value,'actual generated header appears in full compiler-M closure')
    macros=old['builds']['bridge']['argv'];maps_mode='differential'if '-DLI2_MAPS_DIFFERENTIAL=1'in macros else'maintained'
    need('-DLI2_MAPS_MAINTAINED=1'in macros,'actual compiled maintained maps policy')
    undefined=commands['undefined'];need(undefined['argv'][1:]==['-u',str(bridge)]and
        not capture(path.parent,undefined,'stdout')and not capture(path.parent,undefined,'stderr'),'no unresolved bridge symbols')
    symbols=commands['symbols'];need(symbols['argv'][1:]==['-S','--defined-only',str(bridge)]and
        not capture(path.parent,symbols,'stderr'),'complete actual provider symbol observation')
    names={line.split()[-1]for line in capture(path.parent,symbols,'stdout').decode().splitlines()if len(line.split())==4 and line.split()[2]in ('t','T')}
    need(set(contract['providers'])<=names,'all original complete provider entries are defined code')
    dwarf=commands['dwarf'];script=pin(selected/'tests/resident_generation_owner/layout.py')
    need(dwarf['argv'][1:]==['-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','-ex','file '+str(bridge),'-ex','source '+str(script)],
        'whole actual source-owned DWARF observation without inferior execution')
    layout_bytes=capture(path.parent,dwarf,'stdout')
    need(not capture(path.parent,dwarf,'stderr')and layout_bytes.endswith(b'\n')and layout_bytes.count(b'\n')==1,
         'one complete actual DWARF JSON line')
    layout=json.loads(layout_bytes,object_pairs_hook=unique)
    need(old['layout']==dict(bytes=len(layout_bytes),sha256=H(layout_bytes),types=113,fields=1254,raw_bytes=4129856,footer_bytes=64)and
         len(layout['types'])==113 and sum(len(v['fields'])for v in layout['types'].values())==1254 and
         layout['record']=='rgo_bundle'and layout['types']['rgo_bundle']['bytes']==4129856 and
         layout['types']['r3o_wire']['bytes']==2064000 and layout['types']['li2_r3_owner']['bytes']==1246784,
         'complete actual distinct two-activation DWARF closure')
    fast_bytes_completed(old['byte_oracle'],old['commands'],pin)
    for key,checker in [('flags_native_prerequisite',native_prerequisites.flags),('helper_native_prerequisite',native_prerequisites.helper)]:
        prior=old[key]['receipt'];checked=checker(prior['path'],prior['sha256'],old,old,pin,whole)
        need(checked==old[key],'whole original finite native prerequisite and actual source/build joins')
    seed=old['seed_prerequisite'];seed_rows=[commands[n]for n in ('seed-headers','seed-link','seed-libraries','seed-prerequisite')]
    need(seed['status']=='passed'and seed['planned']==1 and seed['launched']is True and seed['exit']==seed['expected_exit']==0 and
         seed['timed_out']is False and seed['bounds']==NATIVE and seed['completed_applications']==seed['owner_subjects']==0 and
         seed['performance_credit']is False,'one separately mandatory unchanged independent seed')
    directory=selected/'tests/provider_app/seed_probe';unit=pin(directory/'probe.c');exe=pin(seed['argv'][-1],seed['elf'])
    flags=['-std=gnu11','-O2','-g','-mgeneral-regs-only','-fno-tree-vectorize','-fno-tree-loop-distribute-patterns','-fno-builtin','-fno-pie','-no-pie','-Wall','-Wextra','-Werror']
    need(seed['argv']==[seed['argv'][0],*flags,'-Wl,-z,noexecstack,--build-id=none',str(unit),'-o',str(exe)]and
         seed_rows[0]['argv']==[seed['argv'][0],*flags,'-M','-MT','li2_seed',str(unit)]and seed_rows[1]['argv']==seed['argv']and
         seed_rows[3]['argv']==[str(exe)]and seed_rows[3]['environment']==ENV,'whole unchanged independent seed compiler/native recipe')
    pin(seed['argv'][0]);pin(directory/'build.sh',seed['recipe'])
    lines=capture(path.parent,seed_rows[0],'stdout').decode().replace('\\\n',' ').splitlines()
    need(len(lines)==1 and lines[0].startswith('li2_seed: ')and not capture(path.parent,seed_rows[0],'stderr'),'complete seed compiler-M rule')
    header_paths={str(pin(x))for x in shlex.split(lines[0].split(':',1)[1])}
    need(header_paths==set(seed['headers'])and {str(unit),str(directory/'record.h')}<=header_paths,'complete actual seed includes')
    for p,v in seed['headers'].items():pin(p,v)
    libraries={}
    for line in capture(path.parent,seed_rows[2],'stdout').decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(match is not None,'complete actual seed library row')
        q=pin(match[1]);need(q.name not in libraries,'unique actual seed library');libraries[q.name]=dict(path=str(q),**fact(q))
    need(libraries==seed['runtime_libraries']and seed_rows[2]['argv']==[next(v['path']for v in libraries.values()if Path(v['path']).name=='ld-linux-x86-64.so.2'),'--list',str(exe)]and
         not capture(path.parent,seed_rows[2],'stderr'),'entire actual seed interpreter/runtime library closure')
    seed_raw=capture(path.parent,seed_rows[3],'stdout');need(not capture(path.parent,seed_rows[3],'stderr')and len(seed_raw)==5792 and
         seed['pid']==seed_rows[3]['pid']and seed['whole_process_ns']==seed_rows[3]['duration_ns']and
         seed['captures']=={k:{j:v[j]for j in ('bytes','sha256')}for k,v in seed_rows[3]['captures'].items()},'whole actual independent seed process/capture joins')
    app_reader=module('app',pin(selected/'tests/resident_generation_app/read.py'))
    policy=module('native_policy',pin(selected/'tests/oneshot_integrated/check.py'))
    seed_reader=module('seed',pin(directory/'read.py'));xstate=module('xstate',pin(selected/'tests/b2_reference/xstate.py'))
    h=struct.unpack_from('<16Q',seed_raw,128);cpuid=[struct.unpack_from('<6I',seed_raw,256+24*i)for i in range(67)]
    facts=xstate.profile(cpuid,h[8],h[10],h[12],h[5],h[6]);profile=seed_reader.read(seed_raw,exe.read_bytes(),facts,xstate,cpu=cpu,pid=seed_rows[3]['pid'])
    need(digest(facts)==digest(seed['format'])and profile==seed['profile']and seed_reader.require(profile,facts,cpu=cpu)==bytes(16),
         'complete unchanged seed/raw/format validators and exact independently observed profile')
    reference=(seed_reader,xstate,profile,facts)
    nr=commands['native-fixture'];np=pin(path.parent/'native-preparation.json');prep=load(np)
    need(nr['argv']==[str(pin(sys.executable)),'-I','-S','-B',str(pin(here.parent/'resident_three/native_launch.py')),'--root',str(root),
         '--original',str(app),'--preparation',str(np)]and nr['environment']==ENV,'whole native launcher/ELF invocation')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']=='native'and prep['pid']==nr['pid']and
         prep['cpu']==[cpu]and prep['reset_mask']==0 and prep['launch_mask']==0xffffffffbffbfae7 and prep['observer']is None and
         prep['argv']==[str(app),'native']and prep['default_rseq']is False and prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH='/usr/lib64')and
         [v['signal']for v in prep['dispositions']]==[n for n in range(1,65)if n not in (9,19)]and all(v['after']==0 for v in prep['dispositions']),
         'whole actual native preparation and signal policy')
    native_raw=capture(path.parent,nr,'stdout');need(not capture(path.parent,nr,'stderr'),'empty actual native stderr')
    app_image=app_reader.elf(app.read_bytes(),policy.native_policy);need(app_image['interpreter']==str(interp),'actual app PT_INTERP')
    native_args=(native_raw,True,nr['exit'],app_image,nr['pid'],cpu,reference)
    native_result=app_reader.read(*native_args);native_controls=app_reader.controls(*native_args)
    need(native_controls['records']==2 and len(native_controls['controls'])==2 and
         all(v['ordinal']==i and len(v['result']['refusals'])==len(set(v['result']['refusals']))==80 and
             v['result']['original_sha256']==H(native_raw[i*341960:(i+1)*341960])and v['result']['native_operations']==0
             for i,v in enumerate(native_controls['controls'])),'all160 original native controls on two actual full records')
    relation=loaded_application_relation(app.read_bytes(),app.read_bytes(),interp,interp)
    need(relation['native']==relation['gated'],'the native and gated lanes use one entire identical built ELF')
    gp=path;gated=old;compiled=old;carrier_row=commands['carrier'];grow=commands['gated-fixture'];carrier=pin(gp.parent/'carrier')
    python=str(pin(sys.executable));carrier_tool=pin(root/'tools/page-entry/carrier.py')
    need(carrier_row['argv']==[python,'-B',str(carrier_tool),'make',str(app),str(bridge),str(carrier)]and
         set(carrier_row['captures'])=={'stdout','stderr'}and not capture(gp.parent,carrier_row,'stderr'),
         'exact actual carrier construction command')
    identity=json.loads(capture(gp.parent,carrier_row,'stdout'),object_pairs_hook=unique)
    need(all(identity[k+'_sha256']==fact(p)['sha256']for k,p in(('original',app),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and
         gated['subject_artifacts']=={k:fact(p)for k,p in(('original',app),('interpreter',interp),('bridge',bridge),('carrier',carrier))},
         'whole real carrier/original/interpreter/bridge artifact identity')
    namespace=module('namespace',pin(root/'tools/page-entry/namespace.py'))
    need(namespace.parse(app.read_bytes())==dict(elf_type=2,needed=[],soname=None,interpreter=interp)and
         namespace.parse(interp.read_bytes())==dict(elf_type=3,needed=[],soname=None,interpreter=None)and
         namespace.parse(carrier.read_bytes())['interpreter']==bridge,'actual empty dependency pair and carrier PT_INTERP')
    objects,description=namespace.plan(app,[app.parent],bytes.fromhex(fact(app)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    need(objects==[]and gated['namespace_plan']==description and
         gated['runtime_libraries']=={interp.name:dict(path=str(interp),**fact(interp))}and
         gated['runtime_library_scope']=='source_owned_no_needed_fixture; no dynamic-loader list command',
         'exact source-owned no-needed namespace/interpreter contract')
    need(gated['external_inputs']==[dict(fact(p),roles=[role])for role,p in(('original',app),('interpreter',interp))]and
         all(fact(pin(gp.parent/'external-inputs'/(str(i)+'.elf')))==fact(p)for i,p in enumerate((app,interp))),
         'both independently retained full original input copies')
    ns=gp.parent/'namespace';observed=load(pin(ns/'namespace.json'));launch=load(pin(ns/'launch.json'));prep=load(pin(gp.parent/'preparation.json'))
    need(observed==dict(description,schema_version=1,scope='explicit_sealed_dependency_namespace',status='prepared_not_executed',
         directory=str(ns),objects=[],search_policy='explicit roots; no RPATH/RUNPATH/cache emulation',
         identity_policy='sealed copies and private paths; not filesystem transparency'),'complete actual empty namespace manifest')
    launcher=pin(here.parent/'resident_three/launch.py')
    need(grow['argv']==[python,'-B',str(launcher),'--root',str(root),'--role','gated','--mode','0','--control','0',
         '--original',str(app),'--preparation',str(gp.parent/'preparation.json'),'--library-root',str(app.parent),
         '--carrier',str(carrier),'--namespace',str(ns),'--record-fd',str(grow['descriptors'][0]['fd'])]and
         len(grow['descriptors'])==1 and grow['descriptors'][0]['name']=='record'and
         type(grow['descriptors'][0]['fd'])is int and grow['descriptors'][0]['fd']>=3 and
         set(grow['captures'])=={'stdout','stderr','record'},'exact one-subject launcher/record argument and complete streams')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']=='gated'and
         prep['pid']==grow['pid']and prep['cpu']==[cpu]and prep['reset_mask']==prep['launch_mask']==0 and
         prep['argv']==[str(app),'gated']and prep['default_rseq']is False and prep['mode']==prep['control']==0 and
         type(prep['previous_mask'])is int and 0<=prep['previous_mask']<1<<64 and
         [v['signal']for v in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and
         all(set(v)=={'signal','before','after'}and type(v['before'])is int and 0<=v['before']<1<<64 and v['after']==0 for v in prep['dispositions']),
         'whole actual PID/CPU/mask/disposition/mode preparation')
    env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',LD_LIBRARY_PATH=str(ns),
             LI2_DEPENDENCY_FDS='',GLIBC_TUNABLES='glibc.pthread.rseq=0',LI2_PERSISTENT_RETAINED_TWO_APP_MODE='0')
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',argv=prep['argv'],
         dependency_fds=[],carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],environment=env)and
         prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'complete actual gated exec/carrier/environment join')
    record_path=pin(gp.parent/grow['captures']['record']['file']);st=record_path.stat()
    need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
         prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino),'same actual exclusive inherited owner record descriptor')
    raw=capture(gp.parent,grow,'stdout');stderr=capture(gp.parent,grow,'stderr');record=capture(gp.parent,grow,'record')
    output_stat=(gp.parent/grow['captures']['stdout']['file']).stat()
    before=grow['stdout_provenance_before'];after=grow['stdout_provenance_after']
    need(before['parent_fd']==after['parent_fd']and before['identity']==after['identity']and
         before['open_route']==after['open_route']=='exclusive-normal-open/Popen-stdout-dup2-exec'and
         type(before['parent_fd'])is int and before['parent_fd']>2,'same actual ordinary stdout descriptor through execution')
    for observation,size in((before,0),(after,len(raw))):
        identity=observation['identity'];data=bytes.fromhex(observation['statx_hex'])
        need(len(identity)==7 and len(data)==256 and identity[:2]==[output_stat.st_dev,output_stat.st_ino]and
             identity[3:6]==[os.major(output_stat.st_dev),os.minor(output_stat.st_dev),output_stat.st_mode]and
             identity[2]>0 and identity[6]&os.O_ACCMODE==os.O_WRONLY and not identity[6]&os.O_PATH and
             struct.unpack_from('<I',data)[0]&0x1103==0x1103 and not struct.unpack_from('<I',data)[0]&0x4000 and
             struct.unpack_from('<H',data,28)[0]==output_stat.st_mode and
             struct.unpack_from('<Q',data,32)[0]==output_stat.st_ino and struct.unpack_from('<Q',data,40)[0]==size and
             struct.unpack_from('<IIQ',data,136)==tuple(identity[3:5]+[identity[2]]),
             'complete actual stdout statx/fstat identity and before/after extent')
    owner=module('owner',pin(selected/'tests/resident_generation_owner/read.py'))
    image=image_inventory(app,interp,carrier,objects,observed)
    image.update(bridge=bridge.read_bytes(),persistent_binding=binding,headers=headers,maps_mode=maps_mode)
    # Both records must identify the actual exclusive inherited sink.
    record_base=layout['types']['rgo_bundle']['fields']['record']['offset']
    for ordinal in range(2):
        for key in('sink_initial','sink_terminal'):
            offset=record_base+ordinal*2064000+layout['types']['r3o_wire']['fields'][key]['offset']
            for name,value in(('st_dev',st.st_dev),('st_ino',st.st_ino)):
                field=layout['types']['stat']['fields'][name]
                need(field['bytes']==8 and struct.unpack_from('<Q',record,offset+field['offset'])[0]==value,
                     'whole typed record identifies actual sink: '+str(ordinal)+'/'+key+'/'+name)
    if effect:
        need(raw==b'' and grow['exit']==125,'failed prefix never becomes successful application output')
        actual_reports,parsed=certificate_reports.failed_prefix(stderr)
        need(actual_reports==old['terminal_prefix'] and actual_reports['LI2_LOADER']['status']==125 and
             actual_reports['LI2_LOADER']['failure_code']==4902,'whole typed failed terminal report remains failed')
        refused=owner.refusal(record,layout,image,grow['pid'],cpu,grow['exit'],effect)
        refusal_controls=owner.refusal_controls(record,layout,image,grow['pid'],cpu,grow['exit'],effect)
        need(refusal_controls['count']==len(refusal_controls['refusals'])==len(set(refusal_controls['refusals']))==18 and
             refusal_controls['source_sha256']==H(record)and refusal_controls['native_operations']==0,
             'all18 exact failed-prefix data controls')
        r['semantic']=dict(status='failed_prefix',refusal=refused,refusal_controls=refusal_controls,native_app_controls=native_controls,
            native_full_frames=10,second_activation_equivalence=False,app_raw=fact(gp.parent/grow['captures']['stdout']['file']),
            owner_raw=fact(record_path),layout=dict(bytes=len(layout_bytes),sha256=H(layout_bytes)),
            qualification_credit=False,performance_credit=False,equivalence_credit=False)
        return
    terminal=terminal_reports.check(stderr);terminal_controls=terminal_reports.controls(stderr)
    need(terminal==gated['terminal_reports']and terminal_controls==gated['terminal_controls'],
         'whole strict terminal schema and every original report mutation')
    app_image=app_reader.elf(app.read_bytes(),policy.native_policy)
    app_args=(raw,False,grow['exit'],app_image,grow['pid'],cpu,reference)
    application=app_reader.read(*app_args)
    app_controls=[gated_controls(app_reader.original,raw[i*341960:(i+1)*341960],False,grow['exit'],app_image,grow['pid'],cpu,reference)for i in range(2)]
    need(all(len(v['refusals'])==len(set(v['refusals']))==80 and v['native_operations']==0 and
             v['original_sha256']==H(raw[i*341960:(i+1)*341960])for i,v in enumerate(app_controls)),
         'all160 unchanged gated application controls')
    owner_args=(record,layout,image,application,grow['pid'],cpu,grow['exit'])
    actual=owner.read(*owner_args)
    owner_controls=[owner.record_controls(*owner_args,i)for i in range(2)]
    prepared=[owner.record_prepared_controls(*owner_args,i)for i in range(2)]
    generation=owner.generation_controls(*owner_args)
    for rows,count in((owner_controls,231),(prepared,24)):
        need(all(v['count']==len(v['refusals'])==len(set(v['refusals']))==count and
                 v['source_sha256']==H(record)and v['native_operations']==0 for v in rows),
             'whole old owner/prepared controls for each actual completion')
    need(generation['count']==len(generation['refusals'])==len(set(generation['refusals']))==40 and
         generation['source_sha256']==H(record)and generation['native_operations']==0,'all40 added generation-boundary controls')
    signal_join=terminal_reports.resident_signals(stderr,actual['signal_counts'])
    signal_controls=terminal_reports.resident_signal_controls(stderr,actual['signal_counts'])
    need(signal_controls['count']==len(signal_controls['refusals'])==len(set(signal_controls['refusals']))==87 and
         signal_controls['stderr_sha256']==H(stderr)and signal_controls['ingress']==list(actual['signal_counts'])and
         signal_controls['native_operations']==0,'all87 exact terminal-to-global-ingress controls')
    pair=owner.pair(native_result,application,actual);pair_controls=owner.pair_controls(native_result,application,actual)
    need(pair_controls['count']==88 and len(pair_controls['activations'])==2 and
         all(v['count']==len(v['refusals'])==len(set(v['refusals']))==44 and v['native_operations']==0
             for v in pair_controls['activations']),'all88 unchanged full-state cross-lane mutations')
    need(pair['publications']==3 and pair['entries']==pair['completed']==2 and pair['interior_signals']==0 and
         pair['native_full_frames']==10 and pair['protected_full_frames']==6,'actual three publications and two complete owner lifetimes')
    r['semantic']=dict(status='observed_unqualified',pair=pair,application_relation=relation,
        native_app_controls=native_controls,gated_app_controls=app_controls,owner_controls=owner_controls,
        pair_controls=pair_controls,prepared_fetch_controls=prepared,generation_controls=generation,
        terminal=terminal,terminal_controls=terminal_controls,signal_join=signal_join,signal_controls=signal_controls,
        content_reference=actual['content_reference'],preserved_boundary_effects=actual['preserved_boundary_effects'],
        source_cost=[v['source_cost']for v in actual['activations']],
        app_raw=fact(gp.parent/grow['captures']['stdout']['file']),owner_raw=fact(record_path),
        layout=dict(bytes=len(layout_bytes),sha256=H(layout_bytes)),maps_mode=maps_mode,
        frames=[dict(ordinal=i,kind=name,greg=v[name]['greg'],fp_sha256=H(v[name]['fp']),
                     uc_sha256=H(v[name]['uc']),si_sha256=H(v[name]['si']))
                for i,v in enumerate(actual['activations'])for name in('before','terminal','next')],
        qualification_credit=False,performance_credit=False)
