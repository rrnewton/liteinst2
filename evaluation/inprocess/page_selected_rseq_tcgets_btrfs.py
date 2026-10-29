"""Twenty real TCGETS pairs and fixed supplied controls under existing custody.

The enclosing driver runs the unchanged sixteen plus four registered profiles and requires
same-revision 6/49/17 cohorts. No supplied frame supplies a native reference.
"""
import hashlib,importlib.util,json,os,shlex,shutil
from pathlib import Path
from page_selected import fact,need,elf
from page_selected_oneshot_build import commands,UNITS,MACROS
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
BOUNDS={'rseq_tcgets_btrfs':[5,512<<20,16<<20,15],
        'rseq_tcgets_btrfs_build':[30,512<<20,16<<20,60]}
WINSZ_BOUNDS={'rseq_tiocgwinsz_btrfs':[5,512<<20,16<<20,15],
              'rseq_tiocgwinsz_btrfs_build':[30,512<<20,16<<20,60]}
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',PYTHONDONTWRITEBYTECODE='1')
NATIVE=(0,)*20
GATED=(0,)*7+(125,)*13
H=lambda b:hashlib.sha256(b).hexdigest()


def qualify(builder,products,root,private,library_root,pin,binary,aliases,run,receipt,*,winsz=False):
    need(type(winsz)is bool,'one fixed additional TIOCGWINSZ profile')
    profile='rseq_tiocgwinsz_btrfs'if winsz else'rseq_tcgets_btrfs';prefix=profile.replace('_','-')
    if winsz:need(receipt.get('rseq_tcgets_btrfs_fixture',{}).get('status')=='passed',
                  'complete unchanged macro-off twenty pairs and sixteen supplied refusals before extension')
    root,private=Path(root),Path(private);selected=root/'tools/page-entry/selected';fixture=selected/'tests/rseq_tcgets_btrfs'
    output=private/prefix;output.mkdir();cpu=next(iter(os.sched_getaffinity(0)))
    state=receipt[profile+'_fixture']=dict(status='failed',cases=[],programs=[],builds=[],generated={},archive=fact(products['archive']))
    for key,value in (WINSZ_BOUNDS if winsz else BOUNDS).items():need(receipt['bounds'].get(key)==value,'exact registered-native bound '+key)
    need(os.sched_getaffinity(0)=={cpu},'one reserved CPU for all actual boundary subjects')
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    prepare=load('rseq_tcgets_btrfs_prepare',fixture/'prepare.py');check=load('rseq_tcgets_btrfs_check',fixture/'check.py')
    reports=load('rseq_tiocgwinsz_btrfs_reports'if winsz else'rseq_tcgets_btrfs_reports',fixture/('winsz.py'if winsz else'reports.py'))
    images=load('rseq_tcgets_btrfs_interpreter',selected/'tests/provider_launch/interpreter.py')
    namespace=load('rseq_tcgets_btrfs_namespace',root/'tools/page-entry/namespace.py')
    policy=load('rseq_tcgets_btrfs_policy',selected/'tests/oneshot_integrated/check.py')
    corpus=json.loads(pin(fixture/'CASES.json').read_bytes())
    need([c['index']for c in corpus['cases']]==list(range(20))and
         tuple(c['native_exit']for c in corpus['cases'])==NATIVE==check.NATIVE_EXIT and
         tuple(c['gated_exit']for c in corpus['cases'])==GATED==check.GATED_EXIT and
         tuple(c['native_result']for c in corpus['cases'])==check.RESULT and
         [x['index']for x in corpus['injected_refusals']]==list(range(1,17)),
         'twenty exact actual pairs and sixteen explicitly supplied refusal controls')
    if winsz:
        extra=json.loads(pin(fixture/'WINSZ-CASES.json').read_bytes());reports.corpus(extra,corpus)
        prior=[b for b in receipt['rseq_tcgets_btrfs_fixture']['builds']if b['name']=='rseq-tcgets-btrfs-observed']
        need(len(prior)==1,'one actual macro-off observed bridge')
        baseline=prior[0]['inspection']['layout']['types']['li2_tcgets_state']
    capture_check=load('rseq_tcgets_capture',fixture/'capture.py')
    for name in ('fixture.S','native_reference.c','record.h','linker.ld','build.sh','layout.py','observe.inc'):pin(fixture/name)
    observed=output/'observed'
    try:state['adapters']=prepare.prepare(root,observed,pin)
    finally:
        for name in ('runtime_loader.c','native_controller.inc','rseq_guard.c','selected_controller.inc','rseq_tcgets_btrfs.inc','rseq_tcgets_observe.inc','rseq_tcgets_record.h','rseq_tcgets_old_record.h'):
            state['generated'][name]=retain('partial observation '+name,observed/name)
    tools={n:pin(shutil.which(n,path=ENV['PATH']))for n in ('gdb','objdump')}
    state['tools']={n:dict(path=str(p),**fact(p))for n,p in tools.items()}
    cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    for name,path in tools.items():
        _,out,err=run(prefix+'-'+name+'-version',[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual inspection tool identity '+name)
    btrfs=pin(shutil.which('btrfs',path='/usr/sbin:/usr/bin:/sbin:/bin'))
    state['tools']['btrfs']=dict(path=str(btrfs),**fact(btrfs))
    def inspect(name,path,record=None,bridge=False):
        binary(path)
        if bridge:bridge_check(path)
        _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
        need(out==err==b'','actual freestanding ELF has no unresolved imports')
        _,symbols,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
        need(not err,'actual retained ELF symbols')
        result=dict(path=str(path),**fact(path))
        if bridge:
            _,assembly,err=run(name+'-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',path],profile='inspect',env=builder.environment)
            need(not err,'actual complete reset body');result['reset']=hidden_memset(path,body_check(path,symbols,assembly,'fast',symbol_name='memset'))
        if record:
            _,out,err=run(name+'-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
                '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(path),'-x',fixture/'layout.py'],env=gdb_env)
            need(not err,'file-only actual DWARF stderr');layout=json.loads(out);result['layout']=layout
            rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[record.encode()]];_,_,ph=elf(path)
            need(layout['record']==record and len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b' and
                 0<int(rows[0][1],16)==layout['types'][record]['bytes']<16<<20 and
                 sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+int(rows[0][1],16)<=p[3]+p[6]for p in ph)==1,
                 'complete actual native or gated record in one writable NX load')
        return result
    recipe_path=pin(selected/('build-'+prefix+'.sh'));argv=commands(recipe_path,builder,output,products['archive'],pin)[0]
    units=[str(selected.parent/p)for p in UNITS[:-1]]
    macros=(MACROS-{'-DLI2_ONESHOT_PUBLICATION=1'})|{'-DLI2_CPUID_NX_ONLY=1','-DLI2_RSEQ_NATIVE=1','-DLI2_RSEQ_NATIVE_BOUNDARY=1','-DLI2_RSEQ_TCGETS_BTRFS=1'}
    if winsz:macros=macros|{'-DLI2_RSEQ_TIOCGWINSZ_BTRFS=1'}
    need(argv[-2:]==['-o',str(output/('bridge-'+prefix+'.so'))] and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         set(x for x in argv if x.startswith('-DLI2_'))==macros and
         sum(x.startswith('-DLI2_')for x in argv)==len(macros)==11+int(winsz) and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact fifteen-unit boundary production recipe without one-shot')
    for kind in('unobserved','observed'):
        name=prefix+'-'+kind;actual=argv.copy();sources=units.copy();bridge=output/(kind+'.so');actual[-1]=str(bridge)
        if kind=='observed':
            actual[-2:-2]=['-Wl,--undefined=rtc_subvol_command']
            for basename in('runtime_loader.c','rseq_guard.c'):
                old,new=str(selected/basename),str(observed/basename)
                need(actual.count(old)==1,'one exact observation translation-unit replacement')
                actual=[new if x==old else x for x in actual];sources=[new if x==old else x for x in sources]
        row=dict(name=name,recipe=fact(recipe_path),argv=actual,archive=fact(products['archive']),translation_units=len(sources));state['builds'].append(row)
        headers(name+'-headers',actual,sources,products['archive'],builder,pin,aliases,run,row)
        if kind=='observed':
            need({str(observed/n)for n in('runtime_loader.c','native_controller.inc','rseq_guard.c','selected_controller.inc','rseq_tcgets_btrfs.inc','rseq_tcgets_observe.inc','rseq_tcgets_record.h','rseq_tcgets_old_record.h')}<=set(row['headers']),
                 'all eight actual observation sources in the compiler include closure')
        try:run(name+'-link',actual,profile=profile+'_build',env=builder.environment)
        finally:row['artifact']=retain(name,bridge)
        row['inspection']=inspect(name,bridge,'rtc_record'if kind=='observed'else None,True)
        if kind=='observed':
            gated_bridge=bridge;gated_layout=row['inspection']['layout'];gated_layout_path=output/'gated-layout.json'
            gated_layout_path.write_text(json.dumps(gated_layout,sort_keys=True)+'\n');pin(binary(gated_layout_path))
    interpreter=output/'interpreter'/'li2-provider-entry.so';metadata=output/'interpreter'/'metadata.S'
    try:need(images.emit(output/'interpreter')==(interpreter,metadata),'unchanged actual interpreter emitter paths')
    finally:
        for path in(interpreter,metadata):state['generated'][path.name]=retain('partial actual interpreter',path)
    for path in(interpreter,metadata):pin(binary(path))
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(fixture/'launch.py')
    def execute(case,original,image,native_layout,native_layout_path,lane):
        native=lane=='native';injected=image['injected'];name=prefix+'-'+str(case)+'-'+str(injected)+('-winsz'if image.get('request_profile',False)else'-tcgets'if winsz else'')+'-'+lane;directory=output/name;directory.mkdir()
        row=dict(name=name,index=case,injected=injected,lane=lane,status='failed',operation_status='unobserved',expected_exit=(125 if injected else (NATIVE if native else GATED)[case]),error=None)
        if winsz:row['request_profile']=image.get('request_profile',False)
        state['cases'].append(row)
        objects,description=namespace.plan(original,[interpreter.parent],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
        row['namespace_plan']=description;row['dependencies']=[]
        for item in objects:
            need(fact(pin(item['path']))['sha256']==H(item['bytes']),'complete actual namespace dependency source')
            row['dependencies'].append(dict(names=item['names'],**fact(pin(item['path']))))
            for alias in item['names']:pin(interpreter.parent/alias)
        prep=directory/'preparation.json';capture_preparation=directory/'capture-preparation.json';capture_object=directory/'capture-object';ns=directory/'namespace';carrier=directory/'carrier'
        route=corpus['cases'][case]['parent_fd_route']
        if route=='subvolume':
            need(case==5 and not injected and os.getuid()==os.geteuid()>0,'fixed unprivileged real subvolume case')
            subvolume=directory/'capture-subvolume';setup=name+'-subvolume-create'
            need(not os.path.lexists(subvolume),'fresh unique subvolume destination')
            row['subvolume_preparation']=dict(command=setup,path=str(subvolume),euid=os.geteuid(),attempted=True)
            command,created,err=run(setup,[btrfs,'subvolume','create','--',subvolume],env=ENV)
            need(command['exit']==0 and command['reaped']is True and not err and
                 subvolume.is_dir()and not subvolume.is_symlink(),'actual bounded subvolume creation before capture open')
            st=subvolume.stat();row['subvolume_preparation'].update(pid=command['pid'],exit=command['exit'],device=st.st_dev,inode=st.st_ino,mode=st.st_mode)
            capture_object=subvolume/'capture-object'
        argv=[builder.tools['python'],launch_tool,'--mode',lane,'--original',original,'--library-root',interpreter.parent,
            '--preparation',prep,'--record-fd','{record_fd}','--capture-route',route,'--capture-object',capture_object,
            '--layout',native_layout_path if native else gated_layout_path]
        if not native:
            try:
                _,out,err=run(name+'-make',[builder.tools['python'],carrier_tool,'make',original,gated_bridge,carrier],env=ENV)
                need(not err,'actual carrier construction stderr')
            finally:retain('partial actual carrier '+name,carrier)
            binary(carrier);v=json.loads(out)
            need(v['original_sha256']==fact(original)['sha256']and v['bridge_sha256']==fact(gated_bridge)['sha256']and
                 v['interpreter_sha256']==fact(interpreter)['sha256']and v['carrier_sha256']==fact(carrier)['sha256'],'actual same-original carrier identities')
            row['carrier']=v;argv+=['--carrier',carrier,'--namespace',ns]
        row['invocation_attempted']=True
        try:
            command,out,err=run(name,argv,profile=profile,expected=None,env=ENV,record=True)
        except BaseException as exc:
            row['error']=type(exc).__name__+': '+str(exc)
            actual=[c for c in receipt['commands']if c['name']==name]
            if actual:row.update({k:actual[-1][k]for k in('exit','pid','captures')if k in actual[-1]})
            raise
        finally:
            for path in(prep,capture_preparation,private/(name+'.record'),ns/'namespace.json',ns/'launch.json'):retain('partial subject '+name+' '+path.name,path)
        row.update(exit=command['exit'],pid=command['pid'],captures=command['captures'])
        need(type(command['exit'])is int and command['exit']==row['expected_exit']and type(command['pid'])is int and command['pid']>0 and
             command['reaped']is True and not command['timed_out']and not command['error']and not command['cleanup_errors']and
             command['descriptors']==[dict(name='record',fd=3,closed=True)],'actual exact subject outcome and closed FD3')
        record_path=pin(binary(private/(name+'.record')));record=record_path.read_bytes()
        actual=json.loads(pin(binary(prep)).read_bytes());row['preparation']=actual
        captured=json.loads(pin(binary(capture_preparation)).read_bytes());need(actual['capture']==captured,'same complete retained capture preparation')
        capture_check.check(captured,route,native_layout if native else gated_layout);row['capture_preparation']=captured
        need(out==b'','no bytes in original invoke stdout capture')
        if route not in('pipe','memfd'):
            st=capture_object.stat();identity=captured['identity']
            need((st.st_dev,st.st_ino,st.st_mode)==(identity['device'],identity['inode'],identity['mode']),'actual retained capture object identity after subject')
            if capture_object.is_file():
                need(st.st_size==0 and capture_object.read_bytes()==b'','actual retained file remains empty through ioctl subject');row['capture_object']=fact(pin(binary(capture_object)))
        else:need(not capture_object.exists(),'anonymous capture route has no fabricated file artifact')
        app_argv=[str(original)]+(['native']if native else[])
        need(actual['mode']==lane and actual['mask']==0 and actual['affinity']==[cpu]and
             [x['signal']for x in actual['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and
             all(x['after']==0 for x in actual['dispositions'])and actual['argv']==app_argv and
             actual['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
             actual['observer']==dict(fd=3,device=record_path.stat().st_dev,inode=record_path.stat().st_ino),
             'actual reset signals/mask, same CPU, exact argv/environment and observed FD identity')
        if not native:
            sealed=json.loads(pin(binary(ns/'namespace.json')).read_bytes());started=json.loads(pin(binary(ns/'launch.json')).read_bytes())
            need(sealed['original']==str(original)and sealed['original_sha256']==fact(original)['sha256']and
                 sealed['interpreter_sha256']==fact(interpreter)['sha256']and len(sealed['objects'])==len(objects),'actual complete original namespace')
            for a,item in zip(sealed['objects'],objects):
                need(a['names']==item['names']and a['sha256']==H(item['bytes'])and a['size']==len(item['bytes'])and
                     a['seals']==namespace.SEALS and a['device']>0 and a['inode']>0,'actual immutable complete dependency object')
                for alias in a['names']:
                    path=ns/alias;value='/proc/self/fd/'+str(a['fd'])
                    need(path.is_symlink()and os.readlink(path)==value,'actual retained namespace alias')
                    receipt.setdefault('rseq_tcgets_btrfs_namespace_aliases',{})[str(path)]=value
            env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
            env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(str(a['fd'])for a in sealed['objects']))
            need(started['argv']==app_argv and started['environment']==env and started['carrier_sha256']==fact(carrier)['sha256'],
                 'actual registered native profile, no disable-rseq or configured policy')
            parsed=reports.reports(err,initial=case>=16);row['reports']=parsed
            need(parsed['loader']['status']==command['exit'],'actual report and operation outcome agree')
            cpuid=parsed['cpuid_nx']
            if case<16:
                need(cpuid['attempts']==cpuid['samples']==cpuid['commits']==parsed['loader']['cpuid']==1 and cpuid['raw']==cpuid['result']and
                     cpuid['phase']==3 and cpuid['hardware_entered']==cpuid['hardware_returned']==1,
                     'actual one first-interpreter CPUID before finite registered operation')
            if command['exit']==0:reports.completed(parsed,command['pid'])
            row['comparison']=check.gated(record,gated_layout,image,command['pid'],command['exit'],captured)
            if winsz:
                row['comparison']['command_completed']=reports.join(parsed,check.Reader(record,gated_layout,'rtc_record'),record,command['pid'],image,baseline)
            else:reports.join(parsed,check.Reader(record,gated_layout,'rtc_record'),record,command['pid'])
        else:
            need(not err,'actual native fixture stderr is empty')
            row['comparison']=check.native(record,native_layout,image,command['pid'],command['exit'])
        need(all(x==cpu for x in row['comparison']['observed_cpus']),'actual observed rseq CPU equals reserved CPU')
        row['operation_status']='before-operation-prefix'if native and case==15 else'completed'if command['exit']==0 else'failed'
        row['status']='passed'
        return row,out,record
    fixture_recipe=pin(fixture/'build.sh');templates=recipe(fixture_recipe,'"$cc_bin"');need(len(templates)==1,'one source-bound actual fixture link recipe')
    if winsz:
        winsz_recipe=pin(fixture/'build-winsz.sh');winsz_templates=recipe(winsz_recipe,'"$cc_bin"')
        need(len(winsz_templates)==1,'one fixed TIOCGWINSZ fixture recipe')
    def build_fixture(case,injected,request_profile=False):
        need(type(request_profile)is bool and (winsz or not request_profile),'explicit request under fixed new bridge only')
        name=prefix+'-program-'+str(case)+'-'+str(injected)+('-winsz'if request_profile else'-tcgets'if winsz else'');directory=output/name;directory.mkdir();original=directory/'original'
        actual_recipe,template=(winsz_recipe,winsz_templates[0])if request_profile else(fixture_recipe,templates[0])
        values={'$cc_bin':builder.tools['cc'],'$fixture_dir':fixture,'$metadata':metadata,'$output':original,'$case_number':case,'$injected':injected}
        argv=expand(template,values);units=[str(fixture/'fixture.S'),str(fixture/'native_reference.c'),str(metadata)]
        need([x for x in argv if x.endswith(('.c','.S'))]==units and argv[-2:]==['-o',str(original)]and
             argv.count('-DRN_CASE='+str(case))==1 and argv.count('-DRTC_INJECT='+str(injected))==1 and all(x in argv for x in('-O2','-g','-Werror','-nostdlib','-no-pie','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-mcmodel=large')),
             'actual original fixture recipe and exact literal case')
        need(argv.count('-DRTC_WINSZ=1')==int(request_profile)and not any(x.startswith('-DRTC_WINSZ=')and x!='-DRTC_WINSZ=1'for x in argv),'fixed actual fixture request macro')
        row=dict(index=case,injected=injected,recipe=fact(actual_recipe),argv=argv,status='failed')
        if winsz:row['request_profile']=request_profile
        state['programs'].append(row)
        flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
        _,out,err=run(name+'-headers',[builder.tools['cc'],*flags,'-M','-MT','rseq_tcgets_btrfs',*units],env=builder.environment)
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(rules)==3 and all(x.startswith('rseq_tcgets_btrfs: ')for x in rules),'actual complete three-TU native fixture include closure')
        row['headers']={str(pin(t)):fact(pin(t))for line in rules for t in shlex.split(line.split(':',1)[1])}
        need(set(units)<=set(row['headers']),'all linked fixture sources in actual include closure')
        try:run(name+'-link',argv,profile=profile+'_build',env=builder.environment)
        finally:row['artifact']=retain('partial actual native fixture '+name,original)
        pin(binary(original));row['inspection']=inspect(name,original,'rtc_native_record')
        image=check.elf(original.read_bytes(),interpreter,case,policy.native_policy,injected,request_profile=request_profile);row['image']=image;row['status']='built'
        native_layout_path=directory/'native-layout.json';native_layout_path.write_text(json.dumps(row['inspection']['layout'],sort_keys=True)+'\n');pin(binary(native_layout_path))
        return original,image,row,native_layout_path
    if winsz:
        base=None
        for case,request_profile in [(0,False)]+[(i,True)for i in range(16)]:
            original,image,row,layout_path=build_fixture(case,0,request_profile);layout=row['inspection']['layout']
            native,nout,nrecord=execute(case,original,image,layout,layout_path,'native')
            gated,gout,grecord=execute(case,original,image,layout,layout_path,'gated')
            row['comparison']=check.pair(nrecord,grecord,nout,gout,{'native':layout,'gated':gated_layout},image,native['pid'],gated['pid'],cpu,gated['capture_preparation'])
            need(row['comparison']['qualified_pair']==1 and row['comparison']['forwarded_pair']==int(case<7)and
                 row['comparison']['required_refusal']==int(case>=7),'exact new native/gated request pair, required refusal remains failed')
            row['comparison']['command_completed']=gated['comparison']['command_completed'];row['status']='passed'
            if case==0 and request_profile:base=(nrecord,layout,image,native['pid'])
        need(base is not None,'fresh actual winsz case0 native reference before supplied result control')
        original,image,row,layout_path=build_fixture(0,15,True);layout=row['inspection']['layout']
        gated,gout,grecord=execute(0,original,image,layout,layout_path,'gated')
        row['comparison']=check.control(base[0],grecord,{'native':base[1],'gated':gated_layout},base[2],image,base[3],gated['pid'],cpu,gated['capture_preparation'])
        need(row['comparison']['operation_status']=='failed'and row['comparison']['exit_status']==125 and
             row['comparison']['actual_syscalls']==1 and row['comparison']['frame_commits']==0 and
             gated['comparison']['command_completed']==[0,0],
             'actual winsz ENOTTY retained separately from supplied0; neither counter nor frame commits')
        row['comparison']['command_completed']=gated['comparison']['command_completed'];row['status']='passed'
        need(len(state['cases'])==35 and all(c['status']=='passed'for c in state['cases'])and
             len(state['programs'])==18 and all(c['status']=='passed'for c in state['programs']),
             'all17 new pairs and one supplied-result refusal under unchanged per-command bounds')
    else:
        base=None
        for case in range(20):
            original,image,row,layout_path=build_fixture(case,0);layout=row['inspection']['layout']
            native,nout,nrecord=execute(case,original,image,layout,layout_path,'native')
            gated,gout,grecord=execute(case,original,image,layout,layout_path,'gated')
            row['comparison']=check.pair(nrecord,grecord,nout,gout,{'native':layout,'gated':gated_layout},image,native['pid'],gated['pid'],cpu,gated['capture_preparation'])
            need(row['comparison']['qualified_pair']==1 and row['comparison']['forwarded_pair']==int(case<7)and
                 row['comparison']['required_refusal']==int(case>=7),'exact actual permitted/refused twenty-pair corpus')
            row['status']='passed'
            if case==0:base=(nrecord,layout,image,native['pid'])
        need(base is not None,'actual current case0 native reference before supplied controls')
        for injected in range(1,17):
            original,image,row,layout_path=build_fixture(0,injected);layout=row['inspection']['layout']
            gated,gout,grecord=execute(0,original,image,layout,layout_path,'gated')
            row['comparison']=check.control(base[0],grecord,{'native':base[1],'gated':gated_layout},base[2],image,base[3],gated['pid'],cpu,gated['capture_preparation'])
            need(row['comparison']['operation_status']=='failed'and row['comparison']['exit_status']==125 and
                 row['comparison']['actual_syscalls']==int(injected==15)and row['comparison']['frame_commits']==0,
                 'supplied controls retain required operation failure and actual-only raw return')
            row['status']='passed'
        need(len(state['cases'])==56 and all(c['status']=='passed'for c in state['cases'])and
             len(state['programs'])==36 and all(c['status']=='passed'for c in state['programs']),
             'all twenty genuine pairs and sixteen additional supplied refusals completed under original bounds')
    finalize(receipt);state['status']='passed'


def finalize(receipt):
    need(all(Path(p).is_symlink()and os.readlink(p)==value for p,value in receipt.get('rseq_tcgets_btrfs_namespace_aliases',{}).items()),
         'all actual sealed namespace alias observations remain unchanged')



def summary(receipt):
    state=receipt.get('rseq_tcgets_btrfs_fixture',{});cases=state.get('cases',[]);commands=receipt.get('commands',[])
    def actual(c):
        rows=[r for r in commands if r.get('name')==c['name']and r.get('profile')=='rseq_tcgets_btrfs']
        return rows[0]if len(rows)==1 and type(rows[0].get('pid'))is int and rows[0]['pid']>0 else None
    def closed(r):return r is not None and r.get('reaped')is True and type(r.get('exit'))is int
    accepted=[c for c in cases if c.get('status')=='passed'and closed(actual(c))and actual(c)['exit']==c['expected_exit']and
              not actual(c).get('timed_out')and not actual(c).get('error')and not actual(c).get('cleanup_errors')]
    programs=state.get('programs',[]);complete=state.get('status')=='passed'and len(accepted)==56 and len(programs)==36 and all(p.get('status')=='passed'for p in programs)
    if state.get('status')=='passed':
        expected=[(i,0,lane)for i in range(20)for lane in('native','gated')]+[(0,j,'gated')for j in range(1,17)]
        need(complete and [(c['index'],c['injected'],c['lane'])for c in cases]==expected and
             [(p['index'],p['injected'])for p in programs]==[(i,0)for i in range(20)]+[(0,j)for j in range(1,17)]and
             all(c['exit']==actual(c)['exit']and c['pid']==actual(c)['pid']for c in cases),
             'exact fixed corpus and actual PID/exit membership before public qualification')
        for c in accepted:
            i,j,lane=c['index'],c['injected'],c['lane'];comparison=c['comparison']
            expected_exit=0 if lane=='native'or i<7 and not j else 125
            expected_events=(1 if i==15 else 2)if lane=='native'else 2 if i<7 and not j else 0 if i>=16 else 1
            expected_syscalls=int(i!=15)if lane=='native'else int(i<7 and not j or j==15)
            need(type(c['expected_exit'])is int and c['expected_exit']==expected_exit and
                 type(comparison['events'])is int and comparison['events']==expected_events and
                 type(comparison['actual_syscalls'])is int and comparison['actual_syscalls']==expected_syscalls,
                 'exact per-case actual event/raw-call distinction and required refusals')
        need(all(p['comparison']['qualified_pair']==1 and p['comparison']['forwarded_pair']==int(p['index']<7)and
                 p['comparison']['required_refusal']==int(p['index']>=7)for p in programs[:20])and
             all(p['comparison']['operation_status']=='failed'and p['comparison']['exit_status']==125 and
                 p['comparison']['actual_syscalls']==int(p['injected']==15)and p['comparison']['frame_commits']==0 for p in programs[20:]),
             'no supplied failure or permission-only prefix is relabelled native completion')
    pairs=[p for p in programs if p.get('status')=='passed'and not p['injected']]
    controls=[p for p in programs if p.get('status')=='passed'and p['injected']]
    return dict(status=state.get('status'),planned_native_gated_pairs=20,planned_supplied_controls=16,
        attempted_processes=len(cases),actual_processes=sum(actual(c)is not None for c in cases),
        closed_processes=sum(closed(actual(c))for c in cases),accepted_processes=len(accepted),
        zero_exit_processes=sum(c['expected_exit']==0 for c in accepted),required_exit125_processes=sum(c['expected_exit']==125 for c in accepted),
        accepted_case_pairs=len(pairs),accepted_supplied_controls=len(controls),
        full_frame_pairs=sum(p['comparison']['full_frame_pairs']for p in pairs),
        actual_observed_syscalls=sum(c['comparison']['actual_syscalls']for c in accepted),
        committed_gated_frames=sum(c['comparison'].get('frame_commits',0)for c in accepted),
        native_before_operation_prefixes=sum(c['comparison'].get('before_operation_prefix',0)for c in accepted),
        subvolume_pairs=sum(p['index']==5 for p in pairs),same_ofd_dup_pairs=sum(p['index']==6 for p in pairs),
        full_finite_profile=complete,full_b2_complete=False,full_b3_complete=False,application_completion=False,performance_credit=False)



def summary_winsz(receipt):
    state=receipt.get('rseq_tiocgwinsz_btrfs_fixture',{});cases=state.get('cases',[]);commands=receipt.get('commands',[])
    pairs=[(0,False)]+[(i,True)for i in range(16)]
    expected=[(i,0,w,lane)for i,w in pairs for lane in('native','gated')]+[(0,15,True,'gated')]
    def actual(c):
        rows=[r for r in commands if r.get('name')==c['name']and r.get('profile')=='rseq_tiocgwinsz_btrfs']
        return rows[0]if len(rows)==1 and type(rows[0].get('pid'))is int and rows[0]['pid']>0 else None
    def closed(row):return row is not None and row.get('reaped')is True and type(row.get('exit'))is int
    accepted=[c for c in cases if c.get('status')=='passed'and closed(actual(c))and actual(c)['exit']==c['expected_exit']and
              not actual(c).get('timed_out')and not actual(c).get('error')and not actual(c).get('cleanup_errors')]
    programs=state.get('programs',[]);complete=state.get('status')=='passed'and len(accepted)==35 and len(programs)==18 and all(p.get('status')=='passed'for p in programs)
    if state.get('status')=='passed':
        need(complete and [(c['index'],c['injected'],c['request_profile'],c['lane'])for c in cases]==expected and
             [(p['index'],p['injected'],p['request_profile'])for p in programs]==[(i,0,w)for i,w in pairs]+[(0,15,True)]and
             all(type(c['index'])is int and type(c['injected'])is int and type(c['request_profile'])is bool and
                 c['exit']==actual(c)['exit']and c['pid']==actual(c)['pid']for c in cases),
             'exact35 actual new process identities; no planned/attempted process is credited')
        for c in accepted:
            i,j,w,lane=c['index'],c['injected'],c['request_profile'],c['lane'];v=c['comparison']
            good=i<7 and not j;expected_exit=0 if lane=='native'or good else 125
            need(type(c['expected_exit'])is int and c['expected_exit']==expected_exit and
                 type(v['events'])is int and v['events']==((1 if i==15 else 2)if lane=='native'else 2 if good else 1)and
                 type(v['actual_syscalls'])is int and v['actual_syscalls']==(int(i!=15)if lane=='native'else int(good or j==15)),
                 'exact per-process genuine events/raw calls and required nonzero operations')
            if lane=='gated':
                need(type(v['frame_commits'])is int and v['frame_commits']==int(good)and
                     type(v['command_completed'])is list and all(type(x)is int for x in v['command_completed'])and
                     v['command_completed']==(([0,1]if w else[1,0])if good else[0,0]),
                     'exact full frame commit and separately validated actual per-command count')
        for p in programs[:17]:
            i,w=p['index'],p['request_profile'];v=p['comparison']
            need(v['qualified_pair']==1 and v['forwarded_pair']==int(i<7)and v['required_refusal']==int(i>=7)and
                 v['command_completed']==(([0,1]if w else[1,0])if i<7 else[0,0]),
                 'every same-ELF pair retains full original comparison and independent command counts')
        v=programs[-1]['comparison']
        need(v['operation_status']=='failed'and v['exit_status']==125 and v['actual_syscalls']==1 and
             v['frame_commits']==0 and v['command_completed']==[0,0],
             'supplied result refusal remains failed despite an actual raw ENOTTY')
        need(receipt.get('rseq_tcgets_btrfs_fixture',{}).get('status')=='passed'and summary(receipt)['full_finite_profile'],
             'complete original macro-off20pairs/16controls remains mandatory before new qualification')
    good_pairs=[p for p in programs if p.get('status')=='passed'and not p['injected']]
    control=[p for p in programs if p.get('status')=='passed'and p['injected']]
    counts=[sum(c['comparison']['command_completed'][i]for c in accepted if c['lane']=='gated')for i in range(2)]
    return dict(status=state.get('status'),planned_native_gated_pairs=17,planned_supplied_controls=1,
        attempted_processes=len(cases),actual_processes=sum(actual(c)is not None for c in cases),
        closed_processes=sum(closed(actual(c))for c in cases),accepted_processes=len(accepted),
        zero_exit_processes=sum(c['expected_exit']==0 for c in accepted),required_exit125_processes=sum(c['expected_exit']==125 for c in accepted),
        accepted_case_pairs=len(good_pairs),accepted_supplied_controls=len(control),
        full_frame_pairs=sum(p['comparison']['full_frame_pairs']for p in good_pairs),
        actual_observed_syscalls=sum(c['comparison']['actual_syscalls']for c in accepted),
        committed_gated_frames=sum(c['comparison'].get('frame_commits',0)for c in accepted),
        native_before_operation_prefixes=sum(c['comparison'].get('before_operation_prefix',0)for c in accepted),
        tcgets_result_validations=counts[0],tiocgwinsz_result_validations=counts[1],
        full_finite_profile=complete,full_b2_complete=False,full_b3_complete=False,application_completion=False,performance_credit=False)
