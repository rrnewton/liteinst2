"""Seventeen finite lease subjects after every unchanged registered/gate cohort.
No supplied frame supplies a native reference; no performance claim.
"""
import hashlib,importlib.util,json,os,shlex,shutil
from pathlib import Path
from page_selected import fact,need,elf
from page_selected_oneshot_build import commands,UNITS,MACROS
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
BOUNDS={'tf_same_page':[5,512<<20,16<<20,15],
        'tf_same_page_build':[30,512<<20,16<<20,60]}
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',PYTHONDONTWRITEBYTECODE='1')
GATED=(0,0,0,0,0,125,125,125,125,125)
NATIVE=(0,0,0,0,0)
H=lambda b:hashlib.sha256(b).hexdigest()


def qualify(builder,products,root,private,library_root,pin,binary,aliases,run,receipt):
    root,private=Path(root),Path(private);selected=root/'tools/page-entry/selected';fixture=selected/'tests/tf_same_page'
    output=private/'tf-same-page';output.mkdir();cpu=next(iter(os.sched_getaffinity(0)))
    state=receipt['tf_same_page_fixture']=dict(status='failed',cases=[],programs=[],builds=[],generated={},archive=fact(products['archive']))
    for key,value in BOUNDS.items():need(receipt['bounds'].get(key)==value,'exact registered-native bound '+key)
    need(os.sched_getaffinity(0)=={cpu},'one reserved CPU for all actual boundary subjects')
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    prepare=load('tf_same_page_prepare',fixture/'prepare.py');check=load('tf_same_page_check',fixture/'check.py')
    reports=load('tf_same_page_reports',fixture/'reports.py')
    images=load('tf_same_page_interpreter',selected/'tests/provider_launch/interpreter.py')
    namespace=load('tf_same_page_namespace',root/'tools/page-entry/namespace.py')
    policy=load('tf_same_page_policy',selected/'tests/oneshot_integrated/check.py')
    corpus=json.loads(pin(fixture/'CASES.json').read_bytes())
    need(corpus['schema']==1 and corpus['subjects']==17 and [c['index']for c in corpus['cases']]==list(range(10)) and
         tuple(c['exit']for c in corpus['cases'])==GATED==check.EXIT and
         tuple(c['generic_instructions']for c in corpus['cases'])==check.GENERIC and
         tuple(c['transfers']for c in corpus['cases'])==check.TRANSFERS,
         'fixed five pairs, two reference lanes and five required failed operations')
    for name in ('fixture.S','native_reference.c','record.h','linker.ld','build.sh','layout.py','observe.inc'):pin(fixture/name)
    observed=output/'observed'
    try:state['adapters']=prepare.prepare(root,observed,pin)
    finally:
        for name in (*prepare.FILES,'tf_lease_observe.inc','tf_lease_record.h','tf_lease_old_record.h','tf_lease_types.h'):
            state['generated'][name]=retain('partial observation '+name,observed/name)
    tools={n:pin(shutil.which(n,path=ENV['PATH']))for n in ('gdb','objdump')}
    state['tools']={n:dict(path=str(p),**fact(p))for n,p in tools.items()}
    cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    for name,path in tools.items():
        _,out,err=run('tf-same-page-'+name+'-version',[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual inspection tool identity '+name)
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
    recipe_path=pin(selected/'build-tf-same-page-lease.sh');argv=commands(recipe_path,builder,output,products['archive'],pin)[0]
    units=[str(selected.parent/p)for p in UNITS[:-1]]
    macros=(MACROS-{'-DLI2_ONESHOT_PUBLICATION=1'})|{'-DLI2_CPUID_NX_ONLY=1','-DLI2_RSEQ_NATIVE=1','-DLI2_RSEQ_NATIVE_BOUNDARY=1','-DLI2_RSEQ_TCGETS_BTRFS=1','-DLI2_RSEQ_TIOCGWINSZ_BTRFS=1','-DLI2_TF_SAME_PAGE_LEASE=1'}
    need(argv[-2:]==['-o',str(output/'bridge-tf-same-page-lease.so')] and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         set(x for x in argv if x.startswith('-DLI2_'))==macros and
         sum(x.startswith('-DLI2_')for x in argv)==len(macros)==13 and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact fifteen-unit boundary production recipe without one-shot')
    bridges={}
    for kind in('unobserved','observed','reference'):
        name='tf-same-page-'+kind;actual=argv.copy();sources=units.copy();bridge=output/(kind+'.so');actual[-1]=str(bridge)
        if kind!='unobserved':
            for basename in('runtime_loader.c','lifecycle_loader.c'):
                old,new=str(selected/basename),str(observed/basename)
                need(actual.count(old)==1,'one exact observation translation-unit replacement')
                actual=[new if x==old else x for x in actual];sources=[new if x==old else x for x in sources]
        if kind=='reference':
            need(actual.count('-DLI2_TF_SAME_PAGE_LEASE=1')==1,'one explicit lease macro removed for old reference')
            actual.remove('-DLI2_TF_SAME_PAGE_LEASE=1')
        row=dict(name=name,recipe=fact(recipe_path),argv=actual,archive=fact(products['archive']),translation_units=len(sources));state['builds'].append(row)
        headers(name+'-headers',actual,sources,products['archive'],builder,pin,aliases,run,row)
        if kind!='unobserved':
            expected=set(prepare.FILES)-({'fetch_rx_transfer.inc'}if kind=='reference'else set())
            expected|={'tf_lease_observe.inc','tf_lease_record.h','tf_lease_old_record.h','tf_lease_types.h'}
            need({str(observed/n)for n in expected}<=set(row['headers']),
                 'all actual finite observer includes, including the copied controller and lifecycle chains')
        try:run(name+'-link',actual,profile='tf_same_page_build',env=builder.environment)
        finally:row['artifact']=retain(name,bridge)
        row['inspection']=inspect(name,bridge,'lso_record'if kind!='unobserved'else None,True)
        bridges[kind]=(bridge,row['inspection'].get('layout'))
    interpreter=output/'interpreter'/'li2-provider-entry.so';metadata=output/'interpreter'/'metadata.S'
    try:need(images.emit(output/'interpreter')==(interpreter,metadata),'unchanged actual interpreter emitter paths')
    finally:
        for path in(interpreter,metadata):state['generated'][path.name]=retain('partial actual interpreter',path)
    for path in(interpreter,metadata):pin(binary(path))
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(selected/'tests/rseq_native/launch.py')
    def execute(case,original,image,native_layout,lane):
        native=lane=='native';gated_bridge,gated_layout=bridges['observed'if lane=='gated'else 'reference'if lane=='reference'else'unobserved'];name='tf-same-page-'+str(case)+'-'+lane;directory=output/name;directory.mkdir()
        row=dict(name=name,index=case,lane=lane,status='failed',operation_status='unobserved',expected_exit=(NATIVE if native else GATED)[case],error=None)
        state['cases'].append(row)
        objects,description=namespace.plan(original,[interpreter.parent],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
        row['namespace_plan']=description;row['dependencies']=[]
        for item in objects:
            need(fact(pin(item['path']))['sha256']==H(item['bytes']),'complete actual namespace dependency source')
            row['dependencies'].append(dict(names=item['names'],**fact(pin(item['path']))))
            for alias in item['names']:pin(interpreter.parent/alias)
        prep=directory/'preparation.json';ns=directory/'namespace';carrier=directory/'carrier'
        argv=[builder.tools['python'],launch_tool,'--mode','native'if native else'gated','--original',original,'--library-root',interpreter.parent,
            '--preparation',prep,'--record-fd','{record_fd}']
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
            command,out,err=run(name,argv,profile='tf_same_page',expected=None,env=ENV,record=True)
        except BaseException as exc:
            row['error']=type(exc).__name__+': '+str(exc)
            actual=[c for c in receipt['commands']if c['name']==name]
            if actual:row.update({k:actual[-1][k]for k in('exit','pid','captures')if k in actual[-1]})
            raise
        finally:
            for path in(prep,private/(name+'.record'),ns/'namespace.json',ns/'launch.json'):retain('partial subject '+name+' '+path.name,path)
        row.update(exit=command['exit'],pid=command['pid'],captures=command['captures'])
        need(type(command['exit'])is int and command['exit']==row['expected_exit']and type(command['pid'])is int and command['pid']>0 and
             command['reaped']is True and not command['timed_out']and not command['error']and not command['cleanup_errors']and
             command['descriptors']==[dict(name='record',fd=3,closed=True)],'actual exact subject outcome and closed FD3')
        record_path=pin(binary(private/(name+'.record')));record=record_path.read_bytes()
        actual=json.loads(pin(binary(prep)).read_bytes());row['preparation']=actual
        app_argv=[str(original)]+(['native']if native else[])
        need(actual['mode']==('native'if native else'gated') and actual['mask']==0 and actual['affinity']==[cpu]and
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
                    receipt.setdefault('tf_same_page_namespace_aliases',{})[str(path)]=value
            env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
            env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(str(a['fd'])for a in sealed['objects']))
            need(started['argv']==app_argv and started['environment']==env and started['carrier_sha256']==fact(carrier)['sha256'],
                 'actual registered native profile, no disable-rseq or configured policy')
            if command['exit']in(0,125):
                parsed=reports.reports(err,lease=lane!='reference');row['reports']=parsed
                need(parsed['loader']['status']==command['exit'],'actual report and process outcome agree')
                cpuid=parsed['cpuid_nx']
                need(cpuid['attempts']==cpuid['samples']==cpuid['commits']==parsed['loader']['cpuid']>0 and cpuid['raw']==cpuid['result']and
                     cpuid['phase']==3 and cpuid['hardware_entered']==cpuid['hardware_returned']==1,'genuine raw first-interpreter CPUID completed before the finite case')
                if command['exit']==0:
                    reports.completed(parsed,command['pid'])
                    need(parsed['rseq_native']['admissions']>0 and parsed['rseq_boundary']['counts']==[0]*6,
                         'actual registered epochs and no invented native-boundary retry')
            else:need(not err,'no fabricated runtime completion report')
            stdout_path=pin(binary(private/(name+'.stdout')))
            launch=parsed['tcgets']['launch'];stat=stdout_path.stat()
            need(launch[:2]==[stat.st_dev,stat.st_ino]and launch[5]&0o170000==0o100000,
                 'actual parent-created stdout identity joins production initialization')
            if lane=='production':
                need(record==b'' and command['exit']==0 and case==0,'unobserved production keeps fd3 empty')
                row['comparison']=dict(case=case,events=0,transfers=0,output=check.output(out,image,False),observed_cpus=[cpu])
            else:
                row['comparison']=check.gated(record,gated_layout,image,command['pid'],command['exit'],lease=lane!='reference')
                reports.join(parsed,check.Reader(record,gated_layout,'lso_record'),record)
        else:
            need(not err,'actual native fixture stderr is empty')
            row['comparison']=check.native(record,native_layout,image,command['pid'],command['exit'])
        need(all(x==cpu for x in row['comparison']['observed_cpus']),'actual case CPU joins independent reserved affinity')
        if case in(8,9):need(row['comparison']['nested_sender_uid']==os.getuid(),'actual kernel self-tgkill sender joins invoking UID')
        if command['exit']!=0:need(out==b'','failed finite effect has no completed output')
        row['operation_status']='completed'if command['exit']==0 else'failed'
        row['status']='passed'
        return row,out,record
    fixture_recipe=pin(fixture/'build.sh');templates=recipe(fixture_recipe,'"$cc_bin"');need(len(templates)==1,'one source-bound actual fixture link recipe')
    for case in range(10):
        name='tf-same-page-program-'+str(case);directory=output/name;directory.mkdir();original=directory/'original'
        values={'$cc_bin':builder.tools['cc'],'$fixture_dir':fixture,'$metadata':metadata,'$output':original,'$case_number':case}
        argv=expand(templates[0],values);units=[str(fixture/'fixture.S'),str(fixture/'native_reference.c'),str(metadata)]
        need([x for x in argv if x.endswith(('.c','.S'))]==units and argv[-2:]==['-o',str(original)]and
             argv.count('-DRN_CASE='+str(case))==1 and all(x in argv for x in('-O2','-g','-Werror','-nostdlib','-no-pie','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-mcmodel=large')),
             'actual original fixture recipe and exact literal case')
        row=dict(index=case,recipe=fact(fixture_recipe),argv=argv,status='failed');state['programs'].append(row)
        flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
        _,out,err=run(name+'-headers',[builder.tools['cc'],*flags,'-M','-MT','tf_same_page',*units],env=builder.environment)
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(rules)==3 and all(x.startswith('tf_same_page: ')for x in rules),'actual complete three-TU native fixture include closure')
        row['headers']={str(pin(t)):fact(pin(t))for line in rules for t in shlex.split(line.split(':',1)[1])}
        need(set(units)<=set(row['headers']),'all linked fixture sources in actual include closure')
        try:run(name+'-link',argv,profile='tf_same_page_build',env=builder.environment)
        finally:row['artifact']=retain('partial actual native fixture '+name,original)
        pin(binary(original));row['inspection']=inspect(name,original,'lso_native_record')
        image=check.elf(original.read_bytes(),interpreter,case,policy.native_policy);row['image']=image;row['status']='built'
        if case<5:
            native,nout,nrecord=execute(case,original,image,row['inspection']['layout'],'native')
            gated,gout,grecord=execute(case,original,image,row['inspection']['layout'],'gated')
            row['comparison']=check.pair(nrecord,grecord,nout,gout,{'native':row['inspection']['layout'],'gated':bridges['observed'][1]},image,native['pid'],gated['pid'],cpu)
            need(row['comparison']['successful_pair']==1,'one complete same-original native/lease pair')
            if case==0:
                reference,rout,rrecord=execute(case,original,image,row['inspection']['layout'],'reference')
                row['reference']=check.pair(nrecord,rrecord,nout,rout,{'native':row['inspection']['layout'],'gated':bridges['reference'][1]},image,native['pid'],reference['pid'],cpu,lease=False)
                production,pout,precord=execute(case,original,image,row['inspection']['layout'],'production')
                need(gout==pout and production['reports']['lease']==gated['reports']['lease'],
                     'actual unobserved production full output and complete transfer accounting equal observed lane')
                for key in('generic_tf_attempts','generic_tf_steps','source_syscalls','cpuid','rdtsc','selected_steps'):
                    need(production['reports']['loader'][key]==gated['reports']['loader'][key],'actual production effect/owner counts '+key)
        else:
            gated,gout,grecord=execute(case,original,image,row['inspection']['layout'],'gated')
            need(gated['operation_status']=='failed'and gated['exit']==125,'expected refusal remains a failed operation')
            row['comparison']=gated['comparison']
        row['status']='passed'
    need(len(state['cases'])==17 and all(c['status']=='passed'for c in state['cases'])and
         len(state['programs'])==10 and all(c['status']=='passed'for c in state['programs']),
         'all seventeen real subjects including five required failed operations')
    finalize(receipt);state['status']='passed'


def finalize(receipt):
    need(all(Path(p).is_symlink()and os.readlink(p)==value for p,value in receipt.get('tf_same_page_namespace_aliases',{}).items()),
         'all actual sealed namespace alias observations remain unchanged')


def summary(receipt):
    state=receipt.get('tf_same_page_fixture',{});cases=state.get('cases',[]);commands=receipt.get('commands',[])
    def actual(c):
        rows=[x for x in commands if x.get('name')==c['name']and x.get('profile')=='tf_same_page']
        return rows[0]if len(rows)==1 and type(rows[0].get('pid'))is int and rows[0]['pid']>0 else None
    def closed(v):return v is not None and v.get('reaped')is True and type(v.get('exit'))is int
    accepted=[c for c in cases if c.get('status')=='passed'and closed(actual(c))and actual(c)['exit']==c['expected_exit']and not actual(c).get('timed_out')and not actual(c).get('error')and not actual(c).get('cleanup_errors')]
    plan=[(0,x)for x in('native','gated','reference','production')]+[(i,l)for i in range(1,5)for l in('native','gated')]+[(i,'gated')for i in range(5,10)]
    complete=state.get('status')=='passed'and len(accepted)==17 and [(c['index'],c['lane'])for c in cases]==plan
    if state.get('status')=='passed':
        need(complete and len(state['programs'])==10 and all(p['status']=='passed'for p in state['programs'])and
             sum(c['expected_exit']==125 for c in accepted)==5 and all(c['exit']==actual(c)['exit']and c['pid']==actual(c)['pid']for c in accepted),
             'complete fixed seventeen-subject qualification and truthful actual-process joins')
    return dict(status=state.get('status'),planned_subjects=17,attempted_subjects=len(cases),actual_subjects=sum(actual(c)is not None for c in cases),
        closed_subjects=sum(closed(actual(c))for c in cases),accepted_subjects=len(accepted),successful_operations=sum(c['expected_exit']==0 for c in accepted),
        required_failed_operations=sum(c['expected_exit']!=0 for c in accepted),accepted_pairs=sum(p.get('comparison',{}).get('successful_pair',0)for p in state.get('programs',[])),
        actual_program_transfers=sum(c.get('comparison',{}).get('transfers',0)for c in accepted),full_finite_profile=complete,
        full_b2_complete=False,full_b3_complete=False,application_completion=False,performance_credit=False)
