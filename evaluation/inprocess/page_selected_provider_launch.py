"""Four genuine carrier entries with the explicit configured provider policy.

Callable from the committed configured-provider evaluator. It shares that
evaluator's exact revision/source, current archive, tools, supervised invocation,
artifact and finalization custody. No component record is substituted here.
"""
import hashlib,importlib.util,json,os,shlex,shutil
from pathlib import Path
from page_selected import fact,need,elf
import page_selected_oneshot_build as old_build
from page_selected_register_time_build import headers,bridge_check
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset

BOUNDS={'provider_launch':[30,512<<20,16<<20,60],
        'provider_launch_build':[30,512<<20,16<<20,60]}
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',
         GLIBC_TUNABLES='glibc.pthread.rseq=0',PYTHONDONTWRITEBYTECODE='1')
H=lambda b:hashlib.sha256(b).hexdigest()

def launch(builder,products,root,private,pin,binary,aliases,run,receipt):
    root,private=Path(root),Path(private)
    selected=root/'tools/page-entry/selected';fixture=selected/'tests/provider_launch'
    output=private/'provider-launch';output.mkdir()
    state=receipt['provider_launch']=dict(status='failed',cases=[],units=[],generated={},archive=fact(products['archive']))
    for name,bounds in BOUNDS.items():need(receipt['bounds'].get(name)==bounds,'unchanged launch bounds '+name)
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    def local_headers(label,flags,sources,row):
        _,out,err=run(label,[builder.tools['cc'],*flags,'-M','-MT','provider_launch',*sources],env=builder.environment)
        need(not err,'actual fixture conditional include stderr')
        rules=out.decode().replace('\\\n',' ').splitlines();row['headers']={}
        need(len(rules)==len(sources) and all(x.startswith('provider_launch: ')for x in rules),'complete actual compiler-M rows')
        for line in rules:
            for token in shlex.split(line.split(':',1)[1]):
                p=pin(Path(token).absolute());row['headers'][str(p)]=fact(p)
        need(set(map(str,sources))<=set(row['headers']),'each actual source bound through compiler-M')
    prepare=load('provider_launch_prepare',fixture/'prepare.py')
    check=load('provider_launch_check',fixture/'check.py')
    reports=load('provider_launch_reports',fixture/'reports.py')
    images=load('provider_launch_interpreter',fixture/'interpreter.py')
    oldcheck=load('provider_launch_old_native_policy',selected/'tests/oneshot_integrated/check.py')
    namespace=load('provider_launch_namespace',root/'tools/page-entry/namespace.py')
    for name in ('fixture.S','linker.ld','layout.py','launch.py','observe.inc','REPORT-ADAPTERS.json'):pin(fixture/name)
    # Keep the old completion parser's entire body after reversing only the
    # explicit 32-native-entry/count/schema successor. No old gate is dropped.
    old_report=pin(selected/'tests/oneshot_integrated/reports.py').read_text()
    new_report=(fixture/'reports.py').read_text();start=new_report.index("\n    need(type(variant)is int")
    inverse=new_report[:start]
    for op in reversed(json.loads((fixture/'REPORT-ADAPTERS.json').read_bytes())):
        need(inverse.count(op['after'])==1,'unique inherited report predicate inverse')
        inverse=inverse.replace(op['after'],op['before'])
    need(inverse==old_report,'all inherited general/one-shot completion assertions retained')
    observed=output/'observed'
    try:state['observer_adapters']=prepare.prepare(root,observed,pin)
    finally:
        for name in ('runtime_loader.c','selected_controller.inc','provider_launch_observe.inc'):
            state['generated'][name]=retain('partial observer source '+name,observed/name)
    recipe=pin(selected/'build-provider-configured.sh')
    commands=old_build.commands(recipe,builder,output,products['archive'],pin)
    argv=commands[0];macros=old_build.MACROS|{'-DLI2_SELECTED_PROVIDER=1'}
    sources=[str(selected.parent/x)for x in old_build.UNITS]
    need([x for x in argv if x.endswith(('.c','.S'))]==sources and argv[-2:]==['-o',str(output/'bridge-provider-configured.so')] and
         set(x for x in argv if x.startswith('-DLI2_'))==macros and sum(x.startswith('-DLI2_')for x in argv)==len(macros) and
         all(x in argv for x in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact configured 16-TU release recipe, no runtime predicate adapter')
    state['unobserved_argv']=argv.copy();state['recipe']=fact(recipe)
    original=str(selected/'runtime_loader.c');replacement=str(observed/'runtime_loader.c')
    need(argv.count(original)==1,'one actual runtime observation adapter')
    argv=[replacement if x==original else x for x in argv];sources=[replacement if x==original else x for x in sources]
    bridge=output/'bridge-provider-observed.so';argv[-1]=str(bridge)
    unit=dict(argv=argv,translation_units=16,archive=fact(products['archive']));state['bridge_build']=unit
    headers('provider-launch-headers',argv,sources,products['archive'],builder,pin,aliases,run,unit)
    _,out,err=run('provider-launch-archive-exports',[builder.tools['nm'],'-g','--defined-only',products['archive']],profile='inspect',env=builder.environment)
    need(not err,'actual current archive exports')
    for name in old_build.EXPORTS:
        rows=[x.split()for x in out.splitlines()if x.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()],'actual current publisher '+name)
    try:run('provider-launch-bridge-link',argv,profile='provider_launch_build',env=builder.environment)
    finally:unit['artifact']=retain('partial configured observed bridge',bridge)
    binary(bridge);state['bridge']=dict(path=str(bridge),**fact(bridge));state['bridge_elf']=bridge_check(bridge)
    tools={}
    for name in ('objdump','gdb'):
        tools[name]=pin(shutil.which(name,path=ENV['PATH']))
    cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    for name,path in tools.items():
        _,out,err=run('provider-launch-version-'+name,[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual strict tool version '+name)
    state['tools']={n:dict(path=str(p),**fact(p))for n,p in tools.items()}
    _,symbols,err=run('provider-launch-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual observed bridge symbol metadata')
    _,assembly,err=run('provider-launch-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual fast reset body');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    _,out,err=run('provider-launch-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(not out and not err,'no configured bridge unresolved imports')
    _,out,err=run('provider-launch-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
        '--readnow','--se='+str(bridge),'-x',fixture/'layout.py'],env=gdb_env)
    need(not err,'actual file-only DWARF stderr');layout=json.loads(out);state['layout']=layout
    rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[b'pl_record']]
    _,_,segments=elf(bridge)
    need(len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b' and int(rows[0][1],16)==layout['types']['pl_record']['bytes']<16<<20 and
         sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+int(rows[0][1],16)<=p[3]+p[6]for p in segments)==1,
         'actual complete record symbol extent in writable NX bridge load')
    interpreter=output/'interpreter'/'li2-provider-entry.so';metadata=output/'interpreter'/'metadata.S'
    try:
        actual_interpreter,actual_metadata=images.emit(output/'interpreter')
        need((actual_interpreter,actual_metadata)==(interpreter,metadata),'exact generated interpreter and metadata paths')
    finally:
        for p in (interpreter,metadata):state['generated'][p.name]=retain('partial interpreter source '+p.name,p)
    for p in (interpreter,metadata):binary(p);pin(p)
    state['interpreter']=dict(path=str(interpreter),**fact(interpreter))
    state['generated']['metadata.S']=fact(metadata)
    need(','not in str(interpreter),'literal linker interpreter argument')
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(fixture/'launch.py')
    for variant in (1,2,3,4):
        name='provider-launch-'+str(variant);directory=output/str(variant);directory.mkdir()
        original=directory/'original';unit=dict(variant=variant,status='failed');state['units'].append(unit)
        flags=['-nostdlib','-no-pie','-O2','-g','-Wall','-Wextra','-Werror','-DENTRY_KIND='+str(variant)]
        local_headers(name+'-headers',flags,[fixture/'fixture.S',metadata],unit)
        argv=[builder.tools['cc'],*flags,
              '-Wl,-T,'+str(fixture/'linker.ld')+',-z,max-page-size=4096,--build-id=none,--no-undefined',
              fixture/'fixture.S',metadata,'-o',original]
        unit['argv']=list(map(str,argv))
        try:run(name+'-link',argv,profile='provider_launch_build',env=builder.environment)
        finally:unit['artifact']=retain('partial original '+name,original)
        binary(original);pin(original)
        _,undef,err=run(name+'-undefined',[builder.tools['nm'],'-u',original],profile='inspect',env=builder.environment)
        need(not undef and not err,'actual main has no dynamic symbol imports')
        image=check.elf(original.read_bytes(),interpreter,variant,oldcheck.native_policy);unit['image']=image
        for suffix,args in (('symbols',[builder.tools['nm'],'-S','-n',original]),('assembly',[tools['objdump'],'-d','-w','-M','att',original])):
            _,out,err=run(name+'-'+suffix,args,profile='inspect',env=builder.environment);need(out and not err,'actual fixture '+suffix)
        carrier=directory/'carrier'
        try:
            _,out,err=run(name+'-make',[builder.tools['python'],carrier_tool,'make',original,bridge,carrier],env=ENV)
            need(not err,'actual carrier creation stderr')
        finally:unit['carrier']=retain('partial carrier '+name,carrier)
        binary(carrier);identities=json.loads(out)
        need(identities['original_sha256']==fact(original)['sha256']and identities['interpreter_sha256']==fact(interpreter)['sha256']and
             identities['bridge_sha256']==fact(bridge)['sha256']and identities['carrier_sha256']==fact(carrier)['sha256'],'actual carrier original/interpreter/bridge identities')
        objects,description=namespace.plan(original,[interpreter.parent],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
        need(len(objects)==1 and objects[0]['bytes']==interpreter.read_bytes() and objects[0]['names']==[interpreter.name],
             'sole actual custom interpreter dependency; no libc or hidden loader behavior')
        for item in objects:
            need(fact(pin(item['path']))['sha256']==H(item['bytes']),'actual dependency source custody')
            for alias in item['names']:need(pin(interpreter.parent/alias)==interpreter,'exact lexical dependency alias')
        unit['namespace_plan']=description;unit['status']='built';outcomes={};ns=directory/'namespace'
        for mode in ('native','gated'):
            case=dict(name=name+'-'+mode,variant=variant,mode=mode,status='failed',error=None);state['cases'].append(case)
            preparation=directory/(mode+'.preparation')
            argv=[builder.tools['python'],launch_tool,'--mode',mode,'--original',original,'--library-root',interpreter.parent,
                  '--preparation',preparation,'--record-fd','{record_fd}']
            if mode=='gated':argv+=['--carrier',carrier,'--namespace',ns]
            try:
                command,out,err=run(case['name'],argv,profile='provider_launch',expected=None,env=ENV,record=True)
            except BaseException as exc:
                case['error']=type(exc).__name__+': '+str(exc)
                actual=[x for x in receipt.get('commands',[])if x['name']==case['name']]
                if actual:case.update({k:actual[-1][k]for k in ('exit','pid','captures')if k in actual[-1]})
                raise
            finally:
                for p in (preparation,private/(case['name']+'.record')):retain('partial launch '+case['name']+' '+p.name,p)
                if mode=='gated':
                    for f in ('namespace.json','launch.json'):retain('partial namespace '+case['name']+' '+f,ns/f)
            case.update(exit=command['exit'],pid=command['pid'],captures=command['captures'])
            binary(preparation);prep=json.loads(preparation.read_bytes());case['preparation']=prep
            path=private/(case['name']+'.record');binary(path)
            need(prep['mask']==0 and [x['signal']for x in prep['dispositions']]==[x for x in range(1,65)if x not in(9,19)] and
                 all(x['after']==0 for x in prep['dispositions'])and prep['argv']==[str(original)]and
                 prep['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'} and
                 prep['observer']==dict(fd=3,device=path.stat().st_dev,inode=path.stat().st_ino),'actual reset/argv/environment and inherited record identity')
            try:
                need(command['exit']==0,'actual successful program exit')
                case['output']=check.output(out)
                if mode=='native':need(not err and not path.read_bytes(),'native custom interpreter baseline, no observer or configured-result claim')
                else:
                    case['reports']=reports.reports(err);reports.completed(case['reports'],command['pid'],variant)
                    case['comparison']=check.check(path.read_bytes(),layout,image)
                    for f in ('namespace.json','launch.json'):binary(ns/f)
                    actual=json.loads((ns/'namespace.json').read_bytes());started=json.loads((ns/'launch.json').read_bytes())
                    need(actual['original_sha256']==fact(original)['sha256']and actual['interpreter_sha256']==fact(interpreter)['sha256']and
                         actual['original']==str(original)and len(actual['objects'])==1,'actual sealed namespace identity')
                    a=actual['objects'][0];item=objects[0]
                    need(a['names']==item['names']and a['sha256']==H(item['bytes'])and a['size']==len(item['bytes'])and
                         a['seals']==namespace.SEALS and a['device']>0 and a['inode']>0,'actual sealed dependency observation')
                    for alias in a['names']:
                        p=ns/alias;need(p.is_symlink()and os.readlink(p)=='/proc/self/fd/'+str(a['fd']),'actual sealed descriptor alias')
                        # Numeric fd symlinks are recorded as immutable link text, never dereferenced in the parent.
                        receipt.setdefault('provider_namespace_aliases',{})[str(p)]=os.readlink(p)
                    target_env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
                    target_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=str(a['fd']),LI2_SELECTED_PROVIDER='mask-random-v1')
                    need(started['argv']==[str(original)]and started['carrier_sha256']==fact(carrier)['sha256']and started['environment']==target_env,
                         'real explicit immutable configured policy in closed launch environment')
                case['status']='passed';outcomes[mode]=out
            except Exception as exc:case['error']=type(exc).__name__+': '+str(exc)
        if set(outcomes)=={'native','gated'}:
            need(outcomes['native'][:26]==outcomes['gated'][:26],'exact stable source bytes and marker; all four clock words retained separately')
    need(len(state['cases'])==8 and all(c['status']=='passed'for c in state['cases']),'all four genuine native/configured pairs')
    finalize(receipt)
    state['status']='passed'
    return bridge

def finalize(receipt):
    """Call again from the enclosing evaluator's finally, before qualification."""
    need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in receipt.get('provider_namespace_aliases',{}).items()),'all actual configured namespace aliases still unchanged')

def summary(receipt):
    s=receipt.get('provider_launch',{})
    return dict(status=s.get('status','unexecuted'),qualified=receipt.get('status')=='passed'and s.get('status')=='passed',
        actual_processes=len(s.get('cases',[])),passed=sum(c['status']=='passed'for c in s.get('cases',[])),
        cases=[{k:c[k]for k in ('name','variant','mode','status','exit')if k in c}|dict(
            comparison=c.get('comparison'),output=c.get('output'),error_type=c['error'].split(':',1)[0]if c.get('error')else None,
            captures={k:{x:v[x]for x in ('bytes','sha256')}for k,v in c.get('captures',{}).items()})for c in s.get('cases',[])],
        archive=s.get('archive'),bridge={k:s.get('bridge',{}).get(k)for k in ('bytes','sha256')},
        full_reports_sha256=H(json.dumps([c.get('reports')for c in s.get('cases',[])],sort_keys=True,separators=(',',':')).encode()),
        native_physical_random_is_not_configured_reference=True,performance_credit=False)
