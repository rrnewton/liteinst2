"""Actual custom-interpreter/main builtin effects and named callback failures.

Shares the enclosing evaluator's current archive, supervised invoke and exact
source/input/tool/artifact custody. Old cohorts remain outside this helper.
"""
import hashlib,importlib.util,json,os,shlex,shutil
from pathlib import Path
from page_selected import fact,need,elf
import page_selected_oneshot_build as old_build
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset

BOUNDS={'provider_builtins':[30,512<<20,16<<20,60],
        'provider_builtins_build':[30,512<<20,16<<20,60]}
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',
         GLIBC_TUNABLES='glibc.pthread.rseq=0',PYTHONDONTWRITEBYTECODE='1')
H=lambda b:hashlib.sha256(b).hexdigest()
NEGATIVES=('clock-status','clock-reserved','clock-wrong-aux','clock-nested',
           'syscall-status','syscall-reserved','native-nonzero-value','replacement-wrong-call',
           'replacement-wrong-tag','invalid-action','syscall-nested','forbidden-native-prctl')


def builtins(builder,products,root,private,pin,binary,aliases,run,receipt):
    root,private=Path(root),Path(private);selected=root/'tools/page-entry/selected'
    fixture=selected/'tests/provider_builtins';output=private/'provider-builtins';output.mkdir()
    state=receipt['provider_builtins']=dict(status='failed',cases=[],units=[],generated={},archive=fact(products['archive']))
    for name,bounds in BOUNDS.items():need(receipt['bounds'].get(name)==bounds,'unchanged builtin bounds '+name)
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    def local_headers(label,flags,sources,row):
        _,out,err=run(label,[builder.tools['cc'],*flags,'-M','-MT','provider_builtins',*sources],env=builder.environment)
        need(not err,'actual fixture conditional include stderr')
        rules=out.decode().replace('\\\n',' ').splitlines();row['headers']={}
        need(len(rules)==len(sources)and all(x.startswith('provider_builtins: ')for x in rules),'complete actual compiler-M rows')
        for line in rules:
            for token in shlex.split(line.split(':',1)[1]):
                p=pin(Path(token).absolute());row['headers'][str(p)]=fact(p)
        need(set(map(str,sources))<=set(row['headers']),'each actual source bound through compiler-M')
    prepare=load('provider_builtin_prepare',fixture/'prepare.py');check=load('provider_builtin_check',fixture/'check.py')
    reports=load('provider_builtin_reports',fixture/'reports.py');images=load('provider_builtin_elf',fixture/'elf.py')
    metadata=load('provider_builtin_metadata',fixture/'metadata.py')
    oldcheck=load('provider_builtin_native_policy',selected/'tests/oneshot_integrated/check.py')
    namespace=load('provider_builtin_namespace',root/'tools/page-entry/namespace.py')
    for name in ('fixture.S','main.ld','interpreter.ld','layout.py','launch.py','observe.inc','callbacks.inc','effects.py','completion.py'):pin(fixture/name)
    plan=json.loads(pin(fixture/'CASES.json').read_bytes())
    need(plan['new_positive_processes']==6 and plan['new_failed_processes']==12 and
         [x['name']for x in plan['negative']]==list(NEGATIVES)and
         all(x['expected_exit']==125 and x['application_committed']==0 and x['application_continued']is False for x in plan['negative'])and
         [x['variant']for x in plan['positive']]==[1,2]and
         all(x['modes']==['native','configured','bridge-native-policy']for x in plan['positive']),
         'exact two three-mode positives and twelve named failed-operation controls')
    observed=output/'observed'
    try:state['observer_adapters']=prepare.prepare(root,observed,pin)
    finally:
        for name in ('runtime_loader.c','selected_provider.inc','selected_controller.inc','selected_oneshot.inc',
                     'provider_builtins_observe.inc','provider_builtins_callbacks.inc'):
            state['generated'][name]=retain('partial builtin observer '+name,observed/name)
    recipe_path=pin(selected/'build-provider-builtins.sh')
    commands=old_build.commands(recipe_path,builder,output,products['archive'],pin)
    need(len(commands)==2,'unchanged two production C recipes')
    argv=commands[0];macros=old_build.MACROS|{'-DLI2_SELECTED_PROVIDER=1','-DLI2_SELECTED_PROVIDER_BUILTINS=1'}
    sources=[str(selected.parent/x)for x in old_build.UNITS]
    need([x for x in argv if x.endswith(('.c','.S'))]==sources and argv[-2:]==['-o',str(output/'bridge-provider-builtins.so')]and
         set(x for x in argv if x.startswith('-DLI2_'))==macros and sum(x.startswith('-DLI2_')for x in argv)==len(macros)and
         all(x in argv for x in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact configured 16-TU release recipe and ten required macros')
    state['unobserved_argv']=argv.copy();state['recipe']=fact(recipe_path)
    original=str(selected/'runtime_loader.c');replacement=str(observed/'runtime_loader.c')
    need(argv.count(original)==1,'one actual runtime observation adapter')
    argv=[replacement if x==original else x for x in argv];sources=[replacement if x==original else x for x in sources]
    bridge=output/'bridge-provider-builtins-observed.so';argv[-1]=str(bridge)
    unit=dict(argv=argv,translation_units=16,archive=fact(products['archive']));state['bridge_build']=unit
    headers('provider-builtins-headers',argv,sources,products['archive'],builder,pin,aliases,run,unit)
    need(all(str(observed/name)in unit['headers']for name in state['generated'])and
         all(str(selected/name)in unit['headers']for name in ('provider_builtin_policy.h','selected_provider_builtins.inc','provider_callback.h')),
         'actual active observation and builtin policy includes')
    _,out,err=run('provider-builtins-archive-exports',[builder.tools['nm'],'-g','--defined-only',products['archive']],profile='inspect',env=builder.environment)
    need(not err,'actual current archive exports')
    for name in old_build.EXPORTS:
        rows=[x.split()for x in out.splitlines()if x.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()],'actual current publisher '+name)
    try:run('provider-builtins-bridge-link',argv,profile='provider_builtins_build',env=builder.environment)
    finally:unit['artifact']=retain('partial builtin observed bridge',bridge)
    binary(bridge);state['bridge']=dict(path=str(bridge),**fact(bridge));state['bridge_elf']=bridge_check(bridge)
    tools={name:pin(shutil.which(name,path=ENV['PATH']))for name in ('objdump','gdb')}
    cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    for name,path in tools.items():
        _,out,err=run('provider-builtins-version-'+name,[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual strict tool version '+name)
    state['tools']={n:dict(path=str(p),**fact(p))for n,p in tools.items()}
    _,symbols,err=run('provider-builtins-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual observed bridge symbol metadata')
    _,assembly,err=run('provider-builtins-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual fast reset body');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    state['callback_symbols']=images.callback_symbols(bridge.read_bytes())
    _,out,err=run('provider-builtins-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(not out and not err,'no builtin bridge unresolved imports')
    _,out,err=run('provider-builtins-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
        '--readnow','--se='+str(bridge),'-x',fixture/'layout.py'],env=gdb_env)
    need(not err,'actual file-only DWARF stderr');layout=json.loads(out);state['layout']=layout
    rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[b'pb_record']];_,_,segments=elf(bridge)
    need(len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b'and int(rows[0][1],16)==layout['types']['pb_record']['bytes']<16<<20 and
         sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+int(rows[0][1],16)<=p[3]+p[6]for p in segments)==1,
         'actual complete record symbol extent in writable NX bridge load')
    build_recipe=pin(fixture/'build.sh');templates=recipe(build_recipe,'"$cc_bin"')
    need(len(templates)==2,'exact two real linked fixture images');state['fixture_recipe']=fact(build_recipe)
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(fixture/'launch.py')
    for variant,negative in [(1,0),(2,0)]+[(1,n)for n in range(1,13)]:
        name='provider-builtins-'+str(variant)+'-'+str(negative);directory=output/(str(variant)+'-'+str(negative));directory.mkdir()
        original=directory/'original';interpreter=directory/'li2-provider-builtins-entry.so';meta=directory/'metadata.S'
        unit=dict(variant=variant,negative=negative,status='failed',builds=[]);state['units'].append(unit)
        try:
            actual=metadata.emit(directory);need(actual==(interpreter,meta),'exact literal metadata paths')
        finally:unit['metadata']=retain('partial literal interpreter metadata '+name,meta)
        binary(meta);pin(meta)
        values={'$cc_bin':builder.tools['cc'],'$fixture_dir':fixture,'$variant':variant,'$negative':negative,'$metadata':meta,'$output':directory}
        expanded=[expand(t,values)for t in templates]
        for role,path,source_list,command in zip((1,2),(interpreter,original),([fixture/'fixture.S'],[fixture/'fixture.S',meta]),expanded):
            flags=['-nostdlib']+(['-shared','-fPIC']if role==1 else['-no-pie'])+['-g','-Wall','-Wextra','-Werror','-DENTRY_KIND='+str(variant),'-DPB_NEGATIVE='+str(negative),'-DIMAGE_ROLE='+str(role)]
            linker=fixture/('interpreter.ld'if role==1 else'main.ld')
            expected=[str(builder.tools['cc']),*flags,'-Wl,-T,'+str(linker)+(',-Bsymbolic'if role==1 else'')+',-z,max-page-size=4096,--build-id=none,--no-undefined',*map(str,source_list),'-o',str(path)]
            need(command==expected,'complete actual fixture recipe expansion')
            part=dict(role=role,argv=command,status='failed');unit['builds'].append(part);label=name+'-'+str(role)
            local_headers(label+'-headers',flags,source_list,part)
            try:run(label+'-link',command,profile='provider_builtins_build',env=builder.environment)
            finally:part['artifact']=retain('partial fixture '+label,path)
            binary(path);pin(path)
            _,out,err=run(label+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
            need(not out and not err,'actual fixture has no unresolved imports')
            for suffix,args in (('symbols',[builder.tools['nm'],'-S','-n',path]),('assembly',[tools['objdump'],'-d','-w','-M','att',path])):
                _,out,err=run(label+'-'+suffix,args,profile='inspect',env=builder.environment);need(out and not err,'actual fixture '+suffix)
            part['status']='built'
        image=dict(variant=variant,negative=negative,callback_symbols=state['callback_symbols'])
        for role,path in (('main',original),('interpreter',interpreter)):
            image[role]=images.inspect(path.read_bytes(),role,variant,negative,interpreter,oldcheck.native_policy,namespace.parse)
        unit['image']=image;carrier=directory/'carrier'
        try:
            _,out,err=run(name+'-make',[builder.tools['python'],carrier_tool,'make',original,bridge,carrier],env=ENV)
            need(not err,'actual carrier creation stderr')
        finally:unit['carrier']=retain('partial carrier '+name,carrier)
        binary(carrier);identities=json.loads(out)
        need(identities['original_sha256']==fact(original)['sha256']and identities['interpreter_sha256']==fact(interpreter)['sha256']and
             identities['bridge_sha256']==fact(bridge)['sha256']and identities['carrier_sha256']==fact(carrier)['sha256'],
             'actual carrier original/interpreter/bridge identities')
        objects,description=namespace.plan(original,[directory],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
        need(len(objects)==1 and objects[0]['bytes']==interpreter.read_bytes()and objects[0]['names']==[interpreter.name],
             'sole actual custom interpreter dependency; no libc or hidden loader behavior')
        for item in objects:
            need(fact(pin(item['path']))['sha256']==H(item['bytes']),'actual dependency custody')
            for alias in item['names']:need(pin(directory/alias)==interpreter,'exact lexical dependency alias')
        unit['namespace_plan']=description;unit['status']='built';outcomes={}
        for mode in (('configured',)if negative else('native','configured','bridge-native-policy')):
            case=dict(name=name+'-'+mode,variant=variant,negative=negative,mode=mode,status='failed',error=None,
                      expected_operation='failed'if negative else'completed');state['cases'].append(case)
            preparation=directory/(mode+'.preparation');ns=directory/(mode+'-namespace')
            argv=[builder.tools['python'],launch_tool,'--mode',mode,'--original',original,'--library-root',directory,
                  '--preparation',preparation,'--record-fd','{record_fd}']
            if mode!='native':argv+=['--carrier',carrier,'--namespace',ns]
            case['invocation_attempted']=True
            try:command,out,err=run(case['name'],argv,profile='provider_builtins',expected=None,env=ENV,record=True)
            except BaseException as exc:
                case['error']=type(exc).__name__+': '+str(exc)
                actual=[x for x in receipt.get('commands',[])if x['name']==case['name']]
                if actual:case.update({k:actual[-1][k]for k in ('exit','pid','captures')if k in actual[-1]})
                raise
            finally:
                for p in (preparation,private/(case['name']+'.record')):retain('partial program '+case['name']+' '+p.name,p)
                if mode!='native':
                    for f in ('namespace.json','launch.json'):retain('partial namespace '+case['name']+' '+f,ns/f)
                    for alias in objects[0]['names']:
                        p=ns/alias
                        try:
                            if p.is_symlink():
                                value=os.readlink(p);saved=receipt.setdefault('provider_builtins_namespace_aliases',{})
                                need(str(p)not in saved or saved[str(p)]==value,'partial namespace alias changed')
                                saved[str(p)]=value
                            else:need(not os.path.lexists(p),'partial namespace alias is not a symlink')
                        except BaseException as exc:
                            receipt['final_errors'].append('partial namespace alias '+str(p)+': '+type(exc).__name__+': '+str(exc))
            case.update(exit=command['exit'],pid=command['pid'],captures=command['captures'])
            try:
                binary(preparation);prep=json.loads(preparation.read_bytes());case['preparation']=prep
                path=private/(case['name']+'.record');binary(path)
                need(prep['mask']==0 and [x['signal']for x in prep['dispositions']]==[x for x in range(1,65)if x not in(9,19)]and
                     all(x['after']==0 for x in prep['dispositions'])and prep['argv']==[str(original)]and
                     prep['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
                     prep['observer']==dict(fd=3,device=path.stat().st_dev,inode=path.stat().st_ino),
                     'actual reset/argv/environment and inherited record identity')
                need(command['exit']==(125 if negative else 0),'actual expected program terminal exit')
                case['output']=check.output(out,negative=negative)
                if mode=='native':need(not err and not path.read_bytes(),'actual native baseline; no observed/configured-result claim')
                else:
                    configured=mode=='configured'
                    case['comparison']=check.check(path.read_bytes(),layout,image,configured=configured,negative=negative,pid=command['pid'])
                    case['reports']=reports.reports(err,configured=configured)
                    reports.check(case['reports'],command['pid'],case['comparison'],negative=negative)
                    case['operation']=dict(status='failed'if negative else'completed',failure_code=case['reports']['loader']['failure_code'])
                    for f in ('namespace.json','launch.json'):binary(ns/f)
                    actual=json.loads((ns/'namespace.json').read_bytes());started=json.loads((ns/'launch.json').read_bytes())
                    need(actual['original_sha256']==fact(original)['sha256']and actual['interpreter_sha256']==fact(interpreter)['sha256']and
                         actual['original']==str(original)and len(actual['objects'])==1,'actual sealed namespace identity')
                    a=actual['objects'][0];item=objects[0]
                    need(a['names']==item['names']and a['sha256']==H(item['bytes'])and a['size']==len(item['bytes'])and
                         a['seals']==namespace.SEALS and a['device']>0 and a['inode']>0,'actual sealed dependency observation')
                    for alias in a['names']:
                        p=ns/alias;need(p.is_symlink()and os.readlink(p)=='/proc/self/fd/'+str(a['fd']),'actual sealed descriptor alias')
                        need(receipt.get('provider_builtins_namespace_aliases',{}).get(str(p))==os.readlink(p),'same retained namespace alias prefix')
                    target_env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
                    target_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=str(a['fd']))
                    if configured:target_env['LI2_SELECTED_PROVIDER']='deterministic-builtins-v1'
                    need(started['argv']==[str(original)]and started['carrier_sha256']==fact(carrier)['sha256']and
                         started['carrier_size']==fact(carrier)['bytes']and started['dependency_fds']==[a['fd']]and started['environment']==target_env,
                         'actual explicit configured/native policy and exact closed launch environment')
                case['status']='passed';outcomes[mode]=out
            except Exception as exc:case['error']=type(exc).__name__+': '+str(exc)
        if not negative and len(outcomes)==3:
            need(len(set(outcomes.values()))==1,'all three actual outputs agree byte-exact; clocks/PIDs remain typed raw observations')
    need(len(state['cases'])==18 and all(c['status']=='passed'for c in state['cases'])and
         sum(c.get('operation',{}).get('status')=='failed'for c in state['cases'])==12,'all six positive and twelve failed-operation controls')
    finalize(receipt);state['status']='passed';return bridge


def finalize(receipt):
    need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in receipt.get('provider_builtins_namespace_aliases',{}).items()),
         'all actual builtin namespace aliases still unchanged')


def summary(receipt):
    s=receipt.get('provider_builtins',{});cases=s.get('cases',[])
    def command(c):
        rows=[x for x in receipt.get('commands',[])if x.get('name')==c['name']and x.get('profile')=='provider_builtins']
        return rows[0]if len(rows)==1 and type(rows[0].get('pid'))is int and rows[0]['pid']>0 else None
    def terminal(c):return c is not None and c.get('reaped')is True and type(c.get('exit'))is int
    actual=[command(c)for c in cases]
    return dict(status=s.get('status','unexecuted'),qualified=receipt.get('status')=='passed'and s.get('status')=='passed',
        planned_cases=18,attempted_cases=len(cases),attempted_invocations=sum(c.get('invocation_attempted')is True for c in cases),
        actual_processes=sum(x is not None for x in actual),completed_invocations=sum(terminal(x)for x in actual),
        accepted=sum(c['status']=='passed'for c in cases),failed_operations=sum(c.get('operation',{}).get('status')=='failed'for c in cases),
        cases=[{k:c[k]for k in ('name','variant','negative','mode','status','exit','expected_operation')if k in c}|dict(
            comparison=c.get('comparison'),operation=c.get('operation'),output=c.get('output'),
            invoked=x is not None,invocation_completed=terminal(x),error_type=c['error'].split(':',1)[0]if c.get('error')else None,
            captures={k:{n:v[n]for n in ('bytes','sha256')}for k,v in c.get('captures',{}).items()})for c,x in zip(cases,actual)],
        archive=s.get('archive'),bridge={k:s.get('bridge',{}).get(k)for k in ('bytes','sha256')},
        full_reports_sha256=H(json.dumps([c.get('reports')for c in cases],sort_keys=True,separators=(',',':')).encode()),
        source_patching_scope='finite same-page windows, unregistered only',full_b2_qualification=False,performance_credit=False)
