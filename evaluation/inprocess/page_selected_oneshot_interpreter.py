"""Fixed ordinary /bin/true interpreter-publication lane under existing custody.

Original six/49/17 prerequisites and the registered fallback pair are run by the
unchanged enclosing driver before this optional lane. No owner is recycled.
"""
import hashlib,importlib.util,json,os,shutil
from pathlib import Path
from page_selected import fact,need,elf
import page_selected_oneshot_build as build
from page_selected_oneshot_registered import BOUNDS,ENV
from page_selected_register_time_build import headers,bridge_check
from page_selected_register_real import resolved_libraries
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
H=lambda b:hashlib.sha256(b).hexdigest()


def interpreter(builder,products,root,private,library_root,pin,binary,aliases,run,receipt):
    root,private=Path(root),Path(private);selected=root/'tools/page-entry/selected'
    fixture=selected/'tests/oneshot_interpreter';output=private/'oneshot-interpreter';output.mkdir()
    state=receipt['oneshot_interpreter']=dict(status='failed',cases=[],generated={},units=[],archive=fact(products['archive']))
    for key,value in BOUNDS.items():need(receipt['bounds'].get(key)==value,'unchanged interpreter bounds '+key)
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    prepare=load('oneshot_interpreter_prepare',fixture/'prepare.py')
    check=load('oneshot_interpreter_check',fixture/'check.py')
    report=load('oneshot_interpreter_reports',fixture/'reports.py')
    old_record=load('oneshot_interpreter_old_view',selected/'tests/oneshot_failure/record.py')
    namespace=load('oneshot_interpreter_namespace',root/'tools/page-entry/namespace.py')
    for name in ('observe.inc','layout.py','REPORT-INVERSES.json'):pin(fixture/name)
    inverse=(fixture/'reports.py').read_text()
    for op in reversed(json.loads((fixture/'REPORT-INVERSES.json').read_bytes())):
        need(inverse.count(op['after'])==1,'unique report inverse');inverse=inverse.replace(op['after'],op['before'])
    need(inverse==pin(selected/'tests/oneshot_integrated/reports.py').read_text(),'complete original report consumer recovered')
    observed=output/'observed'
    try:state['observer_adapters']=prepare.prepare(root,observed,pin)
    finally:
        for name in ('runtime_loader.c','selected_controller.inc','selected_oneshot.inc','selected_chain.inc','oneshot_interpreter_observe.inc'):
            state['generated'][name]=retain('partial interpreter observer '+name,observed/name)
    recipe=pin(selected/'build-oneshot-interpreter.sh');original_argv=build.commands(recipe,builder,output,products['archive'],pin)[0]
    units=[str(selected.parent/p)for p in build.UNITS];macros=build.MACROS|{'-DLI2_ONESHOT_INITIAL_INTERPRETER=1'}
    need([p for p in original_argv if p.endswith(('.c','.S'))]==units and
         original_argv[-2:]==['-o',str(output/'bridge-oneshot-interpreter.so')] and
         set(p for p in original_argv if p.startswith('-DLI2_'))==macros and
         sum(p.startswith('-DLI2_')for p in original_argv)==len(macros) and
         all(p in original_argv for p in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact opt-in 16-TU release recipe; original eight macros plus initial interpreter')
    state['recipe']=fact(recipe)
    _,out,err=run('interpreter-archive-exports',[builder.tools['nm'],'-g','--defined-only',products['archive']],profile='inspect',env=builder.environment)
    need(not err,'actual retained archive exports')
    for name in build.EXPORTS:
        rows=[x.split()for x in out.splitlines()if x.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()],'actual publisher export '+name)
    tools={name:pin(shutil.which(name,path=ENV['PATH']))for name in ('objdump','gdb')}
    cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    for name,path in tools.items():
        _,out,err=run('interpreter-'+name+'-version',[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual interpreter inspection tool '+name)
    state['tools']={name:dict(path=str(path),**fact(path))for name,path in tools.items()}
    bridges={};layout=None
    for mode in ('production','observed'):
        argv=original_argv.copy();actual_units=units.copy();bridge=output/('bridge-'+mode+'.so');argv[-1]=str(bridge)
        if mode=='observed':
            old=str(selected/'runtime_loader.c');new=str(observed/'runtime_loader.c')
            need(argv.count(old)==1,'one actual observation TU');argv=[new if p==old else p for p in argv];actual_units=[new if p==old else p for p in units]
        unit=dict(mode=mode,argv=argv,translation_units=16,archive=fact(products['archive']));state['units'].append(unit)
        headers('interpreter-'+mode+'-headers',argv,actual_units,products['archive'],builder,pin,aliases,run,unit)
        try:run('interpreter-'+mode+'-link',argv,profile='oneshot_registered_build',env=builder.environment)
        finally:unit['artifact']=retain('partial interpreter bridge '+mode,bridge)
        binary(bridge);unit['elf']=bridge_check(bridge);bridges[mode]=bridge
        _,symbols,err=run('interpreter-'+mode+'-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
        need(not err,'actual interpreter bridge symbol metadata')
        _,assembly,err=run('interpreter-'+mode+'-reset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
        need(not err,'actual qualified reset');unit['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
        _,out,err=run('interpreter-'+mode+'-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
        need(not out and not err,'no interpreter bridge unresolved imports')
        if mode=='observed':
            _,out,err=run('interpreter-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
                '-iex','set debuginfod enabled off','-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
                '--readnow','--se='+str(bridge),'-x',fixture/'layout.py'],env=gdb_env)
            need(not err,'actual file-only DWARF stderr');layout=json.loads(out);state['layout']=layout
            layout['symbols']={}
            for symbol in ('selected_oneshot_owners','selected_session','raw','selected_oneshot_frame_range',
                           'li2_lifecycle_oneshot_transfer','li2_lifecycle_oneshot_advance','li2_lifecycle_oneshot_observe','li2_lifecycle_oneshot_release'):
                found=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[symbol.encode()]]
                need(len(found)==1 and len(found[0])==4 and found[0][2]in(b'b',b'B',b't',b'T'),'actual unique owner/callback symbol '+symbol)
                layout['symbols'][symbol]=int(found[0][0],16)
            rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[b'oi_record']];_,_,segments=elf(bridge)
            need(len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b' and
                 int(rows[0][1],16)==layout['types']['oi_record']['bytes']<16<<20 and
                 sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+int(rows[0][1],16)<=p[3]+p[6]for p in segments)==1,
                 'complete actual bounded record in writable NX load')
    original=pin('/bin/true');parsed=namespace.parse(original.read_bytes());interp_name=parsed['interpreter'];interp=pin(interp_name)
    images=check.image(original.read_bytes(),interp.read_bytes());state['images']={str(k):{n:v[n]for n in ('entry','bytes','sha256')}for k,v in images.items()}
    library_root=Path(library_root).resolve(strict=True);need(library_root.is_dir(),'actual dependency root')
    objects,description=namespace.plan(original,[library_root],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    expected={interp:{interp.name}}
    for item in objects:
        path=pin(item['path']);need(fact(path)['sha256']==H(item['bytes']),'actual namespace dependency bytes')
        expected.setdefault(path,set()).update(item['names'])
        for alias in item['names']:need(pin(library_root/alias)==path,'actual dependency alias')
    _,out,err=run('interpreter-loader-list',[interp,'--list',original],profile='oneshot_registered',env=ENV)
    need(not err,'actual loader listing stderr');resolved_libraries(out,expected,interp,pin);state['namespace_plan']=description
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch=pin(selected/'tests/oneshot_registered/launch.py');carriers={}
    for mode,bridge in bridges.items():
        carrier=output/('carrier-'+mode)
        try:
            _,out,err=run('interpreter-'+mode+'-carrier',[builder.tools['python'],carrier_tool,'make',original,bridge,carrier],env=ENV)
            need(not err,'actual interpreter carrier stderr')
        finally:state['generated']['carrier-'+mode]=retain('partial interpreter carrier '+mode,carrier)
        binary(carrier);identity=json.loads(out)
        need(identity['original_sha256']==fact(original)['sha256']and identity['interpreter_sha256']==fact(interp)['sha256']and
             identity['bridge_sha256']==fact(bridge)['sha256']and identity['carrier_sha256']==fact(carrier)['sha256'],'actual carrier identities')
        carriers[mode]=carrier
    for mode in ('native','production','observed'):
        name='interpreter-'+mode;case=dict(name=name,mode=mode,status='failed',error=None);state['cases'].append(case)
        preparation=output/(mode+'.preparation');record=private/(name+'.record');ns=output/('namespace-'+mode)
        argv=[builder.tools['python'],launch,'--mode','native'if mode=='native'else'gated','--original',original,
              '--library-root',library_root,'--preparation',preparation,'--record-fd','{record_fd}']
        if mode!='native':argv+=['--carrier',carriers[mode],'--namespace',ns]
        try:
            command,out,err=run(name,argv,profile='oneshot_registered',expected=None,env=ENV,record=True)
            case.update(exit=command['exit'],pid=command['pid'],captures=command['captures'])
            binary(preparation);binary(record);prep=json.loads(preparation.read_bytes());case['preparation']=prep
            need(prep['mask']==0 and [x['signal']for x in prep['dispositions']]==[x for x in range(1,65)if x not in(9,19)]and
                 all(x['after']==0 for x in prep['dispositions'])and prep['argv']==[str(original)]and
                 prep['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
                 prep['observer']==dict(fd=3,device=record.stat().st_dev,inode=record.stat().st_ino),'actual reset/argv/environment/record identity')
            need(command['exit']==0 and not out,'actual successful silent ordinary true')
            if mode=='native':need(not err and not record.read_bytes(),'native empty stderr and observer record')
            else:
                case['reports']=report.reports(err)
                if mode=='production':need(not record.read_bytes(),'unobserved production record stays empty')
                else:case['comparison']=check.check(record.read_bytes(),layout,images,command['pid'],old_record)
                report.completed(case['reports'],command['pid'],case.get('comparison'))
                for path in (ns/'namespace.json',ns/'launch.json'):binary(path)
                actual=json.loads((ns/'namespace.json').read_bytes());started=json.loads((ns/'launch.json').read_bytes())
                need(actual['original_sha256']==fact(original)['sha256']and actual['interpreter_sha256']==fact(interp)['sha256']and
                     actual['original']==str(original)and len(actual['objects'])==len(objects),'actual complete namespace identity')
                descriptors=[]
                for row,item in zip(actual['objects'],objects,strict=True):
                    need(row['names']==item['names']and row['sha256']==H(item['bytes'])and row['size']==len(item['bytes'])and
                         row['seals']==namespace.SEALS and row['device']>0 and row['inode']>0 and type(row['fd'])is int and row['fd']>3,'actual sealed dependency')
                    descriptors.append(str(row['fd']))
                    for alias in row['names']:
                        p=ns/alias;target='/proc/self/fd/'+str(row['fd']);need(p.is_symlink()and os.readlink(p)==target,'actual sealed descriptor alias')
                        receipt.setdefault('interpreter_namespace_aliases',{})[str(p)]=target
                need(len(set(descriptors))==len(descriptors),'unique actual dependency descriptors')
                environment={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
                environment.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(descriptors))
                need(started['argv']==[str(original)]and started['carrier_sha256']==fact(carriers[mode])['sha256']and
                     started['environment']==environment,'closed actual launch environment; no provider or CPUID-NX option')
            case['status']='passed'
        except Exception as exc:
            case['error']=type(exc).__name__+': '+str(exc)
            actual=[x for x in receipt.get('commands',[])if x['name']==name]
            if actual:case.update({k:actual[-1][k]for k in ('exit','pid','captures')if k in actual[-1]})
        finally:
            for path in (preparation,record):retain('partial interpreter launch '+mode,path)
            if mode!='native':
                for path in (ns/'namespace.json',ns/'launch.json'):retain('partial interpreter namespace '+mode,path)
    need(len(state['cases'])==3 and all(c['status']=='passed'for c in state['cases']),'all three actual ordinary-program lanes')
    finalize(receipt);state['status']='passed'


def finalize(receipt):
    need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in receipt.get('interpreter_namespace_aliases',{}).items()),'all interpreter namespace aliases still unchanged')


def summary(receipt):
    s=receipt.get('oneshot_interpreter',{});names=('interpreter-native','interpreter-production','interpreter-observed')
    actual=completed=accepted=0
    for name in names:
        rows=[c for c in receipt.get('commands',[])if c.get('name')==name]
        if len(rows)!=1 or type(rows[0].get('pid'))is not int or rows[0]['pid']<=0:continue
        row=rows[0];actual+=1
        if type(row.get('exit'))is not int or row['exit']!=0 or row.get('reaped')is not True or row.get('timed_out')is not False or row.get('error')or row.get('cleanup_errors'):continue
        completed+=1;cases=[c for c in s.get('cases',[])if c.get('name')==name]
        accepted+=int(len(cases)==1 and cases[0].get('status')=='passed'and cases[0].get('pid')==row['pid'])
    return dict(status=s.get('status','unexecuted'),qualified=receipt.get('status')=='passed'and s.get('status')=='passed'and accepted==3,
        planned_processes=3,attempted_cases=len(s.get('cases',[])),actual_processes=actual,completed_processes=completed,accepted_cases=accepted,
        cases=[{k:c[k]for k in ('name','mode','status','exit')if k in c}|dict(comparison=c.get('comparison'),
            oneshot={k:v for k,v in c.get('reports',{}).get('oneshot',{}).items()if k not in ('scope','detail_abs','detail_negative')},error_type=c['error'].split(':',1)[0]if c.get('error')else None,
            captures={k:{x:v[x]for x in ('bytes','sha256')}for k,v in c.get('captures',{}).items()})for c in s.get('cases',[])],
        full_reports_sha256=H(json.dumps([c.get('reports')for c in s.get('cases',[])],sort_keys=True,separators=(',',':')).encode()),
        full_b2_qualification=False,performance_credit=False)
