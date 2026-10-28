"""Real registered one-shot fallback pair; callable under existing Build custody.

The caller owns exact-commit/source, capture/tool/artifact and final closure, and
must also retain the unchanged six-owner positive and 49-negative qualifications.
"""
import hashlib,importlib.util,json,os,shlex,shutil
from pathlib import Path
from page_selected import fact,need,elf
import page_selected_oneshot_build as build
from page_selected_register_time_build import headers,bridge_check
from page_selected_register_real import resolved_libraries
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset

BOUNDS={'oneshot_registered':[30,512<<20,16<<20,60],
        'oneshot_registered_build':[30,512<<20,16<<20,60]}
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',
         GLIBC_TUNABLES='glibc.pthread.rseq=0',PYTHONDONTWRITEBYTECODE='1')
H=lambda b:hashlib.sha256(b).hexdigest()


def registered(builder,products,root,private,library_root,pin,binary,aliases,run,receipt):
    root,private=Path(root),Path(private);selected=root/'tools/page-entry/selected'
    fixture=selected/'tests/oneshot_registered';output=private/'oneshot-registered';output.mkdir()
    state=receipt['oneshot_registered']=dict(status='failed',cases=[],generated={},archive=fact(products['archive']))
    for key,value in BOUNDS.items():need(receipt['bounds'].get(key)==value,'unchanged registered bounds '+key)
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    prepare=load('oneshot_registered_prepare',fixture/'prepare.py')
    check=load('oneshot_registered_check',fixture/'check.py')
    completion=load('oneshot_registered_completion',fixture/'reports.py')
    report=load('oneshot_registered_report_parser',selected/'tests/oneshot_integrated/reports.py')
    namespace=load('oneshot_registered_namespace',root/'tools/page-entry/namespace.py')
    for name in ('fixture.S','linker.ld','build.sh','launch.py','observe.inc'):pin(fixture/name)
    observed=output/'observed'
    try:state['observer_adapters']=prepare.prepare(root,observed,pin)
    finally:
        for name in ('runtime_loader.c','selected_controller.inc','selected_oneshot.inc','oneshot_registered_observe.inc'):
            state['generated'][name]=retain('partial fallback source '+name,observed/name)
    recipe=pin(selected/'build-oneshot.sh');argv=build.commands(recipe,builder,output,products['archive'],pin)[0]
    units=[str(selected.parent/p)for p in build.UNITS]
    need([p for p in argv if p.endswith(('.c','.S'))]==units and argv[-2:]==['-o',str(output/'bridge-oneshot.so')] and
         set(p for p in argv if p.startswith('-DLI2_'))==build.MACROS and
         sum(p.startswith('-DLI2_')for p in argv)==len(build.MACROS) and
         all(p in argv for p in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact existing 16-TU release recipe and complete macro set')
    state['recipe']=fact(recipe);state['unobserved_argv']=argv.copy()
    prior=str(selected/'runtime_loader.c');replacement=str(observed/'runtime_loader.c')
    need(argv.count(prior)==1,'one runtime observation adapter')
    argv=[replacement if p==prior else p for p in argv];units=[replacement if p==prior else p for p in units]
    bridge=output/'bridge-registered-observed.so';argv[-1]=str(bridge)
    unit=state['bridge_build']=dict(argv=argv,translation_units=16,archive=fact(products['archive']))
    headers('registered-headers',argv,units,products['archive'],builder,pin,aliases,run,unit)
    _,out,err=run('registered-archive-exports',[builder.tools['nm'],'-g','--defined-only',products['archive']],profile='inspect',env=builder.environment)
    need(not err,'actual retained archive exports')
    for name in build.EXPORTS:
        rows=[x.split()for x in out.splitlines()if x.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()],'actual publisher export '+name)
    try:run('registered-bridge-link',argv,profile='oneshot_registered_build',env=builder.environment)
    finally:unit['artifact']=retain('partial fallback bridge',bridge)
    binary(bridge);state['bridge']=dict(path=str(bridge),**fact(bridge));state['bridge_elf']=bridge_check(bridge)
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    for name in ('basename','dirname'):pin(shutil.which(name,path=ENV['PATH']))
    _,out,err=run('registered-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual objdump version')
    _,symbols,err=run('registered-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual fallback record symbol')
    _,_,segments=elf(bridge);rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[b'orf_record']]
    need(len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b' and int(rows[0][1],16)==check.RECORD_BYTES and
         sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+check.RECORD_BYTES<=p[3]+p[6]for p in segments)==1,
         'complete fixed all-u64/byte record extent in actual writable NX load')
    _,assembly,err=run('registered-reset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual qualified reset instructions');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    _,out,err=run('registered-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(not out and not err,'no observed bridge unresolved imports')
    pin('/bin/true');interp_name=namespace.parse(Path('/bin/true').read_bytes())['interpreter'];interp=pin(interp_name)
    library_root=Path(library_root).resolve(strict=True);need(library_root.is_dir(),'actual dependency root')
    _,out,err=run('registered-fixture-headers',[builder.tools['cc'],'-nostdlib','-pie','-M','-MT','registered',fixture/'fixture.S'],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==1 and rules[0].startswith('registered: '),'one actual assembler include rule')
    deps=shlex.split(rules[0].split(':',1)[1]);need(str(fixture/'fixture.S')in deps,'actual fixture source dependency')
    state['fixture_headers']={str(pin(p)):fact(p)for p in deps}
    original=output/'original'
    try:run('registered-fixture-link',[builder.tools['sh'],fixture/'build.sh',interp_name,library_root,original],profile='oneshot_registered_build',env=dict(ENV,LI2_CC=str(builder.tools['cc'])))
    finally:state['original']=retain('partial registered fixture',original)
    binary(original);pin(original);image=check.elf(original.read_bytes(),str(interp_name));state['image']=image
    parsed=namespace.parse(original.read_bytes());interpreter=namespace.parse(interp.read_bytes())
    need(parsed['needed']==[interp.name] and not interpreter['needed'],'nostdlib fixture links only the actual dependency-free system interpreter')
    for label,args in (('symbols',[builder.tools['nm'],'-S','-n',original]),('assembly',[objdump,'-d','-w','-M','att',original])):
        _,out,err=run('registered-fixture-'+label,args,profile='inspect',env=builder.environment);need(out and not err,'actual fixture '+label)
    carrier=output/'carrier';carrier_tool=pin(root/'tools/page-entry/carrier.py')
    try:
        _,out,err=run('registered-carrier-make',[builder.tools['python'],carrier_tool,'make',original,bridge,carrier],env=ENV)
        need(not err,'actual carrier creation stderr')
    finally:state['carrier']=retain('partial registered carrier',carrier)
    binary(carrier);identities=json.loads(out)
    need(identities['original_sha256']==fact(original)['sha256'] and identities['interpreter_sha256']==fact(interp)['sha256'] and
         identities['bridge_sha256']==fact(bridge)['sha256'] and identities['carrier_sha256']==fact(carrier)['sha256'],'actual carrier identity')
    objects,description=namespace.plan(original,[library_root],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    need(len(objects)==1 and objects[0]['bytes']==interp.read_bytes() and objects[0]['names']==[interp.name],'complete actual interpreter-only dependency graph')
    expected={interp:{interp.name}}
    for item in objects:
        need(fact(pin(item['path']))['sha256']==H(item['bytes']),'actual dependency bytes')
        for alias in item['names']:need(pin(library_root/alias)==interp,'actual dependency alias')
    _,out,err=run('registered-loader-list',[interp,'--list',original],profile='oneshot_registered',env=ENV)
    need(not err,'actual loader listing stderr');resolved_libraries(out,expected,interp,pin);state['namespace_plan']=description
    outcomes={};ns=output/'namespace';launch=pin(fixture/'launch.py')
    for mode in ('native','gated'):
        name='registered-'+mode;case=dict(name=name,mode=mode,status='failed',error=None);state['cases'].append(case)
        preparation=output/(mode+'.preparation');record=private/(name+'.record')
        argv=[builder.tools['python'],launch,'--mode',mode,'--original',original,'--library-root',library_root,
              '--preparation',preparation,'--record-fd','{record_fd}']
        if mode=='gated':argv+=['--carrier',carrier,'--namespace',ns]
        try:
            command,out,err=run(name,argv,profile='oneshot_registered',expected=None,env=ENV,record=True)
            case.update(exit=command['exit'],pid=command['pid'],captures=command['captures'])
            binary(preparation);binary(record);prep=json.loads(preparation.read_bytes());case['preparation']=prep
            need(prep['mask']==0 and [x['signal']for x in prep['dispositions']]==[x for x in range(1,65)if x not in(9,19)] and
                 all(x['after']==0 for x in prep['dispositions']) and prep['argv']==[str(original)] and
                 prep['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'} and
                 prep['observer']==dict(fd=3,device=record.stat().st_dev,inode=record.stat().st_ino),'actual reset/argv/environment/record identity')
            need(command['exit']==0,'actual successful registered program exit');case['output']=check.output(out,command['pid'])
            if mode=='native':need(not err and not record.read_bytes(),'native empty stderr/observer; genuine kernel registration and effects')
            else:
                case['reports']=report.reports(err);completion.completed(case['reports'],command['pid'])
                case['comparison']=check.record(record.read_bytes(),image,command['pid'],out,case['reports']['rseq'])
                for path in (ns/'namespace.json',ns/'launch.json'):binary(path)
                actual=json.loads((ns/'namespace.json').read_bytes());started=json.loads((ns/'launch.json').read_bytes())
                need(actual['original_sha256']==fact(original)['sha256'] and actual['interpreter_sha256']==fact(interp)['sha256'] and
                     actual['original']==str(original) and len(actual['objects'])==1,'actual namespace identity')
                row=actual['objects'][0];item=objects[0]
                need(row['names']==item['names'] and row['sha256']==H(item['bytes']) and row['size']==len(item['bytes']) and
                     row['seals']==namespace.SEALS and row['device']>0 and row['inode']>0,'actual sealed dependency')
                for name in row['names']:
                    alias=ns/name;target='/proc/self/fd/'+str(row['fd'])
                    need(alias.is_symlink() and os.readlink(alias)==target,'actual sealed descriptor alias')
                    receipt.setdefault('registered_namespace_aliases',{})[str(alias)]=target
                environment={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
                environment.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=str(row['fd']))
                need(started['argv']==[str(original)] and started['carrier_sha256']==fact(carrier)['sha256'] and
                     started['environment']==environment,'actual closed launch environment, explicit program registration, no provider option')
            case['status']='passed';outcomes[mode]=out
        except Exception as exc:
            case['error']=type(exc).__name__+': '+str(exc)
            actual=[x for x in receipt.get('commands',[])if x['name']==case['name']]
            if actual:case.update({k:actual[-1][k]for k in ('exit','pid','captures')if k in actual[-1]})
        finally:
            for path in (preparation,record):retain('partial registered launch '+mode,path)
            if mode=='gated':
                for path in (ns/'namespace.json',ns/'launch.json'):retain('partial registered namespace',path)
    need(len(state['cases'])==2 and set(outcomes)=={'native','gated'} and all(c['status']=='passed'for c in state['cases']),'both actual native/registered fallback programs')
    need(outcomes['native'][:21]==outcomes['gated'][:21] and outcomes['native'][45:]==outcomes['gated'][45:]==bytes(8),
         'exact source/marker/registration output; clock words and each real PID checked separately')
    finalize(receipt);state['status']='passed'
    return bridge


def finalize(receipt):
    need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in receipt.get('registered_namespace_aliases',{}).items()),'all registered namespace aliases still unchanged')


def summary(receipt):
    s=receipt.get('oneshot_registered',{})
    names=('registered-native','registered-gated');started={};completed={}
    for name in names:
        rows=[c for c in receipt.get('commands',[])if c.get('name')==name]
        if len(rows)!=1:continue
        row=rows[0]
        if type(row.get('pid'))is not int or row['pid']<=0:continue
        started[name]=row
        # A completed process has returned successfully under supervision;
        # accepting its result additionally requires every case comparison.
        if type(row.get('exit'))is int and row['exit']==0 and row.get('reaped')is True and \
           row.get('timed_out')is False and not row.get('error') and not row.get('cleanup_errors'):
            completed[name]=row
    accepted=0
    for name,row in completed.items():
        cases=[c for c in s.get('cases',[])if c.get('name')==name]
        if len(cases)==1 and cases[0].get('status')=='passed' and type(cases[0].get('pid'))is int and cases[0]['pid']==row['pid']:
            accepted+=1
    return dict(status=s.get('status','unexecuted'),qualified=receipt.get('status')=='passed' and s.get('status')=='passed' and accepted==2,
        planned_processes=2,attempted_cases=len(s.get('cases',[])),actual_processes=len(started),
        completed_processes=len(completed),accepted_cases=accepted,passed=accepted,
        cases=[{k:c[k]for k in ('name','mode','status','exit')if k in c}|dict(output=c.get('output'),comparison=c.get('comparison'),
            error_type=c['error'].split(':',1)[0]if c.get('error')else None,
            captures={k:{x:v[x]for x in ('bytes','sha256')}for k,v in c.get('captures',{}).items()})for c in s.get('cases',[])],
        full_reports_sha256=H(json.dumps([c.get('reports')for c in s.get('cases',[])],sort_keys=True,separators=(',',':')).encode()),
        performance_credit=False,full_b2_qualification=False)
