"""Finite actual-entry CPUID-NX qualifier using the existing Build/invoke custody.

No standalone runner or new receipt framework. Call after the same actual
provider385/callback51 prerequisites, and call finalize again from parent finally.
"""
import hashlib,importlib.util,json,os,re,shlex,shutil,struct
from pathlib import Path
from page_selected import fact,need,elf,bridge_check
from page_selected_oneshot_build import commands,UNITS,MACROS
from page_selected_register_time_build import headers
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
from page_selected_provider_launch import ENV

BOUNDS={'cpuid_nx':[30,512<<20,16<<20,60],'cpuid_nx_build':[30,512<<20,16<<20,60]}
H=lambda b:hashlib.sha256(b).hexdigest()
LANES=('native','faulted-raw','faulted-configured','nx-raw','nx-configured')

def qualify(builder,products,root,private,pin,binary,aliases,run,receipt):
    root,private=Path(root),Path(private);selected=root/'tools/page-entry/selected';fixture=selected/'tests/cpuid_nx'
    output=private/'cpuid-nx';output.mkdir()
    state=receipt['cpuid_nx']=dict(status='failed',builds=[],programs=[],cases=[],generated={},archive=fact(products['archive']))
    for name,bounds in BOUNDS.items():need(receipt['bounds'].get(name)==bounds,'unchanged finite bounds '+name)
    need(receipt.get('original_provider',{}).get('status')=='passed'and receipt.get('provider_callback',{}).get('status')=='passed',
         'unchanged current provider385 and callback51 prerequisites remain mandatory')
    # This is the corrected shared dynamic-library authority, used by both
    # prerequisite cohorts, not a replacement parser for our freestanding ELF.
    pin(root/'evaluation/inprocess/page_selected_provider_libraries.py')
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    prepare=load('cpuid_nx_prepare',fixture/'prepare.py');check=load('cpuid_nx_check',fixture/'check.py')
    reports=load('cpuid_nx_reports',fixture/'reports.py');images=load('cpuid_nx_images',fixture/'interpreter.py')
    namespace=load('cpuid_nx_namespace',root/'tools/page-entry/namespace.py')
    oldcheck=load('cpuid_nx_policy',selected/'tests/oneshot_integrated/check.py')
    cases=json.loads(pin(fixture/'CASES.json').read_bytes());need(cases['lanes']==list(LANES)and len(cases['programs'])==6,'exact finite source corpus')
    for name in ('fixture.S','linker.ld','layout.py','launch.py','observe.inc','disabled_entry.S','disabled_entry.c','PREREQUISITES.json'):pin(fixture/name)
    for name in ('native_pages_compare.py','page_selected_provider_launch.py','page_selected_provider_libraries.py'):
        pin(root/'evaluation/inprocess'/name)
    observed=output/'observed'
    try:state['adapters']=prepare.prepare(root,observed,pin)
    finally:
        for name in ('runtime_loader.c','selected_controller.inc','cpuid_nx_observe.inc'):state['generated'][name]=retain('partial observer '+name,observed/name)
    tools={n:pin(shutil.which(n,path=ENV['PATH']))for n in ('gdb','objdump')}
    cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    state['tools']={k:dict(path=str(v),**fact(v))for k,v in tools.items()}
    for name,path in tools.items():
        _,out,err=run('cpuid-nx-'+name+'-version',[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual tool identity '+name)
    def metadata(label,path,dwarf=False):
        binary(path);bridge_check(path)
        _,out,err=run(label+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
        need(out==err==b'','actual freestanding bridge has no external imports')
        _,symbols,err=run(label+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
        need(not err,'actual bridge symbols')
        _,assembly,err=run(label+'-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',path],profile='inspect',env=builder.environment)
        need(not err,'actual helper body');reset=hidden_memset(path,body_check(path,symbols,assembly,'fast',symbol_name='memset'))
        result=dict(path=str(path),**fact(path),reset=reset)
        if dwarf:
            _,out,err=run(label+'-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
                '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(path),'-x',fixture/'layout.py'],env=gdb_env)
            need(not err,'actual file-only layout stderr');layout=json.loads(out);result['layout']=layout
            rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[b'nx_record']];_,_,ph=elf(path)
            need(len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b'and int(rows[0][1],16)==layout['types']['nx_record']['bytes']<16<<20 and
                 sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+int(rows[0][1],16)<=p[3]+p[6]for p in ph)==1,'complete actual record symbol extent in writable NX owner')
        return result
    bridges={};layouts={};raw_bridges={};disabled={}
    for lane in LANES[1:]:
        nx=lane.startswith('nx-');configured=lane.endswith('configured');directory=output/lane;directory.mkdir()
        recipe=pin(selected/('build-cpuid-nx.sh'if nx else'build-native-pages.sh'))
        rows=commands(recipe,builder,directory,products['archive'],pin);argv=rows[0]
        units=[str(selected.parent/p)for p in UNITS[:-1]];macros=MACROS-{'-DLI2_ONESHOT_PUBLICATION=1'}
        if nx:macros=macros|{'-DLI2_CPUID_NX_ONLY=1'}
        need([x for x in argv if x.endswith(('.c','.S'))]==units and set(x for x in argv if x.startswith('-DLI2_'))==macros and
             sum(x.startswith('-DLI2_')for x in argv)==len(macros)and all(x in argv for x in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
             'exact fifteen-unit native recipe, no one-shot composition')
        if configured:argv.insert(1,'-DLI2_SELECTED_PROVIDER=1')
        for kind in ('unobserved','observed'):
            name='cpuid-'+lane+'-'+kind;target=directory/(kind+'.so');actual=argv.copy();actual[-1]=str(target)
            actual_units=units.copy()
            if kind=='observed':
                prior=str(selected/'runtime_loader.c');new=str(observed/'runtime_loader.c')
                need(actual.count(prior)==1,'one original runtime path replaced only for observation')
                actual=[new if a==prior else a for a in actual];actual_units=[new if a==prior else a for a in actual_units]
            row=dict(name=name,argv=actual,recipe=fact(recipe),archive=fact(products['archive']),translation_units=len(actual_units));state['builds'].append(row)
            headers(name+'-headers',actual,actual_units,products['archive'],builder,pin,aliases,run,row)
            try:run(name+'-link',actual,profile='cpuid_nx_build',env=builder.environment)
            finally:row['partial']=retain(name,target)
            row['artifact']=metadata(name,target,kind=='observed')
            if kind=='observed':bridges[lane]=target;layouts[lane]=row['artifact']['layout']
            else:raw_bridges[lane]=target
        if nx:
            name='cpuid-'+lane+'-initial-disabled';target=directory/'initial-disabled.so';actual=argv.copy()
            extra=[str(fixture/'disabled_entry.S'),str(fixture/'disabled_entry.c')];actual[-2:-2]=extra+['-Wl,-e,nx_disabled_entry'];actual[-1]=str(target)
            row=dict(name=name,argv=actual,ancillary_preentry_control=True);state['builds'].append(row)
            headers(name+'-headers',actual,units+extra,products['archive'],builder,pin,aliases,run,row)
            try:run(name+'-link',actual,profile='cpuid_nx_build',env=builder.environment)
            finally:row['partial']=retain(name,target)
            row['artifact']=metadata(name,target)
            _,out,err=run(name+'-bootstrap',[tools['objdump'],'-d','-w','-M','att','--disassemble=_start',target],profile='inspect',env=builder.environment)
            need(not err,'actual original bootstrap disassembly');matches=re.findall(rb'^\s*([0-9a-f]+):\s+0f a2\s+cpuid\s*$',out,re.M)
            need(len(matches)==2,'both original bootstrap hardware CPUID instructions retained')
            _,out,err=run(name+'-entry',[builder.tools['nm'],'-n',target],profile='inspect',env=builder.environment);need(not err,'actual bootstrap symbols')
            syms={v[2].decode():int(v[0],16)for line in out.splitlines()if len(v:=line.split())==3}
            _,h,_=elf(target);need(h[4]==syms['nx_disabled_entry']and syms['_start']<int(matches[0],16),'actual control ELF entry and original CPUID offset')
            row['cpuid_offset']=int(matches[0],16)-syms['_start'];disabled[lane]=(target,row['cpuid_offset'])
    interpreter=output/'interpreter'/'li2-provider-entry.so';metadata_source=output/'interpreter'/'metadata.S'
    try:made=images.emit(output/'interpreter');need(made==(interpreter,metadata_source),'unchanged real interpreter emitter paths')
    finally:
        for p in (interpreter,metadata_source):state['generated'][p.name]=retain('partial literal interpreter '+p.name,p)
    for p in (interpreter,metadata_source):pin(binary(p))
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(fixture/'launch.py')
    def make_carrier(name,original,bridge,directory):
        target=directory/'carrier'
        try:
            _,out,err=run(name+'-make',[builder.tools['python'],carrier_tool,'make',original,bridge,target],env=ENV)
            need(not err,'actual carrier construction stderr')
        finally:retain('partial carrier '+name,target)
        binary(target);v=json.loads(out)
        need(v['original_sha256']==fact(original)['sha256']and v['bridge_sha256']==fact(bridge)['sha256']and
             v['carrier_sha256']==fact(target)['sha256'],'actual carrier input/bridge identity')
        return target,v
    def execute(name,original,lane,interp,bridge=None,denial='none'):
        directory=output/name;directory.mkdir();configured=lane.endswith('configured');native=lane=='native'
        row=dict(name=name,lane=lane,denial=denial,status='failed',error=None);state['cases'].append(row)
        objects,description=namespace.plan(original,[interp.parent],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
        for item in objects:
            need(fact(pin(item['path']))['sha256']==H(item['bytes']),'actual namespace dependency source')
            for alias in item['names']:pin(interp.parent/alias)
        row['namespace_plan']=description;row['dependencies']=[dict(names=x['names'],**fact(pin(x['path'])))for x in objects]
        prep=directory/'preparation.json';ns=directory/'namespace';carrier=None
        argv=[builder.tools['python'],launch_tool,'--mode','native'if native else'gated','--policy','configured'if configured else'raw',
              '--deny',denial,'--original',original,'--library-root',interp.parent,'--preparation',prep,'--record-fd','{record_fd}']
        if not native:
            carrier,identities=make_carrier(name,original,bridge,directory)
            need(identities['interpreter_sha256']==fact(interp)['sha256'],'actual PT_INTERP carrier identity')
            argv+=['--carrier',carrier,'--namespace',ns]
        row['invocation_attempted']=True  # Entering run does not assert Popen succeeded.
        try:command,out,err=run(name,argv,profile='cpuid_nx',expected=None,env=ENV,record=True)
        except BaseException as exc:
            row['error']=type(exc).__name__+': '+str(exc)
            actual=[x for x in receipt.get('commands',[])if x['name']==name]
            if actual:row.update({k:actual[-1][k]for k in ('exit','pid','captures')if k in actual[-1]})
            raise
        finally:
            for p in (prep,private/(name+'.record'),ns/'namespace.json',ns/'launch.json'):retain('partial launch '+name+' '+p.name,p)
        row.update(exit=command['exit'],pid=command['pid'],captures=command['captures'])
        actual=json.loads(pin(binary(prep)).read_bytes());row['preparation']=actual
        record_path=pin(binary(private/(name+'.record')))
        need(actual['mask']==0 and [x['signal']for x in actual['dispositions']]==[x for x in range(1,65)if x not in(9,19)]and
             all(x['after']==0 for x in actual['dispositions'])and actual['argv']==[str(original)]and
             actual['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
             actual['observer']==dict(fd=3,device=record_path.stat().st_dev,inode=record_path.stat().st_ino)and
             actual['denial']==denial and actual['installed']==(denial!='none')and actual['filter']==denial_filter(denial)and
             actual['policy']==('configured'if configured else'raw'),
             'actual closed environment, signal reset, outer-denial and FD custody')
        if not native:
            sealed=json.loads(pin(binary(ns/'namespace.json')).read_bytes());started=json.loads(pin(binary(ns/'launch.json')).read_bytes())
            need(sealed['original_sha256']==fact(original)['sha256']and sealed['interpreter_sha256']==fact(interp)['sha256']and
                 sealed['original']==str(original)and len(sealed['objects'])==len(objects),'actual complete sealed namespace')
            for a,item in zip(sealed['objects'],objects):
                need(a['names']==item['names']and a['sha256']==H(item['bytes'])and a['size']==len(item['bytes'])and
                     a['seals']==namespace.SEALS and a['device']>0 and a['inode']>0,'actual immutable dependency object')
                for alias in a['names']:
                    p=ns/alias;value='/proc/self/fd/'+str(a['fd']);need(p.is_symlink()and os.readlink(p)==value,'actual sealed fd alias')
                    receipt.setdefault('cpuid_nx_namespace_aliases',{})[str(p)]=value
            env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
            env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(str(a['fd'])for a in sealed['objects']))
            if configured:env['LI2_SELECTED_PROVIDER']='mask-random-v1'
            need(started['argv']==[str(original)]and started['environment']==env and started['carrier_sha256']==fact(carrier)['sha256'],'actual explicit raw/configured policy and argv')
        return row,command,out,err,record_path.read_bytes()
    programs={};native_outputs={}
    for program in range(1,9):
        name='cpuid-program-'+str(program);directory=output/name;directory.mkdir();original=directory/'original'
        flags=['-nostdlib','-no-pie','-O2','-g','-Wall','-Wextra','-Werror','-DPROGRAM='+str(program)]
        units=[fixture/'fixture.S',metadata_source];row=dict(program=program,status='failed');state['programs'].append(row)
        _,out,err=run(name+'-headers',[builder.tools['cc'],*flags,'-M','-MT','cpuid_nx',*units],env=builder.environment)
        rules=out.decode().replace('\\\n',' ').splitlines();need(not err and len(rules)==2 and all(x.startswith('cpuid_nx: ')for x in rules),'actual two fixture include rules')
        row['headers']={str(pin(t)):fact(pin(t))for line in rules for t in shlex.split(line.split(':',1)[1])}
        need(set(map(str,units))<=set(row['headers']),'both actual original TUs bound')
        argv=[builder.tools['cc'],*flags,'-Wl,-T,'+str(fixture/'linker.ld')+',-z,max-page-size=4096,--build-id=none,--no-undefined',*units,'-o',original];row['argv']=list(map(str,argv))
        try:run(name+'-link',argv,profile='cpuid_nx_build',env=builder.environment)
        finally:row['artifact']=retain(name,original)
        pin(binary(original));_,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',original],profile='inspect',env=builder.environment)
        need(out==err==b'','actual fixture has no unresolved imports')
        info=check.image(original.read_bytes(),interpreter,program,oldcheck.native_policy);row['image']=info;row['status']='built';programs[program]=(original,info)
        if program>6:continue
        native_output=None
        for lane in LANES:
            case,command,out,err,record=execute(name+'-'+lane,original,lane,interpreter,None if lane=='native'else bridges[lane])
            need(command['exit']==0,'actual successful route program');check.output(out,info)
            if lane=='native':need(not err and not record,'actual unobserved native baseline');native_output=out;native_outputs[program]=out
            else:
                nx=lane.startswith('nx-');configured=lane.endswith('configured')
                parsed=reports.reports(err,nx,configured);reports.qualify(parsed,command['pid'],2+len(info['pcs']),nx,configured,program)
                case['reports']=parsed;case['comparison']=check.check(record,layouts[lane],info,nx,configured,out)
                case['native_comparison']=check.compare_lanes(native_output,out,info,configured)
            case['status']='passed'
    original,info=programs[1]
    for denial in ('get','set','both'):
        for lane in LANES[1:]:
            case,command,out,err,record=execute('cpuid-deny-'+denial+'-'+lane,original,lane,interpreter,bridges[lane],denial)
            configured=lane.endswith('configured')
            if lane.startswith('nx-'):
                need(command['exit']==0,'NX remains executable with actual control denial')
                parsed=reports.reports(err,True,configured);reports.qualify(parsed,command['pid'],4,True,configured,1)
                case['comparison']=check.check(record,layouts[lane],info,True,configured,out);case['reports']=parsed
                case['native_comparison']=check.compare_lanes(native_outputs[1],out,info,configured)
            else:
                need(command['exit']==125 and not out,'old faulted gate actually refuses')
                code=238 if denial=='set'else 236;case['operation']=reports.arm_refusal(err,code,configured)
                case['comparison']=check.early(record,layouts[lane],code,configured)
            case['status']='passed'
    for program in (7,8):
        original,info=programs[program]
        for lane in LANES[1:]:
            case,command,out,err,record=execute('cpuid-application-'+str(program)+'-'+lane,original,lane,interpreter,bridges[lane])
            need(command['exit']==125 and not out,'application CPUID control is an actual failed operation')
            nx=lane.startswith('nx-');configured=lane.endswith('configured');parsed=reports.reports(err,nx,configured)
            l,n=parsed['loader'],parsed['native'];arg=0x1011 if program==7 else 0x1012
            need(l['status']==125 and l['failure_code']==205 and l['detail_abs']==arg and l['detail_negative']==0 and
                 l['source_syscalls']==1 and l['syscalls']==1 and l['forwarded']==0 and l['cpuid']==3 and
                 n['admissions']==n['closed']>0 and n['close_busy']==n['close_error']==0,'exact pre-forward denial and actual native closure')
            case['comparison']=check.check(record,layouts[lane],info,nx,configured,out,125,205,arg);case['reports']=parsed
            case['operation']=dict(status='failed',failure_code=205,forwarded=0);case['status']='passed'
    original,_=programs[1]
    for lane,(bridge,offset)in disabled.items():
        case,command,out,err,record=execute('cpuid-initial-disabled-'+lane,original,lane,interpreter,bridge)
        need(command['exit']==125 and out==err==b''and len(record)==128,'actual bounded pre-entry hardware fault, not program completion')
        h=struct.unpack('<16Q',record)
        need(h[:7]==(0x3147504449555043,0,11,11,128,0,0)and h[7]-h[15]==offset and h[8:10]==(13,0)and
             h[11]&0xffff==0x33 and h[12:15]==(0,1,0xa20f),'genuine same-process CPUID-disabled #GP at retained original bootstrap CPUID')
        case['operation']=dict(status='failed',genuine_bootstrap_cpuid_fault=True,target_entered=False);case['status']='passed'
    state['raw_bridges']={k:str(v)for k,v in raw_bridges.items()}
    state['status']='finite_passed_pending_boundary'
    _boundary(builder,products,root,private,pin,binary,aliases,run,receipt,raw_bridges,execute,reports)
    need(len(state['cases'])==57 and all(c['status']=='passed'for c in state['cases']),'all30 route,12 actual outer-denial,8 app-denial,2 initial-disabled and5 unchanged boundary cases')
    finalize(receipt);state['status']='passed'

def finalize(receipt):
    need(all(Path(p).is_symlink()and os.readlink(p)==value for p,value in receipt.get('cpuid_nx_namespace_aliases',{}).items()),'all actual namespace alias observations remain unchanged')

def summary(receipt):
    s=receipt.get('cpuid_nx',{});cases=s.get('cases',[])
    def invocation(case):
        rows=[r for r in receipt.get('commands',[])if r.get('name')==case['name']and r.get('profile')=='cpuid_nx']
        # Only the unique retained subject command's actual Popen PID proves a process.
        return rows[0]if len(rows)==1 and type(rows[0].get('pid'))is int and rows[0]['pid']>0 else None
    def completed(command):
        # Terminal invocation, including nonzero/killed exits; not operation success.
        return command is not None and command.get('reaped')is True and type(command.get('exit'))is int
    def nx_report(case):
        report=case.get('reports',{}).get('cpuid_nx')
        if report is None:return None
        keys=('version','status','failure_code','hardware_entered','hardware_returned','phase',
              'attempts','samples','commits','leaf','subleaf','raw','result')
        return {k:report[k]for k in keys if k in report}|dict(private_report_sha256=H(json.dumps(report,sort_keys=True,separators=(',',':')).encode()))
    actual=[invocation(c)for c in cases]
    return dict(status=s.get('status','unexecuted'),qualified=receipt.get('status')=='passed'and s.get('status')=='passed',
        planned_cases=57,attempted_cases=len(cases),
        attempted_invocations=sum(c.get('invocation_attempted')is True for c in cases),
        actual_processes=sum(command is not None for command in actual),
        completed_invocations=sum(completed(command)for command in actual),
        accepted=sum(c.get('status')=='passed'for c in cases),
        failed_operations=sum(c.get('operation',{}).get('status')=='failed'for c in cases),
        cases=[dict(name=c['name'],lane=c['lane'],status=c['status'],exit=c.get('exit'),operation=c.get('operation'),comparison=c.get('comparison'),
            invocation_attempted=c.get('invocation_attempted')is True,invoked=command is not None,invocation_completed=completed(command),
            error_type=c['error'].split(':',1)[0]if c.get('error')else None,
            counts=({k:c['reports']['loader'][k]for k in ('cpuid','source_patches','source_syscalls','generic_tf_steps','rseq')}|
                {k:c['reports']['native'][k]for k in ('admissions','closed','main_admissions','main_refaults')})if c.get('reports')else None,
            cpuid_nx=nx_report(c),
            captures={k:{n:v[n]for n in ('bytes','sha256')}for k,v in c.get('captures',{}).items()})for c,command in zip(cases,actual)],
        source_patching_qualified=False,full_b2_qualified=False,performance_credit=False)

def denial_filter(mode):
    """Exact independent literal filter expected from the actual outer launcher."""
    need(mode in ('none','get','set','both'),'named control denial')
    if mode=='none':return []
    arguments={'get':[0x1011],'set':[0x1012],'both':[0x1011,0x1012]}[mode]
    rows=[[0x20,0,0,4],[0x15,1,0,0xc000003e],[6,0,0,0x80000000],
          [0x20,0,0,0],[0x15,0,2*len(arguments)+1,158],[0x20,0,0,16]]
    for value in arguments:rows.extend([[0x15,0,1,value],[6,0,0,0x50001]])
    return rows+[[6,0,0,0x7fff0000]]

def _boundary(builder,products,root,private,pin,binary,aliases,run,receipt,bridges,execute,reports):
    """The original assembly, linker script and 128-byte/4+1 assertions stay exact."""
    selected=Path(root)/'tools/page-entry/selected';fixture=selected/'tests/native_pages'
    state=receipt['cpuid_nx'];directory=private/'cpuid-nx'/'old-boundary';directory.mkdir()
    spec=importlib.util.spec_from_file_location('cpuid_boundary_namespace',pin(Path(root)/'tools/page-entry/namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    lexical=namespace.parse(pin('/bin/true').read_bytes())['interpreter'];need(lexical is not None,'actual system interpreter spelling')
    interp=pin(lexical);source=pin(fixture/'boundary.S');linker=pin(fixture/'linker.ld');original=directory/'boundary'
    row=state['boundary_build']=dict(status='failed',source=fact(source),linker=fact(linker),interpreter=dict(path=str(interp),**fact(interp)))
    flags=['-nostdlib','-pie','-Wl,--dynamic-linker,'+lexical,
        '-Wl,-T,'+str(linker)+',-z,max-page-size=4096,--build-id=none,--no-as-needed','-L'+str(interp.parent),'-l:'+interp.name]
    _,out,err=run('cpuid-boundary-headers',[builder.tools['cc'],'-M','-MT','cpuid_boundary',source],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines();need(not err and len(rules)==1 and rules[0].startswith('cpuid_boundary: '),'one actual unchanged assembly include rule')
    row['headers']={str(pin(t)):fact(pin(t))for t in shlex.split(rules[0].split(':',1)[1])};need(str(source)in row['headers'],'actual original assembly dependency')
    argv=[builder.tools['cc'],*flags,source,'-o',original];row['argv']=list(map(str,argv))
    try:run('cpuid-boundary-link',argv,profile='cpuid_nx_build',env=builder.environment)
    finally:
        try:
            if original.exists()or original.is_symlink():row['artifact']=fact(binary(original))
        except BaseException as exc:receipt['final_errors'].append('boundary partial retention: '+type(exc).__name__+': '+str(exc))
    pin(binary(original));parsed=namespace.parse(original.read_bytes())
    need(parsed['elf_type']==3 and parsed['interpreter']==lexical,'actual baseline ET_DYN/interpreter identity')
    _,out,err=run('cpuid-boundary-symbols',[builder.tools['nm'],'-n',original],profile='inspect',env=builder.environment);need(not err,'actual unchanged boundary symbols')
    symbols={v[2].decode():int(v[0],16)for line in out.splitlines()if len(v:=line.split())==3}
    need(symbols['li2_boundary_call']==8187 and symbols['li2_boundary_return']==8192 and
         symbols['li2_straddler']==20477 and symbols['li2_straddler_end']==20487,'unchanged exact CALL and straddler geometry')
    row['status']='built';reference=None
    for lane in LANES:
        case,command,out,err,record=execute('cpuid-original-boundary-'+lane,original,lane,interp,None if lane=='native'else bridges[lane])
        need(command['exit']==0 and len(out)==128 and not record,'actual unchanged boundary exit/output; no new observer')
        need(int.from_bytes(out[72:80],'little')==0x4e41544956455047,'original source success marker')
        if lane=='native':need(not err,'native boundary stderr exact');reference=out
        else:
            need(out==reference,'unchanged full128 native/boundary equality')
            p=reports.reports(err,lane.startswith('nx-'),lane.endswith('configured'));reports.completed(p,command['pid'])
            need(p['native']['main_admissions']==4 and p['native']['main_refaults']==1,'unchanged four actual main admissions and one MOVABS refault')
            if lane.startswith('nx-'):
                n=p['cpuid_nx'];need(n['status']==n['failure_code']==0 and n['hardware_entered']==n['hardware_returned']==1 and
                    n['phase']==3 and n['attempts']==n['samples']==n['commits']==p['loader']['cpuid']>0,'actual NX completion throughout unchanged interpreter/boundary')
            if lane.endswith('configured'):
                q=p['provider'];need(q['status']==q['failure_code']==q['busy']==q['random_error']==0 and q['initialized']==1 and
                    [q[k]for k in('cpuid_completed','rdrand_completed','rdseed_completed','rdpid_completed')]==[p['loader'][k]for k in('cpuid','rdrand','rdseed','rdpid')],
                    'actual configured counts match unchanged baseline loader')
            case['reports']=p
        case['comparison']=dict(output_bytes=128,sha256=H(out),unchanged_original_fixture=True);case['status']='passed'
