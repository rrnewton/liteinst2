"""Finite combined CPUID-NX/one-shot interaction under existing Build custody."""
import hashlib,importlib.util,json,os,re,shlex,shutil,struct
from pathlib import Path
from page_selected import fact,need,elf,bridge_check
from page_selected_oneshot_build import commands,UNITS,MACROS
from page_selected_register_time_build import headers
from page_selected_register_real import resolved_libraries
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
from page_selected_oneshot_registered import ENV
from page_selected_cpuid_nx import denial_filter
BOUNDS={'oneshot_cpuid':[30,512<<20,16<<20,60],'oneshot_cpuid_build':[30,512<<20,16<<20,60]}
H=lambda b:hashlib.sha256(b).hexdigest()

def qualify(builder,products,root,private,library_root,pin,binary,aliases,run,receipt):
    root,private=Path(root),Path(private);selected=root/'tools/page-entry/selected';fixture=selected/'tests/oneshot_cpuid'
    output=private/'oneshot-cpuid';output.mkdir()
    state=receipt['oneshot_cpuid']=dict(status='failed',builds=[],programs=[],cases=[],generated={},archive=fact(products['archive']))
    for name,value in BOUNDS.items():need(receipt['bounds'].get(name)==value,'unchanged combined bounds '+name)
    need(all(receipt.get(n,{}).get('status')=='passed'for n in('original_provider','provider_callback','cpuid_nx','companions','oneshot_registered','oneshot_interpreter')),
         'all old385/51/57,6/49/17,registered2 and ordinary3 remain mandatory')
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    prepare=load('oneshot_cpuid_prepare',fixture/'prepare.py');check=load('oneshot_cpuid_check',fixture/'check.py');report=load('oneshot_cpuid_report',fixture/'reports.py')
    oi=load('oneshot_cpuid_original_owner',selected/'tests/oneshot_interpreter/check.py')
    oldreport=load('oneshot_cpuid_original_report',selected/'tests/oneshot_interpreter/reports.py')
    view=load('oneshot_cpuid_view',selected/'tests/oneshot_failure/record.py')
    emitter=load('oneshot_cpuid_emitter',selected/'tests/cpuid_nx/interpreter.py')
    regemitter=load('oneshot_cpuid_registered_emitter',fixture/'registered_interpreter.py')
    regcheck=load('oneshot_cpuid_registered_check',selected/'tests/oneshot_registered/check.py')
    regcomplete=load('oneshot_cpuid_registered_complete',selected/'tests/oneshot_registered/reports.py')
    namespace=load('oneshot_cpuid_namespace',root/'tools/page-entry/namespace.py')
    policy=load('oneshot_cpuid_native_policy',selected/'tests/oneshot_integrated/check.py')
    for name in ('fixture.S','registered.S','linker.ld','registered.ld','layout.py','observe.inc','launch.py'):pin(fixture/name)
    observed={}
    for mode in ('observed','registered'):
        d=output/mode;observed[mode]=d
        try:state[mode+'_adapters']=prepare.prepare(root,d,pin,mode=='registered')
        finally:
            for directory in (d,d.with_name(d.name+'-owners')):
                if directory.exists():
                    for p in sorted(directory.iterdir()):state['generated'][str(p.relative_to(output))]=retain('partial combined source '+p.name,p)
    tools={n:pin(shutil.which(n,path=ENV['PATH']))for n in('gdb','objdump')}
    cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    state['tools']={k:dict(path=str(v),**fact(v))for k,v in tools.items()}
    for name,path in tools.items():
        _,out,err=run('oneshot-cpuid-'+name+'-version',[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual tool identity '+name)
    recipe=pin(selected/'build-oneshot-cpuid-nx.sh');argv=commands(recipe,builder,output,products['archive'],pin)[0]
    units=[str(selected.parent/p)for p in UNITS]
    macros=MACROS|{'-DLI2_ONESHOT_INITIAL_INTERPRETER=1','-DLI2_CPUID_NX_ONLY=1','-DLI2_ONESHOT_CPUID_NX=1'}
    need([x for x in argv if x.endswith(('.c','.S'))]==units and argv[-2:]==['-o',str(output/'bridge-oneshot-cpuid-nx.so')]and
         set(x for x in argv if x.startswith('-DLI2_'))==macros and sum(x.startswith('-DLI2_')for x in argv)==len(macros)and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact raw combined 16-TU release recipe and full closed macro set')
    state['recipe']=fact(recipe)
    def metadata(label,path,dwarf=False):
        binary(path);bridge_check(path)
        _,out,err=run(label+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
        need(out==err==b'','actual complete bridge has no unresolved import')
        _,symbols,err=run(label+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment);need(not err,'actual symbols')
        _,assembly,err=run(label+'-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',path],profile='inspect',env=builder.environment)
        need(not err,'actual reset body');result=dict(path=str(path),**fact(path),reset=hidden_memset(path,body_check(path,symbols,assembly,'fast',symbol_name='memset')))
        if dwarf:
            _,out,err=run(label+'-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
                '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(path),'-x',fixture/'layout.py'],env=gdb_env)
            need(not err,'actual file-only DWARF');layout=json.loads(out);result['layout']=layout;layout['symbols']={}
            for symbol in('selected_oneshot_owners','selected_session','raw','selected_oneshot_frame_range','li2_lifecycle_oneshot_transfer','li2_lifecycle_oneshot_advance','li2_lifecycle_oneshot_observe','li2_lifecycle_oneshot_release'):
                rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[symbol.encode()]]
                need(len(rows)==1 and len(rows[0])==4 and rows[0][2]in(b'b',b'B',b't',b'T'),'actual unique callback/owner '+symbol);layout['symbols'][symbol]=int(rows[0][0],16)
            _,_,ph=elf(path);total=0
            for symbol in('oi_record','oc_record'):
                rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[symbol.encode()]];n=layout['types'][symbol]['bytes'];total+=n
                need(len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b'and int(rows[0][1],16)==n and
                     sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+n<=p[3]+p[6]for p in ph)==1,'complete actual writableNX record '+symbol)
            need(total+regcheck.RECORD_BYTES<16<<20,'complete record stream below unchanged cap')
            if label.endswith('registered'):
                rows=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[b'orf_record']]
                need(len(rows)==1 and len(rows[0])==4 and rows[0][2]==b'b'and int(rows[0][1],16)==regcheck.RECORD_BYTES and
                     sum(p[0]==1 and p[1]==6 and p[3]<=int(rows[0][0],16)<int(rows[0][0],16)+regcheck.RECORD_BYTES<=p[3]+p[6]for p in ph)==1,
                     'whole unchanged registered record extent')
        return result
    bridges={};layouts={}
    for mode in('production','observed','registered','initial-disabled'):
        name='oneshot-cpuid-'+mode;actual=argv.copy();actual_units=units.copy();target=output/(mode+'.so');actual[-1]=str(target)
        if mode in observed:
            prior=str(selected/'runtime_loader.c');new=str(observed[mode]/'runtime_loader.c')
            need(actual.count(prior)==1,'one actual runtime observation replacement');actual=[new if p==prior else p for p in actual];actual_units=[new if p==prior else p for p in actual_units]
        if mode=='initial-disabled':
            extra=[str(selected/'tests/cpuid_nx'/n)for n in('disabled_entry.S','disabled_entry.c')]
            actual[-2:-2]=extra+['-Wl,-e,nx_disabled_entry'];actual_units+=extra
        row=dict(name=name,argv=actual,recipe=fact(recipe),translation_units=len(actual_units),archive=fact(products['archive']));state['builds'].append(row)
        headers(name+'-headers',actual,actual_units,products['archive'],builder,pin,aliases,run,row)
        try:run(name+'-link',actual,profile='oneshot_cpuid_build',env=builder.environment)
        finally:row['partial']=retain(name,target)
        row['artifact']=metadata(name,target,mode in observed);bridges[mode]=target
        if mode in observed:layouts[mode]=row['artifact']['layout']
        if mode=='initial-disabled':
            _,out,err=run(name+'-bootstrap',[tools['objdump'],'-d','-w','-M','att','--disassemble=_start',target],profile='inspect',env=builder.environment)
            need(not err,'actual original bootstrap bytes');matches=re.findall(rb'^\s*([0-9a-f]+):\s+0f a2\s+cpuid\s*$',out,re.M);need(len(matches)==2,'both original bootstrap CPUIDs')
            _,out,err=run(name+'-entry',[builder.tools['nm'],'-n',target],profile='inspect',env=builder.environment);need(not err,'actual bootstrap symbols')
            syms={v[2].decode():int(v[0],16)for line in out.splitlines()if len(v:=line.split())==3};_,h,_=elf(target)
            need(h[4]==syms['nx_disabled_entry']and syms['_start']<int(matches[0],16),'actual preentry control')
            state['bootstrap_offset']=int(matches[0],16)-syms['_start']
    legacy_units=[x for x in receipt['oneshot_interpreter']['units']if x['mode']=='production']
    need(len(legacy_units)==1,'mandatory actual legacy production bridge');legacy=pin(binary(Path(legacy_units[0]['argv'][-1])))
    need(fact(legacy)==legacy_units[0]['artifact'],'unchanged qualified legacy production bridge')
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(fixture/'launch.py')
    def execute(name,original,lane,interp,library,bridge=None,denial='none'):
        directory=output/name;directory.mkdir();native=lane=='native'
        row=dict(name=name,lane=lane,denial=denial,status='failed',error=None);state['cases'].append(row)
        objects,description=namespace.plan(original,[library],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
        for item in objects:
            need(fact(pin(item['path']))['sha256']==H(item['bytes']),'actual complete namespace input')
            for alias in item['names']:need(pin(Path(library)/alias)==pin(item['path']),'actual dependency alias')
        row['namespace_plan']=description
        prep=directory/'preparation.json';ns=directory/'namespace';carrier=directory/'carrier'
        argv=[builder.tools['python'],launch_tool,'--mode','native'if native else'gated','--policy','raw','--deny',denial,
              '--original',original,'--library-root',library,'--preparation',prep,'--record-fd','{record_fd}']
        if not native:
            try:
                _,out,err=run(name+'-make',[builder.tools['python'],carrier_tool,'make',original,bridge,carrier],env=ENV)
                need(not err,'actual carrier creation stderr')
            finally:row['carrier']=retain('partial carrier '+name,carrier)
            binary(carrier);v=json.loads(out)
            need(v['original_sha256']==fact(original)['sha256']and v['interpreter_sha256']==fact(interp)['sha256']and
                 v['bridge_sha256']==fact(bridge)['sha256']and v['carrier_sha256']==fact(carrier)['sha256'],'actual all carrier identities')
            argv+=['--carrier',carrier,'--namespace',ns]
        row['invocation_attempted']=True
        try:command,out,err=run(name,argv,profile='oneshot_cpuid',expected=None,env=ENV,record=True)
        except BaseException as exc:
            row['error']=type(exc).__name__+': '+str(exc)
            actual=[x for x in receipt.get('commands',[])if x['name']==name]
            if actual:row.update({k:actual[-1][k]for k in('exit','pid','captures')if k in actual[-1]})
            raise
        finally:
            for p in(prep,private/(name+'.record'),ns/'namespace.json',ns/'launch.json'):retain('partial launch '+name+' '+p.name,p)
        row.update(exit=command['exit'],pid=command['pid'],captures=command['captures'])
        actual=json.loads(pin(binary(prep)).read_bytes());row['preparation']=actual;rp=pin(binary(private/(name+'.record')))
        mask=oi.MASK if native else 0
        need(actual['mask']==mask and [x['signal']for x in actual['dispositions']]==[x for x in range(1,65)if x not in(9,19)]and
             all(x['after']==0 for x in actual['dispositions'])and actual['argv']==[str(original)]and
             actual['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
             actual['observer']==dict(fd=3,device=rp.stat().st_dev,inode=rp.stat().st_ino)and actual['policy']=='raw'and
             actual['denial']==denial and actual['installed']==(denial!='none')and actual['filter']==denial_filter(denial),
             'actual declared native/bridge mask, signal reset, argv/environment, outer denial and FD identity')
        if not native:
            sealed=json.loads(pin(binary(ns/'namespace.json')).read_bytes());started=json.loads(pin(binary(ns/'launch.json')).read_bytes())
            need(sealed['original_sha256']==fact(original)['sha256']and sealed['interpreter_sha256']==fact(interp)['sha256']and
                 sealed['original']==str(original)and len(sealed['objects'])==len(objects),'actual complete sealed namespace')
            fds=[]
            for a,item in zip(sealed['objects'],objects,strict=True):
                need(a['names']==item['names']and a['sha256']==H(item['bytes'])and a['size']==len(item['bytes'])and a['seals']==namespace.SEALS and
                     a['device']>0 and a['inode']>0 and type(a['fd'])is int and a['fd']>3,'actual immutable dependency/descriptor')
                fds.append(str(a['fd']))
                for alias in a['names']:
                    p=ns/alias;value='/proc/self/fd/'+str(a['fd']);need(p.is_symlink()and os.readlink(p)==value,'actual namespace descriptor alias')
                    receipt.setdefault('oneshot_cpuid_namespace_aliases',{})[str(p)]=value
            need(len(fds)==len(set(fds)),'unique actual dependency descriptors')
            environment={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'};environment.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(fds))
            need(started['argv']==[str(original)]and started['environment']==environment and started['carrier_sha256']==fact(carrier)['sha256']and
                 started['carrier_size']==fact(carrier)['bytes']==row['carrier']['bytes'],'closed raw-profile launch; no provider environment')
        return row,command,out,err,rp.read_bytes()
    def emit(label,emitter):
        d=output/label;paths=(d/emitter.SONAME[:-1].decode(),d/'metadata.S')
        try:need(emitter.emit(d)==paths,'fixed actual emitter outputs')
        finally:
            for p in paths:state['generated'][str(p.relative_to(output))]=retain('partial actual interpreter '+label,p)
        for p in paths:pin(binary(p))
        return paths
    interpreter,metadata_source=emit('finite-interpreter',emitter)
    def fixture_build(name,units,flags,linker):
        directory=output/name;directory.mkdir();original=directory/'original';row=dict(name=name,status='failed');state['programs'].append(row)
        units=[pin(p)for p in units]
        _,out,err=run(name+'-headers',[builder.tools['cc'],*flags,'-M','-MT','oneshot_cpuid',*units],env=builder.environment)
        rules=out.decode().replace('\\\n',' ').splitlines();need(not err and len(rules)==len(units)and all(x.startswith('oneshot_cpuid: ')for x in rules),'all actual fixture include rules')
        row['headers']={str(pin(t)):fact(pin(t))for line in rules for t in shlex.split(line.split(':',1)[1])}
        need(set(map(str,units))<=set(row['headers']),'every actual fixture TU is source-bound')
        argv=[builder.tools['cc'],*flags,'-Wl,-T,'+str(linker)+',-z,max-page-size=4096,--build-id=none,--no-undefined',*units,'-o',original];row['argv']=list(map(str,argv))
        try:run(name+'-link',argv,profile='oneshot_cpuid_build',env=builder.environment)
        finally:row['artifact']=retain('partial fixture '+name,original)
        pin(binary(original));_,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',original],profile='inspect',env=builder.environment)
        need(out==err==b'','actual fixture has no imports');return row,original
    programs={}
    for geometry in(0,1):
        name='oneshot-cpuid-program-'+str(geometry)
        row,original=fixture_build(name,[fixture/'fixture.S',metadata_source],['-nostdlib','-no-pie','-O2','-g','-Wall','-Wextra','-Werror','-DGEOMETRY='+str(geometry)],fixture/'linker.ld')
        info=check.image(original.read_bytes(),interpreter,geometry,policy.native_policy)
        row['image']={k:v for k,v in info.items()if k!='images'}
        row['image']['images']={str(k):{n:v[n]for n in ('entry','loads','bytes','sha256')}for k,v in info['images'].items()}
        row['status']='built';programs[geometry]=(original,info)
        native_output=None
        for lane,bridge,denial in(('native',None,'none'),('legacy',legacy,'none'),('observed',bridges['observed'],'none'),('denied',bridges['observed'],'both')):
            case,command,out,err,record=execute(name+'-'+lane,original,lane,interpreter,interpreter.parent,bridge,denial)
            need(command['exit']==0,'actual successful finite interaction');check.output(out,info)
            if lane=='native':need(not err and not record,'native complete silent observer baseline');native_output=out
            elif lane=='legacy':
                need(not record,'unobserved legacy bridge remains unobserved');parsed=oldreport.reports(err);oldreport.completed(parsed,command['pid'])
                o=parsed['oneshot'];need(o['owners']==o['published']==o['restored']==o['completed']==o['effect_returned']==8 and o['rdtsc_patches']==o['syscall_patches']==4 and
                    parsed['loader']['cpuid']==11,'same finite actual legacy owners/CPUIDs');case['reports']=parsed;case['native_comparison']=check.compare(native_output,out,info)
            else:
                parsed=report.reports(err);case['comparison']=check.cpuid(record,layouts['observed'],info,command['pid'],view,oi,out,main_backing_bytes=case['carrier']['bytes'])
                report.combined(parsed,command['pid'],case['comparison'],True);case['reports']=parsed;case['native_comparison']=check.compare(native_output,out,info)
            case['status']='passed'
    original,info=programs[0]
    case,command,out,err,record=execute('oneshot-cpuid-initial-disabled',original,'initial-disabled',interpreter,interpreter.parent,bridges['initial-disabled'])
    need(command['exit']==125 and out==err==b''and len(record)==128,'actual bootstrap fault remains failed before application entry')
    h=struct.unpack('<16Q',record)
    need(h[:7]==(0x3147504449555043,0,11,11,128,0,0)and h[7]-h[15]==state['bootstrap_offset']and h[8:10]==(13,0)and
         h[11]&0xffff==0x33 and h[12:15]==(0,1,0xa20f),'genuine disabled original bootstrap CPUID at exact emitted offset')
    case['operation']=dict(status='failed',genuine_bootstrap_cpuid_fault=True,target_entered=False);case['status']='passed'
    # Reuse the actual unchanged old control ELFs built and qualified above.
    for program in(7,8):
        rows=[p for p in receipt['cpuid_nx']['programs']if p['program']==program];need(len(rows)==1 and rows[0]['status']=='built','actual old control ELF')
        original=pin(binary(Path(rows[0]['argv'][-1])));need(fact(original)==rows[0]['artifact'],'same actual old control bytes')
        ip=pin(namespace.parse(original.read_bytes())['interpreter'])
        case,command,out,err,record=execute('oneshot-cpuid-app-control-'+str(program),original,'production',ip,ip.parent,bridges['production'])
        need(command['exit']==125 and not out and not record,'application control is an actual failed operation, no invented observer')
        parsed=report.reports(err);l,n=parsed['loader'],parsed['native'];arg=0x1011 if program==7 else 0x1012;c=parsed['cpuid_nx']
        need(l['status']==125 and l['failure_code']==205 and l['detail_abs']==arg and l['detail_negative']==0 and
             l['source_syscalls']==1 and l['syscalls']==1 and l['forwarded']==0 and l['cpuid']==3 and n['admissions']==n['closed']>0 and
             n['close_busy']==n['close_error']==0 and c['hardware_entered']==c['hardware_returned']==1 and c['phase']==3 and
             c['next_pc']==c['pc']+2 and c['attempts']==c['samples']==c['commits']==3 and c['raw']==c['result'],
             'exact actual pre-forward control denial and CPUID/native prefix')
        o=parsed['oneshot'];need(o['owners']==o['published']==o['restored']==o['effect_started']==1 and o['completed']==o['effect_returned']==0 and o['active_phase']==7,
             'actual restored syscall terminal prefix; no returned effect claimed')
        case['reports']=parsed;case['operation']=dict(status='failed',failure_code=205,forwarded=0);case['status']='passed'
    original=pin('/bin/true');interp=pin(namespace.parse(original.read_bytes())['interpreter']);ordinary_images=oi.image(original.read_bytes(),interp.read_bytes())
    # Old ordinary native+legacy+observed-legacy three lanes remain above. These
    # two run the exact same system-linked ELF under the new combined bridge.
    for mode in('production','observed'):
        case,command,out,err,record=execute('oneshot-cpuid-ordinary-'+mode,original,mode,interp,library_root,bridges[mode])
        need(command['exit']==0 and not out,'actual ordinary true completion and exact empty stdout')
        parsed=report.reports(err)
        if mode=='production':need(not record,'production observer stream remains empty')
        else:case['comparison']=check.cpuid(record,layouts[mode],ordinary_images,command['pid'],view,oi,out,ordinary=True)
        report.combined(parsed,command['pid'],case.get('comparison'))
        o=parsed['oneshot']
        need(parsed['loader']['cpuid']==parsed['cpuid_nx']['commits']==38 and
             o['owners']==o['published']==o['restored']==o['effect_started']==o['effect_returned']==o['completed']==8 and
             o['rdtsc_patches']==2 and o['syscall_patches']==6 and o['active_phase']==0,
             'both fixed ordinary lanes require all38 CPUIDs and all eight returned owners: two clocks and six syscalls')
        case['reports']=parsed;case['status']='passed'
    interp,meta=emit('registered-interpreter',regemitter)
    row,original=fixture_build('oneshot-cpuid-registered-program',[fixture/'registered.S',meta],
        ['-nostdlib','-pie','-O2','-g','-Wall','-Wextra','-Werror','-Wl,--dynamic-linker='+str(interp)],fixture/'registered.ld')
    info=regcheck.elf(original.read_bytes(),str(interp));check.registered_setup_image(info);row['image']=info;row['status']='built'
    registered_images={1:oi.elf(original.read_bytes()),2:oi.elf(interp.read_bytes())}
    b=interp.read_bytes();need(len(b)==12288 and b[4096:4103]==bytes.fromhex('0fa2e9f90f0000')and not any(b[4103:8192])and
         b[8192:8192+len(regemitter.CODE)]==regemitter.CODE and not any(b[8192+len(regemitter.CODE):])and
         [(p[1],p[2],p[3],p[5],p[6])for p in registered_images[2]['loads']]==[(4,0,0,4096,4096),(5,4096,4096,8192,8192)]and
         policy.native_policy(b[8192-14:])==0 and regemitter.CODE[:2]==bytes.fromhex('90fc'),
         'actual CPUID-first interpreter, OLD_STEP NOP then clean AT_ENTRY helper/left halo and explicit end-of-RX boundary')
    outcomes={}
    for mode in('native','registered'):
        case,command,out,err,record=execute('oneshot-cpuid-registered-'+mode,original,mode,interp,interp.parent,None if mode=='native'else bridges[mode])
        need(command['exit']==0,'actual successful registered fallback');case['output']=regcheck.output(out,command['pid'])
        if mode=='native':need(not err and not record,'native genuine registration, no bridge observation')
        else:
            parsed=report.reports(err);regcomplete.completed(parsed,command['pid'])
            c=parsed['cpuid_nx'];need(c['hardware_entered']==c['hardware_returned']==1 and c['phase']==3 and
                 c['attempts']==c['samples']==c['commits']==parsed['loader']['cpuid']==1 and c['raw']==c['result'],
                 'actual first-interpreter CPUID complete before registration and unchanged four fallback sites')
            case['registered_comparison']=regcheck.record(record[:regcheck.RECORD_BYTES],info,command['pid'],out,parsed['rseq'])
            case['comparison']=check.cpuid(record[regcheck.RECORD_BYTES:],layouts[mode],registered_images,command['pid'],view,oi,out,registered=True,registration=parsed['rseq'])
            case['reports']=parsed
        outcomes[mode]=(out,command['pid']);case['status']='passed'
    left,right=outcomes['native'][0],outcomes['registered'][0]
    need(left[:21]==right[:21]and left[45:]==right[45:]==bytes(8),'unchanged exact registered source/marker/result; actual clock/PID fields separately checked')
    state['registered_pair']=dict(actual_processes=2,registered_fallbacks=4,owners=0)
    need(len(state['cases'])==15 and all(c['status']=='passed'for c in state['cases']),'all8 finite,1 bootstrap failure,2 control failures,2 ordinary and2 registered actual cases')
    finalize(receipt);state['status']='passed'

def finalize(receipt):
    need(all(Path(p).is_symlink()and os.readlink(p)==v for p,v in receipt.get('oneshot_cpuid_namespace_aliases',{}).items()),'all actual combined namespace aliases remain unchanged')

def summary(receipt):
    s=receipt.get('oneshot_cpuid',{});cases=s.get('cases',[]);actual=closed=accepted=0;rows=[]
    for c in cases:
        commands=[x for x in receipt.get('commands',[])if x.get('name')==c['name']and x.get('profile')=='oneshot_cpuid']
        command=commands[0]if len(commands)==1 and type(commands[0].get('pid'))is int and commands[0]['pid']>0 else None
        invoked=command is not None;complete=invoked and command.get('reaped')is True and type(command.get('exit'))is int and command.get('timed_out')is False and not command.get('error')and not command.get('cleanup_errors')
        actual+=invoked;closed+=complete;accepted+=int(complete and c.get('status')=='passed'and c.get('pid')==command['pid']and type(c.get('exit'))is int and c['exit']==command['exit'])
        comparison=c.get('comparison',{});counts={k:v for k,v in comparison.items()if type(v)in(int,bool)}
        rows.append(dict(name=c['name'],lane=c['lane'],status=c['status'],exit=c.get('exit'),invoked=invoked,closed=bool(complete),
            operation=c.get('operation'),counts=counts,registered=c.get('registered_comparison'),
            capture_count=len(c.get('captures',{})),capture_bytes=sum(v['bytes']for v in c.get('captures',{}).values()),
            captures_sha256=H(json.dumps(c.get('captures',{}),sort_keys=True,separators=(',',':')).encode()),
            error_type=c.get('error','').split(':',1)[0]if c.get('error')else None))
    return dict(status=s.get('status','unexecuted'),qualified=receipt.get('status')=='passed'and s.get('status')=='passed'and accepted==15,
        planned_processes=15,attempted_cases=len(cases),actual_processes=actual,closed_processes=closed,accepted_cases=accepted,
        failed_operations=sum(c.get('operation',{}).get('status')=='failed'for c in cases),cases=rows,
        full_reports_sha256=H(json.dumps([c.get('reports')for c in cases],sort_keys=True,separators=(',',':')).encode()),
        full_b2_qualification=False,performance_credit=False)
