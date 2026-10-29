"""All22 fixed pair-owner cases under the unchanged Build/invoke owner.

Original registered16/boundary4 and same-revision6/49/17 stay mandatory in
the enclosing runner. Expected refusal is qualified only as its exact prefix.
"""
import hashlib,importlib.util,json,os,shlex,shutil
from pathlib import Path
from page_selected import fact,need,elf
from page_selected_repeat_lease_ls import UNITS,MACROS as ORIGINAL_MACROS
MACROS=('NATIVE_PAIR',)+ORIGINAL_MACROS
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
BOUNDS={'native_pair':[5,512<<20,16<<20,15],
        'native_pair_build':[30,512<<20,16<<20,60]}
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',PYTHONDONTWRITEBYTECODE='1')
PROFILES=tuple((i,c)for i in range(21)for c in((0,1)if i==16 else(0,)))
NATIVE=tuple(125 if i==10 else 0 for i,c in PROFILES)
GATED=tuple(125 if i in (*range(10,19),20)else 0 for i,c in PROFILES)
UNSAFE={(14,0),(16,1)}
READER_CONTROLS=(30,30,30,30,30,30,30,30,30,30,30,39,31,31,28,33,31,28,31,31,30,31)
CONTROL_CLASSES={'10':'actual read fault','11':'actual tgkill','12':'actual mprotect denial',
    '13':'supplied sync return','14':'supplied actual registered-word mutation',
    '15':'actual writable private alias','16.0':'supplied page generation',
    '16.1':'supplied registration epoch','17':'supplied owner copy',
    '18':'supplied private counter overflow','19':'actual blocked halo fallback','20':'actual sync denial'}
VIEW_NAMES=('runtime_loader.c','native_controller.inc','native_pair_controller.inc',
    'native_epoch.c','native_pair_control.inc','lifecycle_loader.c',
    'native_pair_lifecycle.inc','native_lifecycle.inc','rseq_guard.c','rseq_native_pair.inc')
GENERATED=VIEW_NAMES+('native_pair_observe.inc','native_pair_record.h',
    'native_pair_runtime_record.h','native_pair_hooks.h')
H=lambda b:hashlib.sha256(b).hexdigest()
def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())


def reader_control_count(values,ordinal):
    need(type(ordinal)is int and 0<=ordinal<len(READER_CONTROLS), 'exact supplied-control profile index')
    expected=READER_CONTROLS[ordinal]
    keys={'supplied_reader_controls','supplied_reader_refusals','common_controls','profile_controls','native_operation_credit'}
    need(type(values)is dict and keys<=values.keys()and len(values)==expected+len(keys)and
         all(type(v)is int for v in values.values())and
         values['supplied_reader_controls']==values['supplied_reader_refusals']==expected and
         values['common_controls']==22 and values['profile_controls']==expected-22 and
         values['native_operation_credit']==0 and all(v==1 for k,v in values.items()if k not in keys),
         'complete exact copied-record refusals, separate from native operation credit')
    return expected


def qualify(builder,products,root,private,library_root,pin,binary,aliases,run,receipt):
    root,private=Path(root),Path(private);selected=root/'tools/page-entry/selected';fixture=selected/'tests/native_pair'
    output=private/'native-pair';output.mkdir();cpu=next(iter(os.sched_getaffinity(0)))
    state=receipt['native_pair_fixture']=dict(status='failed',cases=[],programs=[],builds=[],generated={},archive=fact(products['archive']))
    for key,value in BOUNDS.items():need(receipt['bounds'].get(key)==value,'exact registered-native bound '+key)
    need(os.sched_getaffinity(0)=={cpu},'one reserved CPU for all actual boundary subjects')
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return fact(binary(path))
        except BaseException as exc:receipt['final_errors'].append(label+': '+type(exc).__name__+': '+str(exc))
        return None
    prepare=load('native_pair_prepare',fixture/'prepare.py');check=load('native_pair_check',fixture/'check.py')
    controls=load('native_pair_reader_controls',fixture/'controls.py')
    reports=load('finite_pair_reports',root/'evaluation/inprocess/page_native_pair_reports.py')
    images=load('native_pair_interpreter',selected/'tests/provider_launch/interpreter.py')
    namespace=load('native_pair_namespace',root/'tools/page-entry/namespace.py')
    policy=load('native_pair_policy',selected/'tests/oneshot_integrated/check.py')
    need(len(PROFILES)==22 and len(set(PROFILES))==22 and NATIVE.count(125)==1 and GATED.count(125)==11,
         'fixed22 profiles with11 completed gated operations and11 required refusals')
    need(len(READER_CONTROLS)==len(PROFILES)and sum(READER_CONTROLS)==674,
         'fixed extra supplied-reader population; no additional native subjects')
    for name in ('expected.json','owners.py','terminal.py','fixture.S','native_reference.c','record.h','runtime_record.h','hooks.h',
                 'linker.ld','build.sh','layout.py','observe.inc'):pin(fixture/name)
    adapters=json.loads(pin(fixture/'ADAPTERS.json').read_bytes())
    need(adapters['version']==1 and tuple(x['name']for x in adapters['views'])==VIEW_NAMES,
         'exact ten complete source views, no caller-selected observer')
    observed=output/'observed'
    try:state['adapters']=prepare.prepare(root,observed,pin)
    finally:
        for name in GENERATED:state['generated'][name]=retain('partial observation '+name,observed/name)
    tools={n:pin(shutil.which(n,path=ENV['PATH']))for n in ('gdb','objdump')}
    state['tools']={n:dict(path=str(p),**fact(p))for n,p in tools.items()}
    cache=output/'gdb-cache';cache.mkdir();gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    for name,path in tools.items():
        _,out,err=run('native-pair-'+name+'-version',[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
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
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns the exact pair archive')
    recipe_path=pin(selected/'build-native-pair.sh');templates=recipe(recipe_path,'"$cc_bin"')
    need(len(templates)==1,'one exact pair release link recipe')
    argv=expand(templates[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':selected,
        '$parent_dir':selected.parent,'$archive':archive,'$output':output})
    units=[str(selected.parent/p)for p in UNITS]
    need(argv[-2:]==['-o',str(output/'bridge-native-pair.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and len(units)==18 and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in MACROS]and len(MACROS)==20 and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact18-TU20-macro pair release recipe; old cohorts retain their separate recipes')
    for kind in('unobserved','observed'):
        name='native-pair-'+kind;actual=argv.copy();sources=units.copy();bridge=output/(kind+'.so');actual[-1]=str(bridge)
        if kind=='observed':
            for basename in('runtime_loader.c','lifecycle_loader.c','native_epoch.c','rseq_guard.c'):
                old,new=str(selected/basename),str(observed/basename)
                need(actual.count(old)==1,'one exact observation translation-unit replacement')
                actual=[new if x==old else x for x in actual];sources=[new if x==old else x for x in sources]
        row=dict(name=name,recipe=fact(recipe_path),argv=actual,archive=fact(products['archive']),translation_units=len(sources));state['builds'].append(row)
        headers(name+'-headers',actual,sources,products['archive'],builder,pin,aliases,run,row)
        if kind=='observed':
            need({str(observed/n)for n in GENERATED}<=set(row['headers']),
                 'all14 actual observation sources in the compiler include closure')
        try:run(name+'-link',actual,profile='native_pair_build',env=builder.environment)
        finally:row['artifact']=retain(name,bridge)
        row['inspection']=inspect(name,bridge,'npf_record'if kind=='observed'else None,True)
        if kind=='observed':gated_bridge=bridge;gated_layout=row['inspection']['layout']
    interpreter=output/'interpreter'/'li2-provider-entry.so';metadata=output/'interpreter'/'metadata.S'
    try:need(images.emit(output/'interpreter')==(interpreter,metadata),'unchanged actual interpreter emitter paths')
    finally:
        for path in(interpreter,metadata):state['generated'][path.name]=retain('partial actual interpreter',path)
    for path in(interpreter,metadata):pin(binary(path))
    bridge_image=check.bridge(gated_bridge.read_bytes())
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(selected/'tests/rseq_native/launch.py')
    def execute(ordinal,case,control,original,image,lane):
        native=lane=='native';name='native-pair-'+str(case)+'-'+str(control)+'-'+lane;directory=output/name;directory.mkdir()
        row=dict(name=name,index=case,control=control,ordinal=ordinal,lane=lane,status='failed',operation_status='unobserved',expected_exit=(NATIVE if native else GATED)[ordinal],error=None)
        state['cases'].append(row)
        objects,description=namespace.plan(original,[interpreter.parent],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
        row['namespace_plan']=description;row['dependencies']=[]
        for item in objects:
            need(fact(pin(item['path']))['sha256']==H(item['bytes']),'complete actual namespace dependency source')
            row['dependencies'].append(dict(names=item['names'],**fact(pin(item['path']))))
            for alias in item['names']:pin(interpreter.parent/alias)
        prep=directory/'preparation.json';ns=directory/'namespace';carrier=directory/'carrier'
        argv=[builder.tools['python'],launch_tool,'--mode',lane,'--original',original,'--library-root',interpreter.parent,
            '--preparation',prep,'--record-fd','{record_fd}']
        if not native:
            try:
                _,out,err=run(name+'-make',[builder.tools['python'],carrier_tool,'make',original,gated_bridge,carrier],env=ENV)
                need(not err,'actual carrier construction stderr')
            finally:retain('partial actual carrier '+name,carrier)
            binary(carrier);v=json.loads(out)
            need(v['original_sha256']==fact(original)['sha256']and v['bridge_sha256']==fact(gated_bridge)['sha256']and
                 v['interpreter_sha256']==fact(interpreter)['sha256']and v['carrier_sha256']==fact(carrier)['sha256'],'actual same-original carrier identities')
            row['carrier']=v;row['sealed_carrier_bytes']=fact(carrier)['bytes'];argv+=['--carrier',carrier,'--namespace',ns]
        row['invocation_attempted']=True
        try:
            command,out,err=run(name,argv,profile='native_pair',expected=None,env=ENV,record=True)
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
        need(actual['mode']==lane and actual['mask']==0 and actual['affinity']==[cpu]and
             [x['signal']for x in actual['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and
             all(x['after']==0 for x in actual['dispositions'])and actual['argv']==app_argv and
             actual['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
             actual['observer']==dict(fd=3,device=record_path.stat().st_dev,inode=record_path.stat().st_ino),
             'actual reset signals/mask, same CPU, exact argv/environment and observed FD identity')
        if not native:
            sealed=json.loads(pin(binary(ns/'namespace.json')).read_bytes());started=json.loads(pin(binary(ns/'launch.json')).read_bytes())
            need(all(sealed[k]==v for k,v in description.items())and sealed['directory']==str(ns)and
                 sealed['schema_version']==1 and sealed['status']=='prepared_not_executed'and
                 sealed['original']==str(original)and sealed['original_sha256']==fact(original)['sha256']and
                 sealed['interpreter_sha256']==fact(interpreter)['sha256']and len(sealed['objects'])==len(objects),'actual complete original namespace')
            fds=[]
            for a,item in zip(sealed['objects'],objects,strict=True):
                need(type(a['fd'])is int and a['fd']>2 and a['fd']not in fds and a['source']==str(item['path'])and
                     a['names']==item['names']and a['needed']==item['info']['needed']and
                     a['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and
                     a['sha256']==H(item['bytes'])and a['size']==len(item['bytes'])and
                     a['seals']==namespace.SEALS and a['device']>0 and a['inode']>0,'actual immutable complete dependency object')
                fds.append(a['fd'])
                for alias in a['names']:
                    path=ns/alias;value='/proc/self/fd/'+str(a['fd'])
                    need(path.is_symlink()and os.readlink(path)==value,'actual retained namespace alias')
                    receipt.setdefault('native_pair_namespace_aliases',{})[str(path)]=value
            env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
            env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(str(a['fd'])for a in sealed['objects']))
            need(started==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
                carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],argv=app_argv,
                environment=env,dependency_fds=fds),'exact actual default-rseq launch and complete carrier/environment/FD join')
            if (case,control)in UNSAFE:
                need(err==b'' and command['exit']==125,'actual unsafe exit has empty stderr, never a fabricated terminal')
                row['reports']=None
            else:
                row['reports']=reports.reports(err)
                need(row['reports']['loader']['status']==command['exit'],'actual report and process outcome agree')
        else:need(err==b'','actual native fixture stderr is empty')
        need(len(out)==(20480 if command['exit']==0 else 0),'exact complete semantic output or empty failed-operation output')
        row['operation_status']='completed'if command['exit']==0 else'failed'
        row['status']='captured'
        return row,out,record
    fixture_recipe=pin(fixture/'build.sh');templates=recipe(fixture_recipe,'"$cc_bin"');need(len(templates)==1,'one source-bound actual fixture link recipe')
    for ordinal,(case,control)in enumerate(PROFILES):
        name='native-pair-program-'+str(case)+'-'+str(control);directory=output/name;directory.mkdir();original=directory/'original'
        values={'$cc_bin':builder.tools['cc'],'$fixture_dir':fixture,'$metadata':metadata,'$output':original,'$case_number':case,'$control':control}
        argv=expand(templates[0],values);units=[str(fixture/'fixture.S'),str(fixture/'native_reference.c'),str(metadata)]
        need([x for x in argv if x.endswith(('.c','.S'))]==units and argv[-2:]==['-o',str(original)]and
             argv.count('-DRN_CASE='+str(case))==1 and argv.count('-DNP_CONTROL='+str(control))==1 and
             [x for x in argv if x.startswith('-D')]==['-DRN_CASE='+str(case),'-DNP_CONTROL='+str(control)]and
             all(x in argv for x in('-O2','-g','-Werror','-nostdlib','-fno-pie','-no-pie','-ffreestanding','-fno-builtin','-mgeneral-regs-only','-mcmodel=large')),
             'actual original fixture recipe and exact literal case')
        row=dict(index=case,control=control,ordinal=ordinal,recipe=fact(fixture_recipe),argv=argv,status='failed');state['programs'].append(row)
        flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
        _,out,err=run(name+'-headers',[builder.tools['cc'],*flags,'-M','-MT','native_pair',*units],env=builder.environment)
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(rules)==3 and all(x.startswith('native_pair: ')for x in rules),'actual complete three-TU native fixture include closure')
        row['headers']={str(pin(t)):fact(pin(t))for line in rules for t in shlex.split(line.split(':',1)[1])}
        need(set(units)<=set(row['headers']),'all linked fixture sources in actual include closure')
        try:run(name+'-link',argv,profile='native_pair_build',env=builder.environment)
        finally:row['artifact']=retain('partial actual native fixture '+name,original)
        pin(binary(original));row['inspection']=inspect(name,original,'npf_native_record')
        image=check.elf(original.read_bytes(),interpreter,case,control,policy.native_policy);row['image']=image;row['status']='built'
        native,nout,nrecord=execute(ordinal,case,control,original,image,'native')
        gated,gout,grecord=execute(ordinal,case,control,original,image,'gated')
        image['bridge']=bridge_image
        image['sealed_carrier_bytes']=gated['sealed_carrier_bytes']
        need(type(image['sealed_carrier_bytes'])is int and image['sealed_carrier_bytes']>image['original_bytes'],
             'actual appended sealed carrier extent, independently joined to launch metadata')
        row['comparison']=check.pair(nrecord,grecord,nout,gout,{'native':row['inspection']['layout'],'gated':gated_layout},
            image,native['pid'],gated['pid'],cpu,native['exit'],gated['exit'])
        comparison=row['comparison']
        need(native['pid']!=gated['pid']and type(comparison)is dict and
             all(type(comparison[k])is int for k in('qualified_case','completed_pair','required_refusal','native_events','gated_events','native_exit','gated_exit'))and
             comparison['qualified_case']==1 and comparison['completed_pair']==int(gated['exit']==0)and
             comparison['required_refusal']==int(gated['exit']!=0)and comparison['native_events']>0 and comparison['gated_events']>0 and
             comparison['native_exit']==native['exit']==NATIVE[ordinal]and comparison['gated_exit']==gated['exit']==GATED[ordinal],
             'actual independent per-lane state and exact completed/refused operation distinction')
        gated['terminal']=check.terminal(gated['reports'],grecord,gated_layout,image,gated['pid'],gated['exit'])
        need(type(gated['terminal'])is dict and gated['terminal'] and
             all(type(v)is int for v in gated['terminal'].values()),'actual finite terminal numeric joins')
        row['reader_controls']=controls.validate(check,nrecord,grecord,nout,gout,
            {'native':row['inspection']['layout'],'gated':gated_layout},image,
            native['pid'],gated['pid'],cpu,native['exit'],gated['exit'],gated['reports'])
        reader_control_count(row['reader_controls'],ordinal)
        native['events']=comparison['native_events'];gated['events']=comparison['gated_events']
        native['status']=gated['status']=row['status']='passed'
    need(len(state['cases'])==44 and all(c['status']=='passed'for c in state['cases'])and
         len(state['programs'])==22 and all(c['status']=='passed'for c in state['programs'])and
         sum(c['comparison']['completed_pair']for c in state['programs'])==11 and
         sum(c['comparison']['required_refusal']for c in state['programs'])==11,
         'all22 genuine same-ELF cases:11 completed gated operations and11 exact required refusal prefixes')
    need(sum(reader_control_count(p['reader_controls'],p['ordinal'])for p in state['programs'])==674,
         'all674 supplied-reader refusals after every genuine pair and terminal qualification')
    finalize(receipt);state['status']='passed'


def finalize(receipt):
    need(all(Path(p).is_symlink()and os.readlink(p)==value for p,value in receipt.get('native_pair_namespace_aliases',{}).items()),
         'all actual sealed namespace alias observations remain unchanged')


def summary(receipt):
    state=receipt.get('native_pair_fixture',{});cases=state.get('cases',[]);commands=receipt.get('commands',[])
    expected=[(i,c,lane)for i,c in PROFILES for lane in('native','gated')]
    need(len({(c['index'],c['control'],c['lane'])for c in cases})==len(cases)and
         all((c['index'],c['control'],c['lane'])in expected for c in cases),'unique fixed public pair cases')
    def actual(c):
        rows=[x for x in commands if x.get('name')==c['name']and x.get('profile')=='native_pair']
        return rows[0]if len(rows)==1 and type(rows[0].get('pid'))is int and rows[0]['pid']>0 else None
    def closed(row):return row is not None and row.get('reaped')is True and type(row.get('exit'))is int
    accepted=[c for c in cases if c.get('status')=='passed'and closed(actual(c))and
              actual(c)['exit']==c['expected_exit']and not actual(c).get('timed_out')and not actual(c).get('error')and not actual(c).get('cleanup_errors')]
    programs=state.get('programs',[]);qualified=[p for p in programs if p.get('status')=='passed']
    complete=state.get('status')=='passed'and len(accepted)==44 and len(qualified)==22
    if state.get('status')=='passed':
        need(complete and [(c['index'],c['control'],c['lane'])for c in cases]==expected and
             [(p['index'],p['control'])for p in programs]==list(PROFILES)and
             all(c['exit']==actual(c)['exit']and c['pid']==actual(c)['pid']and
                 c['expected_exit']==(NATIVE if c['lane']=='native'else GATED)[c['ordinal']]for c in cases),
             'complete exact22-case qualification before public acceptance')
        need(all(p['comparison']['qualified_case']==1 and
                 p['comparison']['completed_pair']==int(GATED[p['ordinal']]==0)and
                 p['comparison']['required_refusal']==int(GATED[p['ordinal']]!=0)and
                 p['comparison']['native_exit']==NATIVE[p['ordinal']]and p['comparison']['gated_exit']==GATED[p['ordinal']]
                 for p in programs),'public outcomes are actual qualified cases, never failed operations renamed completed')
        need(sum(reader_control_count(p['reader_controls'],p['ordinal'])for p in programs)==674,
             'complete supplied-reader cohort before public qualification; no native credit')
    rows=[]
    for i,c,lane in expected:
        found=[x for x in cases if(x['index'],x['control'],x['lane'])==(i,c,lane)]
        case=found[0]if found else {};command=actual(case)if found else None;cap=command.get('captures',{})if command else{}
        rows.append([i,c,int(lane=='gated'),'qualified'if case.get('status')=='passed'else case.get('status','unexecuted'),case.get('operation_status','unobserved'),
            (NATIVE if lane=='native'else GATED)[PROFILES.index((i,c))],command.get('exit')if command else None,
            case.get('events'),*[cap.get(k,{}).get('bytes')for k in('stdout','stderr','record')],digest(cap)if cap else None])
    return dict(status=state.get('status'),planned_cases=22,planned_subjects=44,attempted_subjects=len(cases),
        actual_subjects=sum(actual(c)is not None for c in cases),closed_subjects=sum(closed(actual(c))for c in cases),
        qualified_subjects=len(accepted),qualified_cases=len(qualified),
        completed_pairs=sum(p['comparison']['completed_pair']for p in qualified),
        required_refusals=sum(p['comparison']['required_refusal']for p in qualified),
        actual_native_fault_references=sum(p['comparison']['native_exit']==125 for p in qualified),
        columns=['case','control','gated','qualification','operation_status','expected_exit','actual_exit','events','stdout_bytes','stderr_bytes','record_bytes','captures_sha256'],
        rows=rows,control_classes=CONTROL_CLASSES,
        required_supplied_reader_controls=674,
        supplied_reader_refusals=sum(reader_control_count(p['reader_controls'],p['ordinal'])for p in qualified),
        reader_control_columns=['case','control','required','qualified_supplied_refusals'],
        reader_control_rows=[[i,c,READER_CONTROLS[o],next((reader_control_count(p['reader_controls'],o)
            for p in qualified if(p['index'],p['control'])==(i,c)),None)]for o,(i,c)in enumerate(PROFILES)],
        reader_controls_sha256=digest([p['reader_controls']for p in qualified]),
        supplied_reader_native_operation_credit=0,
        full_finite_profile=complete,full_b2_complete=False,full_b3_complete=False,
        application_completion=False,performance_credit=False)
