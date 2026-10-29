"""Source-built normal app under the distinct retained-RX REP lease profile.

The enclosing committed-source evaluator owns all commands and cleanup.
The full existing app/native/seed readers and state-before-stress order remain.
"""
import sys
sys.dont_write_bytecode=True
import ctypes,hashlib,importlib.util,json,os,re,shlex,struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools/page-entry'))
from page_selected import ENV,fact,need,save,elf
from page_selected_register_time_build import recipe as recipe_rows
from page_selected_run_reuse_ls import UNITS,MACROS as CACHE_MACROS
MACROS=('REPEAT_RX_LEASE',*CACHE_MACROS)
import page_selected_repeat_lease_app_reports as terminal
from page_selected_register_time_build import headers,bridge_check,recipe,expand
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
import namespace

LANES=(('state','native'),('state','scripted'),('stress','native'),('stress','scripted'))
BOUNDS={'metadata':[30,512<<20,16<<20,60],'build':[30,512<<20,16<<20,60],
        'seed':[5,512<<20,16<<20,15],'reference':[25,512<<20,16<<20,25],
        'app':[30,512<<20,16<<20,60]}
BASE_ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1')
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
H=lambda b:hashlib.sha256(b).hexdigest()

PUBLIC_BOUNDS={'app_'+k:v for k,v in BOUNDS.items()}

def support(builder,root,private,fixture,pin,binary,aliases,run,receipt):
    """Compile the actual original app/DSO, seed, native tracer and byte policy."""
    selected=fixture.parents[1];output=private/'app-inputs';output.mkdir()
    state=receipt['app_input_build']=dict(status='failed',units=[],artifacts={})
    def compile(name,argv,sources,path):
        argv=list(map(str,argv));sources=list(map(str,sources));path=Path(path)
        need(argv[0]==str(builder.tools['cc'])and argv[-2:]==['-o',str(path)]and
             [x for x in argv if x.endswith(('.c','.S'))]==sources and
             all(x in argv for x in('-O2','-g','-Wall','-Wextra','-Werror')),
             'exact source-built normal-app support command')
        unit=dict(name=name,argv=argv,status='failed');state['units'].append(unit)
        # These support programs do not link decoder.a. Observe the same real
        # compiler-M rules without pretending an unused archive is an input.
        flags=[x for x in argv[1:-2]if x not in sources and
               not x.startswith(('-Wl,','-L','-l'))]
        _,out,err=run(name+'-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*sources],env=builder.environment)
        need(not err,'actual support include observation stderr')
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(len(rules)==len(sources)and all(x.startswith('li2_app: ')for x in rules),
             'one complete actual include rule per support translation unit')
        actual={}
        for rule in rules:
            for token in shlex.split(rule.split(':',1)[1]):
                named=Path(token).absolute();resolved=str(pin(named))
                need(str(named)not in aliases or aliases[str(named)]==resolved,'support include alias identity')
                aliases[str(named)]=resolved;actual[resolved]=fact(resolved)
        need(set(sources)<=set(actual),'every support source in real include closure');unit['headers']=actual
        try:run(name+'-link',argv,profile='build',env=builder.environment)
        finally:
            if path.exists()or path.is_symlink():
                unit['artifact']=dict(fact(binary(path)),mode=path.stat().st_mode&0o777)
                state['artifacts'][name]=unit['artifact']
        need(path.stat().st_mode&0o111,'actual executable support artifact')
        _,header,segments=elf(path)
        need(header[2]==62 and all(not(s[0]==1 and s[1]&3==3)for s in segments),
             'actual x86-64 support ELF without writable executable load')
        unit['status']='passed';return binary(path)
    script=pin(fixture/'build.sh');text=script.read_text()
    found=re.findall(r'^common=\(([^\n]*)\)$',text,re.M)
    need(len(found)==1,'one explicit current app common-flag array')
    common=shlex.split(found[0]);rows=recipe(script,'"$cc"')
    need(len(rows)==2 and all(row.count('${common[@]}')==1 for row in rows),
         'exact current DSO and PIE recipe rows')
    state['app_recipe']=fact(script);appdir=output/'original';appdir.mkdir()
    values={'$cc':builder.tools['cc'],'$source_dir':fixture,'$output':appdir}
    paths=[]
    for name,words,names,filename in zip(('app-dso','app-original'),rows,
            (('module.c','machine.S','sites.S'),('app.c','module.c','machine.S','sites.S')),
            ('libli2-provider-app.so','provider-app'),strict=True):
        words=[part for word in words for part in(common if word=='${common[@]}'else[word])]
        argv=expand(words,values);path=appdir/filename
        paths.append(compile(name,argv,[fixture/x for x in names],path))
    dso,original=paths
    reference=pin(fixture/'reference/build.sh');rows=recipe(reference,'"$cc_bin"')
    need(len(rows)==1,'one exact current native tracer recipe')
    tracer=output/'native-reference';state['reference_recipe']=fact(reference)
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$source_dir':fixture/'reference','$output':tracer})
    tracer=compile('app-reference',argv,[fixture/'reference/trace.c'],tracer)
    seed=pin(fixture/'seed_probe/build.sh');rows=recipe(seed,'"${LI2_CC:')
    need(len(rows)==1,'one exact current seed-probe recipe');state['seed_recipe']=fact(seed)
    probe=output/'seed-probe'
    argv=expand(rows[0],{'${LI2_CC:?exact compiler required}':builder.tools['cc'],'$1':fixture/'seed_probe','$2':probe})
    probe=compile('app-seed',argv,[fixture/'seed_probe/probe.c'],probe)
    policy=output/'native-policy.so';source=pin(selected/'native_policy.c');pin(selected/'native_policy.h')
    policy=compile('app-native-policy',[builder.tools['cc'],'-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror',
        '-fPIC','-shared','-Wl,-z,noexecstack,--build-id=none',source,'-o',policy],[source],policy)
    state['status']='passed'
    return original,dso,probe,tracer,policy


def execute(builder,products,root,private,pin,binary,aliases,owned_run,receipt):
    need(Path(root)==ROOT and len(os.sched_getaffinity(0))==1,'exact repository and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));private=Path(private)
    need(cpu==receipt['cpu'],'actual same CPU as enclosing owner')
    r=receipt['app']=dict(status='failed',cases=[],builds=[],error=None,final_errors=receipt['final_errors'],
        external_all_seven_and_masked_cpuid_prerequisites_required=True)
    ns_aliases=receipt['app_namespace_aliases']={}
    def run(name,argv,profile='metadata',expected=0,env=None,record=False):
        need(profile in BOUNDS,'fixed original app process profile')
        return owned_run(name,argv,profile='app_'+profile,expected=expected,env=env,record=record)
    def retain(path):
        if path.exists()or path.is_symlink():return dict(path=str(path),**fact(binary(path)))
        return None
    def load(name,path):
        s=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
    def partial(directory):
        # Only this attempt's named outputs; no recursive discovery or live
        # output from another invocation is consulted.
        for name in ('preparation.json','namespace/namespace.json','namespace/launch.json',
                     'native/record.bin','native/main.elf','native/dso.elf','native/stdout.bin','native/stderr.txt'):
            try:retain(directory/name)
            except BaseException as e:r['final_errors'].append('partial '+name+': '+repr(e))
        ns=directory/'namespace'
        if (ns/'namespace.json').is_file():
            try:
                value=json.loads((ns/'namespace.json').read_bytes())
                for obj in value['objects']:
                    for name in obj['names']:
                        path=ns/name;need(path.is_symlink(),'actual namespace alias exists')
                        ns_aliases[str(path)]=os.readlink(path)
            except BaseException as e:r['final_errors'].append('partial namespace: '+repr(e))
    def namespace_join(directory,original,interpreter,objects,description):
        ns=directory/'namespace';actual=json.loads(binary(ns/'namespace.json').read_bytes())
        need(all(actual[k]==v for k,v in description.items())and actual['directory']==str(ns)and
            actual['schema_version']==1 and actual['status']=='prepared_not_executed'and
            actual['scope']=='explicit_sealed_dependency_namespace'and len(actual['objects'])==len(objects),
            'actual namespace plan, original and interpreter identity')
        fds=[]
        for row,obj in zip(actual['objects'],objects):
            need(row['names']==obj['names']and row['source']==str(obj['path'])and row['needed']==obj['info']['needed']and
                row['descriptive_pt_interp']==(str(obj['info']['interpreter'])if obj['info']['interpreter']else None)and
                row['sha256']==H(obj['bytes'])and row['size']==len(obj['bytes'])and row['seals']==namespace.SEALS and
                type(row['fd'])is int and row['fd']>=3 and row['device']>0 and row['inode']>0,
                'complete actual sealed dependency identity')
            fds.append(row['fd'])
            for name in row['names']:
                path=ns/name;need(path.is_symlink()and os.readlink(path)=='/proc/self/fd/'+str(row['fd'])and
                    ns_aliases[str(path)]==os.readlink(path),'actual retained sealed alias')
        need(len(set(fds))==len(fds),'distinct actual dependency descriptors')
        return actual,fds
    def preparation(directory,row,role,argv):
        value=json.loads(binary(directory/'preparation.json').read_bytes())
        need(value['role']==role and value['pid']==row['pid']and value['cpu']==[cpu]and
            value['reset_mask']==0 and value['default_rseq']is True and value['argv']==argv and
            [x['signal']for x in value['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and
            all(x['after']==0 for x in value['dispositions']),'actual argv/default-rseq/reset/CPU/PID preparation')
        return value
    fixture=ROOT/'tools/page-entry/selected/tests/provider_app';selected=fixture.parents[1]
    launcher=pin(fixture/'launch.py');pin(__file__)
    app=load('pa_app',fixture/'check.py');reader=load('pa_read',fixture/'read.py')
    need(fact(fixture/'read.py')['sha256']=='198d117c390999c9196a11c859725fecf32c7732f262104ee5a3c3004032a0cc',
        'reviewed complete app reader with exact physical signal alias contract')
    native=load('pa_native',fixture/'reference/read.py');seed=load('pa_seed',fixture/'seed_probe/read.py')
    fmt=load('pa_xstate',selected/'tests/b2_reference/xstate.py')
    boundary=load('pa_boundary',selected/'tests/b2_reference/reference/boundary.py')
    old=load('pa_record',selected/'tests/oneshot_failure/record.py')
    oi=load('pa_oi',selected/'tests/oneshot_interpreter/check.py')
    prep=load('pa_prepare',fixture/'prepare.py')
    for name in ('app.c','app.h','module.c','machine.S','sites.S','build.sh','policy.c','policy.h',
                 'bootstrap.inc','observe.inc','layout.py','reference/trace.c','reference/record.h',
                 'reference/build.sh','seed_probe/probe.c','seed_probe/build.sh'):pin(fixture/name)
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and
         str(archive)==retained['path']and fact(archive)=={k:retained[k]for k in('bytes','sha256')},
         'this successful Build.prepare owns the exact fresh retained decoder archive')
    need(all(receipt['bounds'].get(k)==v for k,v in PUBLIC_BOUNDS.items()),'unchanged normal-app lane bounds')
    original,dso,probe,tracer,libpath=support(builder,ROOT,private,fixture,pin,binary,aliases,run,receipt)
    for path in (original,probe,tracer):need(path.stat().st_mode&0o111,'executable actual input')
    lib=ctypes.CDLL(str(libpath));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
    policy=lambda data:lib.li2_native_policy(data,len(data))
    image_bytes=[original.read_bytes(),dso.read_bytes()];images=[app.elf(data,i,policy)for i,data in enumerate(image_bytes)]
    interpreter=binary(Path(images[0]['interpreter']));roots=[original.parent,Path('/usr/lib64')]
    objects,description=namespace.plan(original,roots,bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
    need(sum('libli2-provider-app.so'in o['names']and o['bytes']==image_bytes[1]for o in objects)==1,'actual exact DT_NEEDED fixture DSO')
    for obj in objects:pin(obj['path'])
    r['namespace_plan']=description;r['built_inputs']={k:dict(path=str(v),**fact(v))for k,v in
        dict(original=original,dso=dso,seed_probe=probe,tracer=tracer,native_policy=libpath,archive=archive).items()}
    for m in tuple(sys.modules.values()):
        path=getattr(m,'__file__',None)
        if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
    tools=dict(builder.tools,objdump=binary('/usr/bin/objdump'),gdb=binary('/usr/bin/gdb'))
    need(tools['gdb']==Path('/usr/bin/gdb').resolve(strict=True),'actual system GDB, not wrapper')
    r['tools']={k:dict(path=str(v),**fact(v))for k,v in tools.items()}
    _,version,err=run('cc-version',[tools['cc'],'--version']);need(not err and
        version.decode().strip()==pin(archive.parent/'cc-version.txt').read_text().strip(),'exact current/retained C compiler spelling and version')
    recipe=pin(selected/'build-repeat-lease.sh');r['recipe']=fact(recipe)
    runtime={n:pin(selected/n).read_bytes()for n in('runtime_loader.c','selected_controller.inc','selected_oneshot_reusable.inc')}
    views,inverses=prep.compose(runtime['runtime_loader.c'],runtime['selected_controller.inc'],runtime['selected_oneshot_reusable.inc'])
    def build_lane(mode,which):
        name=mode+'-'+which;directory=private/name;directory.mkdir();build=directory/'build';build.mkdir()
        state=dict(name=name,status='failed',generated={},inverse_spans=len(inverses));r['builds'].append(state)
        for key,data in views.items():path=build/key;path.write_bytes(data);state['generated'][key]=fact(pin(path))
        rows=recipe_rows(recipe,'"$cc_bin"');need(len(rows)==1,'one exact retained-RX REP lease production recipe')
        argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':selected,
            '$parent_dir':selected.parent,'$archive':archive,'$output':build})
        need(argv[-2:]==['-o',str(build/'bridge-repeat-lease.so')]and
            [x for x in argv if x.endswith(('.c','.S'))]==[str(selected.parent/x)for x in UNITS]and
            [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in MACROS]and
            len(UNITS)==18 and len(MACROS)==19 and
            all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
            'exact complete18-TU19-macro REP lease production composition')
        argv=[str(build/'runtime_loader.c')if x==str(selected/'runtime_loader.c')else
              str(fixture/'policy.c')if x==str(selected/'selected_effect_native.c')else x for x in argv]
        bridge=build/'bridge.so';argv[-1]=str(bridge)
        argv[1:1]=['-DPA_POLICY_SCRIPTED='+str(int(which=='scripted')),'-DPA_WORKLOAD_ROUNDS='+str(3 if mode=='state'else 1536)]
        state['argv']=argv;sources=[x for x in argv if x.endswith(('.c','.S'))]
        headers(name+'-headers',argv,sources,archive,builder,pin,aliases,run,state)
        need(set(str(build/k)for k in views)<=set(state['headers']),'all three genuine observation views compiled')
        try:run(name+'-link',argv,profile='build')
        finally:state['bridge']=retain(bridge)
        state['elf']=bridge_check(binary(bridge))
        _,out,err=run(name+'-undefined',[tools['nm'],'-u',bridge]);need(out==err==b'','no unresolved bridge imports')
        _,symbols,err=run(name+'-symbols',[tools['nm'],'-S','--defined-only',bridge]);need(not err,'actual complete bridge symbols')
        _,assembly,err=run(name+'-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',bridge]);need(not err,'actual reset disassembly')
        state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
        cache=build/'gdb-cache';cache.mkdir()
        _,data,err=run(name+'-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
            '-iex','set debuginfod enabled off','-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
            '--readnow','--se='+str(bridge),'-x',fixture/'layout.py'],env=dict(ENV,XDG_CACHE_HOME=str(cache)))
        need(not err,'actual file-only system GDB layout');layout=json.loads(data);save(build/'layout.json',layout);binary(build/'layout.json')
        _,_,segments=elf(bridge);size=layout['types']['pao_record']['bytes']
        found=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[b'pao_record']]
        need(len(found)==1 and len(found[0])==4 and found[0][2]==b'b','one actual complete record symbol')
        symbol=int(found[0][0],16)
        need(size==11239616 and int(found[0][1],16)==size and
            sum(s[0]==1 and s[1]==6 and s[3]<=symbol<symbol+size<=s[3]+s[6]for s in segments)==1,
            'whole actual observer ELF/DWARF object in RW/NX segment')
        carrier=directory/'carrier'
        try:_,data,err=run(name+'-make',[tools['python'],'-B',ROOT/'tools/page-entry/carrier.py','make',original,bridge,carrier]);need(not err,'carrier construction stderr')
        finally:state['carrier']=retain(carrier)
        identity=json.loads(data);need(all(identity[k+'_sha256']==fact(v)['sha256']for k,v in
            dict(original=original,interpreter=interpreter,bridge=bridge,carrier=carrier).items()),'exact actual carrier identities')
        state['status']='passed';return directory,bridge,layout,binary(carrier)
    # All real subjects below run under the same externally held CPU.
    r['seed_command']='seed'
    seedrow,seedraw,err=run('seed',[probe],profile='seed');need(not err,'independent seed stderr')
    native_dir=private/'native-reference';native_dir.mkdir();reference_output=native_dir/'native'
    common=[tools['python'],'-B',launcher,'--root',ROOT,'--original',original,'--dso',dso]
    for path in roots:common+=['--library-root',path]
    native_argv=common+['--role','reference','--namespace',native_dir/'namespace','--preparation',native_dir/'preparation.json',
                        '--tracer',tracer,'--reference-output',reference_output]
    r['native_reference_command']='native-reference'
    try:nativerow,out,err=run('native-reference',native_argv,profile='reference')
    finally:partial(native_dir)
    need(out==err==b'','native tracer outer completion streams')
    actual,fds=namespace_join(native_dir,original,interpreter,objects,description)
    preparation_data=json.loads(binary(native_dir/'preparation.json').read_bytes());main=preparation_data['main']
    refargv=[str(tracer),'/proc/self/fd/'+str(main['fd']),'/proc/self/fd/'+str(preparation_data['dso_fd']),str(reference_output)]
    prepared=preparation(native_dir,nativerow,'reference',refargv)
    need(prepared['mask']==MASK and prepared['observer']is None and prepared['environment']==dict(BASE_ENV,LD_LIBRARY_PATH=str(native_dir/'namespace'))and
        main['bytes']==len(image_bytes[0])and main['sha256']==H(image_bytes[0])and main['seals']==namespace.SEALS and
        main['device']>0 and main['inode']>0 and main['fd']not in fds and
        prepared['dso_fd']==next(o['fd']for o in actual['objects']if 'libli2-provider-app.so'in o['names']),
        'actual sealed native exec inputs/default registration environment')
    record=binary(reference_output/'record.bin').read_bytes();h=struct.unpack_from('<32Q',record)
    held=[binary(reference_output/n).read_bytes()for n in('main.elf','dso.elf')]
    need(held==image_bytes,'native retained original ELF bytes exact')
    reference=native.read(record,binary(reference_output/'stdout.bin').read_bytes(),binary(reference_output/'stderr.txt').read_bytes(),
        held,app,policy,fmt,tracer_pid=nativerow['pid'],pid=h[4],cpu=cpu,seed_raw=seedraw,seed_elf=probe.read_bytes(),seed_pid=seedrow['pid'],seed_probe=seed)
    r['native_reference']={k:reference[k]for k in('native_complete','raw_sha256','pid','cpu','seed_profile')}
    for mode,which in LANES:
        if mode=='stress':
            need(len(r['cases'])>=2 and all(c['status']=='passed'and c['native_pair']['full_state_qualified']is True
                for c in r['cases'][:2]),'both actual complete state pairs before any stress build')
        name=mode+'-'+which;directory,bridge,layout,carrier=build_lane(mode,which)
        case=dict(name=name,command=name,mode=mode,policy=which,status='failed',error=None);r['cases'].append(case)
        try:
            argv=common+['--role','gated','--mode',mode,'--policy',which,'--carrier',carrier,
                '--namespace',directory/'namespace','--preparation',directory/'preparation.json','--record-fd','{record_fd}']
            try:row,out,err=run(name,argv,profile='app',expected=None,record=True)
            finally:partial(directory)
            need(row['exit']==0,'normal app actual zero exit')
            actual,fds=namespace_join(directory,original,interpreter,objects,description)
            argv=[str(original),mode,which];prepared=preparation(directory,row,'gated',argv)
            rawfile=private/(name+'.record');st=rawfile.stat()
            need(prepared['environment']==BASE_ENV and prepared['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino),
                'actual fresh inherited FD3 and unchanged launcher environment')
            launch=json.loads(binary(directory/'namespace/launch.json').read_bytes())
            need(launch['argv']==argv and launch['carrier_sha256']==fact(carrier)['sha256']and launch['carrier_size']==fact(carrier)['bytes']and
                launch['dependency_fds']==fds and launch['environment']==dict(BASE_ENV,LD_LIBRARY_PATH=str(directory/'namespace'),LI2_DEPENDENCY_FDS=','.join(map(str,fds))),
                'exact real normal-loader argv/environment; no rseq tunable or provider token')
            result=reader.read(binary(rawfile).read_bytes(),out,layout,images,fact(carrier),app,old,oi,fmt,
                pid=row['pid'],cpu=cpu,mode=mode,policy=which,exit_status=row['exit'],seed_raw=seedraw,seed_elf=probe.read_bytes(),seed_pid=seedrow['pid'],seed_probe=seed)
            case['comparison']={k:result[k]for k in('accepted','scope','operations','sampled','mode','policy','pid','cpu','record_bytes','record_sha256',
                'global_counts','publication_qualified','native_xstate_joined','full_state_qualified','capacity_stress_qualified','max_retained_at_fixture_retire')}
            case['application']=app.summary(result['application'])
            if mode=='state':case['native_pair']=reader.native_pair(reference,result,native,app,fmt,boundary,seed)
            parsed,joined=terminal.check(err,row['pid'],row['exit'],row['stdout_provenance_before'],
                rawfile.read_bytes(),layout,result,old,images,image_bytes,fact(carrier))
            case['terminal_reports']=parsed;case['terminal_join']=joined
            case['cache_reuse']={k:joined['cache_reuse'][k]for k in
                ('generations','completed_runs','copied_instructions','retirements','hits','capacity_misses')}
            case['trace_run']={k:joined['trace_run'][k]for k in('entries','completed','preflight_misses','full_misses')}
            case['repeat_lease']=joined['repeat_lease']
            case['reader_controls']=terminal.supplied_controls(err,row['pid'],row['exit'],row['stdout_provenance_before'],
                rawfile.read_bytes(),layout,result,old,images,image_bytes,fact(carrier))
            case['stderr']=fact(private/(name+'.stderr'));case['reports_replayed']=True
            case['status']='passed'
        except BaseException as e:case['error']=type(e).__name__+': '+str(e);raise
    need(len(r['cases'])==4 and all(c['status']=='passed'for c in r['cases'])and not r['final_errors'],'all four exact app lanes')
    r['status']='passed'

def finalize(receipt):
    for path,value in receipt.get('app_namespace_aliases',{}).items():
        need(Path(path).is_symlink()and os.readlink(path)==value,'all retained app namespace aliases stable')
