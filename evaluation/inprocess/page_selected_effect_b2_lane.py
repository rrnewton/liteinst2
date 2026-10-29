"""Five actual effect-provider lanes after this invocation's ten-child reference.

Finite committed-source adapter; no full-program or full B2 claim.
The enclosing original owner supplies every command/capture/cleanup operation.
"""
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,os,shutil
from pathlib import Path
from page_selected import fact,need,elf
import page_selected_oneshot_build as old_build
from page_selected_register_time_build import headers,bridge_check
from page_selected_fast_memset import body_check
from page_selected_rseq_time import hidden_memset
BOUNDS={'reference_c':[30,512<<20,16<<20,60],'reference_c_build':[30,512<<20,16<<20,60]}
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',
         GLIBC_TUNABLES='glibc.pthread.rseq=0',PYTHONDONTWRITEBYTECODE='1')
H=lambda b:hashlib.sha256(b).hexdigest()

def execute(builder,products,root,private,fixture,corpus,refs,profile,pin,binary,aliases,run,receipt,boundary,*,policy='native-post'):
    root,private,fixture,corpus=map(Path,(root,private,fixture,corpus));selected=root/'tools/page-entry/selected'
    need(type(policy)is str and policy in ('native-post','scripted'),'explicit fixed effect lane')
    suffix=''if policy=='native-post'else '-scripted'
    if policy=='scripted':
        prior=receipt['reference_effect']
        need(prior['status']=='passed' and prior['comparison']['accepted']is True and
             prior['comparison']['actual_native']==prior['comparison']['post_native']==17 and
             prior['comparison']['scripted']==0,'complete current Native+post-native prerequisite before Scripted lane')
    archive=pin(products['archive'])
    retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed' and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a' and
         str(archive)==retained['path'] and fact(archive)=={k:retained[k]for k in ('bytes','sha256')},
         'this successful Build.prepare invocation owns the exact freshly retained decoder archive')
    state=receipt['reference_effect'if policy=='native-post'else 'reference_effect_scripted']=dict(status='failed',cases=[],archive=fact(archive),
        policy='b2-native-then-original-five-trajectory-v1'if policy=='native-post'else 'b2-scripted-original-five-trajectory-v1',
        full_b2_qualification=False)
    need(corpus==private/'reference/corpus' and receipt['reference_producer']['environment']['LI2_B2_REFERENCE_DIR']==str(corpus),
         'fresh reference corpus belongs to this exact invocation')
    need(all(receipt['bounds'].get(k)==v for k,v in BOUNDS.items()),'unchanged C-lane resource bounds')
    need(receipt['format_measurement']['status']=='passed','fresh complete native format measurement')
    state['decoder_sources']=dict(builder.record['dep_info'])
    need(receipt['reference_producer']['status']=='passed'and receipt['reference_producer']['build_completed']and
         receipt['reference_producer']['run_completed']and len(refs)==5,'closed genuine producer before any C comparison')
    need(profile['cpu']==next(iter(os.sched_getaffinity(0)))and len(os.sched_getaffinity(0))==1,'stored format CPU equals actual sole allocated CPU')
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def retain(label,path):
        try:
            if path.exists()or path.is_symlink():return dict(fact(binary(path)),mode=path.stat().st_mode&0o777)
        except BaseException as error:receipt['final_errors'].append(label+': '+type(error).__name__+': '+str(error))
        return None
    prepare=load('effect_b2_prepare',fixture/'prepare.py');reader=load('effect_b2_read',fixture/'read.py')
    namespace=load('b2_c_namespace',root/'tools/page-entry/namespace.py')
    for name in ('layout.py','policy.h','policy.c','record.h','observe.inc','reference/boundary.py',
                 'reference/PINS.json','reference/producer/prepare.py'):pin(fixture/name)
    if policy=='scripted':
        pin(fixture/'policy_scripted.c');pin(fixture/'scripted_layout.py')
    layout_path=fixture/('layout.py'if policy=='native-post'else 'scripted_layout.py')
    shared=selected/'tests/b2_reference'
    for name in ('xstate.py','format.inc','reference/capture.h'):pin(shared/name)
    tools={'objdump':pin(shutil.which('objdump',path=ENV['PATH'])),'gdb':pin('/usr/bin/gdb')}
    need(tools['gdb']==Path('/usr/bin/gdb').resolve(strict=True),'actual system GDB, not wrapper')
    state['tools']={n:dict(path=str(p),**fact(p))for n,p in tools.items()}
    output=private/('effect-reference'+suffix);output.mkdir();cache=output/'gdb-cache';cache.mkdir()
    gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    for name,path in tools.items():
        _,out,err=run('reference-c-version'+suffix+'-'+name,[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual strict inspection tool version')
    _,out,err=run('reference-c-archive-exports'+suffix,[builder.tools['nm'],'-g','--defined-only',products['archive']],profile='inspect',env=builder.environment)
    need(not err,'actual retained archive exports')
    for name in old_build.EXPORTS:
        rows=[x.split()for x in out.splitlines()if x.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()],'unchanged real archive definition '+name)
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(selected/'tests/provider_builtins/launch.py')
    recipe=pin(selected/'build-effect-provider.sh')
    recipe_rows=old_build.commands(recipe,builder,output,products['archive'],pin)
    need(len(recipe_rows)==2,'exact two current effect production recipe rows')
    decoder_argv=recipe_rows[1];decoder=Path(decoder_argv[-1]);decoder_sources=[str(selected/'fixture_observe.c')]
    state['decoder_build']=dict(argv=decoder_argv,recipe=fact(recipe),archive=fact(products['archive']))
    headers('effect-decode-headers'+suffix,decoder_argv,decoder_sources,products['archive'],builder,pin,aliases,run,state['decoder_build'])
    try:run('effect-decode-link'+suffix,decoder_argv,profile='reference_c_build',env=builder.environment)
    finally:state['decoder']=retain('partial independent decoder observer',decoder)
    binary(decoder);need(decoder.stat().st_mode&0o111,'actual executable independent decoder observer')
    _,head,segments=elf(decoder)
    need(head[2]==62 and any(p[0]==1 and p[1]&1 and p[3]<=head[4]<p[3]+p[6]for p in segments),
         'actual x86-64 independent decoder executable entry')
    for index,(ref,image)in enumerate(refs):
        directory=output/str(index);directory.mkdir();observed=directory/'observed'
        name='reference-effect'+suffix+'-'+str(index);case=dict(name=name,index=index,case=ref['case'],status='failed',generated={},error=None)
        state['cases'].append(case)
        try:
            try:case['adapters']=prepare.prepare(selected,ref,observed,pin,boundary,policy=policy)
            finally:
                if observed.exists():
                    for path in sorted(observed.iterdir()):
                        if path.is_symlink():pin(path)
                        elif path.is_file():case['generated'][path.name]=retain('partial reference source',path)
            rows=old_build.commands(recipe,builder,directory,products['archive'],pin);need(len(rows)==2,'exact two production recipe rows')
            original_argv=rows[0];sources=[str(selected.parent/'bridge.c')]+[str(selected/x)for x in prepare.TUS[1:]]
            need([x for x in original_argv if x.endswith(('.c','.S'))]==sources and
                 all(x in original_argv for x in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden',
                     '-mgeneral-regs-only','-fno-builtin','-Werror')),'complete real optimized18-TU effect-provider recipe')
            argv=prepare.recipe(original_argv,selected,observed)
            sources=[str(observed/'runtime_loader.c')if x==str(selected/'runtime_loader.c')else
                     str(observed/'be_policy.c')if x==str(selected/'selected_effect_native.c')else x for x in sources]
            case['build']=dict(original_argv=original_argv,argv=argv,recipe=fact(recipe),translation_units=18,macros=list(prepare.MACROS),archive=fact(products['archive']))
            headers(name+'-headers',argv,sources,products['archive'],builder,pin,aliases,run,case['build'])
            need(all(str(observed/x)in case['build']['headers']for x in case['generated'])and
                 str(selected/'selected_effect.h')in case['build']['headers'],
                 'all exact observation/script/format and production effect includes')
            bridge=Path(argv[-1])
            try:run(name+'-link',argv,profile='reference_c_build',env=builder.environment)
            finally:case['bridge']=retain('partial actual C reference link',bridge)
            binary(bridge);case['elf']=bridge_check(bridge)
            _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
            need(not out and not err,'no unresolved C reference imports')
            _,symbols,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
            need(not err,'actual record and source symbols')
            _,assembly,err=run(name+'-memset',[tools['objdump'],'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
            need(not err,'actual qualified reset disassembly')
            case['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
            _,out,err=run(name+'-layout',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
                '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
                '-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',layout_path],env=gdb_env)
            need(not err,'file-only actual record DWARF');layout=json.loads(out);case['layout']=layout
            _,_,segments=elf(bridge);intervals=[]
            for key,size in (('be_record',1263736),('b2_format_record',3536)):
                found=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[key.encode()]]
                need(len(found)==1 and len(found[0])==4 and found[0][2]==b'b'and
                     int(found[0][1],16)==layout[key]['bytes']==size,'actual independent complete record object '+key)
                address=int(found[0][0],16);need(layout['symbols'][key]==address,'actual ELF and DWARF record symbol agree');intervals.append((address,address+size))
                need(sum(p[0]==1 and p[1]==6 and p[3]<=address<address+size<=p[3]+p[6]for p in segments)==1,
                     'complete record inside actual RW/NX load')
            intervals.sort();need(intervals[0][1]<=intervals[1][0],'two disjoint actual record objects')
            original=pin(corpus/('case'+str(index))/'image');interpreter=pin(original.parent/'li2-b2-reference.so')
            need(boundary.fixture(original,ref)==image,'same complete producer image bytes before C launch')
            reference=pin(original.parent/'reference.bin');reference_bytes=reference.read_bytes()
            need(boundary.reference(reference_bytes)==ref,'exact fresh complete raw/model/trap reference')
            case['reference']=fact(reference);case['decodes']=[]
            for j,item in enumerate(ref['rows']):
                pc=item['before']['registers']['rip'];available=min(15,4096-pc%4096)
                source=ref['source'][pc-boundary.BASE:pc-boundary.BASE+available]
                need(len(source)==available and source[:len(item['encoding'])]==item['encoding'],'exact original decoder prefix')
                label=name+'-decode-'+str(j)
                _,decoded,decode_error=run(label,[decoder,'decode',str(pc),source.hex()],profile='inspect',env=ENV)
                need(not decode_error,'fresh independent decoder stdout only')
                case['decodes'].append(dict(command=label,pc=pc,source=source.hex(),row=json.loads(decoded)))
            carrier=directory/'carrier'
            try:
                _,out,err=run(name+'-make',[builder.tools['python'],carrier_tool,'make',original,bridge,carrier],env=ENV)
                need(not err,'actual carrier construction stderr')
            finally:case['carrier']=retain('partial C reference carrier',carrier)
            binary(carrier);identities=json.loads(out)
            need(all(identities[k+'_sha256']==fact(p)['sha256']for k,p in
                     (('original',original),('interpreter',interpreter),('bridge',bridge),('carrier',carrier))),
                 'actual original/custom-interpreter/bridge/carrier identity')
            objects,description=namespace.plan(original,[original.parent],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
            need(len(objects)==1 and objects[0]['bytes']==interpreter.read_bytes()and objects[0]['names']==[interpreter.name],
                 'one exact real interpreter dependency; no hidden loader objects')
            for item in objects:
                need(fact(pin(item['path']))['sha256']==H(item['bytes']),'actual namespace dependency custody')
            case['namespace_plan']=description
            preparation=directory/'preparation.json';ns=directory/'namespace';record=private/(name+'.record')
            argv=[builder.tools['python'],launch_tool,'--mode','configured','--original',original,'--library-root',original.parent,
                  '--preparation',preparation,'--record-fd','{record_fd}','--carrier',carrier,'--namespace',ns]
            case['command']=name;case['invocation_attempted']=True
            try:command,out,err=run(name,argv,profile='reference_c',expected=None,env=ENV,record=True)
            finally:
                for path in (preparation,record,ns/'namespace.json',ns/'launch.json'):retain('partial C reference launch',path)
                for alias in objects[0]['names']:
                    p=ns/alias
                    try:
                        if p.is_symlink():receipt.setdefault('effect_namespace_aliases'if policy=='native-post'else 'effect_scripted_namespace_aliases',{})[str(p)]=os.readlink(p)
                        else:need(not os.path.lexists(p),'partial namespace alias is not a symlink')
                    except BaseException as error:receipt['final_errors'].append('reference namespace alias: '+type(error).__name__+': '+str(error))
            need(command['exit']==0 and out==err==b'','complete finite observer stop, not an application exit')
            binary(preparation);prep=json.loads(preparation.read_bytes());case['preparation']=prep
            need(prep['mask']==0 and [x['signal']for x in prep['dispositions']]==[x for x in range(1,65)if x not in(9,19)]and
                 all(x['after']==0 for x in prep['dispositions'])and prep['argv']==[str(original)]and
                 prep['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
                 prep['observer']==dict(fd=3,device=record.stat().st_dev,inode=record.stat().st_ino),
                 'actual reset, original argv/environment and inherited record identity')
            case['comparison']=reader.record(binary(record).read_bytes(),layout,reference_bytes,profile,command['pid'],profile['cpu'],[d['row']for d in case['decodes']],policy=policy)
            actual=json.loads(binary(ns/'namespace.json').read_bytes());started=json.loads(binary(ns/'launch.json').read_bytes())
            need(actual['original_sha256']==fact(original)['sha256']and actual['interpreter_sha256']==fact(interpreter)['sha256']and
                 actual['original']==str(original)and len(actual['objects'])==1,'actual sealed namespace main/interpreter')
            obj=actual['objects'][0];item=objects[0]
            need(obj['names']==item['names']and obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and
                 obj['seals']==namespace.SEALS and obj['device']>0 and obj['inode']>0,'actual complete sealed interpreter observation')
            for alias in obj['names']:
                path=ns/alias;need(path.is_symlink()and os.readlink(path)=='/proc/self/fd/'+str(obj['fd'])and
                    receipt['effect_namespace_aliases'if policy=='native-post'else 'effect_scripted_namespace_aliases'][str(path)]==os.readlink(path),'actual sealed namespace alias')
            target_env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
            target_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=str(obj['fd']),LI2_SELECTED_PROVIDER='deterministic-builtins-v1')
            need(started['argv']==[str(original)]and started['carrier_sha256']==fact(carrier)['sha256']and
                 started['carrier_size']==fact(carrier)['bytes']and started['dependency_fds']==[obj['fd']]and started['environment']==target_env,
                 'real carrier configuration token; fixture policy remains separately labelled')
            case['status']='passed'
        except BaseException as error:case['error']=type(error).__name__+': '+str(error);raise
    need(len(state['cases'])==5 and all(c['status']=='passed'for c in state['cases']),'all five actual effect trajectories')
    state['comparison']=reader.cohort([c['comparison']for c in state['cases']],policy=policy)
    state['status']='passed'

def finalize(receipt):
    for field in ('effect_namespace_aliases','effect_scripted_namespace_aliases'):
        for path,value in receipt.get(field,{}).items():
            need(Path(path).is_symlink()and os.readlink(path)==value,'retained C reference namespace alias unchanged')
