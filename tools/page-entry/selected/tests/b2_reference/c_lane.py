"""Five real C-provider executions against an already closed ten-child reference."""
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

def execute(builder,products,root,private,fixture,corpus,refs,profile,pin,binary,aliases,run,receipt,boundary):
    root,private,fixture,corpus=map(Path,(root,private,fixture,corpus));selected=root/'tools/page-entry/selected'
    state=receipt['reference_c']=dict(status='failed',cases=[],archive=fact(products['archive']),policy='fixture-five-trajectory-v1')
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
    prepare=load('b2_c_prepare',fixture/'prepare.py');reader=load('b2_c_read',fixture/'read.py')
    namespace=load('b2_c_namespace',root/'tools/page-entry/namespace.py')
    for name in ('xstate.py','format.inc','layout.py','PINS.json','callback/prepare.py','callback/read.py','callback/observe.inc',
                 'reference/boundary.py','reference/capture.h','reference/script.inc'):pin(fixture/name)
    tools={name:pin(shutil.which(name,path=ENV['PATH']))for name in ('objdump','gdb')}
    state['tools']={n:dict(path=str(p),**fact(p))for n,p in tools.items()}
    output=private/'c-reference';output.mkdir();cache=output/'gdb-cache';cache.mkdir()
    gdb_env=dict(builder.environment,XDG_CACHE_HOME=str(cache))
    for name,path in tools.items():
        _,out,err=run('reference-c-version-'+name,[path,'--version'],env=gdb_env if name=='gdb'else builder.environment)
        need(out and not err,'actual strict inspection tool version')
    _,out,err=run('reference-c-archive-exports',[builder.tools['nm'],'-g','--defined-only',products['archive']],profile='inspect',env=builder.environment)
    need(not err,'actual retained archive exports')
    for name in old_build.EXPORTS:
        rows=[x.split()for x in out.splitlines()if x.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()],'unchanged real archive definition '+name)
    carrier_tool=pin(root/'tools/page-entry/carrier.py');launch_tool=pin(selected/'tests/provider_builtins/launch.py')
    for index,(ref,image)in enumerate(refs):
        directory=output/str(index);directory.mkdir();observed=directory/'observed'
        name='reference-c-'+str(index);case=dict(name=name,index=index,case=ref['case'],status='failed',generated={},error=None)
        state['cases'].append(case)
        try:
            try:case['adapters']=prepare.prepare(selected,fixture/'reference',ref,observed,pin,boundary)
            finally:
                if observed.exists():
                    for path in sorted(observed.iterdir()):
                        if path.is_file():case['generated'][path.name]=retain('partial reference source',path)
            recipe=pin(selected/'build-provider-builtins.sh')
            rows=old_build.commands(recipe,builder,directory,products['archive'],pin);need(len(rows)==2,'exact two production recipe rows')
            original_argv=rows[0];sources=[str(selected.parent/x)for x in old_build.UNITS]
            need([x for x in original_argv if x.endswith(('.c','.S'))]==sources and
                 all(x in original_argv for x in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden',
                     '-mgeneral-regs-only','-fno-builtin','-Werror')),'complete real optimized16-TU configured recipe')
            argv=prepare.recipe(original_argv,selected,observed)
            sources=[str(observed/'runtime_loader.c')if x==str(selected/'runtime_loader.c')else x for x in sources]
            case['build']=dict(original_argv=original_argv,argv=argv,recipe=fact(recipe),translation_units=16,archive=fact(products['archive']))
            headers(name+'-headers',argv,sources,products['archive'],builder,pin,aliases,run,case['build'])
            need(all(str(observed/x)in case['build']['headers']for x in case['generated'])and
                 str(selected/'provider_callback.h')in case['build']['headers'],
                 'all exact observation/script/format and production callback includes')
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
                '-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',fixture/'layout.py'],env=gdb_env)
            need(not err,'file-only actual record DWARF');layout=json.loads(out);case['layout']=layout
            _,_,segments=elf(bridge);intervals=[]
            for key,size in (('b2_record',1258752),('b2_format_record',3536)):
                found=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[key.encode()]]
                need(len(found)==1 and len(found[0])==4 and found[0][2]==b'b'and
                     int(found[0][1],16)==layout[key]['bytes']==size,'actual independent complete record object '+key)
                address=int(found[0][0],16);intervals.append((address,address+size))
                need(sum(p[0]==1 and p[1]==6 and p[3]<=address<address+size<=p[3]+p[6]for p in segments)==1,
                     'complete record inside actual RW/NX load')
            intervals.sort();need(intervals[0][1]<=intervals[1][0],'two disjoint actual record objects')
            original=pin(corpus/('case'+str(index))/'image');interpreter=pin(original.parent/'li2-b2-reference.so')
            need(boundary.fixture(original,ref)==image,'same complete producer image bytes before C launch')
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
                        if p.is_symlink():receipt.setdefault('reference_namespace_aliases',{})[str(p)]=os.readlink(p)
                        else:need(not os.path.lexists(p),'partial namespace alias is not a symlink')
                    except BaseException as error:receipt['final_errors'].append('reference namespace alias: '+type(error).__name__+': '+str(error))
            need(command['exit']==0 and out==err==b'','complete finite observer stop, not an application exit')
            binary(preparation);prep=json.loads(preparation.read_bytes());case['preparation']=prep
            need(prep['mask']==0 and [x['signal']for x in prep['dispositions']]==[x for x in range(1,65)if x not in(9,19)]and
                 all(x['after']==0 for x in prep['dispositions'])and prep['argv']==[str(original)]and
                 prep['environment']=={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}and
                 prep['observer']==dict(fd=3,device=record.stat().st_dev,inode=record.stat().st_ino),
                 'actual reset, original argv/environment and inherited record identity')
            case['comparison']=reader.check(binary(record).read_bytes(),layout,ref,boundary,profile)
            actual=json.loads(binary(ns/'namespace.json').read_bytes());started=json.loads(binary(ns/'launch.json').read_bytes())
            need(actual['original_sha256']==fact(original)['sha256']and actual['interpreter_sha256']==fact(interpreter)['sha256']and
                 actual['original']==str(original)and len(actual['objects'])==1,'actual sealed namespace main/interpreter')
            obj=actual['objects'][0];item=objects[0]
            need(obj['names']==item['names']and obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and
                 obj['seals']==namespace.SEALS and obj['device']>0 and obj['inode']>0,'actual complete sealed interpreter observation')
            for alias in obj['names']:
                path=ns/alias;need(path.is_symlink()and os.readlink(path)=='/proc/self/fd/'+str(obj['fd'])and
                    receipt['reference_namespace_aliases'][str(path)]==os.readlink(path),'actual sealed namespace alias')
            target_env={k:v for k,v in ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
            target_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=str(obj['fd']),LI2_SELECTED_PROVIDER='deterministic-builtins-v1')
            need(started['argv']==[str(original)]and started['carrier_sha256']==fact(carrier)['sha256']and
                 started['carrier_size']==fact(carrier)['bytes']and started['dependency_fds']==[obj['fd']]and started['environment']==target_env,
                 'real carrier configuration token; fixture policy remains separately labelled')
            case['status']='passed'
        except BaseException as error:case['error']=type(error).__name__+': '+str(error);raise
    need(len(state['cases'])==5 and all(c['status']=='passed'for c in state['cases'])and
         sum(c['comparison']['selected_callbacks']for c in state['cases'])==17,'all five actual C trajectories and seventeen transitions')
    state['status']='passed'

def finalize(receipt):
    for path,value in receipt.get('reference_namespace_aliases',{}).items():
        need(Path(path).is_symlink()and os.readlink(path)==value,'retained C reference namespace alias unchanged')
