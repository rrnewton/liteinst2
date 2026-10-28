"""One bounded current-C timing lane; original reference oracle stays mandatory."""
import hashlib,importlib.util,json,os,shutil
from pathlib import Path
from page_selected import fact,need,elf
import page_b2_reference as original
H=lambda b:hashlib.sha256(b).hexdigest()
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def adapt(source,target,operations,pin,binary):
    before=pin(source).read_bytes();after=before
    for a,b in operations:
        need(after.count(a.encode())==1,'unique timing source adapter '+str(source));after=after.replace(a.encode(),b.encode())
    inverse=after
    for a,b in reversed(operations):
        need(inverse.count(b.encode())==1,'unique timing source inverse');inverse=inverse.replace(b.encode(),a.encode())
    need(inverse==before,'complete timing donor inverse')
    target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(after);pin(target);binary(target)
    return dict(before=fact(source),after=fact(target),inverse_spans=len(operations))

def fixture_view(root,private,pin,binary,receipt):
    old=root/'tools/page-entry/selected/tests/b2_reference';support=root/'tools/page-entry/selected/tests/hook_cost'
    view=private/'hook-cost-fixture';view.mkdir();facts={}
    names=('xstate.py','format.inc','PINS.json','callback/prepare.py','callback/read.py','callback/observe.inc',
           'reference/boundary.py','reference/capture.h','reference/script.inc')
    for name in names:facts[name]=adapt(old/name,view/name,[],pin,binary)
    facts['original_read.py']=adapt(old/'read.py',view/'original_read.py',[],pin,binary)
    for name in('prepare.py','read.py','timing.py','timing.inc'):facts[name]=adapt(support/name,view/name,[],pin,binary)
    a="('b2_record','b2_row','b2_snapshot','b2_format_record','b2_format_sample')"
    facts['layout.py']=adapt(old/'layout.py',view/'layout.py',[(a,a[:-1]+",'hc_record','hc_row')")],pin,binary)
    carrier=root/'tools/page-entry/carrier.py'
    facts['carrier.py']=adapt(carrier,view/'carrier.py',[
        ('    import namespace\n    with carrier.open',
         '    timing_mode=os.environ.get("LI2_SELECTED_HOOK_COST")\n    if timing_mode not in ("qualify","measure"):\n        raise ValueError("exact private timing mode")\n    import namespace\n    with carrier.open'),
        ('        if disable_rseq:\n','        env["LI2_SELECTED_HOOK_COST"] = timing_mode\n        if disable_rseq:\n')],pin,binary)
    launch=root/'tools/page-entry/selected/tests/provider_builtins/launch.py'
    facts['launch.py']=adapt(launch,view/'launch.py',[
        ('ROOT=Path(__file__).resolve().parents[5]','ROOT=Path('+repr(str(root))+')'),
        ('    import namespace,carrier\n',
         '    import namespace\n    spec=importlib.util.spec_from_file_location("hc_carrier",Path(__file__).parent/"carrier.py")\n    carrier=importlib.util.module_from_spec(spec);spec.loader.exec_module(carrier)\n')],pin,binary)
    # Reuse every original build/header/layout/namespace/run/custody predicate.
    # Only names, observation inputs and the explicit startup mode are adapted.
    path=view/'qualification_lane.py'
    facts['qualification_lane.py']=adapt(old/'c_lane.py',path,[
        ("state=receipt['reference_c']","state=receipt['hook_cost_qualification']"),
        ("PYTHONDONTWRITEBYTECODE='1')","PYTHONDONTWRITEBYTECODE='1',LI2_SELECTED_HOOK_COST='qualify')"),
        ("output=private/'c-reference'","output=private/'hook-cost-build'"),
        ("launch_tool=pin(selected/'tests/provider_builtins/launch.py')","launch_tool=pin(fixture/'launch.py')"),
        ("run('reference-c-version-'","run('hook-cost-version-'"),
        ("run('reference-c-archive-exports'","run('hook-cost-archive-exports'"),
        ("(('b2_record',1258752),('b2_format_record',3536))","(('b2_record',1258752),('b2_format_record',3536),('hc_record',2304))"),
        ("intervals.sort();need(intervals[0][1]<=intervals[1][0],'two disjoint actual record objects')",
         "intervals.sort();need(all(a[1]<=b[0]for a,b in zip(intervals,intervals[1:])),'all three disjoint actual record objects')"),
        ("name='reference-c-'+str(index)","name='hook-cost-qualify-'+str(index)")],pin,binary)
    receipt['hook_cost_adapters']=facts
    return view,load('hc_qualification_lane',path)

def execute(builder,products,root,private,fixture,corpus,refs,profile,pin,binary,aliases,run,receipt,boundary):
    root,private=map(Path,(root,private))
    need(receipt['reference_c']['status']=='passed'and len(refs)==5,'unchanged fresh full C/reference qualification precedes timing')
    view,lane=fixture_view(root,private,pin,binary,receipt)
    lane.execute(builder,products,root,private,view,corpus,refs,profile,pin,binary,aliases,run,receipt,boundary)
    qualified=receipt['hook_cost_qualification'];need(qualified['status']=='passed'and len(qualified['cases'])==5,'same emitted timing ELFs pass all unchanged full-state comparisons first')
    reader=load('hc_timing_full_reader',view/'read.py');namespace=load('hc_namespace',pin(root/'tools/page-entry/namespace.py'))
    output=private/'hook-cost-samples';output.mkdir();cases=receipt['hook_cost_measurements']=[]
    env=dict(lane.ENV,LI2_SELECTED_HOOK_COST='measure')
    def retain(path):
        try:
            if path.exists()or path.is_symlink():return binary(path)
        except BaseException as error:receipt['final_errors'].append('partial timing artifact: '+type(error).__name__+': '+str(error))
        return None
    for index,((ref,image),q)in enumerate(zip(refs,qualified['cases'])):
        need(q['index']==index and q['status']=='passed'and q['comparison']['timing_observation']['mode']==0,
             'exact emitted-ELF full-state prerequisite for each fixture')
        bridge=Path(q['build']['argv'][-1]);need(dict(fact(binary(bridge)),mode=bridge.stat().st_mode&0o777)==q['bridge'],'same previously qualified emitted timing bridge')
        carrier=Path(q['build']['argv'][-1]).parent.parent/'carrier'
        # c_lane places the carrier in the fixture directory above observed/.
        need(dict(fact(binary(carrier)),mode=carrier.stat().st_mode&0o777)==q['carrier'],'same exact qualified sealed carrier input')
        _,symbols,err=run(f'hook-cost-{index}-timer-symbol',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
        need(not err,'actual timing symbol inspection')
        q['timer_inspection']={};_,_,segments=elf(bridge)
        for function in('hc_clock','hc_handler_enter','hc_handler_leave','hc_random_callback','hc_cpuid_callback',
                        'hc_clock_callback','hc_syscall_callback','handler'):
            found=[x.split()for x in symbols.splitlines()if x.split()[-1:]==[function.encode()]]
            need(len(found)==1 and len(found[0])==4 and found[0][2]==b't','one real local timing boundary '+function)
            address,size=(int(found[0][j],16)for j in(0,1))
            need(0<size<=65536 and sum(s[0]==1 and s[1]==5 and s[3]<=address<address+size<=s[3]+s[5]for s in segments)==1,
                 'whole actual timing boundary in file-backed RX load')
            _,body,err=run(f'hook-cost-{index}-body-'+function,[qualified['tools']['objdump']['path'],'-d','-w','-M','att',
                '--disassemble='+function,bridge],profile='inspect',env=builder.environment)
            need(not err and body.count(('<'+function+'>:').encode())==1,'retained actual boundary body')
            if function=='hc_clock':need(b'rdtsc'not in body.lower(),'private timer does not use application TSC permission')
            q['timer_inspection'][function]=dict(address=address,bytes=size,disassembly_sha256=H(body))
        main=pin(Path(corpus)/('case'+str(index))/'image');interpreter=pin(main.parent/'li2-b2-reference.so')
        for phase,count in(('warmup',3),('measure',10)):
            for sample in range(count):
                name=f'hook-cost-{index}-{phase}-{sample}';directory=output/name;directory.mkdir()
                case=dict(index=index,phase=phase,round=sample,status='failed',command=name,error=None,
                          bridge=fact(bridge),carrier=fact(carrier),qualification_command=q['command'])
                cases.append(case)
                try:
                    need(boundary.fixture(main,ref)==image,'unchanged complete actual source image before each measurement')
                    objects,description=namespace.plan(main,[main.parent],bytes.fromhex(fact(main)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
                    need(len(objects)==1 and objects[0]['bytes']==interpreter.read_bytes()and objects[0]['names']==[interpreter.name],
                         'one exact unchanged real interpreter dependency')
                    for item in objects:need(fact(pin(item['path']))['sha256']==H(item['bytes']),'actual timing dependency custody')
                    case['namespace_plan']=description
                    ns=directory/'namespace';preparation=directory/'preparation.json';record=private/(name+'.record')
                    argv=[builder.tools['python'],view/'launch.py','--mode','configured','--original',main,'--library-root',main.parent,
                          '--preparation',preparation,'--record-fd','{record_fd}','--carrier',carrier,'--namespace',ns]
                    case['invocation_attempted']=True
                    try:command,out,err=run(name,argv,profile='reference_c',expected=None,env=env,record=True)
                    finally:
                        for path in(preparation,record,ns/'namespace.json',ns/'launch.json'):retain(path)
                        for alias in objects[0]['names']:
                            path=ns/alias
                            try:
                                if path.is_symlink():receipt.setdefault('reference_namespace_aliases',{})[str(path)]=os.readlink(path)
                                else:need(not os.path.lexists(path),'partial timing alias is not a symlink')
                            except BaseException as error:receipt['final_errors'].append('timing alias: '+type(error).__name__+': '+str(error))
                    need(command['exit']==0 and out==err==b'','complete actual timing subject and empty public output')
                    prep=json.loads(binary(preparation).read_bytes());case['preparation']=prep
                    need(prep['mask']==0 and [x['signal']for x in prep['dispositions']]==[x for x in range(1,65)if x not in(9,19)]and
                         all(x['after']==0 for x in prep['dispositions'])and prep['argv']==[str(main)]and
                         prep['environment']=={k:v for k,v in env.items()if k!='PYTHONDONTWRITEBYTECODE'}and
                         prep['observer']==dict(fd=3,device=record.stat().st_dev,inode=record.stat().st_ino),
                         'actual signal reset/argv/mode/inherited record identity')
                    case['comparison']=reader.check(binary(record).read_bytes(),q['layout'],ref,boundary,profile,mode=1)
                    need(case['comparison']['route_counts']==q['comparison']['timing_observation']['route_counts'],
                         'same observed native/fallback route counts as unchanged full-state qualification')
                    actual=json.loads(binary(ns/'namespace.json').read_bytes());started=json.loads(binary(ns/'launch.json').read_bytes())
                    need(actual['original_sha256']==fact(main)['sha256']and actual['interpreter_sha256']==fact(interpreter)['sha256']and
                         actual['original']==str(main)and len(actual['objects'])==1,'actual original/custom-interpreter identities')
                    obj=actual['objects'][0];item=objects[0]
                    need(obj['names']==item['names']and obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and
                         obj['seals']==namespace.SEALS and obj['device']>0 and obj['inode']>0,'actual sealed dependency observation')
                    for alias in obj['names']:
                        path=ns/alias;need(path.is_symlink()and os.readlink(path)=='/proc/self/fd/'+str(obj['fd'])and
                            receipt['reference_namespace_aliases'][str(path)]==os.readlink(path),'actual stable namespace alias')
                    target_env={k:v for k,v in env.items()if k!='PYTHONDONTWRITEBYTECODE'}
                    target_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=str(obj['fd']),LI2_SELECTED_PROVIDER='deterministic-builtins-v1')
                    need(started['argv']==[str(main)]and started['carrier_sha256']==fact(carrier)['sha256']and started['carrier_size']==len(carrier.read_bytes())and
                         started['dependency_fds']==[obj['fd']]and started['environment']==target_env,'actual fixed measurement mode and carrier launch')
                    need(dict(fact(bridge),mode=bridge.stat().st_mode&0o777)==q['bridge']and
                         dict(fact(carrier),mode=carrier.stat().st_mode&0o777)==q['carrier'],'same qualified executable bytes after subject')
                    case['status']='passed'
                except BaseException as error:case['error']=type(error).__name__+': '+str(error);raise
    need(len(cases)==65 and all(c['status']=='passed'for c in cases),'all fixed warmup and measurement children accepted without retry')

def summary(receipt):
    support=original.ROOT/'tools/page-entry/selected/tests/hook_cost'
    return load('hc_numeric_summary',support/'timing.py').summary(receipt)
