#!/usr/bin/env python3
"""Replay the exact historical437 group layout failure with the corrected reader.

No target is launched. Run with one externally reserved CPU from a clean current
revision; raw captures and the complete replay result remain in private storage.
"""
import argparse,ctypes,hashlib,json,os,platform,struct,sys,types
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root',type=Path,default=Path.cwd())
parser.add_argument('--receipt',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--expect-revision',required=True)
parser.add_argument('--child',action='store_true',help=argparse.SUPPRESS)
parser.add_argument('--receipt-sha256',help=argparse.SUPPRESS)
parser.add_argument('--driver-sha256',help=argparse.SUPPRESS)
ARGS=parser.parse_args()
ROOT=ARGS.root.resolve(strict=True);RECEIPT=ARGS.receipt.resolve(strict=True)
PRIVATE=RECEIPT.parent;OUTPUT=ARGS.output.resolve()
SCRIPT=Path(__file__).resolve(strict=True)
ORIGINAL_REVISION='4370711c27e893a631cf246c496df26648e067ea'
wire=dict(path='tools/page-entry/selected/tests/persistent_group_owner/wire.py',
          before=dict(bytes=39041,sha256='6c3d5be08081de667e97088ea8bd937e8d5c4896590cbc58ef6a17f034069366'),
          after=dict(bytes=39041,sha256='21cd1f57ebf7366673ca3612081e57cd76e85add062bbd5966cbdd91262ece19'),
          offsets=(10558,10964,13037))
USED={};LOADED=[]
def need(ok,message):
    if not ok:raise ValueError(message)
def digest(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'))
def checked(path,expected):
    p=Path(path).resolve(strict=True);b=p.read_bytes()
    need(digest(b)=={k:expected[k]for k in('bytes','sha256')},'exact input: '+str(p))
    USED[str(p)]=digest(b);return b
need((ROOT/'.git').exists()and RECEIPT.name=='receipt.json'and
     PRIVATE.is_relative_to(ROOT/'target')and OUTPUT.is_relative_to(ROOT/'target')and
     not OUTPUT.is_relative_to(PRIVATE)and not PRIVATE.is_relative_to(OUTPUT)and
     len(ARGS.expect_revision)==40 and all(c in '0123456789abcdef'for c in ARGS.expect_revision),
     'explicit repository, closed private receipt, disjoint fresh private output and exact current revision')
DRIVER=digest(SCRIPT.read_bytes());ORIGINAL_RECEIPT=digest(RECEIPT.read_bytes())
checked(SCRIPT,DRIVER);R=json.loads(checked(RECEIPT,ORIGINAL_RECEIPT))
need((ARGS.child and ARGS.receipt_sha256==ORIGINAL_RECEIPT['sha256']and ARGS.driver_sha256==DRIVER['sha256'])or
     (not ARGS.child and ARGS.receipt_sha256 is None and ARGS.driver_sha256 is None),
     'reader child uses the exact parent-bound script and receipt bytes')
need(R['expected_revision']==R['source']['revision']==ORIGINAL_REVISION and
     R['profile']=='persistent-group-loop-v1'and R['status']=='failed'and
     R['totals']['planned']==R['totals']['launched']==2 and R['totals']['observed']==1 and
     R['cases'][1]['error']=='ValueError: actual minimal field layout li2_pg_compact.head'and
     R['source_unchanged']is True and R['cleanup_complete']is True and R['final_errors']==[] and
     R['inputs']==R['inputs_before']==R['inputs_after']and
     R['artifacts']==R['artifacts_before']==R['artifacts_after']and R['source']==R['source_after'],
     'original closed failed group result and its whole input/process closure')
FACTS=dict(R['inputs']);FACTS.update(R['artifacts'])
wire_path=(ROOT/wire['path']).resolve(strict=True)
current=checked(wire_path,wire['after']);old=bytearray(current)
for at in wire['offsets']:
    need(old[at:at+1]==b'4','only reviewed alignment4');old[at:at+1]=b'8'
need(digest(old)=={k:FACTS[str(wire_path)][k]for k in('bytes','sha256')}==wire['before'],
     'exact three-character inverse to the captured reader; no other current-source exception')
def retained(path):
    p=Path(path).resolve(strict=True);need(str(p)in FACTS,'recorded closed input: '+str(p))
    return checked(p,wire['after']if p==wire_path else FACTS[str(p)])
def binary(path):retained(path);return Path(path).resolve(strict=True)
retained(sys.executable)
COMMANDS={c['name']:c for c in R['commands']}
need(len(COMMANDS)==len(R['commands']),'unique actual command names')
def capture(row,kind):
    c=row['captures'][kind];b=retained(PRIVATE/c['file'])
    need(digest(b)=={k:c[k]for k in('bytes','sha256')},'whole actual capture identity');return b
def completed(row):
    need(row['exit']==0 and row['reaped']is True and row['timed_out']is False and
         row['cleanup_errors']==[]and all(d['closed']is True for d in row['descriptors']),
         'only completed original processes are reread')
def load(name,path):
    p=Path(path).resolve(strict=True);raw=retained(p)
    module=types.ModuleType(name);module.__file__=str(p);LOADED.append(module)
    exec(compile(raw,str(p),'exec'),module.__dict__);return module
def closure():
    queue=list(sys.modules.values())+LOADED;seen=set();errors=[]
    while queue:
        module=queue.pop()
        if not isinstance(module,types.ModuleType)or id(module)in seen:continue
        seen.add(id(module));queue.extend(v for v in vars(module).values()if isinstance(v,types.ModuleType))
        p=getattr(module,'__file__',None)
        if p and Path(p).is_file():
            try:retained(p)if str(Path(p).resolve(strict=True))not in USED else checked(p,USED[str(Path(p).resolve(strict=True))])
            except BaseException as error:errors.append(type(error).__name__+': '+str(error))
    for p,value in tuple(USED.items()):
        try:checked(p,value)
        except BaseException as error:errors.append(type(error).__name__+': '+str(error))
    for p,value in R['namespace_aliases'].items():
        if not(Path(p).is_symlink()and os.readlink(p)==value):errors.append('namespace alias changed: '+p)
    need(not errors,'complete source/input closure: '+repr(errors))
def names(value,count,raw,key='original_sha256'):
    xs=value['refusals'];need(type(xs)is list and all(type(x)is str and x for x in xs)and
        len(xs)==len(set(xs))==count and type(value['native_operations'])is int and
        value['native_operations']==0,'exact separate diagnostic control population')
    if key is not None:need(value[key]==digest(raw)['sha256'],'controls bind unchanged actual input')

def worker():
    result=dict(status='diagnostic_failed',stage='inputs',error=None,target_execution=0,qualification_credit=False)
    try:
        tests=ROOT/'tools/page-entry/selected/tests'
        cohort=load('diagnostic_cohort',ROOT/'evaluation/inprocess/persistent_group.py')
        app=load('diagnostic_app',tests/'persistent_group_app/read.py')
        owner=load('diagnostic_owner',tests/'persistent_group_owner/read.py')
        seed=load('diagnostic_seed',tests/'provider_app/seed_probe/read.py')
        xs=load('diagnostic_xstate',tests/'b2_reference/xstate.py')
        need(app.APP_CONTROL_COUNTS=={0:16}and app.PAIR_CONTROL_COUNTS=={0:4}and
             owner.CONTROL_COUNTS=={0:79}and cohort.reports.CONTROL_COUNTS=={(0,0):63},
             'unchanged complete loop-only refusal populations')
        sr=COMMANDS['seed-prerequisite'];completed(sr);raw=capture(sr,'stdout')
        need(not capture(sr,'stderr'),'actual seed stderr empty')
        h=struct.unpack_from('<16Q',raw,128);cp=[struct.unpack_from('<6I',raw,256+24*i)for i in range(67)]
        facts=xs.profile(cp,h[8],h[10],h[12],h[5],h[6])
        profile=seed.read(raw,retained(PRIVATE/'seed-probe'),facts,xs,cpu=R['cpu'],pid=sr['pid'])
        need(canonical(profile)==canonical(R['seed_prerequisite']['profile'])and
             canonical(facts)==canonical(R['seed_prerequisite']['format']),'same whole retained seed/hardware')
        seed_reference=(seed,xs,profile,facts)
        original=binary(PRIVATE/'application/persistent-group-app');carrier=binary(PRIVATE/'carrier')
        bridge=binary(PRIVATE/'persistent-group-capture/bridge-persistent-group-capture.so')
        archive=retained(R['build']['artifacts']['decoder.a']['path'])
        need(digest(archive)==R['release_build']['archive']==R['release_build']['persistent_binding']['archive'],
             'same retained actual decoder archive across build and bound group image')
        for group in(R['reader_support']['headers'],R['application_build']['headers'],R['release_build']['headers']):
            for p,expected in group.items():need(digest(retained(p))==expected,'complete actual source/header closure')
        for item in R['release_build']['persistent_binding']['sources']:
            need(digest(retained(ROOT/'tools/page-entry/selected'/item['path']))=={k:item[k]for k in('bytes','sha256')},'actual bound runtime source')
        for item in R['runtime_libraries'].values():
            need(digest(retained(item['path']))=={k:item[k]for k in('bytes','sha256')},'actual retained loader/library identity')
        for name in('policy-headers','policy-link'):completed(COMMANDS[name]);capture(COMMANDS[name],'stdout');capture(COMMANDS[name],'stderr')
        policy=binary(PRIVATE/'native-policy.so')
        need(digest(policy.read_bytes())==R['reader_support']['native_policy'],'same actual compiled pure classifier')
        closure();result['stage']='application_elf'
        lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
        layout=app.elf(original.read_bytes(),lambda b:lib.li2_native_policy(b,len(b)))
        need(canonical({k:v for k,v in layout.items()if k not in('source','sources')})==canonical(R['application_layout']),
             'complete current app ELF/geometry/policy equals actual original layout')
        observed=json.loads(retained(PRIVATE/'owner-dwarf-layout.json'))
        lr=COMMANDS['owner-layout'];completed(lr)
        need(capture(lr,'stdout')==retained(PRIVATE/'owner-dwarf-layout.json')and not capture(lr,'stderr')and
             digest(bridge.read_bytes())==R['owner_layout']['bridge'],'actual GDB layout and exact bridge')
        interp=binary(R['namespace_plan']['interpreter']);roots=list(map(Path,R['namespace_plan']['roots']))
        objects,description=cohort.namespace.plan(original,roots,bytes.fromhex(digest(original.read_bytes())['sha256']),bytes.fromhex(digest(interp.read_bytes())['sha256']))
        need(canonical(description)==canonical(R['namespace_plan']),'same actual dependency plan')
        for item in objects:need(retained(item['path'])==item['bytes'],'complete dependency bytes')
        nr=COMMANDS['subject-native-0-0'];gr=COMMANDS['subject-gated-0-0'];completed(nr);completed(gr)
        need(nr['bounds']==gr['bounds']==[30,512<<20,16<<20,60]and not capture(nr,'stderr'),'original target bounds and empty native stderr')
        context=dict(cpu=R['cpu'],namespace_aliases={})
        manifests=[]
        for c,row in zip(R['cases'],(nr,gr),strict=True):
            need(c['label']==row['name'],'same two original subjects')
            manifests.append(cohort.preparation(c,row,PRIVATE/c['label'],original,roots,objects,description,carrier,PRIVATE,binary,context))
        need(context['namespace_aliases']==R['namespace_aliases'],'whole actual namespace aliases')
        image=cohort.image_inventory(original,interp,carrier,objects,manifests[1])
        image.update(bridge=bridge.read_bytes(),persistent_binding=R['release_build']['persistent_binding'],headers=R['release_build']['headers'])
        for name,p in(('original',original),('interpreter',interp),('carrier',carrier),('bridge',bridge)):
            need(digest(retained(p))==R['subject_artifacts'][name],'complete actual subject artifact '+name)
        images=R['external_inputs'];raws=[retained(PRIVATE/'external-inputs'/f'{i}.elf')for i in range(len(images))]
        for item,data in zip(images,raws,strict=True):need(digest(data)=={k:item[k]for k in('bytes','sha256')},'exact external image')
        native_raw=capture(nr,'stdout');gated_raw=capture(gr,'stdout');record=capture(gr,'record');stderr=capture(gr,'stderr')
        need(len(record)==observed['types']['pgo_wire']['bytes']+64==4183488<4<<20,'complete original bounded protected record')
        closure();result['stage']='application'
        na=(native_raw,0,True,0,layout,nr['pid'],R['cpu'],seed_reference)
        ga=(gated_raw,0,False,0,layout,gr['pid'],R['cpu'],seed_reference)
        native=app.read(*na);gated=app.read(*ga)
        result['stage']='owner_positive';oa=(record,observed,image,gated,gr['pid'],R['cpu'],0)
        actual=owner.read(*oa)
        result['owner_summary']={k:actual[k]for k in('mode','classified_misses','cold_publications','warm_entries','replacements','permit_claims','interior_signals','word','code','detail','status')}
        result['stage']='terminal_positive'
        ta=(gr['pid'],0,gr['stdout_provenance_before'],images,raws,digest(carrier.read_bytes()),carrier.read_bytes(),actual,owner,0)
        _,result['terminal']=cohort.reports.check(stderr,*ta)
        result['stage']='pair_positive';result['pair']=app.pair(native,gated,actual)
        need(canonical(result['pair'])==canonical(dict(observed_loop_pair=1,invocations=1,generated_completed=2,
             interior_signals=0,warm_entries=1,architectural_link_traversals=6,measured_link_events=0,qualification_credit=False)),
             'unchanged exact cold/warm full-state loop pair')
        # Do not spend mutation work until all four complete positives succeed.
        result['stage']='controls'
        result['app_controls']=app.controls(*na);names(result['app_controls'],16,native_raw)
        result['owner_controls']=owner.controls(*oa);names(result['owner_controls'],79,record)
        result['pair_controls']=app.pair_controls(native,gated,actual);names(result['pair_controls'],4,b'',key=None)
        result['terminal_controls']=cohort.reports.controls(stderr,*ta);names(result['terminal_controls'],63,stderr,key='original_stderr_sha256')
        result.update(status='diagnostic_passed',stage='complete')
    except BaseException as error:result['error']=type(error).__name__+': '+str(error)
    try:closure();result['source_and_inputs_unchanged']=True
    except BaseException as error:
        result.update(status='diagnostic_failed',source_and_inputs_unchanged=False,closure_error=type(error).__name__+': '+str(error))
    result['used_files']=len(USED);result['used_files_sha256']=digest(canonical(USED).encode())['sha256']
    print(canonical(result),flush=True);return int(result['status']!='diagnostic_passed')

def publish(result):
    """Only compact numeric outcomes/hashes; private paths and errors stay private."""
    outcome=result.get('result')or {};row=result['command']
    controls={name:dict(count=len(outcome.get(name,{}).get('refusals',[])),
        sha256=digest(canonical(outcome.get(name,{})).encode())['sha256'])
        for name in('app_controls','owner_controls','pair_controls','terminal_controls')}
    def hw(value):
        if value is None:return None
        value=dict(value);flags=value.pop('isa_flags')
        return dict(value,isa_flags_count=len(flags),isa_flags_sha256=digest(canonical(flags).encode())['sha256'])
    command=['${PYTHON}','-I','-S','-B','${REPO}/'+str(SCRIPT.relative_to(ROOT)),
             '--root','${REPO}','--receipt','${CLOSED_RECEIPT}','--output','${OUTPUT}',
             '--expect-revision',ARGS.expect_revision]
    summary=dict(schema=1,profile='persistent-group-layout-reader-replay-v1',status=result['status'],
        reader_revision=ARGS.expect_revision,source=result.get('source'),source_unchanged=result.get('source_unchanged',False),
        driver=DRIVER,python=result.get('python'),readers=result.get('readers'),
        original_revision=ORIGINAL_REVISION,original_source=R['source'],original_receipt=ORIGINAL_RECEIPT,
        original_status='failed',original_observed=1,original_planned=2,
        original_error='ValueError: actual minimal field layout li2_pg_compact.head',
        original_hardware=hw(R['hardware']),replay_hardware=hw(result.get('hardware')),
        original_cpu=R['cpu'],replay_cpu=result['replay_cpu'],bounds=row['bounds'],capture_limit=row['capture_limit'],
        reproduction_argv=command,reproduction_environment='One externally reserved CPU; exact retained historical437 receipt and all its inputs.',
        reader_argv=command+['--child','--receipt-sha256',ORIGINAL_RECEIPT['sha256'],'--driver-sha256',DRIVER['sha256']],
        exit=row.get('exit'),duration_ns=row.get('duration_ns'),timed_out=row.get('timed_out'),reaped=row.get('reaped'),
        captures={k:{j:v[j]for j in('bytes','sha256')}for k,v in row.get('captures',{}).items()},
        stage=outcome.get('stage'),reader_error_type=(outcome.get('error')or '').split(':',1)[0]or None,
        outer_error_type=result.get('error_type'),pair=outcome.get('pair'),owner_summary=outcome.get('owner_summary'),
        controls=controls,input_count=outcome.get('used_files'),input_manifest_sha256=outcome.get('used_files_sha256'),
        source_and_inputs_unchanged=result['source_and_inputs_unchanged']and outcome.get('source_and_inputs_unchanged',False),
        cleanup_complete=result['cleanup_complete'],final_error_count=len(result['final_errors']),
        receipt=digest((OUTPUT/'RESULT.json').read_bytes()),target_execution=0,qualification_credit=False,
        timing_credit=False,scope='Current readers over historical captures only. Original failed result is unchanged; no new native result or performance credit.')
    text=json.dumps(summary,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<=32<<10 and all(v not in text for v in
         (str(ROOT),str(Path.home()),platform.node(),'/home/')), 'bounded public projection contains no host paths or hostname')
    public=ROOT/'evaluation/inprocess/results'/result['public_name'];public.parent.mkdir(parents=True,exist_ok=True)
    with public.open('x')as f:f.write(text)
    print(public.relative_to(ROOT),flush=True)

def main():
    need(sys.flags.isolated and sys.flags.no_site and not sys.flags.optimize and len(os.sched_getaffinity(0))==1,
         'isolated no-site assertions with one externally reserved reader CPU')
    os.chdir(ROOT);sys.path[:0]=[str(ROOT/'evaluation/inprocess'),str(ROOT/'tools/page-entry')]
    if ARGS.child:return worker()
    OUTPUT.mkdir(mode=0o700)
    row=dict(name='retained-group',argv=[sys.executable,'-I','-S','-B',str(SCRIPT),
             '--root',str(ROOT),'--receipt',str(RECEIPT),'--output',str(OUTPUT),
             '--expect-revision',ARGS.expect_revision,'--child',
             '--receipt-sha256',ORIGINAL_RECEIPT['sha256'],'--driver-sha256',DRIVER['sha256']],
             environment=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC'),profile='reader_only',
             bounds=[30,512<<20,16<<20,60],capture_limit=16<<20,expected_exit=0)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    result=dict(scope='closed437 complete group reader only',status='failed_reader_diagnostic',original_receipt=ORIGINAL_RECEIPT,
                reader_revision=ARGS.expect_revision,original_status='failed',original_observed=1,original_planned=2,
                driver=DRIVER,public_name=stamp+'-persistent-group-layout-replay-'+ARGS.expect_revision[:12]+'.json',
                target_execution=0,qualification_credit=False,replay_cpu=next(iter(os.sched_getaffinity(0))),
                original_cpu=R['cpu'],command=row,result=None,final_errors=[])
    source=None
    try:
        from page_selected_process import invoke
        from checks import source
        from run import hardware
        result['source']=source()
        need(result['source']['revision']==ARGS.expect_revision,'exact current clean invocation revision')
        result['hardware']=hardware(result['replay_cpu']);result['python']=digest(retained(sys.executable))
        result['readers']={name:digest(retained(ROOT/path))for name,path in(
            ('app','tools/page-entry/selected/tests/persistent_group_app/read.py'),
            ('owner','tools/page-entry/selected/tests/persistent_group_owner/read.py'),
            ('wire',wire['path']),('plan','tools/page-entry/selected/tests/persistent_group_owner/plan.py'),
            ('terminal','evaluation/inprocess/persistent_group_reports.py'))}
        closure();out,err=invoke(row,OUTPUT,result['replay_cpu']);need(not err,'reader child stderr empty')
        result['result']=json.loads(out);need(row['exit']==int(result['result']['status']!='diagnostic_passed'),'actual child outcome')
        if result['result']['status']=='diagnostic_passed':result['status']='passed_reader_diagnostic'
    except BaseException as error:result.update(error=type(error).__name__+': '+str(error),error_type=type(error).__name__)
    try:
        need(source is not None and source()==result.get('source'),'exact current source unchanged')
        result['source_unchanged']=True
    except BaseException as error:result['final_errors'].append(type(error).__name__+': '+str(error))
    try:closure()
    except BaseException as error:result['final_errors'].append(type(error).__name__+': '+str(error))
    result['source_and_inputs_unchanged']=not result['final_errors']
    result['cleanup_complete']=row.get('reaped')is True and row.get('cleanup_errors')==[]and all(x['closed']is True for x in row.get('descriptors',[]))
    if result['final_errors']or not result['cleanup_complete']:result['status']='failed_reader_diagnostic'
    with (OUTPUT/'RESULT.json').open('x')as f:json.dump(result,f,indent=2,sort_keys=True);f.write('\n')
    publish(result)
    return int(result['status']!='passed_reader_diagnostic')
if __name__=='__main__':raise SystemExit(main())
