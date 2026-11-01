"""Read-only prerequisite joins for the finite RET owner experiment.

check_all(args,current,pin,archive,build) performs no process invocation, imports
no candidate reader, and never replays controls. The four receipt/SHA pairs are
explicit CLI inputs. A transitive receipt is selected only by its complete fact
already recorded in its authenticated parent's input table, never by a glob.
The caller must retain every pin through its original final closure.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
from call_owner import custody
from call_owner import run as call_api
from call_dispatch_native import run as native_api
from ret_dispatch import run as ret_api
from ret_resume_native import run as ordering_api
from page_selected import ENV
from scalar_span_trace_build import fast_bytes_completed

ROOT = custody.ROOT
COMPILE_SOURCE = ROOT/'evaluation/inprocess/ret_runtime_compile/SOURCE.json'
FINITE = [5,512<<20,16<<20,15]
BUILD = [30,512<<20,16<<20,60]
CALL_RESULT = dict(native_subjects=2,gated_subjects=4,full_builds=2,byte_oracles=2,
    seed_prerequisites=1,native_frames=14,application_controls=80,owner_controls=656,
    pair_controls=160,terminal_controls=292,tls_controls=132,probe_controls=88,
    subentry_controls=76,effect_controls=48,finite_prerequisites=2,owner_pairs=4,
    raw_bytes=990144,record_bytes=990208,record_limit=4194304,archive_builds=0,
    whole_profile_qualified=False,qualification_credit=False,performance_credit=False)
CALL_PREFIX = ('resolve-cc1 resolve-collect2 resolve-as resolve-ld version-cc version-as '
    'version-ld version-nm version-readelf version-python compiler-specs archive-exports '
    'app-interpreter-headers app-interpreter-link app-interpreter-undefined app-interpreter-symbols '
    'app-headers app-link app-undefined app-elf app-objdump-version app-symbols app-body-main '
    'app-body-collect app-body-copy app-body-same app-body-ua_data_pattern app-body-ua_stack_pattern '
    'app-copy-headers app-pure-preprocess copy-pure-preprocess app-copy-link app-copy-symbols '
    'app-copy-body app-copy-libraries app-copy-run policy-headers policy-link seed-headers '
    'seed-link seed-libraries seed-prerequisite').split()
CALL_LANE = ('binding headers link undefined providers symbols elf objdump-version reset '
    'span-bytes-headers-0 span-bytes-link span-bytes-native-libraries span-bytes-oracle '
    'capture-raw-symbols capture-raw-body whole-call-owner-layout carrier').split()
CALL_CASES = [('subject-'+lane+'-'+str(mode)+'-0',mode,lane)
              for mode in (0,1) for lane in ('native','maintained','differential')]
CALL_COMMANDS = CALL_PREFIX+[lane+'-'+x for lane in ('maintained','differential')
    for x in CALL_LANE]+[x[0] for x in CALL_CASES]


def need(ok,message):
    if not ok: raise ValueError(message)


def value(f):
    return {k:f[k] for k in ('bytes','sha256')}


def row(old,name):
    matches=[x for x in old['commands'] if x['name']==name]
    need(len(matches)==1,'one exact retained command: '+name)
    return matches[0]


def captured(path,old,name,stream='stdout'):
    command=row(old,name);f=command['captures'][stream]
    return (path.parent/f['file']).read_bytes()


def child(parent,wanted,pin):
    names=[name for name,f in parent['inputs'].items()
           if f==wanted and Path(name).name=='receipt.json']
    need(len(names)==1,'one whole transitive receipt in authenticated input custody')
    path=pin(names[0]);need(custody.fact(path)==wanted,'exact transitive receipt fact')
    return path


def closed(path,sha,current,pin,profile,status,bounds,commands=None,owner=False):
    path=pin(path)
    need(re.fullmatch('[0-9a-f]{64}',sha) and custody.fact(path)['sha256']==sha,
         'explicit whole prerequisite SHA256')
    old=custody.load(path)
    need(old['schema']==1 and old['profile']==profile and old['status']==status and
         old['revision']==current['revision'] and old['source']==current['source'] and
         old['cpu']==current['cpu']==3 and old['hardware']==current['hardware'],
         'same exact current source, CPU3, hardware and typed prerequisite outcome')
    need(all(old[k] is True for k in ('source_unchanged','inputs_unchanged','cleanup_complete'))
         and old['error'] is None and old['final_errors']==[] and
         old['qualification_credit'] is False and old['performance_credit'] is False and
         old['bounds']==bounds,'complete closed prerequisite with original exact bounds')
    for group in ('inputs','artifacts'):
        for name,wanted in old[group].items():
            need(custody.fact(pin(name))==wanted,'whole retained '+group+': '+name)
    for name,target in old['aliases'].items():
        need(str(pin(name))==target,'whole retained alias')
    for name,target in old.get('context_links',{}).items():
        need(Path(name).is_symlink() and os.readlink(name)==target and
             str(pin(name))==str(Path(target).resolve(strict=True)),'whole retained context link')
    if owner:
        # This fixed tiny-interpreter fixture has no DT_NEEDED objects and
        # therefore creates no dependency FD aliases. Never resolve a closed FD.
        need(old['namespace_aliases']=={},'exact empty dependency-alias population of the fixed CALL fixture')
    for name,exists in old['loader_presence'].items():
        need(Path(name).exists()==exists,'unchanged actual loader configuration presence')
    names=[x['name'] for x in old['commands']]
    need(names and len(names)==len(set(names)) and (commands is None or names==commands),
         'complete unique fixed prerequisite command schedule')
    allowed=list(bounds.values()) if type(bounds)is dict else [bounds]
    records={label for label,_,lane in CALL_CASES if lane!='native'} if owner else set()
    for command in old['commands']:
        need(type(command['exit'])is int and command['exit']==command['expected_exit']==0 and
             command['error'] is None and command['timed_out'] is False and
             command['reaped'] is True and command['cleanup_errors']==[] and
             all(x['closed'] is True for x in command['descriptors']) and
             command['bounds'] in allowed and command['capture_limit']==16<<20,
             'every prerequisite process successful, bounded and fully reaped')
        streams={'stdout','stderr','record'} if command['name'] in records else {'stdout','stderr'}
        need(set(command['captures'])==streams,'exact typed prerequisite stream ownership')
        for stream,f in command['captures'].items():
            q=path.parent/f['file']
            need(q.parent==path.parent and not q.is_symlink(),'contained whole prerequisite capture')
            actual=custody.fact(pin(q))
            need(actual==old['artifacts'][str(q)] and value(actual)==value(f),
                 'actual command capture and whole artifact agree')
            if stream=='record':need(f['bytes']==990208<4<<20,'complete old CALL owner record')
    return path,old


def ledger(v,count,sha=None,key='original_stderr_sha256'):
    names=v['refusals']
    need(type(names)is list and len(names)==len(set(names))==count and
         all(type(x)is str and x for x in names) and type(v['native_operations'])is int and
         v['native_operations']==0,'complete distinct retained control population')
    if sha is not None:need(v[key]==sha,'control ledger binds actual whole capture')


def call217(path,current,pin):
    p=custody.load(path);wanted=native_api.CALL217
    path,p=closed(path,custody.fact(path)['sha256'],current,pin,wanted['profile'],
                  wanted['status'],wanted['bounds'],wanted['commands'])
    finite_names={'emitted-inspection','read-all-chunks',*('native-'+str(i) for i in range(7))}
    need(all(c['bounds']==(FINITE if c['name'] in finite_names else BUILD)
             for c in p['commands']),'each original217 command retains its exact bound')
    need(all(x['environment']==ENV for x in p['commands']),'original CALL217 environment')
    need(row(p,'read-all-chunks')['captures']['stderr']['bytes']==0,'complete CALL217 reader')
    observed=custody.load(path.parent/row(p,'read-all-chunks')['captures']['stdout']['file'])
    expected=native_api.compact(observed);expected['raw_sources']=observed['sources']
    need(p['result']==expected and p['call_push_equivalence'] is None and
         p['production_admission_credit'] is False and observed['cpu']==3,
         'all original217 results without general CALL/PUSH equivalence')
    need(len(observed['sources'])==7,'all seven original raw chunks')
    for i,f in enumerate(observed['sources']):
        c=row(p,'native-'+str(i));out=c['captures']['stdout']
        need(c['bounds']==FINITE and c['captures']['stderr']['bytes']==0 and
             f==dict(chunk=i,pid=c['pid'],bytes=out['bytes'],sha256=out['sha256']),
             'whole original217 raw/PID/CPU/reader join')
    return custody.fact(path)


def call_owner(path,sha,current,pin,archive,build):
    path,p=closed(path,sha,current,pin,'public-call-owner-gated-v1','passed',
                  call_api.BOUNDS,CALL_COMMANDS,owner=True)
    need(p['result']==CALL_RESULT and p['archive_builds']==0 and
         p['pending']==['original392','original522','ten_run_DR'],'exact finite CALL result and pending original gates')
    need(all(c['bounds']==call_api.BOUNDS[c['profile']] for c in p['commands']),
         'every CALL command retains its declared source-owned profile bounds')
    reuse=p['archive_reuse']
    need(reuse['archive']==custody.fact(archive) and reuse['build']==build and
         reuse['cpu']==3 and reuse['fresh_build'] is False and
         reuse['source_tools_features_verified'] is True and reuse['prior_status']=='passed' and
         reuse['prior_owner_credit'] is False,'same exact authenticated public archive build')
    archive_path=child(p,reuse['receipt'],pin)
    checked_archive,checked_build,_,_,_=custody.check_archive(
        archive_path,custody.fact(archive_path)['sha256'],current,pin)
    need(custody.fact(checked_archive)==custody.fact(archive) and checked_build==build,
         'same complete archive source/tool/features/configuration provenance')
    finite=p['finite_prerequisites'];need(set(finite)=={'components','native136'},'both distinct CALL finite prerequisites')
    model_path=child(p,finite['components']['receipt'],pin)
    model=custody.check_components(model_path,custody.fact(model_path)['sha256'],current,pin,archive)
    native_path=child(p,finite['native136']['receipt'],pin)
    native_manifest=custody.load(pin(ROOT/'evaluation/inprocess/call_dispatch_native/SOURCE.json'))
    native_names=('resolve-cc1 resolve-collect2 resolve-as resolve-ld version-cc version-as '
                  'version-ld version-nm').split()
    native_names += ['link-input-'+x for x in native_manifest['link_names']]
    native_names += ('compiler-specs retained-archive-exports headers-0 headers-1 headers-2 '
                     'headers-3 build emitted-inspection runtime-dependencies').split()
    native_names += ['native-'+str(i) for i in range(6)]+['read-all-chunks']
    native_path,native=closed(native_path,custody.fact(native_path)['sha256'],current,pin,
        'public-call-dispatch-native-v1','passed',{'build':BUILD,'native':FINITE},native_names)
    finite_names={'emitted-inspection','read-all-chunks',*('native-'+str(i) for i in range(6))}
    need(all(c['bounds']==(FINITE if c['name'] in finite_names else BUILD)
             for c in native['commands']),'every native136 command retains its exact original bound')
    need(native['archive_reuse']['archive']==custody.fact(archive) and
         native['archive_reuse']['release_build']==build and native['archive_builds']==0 and
         native['emitted_execution']==136 and native['owner_credit']==0 and
         native['prerequisites']['model']['receipt']==custody.fact(model_path),
         'native136 preserves the same complete component and archive chain')
    need(native['commands'][-1]['name']=='read-all-chunks' and
         row(native,'read-all-chunks')['captures']['stderr']['bytes']==0 and
         all(x['environment']==ENV for x in native['commands']),'whole final native136 reader and environment')
    observed=custody.load(native_path.parent/row(native,'read-all-chunks')['captures']['stdout']['file'])
    need(native['result']==native_api.native_compact(observed) and observed['cpu']==3 and
         len(observed['sources'])==6,'all136 pairs and six actual raw chunks')
    for i,f in enumerate(observed['sources']):
        c=row(native,'native-'+str(i));out=c['captures']['stdout']
        need(c['bounds']==FINITE and c['captures']['stderr']['bytes']==0 and
             f==dict(chunk=i,pid=c['pid'],bytes=out['bytes'],sha256=out['sha256']),
             'all native136 actual raw/PID/CPU/reader joins')
    original=call217(child(native,native['prerequisites']['old217']['receipt'],pin),current,pin)
    need(finite['components']==dict(receipt=custody.fact(model_path),revision=current['revision'],
             results={k:v['result'] for k,v in model['components'].items()},fresh_execution=False,owner_credit=False) and
         finite['native136']==dict(receipt=custody.fact(native_path),revision=current['revision'],
             result=native['result'],fresh_execution=False,owner_credit=False),'whole CALL prerequisite summaries')
    need(set(p['lanes'])=={'maintained','differential'} and p['seed_prerequisite']['status']=='passed',
         'both full CALL builds and actual seed')
    for lane in ('maintained','differential'):
        state=p['lanes'][lane];b=state['release_build']
        need(b['status']=='passed' and b['call_owner_capture'] is True and
             b['persistent_binding']['archive']==value(custody.fact(archive)) and
             state['schema']==dict(fields=1249,owner_credit=0,raw_bytes=990144,
                 record_bytes_observed=0,schema_only=True,types=116),
             'both old complete CALL capture builds and exact schema')
        fast_bytes_completed(b,p['commands'],pin)
    need([(x['label'],x['mode'],x['mapping_lane']) for x in p['cases']]==CALL_CASES,
         'all six fixed CALL subjects in order')
    for case,(label,mode,lane) in zip(p['cases'],CALL_CASES,strict=True):
        c=row(p,label);gated=lane!='native'
        need(case['status']=='passed' and case['launched'] is True and case.get('error') is None and
             case['lane']==('gated' if gated else 'native') and case['control']==0 and
             case['exit']==case['expected_exit']==0 and case['timed_out'] is False and
             case['captures']==c['captures'] and case['whole_process_ns']==c['duration_ns'] and
             case['bounds']==c['bounds']==call_api.BOUNDS['program' if gated else 'native'],
             'actual complete same-mode CALL process joins')
        if not gated:
            ledger(case['application_controls'],40,c['captures']['stdout']['sha256'],'original_sha256')
            need(c['captures']['stderr']['bytes']==0,'native CALL stderr empty');continue
        ledger(case['owner_controls'],164,c['captures']['record']['sha256'],'source_sha256')
        ledger(case['pair_controls'],40)
        need(case['owner_record_sha256']==c['captures']['record']['sha256'],'whole actual CALL owner record identity')
        for key,count in (('terminal',73),('tls',33),('probe',22),('subentry',19),('effect',12)):
            ledger(case[key+'_controls'],count,c['captures']['stderr']['sha256'])
        expected=dict(observed_call_owner=1,mode=mode,invocations=1,native_instructions=6,native_full_frames=7,
            generated_completed=1,cold_publications=1,domain_members=1,closed_pages=17,
            modeled_generated_instructions=2 if mode else 4,modeled_ordinary_call=int(bool(mode)),
            modeled_cached_call=int(not mode),original_return_pc=p['application_layout']['page']+0x20d,
            stack_bytes=520,measured_interior_signals=0,lifetime_mode=2,registration_epoch=0,
            registration_calls=0,word_observed=0,qualification_credit=False)
        need(case['pair']==expected,'exact old full-state CALL pair result')
    return dict(receipt=custody.fact(path),result=p['result'],old217=original)


def ret(path,sha,current,pin,archive):
    wanted=custody.load(pin(ROOT/'evaluation/inprocess/ret_resume_native/SOURCE.json'))['prerequisite']
    path,p=closed(path,sha,current,pin,wanted['profile'],wanted['status'],wanted['bounds'],wanted['commands'])
    finite_names={'ret_dispatch-component','ret_dispatch_plan-component',
                  'ret_dispatch_native_high-native','ret_dispatch_native_high-reader',
                  *(name+'-'+step for name in ('ret_native','ret_dispatch_native')
                    for step in ('inspection','native','reader'))}
    need(all(c['bounds']==(FINITE if c['name'] in finite_names else BUILD)
             for c in p['commands']),'each combined RET command retains its exact bound')
    need(p['archive']==custody.fact(archive) and p['archive_builds']==0 and
         p['archive_source_provenance_verified'] is False and p['generated_execution']==32 and
         p['native_execution']==80 and all(p[k] is False for k in
             ('loaded_miss_resumption','production_owner_authority','owner_credit')),
         'exact archive and five separate complete RET scopes')
    need(set(p['components'])=={'ret_native','ret_dispatch','ret_dispatch_plan','ret_dispatch_native','ret_dispatch_native_high'} and
         [p['components'][name]['status'] for name in
             ('ret_native','ret_dispatch','ret_dispatch_plan','ret_dispatch_native','ret_dispatch_native_high')]==
             ['observed_unqualified','passed','passed','finite_ret_adapter_observed','finite_ret_adapter_observed'] and
         all(x['environment']==ENV for x in p['commands']),'fixed complete RET stages/environment')
    for name in ('ret_dispatch','ret_dispatch_plan'):
        expected=ret_api.CASES[name]['stdout'].encode()
        need(captured(path,p,name+'-component')==expected and
             row(p,name+'-component')['captures']['stderr']['bytes']==0 and
             p['components'][name]['result']=={k.decode():int(v) for k,v in re.findall(rb'(\w+)=(\d+)',expected)},
             'all671/924 model cases, added far controls and exact whole component stdout')
    low=p['components']['ret_dispatch_native'];high=p['components']['ret_dispatch_native_high']
    need(high==dict(low,status=high['status'],result=high['result'],
             address_model='high-cluster-low-window',executable_reused_from='ret_dispatch_native') and
         row(p,'ret_dispatch_native_high-native')['argv']==row(p,'ret_dispatch_native-native')['argv']+['--high'],
         'high cohort reuses the same whole inspected executable and all actual build metadata')
    for name,extent in (('ret_native',5879872),('ret_dispatch_native',8845632),('ret_dispatch_native_high',8845632)):
        rr=row(p,name+'-reader');c=row(p,name+'-native');out=c['captures']['stdout']
        need(rr['captures']['stderr']['bytes']==c['captures']['stderr']['bytes']==0 and
             c['bounds']==rr['bounds']==FINITE and out['bytes']==extent,'whole original native chunk/read bounds')
        observed=custody.load(path.parent/rr['captures']['stdout']['file'])
        source=dict(pid=c['pid'],bytes=extent,sha256=out['sha256'])
        if name!='ret_native':source['cpu']=3;result=ret_api.native_compact(observed)
        else:
            need(observed['cpu']==3,'actual RET32 reader CPU');result=ret_api.ret_compact(observed)
            result['observations']=observed['observations']
        need(observed['source']==source and p['components'][name]['result']==result,
             'whole actual RET raw/PID/CPU/reader projection')
        if name=='ret_dispatch_native_high':
            raw=captured(path,p,name+'-native');h=struct.unpack_from('<64Q',raw)
            geometry=dict(model='high-cluster-low-window',cluster=h[21],cluster_bytes=24*4096,
                window=h[34],loaded_miss=h[34]+128,generated=h[30],loaded_jump_offset=190,
                loaded_jump_bytes=6,landing_literal_offset=504,
                signed_distance=h[34]+128-(h[30]+196),beyond_rel32=True)
            need(observed['address_geometry']==geometry and geometry['signed_distance']<-(1<<31) and
                 (h[23],h[30],h[31],h[32],h[33],h[35])==tuple(h[21]+n*4096 for n in (1,3,11,19,20,23)) and
                 h[34]+4096<=1<<31 and h[21]>h[34]+4096+0x7fffffff and h[21]+24*4096<1<<47 and
                 h[15:17]==(c['pid'],3),
                 'actual high raw/PID/CPU/cluster/literal geometry beyond signed32 reach')
        elif name=='ret_dispatch_native':
            need('address_geometry' not in observed,'original low cohort remains separate')
    original=call217(child(p,p['prerequisite']['receipt'],pin),current,pin)
    return path,p,dict(receipt=custody.fact(path),old217=original,ret32_cases=32,models=671,adapter_cases=16,adapter_lanes=24,
        planner_plans=8,planner_models=924,high_adapter_cases=16,high_adapter_lanes=24)


def ordering(path,sha,current,pin,ret_path):
    manifest=custody.load(pin(ROOT/'evaluation/inprocess/ret_resume_native/SOURCE.json'))
    path,p=closed(path,sha,current,pin,'public-ret-resume-native-ordering-v1','observed_unqualified',
                  manifest['bounds'],manifest['commands'])
    finite_names={'emitted-inspection','handler-disassembly','operand-load-inspection','native-0','read-ordering'}
    need(all(c['bounds']==(FINITE if c['name'] in finite_names else BUILD)
             for c in p['commands']),'each ordering command retains its exact bound')
    need(p['prerequisite']==dict(receipt=custody.fact(ret_path),revision=current['revision'],
             status='finite_experiments_passed',cases=32,executed_here=False,ret_continuation_safe=None) and
         p['native_cases']==15 and p['archive_builds']==p['archive_copies']==0 and
         p['ret_continuation_safe'] is None and all(p[k] is False for k in
             ('production_continuation','production_admission_credit','owner_credit')),
         'ordering uses the exact same combined RET prerequisite without owner credit')
    need(all(x['environment']==ENV for x in p['commands']),'original ordering environment')
    c=row(p,'native-0');rr=row(p,'read-ordering');out=c['captures']['stdout']
    need(c['bounds']==rr['bounds']==FINITE and out['bytes']==2879240 and
         c['captures']['stderr']['bytes']==rr['captures']['stderr']['bytes']==0,'whole15-lane ordering chunk and reader')
    observed=custody.load(path.parent/rr['captures']['stdout']['file'])
    need(observed==p['result'] and observed['source']==dict(pid=c['pid'],bytes=out['bytes'],sha256=out['sha256']) and
         observed['cpu']==3 and observed['status']=='hardware_ordering_observed_unqualified' and
         (observed['cases'],observed['targets'],observed['routes'])==(15,5,3) and
         observed['rx_pre_instruction_trace_observed'] is True and
         observed['noncanonical_original_rsp_mapping_observed'] is True and observed['saved_word_poison_controls']==5 and
         [(x['id'],x['kind'],x['route']) for x in observed['observations']]==[(i,i//3,i%3) for i in range(15)] and
         all(observed[k] is False for k in ('loaded_miss_continuation_implemented','production_owner_authority',
             'original_RET32_replaced','original_RET_adapter_cases_replaced','qualification_credit','performance_credit')),
         'all15 full-state hardware observations, poison controls and strict scope')
    inspected=custody.load(path.parent/row(p,'operand-load-inspection')['captures']['stdout']['file'])
    disassembly=row(p,'handler-disassembly')['captures']['stdout']
    need(inspected==p['operand_load_inspection'] and inspected['status']=='single_operand_load_inspected' and
         inspected['disassembly_sha256']==disassembly['sha256'] and inspected['record_bytes']==191928 and
         len(inspected['exact_sequence'])==5 and inspected['elf_sha256']==p['emitted_inspection']['elf_sha256'] and
         all(inspected[k] is False for k in ('native_execution','production_continuation','qualification_credit')),
         'actual complete five-instruction single-load inspection retained')
    return dict(receipt=custody.fact(path),cases=15,targets=5,routes=3,poison_controls=5)


def runtime(path,sha,current,pin,archive,build,call):
    m=custody.load(pin(COMPILE_SOURCE))
    names=('resolve-cc1 resolve-collect2 resolve-as resolve-ld version-cc version-as version-ld '
           'version-nm version-readelf compiler-specs archive-exports').split()
    names += [mode+'-'+x for mode in ('release','differential')
              for x in ('headers','build','undefined','providers','elf')]
    path,p=closed(path,sha,current,pin,'public-ret-runtime-compile-v1','compile_only_passed',BUILD,names)
    need(p['inputs'][str(COMPILE_SOURCE)]==custody.fact(COMPILE_SOURCE) and
         p['archive_builds']==p['subject_executions']==0 and
         all(x['environment']==ENV for x in p['commands']),'exact installed compile source and zero subjects')
    reuse=p['archive_reuse'];oldbuild=reuse['build']
    need(reuse['archive']==custody.fact(archive) and reuse['fresh_build'] is False and
         reuse['source_tools_features_verified'] is True and reuse['prior_status']=='passed' and
         reuse['prior_owner_credit'] is False and oldbuild==build,
         'same exact public archive build; no inherited subject or owner credit')
    need(oldbuild['status']=='passed' and oldbuild['command_completed'] is True and
         oldbuild['configuration_unchanged'] is True and oldbuild['final_errors']==[] and
         oldbuild['decoder_features']==build['decoder_features']==custody.FEATURES and
         oldbuild['dep_info']==build['dep_info'] and len(oldbuild['dep_info'])==10,
         'same actual complete decoder source/features, not inferred archive equivalence')
    for name in ('cc','cc1','collect2','as','ld','nm','readelf'):
        need(value(oldbuild['tools'][name])==value(build['tools'][name])==
             value(custody.fact(pin(p['tools'][name]))),'same complete actual compiler/link tool')
    need(p['composition']==dict(context_files=sum(map(len,m['source_roster'].values())),regular_copies=0,
             source_manifest=custody.fact(COMPILE_SOURCE),tracked_changes=0) and
         set(p['profiles'])=={'release','differential'},'exact installed composition and both compile profiles')
    need(p['call_owner_prerequisite']==call,'same complete finite CALL owner prerequisite')
    image=pin(p['original_image']['path'])
    need({k:p['original_image'][k] for k in ('bytes','sha256','mode')}==custody.fact(image) and
         p['inputs'][str(image)]==custody.fact(image),'whole actual compile-only image')
    for mode in ('release','differential'):
        v=p['profiles'][mode];b=v['binding']
        expected=[]
        selected=path.parent/'context/tools/page-entry/selected'
        for name in m['policy'][mode]:expected.append(dict(path=name,**value(custody.fact(pin(selected/name)))))
        policy=hashlib.sha256(json.dumps(dict(sources=expected,original=b['original'],mode=mode),
                                      sort_keys=True,separators=(',',':')).encode()).hexdigest()
        need(v['status']=='compile_only_passed' and v['mandatory_byte_oracle_executed'] is False and
             v['typed_capture'] is False and v['owner_credit'] is False and
             b['profile']=='private-persistent-ret-compile-'+mode+'-v1' and b['mode']==mode and
             b['compile_only'] is True and b['typed_capture'] is False and b['ret_dispatch'] is True and
             b['call_dispatch'] is True and b['maps_differential']==(mode=='differential') and
             b['archive']==value(custody.fact(archive)) and b['original']['image']==value(custody.fact(image)) and
             b['sources']==expected and b['policy_sha256']==policy and
             len(expected)==(79 if mode=='release' else 82) and
             v['providers']==m['providers'] and len(v['providers'])==67 and len(set(v['providers']))==66 and
             len(v['provider_functions'])==66,'exact compile-only source policy/provider population')
        command=row(p,mode+'-build')
        need(command['argv']==v['argv'] and custody.fact(pin(command['argv'][-1]))==v['bridge'] and
             [x for x in command['argv'] if x.endswith('.a')]==[str(archive)] and
             len([x for x in command['argv'] if x.endswith(('.c','.S'))])==28,
             'actual complete28-TU compile ELF/archive joins')
    return dict(receipt=custody.fact(path),status=p['status'],profiles=['release','differential'],
                subject_executions=0,mandatory_byte_oracle_executed=False)


def check_all(args,current,pin,archive,build):
    """Require all four explicit prerequisites; return no new execution credit."""
    need(current['cpu']==3,'fixed externally reserved CPU3')
    for module in (custody,call_api,native_api,ret_api,ordering_api):pin(module.__file__)
    call=call_owner(args.call_owner_receipt,args.call_owner_receipt_sha256,current,pin,archive,build)
    ret_path,_,rv=ret(args.ret_receipt,args.ret_receipt_sha256,current,pin,archive)
    need(call['old217']==rv['old217'],'both public chains retain the same exact original217 observation')
    order=ordering(args.ret15_receipt,args.ret15_receipt_sha256,current,pin,ret_path)
    compiled=runtime(args.runtime_compile_receipt,args.runtime_compile_receipt_sha256,current,pin,archive,build,call)
    return dict(call_owner=call,ret=rv,ret15=order,runtime_compile=compiled,
                executions_here=0,controls_replayed=0,qualification_credit=False,performance_credit=False)
