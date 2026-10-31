"""One immutable graph, root and internal-head owner entries with full-state pairs."""
import ctypes,json,os,shlex,shutil,re
from pathlib import Path
from page_selected import need,elf,ENV,fact,interpreter
from page_selected_register_time_build import recipe,expand,headers
from persistent_dynamic import (MASK,load,H,digest,named,counts,control_table,seed_prerequisite,
    image_inventory,raw_emission,imported_sources)
from persistent_subentry_build import build_bridge
import namespace
import persistent_active_domain as component
import persistent_subentry_reports as reports
ROOT=Path(__file__).resolve().parents[2]
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/persistent_subentry_app'
OWNER=SELECTED/'tests/persistent_subentry_owner'
APP_COUNTS={0:32};PAIR_COUNTS={0:20};TERMINAL_COUNTS={(0,0):73}
OWNER_COUNTS={0:200}
PAIR_EXPECTED=dict(observed_subentry_pair=1,invocations=1,generated_completed=2,cold_publications=1,
    warm_entries=1,subentry_entries=1,dual_entries=0,closed_pages=34,lifetime_mode=2,registration_epoch=0,
    registration_calls=0,word_observed=0,word_available=False,architectural_compiled_instructions=68,
    measured_interior_signals=0,native_instructions=75,native_full_frames=12,qualification_credit=False)
RETAINED_WIRE_BYTES=3057152
EXPECTED_STATUS={('native',0):'observed_native_subentry_loop',
    ('maintained',0):'observed_generated_subentry_loop_maintained',
    ('differential',0):'observed_generated_subentry_loop_differential'}

def reader_support(builder,private,pin,binary,run,r):
    reader=load('persistent_subentry_app_read',FIXTURE/'read.py',pin)
    owner=load('persistent_subentry_owner_read',OWNER/'read.py',pin)
    policy=private/'native-policy.so';unit=pin(SELECTED/'native_policy.c')
    flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared']
    _,out,err=run('policy-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_policy',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_policy: '),'complete policy include rule')
    headers={str(pin(path)):fact(pin(path))for path in shlex.split(lines[0].split(':',1)[1])}
    need(str(unit)in headers and str(SELECTED/'native_policy.h')in headers,'actual policy sources')
    run('policy-link',[builder.tools['cc'],*flags,'-Wl,-z,noexecstack,--build-id=none',unit,'-o',policy],profile='release_build',env=builder.environment)
    r['reader_support']=dict(headers=headers,native_policy=fact(binary(policy)))
    lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
    return reader,owner,lambda data:lib.li2_native_policy(data,len(data))



def observed_layout(builder,bridge,private,pin,binary,run,r):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(OWNER/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']=='pso_wire'and
        layout['types']['pso_wire']['bytes']==r['release_build']['capture_extents']['wire']==RETAINED_WIRE_BYTES and
        r['release_build']['capture_extents']['stream']==RETAINED_WIRE_BYTES+64<4<<20,'actual retained owner wire and original4MiB record bound')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout



def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,control=case['lane'],case['mode'],case['control'];role='native'if lane=='native'else'gated';prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(not any(k in prep for k in('current_custody','current_control','physical_fallback')),'no unrelated launch profile')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==role and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['argv']==[str(original),str(mode),role]and prep['default_rseq']is False and prep['mode']==mode and prep['control']==control and
        [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and all(x['after']==0 for x in prep['dispositions']),
        'actual exact launch signal/mode/environment preparation')
    if lane=='native':
        need(prep['observer']is None and prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH=':'.join(map(str,roots))),'actual closed native exec environment')
        return None
    ns=directory/'namespace';manifest=json.loads(binary(ns/'namespace.json').read_bytes());launch=json.loads(binary(ns/'launch.json').read_bytes())
    need(all(manifest[k]==v for k,v in description.items())and len(manifest['objects'])==len(objects)and manifest['schema_version']==1 and
        manifest['scope']=='explicit_sealed_dependency_namespace'and manifest['status']=='prepared_not_executed'and manifest['directory']==str(ns)and
        manifest['search_policy']=='explicit roots; no RPATH/RUNPATH/cache emulation'and manifest['identity_policy']=='sealed copies and private paths; not filesystem transparency',
        'actual namespace matches complete independent source plan')
    fds=[]
    for observed,item in zip(manifest['objects'],objects,strict=True):
        need(observed['names']==item['names']and observed['needed']==item['info']['needed']and observed['source']==str(item['path'])and
            observed['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and observed['sha256']==H(item['bytes'])and
            observed['size']==len(item['bytes'])and observed['seals']==namespace.SEALS and type(observed['fd'])is int and observed['fd']>3 and observed['fd']not in fds and
            type(observed['device'])is int and observed['device']>0 and type(observed['inode'])is int and observed['inode']>0,'actual sealed dependency identity')
        fds.append(observed['fd'])
        for name in item['names']:
            p=ns/name;value='/proc/self/fd/'+str(observed['fd']);need(p.is_symlink()and os.readlink(p)==value,'actual sealed dependency alias');r['namespace_aliases'][str(p)]=value
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',argv=prep['argv'],dependency_fds=fds,
        carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],environment=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',
        LD_BIND_NOW='1',LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),GLIBC_TUNABLES='glibc.pthread.rseq=0',
        LI2_PERSISTENT_SUBENTRY_APP_MODE=str(mode)))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest



def repeat_setup_completed(stderr,image,summary,application,protected_tls):
    """Exact positive fixture site and observed-TLS identity; no row rewriting."""
    parsed={}
    for key,prefix in (('repeat_lease',b'LI2_REPEAT_LEASE '),('rseq',b'LI2_RSEQ ')):
        lines=[x for x in stderr.splitlines()if x.startswith(prefix)]
        need(len(lines)==1,'one actual positive fixture REP/rseq row')
        parsed[key]=reports.maps_view.pair.pair_reports.rseq.decode(lines[0][len(prefix):])
        need(prefix+json.dumps(parsed[key],separators=(',',':'),allow_nan=False).encode()==lines[0],
             'canonical actual fixture REP/rseq row')
    observed=reports.repeat_observed_identity(parsed,application['header'][6],application,protected_tls)
    need(summary['observed_tls']==observed,'whole actual observed-TLS REP summary')
    row=parsed['repeat_lease']
    setup=image['repeat_setup'];pc=setup['pc'];destination=setup['destination']
    binding=summary['source_binding']
    need(row['request'][:4]==[pc,setup['next_pc'],346,3]and
         row['request'][5]==0xab48f3 and row['request'][6]&0x400==0 and
         setup['count']==8 and setup['width']==8 and setup['value']==0x8877665544332211 and
         row['progress'][0]==8 and row['frames'][2:4]==[8,destination]and
         row['frames'][9:11]==[0,destination+64]and
         summary['last_code']==346 and summary['last_initial_count']==8 and
         summary['registration_scope']==reports.REPEAT_TLS_SCOPE and
         binding['module']==summary['source_module']==0 and
         binding['file_offset']==summary['source_file_offset']==setup['file_offset']and
         binding['emitted_bytes']=='f348ab'and binding['image_sha256']==image['sha256'],
         'actual positive REP is the exact low fixture STOSQ and complete eight-word destination')


def cohort(builder,products,private,pin,binary,aliases,run,r,original):
    empty_namespace_component(builder,private,pin,binary,run,r)
    subentry_component(builder,private,pin,binary,run,r)
    component.authority_component(builder,products,private,pin,binary,aliases,run,r)
    component.dispatch_component(builder,products,private,pin,binary,aliases,run,r)
    component.native_probe_component(builder,private,pin,binary,run,r)
    component.maps_parse_component(builder,private,pin,binary,run,r)
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k not in('source','sources')}
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    subjects={}
    for lane in ('maintained','differential'):
        directory=private/(lane+'-build');directory.mkdir();holder=r['lanes'][lane]={}
        def lane_run(name,argv,profile='metadata',expected=0,env=None,record=False):
            return run(lane+'-'+name,argv,profile=profile,expected=expected,env=env,record=record)
        bridge=build_bridge(builder,products,directory,pin,binary,aliases,lane_run,holder,original,
            capture=True,differential=lane=='differential')
        raw_emission(builder,bridge,pin,lane_run,holder)
        layout=observed_layout(builder,bridge,directory,pin,binary,lane_run,holder)
        inputs=prepare_inputs(original,bridge,builder,directory,pin,binary,lane_run,holder,r['application_build'])
        subjects[lane]=(bridge,layout,*inputs)
        need(holder['release_build']['status']=='passed'and
             holder['release_build']['profile']=='persistent-subentry-'+('differential'if lane=='differential'else'capture')+'-v1'and
             holder['release_build']['active_domain']['differential']==(lane=='differential')and
             holder['release_build']['active_domain']['native_probe']is True and
             holder['release_build']['persistent_binding']['native_probe']is True and
             holder['release_build']['active_domain']['parse_memo']is True and
             holder['release_build']['persistent_binding']['parse_memo']is True and
             holder['release_build']['active_domain']['subentry']is True and
             holder['release_build']['persistent_binding']['subentry']is True,
             'separate exact maintained/differential actual builds')
    need(digest(r['lanes']['maintained']['subject_artifacts']['original'])==
         digest(r['lanes']['differential']['subject_artifacts']['original'])==digest(fact(original)),
         'one unchanged original image across both independently built lanes')
    launcher=pin(FIXTURE/'launch.py');native_records={}
    imported_sources(pin)
    need(digest(counts(reader.APP_CONTROL_COUNTS))==digest(counts(APP_COUNTS))and
         digest(counts(reader.PAIR_CONTROL_COUNTS))==digest(counts(PAIR_COUNTS))and
         digest(counts(owner_reader.CONTROL_COUNTS))==digest(counts(OWNER_COUNTS))and
         digest(control_table(reports.CONTROL_COUNTS))==digest(control_table(TERMINAL_COUNTS)),
         'literal complete native-app, protected-owner, pair and terminal refusal populations')
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed'
        directory=private/label;directory.mkdir();role='native'if lane=='native'else'gated'
        selected_lane='maintained'if lane=='native'else lane
        holder=r['lanes'][selected_lane]
        bridge,layout,interp,roots,objects,description,images,raws,carrier=subjects[selected_lane]
        carrier_bytes=carrier.read_bytes()
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',role,'--mode',str(mode),'--control','0',
            '--original',original,'--preparation',directory/'preparation.json']
        for p in roots:argv+=['--library-root',p]
        if lane!='native':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,stdout,stderr=run(label,argv,profile='program',expected=c['expected_exit'],record=lane!='native')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1];c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            args=(stdout,mode,lane=='native',row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
            parsed=reader.read(*args)
            if lane=='native':
                need(stderr==b'','actual native reference stderr remains empty')
                c['application_controls']=reader.controls(*args)
                named(c['application_controls'],APP_COUNTS[mode],H(stdout));native_records[mode]=parsed
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(capture['bytes']==layout['types']['pso_wire']['bytes']+64<4<<20 and
                    fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected active-domain record within original4MiB bound')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                image.update(bridge=bridge.read_bytes(),persistent_binding=holder['release_build']['persistent_binding'],headers=holder['release_build']['headers'],app_symbols=app_layout['symbols'])
                owner_args=(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'])
                actual_owner=owner_reader.read(*owner_args)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=reports.check(stderr,*terminal_args,lane=lane,application=parsed);r['terminal_reports'][label]=terminal
                repeat_setup_completed(stderr,app_layout,c['terminal']['repeat_lease'],parsed,
                    tuple((x['before']['fs'],x['before']['gs'])for x in actual_owner['attempts']))
                c['repeat_tls_controls']=reports.repeat_tls_controls(stderr,terminal,row['pid'],images,raws,
                    fact(carrier),carrier_bytes,actual_owner,parsed)
                named(c['repeat_tls_controls'],reports.REPEAT_TLS_CONTROLS,H(stderr),hash_key='original_stderr_sha256')
                c['native_probe_controls']=reports.probe_controls(stderr,terminal)
                named(c['native_probe_controls'],reports.probe.CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['effect_controls']=reports.effect_controls(stderr,terminal)
                named(c['effect_controls'],reports.EFFECT_CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['terminal_controls']=reports.controls(stderr,*terminal_args,lane=lane,application=parsed)
                named(c['terminal_controls'],TERMINAL_COUNTS[mode,0],H(stderr),hash_key='original_stderr_sha256')
                c['subentry_controls']=reports.subentry_controls(stderr,actual_owner,owner_reader)
                named(c['subentry_controls'],reports.SUBENTRY_CONTROL_COUNT,H(stderr),hash_key='original_stderr_sha256')
                c['owner_summary']={k:actual_owner[k]for k in('mode','cold_publications','warm_entries','subentry_entries','dual_entries','replacements','permit_claims','interior_signals','lifetime_mode','registration_epoch','registration_calls','word_observed','tls_complete','code','detail','status')}
                need(all(type(v)is int and 0<=v<1<<64 for v in c['owner_summary'].values()),'only actual bounded owner counters')
                need(actual_owner['lifetime_mode']==2 and actual_owner['registration_epoch']==0 and
                     actual_owner['registration_calls']==0 and actual_owner['word_observed']==0 and
                     actual_owner['word_available']is False and actual_owner['tls_complete']==1,
                     'actual complete mode2 lifetime')
                need(mode==0 and mode in native_records,'actual same-mode complete native loop reference')
                c['pair']=reader.pair(native_records[mode],parsed,actual_owner)
                need(digest(c['pair'])==digest(PAIR_EXPECTED),'actual shared lifetime and full-state pair; no fault qualification')
                c['pair_controls']=reader.pair_controls(native_records[mode],parsed,actual_owner)
                names=c['pair_controls'];need(type(names['refusals'])is list and all(type(n)is str and n for n in names['refusals'])and
                    len(names['refusals'])==len(set(names['refusals']))==PAIR_COUNTS[mode]and
                    type(names['native_operations'])is int and names['native_operations']==0,'all exact cross-lane full-state controls')
                c['owner_reader_controls']=owner_reader.controls(*owner_args)
                named(c['owner_reader_controls'],OWNER_COUNTS[mode],H(record))
            c['status']=EXPECTED_STATUS[lane,mode]
        except Exception as error:
            c.update(status='failed',error_type=type(error).__name__,error=type(error).__name__+': '+str(error))
            if r['error']is None:r['error']=c['error']
            last=r['commands'][-1]if r['commands']else{}
            if not(last.get('name')==label and last.get('reaped')is True and last.get('cleanup_errors')==[]and isinstance(last.get('descriptors'),list)and all(d.get('closed')is True for d in last['descriptors'])):raise
    need(len(r['cases'])==3 and all(c['status']==EXPECTED_STATUS[c['lane'],c['mode']]for c in r['cases'])and not r['error'],
         'all three actual loop outcomes required without skipped or relabelled failures')
    need(sum(c.get('pair',{}).get('observed_subentry_pair',0)for c in r['cases'])==2 and
         sum(len(c.get('application_controls',{}).get('refusals',[]))for c in r['cases'])==APP_COUNTS[0] and
         sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==2*OWNER_COUNTS[0] and
         sum(len(c.get('pair_controls',{}).get('refusals',[]))for c in r['cases'])==2*PAIR_COUNTS[0] and
         sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==2*TERMINAL_COUNTS[0,0],
         'two complete native/generated pairs and each separate exact supplied control population')
    need(sum(len(c.get('native_probe_controls',{}).get('refusals',[]))for c in r['cases'])==44 and
         reports.probe.CONTROL_COUNT==22,'both separate exact native-probe reader populations')
    need(sum(len(c.get('repeat_tls_controls',{}).get('refusals',[]))for c in r['cases'])==62 and
         reports.REPEAT_TLS_CONTROLS==31,'both separate exact observed-TLS REP reader populations')
    need(sum(len(c.get('subentry_controls',{}).get('refusals',[]))for c in r['cases'])==38 and
         reports.SUBENTRY_CONTROL_COUNT==19,'both separate exact actual-entry terminal reader populations')
    need(sum(len(c.get('effect_controls',{}).get('refusals',[]))for c in r['cases'])==24 and
         reports.EFFECT_CONTROL_COUNT==12,'both separate exact tiny-fixture effect populations')


def prepare_inputs(original,bridge,builder,private,pin,binary,run,r,application):
    """Exact no-DT_NEEDED fixture; no claim that its auxv jumper implements --list."""
    interp=pin(interpreter(original));roots=[original.parent]
    expected=application['interpreter']
    need(str(interp)==expected['path']and fact(interp)=={k:expected[k]for k in('bytes','sha256')}and
         namespace.parse(original.read_bytes())==dict(elf_type=2,needed=[],soname=None,interpreter=interp)and
         namespace.parse(interp.read_bytes())==dict(elf_type=3,needed=[],soname=None,interpreter=None),
         'whole exact fresh main/interpreter with two empty DT_NEEDED lists')
    objects,description=namespace.plan(original,roots,bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    need(objects==[],'exact namespace has no dependency objects')
    r['runtime_libraries']={interp.name:dict(path=str(interp),**fact(interp))}
    r['runtime_library_scope']='source_owned_no_needed_fixture; no dynamic-loader list command'
    r['namespace_plan']=description
    images,raws,known=[],[],{};directory=private/'external-inputs';directory.mkdir()
    for role,path in [('original',original),('interpreter',interp)]:
        data=pin(path).read_bytes();identity=dict(bytes=len(data),sha256=H(data));need(fact(path)==identity,'complete independently retained ELF')
        if identity['sha256']in known:
            i=known[identity['sha256']];need(raws[i]==data,'duplicate content equality');images[i]['roles'].append(role);continue
        p=directory/(str(len(images))+'.elf')
        with p.open('xb')as f:f.write(data)
        need(fact(binary(p))==identity,'whole retained input copy');known[identity['sha256']]=len(images)
        images.append(dict(identity,roles=[role]));raws.append(data)
    need(len(images)==2,'distinct complete original and source-owned interpreter images')
    r['external_inputs']=images;carrier=private/'carrier'
    _,out,err=run('carrier',[builder.tools['python'],'-B',pin(SELECTED.parent/'carrier.py'),'make',original,bridge,carrier],profile='program')
    need(not err,'carrier construction stderr');binary(carrier);identity=json.loads(out)
    need(all(identity[k+'_sha256']==fact(p)['sha256']for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and interpreter(carrier)==bridge,'whole actual carrier source identities')
    r['subject_artifacts']={k:fact(p)for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier))}
    return interp,roots,objects,description,images,raws,carrier


def subentry_component(builder,private,pin,binary,run,r):
    fixture=SELECTED/'tests/persistent_subentry'
    script=pin(fixture/'build.sh');prepare=pin(fixture/'prepare.py');unit=pin(fixture/'oracle.c')
    output=private/'subentry-authority'
    expected=b'subentry-authority lookup=112 selection=33 entry=47 lifetime=19 history=25 synthetic_observations=1 native_credit=0\n'
    expected+=b'registered-address cases=6 controls=118 synthetic_observations=1 native_credit=0\n'
    state=r['subentry_component']=dict(status='failed',expected_stdout=expected.decode(),qualification_credit=False,
        recipe=fact(script),prepare=fact(prepare),source=fact(unit),native_operations=0)
    extracted=('persistent_group_controller.inc','persistent_active_domain.inc',
        'persistent_group_source.inc','lifecycle_loader.c','linked_controller.inc','span_source.inc',
        'selected_register_run.inc','persistent_group_rseq.inc')
    state['extraction_inputs']={n:fact(pin(SELECTED/n))for n in extracted}
    rows=recipe(script,'"$python_bin"');ccrows=recipe(script,'"$cc_bin"')
    need(len(rows)==len(ccrows)==1,'one source extraction and one actual predicate component compile')
    values={'$python_bin':builder.tools['python'],'$cc_bin':builder.tools['cc'],
        '$selected':SELECTED,'$output':output,'$fixture':fixture}
    argv=expand(rows[0],values)
    _,out,err=run('subentry-authority-prepare',argv,profile='finite',env=builder.environment)
    need(out==err==b'','exact actual-predicate extraction diagnostics empty')
    generated=pin(binary(str(output)+'.c'))
    argv=expand(ccrows[0],values)
    need(argv[-2:]==['-o',str(output)]and str(generated)in argv and '-DNDEBUG'not in argv and
         all(x in argv for x in ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only')),
         'strict actual predicate compiler recipe with assertions retained')
    flags=[x for x in argv[1:-2]if x!=str(generated)and not x.startswith('-Wl,')]
    _,out,err=run('subentry-authority-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_subentry',generated],profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_subentry: '),'whole actual predicate include closure')
    includes={str(pin(n)):fact(pin(n))for n in shlex.split(lines[0].split(':',1)[1])}
    need(str(generated)in includes,'actual extracted component translation unit')
    state['headers']=includes;state['argv']=argv
    _,out,err=run('subentry-authority-link',argv,profile='finite',env=builder.environment)
    need(out==err==b'','strict actual predicate compile')
    executable=binary(output);state['artifact']=fact(executable)
    row,out,err=run('subentry-authority-run',[executable],profile='finite',env=builder.environment)
    need(row['exit']==0 and out==expected and err==b'','all236 original plus118 registered-address controls complete')
    state.update(status='passed',counts=dict(lookup=112,selection=33,entry=47,lifetime=19,history=25),
        exit=row['exit'],duration_ns=row['duration_ns'],bounds=row['bounds'],
        captures={k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()})
    state['counts']['registered_address']=118


def empty_namespace_component(builder,private,pin,binary,run,r):
    fixture=SELECTED/'tests/empty_namespace'
    script=pin(fixture/'build.sh');prepare=pin(fixture/'prepare.py');unit=pin(fixture/'oracle.c')
    output=private/'empty-namespace'
    expected=b'empty-namespace images=74 pairs=4 parser=18 callers=10 synthetic_initialization=1 native_credit=0\n'
    state=r['empty_namespace_component']=dict(status='failed',expected_stdout=expected.decode(),qualification_credit=False,
        recipe=fact(script),prepare=fact(prepare),source=fact(unit),native_operations=0)
    extracted=('lifecycle_loader.c','runtime_loader.c')
    state['extraction_inputs']={n:fact(pin(SELECTED/n))for n in extracted}
    rows=recipe(script,'"$python_bin"');ccrows=recipe(script,'"$cc_bin"')
    need(len(rows)==len(ccrows)==1,'one source extraction and one actual predicate component compile')
    values={'$python_bin':builder.tools['python'],'$cc_bin':builder.tools['cc'],
        '$selected':SELECTED,'$output':output,'$fixture':fixture}
    argv=expand(rows[0],values)
    _,out,err=run('empty-namespace-prepare',argv,profile='finite',env=builder.environment)
    need(out==err==b'','exact actual-predicate extraction diagnostics empty')
    generated=pin(binary(str(output)+'.c'))
    argv=expand(ccrows[0],values)
    need(argv[-2:]==['-o',str(output)]and str(generated)in argv and '-DNDEBUG'not in argv and
         all(x in argv for x in ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only')),
         'strict actual predicate compiler recipe with assertions retained')
    flags=[x for x in argv[1:-2]if x!=str(generated)and not x.startswith('-Wl,')]
    _,out,err=run('empty-namespace-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_empty_namespace',generated],profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_empty_namespace: '),'whole actual predicate include closure')
    includes={str(pin(n)):fact(pin(n))for n in shlex.split(lines[0].split(':',1)[1])}
    need(str(generated)in includes,'actual extracted component translation unit')
    state['headers']=includes;state['argv']=argv
    _,out,err=run('empty-namespace-link',argv,profile='finite',env=builder.environment)
    need(out==err==b'','strict actual predicate compile')
    executable=binary(output);state['artifact']=fact(executable)
    row,out,err=run('empty-namespace-run',[executable],profile='finite',env=builder.environment)
    need(row['exit']==0 and out==expected and err==b'','all106 actual empty-namespace predicates and callers complete')
    state.update(status='passed',counts=dict(images=74,pairs=4,parser=18,callers=10),
        exit=row['exit'],duration_ns=row['duration_ns'],bounds=row['bounds'],
        captures={k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()})
