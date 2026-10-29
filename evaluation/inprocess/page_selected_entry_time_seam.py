"""Actual entry.S/boot/restore and first-MOV state qualification, never timing credit."""
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,os,re,struct
from pathlib import Path
from page_selected import ENV,fact,need,elf,interpreter
from page_selected_register_time_build import recipe,expand
from page_selected_register_time_compare import decode,SCALARS,ARRAYS,integers
import page_selected_effect_time_compare as timing
import page_selected_effect_ls_reports as effect_reports
from page_selected_register_real import resolved_libraries

H=lambda b:hashlib.sha256(b).hexdigest()
UNITS=('bridge.c','selected/runtime_loader.c','selected/lifecycle_loader.c','selected/entry.S',
       'selected/selected_effect.c','selected/selected_effect_native.c','selected/oneshot.c','selected/provider.c',
       'selected/step_owner.c','selected/selected_selftest.S','selected/support.c','selected/register_run_plan.c',
       'selected/register_run_owner.c','selected/register_run_publish.c','selected/register_run_reset.c',
       'selected/rseq_guard.c','selected/native_policy.c','selected/native_epoch.c','selected/register_run_timing.c')
MACROS=('RUN_TIMING','ENTRY_TIMING','EFFECT_PROVIDER','ONESHOT_REUSABLE','ONESHOT_PUBLICATION',
        'TF_SEALED_CUSTODY','TF_SAME_PAGE_LEASE','TF_HANDOFF','REGISTER_RUN','MAPS_PHASE_REUSE',
        'RSEQ_INACTIVE','NATIVE_PAGES','CPUID_NX_ONLY','RSEQ_NATIVE','RSEQ_NATIVE_BOUNDARY',
        'RSEQ_TCGETS_BTRFS','RSEQ_TIOCGWINSZ_BTRFS','FAST_MEMSET','FAST_EQUAL')
PROGRAM_ENV=dict(ENV,LD_BIND_NOW='1')


def load(path,name,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path))
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def write(path,data,binary):
    with path.open('xb')as f:f.write(data)
    return binary(path)


def image(path):
    raw,h,ps=elf(path);pc=h[4]
    rows=[p for p in ps if p[0]==1 and p[1]&1 and p[3]<=pc and pc+15<=p[3]+p[5]]
    need(len(rows)==1,'unique full file-backed executable interpreter entry')
    p=rows[0];off=p[2]+pc-p[3];page=off&~4095
    need(p[2]%4096==p[3]%4096 and p[2]<=page and page+4096<=p[2]+p[5] and
         pc==timing.ENTRY_OFFSET and raw[off:off+8]==timing.ENTRY_BYTES,
         'source-authenticated exact real-LS first MOV and entire source page')
    return dict(elf_entry=pc,entry_file_offset=off,entry_bytes=raw[off:off+8].hex(),page=raw[page:page+4096])


def layout_for(name,bridge,builder,fixture,pin,run):
    _,out,err=run(name+'-dwarf',[builder.tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','maintenance set worker-threads 1','--readnow',
        '--se='+str(bridge),'-x',pin(fixture/'layout.py')],profile='metadata',env=builder.environment)
    need(not err,'actual file-only complete seam layout stderr');layout=decode(out)
    _,h,ps=elf(bridge)
    need(h[4]==layout['symbols']['eso_entry'] and
         all(sum(p[0]==1 and p[1]&1 and p[3]<=layout['symbols'][k]<p[3]+p[5]for p in ps)==1
             for k in('eso_entry','_start','li2_boot','li2_entry_time_start','eso_saved_before','eso_saved_after',
                       'selected_authenticate','selected_step_failure')),'actual kernel entry and complete executable seam symbols')
    _,out,err=run(name+'-record-symbol',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual seam record symbol stderr')
    rows=[x.split()for x in out.decode('ascii').splitlines()if x.split()and x.split()[-1]=='eso_record']
    need(len(rows)==1 and len(rows[0])==4 and rows[0][2]in('b','B'),'one actual full BSS record')
    address,size=(int(x,16)for x in rows[0][:2])
    need(size==layout['types']['eso_record']['bytes'] and 0<size<16<<20 and
         sum(p[0]==1 and p[1]==6 and p[3]<=address<address+size<=p[3]+p[6]for p in ps)==1,
         'actual DWARF/ELF full record size in one RW/NX extent')
    return layout


def bridge(mode,config,builder,products,root,private,pin,binary,aliases,run,state,prepare,*,link_bridge):
    selected=root/'tools/page-entry/selected';fixture=selected/'tests/entry_seam'
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'same freshly owned Build.prepare decoder archive')
    output=private/('entry-seam-'+str(mode));output.mkdir()
    header=write(output/'register_timing_config.h',config,binary)
    original={n:pin(selected/n).read_bytes()for n in('entry.S','runtime_loader.c','selected_controller.inc','entry_timing.inc')}
    generated,operations=prepare.compose(*(original[n]for n in original))
    for n,data in generated.items():write(output/n,data,binary)
    write(output/'entry_seam_observe.inc',pin(fixture/'observe.inc').read_bytes(),binary)
    seed=pin(fixture/'seed.S')
    source_recipe=pin(selected/'build-effect-timing.sh');rows=recipe(source_recipe,'"$cc_bin"')
    need(len(rows)==1,'one immutable normal timing recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':selected,
        '$parent_dir':selected.parent,'$archive':archive,'$output':output})
    original_units=[str(selected.parent/n)for n in UNITS]
    need([x for x in argv if x.endswith(('.c','.S'))]==original_units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+n+'=1'for n in MACROS]and
         argv[-2:]==['-o',str(output/'bridge-effect-timing.so')]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact original nineteen-TU/nineteen-macro timing recipe before observation')
    replacements={str(selected/n):str(output/n)for n in('entry.S','runtime_loader.c')}
    argv=[replacements.get(x,x)for x in argv]
    entry='-Wl,-e,_start,-Bsymbolic,-z,now,-z,relro,-z,noexecstack,--build-id=none,--no-undefined'
    need(argv.count(entry)==1,'single original linker entry token')
    argv[argv.index(entry)]=entry.replace(',-e,_start,',',-e,eso_entry,')
    argv.insert(1,'-DESO_MODE='+str(mode));argv.insert(argv.index(str(archive)),str(seed))
    units=[replacements.get(x,x)for x in original_units]+[str(seed)]
    need([x for x in argv if x.endswith(('.c','.S'))]==units,'exact two observed substitutions and one independent seed TU')
    state.update(recipe=fact(source_recipe),archive=fact(archive),configuration=fact(header),argv=argv,
        original_sources={n:dict(bytes=len(b),sha256=H(b))for n,b in original.items()},
        observation_inverses=[dict(source=n,offset=at,old_bytes=len(old),old_sha256=H(old),
                                  new_bytes=len(new),new_sha256=H(new))for n,at,old,new in operations])
    result=link_bridge('entry-seam-'+str(mode),argv,units,archive,builder,pin,binary,aliases,run,state)
    state['layout']=layout_for('entry-seam-'+str(mode),result,builder,fixture,pin,run)
    return result,state['layout']


def program(mode,bridge,builder,root,private,pin,binary,run,r,original,interp):
    name='entry-seam-gated'if mode==0 else 'entry-seam-failure-'+str(mode)
    carrier=private/(name+'-carrier');carrier_tool=pin(root/'tools/page-entry/carrier.py')
    namespace=load(root/'tools/page-entry/namespace.py','entry_seam_namespace_'+str(mode),pin)
    objects,description=namespace.plan(original,[Path('/usr/lib64')],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    expected={interp:set()}
    for item in objects:
        p=pin(item['path']);need(fact(p)['sha256']==H(item['bytes']),'all real namespace sources pinned')
        expected.setdefault(p,set()).update(item['names'])
    system=dict(original=fact(original),interpreter=fact(interp),dependencies=[dict(names=x['names'],**fact(x['path']))for x in objects])
    need(r['system_inputs']==system,'same actual discovery program/interpreter/needed DSOs')
    r.setdefault('namespace_plans',{})[name]=description;r.setdefault('namespace_aliases',{})
    _,out,err=run(name+'-libraries',[interp,'--list',original],env=PROGRAM_ENV)
    need(not err,'actual loader dependency listing stderr');resolved_libraries(out,expected,interp,pin)
    _,out,err=run(name+'-carrier',[builder.tools['python'],'-B',carrier_tool,'make',original,bridge,carrier],profile='program',env=PROGRAM_ENV)
    need(not err,'actual carrier construction stderr');binary(carrier);ids=decode(out)
    need(all(ids[k+'_sha256']==fact(p)['sha256']for k,p in
         (('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and interpreter(carrier)==bridge,
         'actual original/interpreter/bridge/carrier identity closure')
    ns=private/(name+'-namespace')
    row,out,err=run(name,[builder.tools['python'],'-B',carrier_tool,'exec-loader','--library-root','/usr/lib64',
        '--namespace',ns,carrier,original,'--',original,'-d','.'],profile='program',expected=0 if mode==0 else 125,
        env=PROGRAM_ENV,record=True,step=True)
    observed=decode(binary(ns/'namespace.json').read_bytes());launch=decode(binary(ns/'launch.json').read_bytes())
    need(all(observed[k]==v for k,v in description.items())and observed['directory']==str(ns)and
         observed['schema_version']==1 and observed['status']=='prepared_not_executed'and len(observed['objects'])==len(objects),
         'actual complete namespace matches independent plan')
    fds=[]
    for obj,item in zip(observed['objects'],objects,strict=True):
        need(type(obj['fd'])is int and obj['fd']>3 and obj['fd']not in fds and obj['source']==str(item['path'])and
             obj['names']==item['names']and obj['needed']==item['info']['needed']and
             obj['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and
             obj['sha256']==H(item['bytes'])and obj['size']==len(item['bytes'])and obj['seals']==namespace.SEALS and
             type(obj['device'])is int and obj['device']>0 and type(obj['inode'])is int and obj['inode']>0,
             'actual sealed dependency identity separate from held record FD3')
        fds.append(obj['fd'])
        for alias in obj['names']:
            path=ns/alias;value='/proc/self/fd/'+str(obj['fd'])
            need(path.is_symlink()and os.readlink(path)==value,'actual sealed dependency alias');r['namespace_aliases'][str(path)]=value
    expected_env={k:v for k,v in PROGRAM_ENV.items()if k!='PYTHONDONTWRITEBYTECODE'}
    expected_env.update(LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)))
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',
        carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],argv=[str(original),'-d','.'],
        environment=expected_env,dependency_fds=fds),'exact argv/environment/carrier/FD join')
    need(out==(b'.\n'if mode==0 else b''),'complete genuine positive or failure stdout')
    cap=row['captures']['record'];path=binary(private/cap['file'])
    need(fact(path)=={k:cap[k]for k in('bytes','sha256')},'full actual FD3 stream identity')
    return row,err,path.read_bytes()


def terminal(stderr,raw,layout,mode,reader):
    """Failure-only source-defined terminal join; never calls it completed LS."""
    need(mode in(1,2,3)and stderr.endswith(b'\n')and 0<len(stderr)<=16<<20,'bounded complete required refusal reports')
    lines=stderr[:-1].split(b'\n');order=['LI2_'+x for x in effect_reports.ORDER]+['LI2_RUN_TIME','LI2_ENTRY_TIME']
    need([x.partition(b' ')[0].decode('ascii')for x in lines]==order and
         all(0<len(x)+1<=4096 and b'\r'not in x for x in lines),'complete exact refusal row order without extra/duplicate rows')
    rows={name:decode(line.partition(b' ')[2])for name,line in zip(order,lines,strict=True)}
    code=(0,803,803,218)[mode];detail=(-1,22,22,11)[mode];negative=int(mode in(1,2))
    for name,v in rows.items():
        need(type(v)is dict and v['status']==125 and v['failure_code']==code,'same actual failed terminal in every row')
        if 'detail_abs'in v:need(v['detail_abs']==detail,'same actual failure detail')
        if 'detail_negative'in v:need(v['detail_negative']==negative,'same actual failure sign')
    l=rows['LI2_LOADER'];er=effect_reports
    er._unsigned(l,er.generic.KEYS-{'scope'},scope='partial_selected_reusable_effects')
    native=rows['LI2_NATIVE'];er._unsigned(native,er.NATIVE_KEYS-{'revisit_ns'},{'revisit_ns':0})
    need(native['admissions']==native['closed']==native['revisit_count']==0 and
         native['attempts']==int(mode!=1) and native['blocked']+native['low_address_refusals']<=native['attempts'],
         'first-entry refusal has no native page admission')
    run=rows['LI2_RUN'];chain=rows['LI2_CHAIN'];registration=rows['LI2_RSEQ']
    need(type(run.get('cache_present'))is int and run['cache_present']==1 and
         type(run.get('publication_present'))is int and run['publication_present']==0,
         'no generated publication before the initial MOV closes')
    arrays={k:n for k,n in er.register.ARRAYS.items()if k not in('cache','initialization','attempt','publication')}
    if run['cache_present']:arrays.update({k:er.register.ARRAYS[k]for k in('cache','initialization','attempt')})
    er._unsigned(run,er.register.SCALARS,arrays)
    er._unsigned(chain,(er.chain.KEYS-{'scope'})|er.lease.EXTRA,scope='opt_in_same_page_tf_lease')
    er._unsigned(registration,er.RSEQ_SCHEMA['scalar_keys'],
        {k:len(v)for k,v in er.RSEQ_SCHEMA['arrays'].items()},er.RSEQ_SCHEMA['scope'])
    need(registration['maps_profile']==1 and l['rseq']==0 and
         run['plan_misses']==int(mode!=1) and
         all(run[k]==0 for k in('completed_runs','copied_instructions','pending'))and
         run['route']==l['step_route']==int(mode!=1)and
         all(chain[k]==0 for k in('attempts','steps','nx_entries','trace_entries','fallbacks','preparations','releases','pending','error','proof_valid')),
         'only original initial STEP, no generated run, chain or application registration')
    need(registration['owner'][:7]==[1,0,0,0,0,0,0], 'actual initialized, unregistered rseq owner before loader entry')
    parsed=dict(loader=l,native=native,effect=rows['LI2_SELECTED_EFFECT'],oneshot=rows['LI2_ONESHOT'],
        cpuid_nx=rows['LI2_CPUID_NX'],rseq_native=rows['LI2_RSEQ_NATIVE'],
        rseq_boundary=rows['LI2_RSEQ_BOUNDARY'],tcgets=rows['LI2_RSEQ_BTRFS_TTY_QUERY'])
    er.extensions(parsed) # unchanged typed schemas and actual prefix domains
    effect=parsed['effect'];oneshot=parsed['oneshot']
    need(all(effect[k]==0 for k in er.EFFECT-{'version','status','failure_code','detail_abs'})and
         effect['classes']==[0]*7,'all pre-effect callback/backend/commit/raw/FP markers remain zero')
    need(all(oneshot[k]==0 for k in('attempted','published','restored','completed','retired','refused',
        'cpuid_patches','syscall_patches','rdtsc_patches','effect_started','effect_returned','active_phase',
        'resetting','last_completed_sequence','last_refused_sequence','backend_prepared','backend_completed',
        'rseq_phase','rseq_error','rseq_attempts','rseq_retired'))and
        oneshot['retained_records']==oneshot['generations']==l['retired']+l['live_pages'],
        'no temporary publication, reusable renewal or publication-rseq owner before first entry')
    trace=rows['LI2_TRACE_RUN'];er.trace_prefix(trace,run,chain,l)
    need(all(trace[k]==0 for k in er.TRACE_RUN-{'version','status','failure_code','detail_abs','detail_negative','route'})and
         trace['route']==run['route'],'no TRACE-to-generated-run credit for the old STEP endpoint')
    need(l['selected_selftests']==1 and l['source_patches']==0 and l['cpuid']==l['rdtsc']==l['rdtscp']==l['syscalls']==0 and
         l['first_target_is_interpreter_entry']==l['interpreter_entry_faults']==l['nx_faults']==int(mode!=1),
         'no later application operation, publication or fabricated first target')
    summary=rows['LI2_RUN_TIME'];need(set(summary)==SCALARS|set(ARRAYS),'exact failed recurring schema')
    for k in SCALARS:need(type(summary[k])is int and 0<=summary[k]<1<<64,'typed failed recurring scalar')
    for k,n in ARRAYS.items():integers(summary[k],n)
    need(all(summary[k]==0 for k in('qualified','completed','publications','hits','full_misses','clock_calls','sites','samples')),
         'failed first entry has no recurring sample or timing credit')
    r=reader.V(raw,layout,'eso_record');e=r.sub('timing','entry_timing')
    want=dict(version=1,status=125,failure_code=code,detail_abs=detail,detail_negative=negative,clock_id=4,qualified=0)
    for name in('mode','initialized','started','ingress','armed','complete','clock_attempted','clock_complete',
                'route','instructions_known','instructions','repeat_iterations','native_pages','native_refaults'):
        want[name]=e.n(name)
    d=e.n('first_detail',True);want.update(observer_error=e.n('first_error'),observer_detail_abs=abs(d),observer_detail_negative=int(d<0))
    for name in('identity','closure','ns'):want[name]=list(reader.q(e.b(name)))
    results=struct.unpack('<2q',e.b('clock_result'));want['clock_results']=[abs(results[0]),int(results[0]<0),abs(results[1]),int(results[1]<0)]
    for group,which in(('before','before'),('after','after')):
        for i,m in enumerate(e.array(group,'li2_maps_stats')):
            want['maps_'+('start'if i==0 else'end')+'_'+which]=[m.n(k)for k in
                ('fresh_calls','acquisitions','reuses','invalidations','handler_id','mutation_epoch','active','valid','poisoned','reserved')]
    need(rows['LI2_ENTRY_TIME']==want,'whole actual terminal entry report equals retained binary state')
    return dict(failure_code=code,detail_abs=detail,detail_negative=negative,report_rows=len(rows),sha256=H(stderr),completed_application=False)


def qualify(builder,products,root,private,pin,binary,aliases,run,r,original,interp,config,*,link_bridge):
    fixture=root/'tools/page-entry/selected/tests/entry_seam'
    q=r['entry_qualification']=dict(status='failed',cases=[],scope='Actual real-LS first MOV/OLD_STEP only; no duration or general entry-route credit')
    need(r['bounds']['program']==[30,512<<20,16<<20,60]and
         len(os.sched_getaffinity(0))==1 and next(iter(os.sched_getaffinity(0)))==r['cpu'],
         'original exact real-program bounds and one reserved CPU')
    original=pin(original);interp=pin(interp);img=image(interp)
    selected=r['selection'];need(config==timing.configuration(fact(interp)['sha256'],selected),'same frozen discovery configuration')
    q['identity']=dict(interpreter=fact(interp),**{k:img[k]for k in('elf_entry','entry_file_offset','entry_bytes')},
        configuration=dict(bytes=len(config),sha256=H(config)),route=4,instructions=1)
    prepare=load(fixture/'prepare.py','entry_seam_prepare',pin);reader=load(fixture/'read.py','entry_seam_reader',pin)
    controls=load(fixture/'controls.py','entry_seam_controls',pin)
    reference=root/'tools/page-entry/selected/tests/b2_reference'
    boundary=load(reference/'reference/boundary.py','entry_seam_boundary',pin);xstate=load(reference/'xstate.py','entry_seam_xstate',pin)
    for mode in range(4):
        case=dict(mode=mode,status='failed');q['cases'].append(case)
        state=case['build']=dict(status='failed')
        binary_path,layout=bridge(mode,config,builder,products,root,private,pin,binary,aliases,run,state,prepare,link_bridge=link_bridge)
        row,stderr,data=program(mode,binary_path,builder,root,private,pin,binary,run,r,original,interp)
        value=reader.check(data,layout,mode,row['pid'],r['cpu'],img,boundary,xstate)
        case.update(pid=row['pid'],exit=row['exit'],record=dict(bytes=len(data),sha256=H(data)),observation=value)
        if mode==0:
            parsed=timing.parse(stderr,row['pid'],row['exit'],row['stdout_provenance_before'])
            timing.qualify(parsed,fact(interp)['sha256'],2,selected,interpreter_entry_offset=img['elf_entry'],entry_bytes=bytes.fromhex(img['entry_bytes']))
            case['full_effect_reports']=True
        else:case['failure_terminal']=terminal(stderr,data,layout,mode,reader)
        case['supplied_mutations']=controls.refusals(data,layout,mode,row['pid'],r['cpu'],img,boundary,xstate,reader)
        case['status']='accepted_required_observation'
    need([x['mode']for x in q['cases']]==list(range(4))and all(x['status']=='accepted_required_observation'for x in q['cases'])and
         [x['exit']for x in q['cases']]==[0,125,125,125]and not r['final_errors'],
         'one genuine full-LS completion and three genuine required failures with all independent state checks')
    q['status']='passed'
    return q
