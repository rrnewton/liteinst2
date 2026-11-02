"""Closed four-subject event evidence; never used as plain release timing.

Every build/transport command is rejoined against its actual source-derived argv.
The original native41/PB/PF and new component/native28/owner56/lifecycle providers
remain mandatory on the same exact revision, CPU, hardware and archive profiles.
"""
import os
from pathlib import Path
import re
from types import SimpleNamespace
from page_selected import ENV, fact, need, interpreter
from direct_frontier_program import decode
from persistent_dynamic import BOUNDS, H, digest, imported_sources
from persistent_loop_effects_program_prerequisite import prerequisites
from persistent_loop_effects_native_prerequisite import archive_join, FEATURES
from persistent_loop_effects_performance_counted_build import bridge_completed
from persistent_loop_effects_counter import final_prefix, prepare_counter_carrier, protocol
from persistent_loop_effects_counter_terminal import completed_terminal, counters, controls, observed
from page_native_pair_performance import PROGRAM_ENV, SELECTED, resolved_libraries
import persistent_loop_effects_counter_process as counter_process
import namespace
from tunables_effects_program import PROGRAMS, ORDER, TARGET
ROOT=Path(__file__).resolve().parents[2]

def retained_workload(kind,original,args,bridge,builder,private,pin,binary,run,r,namespace):
    original=pin(original);interp=pin(interpreter(original));carrier=private/(kind+'-carrier')
    carrier_tool=pin(SELECTED.parent/'carrier.py')
    objects,description=namespace.plan(original,[Path('/usr/lib64')],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    if kind=='hot':need(namespace.parse(original.read_bytes())['needed']==['libc.so.6'],'actual normal libc dynamic workload')
    expected={interp:set()}
    for item in objects:
        p=pin(item['path']);need(fact(p)['sha256']==H(item['bytes']),'every actual namespace dependency pinned')
        expected.setdefault(p,set()).update(item['names'])
    system=dict(original=fact(original),interpreter=fact(interp),dependencies=[dict(names=x['names'],**fact(x['path']))for x in objects])
    r.setdefault('system_inputs',{})[kind]=system;r.setdefault('namespace_plans',{})[kind]=description
    images=[];image_bytes=[];by_hash={}
    for role,path in [('original',original),('interpreter',interp)]+[('dependency-'+str(i),x['path'])for i,x in enumerate(objects)]:
        path=pin(path);data=path.read_bytes();identity=fact(path)
        need(identity==dict(bytes=len(data),sha256=H(data)),'complete stable independent external ELF')
        if identity['sha256']in by_hash:
            index=by_hash[identity['sha256']];need(data==image_bytes[index],'complete duplicate external content identity')
            images[index]['roles'].append(role);continue
        index=len(images);copy=private/'external-inputs'/(identity['sha256']+'.elf')
        need(copy.is_file() and not copy.is_symlink() and copy.read_bytes()==data,
             'whole actual retained external ELF equals its current authenticated source')
        need(fact(binary(copy))==identity,'retained complete external ELF bytes')
        images.append(dict(identity,roles=[role]));image_bytes.append(data);by_hash[identity['sha256']]=index
    r.setdefault('external_inputs',{})[kind]=images
    _,out,err=run(kind+'-native-libraries',[interp,'--list',original],env=PROGRAM_ENV)
    need(not err,'actual native loader listing stderr');resolved_libraries(out,expected,interp,pin)
    _,out,err=run(kind+'-carrier',[builder.tools['python'],'-B',carrier_tool,'make',original,bridge,carrier],profile='program',env=PROGRAM_ENV)
    need(not err,'actual carrier construction stderr');binary(carrier);identities=decode(out)
    need(all(identities[k+'_sha256']==fact(p)['sha256']for k,p in
        (('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and interpreter(carrier)==bridge,
        'actual original/interpreter/release bridge/carrier identities')
    r.setdefault('carriers',{})[kind]=fact(carrier)
    return dict(original=original,argv=[str(original),*args],carrier=carrier,carrier_bytes=carrier.read_bytes(),
        objects=objects,description=description,images=images,image_bytes=image_bytes,carrier_tool=carrier_tool)


def authenticate(path, expected_sha256, r, pin, binary, archive):
    path=pin(path)
    need(path.name=='receipt.json' and path.parent.parent==ROOT/'target/evaluation/inprocess' and
         re.fullmatch('[0-9a-f]{64}',expected_sha256) is not None and fact(path)['sha256']==expected_sha256,
         'explicit whole closed counted four-subject receipt')
    before=fact(path); a=decode(path.read_bytes()); directory=path.parent
    need(a['schema']==1 and a['profile']=='tunables-effects-program-probe-v1' and
         a['status']=='completed_unqualified' and a['revision']==r['revision'] and a['source']==r['source'] and
         a['cpu']==r['cpu'] and a['hardware']==r['hardware'] and a['bounds']==BOUNDS and
         a['source_unchanged'] is True and a['cleanup_complete'] is True and a['error'] is None and
         a['final_errors']==[] and a['prerequisite_stage'] is None and
         all(a[k] is False for k in ('qualification_credit','whole_profile_qualified','performance_credit')),
         'all four actually completed on the same source/CPU/hardware; counted timing has no release credit')
    def closure():
        need(fact(path)==before,'immutable counted receipt')
        for p,v in a['inputs'].items(): need(fact(pin(p))==v,'whole counted input')
        for p,v in a['artifacts'].items():
            actual=binary(p); need(dict(fact(actual),mode=actual.stat().st_mode&0o777)==v,'whole counted artifact and mode')
        for p,v in a['aliases'].items(): need(str(pin(p))==v,'whole counted alias')
        for p,v in a['presence'].items(): need(os.path.lexists(p)==v,'whole counted configuration presence')
        for p,v in a['namespace_aliases'].items():
            need(Path(p).is_symlink() and os.readlink(p)==v,'actual retained counted namespace')
            need(p not in r['namespace_aliases'] or r['namespace_aliases'][p]==v,'no conflicting namespace identity')
            r['namespace_aliases'][p]=v
    closure()
    arguments={}
    names=('direct','block','fused','loop_component','effects_component','loop_native','loop_owner','loop_lifecycle')
    for name in names:
        value=a[name+'_prerequisite']; p=pin(ROOT/value['file'])
        need(p.is_relative_to(ROOT) and fact(p)=={k:value[k] for k in ('bytes','sha256')},
             'whole explicitly recorded '+name+' prerequisite')
        arguments[name+'_receipt']=p; arguments[name+'_receipt_sha256']=value['sha256']
    holder=dict(revision=r['revision'],source=r['source'],cpu=r['cpu'],hardware=r['hardware'],
                namespace_aliases=r['namespace_aliases'])
    prerequisites(SimpleNamespace(**arguments),holder,pin,binary,archive)
    for name in ('prerequisite_archive',)+tuple(n+'_prerequisite' for n in names):
        need(holder[name]==a[name],'independently reconstructed whole '+name)
    need(a['archive']==fact(archive),'same fresh thirteen-source archive in counted and plain profiles')
    commands=a['commands']; rows={x['name']:x for x in commands}; used=[]
    need(commands and len(rows)==len(commands),'unique complete counted command identities')
    def capture(row,stream):
        v=row['captures'][stream]; p=pin(directory/v['file'])
        need(p.parent==directory and fact(p)=={k:v[k] for k in ('bytes','sha256')} and
             0<=v['bytes']<=16<<20,'whole actual bounded counted capture')
        return p.read_bytes()
    subject_names={'subject-'+kind+'-'+lane for kind,lane in ORDER}
    # Labels are literal producer outputs, not arbitrary successful row subsets.
    need([(c['program'],c['lane']) for c in a['cases']]==list(ORDER) and
         [c['label'] for c in a['cases']]==['subject-'+k+'-'+l for k,l in ORDER], 'fixed original four subjects')
    for row in commands:
        subject=row['name'] in subject_names
        need(type(row['exit']) is int and row['exit']==0 and row['expected_exit']==(None if subject else 0) and
             row['bounds']==BOUNDS[row['profile']] and row['capture_limit']==16<<20 and
             row['reaped'] is True and row['timed_out'] is False and row['error'] is None and
             row['cleanup_errors']==[] and type(row['descriptors']) is list and
             all(d.get('closed') is True for d in row['descriptors']), 'whole actual successful bounded command')
        need(set(row['captures'])==({'stdout','stderr','counters'} if row['name'].endswith('-counted') else {'stdout','stderr'}),
             'exact actual counted versus ordinary capture population')
        for stream in row['captures']: capture(row,stream)
        need(decode(pin(directory/(row['name']+'.json')).read_bytes())==row,'whole actual command JSON')
    build=a['build']; tools={n:pin(v['path']) for n,v in build['tools'].items()}
    need(all(fact(tools[n])=={k:v[k] for k in ('bytes','sha256')} for n,v in build['tools'].items()),'whole counted build tools')
    builder=SimpleNamespace(tools=tools,environment=build['environment'],retained=directory/'artifacts',
        paths={'archive':directory/'artifacts/decoder.a'},record=build,mov_guard=True,linked_epoch=True,scalar_span=True,
        extra_decoder_sources=('region.rs','mov_guard.rs','scalar_read.rs','loop_scalar.rs','byte_mov_guard.rs'),decoder_features=FEATURES)
    def recorded(name,argv,profile='metadata',expected=0,env=None,record=False):
        need(name in rows and name not in used,'one source-derived counted command '+name)
        row=rows[name]; environment=dict(ENV if env is None else env)
        if name.startswith(('resolve-','version-')):
            environment={k:v for k,v in environment.items() if k!='LI2_DECODER_FEATURES'}
            if name in ('resolve-cargo','resolve-rustc'):
                environment={k:v for k,v in environment.items() if k in ENV or k in ('HOME','CARGO_HOME','RUSTUP_HOME')}
        need(row['argv']==list(map(str,argv)) and row['environment']==environment and
             row['profile']==profile and row['expected_exit']==expected and record is False,
             'complete source-derived command argv/environment/profile '+name)
        used.append(name); return row,capture(row,'stdout'),capture(row,'stderr')
    _,names_out,err=recorded('tracked-input-list',['git','-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
    need(names_out and not err,'complete tracked counted source listing')
    for raw in names_out.split(b'\0'):
        if raw and not os.fsdecode(raw).startswith('evaluation/inprocess/results/'):
            p=pin(ROOT/os.fsdecode(raw)); need(a['inputs'].get(str(p))==fact(p),'every actual counted source pinned')
    aliases={}; archive_join(a,directory,builder,archive,pin,binary,recorded,aliases)
    protocols={}; protocol(builder,recorded,protocols,pin)
    need(all(protocols[k]==a[k] for k in ('counter_protocol','loop_counter_protocol','loop_effects_counter_protocol')),'both original and additive ABI4 counter protocol populations')
    states={}; rebuilt={}; products={'archive':directory/'artifacts/decoder.a'}
    for kind,program,args,stdout in PROGRAMS:
        original=pin(program); local=directory/(kind+'-build'); state={}
        def labelled(name,argv,**kwargs): return recorded(kind+'-'+name,argv,**kwargs)
        bridge=bridge_completed(builder,products,local,pin,binary,aliases,labelled,state,original,
                                capture=False,retained_counters=True,differential=False)
        need(state['release_build']==a['program_builds'][kind]['release_build'],'whole actual counted bridge build')
        s=retained_workload(kind,original,args,bridge,builder,local,pin,binary,labelled,rebuilt,namespace)
        carrier=prepare_counter_carrier(s,pin)
        need(carrier==a['program_builds'][kind]['counter_carrier'] and
             all(fact(s[k])==a['program_builds'][kind][k] for k in ('original','carrier')) and
             fact(bridge)==a['program_builds'][kind]['bridge'],'whole actual counted carrier and image')
        states[kind]=s
    for key in ('system_inputs','namespace_plans','external_inputs','carriers'):
        need(rebuilt[key]==a[key],'whole independently rebuilt counted '+key)
    counts={}
    for case in a['cases']:
        kind,lane=case['program'],case['lane']; s=states[kind]; name=case['label']; row=rows[name]
        ns=directory/(name+'-namespace')
        argv=s['argv'] if lane=='native' else [tools['python'],'-B',s['carrier_tool'],'exec-loader',
            '--counter-fd',str(row['counter_input']['child_fd']),'--counter-nonce',str(row['counter_input']['nonce']),
            '--library-root','/usr/lib64','--namespace',ns,s['carrier'],s['original'],'--',*s['argv']]
        _,out,err=recorded(name,argv,profile='program',expected=None,env=PROGRAM_ENV)
        need(row['bounds']==TARGET and out==(b'.\n' if kind=='ls' else b'') and
             case['status']==('completed_native_reference' if lane=='native' else 'completed_unqualified') and
             case['launched'] is True and case['exit']==row['exit']==case['expected_exit']==0 and
             case['timed_out'] is False and case['process_ns']==row['process_ns'] and
             case['wrapper_interval_ns']==row['duration_ns'] and
             case['captures']=={k:{j:v[j] for j in ('bytes','sha256')} for k,v in row['captures'].items()},
             'each actual completed program and its retained whole-process interval')
        if lane=='native':
            need(not err and case['counts'] is None and case['counter_collection']=='not_applicable','no invented native counters')
        else:
            prefix=final_prefix(row,directory,binary)
            counter_process.namespace_join(s,ns,binary,r,namespace,row['counter_input'])
            terminal=completed_terminal(err,prefix); actual_controls=controls(err,prefix)
            raw_counters=counters(err)
            need(prefix==case['counts'] and terminal==case['terminal'] and
                 {k:raw_counters[k] for k in ('LI2_CHAIN','LI2_LINKED_NATIVE_PROBE','LI2_NATIVE_PAIR')}==case['terminal_counters'] and
                 actual_controls==case['loop_terminal_controls'] and len(actual_controls['refusals'])==130 and
                 observed(err)==(case['loop_runtime_terminal'],case['loop_effects_terminal'],case['pf_refusal_terminal']) and
                 case['stdout_equal'] is case['namespace_complete'] is True and
                 case['counter_collection']=='closed_usable_prefix','all actual independent cells, terminal, namespace and130controls')
            counts[kind]=dict(cells=prefix,terminal=terminal,controls=130,
                captures={k:{j:v[j] for j in ('bytes','sha256')} for k,v in row['captures'].items()},
                scope='separate counted subject; actual per-cell prefix and successful terminal, no release timing')
    need(used==[x['name'] for x in commands],'all counted build/protocol/four subject commands in original exact order')
    closure(); imported_sources(pin)
    proof=dict(file=str(path.relative_to(ROOT)),**before,status=a['status'],source_sha256=digest(r['source']),
        revision=r['revision'],cpu=r['cpu'],hardware_sha256=digest(r['hardware']),archive=fact(archive),
        old_archive=a['prerequisite_archive'],commands=len(commands),commands_sha256=digest(commands),
        subjects=4,terminal_controls=260,release_timing_credit=False,qualification_credit=False)
    return proof,counts,holder,rebuilt['system_inputs']
