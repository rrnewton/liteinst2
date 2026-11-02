"""Reauthenticate every actual focal build, raw pair and supplied control gate."""
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
from page_selected import ENV,fact,need
from direct_frontier_program import decode,direct_prerequisite
from bounded_block_prerequisite import block_prerequisite
from bounded_fused_prerequisite import fused_prerequisite
from persistent_loop_component_prerequisite import prerequisite as component_prerequisite
from persistent_loop_native_prerequisite import authenticate,archive_join,FEATURES
from persistent_dynamic import BOUNDS,digest,load,imported_sources,image_inventory,raw_emission
from persistent_loop_owner_helpers import (ROOT,OWNER,PROFILE,ORDER,LANES,SCHEDULE,COVERAGE,
    observed_layout,case_argv,evaluate,expected_status)
from persistent_loop_owner_build import bridge_completed,inputs_completed
from persistent_loop_native_build import preparation


def legacy(args,r,pin,binary,archive):
    public_path=pin(args.direct_receipt)
    need(public_path.parent==ROOT/'evaluation/inprocess/results'and public_path.suffix=='.json'and
         re.fullmatch('[0-9a-f]{64}',args.direct_receipt_sha256)is not None and
         fact(public_path)['sha256']==args.direct_receipt_sha256,'explicit whole canonical public native41 prerequisite')
    public=decode(public_path.read_bytes());directory=ROOT/'target/evaluation/inprocess'/public_path.stem
    receipt=pin(directory/'receipt.json');need(fact(receipt)==public['receipt'],'whole native41 public/private join')
    actual=decode(receipt.read_bytes());built=actual['build']['artifacts']['decoder.a'];old=binary(built['path'])
    need(old==directory/'artifacts/decoder.a'and fact(old)=={k:built[k]for k in('bytes','sha256')}and
         actual['build']['decoder_features']==['scalar-region','scalar-span','linked-epoch','mov-guard'],
         'original ten-source archive remains distinct from additive eleven-source archive')
    r['prerequisite_archive']=fact(old);r['prerequisite_stage']='native41'
    r['direct_prerequisite']=direct_prerequisite(public_path,r,pin,binary,old)
    r['prerequisite_stage']='bounded_block'
    r['block_prerequisite']=block_prerequisite(args.block_receipt,args.block_receipt_sha256,r,pin,binary,old)
    r['prerequisite_stage']='bounded_fused'
    r['fused_prerequisite']=fused_prerequisite(args.fused_receipt,args.fused_receipt_sha256,r,pin,binary,old)
    # fused_prerequisite independently reconstructs its mandatory old component.
    r['fused_component_prerequisite']=r['fused_prerequisite']['fused_component_prerequisite']
    r['prerequisite_stage']='loop_component'
    r['loop_component_prerequisite']=component_prerequisite(args.loop_component_receipt,
        args.loop_component_receipt_sha256,r,pin,binary,archive)
    r['prerequisite_stage']=None


def prerequisite(path,expected_sha256,r,pin,binary,archive):
    path=pin(path)
    need(path.name=='receipt.json'and path.parent.parent==ROOT/'target/evaluation/inprocess'and
         re.fullmatch('[0-9a-f]{64}',expected_sha256)is not None and fact(path)['sha256']==expected_sha256,
         'explicit whole private policy14 receipt')
    before=fact(path);a=decode(path.read_bytes());directory=path.parent
    need(a['schema']==1 and a['profile']==PROFILE and a['status']=='observed_focal_unqualified'and
         a['source']==r['source']and a['revision']==r['revision']and a['cpu']==r['cpu']and
         a['hardware']==r['hardware']and a['bounds']==BOUNDS and a['source_unchanged']is True and
         a['inputs_unchanged']is True and a['cleanup_complete']is True and a['error']is None and
         a['final_errors']==[]and a['focal_only']is True and all(a[k]is False for k in
             ('whole_profile_qualified','cold_warm_validated','mixed_policy_validated','replacement_validated',
              'held_cancellation_validated','qualification_credit','performance_credit')),
         'whole same-source/CPU focal result with separate unresolved lifecycle qualification')
    def closure():
        need(fact(path)==before,'whole focal receipt unchanged')
        for p,v in a['inputs'].items():need(fact(pin(p))==v,'whole retained focal input')
        for p,v in a['artifacts'].items():
            item=binary(p);need(dict(fact(item),mode=item.stat().st_mode&0o777)==v,'whole retained artifact and mode')
        for p,v in a['aliases'].items():need(str(pin(p))==v,'actual retained alias')
        for p,v in a['presence'].items():need(os.path.lexists(p)==v,'actual loader configuration presence')
        for p,v in a['namespace_aliases'].items():
            need(Path(p).is_symlink()and os.readlink(p)==v,'whole sealed namespace alias')
            need(p not in r['namespace_aliases']or r['namespace_aliases'][p]==v,'no conflicting inherited namespace')
            r['namespace_aliases'][p]=v
    closure()
    inputs=a['prerequisite_inputs'];need(set(inputs)=={'direct','block','fused','loop_component','loop_native'},
        'every distinct mandatory old/new prerequisite')
    arguments={}
    for name,value in inputs.items():
        need(set(value)=={'path','sha256'}and type(value['path'])is str and
             re.fullmatch('[0-9a-f]{64}',value['sha256'])is not None,'exact explicit prerequisite path/hash')
        arguments[name+'_receipt']=Path(value['path']);arguments[name+'_receipt_sha256']=value['sha256']
    holder=dict(source=r['source'],revision=r['revision'],cpu=r['cpu'],hardware=r['hardware'],namespace_aliases=r['namespace_aliases'])
    legacy(SimpleNamespace(**arguments),holder,pin,binary,archive)
    for k in('prerequisite_archive','direct_prerequisite','block_prerequisite','fused_prerequisite',
             'fused_component_prerequisite','loop_component_prerequisite'):
        need(holder[k]==a[k],'whole independently rechecked mandatory '+k)
    proof,natives,support=authenticate(arguments['loop_native_receipt'],arguments['loop_native_receipt_sha256'],
        holder,pin,binary,archive)
    need(proof==a['loop_native_prerequisite'],'whole actual28-native proof')
    commands=a['commands'];need(tuple((x['name'],x['profile'])for x in commands)==SCHEDULE and
        len(commands)==126 and len({x['name']for x in commands})==126,'complete source-owned126-command schedule')
    rows={x['name']:x for x in commands};used=set();labels={'subject-'+l+'-'+str(c)+'-'+str(p):(l,c,p)for l,c,p in ORDER}
    def capture(row,name):
        v=row['captures'][name];p=pin(directory/v['file'])
        need(p.parent==directory and fact(p)=={k:v[k]for k in('bytes','sha256')},'whole actual bounded child capture')
        return p.read_bytes()
    for row in commands:
        subject=labels.get(row['name']);status=125 if subject and subject[1]>=5 else 0
        need(type(row['exit'])is int and type(row['expected_exit'])is int and row['exit']==row['expected_exit']==status and row['timed_out']is False and
             row['reaped']is True and row['error']is None and row['cleanup_errors']==[]and
             type(row['descriptors'])is list and all(x.get('closed')is True for x in row['descriptors'])and
             row['bounds']==BOUNDS[row['profile']]and row['capture_limit']==16<<20 and
             set(row['captures'])==({'stdout','stderr','record'}if subject else{'stdout','stderr'}),
             'every actual bounded child, expected outcome and complete capture population')
        for stream in row['captures']:capture(row,stream)
        need(decode(pin(directory/(row['name']+'.json')).read_bytes())==row,'whole actual command row')
    build=a['build'];tools={n:pin(v['path'])for n,v in build['tools'].items()}
    need(all(fact(tools[n])=={k:v[k]for k in('bytes','sha256')}for n,v in build['tools'].items()),'whole actual build tools')
    retained=directory/'artifacts';actual_archive=pin(binary(retained/'decoder.a'))
    need(fact(actual_archive)==a['archive']==fact(archive),'same actual fresh eleven-source archive')
    builder=SimpleNamespace(tools=tools,environment=build['environment'],retained=retained,record=build,
        paths={'archive':actual_archive},extra_decoder_sources=('region.rs','mov_guard.rs','scalar_read.rs'),
        decoder_features=FEATURES,mov_guard=True,linked_epoch=True,scalar_span=True)
    def recorded(name,argv,profile='metadata',expected=0,env=None,record=False):
        need(name in rows and name not in used,'one source-derived admission per closed command')
        row=rows[name];environment=dict(ENV if env is None else env)
        if name.startswith(('resolve-','version-')):
            environment={k:v for k,v in environment.items()if k!='LI2_DECODER_FEATURES'}
            if name in('resolve-cargo','resolve-rustc'):
                environment={k:v for k,v in environment.items()if k in ENV or k in('HOME','CARGO_HOME','RUSTUP_HOME','LI2_MAPS_PROFILE')}
        argv=list(map(str,argv))
        if record:
            descriptors=row['descriptors']
            need(len(descriptors)==1 and descriptors[0]['name']=='record'and
                 type(descriptors[0]['fd'])is int and descriptors[0]['fd']>=3 and
                 descriptors[0]['closed']is True and argv.count('{record_fd}')==1,
                 'one actual parent-owned record descriptor replaces one argv placeholder')
            argv=[str(descriptors[0]['fd'])if x=='{record_fd}'else x for x in argv]
        need(row['argv']==argv and row['environment']==environment and row['profile']==profile and
             row['expected_exit']==expected and record is (name in labels),
             'whole source-derived recorded argv/environment/profile/expected outcome '+name)
        used.add(name);return row,capture(row,'stdout'),capture(row,'stderr')
    _,names,err=recorded('tracked-input-list',[tools['git'],'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
    need(names and not err,'whole actual tracked source list')
    for name in names.split(b'\0'):
        if name and not os.fsdecode(name).startswith('evaluation/inprocess/results/'):
            p=pin(ROOT/os.fsdecode(name));need(a['inputs'].get(str(p))==fact(p),'every listed source actually pinned')
    aliases={};archive_join(a,directory,builder,archive,pin,binary,recorded,aliases)
    owner_reader=load('loop_rechecked_focal_owner',OWNER/'read.py',pin);subjects={};original=support['original']
    for lane in LANES:
        local=directory/(lane+'-build');observed={}
        def lane_run(name,argv,profile='metadata',expected=0,env=None,record=False):
            return recorded(lane+'-'+name,argv,profile=profile,expected=expected,env=env,record=record)
        bridge=bridge_completed(builder,{'archive':actual_archive},local,pin,binary,aliases,lane_run,observed,original,
            capture=True,differential=lane=='differential')
        raw_emission(builder,bridge,pin,lane_run,observed)
        layout=observed_layout(builder,bridge,local,pin,binary,lane_run,observed,completed=True)
        values=inputs_completed(original,bridge,builder,local,pin,binary,lane_run,observed,support['application_build'])
        need(digest(observed)==digest(a['lanes'][lane]),'whole independently reconstructed build/DWARF/namespace metadata')
        subjects[lane]=(bridge,layout,*values)
    need([(c['build_lane'],c['mode'],c['placement'])for c in a['cases']]==list(ORDER),'all56 original focal cases and order')
    for case in a['cases']:
        lane,mode,place=case['build_lane'],case['mode'],case['placement'];label='subject-'+lane+'-'+str(mode)+'-'+str(place)
        bridge,layout,interp,roots,objects,description,images,raws,carrier=subjects[lane];local=directory/label
        need(case['label']==label and case['lane']==1 and case['control']==0 and case['cpu']==r['cpu']and
             case['status']==expected_status(mode)and 'errors'not in case,'actual exact focal lane, case and outcome')
        row,out,err=recorded(label,case_argv(builder,original,case,local,roots,carrier,pin),profile='program',
            expected=125 if mode>=5 else 0,record=True)
        need(case['launched']is True and case['exit']==case['expected_exit']==row['exit']and case['timed_out']is False and
             case['whole_process_ns']==row['duration_ns']and
             case['captures']=={k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()},
             'actual subject receipt/capture/duration join without timing credit')
        manifest=preparation(case,row,local,original,roots,objects,description,carrier,directory,binary,holder)
        raw=capture(row,'record');need(128<len(raw)<4<<20,'whole record below unchanged strict4MiB cap')
        image=image_inventory(original,interp,carrier,objects,manifest)
        image.update(bridge=bridge.read_bytes(),persistent_binding=a['lanes'][lane]['release_build']['persistent_binding'],
            headers=a['lanes'][lane]['release_build']['headers'],app_symbols=support['image']['symbols'])
        # Re-run pure raw readers and all supplied corruptions, never a subject.
        # Receipt summaries and modeled timelines cannot supply machine state.
        value=evaluate(case,row,out,err,raw,layout,image,support,natives[mode,place],owner_reader,
            images,raws,carrier,run_controls=True)
        need(all(digest(value[k])==digest(case[k])for k in value),'whole actual full-pair and every named control result')
    need(used==set(rows),'every complete source-derived closed invocation authenticated')
    closure();imported_sources(pin)
    return dict(schema=1,kind='owner',status='verified_prerequisite',file=str(path.relative_to(ROOT)),**before,
        revision=r['revision'],cpu=r['cpu'],source_sha256=digest(r['source']),hardware_sha256=digest(r['hardware']),
        archive=fact(archive),coverage={name:True for name in COVERAGE},qualification_credit=False,performance_credit=False)
