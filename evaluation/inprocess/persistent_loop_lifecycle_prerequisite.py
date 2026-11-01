"""Reauthenticate the actual four native/eight lifecycle records, complete builds and controls."""
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
from persistent_loop_native_prerequisite import archive_join,FEATURES
from persistent_dynamic import BOUNDS,H,digest,load,imported_sources,image_inventory,raw_emission
from persistent_loop_lifecycle_helpers import (ROOT,OWNER,PROFILE,NATIVE_ORDER,ORDER,LANES,SCHEDULE,COVERAGE,
    case_argv,evaluate,providers,builds,coverage,native_summary,application_controls)
from persistent_loop_lifecycle_native_build import (FIXTURE,application,reader_support,observed_layout,
    native_namespace,native_preparation,preparation)
from persistent_loop_owner_prerequisite import legacy
from persistent_dynamic import seed_prerequisite



def prerequisite(path,expected_sha256,r,pin,binary,archive):
    path=pin(path)
    need(path.name=='receipt.json'and path.parent.parent==ROOT/'target/evaluation/inprocess'and
         re.fullmatch('[0-9a-f]{64}',expected_sha256)is not None and fact(path)['sha256']==expected_sha256,
         'explicit whole private schema15 lifecycle receipt')
    before=fact(path);a=decode(path.read_bytes());directory=path.parent
    need(a['schema']==1 and a['profile']==PROFILE and a['status']=='observed_lifecycle_unqualified'and
         a['source']==r['source']and a['revision']==r['revision']and a['cpu']==r['cpu']and
         a['hardware']==r['hardware']and a['bounds']==BOUNDS and a['source_unchanged']is True and
         a['inputs_unchanged']is True and a['cleanup_complete']is True and a['error']is None and
         a['final_errors']==[]and all(a[k]is False for k in
             ('whole_profile_qualified','qualification_credit','performance_credit')),
         'whole same-source/CPU finite lifecycle result without general qualification')
    def closure():
        need(fact(path)==before,'whole lifecycle receipt unchanged')
        for p,v in a['inputs'].items():need(fact(pin(p))==v,'whole retained lifecycle input')
        for p,v in a['artifacts'].items():
            item=binary(p);need(dict(fact(item),mode=item.stat().st_mode&0o777)==v,'whole retained artifact and mode')
        for p,v in a['aliases'].items():need(str(pin(p))==v,'actual retained alias')
        need(set(a['presence'])=={'/etc/ld.so.cache','/etc/ld.so.preload'}and
             a['presence']['/etc/ld.so.preload']is False,
             'complete loader configuration presence and no global preload')
        for p,v in a['presence'].items():need(type(v)is bool and os.path.lexists(p)==v,'actual loader configuration presence')
        for p,v in a['namespace_aliases'].items():
            need(Path(p).is_symlink()and os.readlink(p)==v,'whole sealed namespace alias')
            need(p not in r['namespace_aliases']or r['namespace_aliases'][p]==v,'no conflicting inherited namespace')
            r['namespace_aliases'][p]=v
    closure()
    inputs=a['prerequisite_inputs'];need(set(inputs)=={'direct','block','fused','loop_component'},
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
    commands=a['commands'];need(tuple((x['name'],x['profile'])for x in commands)==SCHEDULE and
        len(commands)==116 and len({x['name']for x in commands})==116,'complete source-owned116-command schedule')
    rows={x['name']:x for x in commands};used=set();labels={'subject-'+l+'-'+str(c)+'-'+str(p):(l,c,p)for l,c,p in ORDER}
    native_labels={'subject-native-'+str(c)+'-'+str(p):(c,p)for c,p in NATIVE_ORDER}
    def capture(row,name):
        v=row['captures'][name];p=pin(directory/v['file'])
        need(p.parent==directory and fact(p)=={k:v[k]for k in('bytes','sha256')}and
             0<=v['bytes']<=row['capture_limit'],'whole actual bounded child capture')
        return p.read_bytes()
    for row in commands:
        subject=labels.get(row['name']);status=0
        need(type(row['exit'])is int and type(row['expected_exit'])is int and row['exit']==row['expected_exit']==status and row['timed_out']is False and
             row['reaped']is True and row['error']is None and row['cleanup_errors']==[]and
             type(row['descriptors'])is list and all(x.get('closed')is True for x in row['descriptors'])and
             type(row['duration_ns'])is int and row['duration_ns']>=0 and
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
                environment={k:v for k,v in environment.items()if k in ENV or k in('HOME','CARGO_HOME','RUSTUP_HOME')}
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
    native_holder={};original=application(builder,directory,pin,binary,aliases,recorded,native_holder)
    need(digest(native_holder['application_build'])==digest(a['application_build']),
         'whole actual lifecycle application recipe, five TUs, ELF and helper oracle')
    reader,controls,native_policy=reader_support(builder,directory,pin,binary,recorded,native_holder)
    need(native_holder['reader_support']==a['reader_support'],'whole actual native policy classifier')
    layout=observed_layout(builder,original,directory,pin,binary,recorded,native_holder,completed=True)
    need(native_holder['native_layout']==a['native_layout'],'whole actual native DWARF provenance')
    owner_reader,reports,counts=providers(pin,controls)
    need(digest(counts)==digest(a['control_populations']),'literal reviewed lifecycle control populations')
    image=reader.elf(original.read_bytes(),native_policy,layout,native_holder['application_build']['headers'])
    elf_controls=controls.elf_controls(reader,original.read_bytes(),native_policy,layout,native_holder['application_build']['headers'])
    need(elf_controls==a['elf_controls']and elf_controls['status']=='passed'and
         elf_controls['count']==a['elf_control_count']==counts['elf'],'all actual native ELF/source controls')
    native_namespace(original,native_holder['application_build'],pin,native_holder)
    need(native_holder['native_namespace']==a['native_namespace'],'whole empty native dependency namespace')
    native_holder.update(cpu=r['cpu'],commands=commands[:next(i for i,c in enumerate(commands)
        if c['name']=='seed-prerequisite')+1],seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,
        expected_exit=0,bounds=BOUNDS['seed'],completed_applications=0,owner_subjects=0,performance_credit=False))
    seed=seed_prerequisite(builder,directory,pin,binary,recorded,native_holder)
    need(native_holder['seed_prerequisite']==a['seed_prerequisite'],'complete separately qualified seed capture')
    seed=(*seed,capture(rows['seed-prerequisite'],'stdout'))
    need([(c['lane'],c['mode'],c['placement'])for c in a['native_cases']]==[(0,c,p)for c,p in NATIVE_ORDER],
         'all four exact native references in original orientation/placement order')
    natives={}
    for case in a['native_cases']:
        mode,place=case['mode'],case['placement'];label='subject-native-'+str(mode)+'-'+str(place)
        need(case['label']==label and case['status']=='observed_native_reference'and
             case['control']==0 and case['cpu']==r['cpu']and 'errors'not in case,
             'one complete native reference and controls before gated execution')
        row,out,err=recorded(label,case_argv(builder,original,case,directory/label,[original.parent],None,pin),profile='program')
        need(not err and case['launched']is True and case['exit']==case['expected_exit']==row['exit']==0 and
             case['timed_out']is False and case['whole_process_ns']==row['duration_ns']and
             case['captures']=={k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()},
             'whole native subject outcome/captures/validation duration')
        native_preparation(directory/label/'preparation.json',row,original,mode,place,r['cpu'],binary)
        parsed=reader.read(out,0,mode,place,row['exit'],image,row['pid'],r['cpu'],seed)
        need(native_summary(parsed,mode,place)==case['native'],'actual full native state summary')
        observed=controls.controls(reader,out,0,mode,place,row['exit'],image,row['pid'],r['cpu'],seed)
        metadata=controls.metadata_controls(reader,image)
        application_controls(observed,metadata,counts['native'][mode],H(out),counts['metadata'],lane=0)
        need(observed==case['controls']and case['control_counts']==dict(native=counts['native'][mode],layout=counts['metadata']),
             'all actual supplied native and DWARF corruptions rechecked')
        natives[mode,place]=parsed
    support=dict(reader=reader,controls=controls,image=image,seed_reference=seed,layout=layout,
        native_policy=native_policy,original=original,headers=native_holder['application_build']['headers'],
        application_build=native_holder['application_build'])
    subjects=builds(builder,{'archive':actual_archive},directory,pin,binary,aliases,recorded,a,support,completed=True)
    need([(c['build_lane'],c['mode'],c['placement'])for c in a['cases']]==list(ORDER),'all eight lifecycle subjects and fixed order')
    for case in a['cases']:
        lane,mode,place=case['build_lane'],case['mode'],case['placement'];label='subject-'+lane+'-'+str(mode)+'-'+str(place)
        bridge,layout,interp,roots,objects,description,images,raws,carrier=subjects[lane];local=directory/label
        need(case['label']==label and case['lane']==1 and case['control']==0 and case['cpu']==r['cpu']and
             case['status']=='observed_lifecycle'and 'errors'not in case,'actual exact lifecycle lane, case and outcome')
        row,out,err=recorded(label,case_argv(builder,original,case,local,roots,carrier,pin),profile='program',
            expected=0,record=True)
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
        value=evaluate(case,row,out,err,raw,layout,image,support,natives[mode,place],owner_reader,reports,
            counts,images,raws,carrier)
        need(all(digest(value[k])==digest(case[k])for k in value),'whole actual full-pair and every named control result')
    need(used==set(rows),'every complete source-derived closed invocation authenticated')
    need(coverage(a['cases'])==a['coverage'],'both actual primary orientations in each placement and lane')
    closure();imported_sources(pin)
    return dict(schema=1,kind='lifecycle',status='verified_prerequisite',file=str(path.relative_to(ROOT)),**before,
        revision=r['revision'],cpu=r['cpu'],source_sha256=digest(r['source']),hardware_sha256=digest(r['hardware']),
        archive=fact(archive),coverage={name:True for name in COVERAGE},qualification_credit=False,performance_credit=False)
