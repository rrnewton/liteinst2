"""Authenticate and reconstruct the actual 28 native references without children."""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
from types import SimpleNamespace
import tomllib

from page_selected import ENV, bridge_check, fact, need
from direct_frontier_program import decode
from persistent_dynamic import BOUNDS, H, digest, imported_sources, seed_prerequisite
from persistent_loop_archive import ARTIFACTS, package_check
from persistent_loop_build_default import before_loop_default
from persistent_loop_native_build import application, reader_support, native_namespace, native_preparation, FIXTURE
from persistent_loop_native import (ROOT, PROFILE, ORDER, SCHEDULE, CONTROL_COUNTS, summary, control_summary)
from checks import admission

FEATURES=('scalar-region','scalar-span','linked-epoch','mov-guard','scalar-read')
SOURCES=('lib.rs','abi.rs','arena.rs','decode.rs','scan.rs','tf.rs','write_footprint.rs',
         'admission_oneshot.rs','region.rs','mov_guard.rs','scalar_read.rs')
EXPORTS=('rust_eh_personality','li2_decoder_tf_classify','li2_decoder_write_footprint',
         'li2_decoder_region_describe','li2_decoder_span_describe','li2_decoder_link_none',
         'li2_decoder_mov_store','li2_decoder_scalar_read_describe','li2_decoder_scalar_read_none')
COVERAGE=('native_v2_all_cases_and_placements','native_full_state','native_controls')


def require_seed_record(replayed,recorded):
    # The format authority uses tuples; the receipt stores JSON arrays. Compare
    # the complete serialized records, preserving every field and scalar type.
    need(digest(replayed)==digest(recorded),'whole original independently qualified seed')


def archive_join(actual,directory,builder,archive,pin,binary,recorded,aliases):
    """Rejoin actual locked Rust source, exact compiler-M and retained build bytes."""
    build=actual['build'];selected=ROOT/'tools/page-entry/selected';target=ROOT/'target/page-entry/selected'
    need(build['status']=='passed' and build['started']is True and build['command_completed']is True and
         build['final_errors']==[] and build['configuration_unchanged']is True and
         build['registry_before']==build['registry_after'] and build['decoder_features']==list(FEATURES),
         'complete fresh eleven-source build and unchanged registry/configuration closure')
    need(admission.cargo_configuration(builder.environment)==build['cargo_configuration'],
         'same whole permitted Cargo configuration at prerequisite consumption')
    need(builder.environment['LI2_DECODER_FEATURES']=='scalar-read,mov-guard' and
         builder.environment['CARGO_INCREMENTAL']=='0' and builder.environment['CARGO_BUILD_JOBS']=='1' and
         builder.environment['CARGO_NET_OFFLINE']=='true' and
         builder.environment['CARGO_TARGET_DIR']==str(ROOT/'target'), 'exact actual offline one-job archive profile')
    for package in build['registry_before']:
        need(package_check(package)==package,'whole current locked registry archive and extracted source')
    for name in ('cargo','rustc'):
        _,out,err=recorded('resolve-'+name,[builder.tools['rustup'],'which',name],env=builder.environment)
        need(not err and out.decode().strip()==str(builder.tools[name]),'actual selected Rust tool')
    for name in ('cc1','collect2','as','ld'):
        _,out,err=recorded('resolve-'+name,[builder.tools['cc'],'-print-prog-name='+name],env=builder.environment)
        value=out.decode().strip();resolved=pin(value if Path(value).is_absolute()else shutil.which(value,path=ENV['PATH']))
        need(not err and resolved==builder.tools[name],'actual selected C subtool')
    for name in ('cc','cargo','rustc','python'):
        _,out,err=recorded('version-'+name,[builder.tools[name],'-vV'if name=='rustc'else'--version'],env=builder.environment)
        need(not err and out.decode().strip()==build['versions'][name],'whole observed compiler/tool version')
        match=re.search(r'\b([0-9]+)\.([0-9]+)\.([0-9]+)\b',build['versions'][name])
        need(match is not None and [int(match[i])for i in(1,2,3)]==build['numeric_versions'][name],
             'actual numeric tool version')
    _,out,err=recorded('cargo-metadata',[builder.tools['cargo'],'metadata','--manifest-path',selected/'decoder/Cargo.toml',
        '--format-version','1','--locked','--offline','--features','scalar-read,mov-guard'],env=builder.environment)
    metadata=decode(out);locked=tomllib.loads(pin(selected/'decoder/Cargo.lock').read_text())['package']
    local=[p for p in metadata['packages']if p['source']is None]
    need(not err and Path(metadata['target_directory']).resolve()==ROOT/'target' and len(local)==1 and
         Path(local[0]['manifest_path'])==selected/'decoder/Cargo.toml' and
         {(p['name'],p['version'])for p in metadata['packages']}=={(p['name'],p['version'])for p in locked},
         'whole actual offline package closure')
    nodes=[n for n in metadata['resolve']['nodes']if n['id']==local[0]['id']]
    need(len(nodes)==1 and nodes[0]['features']==['default','linked-epoch','mov-guard','scalar-read','scalar-region','scalar-span'],
         'literal eleven-source feature resolution')
    registry=[]
    for p in metadata['packages']:
        lock=next(x for x in locked if(x['name'],x['version'])==(p['name'],p['version']))
        if 'checksum' in lock:
            need(p['source']==lock['source'],'actual locked registry identity')
            registry.append(dict(name=p['name'],version=p['version'],root=str(Path(p['manifest_path']).parent),checksum=lock['checksum']))
    need(registry==[{k:p[k]for k in('name','version','root','checksum')}for p in build['registry_before']],
         'all observed packages belong to the complete authenticated registry census')
    observed={};before_loop_default('selected-build',[builder.tools['sh'],selected/'build-loop-decoder.sh'],
        builder,pin,aliases,recorded,observed)
    need(observed['default_include_closure']==actual['default_include_closure'],'complete actual default compiler-M rules')
    recorded('selected-build',[builder.tools['sh'],selected/'build-loop-decoder.sh'],profile='build',env=builder.environment)
    need(set(build['artifacts'])==set(ARTIFACTS)|{'generic-observe'} and
         [row['name']for row in build['artifact_prefix']]==[*ARTIFACTS,'generic-observe'],
         'every actual shared build product was immediately retained in fixed order')
    for row in build['artifact_prefix']:
        item=build['artifacts'][row['name']];p=binary(item['path'])
        need(p==directory/'artifacts'/row['name'] and row['copied']is True and
             row['source_before']==row['result']==fact(p)=={k:item[k]for k in('bytes','sha256')} and
             row['mode']==item['mode']==p.stat().st_mode&0o777 and
             row['source']==str(directory/'generic-observe'if row['name']=='generic-observe'else target/row['name']),
             'whole actual retained artifact and original copy provenance')
    retained=directory/'artifacts';need(fact(retained/'decoder.a')==actual['archive']==fact(archive),
        'same freshly built eleven-source archive as the consuming experiment')
    for name,tool in(('decoder-rustc.txt','rustc'),('decoder-cargo.txt','cargo'),('cc-version.txt','cc')):
        need((retained/name).read_text().strip()==build['versions'][tool],'actual build used the observed tool')
    dep=(retained/'decoder.d').read_text().strip();prefix=str(ROOT/'target/release/libli2_page_selected_decoder.a')+': '
    need(dep.startswith(prefix)and '\n'not in dep,'whole actual decoder dep-info target')
    dependencies=shlex.split(dep[len(prefix):]);expected={str(selected/'decoder/src'/n)for n in SOURCES}
    need(set(dependencies)==expected and len(dependencies)==11 and
         build['dep_info']=={str(Path(p).relative_to(ROOT)):fact(pin(p))for p in dependencies},
         'exact actual eleven-source compiler dependency closure')
    _,out,err=recorded('archive-text-exports',[builder.tools['nm'],'-g','--defined-only',retained/'decoder.a'],
        profile='inspect',env=builder.environment)
    need(not err and build['archive_text_exports']=={n:1 for n in EXPORTS},'exact nine required archive providers')
    for name in EXPORTS:
        rows=[line.split()for line in out.splitlines()if line.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()],'one actual text definition '+name)
    need(not any(line.split()[-1:]==[b'li2_decoder_add_rmw']for line in out.splitlines()),'no unselected ADD provider')
    _,out,err=recorded('bridge-undefined',[builder.tools['nm'],'-u',retained/'bridge-selected.so'],profile='inspect',env=builder.environment)
    need(out==err==b'','actual default bridge has no unresolved imports')
    _,_,err=recorded('bridge-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',retained/'bridge-selected.so'],
        profile='inspect',env=builder.environment)
    need(not err and bridge_check(retained/'bridge-selected.so')==build['bridge_elf'],'whole actual retained bridge ELF')
    argv=[builder.tools['cc'],'-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-I'+str(selected),
        '-Wl,--gc-sections,--exclude-libs,ALL,-z,noexecstack,--build-id=none',
        selected/'tests/generic/observe.c',retained/'decoder.a','-o',directory/'generic-observe']
    before_loop_default('generic-observer-link',argv,builder,pin,aliases,recorded,observed)
    need(observed['generic_observer_headers']==actual['generic_observer_headers'],'whole actual generic observer include closure')
    recorded('generic-observer-link',argv,env=builder.environment)
    need((retained/'bridge-selected.so').stat().st_mode&0o111 and
         (retained/'generic-observe').stat().st_mode&0o111,'whole retained executable build modes')


def authenticate(path,expected_sha256,r,pin,binary,archive):
    """Return (exact compact proof, (case,placement)->actual frames, support).

    No command is launched. `recorded` admits only source-derived whole argv,
    environment, profile and exit expectations against retained closed rows.
    Shared recipe/ELF/copy/seed checks then consume those actual captures. Raw
    reference read() runs again; no receipt summary supplies a machine frame.
    """
    path=pin(path)
    need(path.name=='receipt.json'and path.parent.parent==ROOT/'target/evaluation/inprocess'and
         re.fullmatch('[0-9a-f]{64}',expected_sha256)is not None and fact(path)['sha256']==expected_sha256,
         'explicit whole private paired-native receipt')
    before=fact(path);actual=decode(path.read_bytes());directory=path.parent
    need(actual['schema']==1 and actual['profile']==PROFILE and actual['status']=='observed_native_references'and
         actual['revision']==r['revision']and actual['source']==r['source']and actual['cpu']==r['cpu']and
         actual['hardware']==r['hardware']and actual['bounds']==BOUNDS and
         actual['source_unchanged']is True and actual['inputs_unchanged']is True and actual['cleanup_complete']is True and
         actual['error']is None and actual['final_errors']==[] and all(actual[k]is False for k in
             ('owner_validated','mixed_policy_validated','qualification_credit','performance_credit')),
         'complete same-source same-CPU native cohort without owner or performance credit')
    def closure():
        need(fact(path)==before,'whole native receipt unchanged')
        for name,value in actual['inputs'].items():need(fact(pin(name))==value,'whole actual native input')
        for name,value in actual['artifacts'].items():
            p=binary(name);need(p.is_relative_to(directory)and dict(fact(p),mode=p.stat().st_mode&0o777)==value,
                'whole private native artifact and mode')
        for name,value in actual['aliases'].items():need(str(pin(name))==value,'actual native input alias')
        for name,value in actual['presence'].items():need(os.path.lexists(name)==value,'actual loader configuration presence')
    closure();commands=actual['commands']
    need(set(actual['presence'])=={'/etc/ld.so.cache','/etc/ld.so.preload'}and
         actual['presence']['/etc/ld.so.preload']is False,'exact loader configuration census without global preload')
    need(tuple((c['name'],c['profile'])for c in commands)==SCHEDULE and len(commands)==82,
         'all82 fixed native commands and profiles')
    rows={c['name']:c for c in commands};used=set()
    def capture(row,name):
        item=row['captures'][name];p=pin(directory/item['file'])
        need(p.parent==directory and fact(p)=={k:item[k]for k in('bytes','sha256')}and
             0<=item['bytes']<=row['capture_limit'],'whole exact bounded native command capture')
        return p.read_bytes()
    for row in commands:
        need(type(row['exit'])is int and row['exit']==row['expected_exit']==0 and row['timed_out']is False and
             row['reaped']is True and row['error']is None and row['cleanup_errors']==[] and
             type(row['descriptors'])is list and all(d.get('closed')is True for d in row['descriptors'])and
             type(row['duration_ns'])is int and row['duration_ns']>=0 and
             row['bounds']==BOUNDS[row['profile']]and row['capture_limit']==16<<20 and
             set(row['captures'])=={'stdout','stderr'},'each bounded expected-zero process and exact closed capture population')
        for stream in row['captures']:capture(row,stream)
        need(decode(pin(directory/(row['name']+'.json')).read_bytes())==row,'whole recorded actual child row')
    build=actual['build'];tools={name:pin(value['path'])for name,value in build['tools'].items()}
    need(all(fact(tools[n])=={k:v[k]for k in('bytes','sha256')}for n,v in build['tools'].items()),'whole actual build tools')
    builder=SimpleNamespace(tools=tools,environment=build['environment'],retained=directory/'artifacts',
        extra_decoder_sources=('region.rs','mov_guard.rs','scalar_read.rs'),decoder_features=FEATURES)
    def recorded(name,argv,profile='metadata',expected=0,env=None,record=False):
        need(name in rows and name not in used,'one source-derived admission of each closed command')
        row=rows[name];environment=dict(ENV if env is None else env)
        # Tool resolution/version commands preceded the final build environment.
        # Their exact original environments are derived below, never accepted by
        # dropping a key from the observed row.
        if name.startswith(('resolve-','version-')):
            environment={k:v for k,v in environment.items()if k!='LI2_DECODER_FEATURES'}
            if name in('resolve-cargo','resolve-rustc'):
                environment={k:v for k,v in environment.items()if k in ENV or k in('HOME','CARGO_HOME','RUSTUP_HOME')}
        need(row['argv']==list(map(str,argv))and row['environment']==environment and
             row['profile']==profile and row['expected_exit']==expected==0 and record is False,
             'whole source-derived recorded argv/environment/profile '+name)
        used.add(name);return row,capture(row,'stdout'),capture(row,'stderr')
    _,names,err=recorded('tracked-input-list',[tools['git'],'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
    need(names and not err,'whole actual tracked input listing')
    for name in names.split(b'\0'):
        if name and not os.fsdecode(name).startswith('evaluation/inprocess/results/'):
            p=pin(ROOT/os.fsdecode(name));need(actual['inputs'].get(str(p))==fact(p),'every listed source was pinned')
    aliases={};archive_join(actual,directory,builder,archive,pin,binary,recorded,aliases)
    holder={};original=application(builder,directory,pin,binary,aliases,recorded,holder)
    need(holder['application_build']==actual['application_build'],'whole rebuilt application recipe/ELF/helper observation')
    reader,controls,native_policy=reader_support(builder,directory,pin,binary,recorded,holder)
    need(holder['reader_support']==actual['reader_support'],'whole actual original native-policy build')
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));layout_script=pin(FIXTURE/'layout.py')
    _,out,err=recorded('layout-gdb-version',[gdb,'--version'],env=builder.environment)
    need(out and not err,'actual no-inferior DWARF tool')
    _,out,err=recorded('native-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
        '--readnow','--se='+str(original),'-x',layout_script],profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    layout_path=binary(directory/'native-dwarf-layout.json');layout=decode(out)
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1 and layout_path.read_bytes()==out and
         actual['native_layout']==dict(path=str(layout_path),artifact=fact(layout_path),application=fact(original),observer=fact(layout_script)),
         'whole actual no-inferior ELF/DWARF/source layout')
    image=reader.elf(original.read_bytes(),native_policy,layout,holder['application_build']['headers'])
    need(controls.elf_controls(reader,original.read_bytes(),native_policy,layout,holder['application_build']['headers'])==actual['elf_controls']and
         actual['elf_control_count']==29,'every actual ELF/source control rejoined')
    native_namespace(original,holder['application_build'],pin,holder)
    need(holder['native_namespace']==actual['native_namespace'],'whole empty actual freestanding dependency namespace')
    holder.update(cpu=r['cpu'],commands=commands,seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,
        expected_exit=0,bounds=BOUNDS['seed'],completed_applications=0,owner_subjects=0,performance_credit=False))
    # The seed helper observes its own current last row in a real collector.
    holder['commands']=commands[:next(i for i,c in enumerate(commands)if c['name']=='seed-prerequisite')+1]
    seed=seed_prerequisite(builder,directory,pin,binary,recorded,holder)
    require_seed_record(holder['seed_prerequisite'],actual['seed_prerequisite'])
    seed=(*seed,capture(rows['seed-prerequisite'],'stdout'))
    need([(c['lane'],c['mode'],c['placement'])for c in actual['cases']]==[(0,c,p)for c,p in ORDER],
         'all28 actual native cases in fixed order')
    cases={};launcher=pin(FIXTURE/'launch.py')
    metadata=controls.metadata_controls(reader,image)
    for case in actual['cases']:
        mode,placement=case['mode'],case['placement'];label='subject-native-'+str(mode)+'-'+str(placement)
        prep=directory/label/'preparation.json'
        row,out,err=recorded(label,[tools['python'],'-B',launcher,'--root',ROOT,'--role','native','--case',mode,
            '--placement',placement,'--control','0','--original',original,'--library-root',original.parent,'--preparation',prep],profile='program')
        need(case['label']==label and case['status']=='observed_native_reference'and case['launched']is True and
             case['exit']==case['expected_exit']==row['exit']==0 and case['timed_out']is False and
             case['whole_process_ns']==row['duration_ns']and 'errors'not in case and
             case['captures']=={k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()}and not err,
             'each full native result belongs to its actual expected-zero closed subject')
        native_preparation(prep,row,original,mode,placement,r['cpu'],binary)
        parsed=reader.read(out,0,mode,placement,row['exit'],image,row['pid'],r['cpu'],seed)
        need(summary(parsed,mode,placement)==case['native']and
             control_summary(case['controls'],CONTROL_COUNTS[mode],parsed['raw_sha256'])==case['control_counts']and
             case['controls']['layout_controls']==metadata,'actual full frames and every native/control population')
        cases[mode,placement]=parsed
    need(used==set(rows),'every closed command rejoined against its source-derived invocation')
    need(all(actual['aliases'].get(k)==v for k,v in aliases.items()),'all reconstructed compiler-M aliases remain explicit')
    closure();imported_sources(pin)
    proof=dict(schema=1,kind='native',status='verified_prerequisite',file=str(path.relative_to(ROOT)),**before,
        revision=r['revision'],cpu=r['cpu'],source_sha256=digest(r['source']),hardware_sha256=digest(r['hardware']),
        archive=fact(archive),coverage={name:True for name in COVERAGE},qualification_credit=False,performance_credit=False)
    support=dict(reader=reader,controls=controls,image=image,seed_reference=seed,layout=layout,
        native_policy=native_policy,original=original,headers=holder['application_build']['headers'],
        application_build=holder['application_build'])
    return proof,cases,support


def prerequisite(path,expected_sha256,r,pin,binary,archive):
    return authenticate(path,expected_sha256,r,pin,binary,archive)[0]
