"""One bounded ten-child Rust reference producer in an exact private source view."""
import hashlib,importlib.util,json,os,re,shlex,shutil,tomllib
from pathlib import Path
from page_selected import fact,need
from page_selected_generic_build import package_check
from checks import admission
H=lambda b:hashlib.sha256(b).hexdigest()
TEST='dynamic_five_trajectory_reference_boundary'
BOUNDS={'reference_program':[30,512<<20,16<<20,60]}
ROOTS=('Cargo.toml','Cargo.lock','rust-toolchain.toml','README.md','.cargo','src','tests',
       'benches','examples','crates','tools/rapid-profiler','tools/exception-oracle','tools/elf-rewrite')

def retain_cargo_capture(captured,state,root,view,packages,pin,binary,errors):
    """Independent custody of each real completed artifact, including failures."""
    state['compiler_artifacts']=[];state['dep_info']={}
    try:
        if not captured.exists():return
        lines=captured.read_bytes().splitlines()
    except BaseException as error:
        errors.append('reference build capture: '+type(error).__name__+': '+str(error));return
    for line in lines:
        try:
            message=json.loads(line)
            if message.get('reason')!='compiler-artifact':continue
            state['compiler_artifacts'].append(message)
            names=message['filenames'];need(type(names)is list and names,'complete actual Cargo filename list')
        except BaseException as error:
            errors.append('reference Cargo artifact row: '+type(error).__name__+': '+str(error));continue
        deps=set()
        for name in names:
            try:
                path=pin(name);need(path.is_relative_to(root/'target'),'actual single-target compiler artifact')
                binary(path);stem=path.stem
                if stem.startswith('lib'):stem=stem[3:]
                candidate=path.with_name(stem+'.d')
                if candidate.is_file():deps.add(candidate)
                if message['target']['kind']==['custom-build']:deps.update(path.parent.glob('*.d'))
            except BaseException as error:errors.append('reference Cargo artifact: '+type(error).__name__+': '+str(error))
        if not deps:errors.append('reference Cargo artifact: missing emitted dep-info')
        for path in sorted(deps):
            try:
                pin(path);binary(path);text=path.read_text().replace('\\\n',' ')
                first=text.splitlines()[0];need(': 'in first,'actual complete Rust dependency rule')
                names=shlex.split(first.split(': ',1)[1]);need(names,'actual compiler source dependencies')
                actual={}
                for name in names:
                    try:
                        # Cargo records local paths relative to its workspace,
                        # which is the authenticated private view for this build.
                        dependency=pin(Path(name)if Path(name).is_absolute()else view/name)
                        need(dependency.is_relative_to(view)or dependency.is_relative_to(root/'target')or
                             any(dependency.is_relative_to(Path(p['root']))for p in packages),
                             'actual compiled source belongs to private, locked registry or generated Cargo domain')
                        actual[str(dependency)]=fact(dependency)
                    except BaseException as error:errors.append('reference Cargo source: '+type(error).__name__+': '+str(error))
                state['dep_info'][str(path)]=dict(fact(path),dependencies=actual)
            except BaseException as error:errors.append('reference Cargo dep-info: '+type(error).__name__+': '+str(error))


def produce(builder,root,private,fixture,pin,binary,run,receipt,boundary):
    root,private,fixture=map(Path,(root,private,fixture))
    state=receipt['reference_producer']=dict(status='failed',build_completed=False,run_completed=False,
        source_view={},overlays={},registry=[],packages=[],artifacts={},cases=[],configuration=None)
    output=private/'reference';output.mkdir();view=output/'source';view.mkdir();corpus=output/'corpus';corpus.mkdir()
    pending=[];packages=[];environment=dict(builder.environment)
    # This is an ordinary Rust test with unwind cleanup, not the decoder's
    # panic-abort C archive. Its one Cargo target remains the existing root.
    # Cargo may reuse relative dep-info across distinct private workspaces.
    # A unique invocation cfg covers every compiled unit in the shared target;
    # no source reads are inferred merely from remapping an old .d file.
    build_identity=H(os.fsencode(view.resolve(strict=True)))
    need('CARGO_ENCODED_RUSTFLAGS'not in environment,'unambiguous reference compiler flags')
    environment.update(CARGO_TARGET_DIR=str(root/'target'),CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='1',
        RUSTFLAGS='--cfg=li2_b2_reference_build="'+build_identity+'"',
        CARGO_PROFILE_TEST_DEBUG='0',LI2_B2_REFERENCE_DIR=str(corpus))
    state['environment']=environment.copy()
    def retain(path):
        try:
            if path.exists()or path.is_symlink():state['artifacts'][str(path)]=dict(fact(binary(path)),mode=path.stat().st_mode&0o777)
        except BaseException as error:receipt['final_errors'].append('reference partial artifact: '+type(error).__name__+': '+str(error))
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    try:
        state['configuration']=admission.cargo_configuration(environment)
        context=json.loads(pin(fixture/'reference/PINS.json').read_bytes())
        _,out,err=run('reference-source-paths',[builder.tools['git'],'-C',root,'ls-files','-z','--',*ROOTS,*context])
        need(not err,'actual compiler-source enumeration')
        paths=[Path(os.fsdecode(x))for x in out.split(b'\0')if x]
        need(paths and len(paths)==len(set(paths))and all(not p.is_absolute()and '..'not in p.parts for p in paths),
             'unique closed source-view paths')
        for relative in paths:
            source=pin(root/relative);need(not(root/relative).is_symlink(),'no source-view alias substitution')
            target=view/relative;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('xb')as f:f.write(source.read_bytes())
            target.chmod(source.stat().st_mode&0o777);pin(target)
            need(fact(target)==fact(source),'complete source-view identity')
            state['source_view'][str(relative)]=dict(fact(source),mode=source.stat().st_mode&0o777)
        prepare=load('b2_reference_source_prepare',fixture/'reference/producer/prepare.py')
        state['overlays']=prepare.prepare(root,view)
        need(set(state['overlays'])==set(prepare.DESTINATIONS.values()),'only three frozen Rust source additions')
        for relative,want in state['overlays'].items():need(fact(pin(view/relative))==want,'actual immutable reference addition')
        manifest=pin(view/'Cargo.toml');lock=pin(view/'Cargo.lock')
        _,out,err=run('reference-cargo-metadata',[builder.tools['cargo'],'metadata','--manifest-path',manifest,
            '--format-version','1','--locked','--offline'],env=environment)
        need(not err,'actual reference metadata stderr');metadata=json.loads(out)
        need(Path(metadata['workspace_root'])==view and Path(metadata['target_directory'])==root/'target',
             'private exact source view and sole existing Cargo target')
        locked={(p['name'],p['version']):p for p in tomllib.loads(lock.read_text())['package']}
        state['metadata']=metadata
        for package in metadata['packages']:
            key=(package['name'],package['version']);need(key in locked,'actual locked reference package')
            item=locked[key];path=pin(package['manifest_path'])
            if package['source']is None:
                need(path.is_relative_to(view)and not item.get('source'),'exact local source package')
            else:
                need(package['source']==item['source']and 'checksum'in item,'locked registry package identity')
                p=dict(name=key[0],version=key[1],root=str(path.parent),checksum=item['checksum']);packages.append(p);state['packages'].append(p)
                state['registry'].append(package_check(p))
                pin(path.parent/'.cargo-ok');pin(path.parent.parents[2]/'cache'/path.parent.parent.name/(path.parent.name+'.crate'))
        for query in ('sysroot','target-libdir'):
            _,out,err=run('reference-rust-'+query,[builder.tools['rustc'],'--print',query],env=environment)
            need(not err and Path(out.decode().strip()).is_absolute(),'actual installed Rust library directory')
            state[query]=out.decode().strip()
        libdir=Path(state['target-libdir']).resolve(strict=True)
        state['rust_libraries']={str(pin(p)):fact(p)for p in sorted(libdir.iterdir())if p.is_file()}
        need(state['rust_libraries'],'complete installed Rust library inputs')
        argv=[builder.tools['cargo'],'test','--manifest-path',manifest,'-p','liteinst-launch',
              '--test','b2_dynamic_reference','--no-run','--locked','--offline','--message-format=json']
        state['build_argv']=list(map(str,argv))
        try:_,out,err=run('reference-build',argv,profile='build',env=environment)
        finally:
            retain_cargo_capture(private/'reference-build.stdout',state,root,view,packages,pin,binary,receipt['final_errors'])
        messages=[json.loads(line)for line in out.splitlines()]
        need(messages and messages[-1]=={'reason':'build-finished','success':True},'actual successful reference build terminal')
        products=[m for m in messages if m.get('reason')=='compiler-artifact']
        need(products==state['compiler_artifacts']and not receipt['final_errors'],'complete independently retained Cargo artifact prefix')
        need(all(p.get('fresh')is False for p in products),'every emitted reference compiler artifact freshly compiled for this source view')
        candidates=[m for m in products if m.get('target',{}).get('name')=='b2_dynamic_reference'and m.get('executable')]
        need(len(candidates)==1 and candidates[0]['target']['src_path']==str(view/'crates/liteinst-launch/tests/b2_dynamic_reference.rs')and
             candidates[0]['target']['kind']==['test']and candidates[0]['profile']['test']is True and
             candidates[0]['profile']['debuginfo']==0 and candidates[0].get('fresh')is False,
             'one actual freshly compiled exact named reference test binary without debug sections')
        ids={p['id']for p in metadata['packages']}
        need(all(p['package_id']in ids for p in products),'all actual compiled artifacts have authenticated package sources')
        state['compiler_artifacts']=products
        compiled={p for row in state['dep_info'].values()for p in row['dependencies']}
        required={str(view/p)for p in prepare.DESTINATIONS.values()}|{str(view/'crates/liteinst-launch/tests/support/b2_reference'/n)for n in ('model.rs','raw.rs','cases.rs','checks.rs')}
        need(required<=compiled,'all three real additions and all unchanged reference/model sources in actual dep-info')
        for item in products:
            for path in item['filenames']:
                p=pin(path);need(p.is_relative_to(root/'target'),'actual single-target compiler artifact')
        executable=Path(candidates[0]['executable']);retained=output/'reference-test';pending.append(retained)
        with pin(executable).open('rb')as src,retained.open('xb')as dst:shutil.copyfileobj(src,dst)
        retained.chmod(executable.stat().st_mode&0o777);binary(retained);pin(retained)
        need(fact(retained)==fact(executable),'exact immediately retained actual executable')
        state['executable']=dict(path=str(retained),**fact(retained));state['build_completed']=True
        # Keep actual loader identities closed; compiler-selected objects are
        # separate facts from the Rust source/library archive closure above.
        namespace=load('b2_reference_namespace',root/'tools/page-entry/namespace.py')
        info=namespace.parse(retained.read_bytes());interpreter=pin(info['interpreter'])
        selected={}
        for name in ('libc.so.6','libgcc_s.so.1','libm.so.6'):
            _,out,err=run('reference-runtime-'+name,[builder.tools['cc'],'-print-file-name='+name],env=environment)
            need(not err and Path(out.decode().strip()).is_absolute(),'actual compiler-selected reference runtime')
            p=pin(out.decode().strip());selected[name]=dict(path=str(p),**fact(p))
        _,out,err=run('reference-libraries',[interpreter,'--list',retained],env=environment)
        need(not err,'actual reference loader listing');state['libraries']=libraries(root,retained,interpreter,out,selected,pin)
        state['command']='reference-program'
        row,out,err=run(state['command'],[retained,'--exact',TEST,'--nocapture','--test-threads=1'],
            profile='reference_program',env=environment,record=True,step=True)
        expected=('\nrunning 1 test\ntest '+TEST+' ... LI2_B2_DYNAMIC_REFERENCE programs=5 selected_per_lane=17 raw_processes=5 trap_processes=5 model_passes=5\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in ')
        need(not err and re.fullmatch(re.escape(expected)+r'[0-9]+\.[0-9]+s\n\n',out.decode())and
             row['captures']['record']['bytes']==0,'exact one-test success, all ten reaped reference children and empty observer FD')
        state['run_completed']=True
        need({p.name for p in corpus.iterdir()}=={'case'+str(i)for i in range(5)},'exact five actual reference output directories')
        files_by_case=[]
        for index in range(5):
            directory=corpus/('case'+str(index));files={}
            names=('image','li2-b2-reference.so','reference.bin','reference-complete.txt')
            need({p.name for p in directory.iterdir()}==set(names),'exact complete reference output members')
            for name in names:
                path=directory/name;files[name]=dict(fact(binary(path)),mode=path.stat().st_mode&0o777);pin(path)
            files_by_case.append(files)
        refs=boundary.corpus(corpus)
        for index,(ref,image)in enumerate(refs):
            state['cases'].append(dict(case=ref['case'],selected=len(ref['rows']),files=files_by_case[index],image=image))
        need(len(refs)==5 and sum(len(x['rows'])for x,_ in refs)==17,'complete original five-case corpus')
        state['status']='passed';return corpus,refs
    finally:
        for path in pending:retain(path)
        if corpus.exists():
            for path in sorted(corpus.rglob('*')):
                if path.is_file()and not path.is_symlink():retain(path)
        try:
            state['registry_after']=[package_check(p)for p in packages]
            need(state['registry_after']==state['registry'],'reference registry source closure unchanged')
            need(admission.cargo_configuration(environment)==state['configuration'],'reference Cargo configuration unchanged')
        except BaseException as error:receipt['final_errors'].append('reference final closure: '+type(error).__name__+': '+str(error))
        if receipt['final_errors']:state['status']='failed'


# Same closed PIE loader graph as the format measurement, with the explicit
# compiler-selected libm dependency used by Rust standard libraries.
def libraries(root,executable,interpreter,output,link_inputs,pin):
    # Reuse the existing bounded ELF parser, including its rejection of search,
    # audit and filter policies. No approximate ld.so search is performed here.
    path=pin(Path(root)/'tools/page-entry/namespace.py')
    spec=importlib.util.spec_from_file_location('provider_link_namespace',path)
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    main=namespace.parse(Path(executable).read_bytes())
    interpreter=pin(interpreter);loader=namespace.parse(interpreter.read_bytes())
    need(main['elf_type']==3 and main['interpreter']is not None and
         pin(main['interpreter'])==interpreter,'actual provider PT_INTERP identity')
    need(loader['elf_type']==3 and loader['interpreter']is None and
         loader['soname']is not None,'actual unchained provider interpreter SONAME')
    runtime_names={'libc.so.6','libgcc_s.so.1','libm.so.6'}
    need(loader['soname']not in runtime_names,'distinct interpreter SONAME')
    allowed=runtime_names|{loader['soname']}
    rows={};infos={};vdso=0
    for line in output.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso+=1;continue
        match=re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'closed actual provider loader dependency row')
        name=match[1];alias=match[2];target=pin(alias)
        if name is None or name.startswith('/'):
            need(target==interpreter and(name is None or pin(name)==interpreter),'actual provider interpreter aliases')
            name=loader['soname']
        need(name in allowed and name not in rows,'unique known provider loader object')
        info=namespace.parse(target.read_bytes())
        need(info['elf_type']==3 and info['soname']==name,'actual dependency SONAME/type')
        if name==loader['soname']:need(target==interpreter,'actual needed interpreter identity')
        else:
            selected=link_inputs.get(name)
            need(selected is not None and pin(selected['path'])==target and
                 fact(target)=={k:selected[k]for k in ('bytes','sha256')},'compiler-selected runtime dependency '+name)
        if info['interpreter']is not None:
            need(pin(info['interpreter'])==interpreter,'dependency descriptive PT_INTERP identity')
        need(str(target)not in {r['path']for r in rows.values()},'distinct provider object paths')
        rows[name]=dict(alias=alias,path=str(target),needed=info['needed'],**fact(target));infos[name]=info
    need(vdso==1 and loader['soname']in rows and 'libc.so.6'in rows,'complete actual libc/interpreter listing')
    need(infos[loader['soname']]==loader,'listed interpreter metadata identity')
    # Every DT_NEEDED edge must resolve once, and every listed object must be
    # reachable from the executable or its actual interpreter. Extra objects,
    # missing transitive edges and unsupported SONAMEs cannot be normalized away.
    pending=list(main['needed'])+list(loader['needed']);seen={loader['soname']};at=0
    while at<len(pending):
        name=pending[at];at+=1
        need(name in allowed and name in rows,'every actual provider DT_NEEDED edge resolves')
        if name in seen:continue
        seen.add(name);pending.extend(infos[name]['needed'])
    need(seen==set(rows),'exact reachable provider loader object set')
    return dict(executable=dict(**fact(executable),needed=main['needed']),
                interpreter_soname=loader['soname'],objects=rows,vdso_rows=vdso)


def finalize(receipt):
    state=receipt.get('reference_producer')
    if state is None:return
    need([package_check(p)for p in state.get('packages',[])]==state.get('registry',[]),
         'all locked reference package sources unchanged through C execution')
    if state.get('configuration')is not None:
        need(admission.cargo_configuration(state['environment'])==state['configuration'],
             'reference Cargo configuration unchanged through C execution')
