#!/usr/bin/env python3
"""One fresh startup-artifact capture/build/production attempt. Never native exec.

This driver has concrete command paths. An externally pinned private source
profile binds the integrated reviewed commit without editing tracked code after
that freeze. No receipt boolean substitutes for those pins. A catalog names the
prospective contract only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import types

MIB=1048576
CRATE='evaluation/adjacent-b2/artifact-verifier'
PROGRAMS=('checksum','rle-roundtrip')
PROFILE='elf-disassembly-null-jumps-static-exec-router-bootstrap-v1'
CONTROL=('request.json','command.json','parent-closed.json','receipt.json',
         'stdout.txt','stderr.txt','helper.stdout','helper.stderr')


def need(ok,detail):
    if not ok: raise ValueError(detail)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def write(path,value):
    raw=value if type(value) is bytes else (json.dumps(value,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:
            need(stream.write(raw)==len(raw),'complete driver write')
            stream.flush();os.fsync(stream.fileno())
    finally: os.close(fd)


def load_module(ctx,legacy,name):
    path=ctx.ROOT/CRATE/name
    raw=ctx.read(path,cap=MIB)
    need(name in legacy.STARTUP_MODULES and sha(raw)==legacy.STARTUP_MODULES[name],
         'exact integrated startup helper '+name)
    module=types.ModuleType('_startup_driver_'+name[:-3]);module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def environment(root,toolchain,cargo_home,user_home):
    for directory in (toolchain,cargo_home,user_home):
        need(directory.is_absolute() and directory.resolve(strict=True)==directory and directory.is_dir(),
             'canonical existing explicit environment directory')
    return dict(HOME=str(user_home),CARGO_HOME=str(cargo_home),PATH=str(toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(toolchain/'bin/rustc'),RUSTDOC=str(toolchain/'bin/rustdoc'),CARGO_TARGET_DIR=str(root/'target'),
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_NET_OFFLINE='true',CARGO_TERM_COLOR='never',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3',CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        LC_ALL='C',LANG='C',PYTHONDONTWRITEBYTECODE='1')


def tools(ctx,env):
    paths=dict(python=Path(sys.executable),helper=ctx.ROOT/'tools/unwind-oracle/bounded_command.py',
        **{'as':Path('/usr/bin/as'),'ld':Path('/usr/bin/ld'),'objdump':Path('/usr/bin/objdump'),
           'timeout':Path('/usr/bin/timeout'),'cargo':Path(env['RUSTC']).with_name('cargo'),
           'rustc':Path(env['RUSTC'])})
    return {name:ctx.B.identity(path) for name,path in paths.items()}


def execute(ctx,legacy,custody,store,captured,directory,argv,limits):
    """One request, never a retry. The outer process owns cleanup on uncertainty."""
    directory.mkdir(mode=0o700)
    request,command=legacy.request_and_command(ctx,captured,directory,argv,limits)
    write(directory/'request.json',request);write(directory/'command.json',command)
    parent=dict(wait_returned=False,exit=None,error=None)
    child=None;began=time.monotonic()
    try:
        with (directory/'helper.stdout').open('xb') as stdout,(directory/'helper.stderr').open('xb') as stderr:
            child=subprocess.Popen(command['argv'],cwd=command['cwd'],env=command['env'],stdin=subprocess.DEVNULL,
                stdout=stdout,stderr=stderr,start_new_session=True)
            try:
                child.wait(timeout=command['parent_seconds']);parent['wait_returned']=True
            except BaseException as error:
                parent['error']=type(error).__name__
                if child.poll() is None:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                child.wait(timeout=command['cleanup_seconds']);parent['wait_returned']=True
                raise
    finally:
        parent.update(exit=child.returncode if child else None,seconds=time.monotonic()-began)
        write(directory/'parent-closed.json',parent)
    code,streams=custody.closed(store,directory,request,command,ctx.B.HELPER_SHA)
    terminal=dict(exit=code,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=code==0)
    need(store.read(directory/'helper.stdout',limits[2]*MIB)==(json.dumps(terminal)+'\n').encode(),
         'exact helper terminal response')
    receipt=custody.json_value(store.read(directory/'receipt.json',MIB))
    need(type(receipt['elapsed_seconds']) in (int,float) and 0<=receipt['elapsed_seconds']<=limits[1],
         'unchanged strict helper wall deadline')
    return code,streams


def source_snapshot(ctx,pins,legacy,store):
    required={str(ctx.ROOT/name):h for name,h in pins.SOURCE_PINS.items()}
    required[str(ctx.ROOT/'Cargo.lock')]=pins.PRODUCER_LOCK_SHA256
    for name,h in legacy.ROOTED_BUILD_SOURCES.items():required[str(ctx.ROOT/CRATE/name)]=h
    for name,h in legacy.STARTUP_MODULES.items():required[str(ctx.ROOT/CRATE/name)]=h
    result={}
    for path,h in required.items():
        raw=store.read(Path(path),16*MIB)
        need(sha(raw)==custody_digest(h),'frozen complete source profile')
        result[path]=store.pin(Path(path),16*MIB)
    return result


def custody_digest(value):
    need(type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value),
         'frozen lower-case digest')
    return value


def fresh_capture(ctx,a,legacy,custody,originals,pins,store,captured,directory,configurations,stable):
    directory.mkdir(mode=0o700)
    for program in PROGRAMS:(directory/program).mkdir(mode=0o700)
    phase_plan=originals.phases(ctx.ROOT,directory,captured['tools'])
    initial={path:ctx.B.identity(path) for path in sorted(originals.source_inputs(ctx,pins))}
    for path,pin in initial.items():store.read(Path(path),16*MIB,pin)
    plan=dict(schema=originals.PLAN_SCHEMA,profile=originals.PROFILE,source_revision=pins.SOURCE_REVISION,
        revision=captured['revision'],env=captured['env'],tools=captured['tools'],inputs=initial,phases=phase_plan,
        configuration_profile=captured['configuration_profile'],configurations=configurations,
        hardware='AMD EPYC Zen 5 dev host',affinity=sorted(os.sched_getaffinity(0)),
        load_average=Path('/proc/loadavg').read_text().split()[:3],qualification_complete=False)
    write(directory/'planned.json',plan)
    planned_pin=store.pin(directory/'planned.json',MIB)
    results={p['name']:dict(status='UNRUN',exit=None,error=None) for p in phase_plan}
    files=dict(initial);error=None
    try:
        for phase in phase_plan:
            row=results[phase['name']]
            if any(results[dep]['status']!='PASS' for dep in phase['dependencies']):continue
            stable();row['status']='FAILED'
            d=directory/phase['name']
            try:
                code,streams=execute(ctx,legacy,custody,store,captured,d,phase['argv'],phase['limits'])
                row['exit']=code
                for name in CONTROL:files[str(d/name)]=store.pin(d/name,128*MIB)
                if code!=0:
                    row['error']='exact tool exit '+str(code)
                    continue
                if 'product' in phase:
                    builder=ctx.load(a.ROUTED.builder,a.ROUTED.builder_sha)
                    builder.check_artifact(streams['stdout'],phase)
                    files[phase['product']]=store.pin(Path(phase['product']),128*MIB)
                else:need(streams['stderr']==b'','original-facts tool stderr')
                for path in phase.get('outputs',[]):files[path]=store.pin(Path(path),MIB)
                stable();row['status']='PASS'
            except BaseException as failure:
                row['error']=type(failure).__name__+': '+str(failure)
                raise
    except BaseException as failure:
        error=type(failure).__name__+': '+str(failure)
    finally:
        # Always retain the attempted roster/outcomes. No closure label converts
        # a missing receipt, failed phase or partial output to original facts.
        write(directory/'closed.json',dict(schema=originals.SCHEMA,profile=originals.PROFILE,
            planned=planned_pin,source_revision=pins.SOURCE_REVISION,revision=captured['revision'],
            results=results,files=files,configuration_complete=error is None,
            configurations=configurations,error=error,qualification_complete=False))
    need(error is None and all(row['status']=='PASS' for row in results.values()),
         'fresh original capture incomplete; no producer dispatch')
    reference=dict(directory=str(directory),sha256=sha(store.read(directory/'closed.json',MIB)))
    args=types.SimpleNamespace(startup_custody=custody,startup_pins=pins)
    facts=originals.authenticate(ctx,a,legacy,args,store,reference)
    return reference,facts


def producer_build(ctx,a,legacy,custody,pins,store,captured,directory,configurations,stable):
    need(custody_digest(pins.PRODUCER_LOCK_SHA256)==sha(ctx.read(ctx.ROOT/'Cargo.lock',cap=16*MIB)),
         'exact producer workspace lock')
    launcher=ctx.ROOT/CRATE/'startup_cargo_from_root.py'
    argv=[captured['tools']['python']['path'],'-B',str(launcher),captured['tools']['cargo']['path'],str(ctx.ROOT),'producer']
    stable()
    code,streams=execute(ctx,legacy,custody,store,captured,directory,argv,(120,180,128))
    need(code==0,'closed producer build failed')
    binary=ctx.ROOT/'target/release/examples/offline_router_sites'
    builder=ctx.load(a.ROUTED.builder,a.ROUTED.builder_sha)
    builder.check_artifact(streams['stdout'],dict(product_name='offline_router_sites',product_kind='example',product=str(binary)))
    stable()
    required={str(ctx.ROOT/name):h for name,h in pins.SOURCE_PINS.items()}
    required[str(ctx.ROOT/'Cargo.lock')]=pins.PRODUCER_LOCK_SHA256
    required[str(launcher)]=legacy.STARTUP_MODULES['startup_cargo_from_root.py']
    for name,h in legacy.ROOTED_BUILD_SOURCES.items():required[str(ctx.ROOT/CRATE/name)]=h
    files={}
    for path,h in required.items():
        raw=store.read(Path(path),16*MIB);need(sha(raw)==h,'producer build input source identity')
        files[path]=store.pin(Path(path),16*MIB)
    for path in [binary,*(directory/name for name in CONTROL)]:files[str(path)]=store.pin(path,128*MIB)
    write(directory/'closed.json',dict(schema='LI2STARTUP-BUILD-1',role='producer',source_revision=pins.SOURCE_REVISION,
        files=files,configurations=configurations,configuration_profile=captured['configuration_profile'],
        cargo_cwd='/',lock_sha256=pins.PRODUCER_LOCK_SHA256))
    reference=dict(directory=str(directory),sha256=sha(store.read(directory/'closed.json',MIB)))
    checked,observed=custody.build(ctx,a,legacy,pins,store,'producer',reference,captured)
    need(checked==binary and observed==configurations,'independent producer build receipt roundtrip')
    return reference,binary


def startup_policy(program,inputs,interpreter,bootstrap,dependencies,contract):
    need(program in PROGRAMS and inputs['policy'].startswith(b'LI2DISASM-POLICY 6\n'),
         'full unchanged v6 planning inputs')
    for path in [interpreter,bootstrap,*dependencies]:
        need(type(path) is str and path.startswith('/') and len(path)<=4095
             and all(33<=ord(c)<=126 for c in path)
             and all(c not in ('','.','..') for c in path.split('/')[1:]),'canonical startup policy pathname')
    need(1<=len(dependencies)<=16 and list(dependencies)==sorted(dependencies)
         and interpreter in dependencies and bootstrap not in dependencies,'exact sorted dependency policy roster')
    custody_digest(contract);need(contract!='0'*64,'prospective contract identity')
    lines=['LI2BOOTSTRAP-POLICY 1','profile linux-x86-64-static-exec-router-bootstrap-v1',
        'program '+program,'original '+sha(inputs['original']),'disassembly '+sha(inputs['ledger']),
        'planning-policy '+sha(inputs['policy']),'interpreter '+interpreter,'bootstrap '+bootstrap,
        'app-stack 4481024 65536','qualification-contract '+contract,
        'startup-limits 4096 4096 4097 112 16384 4096 65536 1048576']
    for path,pin in dependencies.items():lines.append('dependency '+path+' '+custody_digest(pin['sha256']))
    raw=('\n'.join(lines)+'\n').encode('ascii');need(len(raw)<=65536,'startup policy bound')
    return raw


def materials(ctx,a,legacy,custody,store,facts,directory,interpreter,bootstrap_paths,dependencies,contract):
    directory.mkdir(mode=0o700)
    adapter=ctx.load('adjacent_routed_jmp_material.py',a.MATERIAL_SHA)
    sources={}
    for program in PROGRAMS:
        inputs=facts['inputs'][program]
        result=adapter.attempt_adjacent_routed_jmp(program,inputs,{key:sha(value) for key,value in inputs.items()},
                                                 upper=2,lower=1,joint=2)
        raw=result['files']
        saved=dict(result);saved['files']={name:dict(bytes=len(value),sha256=sha(value)) for name,value in raw.items()}
        write(directory/(program+'-material.json'),saved)
        need(a.check_material(program,result,raw,inputs['original'],a.ROUTED) is not None,'whole original materials refused')
        expected=legacy.expected_files(ctx,a,program,inputs,raw)
        need(len(expected)==5,'unchanged independent original expected-file roster')
        group=dict(original=inputs['original'],ledger=raw['ledger.txt'],policy=raw['policy.txt'])
        group['startup']=startup_policy(program,group,interpreter,bootstrap_paths[program],dependencies,contract)
        sources[program]={}
        for key,value in group.items():
            path=directory/(program+'-'+key);write(path,value);sources[program][key]=path
            store.read(path,65536 if key=='startup' else MIB)
        write(directory/(program+'-heads.txt'),inputs['heads'])
        write(directory/(program+'-inventory.tsv'),raw['source-inventory.tsv'])
        for name,value in expected.items():write(directory/(program+'-expected-'+name),value)
    facts['stable']();store.verify()
    return sources


def inventory(store,path,expected_sha):
    raw=store.read(path,MIB)
    need(sha(raw)==custody_digest(expected_sha),'passive inventory exact identity')
    value=json.loads(raw)
    need(value['kind']=='PASSIVE_HOST_INPUT_INVENTORY_ONLY' and value['qualification'] is False
         and value['launches']==0,'passive facts never runtime qualification')
    dependencies={};interpreter=None
    for row in value['files']:
        if row['input'] not in ('/lib64/ld-linux-x86-64.so.2','/lib64/libc.so.6','/lib64/libgcc_s.so.1'):continue
        need(row['readelf_exit']==0,'passive ELF inspection failure')
        pin=dict(path=row['canonical'],bytes=row['bytes'],sha256=row['sha256'],
                 stat=[row['device'],row['inode'],row['mode'],row['bytes'],row['mtime_ns'],row['ctime_ns']])
        store.read(Path(pin['path']),16*MIB,pin)
        need(pin['path'] not in dependencies,'duplicate canonical dependency')
        dependencies[pin['path']]=pin
        if row['input']=='/lib64/ld-linux-x86-64.so.2':interpreter=pin['path']
    need(interpreter is not None and len(dependencies)==3,'exact three passive dependency files')
    need(sum(pin['bytes'] for pin in dependencies.values())<=128*MIB,'unchanged dependency byte bound')
    return interpreter,{path:dependencies[path] for path in sorted(dependencies)}


def main():
    # Only the root-owned exact integrated script is dispatched. Imported helper
    # modules are separately authenticated by the frozen startup module profile.
    import verify_saved as legacy
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('output','toolchain','cargo-home','user-home','host-inventory','contract-record','source-profile'):
        parser.add_argument('--'+key,type=Path,required=True)
    for key in ('host-inventory-sha256','contract-sha256','source-profile-sha256'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--failure-history',type=Path,action='append',default=[])
    args=parser.parse_args()
    need(not sys.flags.optimize,'assertions required')
    root=Path(__file__).resolve().parents[3]
    ctx,a=legacy.context(root)
    custody=load_module(ctx,legacy,'startup_custody.py')
    originals=load_module(ctx,legacy,'startup_originals.py')
    pin_loader=load_module(ctx,legacy,'startup_pins.py')
    profile_path=custody.absolute(str(args.source_profile))
    profile_sha=custody_digest(args.source_profile_sha256)
    pins=pin_loader.load(ctx,profile_path,profile_sha)
    source_profile=dict(path=str(profile_path),sha256=profile_sha)
    env=environment(root,args.toolchain,args.cargo_home,args.user_home)
    tool_pins=tools(ctx,env)
    custody.environment(ctx,env,tool_pins)
    revision=custody.source_profile(ctx,pins,env)
    captured=dict(env=env,tools=tool_pins,revision=revision)
    rooted=legacy.rooted_module(ctx)
    configs=rooted.configurations(ctx,captured,profile=rooted.COMMENT_PROFILE)
    captured['configuration_profile']=rooted.COMMENT_PROFILE
    out=custody.absolute(str(args.output))
    need(out.is_relative_to(root/'ignored') and out.parent.resolve(strict=True)==out.parent
         and not os.path.lexists(out),'new ignored run directory')
    out.mkdir(mode=0o700)
    store=custody.Store(512*MIB)
    report=dict(schema='LI2STARTUP-PRODUCTION-RUN-1',profile=PROFILE,revision=revision,source_revision=pins.SOURCE_REVISION,
        source_profile=source_profile,original_capture=None,producer_build=None,plan=None,binding=None,producer_attempts=0,producer_dispatches=0,
        expected_programs=2,expected_heads=187,expected_selected=42,adjacent_upper=2,adjacent_lower=1,adjacent_joint=2,
        producer_status='UNRUN',candidate_complete=False,artifact_complete=False,qualification_complete=False,
        native_dispatches=0,bootstrap_builds=0,execution_authorized=False,performance_eligible=False,error=None)
    try:
        need(sha(store.read(profile_path,MIB))==profile_sha,'frozen external source-profile identity')
        source=source_snapshot(ctx,pins,legacy,store)
        contract=store.read(custody.absolute(str(args.contract_record)),MIB)
        need(sha(contract)==custody_digest(args.contract_sha256),'prospective contract record identity')
        interpreter,dependencies=inventory(store,custody.absolute(str(args.host_inventory)),args.host_inventory_sha256)
        need(len(args.failure_history)<=64 and len({str(p) for p in args.failure_history})==len(args.failure_history),
             'bounded unique retained failure history')
        history=[store.pin(custody.absolute(str(path)),MIB) for path in args.failure_history]
        for pin in history:custody.json_value(store.read(Path(pin['path']),MIB,pin))
        package=out/'package';package.mkdir(mode=0o700)
        bootstrap={p:str(package/(p+'-bootstrap.so')) for p in PROGRAMS}
        need(len(set(bootstrap.values()))==2,'distinct per-program future DSO paths')
        write(out/'run-planned.json',dict(schema='LI2STARTUP-PRODUCTION-PLAN-1',profile=PROFILE,
            revision=revision,source_revision=pins.SOURCE_REVISION,source_profile=source_profile,
            env=env,tools=tool_pins,files=source,
            configuration_profile=rooted.COMMENT_PROFILE,cargo_cwd='/',configurations=configs,
            host_inventory=store.pin(args.host_inventory,MIB),contract_record=store.pin(args.contract_record,MIB),
            dependencies=dependencies,bootstrap_paths=bootstrap,failure_history=history,
            hardware='AMD EPYC Zen 5 dev host',cpus=sorted(os.sched_getaffinity(0)),
            load_average=Path('/proc/loadavg').read_text().split()[:3],
            original_phase_count=12,producer_build_attempts=1,whole_producer_attempts=1,
            producer_limits=[20,30,16],native_dispatches=0,bootstrap_builds=0,qualification_complete=False))
        def stable():
            store.verify()
            need(custody.source_profile(ctx,pins,env)==revision,'source HEAD changed during run')
            need(rooted.configurations(ctx,captured,profile=rooted.COMMENT_PROFILE)==configs,'rooted Cargo scope changed')
            for pin in tool_pins.values():need(ctx.B.identity(pin['path'])==pin,'tool identity changed')
        capture,facts=fresh_capture(ctx,a,legacy,custody,originals,pins,store,captured,out/'originals',configs,stable)
        report['original_capture']=capture
        build,binary=producer_build(ctx,a,legacy,custody,pins,store,captured,out/'producer-build',configs,stable)
        report['producer_build']=build
        originals_sources=materials(ctx,a,legacy,custody,store,facts,out/'materials',interpreter,bootstrap,dependencies,args.contract_sha256)
        copies=custody.copy_inputs(originals_sources,out/'inputs')
        plan=dict(schema='LI2STARTUP-SAVED-PLAN-1',profile=PROFILE,capture=capture,source_revision=pins.SOURCE_REVISION,
            source_profile=source_profile,
            env=env,tools=tool_pins,configuration_profile=rooted.COMMENT_PROFILE,configurations=configs,
            producer_build=build,inputs=copies,dependencies=dependencies,
            producer_directory=str(out/'producer'),output=str(out/'product'))
        plan_path=out/'startup-plan.json';write(plan_path,plan)
        plan_sha=sha(store.read(plan_path,MIB));report['plan']=store.pin(plan_path,MIB)
        custody.frozen_inputs(store,plan);stable()
        argv=custody.producer_argv(binary,plan)
        report.update(producer_attempts=1,producer_dispatches=None,producer_status='FAILED')
        command_error=None
        try:
            code,streams=execute(ctx,legacy,custody,store,captured,Path(plan['producer_directory']),argv,(20,30,16))
            report['producer_exit']=code
            report['producer_dispatches']=1
            if code in (0,2):
                expected=(f'profile={PROFILE} candidate_complete={str(code==0).lower()} qualification_complete=false '
                          'required_programs=2 required_heads=187 required_selected=42\n').encode()
                need(streams['stdout']==expected and streams['stderr']==b'','exact full-program producer response')
                report.update(producer_status='PRODUCER_COMPLETE_UNVERIFIED' if code==0 else 'REFUSED',candidate_complete=code==0)
            else:
                report['producer_status']='FAILED'
        except BaseException as error:
            command_error=error
        # Preserve closed failure bytes as well as success. Missing receipt or
        # uncertain custody is retained in run-closed and cannot mint a capsule.
        try:
            stable();custody.frozen_inputs(store,plan)
            binding=out/'startup-binding.json'
            binding_sha=custody.close_binding(plan_path,plan_sha,Path(plan['producer_directory']),Path(plan['output']),
                [Path(pin['path']) for pin in history],binding)
            report['binding']=dict(path=str(binding),sha256=binding_sha)
        except BaseException as error:
            if command_error is None:command_error=error
        if command_error is not None:raise command_error
        stable()
    except BaseException as error:
        report['error']=type(error).__name__+': '+str(error)
    finally:
        try:store.verify()
        except BaseException as error:
            report['error']=(report['error'] or '')+'; final custody: '+str(error)
        try:store.close()
        except BaseException as error:
            report['error']=(report['error'] or '')+'; descriptor close: '+str(error)
        report['load_average_end']=Path('/proc/loadavg').read_text().split()[:3]
        write(out/'run-closed.json',report)
    print(json.dumps({key:report[key] for key in ('producer_status','producer_dispatches','candidate_complete',
        'artifact_complete','qualification_complete','native_dispatches','bootstrap_builds','error')}))
    return 0 if report['error'] is None and report['candidate_complete'] and report['binding'] is not None else 1


if __name__=='__main__':
    raise SystemExit(main())
