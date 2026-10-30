#!/usr/bin/env python3
"""Exactly two standalone release bootstrap builds after actual saved main joins.

No candidate, observer, original program, planner or verifier is dispatched.
Linked DSO facts remain pending the separate reviewed platform contract.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import types

MIB=1048576
CRATE='evaluation/adjacent-b2/artifact-verifier'
PROGRAMS=('checksum','rle-roundtrip')
CONTROL=('request.json','command.json','parent-closed.json','receipt.json','stdout.txt','stderr.txt','helper.stdout','helper.stderr')
PROFILE=dict(opt_level='3',debuginfo=0,debug_assertions=True,overflow_checks=True,test=False)


def need(ok,detail):
    if not ok:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(ctx,pins,name):
    relative=CRATE+'/'+name
    raw=ctx.read(ctx.ROOT/relative,cap=MIB)
    need(relative in pins.SOURCE_PINS and sha(raw)==pins.SOURCE_PINS[relative],'complete frozen bootstrap helper source')
    module=types.ModuleType('_bootstrap_'+name[:-3]);module.__file__=str(ctx.ROOT/relative)
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


def artifact(raw,root):
    """The DSO has filenames and executable=null; never relabel a bin receipt."""
    rows=[json.loads(row) for row in raw.splitlines()]
    matches=[r for r in rows if r.get('reason')=='compiler-artifact'
             and r['target']['name']=='liteinst_bootstrap']
    product=root/'target/release/libliteinst_bootstrap.so'
    need(len(matches)==1,'one bootstrap compiler artifact')
    row=matches[0]
    need(row['profile']==PROFILE and all(type(row['profile'][k]) is type(v) for k,v in PROFILE.items()),
         'exact release bootstrap compiler profile')
    need(row['target']['kind']==['cdylib'] and row['target']['crate_types']==['cdylib']
         and row['target']['src_path']==str(root/'crates/liteinst-bootstrap/src/lib.rs')
         and row['manifest_path']==str(root/'crates/liteinst-bootstrap/Cargo.toml')
         and row['filenames']==[str(product)] and row['executable'] is None,'exact standalone cdylib product')
    finished=[r for r in rows if r.get('reason')=='build-finished']
    need(finished==[dict(reason='build-finished',success=True)] and finished[0]['success'] is True,'actual successful build terminal')
    return product


def build_plan(root,completed,directory):
    plans={}
    for program in PROGRAMS:
        item=completed['programs'][program]
        catalog=item['catalog_pin']
        destination=item['policy']['bootstrap']
        env=dict(completed['captured']['env'],LITEINST_BOOTSTRAP_CATALOG=catalog['path'])
        argv=[completed['captured']['tools']['python']['path'],'-B',str(root/CRATE/'startup_bootstrap_from_root.py'),
              completed['captured']['tools']['cargo']['path'],str(root)]
        plans[program]=dict(directory=str(directory/program),argv=argv,env=env,catalog=catalog,
            destination=destination,limits=[120,180,128],cargo_cwd='/',attempts=1)
    need(len({row['destination'] for row in plans.values()})==2,'distinct immutable product destinations')
    return plans


def copy_artifact(custody,source,destination,store):
    """Capture one actual built inode before the next catalog rebuild replaces it.

    The final package owns the immutable destination copy. The source's before
    and after identity is a historical fact about this exact copy operation;
    it is not falsely required to survive a later build using the same target.
    """
    observed=custody.Store(32*MIB)
    try:
        raw=observed.read(source,16*MIB)
        before=observed.pin(source,16*MIB)
        fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        try:
            with os.fdopen(fd,'wb',closefd=False) as stream:
                need(stream.write(raw)==len(raw),'complete immutable DSO copy')
                stream.flush();os.fsync(stream.fileno())
        finally:
            os.close(fd)
        pin=store.pin(destination,16*MIB)
        need(store.read(destination,16*MIB,pin)==raw,'destination bytes equal actual built artifact')
        observed.verify()
        after=observed.pin(source,16*MIB)
        need(before==after,'built artifact changed during owned copy')
        parent=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
        return raw,pin,dict(source_before=before,source_after=after,destination=pin,bytes_equal=True)
    finally:
        observed.close()


def main():
    import verify_saved as legacy
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','source-profile','capture','diagnostic','verifier-build','startup-binding','main-joins'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('source-profile-sha256','capture-sha256','diagnostic-sha256','verifier-build-sha256',
                 'verifier-lock-sha256','startup-binding-sha256','main-joins-sha256'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    need(not sys.flags.optimize,'assertions required')
    root=Path(__file__).resolve().parents[3]
    ctx,a=legacy.context(root)
    # Authenticate the established loaders before using the external profile.
    def common(name):
        raw=ctx.read(root/CRATE/name,cap=MIB)
        need(name in legacy.STARTUP_MODULES and sha(raw)==legacy.STARTUP_MODULES[name],'exact integrated common helper')
        module=types.ModuleType('_bootstrap_common_'+name[:-3]);module.__file__=str(root/CRATE/name)
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
        return module
    custody=common('startup_custody.py')
    loader=common('startup_pins.py')
    pins=loader.load(ctx,args.source_profile,args.source_profile_sha256)
    driver=load(ctx,pins,'startup_produce.py')
    completed_reader=load(ctx,pins,'startup_completed.py')
    dso=load(ctx,pins,'startup_dso.py')
    originals=common('startup_originals.py')
    startup=common('startup_saved.py')
    # The running entrypoint itself must be in the independently frozen profile.
    need(sha(ctx.read(Path(__file__),cap=MIB))==pins.SOURCE_PINS[CRATE+'/startup_bootstrap.py'],'exact bootstrap entrypoint')
    output=custody.absolute(str(args.output))
    need(output.is_relative_to(root/'ignored') and output.parent.resolve(strict=True)==output.parent
         and not os.path.lexists(output)
         and all(not output.is_relative_to(path) for path in (args.capture,args.diagnostic,args.verifier_build,args.startup_binding.parent,args.main_joins)),
         'new separate private bootstrap run')
    output.mkdir(mode=0o700)
    store=custody.Store(2*1024*MIB)
    report=dict(schema='LI2STARTUP-BOOTSTRAP-RUN-1',source_revision=pins.SOURCE_REVISION,
        programs={p:dict(status='UNRUN',attempts=0,build_dispatches=0,error=None) for p in PROGRAMS},
        plan=None,producer_dispatches=0,verifier_dispatches=0,native_dispatches=0,observer_dispatches=0,
        ordinary_n01_invocations=0,bootstrap_builds_complete=False,platform_contract_accepted=False,
        artifact_complete=False,qualification_complete=False,execution_authorized=False,performance_eligible=False,error=None)
    try:
        profile_raw=store.read(args.source_profile,MIB)
        need(sha(profile_raw)==args.source_profile_sha256,'frozen private source profile')
        complete=completed_reader.authenticate(ctx,a,legacy,custody,pins,originals,startup,args,store,
            dict(directory=str(args.main_joins),sha256=args.main_joins_sha256))
        package=dso.resolver(ctx)
        package_pin=store.pin(root/dso.PACKAGE,MIB)
        need(package_pin['sha256']==dso.PACKAGE_SHA,'exact DSO resolver source')
        captured=complete['captured']
        revision=custody.source_profile(ctx,pins,captured['env'])
        sources=driver.source_snapshot(ctx,pins,legacy,store)
        lock=root/'crates/liteinst-bootstrap/Cargo.lock'
        lock_pin=store.pin(lock,16*MIB)
        need(lock_pin['sha256']==pins.SOURCE_PINS['crates/liteinst-bootstrap/Cargo.lock'],'existing separate bootstrap lock')
        plans=build_plan(root,complete,output)
        # Both final paths and their containing directory identities are frozen
        # before the first build, not selected based on a build's outcome.
        parents={}
        for row in plans.values():
            target=custody.absolute(row['destination'])
            need(target.is_relative_to(root/'ignored') and target.parent.resolve(strict=True)==target.parent
                 and not os.path.lexists(target),'new pre-frozen catalog bootstrap destination')
            fd=store.directory(target.parent)
            try:parents[str(target.parent)]=custody.stamp(os.fstat(fd))[:3]
            finally:os.close(fd)
        driver.write(output/'planned.json',dict(schema='LI2STARTUP-BOOTSTRAP-PLAN-1',revision=revision,
            source_revision=pins.SOURCE_REVISION,source_profile=dict(path=str(args.source_profile),sha256=args.source_profile_sha256),
            main_joins=complete['reference'],startup_binding=store.pin(args.startup_binding,MIB),
            sources=sources,resolver_source=package_pin,lock=lock_pin,tools=captured['tools'],
            configurations=complete['configurations'],configuration_profile=complete['plan']['configuration_profile'],
            cargo_cwd='/',builds=plans,destination_parents=parents,hardware='AMD EPYC Zen 5 dev host',
            cpus=sorted(os.sched_getaffinity(0)),load_average=Path('/proc/loadavg').read_text().split()[:3],
            producer_dispatches=0,verifier_dispatches=0,native_dispatches=0,qualification_complete=False))
        planned_pin=store.pin(output/'planned.json',MIB)
        report['plan']=planned_pin
        def stable():
            complete['stable']();store.verify()
            need(custody.source_profile(ctx,pins,captured['env'])==revision,'bootstrap source HEAD drift')
            for tool in captured['tools'].values():
                need(ctx.B.identity(tool['path'])==tool,'bootstrap tool drift')
        for program in PROGRAMS:
            row=report['programs'][program];plan=plans[program]
            stable();row.update(status='BUILD_FAILED',attempts=1,build_dispatches=None)
            build_capture=dict(env=plan['env'],tools=captured['tools'])
            code,streams=driver.execute(ctx,legacy,custody,store,build_capture,Path(plan['directory']),plan['argv'],tuple(plan['limits']))
            row.update(build_dispatches=1,exit=code)
            need(code==0,'bootstrap build exact raw exit')
            product=artifact(streams['stdout'],root)
            stable()
            raw,pin,copy=copy_artifact(custody,product,Path(plan['destination']),store)
            directory=Path(plan['directory'])
            driver.write(directory/'copy.json',copy)
            row.update(status='LINKED_INSPECTION_FAILED',destination=pin,copy=store.pin(directory/'copy.json',MIB))
            inspected=dso.inspect(raw,complete['programs'][program]['product']['catalog.li2boot'],package)
            driver.write(directory/'linked-facts.json',inspected)
            files={str(directory/name):store.pin(directory/name,128*MIB) for name in CONTROL}
            files[str(directory/'linked-facts.json')]=store.pin(directory/'linked-facts.json',16*MIB)
            files[str(directory/'copy.json')]=row['copy']
            stable()
            closure=dict(schema='LI2STARTUP-BOOTSTRAP-BUILD-1',program=program,revision=revision,plan=planned_pin,
                source_revision=pins.SOURCE_REVISION,source_profile=dict(path=str(args.source_profile),sha256=args.source_profile_sha256),
                main_joins=complete['reference'],sources=sources,resolver_source=package_pin,lock=lock_pin,
                catalog=plan['catalog'],destination=pin,copy=copy,files=files,env=plan['env'],tools=captured['tools'],
                configurations=complete['configurations'],configuration_profile='rooted-offline-neutral-toml-comments-v1',
                cargo_cwd='/',status='BUILT_INSPECTED_PENDING_FINAL_PACKAGE',qualification_complete=False,execution_authorized=False)
            driver.write(directory/'closed.json',closure)
            row.update(status='BUILT_INSPECTED_PENDING_FINAL_PACKAGE',destination=pin,
                closure=store.pin(directory/'closed.json',MIB),facts=files[str(directory/'linked-facts.json')])
        stable();report['bootstrap_builds_complete']=True
    except BaseException as error:
        report['error']=type(error).__name__+': '+str(error)
        for row in report['programs'].values():
            if row['attempts'] and row['status']!='BUILT_INSPECTED_PENDING_FINAL_PACKAGE':
                row['error']=report['error']
    finally:
        try:store.verify()
        except BaseException as error:report['error']=(report['error'] or '')+'; final custody: '+str(error)
        try:store.close()
        except BaseException as error:report['error']=(report['error'] or '')+'; close custody: '+str(error)
        report['load_average_end']=Path('/proc/loadavg').read_text().split()[:3]
        driver.write(output/'closed.json',report)
    print(json.dumps({key:report[key] for key in ('bootstrap_builds_complete','qualification_complete','execution_authorized','error')}))
    return 0 if report['bootstrap_builds_complete'] and report['error'] is None else 1


if __name__=='__main__':
    raise SystemExit(main())
