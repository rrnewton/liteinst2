#!/usr/bin/env python3
"""Prepare selected scalar products or release tests without dispatching either.

The existing bounded command helper and process owner remain authoritative.
Use the canonical CLI order documented in BUILD.md; each phase has one attempt.
"""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
OUTER_SECONDS = {'products': 1200, 'tests': 600}
BUILD_SOURCE_ROOTS = ('.cargo','src','crates','tools','Cargo.toml','Cargo.lock','build.rs',
                      'evaluation/ordinary-selected-session')


def load_driver(rev):
    """Authenticate both public entrypoints before importing any project code."""
    assert len(rev)==40 and all(c in '0123456789abcdef' for c in rev)
    assert subprocess.check_output(['/usr/bin/git','-C',ROOT,'rev-parse','HEAD'],timeout=15).decode().strip()==rev
    assert subprocess.check_output(['/usr/bin/git','-C',ROOT,'status','--porcelain','--untracked-files=no'],timeout=15)==b''
    for name in ('build.py','reproduce.py'):
        path=HERE/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size<=MIB
        raw=path.read_bytes()
        assert raw==subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',rev+':'+str(path.relative_to(ROOT))],timeout=15)
    spec=importlib.util.spec_from_file_location('_selected_public_build_driver',HERE/'reproduce.py')
    assert spec is not None and spec.loader is not None
    driver=importlib.util.module_from_spec(spec);sys.modules[spec.name]=driver;spec.loader.exec_module(driver)
    return driver


def source_inventory(run,git):
    names=git('ls-files','-z','--',*BUILD_SOURCE_ROOTS).decode().rstrip('\0').split('\0')
    assert names and all(names) and len(names)==len(set(names))
    committed=git('ls-tree','-r','--name-only','-z',run.a.revision,'--',*BUILD_SOURCE_ROOTS).decode().rstrip('\0').split('\0')
    assert names==committed
    result={}
    for name in names:
        raw=git('show',run.a.revision+':'+name)
        digest=hashlib.sha256(raw).hexdigest()
        assert run.sources[str(ROOT/name)]['sha256']==digest
        result[name]=digest
    return result


def tools_metadata(run,recipe):
    """Pin the compiler's actual subprocesses as well as the public tools."""
    names=('gcc','strip','readelf','objdump','taskset','git','cargo','rustc','rustdoc','python')
    paths={name:run.tools[name] for name in names}
    paths['clang']=Path('/usr/bin/clang').resolve(strict=True)
    for name in ('cc1','collect2','as','ld'):
        raw=subprocess.check_output([paths['gcc'],'-print-prog-name='+name],env=run.env,timeout=10)
        assert len(raw)<=MIB
        text=raw.decode().strip();assert text and '\n' not in text
        path=Path(text) if '/' in text else Path(shutil.which(text,path='/usr/bin:/bin'))
        paths[name]=path.resolve(strict=True)
    result={}
    for name,path in paths.items():
        value=recipe.pin(recipe.read(path,512*MIB))
        if str(path) in run.tool_pins: assert run.tool_pins[str(path)]==value
        else: run.tool_pins[str(path)]=value
        result[name]=dict(path=str(path),**value)
    versions={}
    for name in ('gcc','strip','readelf','objdump','clang','cargo','rustc'):
        raw=subprocess.check_output([paths[name],'--version'],env=run.env,stderr=subprocess.STDOUT,timeout=10)
        assert len(raw)<=MIB;versions[name]=raw.decode()
    run.env['CLANG']=str(paths['clang'])
    return result,versions


def stage_limits(index):
    assert type(index) is int and 0<=index<12
    return (120,180,128*MIB) if index<4 else (20,30,4*MIB)


def test_command(cargo):
    return [cargo,'test','--release','-p','rapid-profiler','--bin','ordinary-interval','--no-run',
            '--locked','--offline','--jobs','4','--message-format=json-render-diagnostics']


def producer_record(run,driver,recipe,hardware,previous=None):
    keys=driver.PUBLIC_BUILD_OPTIONS+(driver.PUBLIC_TEST_OPTIONS if run.a.phase=='tests' else ())
    options={key:str(getattr(run.a,key.replace('-','_'))) for key in keys}
    before=run.raw/'sources-before.json';after=run.raw/'sources-after.json'
    pin=run.retained[str(before)]
    record=dict(schema=driver.PUBLIC_BUILD_SCHEMA,phase=run.a.phase,revision=run.a.revision,
        recipe=driver.PUBLIC_BUILD_RECIPE,recipe_sha256=run.sources[str(ROOT/driver.PUBLIC_BUILD_RECIPE)]['sha256'],
        invocation=[str(run.tools['python']),'-B',sys.argv[0],*sys.argv[1:]],options=options,
        source_before=dict(path=str(before),**pin),source_after=dict(path=str(after),**pin))
    driver.public_build_invocation(record,run.a.phase,run.a.revision,run.raw,str(run.tools['python']),hardware,previous)
    return record


def copy_product(run,recipe,source,destination):
    """Copy the first authenticated bytes, never a newly read replacement."""
    raw=recipe.read(source,128*MIB);pin=recipe.pin(raw)
    run.remember(source,pin,128*MIB)
    identity=(source.stat().st_dev,source.stat().st_ino)
    run.budget.charge(str(destination),len(raw))
    with destination.open('xb') as stream: stream.write(raw)
    os.chmod(destination,0o755)
    assert (destination.stat().st_dev,destination.stat().st_ino)!=identity
    assert run.remember(destination,pin,128*MIB)==pin
    run.unchanged()
    return pin


def bounded(run,driver,recipe,name,directory,argv,limits):
    """Emit the historical receipt layout using the existing owned helper."""
    cpu,wall,cap=limits
    assert type(cpu) is int and type(wall) is int and type(cap) is int
    run.unchanged()
    if directory!=run.raw: directory.mkdir()
    request=dict(argv=list(map(str,argv)),cwd=str(ROOT),env=run.env,stdout=str(directory/'stdout'),
        stderr=str(directory/'stderr'),cpu_seconds=cpu,wall_seconds=wall,file_bytes=cap)
    run.freeze(directory/'request.json',request)
    helper=ROOT/'tools/unwind-oracle/bounded_command.py'
    owned,closed=run.owned(name+'-owner',[run.tools['python'],'-B',helper,'--request',directory/'request.json',
        '--receipt',directory/'receipt.json'],wall+25,growth=2*cap+10*MIB)
    run.safe=False
    run.freeze(directory/'closed.json',closed)
    parent=recipe.read(owned/'parent.log',MIB)
    driver.write_blob(run,recipe,directory/'owner.log',parent)
    code,out,err,receipt=driver.closed_stage(run,recipe,directory,request,closed)
    run.safe=True
    run.budget.complete()
    row=dict(name=name,request_sha256=run.retained[str(directory/'request.json')]['sha256'],
        receipt_sha256=run.retained[str(directory/'receipt.json')]['sha256'],closed=closed,
        stdout_sha256=receipt['stdout_sha256'],stderr_sha256=receipt['stderr_sha256'])
    run.unchanged()
    assert code==0
    return row,out,err


def products(run,driver,recipe,git,result):
    tools,versions=tools_metadata(run,recipe)
    sources=source_inventory(run,git)
    producer=producer_record(run,driver,recipe,run.a.hardware)
    out=run.raw/'products';out.mkdir()
    argv=driver.build_argv(tools,out)
    assert len(argv)==len(driver.BUILD_STAGES)==12
    plan=dict(schema=driver.PUBLIC_BUILD_SCHEMA,phase='products',stages=[dict(name=name,argv=command,
        cpu_seconds=stage_limits(index)[0],wall_seconds=stage_limits(index)[1],file_bytes=stage_limits(index)[2])
        for index,(name,command) in enumerate(zip(driver.BUILD_STAGES,argv))])
    run.freeze(run.raw/'consumed-build-plan.json',plan)
    frozen=dict(revision=run.a.revision,hardware=run.a.hardware,sources=sources,tools=tools,versions=versions,
        environment=run.env,cpus=run.cpus,load_before=list(os.getloadavg()),
        build_plan_sha256=run.retained[str(run.raw/'consumed-build-plan.json')]['sha256'],stages=[],producer=producer)
    run.freeze(run.raw/'frozen.json',frozen,16*MIB)
    result.update(frozen)
    for index,(name,command) in enumerate(zip(driver.BUILD_STAGES,argv)):
        row,stdout,stderr=bounded(run,driver,recipe,name,run.raw/name,command,stage_limits(index))
        result['stages'].append(row)
        if index<3: assert stdout==stderr==b''
        if index==3:
            source,artifact=run.m['native'].artifact(stdout,'ordinary-interval','ordinary-interval/main.rs','bin',False)
            copy_product(run,recipe,source,out/'ordinary-interval')
            run.freeze(run.raw/'compiler-artifact.json',artifact)
    assert tuple(row['name'] for row in result['stages'])==driver.BUILD_STAGES
    assert sorted(p.name for p in out.iterdir())==sorted(driver.BUILD_FILES)
    result['products']={name:run.remember(out/name,cap=128*MIB) for name in driver.BUILD_FILES}
    run.freeze(run.raw/'closed-stages.json',result['stages'],16*MIB)
    assert source_inventory(run,git)==sources
    result['status']='BUILD_AND_ELF_CAPTURE_PASS'


def tests(run,driver,recipe,git,result):
    a=run.a
    build=driver.accept_build(run,recipe,a.build,a.build_sha,a.build_owner,a.build_owner_sha,git)
    assert 'producer' in build and build['producer']['schema']==driver.PUBLIC_BUILD_SCHEMA
    tools,versions=tools_metadata(run,recipe)
    assert tools==build['tools'] and versions==build['versions']
    assert dict(run.env,TMPDIR=build['environment']['TMPDIR'])==build['environment']
    run.env.clear();run.env.update(build['environment'])
    previous=dict(path=str(a.build),sha256=a.build_sha)
    producer=producer_record(run,driver,recipe,build['hardware'],previous)
    source_inventory(run,git)
    _,stdout,_=bounded(run,driver,recipe,'release-tests',run.raw,test_command(tools['cargo']['path']),(120,180,128*MIB))
    source,artifact=run.m['native'].artifact(stdout,'ordinary-interval','ordinary-interval/main.rs','bin',True)
    product=run.raw/'ordinary-interval-tests';pin=copy_product(run,recipe,source,product)
    run.freeze(run.raw/'compiler-artifact.json',artifact)
    driver.source_build_join(build,run.sources,git)
    required=('request.json','receipt.json','closed.json','owner.log','stdout','stderr','compiler-artifact.json')
    result.update(status='RELEASE_TEST_BUILD_PASS',revision=a.revision,original_build_revision=build['revision'],
        original_build_receipt=previous,compiled_inputs_unchanged=True,binary=dict(path=str(product),**pin),
        members={name:run.retained[str(run.raw/name)] for name in required},cpu_affinity=run.cpus,producer=producer)


def outer_source_inventory(driver,rev):
    """The existing source family, checked against Git before and after ownership."""
    def git(*args):
        raw=subprocess.check_output(['/usr/bin/git','-C',ROOT,*args],timeout=15)
        assert len(raw)<=32*MIB
        return raw
    assert git('rev-parse','HEAD').decode().strip()==rev
    assert git('status','--porcelain','--untracked-files=no')==b''
    roots=('.cargo','src','crates','tools','tests/support','tests/call_tree_truth.rs','Cargo.toml','Cargo.lock','README.md','build.rs',':(glob)**/Cargo.toml')
    names=set(git('ls-files','-z','--',*roots).decode().rstrip('\0').split('\0'))
    for directory in ('ordinary-selected-session','ordinary-leaf-set-session','ordinary-module-session',
                      'ordinary-module-native','ordinary-module','ordinary-csv','ordinary-call-pair-session'):
        rows=git('ls-files','-z','--','evaluation/'+directory).decode().rstrip('\0').split('\0')
        names.update(name for name in rows if Path(name).suffix in ('.py','.c','.rs','.S','.map','.md'))
    names.add('evaluation/admission/processes.py')
    assert '' not in names
    result={}
    for name in sorted(names):
        path=ROOT/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size<=128*MIB
        raw=path.read_bytes()
        assert raw==git('show',rev+':'+name)
        result[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    return result


ACCURACY_SOURCES = (
    'evaluation/ordinary-accuracy/README.md',
    'evaluation/ordinary-accuracy/READER.md',
    'evaluation/ordinary-accuracy/output.py',
    'evaluation/ordinary-accuracy/phase_output.py',
    'evaluation/ordinary-accuracy/phase_controls.py',
    'evaluation/ordinary-accuracy/reader_controls.py',
    'evaluation/ordinary-accuracy/test_truth.py',
    'evaluation/ordinary-accuracy/truth.py',
)


def accuracy_source_additions(rev):
    """A separate finite family; the old build/owner inventory stays unchanged."""
    paths=subprocess.check_output(['/usr/bin/git','-C',ROOT,'ls-tree','-r','--name-only','-z',
        rev,'--','evaluation/ordinary-accuracy'],timeout=15).decode().rstrip('\0').split('\0')
    live=subprocess.check_output(['/usr/bin/git','-C',ROOT,'ls-files','-z','--',
        'evaluation/ordinary-accuracy'],timeout=15).decode().rstrip('\0').split('\0')
    assert sorted(paths)==sorted(live)==sorted(ACCURACY_SOURCES)
    result={}
    for name in ACCURACY_SOURCES:
        path=ROOT/name
        assert path.resolve(strict=True)==path and path.is_file() and not path.is_symlink() and path.stat().st_size<=MIB
        raw=path.read_bytes()
        assert raw==subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',rev+':'+name],timeout=15)
        result[name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    return result


def outer_accuracy_source_inventory(driver,rev):
    result=outer_source_inventory(driver,rev)
    extra=accuracy_source_additions(rev)
    assert not set(result)&set(extra)
    result.update(extra)
    return result


def main():
    started=time.monotonic()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=('products','tests'),required=True)
    for name in ('revision','reservation-tag','hardware'): parser.add_argument('--'+name,required=True)
    for name in ('raw','toolchain','user-home','cargo-home'): parser.add_argument('--'+name,type=Path,required=True)
    for name in ('build','build-owner'): parser.add_argument('--'+name,type=Path)
    for name in ('build-sha','build-owner-sha'): parser.add_argument('--'+name)
    a=parser.parse_args()
    prior=(a.build,a.build_sha,a.build_owner,a.build_owner_sha)
    assert all(value is not None for value in prior) if a.phase=='tests' else all(value is None for value in prior)
    driver=load_driver(a.revision)
    run,recipe,_,_,_,git=driver.bootstrap(a,started)
    run.deadline=started+OUTER_SECONDS[a.phase]
    result=dict(status='FAILED',revision=a.revision,native_dispatches=0,source_unchanged=False)
    try:
        if a.phase=='products': products(run,driver,recipe,git,result)
        else: tests(run,driver,recipe,git,result)
        run.unchanged();assert run.safe and not run.budget.exceeded
        run.freeze(run.raw/'sources-after.json',run.sources,16*MIB)
        assert run.retained[str(run.raw/'sources-after.json')]==run.retained[str(run.raw/'sources-before.json')]
        result['source_unchanged']=True
    except BaseException as error:
        result.update(status='FAILED',error=type(error).__name__+': '+str(error))
    finally:
        run.budget.stopped()
        result.update(load_after=list(os.getloadavg()),custody_closed=run.safe,evidence_budget=run.budget.summary(),
            attempted_stages=run.result['stages'])
        try:
            assert run.safe and result['source_unchanged'] is True and not run.budget.exceeded
            run.unchanged()
        except BaseException as error:
            result.update(status='FAILED',final_error=type(error).__name__+': '+str(error))
        recipe.save(run.raw/'result.json',result,32*MIB)
        if a.phase=='products' and result['status']=='BUILD_AND_ELF_CAPTURE_PASS':
            print(json.dumps(dict(status=result['status'],revision=a.revision,products=result['products'],native_dispatches=0)))
        else: print(json.dumps(result))
    return 0 if result['status'] in ('BUILD_AND_ELF_CAPTURE_PASS','RELEASE_TEST_BUILD_PASS') and time.monotonic()<run.deadline else 1


if __name__=='__main__':
    raise SystemExit(main())
