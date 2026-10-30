#!/usr/bin/env python3
"""Public adapter for the existing process owner; never supervises processes itself."""
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
import re
import subprocess

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
MIB=1048576
WALL_SECONDS=1200
OUTPUT_BYTES=8*MIB
COMMON=('phase','revision','reservation-tag','owner','raw','toolchain','user-home','cargo-home','hardware')
BUILD=('build','build-sha','build-owner','build-owner-sha')
TEST=('test-product','test-product-sha','test-owner','test-owner-sha')
CONTROLS=('controls','controls-sha','controls-owner','controls-owner-sha','geometry','geometry-sha')
EXTRAS={'products':(),'tests':BUILD,'controls':BUILD+TEST,'campaign':BUILD+CONTROLS}
PROFILES=('selected-session-functional-v1','selected-session-whole-functional-v1')
SDK_BUILD=('sdk-build','sdk-build-sha','sdk-build-owner','sdk-build-owner-sha')
SDK_CONTROLS=('sdk-controls','sdk-controls-sha','sdk-controls-owner','sdk-controls-owner-sha')
SDK_OLD_CONTROLS=('controls','controls-sha','controls-owner','controls-owner-sha')
SDK_GEOMETRY=('geometry','geometry-sha')
SDK_EXTRAS={'sdk-build':BUILD,'sdk-controls':BUILD+SDK_BUILD+SDK_OLD_CONTROLS,
    'sdk-cohort':BUILD+SDK_BUILD+SDK_CONTROLS+SDK_GEOMETRY+('cohort',),
    'sdk-collect':BUILD+SDK_BUILD+SDK_CONTROLS+SDK_GEOMETRY+('cohorts','cohorts-sha')}
COHORTS=('unstripped-k10','unstripped-k1000','stripped-k10','stripped-k1000')


def sdk_commands(options,python,script):
    phase=options['phase'];assert phase in SDK_EXTRAS
    keys=COMMON+SDK_EXTRAS[phase]
    assert set(options)==set(keys) and all(type(v) is str and v for v in options.values())
    assert re.fullmatch('[0-9a-f]{40}',options['revision'])
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}',options['reservation-tag'])
    assert 1<=len(options['hardware'])<=160 and options['hardware'].isascii() and all(32<=ord(c)<127 for c in options['hardware'])
    assert script in ('evaluation/ordinary-selected-session/owner.py',str(HERE/'owner.py'))
    for key in keys:
        if key.endswith('-sha'): assert re.fullmatch('[0-9a-f]{64}',options[key])
        elif key not in ('phase','revision','reservation-tag','hardware','cohort'): assert Path(options[key]).is_absolute()
    if phase=='sdk-cohort': assert options['cohort'] in COHORTS
    invocation=[python,'-B',script]+[word for key in keys for word in ('--'+key,options[key])]
    child_keys=('phase','revision','reservation-tag','raw','toolchain','user-home','cargo-home','hardware')+SDK_EXTRAS[phase]
    child=[python,'-B',str(HERE/'sdk_state.py')]+[word for key in child_keys for word in ('--'+key,options[key])]
    return invocation,child


def commands(options,python,script):
    """A finite argv grammar; no arbitrary executable or shell command input."""
    if options['phase'] in SDK_EXTRAS:
        return sdk_commands(options,python,script)
    phase=options['phase'];assert phase in EXTRAS
    selected=('profile',) if 'profile' in options else ()
    if selected:
        assert phase in ('controls','campaign') and options['profile'] in PROFILES
    keys=COMMON+EXTRAS[phase]+selected
    assert set(options)==set(keys)
    assert all(type(v) is str and v for v in options.values())
    assert re.fullmatch('[0-9a-f]{40}',options['revision'])
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}',options['reservation-tag'])
    assert 1<=len(options['hardware'])<=160 and options['hardware'].isascii() and all(32<=ord(c)<127 for c in options['hardware'])
    assert script in ('evaluation/ordinary-selected-session/owner.py',str(HERE/'owner.py'))
    for key in keys:
        if key.endswith('-sha'): assert re.fullmatch('[0-9a-f]{64}',options[key])
        elif key not in ('phase','revision','reservation-tag','hardware','profile'):
            assert Path(options[key]).is_absolute()
    invocation=[python,'-B',script]+[word for key in keys for word in ('--'+key,options[key])]
    if phase in ('products','tests'):
        target=HERE/'build.py'
        child_keys=('phase','revision','reservation-tag','raw','toolchain','user-home','cargo-home','hardware')+EXTRAS[phase]
    else:
        target=HERE/'reproduce.py'
        child_keys=('phase','revision','reservation-tag','raw','toolchain','user-home','cargo-home')+EXTRAS[phase]
    child_keys+=selected
    child=[python,'-B',str(target)]+[word for key in child_keys for word in ('--'+key,options[key])]
    return invocation,child


def environment(options):
    return dict(HOME=options['user-home'],CARGO_HOME=options['cargo-home'],
        PATH=options['toolchain']+'/bin:/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',LC_ALL='C')


def log_paths(output):
    """The existing process owner only accepts logs below target/evaluation."""
    assert output.is_absolute() and output.is_relative_to(ROOT/'ignored') and output.suffix=='.json'
    label=hashlib.sha256(str(output).encode('utf-8')).hexdigest()
    capture=ROOT/'target/evaluation'/('selected-public-owner-'+label)/'owner.log'
    return capture,output.with_suffix('.log')


def prepare_log(output):
    capture,archive=log_paths(output)
    base=ROOT/'target/evaluation'
    base.mkdir(parents=True,exist_ok=True)
    assert base.resolve(strict=True)==base
    capture.parent.mkdir(mode=0o700,exist_ok=False)
    assert capture.parent.resolve(strict=True)==capture.parent
    assert not os.path.lexists(capture) and not os.path.lexists(archive)
    return capture,archive


def archive_closed_log(recipe,closed,capture,archive):
    """No capture read is permitted until the existing owner proves cleanup."""
    if closed['cleanup_complete'] is not True:
        return False
    assert capture.is_relative_to(ROOT/'target/evaluation') and archive.is_relative_to(ROOT/'ignored')
    data=recipe.read(capture,OUTPUT_BYTES)
    assert hashlib.sha256(data).hexdigest()==closed['private_log_sha256']
    with archive.open('xb') as stream:
        assert stream.write(data)==len(data)
    saved=recipe.read(archive,OUTPUT_BYTES)
    assert saved==data and hashlib.sha256(saved).hexdigest()==closed['private_log_sha256']
    return True


def own_command(process_owner,recipe,command,env,capture,archive):
    # All signal, timeout, descendant and final reap logic stays in this existing API.
    try: closed=process_owner.run_command(command,env,capture,WALL_SECONDS,OUTPUT_BYTES)
    except BaseException as error:
        return dict(closed=None,log_archived=False,owner_error=type(error).__name__+': '+str(error))
    result=dict(closed=closed,log_archived=False)
    if closed['cleanup_complete'] is True:
        try: result['log_archived']=archive_closed_log(recipe,closed,capture,archive)
        except BaseException as error:
            result['log_error']=type(error).__name__+': '+str(error)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=tuple(EXTRAS)+tuple(SDK_EXTRAS),required=True)
    parser.add_argument('--profile',choices=PROFILES)
    for name in COMMON[1:]: parser.add_argument('--'+name,required=True)
    for name in dict.fromkeys(BUILD+TEST+CONTROLS+tuple(x for row in SDK_EXTRAS.values() for x in row)): parser.add_argument('--'+name)
    args=parser.parse_args();phase=args.phase
    extras=SDK_EXTRAS[phase] if phase in SDK_EXTRAS else EXTRAS[phase]
    permitted=COMMON+extras
    if args.profile is not None:
        assert phase in ('controls','campaign')
        permitted+=('profile',)
    assert all(getattr(args,key.replace('-','_')) is None for key in set(BUILD+TEST+CONTROLS+tuple(x for row in SDK_EXTRAS.values() for x in row))-set(extras))
    options={key:getattr(args,key.replace('-','_')) for key in permitted}
    python=str(Path(sys.executable).resolve(strict=True))
    invocation,command=commands(options,python,sys.argv[0])
    assert invocation==[python,'-B',sys.argv[0],*sys.argv[1:]]
    checked=('owner.py','build.py','reproduce.py')+(('sdk_state.py','sdk_state_controls.py') if phase in SDK_EXTRAS else ())
    return _run_owner(args,options,invocation,command,checked,'owner.py','selected-session-public-owner-v1')


def _run_owner(args,options,invocation,command,checked,owner_name,owner_schema):
    # Only fixed entrypoint wrappers call this; process supervision remains unchanged.
    assert (owner_name,owner_schema) in (('owner.py','selected-session-public-owner-v1'),
        ('accuracy_owner.py','selected-sdk-accuracy-public-owner-v1'))
    phase=args.phase
    os.chdir(ROOT)
    for name in checked:
        path=HERE/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size<=MIB
        expected=subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',args.revision+':'+str(path.relative_to(ROOT))],timeout=15)
        assert path.read_bytes()==expected
    spec=importlib.util.spec_from_file_location('_selected_public_owner_build',HERE/'build.py')
    assert spec is not None and spec.loader is not None
    builder=importlib.util.module_from_spec(spec);sys.modules[spec.name]=builder;spec.loader.exec_module(builder)
    driver=builder.load_driver(args.revision)
    before=builder.outer_source_inventory(driver,args.revision)
    recipe_path=ROOT/driver.RECIPE
    assert hashlib.sha256(recipe_path.read_bytes()).hexdigest()==driver.RECIPE_SHA
    recipe=driver.load('public_outer_recipe',recipe_path)
    owner_path=ROOT/'evaluation/admission/processes.py'
    assert before[str(owner_path.relative_to(ROOT))]['sha256']==recipe.OWNER_SHA
    process_owner=driver.load('public_outer_owner',owner_path)
    output=Path(args.owner);capture,log=log_paths(output);raw=Path(args.raw)
    assert output.parent.resolve(strict=True)==output.parent and output.is_relative_to(ROOT/'ignored') and output.suffix=='.json'
    assert raw.parent.resolve(strict=True)==raw.parent and raw.is_relative_to(ROOT/'ignored')
    assert len({output,log,raw})==3
    assert not any(os.path.lexists(p) for p in (output,log,raw))
    for name in ('toolchain','user-home','cargo-home'):
        path=Path(options[name]);assert path.resolve(strict=True)==path and path.is_dir()
    cpus=sorted(os.sched_getaffinity(0));assert len(cpus)==3 and all(0<=cpu<1024 for cpu in cpus)
    env=environment(options)
    result=dict(base=args.revision,working_source_sha256={},command=command,env=env,
        wall_limit_seconds=WALL_SECONDS,output_limit_bytes=OUTPUT_BYTES,reserved_cpus=cpus,
        load_before=list(os.getloadavg()),hardware=args.hardware,attempts=1,source_unchanged=False,
        public_owner=dict(schema=owner_schema,phase=phase,revision=args.revision,
            recipe='evaluation/ordinary-selected-session/'+owner_name,
            recipe_sha256=before['evaluation/ordinary-selected-session/'+owner_name]['sha256'],invocation=invocation))
    assert prepare_log(output)==(capture,log)
    result.update(own_command(process_owner,recipe,command,env,capture,log))
    result.update(capture_log=str(capture),load_after=list(os.getloadavg()))
    closed=result['closed']
    if closed is not None and closed['cleanup_complete'] is True and result['log_archived'] is True:
        try: result['source_unchanged']=builder.outer_source_inventory(driver,args.revision)==before
        except BaseException as error: result['source_error']=type(error).__name__+': '+str(error)
    with output.open('x') as stream: json.dump(result,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps(dict(owner=str(output),exit_code=None if closed is None else closed['exit_code'],
        cleanup_complete=False if closed is None else closed['cleanup_complete'],
        log_archived=result['log_archived'],source_unchanged=result['source_unchanged'])))
    return 0 if closed is not None and closed['exit_code']==0 and closed['termination'] is None and closed['cleanup_complete'] is True and closed['reaped_descendants']==0 and result['log_archived'] is True and result['source_unchanged'] is True else 1


if __name__=='__main__':
    raise SystemExit(main())
