#!/usr/bin/env python3
"""Root-owned, once-only launcher. A CLOSED root protocol is a separate input.

No recipe or native result is accepted by this wrapper. Only the selected
allocator/recipe invocation, bounded closure and immutable source joins are
recorded. There is no gate-receipt reader or retry operation.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

MIB = 1048576
OWNER = 'evaluation/admission/processes.py'
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
ALLOCATOR_MAP_SHA = '5f47ef0ee344f8e28bdb200e2ae21bab2c4a276d2746d73c204410a2a798d212'
PROFILES = {
    'call-pair-original-native': dict(script='evaluation/ordinary-call-pair-native/reproduce.py',
        cpus=3, stages=37, application_attempts=0, expected_aborts=0, old_pairs=0, new_pairs=192,
        terminal='CALL_PAIR_ORIGINAL_NATIVE_LOCAL_COMPLETE',
        recipe_profile='normal-call-pair-original-rust-v1', coverage_groups=12,
        target_calls=768, target_returns=768, outer_returns=384, normal_reaps=384),
    'preparation-refusal': dict(script='evaluation/ordinary-leaf-set-session/preparation_refusal.py',
        cpus=2, stages=8, application_attempts=1, expected_aborts=1, old_pairs=0, new_pairs=0,
        terminal='EXPECTED_PREPARATION_REFUSAL'),
    'leaf-whole-native': dict(script='evaluation/ordinary-leaf-set-native/reproduce.py',
        cpus=3, stages=32, application_attempts=0, expected_aborts=0, old_pairs=48, new_pairs=1280,
        terminal='LEAF_SET_WHOLE_NATIVE_LOCAL_COMPLETE'),
    'leaf-whole-session': dict(script='evaluation/ordinary-leaf-set-whole-session/reproduce.py',
        cpus=3, stages=175, application_attempts=144, expected_aborts=0, old_pairs=0, new_pairs=0,
        terminal='LEAF_SET_WHOLE_FUNCTIONAL_PASS', recipe_profile='leaf-set-whole-session-v1',
        reference_children=24, qualifications=5, installed_per_qualification=24, installed_children=120,
        records_per_qualification=4064, calls_per_qualification=10160, epochs=520, resident_banks=3,
        arm_deadline_ns=2000000, period_ns=10000000, shutdown_ns=2000000000,
        catalog_sha256='68836b6094e77ff46412d18c7f4db6fe24ed12a487e487648edddcdbe6877470',
        csv_policy='certified', length_policy='whole', digits_policy='whole', spaces_policy='whole'),
}
TOOLS = ('python','git','du','systemd-run','true','cargo','rustc','rustdoc','gcc','readelf','objdump','bash','rg')
COMMON = (OWNER, 'evaluation/ordinary-module-session/reproduce.py',
    'evaluation/ordinary-module-session/corpus.py', 'evaluation/ordinary-module-session/produce.py',
    'evaluation/ordinary-module-session/output.py', 'evaluation/ordinary-module-session/controls.py',
    'evaluation/ordinary-module-native/reproduce.py', 'evaluation/ordinary-module-native/module_native.py',
    'evaluation/ordinary-module-native/controls.py', 'evaluation/ordinary-module/reproduce.py',
    'evaluation/ordinary-csv/reproduce.py', 'tools/unwind-oracle/bounded_command.py', 'tests/call_tree_truth.rs')
EXTRA = {
    'call-pair-original-native': tuple('evaluation/ordinary-rust-invoke-native/'+n for n in (
        'reproduce.py','rust_invoke.py','caller.py','controls.py','runner_controls.py')) +
        tuple('evaluation/ordinary-leaf-set-native/'+n for n in (
        'reproduce.py','leaf_set_native.py','controls.py','runner_controls.py','README.md')) +
        tuple('evaluation/ordinary-call-pair-native/'+n for n in (
        'reproduce.py','call_pair_native.py','controls.py','runner_controls.py','README.md')) +
        ('evaluation/ordinary-leaf-set-session/reproduce.py',),
    'preparation-refusal': tuple('evaluation/ordinary-leaf-set-session/'+n for n in (
        'preparation_refusal.py','preparation_refusal.S','preparation_refusal_controls.py','PREPARATION_REFUSAL.md')),
    'leaf-whole-native': tuple('evaluation/ordinary-rust-invoke-native/'+n for n in (
        'reproduce.py','rust_invoke.py','caller.py','controls.py','runner_controls.py')) +
        tuple('evaluation/ordinary-leaf-set-native/'+n for n in (
        'reproduce.py','leaf_set_native.py','controls.py','runner_controls.py','README.md')) +
        ('evaluation/ordinary-leaf-set-session/reproduce.py',),
    'leaf-whole-session': tuple('evaluation/ordinary-leaf-set-whole-session/'+n for n in (
        'reproduce.py','produce.py','catalog.py','profile.py','profile_controls.py','README.md')) +
        tuple('evaluation/ordinary-leaf-set-session/'+n for n in (
        'reproduce.py','produce.py','catalog.py','output.py','controls.py','runner_controls.py',
        'original.c','original_controls.c','original_controls.py','original_output.py','README.md')) +
        tuple('evaluation/ordinary-module-session/'+n for n in (
        'owners.py','original.c','original_mount_controls.c')) +
        ('tools/rapid-profiler/selected-work/check_output.py','tools/rapid-profiler/verify_normal_session.py',
        'tools/rapid-profiler/normal-work/leaf_set.c','tools/rapid-profiler/normal-work/csv_fields.c',
        'tools/rapid-profiler/strnlen-work/localize.map'),
}


def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')


def pin(data):
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def read(path, cap):
    def identity(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data=stream.read(cap+1)
        assert len(data)==before.st_size and identity(before)==identity(os.fstat(stream.fileno()))==identity(path.lstat())
        return data


def save(path, value, cap=256*1024):
    data=canonical(value); assert len(data) <= cap
    with path.open('xb') as stream: stream.write(data)
    return pin(data)


def validate_protocol(p):
    assert set(p)=={'CLOSED','execution','version','profile','qualification','revision','tag','paths','launcher',
        'source_pins','tools','allocator_revision','allocator_sources','session_env','limits'}
    assert p['CLOSED'] is True and p['execution']=='UNRUN' and type(p['version']) is int and p['version']==1
    assert p['profile'] in PROFILES and p['qualification']==PROFILES[p['profile']]
    assert all(type(p['qualification'][k]) is type(v) for k,v in PROFILES[p['profile']].items())
    for key in ('revision','allocator_revision'): assert re.fullmatch('[0-9a-f]{40}',p[key])
    assert re.fullmatch('[a-z0-9-]{1,128}',p['tag'])
    assert p['limits']==dict(outer_seconds=7200 if p['profile']=='leaf-whole-session' else 1200,
        outer_log_bytes=8*MIB,evidence_bytes=2*1024**3,
        build_reserve_bytes=1024**3,wrapper_bytes=24*MIB,slot_limit_bytes=20000000000)
    assert all(type(v) is int for v in p['limits'].values())
    paths=p['paths']; assert set(paths)=={'root','raw','capture','log_dir','toolchain','user_home','cargo_home','allocator_root'}
    for value in paths.values():
        assert type(value) is str and '\0' not in value and Path(value).is_absolute()
        assert str(Path(value))==value and '..' not in Path(value).parts
    root=Path(paths['root']); raw=Path(paths['raw']); capture=Path(paths['capture']); logs=Path(paths['log_dir'])
    assert all(x.is_relative_to(root/'ignored') and x!=root/'ignored' for x in (raw,capture))
    assert not raw.is_relative_to(capture) and not capture.is_relative_to(raw)
    assert logs.parent==root/'target/evaluation'
    assert raw.name!=logs.name and re.fullmatch('[A-Za-z0-9_.-]+',raw.name) and re.fullmatch('[A-Za-z0-9_.-]+',logs.name)
    assert set(p['tools'])==set(TOOLS) and p['source_pins']
    def shape(value, path=False):
        assert set(value)==({'path','bytes','sha256'} if path else {'bytes','sha256'})
        assert type(value['bytes']) is int and 0 <= value['bytes'] <= 512*MIB
        assert re.fullmatch('[0-9a-f]{64}',value['sha256'])
        if path: assert Path(value['path']).is_absolute() and '\0' not in value['path']
    shape(p['launcher'],True)
    for value in p['tools'].values(): shape(value,True)
    for name,value in p['source_pins'].items():
        assert not Path(name).is_absolute() and str(Path(name))==name and '..' not in Path(name).parts
        shape(value)
    assert set(COMMON+EXTRA[p['profile']]) <= p['source_pins'].keys()
    assert p['source_pins'][OWNER]['sha256']==OWNER_SHA
    assert pin(canonical(p['allocator_sources']))['sha256']==ALLOCATOR_MAP_SHA
    assert set(p['session_env']) <= {'XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS'}
    assert all(type(v) is str and v and '\0' not in v for v in p['session_env'].values())
    return PROFILES[p['profile']]


def command_environment(p):
    paths=p['paths']; profile=validate_protocol(p); python=p['tools']['python']['path']
    argv=[python,'-B',str(Path(paths['allocator_root'])/'py/dagrun/cpuset_allocator.py'),
        'run','--cores',str(profile['cpus']),'--sample-s','1','--tag',p['tag'],'--',
        python,'-B',str(Path(paths['root'])/profile['script']),'--revision',p['revision'],
        '--reservation-tag',p['tag'],'--raw',paths['raw'],'--toolchain',paths['toolchain'],
        '--user-home',paths['user_home'],'--cargo-home',paths['cargo_home']]
    env=dict(HOME=paths['user_home'],PATH=paths['toolchain']+'/bin:/usr/bin:/bin',
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',
        LANG='C.UTF-8',LC_ALL='C.UTF-8',**p['session_env'])
    return argv,env


def execution_paths(p, env):
    # Allocator names and Rust's default linker use this exact PATH.
    # cc must resolve to the pinned gcc, not an earlier executable shadow.
    resolved={}
    for name,pinned in (('systemd-run','systemd-run'),('true','true'),('cc','gcc')):
        selected=shutil.which(name,path=env['PATH'])
        assert selected is not None
        actual=Path(selected).resolve(strict=True)
        assert actual==Path(p['tools'][pinned]['path'])
        resolved[name]=str(actual)
    return resolved


def disk_room(slot_bytes, limits):
    assert type(slot_bytes) is int and slot_bytes >= 0
    projected=slot_bytes+limits['evidence_bytes']+limits['build_reserve_bytes']+limits['wrapper_bytes']
    assert projected < limits['slot_limit_bytes']
    return projected


def closed_log(closed, reader):
    # This guard precedes even the first log read. No recipe files are read here.
    assert closed['cleanup_complete'] is True
    data=reader(); assert len(data) <= 8*MIB and pin(data)['sha256']==closed['private_log_sha256']
    return data


def allocator_return(data, closed, profile):
    assert closed['cleanup_complete'] is True and closed['termination'] is None
    assert type(closed['exit_code']) is int and closed['exit_code'] in (0,1)
    assert type(closed['reaped_descendants']) is int and closed['reaped_descendants']==0
    assert b'\r' not in data
    lines=data.decode('ascii').split('\n'); assert lines.pop()=='' and len(lines)==2
    assert all(len(line)<=65536 for line in lines)
    match=re.fullmatch(r'cpuset-alloc: run: reserved (\{.*\}); running whole tree pinned via AllowedCPUs=([0-9,]+)',lines[0])
    assert match
    assignment=json.loads(match[1]); assert set(assignment)=={'cores','count'}
    cores=assignment['cores']; assert type(cores) is list and len(cores)==len(set(cores))==profile['cpus']
    assert all(type(c) is int and 0 <= c < 1024 for c in cores)
    assert type(assignment['count']) is int and assignment['count']==len(cores)
    assert match[2]==','.join(map(str,sorted(cores)))
    summary=json.loads(lines[1]); assert type(summary) is dict
    assert summary['status']==(profile['terminal'] if closed['exit_code']==0 else 'FAILED')
    if closed['exit_code']==0: assert summary['custody_closed'] is True
    # A release exception adds diagnostics or changes the allocator exit. This
    # is the pinned context-manager return, not an independent ledger readback.
    return dict(status='SOURCE_JOINED_NORMAL_ALLOCATOR_RETURN',cores=cores,count=len(cores),
        recipe_exit=closed['exit_code'],recipe_summary=summary,ledger_readback=False)


def main():
    started=time.monotonic(); deadline=started+1200
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--protocol',type=Path,required=True); ap.add_argument('--sha256',required=True)
    a=ap.parse_args(); assert re.fullmatch('[0-9a-f]{64}',a.sha256)
    protocol_bytes=read(a.protocol,2*MIB); assert pin(protocol_bytes)['sha256']==a.sha256
    p=json.loads(protocol_bytes); assert protocol_bytes==canonical(p)
    profile=validate_protocol(p); paths={k:Path(v) for k,v in p['paths'].items()}
    # The scalar route keeps the same original start; no deadline renewal.
    if p['profile']=='leaf-whole-session': deadline=started+7200
    root=paths['root']; capture=paths['capture']; logs=paths['log_dir']; raw=paths['raw']
    assert a.protocol.is_absolute() and a.protocol.resolve(strict=True)==a.protocol
    launcher=Path(p['launcher']['path']); assert Path(__file__).resolve(strict=True)==launcher
    assert pin(read(launcher,MIB))=={k:v for k,v in p['launcher'].items() if k!='path'}
    for key,path in paths.items():
        check=path.parent if key in ('raw','capture','log_dir') else path
        assert check.resolve(strict=True)==check and check.is_dir()
    assert not any(os.path.lexists(x) for x in (raw,capture,logs,root/'target/evaluation'/raw.name))
    assert not a.protocol.is_relative_to(raw) and not a.protocol.is_relative_to(capture)
    argv,env=command_environment(p); os.chdir(root)
    capture.mkdir(mode=0o700)
    result=dict(status='FAILED',profile=p['profile'],qualification=profile,revision=p['revision'],attempts=0,
        selected_outcome='UNRUN',protocol_sha256=a.sha256,source_verified_after=False,
        reservation=dict(status='UNVERIFIED'),start_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        load_before=list(os.getloadavg()),outer_seconds=p['limits']['outer_seconds'],cleanup_seconds=3,
        scope='Invocation/closure record only; root must audit recipe results and qualification separately.')
    retained={}
    def remaining():
        value=deadline-time.monotonic(); assert value>0; return value
    def git(directory,*args):
        data=subprocess.check_output([p['tools']['git']['path'],'-C',directory,*args],env=env,timeout=min(15,remaining()))
        assert len(data)<=32*MIB; return data
    def authenticate():
        remaining()
        assert pin(read(a.protocol,2*MIB))==pin(protocol_bytes)
        assert pin(read(launcher,MIB))=={k:v for k,v in p['launcher'].items() if k!='path'}
        for name,value in p['tools'].items():
            path=Path(value['path']); assert path.resolve(strict=True)==path
            assert pin(read(path,512*MIB))=={k:v for k,v in value.items() if k!='path'}
            if name in ('cargo','rustc','rustdoc'): assert (paths['toolchain']/'bin'/name).resolve(strict=True)==path
            elif name=='python': assert Path(sys.executable).resolve(strict=True)==path
            else: assert Path('/usr/bin',name).resolve(strict=True)==path
        execution_paths(p,env)
        assert git(root,'rev-parse','--show-toplevel').decode().strip()==str(root)
        assert git(root,'rev-parse','HEAD').decode().strip()==p['revision']
        assert git(root,'status','--porcelain','--untracked-files=no')==b''
        names=git(root,'ls-files','-z','--','src','crates','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock',
            'README.md','build.rs','.cargo',':(glob)**/Cargo.toml',*COMMON,*EXTRA[p['profile']]).decode().rstrip('\0').split('\0')
        assert all(names) and len(names)==len(set(names)) and set(names)==set(p['source_pins'])
        for name,value in p['source_pins'].items():
            data=read(root/name,512*MIB); assert pin(data)==value and data==git(root,'show',p['revision']+':'+name)
        allocator=paths['allocator_root']; expected=p['allocator_sources']
        assert set(expected)=={str(x.relative_to(allocator)) for x in (allocator/'py/dagrun').rglob('*.py')}
        assert git(allocator,'rev-parse','HEAD').decode().strip()==p['allocator_revision']
        for name,digest in expected.items():
            data=read(allocator/name,MIB); assert pin(data)['sha256']==digest
            assert data==git(allocator,'show',p['allocator_revision']+':'+name)
        for name,value in retained.items(): assert pin(read(Path(name),8*MIB))==value
        remaining()
    try:
        retained[str(capture/'protocol.json')]=save(capture/'protocol.json',p,2*MIB)
        authenticate()
        observed=subprocess.check_output([p['tools']['du']['path'],'-sb','--',root],env=env,timeout=min(30,remaining()))
        size,name=observed.rstrip(b'\n').split(b'\t'); assert name.decode()==str(root) and re.fullmatch(rb'0|[1-9][0-9]*',size)
        result['disk']=dict(slot_bytes=int(size),projected_bytes=disk_room(int(size),p['limits']),
            **{k:v for k,v in p['limits'].items() if k not in ('outer_seconds','outer_log_bytes')},
            scope='Prospective allowance, not a filesystem quota or free-space guarantee.')
        logs.mkdir(mode=0o700); log=logs/'outer.log'; assert not os.path.lexists(log)
        retained[str(capture/'request.json')]=save(capture/'request.json',dict(command=argv,env=env,cwd=str(root),
            tag=p['tag'],profile=p['profile'],limits=p['limits'],protocol_sha256=a.sha256,attempts=1,retries=0))
        assert pin(read(root/OWNER,MIB))==p['source_pins'][OWNER]
        spec=importlib.util.spec_from_file_location('_leaf_qualification_owner',root/OWNER); assert spec and spec.loader
        owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner); assert owner.ROOT==root
        result['allocator_execution_paths']=execution_paths(p,env)
        timeout=remaining(); result.update(attempts=1,selected_outcome='FAILED',owner_timeout_seconds=timeout)
        closed=owner.run_command(argv,env,log,timeout,8*MIB)
        result['closed']=closed
        retained[str(capture/'closed.json')]=save(capture/'closed.json',closed)
        data=closed_log(closed,lambda:read(log,8*MIB))
        retained[str(log)]=pin(data)
        with (capture/'outer.log').open('xb') as stream: stream.write(data)
        retained[str(capture/'outer.log')]=pin(data)
        result['reservation']=allocator_return(data,closed,profile)
        authenticate(); result['source_verified_after']=True
        result.update(status='CLOSED_EXIT_'+str(closed['exit_code'])+'_RECIPE_AUDIT_REQUIRED',
            selected_outcome='CLOSED_EXIT_'+str(closed['exit_code']))
    except BaseException as error:
        result['error']=type(error).__name__
    finally:
        result.update(end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),load_after=list(os.getloadavg()),
            elapsed_seconds=time.monotonic()-started,retained=retained)
        if not result['source_verified_after'] and result['reservation']['status']!='UNVERIFIED':
            result['reservation']['authority']='UNQUALIFIED_SOURCE_JOIN_FAILED'
        save(capture/'result.json',result)
    print(json.dumps(dict(status=result['status'],profile=p['profile'],attempts=result['attempts'],
        selected_outcome=result['selected_outcome'],qualification_audit_required=True)))
    return 0 if result['status']=='CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED' else 1


if __name__=='__main__':
    raise SystemExit(main())
