#!/usr/bin/env python3
"""Freeze one CallPair session protocol; no native or campaign acceptance."""
import sys
if sys.flags.optimize or not sys.flags.isolated:
    raise SystemExit('use Python -I -B with assertions enabled')
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import types

PUBLIC = 'evaluation/ordinary-call-pair-session/'
NATIVE_PUBLIC = 'evaluation/ordinary-call-pair-native/'
LAUNCHER_SHA = '1bdfcbc55340843fd7c11293234a9e1f72d9148f2ee5d1d5f1fecc4fa0359f46'
NATIVE_LAUNCHER_SHA = '5665c1dd0b98ff0884fd3132ed807b33e814463d226158f532ea4605ea90b7e5'
NATIVE_FREEZER_SHA = 'd5988152be6b826d368f43723afd16b411e36cb1d02e3e11530349405390484f'
OWNER = 'evaluation/admission/processes.py'
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
MIB = 1048576


def bootstrap_read(path, cap):
    identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert path.resolve(strict=True)==path
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        before=os.fstat(f.fileno());assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data=f.read(cap+1)
        assert len(data)==before.st_size and identity(before)==identity(os.fstat(f.fileno()))==identity(path.lstat())
        return data


def path_value(value):
    assert type(value) is str and value and '\0' not in value and '\n' not in value and '\r' not in value
    p=Path(value);assert p.is_absolute() and str(p)==value and '..' not in p.parts
    assert p.resolve(strict=True)==p and p.is_dir()
    return p


def module(name,path,data):
    m=types.ModuleType(name);m.__file__=str(path)
    exec(compile(data,str(path),'exec'),m.__dict__)
    return m


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('revision','toolchain','cargo-home','user-home','allocator-root','hardware-label',
                 'native-protocol','native-protocol-sha256','native-receipt','native-receipt-sha256'):
        ap.add_argument('--'+name,required=True)
    ap.add_argument('--xdg-runtime-dir');ap.add_argument('--dbus-session-bus-address');a=ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}',a.revision)
    for value in (a.native_protocol_sha256,a.native_receipt_sha256):assert re.fullmatch('[0-9a-f]{64}',value)
    script=Path(__file__).absolute();assert script.resolve(strict=True)==script;root=script.parents[2]
    assert script==root/PUBLIC/'freeze.py'
    paths={key:path_value(getattr(a,key)) for key in ('toolchain','cargo_home','user_home','allocator_root')}
    # This sanitized bootstrap environment is explicit before the first Git call.
    env=dict(HOME=str(paths['user_home']),PATH=str(paths['toolchain'])+'/bin:/usr/bin:/bin',
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',
        LANG='C.UTF-8',LC_ALL='C.UTF-8')
    first={}
    def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    def held(path,cap):
        data=bootstrap_read(path,cap);key=str(path);value=pin(data)
        if key in first:assert first[key]==value
        else:first[key]=value
        return data
    git_path=Path('/usr/bin/git').resolve(strict=True);assert os.access(git_path,os.X_OK);held(git_path,512*MIB)
    def git(directory,*args):
        assert pin(bootstrap_read(git_path,512*MIB))==first[str(git_path)]
        data=subprocess.check_output([str(git_path),'-C',str(directory),*args],env=env,timeout=15)
        assert len(data)<=32*MIB;return data
    def clean():
        assert git(root,'rev-parse','--show-toplevel').decode().strip()==str(root)
        assert git(root,'rev-parse','HEAD').decode().strip()==a.revision
        assert git(root,'status','--porcelain','--untracked-files=no')==b''
    clean();bootstrap={}
    names=(PUBLIC+'freeze.py',PUBLIC+'launch.py',PUBLIC+'ROOT_PROTOCOL.md',
           NATIVE_PUBLIC+'freeze.py',NATIVE_PUBLIC+'launch.py',NATIVE_PUBLIC+'ROOT_PROTOCOL.md',OWNER)
    for name in names:
        data=held(root/name,MIB);assert data==git(root,'show',a.revision+':'+name);bootstrap[name]=data
    for name,digest in ((PUBLIC+'launch.py',LAUNCHER_SHA),(NATIVE_PUBLIC+'launch.py',NATIVE_LAUNCHER_SHA),
                        (NATIVE_PUBLIC+'freeze.py',NATIVE_FREEZER_SHA),(OWNER,OWNER_SHA)):
        assert pin(bootstrap[name])['sha256']==digest
    F=module('_call_pair_public_freeze_helpers',root/NATIVE_PUBLIC/'freeze.py',bootstrap[NATIVE_PUBLIC+'freeze.py'])
    L=module('_call_pair_session_protocol',root/PUBLIC/'launch.py',bootstrap[PUBLIC+'launch.py'])
    assert L.NATIVE_SHA==NATIVE_LAUNCHER_SHA and L.N.OWNER_SHA==OWNER_SHA
    session_env=F.session_values(a.xdg_runtime_dir,a.dbus_session_bus_address)
    env.update(session_env)
    tools={}
    for name in L.N.TOOLS:
        q=(Path(sys.executable) if name=='python' else paths['toolchain']/'bin'/name
           if name in ('cargo','rustc','rustdoc') else Path('/usr/bin')/name).resolve(strict=True)
        assert os.access(q,os.X_OK);tools[name]=dict(path=str(q),**pin(held(q,512*MIB)))
    sources={}
    for name in L.source_names(root,git):
        data=held(root/name,512*MIB);assert data==git(root,'show',a.revision+':'+name);sources[name]=pin(data)
    allocator=paths['allocator_root']
    def allocator_check():
        assert git(allocator,'rev-parse','HEAD').decode().strip()==F.ALLOCATOR_REVISION
        assert git(allocator,'status','--porcelain','--untracked-files=no')==b''
        assert {str(q.relative_to(allocator)) for q in (allocator/'py/dagrun').rglob('*.py')}==set(F.ALLOCATOR_SOURCES)
        for name,digest in F.ALLOCATOR_SOURCES.items():
            data=held(allocator/name,MIB)
            assert pin(data)['sha256']==digest and data==git(allocator,'show',F.ALLOCATOR_REVISION+':'+name)
    allocator_check()
    native={}
    for key,cap in (('protocol',2*MIB),('receipt',16384)):
        q=Path(getattr(a,'native_'+key));data=held(q,cap)
        expected=getattr(a,'native_'+key+'_sha256');assert pin(data)['sha256']==expected
        native[key]=dict(path=str(q),**pin(data))
    compat=root/'ignored/a5/normal-call-pair-launch-source-v1/launch.py'
    assert held(compat,MIB)==bootstrap[NATIVE_PUBLIC+'launch.py']
    for parent in (root/'ignored',root/'ignored/a5',root/'target',root/'target/evaluation'):
        if not os.path.lexists(parent):parent.mkdir(mode=0o700)
        assert parent.resolve(strict=True)==parent and parent.is_dir()
    destination=root/'ignored/a5'/('call-pair-session-public-'+a.revision)
    raw=destination/('call-pair-session-'+a.revision);capture=destination/'owner'
    logs=root/'target/evaluation'/('call-pair-session-owner-'+a.revision);inner_logs=root/'target/evaluation'/raw.name
    F.absent((destination,raw,capture,logs,inner_logs))
    p=dict(CLOSED=True,execution='UNRUN',version=1,profile=L.PROFILE,qualification=dict(L.QUALIFICATION),
        revision=a.revision,tag='call-pair-session-'+a.revision,hardware_label=a.hardware_label,
        paths=dict(root=str(root),raw=str(raw),capture=str(capture),log_dir=str(logs),**{k:str(v) for k,v in paths.items()}),
        launcher=dict(path=str(root/PUBLIC/'launch.py'),**pin(bootstrap[PUBLIC+'launch.py'])),source_pins=sources,tools=tools,
        allocator_revision=F.ALLOCATOR_REVISION,allocator_sources=dict(F.ALLOCATOR_SOURCES),session_env=session_env,
        limits=dict(L.LIMITS),native=native)
    L.validate_protocol(p);argv,selected_env=L.command_environment(p);assert selected_env==env
    resolved=L.execution_paths(p,env)
    def native_check():
        np=L.native_inputs(p,held)
        native_names=git(root,'ls-files','-z','--','src','crates','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock',
            'README.md','build.rs','.cargo',':(glob)**/Cargo.toml',*L.N.COMMON,*L.N.EXTRA['call-pair-original-native']).decode().rstrip('\0').split('\0')
        assert all(native_names) and len(native_names)==len(set(native_names)) and set(native_names)==set(np['source_pins'])
    native_check()
    destination.mkdir(mode=0o700)
    def save(name,value,cap):
        data=F.canonical(value);assert len(data)<=cap;q=destination/name
        with q.open('xb') as f:f.write(data)
        assert held(q,cap)==data
        return dict(path=str(q),**pin(data))
    save('freeze-attempt.json',dict(status='FAILED_UNLESS_SOURCE_FROZEN_MARKER',execution='UNRUN',revision=a.revision,attempts=1,retries=0),MIB)
    try:
        protocol_pin=save('protocol.json',p,2*MIB)
        clean();assert L.source_names(root,git)==sorted(sources)
        for name,value in sources.items():
            data=held(root/name,512*MIB);assert pin(data)==value and data==git(root,'show',a.revision+':'+name)
        for name,data in bootstrap.items():assert held(root/name,MIB)==data==git(root,'show',a.revision+':'+name)
        for name,value in tools.items():
            q=Path(value['path']);assert os.access(q,os.X_OK) and pin(held(q,512*MIB))=={k:v for k,v in value.items() if k!='path'}
            selected=(Path(sys.executable) if name=='python' else paths['toolchain']/'bin'/name
                      if name in ('cargo','rustc','rustdoc') else Path('/usr/bin')/name)
            assert selected.resolve(strict=True)==q
        allocator_check();native_check()
        assert F.session_values(a.xdg_runtime_dir,a.dbus_session_bus_address)==session_env
        assert L.execution_paths(p,env)==resolved;L.validate_protocol(p);F.absent((raw,capture,logs,inner_logs))
        for name,value in first.items():assert pin(bootstrap_read(Path(name),max(MIB,value['bytes'])))==value
        clean()
        marker=save('source-frozen.json',dict(status='SOURCE_FROZEN_UNRUN',execution='UNRUN',revision=a.revision,
            profile=L.PROFILE,protocol=protocol_pin,launcher=p['launcher'],native=native,hardware_label=a.hardware_label,
            command=argv,environment=env,first_pins=first.copy(),source_count=len(sources),tools=13,allocator_sources=31,
            allocator_execution_paths=resolved,qualification_attempts=0,
            scope='Source/prerequisite pin freeze only; no native acceptance, reservation, campaign execution or result audit.'),2*MIB)
    except BaseException as error:
        save('freeze-failure.json',dict(status='FAILED',execution='UNRUN',revision=a.revision,
            error=type(error).__name__,first_pins=first.copy()),2*MIB)
        raise
    print(json.dumps(dict(status='SOURCE_FROZEN_UNRUN',protocol=protocol_pin,marker=marker)))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
