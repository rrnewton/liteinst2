#!/usr/bin/env python3
"""One bounded CallPair session invocation; recipe/native acceptance stays separate."""
import sys
if sys.flags.optimize or not sys.flags.isolated:
    raise SystemExit('use Python -I -B with assertions enabled')
sys.dont_write_bytecode = True
import time
STARTED = time.monotonic()
import argparse
import ast
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import types

ROOT = Path(__file__).resolve().parents[2]
MIB = 1048576
NATIVE_OWNER = 'evaluation/ordinary-call-pair-native/launch.py'
NATIVE_SHA = '5665c1dd0b98ff0884fd3132ed807b33e814463d226158f532ea4605ea90b7e5'
NATIVE_FREEZER = 'evaluation/ordinary-call-pair-native/freeze.py'
NATIVE_FREEZER_SHA = 'd5988152be6b826d368f43723afd16b411e36cb1d02e3e11530349405390484f'
CAMPAIGN = 'evaluation/ordinary-call-pair-session/reproduce.py'
CAMPAIGN_SHA = '00dc82bc29b00c158f68a9a0f6fe3ed2167758835b7327d49ba12fe502ed742e'
RECIPE = 'evaluation/ordinary-module-session/reproduce.py'
RECIPE_SHA = '4389493950775ca1c494bf7e28ff8326cbd61d2fbbda0ef53af953a4ff24f659'
ALLOCATOR_REVISION = 'd0c2867be75b495eb64239e664c6306af9747783'
PROFILE = 'call-pair-session-qualification-v1'
PASS = 'CALL_PAIR_SESSION_FUNCTIONAL_PASS'
QUALIFICATION = dict(cpus=3, stages=395, references=32, malformed=8, installed=320,
    qualifications=5, k_order=[10,1000], case_count=32, epochs=520, banks=3,
    arm_ns=2000000, period_ns=10000000, shutdown_ns=2000000000,
    recipe=CAMPAIGN, terminal=PASS, native_pairs=192)
LIMITS = dict(outer_seconds=7200, outer_log_bytes=8*MIB, evidence_bytes=2*1024**3,
    build_reserve_bytes=1024**3, wrapper_bytes=24*MIB, slot_limit_bytes=20000000000)


def _bootstrap_read(path, cap):
    identity = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    assert path.resolve(strict=True) == path
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
        before=os.fstat(f.fileno());assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data=f.read(cap+1)
        assert len(data)==before.st_size and identity(before)==identity(os.fstat(f.fileno()))==identity(path.lstat())
        return data


def module(name, path, data):
    m=types.ModuleType(name);m.__file__=str(path)
    exec(compile(data,str(path),'exec'),m.__dict__)
    return m


# Authenticate exact shared bytes before compilation. No shared main or globals
# are changed; only domain-independent helpers and the native validator are used.
_NATIVE_BYTES=_bootstrap_read(ROOT/NATIVE_OWNER,MIB)
assert hashlib.sha256(_NATIVE_BYTES).hexdigest()==NATIVE_SHA
N=module('_call_pair_session_shared_owner',ROOT/NATIVE_OWNER,_NATIVE_BYTES)
_FREEZER_BYTES=_bootstrap_read(ROOT/NATIVE_FREEZER,MIB)
assert hashlib.sha256(_FREEZER_BYTES).hexdigest()==NATIVE_FREEZER_SHA
F=module('_call_pair_session_freeze_helpers',ROOT/NATIVE_FREEZER,_FREEZER_BYTES)
canonical,pin,read,save=N.canonical,N.pin,N.read,N.save
execution_paths,disk_room,closed_log=N.execution_paths,N.disk_room,N.closed_log


def json_value(data):
    def pairs(items):
        value={}
        for key,item in items:
            assert key not in value
            value[key]=item
        return value
    def invalid(value):raise AssertionError('nonfinite JSON')
    return json.loads(data.decode('ascii'),object_pairs_hook=pairs,parse_constant=invalid)


def shape(value, file=False):
    assert type(value) is dict and set(value)==({'path','bytes','sha256'} if file else {'bytes','sha256'})
    assert type(value['bytes']) is int and 0 <= value['bytes'] <= 512*MIB
    assert type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256'])
    if file:
        v=value['path'];assert type(v) is str and '\0' not in v
        q=Path(v);assert q.is_absolute() and str(q)==v and '..' not in q.parts
    return {k:value[k] for k in ('bytes','sha256')}


def validate_protocol(p):
    assert set(p)=={'CLOSED','execution','version','profile','qualification','revision','tag','paths','launcher',
        'source_pins','tools','allocator_revision','allocator_sources','session_env','limits','native','hardware_label'}
    assert p['CLOSED'] is True and p['execution']=='UNRUN' and type(p['version']) is int and p['version']==1
    assert p['profile']==PROFILE and canonical(p['qualification'])==canonical(QUALIFICATION)
    assert canonical(p['limits'])==canonical(LIMITS)
    assert re.fullmatch('[0-9a-f]{40}',p['revision']) and p['allocator_revision']==ALLOCATOR_REVISION
    assert re.fullmatch('[a-z0-9-]{1,128}',p['tag'])
    assert type(p['hardware_label']) is str and re.fullmatch(r'[\x20-\x7e]{1,128}',p['hardware_label'])
    paths=p['paths'];assert set(paths)=={'root','raw','capture','log_dir','toolchain','user_home','cargo_home','allocator_root'}
    for value in paths.values():
        assert type(value) is str and '\0' not in value
        q=Path(value);assert q.is_absolute() and str(q)==value and '..' not in q.parts
    root=Path(paths['root']);raw=Path(paths['raw']);capture=Path(paths['capture']);logs=Path(paths['log_dir'])
    assert all(q.is_relative_to(root/'ignored') and q!=root/'ignored' for q in (raw,capture))
    assert not raw.is_relative_to(capture) and not capture.is_relative_to(raw)
    assert logs.parent==root/'target/evaluation' and raw.name!=logs.name
    assert all(re.fullmatch('[A-Za-z0-9_.-]+',q.name) for q in (raw,logs))
    shape(p['launcher'],True);assert set(p['tools'])==set(N.TOOLS)
    for value in p['tools'].values():shape(value,True)
    assert p['source_pins']
    for name,value in p['source_pins'].items():
        q=Path(name);assert not q.is_absolute() and str(q)==name and '..' not in q.parts;shape(value)
    assert p['source_pins'][N.OWNER]['sha256']==N.OWNER_SHA
    assert p['source_pins'][NATIVE_OWNER]['sha256']==NATIVE_SHA
    assert p['source_pins'][CAMPAIGN]['sha256']==CAMPAIGN_SHA
    assert pin(canonical(p['allocator_sources']))['sha256']==N.ALLOCATOR_MAP_SHA
    assert set(p['session_env']) <= {'XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS'}
    assert all(type(v) is str and v and '\0' not in v for v in p['session_env'].values())
    assert set(p['native'])=={'protocol','receipt'}
    for v in p['native'].values():
        shape(v,True);q=Path(v['path'])
        assert q.is_relative_to(root/'ignored') and not any(q.is_relative_to(x) for x in (raw,capture,logs))
    assert p['native']['protocol']['path']!=p['native']['receipt']['path']
    return QUALIFICATION


def command_environment(p):
    validate_protocol(p);paths=p['paths'];python=p['tools']['python']['path']
    argv=[python,'-B',str(Path(paths['allocator_root'])/'py/dagrun/cpuset_allocator.py'),
        'run','--cores','3','--sample-s','1','--tag',p['tag'],'--',python,'-B',str(Path(paths['root'])/CAMPAIGN),
        '--revision',p['revision'],'--reservation-tag',p['tag'],'--raw',paths['raw'],
        '--toolchain',paths['toolchain'],'--user-home',paths['user_home'],'--cargo-home',paths['cargo_home'],
        '--native-receipt',p['native']['receipt']['path'],'--native-receipt-sha256',p['native']['receipt']['sha256'],
        '--native-protocol',p['native']['protocol']['path'],'--native-protocol-sha256',p['native']['protocol']['sha256']]
    env=dict(HOME=paths['user_home'],PATH=paths['toolchain']+'/bin:/usr/bin:/bin',
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',
        LANG='C.UTF-8',LC_ALL='C.UTF-8',**p['session_env'])
    return argv,env


def literal_assignment(data, name):
    values=[n.value for n in ast.parse(data).body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
    assert len(values)==1
    return ast.literal_eval(values[0])


def source_names(root, git):
    # Mirror the authenticated campaign's source inventory, then add these
    # public owner sources and the exact public native bootstrap sources.
    campaign=read(root/CAMPAIGN,MIB);recipe=read(root/RECIPE,MIB)
    assert pin(campaign)['sha256']==CAMPAIGN_SHA and pin(recipe)['sha256']==RECIPE_SHA
    required=set(literal_assignment(campaign,'REQUIRED_NATIVE'))|set(literal_assignment(campaign,'HELPER_PINS'))
    required.update(N.COMMON+N.EXTRA['call-pair-original-native'])
    required.update(literal_assignment(recipe,'MODULES').values())
    required.update(('evaluation/ordinary-leaf-set-session/reproduce.py','evaluation/ordinary-call-pair-native/reproduce.py',
        'evaluation/ordinary-module-session/owners.py'))
    required.update('evaluation/ordinary-call-pair-session/'+n for n in ('native_receipt.py','profile.py','output.py',
        'original_output.py','reproduce.py','runner_controls.py','README.md','produce.py','producer_controls.py',
        'receipt_controls.py','controls.py','original.c','original_controls.c','original_controls.py',
        'launch.py','freeze.py','ROOT_PROTOCOL.md'))
    required.update('evaluation/ordinary-call-pair-native/'+n for n in ('launch.py','freeze.py','ROOT_PROTOCOL.md'))
    for directory in ('evaluation/ordinary-module-session','evaluation/ordinary-leaf-set-session','evaluation/ordinary-leaf-set-whole-session'):
        names=git(root,'ls-files','-z','--',directory).decode().rstrip('\0').split('\0')
        required.update(n for n in names if n.endswith(('.py','.c','.S','.md')))
    data=git(root,'ls-files','-z','--','src','crates','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock',
        'README.md','build.rs','.cargo',':(glob)**/Cargo.toml',*sorted(required))
    assert data.endswith(b'\0');names=data[:-1].decode().split('\0')
    assert all(names) and len(names)==len(set(names)) and required <= set(names)
    return sorted(names)


def native_inputs(p, reader):
    # Freeze structural/current-source joins only. Never read the named result
    # files here and never turn a root manifest into native acceptance.
    data={}
    for key,cap in (('protocol',2*MIB),('receipt',16384)):
        expected=p['native'][key];path=Path(expected['path'])
        assert path.resolve(strict=True)==path
        data[key]=reader(path,cap)
        assert pin(data[key])==shape(expected,True)
    np=json_value(data['protocol']);manifest=json_value(data['receipt'])
    assert data['protocol']==canonical(np) and data['receipt']==canonical(manifest)
    N.validate_protocol(np)
    assert np['profile']=='call-pair-original-native' and np['revision']==p['revision']
    assert np['launcher']['sha256']==NATIVE_SHA
    native_launcher=Path(np['launcher']['path']);assert native_launcher.resolve(strict=True)==native_launcher
    assert pin(reader(native_launcher,MIB))==shape(np['launcher'],True)
    assert np['allocator_revision']==p['allocator_revision'] and np['allocator_sources']==p['allocator_sources']
    assert np['tools']==p['tools']
    for key in ('root','toolchain','cargo_home','user_home','allocator_root'):assert np['paths'][key]==p['paths'][key]
    for name,value in np['source_pins'].items():assert p['source_pins'][name]==value
    assert set(manifest)=={'schema','version','revision','profile','protocol','launcher_result','recipe_result'}
    assert manifest['schema']=='call-pair-native-prerequisite-v1' and type(manifest['version']) is int and manifest['version']==1
    assert manifest['revision']==p['revision'] and manifest['profile']=='normal-call-pair-original-rust-v1'
    assert manifest['protocol']==p['native']['protocol']
    for key,directory in (('launcher_result','capture'),('recipe_result','raw')):
        shape(manifest[key],True)
        assert manifest[key]['path']==str(Path(np['paths'][directory])/'result.json')
    return np


def allocator_return(data, closed):
    assert closed['cleanup_complete'] is True and closed['termination'] is None
    assert type(closed['exit_code']) is int and closed['exit_code'] in (0,1)
    assert type(closed['reaped_descendants']) is int and closed['reaped_descendants']==0
    assert b'\r' not in data
    lines=data.decode('ascii').split('\n');assert lines.pop()=='' and len(lines)==2
    assert all(len(line)<=65536 for line in lines)
    m=re.fullmatch(r'cpuset-alloc: run: reserved (\{.*\}); running whole tree pinned via AllowedCPUs=([0-9,]+)',lines[0]);assert m
    assignment=json_value(m[1].encode('ascii'));assert set(assignment)=={'cores','count'}
    cores=assignment['cores'];assert type(cores) is list and len(cores)==len(set(cores))==3
    assert all(type(c) is int and 0 <= c < 1024 for c in cores)
    assert type(assignment['count']) is int and assignment['count']==3
    ordered=sorted(cores);assert m[2]==','.join(map(str,ordered))
    summary=json_value(lines[1].encode('ascii'))
    assert set(summary)=={'profile','status','summary_sha256','outcomes_sha256'}
    assert summary['profile']==PROFILE and summary['status'] in (PASS,'FAILED')
    for key in ('summary_sha256','outcomes_sha256'):assert type(summary[key]) is str and re.fullmatch('[0-9a-f]{64}',summary[key])
    if closed['exit_code']==0:assert summary['status']==PASS
    # A late final campaign deadline can print PASS then return1. The actual
    # exit remains authoritative: every exit1 is retained as a failed invocation.
    return dict(status='SOURCE_JOINED_NORMAL_ALLOCATOR_RETURN',cores=cores,count=3,
        cpu_roles=dict(controller=ordered[0],worker=ordered[1],producer=ordered[2]),
        recipe_exit=closed['exit_code'],recipe_summary=summary,ledger_readback=False)


def main():
    deadline=STARTED+7200
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--protocol',type=Path,required=True);ap.add_argument('--sha256',required=True)
    a=ap.parse_args();assert re.fullmatch('[0-9a-f]{64}',a.sha256)
    protocol_bytes=read(a.protocol,2*MIB);assert pin(protocol_bytes)['sha256']==a.sha256
    p=json_value(protocol_bytes);assert protocol_bytes==canonical(p);validate_protocol(p)
    paths={k:Path(v) for k,v in p['paths'].items()};root=paths['root'];capture=paths['capture'];logs=paths['log_dir'];raw=paths['raw']
    assert root==ROOT and a.protocol.is_absolute() and a.protocol.resolve(strict=True)==a.protocol
    launcher=Path(p['launcher']['path']);assert Path(__file__).resolve(strict=True)==launcher
    assert pin(read(launcher,MIB))==shape(p['launcher'],True)
    for key,path in paths.items():
        check=path.parent if key in ('raw','capture','log_dir') else path
        assert check.resolve(strict=True)==check and check.is_dir()
    assert not any(os.path.lexists(x) for x in (raw,capture,logs,root/'target/evaluation'/raw.name))
    assert not any(a.protocol.is_relative_to(x) for x in (raw,capture))
    argv,env=command_environment(p);os.chdir(root);capture.mkdir(mode=0o700)
    result=dict(status='FAILED',profile=PROFILE,qualification=QUALIFICATION,revision=p['revision'],attempts=0,
        selected_outcome='UNRUN',protocol_sha256=a.sha256,source_verified_after=False,reservation=dict(status='UNVERIFIED'),
        hardware_label=p['hardware_label'],hardware_authority='operator supplied',start_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
        load_before=list(os.getloadavg()),outer_seconds=7200,cleanup_seconds=3,
        scope='Invocation/closure only; root must audit recipe custody, retention, native prerequisite and all campaign outcomes.')
    retained={}
    def remaining():
        value=deadline-time.monotonic();assert value>0;return value
    def git(directory,*args):
        value=subprocess.check_output([p['tools']['git']['path'],'-C',directory,*args],env=env,timeout=min(15,remaining()))
        assert len(value)<=32*MIB;return value
    def first(path,data):
        value=pin(data);key=str(path)
        if key in retained:assert retained[key]==value
        else:retained[key]=value
        return data
    def authenticate():
        remaining();assert pin(read(a.protocol,2*MIB))==pin(protocol_bytes)
        assert pin(read(launcher,MIB))==shape(p['launcher'],True)
        assert read(root/NATIVE_OWNER,MIB)==_NATIVE_BYTES and read(root/NATIVE_FREEZER,MIB)==_FREEZER_BYTES
        assert F.session_values(p['session_env'].get('XDG_RUNTIME_DIR'),p['session_env'].get('DBUS_SESSION_BUS_ADDRESS'))==p['session_env']
        for name,value in p['tools'].items():
            path=Path(value['path']);assert path.resolve(strict=True)==path
            assert pin(read(path,512*MIB))==shape(value,True)
            selected=(paths['toolchain']/'bin'/name if name in ('cargo','rustc','rustdoc') else Path(sys.executable)
                      if name=='python' else Path('/usr/bin')/name)
            assert selected.resolve(strict=True)==path
        execution_paths(p,env)
        assert git(root,'rev-parse','--show-toplevel').decode().strip()==str(root)
        assert git(root,'rev-parse','HEAD').decode().strip()==p['revision']
        assert git(root,'status','--porcelain','--untracked-files=no')==b''
        assert set(source_names(root,git))==set(p['source_pins'])
        for name,value in p['source_pins'].items():
            data=read(root/name,512*MIB);assert pin(data)==value and data==git(root,'show',p['revision']+':'+name)
        allocator=paths['allocator_root'];expected=p['allocator_sources']
        assert set(expected)=={str(q.relative_to(allocator)) for q in (allocator/'py/dagrun').rglob('*.py')}
        assert git(allocator,'rev-parse','HEAD').decode().strip()==p['allocator_revision']
        assert git(allocator,'status','--porcelain','--untracked-files=no')==b''
        for name,digest in expected.items():
            data=read(allocator/name,MIB);assert pin(data)['sha256']==digest and data==git(allocator,'show',p['allocator_revision']+':'+name)
        np=native_inputs(p,lambda path,cap:first(path,read(path,cap)))
        native_names=git(root,'ls-files','-z','--','src','crates','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock',
            'README.md','build.rs','.cargo',':(glob)**/Cargo.toml',*N.COMMON,*N.EXTRA['call-pair-original-native']).decode().rstrip('\0').split('\0')
        assert all(native_names) and len(native_names)==len(set(native_names)) and set(native_names)==set(np['source_pins'])
        for name,value in retained.items():
            path=Path(name);assert path.resolve(strict=True)==path
            assert pin(read(path,max(8*MIB,value['bytes'])))==value
        remaining()
    try:
        retained[str(capture/'protocol.json')]=save(capture/'protocol.json',p,2*MIB)
        authenticate()
        observed=subprocess.check_output([p['tools']['du']['path'],'-sb','--',root],env=env,timeout=min(30,remaining()))
        size,name=observed.rstrip(b'\n').split(b'\t');assert name.decode()==str(root) and re.fullmatch(rb'0|[1-9][0-9]*',size)
        result['disk']=dict(slot_bytes=int(size),projected_bytes=disk_room(int(size),p['limits']),
            **{k:v for k,v in p['limits'].items() if k not in ('outer_seconds','outer_log_bytes')},scope='Prospective allowance, not a quota.')
        logs.mkdir(mode=0o700);log=logs/'outer.log';assert not os.path.lexists(log)
        retained[str(capture/'request.json')]=save(capture/'request.json',dict(command=argv,env=env,cwd=str(root),
            tag=p['tag'],profile=PROFILE,limits=p['limits'],native=p['native'],protocol_sha256=a.sha256,attempts=1,retries=0))
        held=read(root/N.OWNER,MIB);assert pin(held)==p['source_pins'][N.OWNER]
        owner=module('_call_pair_session_process_owner',root/N.OWNER,held);assert owner.ROOT==root
        result['allocator_execution_paths']=execution_paths(p,env)
        timeout=remaining();result.update(attempts=1,selected_outcome='FAILED',owner_timeout_seconds=timeout)
        closed=owner.run_command(argv,env,log,timeout,8*MIB);result['closed']=closed
        retained[str(capture/'closed.json')]=save(capture/'closed.json',closed)
        data=closed_log(closed,lambda:read(log,8*MIB));retained[str(log)]=pin(data)
        with (capture/'outer.log').open('xb') as stream:stream.write(data)
        retained[str(capture/'outer.log')]=pin(data)
        result['reservation']=allocator_return(data,closed)
        authenticate();result['source_verified_after']=True
        result.update(status='CLOSED_EXIT_'+str(closed['exit_code'])+'_RECIPE_AUDIT_REQUIRED',selected_outcome='CLOSED_EXIT_'+str(closed['exit_code']))
    except BaseException as error:result['error']=type(error).__name__
    finally:
        result.update(end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),load_after=list(os.getloadavg()),
            elapsed_seconds=time.monotonic()-STARTED,retained=retained)
        if not result['source_verified_after'] and result['reservation']['status']!='UNVERIFIED':result['reservation']['authority']='UNQUALIFIED_SOURCE_JOIN_FAILED'
        save(capture/'result.json',result)
    print(json.dumps(dict(status=result['status'],profile=PROFILE,attempts=result['attempts'],
        selected_outcome=result['selected_outcome'],qualification_audit_required=True)))
    return 0 if result['status']=='CLOSED_EXIT_0_RECIPE_AUDIT_REQUIRED' and time.monotonic()<deadline else 1


if __name__=='__main__':
    raise SystemExit(main())
