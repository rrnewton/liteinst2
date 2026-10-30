#!/usr/bin/env python3
"""Pinned unsafe final-checker caller, observer build/transport and N01 entrypoint.

No import dispatches. The external final profile SHA and explicitly accepted
contract select reviewed code/obligations; a sealed memfd authenticates neither.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import types

MIB=1048576
NATIVE='evaluation/offline-router-native/'
CRATE='evaluation/adjacent-b2/artifact-verifier/'
PROGRAMS=('checksum','rle-roundtrip')
CONTROLS=('request.json','command.json','parent-closed.json','receipt.json','stdout.txt','stderr.txt','helper.stdout','helper.stderr')
OBSERVER=('Cargo.toml','Cargo.lock','src/lib.rs','src/main.rs','src/tests.rs','src/wire.rs')
RELEASE=dict(opt_level='3',debuginfo=0,debug_assertions=True,overflow_checks=True,test=False)


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def decode(raw,cap=MIB):
    need(type(raw) is bytes and len(raw)<=cap,'bounded JSON control')
    def pairs(rows):
        out={}
        for k,v in rows:
            need(k not in out,'duplicate control key');out[k]=v
        return out
    def constant(_):raise ValueError('nonfinite JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)


def stamp(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(path,cap=MIB):
    """All-component no-follow bounded read, including bootstrap source reads."""
    path=Path(path)
    need(path.is_absolute() and str(path)==os.path.normpath(str(path)),'canonical absolute input')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_size<=cap,'bounded regular file')
            raw=bytearray()
            while len(raw)<before.st_size:
                part=os.read(fd,min(65536,before.st_size-len(raw)));need(part,'short read');raw.extend(part)
            need(not os.read(fd,1) and stamp(before)==stamp(os.fstat(fd))==stamp(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
                 'stable full file read')
            return bytes(raw),dict(path=str(path),bytes=len(raw),sha256=sha(raw),stat=stamp(before))
        finally:os.close(fd)
    finally:os.close(parent)


def write(path,value,mode=0o600):
    raw=value if type(value) is bytes else (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            need(stream.write(raw)==len(raw),'whole owned output');stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    return read(path,max(MIB,len(raw)))[1]


def source(root,relative,wanted):
    need(relative.startswith(NATIVE) or relative.startswith(CRATE),'source scope')
    raw,_=read(root/relative,2*MIB);need(sha(raw)==wanted,'externally pinned source')
    module=types.ModuleType('_native_'+Path(relative).stem);module.__file__=str(root/relative)
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


def open_session(root,profile_path,profile_sha256,accept_contract_sha256,accept_kernel_basis_sha256=None):
    raw,_=read(profile_path);need(sha(raw)==profile_sha256,'external final profile digest')
    profile=decode(raw);pins=profile['native_sources']
    need(sha(read(root/NATIVE/'native_launch.py')[0])==pins[NATIVE+'native_launch.py'],'actual checked launcher source')
    final=source(root,NATIVE+'final_admission.py',pins[NATIVE+'final_admission.py'])
    if accept_kernel_basis_sha256 is None:
        session=final.open_session(root,profile_path,profile_sha256,accept_contract_sha256)
    else:
        session=final.open_session(root,profile_path,profile_sha256,accept_contract_sha256,accept_kernel_basis_sha256)
    return final,session


class KernelSigaction(ctypes.Structure):
    # Linux x86-64 kernel ABI, NOT glibc's larger sigaction/sigset_t layout.
    _fields_=[(name,ctypes.c_uint64) for name in ('handler','flags','restorer','mask')]


def raw_syscall(number,*arguments):
    libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
    ctypes.set_errno(0)
    result=libc.syscall(ctypes.c_long(number),*arguments)
    need(result>=0,'successful checked raw Linux syscall')
    return result


def kernel_action(number,reset=False):
    need(number in (32,33),'only owned launch hidden signals')
    old=KernelSigaction(*([2**64-1]*4));default=KernelSigaction()
    need(raw_syscall(13,ctypes.c_long(number),ctypes.byref(default) if reset else ctypes.c_void_p(),
                    ctypes.byref(old),ctypes.c_size_t(8))==0,'exact rt_sigaction result')
    return tuple(getattr(old,name) for name,_ in KernelSigaction._fields_)


def kernel_mask():
    mask=ctypes.c_uint64(2**64-1)
    need(raw_syscall(14,ctypes.c_long(0),ctypes.c_void_p(),ctypes.byref(mask),ctypes.c_size_t(8))==0,
         'exact rt_sigprocmask result')
    return mask.value


def launch_task_ids():
    flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_DIRECTORY
    proc=os.open('/proc',flags)
    try:
        libc=ctypes.CDLL(None,use_errno=True);buffer=ctypes.create_string_buffer(256)
        need(libc.fstatfs(ctypes.c_int(proc),ctypes.byref(buffer))==0 and
             ctypes.c_long.from_buffer(buffer).value==0x9fa0,'actual procfs task inventory')
        process=os.open(str(os.getpid()),flags,dir_fd=proc)
        try:
            tasks=os.open('task',flags,dir_fd=process)
            try:
                names=[]
                with os.scandir(tasks) as entries:
                    for entry in entries:
                        need(len(names)<2 and entry.name.isascii() and entry.name.isdecimal() and
                             str(int(entry.name))==entry.name,'bounded canonical task inventory')
                        names.append(int(entry.name))
                return names
            finally:os.close(tasks)
        finally:os.close(process)
    finally:os.close(proc)


def single_launch_main():
    need(os.uname().sysname=='Linux' and os.uname().machine=='x86_64','raw signal ABI platform')
    pid=os.getpid()
    need(raw_syscall(186)==pid and launch_task_ids()==[pid],
         'dedicated single-main launcher; no NPTL peer may own signals32/33')


def normalize_launch_signals():
    # Only main() or the dedicated observer-child process calls this. No helper
    # exists yet, and an unknown task refuses before any signal disposition changes.
    single_launch_main()
    need(kernel_mask()==0,'whole actual kernel signal mask is empty')
    for number in (32,33):
        kernel_action(number,reset=True)
        need(kernel_action(number)==(0,0,0,0),'exact raw default hidden-signal readback')
    single_launch_main()
    need(kernel_mask()==0,'normalization preserves the whole empty kernel mask')


def child_signals():
    single_launch_main()
    need(kernel_mask()==0 and all(kernel_action(n)==(0,0,0,0) for n in (32,33)),
         'actual kernel hidden signals default and whole signal mask empty')
    need(not signal.pthread_sigmask(signal.SIG_BLOCK,[]),'empty inherited signal mask')
    restored={getattr(signal,n) for n in ('SIGPIPE','SIGXFZ','SIGXFSZ') if hasattr(signal,n)}
    for sig in signal.valid_signals():
        if sig not in restored:
            need(signal.getsignal(sig)!=signal.SIG_IGN,'no ignored signal inherited by ordinary exec')


def new_output(root,path):
    path=Path(path)
    need(path.is_absolute() and path.is_relative_to(root/'ignored') and path.parent.resolve(strict=True)==path.parent
         and not os.path.lexists(path),'new owned private output')
    path.mkdir(mode=0o700)
    return path


def artifact_modules(root,reference):
    raw,_=read(reference['path']);need(sha(raw)==reference['sha256'],'old artifact source profile')
    old=decode(raw)
    def load(name):return source(root,CRATE+name,old['sources'][CRATE+name])
    legacy=load('verify_saved.py');ctx,a=legacy.context(root)
    custody=load('startup_custody.py');pinloader=load('startup_pins.py')
    pins=pinloader.load(ctx,Path(reference['path']),reference['sha256'])
    return types.SimpleNamespace(legacy=legacy,ctx=ctx,a=a,custody=custody,pins=pins,
        originals=load('startup_originals.py'),driver=load('startup_produce.py'))


def cargo_command(cargo,root,env):
    need(root.is_absolute() and root.resolve(strict=True)==root and
         Path(cargo).is_absolute() and env['CARGO_TARGET_DIR']==str(root/'target'),'rooted single target')
    return [cargo,'build','--release','--locked','--offline','--manifest-path',
        str(root/NATIVE/'observer/Cargo.toml'),'--bin','li2-kernel-exec-observer','--message-format=json']


def compiler_artifact(raw,root):
    rows=[decode(line) for line in raw.splitlines()]
    expected=root/'target/release/li2-kernel-exec-observer'
    matches=[r for r in rows if r.get('reason')=='compiler-artifact' and r['target']['name']=='li2-kernel-exec-observer']
    need(len(matches)==1,'one actual observer compiler artifact')
    row=matches[0]
    need(row['manifest_path']==str(root/NATIVE/'observer/Cargo.toml') and row['target']['kind']==['bin']
         and row['target']['crate_types']==['bin'] and row['target']['src_path']==str(root/NATIVE/'observer/src/main.rs')
         and row['filenames']==[str(expected)] and row['executable']==str(expected),'exact observer binary artifact')
    need(row['profile']==RELEASE and all(type(row['profile'][k]) is type(v) for k,v in RELEASE.items()),'strict release profile')
    terminal=[r for r in rows if r.get('reason')=='build-finished']
    need(terminal==[dict(reason='build-finished',success=True)] and terminal[0]['success'] is True,'actual successful Cargo terminal')
    return expected


def build_inputs(root,plan,modules,store):
    need(set(plan)=={'schema','root','native_sources','artifact_source_profile','capture','output','destination'}
         and plan['schema']=='LI2NATIVE-OBSERVER-BUILD-PLAN-1' and plan['root']==str(root),'exact prospective build plan')
    native=plan['native_sources']
    need(type(native) is dict and len(native)<=128 and NATIVE+'native_launch.py' in native
         and all(NATIVE+'observer/'+p in native for p in OBSERVER),'whole observer build source roster')
    expected={NATIVE+'observer/'+p for p in OBSERVER}
    need({p for p in native if p.startswith(NATIVE+'observer/')}==expected,'no omitted observer compilation roots')
    need(not os.path.lexists(root/NATIVE/'observer/build.rs') and not os.path.lexists(root/NATIVE/'observer/src/bin'),
         'no unlisted automatic build script or binary')
    for path,digest in native.items():
        need(path.startswith(NATIVE) and '..' not in Path(path).parts and not Path(path).is_absolute(),'native source scope')
        need(sha(store.read(root/path,2*MIB))==digest,'all prospective native source bytes')
    args=types.SimpleNamespace(startup_custody=modules.custody,startup_pins=modules.pins)
    originals=modules.originals.authenticate(modules.ctx,modules.a,modules.legacy,args,store,plan['capture'])
    saved=decode(store.read(Path(plan['capture']['directory'])/'planned.json',MIB))
    captured=dict(env=saved['env'],tools=saved['tools'])
    modules.custody.environment(modules.ctx,captured['env'],captured['tools'])
    rooted=modules.legacy.rooted_module(modules.ctx)
    configs=rooted.configurations(modules.ctx,captured,profile=rooted.COMMENT_PROFILE)
    modules.custody.join_stability(originals['stability'],modules.ctx,modules.pins,store,
        captured,configs,rooted.COMMENT_PROFILE)
    revision=modules.custody.source_profile(modules.ctx,modules.pins,captured['env'])
    def stable():
        modules.custody.join_stability(originals['stability'],modules.ctx,modules.pins,store,
            captured,configs,rooted.COMMENT_PROFILE)
        # No operation between duplicate predicates: the joined original
        # callback checks Store, source and config once, freshly on each call.
        need(originals['stable']()==revision,'observer build revision drift')
    return captured,configs,revision,stable


def build_observer(root,plan_path,plan_sha256):
    raw,plan_pin=read(plan_path);need(sha(raw)==plan_sha256,'externally frozen prospective observer build')
    plan=decode(raw);modules=artifact_modules(root,plan['artifact_source_profile'])
    store=modules.custody.Store(2*1024*MIB);output=None
    result=dict(schema='LI2NATIVE-OBSERVER-BUILD-1',plan=plan_pin,status='UNRUN',error=None,files={},copy=None,
        configurations=None,configuration_profile='rooted-offline-neutral-toml-comments-v1',revision=None,
        build_attempts=0,native_dispatches=0)
    try:
        captured,configs,revision,stable=build_inputs(root,plan,modules,store)
        output=new_output(root,plan['output'])
        destination=Path(plan['destination'])
        need(destination.is_relative_to(root/'ignored') and destination.parent.resolve(strict=True)==destination.parent
             and not os.path.lexists(destination),'new immutable observer destination')
        store.read(plan_path,MIB,plan_pin)
        result.update(configurations=configs,revision=revision,status='BUILD_FAILED',build_attempts=1)
        argv=[captured['tools']['python']['path'],'-B',str(root/NATIVE/'native_launch.py'),'cargo-child',
              captured['tools']['cargo']['path'],str(root)]
        stable()
        code,streams=modules.driver.execute(modules.ctx,modules.legacy,modules.custody,store,captured,output/'build',argv,(120,180,128))
        for name in CONTROLS:result['files'][name]=store.pin(output/'build'/name,128*MIB)
        need(code==0,'observer build exact exit zero')
        artifact=compiler_artifact(streams['stdout'],root);stable()
        before_raw,before=read(artifact,16*MIB)
        copied=write(destination,before_raw,0o500)
        after_raw,after=read(artifact,16*MIB)
        need(before==after and before_raw==after_raw==store.read(destination,16*MIB,copied),'exact temporal observer copy')
        result['copy']=dict(source_before=before,source_after=after,destination=copied)
        stable();result['status']='BUILT'
    except BaseException as error:result['error']=type(error).__name__+': '+str(error)
    finally:
        try:store.close()
        except BaseException as error:result['error']=(result['error'] or '')+'; close: '+str(error)
    if output is not None:write(output/'closed.json',result)
    need(output is not None and result['status']=='BUILT' and result['error'] is None,'observer build refused; retained actual outcome')
    return 0


def observer_build(session,root):
    """Reconstruct raw Cargo/helper/copy closure; never trust BUILT alone."""
    profile=session.profile;reference=profile['observer']['build']
    modules=artifact_modules(root,profile['artifact_source_profile']);store=modules.custody.Store(2*1024*MIB)
    try:
        directory=Path(reference['directory']);raw=store.read(directory/'closed.json',MIB)
        need(sha(raw)==reference['sha256'],'frozen observer build closure')
        value=decode(raw)
        need(set(value)=={'schema','plan','status','error','files','copy','configurations','configuration_profile','revision','build_attempts','native_dispatches'}
             and value['schema']=='LI2NATIVE-OBSERVER-BUILD-1' and value['status']=='BUILT' and value['error'] is None
             and type(value['build_attempts']) is int and value['build_attempts']==1
             and type(value['native_dispatches']) is int and value['native_dispatches']==0,'exact observer build outcome roster')
        plan=decode(store.read(Path(value['plan']['path']),MIB,value['plan']))
        need(plan['native_sources']==profile['native_sources'] and plan['artifact_source_profile']==profile['artifact_source_profile']
             and plan['capture']==dict(directory=profile['arguments']['capture'],sha256=profile['arguments']['capture_sha256'])
             and plan['output']==str(directory) and plan['destination']==profile['observer']['binary']['path'],'build joins final reviewed source/profile')
        captured,configs,revision,stable=build_inputs(root,plan,modules,store)
        need(value['configurations']==configs and value['configuration_profile']=='rooted-offline-neutral-toml-comments-v1'
             and value['revision']==revision,'actual observer build revision/configuration')
        argv=[captured['tools']['python']['path'],'-B',str(root/NATIVE/'native_launch.py'),'cargo-child',captured['tools']['cargo']['path'],str(root)]
        request,command=modules.legacy.request_and_command(modules.ctx,captured,directory/'build',argv,(120,180,128))
        code,streams=modules.custody.closed(store,directory/'build',request,command,modules.ctx.B.HELPER_SHA)
        need(code==0 and set(value['files'])==set(CONTROLS),'whole successful observer build closure')
        for name in CONTROLS:need(value['files'][name]==store.pin(directory/'build'/name,128*MIB),'retained raw observer control')
        source_path=compiler_artifact(streams['stdout'],root)
        copy=value['copy'];need(set(copy)=={'source_before','source_after','destination'},'exact temporal copy receipt')
        before,after,target=copy['source_before'],copy['source_after'],copy['destination']
        need(before==after and before['path']==str(source_path) and target==profile['observer']['binary']
             and before['sha256']==target['sha256'] and before['bytes']==target['bytes']
             and before['stat'][:2]!=target['stat'][:2],'whole temporal copy identity join')
        need(stat.S_IMODE(target['stat'][2])==0o500 and Path(target['path']).is_relative_to(root/'ignored'),'owned immutable executable observer')
        store.read(Path(target['path']),16*MIB,target)
        need(os.stat(target['path'],follow_symlinks=False).st_uid==os.geteuid(),'owned observer binary')
        stable();session.stable()
        return modules,store,target,stable
    except BaseException:store.close();raise


def tools_for(session):
    captured=session.execution_inputs()
    return {name:captured['tools'][name] for name in ('python','timeout','helper')}


def observer_receipt(raw,request,expected_hash):
    # stdout may contain maps; the existing full-output stream cap remains16MiB.
    need(len(raw)<=16*MIB and raw.endswith(b'\n'),'whole bounded observer receipt')
    value=decode(raw,16*MIB)
    required={'schema','request_sha256','transport_accepted','child_started','stops','exec_auxv','entry_auxv','exec_maps','entry_maps',
        'exec_status','entry_status','entry_registers','entry_xstate','debug_restored','primary_error','restore_error','cleanup_error',
        'absence_echild','cleanup','observation','route_coverage_complete','native_correctness_complete'}
    extended='kernel_basis' in request
    if extended:required|={'kernel_basis','kernel_checks','kernel_query'}
    need(set(value)==required and value['schema']==('LI2-OBSERVER-RECEIPT-3' if extended else 'LI2-OBSERVER-RECEIPT-2')
         and value['request_sha256']==expected_hash,'exact observer receipt schema/request')
    if extended:
        # Canonical JSON comparison also rejects bool-for-int substitutions.
        need(json.dumps(value['kernel_basis'],sort_keys=True)==json.dumps(request['kernel_basis'],sort_keys=True),
             'exact requested kernel basis, never an inferred fallback')
        query=value['kernel_query']
        need(type(value['kernel_checks']) is int and value['kernel_checks']==6 and
             type(query) is dict and set(query)=={'result','errno','output_hex'} and
             type(query['result']) is int and query['result']==-1 and
             type(query['errno']) is int and query['errno']==22 and query['output_hex']=='55aa55aa55aa55aa',
             'all six actual kernel checks and exact last consistency query')
    need(all(value[k] is True for k in ('transport_accepted','child_started','debug_restored','absence_echild'))
         and all(value[k] is None for k in ('primary_error','restore_error','cleanup_error')),'complete observation/restoration/cleanup')
    need(value['route_coverage_complete'] is False and value['native_correctness_complete'] is False,'pre-entry is not route/native evidence')
    cleanup=value['cleanup']
    need(type(cleanup) is dict and set(cleanup)=={'direct_pid','terminal_statuses','unexpected_child'}
         and type(cleanup['direct_pid']) is int and 0<cleanup['direct_pid']<1<<31
         and cleanup['unexpected_child'] is False,'exact cleanup owner and no descendants')
    terminal=cleanup['terminal_statuses']
    need(type(terminal) is list and len(terminal)==1 and type(terminal[0]) is dict
         and set(terminal[0])=={'pid','status'} and type(terminal[0]['pid']) is int
         and terminal[0]['pid']==cleanup['direct_pid'] and type(terminal[0]['status']) is int
         and terminal[0]['status']==9,'exact direct-child SIGKILL terminal status')
    stops=value['stops'];need(type(stops) is list and len(stops)==3,'exact stop population')
    for row,kind,status in zip(stops,('initial','exec','entry'),(0x137f,0x4057f,0x57f)):
        need(set(row)=={'kind','status','siginfo'} and row['kind']==kind and type(row['status']) is int
             and row['status']==status,'exact initial-stop/TRACEEXEC/hardware-entry sequence')
        size=0 if kind=='exec' else 128
        need(type(row['siginfo']) is str and len(row['siginfo'])==2*size
             and bytes.fromhex(row['siginfo']).hex()==row['siginfo'],'whole exact stop siginfo bytes')
    for name,size in (('entry_registers',216),('entry_xstate',request['xstate_bytes'])):
        text=value[name];need(type(text) is str and len(text)==2*size and bytes.fromhex(text).hex()==text,'complete unnormalized register image')
    for name,cap in (('exec_auxv',4096),('entry_auxv',4096),('exec_maps',MIB),('entry_maps',MIB),('exec_status',65536),('entry_status',65536)):
        text=value[name];need(type(text) is str and 0<len(text)<=2*cap and len(text)%2==0
            and bytes.fromhex(text).hex()==text,'complete bounded raw stop evidence')
    observation=value['observation']
    need(set(observation)=={'completion','main_entry','bootstrap_bias','stopped_before_main_execution','observer_killed_child','absence_echild','route_coverage_complete'}
         and type(observation['completion']) is int and observation['completion']==1
         and type(observation['main_entry']) is int and observation['main_entry']==request['entry']
         and type(observation['bootstrap_bias']) is int and 0<observation['bootstrap_bias']<1<<47
         and observation['bootstrap_bias']%4096==0
         and all(observation[k] is True for k in ('stopped_before_main_execution','observer_killed_child','absence_echild'))
         and observation['route_coverage_complete'] is False,'exact pre-entry completion observation')
    return value


def observer_child(root,profile_path,profile_hash,contract_hash,work_path,work_hash,kernel_hash=None):
    final,session=open_session(root,profile_path,profile_hash,contract_hash,kernel_hash)
    build_store=None
    try:
        session.check_source(NATIVE+'native_launch.py')
        normalize_launch_signals()
        wire=source(root,NATIVE+'native_wire.py',session.check_source(NATIVE+'native_wire.py'))
        raw,_=read(work_path);need(sha(raw)==work_hash,'exact prospective child request capsule')
        work=decode(raw)
        need(set(work)=={'schema','program','main','dataset','wire'} and work['schema']=='LI2NATIVE-OBSERVE-CHILD-1'
             and work['program'] in PROGRAMS,'finite observer child schema')
        session.bind_main_copy(work['program'],work['main'])
        request=session.request(work['program'],work['dataset']);encoded=wire.encode(request)
        saved,pin=read(work['wire']['path'],wire.CAP)
        need(pin==work['wire'] and saved==encoded,'whole prospective Request reconstruction')
        _,build_store,binary,stable=observer_build(session,root)
        final.no_capabilities(binary)
        fd,digest=wire.sealed(encoded)
        try:
            stable();session.stable();child_signals()
            os.set_inheritable(fd,True)
            os.execve(binary['path'],[binary['path'],'--checked-launcher-request-fd',str(fd),'--request-sha256',digest],{})
        finally:os.close(fd)
    finally:
        if build_store is not None:build_store.close()
        session.close()


def observe_population(root,output,profile_path,profile_hash,contract_hash,session,kernel_hash=None):
    output=new_output(root,output)
    n01=source(root,NATIVE+'n01.py',session.check_source(NATIVE+'n01.py'))
    wire=source(root,NATIVE+'native_wire.py',session.check_source(NATIVE+'native_wire.py'))
    package=n01.load_pinned(root/NATIVE/'package.py',n01.PACKAGE_SHA,'observer_package')
    collector=n01.load_pinned(root/'evaluation/offline-corpus/adjacent_whole.py',n01.COLLECTOR_SHA,'observer_collector')
    held=package.Custody();readers=[];retained=[];build_store=None
    rows=[dict(program=p,status='UNRUN',attempted=False,error=None) for p in PROGRAMS]
    report=dict(schema='LI2NATIVE-OBSERVATIONS-1',programs=rows,route_coverage_complete=False,native_correctness_complete=False,
                ordinary_n01_invocations=0,qualification_complete=False,error=None)
    try:
        _,build_store,_,build_stable=observer_build(session,root)
        tools=tools_for(session)
        for pin in tools.values():held.retain(pin,16*MIB)
        need(tools['helper']['sha256']==n01.HELPER_SHA,'unchanged helper')
        plans={}
        for program in PROGRAMS:
            folder=output/program;folder.mkdir(mode=0o700)
            main=write(folder/'candidate',session.programs[program]['main_bytes'],0o700)
            session.bind_main_copy(program,main);held.retain(main,16*MIB)
            dataset=write(folder/'empty',b'',0o400);held.retain(dataset,65536)
            request=session.request(program,dataset);raw=wire.encode(request)
            wire_pin=write(folder/'request.wire',raw,0o400)
            work=write(folder/'child.json',dict(schema='LI2NATIVE-OBSERVE-CHILD-1',program=program,main=main,dataset=dataset,wire=wire_pin),0o400)
            build_store.read(Path(wire_pin['path']),wire.CAP,wire_pin)
            build_store.read(Path(work['path']),MIB,work)
            argv=[tools['python']['path'],'-B',str(root/NATIVE/'native_launch.py'),'observer-child','--root',str(root),
                '--final-profile',str(profile_path),'--final-profile-sha256',profile_hash,'--accept-contract-sha256',contract_hash,
                '--child-request',work['path'],'--child-request-sha256',work['sha256']]
            if kernel_hash is not None:argv+=['--accept-kernel-basis-sha256',kernel_hash]
            plans[program]=dict(argv=argv,request=request,wire_sha256=sha(raw))
        write(output/'planned.json',dict(programs=list(PROGRAMS),attempts_per_program=1,observer_deadline_seconds=15,
              observer_cleanup_seconds=5,ordinary_n01_invocations=0,requests={p:plans[p]['wire_sha256'] for p in PROGRAMS}))
        def stable():
            build_stable();session.stable();held.verify()
            for reader,identity,members in retained:
                fd=reader.directory('importer')
                try:need(collector.stamp(os.fstat(fd))==identity,'retained observer control directory identity')
                finally:os.close(fd)
                need(reader.names('importer')==members,'retained observer control membership')
                reader.verify()
        for row in rows:
            program=row['program'];folder=output/program;importer=folder/'importer';importer.mkdir()
            stable();child_signals()
            row.update(status='FAILED',attempted=True)
            reader=collector.OutputReader(folder);readers.append(reader)
            ctx=types.SimpleNamespace(ROOT=folder,B=types.SimpleNamespace(write=write))
            request,command=collector.invoke(ctx,importer,plans[program]['argv'],{},tools)
            code,stdout,stderr=n01.completed(collector,reader,request,command)
            stable();reader.verify()
            need(code==0 and stderr==b'','observer exact helper exit/stdout/stderr')
            observer_receipt(stdout,plans[program]['request'],plans[program]['wire_sha256'])
            fd=reader.directory('importer')
            try:identity=collector.stamp(os.fstat(fd))
            finally:os.close(fd)
            retained.append((reader,identity,reader.names('importer')))
            row['status']='PASS'
        stable()
    except BaseException as error:
        report['error']=type(error).__name__+': '+str(error)
        for row in rows:
            if row['status']=='FAILED':row['error']=report['error']
    finally:
        owners=[*readers,held]+([build_store] if build_store is not None else [])+[session]
        for owner in owners:
            try:owner.close()
            except BaseException as error:
                report['error']=(report['error'] or '')+'; close: '+type(error).__name__+': '+str(error)
    report['pre_entry_observation_complete']=report['error'] is None and all(row['status']=='PASS' for row in rows)
    write(output/'closed.json',report)
    return 0 if report['pre_entry_observation_complete'] else 1


def main():
    need(not sys.flags.optimize,'assertions required')
    if len(sys.argv)==4 and sys.argv[1]=='cargo-child':
        root=Path(sys.argv[3]);argv=cargo_command(sys.argv[2],root,dict(os.environ))
        os.chdir('/');os.execve(argv[0],argv,dict(os.environ))
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('build-observer','observe','n01','observer-child'))
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[2])
    for name in ('final-profile','output','build-plan','child-request'):parser.add_argument('--'+name,type=Path)
    for name in ('final-profile-sha256','accept-contract-sha256','accept-kernel-basis-sha256','build-plan-sha256','child-request-sha256'):parser.add_argument('--'+name)
    args=parser.parse_args();root=args.root
    need(root.is_absolute() and root.resolve(strict=True)==root,'canonical checkout root')
    roster={'build-observer':{'build_plan','build_plan_sha256'},
        'observe':{'final_profile','final_profile_sha256','accept_contract_sha256','output'},
        'n01':{'final_profile','final_profile_sha256','accept_contract_sha256','output'},
        'observer-child':{'final_profile','final_profile_sha256','accept_contract_sha256','child_request','child_request_sha256'}}
    supplied={name for name,value in vars(args).items() if name not in ('mode','root') and value is not None}
    expected=roster[args.mode]
    if args.accept_kernel_basis_sha256 is not None:
        need(args.mode!='build-observer','kernel acceptance belongs only to final launch')
        expected=expected|{'accept_kernel_basis_sha256'}
    need(supplied==expected,'exact mode-specific launch argument roster')
    if args.mode=='build-observer':return build_observer(root,args.build_plan,args.build_plan_sha256)
    if args.mode=='observer-child':return observer_child(root,args.final_profile,args.final_profile_sha256,args.accept_contract_sha256,args.child_request,args.child_request_sha256,args.accept_kernel_basis_sha256)
    _,session=open_session(root,args.final_profile,args.final_profile_sha256,args.accept_contract_sha256,args.accept_kernel_basis_sha256)
    try:
        normalize_launch_signals()
        if args.mode=='observe':return observe_population(root,args.output,args.final_profile,args.final_profile_sha256,args.accept_contract_sha256,session,args.accept_kernel_basis_sha256)
        n01=source(root,NATIVE+'n01.py',session.check_source(NATIVE+'n01.py'))
        return n01.run_final(root,args.output,session,dict(path=str(args.final_profile),sha256=args.final_profile_sha256))
    finally:session.close()


if __name__=='__main__':
    raise SystemExit(main())
