#!/usr/bin/env python3
"""Five fixed workspace gates; twelve externally reserved CPUs, private output."""
import sys
if not (__debug__ and sys.flags.isolated and sys.flags.dont_write_bytecode):
    raise SystemExit('use Python -I -B with assertions enabled')
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

CAP = 8*1048576
HELPER = 'evaluation/admission/processes.py'
HELPER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
COMMANDS = [
    ['fmt', ['cargo','fmt','--check'], 180],
    ['clippy', ['cargo','clippy','--workspace','--all-targets','--all-features','--','-D','warnings'], 180],
    ['check', ['cargo','check','--workspace','--all-features','--all-targets'], 180],
    ['workspace', ['cargo','test','-j','12','--workspace','--no-fail-fast'], 900],
    ['serial-launch', ['cargo','test','-p','liteinst-launch','--tests','--','--test-threads=1','--nocapture'], 180],
]
SCOPE = ('src','crates','tests','examples','tools','.cargo','Cargo.toml','Cargo.lock',
         'build.rs','rust-toolchain','rust-toolchain.toml',HELPER)


def read(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode) and before.st_size <= limit
        data = stream.read(limit+1); after = os.fstat(stream.fileno()); current = path.lstat()
        assert len(data) == before.st_size <= limit
        assert all(getattr(before,k) == getattr(after,k) == getattr(current,k)
                   for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns'))
    return data


def pin(path):
    with os.fdopen(os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode) and before.st_size <= 512*1048576
        h = hashlib.sha256(); total = 0
        for block in iter(lambda: stream.read(1048576), b''):
            total += len(block); assert total <= before.st_size; h.update(block)
        assert total == before.st_size
        after = os.fstat(stream.fileno()); current = path.lstat()
        assert all(getattr(before,k) == getattr(after,k) == getattr(current,k)
                   for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns'))
    return dict(bytes=total, sha256=h.hexdigest())


def durable(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False)+'\n').encode(); assert len(data) <= CAP
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def normal(row):
    return row['exit_code'] == 0 and row['termination'] is None and row['cleanup_complete'] is True and row['reaped_descendants'] == 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('root','output','toolchain','budget'): p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--revision',required=True); p.add_argument('--budget-sha256',required=True)
    a = p.parse_args(); assert re.fullmatch('[0-9a-f]{40}',a.revision) and re.fullmatch('[0-9a-f]{64}',a.budget_sha256)
    root,out,tc,bp = a.root,a.output,a.toolchain,a.budget
    assert all(v.is_absolute() and v.resolve(strict=True)==v for v in (root,tc,bp))
    assert root.is_dir() and tc.is_dir() and out.is_absolute() and out.parent.resolve(strict=True)==out.parent
    assert out.is_relative_to(root/'ignored') and out!=root/'ignored'
    out.mkdir(mode=0o700); logs=root/'target/evaluation'/out.name
    started=time.monotonic(); safe=True; before_done=False; frozen={}
    receipt=dict(status='FAILED',revision=a.revision,commands=COMMANDS,output_cap=CAP,results=[],scans=[],
                 outcomes=[dict(name=n,command=c,wall_seconds=w,status='UNOBSERVED') for n,c,w in COMMANDS],
                 qualification='NONE',scope='Workspace command closure only; separate test census review required.')
    try:
        assert not logs.exists()
        rust_tools=('cargo','rustc','rustdoc','rustfmt','cargo-clippy','clippy-driver')
        tools={n:(tc/'bin'/n).resolve(strict=True) for n in rust_tools}
        tools.update({n:Path('/usr/bin',n).resolve(strict=True) for n in ('git','du','prlimit')})
        tools['python']=Path(sys.executable).resolve(strict=True)
        env=dict(HOME=os.environ['HOME'],PATH=str(tc/'bin')+':/usr/bin:/bin',LANG='C',LC_ALL='C',
                 RUSTC=str(tools['rustc']),RUSTDOC=str(tools['rustdoc']),CARGO_INCREMENTAL='0',
                 CARGO_BUILD_JOBS='12',RUST_TEST_THREADS='12',CARGO_NET_OFFLINE='true',
                 CARGO_TARGET_DIR=str(root/'target'),CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0')
        cpus=sorted(os.sched_getaffinity(0)); assert len(cpus)==12
        def git(*args):
            data=subprocess.check_output([str(tools['git']),'-C',str(root),*args],env=env,timeout=15)
            assert len(data)<=CAP; return data
        def clean():
            assert git('rev-parse','--show-toplevel').decode().strip()==str(root)
            assert git('rev-parse','HEAD').decode().strip()==a.revision
            assert git('status','--porcelain','--untracked-files=no')==b''
        clean(); os.chdir(root)
        budget_bytes=read(bp,CAP); assert hashlib.sha256(budget_bytes).hexdigest()==a.budget_sha256
        budget=json.loads(budget_bytes)
        assert set(budget)=={'schema','initial_slot','increment_reserve','ceilings'} and type(budget['schema']) is int and budget['schema']==1
        initial,reserve,ceilings=budget['initial_slot'],budget['increment_reserve'],budget['ceilings']
        assert type(reserve) is int and reserve==2**31+2**26
        assert type(initial) is list and type(ceilings) is list and len(initial)==len(ceilings)==2
        assert all(type(n) is int and n>=0 for n in initial+ceilings)
        assert [n+reserve for n in initial]==ceilings and all(n<20000000000 for n in ceilings)
        names=git('ls-files','-z','--',*SCOPE).decode().rstrip('\0').split('\0')
        assert names and all(names) and len(names)==len(set(names)) and HELPER in names
        for name in names: frozen[str(root/name)]=pin(root/name)
        script=Path(__file__).resolve()
        for path in (script,bp,*tools.values()): frozen[str(path)]=pin(path)
        assert frozen[str(bp)]==dict(bytes=len(budget_bytes),sha256=a.budget_sha256)
        helper=root/HELPER; assert frozen[str(helper)]['sha256']==HELPER_SHA
        assert read(helper,CAP)==git('show',a.revision+':'+HELPER)
        spec=importlib.util.spec_from_file_location('workspace_owner',helper)
        owner=importlib.util.module_from_spec(spec); spec.loader.exec_module(owner)
        logs.mkdir(parents=True,exist_ok=False)
        assert (root/'target').resolve(strict=True)==root/'target'
        receipt.update(tree=git('rev-parse','HEAD^{tree}').decode().strip(),cpus=cpus,load_before=os.getloadavg(),
                       environment=env,serial_environment=env|{'RUST_TEST_THREADS':'1'},capacity_budget=budget,
                       budget_pin=frozen[str(bp)],sources_and_tools=frozen,script=dict(path=str(script),**frozen[str(script)]),
                       launch_argv=sys.argv,independent_allocator_live_witness=False,
                       started_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        durable(out/'planned.json',receipt)
        def unchanged():
            clean(); assert sorted(os.sched_getaffinity(0))==cpus
            assert all((tc/'bin'/n).resolve(strict=True)==tools[n] for n in rust_tools)
            assert git('ls-files','-z','--',*SCOPE).decode().rstrip('\0').split('\0')==names
            assert all(pin(Path(path))==wanted for path,wanted in frozen.items())
        def owned(name,command,wall,cap,environment,collection):
            nonlocal safe
            unchanged(); row=dict(name=name,command=command,wall_seconds=wall,log_bytes=cap,status='DISPATCHED_UNKNOWN',load_before=os.getloadavg())
            collection.append(row); safe=False
            result=owner.run_command(command,environment,logs/(name+'.log'),wall,cap)
            row['result']=result
            row['owner_record']=durable(out/(name+'-owner.json'),dict(name=name,command=command,wall_seconds=wall,log_bytes=cap,result=result))
            safe=result['cleanup_complete'] is True
            if safe: row['status']='FAILED'
            assert safe, 'owner cleanup incomplete: capture remains unread'
            data=read(logs/(name+'.log'),cap); assert hashlib.sha256(data).hexdigest()==result['private_log_sha256']
            with (out/(name+'.log')).open('xb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            row.update(capture=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest()),load_after=os.getloadavg())
            unchanged()
            if not normal(result): raise RuntimeError(name+' failed; retained CLOSED capture')
            row['status']='PASS'; return data
        def scan(tag):
            values=[]
            for apparent in (False,True):
                name=tag+('-apparent' if apparent else '-allocated')
                command=[str(tools['prlimit']),'--cpu=30','--as=268435456','--fsize=65536','--core=0','--',str(tools['du']),'--block-size=1','--count-links','-s']
                if apparent: command.append('--apparent-size')
                paths=[root,root/'ignored',root/'target']; command.extend(map(str,paths))
                data=owned(name,command,45,65536,env,receipt['scans']); lines=data.decode().splitlines(); assert len(lines)==3
                measured=[]
                for line,path in zip(lines,paths):
                    match=re.fullmatch(r'(0|[1-9][0-9]*)\t'+re.escape(str(path)),line); assert match
                    measured.append(int(match[1]))
                receipt['scans'][-1]['values']=measured; values.append(measured[0])
            assert all(n<limit for n,limit in zip(values,ceilings)), 'fixed cumulative capacity ceiling exceeded'
            receipt['remaining_reserve_'+tag]=[limit-n for n,limit in zip(values,ceilings)]
        scan('before'); before_done=True
        for outcome,(name,command,wall) in zip(receipt['outcomes'],COMMANDS):
            outcome['status']='DISPATCHED_UNKNOWN'
            try:
                owned(name,command,wall,CAP,env|({'RUST_TEST_THREADS':'1'} if name=='serial-launch' else {}),receipt['results'])
                outcome['status']='PASS'
            except BaseException:
                if safe: outcome['status']='FAILED'
                raise
        unchanged(); receipt['commands_passed']=True
    except BaseException as error:
        receipt['error']=type(error).__name__+': '+str(error)
    finally:
        if before_done and safe:
            try:
                scan('after'); unchanged(); receipt.update(source_unchanged=True,capacity_after_verified=True)
            except BaseException as error:
                receipt['postflight_error']=type(error).__name__+': '+str(error)
        if receipt.get('commands_passed') and receipt.get('capacity_after_verified') and receipt.get('source_unchanged') and 'error' not in receipt:
            receipt['status']='PASS'
        receipt.update(cleanup_complete=safe,closed_utc=dt.datetime.now(dt.timezone.utc).isoformat(),seconds=time.monotonic()-started,load_after=os.getloadavg())
        durable(out/'closed.json',receipt)
    return 0 if receipt['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
