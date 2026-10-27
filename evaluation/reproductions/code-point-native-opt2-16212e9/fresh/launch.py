#!/usr/bin/env python3
"""Bound one build/prepare/native stage of an independent fresh repetition."""
import argparse,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
if sys.flags.optimize:raise SystemExit('assertions required')
REVISION='16212e9ab00a18ce003a305f7265bce8633e1c0e'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('stage',choices=('build','prepare','run'));ap.add_argument('--cohort',type=Path,required=True)
    for key in('toolchain','user-home','cargo-home'):ap.add_argument('--'+key,type=Path)
    ap.add_argument('--sole-writer',action='store_true',required=True);args=ap.parse_args()
    repo=Path.cwd().resolve();packet=Path(__file__).resolve().parent;root=args.cohort
    assert packet.is_relative_to(repo/'ignored')and packet.resolve(strict=True)==packet
    assert root.is_absolute()and root.parent==repo/'ignored'and not root.is_symlink()
    assert not packet.is_relative_to(root)and not root.is_relative_to(packet)
    pins=json.loads((packet/'pins.json').read_text());assert set(pins)=={'schema','revision','files'}and pins['schema']==1 and pins['revision']==REVISION
    assert set(pins['files'])=={'build.py','run.py','prepare.py','launch.py','CASES.json','source-members.json'}
    for name,pin in pins['files'].items():
        data=(packet/name).read_bytes();assert pin==dict(sha256=sha(data),bytes=len(data))
    assert {0,1,2,3}<=os.sched_getaffinity(0);os.sched_setaffinity(0,{0,1,2,3})
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    if args.stage=='build':
        assert not root.exists();root.mkdir()
        for value in(args.toolchain,args.user_home,args.cargo_home):assert value is not None and value.is_absolute()and value.resolve(strict=True)==value and value.is_dir()
        source=packet/'build.py';bound=240
        argv=['/usr/bin/python3.9','-B',str(source),'--repo',str(repo),'--output',str(root/(root.name+'-native-build')),'--toolchain',str(args.toolchain),'--user-home',str(args.user_home),'--cargo-home',str(args.cargo_home),'--phase','native-build']
    else:
        assert root.resolve(strict=True)==root
        source=packet/('prepare.py'if args.stage=='prepare'else'run.py');bound=90 if args.stage=='prepare'else 1200
        if args.stage=='prepare':argv=['/usr/bin/python3.9','-B',str(source),'--cohort',str(root)]
        else:
            binding=root/'activation/binding.json';binding_hash=sha(binding.read_bytes());prepared=json.loads((root/'prepare-parent/closed.json').read_text())
            assert prepared['exit']==0 and prepared['parent_error']is None and prepared['parent_wait_returned']is True
            assert not (root/'native').exists()
            argv=['/usr/bin/python3.9','-B',str(source),'--binding',str(binding),'--binding-sha256',binding_hash,'--raw',str(root/'native')]
    parent=root/(args.stage+'-parent');assert not parent.exists();parent.mkdir()
    def write(name,value):
        with(parent/name).open('x')as f:json.dump(value,f,sort_keys=True,indent=2,allow_nan=False);f.write('\n')
    write('command.json',dict(argv=argv,cwd=str(repo),env=env,affinity=[0,1,2,3],parent_timeout_seconds=bound,parent_cleanup_seconds=10,source_revision=REVISION,source_sha256=sha(source.read_bytes()),parent_source_sha256=sha(Path(__file__).read_bytes()),cohort='fresh-independent-repetition',historical_result_transfer=False))
    child=None;error=None;start=time.monotonic()
    try:
        with(parent/'stdout.txt').open('xb')as out,(parent/'stderr.txt').open('xb')as err:
            child=subprocess.Popen(argv,cwd=repo,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
            try:
                write('started.json',dict(pid=child.pid));child.wait(timeout=bound)
            except BaseException as failure:
                error=type(failure).__name__
                if child.poll()is None:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:error+=':CLEANUP_WAIT_EXPIRED';raise
                raise
    finally:
        if child is not None:
            closed=dict(exit=child.returncode,parent_error=error,parent_wait_returned=child.returncode is not None,pid=child.pid,seconds=time.monotonic()-start,stdout_sha256=sha((parent/'stdout.txt').read_bytes()),stderr_sha256=sha((parent/'stderr.txt').read_bytes()))
            write('closed.json',closed)
    assert child is not None
    print(json.dumps(closed,sort_keys=True));raise SystemExit(0 if child.returncode==0 and error is None else 1)
if __name__=='__main__':main()
