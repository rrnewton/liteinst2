#!/usr/bin/env python3
"""Root-owned bounded caller for twelve pure controls; never a product admission."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import argparse, hashlib, json, math, os, re, signal, stat, subprocess, time
from pathlib import Path

R=Path(__file__).resolve().parents[4]
E=R/'ignored/a3/common-core-canonical-epoch-50c0715-v1'
OUT=E/'canonical-pure-controls-v1'
P=R/'ignored/a3/common-core-canonical-verifier-proposal-v3'
ENV=dict(PATH='/usr/bin:/bin',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
CAP=128*1024*1024
PINS={
 'controls.py':'e9e70c86a41181cb1b386a525a1b0872332eb1d7633b32ae4162455c25fc6953',
 'payload/evaluation/e9-common-app/run_core_pairs.py':'c2bbca05f9cf4c728f8d3f939588e027e53266109bc1185083ac0594a471e05e',
 'payload/build.py':'5fbf13ecb2dd61316be9880af70ceaa7b8686365d894441405472f3e758df26a',
}
HELPER='c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
METHODS=(
 'test_complete_source_correspondence',
 'test_missing_each_original_attribute_refuses',
 'test_duplicate_each_original_attribute_refuses',
 'test_preexisting_each_canonical_attribute_refuses',
 'test_near_spelling_is_not_a_path_exemption',
 'test_exact_seven_member_map',
 'test_fresh_epoch_is_one_explicit_direct_child',
 'test_closed_historical_epoch_refuses',
 'test_epoch_scope_ancestors_descendants_and_escape_refuse',
 'test_raw_build_and_review_must_match_the_exact_new_root',
 'test_unactivated_scope_refuses_before_any_read',
 'test_explicit_dispatch_and_no_fallback_after_refusal',
)

def sha(data):return hashlib.sha256(data).hexdigest()
def six(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path):
    assert path.is_absolute() and path.resolve(strict=True)==path and not path.is_relative_to(R/'target')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno());assert stat.S_ISREG(before.st_mode) and 0<=before.st_size<=CAP
        data=stream.read(before.st_size+1)
        assert len(data)==before.st_size and six(before)==six(os.fstat(stream.fileno()))==six(path.lstat())
    return data,dict(sha256=sha(data),bytes=len(data),stat=six(before))
def put(path,value):
    data=value if type(value) is bytes else (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with path.open('xb') as stream:stream.write(data)
def loads(data):
    def pairs(rows):
        result={}
        for key,value in rows:assert key not in result;result[key]=value
        return result
    def invalid(value):raise AssertionError('invalid JSON constant '+value)
    return json.loads(data,object_pairs_hook=pairs,parse_constant=invalid)
def snapshot():
    values={}
    for relative,digest in PINS.items():
        path=P/relative;data,owner=read(path);assert sha(data)==digest;values[str(path)]=owner
    helper=R/'tools/unwind-oracle/bounded_command.py';data,owner=read(helper)
    assert sha(data)==HELPER;values[str(helper)]=owner
    self_path=Path(__file__).resolve();values[str(self_path)]=read(self_path)[1]
    tools={}
    for spelling in ('/usr/bin/python3.9','/usr/bin/timeout'):
        path=Path(spelling);resolved=path.resolve(strict=True);owner=read(resolved)[1]
        assert owner['stat'][2]&0o111
        tools[spelling]=dict(resolved=str(resolved),owner=owner,lexical_stat=six(path.lstat()))
    return dict(files=values,tools=tools)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--run-controls',action='store_true',required=True)
    args=ap.parse_args();assert args.run_controls
    assert R.resolve(strict=True)==R and E.parent==R/'ignored/a3' and E.name!='common-native-epoch-v1'
    assert not OUT.exists() and not OUT.is_symlink()
    if not E.exists():E.mkdir(mode=0o700)
    assert E.resolve(strict=True)==E and stat.S_ISDIR(E.lstat().st_mode)
    assert {0,1,2,3}<=set(os.sched_getaffinity(0));os.sched_setaffinity(0,{0,1,2,3})
    assert sorted(os.sched_getaffinity(0))==[0,1,2,3]
    before=snapshot()
    OUT.mkdir(mode=0o700);put(OUT/'before.json',before)
    request=dict(argv=['/usr/bin/python3.9','-B',str(P/'controls.py'),'-v'],cwd=str(R),env=ENV,
        stdout=str(OUT/'stdout.txt'),stderr=str(OUT/'stderr.txt'),cpu_seconds=10,wall_seconds=15,file_bytes=1048576)
    outer=['/usr/bin/timeout','--signal=TERM','--kill-after=10s','25s','/usr/bin/python3.9','-B',
        str(R/'tools/unwind-oracle/bounded_command.py'),'--request',str(OUT/'request.json'),'--receipt',str(OUT/'receipt.json')]
    command=dict(argv=outer,cwd=str(R),env=ENV,parent_timeout_seconds=40,cpus=[0,1,2,3],
        scope='SOURCE_ONLY_PURE_CANONICAL_CONTROLS',methods=list(METHODS),source_pins=PINS,helper_sha256=HELPER)
    put(OUT/'request.json',request);put(OUT/'command.json',command)
    started=time.monotonic();child=None;parent_error=None
    try:
        with (OUT/'controller.stdout').open('xb') as out,(OUT/'controller.stderr').open('xb') as err:
            child=subprocess.Popen(outer,cwd=R,env=ENV,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
            try:
                put(OUT/'started.json',dict(pid=child.pid,command_sha256=sha(read(OUT/'command.json')[0])))
                child.wait(timeout=40)
            except BaseException as error:
                parent_error=type(error).__name__
                if child.poll() is None:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                try:child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    parent_error=type(error).__name__+':CLEANUP_WAIT_EXPIRED'
                    raise
                raise
    finally:
        if child is not None:
            put(OUT/'closed.json',dict(exit=child.returncode,parent_error=parent_error,parent_wait_returned=child.returncode is not None,
                pid=child.pid,seconds=time.monotonic()-started,stdout_sha256=sha(read(OUT/'controller.stdout')[0]),stderr_sha256=sha(read(OUT/'controller.stderr')[0])))
    after=snapshot();put(OUT/'after.json',after);assert after==before
    assert child is not None and child.returncode==0 and parent_error is None
    assert read(OUT/'controller.stderr')[0]==b''
    assert read(OUT/'controller.stdout')[0]==(json.dumps(dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True))+'\n').encode()
    receipt=loads(read(OUT/'receipt.json')[0])
    assert set(receipt)=={'request_sha256','helper_sha256','exit','wall_timeout','unexpected_descendants','absence_proof','stdout_sha256','stderr_sha256','elapsed_seconds','cleanup_events','cleanup_error','aborted','inputs_unchanged'}
    assert receipt['request_sha256']==sha(read(OUT/'request.json')[0]) and receipt['helper_sha256']==HELPER
    assert type(receipt['exit']) is int and receipt['exit']==0 and receipt['wall_timeout'] is False
    assert receipt['absence_proof']=='ECHILD' and receipt['unexpected_descendants']==receipt['cleanup_events']==[]
    assert receipt['cleanup_error'] is receipt['aborted'] is None and receipt['inputs_unchanged'] is True
    assert type(receipt['elapsed_seconds']) in (int,float) and math.isfinite(receipt['elapsed_seconds']) and 0<=receipt['elapsed_seconds']<=15
    for stream in ('stdout','stderr'):
        data=read(OUT/(stream+'.txt'))[0]
        assert len(data)<=1048576 and sha(data)==receipt[stream+'_sha256']
    assert read(OUT/'stdout.txt')[0]==b''
    text=read(OUT/'stderr.txt')[0].decode()
    expected=''.join(name+' (__main__.CanonicalControls) ... ok\n' for name in sorted(METHODS))
    assert text.startswith(expected)
    assert re.fullmatch(r'\n-{70}\nRan 12 tests in [0-9]+\.[0-9]+s\n\nOK\n',text[len(expected):])
    put(OUT/'checks.json',dict(status='CLOSED_PURE_SOURCE_CONTROLS_PASS',methods={name:'PASS' for name in sorted(METHODS)},
        tests=12,source_tools_exact_before_after=True,strict_receipt=True,parent_wait=True,
        source_imports_only=True,compiler_executions=0,application_or_verifier_executions=0,
        product_admission=False,runtime_admission=False,namespace_admission=False,qualification_complete=False))
    print(json.dumps(dict(status='CLOSED_PURE_SOURCE_CONTROLS_PASS',tests=12,output=str(OUT),qualification_complete=False),sort_keys=True))

if __name__=='__main__':main()
